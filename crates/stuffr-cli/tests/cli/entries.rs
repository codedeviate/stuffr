use crate::common::*;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use tar::{Builder, Header};

// ---------------------------------------------------------------------
// Entry-aware pack/unpack/cat.
//
// The hostile fixtures below are written with the RAW `tar` crate, bypassing
// `Header::set_path` (which refuses `..` and absolute names outright), so
// they carry names stuffr itself would never produce. That is the point:
// containment has to refuse an archive somebody else wrote.
// ---------------------------------------------------------------------

#[test]
fn a_traversing_entry_is_refused_and_writes_nothing_outside_the_destination() {
    let dir = tmp_dir();
    let evil = dir.join("evil.tar");
    // Written with the raw `tar` crate, NOT through stuffr — stuffr must be
    // able to refuse archives it would never itself produce.
    write_raw_tar(&evil, &[Raw::File("../escaped.txt", b"pwned")]);

    let out = run_output(&[
        "unpack",
        evil.to_str().unwrap(),
        "-C",
        dir.join("out").to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(7),
        "a traversing entry must be refused as an unsafe path (exit 7), stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !dir.join("escaped.txt").exists(),
        "the file escaped the destination"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("../escaped.txt"),
        "the refusal must name the offending entry, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A **file** entry named `.` must be refused, not `File::create`d over the
/// caller's own destination directory.
///
/// `safe_join` resolves `.` to `dest` itself, deliberately — that is the
/// first entry `tar cf x.tar .` emits, and a DIRECTORY entry naming it is
/// correct and common. It cannot decide the case alone because it never sees
/// the entry's kind, so `entries.rs` refuses a non-`Dir` entry that resolves
/// to `dest` after the join.
///
/// Before that refusal existed this was **exit 1** — `i/o error: Is a
/// directory (os error 21)` — from three bytes of hostile name. Exit 1 means
/// *stuffr* failed, the one code hostile input must never produce and the
/// invariant `check_error_is_classified` exists to hold.
///
/// Written with the raw `tar` crate, never through stuffr: this is a shape
/// stuffr would not itself produce, and the hole is pre-existing in
/// `entries.rs` rather than anything a container introduced.
#[test]
fn a_file_entry_naming_the_destination_itself_is_refused() {
    let dir = tmp_dir();
    let evil = dir.join("dot.tar");
    write_raw_tar(&evil, &[Raw::File(".", b"pwned")]);
    let out_dir = dir.join("out");

    let out = run_output(&[
        "unpack",
        evil.to_str().unwrap(),
        "-C",
        out_dir.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(7),
        "a file entry naming the destination must be an unsafe path (exit 7), never exit 1 \
         (`stuffr failed`), stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out_dir.is_dir(),
        "the destination must still be a directory, not a file stuffr created over it"
    );

    // A DIRECTORY entry named `.` is the legitimate shape and must still
    // work — the refusal is pinned to the kind, not to the name.
    let ok = dir.join("dotdir.tar");
    write_raw_tar(&ok, &[Raw::Dir("."), Raw::File("a.txt", b"hi")]);
    let ok_dir = dir.join("ok");
    let out = run_output(&[
        "unpack",
        ok.to_str().unwrap(),
        "-C",
        ok_dir.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "`tar cf x.tar .`'s own leading directory entry must still extract, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(ok_dir.join("a.txt")).unwrap(), b"hi");
}

/// The same refusal reached through LHA, which is where it was found.
///
/// `delharc`'s own name accessor stripped `.` to the empty string, so this
/// entry used to be refused one step earlier by `safe_join`'s "empty entry
/// name". Reporting the name verbatim — which is what containment needs —
/// let the raw `.` through to the hole `entries.rs` now closes, so BOTH
/// containers are tested: closing it in one place is the point.
#[test]
fn an_lha_file_entry_naming_the_destination_itself_is_refused() {
    let dir = tmp_dir();
    let evil = dir.join("dot.lzh");
    std::fs::write(&evil, raw_lha_entry(b".", b"-lh0-", b"pwned")).unwrap();
    let out_dir = dir.join("out");

    let out = run_output(&[
        "unpack",
        evil.to_str().unwrap(),
        "-C",
        out_dir.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(7),
        "an LHA file entry naming the destination must be exit 7, never exit 1, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out_dir.is_dir(),
        "the destination must still be a directory"
    );
}

#[test]
fn an_absolute_entry_path_is_refused() {
    let dir = tmp_dir();
    let evil = dir.join("abs.tar");
    // PID-qualified: a shared, fixed /tmp name left behind by one failing run
    // would make every later run fail for the wrong reason.
    let escape = std::env::temp_dir().join(format!("stuffr-abs-{}-escape.txt", std::process::id()));
    let _ = std::fs::remove_file(&escape);
    write_raw_tar(&evil, &[Raw::File(escape.to_str().unwrap(), b"pwned")]);

    let out = run_output(&[
        "unpack",
        evil.to_str().unwrap(),
        "-C",
        dir.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(7),
        "an absolute entry name must be refused as an unsafe path (exit 7), stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !escape.exists(),
        "an absolute entry name wrote outside the destination: {}",
        escape.display()
    );
}

#[test]
fn cat_streams_one_named_entry_from_a_pipe() {
    let bytes = std::fs::read(write_fixture_tar(
        &tmp_dir(),
        &[("a.txt", b"alpha"), ("b.txt", b"beta")],
    ))
    .unwrap();
    assert_eq!(run_with_stdin(&["cat", "-", "b.txt"], &bytes), "beta");
}

#[test]
fn pack_collects_several_paths_into_one_archive() {
    let dir = tmp_dir();
    std::fs::write(dir.join("one.txt"), b"1").unwrap();
    std::fs::write(dir.join("two.txt"), b"2").unwrap();
    let out = dir.join("bundle.tar");
    let packed = run_output(&[
        "pack",
        dir.join("one.txt").to_str().unwrap(),
        dir.join("two.txt").to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ]);
    assert!(
        packed.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&packed.stderr)
    );
    let listed = String::from_utf8(run_output(&["list", out.to_str().unwrap()]).stdout).unwrap();
    assert!(
        listed.contains("one.txt") && listed.contains("two.txt"),
        "both entries must be listed, got: {listed}"
    );
    // Stored under their basenames, not the absolute paths they came from:
    // stuffr must not write an archive it would itself refuse at exit 7.
    assert!(
        !listed.contains(dir.to_str().unwrap()),
        "absolute paths must not be stored as entry names, got: {listed}"
    );
}

// --- Hostile cases beyond the brief ---------------------------------------

#[test]
fn a_symlink_whose_target_escapes_the_destination_is_refused_before_it_is_created() {
    let dir = tmp_dir();
    let dest = dir.join("out");
    let evil = write_raw_tar(
        &dir.join("link.tar"),
        &[Raw::Symlink("link", "../../etc/passwd")],
    );

    let out = run_output(&[
        "unpack",
        evil.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(7),
        "an escaping symlink target must be refused (exit 7), stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        std::fs::symlink_metadata(dest.join("link")).is_err(),
        "the symlink must not have been created at all"
    );
    // The ENTRY, not the target text (0.10.1 final review F2): `link` is
    // what `stuffr list` shows and what the user can go and look at.
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(
            "unsafe entry path `link` refused: symlink target `../../etc/passwd` \
             climbs out of the destination"
        ),
        "the refusal must name the offending entry, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Spec 8a: the refusal quotes the target, so a user can find the offending
/// link text, not only the entry name.
#[test]
fn a_hard_link_whose_target_is_unsafe_quotes_the_target() {
    let dir = tmp_dir();
    let dest = dir.join("out");
    let evil = write_raw_tar(
        &dir.join("h.tar"),
        &[Raw::Hardlink("hl", "../../etc/passwd")],
    );
    let out = run_output(&[
        "unpack",
        evil.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(7), "stderr: {stderr}");
    assert!(
        stderr.contains(
            "unsafe entry path `hl` refused: its hard-link target `../../etc/passwd` \
             is not a safe path inside the destination"
        ),
        "got: {stderr}"
    );
}

/// A target is archive-controlled text: control characters in it are escaped
/// exactly as entry names are, never printed raw.
#[test]
fn a_symlink_target_with_control_characters_is_quoted_escaped() {
    let dir = tmp_dir();
    let dest = dir.join("out");
    let evil = write_raw_tar(
        &dir.join("esc.tar"),
        &[Raw::Symlink("link", "../\x1b`x/../..")],
    );
    let out = run_output(&[
        "unpack",
        evil.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(7), "stderr: {stderr}");
    assert!(!stderr.contains('\x1b'), "raw ESC leaked: {stderr:?}");
    assert!(
        stderr.contains("symlink target `../\\x1b`x/../..` climbs out of the destination"),
        "got: {stderr:?}"
    );
}

#[test]
fn an_entry_written_through_an_escaping_symlink_lands_nowhere() {
    // The two-entry attack: entry 1's own PATH is perfectly contained, so
    // only its TARGET can refuse it; entry 2 is then an ordinary contained
    // name that the OS would resolve THROUGH the link. The link points at
    // this test's own directory (outside the destination) so the escape has
    // a checkable artifact rather than needing to inspect /etc.
    let dir = tmp_dir();
    let dest = dir.join("out");
    let evil = write_raw_tar(
        &dir.join("through.tar"),
        &[
            Raw::Symlink("evil", dir.to_str().unwrap()),
            Raw::File("evil/pwned.txt", b"pwned"),
        ],
    );

    let out = run_output(&[
        "unpack",
        evil.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(7),
        "an absolute symlink target must be refused (exit 7), stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !dir.join("pwned.txt").exists(),
        "the second entry was written through the symlink, outside the destination"
    );
    assert!(
        std::fs::symlink_metadata(dest.join("evil")).is_err(),
        "the symlink must not have been created"
    );
}

#[test]
fn a_symlink_chain_cannot_walk_out_of_the_destination() {
    // Neither link's own path escapes, and neither target is absolute: the
    // escape only exists once the two are followed together. `b`'s target is
    // refused on its own terms, which is what keeps the chain from ever
    // being walkable.
    let dir = tmp_dir();
    let dest = dir.join("out");
    let evil = write_raw_tar(
        &dir.join("chain.tar"),
        &[
            Raw::Symlink("a", "b"),
            Raw::Symlink("b", "../.."),
            Raw::File("a/pwned.txt", b"pwned"),
        ],
    );

    let out = run_output(&[
        "unpack",
        evil.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(7),
        "a chained symlink escape must be refused (exit 7), stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !dir.join("pwned.txt").exists() && !dir.parent().unwrap().join("pwned.txt").exists(),
        "the chain wrote outside the destination"
    );
}

#[test]
fn a_traversal_buried_inside_a_deeper_path_is_refused() {
    // `a/b/../../../escaped.txt` nets one level above the destination, but
    // only after two real components have been pushed — the shape a
    // "does the name start with ..?" check would wave straight through.
    let dir = tmp_dir();
    let dest = dir.join("out");
    let evil = write_raw_tar(
        &dir.join("deep.tar"),
        &[Raw::File("a/b/../../../escaped.txt", b"pwned")],
    );

    let out = run_output(&[
        "unpack",
        evil.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(7),
        "a buried traversal must be refused (exit 7), stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !dir.join("escaped.txt").exists(),
        "the buried traversal escaped the destination"
    );
}

#[test]
fn a_directory_entry_that_escapes_the_destination_is_refused() {
    // A directory entry creates a path without writing a byte of payload, so
    // a containment check placed on the file-writing branch alone would miss
    // it entirely.
    let dir = tmp_dir();
    let dest = dir.join("out");
    let evil = write_raw_tar(&dir.join("dir.tar"), &[Raw::Dir("../escaped-dir/")]);

    let out = run_output(&[
        "unpack",
        evil.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(7),
        "an escaping directory entry must be refused (exit 7), stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !dir.join("escaped-dir").exists(),
        "the directory escaped the destination"
    );
}

// --- Legitimate archives must still extract ------------------------------

#[test]
fn an_entry_named_dot_extracts_alongside_the_real_entries() {
    // `.` names the destination itself and is accepted, not refused: this is
    // the first entry `tar cf x.tar .` emits, and refusing it would turn a
    // security refusal loose on the most common tarball there is.
    let dir = tmp_dir();
    let dest = dir.join("out");
    let archive = write_raw_tar(
        &dir.join("dot.tar"),
        &[Raw::Dir("./"), Raw::File("./a.txt", b"alpha")],
    );

    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "a `./` entry must be accepted, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"alpha");
}

/// The `tar cf x.tar .` idiom, built by the SYSTEM tar rather than by the
/// `tar` crate, extracted with stuffr and compared byte for byte. Three
/// safety checks in this phase have each threatened to fire on benign input;
/// this is the one that proves the containment check does not.
#[test]
fn a_system_tar_of_dot_extracts_cleanly() {
    let Some(tar_bin) = which_tar() else {
        eprintln!("system tar not found; skipping");
        return;
    };
    let dir = tmp_dir();
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("nested")).unwrap();
    std::fs::write(src.join("top.txt"), b"top level").unwrap();
    std::fs::write(src.join("nested/deep.txt"), b"nested payload").unwrap();

    let archive = dir.join("dot.tar");
    let status = Command::new(&tar_bin)
        .arg("cf")
        .arg(&archive)
        .arg(".")
        .current_dir(&src)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "the system tar failed to build the fixture"
    );

    let dest = dir.join("out");
    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "`tar cf x.tar .` must extract cleanly, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(dest.join("top.txt")).unwrap(), b"top level");
    assert_eq!(
        std::fs::read(dest.join("nested/deep.txt")).unwrap(),
        b"nested payload"
    );
}

/// 0.8.1 Task 2 fix round, I1: a pax `x` header past `tar.rs`'s
/// `MAX_PAX_EXTENSION` (16 MiB) is refused at exit 6 — with every byte of
/// its 17 MiB payload present, and equally when it declares 4 GiB and
/// delivers 1 KiB. Exit 6 in both, because the ceiling is checked against
/// the DECLARED size before a payload byte is read (`Error::exit_code`'s
/// "refused before an allocator was asked"), so how much is present never
/// enters into it.
#[test]
fn a_tar_pax_header_past_the_ceiling_exits_6() {
    let dir = tmp_dir();
    let mut builder = Builder::new(Vec::new());
    let comment = vec![b'c'; 17 << 20];
    builder
        .append_pax_extensions([("comment", &comment[..])])
        .unwrap();
    let mut header = Header::new_ustar();
    header.set_path("after.txt").unwrap();
    header.set_mode(0o644);
    header.set_size(5);
    header.set_cksum();
    builder.append(&header, &b"hello"[..]).unwrap();
    let big = builder.into_inner().unwrap();
    assert!(big.len() > 17 << 20, "the payload is really there");
    let big_path = dir.join("big-pax.tar");
    std::fs::write(&big_path, &big).unwrap();

    let mut header = Header::new_ustar();
    header.set_path("PaxHeaders/big").unwrap();
    header.set_entry_type(tar::EntryType::XHeader);
    header.set_size(4 << 30);
    header.set_cksum();
    let mut short = header.as_bytes().to_vec();
    short.extend_from_slice(&[b'c'; 1024]);
    let short_path = dir.join("short-pax.tar");
    std::fs::write(&short_path, &short).unwrap();

    for path in [&big_path, &short_path] {
        let out = run_output(&["list", path.to_str().unwrap()]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(6), "{path:?}: {stderr}");
        assert!(stderr.contains("pax extended header"), "{path:?}: {stderr}");
    }
    // A pipe, written from a thread: stuffr refuses on the header and exits
    // without draining the 17 MiB behind it, so the writer meets a broken
    // pipe — which is the point, not a failure.
    let mut child = Command::new(STUFFR)
        .args(["list", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&big);
    });
    let out = child.wait_with_output().unwrap();
    writer.join().unwrap();
    assert_eq!(
        out.status.code(),
        Some(6),
        "a pipe: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The ceiling's healthy side: GNU tar's own `--format=pax` archive of a
/// file whose path is 300 bytes — past ustar's 255, so carried in a pax
/// `path` record — lists normally under its full name.
#[test]
fn a_gnu_tar_pax_archive_with_a_300_byte_path_lists_normally() {
    let dir = tmp_dir();
    let src = dir.join("src");
    let rel = format!("{}/{}", "d".repeat(200), "f".repeat(99));
    assert_eq!(rel.len(), 300);
    std::fs::create_dir_all(src.join("d".repeat(200))).unwrap();
    std::fs::write(src.join(&rel), b"long path").unwrap();
    let archive = dir.join("pax.tar");
    run_tool(
        &require_gnu_tar(),
        &[os(&"--format=pax"), os(&"-cf"), os(&archive), os(&rel)],
        &src,
        b"",
    );
    let bytes = std::fs::read(&archive).unwrap();
    assert!(
        Header::from_byte_slice(&bytes[..512])
            .entry_type()
            .is_pax_local_extensions(),
        "GNU tar carried the path in a pax `x` header"
    );
    let out = run_output(&["list", archive.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains(&rel), "{stdout}");
}

// Symlink creation is unix-only, the way `ops_compress.rs` gates its own
// symlink tests.
#[cfg(unix)]
#[test]
fn extraction_writes_files_directories_and_contained_symlinks() {
    let dir = tmp_dir();
    let dest = dir.join("out");
    let archive = write_raw_tar(
        &dir.join("good.tar"),
        &[
            Raw::Dir("sub/"),
            Raw::File("sub/a.txt", b"alpha"),
            Raw::Symlink("sub/link", "a.txt"),
        ],
    );

    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dest.join("sub").is_dir());
    assert_eq!(std::fs::read(dest.join("sub/a.txt")).unwrap(), b"alpha");
    let link = std::fs::symlink_metadata(dest.join("sub/link")).unwrap();
    assert!(
        link.file_type().is_symlink(),
        "a symlink entry must become a symlink"
    );
    assert_eq!(
        std::fs::read_link(dest.join("sub/link")).unwrap(),
        Path::new("a.txt")
    );
    // Following it stays inside the destination, which is why it was allowed.
    assert_eq!(std::fs::read(dest.join("sub/link")).unwrap(), b"alpha");
}

#[test]
fn extraction_selects_only_the_entries_a_pattern_names() {
    let dir = tmp_dir();
    let dest = dir.join("out");
    let archive = write_fixture_tar(
        &dir,
        &[
            ("a.txt", b"alpha"),
            ("b.txt", b"beta"),
            ("d/c.txt", b"gamma"),
        ],
    );

    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
        "b.txt",
        "d",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !dest.join("a.txt").exists(),
        "an unmatched entry was extracted"
    );
    assert_eq!(std::fs::read(dest.join("b.txt")).unwrap(), b"beta");
    // A pattern naming a directory selects everything beneath it.
    assert_eq!(std::fs::read(dest.join("d/c.txt")).unwrap(), b"gamma");
}

#[test]
fn a_pattern_matching_no_entry_is_a_usage_error_rather_than_a_silent_success() {
    let dir = tmp_dir();
    let archive = write_fixture_tar(&dir, &[("a.txt", b"alpha")]);
    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dir.join("out").to_str().unwrap(),
        "nosuch.txt",
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "extracting nothing at all must not report success, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = run_output(&["cat", archive.to_str().unwrap(), "nosuch.txt"]);
    assert_eq!(out.status.code(), Some(2), "cat must agree with unpack");
}

#[test]
fn extraction_refuses_an_existing_file_unless_force_is_given() {
    let dir = tmp_dir();
    let dest = dir.join("out");
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::write(dest.join("a.txt"), b"mine").unwrap();
    let archive = write_fixture_tar(&dir, &[("a.txt", b"alpha")]);

    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "an existing file must be refused like every other output, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"mine");

    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
        "--force",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"alpha");
}

// Symlink creation is unix-only, the way `ops_compress.rs` gates its own
// symlink tests.
#[cfg(unix)]
#[test]
fn a_pre_existing_symlink_at_a_target_path_is_replaced_not_written_through() {
    // `File::create` follows a symlink. Somebody who can plant
    // `dest/a.txt -> outside` before extraction would otherwise redirect the
    // entry's bytes there; --force removes what is in the way rather than
    // writing through it.
    let dir = tmp_dir();
    let dest = dir.join("out");
    std::fs::create_dir_all(&dest).unwrap();
    let outside = dir.join("outside.txt");
    std::fs::write(&outside, b"untouched").unwrap();
    std::os::unix::fs::symlink(&outside, dest.join("a.txt")).unwrap();
    let archive = write_fixture_tar(&dir, &[("a.txt", b"alpha")]);

    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
        "--force",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(&outside).unwrap(),
        b"untouched",
        "the entry was written through the pre-existing symlink"
    );
    assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"alpha");
}

#[test]
fn extraction_of_a_corrupt_archive_exits_five_not_seven() {
    // Corrupt, hostile and oversized must stay three distinguishable
    // answers: a script branches on which one it got.
    let dir = tmp_dir();
    let good = write_fixture_tar(&dir, &[("a.txt", b"alpha"), ("b.txt", b"beta")]);
    let corrupt = corrupt_midway(&good);
    let out = run_output(&[
        "unpack",
        corrupt.to_str().unwrap(),
        "-C",
        dir.join("out").to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(5),
        "a corrupt archive is exit 5, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn extraction_of_a_bomb_exits_six_at_a_tight_max_ratio() {
    let dir = tmp_dir();
    let bomb = write_bomb_tar_gz(&dir);
    let out = run_output(&[
        "unpack",
        bomb.to_str().unwrap(),
        "-C",
        dir.join("out").to_str().unwrap(),
        "--max-ratio",
        "2",
    ]);
    assert_eq!(
        out.status.code(),
        Some(6),
        "a bomb is a resource limit (exit 6), stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cat_streams_every_entry_a_pattern_names_and_bounds_the_ratio() {
    let dir = tmp_dir();
    let archive = write_fixture_tar(&dir, &[("a.txt", b"alpha"), ("b.txt", b"beta")]);
    let out = run_output(&["cat", archive.to_str().unwrap(), "a.txt"]);
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "alpha");

    let bomb = write_bomb_tar_gz(&dir);
    let out = run_output(&[
        "cat",
        bomb.to_str().unwrap(),
        "bomb.bin",
        "--max-ratio",
        "2",
    ]);
    assert_eq!(
        out.status.code(),
        Some(6),
        "cat must bound an entry the same way extraction does, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn an_archive_needs_a_destination_and_the_error_says_which_flag() {
    // `unpack backup.tar` with no -C used to reach the single-stream decoder
    // and report "containers arrive in Phase 2". It now names the flag that
    // does what the user meant.
    let dir = tmp_dir();
    let archive = write_fixture_tar(&dir, &[("a.txt", b"alpha")]);
    let out = run_output(&["unpack", archive.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("-C") && stderr.contains("tar"),
        "the error must name both the container and the flag, got: {stderr}"
    );
    assert!(
        !dir.join("fixture").exists(),
        "nothing may be written for a refused command"
    );
}

#[test]
fn pack_refuses_several_paths_when_the_output_is_not_a_container() {
    let dir = tmp_dir();
    std::fs::write(dir.join("one.txt"), b"1").unwrap();
    std::fs::write(dir.join("two.txt"), b"2").unwrap();
    let out = run_output(&[
        "pack",
        dir.join("one.txt").to_str().unwrap(),
        dir.join("two.txt").to_str().unwrap(),
        "-o",
        dir.join("bundle.gz").to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "a codec cannot hold two inputs, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !dir.join("bundle.gz").exists(),
        "a refused command must write nothing"
    );
}

#[test]
fn pack_into_a_container_round_trips_through_extraction() {
    let dir = tmp_dir();
    std::fs::write(dir.join("one.txt"), b"first").unwrap();
    std::fs::write(dir.join("two.txt"), b"second").unwrap();
    let archive = dir.join("bundle.tar");
    let out = run_output(&[
        "pack",
        dir.join("one.txt").to_str().unwrap(),
        dir.join("two.txt").to_str().unwrap(),
        "-o",
        archive.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let dest = dir.join("out");
    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(dest.join("one.txt")).unwrap(), b"first");
    assert_eq!(std::fs::read(dest.join("two.txt")).unwrap(), b"second");
}

#[test]
fn pack_refuses_two_inputs_that_would_share_one_entry_name() {
    let dir = tmp_dir();
    std::fs::create_dir_all(dir.join("a")).unwrap();
    std::fs::create_dir_all(dir.join("b")).unwrap();
    std::fs::write(dir.join("a/same.txt"), b"1").unwrap();
    std::fs::write(dir.join("b/same.txt"), b"2").unwrap();
    let archive = dir.join("dup.tar");
    let out = run_output(&[
        "pack",
        dir.join("a/same.txt").to_str().unwrap(),
        dir.join("b/same.txt").to_str().unwrap(),
        "-o",
        archive.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "two entries with one name would make an archive that cannot be \
         extracted without --force, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!archive.exists(), "a refused command must write nothing");
}

/// Was `pack_of_a_directory_says_so_rather_than_writing_an_empty_archive`,
/// which asserted exit 2 on a directory. Phase 2c walks it instead, so the
/// property worth keeping is the one the old name was really about: a
/// directory must not silently produce an archive with nothing in it. An
/// EMPTY directory is still one real entry.
#[test]
fn pack_of_an_empty_directory_stores_the_directory_itself() {
    let dir = tmp_dir();
    std::fs::create_dir_all(dir.join("tree")).unwrap();
    let archive = dir.join("tree.tar");
    let out = run_output(&[
        "pack",
        dir.join("tree").to_str().unwrap(),
        "-o",
        archive.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let listed = run_output(&["list", archive.to_str().unwrap()]);
    let text = String::from_utf8_lossy(&listed.stdout);
    assert!(
        text.contains("tree"),
        "the directory itself must be an entry, not an empty archive: {text}"
    );
}

#[test]
fn flags_that_the_container_path_cannot_honour_are_refused_not_ignored() {
    // The tree's rule (see `threads_is_not_offered_on_decode_subcommands`):
    // a flag that would be silently ignored is refused instead.
    //
    // `--memory-limit` used to be in this list and no longer is: the Phase 2
    // final review's C1 threaded it through container resolution, so it is
    // now honoured rather than refused — see
    // `memory_limit_is_honoured_rather_than_refused_on_the_container_path`.
    let dir = tmp_dir();
    let archive = write_fixture_tar(&dir, &[("a.txt", b"alpha")]);
    let dest = dir.join("out");
    for extra in [vec!["--format", "gzip"], vec!["-o", "somewhere"]] {
        let mut args = vec![
            "unpack",
            archive.to_str().unwrap(),
            "-C",
            dest.to_str().unwrap(),
        ];
        args.extend_from_slice(&extra);
        let out = run_output(&args);
        assert_eq!(
            out.status.code(),
            Some(2),
            "`{}` must be refused alongside -C, stderr: {}",
            extra.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// The same rule, applied to the PACK side, which had it backwards.
///
/// `entries::create_archive` builds `CreateOpts { level, ..Default::default() }`
/// — it hands the container no governor, no worker count and no weak-encoder
/// consent, because none of the four registered containers compresses
/// anything itself. So `--threads`, `--turbo` and `--allow-weak-encoder`
/// were accepted and silently dropped: precisely what the extract side above
/// refuses. Consistency, not new capability.
#[test]
fn pack_flags_the_container_path_cannot_honour_are_refused_not_ignored() {
    let dir = tmp_dir();
    let src = dir.join("a.txt");
    std::fs::write(&src, b"alpha").unwrap();
    let archive = dir.join("bundle.tar");
    for extra in [
        vec!["--threads", "4"],
        vec!["--turbo"],
        vec!["--allow-weak-encoder"],
    ] {
        let mut args = vec![
            "pack",
            src.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
        ];
        args.extend_from_slice(&extra);
        let out = run_output(&args);
        assert_eq!(
            out.status.code(),
            Some(2),
            "`{}` must be refused on the container pack path, stderr: {}",
            extra.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !archive.exists(),
            "a refused command must write nothing: {}",
            extra.join(" ")
        );
    }

    // The same flags stay ACCEPTED on the single-stream codec path, which
    // genuinely honours them — the refusal above must not have leaked.
    let out = run_output(&[
        "pack",
        src.to_str().unwrap(),
        "--format",
        "gzip",
        "--threads",
        "2",
        "--force",
    ]);
    assert!(
        out.status.success(),
        "the codec path still honours --threads, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The gap the two lexical checks cannot see on their own, demonstrated
/// outside stuffr first (a shell reproduction is in the task report): every
/// step below is contained COMPONENT-WISE from the destination, and the OS
/// still resolves the last one outside it.
///
/// * `a/b/up -> ..` is contained: it resolves to `<dest>/a`.
/// * `a/b/up/link -> ../..` resolves, component-wise from `<dest>`, to `a`
///   — inside. Resolved by the OS through `up`, whose real parent is
///   `<dest>/a`, it lands on `<dest>/..`: the directory holding `<dest>`.
/// * `a/b/up/link/pwned.txt` is then an ordinary contained name written
///   straight through it.
///
/// So an entry whose PATH COMPONENTS include an existing symlink is refused
/// outright — the same defence libarchive's SECURE_SYMLINKS provides, and it
/// closes the pre-existing-hostile-symlink case in the destination too.
#[cfg(unix)]
#[test]
fn an_entry_written_through_a_symlinked_path_component_is_refused() {
    let dir = tmp_dir();
    let dest = dir.join("out");
    let evil = write_raw_tar(
        &dir.join("component.tar"),
        &[
            Raw::Dir("a/b/"),
            Raw::Symlink("a/b/up", ".."),
            Raw::Symlink("a/b/up/link", "../.."),
            Raw::File("a/b/up/link/pwned.txt", b"pwned"),
        ],
    );

    let out = run_output(&[
        "unpack",
        evil.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(7),
        "an entry resolving through a symlinked component must be refused (exit 7), \
         stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !dir.join("pwned.txt").exists(),
        "the entry escaped the destination through a symlinked path component"
    );
}

/// Security audit EXTRACT-8: `unpack --force` of an archive holding an
/// entry with the archive's own name, into the archive's own directory,
/// used to unlink the archive to make room. The entry is refused now and
/// the archive is left intact. The refusal is a fidelity warning like every
/// other entry `unpack` skips: exit 0, and 4 under `--strict-fidelity`.
#[test]
fn unpack_force_never_replaces_the_archive_it_is_reading() {
    let dir = tmp_dir();
    let work = dir.join("w");
    std::fs::create_dir_all(&work).unwrap();
    let archive = work.join("self.zip");
    let bytes = stored_zip_of(&[("self.zip", b"gone"), ("later.txt", b"later")]);
    std::fs::write(&archive, &bytes).unwrap();

    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        work.to_str().unwrap(),
        "--force",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(
        std::fs::read(&archive).unwrap(),
        bytes,
        "the archive must survive"
    );
    assert!(
        stderr.contains("self.zip") && stderr.contains("archive being read"),
        "the skip must name the entry and why: {stderr}"
    );
    assert_eq!(std::fs::read(work.join("later.txt")).unwrap(), b"later");

    let strict = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        work.to_str().unwrap(),
        "--force",
        "--strict-fidelity",
    ]);
    assert_eq!(
        strict.status.code(),
        Some(4),
        "stderr: {}",
        String::from_utf8_lossy(&strict.stderr)
    );
    assert_eq!(std::fs::read(&archive).unwrap(), bytes);
}
