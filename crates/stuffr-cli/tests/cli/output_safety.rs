use crate::common::*;
use std::process::Command;

// ---------------------------------------------------------------------
// Bug hunt 2026-11-15: native output safety. An output name that is (or
// leads to) the file being read, and a `-C` naming a non-directory.
// ---------------------------------------------------------------------

#[cfg(unix)]
fn assert_same_file_refusal(out: &std::process::Output) {
    assert_eq!(out.status.code(), Some(2), "{}", stderr_text(out));
    assert!(
        stderr_text(out).contains("are the same file"),
        "{}",
        stderr_text(out)
    );
}

/// Findings 5 and 11: `pack --force IN -o LINK` with `LINK -> IN` truncated
/// the input through the link before reading it (exit 0, input gone).
#[cfg(unix)]
#[test]
fn pack_refuses_an_output_that_is_a_symlink_to_its_input() {
    let dir = tmp_dir();
    let a = dir.join("a");
    let data: Vec<u8> = (0..5000u32).map(|i| b"abcdefgh\n"[(i % 9) as usize]).collect();
    std::fs::write(&a, &data).unwrap();
    let link = dir.join("link.gz");
    std::os::unix::fs::symlink("a", &link).unwrap();
    let out = run_output(&[
        "pack",
        "--force",
        a.to_str().unwrap(),
        "-o",
        link.to_str().unwrap(),
    ]);
    assert_same_file_refusal(&out);
    assert_eq!(std::fs::read(&a).unwrap(), data, "the input was touched");

    // The derived name too: `pack --force --format xz a` with `a.xz -> a`.
    let xz = dir.join("a.xz");
    std::os::unix::fs::symlink("a", &xz).unwrap();
    let out = run_output(&["pack", "--force", "--format", "xz", a.to_str().unwrap()]);
    assert_same_file_refusal(&out);
    assert_eq!(std::fs::read(&a).unwrap(), data, "the input was touched");
}

/// The stdin spelling of the same: `pack --force - -o l.gz < a`, `l.gz -> a`.
#[cfg(unix)]
#[test]
fn pack_refuses_stdin_redirected_from_its_own_output() {
    let dir = tmp_dir();
    let a = dir.join("a");
    let data = b"the input must survive\n".repeat(200);
    std::fs::write(&a, &data).unwrap();
    let link = dir.join("l.gz");
    std::os::unix::fs::symlink("a", &link).unwrap();
    let out = Command::new(STUFFR)
        .args(["pack", "--force", "-", "-o", link.to_str().unwrap()])
        .stdin(std::fs::File::open(&a).unwrap())
        .output()
        .unwrap();
    assert_same_file_refusal(&out);
    assert_eq!(std::fs::read(&a).unwrap(), data, "the input was touched");
}

/// Findings 5 and 11, unpack: the decoder fed on its own output through the
/// link (an unbounded disk fill for a large input). Small inputs only here.
#[cfg(unix)]
#[test]
fn unpack_refuses_an_output_that_is_a_symlink_to_its_input() {
    let dir = tmp_dir();
    let plain = dir.join("p");
    std::fs::write(&plain, b"some text to compress\n".repeat(40)).unwrap();
    let gz = dir.join("in.gz");
    assert!(run(&["pack", plain.to_str().unwrap(), "-o", gz.to_str().unwrap()]).success());
    let before = std::fs::read(&gz).unwrap();

    // Explicit -o.
    let out_link = dir.join("out");
    std::os::unix::fs::symlink("in.gz", &out_link).unwrap();
    let out = run_output(&[
        "unpack",
        gz.to_str().unwrap(),
        "-o",
        out_link.to_str().unwrap(),
        "--force",
    ]);
    assert_same_file_refusal(&out);
    assert_eq!(std::fs::read(&gz).unwrap(), before, "the input was touched");

    // The derived name: `unpack --force in.gz` with `in -> in.gz`.
    let derived = dir.join("in");
    std::os::unix::fs::symlink("in.gz", &derived).unwrap();
    let out = run_output(&["unpack", "--force", gz.to_str().unwrap()]);
    assert_same_file_refusal(&out);
    assert_eq!(std::fs::read(&gz).unwrap(), before, "the input was touched");
}

/// A hard link is the same file too (as for convert), and so is the input
/// named as its own output.
#[cfg(unix)]
#[test]
fn pack_refuses_a_hard_link_or_the_input_itself_as_output() {
    let dir = tmp_dir();
    let a = dir.join("a");
    let data = b"payload\n".repeat(100);
    std::fs::write(&a, &data).unwrap();
    let hard = dir.join("h.gz");
    std::fs::hard_link(&a, &hard).unwrap();
    for target in [&hard, &a] {
        let out = run_output(&[
            "pack",
            "--force",
            "--format",
            "gzip",
            a.to_str().unwrap(),
            "-o",
            target.to_str().unwrap(),
        ]);
        assert_same_file_refusal(&out);
        assert_eq!(std::fs::read(&a).unwrap(), data, "the input was touched");
    }
}

/// Other non-regular destinations keep working: a device is written through.
#[cfg(unix)]
#[test]
fn pack_and_unpack_still_write_through_to_a_device() {
    let dir = tmp_dir();
    let a = dir.join("a");
    std::fs::write(&a, b"payload\n".repeat(100)).unwrap();
    let out = run_output(&[
        "pack",
        "--force",
        "--format",
        "gzip",
        a.to_str().unwrap(),
        "-o",
        "/dev/null",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    let gz = dir.join("a.gz");
    assert!(run(&["pack", a.to_str().unwrap(), "-o", gz.to_str().unwrap()]).success());
    let out = run_output(&["unpack", "--force", gz.to_str().unwrap(), "-o", "/dev/null"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    // And a symlink to an unrelated file is still written through.
    let target = dir.join("elsewhere");
    std::fs::write(&target, b"old").unwrap();
    let link = dir.join("latest");
    std::os::unix::fs::symlink("elsewhere", &link).unwrap();
    let out = run_output(&[
        "unpack",
        "--force",
        gz.to_str().unwrap(),
        "-o",
        link.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
    assert_eq!(std::fs::read(&target).unwrap(), b"payload\n".repeat(100));
}

/// Findings 6 and 12: a container output that is a symlink to a file inside
/// the tree being packed overwrote that file with the archive and stored the
/// archive's own head as its entry, at exit 0.
#[cfg(unix)]
#[test]
fn container_pack_refuses_an_output_symlinked_to_a_walked_file() {
    let dir = tmp_dir();
    let tree = dir.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    let notes = tree.join("notes.txt");
    std::fs::write(&notes, b"important-data-1234567890\n").unwrap();
    std::fs::write(tree.join("o.txt"), b"other\n").unwrap();
    for name in ["latest.tar", "latest.tar.gz"] {
        let link = dir.join(name);
        std::os::unix::fs::symlink("tree/notes.txt", &link).unwrap();
        let out = run_output(&[
            "pack",
            tree.to_str().unwrap(),
            "-o",
            link.to_str().unwrap(),
            "--force",
        ]);
        assert_same_file_refusal(&out);
        assert_eq!(
            std::fs::read(&notes).unwrap(),
            b"important-data-1234567890\n",
            "{name}: the walked file was touched"
        );
    }
}

/// A container output symlinked to a file OUTSIDE the walk is still written
/// through, and a regular output inside the tree is still excluded with a
/// note (both unchanged).
#[cfg(unix)]
#[test]
fn container_pack_still_writes_through_an_unrelated_symlink() {
    let dir = tmp_dir();
    let tree = dir.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a.txt"), b"a\n").unwrap();
    let target = dir.join("archives.tar");
    std::fs::write(&target, b"old").unwrap();
    let link = dir.join("latest.tar");
    std::os::unix::fs::symlink("archives.tar", &link).unwrap();
    let out = run_output(&[
        "pack",
        tree.to_str().unwrap(),
        "-o",
        link.to_str().unwrap(),
        "--force",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
    assert!(std::fs::metadata(&target).unwrap().len() > 3);
}
