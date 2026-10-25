use crate::common::*;
use std::process::Command;

// ---------------------------------------------------------------------
// Phase 2c final review: the four findings whose reproduction is a CLI
// invocation, and the summary line that reports them.
// ---------------------------------------------------------------------

/// Finding 3. `pack . -o backup.tar` excludes the archive from its own walk,
/// which is stuffr being correct — and Phase 2c recorded it as a fidelity
/// warning, so `--strict-fidelity` exited 0 on the first run and **4 on every
/// run after**, forever, on an archive that had lost nothing the user wanted.
/// That is the flagship nightly-backup shape `examples.txt` advertises.
#[test]
fn excluding_the_output_from_its_own_walk_is_a_note_not_a_fidelity_loss() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("a.txt"), b"payload\n").unwrap();
    let out = root.join("backup.tar");

    // Three runs, because the defect only appears from the SECOND: on the
    // first there is no `backup.tar` on disk for the walk to find.
    for run in 1..=3 {
        let st = Command::new(STUFFR)
            .args([
                "pack",
                root.to_str().unwrap(),
                "-o",
                out.to_str().unwrap(),
                "--force",
                "--strict-fidelity",
            ])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&st.stderr).to_string();
        assert_eq!(
            st.status.code(),
            Some(0),
            "run {run}: declining to store the archive inside itself is not a \
             fidelity loss, so the strict gate must stay green; stderr: {stderr}"
        );
        // Still SAID, every run — routing it off the gate must not silence
        // it. Without this half the test passes against an implementation
        // that simply drops the file without a word.
        if run > 1 {
            assert!(
                stderr.contains("proj/backup.tar"),
                "run {run}: the user must still be told, by name: {stderr}"
            );
        }
        // And the summary line must not claim a loss it is not reporting.
        assert!(
            stderr.contains("no fidelity loss"),
            "run {run}: the count in the summary must agree with the (empty) \
             warning list: {stderr}"
        );
    }

    // The archive is real and does not nest a copy of itself.
    let listed = run_output(&["list", out.to_str().unwrap()]);
    let text = String::from_utf8_lossy(&listed.stdout);
    assert!(text.contains("proj/a.txt"), "{text}");
    assert!(
        !text.contains("backup.tar"),
        "the archive must not be inside itself: {text}"
    );
}

/// Finding 4. `compound_alias` stripped the `t` and looked up `bz`, which
/// bzip2 does not register (it registers `bz2`), so the whole name resolved
/// to `Chain::Raw` — which on the write side is not a refusal but a silent
/// fall back to `default_format()`. `-o f.tbz` wrote a **gzip stream with no
/// tar inside it, at exit 0**: a name promising one thing, bytes that are
/// another, reported as success.
#[test]
fn a_tbz_output_writes_tar_inside_bzip2_and_not_a_bare_gzip() {
    let dir = tmp_dir();
    let src = dir.join("notes.txt");
    std::fs::write(&src, b"payload\n").unwrap();

    let out = dir.join("f.tbz");
    let st = Command::new(STUFFR)
        .args(["pack", src.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );

    // The BYTES, not the exit code: exit 0 is exactly what the defect gave.
    let bytes = std::fs::read(&out).unwrap();
    assert_eq!(
        &bytes[..3],
        b"BZh",
        "a .tbz must be bzip2 — it was gzip (1f 8b) before this: {:02x?}",
        &bytes[..4.min(bytes.len())]
    );
    // And a tar really is inside it, which the gzip it used to write had no
    // room for at all.
    let listed = run_output(&["list", out.to_str().unwrap()]);
    assert!(
        listed.status.success(),
        "a .tbz must open as an archive: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    assert!(
        String::from_utf8_lossy(&listed.stdout).contains("notes.txt"),
        "the tar layer must be there: {}",
        String::from_utf8_lossy(&listed.stdout)
    );

    // `.tbz2` was never broken and must stay unbroken: stripping its `t`
    // already yields bzip2's own registered `bz2`.
    let out2 = dir.join("f.tbz2");
    assert!(
        Command::new(STUFFR)
            .args(["pack", src.to_str().unwrap(), "-o", out2.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(&std::fs::read(&out2).unwrap()[..3], b"BZh");

    // The fix is in the compound alias, NOT the registry: `.bz` is bzip1, a
    // different and obsolete format, and must not have become writable as
    // bzip2 on the way past.
    let out3 = dir.join("f.bz");
    assert!(
        Command::new(STUFFR)
            .args(["pack", src.to_str().unwrap(), "-o", out3.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    assert_ne!(
        &std::fs::read(&out3).unwrap()[..3],
        b"BZh",
        "`bz` must not resolve to bzip2 outside the `t`-prefixed compound form"
    );
}

/// Finding 5. Phase 2c made a directory a legitimate input on the container
/// path and left it landing on `Error::exit_code`'s `_ => 1` wildcard on the
/// other: `File::open` on a directory succeeds on unix and fails at the first
/// `read`, so `pack proj -o proj.gz` reported `i/o error: Is a directory
/// (os error 21)` at exit 1 — as if stuffr had failed.
#[test]
fn a_directory_on_the_single_stream_path_is_a_usage_error_naming_the_fix() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("a.txt"), b"payload\n").unwrap();

    let out = dir.join("proj.gz");
    let st = Command::new(STUFFR)
        .args(["pack", root.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&st.stderr).to_string();
    assert_eq!(
        st.status.code(),
        Some(2),
        "asking a codec for a tree is the caller's mistake, not an i/o \
         failure; stderr: {stderr}"
    );
    assert!(
        !stderr.contains("os error 21"),
        "the raw EISDIR must not reach the user: {stderr}"
    );
    // Naming the fix is the point of the finding — an exit code alone leaves
    // the reader no better off than the wildcard did.
    assert!(
        stderr.contains("proj.tar.gz"),
        "the message must name the output that works: {stderr}"
    );
    assert!(
        !out.exists(),
        "the refusal happens before the destination is touched"
    );

    // And the output it names really does work.
    let good = dir.join("proj.tar.gz");
    assert!(
        Command::new(STUFFR)
            .args(["pack", root.to_str().unwrap(), "-o", good.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
}

/// Minor 1. The pack summary printed `out.fidelity.rung`, which
/// `create_archive` hardcodes to `Rung::Exact` — so `pack proj -o out.ar`
/// announced "exact fidelity" and then named four losses on the next four
/// lines. The number printed must be one the following lines agree with.
#[test]
fn the_pack_summary_counts_losses_rather_than_claiming_exact_fidelity() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("sub").join("a.txt"), b"payload\n").unwrap();

    // `ar` stores neither directories nor symlinks, so a walked tree loses
    // its directory entries there and nowhere else.
    let out = dir.join("p.a");
    let st = Command::new(STUFFR)
        .args(["pack", root.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    let stderr = String::from_utf8_lossy(&st.stderr).to_string();

    assert!(
        !stderr.contains("exact fidelity"),
        "a pack that lost entries must not announce exact fidelity: {stderr}"
    );
    // The two numbers must be the SAME number, read out of the two lines
    // that print it. An assertion on either alone passes against a summary
    // that prints a constant.
    let reported: usize = stderr
        .lines()
        .find_map(|l| l.split_once(" fidelity loss(es)"))
        .and_then(|(head, _)| head.rsplit(", ").next())
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or_else(|| panic!("the summary must carry a loss count: {stderr}"));
    let listed: usize = stderr
        .lines()
        .find_map(|l| l.strip_prefix("stuffr: "))
        .and_then(|l| l.split_once(" fidelity warning(s):"))
        .and_then(|(n, _)| n.parse().ok())
        .unwrap_or_else(|| panic!("the warning header must carry a count: {stderr}"));
    assert_eq!(
        reported, listed,
        "the summary's count and the warning list's count are the same fact: {stderr}"
    );
    assert!(
        reported > 0,
        "packing a tree into `ar` really does lose the \
                          directory entries: {stderr}"
    );

    // And a pack that loses nothing says so, rather than saying "0".
    let clean = dir.join("p.tar");
    let st = Command::new(STUFFR)
        .args([
            "pack",
            root.to_str().unwrap(),
            "-o",
            clean.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&st.stderr).to_string();
    assert!(
        stderr.contains("no fidelity loss"),
        "a lossless pack must say so: {stderr}"
    );
}
