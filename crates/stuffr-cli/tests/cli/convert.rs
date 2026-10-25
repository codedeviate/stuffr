use crate::common::*;

use std::path::PathBuf;
use std::process::Command;

// ---------------------------------------------------------------------------
// `stuffr convert` (Phase 5a): codec mode here; entry mode (a container
// change) further down.
// ---------------------------------------------------------------------------

#[test]
fn convert_recompresses_a_tar_gz_to_tar_zst() {
    let (dir, a) = convert_fixture();
    let b = dir.join("b.tar.zst");
    // The default (pure) build's zstd encoder is the weak fallback, which
    // needs consent; on a c-backed build the flag is accepted and unused.
    let out = run_output(&[
        "convert",
        a.to_str().unwrap(),
        "-o",
        b.to_str().unwrap(),
        "--allow-weak-encoder",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    // The progress line names the TARGET chain, never `Outcome.format`.
    assert!(
        stderr_text(&out).contains("-> tar over zstd ("),
        "{}",
        stderr_text(&out)
    );
    assert_unpacks_to_the_fixture(&dir, &b, "out");
}

#[test]
fn convert_accepts_the_destination_as_a_second_positional() {
    let (dir, a) = convert_fixture();
    let b = dir.join("b.tar.xz");
    let out = run_output(&["convert", a.to_str().unwrap(), b.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    assert_unpacks_to_the_fixture(&dir, &b, "out");
}

#[test]
fn convert_refuses_both_destination_forms_at_once() {
    let (dir, a) = convert_fixture();
    let b = dir.join("b.tar.xz");
    let c = dir.join("c.tar.xz");
    let out = run_output(&[
        "convert",
        a.to_str().unwrap(),
        b.to_str().unwrap(),
        "-o",
        c.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr_text(&out));
    assert!(!b.exists() && !c.exists());
    // Neither form at all is the same mistake from the other side.
    let out = run_output(&["convert", a.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr_text(&out));
}

#[test]
fn convert_refuses_a_plain_stream_into_a_container() {
    let dir = tmp_dir();
    let x = dir.join("x");
    std::fs::write(&x, b"just bytes\n".repeat(20)).unwrap();
    let gz = dir.join("x.gz");
    assert!(run(&["pack", x.to_str().unwrap(), "-o", gz.to_str().unwrap()]).success());
    let zip = dir.join("x.zip");
    let out = run_output(&["convert", gz.to_str().unwrap(), "-o", zip.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr_text(&out));
    let err = stderr_text(&out);
    assert!(
        err.contains("is gzip") && err.contains("would be zip"),
        "both chains must be named: {err}"
    );
    assert!(!zip.exists());
    // And the mirror image: a container into a plain stream.
    let (fdir, a) = convert_fixture();
    let plain = fdir.join("a.gz");
    let out = run_output(&[
        "convert",
        a.to_str().unwrap(),
        "-o",
        plain.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr_text(&out));
    let err = stderr_text(&out);
    assert!(
        err.contains("is tar over gzip") && err.contains("would be gzip"),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn convert_refuses_nothing_to_convert() {
    let (dir, a) = convert_fixture();
    let b = dir.join("b.tar.gz");
    let out = run_output(&["convert", a.to_str().unwrap(), "-o", b.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr_text(&out));
    assert!(
        stderr_text(&out).contains("nothing to convert"),
        "{}",
        stderr_text(&out)
    );
    assert!(!b.exists());
    // A re-encode flag makes the identical chain a real conversion.
    let out = run_output(&[
        "convert",
        a.to_str().unwrap(),
        "-o",
        b.to_str().unwrap(),
        "--level",
        "9",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    assert_unpacks_to_the_fixture(&dir, &b, "out");
}

#[cfg(unix)]
#[test]
fn convert_refuses_overwriting_its_own_input() {
    let (dir, a) = convert_fixture();
    let before = std::fs::read(&a).unwrap();
    let a_str = a.to_str().unwrap();
    // `--level 9` so an identical chain is not refused as "nothing to
    // convert" first: the refusal under test must be the same-file one.
    let check = |out: std::process::Output| {
        assert_eq!(out.status.code(), Some(2), "{}", stderr_text(&out));
        assert!(
            stderr_text(&out).contains("same file"),
            "{}",
            stderr_text(&out)
        );
        assert_eq!(std::fs::read(&a).unwrap(), before, "the input was touched");
    };
    check(run_output(&[
        "convert", a_str, a_str, "--force", "--level", "9",
    ]));

    let link = dir.join("l.tar.gz");
    std::os::unix::fs::symlink(&a, &link).unwrap();
    check(run_output(&[
        "convert",
        a_str,
        link.to_str().unwrap(),
        "--force",
        "--level",
        "9",
    ]));

    check(
        Command::new(STUFFR)
            .current_dir(&dir)
            .args([
                "convert",
                "a.tar.gz",
                "./a.tar.gz",
                "--force",
                "--level",
                "9",
            ])
            .output()
            .unwrap(),
    );

    // A hard link is the same inode under a name nothing canonicalises to.
    let hard = dir.join("h.tar.gz");
    std::fs::hard_link(&a, &hard).unwrap();
    check(run_output(&[
        "convert",
        a_str,
        "-o",
        hard.to_str().unwrap(),
        "--force",
        "--level",
        "9",
    ]));
}

#[test]
fn convert_to_stdout_needs_format() {
    let dir = tmp_dir();
    let payload = b"payload for the pipe\n".repeat(40);
    let x = dir.join("x");
    std::fs::write(&x, &payload).unwrap();
    let gz = dir.join("x.gz");
    assert!(run(&["pack", x.to_str().unwrap(), "-o", gz.to_str().unwrap()]).success());

    let out = run_output(&["convert", gz.to_str().unwrap(), "-o", "-"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr_text(&out));
    assert!(out.stdout.is_empty());

    let out = run_output(&["convert", gz.to_str().unwrap(), "-o", "-", "--format", "xz"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    assert!(out.stdout.starts_with(b"\xfd7zXZ\x00"), "not an xz stream");
    let back = run_with_stdin_output(&["cat", "-"], &out.stdout);
    assert_eq!(back.status.code(), Some(0), "{}", stderr_text(&back));
    assert_eq!(back.stdout, payload);
}

#[test]
fn convert_reads_stdin() {
    let (dir, a) = convert_fixture();
    let b = dir.join("b.tar.xz");
    let out = run_with_stdin_output(
        &["convert", "-", "-o", b.to_str().unwrap()],
        &std::fs::read(&a).unwrap(),
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    assert_unpacks_to_the_fixture(&dir, &b, "out");
}

#[test]
fn convert_refuses_a_format_that_contradicts_the_name() {
    let (dir, a) = convert_fixture();
    let b = dir.join("b.tar.xz");
    let out = run_output(&[
        "convert",
        a.to_str().unwrap(),
        "-o",
        b.to_str().unwrap(),
        "--format",
        "zstd",
    ]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr_text(&out));
    assert!(!b.exists());
    // A container --format against a name saying another container is
    // `pack`'s own refusal, reached through the same resolver.
    let out = run_output(&[
        "convert",
        a.to_str().unwrap(),
        "-o",
        b.to_str().unwrap(),
        "--format",
        "zip",
    ]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr_text(&out));
    // A --format agreeing with the name is no contradiction.
    let out = run_output(&[
        "convert",
        a.to_str().unwrap(),
        "-o",
        b.to_str().unwrap(),
        "--format",
        "xz",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    assert_unpacks_to_the_fixture(&dir, &b, "out");
}

#[test]
fn convert_refuses_encoder_flags_a_codecless_target_cannot_honour() {
    let (dir, a) = convert_fixture();
    let b = dir.join("b.tar");
    for flag in [
        &["--threads", "2"][..],
        &["--turbo"][..],
        &["--allow-weak-encoder"][..],
    ] {
        let mut args = vec!["convert", a.to_str().unwrap(), "-o", b.to_str().unwrap()];
        args.extend_from_slice(flag);
        let out = run_output(&args);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{flag:?}: {}",
            stderr_text(&out)
        );
        let err = stderr_text(&out);
        assert!(err.contains(flag[0]), "{err}");
        // `pack`'s wording is about containers; this target is a bare tar
        // reached by removing a codec, and the message must say so.
        assert!(!err.contains("no container in this build"), "{err}");
        assert!(err.contains("no codec layer"), "{err}");
        assert!(!b.exists());
    }
    // `--level` is accepted and inert there, exactly as `pack -o x.tar
    // --level 9` accepts it.
    let out = run_output(&[
        "convert",
        a.to_str().unwrap(),
        "-o",
        b.to_str().unwrap(),
        "--level",
        "9",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    assert!(
        stderr_text(&out).contains("-> tar ("),
        "{}",
        stderr_text(&out)
    );
}

#[test]
fn convert_points_an_unrecognised_input_at_pack() {
    let dir = tmp_dir();
    let notes = dir.join("notes.txt");
    std::fs::write(&notes, b"plain text that no probe recognises\n").unwrap();
    let out_path = dir.join("notes.txt.gz");
    let out = run_output(&[
        "convert",
        notes.to_str().unwrap(),
        "-o",
        out_path.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr_text(&out));
    assert!(
        stderr_text(&out).contains("stuffr pack"),
        "{}",
        stderr_text(&out)
    );
    assert!(!out_path.exists());
}

#[test]
fn convert_to_a_bare_stream_names_raw_in_its_progress_line() {
    let dir = tmp_dir();
    let payload = b"decoded by convert\n".repeat(30);
    let x = dir.join("x");
    std::fs::write(&x, &payload).unwrap();
    let gz = dir.join("x.gz");
    assert!(run(&["pack", x.to_str().unwrap(), "-o", gz.to_str().unwrap()]).success());
    let back = dir.join("back");
    let out = run_output(&[
        "convert",
        gz.to_str().unwrap(),
        "-o",
        back.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    assert!(
        stderr_text(&out).contains("-> raw ("),
        "{}",
        stderr_text(&out)
    );
    assert_eq!(std::fs::read(&back).unwrap(), payload);
}

// ---------------------------------------------------------------------------
// `stuffr convert`, fix round 1 of Phase 5a Task 2.
// ---------------------------------------------------------------------------

#[test]
fn convert_refuses_usage_errors_before_opening_the_input() {
    let dir = tmp_dir();
    let bad = convert_corrupt_gz(&dir);
    let bad_s = bad.to_str().unwrap();
    let q = dir.join("q.tar.xz");
    let q_s = q.to_str().unwrap();
    // The control: without a usage error the corrupt input IS exit 5, so the
    // exit 2 below proves the refusal ran first.
    let out = run_output(&["convert", bad_s, "-o", q_s]);
    assert_eq!(out.status.code(), Some(5), "{}", stderr_text(&out));
    // A level out of range, on a file...
    let out = run_output(&["convert", bad_s, "-o", q_s, "--level", "99"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr_text(&out));
    assert!(!q.exists());
    // ...and on stdin, which must not be consumed to find that out.
    let out = run_with_stdin_output(&["convert", "-", "-o", q_s, "--level", "99"], &[0xde; 64]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr_text(&out));
    // A weak encoder without consent. The pure build's zstd encoder is the
    // weak one; a c-backed build has no such refusal to test.
    let zst = dir.join("q.tar.zst");
    let out = run_output(&["convert", bad_s, "-o", zst.to_str().unwrap()]);
    if stderr_text(&out).contains("weak") {
        assert_eq!(out.status.code(), Some(2), "{}", stderr_text(&out));
    }
}

#[test]
fn convert_refuses_a_codecless_identical_chain_whatever_the_flags() {
    let (dir, a) = convert_fixture();
    let tar = dir.join("a.tar");
    let out = run_output(&["convert", a.to_str().unwrap(), "-o", tar.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    let i = dir.join("i.tar");
    for extra in [&[][..], &["--level", "9"][..]] {
        let mut args = vec!["convert", tar.to_str().unwrap(), "-o", i.to_str().unwrap()];
        args.extend_from_slice(extra);
        let out = run_output(&args);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{extra:?}: {}",
            stderr_text(&out)
        );
        let err = stderr_text(&out);
        assert!(err.contains("nothing to convert"), "{err}");
        assert!(
            !err.contains("Pass --level"),
            "no hint without a codec: {err}"
        );
        assert!(!i.exists());
    }
}

#[cfg(unix)]
#[test]
fn convert_refuses_stdin_redirected_from_its_own_output() {
    let (dir, a) = convert_fixture();
    let big = dir.join("big.tar.xz");
    assert!(run(&["convert", a.to_str().unwrap(), "-o", big.to_str().unwrap()]).success());
    let before = std::fs::read(&big).unwrap();
    let link = dir.join("l.tar.xz");
    std::os::unix::fs::symlink(&big, &link).unwrap();
    let out = Command::new(STUFFR)
        .args([
            "convert",
            "-",
            "-o",
            link.to_str().unwrap(),
            "--force",
            "--level",
            "1",
        ])
        .stdin(std::fs::File::open(&big).unwrap())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", stderr_text(&out));
    assert!(
        stderr_text(&out).contains("same file"),
        "{}",
        stderr_text(&out)
    );
    assert_eq!(
        std::fs::read(&big).unwrap(),
        before,
        "the input was truncated"
    );
}

#[test]
fn convert_progress_line_says_what_the_write_lost_in_packs_words() {
    let (dir, a) = convert_fixture();
    let b = dir.join("b.tar.xz");
    let out = run_output(&["convert", a.to_str().unwrap(), b.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    assert!(
        stderr_text(&out).contains(" bytes, no fidelity loss)"),
        "{}",
        stderr_text(&out)
    );
    // From stdin the READ rung is forward-only; that is not a claim about
    // the write and must not reach its line.
    let data = std::fs::read(&a).unwrap();
    let c = dir.join("c.tar.xz");
    let out = run_with_stdin_output(&["convert", "-", "-o", c.to_str().unwrap()], &data);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    let err = stderr_text(&out);
    assert!(err.contains(" bytes, no fidelity loss)"), "{err}");
    assert!(!err.contains("forward-only"), "{err}");
}

#[test]
fn convert_container_to_stdout_plain_points_at_the_pipe() {
    let (dir, a) = convert_fixture();
    let out = run_output(&["convert", a.to_str().unwrap(), "-o", "-", "--format", "xz"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr_text(&out));
    assert!(
        stderr_text(&out).contains("stuffr pack - -o - --format xz"),
        "{}",
        stderr_text(&out)
    );
    // The pipe it names works.
    let first = Command::new(STUFFR)
        .args(["convert", a.to_str().unwrap(), "-o", "-", "--format", "tar"])
        .output()
        .unwrap();
    assert_eq!(first.status.code(), Some(0));
    let second = run_with_stdin_output(&["pack", "-", "-o", "-", "--format", "xz"], &first.stdout);
    assert_eq!(second.status.code(), Some(0), "{}", stderr_text(&second));
    let xz = dir.join("piped.tar.xz");
    std::fs::write(&xz, &second.stdout).unwrap();
    let tar = dir.join("piped.tar");
    assert!(run(&["unpack", xz.to_str().unwrap(), "-o", tar.to_str().unwrap()]).success());
    assert_eq!(std::fs::read(&tar).unwrap(), first.stdout);
}

// ---------------------------------------------------------------------------
// `stuffr convert`, entry mode (Phase 5a Task 5): the container changes, and
// entries are read from one and written into the other.
// ---------------------------------------------------------------------------

#[test]
fn convert_tar_gz_to_zip_round_trips() {
    let (dir, a) = convert_fixture();
    let zip = dir.join("a.zip");
    let out = run_output(&["convert", a.to_str().unwrap(), "-o", zip.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    let err = stderr_text(&out);
    // One progress line for both modes: the TARGET chain and pack's words.
    assert!(err.contains("-> zip ("), "{err}");
    assert!(err.contains(" bytes, no fidelity loss)"), "{err}");
    assert_unpacks_to_the_fixture(&dir, &zip, "out");
}

#[test]
fn convert_refuses_a_tar_gz_whose_gzip_trailer_disagrees() {
    let (dir, _, corrupt) = gnu_padded_tar_gz();
    let zip = dir.join("out.zip");
    let out = run_output(&["convert", corrupt.to_str().unwrap(), zip.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(5), "{}", stderr_text(&out));
    assert!(!zip.exists(), "a corrupt source publishes nothing");
}

#[test]
fn every_read_verb_checks_the_gzip_trailer_under_a_padded_tar() {
    let (dir, _, corrupt) = gnu_padded_tar_gz();
    let c = corrupt.to_str().unwrap();
    let x = dir.join("x");
    for args in [
        vec!["test", c],
        vec!["list", c],
        vec!["cat", c],
        vec!["unpack", c, "-C", x.to_str().unwrap()],
    ] {
        let out = run_output(&args);
        assert_eq!(
            out.status.code(),
            Some(5),
            "{args:?}: {}",
            stderr_text(&out)
        );
    }
}

#[test]
fn a_clean_gnu_padded_tar_gz_converts_and_tests_clean() {
    let (dir, clean, _) = gnu_padded_tar_gz();
    let c = clean.to_str().unwrap();
    let out = run_output(&["test", c]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    let zip = dir.join("out.zip");
    let out = run_output(&["convert", c, zip.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    let out = run_output(&["test", zip.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
}

/// The matrix: every writable container packed by stuffr, converted into
/// every OTHER writable container, read back by `unpack`. Payloads must be
/// exact, the exit 0, and the warnings exactly what the target's caps (and
/// the source's own metadata) predict — no more, no fewer.
#[test]
fn convert_every_container_into_every_other() {
    let containers = writable_containers();
    assert!(
        containers.len() >= 4,
        "tar, ar, cpio and zip are in every build: {containers:?}"
    );
    let dir = tmp_dir();
    let d = dir.join("d");
    std::fs::create_dir_all(d.join("sub")).unwrap();
    let (one, two) = convert_payloads();
    std::fs::write(d.join("one.txt"), &one).unwrap();
    std::fs::write(d.join("sub/two.bin"), &two).unwrap();

    for (src_id, src_ext, _) in &containers {
        let s = dir.join(format!("s-{src_id}.{src_ext}"));
        let out = run_output(&["pack", d.to_str().unwrap(), "-o", s.to_str().unwrap()]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "pack {src_id}: {}",
            stderr_text(&out)
        );

        for (dst_id, dst_ext, dst_caps) in &containers {
            if dst_id == src_id {
                continue;
            }
            let label = format!("{src_id}-to-{dst_id}");
            let t = dir.join(format!("t-{label}.{dst_ext}"));
            let out = run_output(&["convert", s.to_str().unwrap(), "-o", t.to_str().unwrap()]);
            let err = stderr_text(&out);
            assert_eq!(out.status.code(), Some(0), "{label}: {err}");
            assert!(err.contains(&format!("-> {dst_id} (")), "{label}: {err}");

            let (skips, ownership) = predicted_convert_warnings(&s, dst_caps);
            let total = skips + ownership;
            assert_eq!(
                err.matches("skipped entry").count(),
                skips,
                "{label}: skip warnings: {err}"
            );
            assert_eq!(
                err.matches("missing metadata: uid_gid").count(),
                ownership,
                "{label}: ownership warnings: {err}"
            );
            if total == 0 {
                assert!(err.contains("no fidelity loss)"), "{label}: {err}");
                assert!(!err.contains("fidelity warning"), "{label}: {err}");
            } else {
                assert!(
                    err.contains(&format!("{total} fidelity loss(es))")),
                    "{label}: {err}"
                );
                assert!(
                    err.contains(&format!("stuffr: {total} fidelity warning(s):")),
                    "{label}: {err}"
                );
            }

            let back = dir.join(format!("back-{label}"));
            let out = run_output(&["unpack", t.to_str().unwrap(), "-C", back.to_str().unwrap()]);
            assert_eq!(
                out.status.code(),
                Some(0),
                "unpack {label}: {}",
                stderr_text(&out)
            );
            assert_eq!(
                std::fs::read(back.join("d/one.txt")).unwrap(),
                one,
                "{label}"
            );
            assert_eq!(
                std::fs::read(back.join("d/sub/two.bin")).unwrap(),
                two,
                "{label}"
            );
        }
    }
}

/// M2 (Phase 5a final review): `convert DIR x.zip` is exit 2 naming `pack`,
/// as `pack DIR -o x.gz` already is — not `i/o error: Is a directory` at
/// exit 1.
#[test]
fn convert_refuses_a_directory_input_as_a_usage_error() {
    let (dir, _) = convert_fixture();
    let zip = dir.join("x.zip");
    let out = run_output(&[
        "convert",
        dir.join("d").to_str().unwrap(),
        zip.to_str().unwrap(),
    ]);
    let err = stderr_text(&out);
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(
        err.contains("is a directory") && err.contains("stuffr pack"),
        "{err}"
    );
    assert!(!zip.exists());
}

/// I1 (Phase 5a final review): a target that stores no owner loses nothing
/// when the source has none, so lha to zip (neither stores one) is lossless
/// and passes `--strict-fidelity`; zip to tar still reports the ids it is
/// about to write as `root:root`.
#[test]
fn convert_reports_missing_ownership_only_into_a_target_that_stores_one() {
    let (dir, _) = convert_fixture();
    let d = dir.join("d");
    let lha = dir.join("s.lzh");
    let out = run_output(&["pack", d.to_str().unwrap(), "-o", lha.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));

    let zip = dir.join("t.zip");
    let out = run_output(&[
        "convert",
        lha.to_str().unwrap(),
        zip.to_str().unwrap(),
        "--strict-fidelity",
    ]);
    let err = stderr_text(&out);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(!err.contains("uid_gid"), "{err}");
    assert!(err.contains("no fidelity loss)"), "{err}");

    let tar = dir.join("t.tar");
    let out = run_output(&["convert", zip.to_str().unwrap(), tar.to_str().unwrap()]);
    let err = stderr_text(&out);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(err.contains("missing metadata: uid_gid"), "{err}");
}

/// Archives written by the real tools — not by stuffr — convert to
/// `.tar.xz` and unpack to exactly the files fed to the tool.
#[test]
fn convert_reads_archives_the_reference_tools_wrote() {
    let dir = tmp_dir();
    let tree = dir.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    let (one, two) = convert_payloads();
    std::fs::write(tree.join("one.txt"), &one).unwrap();
    std::fs::write(tree.join("two.bin"), &two).unwrap();
    let names = [os(&"one.txt"), os(&"two.bin")];

    let mut sources: Vec<(&str, PathBuf)> = Vec::new();

    let zip = dir.join("ref.zip");
    let mut args = vec![os(&"-q"), os(&zip)];
    args.extend(names);
    run_tool(&require_bin("zip"), &args, &tree, b"");
    sources.push(("zip", zip));

    // Both tar implementations where they differ (bsdtar on macOS, GNU tar
    // from Homebrew); on Linux the two are the same program.
    for (label, bin) in [("tar", require_bin("tar")), ("gtar", require_gnu_tar())] {
        let tar = dir.join(format!("ref-{label}.tar"));
        let mut args = vec![os(&"-cf"), os(&tar)];
        args.extend(names);
        run_tool(&bin, &args, &tree, b"");
        sources.push((label, tar));
    }

    let cpio = dir.join("ref.cpio");
    let bytes = run_tool(
        &require_bin("cpio"),
        &[os(&"-o"), os(&"-H"), os(&"newc")],
        &tree,
        b"one.txt\ntwo.bin\n",
    );
    std::fs::write(&cpio, bytes).unwrap();
    sources.push(("cpio", cpio));

    // `S`: no symbol table. macOS's `ar rc` over non-object members writes
    // an archive holding only an empty `__.SYMDEF SORTED` (measured: 96
    // bytes, neither member), which would test nothing.
    let ar = dir.join("ref.a");
    let mut args = vec![os(&"rcS"), os(&ar)];
    args.extend(names);
    run_tool(&require_bin("ar"), &args, &tree, b"");
    sources.push(("ar", ar));

    for (label, src) in sources {
        let x = dir.join(format!("x-{label}.tar.xz"));
        let out = run_output(&["convert", src.to_str().unwrap(), "-o", x.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(0), "{label}: {}", stderr_text(&out));
        let back = dir.join(format!("back-{label}"));
        let out = run_output(&["unpack", x.to_str().unwrap(), "-C", back.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(0), "{label}: {}", stderr_text(&out));
        assert_eq!(std::fs::read(back.join("one.txt")).unwrap(), one, "{label}");
        assert_eq!(std::fs::read(back.join("two.bin")).unwrap(), two, "{label}");
    }
}

/// A real reader for convert's output: the system `unzip` lists the zip a
/// tar was converted into.
#[test]
fn convert_writes_a_zip_the_system_unzip_reads() {
    let (dir, a) = convert_fixture();
    let tar = dir.join("s.tar");
    let out = run_output(&["convert", a.to_str().unwrap(), "-o", tar.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    let zip = dir.join("t.zip");
    let out = run_output(&[
        "convert",
        tar.to_str().unwrap(),
        "-o",
        zip.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    let listing = run_tool(&require_bin("unzip"), &[os(&"-l"), os(&zip)], &dir, b"");
    let listing = String::from_utf8_lossy(&listing);
    assert!(listing.contains("d/one.txt"), "{listing}");
    assert!(listing.contains("d/sub/two.bin"), "{listing}");
}

/// A zip another tool streamed to a pipe declares its sizes only in data
/// descriptors AFTER each payload, which a forward reader cannot frame. On
/// stdin convert spools it, so every entry comes out whole.
#[test]
fn convert_reads_a_descriptor_zip_from_stdin() {
    let dir = tmp_dir();
    let tree = dir.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    let (one, two) = convert_payloads();
    std::fs::write(tree.join("one.txt"), &one).unwrap();
    std::fs::write(tree.join("two.bin"), &two).unwrap();
    // `-` writes to stdout, which `run_tool` captures through a pipe: the
    // system zip cannot seek back, so it writes data descriptors.
    let zip = run_tool(
        &require_bin("zip"),
        &[os(&"-q"), os(&"-"), os(&"one.txt"), os(&"two.bin")],
        &tree,
        b"",
    );
    // The fixture asserted, not assumed: general-purpose flag bit 3 on the
    // first local header is what "uses a data descriptor" means.
    assert_eq!(&zip[..4], b"PK\x03\x04");
    assert_ne!(
        u16::from_le_bytes([zip[6], zip[7]]) & 0x08,
        0,
        "the system zip did not write data descriptors, so this proves nothing"
    );

    let out_tar = dir.join("out.tar");
    let out = run_with_stdin_output(&["convert", "-", "-o", out_tar.to_str().unwrap()], &zip);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    let back = dir.join("back");
    let out = run_output(&[
        "unpack",
        out_tar.to_str().unwrap(),
        "-C",
        back.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    assert_eq!(std::fs::read(back.join("one.txt")).unwrap(), one);
    assert_eq!(std::fs::read(back.join("two.bin")).unwrap(), two);
}

/// A symlink into a container with no symlink entries is a fidelity loss:
/// under `--strict-fidelity` that is exit 4, and — as for `pack` — the
/// output is still written.
#[cfg(unix)]
#[test]
fn convert_strict_fidelity_exits_4_and_keeps_the_output() {
    let ar_caps = stuffr::registry()
        .container(stuffr::FormatId::new("ar"))
        .expect("ar is in every build")
        .caps();
    assert!(!ar_caps.stores_symlinks, "the premise: ar has no symlinks");
    let dir = tmp_dir();
    let d = dir.join("d");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("real.txt"), b"real").unwrap();
    std::os::unix::fs::symlink("real.txt", d.join("link.txt")).unwrap();
    let tar = dir.join("s.tar");
    let out = run_output(&["pack", d.to_str().unwrap(), "-o", tar.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));

    let a = dir.join("t.a");
    let out = run_output(&[
        "convert",
        tar.to_str().unwrap(),
        "-o",
        a.to_str().unwrap(),
        "--strict-fidelity",
    ]);
    assert_eq!(out.status.code(), Some(4), "{}", stderr_text(&out));
    assert!(
        stderr_text(&out).contains("d/link.txt"),
        "the warning names the entry: {}",
        stderr_text(&out)
    );
    assert!(a.exists(), "the output is written, as pack writes it");
    let back = dir.join("back");
    let out = run_output(&["unpack", a.to_str().unwrap(), "-C", back.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    assert_eq!(std::fs::read(back.join("d/real.txt")).unwrap(), b"real");
}

/// Controller ruling C4b: `--strict-fidelity` on convert judges the merged
/// report's WARNINGS, not the read rung. A tar on a pipe reads forward-only
/// — at full data fidelity, as `ContainerCaps::forward_parse` promises — so
/// a conversion that lost nothing is exit 0 under the gate, not exit 4.
#[test]
fn convert_strict_fidelity_passes_a_lossless_piped_source() {
    let (dir, a) = convert_fixture();
    let tar = dir.join("s.tar");
    let out = run_output(&["convert", a.to_str().unwrap(), "-o", tar.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    let zip = dir.join("t.zip");
    let out = run_with_stdin_output(
        &[
            "convert",
            "-",
            "-o",
            zip.to_str().unwrap(),
            "--strict-fidelity",
        ],
        &std::fs::read(&tar).unwrap(),
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    assert!(
        stderr_text(&out).contains(" bytes, no fidelity loss)"),
        "{}",
        stderr_text(&out)
    );
    assert_unpacks_to_the_fixture(&dir, &zip, "out");
}

/// A name a target's writer genuinely refuses: an `lha` level-1 header's
/// filename field holds under 255 bytes (`MAX_LEVEL1_NAME`), and the writer
/// says so at `add` with `Error::Unsupported`. (`ar` would not do: its BSD
/// `#1/N` form holds any name, so `pack` succeeds and nothing is proven.)
/// `convert` hands the name to the same writer, so it must exit as `pack`
/// does — and, failing, publish no OUT.
#[test]
fn convert_into_lha_with_a_name_too_long_matches_pack() {
    let dir = tmp_dir();
    let d = dir.join("d");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(
        d.join(format!("{}.txt", "n".repeat(240))),
        b"too long for lha",
    )
    .unwrap();

    let packed = dir.join("p.lzh");
    let pack = run_output(&["pack", d.to_str().unwrap(), "-o", packed.to_str().unwrap()]);
    // The premise, asserted: the lha writer really refuses this name.
    assert_eq!(pack.status.code(), Some(3), "{}", stderr_text(&pack));
    assert!(
        stderr_text(&pack).contains("LHA cannot store"),
        "{}",
        stderr_text(&pack)
    );
    assert!(!packed.exists());

    let tar = dir.join("s.tar");
    let out = run_output(&["pack", d.to_str().unwrap(), "-o", tar.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    let converted = dir.join("c.lzh");
    let convert = run_output(&[
        "convert",
        tar.to_str().unwrap(),
        "-o",
        converted.to_str().unwrap(),
    ]);
    assert_eq!(
        convert.status.code(),
        pack.status.code(),
        "pack: {}\nconvert: {}",
        stderr_text(&pack),
        stderr_text(&convert)
    );
    assert!(
        stderr_text(&convert).contains("LHA cannot store"),
        "{}",
        stderr_text(&convert)
    );
    assert!(!converted.exists(), "a failed convert leaves no OUT");
}

/// Entry mode into a container this build only READS (`zoo`, `arc`) is a
/// capability refusal, exit 3, with no OUT — from a file and from stdin.
/// It is raised once the source is open (a codec-mode `x.zoo.gz -> x.zoo`
/// is legal, and the mode is not known before), never as a corrupt input.
#[test]
fn convert_into_a_read_only_container_exits_3_and_writes_nothing() {
    let registry = stuffr::registry();
    let read_only: Vec<(String, String)> = registry
        .matrix()
        .into_iter()
        .filter(|row| registry.container(row.id).is_some() && row.read && !row.write)
        .map(|row| (row.id.to_string(), row.extensions[0].to_string()))
        .collect();
    assert!(
        !read_only.is_empty(),
        "the premise: arc and zoo are read-only"
    );
    let (dir, a) = convert_fixture();
    let data = std::fs::read(&a).unwrap();
    for (id, ext) in read_only {
        let t = dir.join(format!("t.{ext}"));
        let out = run_output(&["convert", a.to_str().unwrap(), "-o", t.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(3), "{id}: {}", stderr_text(&out));
        assert!(!t.exists(), "{id}: no OUT");
        let out = run_with_stdin_output(&["convert", "-", "-o", t.to_str().unwrap()], &data);
        assert_eq!(
            out.status.code(),
            Some(3),
            "{id} stdin: {}",
            stderr_text(&out)
        );
        assert!(!t.exists(), "{id} stdin: no OUT");
    }
}

/// Task 6's fuzz finding at the CLI: an ar member named `a\0bc.txt` converted
/// into tar is skipped with a warning (exit 0, the rest written), and
/// `--strict-fidelity` turns that warning into exit 4 — where it used to
/// land in the tar as `a` and report "no fidelity loss".
#[test]
fn convert_skips_a_name_with_a_nul_its_target_cannot_store() {
    let dir = tmp_dir();
    let src = dir.join("in.a");
    std::fs::write(
        &src,
        bsd_ar_with_names(&[(b"keep.txt", b"kept\n"), (b"a\0bc.txt", b"nul\n")]),
    )
    .unwrap();
    let tar = dir.join("out.tar");
    let out = run_output(&[
        "convert",
        src.to_str().unwrap(),
        "-o",
        tar.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    let err = stderr_text(&out);
    assert!(
        err.contains("skipped entry `a\\0bc.txt`") && err.contains("NUL"),
        "the warning names the entry and why: {err}"
    );
    let back = dir.join("back");
    let out = run_output(&[
        "unpack",
        tar.to_str().unwrap(),
        "-C",
        back.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    assert_eq!(std::fs::read(back.join("keep.txt")).unwrap(), b"kept\n");
    assert_eq!(
        std::fs::read_dir(&back).unwrap().count(),
        1,
        "only the entry tar can hold"
    );

    let strict = dir.join("strict.tar");
    let out = run_output(&[
        "convert",
        src.to_str().unwrap(),
        "-o",
        strict.to_str().unwrap(),
        "--strict-fidelity",
    ]);
    assert_eq!(out.status.code(), Some(4), "{}", stderr_text(&out));
}

/// A BSD `#1/N` member is padded by its WHOLE size, name included, and
/// `ar` 0.9.0 pads by the payload alone, so an odd `N` used to throw every
/// later member one byte off (`ar.rs`'s `PadAfter`). The fixture is
/// hand-built — `#1/3` with an even payload (a true pad byte the crate does
/// not expect), `#1/5` with an odd one (no pad byte, though the crate
/// expects one), then an inline name — and macOS's own `ar t` is the witness
/// that it is a valid archive.
#[cfg(target_os = "macos")]
#[test]
fn bsd_ar_with_odd_names_lists_and_unpacks() {
    fn header(identifier: &str, size: usize) -> Vec<u8> {
        let h = format!(
            "{identifier:<16}{:<12}{:<6}{:<6}{:<8}{size:<10}`\n",
            0, 0, 0, "100644"
        );
        assert_eq!(h.len(), 60);
        h.into_bytes()
    }
    let members: [(&str, bool, &[u8]); 3] = [
        ("abc", true, b"ABCD"),
        ("hello", true, b"HELLO"),
        ("plain.txt", false, b"xyz"),
    ];
    let mut bytes = b"!<arch>\n".to_vec();
    for (name, extended, data) in members {
        let body = if extended {
            [name.as_bytes(), data].concat()
        } else {
            data.to_vec()
        };
        let identifier = if extended {
            format!("#1/{}", name.len())
        } else {
            name.to_string()
        };
        bytes.extend(header(&identifier, body.len()));
        bytes.extend_from_slice(&body);
        if body.len() % 2 == 1 {
            bytes.push(b'\n');
        }
    }
    let dir = tmp_dir();
    let archive = dir.join("odd.a");
    std::fs::write(&archive, &bytes).unwrap();
    let names: Vec<&str> = members.iter().map(|(name, _, _)| *name).collect();

    let ar = require_bin("/usr/bin/ar");
    let out = Command::new(&ar).arg("t").arg(&archive).output().unwrap();
    assert!(out.status.success(), "{}", stderr_text(&out));
    assert_eq!(
        String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .collect::<Vec<_>>(),
        names,
        "the system `ar` reads the fixture"
    );

    let out = run_output(&["list", "--json", archive.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let listed: Vec<&str> = v
        .as_array()
        .expect("a JSON array of entries")
        .iter()
        .map(|row| row["name"].as_str().unwrap())
        .collect();
    assert_eq!(listed, names);

    let back = dir.join("back");
    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        back.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    for (name, _, data) in members {
        assert_eq!(std::fs::read(back.join(name)).unwrap(), data, "{name}");
    }
}

/// 0.10.3: `llvm-ar` writes GNU's 64-bit symbol table (`/SYM64/`) past
/// `SYM64_THRESHOLD`, which `list` used to refuse as corrupt. Optional
/// cross-tool witness: skipped (not failed) when `llvm-ar` or `cc` is absent,
/// as neither is on a stock CI image or macOS.
#[test]
fn llvm_ar_with_a_sym64_symbol_table_lists() {
    let llvm_ar = which("llvm-ar").or_else(|| {
        let p = PathBuf::from("/opt/homebrew/opt/llvm/bin/llvm-ar");
        p.is_file().then_some(p)
    });
    let (Some(llvm_ar), Some(cc)) = (llvm_ar, which("cc")) else {
        eprintln!("skipped: needs llvm-ar and cc");
        return;
    };
    let dir = tmp_dir();
    std::fs::write(dir.join("obj.c"), "int f(void) { return 1; }\n").unwrap();
    let st = Command::new(cc)
        .current_dir(&dir)
        .args(["-c", "obj.c", "-o", "obj.o"])
        .status()
        .unwrap();
    assert!(st.success());
    let st = Command::new(llvm_ar)
        .current_dir(&dir)
        .env("SYM64_THRESHOLD", "0")
        .args(["rcs", "--format=gnu", "out.a", "obj.o"])
        .status()
        .unwrap();
    assert!(st.success());
    let bytes = std::fs::read(dir.join("out.a")).unwrap();
    if !bytes[8..].starts_with(b"/SYM64/") {
        eprintln!("skipped: this llvm-ar did not write /SYM64/");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    let out = run_output(&["list", dir.join("out.a").to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains("obj.o"));
}

/// A hostile entry name inside a library error message must not reach the
/// terminal raw: a truncated ar member named `a<ESC>[31mbc` is reported
/// with the escape written out, and the exit code stays the classified 5.
#[test]
fn a_hostile_name_in_a_corrupt_archive_error_is_escaped() {
    let dir = tmp_dir();
    let src = dir.join("in.a");
    let mut bytes = bsd_ar_with_names(&[(b"a\x1b[31mbc", b"0123456789")]);
    bytes.truncate(bytes.len() - 6);
    std::fs::write(&src, bytes).unwrap();
    let out = run_output(&["test", src.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(5), "{}", stderr_text(&out));
    assert!(!out.stderr.contains(&0x1b), "raw ESC on stderr");
    let err = stderr_text(&out);
    assert!(err.contains("a\\x1b[31mbc"), "{err}");
}

#[test]
fn control_bytes_in_entry_names_never_reach_the_terminal_raw() {
    let dir = tmp_dir();
    let tar = dir.join("x.tar");
    let evil = "a\x1b[31mb\nc";
    write_raw_tar(&tar, &[Raw::File(evil, b"hi"), Raw::Fifo("p\x1b[2Jipe")]);
    let t = tar.to_str().unwrap();

    // Text listing: escaped, one line per entry, no raw ESC.
    let out = run_output(&["list", t]);
    assert!(out.status.success());
    assert!(!out.stdout.contains(&0x1b), "raw ESC in list stdout");
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("a\\x1b[31mb\\nc"), "{text}");
    assert_eq!(text.lines().count(), 2, "{text}");

    // The skip warning for the fifo carries no raw control byte.
    let dest = dir.join("out");
    let out = run_output(&["unpack", t, "-C", dest.to_str().unwrap()]);
    assert!(!out.stderr.contains(&0x1b), "raw ESC on unpack stderr");
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(err.contains("p\\x1b[2Jipe"), "{err}");

    // Salvage rows too.
    let out = run_output(&["salvage", t, "--list"]);
    assert!(!out.stdout.contains(&0x1b), "raw ESC in salvage stdout");
    assert!(!out.stderr.contains(&0x1b), "raw ESC in salvage stderr");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(text.contains("a\\x1b[31mb\\nc"), "{text}");

    // JSON stays raw-in-value: serde decodes back to the exact name.
    let out = run_output(&["list", "--json", t]);
    let rows: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rows[0]["name"].as_str().unwrap(), evil);
}
