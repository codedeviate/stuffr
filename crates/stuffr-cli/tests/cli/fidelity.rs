use crate::common::*;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

// ---------------------------------------------------------------------
// Extraction fidelity.
//
// `--strict-fidelity` gates on `FidelityReport::has_warnings`, so a loss that
// raises no warning is a loss the flag reports as success. These tests are
// the difference between the warnings meaning something and being decoration.
// ---------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn extraction_restores_modes_and_mtimes_for_files_and_directories() {
    let dir = tmp_dir();
    let dest = dir.join("out");
    let archive = write_raw_tar(
        &dir.join("meta.tar"),
        &[
            Raw::Dir("sub/"),
            Raw::ModedFile("sub/script.sh", b"#!/bin/sh\n", 0o750),
            Raw::ModedFile("readonly.txt", b"ro", 0o400),
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

    assert_eq!(mode_of(&dest.join("sub/script.sh")), 0o750);
    assert_eq!(mode_of(&dest.join("readonly.txt")), 0o400);
    assert_eq!(mode_of(&dest.join("sub")), 0o755);
    assert_eq!(mtime_secs(&dest.join("sub/script.sh")), FIXTURE_MTIME);
    assert_eq!(mtime_secs(&dest.join("readonly.txt")), FIXTURE_MTIME);
    // A directory's mtime is restored AFTER its children are written —
    // creating one of them would otherwise bump it back to now.
    assert_eq!(mtime_secs(&dest.join("sub")), FIXTURE_MTIME);

    // Nothing was lost, so the gate passes.
    let strict = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dir.join("strict").to_str().unwrap(),
        "--strict-fidelity",
    ]);
    assert!(
        strict.status.success(),
        "an extraction that lost nothing must pass --strict-fidelity, stderr: {}",
        String::from_utf8_lossy(&strict.stderr)
    );
}

#[cfg(unix)]
#[test]
fn a_setuid_bit_is_not_restored_and_strict_fidelity_fails_on_the_loss() {
    // An archive is untrusted input; honouring its setuid bit hands over a
    // privilege-escalation primitive for free. Dropping it is a real
    // difference from what the archive declared, so it is REPORTED — which is
    // what makes `--strict-fidelity` able to see it.
    let dir = tmp_dir();
    let dest = dir.join("out");
    let archive = write_raw_tar(
        &dir.join("setuid.tar"),
        &[Raw::ModedFile("suid", b"payload", 0o4755)],
    );

    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "the extraction itself succeeds, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        mode_of(&dest.join("suid")),
        0o755,
        "the setuid bit must not be restored"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("suid") && stderr.contains("mode"),
        "the loss must be reported, naming the entry and the field: {stderr}"
    );

    let strict = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dir.join("strict").to_str().unwrap(),
        "--force",
        "--strict-fidelity",
    ]);
    assert_eq!(
        strict.status.code(),
        Some(4),
        "a dropped mode must fail --strict-fidelity, stderr: {}",
        String::from_utf8_lossy(&strict.stderr)
    );
}

#[cfg(unix)]
#[test]
fn an_entry_with_no_shape_on_disk_is_skipped_and_said_out_loud() {
    // A fifo is `EntryKind::Other`. Writing it out as a regular file carrying
    // its "contents" would materialise something the archive never held.
    let dir = tmp_dir();
    let dest = dir.join("out");
    let archive = write_raw_tar(
        &dir.join("fifo.tar"),
        &[Raw::File("a.txt", b"alpha"), Raw::Fifo("pipe")],
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
    assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"alpha");
    assert!(
        std::fs::symlink_metadata(dest.join("pipe")).is_err(),
        "a fifo entry must not become a regular file"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("skipped entry") && stderr.contains("pipe"),
        "the skip must name the entry and why: {stderr}"
    );

    let strict = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dir.join("strict").to_str().unwrap(),
        "--strict-fidelity",
    ]);
    assert_eq!(
        strict.status.code(),
        Some(4),
        "a skipped entry must fail --strict-fidelity, stderr: {}",
        String::from_utf8_lossy(&strict.stderr)
    );
}

#[cfg(unix)]
#[test]
fn a_symlinks_own_mode_and_mtime_are_reported_as_lost() {
    // `set_permissions` and `File::set_times` both follow a link, and there
    // is no `lchmod`/`lutimes` in std — so the link's own metadata cannot be
    // restored, and saying so is the whole job of the fidelity report.
    let dir = tmp_dir();
    let dest = dir.join("out");
    let archive = write_raw_tar(
        &dir.join("link.tar"),
        &[Raw::File("a.txt", b"alpha"), Raw::Symlink("link", "a.txt")],
    );

    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
        "--strict-fidelity",
    ]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("link") && stderr.contains("mtime"),
        "the loss must name the entry and the field: {stderr}"
    );
    // The link itself still extracted — this is a fidelity report, not a
    // refusal.
    assert_eq!(
        std::fs::read_link(dest.join("link")).unwrap(),
        Path::new("a.txt")
    );
}

#[test]
fn test_verb_passes_strict_fidelity_on_an_ordinary_tarball() {
    // The counterpart assertion to the four above: the flag is not simply
    // "fail whenever it is given". A tar read approximates nothing.
    let dir = tmp_dir();
    let archive = write_fixture_tar(&dir, &[("a.txt", b"alpha")]);
    let out = run_output(&["test", archive.to_str().unwrap(), "--strict-fidelity"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// An `st_mode`-shaped mode field must not read as "setuid was refused".
///
/// Apache Commons Compress writes `TarArchiveEntry.DEFAULT_FILE_MODE =
/// 0100644` — the file-type bit `S_IFREG` still in it — which puts this shape
/// in Java, Gradle and Maven tarballs. `0o100644 & !0o777` is `0o100000`,
/// non-zero, so an unmasked check would report a dropped mode for EVERY entry
/// of an entirely ordinary archive and fail `--strict-fidelity` on all of
/// them, while the file itself lands at `0o644` exactly as it should. The
/// permission apply was always right; only the warning was wrong.
#[cfg(unix)]
#[test]
fn an_st_mode_shaped_header_mode_raises_no_warning() {
    let dir = tmp_dir();
    let dest = dir.join("out");
    let archive = write_raw_tar(
        &dir.join("commons.tar"),
        &[Raw::ModedFile("a.txt", b"alpha", 0o100_644)],
    );

    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
        "--strict-fidelity",
    ]);
    assert!(
        out.status.success(),
        "an st_mode-shaped mode field must not fail the gate, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("missing metadata"),
        "nothing was lost, so nothing may be reported: {stderr}"
    );
    assert_eq!(
        mode_of(&dest.join("a.txt")),
        0o644,
        "the permission bits apply; the type bits are not permissions"
    );

    // The setuid case must still be caught — the mask must not have widened
    // into "ignore everything above 0o777".
    let suid = write_raw_tar(
        &dir.join("suid.tar"),
        &[Raw::ModedFile("b.txt", b"beta", 0o104_755)],
    );
    let out = run_output(&[
        "unpack",
        suid.to_str().unwrap(),
        "-C",
        dir.join("suid-out").to_str().unwrap(),
        "--strict-fidelity",
    ]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "setuid inside an st_mode-shaped field is still a dropped mode, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The Phase 2 final review's C1, pinned on every entry-aware verb.
///
/// `entries::open_archive` resolved the codec layer beneath a container
/// through `resolve_chain_deep`, which built each decoder from
/// `DecodeOpts::default()` — `memory_limit: None`, i.e. unbounded. So a
/// 336-byte `.tar.lz` whose header declares a 512 MiB dictionary drove
/// 182 MB peak RSS through `list` and 307 MB through `test`, both exiting 0,
/// while single-stream `unpack` of the identical bytes refused it at exit 6
/// in 1.7 MB. That is the denial of service Phase 1f closed, reopened behind
/// `list` — the verb advertised as reading nothing and extracting nothing.
///
/// `--max-ratio` cannot substitute: it counts decoded OUTPUT bytes and the
/// allocation precedes any output. Only `DecodeOpts::memory_limit` sees it.
///
/// Every invocation passes `--memory-limit` EXPLICITLY. Relying on the
/// default would make the test host-dependent and green only by accident:
/// `default_memory_limit()` is 25% of available RAM, which is the 256 MiB
/// floor on macOS (no `/proc/meminfo`) but roughly 3.5 GiB on a 16 GB Linux
/// CI runner — comfortably above the 512 MiB this fixture declares, so all
/// four verbs would exit 0 and the assertion would fail on every Linux job.
/// Measured directly: `stuffr list crafted.tar.lz --memory-limit 3500M`
/// exits 0. 0x1D is lzip's LARGEST coded dictionary, so the fixture cannot
/// be made hungrier to compensate. `cli/verbs.rs`'s
/// `info_reports_the_resolved_memory_limit` states the same convention.
#[test]
fn a_container_under_a_codec_declaring_a_huge_dictionary_is_refused_on_every_verb() {
    let (_legit, crafted, _dir) = craft_a_tar_lz_declaring_a_huge_dictionary("c1-refuse");
    let path = crafted.to_str().unwrap();
    // Below the fixture's 512 MiB declaration, above what the legitimate
    // sibling needs — see `a_legitimate_archive_of_the_same_size_still_works_on_every_verb`.
    const LIMIT: &str = "64M";

    for args in [
        vec!["list", path, "--memory-limit", LIMIT],
        vec!["test", path, "--memory-limit", LIMIT],
        vec!["cat", path, "a.txt", "--memory-limit", LIMIT],
    ] {
        let out = Command::new(STUFFR).args(&args).output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert_eq!(
            out.status.code(),
            Some(6),
            "`stuffr {}` must refuse a 512 MiB dictionary declaration at exit 6, \
             not allocate for it; stderr: {stderr}",
            args.join(" ")
        );
        assert!(
            stderr.contains("memory-limit"),
            "the refusal must name the flag that raises it; stderr: {stderr}"
        );
    }

    // The single-stream path already did this; it must keep doing it.
    let out = Command::new(STUFFR)
        .args([
            "unpack",
            path,
            "-o",
            "/dev/null",
            "--force",
            "--memory-limit",
            LIMIT,
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(6),
        "the single-stream path's existing refusal must be unchanged; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // And over a pipe, where there is no path to resolve the chain from.
    let mut child = Command::new(STUFFR)
        .args(["list", "-", "--memory-limit", LIMIT])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let bytes = std::fs::read(&crafted).unwrap();
    child.stdin.take().unwrap().write_all(&bytes).unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(6),
        "a piped crafted archive must be refused too; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The other half of C1, and the one that catches an over-broad fix: a
/// LEGITIMATE archive of the same size, differing in that one header byte,
/// must still work on every verb. A guard that refused this would be a
/// worse defect than the one it closed.
#[test]
fn a_legitimate_archive_of_the_same_size_still_works_on_every_verb() {
    let (legit, crafted, _dir) = craft_a_tar_lz_declaring_a_huge_dictionary("c1-allow");
    let path = legit.to_str().unwrap();
    assert_eq!(
        std::fs::metadata(&legit).unwrap().len(),
        std::fs::metadata(&crafted).unwrap().len(),
        "the two fixtures must differ only in that one byte"
    );

    // The SAME explicit limit its crafted sibling is refused at, so the pair
    // proves the bound discriminates on the declaration rather than refusing
    // everything — and so neither half depends on the host's RAM.
    const LIMIT: &str = "64M";

    let out = Command::new(STUFFR)
        .args(["list", path, "--memory-limit", LIMIT])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("a.txt"),
        "list must still show the entry"
    );

    let out = Command::new(STUFFR)
        .args(["test", path, "--memory-limit", LIMIT])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = Command::new(STUFFR)
        .args(["cat", path, "a.txt", "--memory-limit", LIMIT])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(out.stdout, b"hello from inside the tar");

    let dest = tmp("c1-allow-dest");
    let _ = std::fs::remove_dir_all(&dest);
    let out = Command::new(STUFFR)
        .args([
            "unpack",
            path,
            "-C",
            dest.to_str().unwrap(),
            "--memory-limit",
            LIMIT,
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dest.join("a.txt").exists());
}

/// A zstd frame of one raw (stored) block holding `payload`, declaring
/// `window_descriptor` (RFC 8878: window = 2^(10+e) * (1 + m/8), e the top
/// five bits, m the low three). Valid zstd: no checksum, no content size.
fn raw_zstd_frame(window_descriptor: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0x00, window_descriptor];
    let block = ((payload.len() as u32) << 3) | 1; // last block, raw
    frame.extend_from_slice(&block.to_le_bytes()[..3]);
    frame.extend_from_slice(payload);
    frame
}

/// PARSE-2/PARSE-3 (2026-10-31 audit): the pure-tier zstd decoder honours
/// `--memory-limit` at every frame start, and a window above ruzstd's own
/// 128 MiB cap is exit 6 naming `c-backed`, not "archive is corrupt". Pure
/// tier only: under `zstd-c` the registry's zstd is libzstd.
#[cfg(not(feature = "zstd-c"))]
#[test]
fn pure_zstd_refuses_a_window_over_the_memory_limit_on_every_frame() {
    let dir = tmp("zstd-window");
    std::fs::create_dir_all(&dir).unwrap();
    let small = raw_zstd_frame(10 << 3, b"first-"); // 1 MiB window
    let big = raw_zstd_frame((16 << 3) | 4, b"second"); // 96 MiB window
    let over_cap = raw_zstd_frame((17 << 3) | 1, b"third"); // 144 MiB window

    let run = |name: &str, bytes: &[u8], limit: &str| {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        Command::new(STUFFR)
            .args(["cat", path.to_str().unwrap(), "--memory-limit", limit])
            .output()
            .unwrap()
    };

    let out = run("small.zst", &small, "1M");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"first-");

    let out = run("big.zst", &big, "1M");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(6), "stderr: {stderr}");
    assert!(
        stderr.contains("memory-limit") && stderr.contains("96 MiB"),
        "{stderr}"
    );

    // The second frame declares more than the first: checked too.
    let out = run("two.zst", &[small.clone(), big.clone()].concat(), "8M");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(6), "stderr: {stderr}");
    assert!(stderr.contains("96 MiB"), "{stderr}");
    let out = run("two-ok.zst", &[small.clone(), big].concat(), "100M");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"first-second");

    let out = run("over-cap.zst", &over_cap, "64G");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(6), "stderr: {stderr}");
    assert!(
        stderr.contains("c-backed") && !stderr.contains("corrupt"),
        "{stderr}"
    );
}

/// T13 (2026-10-31 audit): the C-tier zstd decoder honours `--memory-limit`
/// too, through libzstd's `ZSTD_d_windowLogMax` (the largest power of two
/// within the limit), on every frame; the refusal is exit 6, not "corrupt".
/// A large limit raises the cap above libzstd's default 128 MiB.
#[cfg(feature = "zstd-c")]
#[test]
fn c_zstd_refuses_a_window_over_the_memory_limit_on_every_frame() {
    let dir = tmp("zstd-c-window");
    std::fs::create_dir_all(&dir).unwrap();
    let small = raw_zstd_frame(10 << 3, b"first-"); // 1 MiB window
    let big = raw_zstd_frame((16 << 3) | 4, b"second"); // 96 MiB window
    let over_default = raw_zstd_frame((17 << 3) | 1, b"third"); // 144 MiB window

    let run = |name: &str, bytes: &[u8], limit: &str| {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        Command::new(STUFFR)
            .args(["cat", path.to_str().unwrap(), "--memory-limit", limit])
            .output()
            .unwrap()
    };

    let out = run("small.zst", &small, "1M");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"first-");

    let out = run("big.zst", &big, "1M");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(6), "stderr: {stderr}");
    assert!(
        stderr.contains("memory-limit") && !stderr.contains("corrupt"),
        "{stderr}"
    );

    // The second frame declares more than the first: bounded too.
    let out = run("two.zst", &[small.clone(), big.clone()].concat(), "8M");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(6), "stderr: {stderr}");
    let out = run("two-ok.zst", &[small, big].concat(), "128M");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"first-second");

    // Above libzstd's default cap, decodable under a large enough limit.
    let out = run("over-default.zst", &over_default, "256M");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"third");
}

/// `--memory-limit` is now ACCEPTED and honoured on the entry-aware paths,
/// where it used to be refused at exit 2 with "not yet honoured for a
/// container". Raising it past the declaration lets the crafted archive
/// through, which is the proof the flag actually reaches the decoder rather
/// than being parsed and dropped.
#[test]
fn memory_limit_is_honoured_rather_than_refused_on_the_container_path() {
    let (_legit, crafted, _dir) = craft_a_tar_lz_declaring_a_huge_dictionary("c1-flag");
    let path = crafted.to_str().unwrap();

    for args in [
        vec!["list", path, "--memory-limit", "1G"],
        vec!["test", path, "--memory-limit", "1G"],
        vec!["cat", path, "a.txt", "--memory-limit", "1G"],
    ] {
        let out = Command::new(STUFFR).args(&args).output().unwrap();
        assert!(
            out.status.success(),
            "`stuffr {}` must succeed once the limit is raised past the declaration; \
             stderr: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let dest = tmp("c1-flag-dest");
    let _ = std::fs::remove_dir_all(&dest);
    let out = Command::new(STUFFR)
        .args([
            "unpack",
            path,
            "-C",
            dest.to_str().unwrap(),
            "--memory-limit",
            "1G",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "unpack -C must accept --memory-limit rather than refusing it; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The Phase 2 final review's I1, end to end.
///
/// `sub/top -> ..` points at the extraction root. bsdtar and GNU tar both
/// extract it; stuffr aborted the whole extraction at exit 7 with "unsafe
/// entry path `sub/..` refused: path traversal nets back to the
/// destination" — naming a path that is not an entry in the archive, so the
/// user could not find it. `dest` is inside `dest`; there is no escape here.
#[test]
fn a_symlink_pointing_at_the_extraction_root_is_extracted_not_refused() {
    let dir = tmp_dir();
    let dest = dir.join("out");
    let archive = write_raw_tar(
        &dir.join("root-link.tar"),
        &[
            Raw::Dir("sub"),
            Raw::Symlink("sub/top", ".."),
            Raw::File("sub/a.txt", b"alpha"),
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
        "a symlink netting to the destination is contained, not an escape; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let link = dest.join("sub/top");
    assert!(
        std::fs::symlink_metadata(&link).is_ok(),
        "the symlink must have been created"
    );
    assert_eq!(std::fs::read_link(&link).unwrap(), Path::new(".."));
    assert!(dest.join("sub/a.txt").exists(), "extraction must not abort");
}

/// The regression guard for the test above: one step further out is still
/// an escape, and must still exit 7 — naming the ENTRY since the 0.10.1
/// final review's F2 (it named the target text, which `list` never shows).
#[test]
fn a_symlink_one_step_past_the_extraction_root_is_still_refused() {
    for (tag, target) in [
        ("i1-two-up", "../.."),
        ("i1-deep", "../../../etc"),
        ("i1-mixed", "../sub/../.."),
    ] {
        let dir = tmp_dir();
        let dest = dir.join(tag);
        let archive = write_raw_tar(
            &dir.join(format!("{tag}.tar")),
            &[Raw::Dir("sub"), Raw::Symlink("sub/top", target)],
        );
        let out = run_output(&[
            "unpack",
            archive.to_str().unwrap(),
            "-C",
            dest.to_str().unwrap(),
        ]);
        assert_eq!(
            out.status.code(),
            Some(7),
            "`{target}` escapes and must still be refused, stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(
            stderr.contains("unsafe entry path `sub/top` refused"),
            "the refusal must name the entry `sub/top`, got: {stderr}"
        );
        assert!(
            std::fs::symlink_metadata(dest.join("sub/top")).is_err(),
            "the symlink must not have been created"
        );
    }
}

/// 0.10.1 final review, Important 1, with the user's ruling: a `..` after a
/// name in a symlink target is SKIPPED, not refused. GNU tar's `--transform`
/// applies to symlink targets by default, so `--transform 's,^,pkg-1.0/,'`
/// over `bin/foo -> ../lib/foo` stores `pkg-1.0/bin/foo ->
/// pkg-1.0/../lib/foo`. 0.10.0 and GNU tar extract that archive; the first
/// 0.10.1 build aborted at exit 7 with only `pkg-1.0/bin/` written. Now:
/// exit 0, `lib/foo` extracted, one named skip; exit 4 under
/// `--strict-fidelity`, with the same tree on disk.
#[cfg(unix)]
#[test]
fn a_gnu_tar_transform_rewritten_symlink_target_is_skipped_not_fatal() {
    let gtar = require_gnu_tar();
    let dir = tmp_dir();
    let tree = dir.join("tree");
    std::fs::create_dir_all(tree.join("bin")).unwrap();
    std::fs::create_dir_all(tree.join("lib")).unwrap();
    std::fs::write(tree.join("lib/foo"), b"lib-bytes").unwrap();
    std::os::unix::fs::symlink("../lib/foo", tree.join("bin/foo")).unwrap();
    let archive = dir.join("pkg.tar");
    let made = Command::new(&gtar)
        .args([
            "-cf",
            archive.to_str().unwrap(),
            "--transform",
            "s,^,pkg-1.0/,",
            "-C",
        ])
        .arg(&tree)
        .args(["bin", "lib"])
        .output()
        .unwrap();
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    // The premise: GNU tar really did rewrite the target.
    let listed = Command::new(&gtar)
        .args(["-tvf", archive.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&listed.stdout).contains("pkg-1.0/bin/foo -> pkg-1.0/../lib/foo"),
        "{}",
        String::from_utf8_lossy(&listed.stdout)
    );

    for (strict, code) in [(false, 0), (true, 4)] {
        let dest = dir.join(if strict { "strict" } else { "plain" });
        let mut args = vec![
            "unpack",
            archive.to_str().unwrap(),
            "-C",
            dest.to_str().unwrap(),
        ];
        if strict {
            args.push("--strict-fidelity");
        }
        let out = run_output(&args);
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert_eq!(
            out.status.code(),
            Some(code),
            "strict={strict}, stderr: {stderr}"
        );
        assert_eq!(
            std::fs::read(dest.join("pkg-1.0/lib/foo")).unwrap(),
            b"lib-bytes",
            "strict={strict}: extraction continues past the skip"
        );
        assert!(
            std::fs::symlink_metadata(dest.join("pkg-1.0/bin/foo")).is_err(),
            "strict={strict}: the skipped link is not created"
        );
        assert_eq!(
            stderr
                .matches(
                    "skipped entry `pkg-1.0/bin/foo`: symlink target uses `..` after a name, \
                     which can climb out through another link"
                )
                .count(),
            1,
            "strict={strict}: one named skip, stderr: {stderr}"
        );
    }
}

/// The Phase 2 final review's I2, across the third dimension round 3
/// missed: container × WRAPPED-IN-A-CODEC × source shape.
///
/// `fidelity_is_knowable_without_opening` returned `true` as soon as the
/// rung was authoritative — but the rung is the RAW INPUT's seekability,
/// which says nothing about a container reached through a decoder.
/// `bundle.zip.gz` on disk is a seekable file, so `info` printed
/// `rung: exact / fidelity: nothing approximated`, while `stuffr test
/// bundle.zip.gz --strict-fidelity` on the same bytes reported
/// `TrailingIndexUnread` and `EntryCountUnknown` and exited 4.
///
/// Every cell is checked against ground truth from `test`, which actually
/// opens the archive — so the assertions cannot drift into merely agreeing
/// with the predicate.
///
/// The wrapper is xz, not gzip: since the T10 review's I1 a gzip layer
/// withholds the claim by itself (it judges its trailing bytes only at the
/// end of the stream — see
/// `info_withholds_the_claim_for_a_codec_that_judges_its_trailing_bytes`), so
/// a gzip wrapper would hide the container × rung rule this test is about.
#[test]
fn info_does_not_claim_nothing_was_approximated_for_a_container_under_a_codec() {
    let dir = tmp("info-codec-wrapped-matrix");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let one = dir.join("one.txt");
    std::fs::write(&one, b"payload").unwrap();

    for (ext, has_trailing_index) in [("zip", true), ("tar", false), ("cpio", false), ("a", false)]
    {
        let bare = dir.join(format!("bundle.{ext}"));
        assert!(
            Command::new(STUFFR)
                .args(["pack", one.to_str().unwrap(), "-o", bare.to_str().unwrap()])
                .status()
                .unwrap()
                .success(),
            "packing a .{ext} must succeed"
        );
        // Two steps here on purpose, not because one is impossible: since
        // Phase 2c `-o bundle.tar.gz` composes both layers in a single
        // command. What this test needs is a codec wrapped around an
        // ALREADY-WRITTEN container file, so that `info` sees a codec whose
        // inner layer it must resolve — and packing the container first is
        // the clearest way to get exactly that byte sequence.
        assert!(
            Command::new(STUFFR)
                .args(["pack", bare.to_str().unwrap(), "--format", "xz", "--force"])
                .status()
                .unwrap()
                .success(),
            "wrapping the .{ext} in xz must succeed"
        );
        let wrapped = dir.join(format!("bundle.{ext}.xz"));
        let bytes = std::fs::read(&wrapped).unwrap();

        // Ground truth first, from the verb that opens the archive. Since
        // ruling B2 a zip read forward checks its central directory at the
        // end, so a zip whose index agrees loses nothing even under a codec;
        // what a forward read CAN lose is shown by a cloaked one, whose
        // disagreement only that end-of-stream read finds. So the zip leg
        // compresses a cloaked copy. info sees neither far and withholds for both.
        if has_trailing_index {
            let clean = std::fs::read(&bare).unwrap();
            std::fs::write(&bare, cloak_first_local_name(&clean)).unwrap();
            assert!(
                Command::new(STUFFR)
                    .args(["pack", bare.to_str().unwrap(), "--format", "xz", "--force"])
                    .status()
                    .unwrap()
                    .success()
            );
            std::fs::write(&bare, clean).unwrap();
        }
        let strict = Command::new(STUFFR)
            .args(["test", wrapped.to_str().unwrap(), "--strict-fidelity"])
            .output()
            .unwrap();
        let strict_err = String::from_utf8_lossy(&strict.stderr).to_string();
        let really_loses = !strict.status.success();
        assert_eq!(
            really_loses, has_trailing_index,
            ".{ext}.xz: only a trailing index can be missed by a forward read; \
             stderr: {strict_err}"
        );

        // (a) A SEEKABLE FILE, where the path's extensions name the whole
        //     chain (`bundle.zip.xz` -> zip over xz). This is the cell
        //     I2 reported: `rung: exact`, because the FILE is seekable,
        //     over a container that is not read from that file at all.
        let text = String::from_utf8(
            Command::new(STUFFR)
                .args(["info", wrapped.to_str().unwrap()])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        assert!(
            text.contains("exact"),
            ".{ext}.xz from a file: the rung is real and unchanged: {text}"
        );
        assert!(
            text.contains(ext),
            ".{ext}.xz from a file must resolve the whole chain: {text}"
        );
        if has_trailing_index {
            assert!(
                text.contains("not evaluated"),
                ".{ext}.xz from a file: the zip is read out of an xz decoder, which is \
                 forward-only however seekable the FILE is — `test` on these very bytes \
                 exits 4. info has not looked and must not claim: {text}"
            );
            assert!(!text.contains("nothing approximated"), "{text}");
        } else {
            assert!(
                text.contains("nothing approximated"),
                ".{ext}.xz from a file carries every entry's metadata inline, so a forward \
                 read loses nothing — withholding here would be a false negative, the \
                 round-3 defect repeating: {text}"
            );
            assert!(!text.contains("not evaluated"), "{text}");
        }

        // (b) A PIPE with no path. `inspect` resolves the chain with the
        //     SHALLOW `resolve_chain` — it identifies a stream without
        //     decoding it, and seeing the zip inside would mean running the
        //     xz decoder. With no path to read extensions from, there is
        //     nothing to name the inner layer, so the chain bottoms out at
        //     the codec and `info` reports on the codec alone. That is a
        //     documented limit of `info`, not the I2 defect: the claim it
        //     makes is about what it identified. Pinned so the two cells
        //     cannot be confused for one another later.
        let text = info_over_stdin(&bytes);
        assert!(text.contains("forward-only"), ".{ext}.xz on a pipe: {text}");
        assert!(
            text.contains("chain:    xz"),
            ".{ext}.xz on a pipe resolves to the codec alone — info does not decode to \
             look inside: {text}"
        );

        // And the codec-wrapped verdict must not have leaked onto the BARE
        // container: a seekable bare zip still reads its central directory.
        let text = String::from_utf8(
            Command::new(STUFFR)
                .args(["info", bare.to_str().unwrap()])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        assert!(
            text.contains("nothing approximated"),
            "a bare seekable .{ext} is unaffected by the codec-wrapped rule: {text}"
        );
    }
}

/// The Phase 2 final review's I3: `entries::test` built no `ArchiveBudget`
/// at all, so a 204 KB zip holding one 200 MB entry verified clean at exit
/// 0 under `--max-ratio 10` while `cat` and `unpack` of the identical file
/// refused it at exit 6. `test` is the verb reached for to inspect an
/// UNTRUSTED archive; it must not be the only unbounded one.
#[test]
fn every_entry_aware_verb_applies_the_same_expansion_bound() {
    let dir = tmp_dir();
    // Highly compressible, and large enough that a ratio of 10 cannot cover
    // it while staying quick to build.
    let payload = vec![0u8; 8 * 1024 * 1024];
    let big = dir.join("big.bin");
    std::fs::write(&big, &payload).unwrap();
    let bomb = dir.join("bomb.zip");
    assert!(
        Command::new(STUFFR)
            .args(["pack", big.to_str().unwrap(), "-o", bomb.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    let compressed = std::fs::metadata(&bomb).unwrap().len();
    assert!(
        compressed * 10 < payload.len() as u64,
        "the fixture must actually exceed a ratio of 10 ({compressed} compressed)"
    );

    let dest = dir.join("out");
    for args in [
        vec!["test", bomb.to_str().unwrap(), "--max-ratio", "10"],
        vec![
            "cat",
            bomb.to_str().unwrap(),
            "big.bin",
            "--max-ratio",
            "10",
        ],
        vec![
            "unpack",
            bomb.to_str().unwrap(),
            "-C",
            dest.to_str().unwrap(),
            "--max-ratio",
            "10",
        ],
    ] {
        let out = Command::new(STUFFR).args(&args).output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(6),
            "`stuffr {}` must refuse the same bomb the other verbs refuse; stderr: {}",
            args[0],
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // The other half: the default ratio still lets the same archive through
    // on all three, so the new bound is not simply refusing everything.
    let _ = std::fs::remove_dir_all(&dest);
    for args in [
        vec!["test", bomb.to_str().unwrap()],
        vec!["cat", bomb.to_str().unwrap(), "big.bin"],
        vec![
            "unpack",
            bomb.to_str().unwrap(),
            "-C",
            dest.to_str().unwrap(),
        ],
    ] {
        let out = Command::new(STUFFR).args(&args).output().unwrap();
        assert!(
            out.status.success(),
            "`stuffr {}` must still accept a legitimate archive under the default ratio; \
             stderr: {}",
            args[0],
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// The Phase 2 re-review's second finding: the pipe path refused every real
/// archive.
///
/// `ArchiveBudget::ceiling` returned a flat `RATIO_FLOOR` (1 MiB) whenever
/// the compressed total was unknown, which is always true of a pipe — so
/// `cat photos.zip | stuffr test -` refused any archive over a megabyte, and
/// `--max-ratio`, the flag the refusal names, could not raise it. The
/// examples page documents that exact invocation. `test` acquired the defect
/// when it gained a budget; `cat` and `unpack -C` had carried it since the
/// budget was introduced.
///
/// The fix gives the ratio a denominator on a pipe: bytes actually pulled so
/// far, which `open_archive`'s `Counting` wrapper already tallies. All three
/// assertions below are needed — one that a real archive passes, one that a
/// bomb is still refused, and one that raising the flag now changes the
/// outcome, which is what proves the flag reaches this path at all.
#[test]
fn a_piped_archive_larger_than_the_ratio_floor_is_not_refused() {
    let dir = tmp_dir();
    // Incompressible, so no codec layer can mask the size, and comfortably
    // past the 1 MiB floor.
    let payload: Vec<u8> = (0..3u32 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let src = dir.join("big.bin");
    std::fs::write(&src, &payload).unwrap();
    let archive = dir.join("big.tar");
    assert!(
        Command::new(STUFFR)
            .args([
                "pack",
                src.to_str().unwrap(),
                "-o",
                archive.to_str().unwrap()
            ])
            .status()
            .unwrap()
            .success()
    );
    let bytes = std::fs::read(&archive).unwrap();
    assert!(
        bytes.len() as u64 > stuffr::RATIO_FLOOR,
        "the fixture must exceed the floor or this test proves nothing"
    );

    // Feed stdin from a THREAD, never inline. `stuffr cat - big.bin` writes
    // the 3 MB entry straight back to stdout, and an inline `write_all` here
    // deadlocks the moment that fills the 64 KB pipe buffer: the child blocks
    // writing stdout while this process blocks writing stdin, and neither
    // moves. `wait_with_output` drains stdout and stderr concurrently, so the
    // writer only needs to be off this thread. (Learned the hard way — this
    // hung the gate for 26 minutes.)
    let piped = |args: &[&str], input: &[u8]| {
        let mut child = Command::new(STUFFR)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut sin = child.stdin.take().unwrap();
        let data = input.to_vec();
        // A refusal closes the pipe early, so a broken pipe is an expected
        // outcome here rather than a test failure.
        let writer = std::thread::spawn(move || {
            let _ = sin.write_all(&data);
        });
        let out = child.wait_with_output().unwrap();
        writer.join().unwrap();
        out
    };

    let dest = dir.join("out");
    for args in [
        vec!["test", "-"],
        vec!["cat", "-", "big.bin"],
        vec!["unpack", "-", "-C", dest.to_str().unwrap()],
    ] {
        let out = piped(&args, &bytes);
        assert!(
            out.status.success(),
            "`stuffr {}` over a pipe must not refuse a {}-byte archive; stderr: {}",
            args.join(" "),
            bytes.len(),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // The bound is still real over a pipe. Same fixture shape as
    // `every_entry_aware_verb_applies_the_same_expansion_bound`, piped.
    let zeros = vec![0u8; 8 * 1024 * 1024];
    let zsrc = dir.join("zeros.bin");
    std::fs::write(&zsrc, &zeros).unwrap();
    let bomb = dir.join("bomb.zip");
    assert!(
        Command::new(STUFFR)
            .args(["pack", zsrc.to_str().unwrap(), "-o", bomb.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    let bomb_bytes = std::fs::read(&bomb).unwrap();

    let piped_test = |extra: &[&str]| {
        let mut argv = vec!["test", "-"];
        argv.extend_from_slice(extra);
        piped(&argv, &bomb_bytes)
    };

    assert_eq!(
        piped_test(&["--max-ratio", "10"]).status.code(),
        Some(6),
        "a bomb piped in must still be refused"
    );
    assert!(
        piped_test(&["--max-ratio", "100000"]).status.success(),
        "raising --max-ratio must change the outcome on a pipe — that is what \
         proves the flag reaches this path rather than being parsed and dropped"
    );
}

/// The Phase 2 final review's I6, at the exit-code boundary a user sees.
///
/// A valid `odc` cpio archive reported `archive is corrupt: Invalid magic
/// number` at exit 5 — telling the user their intact file was damaged.
#[test]
fn a_valid_odc_cpio_archive_reports_a_capability_limit_not_corruption() {
    let dir = tmp_dir();
    // A real `newc` archive with only its magic rewritten to odc's, so the
    // classification is provably decided on the magic. `cpio.rs`'s own
    // `a_real_odc_archive_from_system_cpio_is_unsupported_not_corrupt`
    // proves that magic is what the reference tool actually emits.
    let src = dir.join("f.txt");
    std::fs::write(&src, b"payload").unwrap();
    let newc = dir.join("archive.cpio");
    assert!(
        Command::new(STUFFR)
            .args(["pack", src.to_str().unwrap(), "-o", newc.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    let mut bytes = std::fs::read(&newc).unwrap();
    assert_eq!(&bytes[..6], b"070701");
    bytes[..6].copy_from_slice(b"070707");
    let odc = dir.join("odc.cpio");
    std::fs::write(&odc, &bytes).unwrap();

    let out = Command::new(STUFFR)
        .args(["list", odc.to_str().unwrap()])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(
        out.status.code(),
        Some(3),
        "an intact archive in an unreadable variant is a capability limit, \
         not damage; stderr: {stderr}"
    );
    assert!(
        stderr.contains("odc"),
        "the message must name the variant: {stderr}"
    );
    assert!(
        !stderr.contains("corrupt"),
        "the message must not suggest damage: {stderr}"
    );

    // The neighbour it must not have swallowed: a genuinely damaged newc
    // archive is still exit 5.
    let mut broken = std::fs::read(&newc).unwrap();
    broken.truncate(30);
    let cut = dir.join("cut.cpio");
    std::fs::write(&cut, &broken).unwrap();
    let out = Command::new(STUFFR)
        .args(["list", cut.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(5),
        "a truncated archive really is damaged; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// "You pointed the verb at the wrong file" must be ONE exit code.
///
/// `stuffr list plain.txt.gz` (a codec stream, `NotAnArchive`) exited 2
/// while `stuffr list plain.txt` (no format at all, `UnknownFormat`) exited
/// 1 — an internal failure — for the same class of mistake.
#[test]
fn pointing_a_verb_at_the_wrong_file_always_exits_two() {
    let dir = tmp_dir();

    let plain = dir.join("plain.txt");
    std::fs::write(&plain, b"just some text, no format at all").unwrap();
    let gz = dir.join("plain.txt.gz");
    assert!(
        Command::new(STUFFR)
            .args([
                "pack",
                plain.to_str().unwrap(),
                "--format",
                "gzip",
                "-o",
                gz.to_str().unwrap()
            ])
            .status()
            .unwrap()
            .success()
    );

    for (label, path) in [
        ("a codec stream, which is not an archive", &gz),
        ("a file of no recognised format", &plain),
    ] {
        let out = Command::new(STUFFR)
            .args(["list", path.to_str().unwrap()])
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "{label}: both are the caller pointing `list` at the wrong file, \
             so both are exit 2; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// The Phase 2 final review's I5: three multi-line string literals in
/// `main.rs` had been collapsed with their continuation indentation left
/// in, so users saw runs of 22-30 spaces mid-sentence:
///
/// ```text
/// stuffr: usage error: packing 2 paths needs an output naming a container
/// (`-o bundle.tar`,                      or --format tar); a codec …
/// ```
///
/// All three were on new container paths and nothing asserted on any of
/// them. Asserted structurally rather than by exact text, so rewording a
/// message does not break the test but re-introducing the defect does.
///
/// These three cases are RENDERED evidence — real stderr from a real process —
/// and they are deliberately kept, but they are no longer the guard: three
/// hardcoded invocations could not cover a message a later task adds, and in
/// Phase 2c exactly that happened. See
/// `no_message_literal_in_the_workspace_carries_a_run_of_collapsed_indentation`
/// for the enumeration nothing can escape.
#[test]
fn no_cli_message_contains_a_run_of_collapsed_indentation() {
    let dir = tmp_dir();
    let a = dir.join("a.txt");
    let b = dir.join("b.txt");
    std::fs::write(&a, b"alpha").unwrap();
    std::fs::write(&b, b"beta").unwrap();
    let archive = write_fixture_tar(&dir, &[("x.txt", b"x")]);

    let cases: Vec<Vec<String>> = vec![
        // "packing N paths needs an output naming a container…"
        vec![
            "pack".into(),
            a.to_str().unwrap().into(),
            b.to_str().unwrap().into(),
        ],
        // "collecting several paths into an archive needs an explicit -o…"
        vec![
            "pack".into(),
            a.to_str().unwrap().into(),
            b.to_str().unwrap().into(),
            "--format".into(),
            "tar".into(),
        ],
        // "`x.txt` names an archive entry; pass -C DIR…"
        vec![
            "unpack".into(),
            archive.to_str().unwrap().into(),
            "x.txt".into(),
        ],
    ];

    for args in cases {
        let out = Command::new(STUFFR).args(&args).output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert_eq!(
            out.status.code(),
            Some(2),
            "`stuffr {}` must be a usage error; stderr: {stderr}",
            args.join(" ")
        );
        assert!(
            !stderr.contains("   "),
            "a CLI message must not carry a run of collapsed continuation \
             indentation; `stuffr {}` printed: {stderr:?}",
            args.join(" ")
        );
        assert!(
            !stderr.trim().is_empty(),
            "and it must actually say something: {stderr:?}"
        );
    }

    // The exact shape of the worst one, pinned so a reworded message that
    // re-collapses is still caught by a human reading the failure.
    let out = Command::new(STUFFR)
        .args(["pack", a.to_str().unwrap(), b.to_str().unwrap()])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        stderr.contains("`-o bundle.tar`, or --format tar"),
        "the phrase either side of the old collapse must read as one sentence: {stderr:?}"
    );
}

/// The Phase 2c headline: a container over a codec, written in one step.
///
/// The trailer is checked with the SYSTEM tool, not our own reader. The whole
/// bug this phase fixes is a codec trailer that never got written, and our own
/// decoder may be lenient about a missing one — so asserting with `stuffr
/// list` could pass against the very defect under repair.
#[test]
fn a_container_over_a_codec_is_written_in_one_step() {
    let dir = tmp_dir();
    let src = dir.join("notes.txt");
    std::fs::write(&src, b"hello from inside the tar\n").unwrap();
    let out = dir.join("bundle.tar.gz");

    let st = Command::new(STUFFR)
        .args(["pack", src.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );

    // 1. It really is gzip, and the trailer is intact: `gunzip -t` verifies
    //    the CRC32 and ISIZE that the old code never wrote.
    let t = Command::new("gunzip")
        .args(["-t", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        t.status.success(),
        "gunzip -t rejected it: {}",
        String::from_utf8_lossy(&t.stderr)
    );

    // 2. It really is a tar inside, per the system tar.
    let l = Command::new("tar")
        .args(["tzf", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        l.status.success(),
        "tar tzf failed: {}",
        String::from_utf8_lossy(&l.stderr)
    );
    assert!(String::from_utf8_lossy(&l.stdout).contains("notes.txt"));

    // 3. And stuffr reads back what it wrote.
    let r = Command::new(STUFFR)
        .args(["list", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(r.status.success());
    assert!(String::from_utf8_lossy(&r.stdout).contains("notes.txt"));
}

/// v0.2.0 wrote the wrong format, silently, in three different ways. Each
/// line here failed against that binary.
#[test]
fn a_dot_tar_dot_gz_output_is_never_silently_the_wrong_format() {
    let dir = tmp_dir();
    let src = dir.join("notes.txt");
    std::fs::write(&src, b"payload\n").unwrap();

    // Every spelling that means "tar inside gzip".
    for (name, extra) in [
        ("a.tar.gz", vec![]),
        ("b.tgz", vec![]),
        ("c.tar.gz", vec!["--format", "tar"]),
    ] {
        let out = dir.join(name);
        let mut args = vec!["pack", src.to_str().unwrap(), "-o", out.to_str().unwrap()];
        args.extend(extra);
        let st = Command::new(STUFFR).args(&args).output().unwrap();
        assert!(
            st.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&st.stderr)
        );

        // Must be gzip with a valid trailer...
        let t = Command::new("gunzip")
            .args(["-t", out.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            t.status.success(),
            "{name} is not valid gzip: {}",
            String::from_utf8_lossy(&t.stderr)
        );
        // ...and a tar inside. v0.2.0 produced one or the other, never both.
        let l = Command::new("tar")
            .args(["tzf", out.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            l.status.success(),
            "{name} has no tar inside: {}",
            String::from_utf8_lossy(&l.stderr)
        );
        assert!(
            String::from_utf8_lossy(&l.stdout).contains("notes.txt"),
            "{name}"
        );
    }
}

/// The neighbours must not regress: a codec-only output still takes the
/// single-stream path, and a container-only output still takes the bare path.
#[test]
fn a_codec_only_or_container_only_output_is_unaffected() {
    let dir = tmp_dir();
    let src = dir.join("notes.txt");
    std::fs::write(&src, b"payload\n").unwrap();

    let gz = dir.join("plain.gz");
    assert!(
        Command::new(STUFFR)
            .args(["pack", src.to_str().unwrap(), "-o", gz.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    // A bare codec output is NOT a tar — decompressing gives the file itself.
    let out = Command::new("gunzip")
        .args(["-c", gz.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.stdout, b"payload\n");

    let tar = dir.join("plain.tar");
    assert!(
        Command::new(STUFFR)
            .args(["pack", src.to_str().unwrap(), "-o", tar.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    let l = Command::new("tar")
        .args(["tf", tar.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&l.stdout).contains("notes.txt"));
}

/// A zip inside a codec: the shape that would have shown the stray
/// `flush_destination` in `ZipWrite::finish`, which emitted a `Z_SYNC_FLUSH`
/// empty stored block into the gzip stream before the trailer. And a bare
/// zip must still round-trip after that call was removed.
#[test]
fn a_zip_round_trips_bare_and_inside_a_codec() {
    let dir = tmp_dir();
    let src = dir.join("notes.txt");
    std::fs::write(&src, b"zip payload\n").unwrap();

    for name in ["bare.zip", "wrapped.zip.gz"] {
        let out = dir.join(name);
        let st = Command::new(STUFFR)
            .args(["pack", src.to_str().unwrap(), "-o", out.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            st.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&st.stderr)
        );
        if name.ends_with(".gz") {
            let t = Command::new("gunzip")
                .args(["-t", out.to_str().unwrap()])
                .output()
                .unwrap();
            assert!(
                t.status.success(),
                "{name} is not valid gzip: {}",
                String::from_utf8_lossy(&t.stderr)
            );
        }
        let r = Command::new(STUFFR)
            .args(["list", out.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            r.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&r.stderr)
        );
        assert!(
            String::from_utf8_lossy(&r.stdout).contains("notes.txt"),
            "{name}"
        );
    }
}

/// `--format` and the output's own name are two sources of truth about the
/// container, and they can disagree. Writing the file anyway is worse than
/// refusing: the bytes are valid gzip, so `pack` exits 0 and `list` on the
/// very same path then exits 5 — stuffr calling its own output corrupt, at
/// the exit code that publicly means "these bytes are damaged".
///
/// Measured at the commit that introduced composition:
/// `pack notes.txt --format zip -o x.tar.gz` wrote a zip inside gzip under a
/// `.tar.gz` name, `stuffr info` reported "tar over gzip", and `stuffr list`
/// exited 5.
#[test]
fn a_format_flag_contradicting_the_output_name_is_refused_before_anything_is_written() {
    let dir = tmp_dir();
    let src = dir.join("notes.txt");
    std::fs::write(&src, b"payload\n").unwrap();

    for (fmt, name) in [
        ("zip", "x.tar.gz"),
        ("tar", "x.zip.gz"),
        ("tar", "x.cpio"),
        ("cpio", "x.tgz"),
    ] {
        let out = dir.join(name);
        let o = Command::new(STUFFR)
            .args([
                "pack",
                src.to_str().unwrap(),
                "--format",
                fmt,
                "-o",
                out.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert_eq!(
            o.status.code(),
            Some(2),
            "--format {fmt} -o {name} must be a usage error, not a written file"
        );
        let stderr = String::from_utf8_lossy(&o.stderr).to_string();
        assert!(
            stderr.contains(fmt) && stderr.contains(name),
            "the message must name both sides of the contradiction: {stderr:?}"
        );
        // "before anything is written" is the whole point of exit 2 here.
        assert!(!out.exists(), "--format {fmt} -o {name} left a file behind");
    }

    // The agreeing spellings are untouched, including the one where the name
    // carries only a codec and --format supplies the container.
    for (fmt, name) in [("tar", "ok.tar.gz"), ("tar", "ok.gz"), ("zip", "ok.zip.gz")] {
        let out = dir.join(name);
        let o = Command::new(STUFFR)
            .args([
                "pack",
                src.to_str().unwrap(),
                "--format",
                fmt,
                "-o",
                out.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            o.status.success(),
            "--format {fmt} -o {name} must still work: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        let l = Command::new(STUFFR)
            .args(["list", out.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            l.status.success(),
            "stuffr must be able to read back what it wrote to {name}: {}",
            String::from_utf8_lossy(&l.stderr)
        );
        assert!(
            String::from_utf8_lossy(&l.stdout).contains("notes.txt"),
            "{name}"
        );
    }
}

/// Phase 2c used to hardcode the composed path's governor to `None`
/// specifically so `STUFFR_THREADS` could not succeed at what `--threads`
/// was refused for (no container compressed anything itself, so there was
/// genuinely nothing to hand a worker count to). Now that
/// `refuse_unhonoured_encoder_flags` only refuses these where the resolved
/// chain has NO codec layer, `-o out.tar.xz` names a real codec underneath
/// the container, and `entries::create_archive` builds its governor from
/// `ops::resolved_budget(o)` exactly as the single-stream path does —
/// which means `STUFFR_THREADS` is consulted here now, precisely because
/// `--threads` is honoured here now. The two must not drift apart again.
///
/// This is the reproducibility promise working the other way: a
/// multi-threaded xz encode splits the input per worker, so the same input
/// and the same flags now produce DIFFERENT bytes under a different
/// `STUFFR_THREADS` — where before the fix they were, wrongly, identical.
#[test]
fn the_composed_path_honours_stuffr_threads_now_that_a_codec_is_present() {
    let dir = tmp_dir();
    let src = dir.join("big.txt");
    // Compressible but not trivially so, and large enough that xz would
    // really split it across workers.
    let mut data = Vec::with_capacity(4 << 20);
    let mut x: u32 = 0x1234_5678;
    while data.len() < (4 << 20) {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        data.extend_from_slice(format!("line {} of the corpus\n", x >> 16).as_bytes());
    }
    std::fs::write(&src, &data).unwrap();

    let plain = dir.join("plain.tar.xz");
    let env = dir.join("env.tar.xz");
    for (out, threads) in [(&plain, None), (&env, Some("4"))] {
        let mut cmd = Command::new(STUFFR);
        cmd.args([
            "pack",
            src.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--level",
            "1",
        ]);
        match threads {
            Some(n) => cmd.env("STUFFR_THREADS", n),
            None => cmd.env_remove("STUFFR_THREADS"),
        };
        let o = cmd.output().unwrap();
        assert!(
            o.status.success(),
            "pack failed: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    }
    assert_ne!(
        std::fs::read(&plain).unwrap(),
        std::fs::read(&env).unwrap(),
        "STUFFR_THREADS=4 must now change the bytes on a composed write with a codec \
         layer, the same way it already does on a single-stream one; identical bytes \
         here means the governor silently went back to None"
    );

    // And the flag it mirrors is honoured directly too, not just the
    // variable behind it — the two stay consistent by construction, but
    // both are worth asserting since either could regress independently.
    let flagged = Command::new(STUFFR)
        .args([
            "pack",
            src.to_str().unwrap(),
            "-o",
            dir.join("flag.tar.xz").to_str().unwrap(),
            "--threads",
            "4",
        ])
        .output()
        .unwrap();
    assert!(
        flagged.status.success(),
        "--threads must be honoured where a codec is present: {}",
        String::from_utf8_lossy(&flagged.stderr)
    );
}

/// Phase 2's minor 4 refused --threads whenever the output named a container,
/// reasoning that no container compresses anything itself. Composition makes
/// that false: `-o out.tar.xz` HAS a codec layer, and xz encodes in parallel.
#[test]
fn encoder_flags_are_refused_only_where_there_is_no_codec_to_honour_them() {
    let dir = tmp_dir();
    let src = dir.join("notes.txt");
    std::fs::write(&src, b"payload\n").unwrap();

    // Bare container: still refused, still exit 2.
    let st = Command::new(STUFFR)
        .args([
            "pack",
            src.to_str().unwrap(),
            "-o",
            dir.join("a.tar").to_str().unwrap(),
            "--threads",
            "2",
        ])
        .output()
        .unwrap();
    assert_eq!(
        st.status.code(),
        Some(2),
        "a bare container has no codec to hand threads to"
    );

    // Container over codec: accepted.
    let out = dir.join("b.tar.gz");
    let st = Command::new(STUFFR)
        .args([
            "pack",
            src.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--threads",
            "2",
        ])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "a composed write HAS a codec: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    assert!(
        Command::new("gunzip")
            .args(["-t", out.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );

    // --level likewise reaches the codec layer — and this is asserted on the
    // BYTES, not on exit 0 plus `gunzip -t`, which is what it used to be.
    // Deleting `level: o.level` from the `EncodeOpts` that
    // `entries::create_archive` builds left the old form entirely green: both
    // levels still exited 0 and both still gunzipped. The only evidence that
    // the flag reached the encoder is that the two levels produce DIFFERENT
    // output, so that is what is checked.
    //
    // A payload with real structure, not `notes.txt`'s eight bytes: gzip
    // levels are indistinguishable on input too small or too uniform for the
    // match finder's effort to matter.
    let big = dir.join("big.txt");
    let mut payload = String::new();
    for i in 0..4000 {
        payload.push_str(&format!(
            "line {i} of a log with some repeated shape {}\n",
            i % 97
        ));
    }
    std::fs::write(&big, payload.as_bytes()).unwrap();

    let mut sizes = Vec::new();
    for level in ["1", "9"] {
        let out = dir.join(format!("c{level}.tar.gz"));
        assert!(
            Command::new(STUFFR)
                .args([
                    "pack",
                    big.to_str().unwrap(),
                    "-o",
                    out.to_str().unwrap(),
                    "--level",
                    level,
                ])
                .status()
                .unwrap()
                .success(),
            "--level {level} must be accepted on a composed write"
        );
        assert!(
            Command::new("gunzip")
                .args(["-t", out.to_str().unwrap()])
                .status()
                .unwrap()
                .success(),
            "--level {level} must still produce valid gzip"
        );
        sizes.push(std::fs::metadata(&out).unwrap().len());
    }
    assert!(
        sizes[0] > sizes[1],
        "--level must reach the codec beneath the container: level 1 produced \
         {} bytes and level 9 produced {} — equal sizes mean the flag was \
         accepted and dropped",
        sizes[0],
        sizes[1]
    );

    // And the single-stream codec path is untouched.
    assert!(
        Command::new(STUFFR)
            .args([
                "pack",
                src.to_str().unwrap(),
                "-o",
                dir.join("d.gz").to_str().unwrap(),
                "--threads",
                "2",
            ])
            .status()
            .unwrap()
            .success()
    );
}

// ---------------------------------------------------------------------
// Cloaking: a zip whose local header and central directory disagree
// (GHSA-m665-v7pm-7grj). A warning, exit 4 under --strict-fidelity.
// ---------------------------------------------------------------------

#[test]
fn a_cloaked_zip_file_warns_and_exits_4_under_strict() {
    let dir = tmp_dir();
    let clean = write_zip_via_pack(&dir, &[("a.txt", b"alpha")]);
    let mut bytes = std::fs::read(&clean).unwrap();
    assert_eq!(&bytes[..4], b"PK\x03\x04");
    let name_len = usize::from(u16::from_le_bytes([bytes[26], bytes[27]]));
    let central_name = String::from_utf8(bytes[30..30 + name_len].to_vec()).unwrap();
    // The last byte of the LOCAL name only; the central record keeps it.
    bytes[30 + name_len - 1] ^= 0x20;
    let cloaked = dir.join("cloaked.zip");
    std::fs::write(&cloaked, &bytes).unwrap();

    let out = run_output(&["test", cloaked.to_str().unwrap()]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("local header and central directory disagree on name")
            && stderr.contains(&central_name),
        "the warning must name the field and the entry: {stderr}"
    );

    let strict = run_output(&["test", cloaked.to_str().unwrap(), "--strict-fidelity"]);
    assert_eq!(
        strict.status.code(),
        Some(4),
        "stderr: {}",
        String::from_utf8_lossy(&strict.stderr)
    );

    // The untouched archive passes strict mode, so it is the cloak that fails.
    let clean_strict = run_output(&["test", clean.to_str().unwrap(), "--strict-fidelity"]);
    assert_eq!(
        clean_strict.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&clean_strict.stderr)
    );
}

/// Ruling B2, over a pipe: the forward reader reads the central directory at
/// the end and compares it with the local headers it walked. A well-formed
/// piped zip now passes `--strict-fidelity` (exit 0; it was 4 in 0.22.0, a
/// deliberate change); the same bytes with one local name cloaked warn and
/// exit 4 under strict, naming the field.
#[test]
fn a_piped_zip_is_checked_against_its_central_directory() {
    let dir = tmp_dir();
    let clean = write_zip_via_pack(&dir, &[("a.txt", b"alpha"), ("b.txt", b"bravo")]);
    let bytes = std::fs::read(&clean).unwrap();

    let strict = run_with_stdin_output(&["test", "-", "--strict-fidelity"], &bytes);
    let stderr = String::from_utf8_lossy(&strict.stderr);
    assert_eq!(strict.status.code(), Some(0), "stderr: {stderr}");
    assert!(!stderr.contains("fidelity warning"), "stderr: {stderr}");

    let mut cloaked = bytes.clone();
    assert_eq!(&cloaked[..4], b"PK\x03\x04");
    let name_len = usize::from(u16::from_le_bytes([cloaked[26], cloaked[27]]));
    // The last byte of the first LOCAL name only; the central record keeps it.
    cloaked[30 + name_len - 1] ^= 0x20;
    let delivered = String::from_utf8(cloaked[30..30 + name_len].to_vec()).unwrap();

    let lenient = run_with_stdin_output(&["test", "-"], &cloaked);
    let stderr = String::from_utf8_lossy(&lenient.stderr);
    assert_eq!(lenient.status.code(), Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("local header and central directory disagree on name")
            && stderr.contains(&delivered),
        "the warning must name the field and the entry as delivered: {stderr}"
    );
    let strict = run_with_stdin_output(&["test", "-", "--strict-fidelity"], &cloaked);
    assert_eq!(
        strict.status.code(),
        Some(4),
        "stderr: {}",
        String::from_utf8_lossy(&strict.stderr)
    );
}

/// Real writers on this platform raise no header warning: Apple's Info-ZIP
/// `zip -r` (a UTF-8 name stored with bit 11 clear) and `ditto -c -k`
/// (bit 3, data descriptors, local CRC and sizes zero). Skips where the
/// tools are absent.
#[cfg(target_os = "macos")]
#[test]
fn real_tool_zips_raise_no_header_warning() {
    let dir = tmp_dir();
    let tree = dir.join("tree");
    std::fs::create_dir_all(tree.join("sub")).unwrap();
    std::fs::write(tree.join("plain.txt"), b"plain\n").unwrap();
    std::fs::write(tree.join("café 日本.txt"), b"unicode name\n").unwrap();
    std::fs::write(tree.join("sub/b.bin"), vec![7u8; 70_000]).unwrap();

    let mut made = Vec::new();
    if Path::new("/usr/bin/zip").exists() {
        let z = dir.join("infozip.zip");
        let ok = Command::new("/usr/bin/zip")
            .current_dir(&dir)
            .args(["-q", "-r", z.to_str().unwrap(), "tree"])
            .status()
            .unwrap()
            .success();
        assert!(ok, "/usr/bin/zip failed");
        made.push(z);
    } else {
        eprintln!("note: /usr/bin/zip absent; skipping its leg");
    }
    if Path::new("/usr/bin/ditto").exists() {
        let z = dir.join("ditto.zip");
        let ok = Command::new("/usr/bin/ditto")
            .args(["-c", "-k", tree.to_str().unwrap(), z.to_str().unwrap()])
            .status()
            .unwrap()
            .success();
        assert!(ok, "ditto failed");
        made.push(z);
    } else {
        eprintln!("note: /usr/bin/ditto absent; skipping its leg");
    }

    for z in made {
        for verb in ["test", "list"] {
            let out = run_output(&[verb, z.to_str().unwrap(), "--strict-fidelity"]);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_eq!(
                out.status.code(),
                Some(0),
                "{verb} {}: stderr: {stderr}",
                z.display()
            );
            assert!(
                !stderr.contains("disagree"),
                "{verb} {}: {stderr}",
                z.display()
            );
        }
    }
}

// ---------------------------------------------------------------------
// PARSE-1: what follows a verified gzip member / bzip2 stream.
// ---------------------------------------------------------------------

/// Packs `plain` with stuffr itself into `dir/name` (the extension picks the
/// codec) and returns the compressed bytes.
fn packed(dir: &Path, name: &str, plain: &[u8]) -> Vec<u8> {
    let src = dir.join(format!("{name}.in"));
    std::fs::write(&src, plain).unwrap();
    let dst = dir.join(name);
    let out = run_output(&["pack", src.to_str().unwrap(), "-o", dst.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::read(dst).unwrap()
}

/// Two members, the second's first magic byte flipped to `flip`: `unpack`
/// recovers the first, warns on stderr naming the format and the ignored
/// byte count, exits 0 without and 4 with `--strict-fidelity` — never 0
/// silently, which dropped every later member before the fix.
fn flipped_second_member_warns(ext: &str, format: &str, flip: u8) {
    let dir = tmp_dir();
    let first = b"first member\n".repeat(100);
    let a = packed(&dir, &format!("a.{ext}"), &first);
    let b = packed(
        &dir,
        &format!("b.{ext}"),
        &b"SECOND MEMBER\n".repeat(100_000),
    );
    let mut x = [a.clone(), b.clone()].concat();
    x[a.len()] = flip;
    let input = dir.join(format!("two-flip.{ext}"));
    std::fs::write(&input, &x).unwrap();

    for (strict, code) in [(false, 0), (true, 4)] {
        let output = dir.join(format!("out-{strict}"));
        let mut args = vec![
            "unpack",
            input.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
        ];
        if strict {
            args.push("--strict-fidelity");
        }
        let out = run_output(&args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(code), "strict={strict}: {stderr}");
        assert!(
            stderr.contains(&format!(
                "`{format}` stream is followed by {} byte(s)",
                b.len()
            )),
            "strict={strict}: {stderr}"
        );
        if !strict {
            assert_eq!(std::fs::read(&output).unwrap(), first);
        }
    }

    // `cat` has no --strict-fidelity; it still says what it ignored.
    let out = run_output(&["cat", input.to_str().unwrap()]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "cat: {stderr}");
    assert_eq!(out.stdout, first);
    assert!(
        stderr.contains(&format!("`{format}` stream is followed by")),
        "cat: {stderr}"
    );
}

#[test]
fn a_flipped_gzip_member_boundary_warns_and_fails_strict_fidelity() {
    flipped_second_member_warns("gz", "gzip", 0x1e);
}

#[test]
fn a_flipped_bzip2_stream_boundary_warns_and_fails_strict_fidelity() {
    flipped_second_member_warns("bz2", "bzip2", 0x41);
}

/// A tail that starts as a member header and cannot be one is corrupt.
#[test]
fn a_damaged_later_member_header_is_exit_5() {
    let dir = tmp_dir();
    let gz = packed(&dir, "a.gz", b"first");
    let bz = packed(&dir, "a.bz2", b"first");
    let mut gz_method = [gz.clone(), gz.clone()].concat();
    gz_method[gz.len() + 2] = 7;
    let mut bz_level = [bz.clone(), bz.clone()].concat();
    bz_level[bz.len() + 3] = b'0';
    let mut bz_block = [bz.clone(), bz.clone()].concat();
    bz_block[bz.len() + 5] ^= 0xff;
    let cases = [
        ("method.gz", gz_method),
        ("cut.gz", [gz.clone(), vec![0x1f]].concat()),
        ("level.bz2", bz_level),
        ("block.bz2", bz_block),
    ];
    for (name, bytes) in cases {
        let input = dir.join(name);
        std::fs::write(&input, &bytes).unwrap();
        let output = dir.join(format!("{name}.out"));
        let out = run_output(&[
            "unpack",
            input.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
        ]);
        assert_eq!(
            out.status.code(),
            Some(5),
            "{name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!output.exists(), "{name}: nothing published");
    }
}

/// NUL and `'X'` padding after the last member stays silent, strict or not.
#[test]
fn padding_after_the_last_member_passes_strict_fidelity() {
    let dir = tmp_dir();
    for ext in ["gz", "bz2"] {
        let plain = b"padded payload".repeat(20);
        let c = packed(&dir, &format!("p.{ext}"), &plain);
        for pad in [0u8, b'X'] {
            let input = dir.join(format!("pad-{pad}.{ext}"));
            std::fs::write(&input, [c.clone(), vec![pad; 512]].concat()).unwrap();
            let output = dir.join(format!("pad-{pad}-{ext}.out"));
            let out = run_output(&[
                "unpack",
                input.to_str().unwrap(),
                "-o",
                output.to_str().unwrap(),
                "--strict-fidelity",
            ]);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_eq!(out.status.code(), Some(0), "{ext} pad {pad}: {stderr}");
            assert!(!stderr.contains("warning"), "{ext} pad {pad}: {stderr}");
            assert_eq!(std::fs::read(&output).unwrap(), plain);
        }
    }
}

// ---------------------------------------------------------------------
// T10b: the same rule for a codec UNDER a container (`.tar.gz`).
// ---------------------------------------------------------------------

/// Packs a one-file tree into `dir/name` (the extension picks the chain) and
/// returns the archive's bytes.
fn packed_tree(dir: &Path, name: &str) -> Vec<u8> {
    let tree = dir.join(format!("{name}.tree"));
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a.txt"), b"tarred payload\n".repeat(50)).unwrap();
    let dst = dir.join(name);
    let out = run_output(&["pack", tree.to_str().unwrap(), "-o", dst.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::read(dst).unwrap()
}

/// A `.tar.gz` / `.tar.bz2` whose codec stream is followed by junk: every
/// verb that walks the archive to its end says so, and `--strict-fidelity`
/// turns it into exit 4. The codec's sink used to be dropped under a
/// container, so all of them reported the archive clean at exit 0.
fn junk_after_a_container_codec_warns(ext: &str, format: &str) {
    let dir = tmp_dir();
    let archive = packed_tree(&dir, &format!("t.tar.{ext}"));
    let junk = b"this is not another member";
    let input = dir.join(format!("junk.tar.{ext}"));
    std::fs::write(&input, [archive, junk.to_vec()].concat()).unwrap();
    let input = input.to_str().unwrap();
    let said = format!("`{format}` stream is followed by {} byte(s)", junk.len());

    let check = |what: &str, args: &[&str], code: i32| {
        let out = run_output(args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(code), "{what}: {stderr}");
        assert!(stderr.contains(&said), "{what}: {stderr}");
    };
    for strict in [false, true] {
        let code = if strict { 4 } else { 0 };
        fn flag(strict: bool, mut v: Vec<&str>) -> Vec<&str> {
            if strict {
                v.push("--strict-fidelity");
            }
            v
        }
        let dest = dir.join(format!("out-{strict}"));
        check(
            "unpack -C",
            &flag(strict, vec!["unpack", input, "-C", dest.to_str().unwrap()]),
            code,
        );
        assert!(dest.join(format!("t.tar.{ext}.tree/a.txt")).exists());
        check("test", &flag(strict, vec!["test", input]), code);
        check("list", &flag(strict, vec!["list", input]), code);
        let converted = dir.join(format!("conv-{strict}.tar"));
        check(
            "convert",
            &flag(
                strict,
                vec!["convert", input, "-o", converted.to_str().unwrap()],
            ),
            code,
        );
    }
    let entry = format!("t.tar.{ext}.tree/a.txt");
    let out = run_output(&["cat", input, &entry]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "cat ENTRY: {stderr}");
    assert_eq!(out.stdout, b"tarred payload\n".repeat(50));
    assert!(stderr.contains(&said), "cat ENTRY: {stderr}");
}

#[test]
fn junk_after_a_tar_gz_warns_and_fails_strict_fidelity() {
    junk_after_a_container_codec_warns("gz", "gzip");
}

#[test]
fn junk_after_a_tar_bz2_warns_and_fails_strict_fidelity() {
    junk_after_a_container_codec_warns("bz2", "bzip2");
}

/// NUL padding after a `.tar.gz`'s gzip member stays silent under a
/// container too (GNU tar and some uploaders pad this way).
#[test]
fn nul_padding_after_a_tar_gz_passes_strict_fidelity() {
    let dir = tmp_dir();
    let archive = packed_tree(&dir, "p.tar.gz");
    let input = dir.join("padded.tar.gz");
    std::fs::write(&input, [archive, vec![0u8; 1024]].concat()).unwrap();
    let input = input.to_str().unwrap();
    let dest = dir.join("out");
    for args in [
        vec!["unpack", input, "-C", dest.to_str().unwrap()],
        vec!["test", input],
    ] {
        let mut args = args;
        args.push("--strict-fidelity");
        let out = run_output(&args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(0), "{}: {stderr}", args[0]);
        assert!(!stderr.contains("followed by"), "{}: {stderr}", args[0]);
    }
}

/// The T10 review's I1: `info` printed "fidelity: nothing approximated" for a
/// bare `.gz`/`.bz2` whose decode then warned about the bytes after its last
/// member. gzip and bzip2 judge those only at the end of the stream, which
/// `info` never reads, so it withholds the claim — and points at a verb that
/// works on a bare stream (`test` refuses one), while a `.tar.gz` still
/// points at `test`.
#[test]
fn info_withholds_the_claim_for_a_codec_that_judges_its_trailing_bytes() {
    let dir = tmp_dir();
    for (ext, flip) in [("gz", 0x1eu8), ("bz2", 0x41)] {
        let a = packed(&dir, &format!("a.{ext}"), &b"first member\n".repeat(100));
        let b = packed(&dir, &format!("b.{ext}"), &b"SECOND MEMBER\n".repeat(100));
        let mut x = [a.clone(), b].concat();
        x[a.len()] = flip;
        let input = dir.join(format!("two-flip.{ext}"));
        std::fs::write(&input, &x).unwrap();

        let cat = run_output(&["cat", input.to_str().unwrap()]);
        assert!(
            String::from_utf8_lossy(&cat.stderr).contains("stream is followed by"),
            ".{ext}: ground truth, the decode warns"
        );
        for (what, text) in [
            (
                "a file",
                String::from_utf8(run_output(&["info", input.to_str().unwrap()]).stdout).unwrap(),
            ),
            ("a pipe", info_over_stdin(&x)),
        ] {
            assert!(
                !text.contains("nothing approximated"),
                ".{ext} {what}: {text}"
            );
            assert!(
                text.contains("not evaluated") && text.contains("stuffr cat FILE >/dev/null"),
                ".{ext} {what}: {text}"
            );
            assert!(!text.contains("stuffr test"), ".{ext} {what}: {text}");
        }
        let json = run_output(&["info", "--json", input.to_str().unwrap()]);
        let v: serde_json::Value =
            serde_json::from_str(&String::from_utf8(json.stdout).unwrap()).unwrap();
        assert_eq!(v["fidelity_evaluated"], false, ".{ext}: {v}");

        let tarball = dir.join(format!("t.tar.{ext}"));
        std::fs::write(&tarball, packed_tree(&dir, &format!("t.tar.{ext}"))).unwrap();
        let text =
            String::from_utf8(run_output(&["info", tarball.to_str().unwrap()]).stdout).unwrap();
        assert!(
            text.contains("not evaluated") && text.contains("stuffr test"),
            ".tar.{ext}: {text}"
        );
    }
}

/// N1: a file of empty gzip members / bzip2 streams starts a fresh decoder
/// per member and yields nothing, so `--max-ratio` cannot see the work; past
/// a free allowance each member must be paid for in bytes moved, or the file
/// is refused as a resource limit (exit 6).
#[test]
fn a_file_of_empty_members_is_a_resource_limit() {
    let dir = tmp_dir();
    for (ext, count) in [("gz", 100_000), ("bz2", 20_000)] {
        let empty = packed(&dir, &format!("empty.{ext}"), b"");
        let input = dir.join(format!("many-empty.{ext}"));
        std::fs::write(&input, empty.repeat(count)).unwrap();
        let output = dir.join(format!("many-empty-{ext}.out"));
        let out = run_output(&[
            "unpack",
            input.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
        ]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(6), ".{ext}: {stderr}");
        assert!(stderr.contains("starts more members"), ".{ext}: {stderr}");
        assert!(!output.exists(), ".{ext}: nothing published");
    }
}
