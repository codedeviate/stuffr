use crate::common::*;

// ---------------------------------------------------------------------
// `--max-ratio` on `list`/`test`: the codec layer beneath a container is
// bounded the same way `unpack`/`cat` already bound a bare codec stream.
//
// A single gzip member cannot itself reach the 10_000:1 default — its own
// structural ceiling on all-zero input is roughly 1024:1 (measured below,
// and documented on `examples.txt`'s "GUARDING AGAINST DECOMPRESSION
// BOMBS" section for the plain-codec case). `a_bomb_exits_six_and_leaves_
// no_partial_output` above hits this identical ceiling on the codec path
// and works around it with an explicit, tighter `--max-ratio`; these tests
// follow the same convention rather than inventing a new one.
// ---------------------------------------------------------------------

#[test]
fn list_and_test_refuse_a_bomb_tar_gz_at_a_tight_max_ratio() {
    let dir = tmp_dir();
    let bomb = write_bomb_tar_gz(&dir);
    // Real measured ratio is roughly 1000:1 (2 MiB in, ~2 KiB of gzip out);
    // 100 is comfortably below that, exactly as the existing codec-path
    // bomb test uses for the identical reason.
    let list_out = run_output(&["list", bomb.to_str().unwrap(), "--max-ratio", "100"]);
    assert_eq!(
        list_out.status.code(),
        Some(6),
        "list stderr: {}",
        String::from_utf8_lossy(&list_out.stderr)
    );
    let list_err = String::from_utf8_lossy(&list_out.stderr);
    assert!(
        list_err.contains("100") && list_err.contains("--max-ratio"),
        "must name the limit and the flag, matching how decompress reports it: {list_err}"
    );

    let test_out = run_output(&["test", bomb.to_str().unwrap(), "--max-ratio", "100"]);
    assert_eq!(
        test_out.status.code(),
        Some(6),
        "test stderr: {}",
        String::from_utf8_lossy(&test_out.stderr)
    );
    let test_err = String::from_utf8_lossy(&test_out.stderr);
    assert!(
        test_err.contains("100") && test_err.contains("--max-ratio"),
        "must name the limit and the flag: {test_err}"
    );
}

#[test]
fn raising_max_ratio_lets_the_bomb_through() {
    // Proves the flag is wired, not merely accepted and ignored: the exact
    // same archive `list_and_test_refuse_a_bomb_tar_gz_at_a_tight_max_ratio`
    // refuses at 100 must succeed once the limit is raised past its real
    // (roughly 1000:1) ratio.
    let dir = tmp_dir();
    let bomb = write_bomb_tar_gz(&dir);

    let list_out = run_output(&["list", bomb.to_str().unwrap(), "--max-ratio", "100000"]);
    assert!(
        list_out.status.success(),
        "list stderr: {}",
        String::from_utf8_lossy(&list_out.stderr)
    );

    let test_out = run_output(&["test", bomb.to_str().unwrap(), "--max-ratio", "100000"]);
    assert!(
        test_out.status.success(),
        "test stderr: {}",
        String::from_utf8_lossy(&test_out.stderr)
    );
}

/// The false-positive trap the guard must NOT fall into: a real, sizeable
/// (not trivially tiny) archive that gzip legitimately crushes hard must
/// pass at the UNCHANGED default ratio — no `--max-ratio` given at all.
#[test]
fn a_legitimately_compressible_tar_gz_is_not_refused_at_the_default_ratio() {
    let dir = tmp_dir();
    let text = "the quick brown fox jumps over the lazy dog\n".repeat(200_000);
    let archive = write_fixture_tar_gz(&dir, "legit.tar.gz", &[("log.txt", text.as_bytes())]);

    let list_out = run_output(&["list", archive.to_str().unwrap()]);
    assert!(
        list_out.status.success(),
        "a legitimately compressible archive must not be refused at the default ratio: {}",
        String::from_utf8_lossy(&list_out.stderr)
    );
    assert!(
        String::from_utf8(list_out.stdout)
            .unwrap()
            .contains("log.txt")
    );

    let test_out = run_output(&["test", archive.to_str().unwrap()]);
    assert!(
        test_out.status.success(),
        "a legitimately compressible archive must not be refused at the default ratio: {}",
        String::from_utf8_lossy(&test_out.stderr)
    );
}
