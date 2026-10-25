use crate::common::*;

// ---------------------------------------------------------------------
// Selecting entries by index.
//
// `ArchiveRead::by_index` existed and was implemented on all four
// containers from Phase 2 onward with no call site above the container
// layer at all — built and dormant, the same shape `UnsafePath` and
// `ContainerCaps` were in earlier phases. These tests are the contract for
// the surface that finally reaches it.
//
// Index is 0-based and counts in ARCHIVE ORDER: the order `next_entry`
// yields, which is the order `list` prints. `list`'s first column and
// `--index` therefore read one enumeration, and the first test here is the
// one that keeps them from drifting apart.
// ---------------------------------------------------------------------

/// The index column and `--index` must name the same entry, because a user
/// reads the first and types the second. Checked for EVERY row rather than
/// one, so an off-by-one that happens to be invisible at position 0 still
/// fails.
#[test]
fn the_index_list_prints_is_the_index_cat_selects_by() {
    let dir = tmp_dir();
    let archive = write_fixture_tar(
        &dir,
        &[
            ("a.txt", b"alpha"),
            ("b.txt", b"bravo"),
            ("c.txt", b"charlie"),
        ],
    );
    let listing =
        String::from_utf8(run_output(&["list", archive.to_str().unwrap()]).stdout).unwrap();
    let rows: Vec<&str> = listing.lines().collect();
    assert_eq!(rows.len(), 3, "{listing}");

    for (want_index, (_, payload)) in [
        ("a.txt", &b"alpha"[..]),
        ("b.txt", &b"bravo"[..]),
        ("c.txt", &b"charlie"[..]),
    ]
    .iter()
    .enumerate()
    {
        // The first column of the listing is the number `--index` takes.
        let printed = rows[want_index].split_whitespace().next().unwrap();
        assert_eq!(
            printed,
            want_index.to_string(),
            "list's first column must be the 0-based archive position: {listing}"
        );
        let out = run_output(&[
            "cat",
            archive.to_str().unwrap(),
            "--index",
            &want_index.to_string(),
        ]);
        assert!(
            out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            out.stdout, *payload,
            "row {want_index} of the listing and `--index {want_index}` must be \
             the same entry"
        );
    }
}

/// The property the two-route implementation rests on, at the level a user
/// meets it: a zip on a real file is reached through its central directory,
/// the same zip on a pipe is reached by counting the forward walk, and the
/// two must hand back the same bytes.
///
/// Compared against the ORIGINAL content as well as against each other —
/// two routes wrong in the same direction would agree with each other
/// perfectly and both be wrong.
#[test]
fn index_selection_agrees_between_a_seekable_zip_and_the_same_zip_on_a_pipe() {
    let dir = tmp_dir();
    let payloads: [&[u8]; 4] = [b"first", b"second!!", b"third:::", b"fourth"];
    let zip = write_zip_via_pack(
        &dir,
        &[
            ("one.txt", payloads[0]),
            ("two.txt", payloads[1]),
            ("three.txt", payloads[2]),
            ("four.txt", payloads[3]),
        ],
    );
    let bytes = std::fs::read(&zip).unwrap();

    for (i, payload) in payloads.iter().enumerate() {
        let n = i.to_string();
        let seekable = run_output(&["cat", zip.to_str().unwrap(), "--index", &n]);
        assert!(
            seekable.status.success(),
            "index {n} on a file: {}",
            String::from_utf8_lossy(&seekable.stderr)
        );
        let piped = run_with_stdin_output(&["cat", "-", "--index", &n], &bytes);
        assert!(
            piped.status.success(),
            "index {n} on a pipe: {}",
            String::from_utf8_lossy(&piped.stderr)
        );

        assert_eq!(
            seekable.stdout, piped.stdout,
            "the random-access and counted routes disagreed at index {n}"
        );
        assert_eq!(
            seekable.stdout,
            payload.to_vec(),
            "index {n} did not reach the entry the archive was built with"
        );
    }
}

/// Repeatable, delivered in archive order however the flags were ordered,
/// and a repeat selects its entry once. That contract is what lets the two
/// routes above agree at all: the counted route can only ever produce
/// archive order.
#[test]
fn repeated_index_flags_are_deduplicated_and_delivered_in_archive_order() {
    let dir = tmp_dir();
    let archive = write_fixture_tar(
        &dir,
        &[
            ("a.txt", b"alpha"),
            ("b.txt", b"bravo"),
            ("c.txt", b"charlie"),
        ],
    );
    let out = run_output(&[
        "cat",
        archive.to_str().unwrap(),
        "--index",
        "2",
        "--index",
        "0",
        "--index",
        "2",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.stdout, b"alphacharlie",
        "archive order, once each — not typed order, and not twice"
    );
}

/// An index past the end is the caller's mistake, so exit 2 and say how many
/// entries there actually are. Pinned on both routes, since each discovers
/// the overrun at a different moment.
#[test]
fn an_index_past_the_end_is_a_usage_error_naming_the_real_entry_count() {
    let dir = tmp_dir();
    let archive = write_fixture_tar(&dir, &[("a.txt", b"alpha"), ("b.txt", b"bravo")]);
    let zip = write_zip_via_pack(&dir, &[("one.txt", b"first"), ("two.txt", b"second")]);

    for path in [&archive, &zip] {
        let out = run_output(&["cat", path.to_str().unwrap(), "--index", "9"]);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{}: stderr {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("#9") && stderr.contains("0-1"),
            "the refusal must name the index asked for and the VALID range, \
             whichever route found it: {stderr}"
        );
        assert!(
            out.stdout.is_empty(),
            "an out-of-range index must not stream anything first"
        );
    }
}

/// `--index` and PATTERNS are alternative ways of saying "which entries",
/// never a combination — exit 2 rather than a guess at union or
/// intersection.
#[test]
fn index_and_patterns_together_are_a_usage_error() {
    let dir = tmp_dir();
    let archive = write_fixture_tar(&dir, &[("a.txt", b"alpha"), ("b.txt", b"bravo")]);
    let dest = dir.join("out");

    let out = run_output(&["cat", archive.to_str().unwrap(), "a.txt", "--index", "1"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--index"), "{stderr}");

    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "a.txt",
        "-C",
        dest.to_str().unwrap(),
        "--index",
        "1",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        !dest.exists(),
        "the refusal must come before anything is created"
    );
}

/// `--index` selects entries, so on `unpack` it needs -C for exactly the
/// reason a pattern does — and the refusal names the flag the user typed.
#[test]
fn unpack_by_index_without_a_directory_names_the_index_in_its_refusal() {
    let dir = tmp_dir();
    let archive = write_fixture_tar(&dir, &[("a.txt", b"alpha"), ("b.txt", b"bravo")]);

    let out = run_output(&["unpack", archive.to_str().unwrap(), "--index", "1"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--index 1") && stderr.contains("-C"),
        "the refusal must name what was typed and what to do instead: {stderr}"
    );
}

/// The containered half of the feature: `unpack --index N -C out` writes
/// exactly that entry and nothing else.
#[test]
fn unpack_by_index_extracts_only_the_selected_entry() {
    let dir = tmp_dir();
    let archive = write_fixture_tar(
        &dir,
        &[
            ("a.txt", b"alpha"),
            ("b.txt", b"bravo"),
            ("c.txt", b"charlie"),
        ],
    );
    let dest = dir.join("out");
    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
        "--index",
        "1",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(dest.join("b.txt")).unwrap(), b"bravo");
    assert!(!dest.join("a.txt").exists(), "only the selected entry");
    assert!(!dest.join("c.txt").exists(), "only the selected entry");
}

/// `--json` carries the index too, since a script selecting by position has
/// to read it from somewhere.
#[test]
fn list_json_carries_the_archive_index_of_every_entry() {
    let dir = tmp_dir();
    let archive = write_fixture_tar(&dir, &[("a.txt", b"alpha"), ("b.txt", b"bravo")]);
    let out = run_output(&["list", "--json", archive.to_str().unwrap()]);
    let text = String::from_utf8(out.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let rows = v.as_array().unwrap();
    assert_eq!(rows[0]["index"], 0);
    assert_eq!(rows[0]["name"], "a.txt");
    assert_eq!(rows[1]["index"], 1);
    assert_eq!(rows[1]["name"], "b.txt");
}
