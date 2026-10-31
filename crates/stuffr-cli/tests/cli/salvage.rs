use crate::common::*;

// ---------------------------------------------------------------------
// `salvage`.
//
// The fixture below is a hand-assembled zip, not one built through
// `stuffr pack` (which never writes a duplicate record) or through the
// `zip` crate (no dev-dependency on it here, deliberately — see
// `write_zip_via_pack`'s own doc for why these tests avoid depending on a
// second zip-writing stack). It reproduces the exact shape
// `stuffr-formats/src/zip.rs`'s own `build_shadowing_zip` fixture does
// (that one is `pub(crate)` to `stuffr-formats` and unreachable from here):
// six distinct names, Stored (so a local header's declared compressed size
// is the whole payload, no deflate framing to reason about), with
// `shadowed-a.bin` and `shadowed-b.bin` each written a SECOND time — a
// byte-identical local header and payload, appended after the six
// originals — and a central directory carrying all EIGHT records (the six
// originals, then a duplicate central record for each shadowed name,
// pointing at the SECOND physical copy). A last-record-wins reader (`zip`,
// and so `stuffr list`) collapses that to 6 names; `stuffr salvage`'s raw
// scan walks local headers in FILE ORDER and finds all 8, so scan
// positions 6 and 7 are the two shadows of scan positions 2 and 3.
// ---------------------------------------------------------------------

/// The final whole-branch review's F3, end to end: an ordinary one-entry
/// zip whose entry name holds interior NUL bytes — `zt\0ee\0a.txt`, the
/// exact shape a zeroed run inside `ztree/a.txt` produces, and what the
/// reviewer's sweep actually hit on a mutated `stuffr pack` output.
///
/// Before the fix:
///
/// ```text
/// $ stuffr list   nul.zip     # exit 0
/// $ stuffr test   nul.zip     # exit 0, "exact fidelity"
/// $ stuffr unpack nul.zip -C out
/// stuffr: i/o error: file name contained an unexpected NUL byte
/// exit=1                      # "stuffr itself failed", on input the
///                             # archive chose
/// ```
///
/// It was the ONLY exit 1 in a 31,460-invocation corruption sweep over
/// 2,860 mutated archives in all five salvageable formats. `list` and
/// `test` still exit 0 here and that is correct — neither turns a name into
/// a path, so neither can see the problem; the same asymmetry zip's
/// declared-size lie already has.
#[test]
fn unpack_refuses_a_nul_bearing_entry_name_rather_than_failing() {
    let dir = tmp_dir();
    let rec = salvage_fixture_local_record(0, "zt\0ee\0a.txt", b"hello world\n");
    let mut out = rec.bytes.clone();
    let cd_start = u32::try_from(out.len()).unwrap();
    out.extend_from_slice(&salvage_fixture_central_record(&rec));
    let cd_size = u32::try_from(out.len()).unwrap() - cd_start;
    out.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_start.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    let archive = dir.join("nul.zip");
    std::fs::write(&archive, &out).unwrap();

    let listed = run_output(&["list", archive.to_str().unwrap()]);
    assert_eq!(listed.status.code(), Some(0), "list reads the archive fine");

    let unpacked = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dir.join("out").to_str().unwrap(),
    ]);
    let stderr = String::from_utf8(unpacked.stderr).unwrap();
    assert_eq!(
        unpacked.status.code(),
        Some(7),
        "hostile input must never be exit 1: {stderr}"
    );
    assert!(
        stderr.contains("NUL"),
        "and the refusal must name what it refused: {stderr}"
    );
}

/// The two fixtures must actually differ, and differ only where they are
/// meant to. Without this, a builder bug that ignored
/// [`SalvageFixtureDuplicates::Distinct`] would leave every test standing on
/// the new fixture silently re-testing the old one — the precise failure
/// mode (a fixture that does not model what its name says) that hid three
/// findings behind the identical-duplicate fixture in the first place.
#[test]
fn the_two_salvage_duplicate_fixtures_share_a_shape_and_differ_in_content() {
    let identical = build_shadowing_zip_fixture();
    let distinct = build_duplicate_name_zip_fixture();
    assert_eq!(
        identical.len(),
        distinct.len(),
        "length-preserving by construction"
    );
    assert_ne!(identical, distinct, "but not the same bytes");
    // Everything before the first duplicate's local record is byte-identical
    // — the six originals are untouched, which is what makes the two
    // fixtures a controlled pair rather than two different archives.
    let first_dup_at = identical
        .windows(4)
        .enumerate()
        .filter(|(_, w)| *w == b"PK\x03\x04")
        .map(|(i, _)| i)
        .nth(6)
        .expect("the fixture has eight local headers");
    assert_eq!(identical[..first_dup_at], distinct[..first_dup_at]);
}

/// The distinct-content fixture is structurally the same archive to both
/// readers: `list` still collapses it to six rows and still warns that two
/// records are unreachable, and `salvage --list` still reaches all eight.
/// That equivalence is what makes it a controlled comparison — whatever
/// differs between the two fixtures downstream differs because the
/// duplicates' CONTENT differs, not because the archives are shaped
/// differently.
#[test]
fn the_duplicate_name_fixture_reads_the_same_as_the_identical_one() {
    let dir = tmp_dir();
    let archive = write_duplicate_name_zip_fixture(&dir);

    let list_out = run_output(&["list", archive.to_str().unwrap()]);
    let listing = String::from_utf8(list_out.stdout).unwrap();
    assert_eq!(
        listing.lines().count(),
        6,
        "`list` collapses a repeated name whatever the bytes under it: {listing}"
    );
    let warnings = String::from_utf8(list_out.stderr).unwrap();
    assert!(
        warnings.contains("8") && warnings.contains("6"),
        "`list` must still warn that the index declares more records than it reaches: {warnings}"
    );

    let salvage_out = run_output(&["salvage", archive.to_str().unwrap(), "--list"]);
    let stdout = String::from_utf8(salvage_out.stdout).unwrap();
    assert_eq!(
        stdout.lines().count(),
        8,
        "`salvage --list` must reach every scanned record here too: {stdout}"
    );
    assert_eq!(
        stdout.matches("Intact").count(),
        8,
        "every record verifies: the duplicates carry their own correct CRC-32, which is what \
         makes losing one of them a real loss: {stdout}"
    );
}

/// The finding this closes, reproduced as a FILE COUNT and a BYTE
/// COMPARISON, which is how it was found and the only way it shows up at
/// all: before the fix, `salvage -C` on an archive whose duplicates differ
/// printed `8 scanned: 8 written` at exit 0 and left SIX files, with
/// `shadowed-a.bin` holding record 6's payload and record 2's gone —
/// while `salvage --index 2 -o f` returned record 2 correctly the whole
/// time. No error code was involved anywhere; a test asserting on one
/// would have passed through the defect untouched.
#[test]
fn salvage_recovers_both_records_under_a_repeated_name() {
    let dir = tmp_dir();
    let archive = write_duplicate_name_zip_fixture(&dir);
    let out_dir = dir.join("recovered");

    let out = run_output(&[
        "salvage",
        archive.to_str().unwrap(),
        "-C",
        out_dir.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "a run that had to change a name must not exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut names: Vec<String> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "five.txt",
            "one.txt",
            "shadowed-a.bin",
            "shadowed-a.bin.salvaged-6",
            "shadowed-b.bin",
            "shadowed-b.bin.salvaged-7",
            "six.txt",
            "two.txt",
        ],
        "eight records written must be eight files, with the later record of each pair \
         under a name derived from its own scan position"
    );

    // The bytes, not just the count: the record that owns the name keeps
    // it, and the later one is beside it rather than on top of it.
    let first = std::fs::read(out_dir.join("shadowed-a.bin")).unwrap();
    let second = std::fs::read(out_dir.join("shadowed-a.bin.salvaged-6")).unwrap();
    assert_eq!(
        first, b"payload for the first record that will be shadowed",
        "record 2 must keep its own name and its own bytes"
    );
    assert_eq!(
        second, b"DIFFERENT bytes under the first duplicated name!!!",
        "record 6's bytes must be on disk too, not lost to an overwrite"
    );
    assert_ne!(first, second, "the fixture's whole premise");

    let summary = String::from_utf8(out.stderr).unwrap();
    assert!(
        summary.contains("8 written"),
        "every written record is counted, and now there are eight files to match: {summary}"
    );
    assert!(
        summary.contains("2 renamed to avoid a name collision"),
        "the summary must say a name had to be changed: {summary}"
    );
}

/// The complement, and the reason the identical-duplicate fixture is kept:
/// when a duplicate IS a proven copy, nothing is renamed and nothing is
/// written twice — recovering the same bytes under a second name would be
/// noise, not a service. Without this, a fix that renamed every repeated
/// name would pass the test above and quietly double every shadowing
/// archive's output.
#[test]
fn a_proven_duplicate_is_still_skipped_rather_than_renamed() {
    let dir = tmp_dir();
    let archive = write_shadowing_zip_fixture(&dir);
    let out_dir = dir.join("recovered");

    let out = run_output(&[
        "salvage",
        archive.to_str().unwrap(),
        "-C",
        out_dir.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(4));
    assert_eq!(
        std::fs::read_dir(&out_dir).unwrap().count(),
        6,
        "six distinct names, and the two byte-identical duplicates add nothing"
    );
    let summary = String::from_utf8(out.stderr).unwrap();
    assert!(
        summary.contains("2 skipped"),
        "a proven copy is skipped, as it always was: {summary}"
    );
    assert!(
        summary.contains("0 renamed to avoid a name collision"),
        "and nothing needed renaming: {summary}"
    );
}

/// The two annotations, measured against each other on the two fixtures.
///
/// On the identical-duplicate archive the duplicates are PROVEN copies and
/// are marked `[shadowed: dup of #N]`. On the distinct-content one nothing
/// is provably a copy, so the same two rows are marked `[name collision: #N
/// uses this name too]` instead — the fact `stuffr list` warns about. Before
/// this, salvage marked the second archive in no way at all, so `list` and
/// `salvage` told a user two contradictory things about the same eight
/// records.
#[test]
fn a_name_collision_and_a_shadow_are_two_different_annotations() {
    let dir = tmp_dir();
    let identical = write_shadowing_zip_fixture(&dir);
    let distinct = write_duplicate_name_zip_fixture(&dir);

    let id_rows =
        String::from_utf8(run_output(&["salvage", identical.to_str().unwrap(), "--list"]).stdout)
            .unwrap();
    assert_eq!(
        id_rows.matches("[shadowed: dup of #").count(),
        2,
        "byte-identical duplicates are shadows: {id_rows}"
    );
    assert_eq!(
        id_rows.matches("[name collision:").count(),
        0,
        "a proven copy reports the stronger fact and only that one: {id_rows}"
    );

    let di_rows =
        String::from_utf8(run_output(&["salvage", distinct.to_str().unwrap(), "--list"]).stdout)
            .unwrap();
    assert_eq!(
        di_rows.matches("[shadowed: dup of #").count(),
        0,
        "no checksum agrees here, so nothing is a proven copy: {di_rows}"
    );
    assert!(
        di_rows.contains("[name collision: #2 uses this name too]"),
        "record 6 repeats record 2's name: {di_rows}"
    );
    assert!(
        di_rows.contains("[name collision: #3 uses this name too]"),
        "record 7 repeats record 3's name: {di_rows}"
    );
    assert_eq!(
        di_rows.matches("[name collision:").count(),
        2,
        "exactly the two repeated names, never the six originals: {di_rows}"
    );
}

/// `--list` prints every record the scan found — 8, on the fixture above —
/// where plain `list` prints only the 6 names its central-directory reader
/// collapses onto. The two shadows are annotated `[shadowed: dup of #N]`,
/// naming the EARLIER scan position they duplicate.
#[test]
fn salvage_list_reaches_every_record() {
    let dir = tmp_dir();
    let archive = write_shadowing_zip_fixture(&dir);

    let listing =
        String::from_utf8(run_output(&["list", archive.to_str().unwrap()]).stdout).unwrap();
    assert_eq!(
        listing.lines().count(),
        6,
        "sanity check on the fixture itself: `list` must collapse to 6 rows: {listing}"
    );

    let out_dir = dir.join("recovered");
    let salvage_out = run_output(&[
        "salvage",
        archive.to_str().unwrap(),
        "-C",
        out_dir.to_str().unwrap(),
        "--list",
    ]);
    let stdout = String::from_utf8(salvage_out.stdout).unwrap();
    assert_eq!(
        stdout.lines().count(),
        8,
        "`salvage --list` must reach every scanned record, shadowed ones included: {stdout}"
    );
    let shadow_lines: Vec<&str> = stdout
        .lines()
        .filter(|l| l.contains("[shadowed: dup of #"))
        .collect();
    assert_eq!(
        shadow_lines.len(),
        2,
        "exactly the two duplicate records must be annotated as shadows: {stdout}"
    );
    assert!(
        shadow_lines[0].contains("[shadowed: dup of #2]"),
        "the first shadow must name scan position 2 (shadowed-a.bin) as its original: {stdout}"
    );
    assert!(
        shadow_lines[1].contains("[shadowed: dup of #3]"),
        "the second shadow must name scan position 3 (shadowed-b.bin) as its original: {stdout}"
    );
}

/// `--index` on `salvage` selects by SCAN position, a different numbering
/// from `list`'s own index — `list --index 6` cannot even reach a row (the
/// listing this fixture prints has only 6 rows, 0-5), while `salvage --index
/// 6` reaches the shadow of scan position 2. Any message naming this
/// numbering must say "scan position", never "index".
#[test]
fn salvage_index_names_a_scan_position_not_a_list_index() {
    let dir = tmp_dir();
    let archive = write_shadowing_zip_fixture(&dir);

    let list_out = run_output(&["list", archive.to_str().unwrap(), "--index", "6"]);
    assert!(
        !list_out.status.success(),
        "list's own numbering has only 6 rows (0-5); --index 6 must not succeed"
    );

    let out_dir = dir.join("recovered");
    let out = run_output(&[
        "salvage",
        archive.to_str().unwrap(),
        "-C",
        out_dir.to_str().unwrap(),
        "--index",
        "6",
        "--list",
    ]);
    // Scan position 6 IS the shadow, so selecting only it selects a record
    // this run skips — exit 4 (Ruling R-N: any entry skipped, for any
    // reason, is a degraded run), not 0.
    assert_eq!(
        out.status.code(),
        Some(4),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Fix round 1, REQUIRED 2: `--list` always reports the FULL scan, even
    // under `--index` — `--index` narrows what is WRITTEN, never what
    // `--list` shows. All 8 rows must still be present, with every position
    // `--index` excluded tagged `[not selected]` and the selected one (6)
    // still showing its own, more permanent `[shadowed: ...]` annotation.
    let stdout = String::from_utf8(out.stdout).unwrap();
    let rows: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        rows.len(),
        8,
        "--list must keep showing the full scan under --index too: {stdout}"
    );
    for (pos, row) in rows.iter().enumerate() {
        assert!(
            row.starts_with(&format!("{pos} ")),
            "row {pos} must lead with its own scan position: {stdout}"
        );
        match pos {
            // Selected, and shadows #2 — shadow detection runs BEFORE
            // `select` (a shadow is a permanent fact about the entry, unlike
            // selection), so this shows its shadow annotation, not
            // "not selected", even though it happens to be the one entry
            // `--index 6` did ask for.
            6 => assert!(
                row.contains("[shadowed: dup of #2]") && !row.contains("[not selected]"),
                "the selected row must show its shadow annotation, not a not-selected one: \
                 {row}"
            ),
            // Not selected, but ALSO a shadow (of #3) — same reasoning as
            // above, from the other direction: the shadow annotation wins
            // over "not selected" regardless of which one selection alone
            // would have produced.
            7 => assert!(
                row.contains("[shadowed: dup of #3]") && !row.contains("[not selected]"),
                "an unselected shadow must still show its shadow annotation: {row}"
            ),
            _ => assert!(
                row.contains("[not selected]"),
                "every non-shadow position other than the selected one must be tagged \
                 not selected: {row}"
            ),
        }
    }

    // The measurement that exposed REQUIRED 1: `--index` must select what
    // is WRITTEN, not just what is reported. Scan position 0 (`one.txt`) is
    // NOT a shadow, so this is the clean case that proves the fix rather
    // than one where nothing would be written either way.
    let out_dir2 = dir.join("recovered2");
    let out2 = run_output(&[
        "salvage",
        archive.to_str().unwrap(),
        "-C",
        out_dir2.to_str().unwrap(),
        "--index",
        "0",
    ]);
    assert!(
        out2.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out2.stderr)
    );
    let names: Vec<String> = std::fs::read_dir(&out_dir2)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        names,
        vec!["one.txt".to_string()],
        "-C DIR --index 0 must leave ONLY the selected record in DIR; found {names:?}"
    );

    // Naming rule: an out-of-range request must say "scan position", never
    // "index" — this project's own conformance harness ended up with
    // colliding property numbers by letting two numbering schemes share a
    // word, and this feature exists specifically not to repeat that.
    let bad = run_output(&[
        "salvage",
        archive.to_str().unwrap(),
        "-C",
        out_dir.to_str().unwrap(),
        "--index",
        "99",
    ]);
    assert!(!bad.status.success());
    let stderr = String::from_utf8_lossy(&bad.stderr);
    assert!(
        stderr.contains("scan position"),
        "an out-of-range --index must name it a scan position: {stderr}"
    );
    assert!(
        !stderr.to_lowercase().contains("index "),
        "the message must never say \"index\", to avoid being read as list's numbering: {stderr}"
    );
}

/// `salvage` without `-C` is refused: it has no single-stream mode, so
/// there is always somewhere recovered content must land.
#[test]
fn salvage_without_directory_is_refused() {
    let dir = tmp_dir();
    let archive = write_shadowing_zip_fixture(&dir);
    let out = run_output(&["salvage", archive.to_str().unwrap()]);
    assert!(!out.status.success());
    assert_eq!(out.status.code(), Some(2), "missing -C is a usage error");
}

/// A default (non-`--list`) run recovers every non-shadowed entry, prints
/// its summary to stderr, and exits 4 — not 0 — because two of the eight
/// scanned records are shadows this run skips (Ruling R-N: any entry
/// skipped, for any reason, is a degraded run).
#[test]
fn salvage_default_run_recovers_and_reports_the_shadow_skips() {
    let dir = tmp_dir();
    let archive = write_shadowing_zip_fixture(&dir);
    let out_dir = dir.join("recovered");
    let out = run_output(&[
        "salvage",
        archive.to_str().unwrap(),
        "-C",
        out_dir.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stdout.is_empty(),
        "the default report goes to stderr, not stdout: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("8 scanned")
            && stderr.contains("6 written")
            && stderr.contains("2 skipped"),
        "the summary must count the two shadow skips: {stderr}"
    );
    assert_eq!(
        std::fs::read(out_dir.join("one.txt")).unwrap(),
        b"payload for entry one"
    );
    assert_eq!(
        std::fs::read(out_dir.join("shadowed-a.bin")).unwrap(),
        b"payload for the first record that will be shadowed"
    );
    // The two shadows recover nothing under their own name a second time —
    // `place_salvaged_entry` checks `shadows` before ever computing a
    // target, so there is no second write, partial or otherwise, to find.
    assert_eq!(std::fs::read_dir(&out_dir).unwrap().count(), 6);
}

/// The final whole-branch review's F1 reproducer, driven through the real
/// binary: a **228-byte** zip of three Stored local headers whose MIDDLE
/// name is EMPTY — one corrupted length byte, the shape the reviewer hit
/// from ordinary random corruption of a real `stuffr pack` output.
///
/// Before the final fix wave this printed one line — `stuffr: unsafe entry
/// path `` refused: empty entry name` — exited 7 with only `first.txt` on
/// disk, **never attempted `third.txt`, and printed no summary at all**,
/// while `--index 0 --index 2` recovered both. The unit test beside
/// `entries::salvage`'s own code pins the dispositions; this one exists
/// because three of the four things that were wrong are only observable at
/// the CLI: the summary line, the per-entry stderr line, and the exit code
/// a script reads.
#[test]
fn salvage_recovers_past_an_entry_whose_name_containment_refuses() {
    let dir = tmp_dir();
    let mut bytes = Vec::new();
    for (name, payload) in [
        ("first.txt", &b"AAAAAAAAAA"[..]),
        ("", &b"BBBBBBBBBB"[..]),
        ("third.txt", &b"CCCCCCCCCC"[..]),
    ] {
        let rec = salvage_fixture_local_record(u32::try_from(bytes.len()).unwrap(), name, payload);
        bytes.extend_from_slice(&rec.bytes);
    }
    let archive = dir.join("midbad.zip");
    std::fs::write(&archive, &bytes).unwrap();

    let out_dir = dir.join("recovered");
    let out = run_output(&[
        "salvage",
        archive.to_str().unwrap(),
        "-C",
        out_dir.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8(out.stderr).unwrap();

    assert_eq!(
        out.status.code(),
        Some(7),
        "the hostile-path contract is unchanged — the RUN still answers 7: {stderr}"
    );
    assert_eq!(
        std::fs::read(out_dir.join("third.txt")).unwrap(),
        b"CCCCCCCCCC",
        "the record AFTER the refused one is exactly what the old behaviour lost"
    );
    assert_eq!(
        std::fs::read(out_dir.join("first.txt")).unwrap(),
        b"AAAAAAAAAA"
    );
    assert_eq!(
        std::fs::read_dir(&out_dir).unwrap().count(),
        2,
        "and nothing at all is written for the refused entry"
    );
    assert!(
        stderr.contains("3 scanned")
            && stderr.contains("2 written")
            && stderr.contains("1 skipped"),
        "the summary must print — a run that returns Err never prints one, so a user was \
         never told what WAS recovered: {stderr}"
    );
    assert!(
        stderr.contains("empty entry name"),
        "and the refusal must still be named, on stderr, every run: {stderr}"
    );
}

/// The status column must name a `Partial`/`Unverified` entry's CAUSE, not
/// just its tier — "ran out" and "checksum disagreed" are different
/// diagnoses, and so are "this build cannot decode the method" and "no
/// length was available to bound the payload".
#[test]
fn salvage_list_names_partial_and_unverified_causes() {
    let dir = tmp_dir();
    let path = dir.join("mixed.zip");
    std::fs::write(&path, build_partial_and_unverified_zip_fixture()).unwrap();
    let out_dir = dir.join("recovered");

    let out = run_output(&[
        "salvage",
        path.to_str().unwrap(),
        "-C",
        out_dir.to_str().unwrap(),
        "--list",
    ]);
    // Exit 3 (any Unverified entry) outranks exit 4 (Ruling R-N) even though
    // this run also has a Partial entry.
    assert_eq!(
        out.status.code(),
        Some(3),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let rows: Vec<&str> = stdout.lines().collect();
    assert_eq!(rows.len(), 2, "{stdout}");
    assert!(
        rows[0].contains("Partial (checksum mismatch)"),
        "a full decode that disagrees with the declared CRC-32 must name that cause: {stdout}"
    );
    assert!(
        rows[1].contains("Unverified (undecodable method)"),
        "a recognised-but-undecodable method must name that cause: {stdout}"
    );
    // `--partial=keep` is the default, so the mismatched entry is still
    // written — under `name.partial`, never its real name.
    assert_eq!(
        std::fs::read(out_dir.join("mismatched.bin.partial")).unwrap(),
        b"this payload's crc field below is wrong on purpose"
    );
    assert!(!out_dir.join("mismatched.bin").exists());
    assert!(!out_dir.join("undecodable.bin").exists());
}

/// Fix round 1, REQUIRED 3: a `--partial=skip` entry must still name its
/// cause in `--list`, not fall through to bare "Partial" — the gap the fix
/// brief singled out because it hits exactly the entries the flag caused to
/// be dropped, in a verb whose whole selling point is per-entry honesty.
#[test]
fn salvage_skipped_partial_names_its_cause() {
    let dir = tmp_dir();
    let path = dir.join("mixed.zip");
    std::fs::write(&path, build_partial_and_unverified_zip_fixture()).unwrap();
    let out_dir = dir.join("recovered");

    let out = run_output(&[
        "salvage",
        path.to_str().unwrap(),
        "-C",
        out_dir.to_str().unwrap(),
        "--partial=skip",
        "--list",
    ]);
    assert_eq!(
        out.status.code(),
        Some(3),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let rows: Vec<&str> = stdout.lines().collect();
    assert_eq!(rows.len(), 2, "{stdout}");
    assert!(
        rows[0].contains("Partial (checksum mismatch)"),
        "--partial=skip must still name the cause, not fall back to bare \"Partial\": {stdout}"
    );
    // `--partial=skip` means the entry is never written at all, cause known
    // or not.
    assert!(!out_dir.join("mismatched.bin").exists());
    assert!(!out_dir.join("mismatched.bin.partial").exists());
}

/// Fix round 1, REQUIRED 2 (first surface form): `--list` must work with NO
/// destination at all — listing is not recovering, and this is the
/// diagnostic half of the feature that answers "what does this archive
/// hold" without extracting anything.
#[test]
fn salvage_list_works_with_no_destination() {
    let dir = tmp_dir();
    let archive = write_shadowing_zip_fixture(&dir);

    let out = run_output(&["salvage", archive.to_str().unwrap(), "--list"]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        stdout.lines().count(),
        8,
        "a report-only run must still list the full scan: {stdout}"
    );
    // Nothing was created anywhere: no `-C` directory, and no directory
    // named after the archive either.
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        1,
        "report-only `--list` must touch nothing on disk but the archive itself"
    );
}

/// Fix round 1, REQUIRED 2 (second surface form): `-o FILE --index N`
/// recovers exactly one entry's bytes to a named file, with no `-C`
/// directory involved at all.
#[test]
fn salvage_output_recovers_one_entry_to_a_named_file() {
    let dir = tmp_dir();
    let archive = write_shadowing_zip_fixture(&dir);
    let out_file = dir.join("recovered-one.txt");

    let out = run_output(&[
        "salvage",
        archive.to_str().unwrap(),
        "-o",
        out_file.to_str().unwrap(),
        "--index",
        "0",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(&out_file).unwrap(), b"payload for entry one");

    // Refused: more than one selected record.
    let too_many = run_output(&[
        "salvage",
        archive.to_str().unwrap(),
        "-o",
        out_file.to_str().unwrap(),
        "--index",
        "0",
        "--index",
        "1",
    ]);
    assert_eq!(too_many.status.code(), Some(2));

    // Refused: -o together with -C.
    let both = run_output(&[
        "salvage",
        archive.to_str().unwrap(),
        "-o",
        out_file.to_str().unwrap(),
        "-C",
        dir.join("out").to_str().unwrap(),
        "--index",
        "0",
    ]);
    assert_eq!(both.status.code(), Some(2));
}

/// `-o` against a Partial entry lands under `FILE.partial`, never `FILE` —
/// the same rule `-C` follows, applied to a caller-named path.
#[test]
fn salvage_output_suffixes_a_partial_entry() {
    let dir = tmp_dir();
    let path = dir.join("mixed.zip");
    std::fs::write(&path, build_partial_and_unverified_zip_fixture()).unwrap();
    let out_file = dir.join("wanted.bin");

    let out = run_output(&[
        "salvage",
        path.to_str().unwrap(),
        "-o",
        out_file.to_str().unwrap(),
        "--index",
        "0",
    ]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out_file.exists(),
        "a Partial entry must never land under the literal -o path"
    );
    let partial_path = dir.join("wanted.bin.partial");
    assert_eq!(
        std::fs::read(&partial_path).unwrap(),
        b"this payload's crc field below is wrong on purpose"
    );
}

/// Security audit EXTRACT-1 (a): `salvage -C` has no `--force`, and it used
/// to replace whatever the destination already held under an entry's name —
/// a hostile archive salvaged into a home directory replaced `.bashrc` and
/// `.ssh/authorized_keys` (0600 became 0644) at exit 0. A file this run did
/// not write is never removed or overwritten now: the recovered copy lands
/// beside it as `NAME.salvaged-N`, and the run exits 4.
#[cfg(unix)]
#[test]
fn salvage_never_replaces_a_file_the_destination_already_held() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmp_dir();
    let archive = dir.join("hostile.zip");
    std::fs::write(
        &archive,
        stored_zip_of(&[
            ("a.txt", b"attacker a\n"),
            (".ssh/authorized_keys", b"ssh-ed25519 ATTACKER\n"),
            ("fresh.txt", b"nothing was here\n"),
        ]),
    )
    .unwrap();
    let dest = dir.join("home");
    std::fs::create_dir_all(dest.join(".ssh")).unwrap();
    std::fs::write(dest.join("a.txt"), b"mine\n").unwrap();
    let keys = dest.join(".ssh/authorized_keys");
    std::fs::write(&keys, b"ssh-ed25519 MINE\n").unwrap();
    std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o600)).unwrap();

    let out = run_output(&[
        "salvage",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(4), "stderr: {stderr}");

    assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"mine\n");
    assert_eq!(std::fs::read(&keys).unwrap(), b"ssh-ed25519 MINE\n");
    assert_eq!(
        std::fs::metadata(&keys).unwrap().permissions().mode() & 0o7777,
        0o600,
        "the pre-existing file's mode must not change"
    );
    assert_eq!(
        std::fs::read(dest.join("a.txt.salvaged-0")).unwrap(),
        b"attacker a\n"
    );
    assert_eq!(
        std::fs::read(dest.join(".ssh/authorized_keys.salvaged-1")).unwrap(),
        b"ssh-ed25519 ATTACKER\n"
    );
    assert_eq!(
        std::fs::read(dest.join("fresh.txt")).unwrap(),
        b"nothing was here\n",
        "an entry whose name was free still lands under it"
    );
    assert!(
        stderr.contains("2 renamed"),
        "the summary must count both renames: {stderr}"
    );
    assert!(
        stderr.contains("a.txt.salvaged-0") && stderr.contains("authorized_keys.salvaged-1"),
        "stderr must name where each recovered copy went: {stderr}"
    );
}

/// Security audit EXTRACT-1 (b): an entry carrying the archive's own name,
/// salvaged into the archive's own directory, used to unlink the archive;
/// every later entry then failed to re-read it and the run left the
/// directory empty. The archive is byte-identical afterwards now, and the
/// other entries are recovered.
#[test]
fn salvage_never_replaces_the_archive_it_is_reading() {
    let dir = tmp_dir();
    let work = dir.join("w");
    std::fs::create_dir_all(&work).unwrap();
    let archive = work.join("damaged.zip");
    const LATER: &[u8] = &[b'x'; 1100];
    let bytes = stored_zip_of(&[("damaged.zip", b"gone"), ("later.txt", LATER)]);
    std::fs::write(&archive, &bytes).unwrap();

    let out = run_output(&[
        "salvage",
        archive.to_str().unwrap(),
        "-C",
        work.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(4), "stderr: {stderr}");
    assert_eq!(
        std::fs::read(&archive).unwrap(),
        bytes,
        "the archive must survive"
    );
    assert_eq!(
        std::fs::read(work.join("damaged.zip.salvaged-0")).unwrap(),
        b"gone"
    );
    assert_eq!(std::fs::read(work.join("later.txt")).unwrap(), LATER);
}

/// Security audit EXTRACT-1, the `-o` half: `-o FILE` replaces an existing
/// FILE (the caller named it), but never the archive being salvaged.
#[test]
fn salvage_output_refuses_to_name_the_archive_it_is_reading() {
    let dir = tmp_dir();
    let archive = dir.join("a.zip");
    let bytes = stored_zip_of(&[("x.txt", b"recovered")]);
    std::fs::write(&archive, &bytes).unwrap();

    let out = run_output(&[
        "salvage",
        archive.to_str().unwrap(),
        "--index",
        "0",
        "-o",
        archive.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(&archive).unwrap(), bytes);
}

/// Fix round 1 of EXTRACT-1: a symlink at a salvage target — live or
/// dangling — is the destination's, so it stays exactly as it was, what it
/// points at is untouched (nothing is written through it), and the record
/// lands as `NAME.salvaged-N`.
#[cfg(unix)]
#[test]
fn salvage_leaves_a_symlink_at_its_target_alone() {
    let dir = tmp_dir();
    let archive = dir.join("links.zip");
    std::fs::write(
        &archive,
        stored_zip_of(&[
            ("live", b"recovered live"),
            ("dangling", b"recovered dangling"),
        ]),
    )
    .unwrap();
    let dest = dir.join("out");
    std::fs::create_dir_all(&dest).unwrap();
    let pointee = dir.join("pointee.txt");
    std::fs::write(&pointee, b"untouched").unwrap();
    let missing = dir.join("missing.txt");
    std::os::unix::fs::symlink(&pointee, dest.join("live")).unwrap();
    std::os::unix::fs::symlink(&missing, dest.join("dangling")).unwrap();

    let out = run_output(&[
        "salvage",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read_link(dest.join("live")).unwrap(), pointee);
    assert_eq!(std::fs::read_link(dest.join("dangling")).unwrap(), missing);
    assert_eq!(std::fs::read(&pointee).unwrap(), b"untouched");
    assert!(
        !missing.exists(),
        "nothing may be created through a dangling link"
    );
    assert_eq!(
        std::fs::read(dest.join("live.salvaged-0")).unwrap(),
        b"recovered live"
    );
    assert_eq!(
        std::fs::read(dest.join("dangling.salvaged-1")).unwrap(),
        b"recovered dangling"
    );
}

/// Fix round 1 of EXTRACT-1: the archive reached through another name at
/// the target — a symlink to it, or a hard link to it — is never removed or
/// overwritten by salvage.
#[cfg(unix)]
#[test]
fn salvage_never_replaces_the_archive_through_a_link_at_the_target() {
    let dir = tmp_dir();
    let archive = dir.join("damaged.zip");
    let bytes = stored_zip_of(&[("soft.zip", b"one"), ("hard.zip", b"two")]);
    std::fs::write(&archive, &bytes).unwrap();
    let dest = dir.join("out");
    std::fs::create_dir_all(&dest).unwrap();
    std::os::unix::fs::symlink(&archive, dest.join("soft.zip")).unwrap();
    std::fs::hard_link(&archive, dest.join("hard.zip")).unwrap();

    let out = run_output(&[
        "salvage",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(&archive).unwrap(), bytes);
    assert_eq!(std::fs::read_link(dest.join("soft.zip")).unwrap(), archive);
    assert_eq!(std::fs::read(dest.join("hard.zip")).unwrap(), bytes);
    assert_eq!(
        std::fs::read(dest.join("soft.zip.salvaged-0")).unwrap(),
        b"one"
    );
    assert_eq!(
        std::fs::read(dest.join("hard.zip.salvaged-1")).unwrap(),
        b"two"
    );
}

/// Fix round 1 of EXTRACT-1: a re-run into the same directory leaves the
/// first run's output alone and writes its copies beside it.
#[test]
fn a_salvage_rerun_writes_beside_the_previous_output() {
    let dir = tmp_dir();
    let archive = dir.join("a.zip");
    std::fs::write(&archive, stored_zip_of(&[("x.txt", b"recovered")])).unwrap();
    let dest = dir.join("out");
    let run = || {
        run_output(&[
            "salvage",
            archive.to_str().unwrap(),
            "-C",
            dest.to_str().unwrap(),
        ])
    };
    assert_eq!(run().status.code(), Some(0));
    std::fs::write(dest.join("x.txt"), b"edited since").unwrap();
    let second = run();
    assert_eq!(
        second.status.code(),
        Some(4),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(std::fs::read(dest.join("x.txt")).unwrap(), b"edited since");
    assert_eq!(
        std::fs::read(dest.join("x.txt.salvaged-0")).unwrap(),
        b"recovered"
    );
}
