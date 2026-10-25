use crate::common::*;
use std::path::Path;
use std::process::Command;

// ---------------------------------------------------------------------
// Task 7: the evidence.
//
// A damage catalogue built over ONE archive the REAL `zip` binary wrote
// (never this project's own writer), an external witness (`zip -FF`)
// cross-checked against the identical bytes, and — from the other
// direction — the healthy-archive-agrees-with-list property, proven inside
// `stuffr-formats` itself: see `zip_salvage.rs`'s
// `salvage_of_a_healthy_archive_agrees_with_list`, which this crate has no
// way to duplicate (it does not depend on `stuffr-formats`'s internals, on
// purpose, matching this section's own choice below to hand-parse a real
// zip rather than pull in a second zip-writing/reading stack).
//
// The reference archive: three Stored (`-0`, no compression to reason
// about), no-extra-field (`-X`) entries, so a payload byte or a CRC-32
// field can be mutated in place without moving any offset or length
// anywhere else in the file. What went in is known because THIS TEST chose
// the three files' names and bytes, not recovered from the archive after
// the fact — "the expectation is the pre-damage state, written by zip, not
// by us."
// ---------------------------------------------------------------------

/// Damage catalogue row 1/5: a truncated tail — the canonical damaged zip,
/// an interrupted download. Cutting the archive partway through its LAST
/// entry's payload (dropping the central directory along with the missing
/// bytes) must recover the two earlier entries `Intact`, must NOT invent
/// the missing bytes of the third, and must SAY SO.
///
/// **This test asserted the opposite until the final whole-branch review**:
/// that the truncated entry was absent from the scan entirely. That was the
/// behaviour, and it was a correct refusal (`zip -FF` fabricates the
/// missing bytes and reports success — see `zip_salvage.rs`'s module doc)
/// implemented as silence. A three-header archive reported "2 scanned: 2
/// written" at exit 0, at every one of six truncation points swept across
/// the last entry, for a file the user reached for `salvage` precisely
/// because it was truncated. The refusal to invent is unchanged; what the
/// run says about it is not.
#[test]
fn damage_catalogue_truncated_tail() {
    let dir = tmp_dir();
    let (archive, _entries) = build_real_healthy_zip(&dir);
    let healthy = std::fs::read(&archive).unwrap();

    let real_entries = parse_real_zip_local_entries(&healthy);
    assert_eq!(
        real_entries
            .iter()
            .map(|e| e.name.as_str())
            .collect::<Vec<_>>(),
        vec!["alpha.txt", "beta.txt", "gamma.bin"],
        "sanity: the reference archive's own three entries, in file order"
    );
    let gamma = &real_entries[2];
    let cut = gamma.payload.start + gamma.payload.len() / 2;
    let path = dir.join("truncated.zip");
    std::fs::write(&path, &healthy[..cut]).unwrap();

    let rows = salvage_list_rows(&path);
    assert_eq!(
        rows.len(),
        3,
        "all three local headers are there, and the third one being uncompletable is a \
         fact worth a row: {rows:?}"
    );
    assert!(
        rows[0].contains("alpha.txt") && rows[0].contains("Intact"),
        "{rows:?}"
    );
    assert!(
        rows[1].contains("beta.txt") && rows[1].contains("Intact"),
        "{rows:?}"
    );
    assert!(
        rows[2].contains("gamma.bin") && rows[2].contains("Partial (truncated)"),
        "the truncated entry must be named, and named as truncated rather than as a bad \
         checksum — the payload ran out, nothing disagreed: {rows:?}"
    );

    // And the run must not exit 0. Recovering into a directory writes the
    // genuine prefix under `.partial`, never under the entry's real name.
    let out_dir = dir.join("recovered");
    let out = run_output(&[
        "salvage",
        path.to_str().unwrap(),
        "-C",
        out_dir.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "a run that dropped something must not exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut names: Vec<String> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        ["alpha.txt", "beta.txt", "gamma.bin.partial"],
        "the surviving prefix lands under `.partial`, never under `gamma.bin`"
    );

    // Not one invented byte: what is on disk is exactly the prefix that
    // survived the cut, and strictly shorter than the entry declared.
    let recovered = std::fs::read(out_dir.join("gamma.bin.partial")).unwrap();
    let declared = gamma.payload.len();
    assert!(
        !recovered.is_empty() && recovered.len() < declared,
        "{} recovered bytes against a declared {declared}",
        recovered.len()
    );
    assert_eq!(
        recovered[..],
        healthy[gamma.payload.start..cut],
        "every recovered byte must come from the truncated file itself — `zip -FF` fills \
         the gap from its own buffer and calls the result fixed"
    );
}

/// The sweep the whole-branch review ran, as a test: every truncation point
/// inside the last entry's payload must produce a row and a non-zero exit.
///
/// One point would not be enough. The defect this closes was uniform — 100,
/// 500, 2000, 3000, 4030 and 4043 bytes of the last payload present all
/// reported "2 scanned" at exit 0 — and a single sample could pass on a
/// boundary while the interior stayed silent.
#[test]
fn every_truncation_point_inside_the_last_entry_is_reported() {
    let dir = tmp_dir();
    let (archive, _entries) = build_real_healthy_zip(&dir);
    let healthy = std::fs::read(&archive).unwrap();
    let real_entries = parse_real_zip_local_entries(&healthy);
    let gamma = &real_entries[2];
    let declared = gamma.payload.len();

    // Both ends included: 0 surviving payload bytes (the header alone) and
    // one byte short of complete.
    for keep in [0, 1, declared / 4, declared / 2, declared - 1] {
        let path = dir.join(format!("truncated-{keep}.zip"));
        std::fs::write(&path, &healthy[..gamma.payload.start + keep]).unwrap();

        let rows = salvage_list_rows(&path);
        assert_eq!(
            rows.len(),
            3,
            "keep={keep}: the third header is there and must be counted: {rows:?}"
        );
        assert!(
            rows[2].contains("Partial (truncated)"),
            "keep={keep}: {rows:?}"
        );

        let out_dir = dir.join(format!("out-{keep}"));
        let out = run_output(&[
            "salvage",
            path.to_str().unwrap(),
            "-C",
            out_dir.to_str().unwrap(),
        ]);
        assert_eq!(
            out.status.code(),
            Some(4),
            "keep={keep}: must not exit 0: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // The complement, so none of the above can pass by reporting everything
    // as truncated: the UNCUT archive still exits 0 with three clean rows.
    let whole = dir.join("whole.zip");
    std::fs::write(&whole, &healthy).unwrap();
    let out = run_output(&["salvage", whole.to_str().unwrap(), "--list"]);
    assert_eq!(out.status.code(), Some(0));
    let rows = String::from_utf8(out.stdout).unwrap();
    assert_eq!(rows.matches("Partial").count(), 0, "{rows}");
}

/// Damage catalogue row 2/5: a zeroed central directory. With the index
/// destroyed entirely, `salvage_zip` falls back to the raw local-header
/// scan alone and must still find and verify all three entries.
#[test]
fn damage_catalogue_zeroed_central_directory() {
    let dir = tmp_dir();
    let (archive, _entries) = build_real_healthy_zip(&dir);
    let healthy = std::fs::read(&archive).unwrap();
    let path = dir.join("zeroed_cd.zip");
    std::fs::write(&path, mutate_zeroed_central_directory(&healthy)).unwrap();

    let rows = salvage_list_rows(&path);
    assert_eq!(rows.len(), 3, "{rows:?}");
    for (row, name) in rows.iter().zip(["alpha.txt", "beta.txt", "gamma.bin"]) {
        assert!(
            row.contains(name) && row.contains("Intact"),
            "every entry must still be found by the raw scan and verify Intact: {row}"
        );
    }
}

/// Damage catalogue row 3/5: a hole punched mid-payload. Only the MIDDLE
/// entry's content is damaged (its declared length and its own CRC-32
/// field are untouched), so its neighbours must be unaffected and it alone
/// must come back `Partial`.
#[test]
fn damage_catalogue_hole_punched_mid_payload() {
    let dir = tmp_dir();
    let (archive, _entries) = build_real_healthy_zip(&dir);
    let healthy = std::fs::read(&archive).unwrap();
    let path = dir.join("hole_punched.zip");
    std::fs::write(&path, mutate_hole_punched_mid_payload(&healthy)).unwrap();

    let rows = salvage_list_rows(&path);
    assert_eq!(rows.len(), 3, "{rows:?}");
    assert!(
        rows[0].contains("alpha.txt") && rows[0].contains("Intact"),
        "{rows:?}"
    );
    assert!(
        rows[1].contains("beta.txt") && rows[1].contains("Partial"),
        "the punched entry's content no longer matches its own declared CRC-32: {rows:?}"
    );
    assert!(
        rows[2].contains("gamma.bin") && rows[2].contains("Intact"),
        "{rows:?}"
    );
}

/// Damage catalogue row 4/5: one CRC corrupted. Only the FIRST entry's
/// LOCAL-HEADER `crc32` field is flipped — its payload and the central
/// directory's own copy of the checksum are untouched — so the raw scan
/// (which builds its verifier from the LOCAL header, not the central
/// directory) reports a checksum that no longer matches the real content.
#[test]
fn damage_catalogue_one_crc_corrupted() {
    let dir = tmp_dir();
    let (archive, _entries) = build_real_healthy_zip(&dir);
    let healthy = std::fs::read(&archive).unwrap();
    let path = dir.join("crc_corrupted.zip");
    std::fs::write(&path, mutate_one_crc_corrupted(&healthy)).unwrap();

    let rows = salvage_list_rows(&path);
    assert_eq!(rows.len(), 3, "{rows:?}");
    assert!(
        rows[0].contains("alpha.txt") && rows[0].contains("Partial"),
        "the corrupted entry's declared checksum no longer matches its (untouched) payload: \
         {rows:?}"
    );
    assert!(
        rows[1].contains("beta.txt") && rows[1].contains("Intact"),
        "{rows:?}"
    );
    assert!(
        rows[2].contains("gamma.bin") && rows[2].contains("Intact"),
        "{rows:?}"
    );
}

/// Damage catalogue row 5/5: a duplicated record. 8 records over 6 names is
/// `build_shadowing_zip_fixture`'s own shape; this is its 4-records-over-3-
/// names sibling, built over an archive the SYSTEM `zip` wrote.
#[test]
fn damage_catalogue_duplicated_record() {
    let dir = tmp_dir();
    let (archive, _entries) = build_real_healthy_zip(&dir);
    let healthy = std::fs::read(&archive).unwrap();
    let path = dir.join("duplicated.zip");
    std::fs::write(&path, duplicate_first_central_directory_record(&healthy)).unwrap();

    let rows = salvage_list_rows(&path);
    assert_eq!(rows.len(), 4, "3 names, 4 physical records: {rows:?}");
    assert!(
        rows[0].contains("alpha.txt") && rows[0].contains("Intact"),
        "{rows:?}"
    );
    assert!(
        rows[1].contains("beta.txt") && rows[1].contains("Intact"),
        "{rows:?}"
    );
    assert!(
        rows[2].contains("gamma.bin") && rows[2].contains("Intact"),
        "{rows:?}"
    );
    assert!(
        rows[3].contains("alpha.txt")
            && rows[3].contains("Intact")
            && rows[3].contains("[shadowed: dup of #0]"),
        "the extra physical copy must be reported Intact (nothing in it is damaged) AND \
         flagged as shadowing scan position 0: {rows:?}"
    );
}

/// Step 3: the external witness, row 1/3. Info-Zip's `zip -FF` is a
/// genuine second implementation of zip recovery, cross-checked here on
/// the zeroed-central-directory shape — the one damage catalogue row that
/// forces BOTH tools onto a raw local-header scan with nothing to
/// reconcile against, so it needs `zip -FF`'s own recovery step (unlike
/// the two sibling tests below it, which check a reference tool directly
/// with no recovery step at all). `zip_salvage.rs`'s own module doc
/// records the ONE shape found where the two tools do NOT agree (a
/// truncated last entry, where `zip -FF` was measured fabricating bytes
/// for content that no longer exists) and why that is Info-Zip's tool
/// being the one that is wrong, rather than tuned away here.
#[cfg(unix)]
#[test]
fn info_zip_recovers_the_same_entries_we_do() {
    let zip_bin = require_bin("zip");
    let unzip_bin = require_bin("unzip");

    let dir = tmp_dir();
    let (archive, _entries) = build_real_healthy_zip(&dir);
    let healthy = std::fs::read(&archive).unwrap();
    let damaged = dir.join("zeroed_cd_for_witness.zip");
    std::fs::write(&damaged, mutate_zeroed_central_directory(&healthy)).unwrap();

    // Our own recovery.
    let rows = salvage_list_rows(&damaged);
    assert_eq!(rows.len(), 3, "{rows:?}");
    for (row, name) in rows.iter().zip(["alpha.txt", "beta.txt", "gamma.bin"]) {
        assert!(
            row.contains(name) && row.contains("Intact"),
            "our own recovery must find every entry, Intact: {row}"
        );
    }

    // Info-Zip's own recovery.
    let fixed = dir.join("witness_fixed.zip");
    let out = run_zip_ff(&zip_bin, &damaged, &fixed);
    assert!(
        out.status.success(),
        "zip -FF failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let test_out = Command::new(&unzip_bin)
        .args(["-t", fixed.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        test_out.status.success(),
        "unzip -t reported a problem with zip -FF's own recovered archive: {}",
        String::from_utf8_lossy(&test_out.stdout)
    );
    let test_text = String::from_utf8_lossy(&test_out.stdout);
    for name in ["alpha.txt", "beta.txt", "gamma.bin"] {
        let line = test_text
            .lines()
            .find(|l| l.contains(name))
            .unwrap_or_else(|| {
                panic!("zip -FF's own recovery must still contain `{name}`: {test_text}")
            });
        assert!(
            line.contains("OK"),
            "we call `{name}` Intact; Info-Zip's own independent recovery must agree it \
             decodes cleanly: {line}"
        );
    }
}

/// Step 3: the external witness, row 2/3 (fix round 1, REQUIRED 1). A hole
/// punched mid-payload leaves the central directory untouched, so — unlike
/// the zeroed-CD test above — this needs no `zip -FF` recovery step and no
/// interactive prompt at all: plain `unzip -t` reads the same intact index
/// stuffr's own central-directory reconciliation would, and only its
/// per-entry CRC-32 check can disagree.
#[cfg(unix)]
#[test]
fn info_zip_agrees_on_a_hole_punched_payload() {
    let unzip_bin = require_bin("unzip");

    let dir = tmp_dir();
    let (archive, _entries) = build_real_healthy_zip(&dir);
    let healthy = std::fs::read(&archive).unwrap();
    let path = dir.join("hole_punched_for_witness.zip");
    std::fs::write(&path, mutate_hole_punched_mid_payload(&healthy)).unwrap();

    let rows = salvage_list_rows(&path);
    assert_eq!(rows.len(), 3, "{rows:?}");
    let lines = unzip_test_lines(&unzip_bin, &path);
    for (name, intact) in [
        ("alpha.txt", true),
        ("beta.txt", false),
        ("gamma.bin", true),
    ] {
        let our_row = rows
            .iter()
            .find(|r| r.contains(name))
            .unwrap_or_else(|| panic!("our own recovery must still report `{name}`: {rows:?}"));
        assert_eq!(
            our_row.contains("Intact"),
            intact,
            "our own verdict for `{name}`: {our_row}"
        );
        let their_line = unzip_test_line_for(&lines, name);
        assert_eq!(
            their_line.contains("OK"),
            intact,
            "Info-Zip's own independent verdict for `{name}` must agree with ours: {their_line}"
        );
    }
}

/// Step 3: the external witness, row 3/3 (fix round 1, REQUIRED 1). One
/// CRC corrupted leaves the central directory untouched too — same
/// reasoning as the hole-punch test above, no `zip -FF` step needed.
#[cfg(unix)]
#[test]
fn info_zip_agrees_on_a_corrupted_crc() {
    let unzip_bin = require_bin("unzip");

    let dir = tmp_dir();
    let (archive, _entries) = build_real_healthy_zip(&dir);
    let healthy = std::fs::read(&archive).unwrap();
    let path = dir.join("crc_corrupted_for_witness.zip");
    std::fs::write(&path, mutate_one_crc_corrupted(&healthy)).unwrap();

    let rows = salvage_list_rows(&path);
    assert_eq!(rows.len(), 3, "{rows:?}");
    let lines = unzip_test_lines(&unzip_bin, &path);
    for (name, intact) in [
        ("alpha.txt", false),
        ("beta.txt", true),
        ("gamma.bin", true),
    ] {
        let our_row = rows
            .iter()
            .find(|r| r.contains(name))
            .unwrap_or_else(|| panic!("our own recovery must still report `{name}`: {rows:?}"));
        assert_eq!(
            our_row.contains("Intact"),
            intact,
            "our own verdict for `{name}`: {our_row}"
        );
        let their_line = unzip_test_line_for(&lines, name);
        assert_eq!(
            their_line.contains("OK"),
            intact,
            "Info-Zip's own independent verdict for `{name}` must agree with ours: {their_line}"
        );
    }
}

/// Fix round 5, NEW-G. **A salvage entry that could not be written must be
/// named on stderr by the invocation a user actually types** — plain `-C`,
/// with no `--list`.
///
/// Task 3c's fix round 4 turned a filesystem failure from an aborted run
/// (exit 1, on a name the ARCHIVE chose) into a per-entry skip, and rested
/// that ruling on "the reason is on its own row, so nothing is silent". The
/// row only existed under `--list`. Measured on the shipped binary against a
/// read-only destination and a genuine ENOSPC volume, plain `salvage -C DIR`
/// printed `3 scanned: 0 written … 3 skipped` at exit 4 and **nothing on
/// stderr at all** — so a user could not tell a full disk from one entry the
/// archive made unwritable, which is the exact question that ruling's trade
/// turns on.
///
/// The fixture is the one from `entries.rs`'s own regression test: three
/// healthy Stored entries with a 404-character name in the middle, longer
/// than `NAME_MAX` on every filesystem this project builds for (255 on APFS,
/// ext4 and XFS), so `File::create` refuses it deterministically and without
/// needing a special volume, a permission trick or a `root` check.
///
/// Asserts the whole shape, because each half was separately wrong at some
/// point in this task's history: the run COMPLETES (exit 4, not 1), the
/// entries on either side are on disk with their real bytes, and the failure
/// is NAMED on stderr without `--list`.
#[test]
fn a_salvage_entry_that_cannot_be_written_is_named_on_stderr_without_list() {
    fn stored_local_record(name: &str, payload: &[u8]) -> Vec<u8> {
        let crc = salvage_fixture_crc32(payload);
        let len = u32::try_from(payload.len()).unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
        bytes.extend_from_slice(&20u16.to_le_bytes()); // version needed
        bytes.extend_from_slice(&0u16.to_le_bytes()); // flags
        bytes.extend_from_slice(&0u16.to_le_bytes()); // Stored
        bytes.extend_from_slice(&0u16.to_le_bytes()); // mod time
        bytes.extend_from_slice(&0x21u16.to_le_bytes()); // mod date
        bytes.extend_from_slice(&crc.to_le_bytes());
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(&u16::try_from(name.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes()); // extra len
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    let dir = tmp_dir();
    let long_name = format!("{}.txt", "L".repeat(400));
    let mut zip = stored_local_record("a.txt", b"AAAA");
    zip.extend_from_slice(&stored_local_record(&long_name, b"BBBB"));
    zip.extend_from_slice(&stored_local_record("z.txt", b"ZZZZ"));
    let archive = dir.join("unwritable-name.zip");
    std::fs::write(&archive, &zip).unwrap();

    let out_dir = dir.join("recovered");
    // No `--list`: this is the invocation the finding is about.
    let out = run_output(&[
        "salvage",
        archive.to_str().unwrap(),
        "--format",
        "zip",
        "-C",
        out_dir.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();

    assert_eq!(
        out.status.code(),
        Some(4),
        "one unwritable name is a degraded run, never a failed one (and never exit 1, the \
         code reserved for stuffr itself failing, on input the archive chose): {stderr}"
    );
    assert!(
        stderr.contains("could not be written"),
        "the run must SAY an entry was not written, on stderr, without --list — the whole \
         fold rests on this not being silent: {stderr}"
    );
    assert!(
        stderr.contains("#1"),
        "and it must name WHICH entry by scan position, or a user cannot act on it: {stderr}"
    );

    // The survivors on either side, byte-for-byte — `z.txt` is the one the
    // pre-round-4 abort lost entirely.
    assert_eq!(std::fs::read(out_dir.join("a.txt")).unwrap(), b"AAAA");
    assert_eq!(std::fs::read(out_dir.join("z.txt")).unwrap(), b"ZZZZ");
}

/// **Fix round 1's LOW: the prose about which formats salvage actually
/// scans had no guard, and had just gone stale once.**
///
/// `salvage_format_by_name`'s *table* is already pinned against the live
/// registry (`main.rs`'s
/// `salvage_format_by_name_recognises_every_registered_container`), but that
/// table says only which names are *recognised* — every registered container
/// is, compiled scanner or not. Which of them this build can actually SCAN
/// was hand-maintained prose in two places, and both said "only zip" from
/// Salvage Stage 1 until Stage 2 Task 4 noticed: `arc` had been wired for a
/// whole task with neither document mentioning it.
///
/// So this derives the truth from the BINARY rather than from any list.
/// Every name `--format` accepts is run against a junk file: a wired format
/// reaches its own scanner and finds nothing (`the scan found nothing
/// recoverable`, exit 5), an unwired one is refused by `salvage_scan`'s own
/// fallback (`salvage has no scanner for`, exit 3). Those two messages are
/// the discriminator, and they are `entries.rs`'s own words, not this
/// test's guess at them.
///
/// Both documents carry one machine-readable sentence — `Scanners exist
/// for: …` — and both must name exactly that set. A scanner landing without
/// its documentation, or documentation naming a scanner that does not exist,
/// fails here.
#[test]
fn the_documented_salvage_scanner_list_matches_what_the_binary_actually_scans() {
    /// Pulls the comma-separated list out of the one marker sentence both
    /// documents carry.
    fn documented(text: &str, label: &str) -> Vec<String> {
        let at = text
            .find("Scanners exist for:")
            .unwrap_or_else(|| panic!("{label} must carry a `Scanners exist for:` sentence"));
        let rest = &text[at + "Scanners exist for:".len()..];
        let end = rest.find('.').unwrap_or_else(|| {
            panic!("{label}'s `Scanners exist for:` sentence must end in a `.`")
        });
        let mut names: Vec<String> = rest[..end]
            .split(',')
            .map(|n| n.trim().to_string())
            .filter(|n| !n.is_empty())
            .collect();
        names.sort();
        names
    }

    let tmp = tmp_dir();
    let junk = tmp.join("salvage-doc-guard-not-an-archive.bin");
    std::fs::write(&junk, b"these bytes are no format's magic at all\n").unwrap();

    // Every name `salvage_format_by_name` accepts — taken from its own
    // `Usage` message rather than restated here, so a ninth name cannot be
    // added to that table without this test seeing it.
    let usage = run_output(&[
        "salvage",
        "--format",
        "definitely-not-a-format",
        junk.to_str().unwrap(),
        "--list",
    ]);
    let usage_text = String::from_utf8_lossy(&usage.stderr).to_string();
    let recognised: Vec<String> = usage_text
        .split_once("salvage recognizes:")
        .unwrap_or_else(|| panic!("expected the `salvage recognizes:` usage message: {usage_text}"))
        .1
        .split(',')
        .map(|n| n.trim().trim_end_matches('\n').to_string())
        .filter(|n| !n.is_empty())
        .collect();
    assert!(
        recognised.len() >= 8,
        "the parse found {recognised:?}; if that is short the scan is broken, not the table"
    );

    let mut wired: Vec<String> = Vec::new();
    for name in &recognised {
        let out = run_output(&[
            "salvage",
            "--format",
            name,
            junk.to_str().unwrap(),
            "--list",
        ]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let unwired = stderr.contains("salvage has no scanner for");
        if !unwired {
            assert!(
                stderr.contains("found nothing recoverable"),
                "`--format {name}` over junk answered neither refusal nor an empty scan, so \
                 this test can no longer tell wired from unwired: {stderr}"
            );
            wired.push(name.clone());
        }
    }
    wired.sort();
    assert!(
        !wired.is_empty(),
        "no format scanned at all — the discriminator is broken, not the docs"
    );

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let examples = std::fs::read_to_string(manifest_dir.join("src").join("examples.txt")).unwrap();
    let help = String::from_utf8_lossy(&run_output(&["salvage", "--help"]).stdout).to_string();

    assert_eq!(
        documented(&examples, "examples.txt"),
        wired,
        "`examples.txt` names a different set of salvage scanners than this binary has"
    );
    assert_eq!(
        documented(&help, "`salvage --format`'s help"),
        wired,
        "`--format`'s help names a different set of salvage scanners than this binary has"
    );
}

/// Salvage Stage 3 Task 5: `stuffr formats` grew a SALVAGE column, and the
/// examples page must say what it prints — derived from the BINARY's own
/// table, the way the scanner-list guard above derives from its exit codes,
/// so neither a page naming the wrong set nor a column change the page
/// never caught up with can pass.
///
/// The page carries one machine-readable sentence per non-`-` value,
/// `SALVAGE reads VALUE for: a, b, c.`, and each must name exactly the rows
/// `stuffr formats` prints with that value. Both legs run it: which rows
/// exist is the registry's, and which value each shows comes from
/// `ContainerCaps::salvage` and the format's attestation class, not from
/// anything this test or the page restates.
#[test]
fn the_examples_page_documents_the_salvage_column_stuffr_formats_prints() {
    let formats = run_output(&["formats"]);
    assert!(formats.status.success(), "stuffr formats must exit 0");
    let table = String::from_utf8(formats.stdout).unwrap();
    let mut lines = table.lines();
    let header: Vec<&str> = lines.next().unwrap().split_whitespace().collect();
    // Every column before EXTENSIONS is one token wide, so the header's
    // token index is the row's too; EXTENSIONS (empty, or several) is last.
    let at = header
        .iter()
        .position(|c| *c == "SALVAGE")
        .unwrap_or_else(|| panic!("stuffr formats must print a SALVAGE column: {header:?}"));
    let mut shown: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for line in lines.take_while(|l| !l.trim().is_empty()) {
        let cells: Vec<&str> = line.split_whitespace().collect();
        shown
            .entry(cells[at].to_string())
            .or_default()
            .push(cells[0].to_string());
    }
    for value in shown.keys() {
        assert!(
            ["yes", "weak", "-"].contains(&value.as_str()),
            "SALVAGE printed `{value}`, which the page does not define"
        );
    }

    let out = run_output(&["--examples"]);
    let examples = String::from_utf8(out.stdout).unwrap();
    for value in ["yes", "weak"] {
        let marker = format!("SALVAGE reads {value} for:");
        let at = examples
            .find(&marker)
            .unwrap_or_else(|| panic!("the examples page must carry a `{marker}` sentence"));
        let rest = &examples[at + marker.len()..];
        let end = rest
            .find('.')
            .unwrap_or_else(|| panic!("the `{marker}` sentence must end in a `.`"));
        let mut documented: Vec<String> = rest[..end]
            .split(',')
            .map(|n| n.trim().to_string())
            .filter(|n| !n.is_empty())
            .collect();
        documented.sort();
        let mut printed = shown.get(value).cloned().unwrap_or_default();
        printed.sort();
        assert!(
            !printed.is_empty(),
            "no row printed SALVAGE `{value}` — the column is broken, not the page"
        );
        assert_eq!(
            documented, printed,
            "`--examples` says SALVAGE reads `{value}` for a different set of formats than \
             `stuffr formats` prints"
        );
    }
}
