use crate::common::*;
use std::path::Path;
use std::process::Command;

// ---------------------------------------------------------------------
// Salvage Stage 2 Task 7: the legacy damage catalogue, end to end.
//
// The fast half of this catalogue lives beside each scanner — see
// `crates/stuffr-formats/src/legacy/{arc,zoo,lha,arj}_salvage.rs`'s own
// `mod damage_catalogue`, which owns the agreement property (salvage of an
// UNDAMAGED archive must agree exactly with what the ordinary reader
// enumerates) and the full mutation table (truncated tail, a byte flipped
// mid-payload, a header field corrupted, each run with every entry taking
// its turn as the damaged one). Those tests reach parsers and geometry this
// binary deliberately cannot see, exactly as `zip_salvage.rs`'s own
// `salvage_of_a_healthy_archive_agrees_with_list` does for zip.
//
// What this file adds is the part only a process can state: the ROWS a user
// reads, the EXIT CODE a script branches on, and — the claim that separates
// this tool from `zip -FF` — that the bytes on disk after a recovery are a
// genuine prefix of what went in, with nothing invented to fill the gap.
//
// **The evidence behind each format is NOT equal, and these tests say so
// rather than presenting four identical-looking rows:**
//
// * **ARC and ZOO** — the archives are the borrowed `unarc-rs` 0.6.3
//   corpus, written by DOS-era archivers decades before this project
//   existed, each entry carrying the CRC-16 its ORIGINAL writer computed.
//   That checksum is the witness, and no `arc`/`zoo` binary is obtainable
//   on any platform in reach to add a second one.
// * **LHA** — `lhasa` exists, reads `.lzh`, and shares no code with
//   `delharc`. `lhasa_agrees_with_the_lha_damage_catalogue` below uses it
//   as a live witness: it pronounces the archive good BEFORE any damage and
//   names the damaged entry AFTER, so the damage is real by an outside
//   account and not only by ours.
// * **ARJ** — **no `arj`/`unarj` binary is obtainable anywhere in reach.**
//   `no_dedicated_arj_tool_is_obtainable_to_witness_this_catalogue` is the
//   tripwire that keeps that from being quietly forgotten.
// ---------------------------------------------------------------------

/// ARC. Two borrowed entries (`cpm.arc`, `DDTZ.COM` then `READ.COM`) so the
/// "earlier entries untouched" half of the row is a real claim, and the
/// witness is the CRC-16 each entry's own header records.
#[test]
fn damage_catalogue_arc_truncated_tail() {
    legacy_truncated_tail_row("arc", "arc/cpm.arc", 40, &["DDTZ.COM", "READ.COM"]);
}

/// ARC again, over the one borrowed fixture whose payload IS its content
/// (`store.arc`, method 2, Unpacked): with no decoder between the archive
/// and the file on disk, "the recovered bytes are a prefix of what went in"
/// is a statement about the archive's own bytes.
#[test]
fn damage_catalogue_arc_truncated_tail_over_a_stored_entry() {
    legacy_truncated_tail_row("arc/stored", "arc/store.arc", 5_000, &["LICENSE"]);
}

/// ZOO. `store.zoo`'s single method-0 entry, same reasoning as
/// `store.arc` above — and the same witness, a CRC-16 zoo 2.10 computed.
#[test]
fn damage_catalogue_zoo_truncated_tail() {
    legacy_truncated_tail_row("zoo", "zoo/store.zoo", 5_000, &["license"]);
}

/// LHA. `sample.lzh` — the one legacy fixture an implementation outside
/// this project has agreed with (`lhasa`; see
/// `crates/stuffr-formats/fixtures/legacy/MANIFEST.md`). Two `-lh0-`
/// entries, so both halves of the row are real claims.
#[test]
fn damage_catalogue_lha_truncated_tail() {
    legacy_truncated_tail_row(
        "lha",
        "sample.lzh",
        4,
        &["sample/hello.txt", "sample/sub/b.bin"],
    );
}

/// ARJ. `sample.arj`, and **nothing outside this project has ever agreed
/// with these bytes** — see `the_arj_damage_catalogue_still_has_no_
/// external_witness` below, and this section's own header comment.
#[test]
fn damage_catalogue_arj_truncated_tail() {
    legacy_truncated_tail_row(
        "arj",
        "sample.arj",
        7,
        &["sample/hello.txt", "sample/sub/b.bin"],
    );
}

/// **The external witness for LHA, and the only live one in this
/// catalogue.**
///
/// `lhasa` shares no code with `delharc` (the parser stuffr reads `.lzh`
/// through) and none at all with `lha_salvage.rs`'s own second header
/// parser. Here it does two jobs no assertion of ours can do:
///
/// 1. It pronounces the archive GOOD before any damage — so "the
///    expectation is the pre-damage state" rests on an outside opinion,
///    not only on stuffr having written the file itself.
/// 2. It names the damaged entry AFTER — so the damage is real, and
///    localised to the entry this test aimed at, by an outside account.
///
/// Only then is `stuffr salvage`'s own verdict compared against it: the
/// entry `lhasa` calls bad is the entry salvage calls `Partial`, and every
/// entry `lhasa` calls good is one salvage calls `Intact`.
#[test]
fn lhasa_agrees_with_the_lha_damage_catalogue() {
    let lha_bin = require_lhasa();
    let banner = lhasa_banner(&lha_bin);
    let dir = tmp_dir();
    std::fs::create_dir_all(dir.join("tree/sub")).unwrap();
    let alpha = b"alpha payload, the first entry, repeated often.\n".repeat(120);
    let beta = b"beta payload, the middle entry, repeated often.\n".repeat(90);
    let gamma = b"gamma payload, the last entry, repeated often.\n".repeat(70);
    std::fs::write(dir.join("tree/alpha.txt"), &alpha).unwrap();
    std::fs::write(dir.join("tree/beta.txt"), &beta).unwrap();
    std::fs::write(dir.join("tree/sub/gamma.bin"), &gamma).unwrap();
    let archive = dir.join("healthy.lzh");

    let packed = run_output(&[
        "pack",
        dir.join("tree").to_str().unwrap(),
        "--format",
        "lha",
        "-o",
        archive.to_str().unwrap(),
    ]);
    assert_eq!(packed.status.code(), Some(0));

    /// Every entry `lha t` reported on, and whether it passed. lhasa writes
    /// one `NAME\t- Tested` or `NAME\t- CRC error` phrase per entry; the
    /// `\r`-driven progress it interleaves means a phrase can share a line
    /// with earlier progress text, so this scans phrases rather than lines.
    fn lhasa_verdicts(output: &[u8]) -> Vec<(String, bool)> {
        let text = String::from_utf8_lossy(output).replace('\r', "\n");
        let mut out: Vec<(String, bool)> = Vec::new();
        for chunk in text.split('\n') {
            for (marker, ok) in [("\t- Tested", true), ("\t- CRC error", false)] {
                if let Some(at) = chunk.find(marker) {
                    let name = chunk[..at].rsplit(':').next().unwrap().trim().to_string();
                    if !name.is_empty() && !out.iter().any(|(n, _)| *n == name) {
                        out.push((name, ok));
                    }
                }
            }
        }
        out
    }

    // 1. The outside opinion on the PRE-DAMAGE archive.
    let healthy_test = Command::new(&lha_bin)
        .arg("t")
        .arg(&archive)
        .output()
        .unwrap();
    assert!(
        healthy_test.status.success(),
        "{banner} must accept the undamaged archive: {}{}",
        String::from_utf8_lossy(&healthy_test.stdout),
        String::from_utf8_lossy(&healthy_test.stderr)
    );
    let mut combined = healthy_test.stdout.clone();
    combined.extend_from_slice(&healthy_test.stderr);
    let before = lhasa_verdicts(&combined);
    assert_eq!(
        before
            .iter()
            .map(|(n, _)| n.as_str())
            .collect::<Vec<_>>()
            .join(","),
        "tree/alpha.txt,tree/beta.txt,tree/sub/gamma.bin",
        "sanity: {banner} must report on all three entries — otherwise the comparison below \
         is against a partial account"
    );
    assert!(
        before.iter().all(|(_, ok)| *ok),
        "{banner} must call every entry of the undamaged archive good: {before:?}"
    );

    // 2. The damage: one byte inside the MIDDLE entry's compressed payload.
    //    Located by searching for the entry's own `-lh5-` header, so this
    //    test never asks stuffr where anything is.
    let healthy = std::fs::read(&archive).unwrap();
    let beta_header = healthy
        .windows(5)
        .enumerate()
        .filter(|(_, w)| *w == b"-lh5-")
        .map(|(i, _)| i)
        .nth(1)
        .expect("the middle entry's own method identifier");
    let mut bytes = healthy.clone();
    // Past the header (`header_len` byte, plus its two framing bytes, plus
    // the name and the rest), a few bytes into the payload itself.
    let beta_start = beta_header - 2;
    let payload_at = beta_start + bytes[beta_start] as usize + 2 + 4;
    bytes[payload_at] ^= 0xFF;
    let damaged = dir.join("damaged.lzh");
    std::fs::write(&damaged, &bytes).unwrap();

    // 3. The outside opinion on the DAMAGED archive: one entry bad, and
    //    which one.
    let damaged_test = Command::new(&lha_bin)
        .arg("t")
        .arg(&damaged)
        .output()
        .unwrap();
    assert!(
        !damaged_test.status.success(),
        "{banner} must refuse the damaged archive, or this test proved nothing"
    );
    let mut combined = damaged_test.stdout.clone();
    combined.extend_from_slice(&damaged_test.stderr);
    let after = lhasa_verdicts(&combined);
    let condemned: Vec<&str> = after
        .iter()
        .filter(|(_, ok)| !*ok)
        .map(|(n, _)| n.as_str())
        .collect();
    assert_eq!(
        condemned,
        ["tree/beta.txt"],
        "{banner} must condemn exactly the entry this test damaged: {after:?}"
    );

    // 4. And stuffr must agree with it, entry by entry.
    let rows = salvage_list_rows(&damaged);
    assert_eq!(
        rows.len(),
        5,
        "three files and two directory entries: {rows:?}"
    );
    for (name, ok) in &after {
        let row = rows
            .iter()
            .find(|r| r.contains(name.as_str()))
            .unwrap_or_else(|| {
                panic!("salvage lost `{name}` that {banner} still reports: {rows:?}")
            });
        if *ok {
            assert!(
                row.contains("Intact"),
                "{banner} calls `{name}` good and salvage does not: {row}"
            );
        } else {
            assert!(
                row.contains("Partial"),
                "{banner} calls `{name}` bad and salvage calls it whole: {row}"
            );
        }
    }
}

/// **The tripwire, not a skip — and named for what it measures.**
///
/// Fix round 1, F7: this was `the_arj_damage_catalogue_still_has_no_external
/// _witness`, which claims more than the body checks. p7zip reading ARJ is a
/// documented fact, so "no external witness exists" is already false as a
/// statement about the world; what is true, and what decides whether this
/// catalogue can be strengthened, is that **no dedicated ARJ tool is
/// obtainable here**. The name now says that, and the exclusion of `7z` is
/// argued below rather than hidden behind a stronger claim.
///
/// ARJ's whole damage catalogue — here and in
/// `crates/stuffr-formats/src/legacy/arj_salvage.rs` — rests on
/// `unarj-rs` plus this project's own reading of the ARJ specification.
/// `fixtures/legacy/sample.arj` was hand-built from that same reading, so a
/// test can only prove the parser agrees with our own transcription; if
/// both sides share a misreading, every test in this repository stays
/// green. Phase 3c recorded the gap on the read and the write sides, and
/// the brief for this task asked that it be RESTATED rather than quietly
/// forgotten once a catalogue exists.
///
/// This is that restatement, made falsifiable: the day an `arj` or `unarj`
/// binary becomes obtainable, this test goes red and names what to do about
/// it. It is deliberately NOT a `require_bin`-shaped skip — there is
/// nothing to require — and deliberately not a comment, because a comment
/// cannot notice the world changing.
///
/// **`7z` is deliberately NOT in the list below**, though p7zip is
/// documented as reading ARJ. Two reasons, both about what this tripwire is
/// for: it is present on some CI images and absent on others, so naming it
/// would turn "the world changed" into "this runner differs from that one";
/// and nothing in this project has ever measured p7zip against an ARJ
/// stuffr wrote, so promoting it would be adopting a witness on its
/// reputation. If someone does that measurement, `7z` becomes a better
/// answer than this test and this test should go.
#[test]
fn no_dedicated_arj_tool_is_obtainable_to_witness_this_catalogue() {
    for candidate in ["arj", "unarj", "arj32"] {
        assert!(
            which(candidate).is_none(),
            "`{candidate}` is on PATH now. ARJ's catalogue has been checked against nothing \
             but this project's own reading of the spec since Phase 3b — promote \
             `damage_catalogue_arj_truncated_tail` and \
             `legacy::arj_salvage`'s own `mod damage_catalogue` to use this tool as a real \
             external witness (the shape `lhasa_agrees_with_the_lha_damage_catalogue` \
             above already has), and delete this test."
        );
    }

    // And the fixture the catalogue stands on is still the hand-built one,
    // unchanged — so the gap this test names is the gap that actually
    // exists, not a stale description of a fixture somebody has since
    // replaced with tool-written bytes.
    let sample = std::fs::read(legacy_fixture("sample.arj")).unwrap();
    assert_eq!(
        sample.len(),
        173,
        "`sample.arj` is no longer the 173-byte fixture MANIFEST.md describes; re-read its \
         provenance before trusting anything this catalogue asserts"
    );
}

/// **Ruling S-AA, falsified at the surface a user actually reads.**
///
/// Three damaged copies of the SAME borrowed ZOO corpus, differing only in
/// what was done to them, must print three different causes:
///
/// | damage | cause | what a user should do about it |
/// |---|---|---|
/// | the file cut mid-payload | `truncated` | find a longer copy; the bytes are gone |
/// | a byte flipped in an `lzd` payload | `decode failed` | the bytes present are damaged |
/// | a byte flipped in a `Stored` payload | `checksum mismatch` | you have every byte and they are wrong |
///
/// **Two of those three rows read `Partial (truncated)` before this fix
/// round**, over archives from which nothing had been cut — the `lzd` one
/// because its decoder aborts where the damage is, which the old two-cause
/// split could not distinguish from a short file. `stuffr::entries::
/// PartialCause`'s own doc carries the ruling; this is the test that makes
/// it falsifiable: forcing `declared_payload_is_all_present` either way
/// collapses two of these rows onto one string.
///
/// The first and third rows are the CONTROL for the second. All three run
/// over `unarc-rs`'s borrowed corpus — bytes zoo 2.10 wrote — and the
/// difference between `store.zoo` and `default.zoo` is the packing method
/// alone (0 vs 1), so nothing but the codec and the damage varies.
#[test]
fn damage_catalogue_the_three_partial_causes_are_distinguishable() {
    let dir = tmp_dir();
    let stored = std::fs::read(legacy_fixture("zoo/store.zoo")).unwrap();
    let lzd = std::fs::read(legacy_fixture("zoo/default.zoo")).unwrap();

    // Both fixtures' single record puts its payload at the offset its own
    // directory entry declares (`zoo.h`'s `SIZ_DIR`-relative field at +10),
    // read here rather than hardcoded so a fixture change cannot make this
    // test aim at the wrong bytes.
    let payload_at = |bytes: &[u8]| -> usize {
        u32::from_le_bytes(bytes[42 + 10..42 + 14].try_into().unwrap()) as usize
    };
    let declared_len = |bytes: &[u8]| -> usize {
        u32::from_le_bytes(bytes[42 + 24..42 + 28].try_into().unwrap()) as usize
    };

    // 1. The FILE is short: 100 of the declared bytes present.
    let cut = dir.join("cut.zoo");
    std::fs::write(&cut, &stored[..payload_at(&stored) + 100]).unwrap();

    // 2. Every declared byte present, one flipped inside an `lzd` stream —
    //    the decoder stops where the damage is.
    let mut bytes = lzd.clone();
    let at = payload_at(&lzd) + declared_len(&lzd) / 2;
    bytes[at] ^= 0xFF;
    let damaged_lzd = dir.join("lzd.zoo");
    std::fs::write(&damaged_lzd, &bytes).unwrap();

    // 3. Every declared byte present, one flipped inside a Stored payload —
    //    it all decodes and disagrees with the recorded CRC-16.
    let mut bytes = stored.clone();
    let at = payload_at(&stored) + declared_len(&stored) / 2;
    bytes[at] ^= 0xFF;
    let damaged_stored = dir.join("stored.zoo");
    std::fs::write(&damaged_stored, &bytes).unwrap();

    for (path, cause, why) in [
        (
            &cut,
            "Partial (truncated)",
            "bytes this entry declares are genuinely missing from the file",
        ),
        (
            &damaged_lzd,
            "Partial (decode failed)",
            "every declared byte is present and the decoder could not turn them into the \
             declared content — saying `truncated` here sent a user looking for a longer \
             copy of a file that is not short",
        ),
        (
            &damaged_stored,
            "Partial (checksum mismatch)",
            "every declared byte is present, it all decoded, and it is not what was written",
        ),
    ] {
        let rows = salvage_list_rows(path);
        assert_eq!(rows.len(), 1, "{}: {rows:?}", path.display());
        assert!(
            rows[0].contains(cause),
            "{}: expected `{cause}` — {why}: {}",
            path.display(),
            rows[0]
        );
        // And no row may carry a DIFFERENT cause as well, which is what
        // would happen if two of the three strings were prefixes of each
        // other or if the match above were satisfied by a substring.
        for other in [
            "Partial (truncated)",
            "Partial (decode failed)",
            "Partial (checksum mismatch)",
        ] {
            if other != cause {
                assert!(
                    !rows[0].contains(other),
                    "{}: row claims `{other}` as well as `{cause}`: {}",
                    path.display(),
                    rows[0]
                );
            }
        }
    }

    // The complement: none of the three fixtures is damaged in a way this
    // test merely assumed. Undamaged, all three verify.
    for (label, bytes) in [("store.zoo", &stored), ("default.zoo", &lzd)] {
        let whole = dir.join(format!("whole-{label}"));
        std::fs::write(&whole, bytes).unwrap();
        let rows = salvage_list_rows(&whole);
        assert_eq!(rows.len(), 1);
        assert!(
            rows[0].contains("Intact"),
            "{label} must be healthy before anything is done to it: {}",
            rows[0]
        );
    }
}

/// Salvage Stage 3 Task 2: `stuffr salvage` over a real tar, at the CLI.
///
/// The first header's name has one flipped byte, so `stuffr list` refuses
/// the whole archive at exit 5 while every later header is untouched. The
/// salvage run DETECTS the format from the `ustar` magic, reports each
/// survivor `Complete` — the tier no registered format reached before tar,
/// and never `Intact`, which would claim a content checksum tar does not
/// carry — writes each one byte for byte, and exits 0.
#[test]
fn salvage_recovers_a_damaged_tar_as_complete() {
    let dir = tmp_dir();
    let good = write_fixture_tar(
        &dir,
        &[
            ("first.txt", b"lost with its header"),
            ("second.txt", b"recovered"),
            ("third.txt", b"also recovered"),
        ],
    );
    let mut bytes = std::fs::read(&good).unwrap();
    bytes[0] ^= 0x01;
    let archive = dir.join("damaged.tar");
    std::fs::write(&archive, &bytes).unwrap();

    let listed = run_output(&["list", archive.to_str().unwrap()]);
    assert_eq!(
        listed.status.code(),
        Some(5),
        "the ordinary reader must refuse it: {}",
        String::from_utf8_lossy(&listed.stderr)
    );

    let out = run_output(&["salvage", archive.to_str().unwrap(), "--list"]);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(stdout.lines().count(), 2, "{stdout}");
    assert_eq!(stdout.matches("Complete").count(), 2, "{stdout}");
    assert!(!stdout.contains("Intact"), "{stdout}");
    assert!(
        stdout.contains("second.txt") && stdout.contains("third.txt"),
        "{stdout}"
    );

    let out_dir = dir.join("recovered");
    let written = run_output(&[
        "salvage",
        archive.to_str().unwrap(),
        "-C",
        out_dir.to_str().unwrap(),
    ]);
    assert_eq!(
        written.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&written.stderr)
    );
    assert_eq!(
        std::fs::read(out_dir.join("second.txt")).unwrap(),
        b"recovered"
    );
    assert_eq!(
        std::fs::read(out_dir.join("third.txt")).unwrap(),
        b"also recovered"
    );
    assert!(!out_dir.join("first.txt").exists());
}

/// Ruling 3-J at the CLI: Task 2's review reproduced `salvage` answering "the
/// scan found nothing recoverable" at exit 5 over a healthy tar `list` reads
/// at exit 0 — one v7-style header with junk in its magic field. It is exit 3
/// now, naming the shape.
#[test]
fn salvage_says_exit_3_for_a_tar_header_it_cannot_gate() {
    let dir = tmp_dir();
    let mut b = v7_tar_entry("j.txt", b"junk", b"JUNKJUNK");
    b.resize(2048, 0);
    let archive = dir.join("junkmagic.tar");
    std::fs::write(&archive, &b).unwrap();

    assert_eq!(run(&["list", archive.to_str().unwrap()]).code(), Some(0));
    let out = run_output(&[
        "salvage",
        "--format",
        "tar",
        archive.to_str().unwrap(),
        "--list",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(3), "{stderr}");
    assert!(stderr.contains("magic field"), "{stderr}");
    assert!(!stderr.contains("nothing recoverable"), "{stderr}");
}

/// Task 2-N fix round 1, I1: a real ustar tar whose first header lost byte
/// 0 to a NUL. `list` refuses it at exit 5, and so must `salvage`: the
/// header's checksum-valid copy one byte late is a COPY, not a header this
/// build cannot gate. It briefly said exit 3, "`stuffr list` and `stuffr
/// unpack` read these headers normally" — false on both counts. With a
/// second entry behind it the run recovers that one at exit 0 and prints no
/// sighting note.
#[test]
fn salvage_calls_a_tar_whose_only_header_lost_byte_0_nothing_recoverable() {
    let dir = tmp_dir();
    for (label, files) in [
        ("one", &[("a.txt", &b"alpha"[..])][..]),
        (
            "two",
            &[("a.txt", &b"alpha"[..]), ("b.txt", &b"beta"[..])][..],
        ),
    ] {
        let mut bytes: Vec<u8> = files
            .iter()
            .flat_map(|(name, data)| ustar_tar_entry(name, data))
            .collect();
        bytes.resize(bytes.len() + 1024, 0);
        // The fixture must really carry a checksum-valid copy one byte late.
        let late = &bytes[1..513];
        let field = &late[148..156];
        let digits = &field[..field.iter().position(|&x| x == 0).unwrap()];
        let recorded = std::str::from_utf8(digits).unwrap();
        let summed: u32 = late[..148]
            .iter()
            .chain(&late[156..])
            .map(|&x| u32::from(x))
            .sum::<u32>()
            + 8 * 32;
        assert_eq!(u32::from_str_radix(recorded, 8).unwrap(), summed, "{label}");
        bytes[0] = 0;
        let archive = dir.join(format!("nul0-{label}.tar"));
        std::fs::write(&archive, &bytes).unwrap();

        assert_eq!(
            run(&["list", archive.to_str().unwrap()]).code(),
            Some(5),
            "{label}"
        );
        let out = run_output(&[
            "salvage",
            "--format",
            "tar",
            archive.to_str().unwrap(),
            "--list",
        ]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        if label == "one" {
            assert_eq!(out.status.code(), Some(5), "{label}: {stdout}{stderr}");
            assert!(stderr.contains("nothing recoverable"), "{label}: {stderr}");
        } else {
            assert_eq!(out.status.code(), Some(0), "{label}: {stdout}{stderr}");
            assert_eq!(stdout.lines().count(), 1, "{label}: {stdout}");
            assert!(stdout.contains("b.txt"), "{label}: {stdout}");
            assert_eq!(stderr, "", "{label}: no sighting note");
        }
        assert!(!stderr.contains("stuffr list"), "{label}: {stderr}");
    }
}

/// 0.10.3 §2: forged pax `x` chains converging on one header. Five chains
/// reach one empty-named ustar header; salvage reads four of them and
/// reports the header as a sighting at its offset, in the work-bounded
/// sentence (Ruling T3-3), never "a shape it has no gate for". Pinned at the
/// CLI's existing sighting rule: exit 5 when nothing was recovered (the sighting
/// note, then "nothing recoverable"), exit 4 when an ordinary entry before
/// the chains was recovered alongside it.
#[test]
fn salvage_reports_a_tar_header_too_many_chains_converge_on() {
    fn ustar_block(name: &[u8], typeflag: u8, size: u64) -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[..name.len()].copy_from_slice(name);
        b[100..108].copy_from_slice(b"0000644\0");
        b[108..116].copy_from_slice(b"0000000\0");
        b[116..124].copy_from_slice(b"0000000\0");
        b[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
        b[136..148].copy_from_slice(b"00000000000\0");
        b[156] = typeflag;
        b[257..263].copy_from_slice(b"ustar\0");
        b[263..265].copy_from_slice(b"00");
        b[148..156].fill(b' ');
        let sum: u32 = b.iter().map(|&x| u32::from(x)).sum();
        b[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        b
    }
    /// `prefix`, then five forged `x` heads all spanning to one empty-named
    /// terminal; answers the bytes and the terminal's offset.
    fn converging(prefix: &[u8]) -> (Vec<u8>, usize) {
        let forged = 5;
        let terminal_at = prefix.len() + forged * 512;
        let mut out = prefix.to_vec();
        for k in 0..forged {
            let span = (terminal_at - prefix.len() - k * 512 - 512) as u64;
            out.extend_from_slice(&ustar_block(b"", b'x', span));
        }
        out.extend_from_slice(&ustar_block(b"", b'0', 0));
        out.extend_from_slice(&[0u8; 1024]);
        (out, terminal_at)
    }
    const SHAPE: &str =
        "header(s) reached by more than four extension chains, whose further chains were not read";

    let dir = tmp_dir();
    let salvage_list = |p: &Path| run_output(&["salvage", p.to_str().unwrap(), "--list"]);

    let (bytes, terminal_at) = converging(&[]);
    let archive = dir.join("converged.tar");
    std::fs::write(&archive, &bytes).unwrap();
    let out = salvage_list(&archive);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(5), "{stdout}{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains(SHAPE), "{stderr}");
    assert!(
        stderr.contains(&format!("offset(s) {terminal_at}")),
        "{stderr}"
    );
    assert!(stderr.contains("nothing recoverable"), "{stderr}");
    // Ruling T3-3: the work-bounded sentence, not the ungateable one.
    assert!(
        stderr.contains(&format!(
            "salvage -> this build's salvage scanner bounds the work it spends on extension \
             chains, and did not read the chains in front of 1 tar {SHAPE} at offset(s) \
             {terminal_at} — so whatever those chains describe is not listed or recovered there, \
             though the scan went on past them; `stuffr list` and `stuffr unpack` may read these \
             headers normally\n"
        )),
        "{stderr}"
    );
    assert!(!stderr.contains("no gate for"), "{stderr}");

    let mut entry = ustar_block(b"ok.txt", b'0', 4);
    entry.extend_from_slice(b"fine");
    entry.resize(1024, 0);
    let (bytes, terminal_at) = converging(&entry);
    let archive = dir.join("mixed-converged.tar");
    std::fs::write(&archive, &bytes).unwrap();
    let out = salvage_list(&archive);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(4), "{stdout}{stderr}");
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    assert!(
        stdout.contains("ok.txt") && stdout.contains("Complete"),
        "{stdout}"
    );
    assert!(stderr.contains(SHAPE), "{stderr}");
    assert!(
        stderr.contains(&format!("offset(s) {terminal_at}")),
        "{stderr}"
    );
    assert!(
        stderr.contains("bounds the work it spends on extension chains"),
        "{stderr}"
    );
    assert!(!stderr.contains("no gate for"), "{stderr}");
}

/// 0.10.4 Task 4: an exit-3 refusal (an ungateable header, nothing
/// recovered) also carries the work-bounded sighting it would otherwise
/// drop — on one line, after the refusal's own words.
#[test]
fn salvage_refusal_carries_the_bounded_sighting() {
    fn block(name: &[u8], typeflag: u8, size: u64, magic: &[u8; 8]) -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[..name.len()].copy_from_slice(name);
        b[100..108].copy_from_slice(b"0000644\0");
        b[108..116].copy_from_slice(b"0000000\0");
        b[116..124].copy_from_slice(b"0000000\0");
        b[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
        b[136..148].copy_from_slice(b"00000000000\0");
        b[156] = typeflag;
        b[257..265].copy_from_slice(magic);
        b[148..156].fill(b' ');
        let sum: u32 = b.iter().map(|&x| u32::from(x)).sum();
        b[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        b
    }
    // A checksum-valid header with unrecognised magic, then five forged
    // chains converging on one terminal.
    let mut bytes = block(b"j.txt", b'0', 0, b"JUNKJUNK");
    let terminal_at = bytes.len() + 5 * 512;
    let first_head = bytes.len();
    for k in 0..5 {
        let span = (terminal_at - first_head - k * 512 - 512) as u64;
        bytes.extend_from_slice(&block(b"", b'x', span, b"ustar\x0000"));
    }
    bytes.extend_from_slice(&block(b"", b'0', 0, b"ustar\x0000"));
    bytes.extend_from_slice(&[0u8; 1024]);

    let dir = tmp_dir();
    let archive = dir.join("refusal-with-note.tar");
    std::fs::write(&archive, &bytes).unwrap();
    let out = run_output(&["salvage", archive.to_str().unwrap(), "--list"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(3), "{stdout}{stderr}");
    assert!(stderr.contains("magic field"), "{stderr}");
    assert!(stderr.contains("did not read the chains"), "{stderr}");
    assert!(
        stderr.contains(&format!("offset(s) {terminal_at}")),
        "{stderr}"
    );
}

/// 0.10.3 Task 4b: zip local headers whose names the scan's verdict budget
/// would not pay for. Each forged header declares an all-ASCII name that
/// runs to the file's last byte, `0xFF`, so every name is read whole and
/// then refused; past the budget the rest are refused unread and reported
/// in the verdict-bounded sentence — not the ungateable one, and not the
/// extension-chain one. Pinned at the CLI's existing sighting rule: exit 5
/// when nothing was recovered, exit 4 when an Intact entry before the
/// forgeries was recovered alongside them.
#[test]
fn salvage_reports_zip_headers_its_verdict_budget_did_not_judge() {
    /// `prefix`, then 32 KiB of forged headers, every one whose name length
    /// is ASCII in both bytes.
    fn forged(prefix: &[u8]) -> Vec<u8> {
        const LEN: usize = 32 * 1024;
        let mut out = prefix.to_vec();
        let end = prefix.len() + LEN;
        while out.len() + 64 <= end {
            let name_len = end - out.len() - 30;
            if name_len & 0x8080 == 0 {
                out.extend_from_slice(b"PK\x03\x04");
                for field in [20u16, 0, 0, 0, 0] {
                    out.extend_from_slice(&field.to_le_bytes());
                }
                for field in [0u32, 0x7F7F_7F7F, 0x7F7F_7F7F] {
                    out.extend_from_slice(&field.to_le_bytes());
                }
                out.extend_from_slice(&u16::try_from(name_len).unwrap().to_le_bytes());
                out.extend_from_slice(&0u16.to_le_bytes());
                out.resize(out.len() + 34, b'A');
            } else {
                out.resize(out.len() + 64, b'A');
            }
        }
        out.resize(end - 1, b'A');
        out.push(0xFF);
        out
    }
    const SHAPE: &str = "local header(s) whose name it did not read once that work was spent";
    const OPENING: &str = "salvage -> this build's salvage scanner bounds the work it spends \
                           judging candidate headers across the whole scan, and did not judge \
                           ";
    const CLOSING: &str = " — so whatever those headers describe is not listed or recovered \
                           there, though the scan went on past them; `stuffr list` and `stuffr \
                           unpack` may read these headers normally\n";

    let dir = tmp_dir();
    let salvage_list = |p: &Path| run_output(&["salvage", p.to_str().unwrap(), "--list"]);

    let archive = dir.join("budget.zip");
    std::fs::write(&archive, forged(&[])).unwrap();
    let out = salvage_list(&archive);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(5), "{stdout}{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    let note = stderr
        .lines()
        .find(|l| l.contains("bounds the work"))
        .unwrap_or_else(|| panic!("no budget note: {stderr}"));
    assert!(note.starts_with(OPENING), "{note}");
    assert!(format!("{note}\n").ends_with(CLOSING), "{note}");
    assert!(
        note.contains(&format!(" zip {SHAPE} at offset(s) ")),
        "{note}"
    );
    assert!(!stderr.contains("no gate for"), "{stderr}");
    assert!(!stderr.contains("extension chains"), "{stderr}");
    assert!(stderr.contains("nothing recoverable"), "{stderr}");

    // An empty stored entry, whole and Intact, in front of the forgeries.
    let mut entry = b"PK\x03\x04".to_vec();
    for field in [20u16, 0, 0, 0, 0] {
        entry.extend_from_slice(&field.to_le_bytes());
    }
    for field in [0u32, 0, 0] {
        entry.extend_from_slice(&field.to_le_bytes());
    }
    entry.extend_from_slice(&6u16.to_le_bytes());
    entry.extend_from_slice(&0u16.to_le_bytes());
    entry.extend_from_slice(b"ok.txt");
    let archive = dir.join("mixed-budget.zip");
    std::fs::write(&archive, forged(&entry)).unwrap();
    let out = salvage_list(&archive);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(4), "{stdout}{stderr}");
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    assert!(
        stdout.contains("ok.txt") && stdout.contains("Intact"),
        "{stdout}"
    );
    assert!(
        stderr.contains(OPENING) && stderr.contains(SHAPE),
        "{stderr}"
    );
    assert!(!stderr.contains("no gate for"), "{stderr}");
}

/// Task 2-N, N3: in a MIXED run an ungateable header used to be completely
/// silent. `JUNKJUNK` then a healthy `ok.txt`: `list` shows two entries,
/// and `salvage` gave one row at exit 0 with an EMPTY stderr. Task 2-N added
/// the sentence saying a header was seen, where, and that `list` may read
/// it — under `--list` and under `-C` alike. It is still never a row.
///
/// **The exit code is 4, not 0, since the final whole-branch review's I-1**
/// (reversing Ruling S-X for this case): the note alone left `salvage -C out
/// && rm mixed.tar` deleting `j.txt`, which `list` reads. A healthy archive
/// keeps exit 0 and an empty stderr under `--list` (and only `-C`'s own
/// summary line under `-C`): neither the note nor the code may fire where
/// nothing was refused.
#[test]
fn salvage_names_an_ungateable_tar_header_in_a_mixed_run() {
    let dir = tmp_dir();
    let mut mixed = v7_tar_entry("j.txt", b"junk", b"JUNKJUNK");
    let ok_at = mixed.len();
    mixed.extend_from_slice(&v7_tar_entry("ok.txt", b"fine", &[0; 8]));
    mixed.extend_from_slice(&[0u8; 1024]);
    let healthy = mixed[ok_at..].to_vec();
    let archive = dir.join("mixed.tar");
    std::fs::write(&archive, &mixed).unwrap();
    let whole = dir.join("healthy.tar");
    std::fs::write(&whole, &healthy).unwrap();

    let listed = run_output(&["list", archive.to_str().unwrap()]);
    assert_eq!(listed.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&listed.stdout).lines().count(), 2);

    let salvage_list =
        |p: &Path| run_output(&["salvage", "--format", "tar", p.to_str().unwrap(), "--list"]);

    let out = salvage_list(&archive);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(4), "{stdout}{stderr}");
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    assert!(
        stdout.contains("ok.txt") && !stdout.contains("j.txt"),
        "{stdout}"
    );
    for needle in ["magic field", "offset(s) 0", "stuffr list"] {
        assert!(stderr.contains(needle), "{needle:?} missing: {stderr}");
    }

    let out_dir = dir.join("recovered");
    let written = run_output(&[
        "salvage",
        "--format",
        "tar",
        archive.to_str().unwrap(),
        "-C",
        out_dir.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&written.stderr);
    assert_eq!(written.status.code(), Some(4), "{stderr}");
    assert!(
        stderr.contains("magic field") && stderr.contains("offset(s) 0"),
        "{stderr}"
    );
    assert_eq!(std::fs::read(out_dir.join("ok.txt")).unwrap(), b"fine");
    assert!(!out_dir.join("j.txt").exists());

    // An `--index`-selective run is about the positions it named, and a
    // sighting has no position to name — the same exemption `NotSelected`
    // has. Asking for `ok.txt` alone and getting it whole is exit 0; the
    // note still prints, so the header is not hidden.
    let picked_dir = dir.join("picked");
    let picked = run_output(&[
        "salvage",
        "--format",
        "tar",
        archive.to_str().unwrap(),
        "--index",
        "0",
        "-C",
        picked_dir.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&picked.stderr);
    assert_eq!(picked.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("magic field"), "{stderr}");
    assert_eq!(std::fs::read(picked_dir.join("ok.txt")).unwrap(), b"fine");

    let out = salvage_list(&whole);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "",
        "a healthy tar says nothing"
    );
    let healthy_dir = dir.join("healthy-out");
    let written = run_output(&[
        "salvage",
        "--format",
        "tar",
        whole.to_str().unwrap(),
        "-C",
        healthy_dir.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&written.stderr);
    assert_eq!(written.status.code(), Some(0), "{stderr}");
    // `-C`'s own summary line goes to stderr; it must be the only line.
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert!(
        stderr.contains("1 scanned: 1 written") && !stderr.contains("stuffr list"),
        "{stderr}"
    );
}
