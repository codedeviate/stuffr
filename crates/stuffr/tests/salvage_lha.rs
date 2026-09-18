//! `stuffr::entries::salvage` end to end over a real LHA archive.
//!
//! Salvage Stage 2 Task 5. The scanner's own unit tests live beside it in
//! `stuffr-formats`; this file drives the OPS layer — `entries::salvage` →
//! `place_salvaged_file` → `write_salvaged_payload`'s `lha` arm — because
//! that seam is where ARC's own Task 3 defect hid: a real scanner with an
//! unpopulated [`stuffr_core::EntryMeta::codec`] reported entries perfectly
//! and wrote nothing, every one of them a silent
//! `SalvageDisposition::SkippedNotBuiltIn`, and nothing below the CLI
//! noticed.
//!
//! **The fixture is read from disk rather than `include_bytes!`d**, the same
//! way `fuzz_corpus.rs`'s own `legacy_container_fixture` and
//! `salvage_zoo.rs` reach theirs: the legacy fixtures live in
//! `crates/stuffr-formats/fixtures/`, outside this crate's own directory,
//! and `cargo package` only includes files inside the crate being packaged.
//!
//! # Why LHA is the sharpest case for this verb
//!
//! ZOO's motivating damage is a zeroed link in a chain the reader follows.
//! LHA has no chain, no index, no entry count and no trailer AT ALL: the
//! only way `stuffr list` reaches entry N is by having successfully parsed
//! entries 1..N. So **two damaged bytes in the first header cost every entry
//! in the archive**, and that is the reproducer below — not a shape invented
//! for a test, but the ordinary consequence of a bad sector or an
//! interrupted download landing in the first 40 bytes of a file.
//!
//! `sample.lzh`'s two entries are stored (`-lh0-`), and their expected
//! contents are `lhasa 0.6.0`'s — an implementation sharing no code with
//! `delharc`, which verified this hand-built fixture when Phase 3b added it
//! (`lha v`/`lha t`/`lha x`; see
//! `crates/stuffr-formats/fixtures/legacy/MANIFEST.md`). They are written
//! out here as literals rather than re-derived from the archive, because
//! re-deriving them would mean a second copy of the very header layout the
//! scanner under test owns, and an expectation computed by the code under
//! test is no expectation at all.

use std::path::{Path, PathBuf};

use stuffr::entries::{self, SalvageDisposition, SalvageOpts};
use stuffr_core::FormatId;
use stuffr_core::salvage::SalvagePolicy;

/// `sample.lzh`'s two entries, as `lhasa` extracts them. See this module's
/// doc for why these are literals.
const EXPECTED: [(&str, &[u8]); 2] = [
    ("sample/hello.txt", b"alpha\n"),
    ("sample/sub/b.bin", b"beta\n"),
];

/// The two bytes a level-0/1 LHA header opens with: its own length, and the
/// checksum over everything behind it. Named here, in one block, rather than
/// written inline — the same discipline `salvage_zoo.rs`'s offset block
/// keeps, and for the same reason: this is an integration test of `stuffr`,
/// two module boundaries from `legacy::lha_salvage`'s own constants, so the
/// copy cannot be avoided but it can be confined.
///
/// Nothing here is load-bearing for the SCANNER's correctness. These offsets
/// exist only to damage a fixture in a specific way; a wrong one makes a
/// test fail to reproduce the damage it names, and cannot make a broken
/// scanner look correct.
const HEADER_LEN_I: usize = 0;
const HEADER_CSUM_I: usize = 1;

fn fixture_bytes() -> Vec<u8> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../stuffr-formats/fixtures/legacy/sample.lzh");
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "stuffr-salvage-lha-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn opts(dest: Option<PathBuf>) -> SalvageOpts {
    SalvageOpts {
        dest,
        policy: SalvagePolicy::default(),
        select: None,
        // Named explicitly rather than detected, so a change to magic
        // resolution can never turn this into a test of something else.
        format: Some(FormatId::new("lha")),
    }
}

/// The seam ARC's Task 3 shipped broken: a real scanner whose entries reach
/// a real payload writer and land real bytes on disk.
#[test]
fn the_externally_verified_fixture_is_recovered_byte_for_byte_through_the_ops_layer() {
    let scratch = Scratch::new("recover");
    let archive = scratch.0.join("sample.lzh");
    std::fs::write(&archive, fixture_bytes()).unwrap();
    let dest = scratch.0.join("out");

    let outcome = entries::salvage(&archive, &opts(Some(dest.clone())))
        .expect("a healthy LHA archive must salvage cleanly");

    assert_eq!(outcome.entries.len(), 2, "sample.lzh holds two entries");
    for (record, (name, content)) in outcome.entries.iter().zip(EXPECTED) {
        assert_eq!(record.name, name);
        let SalvageDisposition::Written(path) = &record.disposition else {
            panic!(
                "an Intact entry must be WRITTEN under its own name, not {:?} — a \
                 SkippedNotBuiltIn here is the ARC Task 3 defect recurring",
                record.disposition
            );
        };
        assert_eq!(path, &dest.join(name));
        assert_eq!(std::fs::read(path).unwrap(), content, "{name}");
    }
    assert_eq!(entries::salvage_exit_code(&outcome), 0);
}

/// **The motivating reproducer, recovered.** Two bytes — the first header's
/// own length and checksum — and the ordinary reader reaches NO entry in the
/// archive, because LHA gives it no other way in. The scanner finds each
/// header independently, so the second entry comes back whole and `Intact`.
///
/// The ordinary reader is the control: without it this is only a test that
/// salvage found an entry, not that it found one nothing else could.
#[test]
fn an_archive_whose_first_header_was_destroyed_still_salvages_the_rest() {
    let scratch = Scratch::new("destroyed-header");
    let mut bytes = fixture_bytes();
    bytes[HEADER_LEN_I] = 0xFF;
    bytes[HEADER_CSUM_I] = 0xFF;

    let archive = scratch.0.join("damaged.lzh");
    std::fs::write(&archive, &bytes).unwrap();

    // An `Err` is the other honest control outcome — `lha.rs` classifies a
    // malformed header as `Error::Corrupt` — and the point either way is
    // that `list` hands back no entry, so only the `Ok` arm has anything to
    // assert.
    let listed = entries::list(stuffr::ops::Input::Path(archive.clone()), u64::MAX, None);
    if let Ok((rows, _)) = listed {
        assert!(
            rows.is_empty(),
            "the control failed: the ordinary reader still reaches {} entries, so this \
             fixture no longer reproduces the damage salvage is being tested against",
            rows.len()
        );
    }

    let dest = scratch.0.join("out");
    let outcome = entries::salvage(&archive, &opts(Some(dest.clone())))
        .expect("a destroyed first header is what salvage is for, not a reason to fail");
    assert_eq!(
        outcome.entries.len(),
        1,
        "the first header is genuinely gone; the second entry is what survives"
    );
    let record = &outcome.entries[0];
    assert_eq!(record.name, EXPECTED[1].0);
    let SalvageDisposition::Written(path) = &record.disposition else {
        panic!("expected a written entry, got {:?}", record.disposition);
    };
    assert_eq!(std::fs::read(path).unwrap(), EXPECTED[1].1);
    assert_eq!(
        entries::salvage_exit_code(&outcome),
        0,
        "every entry the scan could reach was recovered whole and proven against its own \
         CRC-16 — there is nothing degraded to report"
    );
}

/// **Ruling S-U, at the layer where the finding was made.** The review did
/// not find the level-2 gap by reading the scanner; it found it by running
/// two verbs over one healthy file and getting two answers — `stuffr list`
/// exit 0 printing the entry, `stuffr salvage --list` exit 5 saying nothing
/// was recoverable. So the regression guard belongs here, phrased as the
/// agreement rather than as either half: **the ordinary reader and the
/// recovery verb must not contradict each other about an undamaged
/// archive.**
///
/// The level-2 builder is local and duplicates a layout `lha_salvage.rs`
/// owns — unavoidable across two crates and two module boundaries, the same
/// trade `salvage_zoo.rs`'s offset block makes. It is safe here because
/// `entries::list` is the test's own CONTROL: a builder that got the layout
/// wrong fails the control before it can make the scanner look right.
#[test]
fn list_and_salvage_agree_about_a_healthy_level_2_archive() {
    let scratch = Scratch::new("level2");
    let content: &[u8] = b"level two payload, thirty bytes";
    let archive = scratch.0.join("level2.lzh");
    std::fs::write(&archive, build_level2(b"level2.txt", content)).unwrap();

    // The CONTROL, and the half the ruling is about: the ordinary reader
    // does read this file.
    let (rows, _) = entries::list(stuffr::ops::Input::Path(archive.clone()), u64::MAX, None)
        .expect("a healthy level-2 archive is not damaged");
    assert_eq!(rows.len(), 1, "the control failed: {rows:?}");
    assert_eq!(rows[0].name, "level2.txt");

    let dest = scratch.0.join("out");
    let outcome = entries::salvage(&archive, &opts(Some(dest.clone())))
        .expect("and neither is it unreadable to salvage");
    assert_eq!(
        outcome.entries.len(),
        1,
        "`list` reads this archive and `salvage` must not answer `nothing recoverable` for \
         it — one tool contradicting itself across two lines, on a file with nothing wrong \
         with it, is what Ruling S-U closed"
    );
    let record = &outcome.entries[0];
    assert_eq!(record.name, "level2.txt");
    let SalvageDisposition::Written(path) = &record.disposition else {
        panic!("expected a written entry, got {:?}", record.disposition);
    };
    assert_eq!(std::fs::read(path).unwrap(), content);
    assert_eq!(entries::salvage_exit_code(&outcome), 0);
}

/// A minimal but genuine level-2 archive: a `u16` total header size where
/// levels 0 and 1 keep a length byte and a checksum byte, no filename in the
/// base header, and the two extension headers a real level-2 writer emits —
/// `0x00` (the common header, carrying a CRC-16 over the whole header) and
/// `0x01` (the filename).
///
/// The CRC-16 is CRC-16/ARC, reimplemented here rather than reused because
/// `legacy::crc`'s is private to another crate — the same reason
/// `salvage_zoo.rs` carries its own copy.
fn build_level2(name: &[u8], content: &[u8]) -> Vec<u8> {
    fn crc16_arc(data: &[u8]) -> u16 {
        let mut crc: u16 = 0;
        for &b in data {
            crc ^= u16::from(b);
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xA001 & mask);
            }
        }
        crc
    }

    const BASE_LEN: usize = 26;
    let common_len = 5usize;
    let name_len = 1 + name.len() + 2;
    let total = BASE_LEN + common_len + name_len;

    let mut h: Vec<u8> = Vec::new();
    h.extend_from_slice(&(total as u16).to_le_bytes());
    h.extend_from_slice(b"-lh0-");
    h.extend_from_slice(&(content.len() as u32).to_le_bytes());
    h.extend_from_slice(&(content.len() as u32).to_le_bytes());
    h.extend_from_slice(&1_000_000_000u32.to_le_bytes());
    h.push(0x20);
    h.push(2);
    h.extend_from_slice(&crc16_arc(content).to_le_bytes());
    h.push(b'U');
    h.extend_from_slice(&(common_len as u16).to_le_bytes());
    assert_eq!(h.len(), BASE_LEN);

    h.push(0x00);
    h.extend_from_slice(&0u16.to_le_bytes()); // the header CRC, still zero
    h.extend_from_slice(&(name_len as u16).to_le_bytes());
    h.push(0x01);
    h.extend_from_slice(name);
    h.extend_from_slice(&0u16.to_le_bytes());
    assert_eq!(h.len(), total);

    let crc = crc16_arc(&h);
    h[BASE_LEN + 1..BASE_LEN + 3].copy_from_slice(&crc.to_le_bytes());

    let mut out = h;
    out.extend_from_slice(content);
    out.push(0); // end-of-archive marker
    out
}

/// A truncated download, the commonest damaged archive there is: the last
/// entry's payload is cut short, so it lands as `NAME.partial` rather than
/// under its real name, and the run reports it rather than exiting 0 in
/// silence.
///
/// **The bytes that ARE present must be in that file.** `delharc`'s decoder
/// API is all-or-nothing per call, so before `lha_salvage.rs`'s
/// `recover_the_last_chunk` existed this file was EMPTY for any entry
/// smaller than one decode chunk — a `.partial` artifact claiming a
/// surviving prefix and holding none.
#[test]
fn a_truncated_tail_lands_as_partial_with_its_surviving_bytes() {
    let scratch = Scratch::new("truncated");
    let bytes = fixture_bytes();
    // `sample.lzh` ends with the optional one-byte end-of-archive marker
    // (`…62 65 74 61 0a 00` — `beta\n` then the `0`), so cutting THREE bytes
    // takes that marker and two of the final entry's five payload bytes.
    const CUT: usize = 3;
    const PRESENT: usize = 3;
    let archive = scratch.0.join("truncated.lzh");
    std::fs::write(&archive, &bytes[..bytes.len() - CUT]).unwrap();
    let dest = scratch.0.join("out");

    let outcome = entries::salvage(&archive, &opts(Some(dest.clone())))
        .expect("a truncated archive is what salvage is for");
    assert_eq!(outcome.entries.len(), 2);

    let first = &outcome.entries[0];
    assert!(
        matches!(&first.disposition, SalvageDisposition::Written(_)),
        "the untouched entry is unaffected: {:?}",
        first.disposition
    );

    let last = &outcome.entries[1];
    let SalvageDisposition::WrittenPartial { path, .. } = &last.disposition else {
        panic!(
            "a truncated entry must land as `.partial`, never under its real name: {:?}",
            last.disposition
        );
    };
    assert_eq!(path, &dest.join(format!("{}.partial", EXPECTED[1].0)));
    let recovered = std::fs::read(path).unwrap();
    assert_eq!(
        recovered,
        &EXPECTED[1].1[..PRESENT],
        "every present byte must be recovered, as a genuine prefix — an empty `.partial` is \
         the shape `recover_the_last_chunk` exists to prevent"
    );
    assert_eq!(
        entries::salvage_exit_code(&outcome),
        4,
        "something was recovered as less than whole, which is exit 4"
    );
}
