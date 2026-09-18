//! `stuffr::entries::salvage` end to end over a real ARJ archive.
//!
//! Salvage Stage 2 Task 6. The scanner's own unit tests live beside it in
//! `stuffr-formats`; this file drives the OPS layer — `entries::salvage` →
//! `place_salvaged_file` → `write_salvaged_payload`'s `arj` arm — because
//! that seam is where ARC's own Task 3 defect hid: a real scanner with an
//! unpopulated [`stuffr_core::EntryMeta::codec`] reported entries perfectly
//! and wrote nothing, every one of them a silent
//! `SalvageDisposition::SkippedNotBuiltIn`, and nothing below the CLI
//! noticed.
//!
//! **The fixture is read from disk rather than `include_bytes!`d**, the same
//! way `fuzz_corpus.rs`'s own `legacy_container_fixture` reaches it:
//! `sample.arj` lives in `crates/stuffr-formats/fixtures/`, outside this
//! crate's own directory, and `cargo package` only includes files inside the
//! crate being packaged.
//!
//! # What this file can and cannot witness
//!
//! `sample.arj` stores both its entries with method 0 (`Stored`), so a
//! recovered payload can be compared against a byte RANGE of the archive
//! with no decoder of this project's in the loop — the same discipline
//! `salvage_zoo.rs` applies to `store.zoo`. What it cannot do is make the
//! fixture independent evidence: `crates/stuffr-formats/fixtures/legacy/
//! MANIFEST.md` records that `sample.arj` was hand-built in Phase 3b from
//! the published ARJ header tables with **no tool anywhere able to check
//! it**, which is the weakest provenance in that tree. See
//! `legacy::arj_salvage`'s module doc; nothing here is as strong as
//! `salvage_lha.rs`'s `lhasa`-verified fixture or ZOO's borrowed CRC-16
//! corpus.

use std::path::{Path, PathBuf};

use stuffr::entries::{self, PartialCause, SalvageDisposition, SalvageOpts};
use stuffr_core::FormatId;
use stuffr_core::salvage::SalvagePolicy;

/// The ARJ envelope's `u16` basic header size, at the header's own offset 2
/// — the field `unarj_rs::arj_archive::read_header` bounds against its own
/// 2600-byte `MAX_HEADER_SIZE`.
///
/// The only offset this file needs, and it is needed for one purpose: to
/// damage the archive's MAIN header in a way that stops the ordinary reader
/// from opening the archive at all, without touching a byte of either local
/// file header. A wrong value here makes the test fail to reproduce the
/// damage it names — it cannot make a broken scanner look correct.
const BASIC_HEADER_SIZE_I: usize = 2;

fn fixture_bytes() -> Vec<u8> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../stuffr-formats/fixtures/legacy/sample.arj");
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "stuffr-salvage-arj-{tag}-{}-{}",
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
        format: Some(FormatId::new("arj")),
    }
}

/// The seam ARC's Task 3 shipped broken: a real scanner whose entries reach
/// a real payload writer and land real bytes on disk.
#[test]
fn the_hand_built_fixture_is_recovered_byte_for_byte_through_the_ops_layer() {
    let scratch = Scratch::new("recover");
    let bytes = fixture_bytes();
    let archive = scratch.0.join("sample.arj");
    std::fs::write(&archive, &bytes).unwrap();
    let dest = scratch.0.join("out");

    let outcome = entries::salvage(&archive, &opts(Some(dest.clone())))
        .expect("a healthy ARJ archive must salvage cleanly");

    assert_eq!(outcome.entries.len(), 2, "sample.arj holds two entries");
    for (record, (name, content)) in outcome.entries.iter().zip([
        ("sample/hello.txt", &b"alpha\n"[..]),
        ("sample/sub/b.bin", &b"beta\n"[..]),
    ]) {
        assert_eq!(record.name, name);
        let SalvageDisposition::Written(path) = &record.disposition else {
            panic!(
                "an Intact entry must be WRITTEN under its own name, not {:?} — a \
                 SkippedNotBuiltIn here is the ARC Task 3 defect recurring",
                record.disposition
            );
        };
        assert_eq!(path, &dest.join(name));
        assert_eq!(std::fs::read(path).unwrap(), content);
    }
    assert_eq!(entries::salvage_exit_code(&outcome), 0);
}

/// **The motivating reproducer, recovered.** `unarj_rs::ArjArchieve::new`
/// reads the MAIN header before it will hand back a single entry, and
/// refuses outright when that header's declared size is past the
/// specification's 2600-byte maximum. Two bytes, and the ordinary reader
/// reaches NO entry in an otherwise perfect archive — a sharper shape than
/// LHA's, where a damaged header costs only the entries behind it.
///
/// The `0x60 0xEA` id at offset 0 is deliberately left intact so format
/// detection still resolves this as an ARJ; only the size word is damaged.
#[test]
fn an_archive_whose_main_header_was_destroyed_still_salvages_every_entry() {
    let scratch = Scratch::new("destroyed-main");
    let mut bytes = fixture_bytes();
    bytes[BASIC_HEADER_SIZE_I] = 0xFF;
    bytes[BASIC_HEADER_SIZE_I + 1] = 0xFF;

    let archive = scratch.0.join("destroyed.arj");
    std::fs::write(&archive, &bytes).unwrap();

    // The control: the ordinary reader must NOT reach the entries, or this
    // test would pass without salvage having done anything.
    let listed = entries::list(stuffr::ops::Input::Path(archive.clone()), u64::MAX, None);
    // An `Err` is the honest control outcome here — `read_header` raises
    // "Header size is too big" — and the point either way is that `list`
    // hands back no entry, so only the `Ok` arm has anything to assert.
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
        .expect("a destroyed main header is what salvage is for, not a reason to fail");
    assert_eq!(outcome.entries.len(), 2);
    for (record, (name, content)) in outcome.entries.iter().zip([
        ("sample/hello.txt", &b"alpha\n"[..]),
        ("sample/sub/b.bin", &b"beta\n"[..]),
    ]) {
        let SalvageDisposition::Written(path) = &record.disposition else {
            panic!("expected a written entry, got {:?}", record.disposition);
        };
        assert_eq!(path, &dest.join(name));
        assert_eq!(std::fs::read(path).unwrap(), content);
    }
}

/// A truncated tail lands as `NAME.partial` carrying its genuine surviving
/// bytes, at exit 4 — `zip_salvage.rs`'s "criterion 6 reports, it does not
/// reject" ruling, reaching the ops layer for ARJ.
///
/// Nothing is padded and nothing is invented: the recovered file is a
/// strict, shorter PREFIX of what the entry declared.
#[test]
fn a_truncated_tail_lands_as_partial_with_its_surviving_bytes() {
    let scratch = Scratch::new("truncated");
    let mut bytes = fixture_bytes();
    // Drop the end-of-archive marker and three bytes of the last entry's
    // five-byte payload.
    bytes.truncate(bytes.len() - 4 - 3);

    let archive = scratch.0.join("cut.arj");
    std::fs::write(&archive, &bytes).unwrap();
    let dest = scratch.0.join("out");

    let outcome = entries::salvage(&archive, &opts(Some(dest.clone())))
        .expect("a truncated archive is what salvage is for");
    assert_eq!(outcome.entries.len(), 2);

    // The first entry is whole and lands under its own name.
    let SalvageDisposition::Written(first) = &outcome.entries[0].disposition else {
        panic!("expected a written entry, got {:?}", outcome.entries[0]);
    };
    assert_eq!(std::fs::read(first).unwrap(), b"alpha\n");

    // The second is a prefix, and says so in its NAME as well as its status.
    let SalvageDisposition::WrittenPartial {
        path: second,
        cause,
    } = &outcome.entries[1].disposition
    else {
        panic!(
            "a truncated entry must land as a partial, not {:?}",
            outcome.entries[1].disposition
        );
    };
    assert_eq!(second, &dest.join("sample/sub/b.bin.partial"));
    assert_eq!(
        *cause,
        PartialCause::Truncated,
        "the payload ran out; nothing decoded and disagreed with a checksum"
    );
    let recovered = std::fs::read(second).unwrap();
    assert!(
        !recovered.is_empty() && b"beta\n".starts_with(recovered.as_slice()),
        "recovered {recovered:?}, which must be a genuine PREFIX of the original — nothing \
         is ever padded or invented"
    );
    assert_eq!(entries::salvage_exit_code(&outcome), 4);
}
