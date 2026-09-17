//! `stuffr::entries::salvage` end to end over a real ZOO archive.
//!
//! Salvage Stage 2 Task 4. The scanner's own unit tests live beside it in
//! `stuffr-formats`; this file drives the OPS layer — `entries::salvage` →
//! `place_salvaged_file` → `write_salvaged_payload`'s `zoo` arm — because
//! that seam is where ARC's own Task 3 defect hid: a real scanner with an
//! unpopulated [`stuffr_core::EntryMeta::codec`] reported entries perfectly
//! and wrote nothing, every one of them a silent
//! `SalvageDisposition::SkippedNotBuiltIn`, and nothing below the CLI
//! noticed.
//!
//! **The fixture is read from disk rather than `include_bytes!`d**, the same
//! way `fuzz_corpus.rs`'s own `legacy_container_fixture` reaches it: the
//! ZOO corpus lives in `crates/stuffr-formats/fixtures/`, outside this
//! crate's own directory, and `cargo package` only includes files inside
//! the crate being packaged.
//!
//! `store.zoo` is the one borrowed fixture whose payload IS its content
//! (method 0), so this file can assert recovered BYTES against a byte range
//! of the archive with no decoder of this project's in the loop at all.
//! `crates/stuffr-formats/fixtures/legacy/MANIFEST.md` records its
//! provenance: `unarc-rs` 0.6.3's MIT/Apache test corpus, borrowed as bytes
//! only.

use std::path::{Path, PathBuf};

use stuffr::entries::{self, SalvageDisposition, SalvageOpts};
use stuffr_core::FormatId;
use stuffr_core::salvage::SalvagePolicy;

/// The archive's own `zoo_start` (`zoo.h`'s `ZSTART_I 24`) — the absolute
/// position of the first directory record.
///
/// Two field offsets are read by hand in this file and no more; that is
/// deliberately not a copy of the 56-byte record layout the scanner and
/// `zoo.rs` share, only the two pointers one test needs to damage.
const ZSTART_I: usize = 24;
/// `zoo.h`'s `NEXT_I 6` within a directory record.
const NEXT_I: usize = 6;

fn fixture_bytes() -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../stuffr-formats/fixtures/legacy/zoo/store.zoo");
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The licence text `store.zoo` stores uncompressed, taken as a byte range
/// of the archive itself — the entry's `offset` and `size_now` fields, read
/// straight out of its own record. No decoder, and nothing this project
/// wrote, stands between this expectation and the fixture.
fn stored_payload(bytes: &[u8]) -> Vec<u8> {
    let le32 = |i: usize| u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
    let record = le32(ZSTART_I) as usize;
    let offset = le32(record + 10) as usize;
    let size_now = le32(record + 24) as usize;
    bytes[offset..offset + size_now].to_vec()
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "stuffr-salvage-zoo-{tag}-{}-{}",
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
        format: Some(FormatId::new("zoo")),
    }
}

/// The seam ARC's Task 3 shipped broken: a real scanner whose entries reach
/// a real payload writer and land real bytes on disk.
#[test]
fn a_borrowed_zoo_fixture_is_recovered_byte_for_byte_through_the_ops_layer() {
    let scratch = Scratch::new("recover");
    let bytes = fixture_bytes();
    let archive = scratch.0.join("store.zoo");
    std::fs::write(&archive, &bytes).unwrap();
    let dest = scratch.0.join("out");

    let outcome = entries::salvage(&archive, &opts(Some(dest.clone())))
        .expect("a healthy ZOO archive must salvage cleanly");

    assert_eq!(outcome.entries.len(), 1, "store.zoo holds one entry");
    let record = &outcome.entries[0];
    assert_eq!(record.name, "license");
    let SalvageDisposition::Written(path) = &record.disposition else {
        panic!(
            "an Intact entry must be WRITTEN under its own name, not {:?} — a \
             SkippedNotBuiltIn here is the ARC Task 3 defect recurring",
            record.disposition
        );
    };
    assert_eq!(path, &dest.join("license"));
    assert_eq!(
        std::fs::read(path).unwrap(),
        stored_payload(&bytes),
        "the recovered bytes must equal the archive's own stored payload range"
    );
}

/// **The motivating reproducer, recovered.** `zoo.rs`'s
/// `refuse_a_chain_that_reaches_nothing` doc records that zeroing the first
/// record's `next` in `store.zoo` turns that record into a terminator: four
/// bytes, and the ordinary reader reaches no entry at all over 11 KiB of
/// content. That is the archive `salvage` exists for, and this pins that the
/// scanner does not inherit the chain's own damage — it never follows
/// `next`, so a zeroed one costs nothing.
#[test]
fn an_archive_whose_chain_was_zeroed_still_salvages_its_entry() {
    let scratch = Scratch::new("zeroed-chain");
    let mut bytes = fixture_bytes();
    let record = u32::from_le_bytes([
        bytes[ZSTART_I],
        bytes[ZSTART_I + 1],
        bytes[ZSTART_I + 2],
        bytes[ZSTART_I + 3],
    ]) as usize;
    let expected = stored_payload(&bytes);
    for b in &mut bytes[record + NEXT_I..record + NEXT_I + 4] {
        *b = 0;
    }

    let archive = scratch.0.join("chain-damaged.zoo");
    std::fs::write(&archive, &bytes).unwrap();

    // The ordinary reader is the control: it must NOT reach the entry, or
    // this test would pass without salvage having done anything.
    let listed = entries::list(stuffr::ops::Input::Path(archive.clone()), u64::MAX, None);
    // An `Err` is the other honest control outcome —
    // `refuse_a_chain_that_reaches_nothing` refuses this exact shape as
    // `Error::Corrupt` — and the point either way is that `list` hands back
    // no entry, so only the `Ok` arm has anything to assert.
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
        .expect("a zeroed chain is what salvage is for, not a reason to fail");
    assert_eq!(outcome.entries.len(), 1);
    let SalvageDisposition::Written(path) = &outcome.entries[0].disposition else {
        panic!(
            "expected a written entry, got {:?}",
            outcome.entries[0].disposition
        );
    };
    assert_eq!(std::fs::read(path).unwrap(), expected);
}
