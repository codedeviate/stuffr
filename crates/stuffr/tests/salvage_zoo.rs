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

// ---------------------------------------------------------------------
// `zoo.h`'s record layout, hand-copied — and that IS a copy, which this
// comment used to deny.
//
// **Fix round 2, NEW-2.** An earlier version of this block said "two field
// offsets are read by hand in this file and no more … deliberately not a
// copy of the 56-byte record layout". Ruling S-R's test then added three
// more offsets, a CRC-16/ARC reimplementation and the literal `56`, and the
// sentence became the counterexample it cited. Corrected rather than
// restored, because the property cannot be restored from here:
// `legacy::zoo`'s `SIZ_DIRL`, `VARDIRLEN_I` and `DCRC_I` are all
// `pub(super)` inside `stuffr-formats::legacy`, and this file is an
// integration test of `stuffr` — a different crate, two module boundaries
// away. Widening them to `pub` to satisfy a test would put ZOO's private
// record layout in the published API of a crate whose own doc calls that
// layout the thing `unarc-rs` got wrong.
//
// What IS held: every number lives here, named, in one block — never
// inline in an expression — so the whole copy is one place to check
// against `zoo.rs` if either ever moves. `zoo_salvage.rs`'s own tests, one
// crate down, use `zoo.rs`'s constants directly and copy nothing.
//
// Nothing below is load-bearing for the SCANNER's correctness: these
// offsets exist only to damage a fixture in a specific way (zero a `next`
// link, set a `deleted` flag) and to re-stamp the record's own checksum
// afterwards so the scanner's gate does not reject it for the wrong
// reason. A wrong offset here makes a test fail to reproduce the damage it
// names — it cannot make a broken scanner look correct.
// ---------------------------------------------------------------------

/// The archive's own `zoo_start` (`zoo.h`'s `ZSTART_I 24`) — the absolute
/// position of the first directory record.
const ZSTART_I: usize = 24;
/// `zoo.h`'s `NEXT_I 6` within a directory record.
const NEXT_I: usize = 6;
/// `zoo.h`'s `DELETE_I 30` within a directory record.
const DELETE_I: usize = 30;
/// `zoo.h`'s `VARDIRLEN_I 51` and `DCRC_I 54`, needed only to re-stamp a
/// record's own checksum after a test damages one byte of it.
const VARDIRLEN_I: usize = 51;
const DCRC_I: usize = 54;
/// `zoo.h`'s `SIZ_DIRL 56` — the fixed part of a type-2 directory record,
/// which `dir_to_b`'s checksum covers along with the variable part.
///
/// **The number this format's entire module doc is about**, and the one
/// `unarc-rs` models as 59. It appeared here as a bare literal inside a
/// slice expression; named, it is one site rather than one hiding place.
const SIZ_DIRL: usize = 56;

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

/// CRC-16/ARC, reimplemented here rather than reused because
/// `legacy::crc`'s is private to another crate. Needed only so a test can
/// damage one byte of a record and leave the record's own `dir_crc` honest,
/// which is what keeps the scanner's gate from rejecting it for the wrong
/// reason.
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

/// Sets the first record's `deleted` flag and re-stamps that record's own
/// `dir_crc` (`portable.c`'s `dir_to_b`: the field itself zeroed, CRC-16/ARC
/// over `SIZ_DIRL + var_dir_len` bytes), so the archive is byte-perfect
/// apart from the one flag — exactly what `zoo d` leaves behind.
fn mark_first_record_deleted(bytes: &mut [u8]) {
    let record = u32::from_le_bytes([
        bytes[ZSTART_I],
        bytes[ZSTART_I + 1],
        bytes[ZSTART_I + 2],
        bytes[ZSTART_I + 3],
    ]) as usize;
    bytes[record + DELETE_I] = 1;
    let var_len = usize::from(u16::from_le_bytes([
        bytes[record + VARDIRLEN_I],
        bytes[record + VARDIRLEN_I + 1],
    ]));
    bytes[record + DCRC_I] = 0;
    bytes[record + DCRC_I + 1] = 0;
    let crc = crc16_arc(&bytes[record..record + SIZ_DIRL + var_len]);
    bytes[record + DCRC_I..record + DCRC_I + 2].copy_from_slice(&crc.to_le_bytes());
}

/// **Ruling S-R, end to end.** A deleted record is recovered — `list` hands
/// back nothing for the same archive — and the report says so, while the
/// exit code stays 0.
///
/// The exit code is the half worth pinning at this layer: recovering a
/// deleted record is this verb working as designed, not degraded fidelity,
/// so `salvage_exit_code` must never read `marked_deleted`. A future change
/// that routed the annotation through the exit-code aggregation would be
/// invisible to the scanner's own unit tests and fails here.
#[test]
fn a_deleted_record_is_recovered_annotated_and_does_not_move_the_exit_code() {
    let scratch = Scratch::new("deleted");
    let mut bytes = fixture_bytes();
    let expected = stored_payload(&bytes);
    mark_first_record_deleted(&mut bytes);

    let archive = scratch.0.join("deleted.zoo");
    std::fs::write(&archive, &bytes).unwrap();

    // The control: every ordinary verb reports an empty archive.
    let (rows, _) = entries::list(stuffr::ops::Input::Path(archive.clone()), u64::MAX, None)
        .expect("a deleted-only archive is not damaged, just empty to the reader");
    assert!(
        rows.is_empty(),
        "the control failed: the ordinary reader listed {} entries",
        rows.len()
    );

    let dest = scratch.0.join("out");
    let outcome = entries::salvage(&archive, &opts(Some(dest.clone())))
        .expect("a deleted record is content salvage exists to give back");
    assert_eq!(outcome.entries.len(), 1);
    let record = &outcome.entries[0];
    assert!(
        record.marked_deleted,
        "the one place salvage's leniency used to carry no marker at all"
    );
    let SalvageDisposition::Written(path) = &record.disposition else {
        panic!("expected a written entry, got {:?}", record.disposition);
    };
    assert_eq!(std::fs::read(path).unwrap(), expected);
    assert_eq!(
        entries::salvage_exit_code(&outcome),
        0,
        "recovering a deleted record is this verb working, not degraded fidelity — the \
         annotation is the whole signal, and that is deliberate"
    );
}
