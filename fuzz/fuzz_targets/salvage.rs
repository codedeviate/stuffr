#![no_main]
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::io::Cursor;
use stuffr::entries::{self, SalvageOpts};
use stuffr_core::salvage::{SalvagePolicy, SalvageStatus};
use stuffr_core::testing::{check_error_is_classified, check_salvage_claim};
use stuffr_formats::zip_salvage;

/// Local file header layout, duplicated deliberately rather than imported —
/// `zip_salvage.rs`'s own constants are private, and `container.rs`'s
/// `declared_zip_index` makes the identical argument for its own duplicated
/// EOCD parse: a divergence between this copy and the library's own is
/// itself the finding this cross-check exists to surface, so factoring the
/// two into one function would make that divergence unreachable by
/// construction.
const SIG_LOCAL_HEADER: [u8; 4] = *b"PK\x03\x04";
/// General-purpose bit flag bit 3 (APPNOTE 4.4.4): when set, crc32 and both
/// sizes live in a trailing data descriptor instead of the local header.
const FLAG_DATA_DESCRIPTOR: u16 = 0x0008;
const LOCAL_HEADER_TOTAL: usize = 30;

/// Whether the local header at `offset` in `data` directly carries a
/// checksum for a method this build's salvage engine can decode (Store = 0,
/// Deflate = 8) — the same two facts `zip_salvage.rs`'s own
/// `verify_candidate` consults before it will ever compute one and compare
/// it against `Candidate::verifier`.
///
/// `None`, not `Some(false)`, when general-purpose bit 3 is set: a
/// data-descriptor entry's verifier can still come from a reconciled
/// central-directory record carrying a real checksum (`zip_salvage.rs`'s
/// own "general-purpose bit 3" section), and this function has no
/// independent way to know that without re-parsing the whole central
/// directory. Inconclusive, not a violation — the same discipline
/// `container.rs`'s `forward_entry_count` follows for its own "can't tell"
/// case, so this cross-check cannot cry wolf on a legitimately
/// CD-reconciled entry.
fn locally_offers_checkable_crc(data: &[u8], offset: u64) -> Option<bool> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(LOCAL_HEADER_TOTAL)?;
    let fixed = data.get(start..end)?;
    if fixed[0..4] != SIG_LOCAL_HEADER {
        return None;
    }
    let flags = u16::from_le_bytes([fixed[6], fixed[7]]);
    if flags & FLAG_DATA_DESCRIPTOR != 0 {
        return None;
    }
    let method = u16::from_le_bytes([fixed[8], fixed[9]]);
    Some(matches!(method, 0 | 8))
}

fuzz_target!(|data: &[u8]| {
    // `entries::salvage` takes a path, not a `Source` — the same reason
    // `chain.rs`'s `entries::list` and `container.rs`'s seekable branch both
    // spool to a real file: salvage is inherently seek-bound (a resync scan
    // over the whole archive), so only a real file exercises the path a
    // real caller's `stuffr salvage ARCHIVE` takes.
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("input");
    std::fs::write(&path, data).expect("write temp input");

    // `dest: None` — report-only. This target is about parsing and
    // verification honesty (no panic, every `Err` classified, every
    // `Intact` backed by a real checksum comparison), not about the
    // filesystem write/containment path `extract`'s own fuzzing already
    // covers via `chain.rs`.
    let opts = SalvageOpts {
        dest: None,
        policy: SalvagePolicy::default(),
        select: None,
    };

    let outcome = match entries::salvage(&path, &opts) {
        Ok(o) => o,
        Err(e) => {
            check_error_is_classified(&e).expect("salvage error classification");
            return;
        }
    };

    // Independent second pass, at the core scanner level, over the
    // IDENTICAL bytes and policy — purely to recover each scan position's
    // byte OFFSET, which `entries::salvage`'s own `SalvagedRecord` does not
    // carry. Deterministic (same input, same policy), so this is not a
    // weaker approximation of the ops layer's own scan, it is the identical
    // computation run a second time from outside — the same "second
    // independent walk" shape `container.rs`'s `forward_entry_count` uses
    // for its own cross-check.
    let mut cursor = Cursor::new(data.to_vec());
    let offsets: HashMap<usize, u64> = match zip_salvage::salvage_zip(&mut cursor, &opts.policy) {
        Ok(scan) => scan
            .entries
            .into_iter()
            .map(|e| (e.scan_position, e.offset))
            .collect(),
        Err(e) => {
            check_error_is_classified(&e).expect("independent scan error classification");
            HashMap::new()
        }
    };

    for record in &outcome.entries {
        if record.status != SalvageStatus::Intact {
            continue;
        }
        // A scan position the independent pass did not also report is not
        // this check's job (the two disagreeing on structure would be a
        // different finding, over a determinism assumption this target does
        // not otherwise test) — skip rather than assert something neither
        // scan actually observed.
        let Some(&offset) = offsets.get(&record.scan_position) else {
            continue;
        };
        if let Some(offers_crc) = locally_offers_checkable_crc(data, offset) {
            check_salvage_claim(record.status, offers_crc)
                .expect("salvage claim: Intact without a checkable checksum");
        }
    }
});
