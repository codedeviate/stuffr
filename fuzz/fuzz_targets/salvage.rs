#![no_main]
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::io::Cursor;
use stuffr::entries::{self, SalvageOpts};
use stuffr_core::salvage::{SalvagePolicy, SalvageStatus};
use stuffr_core::testing::{SALVAGE_SLOTS, check_error_is_classified, check_salvage_claim};
use stuffr_formats::legacy::{arc_salvage, arj_salvage, lha_salvage, zoo_salvage};
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
/// `zoo.h`: `#define ZOO_TAG ((unsigned long) 0xFDC4A7DCL)`, little-endian.
/// Duplicated here for the same reason the zip constants above are.
const ZOO_TAG_BYTES: [u8; 4] = 0xFDC4_A7DCu32.to_le_bytes();

/// The two bytes every ARJ header opens with — spec, both header tables:
/// "header id (main and local file header) = 0x60 0xEA". Duplicated here for
/// the same reason every constant above is.
const ARJ_HEADER_ID: [u8; 2] = [0x60, 0xEA];
/// Bytes from an ARJ header's own first byte to its `method` field: the
/// two-byte id plus the `u16` basic header size (4), then the content's own
/// `method` at offset 5.
const ARJ_METHOD_OFFSET: usize = 4 + 5;
/// The same, for the content's `file type` at offset 6.
const ARJ_FILE_TYPE_OFFSET: usize = 4 + 6;
/// Spec, LOCAL file header table: "file type ... (3 = directory)".
const ARJ_FILE_TYPE_DIRECTORY: u8 = 3;

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

/// Mirrors `locally_offers_checkable_crc` above, for the `arc` slot.
///
/// ARC's header has no data-descriptor-style deferral the way zip's does:
/// `marker(1) + method(1) + name(13) + compressed_size(4) + date(2) +
/// time(2) + crc16(2) + original_size(4)` (`arc.rs`'s own `HEADER_LEN` doc)
/// is the WHOLE record, so a header that is real at all carries its CRC-16
/// inline, unconditionally — `arc_salvage.rs`'s own `read_candidate_at`
/// never constructs a `Candidate` with `verifier: None`. Rather than trust
/// that module's doc comment, this re-derives the two cheap, non-allocating
/// structural facts its own discovery gate checks before it will trust a
/// marker sighting at all: the marker byte itself, and a method byte drawn
/// from the eleven values ARC ever assigned (`arc.rs`'s own `ARC_MAGIC`
/// table). `None` when neither holds — inconclusive, not a violation, same
/// as the zip version above.
fn arc_locally_offers_checkable_crc(data: &[u8], offset: u64) -> Option<bool> {
    let at = usize::try_from(offset).ok()?;
    let marker = *data.get(at)?;
    let method = *data.get(at.checked_add(1)?)?;
    if marker != 0x1A {
        return None;
    }
    Some((1..=11).contains(&method))
}

/// Mirrors the two functions above, for the `zoo` slot (Stage 2 Task 4).
///
/// ZOO has no deferral either: `zoo.h`'s directory entry carries `crc` as a
/// `u16` at offset 18 of a record that opens with `ZOO_TAG`, so a record
/// that is real at all carries its CRC-16 inline, unconditionally —
/// `zoo_salvage.rs`'s own `read_candidate_at` never constructs a
/// `Candidate` with `verifier: None`. Rather than trust that module's doc,
/// this re-derives the two cheap, non-allocating structural facts its own
/// discovery gate checks before it will trust a tag sighting: the four-byte
/// tag itself, and a packing method inside `zoo.h`'s `#define MAX_PACK 2`.
/// `None` when the tag does not match — inconclusive, not a violation, same
/// as the two above.
///
/// The record `type` byte at offset 4 is deliberately NOT re-checked here:
/// it decides the record's LENGTH, not whether a checksum exists, and this
/// function answers only the latter.
fn zoo_locally_offers_checkable_crc(data: &[u8], offset: u64) -> Option<bool> {
    let at = usize::try_from(offset).ok()?;
    let tag = data.get(at..at.checked_add(4)?)?;
    if tag != ZOO_TAG_BYTES {
        return None;
    }
    let method = *data.get(at.checked_add(5)?)?;
    Some(method <= 2)
}

/// The `-lh*-`/`-lz*-` identifiers this build can actually decode a payload
/// for, plus `-lhd-`, whose payload is empty BY DEFINITION and whose CRC-16
/// is therefore still compared against something. Duplicated here rather
/// than imported for the same reason the zip and zoo constants above are:
/// `lha_salvage.rs`'s own `Method` table is `pub(super)`, and a divergence
/// between this copy and the library's own is itself the finding this
/// cross-check exists to surface.
const LHA_CHECKABLE: [&[u8; 5]; 10] = [
    b"-lhd-", b"-lh0-", b"-lh1-", b"-lh4-", b"-lh5-", b"-lh6-", b"-lh7-", b"-lzs-", b"-lz4-",
    b"-lz5-",
];

/// Mirrors the three functions above, for the `lha` slot (Stage 2 Task 5).
///
/// LHA has no deferral either: every level-0/1 entry header carries a
/// CRC-16/ARC over the UNCOMPRESSED file inline, immediately behind the
/// filename, so a header that is real at all carries its checksum —
/// `lha_salvage.rs`'s own `read_candidate_at` never constructs a `Candidate`
/// with `verifier: None`. What decides whether that checksum is CHECKABLE is
/// the method: `-lhx-` is recognised by the format and compiled out of this
/// build (`delharc` with `std`, `lh1`, `lz`), so nothing is ever decoded for
/// it and nothing compared — `Some(false)`, which is exactly the claim
/// `check_salvage_claim` refuses to see alongside `Intact`.
///
/// `None` — inconclusive, not a violation — when the five bytes at offset 2
/// are not an identifier this table names at all, the same discipline the
/// three functions above follow for their own "can't tell" case.
///
/// The header CHECKSUM at offset 1 is deliberately NOT re-checked here: it
/// decides whether these bytes are a header, not whether a file checksum
/// exists, and this function answers only the latter.
fn lha_locally_offers_checkable_crc(data: &[u8], offset: u64) -> Option<bool> {
    let at = usize::try_from(offset).ok()?;
    let id = data.get(at.checked_add(2)?..at.checked_add(7)?)?;
    if id == b"-lhx-" {
        return Some(false);
    }
    LHA_CHECKABLE
        .iter()
        .any(|known| known.as_slice() == id)
        .then_some(true)
}

/// Mirrors the four functions above, for the `arj` slot (Stage 2 Task 6).
///
/// ARJ has no deferral either: every local file header carries a CRC-32 over
/// the ORIGINAL file inline, at content offset 20, so a header that is real
/// at all carries its checksum — `arj_salvage.rs`'s own `read_candidate_at`
/// never constructs a `Candidate` with `verifier: None`. What decides whether
/// that checksum is CHECKABLE is the METHOD: `unarj-rs` names methods 8 and 9
/// (`NO DATA`, `NO DATA NO CRC`) and has a decoder for neither, so nothing is
/// ever decoded for them and nothing compared — `Some(false)`, which is
/// exactly the claim `check_salvage_claim` refuses to see alongside `Intact`.
/// That is the `-lhx-` case one function up, in ARJ's own spelling.
///
/// **A DIRECTORY entry answers `Some(true)` regardless of its method byte**,
/// and that is not a loophole: ARJ records the kind in a field of its own, so
/// a directory's payload is empty BY DEFINITION and its CRC-32 is still
/// compared — against the checksum of zero bytes. The identical treatment
/// `LHA_CHECKABLE` gives `-lhd-`, for the identical reason. Without it this
/// function would cry wolf on the one shape where `Intact` is honest and the
/// method byte says nothing.
///
/// `None` — inconclusive, not a violation — when the two-byte id is absent or
/// the method byte is one the format never assigned, the same discipline the
/// four functions above follow for their own "can't tell" case.
///
/// The basic header CRC-32 is deliberately NOT re-checked here: it decides
/// whether these bytes are a header, not whether a FILE checksum exists, and
/// this function answers only the latter.
fn arj_locally_offers_checkable_crc(data: &[u8], offset: u64) -> Option<bool> {
    let at = usize::try_from(offset).ok()?;
    let id = data.get(at..at.checked_add(ARJ_HEADER_ID.len())?)?;
    if id != ARJ_HEADER_ID {
        return None;
    }
    if *data.get(at.checked_add(ARJ_FILE_TYPE_OFFSET)?)? == ARJ_FILE_TYPE_DIRECTORY {
        return Some(true);
    }
    match *data.get(at.checked_add(ARJ_METHOD_OFFSET)?)? {
        0..=4 => Some(true),
        8 | 9 => Some(false),
        _ => None,
    }
}

/// What a slot with no cross-check arm below gets: a loud abort, never a
/// silent skip.
///
/// **Stage 2 Task 6's fix round 1, and it is this project's signature defect
/// caught one task after `CLAUDE.md` recorded it.** Both `match name` blocks
/// below used to end `_ => HashMap::new()` / `_ => None`, with a comment
/// calling that "an honest 'not built yet', not a silent pass". It is honest
/// about the TARGET and says nothing to anyone reading a REPORT: Task 6
/// appended `arj` to `SALVAGE_SLOTS` and seeded its corpus without adding
/// either arm, so `check_salvage_claim` was unreachable for that slot on
/// every input, forever — while `make fuzz` reported `target 'salvage': OK`
/// and the task report claimed the oracle was firing.
///
/// A panic here cannot be reached by hostile INPUT, and that still holds
/// after Stage 2 Task 8 gave the slot a second source: the selector byte is
/// reduced `% SALVAGE_SLOTS.len()`, so every one of its 256 values names a
/// listed slot, and [`slot_from_payload`] answers only names it found by
/// searching `SALVAGE_SLOTS` itself — a payload detecting as `tar` yields
/// `None` and falls back to the selector rather than reaching here. So the
/// panic is reachable only by appending a slot without its arm, which is
/// precisely the state that must stop being quiet.
fn no_cross_check_arm(name: &str) -> ! {
    panic!(
        "SALVAGE_SLOTS names `{name}`, which `entries::salvage` dispatches to a real scanner, \
         but this target has no cross-check arm for it — so `check_salvage_claim` can never \
         fire for that slot and its whole share of every run proves nothing. Add both arms \
         (the independent-scan dispatch and `offers_crc`) in the same commit that appends the \
         slot."
    )
}

/// Which slot the PAYLOAD ITSELF names, independently of the selector byte —
/// `None` when this project's own format detection does not recognise the
/// bytes as an archive in a format `SALVAGE_SLOTS` lists.
///
/// **Ruling S-S, and the structural half of Stage 2 Task 8.** The slot used
/// to be `selector % SALVAGE_SLOTS.len()` and nothing else, which made the
/// selector byte fight its own corpus: one mutated byte moves a seeded
/// archive onto a different format's scanner, that input explores different
/// code, libFuzzer keeps it for the new coverage, and the slot a seed was
/// written for fills up with other formats' bodies. Measured at Task 4 over
/// the 4,726 inputs a 200,000-run session accumulated: the `zoo` slot held
/// 876 of them and **not one produced a salvaged record of any status**,
/// with two real ZOO seeds in the corpus the whole time. There are five
/// slots now, so the pressure is 4-in-5 rather than 2-in-3.
///
/// Deriving the slot from the bytes is self-correcting where a selector byte
/// is not: mutation preserves a ZOO archive's four-byte tag at offset 20 far
/// more often than it preserves one chosen byte at offset 0, so a descendant
/// of a ZOO seed keeps reaching the ZOO scanner, and — the half that matters
/// as much — a descendant of a ZIP seed stops squatting on the ZOO slot.
///
/// It reuses [`stuffr_core::resolve_chain`] over `stuffr`'s own registry
/// rather than re-deriving each format's magic here, deliberately and
/// unlike every `*_locally_offers_checkable_crc` function above: those exist
/// to be an INDEPENDENT reading of the same bytes, so duplication is their
/// whole value, while this one only has to route an input and gains nothing
/// from disagreeing with the library about what a ZOO archive looks like.
/// It is the same call `entries::salvage`'s own `resolve_salvage_format`
/// makes for a real `stuffr salvage ARCHIVE` with no `--format`, minus the
/// path (the temp file is named `input`, so an extension would say nothing).
///
/// **The cost is named rather than hidden: cross-feeding narrows.** An input
/// carrying real zip magic can no longer be handed to the ARC scanner by a
/// selector byte, and `arc`'s measured 529-of-679 salvaged rows at Task 4
/// came exactly that way — from mutated zip bodies whose two-byte ARC anchor
/// (`0x1A` plus a method in `1..=11`, one coincidence per ~8 KiB) matched by
/// accident. That route is traded for real ARC seeds, which Task 8 adds in
/// the same change; feeding one format's scanner another format's bytes
/// stays reachable for every input whose magic this function does NOT
/// recognise, which after mutation is the overwhelming majority.
fn slot_from_payload(payload: &[u8]) -> Option<&'static str> {
    let prefix = &payload[..payload.len().min(stuffr_core::PROBE_LEN)];
    let container = stuffr_core::resolve_chain(stuffr::registry(), None, prefix)
        .ok()?
        .container()?;
    SALVAGE_SLOTS
        .iter()
        .copied()
        .find(|&slot| slot == container.as_str())
}

/// One line per input on stderr when `STUFFR_FUZZ_SALVAGE_TRACE` is set in
/// the environment, and nothing at all otherwise.
///
/// **An execution count is not evidence, and this is what replaces it.**
/// Stage 1's target truthfully reported `2000 executions — OK` while zero of
/// its inputs produced a salvaged record of any status, so its only oracle
/// call was unreachable by construction. The two tasks since each measured
/// the difference by hand-patching this file and reverting the patch, which
/// leaves the number in a report and no way to reproduce it. Gated tracing
/// makes the measurement a property of the harness instead:
///
/// ```text
/// STUFFR_FUZZ_SALVAGE_TRACE=1 cargo +nightly fuzz run salvage -- -runs=0 2>&1 \
///   | grep '^salvage-trace '
/// ```
///
/// `-runs=0` still executes every corpus file exactly once, so the lines are
/// one per input and can be summed per slot. `oracle` counts calls to
/// [`check_salvage_claim`], which is a DIFFERENT number from `intact`:
/// the call is skipped when the independent second scan did not also report
/// that scan position, or when this target's own raw-byte cross-check cannot
/// tell whether a checksum was checkable (`inconclusive`). Conflating the
/// two is the error the last two tasks each made once.
/// The per-entry ceiling this target runs under, in place of
/// [`SalvagePolicy::default`]'s 4 GiB.
///
/// Stage 2 Task 8 gave this target a real `dest` (Ruling S-O), which turns
/// every ceiling in the policy into a DISK bound as well as an allocation
/// one: a few-KiB input declaring a 4 GiB entry, or a Deflate payload
/// expanding towards its 1032:1 maximum, is now something the target tries
/// to place in a FILE rather than merely to verify in memory. 256 KiB sits
/// more than an order of magnitude above the largest entry any seed carries
/// (`store.zoo`'s 11,357-byte payload), so nothing the corpus starts from is
/// refused for its size, while an entry a mutation inflated is reported
/// `Unverified(OverEntryCeiling)` — a per-entry STATUS, never an error, so
/// it cannot end a run or take the entries around it with it.
///
/// This bounds one entry, not one iteration: a mutated archive can carry
/// many candidates. What bounds the iteration is that `dest` lives inside
/// the same `tempfile::tempdir()` as the input and is removed when that
/// handle drops, at the end of every iteration — nothing accumulates across
/// runs.
const FUZZ_MAX_ENTRY: u64 = 256 * 1024;

fuzz_target!(|data: &[u8]| {
    // Task 3b: the leading byte selects a format from `SALVAGE_SLOTS`,
    // mirroring `container.rs`'s own leading-selector-byte shape rather than
    // inventing a second one. Before this, `opts.format` was pinned to
    // `zip` alone — correct at the time (Stage 1 measured 20000 executions
    // with `format: None` reaching `zip_salvage` zero times, because
    // arbitrary bytes essentially never carry real zip magic and
    // `resolve_chain` rejected them first), but a pin means only zip is ever
    // fuzzed. `arc` landed with its own scanner in Stage 2 Task 3, and this
    // project's fuzzing has found a real bug in every hand-written binary
    // parser it has been pointed at, so a second pinned target is worse than
    // this one selector byte spending a small, bounded fraction of each
    // corpus seed on which format the rest of `data` is interpreted as.
    let Some((&selector, payload)) = data.split_first() else {
        return;
    };
    // Ruling S-S: the payload's own magic wins where there is one, and the
    // selector byte decides for everything else. See `slot_from_payload`.
    let name = slot_from_payload(payload)
        .unwrap_or(SALVAGE_SLOTS[selector as usize % SALVAGE_SLOTS.len()]);

    // `entries::salvage` takes a path, not a `Source` — the same reason
    // `chain.rs`'s `entries::list` and `container.rs`'s seekable branch both
    // spool to a real file: salvage is inherently seek-bound (a resync scan
    // over the whole archive), so only a real file exercises the path a
    // real caller's `stuffr salvage ARCHIVE` takes.
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("input");
    std::fs::write(&path, payload).expect("write temp input");

    // **`dest: Some(...)` as of Stage 2 Task 8 — Ruling S-O.** This said
    // `dest: None`, on the reasoning that the target was "about parsing and
    // verification honesty, not about the filesystem write/containment path
    // `extract`'s own fuzzing already covers via `chain.rs`". That reasoning
    // was measurably wrong twice over: `chain.rs` drives `entries::list`,
    // which places nothing on disk at all, and salvage's write side is not
    // `extract`'s — it owns disambiguation (`NAME.salvaged-N`), the
    // `.partial` spelling, and a per-run claimed-path map none of which
    // exists anywhere else. What the gap cost is on the record: a zip entry
    // with a 404-character name made `salvage -C` print `i/o error: File
    // name too long` and exit **1** — the one exit code this project treats
    // as never acceptable for hostile input — abandoning every entry behind
    // it, and it survived a whole stage of fuzzing because nothing in view
    // of the oracle ever asked the filesystem for anything.
    //
    // The destination is a sibling of the input inside the same tempdir, so
    // it is removed with it at the end of every iteration.
    //
    // `format: Some(name)` — bypasses auto-detection exactly as the old
    // pinned `Some(zip)` did, and for the identical reason: arbitrary
    // fuzzer bytes essentially never carry a real magic for WHATEVER format
    // the selector byte chose, so auto-detection would reject nearly every
    // input as `Error::UnknownFormat` before it ever reached a scanner —
    // collapsing this target's coverage of exactly the code the independent
    // second pass below cross-checks. Naming a format `salvage_scan` has no
    // scanner for (every slot outside `SALVAGE_SLOTS`) or has not compiled
    // in (a build missing the `zip`/`arc` feature) both answer through the
    // ordinary `Err` arm below — `Error::Unsupported` and
    // `Error::FormatNotEnabled` respectively, both classified exit codes,
    // never a panic — so `SALVAGE_SLOTS` needs no separate "not compiled"
    // branch of its own.
    let opts = SalvageOpts {
        dest: Some(tmp.path().join("recovered")),
        // `max_entry` narrowed from the default 4 GiB — see
        // `FUZZ_MAX_ENTRY`, which is a disk bound now that `dest` is real.
        policy: SalvagePolicy {
            max_entry: FUZZ_MAX_ENTRY,
            ..SalvagePolicy::default()
        },
        select: None,
        format: Some(stuffr_core::FormatId::new(name)),
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
    // for its own cross-check. Dispatched on `name` because each format's
    // scanner has its own entry point and its own raw-byte cross-check
    // below; a slot appended to `SALVAGE_SLOTS` without a matching arm here
    // ABORTS the run (`no_cross_check_arm`) rather than skipping this
    // cross-check. That used to be a `_` arm returning an empty map, on the
    // reasoning that skipping is "an honest 'not built yet', not a silent
    // pass" — see `no_cross_check_arm`'s own doc for the task that shipped
    // exactly that state and reported the opposite.
    let mut cursor = Cursor::new(payload.to_vec());
    let offsets: HashMap<usize, u64> = match name {
        "zip" => match zip_salvage::salvage_zip(&mut cursor, &opts.policy) {
            Ok(scan) => scan
                .entries
                .into_iter()
                .map(|e| (e.scan_position, e.offset))
                .collect(),
            Err(e) => {
                check_error_is_classified(&e).expect("independent scan error classification");
                HashMap::new()
            }
        },
        "arc" => match arc_salvage::salvage_arc(&mut cursor, &opts.policy) {
            Ok(scan) => scan
                .entries
                .into_iter()
                .map(|e| (e.scan_position, e.offset))
                .collect(),
            Err(e) => {
                check_error_is_classified(&e).expect("independent scan error classification");
                HashMap::new()
            }
        },
        "zoo" => match zoo_salvage::salvage_zoo(&mut cursor, &opts.policy) {
            Ok(scan) => scan
                .entries
                .into_iter()
                .map(|e| (e.scan_position, e.offset))
                .collect(),
            Err(e) => {
                check_error_is_classified(&e).expect("independent scan error classification");
                HashMap::new()
            }
        },
        "lha" => match lha_salvage::salvage_lha(&mut cursor, &opts.policy) {
            Ok(scan) => scan
                .entries
                .into_iter()
                .map(|e| (e.scan_position, e.offset))
                .collect(),
            Err(e) => {
                check_error_is_classified(&e).expect("independent scan error classification");
                HashMap::new()
            }
        },
        "arj" => match arj_salvage::salvage_arj(&mut cursor, &opts.policy) {
            Ok(scan) => scan
                .entries
                .into_iter()
                .map(|e| (e.scan_position, e.offset))
                .collect(),
            Err(e) => {
                check_error_is_classified(&e).expect("independent scan error classification");
                HashMap::new()
            }
        },
        other => no_cross_check_arm(other),
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
        let offers_crc = match name {
            "zip" => locally_offers_checkable_crc(payload, offset),
            "arc" => arc_locally_offers_checkable_crc(payload, offset),
            "zoo" => zoo_locally_offers_checkable_crc(payload, offset),
            "lha" => lha_locally_offers_checkable_crc(payload, offset),
            "arj" => arj_locally_offers_checkable_crc(payload, offset),
            other => no_cross_check_arm(other),
        };
        if let Some(offers_crc) = offers_crc {
            check_salvage_claim(record.status, offers_crc)
                .expect("salvage claim: Intact without a checkable checksum");
        }
    }
});
