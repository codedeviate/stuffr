#![no_main]
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::io::Cursor;
use std::sync::OnceLock;
use stuffr::entries::{self, SalvageOpts};
use stuffr_core::salvage::{SalvagePolicy, SalvageStatus};
use stuffr_core::testing::{
    Attestation, CountingSource, SALVAGE_FUZZ_MAX_ENTRY, SALVAGE_SLOTS, check_error_is_classified,
    check_salvage_claim, check_scan_is_linear,
};
use stuffr_formats::legacy::{arc_salvage, arj_salvage, lha_salvage, zoo_salvage};
use stuffr_formats::{ar_salvage, cpio_salvage, tar_salvage, zip_salvage};

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

/// A tar header block's size, and where its checksum field sits in it:
/// POSIX.1-1988 ustar's `chksum`, eight bytes after `name` (100), `mode`,
/// `uid`, `gid` (8 each), `size` and `mtime` (12 each). Duplicated here for
/// the same reason every constant above is — `tar_salvage.rs`'s own are
/// private, and a divergence is itself the finding.
const TAR_BLOCK: usize = 512;
const TAR_CHECKSUM: std::ops::Range<usize> = 148..156;

/// The `tar` slot's cross-check (Salvage Stage 3 Task 2), and a different
/// QUESTION from the five above, because tar's class is
/// [`Attestation::HeaderChecksumOnly`]: tar carries no content checksum, so
/// what `check_salvage_claim` needs to know about a `Complete` record is
/// whether the HEADER checksum it stands on really agrees.
///
/// **Recomputed here from the definition, never taken from the scanner.**
/// Passing the scanner's own verdict as `verifier_was_checked` would be
/// circular — the oracle would be checking the scanner's answer against the
/// scanner's answer. This sums the 512 bytes at the record's offset with the
/// checksum field counted as eight spaces, and compares that with the
/// field's own text read as octal (up to its first NUL, trimmed — the
/// spelling the `tar` crate's reader accepts, so a header `stuffr list`
/// takes is one this takes).
///
/// `None` — inconclusive — only when fewer than 512 bytes sit at the
/// offset. A field that is not a number is `Some(false)`: a header whose
/// checksum does not agree is exactly what a `Complete` must never stand on.
fn tar_header_checksum_agrees(data: &[u8], offset: u64) -> Option<bool> {
    let at = usize::try_from(offset).ok()?;
    let block = data.get(at..at.checked_add(TAR_BLOCK)?)?;
    let field = &block[TAR_CHECKSUM];
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    let Some(recorded) = std::str::from_utf8(&field[..end])
        .ok()
        .and_then(|text| u64::from_str_radix(text.trim(), 8).ok())
    else {
        return Some(false);
    };
    let summed: u64 = block
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            if TAR_CHECKSUM.contains(&i) {
                u64::from(b' ')
            } else {
                u64::from(b)
            }
        })
        .sum();
    // The recorded value is compared as the reader compares it, truncated
    // to 32 bits; a sum of 512 bytes never exceeds 17.
    Some(summed == u64::from(recorded as u32))
}

/// The `cpio` slot's cross-check (Salvage Stage 3 Task 3). cpio's class is
/// [`Attestation::Nothing`]: `newc` carries no checksum of any kind, so the
/// honest answer to "was the verifier checked?" is `false` for every record,
/// and that is what this returns — `Some(false)` — whenever the record's
/// offset really does hold the `070701` magic the scanner found it by.
///
/// **What this can catch is the two claims the class forbids.** An `Intact`
/// or a `Complete` is refused for this class whatever the flag says, so the
/// loop checks those before reaching here; an `Unattested` passed with
/// `true` would be refused too, so a future edit that sourced this flag from
/// the scanner's own verdict (circular, as `tar_header_checksum_agrees`'s
/// doc says) and got `true` would abort. The magic re-read is independent of
/// the scanner — six bytes compared here, not by `cpio_salvage.rs` — and a
/// record at an offset without it is `None` (inconclusive), counted in the
/// trace rather than silently passed.
fn cpio_offers_no_verifier(data: &[u8], offset: u64) -> Option<bool> {
    let at = usize::try_from(offset).ok()?;
    (data.get(at..at.checked_add(6)?)? == b"070701").then_some(false)
}

/// The `ar` slot's cross-check (Salvage Stage 3 Task 4). `ar`'s class is
/// [`Attestation::Nothing`], exactly as cpio's is — no checksum over a
/// member's content or its header — so the honest answer is `Some(false)`
/// for every record, given whenever the record's offset really does hold a
/// member header: past the eight-byte global header, with the two-byte
/// `` `\n `` terminator at its fixed place, read here from the raw bytes
/// rather than by `ar_salvage.rs` (whose walk is `ar::Archive`'s, which
/// never checks that terminator at all). A record without it is `None`,
/// inconclusive, and counted in the trace.
fn ar_offers_no_verifier(data: &[u8], offset: u64) -> Option<bool> {
    let at = usize::try_from(offset).ok()?;
    (at >= 8 && data.get(at.checked_add(58)?..at.checked_add(60)?)? == b"`\n").then_some(false)
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
/// searching `SALVAGE_SLOTS` itself — a payload detecting as a container no
/// slot names yields `None` and falls back to the selector rather than
/// reaching here. So the
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

/// Why the per-entry ceiling is [`SALVAGE_FUZZ_MAX_ENTRY`] rather than
/// [`SalvagePolicy::default`]'s 4 GiB, and what actually bounds one
/// iteration.
///
/// Stage 2 Task 8 gave this target a real `dest` (Ruling S-O), which turns
/// every ceiling in the policy into a DISK bound as well as an allocation
/// one: a few-KiB input declaring a 4 GiB entry, or a Deflate payload
/// expanding towards its 1032:1 maximum, is now something the target tries
/// to place in a FILE rather than merely to verify in memory. The figure
/// itself, and why 256 KiB, live on the constant — in `stuffr-core`, so the
/// corpus generator's own test can assert every seed against it. It was a
/// constant in THIS file when Task 8 first shipped, and the review found the
/// consequence at once: `fuzz/` is excluded from the workspace, so nothing
/// the gate runs could see the figure, and a future seed carrying a larger
/// entry would have been silently refused inside every run with the whole
/// suite green.
///
/// **That bounds one ENTRY. One ITERATION is bounded by the input's own
/// size, and the number is worth stating because it is the one that decides
/// whether a run can fill a disk.** Nothing caps the candidate COUNT —
/// `SalvagePolicy` has no such field, and a mutated archive can carry many
/// headers — but every byte written comes from the input, and libFuzzer
/// resolves `-max_len` to the largest file in the corpus, **measured at
/// 11,530 bytes** over the seeded corpus. The only inflation vector is a
/// codec, capped near 1032:1 by Deflate, so the worst case is roughly
/// **11 MB per iteration**, removed with the tempdir at the end of it. That
/// figure MOVES the day a seed larger than ~11 KB is added: it is a property
/// of the corpus, not of this file.
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

/// Which class of evidence the FORMAT behind a slot offers — the
/// [`Attestation`] that is [`check_salvage_claim`]'s third argument, and a
/// fact about the format, not about one candidate.
///
/// Five slots are [`Attestation::ContentChecksum`]: zip carries a CRC-32,
/// and ARC, ZOO, LHA and ARJ each carry a CRC of their own. `tar` (Stage 3
/// Task 2) is [`Attestation::HeaderChecksumOnly`], and `cpio` (Task 3) and
/// `ar` (Task 4) are [`Attestation::Nothing`]. Per slot, never one
/// constant, because the classes differ — a constant would carry the wrong
/// class into the exact slots the argument exists for, silently.
///
/// **Read from `entries::salvage_attestation` since Salvage Stage 3 Task 5**,
/// not stated here. This was a `match` of its own, and `stuffr formats`'
/// SALVAGE column needs the same fact, which a fuzz target excluded from
/// the workspace cannot export — so the class now lives in ONE table, the
/// facade's scanner dispatch, beside each scanner's entry point. That table
/// is still apart from the code under test: no scanner consults it when it
/// decides a status, so the oracle still checks each scanner's statuses
/// against a class the scanner did not choose for itself. A slot with no
/// scanner (`None`) aborts the run, as an unmatched name here always did —
/// the loud-not-silent rule [`no_cross_check_arm`] states.
///
/// It was a `bool` (`format_offers_verifier`) for one commit, and that
/// could not tell a header-only checksum from a content one: a scanner in
/// any of these five slots answering `Complete` after its CRC had been
/// compared and disagreed passed the oracle. Ruling 3-G.
fn attestation(name: &'static str) -> Attestation {
    entries::salvage_attestation(stuffr_core::FormatId::new(name)).unwrap_or_else(|| {
        panic!(
            "SALVAGE_SLOTS names `{name}`, but `entries::salvage_attestation` reports no \
             scanner for it in this build — so `check_salvage_claim` has no class to judge it \
             by. Append a slot only in the commit that wires its scanner."
        )
    })
}

/// Runs [`check_salvage_claim`] and reports that one call was made.
///
/// **The count is the RESULT of performing the check, never a statement
/// beside it**, and the difference is this project's signature defect in
/// miniature: an `oracle += 1;` sitting next to the call survives an edit
/// that deletes the call, and the trace then reports oracle activity for a
/// harness that has none — the same detached-instrument shape as Stage 1's
/// unreachable oracle and Task 6's missing `arj` arm. Here the only way to
/// obtain the increment is to have called the oracle.
fn run_oracle(status: SalvageStatus, offers_crc: bool, attestation: Attestation) -> usize {
    check_salvage_claim(&status, offers_crc, attestation)
        .expect("salvage claim: a status claiming more than the format or the scan supports");
    1
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
/// one per input and can be summed per slot. `claims` counts records in any
/// of the three tiers the oracle can refuse (`Intact`, `Complete`,
/// `Unattested` — see [`makes_a_claim`]), `intact` the first of them alone,
/// and `oracle` counts calls to [`check_salvage_claim`], which is a
/// DIFFERENT number from both: the call is skipped when the independent
/// second scan did not also report that scan position, or when this
/// target's own raw-byte cross-check cannot tell whether a checksum was
/// checkable (`inconclusive`). Conflating the two is the error the last two
/// tasks each made once. A claim the slot's class forbids outright is the
/// one exception — it is checked with no cross-check at all (Ruling 3-I),
/// and on a healthy scanner there are none, so on a healthy run `claims`
/// minus `intact` is also the number of records whose tier needed a
/// cross-check the checksummed slots do not have.
/// `routed` says which of the two decided the slot — `magic` when the
/// payload named itself and `selector` when it fell back to the leading byte
/// — so the effect of Ruling S-S's change is measurable on its own rather
/// than only visible as a shift in the totals.
fn trace(slot: &str, routed: &str, rows: usize, tally: Tally) {
    static ON: OnceLock<bool> = OnceLock::new();
    if *ON.get_or_init(|| std::env::var_os("STUFFR_FUZZ_SALVAGE_TRACE").is_some()) {
        eprintln!(
            "salvage-trace slot={slot} routed={routed} rows={rows} intact={} claims={} \
             oracle={} inconclusive={}",
            tally.intact, tally.claims, tally.oracle, tally.inconclusive
        );
    }
}

/// One line per input on stderr when `STUFFR_FUZZ_SCAN_TRACE` is set, and
/// nothing otherwise: the bytes the independent second scan was delivered
/// against the input's length — the two figures [`check_scan_is_linear`]
/// judges, printed BEFORE it judges them so an aborting input still leaves
/// its line.
///
/// ```text
/// STUFFR_FUZZ_SCAN_TRACE=1 cargo +nightly fuzz run salvage -- -runs=0 2>&1 \
///   | grep '^scan-trace '
/// ```
///
/// This is how 0.10.3 Task 4 measured the corpus that
/// `stuffr_core::testing::SCAN_READ_FACTOR` and `SCAN_READ_SLACK` cite, and
/// how a later change to a scanner's resync loop re-measures it.
fn scan_trace(slot: &str, len: u64, read: u64) {
    static ON: OnceLock<bool> = OnceLock::new();
    if *ON.get_or_init(|| std::env::var_os("STUFFR_FUZZ_SCAN_TRACE").is_some()) {
        let ratio = read as f64 / len.max(1) as f64;
        eprintln!("scan-trace slot={slot} len={len} read={read} ratio={ratio:.3}");
    }
}

/// What one input's loop counted, for [`trace`]. A struct rather than four
/// positional `usize`s, because two of them (`claims` and `oracle`) are
/// easy to transpose and the whole point of the line is that they differ.
#[derive(Default)]
struct Tally {
    intact: usize,
    claims: usize,
    oracle: usize,
    inconclusive: usize,
}

/// Whether `status` is one of the three tiers [`check_salvage_claim`] can
/// refuse — the tiers that CLAIM something (a checksum agreed, a header
/// self-verified, nothing attests the entry). `Unverified` and `Partial`
/// are unconstrained by the oracle for every class, so consulting it for
/// them would only inflate the `oracle` count with calls that cannot fail.
///
/// An exhaustive `match`, so a sixth tier added to [`SalvageStatus`] does
/// not compile here until somebody decides whether it makes a claim.
fn makes_a_claim(status: SalvageStatus) -> bool {
    match status {
        SalvageStatus::Intact | SalvageStatus::Complete | SalvageStatus::Unattested => true,
        SalvageStatus::Unverified(_) | SalvageStatus::Partial => false,
    }
}

/// Whether the oracle refuses `status` for a slot of class `class` under
/// BOTH values of its checked flag — i.e. whether the claim is forbidden
/// for the class outright, so that no independent cross-check could change
/// the verdict.
///
/// **Asked of the oracle itself rather than restated as a table here.** A
/// copy of the truth table in this file would be a second source that could
/// drift from `honesty.rs`'s, and a drifted copy that thought a cell was
/// permitted would silently skip exactly the call this function exists to
/// make. These two calls are not counted: they decide whether the counted
/// one — [`run_oracle`] — is made with or without a cross-check.
fn refused_whatever_was_checked(status: SalvageStatus, class: Attestation) -> bool {
    check_salvage_claim(&status, true, class).is_err()
        && check_salvage_claim(&status, false, class).is_err()
}

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
    let (name, routed) = match slot_from_payload(payload) {
        Some(name) => (name, "magic"),
        None => (
            SALVAGE_SLOTS[selector as usize % SALVAGE_SLOTS.len()],
            "selector",
        ),
    };

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
        // `max_entry` narrowed from the default 4 GiB — see the comment
        // above `slot_from_payload`, and `SALVAGE_FUZZ_MAX_ENTRY` itself.
        policy: SalvagePolicy {
            max_entry: SALVAGE_FUZZ_MAX_ENTRY,
            ..SalvagePolicy::default()
        },
        select: None,
        format: Some(stuffr_core::FormatId::new(name)),
    };

    // Held, not matched: the counted second pass and the linearity check
    // below must run whether or not this pass erred. An `Err` (commonly
    // `Unsupported`: nothing recovered plus one ungateable shape) used to
    // `return` here, so exactly those inputs were never held to the bound.
    let first_pass = entries::salvage(&path, &opts);

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
    //
    // The source is wrapped in a `CountingSource` once, and every arm reads
    // through it, so after the match it holds every byte this scan was
    // delivered — re-reads included — and `check_scan_is_linear` holds the
    // scan to work linear in its input. 0.10.3 closed two classes where a
    // hostile input made a scanner re-read the same bytes per candidate
    // (cpio zero runs, tar converging extension chains); this is the
    // oracle that would have found them, for every slot at once. See
    // `scan_trace` for the measurement it makes reproducible.
    let mut cursor = CountingSource::new(Cursor::new(payload.to_vec()));
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
        "tar" => match tar_salvage::salvage_tar(&mut cursor, &opts.policy) {
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
        "cpio" => match cpio_salvage::salvage_cpio(&mut cursor, &opts.policy) {
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
        "ar" => match ar_salvage::salvage_ar(&mut cursor, &opts.policy) {
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
    let len = payload.len() as u64;
    scan_trace(name, len, cursor.bytes_read());
    check_scan_is_linear(cursor.bytes_read(), len)
        .expect("salvage: scan work is linear in its input");

    let outcome = match first_pass {
        Ok(o) => o,
        Err(e) => {
            check_error_is_classified(&e).expect("salvage error classification");
            trace(name, routed, 0, Tally::default());
            return;
        }
    };

    let mut intact = 0usize;
    let mut claims = 0usize;
    let mut oracle = 0usize;
    let mut inconclusive = 0usize;
    let class = attestation(name);
    for record in &outcome.entries {
        if !makes_a_claim(record.status) {
            continue;
        }
        claims += 1;
        if record.status == SalvageStatus::Intact {
            intact += 1;
        }
        // Ruling 3-I. A claim this slot's class never permits is refused
        // whichever way the checked flag falls, so no cross-check below
        // could rescue it and none is consulted: the call is made straight
        // away, and it aborts. That is the `Complete`-after-a-disagreeing-
        // CRC hole (exit 4 turned into exit 0) and a scanner that forgot to
        // override `verify` (the trait default answers `Unattested`), for
        // all five checksummed slots — neither of which this loop could see
        // while it skipped every record that was not `Intact`.
        if refused_whatever_was_checked(record.status, class) {
            oracle += run_oracle(record.status, false, class);
            continue;
        }
        // A scan position the independent pass did not also report is not
        // this check's job (the two disagreeing on structure would be a
        // different finding, over a determinism assumption this target does
        // not otherwise test) — skip rather than assert something neither
        // scan actually observed.
        let Some(&offset) = offsets.get(&record.scan_position) else {
            inconclusive += 1;
            continue;
        };
        // Whether the checksum this slot's class offers was really there to
        // be checked: a CONTENT checksum for the five checksummed slots, the
        // HEADER checksum for tar, nothing at all for cpio and ar — each re-derived
        // from the raw bytes.
        let checked = match name {
            "zip" => locally_offers_checkable_crc(payload, offset),
            "arc" => arc_locally_offers_checkable_crc(payload, offset),
            "zoo" => zoo_locally_offers_checkable_crc(payload, offset),
            "lha" => lha_locally_offers_checkable_crc(payload, offset),
            "arj" => arj_locally_offers_checkable_crc(payload, offset),
            "tar" => tar_header_checksum_agrees(payload, offset),
            "cpio" => cpio_offers_no_verifier(payload, offset),
            "ar" => ar_offers_no_verifier(payload, offset),
            other => no_cross_check_arm(other),
        };
        match checked {
            Some(checked) => {
                oracle += run_oracle(record.status, checked, class);
            }
            None => inconclusive += 1,
        }
    }
    trace(
        name,
        routed,
        outcome.entries.len(),
        Tally {
            intact,
            claims,
            oracle,
            inconclusive,
        },
    );
});
