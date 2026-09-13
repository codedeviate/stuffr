#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use stuffr_core::testing::{
    CONTAINER_SLOTS, check_entry_count, check_entry_size, check_error_is_classified,
    check_fidelity_claim,
};
use stuffr_core::{
    Container, Error, FileSource, FormatId, OpenOpts, ReaderSource, Source, StreamPolicy,
};

/// Independently parses a seekable zip's declared entry count from its EOCD
/// record, applying the same two guards
/// `crates/stuffr-formats/src/zip.rs`'s `read_declared_index` (~:554) and
/// `note_unreachable_records` (~:652) apply before trusting it:
///
/// 1. The EOCD signature is accepted only when its declared comment length
///    runs EXACTLY to the end of the file — never a bare backwards signature
///    match, which also occurs inside file comments and stored payloads.
/// 2. The declared `cd_offset` must be the one `zip::ZipArchive` itself used.
///    `zip.rs` has this for free from the archive it already has open;
///    outside that module the only way to get it is to open a SECOND,
///    independent `zip::ZipArchive` over the identical bytes, via the
///    identical `zip` crate, and read its own `offset()` /
///    `central_directory_start()`. Because both parses run the SAME crate
///    logic over the SAME bytes, this is not a weaker approximation of
///    zip.rs's guard — it is the same computation, checked from outside.
///
/// DELIBERATE DUPLICATION, not a shared helper: a divergence between this
/// parse and stuffr's own internal one is *itself* the finding this target
/// exists to surface. Factoring the two into one function would make that
/// divergence unreachable by construction — the exact vacuity this whole
/// harness exists to prevent.
///
/// Zip64 is out of scope: this returns `None` on anything it cannot parse
/// with certainty (including a saturated 16-bit count/32-bit offset that
/// would need the zip64 escape hatch), the same conservative default
/// `read_declared_index` uses for its own uncertain cases.
fn declared_zip_index(path: &Path) -> Option<usize> {
    const SIG_END_OF_CENTRAL_DIR: [u8; 4] = *b"PK\x05\x06";
    const END_OF_CENTRAL_DIR_TOTAL: usize = 22;
    const MAX_EOCD_SEARCH: u64 = 22 + u16::MAX as u64;

    let mut file = std::fs::File::open(path).ok()?;
    let end = file.seek(SeekFrom::End(0)).ok()?;
    let window = end.min(MAX_EOCD_SEARCH);
    if window < END_OF_CENTRAL_DIR_TOTAL as u64 {
        return None;
    }
    file.seek(SeekFrom::Start(end - window)).ok()?;
    let mut tail = vec![0u8; usize::try_from(window).ok()?];
    file.read_exact(&mut tail).ok()?;

    // Guard 1.
    let at = (0..=tail.len().checked_sub(END_OF_CENTRAL_DIR_TOTAL)?)
        .rev()
        .find(|&i| {
            tail[i..i + 4] == SIG_END_OF_CENTRAL_DIR
                && i + END_OF_CENTRAL_DIR_TOTAL
                    + u16::from_le_bytes([tail[i + 20], tail[i + 21]]) as usize
                    == tail.len()
        })?;

    // `entries` — the value this function returns as `declared` — comes
    // ENTIRELY from these two raw bytes of the EOCD record, never from
    // `archive.len()` below. That distinction is load-bearing: `len()` counts
    // distinct NAMES in the `zip` crate's `IndexMap`, which is exactly what
    // collapses when two central-directory records share a name (the
    // Notion.zip bug this whole check exists to catch). If `declared` were
    // read from `archive.len()` instead, `check_entry_count` would compare
    // the collapsed count against itself and could never disagree — a
    // tautology. `entries` here is the archive's own un-collapsed claim.
    let entries = u16::from_le_bytes([tail[at + 10], tail[at + 11]]);
    let cd_offset = u32::from_le_bytes([tail[at + 16], tail[at + 17], tail[at + 18], tail[at + 19]]);
    if entries == u16::MAX || cd_offset == u32::MAX {
        // zip64 escape hatch — out of scope here, see the doc comment.
        return None;
    }

    // Guard 2. `archive` is used ONLY for `.offset()` and
    // `.central_directory_start()` — both byte POSITIONS the crate located
    // while parsing, not entry counts, so neither is subject to the
    // name-collapsing `.len()` performs. `.len()` itself is never called on
    // this archive; `enumerated` (the walk's own count, compared against
    // `entries` above by the caller) comes from `ar.next_entry()` on
    // stuffr's own container reader, a completely separate object.
    let file2 = std::fs::File::open(path).ok()?;
    let archive = zip::ZipArchive::new(file2).ok()?;
    if u64::from(cd_offset).checked_add(archive.offset()) != Some(archive.central_directory_start())
    {
        return None;
    }

    Some(usize::from(entries))
}

/// Walks `payload` through `container` a SECOND time, forward-only, counting
/// entries — Ruling B's independent observation for `check_fidelity_claim`.
///
/// This is not redundant with `check_entry_count`: that check compares the
/// EOCD's declared count (zip only) against the PRIMARY (seekable) walk's own
/// enumeration, and whenever the two genuinely disagree, `zip.rs`'s own
/// `note_unreachable_records` — which runs the identical two guards — has
/// already added `Fidelity::EntryCountMismatch` to the report, which makes
/// `report.is_lossless()` false and lets `check_fidelity_claim` return `Ok`
/// regardless of `approximated`. So a disagreement between "declared" and
/// "seekably enumerated" can never be the fact that makes `check_fidelity_claim`
/// fire — it is always already owned up to, or the archive never gets this far
/// because `check_entry_count` panicked first.
///
/// The genuinely independent fact is a disagreement between two *readings of
/// the same bytes that never touch the EOCD's declared count at all*: the
/// seekable walk (which, for zip, counts central-directory records) against a
/// forward-only walk of the identical bytes (which counts LOCAL file headers
/// as they stream past). A local header with no corresponding central-directory
/// record — extra bytes the seekable/authoritative reading never sees at
/// all — makes the forward count diverge from the seekable one while the
/// central directory itself, and hence the EOCD's declared count, is entirely
/// self-consistent: `check_entry_count` passes cleanly, no
/// `EntryCountMismatch` warning is ever raised, and the report stays
/// `Rung::Exact` with empty `warnings` — exactly the `is_lossless()` state
/// `check_fidelity_claim` polices. Not zip-specific in principle (any
/// container's forward and seekable readers could in principle diverge for
/// reasons neither of the other two checks would ever observe), so this runs
/// for every slot, not only zip.
///
/// **What a divergence PROVES is not the same for zip as for the other
/// three**, and reading this count as "the seekable walk approximated
/// something" regardless of slot was the over-strict shape the Phase 3a
/// whole-branch review caught before the first deep run. See the predicate at
/// the bottom of the target for the split and the argument.
///
/// `None` means "inconclusive", not "zero entries": any error along this path
/// still goes through `check_error_is_classified` (so a genuine
/// misclassification reachable ONLY via the forward-only route is still
/// caught), but a legitimately classified refusal — `Unsupported` on a zip
/// using data descriptors, say, which `zip.rs`'s forward reader cannot walk —
/// means this comparison simply has nothing to say, not that anything is
/// wrong.
fn forward_entry_count(container: &dyn Container, payload: &[u8]) -> Option<usize> {
    let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(payload.to_vec())));
    let resolved = match stuffr_core::resolve(
        src,
        container.id(),
        container.caps(),
        &StreamPolicy::ForwardOnly,
    ) {
        Ok(r) => r,
        Err(e) => {
            check_error_is_classified(&e).expect("forward cross-check: resolve classification");
            return None;
        }
    };
    let mut ar = match container.open(resolved, &OpenOpts::default()) {
        Ok(a) => a,
        Err(e) => {
            check_error_is_classified(&e).expect("forward cross-check: open classification");
            return None;
        }
    };

    let mut count = 0usize;
    let mut buf = [0u8; 4096];
    loop {
        let mut entry = match ar.next_entry() {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(e) => {
                check_error_is_classified(&e)
                    .expect("forward cross-check: next_entry classification");
                return None;
            }
        };
        count += 1;
        // Drain the payload: the forward reader's position for entry N+1
        // depends on having consumed entry N's bytes, since there is no seek
        // to skip ahead with. Leaving this unread would make the count an
        // artefact of OUR walk, not a fact about the archive.
        loop {
            match entry.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) => {
                    let e = Error::from_decode_io(e);
                    check_error_is_classified(&e)
                        .expect("forward cross-check: entry read classification");
                    return None;
                }
            }
        }
    }
    Some(count)
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, payload)) = data.split_first() else {
        return;
    };

    // The selector's high bit picks the ladder rung, and this is load-
    // bearing: without the seekable half, `check_entry_count` can never
    // fire, because `ReaderSource` declares `seekable: false` and zip's
    // forward path never reads the central directory that carries a
    // declared count. A forward-only target would leave that invariant
    // permanently vacuous.
    let seekable = selector & 0x80 != 0;
    let name = CONTAINER_SLOTS[(selector & 0x7f) as usize % CONTAINER_SLOTS.len()];

    let registry = stuffr::registry();
    let Some(container) = registry.container(FormatId::new(name)) else {
        return;
    };

    // The tempdir/file is needed ONLY on the seekable path: the forward-only
    // branch below builds its `Source` straight from an in-memory `Cursor`
    // and never touches a path. `_tmp_guard` keeps the `TempDir` alive (and
    // therefore its cleanup deferred to the end of this closure) without
    // paying for one on iterations that never use it.
    let mut _tmp_guard: Option<tempfile::TempDir> = None;
    let path: Option<PathBuf> = if seekable {
        let tmp = tempfile::tempdir().expect("tempdir");
        let p = tmp.path().join("input");
        std::fs::write(&p, payload).expect("write temp input");
        _tmp_guard = Some(tmp);
        Some(p)
    } else {
        None
    };

    let src: Box<dyn Source> = if let Some(p) = &path {
        match FileSource::open(p) {
            Ok(s) => Box::new(s),
            Err(e) => {
                check_error_is_classified(&e).expect("FileSource::open error classification");
                return;
            }
        }
    } else {
        Box::new(ReaderSource::new(std::io::Cursor::new(payload.to_vec())))
    };

    let policy = if seekable {
        StreamPolicy::default()
    } else {
        StreamPolicy::ForwardOnly
    };

    let resolved = match stuffr_core::resolve(src, container.id(), container.caps(), &policy) {
        Ok(r) => r,
        Err(e) => {
            check_error_is_classified(&e).expect("resolve error classification");
            return;
        }
    };

    let mut ar = match container.open(resolved, &OpenOpts::default()) {
        Ok(a) => a,
        Err(e) => {
            check_error_is_classified(&e).expect("open error classification");
            return;
        }
    };

    let mut enumerated: usize = 0;

    loop {
        let mut entry = match ar.next_entry() {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(e) => {
                check_error_is_classified(&e).expect("next_entry error classification");
                return;
            }
        };
        let declared_size = entry.meta().size;
        let entry_name = entry.meta().name.clone();
        // Cloned alongside the name, and for the same reason: `entry.meta()`
        // borrows `entry`, which `entry.reader()` below needs mutably.
        // `check_entry_size` consults the kind because a SYMLINK's payload is
        // read by the container itself and the caller is handed
        // `io::empty()` — see that function's own doc for why passing the
        // kind is what stops this target aborting on the first legitimate
        // archive `make fuzz-corpus` writes.
        let entry_kind = entry.meta().kind.clone();
        enumerated += 1;

        let mut produced = 0u64;
        let mut buf = [0u8; 4096];
        loop {
            match entry.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => produced += n as u64,
                Err(e) => {
                    // `from_decode_io`, NOT the bare `Error::Io` `Error::from`
                    // would give: an `io::Error` here can be malformed-input
                    // `InvalidData`, which this boundary is EXPECTED to
                    // reclassify as `Error::Corrupt` (exit 5) — see
                    // `error.rs`'s own doc on `from_decode_io` and its other
                    // callers (`ops.rs`, `entries.rs`, `conformance.rs`).
                    // Using the bare `From` here would make this oracle call
                    // an unconditional panic wearing an invariant's clothes:
                    // every read error, hostile or not, is `Error::Io`, which
                    // is exit 1 by construction, which
                    // `check_error_is_classified` always refuses.
                    let e = Error::from_decode_io(e);
                    check_error_is_classified(&e).expect("entry read error classification");
                    return;
                }
            }
        }
        // `entry` is dropped at the end of this loop body, releasing its
        // borrow on `ar` before the next `ar.next_entry()` call.

        check_entry_size(declared_size, produced, &entry_name, &entry_kind).expect("entry size");
    }

    // Read the report only now that the walk is complete, not mid-walk.
    let report = ar.fidelity();

    // Ruling A: `declared` is obtained by an independent parse, zip slot on
    // the seekable path only. Every other slot, and zip on the forward-only
    // path, declares no count — `ArchiveRead` exposes none itself — so
    // `declared = None` there and `check_entry_count` returns `Ok`
    // immediately, correctly: only zip has a count to check against.
    let declared: Option<usize> = if seekable && name == "zip" {
        declared_zip_index(path.as_deref().expect("path is Some whenever seekable"))
    } else {
        None
    };

    check_entry_count(declared, enumerated, report).expect("entry count");

    // Ruling B: `approximated` must be an independent observation — one that
    // can be TRUE in a state where every other oracle call in this target
    // still returns `Ok`. `forward_entry_count`'s cross-check is exactly
    // that: see its own doc comment for why it cannot be satisfied by the
    // same fact `check_entry_count` already owns up to. Only run on the
    // seekable path: `Rung::ForwardOnly` is never `is_authoritative()`
    // (`fidelity.rs`), so `report.is_lossless()` is already false on the
    // forward-only branch and `check_fidelity_claim` can never fire there
    // regardless — running the second walk would cost a walk for an
    // observation that can never matter.
    //
    // The PREDICATE is per-slot, because what a divergence proves is not the
    // same for zip as for the other three, and the difference is the format's
    // and not an implementation detail:
    //
    // * **zip has an authoritative index.** The central directory decides
    //   what the archive contains; a `PK\x03\x04` the CD does not reference
    //   is not an entry. A self-extracting stub, an archive comment, junk
    //   appended past the EOCD, or a fuzzer's mutation landing inside a
    //   STORED payload all make the forward walk count local headers the
    //   seekable read is right to ignore — the parked reproducer itself
    //   carries one at offset 521. `forward != seekable` therefore reports a
    //   correct seekable read as a finding, which is the shape that gets a
    //   scheduled job muted. Not hypothetical: a two-entry zip with one
    //   extra local header spliced in ahead of the central directory —
    //   what a tool that "deletes" an entry by rewriting the index alone
    //   leaves behind — lists as two entries under `unzip -l` and under
    //   stuffr alike, at exit 0 with an empty report, and aborted this
    //   target under the wide predicate. The one direction that cannot be explained that
    //   way is a seekable read that reaches NOTHING while a forward walk of
    //   the same bytes reaches something: an authoritative index excluding
    //   every local header in the file is not a reading of a healthy archive,
    //   it is an index that does not describe this file. That is exactly the
    //   568-byte finding (0 vs 4).
    //
    //   **Measured, and stated rather than glossed: that zip arm is
    //   currently unreachable.** `zip.rs`'s
    //   `refuse_an_index_that_reaches_nothing` refuses the same inputs at
    //   `open`, so this line is never reached for them — the parked
    //   reproducer runs clean through this target now, under the WIDE
    //   predicate as well. `forward > 0` needs a local file header at
    //   offset 0 (`ZipStreamed` ends immediately on anything else: a
    //   four-byte stub prepended to that reproducer makes the forward walk
    //   count 0, not 4), and offset 0 is exactly the evidence that guard
    //   fires on. Kept anyway, and NOT vacuous in the tautological sense:
    //   what satisfies it is a DIFFERENT piece of code, so loosening or
    //   removing that guard brings this arm straight back to life. An
    //   oracle whose only witness is the fix it polices is worth keeping;
    //   one that cannot fail whatever the code does is not.
    // * **tar, ar and cpio have no index at all.** Both walks are the same
    //   forward parse of the same bytes; neither reader has a second source
    //   of truth to disagree with. Any divergence there is a real finding,
    //   and narrowing these three to the zero case as well would throw away a
    //   sound observation on three of the four slots to fix a problem only
    //   the fourth has.
    let approximated = seekable
        && forward_entry_count(container.as_ref(), payload).is_some_and(|forward| {
            if name == "zip" {
                enumerated == 0 && forward > 0
            } else {
                forward != enumerated
            }
        });

    check_fidelity_claim(report, approximated).expect("fidelity claim");
});
