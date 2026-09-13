#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use stuffr_core::testing::{
    CONTAINER_SLOTS, check_entry_count, check_entry_size, check_error_is_classified,
    check_fidelity_claim,
};
use stuffr_core::{Error, FileSource, FormatId, OpenOpts, ReaderSource, Source, StreamPolicy};

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

    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("input");

    let src: Box<dyn Source> = if seekable {
        std::fs::write(&path, payload).expect("write temp input");
        match FileSource::open(&path) {
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
    // Independent observation 1 for Ruling B: some entry's produced byte
    // count disagreed with its declared size.
    let mut short_entry_seen = false;

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
        enumerated += 1;

        let mut produced = 0u64;
        let mut buf = [0u8; 4096];
        loop {
            match entry.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => produced += n as u64,
                Err(e) => {
                    let e = Error::from(e);
                    check_error_is_classified(&e).expect("entry read error classification");
                    return;
                }
            }
        }
        // `entry` is dropped at the end of this loop body, releasing its
        // borrow on `ar` before the next `ar.next_entry()` call.

        check_entry_size(declared_size, produced, &entry_name).expect("entry size");
        if declared_size.is_some_and(|d| d != produced) {
            short_entry_seen = true;
        }
    }

    // Read the report only now that the walk is complete, not mid-walk.
    let report = ar.fidelity();

    // Ruling A: `declared` is obtained by an independent parse, zip slot on
    // the seekable path only. Every other slot, and zip on the forward-only
    // path, declares no count — `ArchiveRead` exposes none itself — so
    // `declared = None` there and `check_entry_count` returns `Ok`
    // immediately, correctly: only zip has a count to check against.
    let declared: Option<usize> = if seekable && name == "zip" {
        declared_zip_index(&path)
    } else {
        None
    };
    // Independent observation 2 for Ruling B: the index this target itself
    // parsed disagreed with what the walk actually enumerated.
    let count_mismatch_seen = declared.is_some_and(|d| d != enumerated);

    check_entry_count(declared, enumerated, report).expect("entry count");

    // Ruling B: `approximated` must be an independent observation, never
    // `report.has_warnings()` (a tautology — the report is what is being
    // checked) and never a constant `false` (which disables the invariant
    // outright). Both terms above come from facts THIS walk observed.
    let approximated = short_entry_seen || count_mismatch_seen;
    check_fidelity_claim(report, approximated).expect("fidelity claim");
});
