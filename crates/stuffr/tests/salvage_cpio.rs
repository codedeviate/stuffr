//! `stuffr::entries::salvage` end to end over a real `newc` cpio archive.
//!
//! Salvage Stage 3 Task 3. The scanner's own tests live beside it in
//! `stuffr-formats`; this file drives the OPS layer — `entries::salvage` →
//! `place_salvaged_file` → `write_salvaged_payload`'s `cpio` arm — because
//! that seam is where ARC's Task 3 defect hid (a real scanner, an unset
//! `EntryMeta::codec`, every entry a silent `SkippedNotBuiltIn`).
//!
//! **It is also the first place `SalvageStatus::Unattested` is observed
//! coming out of the public path**: until this task no registered format
//! produced it, and the tier was pinned only over constructed values.
//!
//! The archives are written by `entries::create_archive` — this project's
//! own writer — so these tests prove the ops layer carries the scanner's
//! findings to disk faithfully, not that the scanner reads cpio correctly;
//! `cpio_salvage.rs`'s reference-writer test is where other implementations
//! are the witness.

use std::path::{Path, PathBuf};

use stuffr::entries::{self, PartialCause, SalvageDisposition, SalvageOpts};
use stuffr::ops::{CompressOpts, Input, Output};
use stuffr_core::FormatId;
use stuffr_core::salvage::{SalvagePolicy, SalvageStatus};

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "stuffr-salvage-cpio-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The three files every test packs, under `tree/`, in walk order.
const FILES: [(&str, &[u8]); 3] = [
    ("a.txt", b"the first file\n"),
    (
        "b.txt",
        b"the second file, which is longer than the first\n",
    ),
    ("c.txt", b"third\n"),
];

/// Packs [`FILES`] as `tree/…` into a cpio through the same writer `stuffr
/// pack` uses, and returns the archive's bytes.
fn packed_cpio(scratch: &Path) -> Vec<u8> {
    let tree = scratch.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    for (name, data) in FILES {
        std::fs::write(tree.join(name), data).unwrap();
    }
    let archive = scratch.join("packed.cpio");
    entries::create_archive(
        &[tree],
        Output::Path(archive.clone()),
        FormatId::new("cpio"),
        None,
        &CompressOpts {
            sync: false,
            ..Default::default()
        },
    )
    .expect("pack the tree");
    std::fs::read(&archive).unwrap()
}

fn opts(dest: Option<PathBuf>, strict: bool) -> SalvageOpts {
    SalvageOpts {
        dest,
        policy: SalvagePolicy {
            strict,
            ..SalvagePolicy::default()
        },
        select: None,
        format: None,
    }
}

/// **`Unattested` is reachable through the public path, and is WRITTEN.**
/// A cpio whose first header (the directory `tree`) has one non-hex digit:
/// `stuffr list` refuses the whole archive, and salvage — format DETECTED
/// from the untouched magic — writes every file behind it byte for byte
/// under its own name, and the run exits 4, never 0: nothing in `newc`
/// attests any of them.
#[test]
fn a_damaged_cpio_is_recovered_unattested_through_the_ops_layer() {
    let scratch = Scratch::new("unattested");
    let mut bytes = packed_cpio(&scratch.0);
    bytes[6] = b'x';
    let archive = scratch.0.join("damaged.cpio");
    std::fs::write(&archive, &bytes).unwrap();

    let refused = entries::list(
        Input::Path(archive.clone()),
        stuffr::DEFAULT_MAX_RATIO,
        None,
    )
    .expect_err("the ordinary reader must refuse an archive whose first header is not hex");
    assert_eq!(refused.exit_code(), 5, "{refused}");

    let dest = scratch.0.join("out");
    let outcome = entries::salvage(&archive, &opts(Some(dest.clone()), false))
        .expect("a damaged cpio must salvage");
    assert_eq!(
        outcome
            .entries
            .iter()
            .map(|r| (r.name.clone(), r.status))
            .collect::<Vec<_>>(),
        FILES
            .iter()
            .map(|(name, _)| (format!("tree/{name}"), SalvageStatus::Unattested))
            .collect::<Vec<_>>(),
        "the damaged directory header is lost and nothing else is; every survivor is \
         Unattested — never Complete, which would claim a header self-check cpio lacks"
    );
    for (record, (name, content)) in outcome.entries.iter().zip(FILES) {
        let SalvageDisposition::Written(path) = &record.disposition else {
            panic!(
                "an Unattested entry must be WRITTEN under its own name, not {:?} — a \
                 SkippedNotBuiltIn here is the ARC Task 3 defect recurring",
                record.disposition
            );
        };
        assert_eq!(path, &dest.join("tree").join(name));
        assert_eq!(std::fs::read(path).unwrap(), content);
    }
    assert!(outcome.sightings.is_empty());
    assert_eq!(entries::salvage_exit_code(&outcome), 4);

    // `--strict` demands proof this format cannot give: every entry is
    // declined, and the run still exits 4 — nothing was refused as corrupt.
    let strict_dest = scratch.0.join("strict");
    let strict = entries::salvage(&archive, &opts(Some(strict_dest.clone()), true)).unwrap();
    assert!(
        strict
            .entries
            .iter()
            .all(|r| r.disposition == SalvageDisposition::SkippedUnattested),
        "{:?}",
        strict.entries
    );
    assert!(!strict_dest.join("tree").join("a.txt").exists());
}

/// A cpio cut short inside its last payload: that entry is `Partial
/// (truncated)`, lands as `NAME.partial` holding exactly the bytes that
/// exist — never padded — and the run exits 4.
#[test]
fn a_truncated_cpio_writes_its_genuine_prefix_as_partial() {
    let scratch = Scratch::new("partial");
    let whole = packed_cpio(&scratch.0);
    let last_payload_at = whole
        .windows(FILES[2].1.len())
        .rposition(|w| w == FILES[2].1)
        .expect("c.txt's payload");
    let keep = 3;
    let archive = scratch.0.join("cut.cpio");
    std::fs::write(&archive, &whole[..last_payload_at + keep]).unwrap();

    let dest = scratch.0.join("out");
    let outcome = entries::salvage(&archive, &opts(Some(dest.clone()), false))
        .expect("a truncated cpio must salvage");
    let last = outcome.entries.last().expect("entries");
    assert_eq!(last.name, "tree/c.txt");
    assert_eq!(last.status, SalvageStatus::Partial);
    assert_eq!(
        last.disposition,
        SalvageDisposition::WrittenPartial {
            path: dest.join("tree").join("c.txt.partial"),
            cause: PartialCause::Truncated,
        }
    );
    assert_eq!(
        std::fs::read(dest.join("tree").join("c.txt.partial")).unwrap(),
        &FILES[2].1[..keep]
    );
    assert_eq!(entries::salvage_exit_code(&outcome), 4);
}
