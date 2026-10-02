//! `stuffr::entries::salvage` end to end over a real `ar` archive.
//!
//! Salvage Stage 3 Task 4. The scanner's own tests live beside it in
//! `stuffr-formats`; this file drives the OPS layer — `entries::salvage` →
//! `place_salvaged_file` → `write_salvaged_payload`'s `ar` arm — and the
//! facade's carriage of the walk's stop, which is the only place the
//! members past a hole are accounted for at all.
//!
//! The archives are written by `entries::create_archive` — this project's
//! own writer — so these tests prove the ops layer carries the scanner's
//! findings to disk faithfully; `ar_salvage.rs`'s reference-writer test is
//! where other implementations are the witness.
#![cfg(feature = "ar")]

use std::path::{Path, PathBuf};

use stuffr::entries::{self, PartialCause, SalvageDisposition, SalvageOpts};
use stuffr::ops::{CompressOpts, Input, Output};
use stuffr_core::FormatId;
use stuffr_core::salvage::{SalvagePolicy, SalvageStatus, WalkStopKind};

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "stuffr-salvage-ar-{tag}-{}-{}",
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

/// The four files every test packs, under `tree/`, in walk order.
const FILES: [(&str, &[u8]); 4] = [
    ("a.txt", b"the first file\n"),
    ("b.txt", b"the second, odd-length"),
    ("c.txt", b"third\n"),
    ("d.txt", b"the last one\n"),
];

/// Packs [`FILES`] as `tree/…` into an `ar` through the writer `stuffr pack`
/// uses, returning the bytes and each member header's offset (every name is
/// `/`-bearing, so each header opens `#1/`).
fn packed_ar(scratch: &Path) -> (Vec<u8>, Vec<usize>) {
    let tree = scratch.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    for (name, data) in FILES {
        std::fs::write(tree.join(name), data).unwrap();
    }
    let archive = scratch.join("packed.a");
    entries::create_archive(
        &[tree],
        Output::Path(archive.clone()),
        FormatId::new("ar"),
        None,
        &CompressOpts {
            sync: false,
            ..Default::default()
        },
    )
    .expect("pack the tree");
    let bytes = std::fs::read(&archive).unwrap();
    let offsets = bytes
        .windows(3)
        .enumerate()
        .filter(|(i, w)| *w == b"#1/" && *i >= 8)
        .map(|(i, _)| i)
        .collect();
    (bytes, offsets)
}

fn opts(dest: Option<PathBuf>) -> SalvageOpts {
    SalvageOpts {
        dest,
        policy: SalvagePolicy::default(),
        select: None,
        format: None,
    }
}

/// A hole at the THIRD member: the ops layer writes the two before it, byte
/// for byte, writes nothing after it, and carries the walk's stop — the only
/// trace of the two intact members past the hole — through to its caller.
#[test]
fn a_holed_ar_writes_what_precedes_the_hole_and_carries_the_stop() {
    let scratch = Scratch::new("hole");
    let (mut bytes, offsets) = packed_ar(&scratch.0);
    assert_eq!(offsets.len(), FILES.len(), "{offsets:?}");
    let hole = offsets[2];
    bytes[hole + 40..hole + 48].copy_from_slice(b"99999999");
    let archive = scratch.0.join("holed.a");
    std::fs::write(&archive, &bytes).unwrap();

    let refused = entries::list(
        Input::Path(archive.clone()),
        stuffr::DEFAULT_MAX_RATIO,
        None,
    )
    .expect_err("the ordinary reader must refuse a member whose mode is not octal");
    assert_eq!(refused.exit_code(), 5, "{refused}");

    let dest = scratch.0.join("out");
    let outcome = entries::salvage(&archive, &opts(Some(dest.clone()))).expect("salvage");
    assert_eq!(
        outcome
            .entries
            .iter()
            .map(|r| (r.name.clone(), r.status))
            .collect::<Vec<_>>(),
        FILES[..2]
            .iter()
            .map(|(name, _)| (format!("tree/{name}"), SalvageStatus::Unattested))
            .collect::<Vec<_>>()
    );
    for (record, (name, content)) in outcome.entries.iter().zip(FILES) {
        let SalvageDisposition::Written(path) = &record.disposition else {
            panic!(
                "an Unattested member must be WRITTEN, not {:?}",
                record.disposition
            );
        };
        assert_eq!(path, &dest.join("tree").join(name));
        assert_eq!(std::fs::read(path).unwrap(), content);
    }
    assert!(!dest.join("tree").join("c.txt").exists());
    assert!(!dest.join("tree").join("d.txt").exists());
    let stop = outcome
        .walk_stop
        .as_ref()
        .expect("the stop reaches the caller");
    assert_eq!(
        (stop.offset, stop.kind),
        (hole as u64, WalkStopKind::Unreadable)
    );
    assert!(stop.cause.contains("file mode"), "{}", stop.cause);
    assert_eq!(entries::salvage_exit_code(&outcome), 4);
}

/// Cut inside the last payload: that member lands as `NAME.partial` with
/// exactly the bytes that exist, never padded; no stop, and exit 4.
#[test]
fn a_truncated_ar_writes_its_genuine_prefix_as_partial() {
    let scratch = Scratch::new("partial");
    let (whole, _) = packed_ar(&scratch.0);
    let last_payload_at = whole
        .windows(FILES[3].1.len())
        .rposition(|w| w == FILES[3].1)
        .expect("d.txt's payload");
    let keep = 4;
    let archive = scratch.0.join("cut.a");
    std::fs::write(&archive, &whole[..last_payload_at + keep]).unwrap();

    let dest = scratch.0.join("out");
    let outcome = entries::salvage(&archive, &opts(Some(dest.clone()))).expect("salvage");
    assert_eq!(outcome.entries.len(), FILES.len());
    let last = outcome.entries.last().unwrap();
    assert_eq!(last.name, "tree/d.txt");
    assert_eq!(last.status, SalvageStatus::Partial);
    assert_eq!(
        last.disposition,
        SalvageDisposition::WrittenPartial {
            path: dest.join("tree").join("d.txt.partial"),
            cause: PartialCause::Truncated,
        }
    );
    assert_eq!(
        std::fs::read(dest.join("tree").join("d.txt.partial")).unwrap(),
        &FILES[3].1[..keep]
    );
    assert!(outcome.walk_stop.is_none());
    assert_eq!(entries::salvage_exit_code(&outcome), 4);
}
