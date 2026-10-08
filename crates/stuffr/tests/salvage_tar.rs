//! `stuffr::entries::salvage` end to end over a real tar archive.
//!
//! Salvage Stage 3 Task 2. The scanner's own unit tests live beside it in
//! `stuffr-formats`; this file drives the OPS layer — `entries::salvage` →
//! `place_salvaged_file` → `write_salvaged_payload`'s `tar` arm — because
//! that seam is where ARC's Task 3 defect hid (a real scanner, an unset
//! `EntryMeta::codec`, every entry a silent `SkippedNotBuiltIn`).
//!
//! **It is also the first place `SalvageStatus::Complete` is observed coming
//! out of the public path.** Until this task no registered format produced
//! it, so the tier was pinned only by unit tests over constructed values.
//!
//! The archives are written by `entries::create_archive` — this project's
//! own writer, on the `tar` crate's `Builder` — so what these tests prove is
//! that the ops layer carries the scanner's findings to disk faithfully,
//! not that the scanner reads tar correctly; `tar_salvage.rs`'s
//! reference-writer test is where other implementations are the witness.

use std::path::{Path, PathBuf};

use stuffr::entries::{self, PartialCause, SalvageDisposition, SalvageOpts};
use stuffr::ops::{CompressOpts, Input, Output};
use stuffr_core::salvage::{SalvagePolicy, SalvageStatus};
use stuffr_core::{EntryKind, EntryMeta, FormatId};

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "stuffr-salvage-tar-{tag}-{}-{}",
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

/// The three files every test packs, under `tree/`, in the order the walk
/// stores them (each level sorted).
const FILES: [(&str, &[u8]); 3] = [
    ("a.txt", b"the first file\n"),
    (
        "b.txt",
        b"the second file, which is longer than the first\n",
    ),
    ("c.txt", b"third\n"),
];

/// Packs [`FILES`] as `tree/…` into a tar at `scratch/archive.tar` through
/// the same writer `stuffr pack` uses, and returns the archive's bytes.
fn packed_tar(scratch: &Path) -> Vec<u8> {
    let tree = scratch.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    for (name, data) in FILES {
        std::fs::write(tree.join(name), data).unwrap();
    }
    let archive = scratch.join("packed.tar");
    entries::create_archive(
        &[tree],
        Output::Path(archive.clone()),
        FormatId::new("tar"),
        None,
        &CompressOpts {
            sync: false,
            ..Default::default()
        },
    )
    .expect("pack the tree");
    std::fs::read(&archive).unwrap()
}

fn opts(dest: Option<PathBuf>, format: Option<&'static str>) -> SalvageOpts {
    SalvageOpts {
        dest,
        policy: SalvagePolicy::default(),
        select: None,
        format: format.map(FormatId::new),
    }
}

/// **`Complete` is reachable through the public path.** A tar whose FIRST
/// header has one flipped byte: `stuffr list` refuses the whole archive,
/// and salvage — with the format DETECTED from the `ustar` magic, not
/// named — recovers everything behind it as `Complete`, writes each file
/// byte for byte under its own name, and exits 0.
#[test]
fn a_damaged_tar_is_recovered_complete_through_the_ops_layer() {
    let scratch = Scratch::new("complete");
    let mut bytes = packed_tar(&scratch.0);
    // The first header is the directory `tree`; its name's first byte.
    bytes[0] ^= 0x01;
    let archive = scratch.0.join("damaged.tar");
    std::fs::write(&archive, &bytes).unwrap();

    let refused = entries::list(
        Input::Path(archive.clone()),
        stuffr::DEFAULT_MAX_RATIO,
        None,
    )
    .expect_err("the ordinary reader must refuse an archive whose first header disagrees");
    assert_eq!(refused.exit_code(), 5, "{refused}");

    let dest = scratch.0.join("out");
    let outcome = entries::salvage(&archive, &opts(Some(dest.clone()), None))
        .expect("a damaged tar must salvage");

    assert_eq!(
        outcome
            .entries
            .iter()
            .map(|r| (r.name.clone(), r.status))
            .collect::<Vec<_>>(),
        FILES
            .iter()
            .map(|(name, _)| (format!("tree/{name}"), SalvageStatus::Complete))
            .collect::<Vec<_>>(),
        "the damaged directory header is lost and nothing else is; every survivor is \
         Complete — never Intact, which would claim a content checksum tar does not have"
    );
    for (record, (name, content)) in outcome.entries.iter().zip(FILES) {
        let SalvageDisposition::Written(path) = &record.disposition else {
            panic!(
                "a Complete entry must be WRITTEN under its own name, not {:?} — a \
                 SkippedNotBuiltIn here is the ARC Task 3 defect recurring",
                record.disposition
            );
        };
        assert_eq!(path, &dest.join("tree").join(name));
        assert_eq!(std::fs::read(path).unwrap(), content);
    }
    assert_eq!(entries::salvage_exit_code(&outcome), 0);
}

/// The one damage tar's own evidence CAN see: an archive cut short inside
/// its last payload. That entry is `Partial (truncated)`, lands as
/// `NAME.partial` holding exactly the bytes that exist — never padded — and
/// the run exits 4.
#[test]
fn a_truncated_tar_writes_its_genuine_prefix_as_partial() {
    let scratch = Scratch::new("partial");
    let whole = packed_tar(&scratch.0);
    // The last payload block sits in front of the two-block end marker.
    let last_payload_at = whole.len() - 3 * 512;
    let keep = 3;
    let archive = scratch.0.join("cut.tar");
    std::fs::write(&archive, &whole[..last_payload_at + keep]).unwrap();

    let dest = scratch.0.join("out");
    let outcome = entries::salvage(&archive, &opts(Some(dest.clone()), Some("tar")))
        .expect("a truncated tar must salvage");

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
    assert!(
        outcome.entries[..outcome.entries.len() - 1]
            .iter()
            .all(|r| r.status == SalvageStatus::Complete),
        "{:?}",
        outcome.entries
    );
    assert_eq!(entries::salvage_exit_code(&outcome), 4);
}

/// One v7-style header with `magic` over bytes 257..265, a correct
/// checksum (`%06o\0 `, GNU tar's spelling), then `data` padded to a block and
/// the two-block end-of-archive marker. Built by hand: nothing in reach
/// writes junk into a v7 header's padding on purpose.
fn one_entry_v7_tar(name: &str, data: &[u8], magic: &[u8; 8]) -> Vec<u8> {
    let mut b = vec![0u8; 512];
    b[..name.len()].copy_from_slice(name.as_bytes());
    b[100..108].copy_from_slice(b"0000644\0");
    b[108..116].copy_from_slice(b"0000000\0");
    b[116..124].copy_from_slice(b"0000000\0");
    b[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
    b[136..148].copy_from_slice(b"14727046122\0");
    b[257..265].copy_from_slice(magic);
    b[148..156].fill(b' ');
    let sum: u32 = b.iter().map(|&x| u32::from(x)).sum();
    b[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    b.extend_from_slice(data);
    b.resize(1024, 0);
    b.extend_from_slice(&[0u8; 1024]);
    b
}

/// Ruling 3-J through the public path. A healthy archive `stuffr list`
/// reads, whose only header carries junk in its magic field, is one the
/// scan cannot tell from a header seen a byte late — so it refuses it, and
/// the run says so at **exit 3** ("this build"), never "nothing recoverable"
/// at exit 5 ("this archive"), which is what it said before.
#[test]
fn a_header_the_scan_cannot_gate_is_exit_3_not_nothing_recoverable() {
    let scratch = Scratch::new("ungateable");
    let archive = scratch.0.join("junkmagic.tar");
    std::fs::write(&archive, one_entry_v7_tar("j.txt", b"junk", b"JUNKJUNK")).unwrap();

    let (listed, _) = entries::list(
        Input::Path(archive.clone()),
        stuffr::DEFAULT_MAX_RATIO,
        None,
    )
    .expect("the ordinary reader reads it");
    assert_eq!(listed.len(), 1);

    let err = entries::salvage(&archive, &opts(None, Some("tar")))
        .expect_err("nothing recoverable is not the truth about this archive");
    assert_eq!(err.exit_code(), 3, "{err}");
    assert!(err.to_string().contains("stuffr list"), "{err}");
}

/// Review Focus 5 (0.10.1): salvage's write path shares `extract`'s ONE
/// placement owner, `place_entry`. An archive that contradicts itself on
/// disk — directory `x` then file `x`, file `a` then `a/b` — gives each
/// later entry salvage's own `SkippedUnwritable` naming the conflict, the
/// rest is written, and the run never ends at exit 1. `SkippedUnwritable`
/// because it is the disposition for "this entry could not be placed on
/// disk" and already folds every other placement failure; a skip here is
/// the same fact with a better reason.
#[test]
fn a_self_contradicting_tar_salvages_with_named_unwritable_skips() {
    let scratch = Scratch::new("conflict");
    let archive = conflict_tar(
        &scratch.0.join("c.tar"),
        &[
            ("x", EntryKind::Dir, b""),
            ("x", EntryKind::File, b"file over dir"),
            ("a", EntryKind::File, b"alpha"),
            ("a/b", EntryKind::File, b"beneath a file"),
            ("ok.txt", EntryKind::File, b"fine"),
        ],
    );
    let dest = scratch.0.join("out");
    let outcome = entries::salvage(&archive, &opts(Some(dest.clone()), Some("tar")))
        .expect("never a run-level error");

    let by_name: Vec<(&str, &SalvageDisposition)> = outcome
        .entries
        .iter()
        .map(|e| (e.name.as_str(), &e.disposition))
        .collect();
    assert_eq!(by_name.len(), 5, "{by_name:?}");
    assert!(
        matches!(by_name[0], ("x", SalvageDisposition::Directory(_))),
        "{by_name:?}"
    );
    assert_eq!(
        by_name[1],
        (
            "x",
            &SalvageDisposition::SkippedUnwritable {
                reason: "a directory `x` from earlier in this archive is in the way".into()
            }
        )
    );
    assert!(
        matches!(by_name[2], ("a", SalvageDisposition::Written(_))),
        "{by_name:?}"
    );
    assert_eq!(
        by_name[3],
        (
            "a/b",
            &SalvageDisposition::SkippedUnwritable {
                reason: "`a`, earlier in this archive, is not a directory, so `a/b` cannot \
                         be placed beneath it"
                    .into()
            }
        )
    );
    assert!(
        matches!(by_name[4], ("ok.txt", SalvageDisposition::Written(_))),
        "{by_name:?}"
    );
    assert!(dest.join("x").is_dir());
    assert_eq!(std::fs::read(dest.join("a")).unwrap(), b"alpha");
    assert_eq!(std::fs::read(dest.join("ok.txt")).unwrap(), b"fine");
}

/// A tar of `entries` (name, kind, payload), through stuffr's own writer.
fn conflict_tar(path: &Path, entries: &[(&str, EntryKind, &[u8])]) -> PathBuf {
    let container = stuffr::registry()
        .require_container(FormatId::new("tar"))
        .unwrap();
    let file = std::fs::File::create(path).unwrap();
    let mut ar = container
        .create(stuffr::PlainSink::new(Box::new(file)), &Default::default())
        .unwrap();
    for (name, kind, data) in entries {
        let mut d = *data;
        let mode = if *kind == EntryKind::Dir {
            0o755
        } else {
            0o644
        };
        ar.add(
            &EntryMeta {
                name: (*name).into(),
                size: Some(data.len() as u64),
                kind: kind.clone(),
                mode: Some(mode),
                ..Default::default()
            },
            &mut d,
        )
        .unwrap();
    }
    ar.finish().unwrap().finish().unwrap();
    path.to_path_buf()
}

/// Fix round 1, Minor 4: what the DESTINATION already held is folded into
/// `SkippedUnwritable` with a reason naming no `--force` (salvage has none).
/// Shape 1: a directory where a file record goes. It is never removed.
#[test]
fn a_destination_directory_at_a_file_records_path_names_no_force() {
    let scratch = Scratch::new("held-dir");
    let archive = conflict_tar(
        &scratch.0.join("c.tar"),
        &[
            ("x", EntryKind::File, b"file"),
            ("ok.txt", EntryKind::File, b"fine"),
        ],
    );
    let dest = scratch.0.join("out");
    std::fs::create_dir_all(dest.join("x")).unwrap();
    let outcome = entries::salvage(&archive, &opts(Some(dest.clone()), Some("tar"))).unwrap();
    assert_eq!(
        outcome.entries[0].disposition,
        SalvageDisposition::SkippedUnwritable {
            reason: "an existing directory is at this path, and salvage never removes a \
                     directory"
                .into()
        }
    );
    assert!(dest.join("x").is_dir());
    assert_eq!(std::fs::read(dest.join("ok.txt")).unwrap(), b"fine");
}

/// Shape 2: a stale file where a directory record goes. Not removed — it
/// could as well be a file this same run recovered.
#[test]
fn a_file_at_a_directory_records_path_names_no_force() {
    let scratch = Scratch::new("held-file");
    let archive = conflict_tar(
        &scratch.0.join("c.tar"),
        &[
            ("x", EntryKind::Dir, b""),
            ("ok.txt", EntryKind::File, b"fine"),
        ],
    );
    let dest = scratch.0.join("out");
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::write(dest.join("x"), b"stale").unwrap();
    let outcome = entries::salvage(&archive, &opts(Some(dest.clone()), Some("tar"))).unwrap();
    assert_eq!(
        outcome.entries[0].disposition,
        SalvageDisposition::SkippedUnwritable {
            reason: "something that is not a directory is already at this path".into()
        }
    );
    assert_eq!(std::fs::read(dest.join("x")).unwrap(), b"stale");
    assert_eq!(std::fs::read(dest.join("ok.txt")).unwrap(), b"fine");
}

/// Fix round 2, M1: a directory record whose final component is too long,
/// under a parent that does not exist yet, reaches the `Dir` arm's own
/// `create_dir_all`; it is skipped with the pinned reason, not a generic
/// i/o error.
#[test]
fn an_over_long_directory_record_is_skipped_with_the_pinned_reason() {
    let scratch = Scratch::new("long-dir");
    let long = format!("n/{}", "L".repeat(300));
    let archive = conflict_tar(
        &scratch.0.join("c.tar"),
        &[
            (long.as_str(), EntryKind::Dir, b""),
            ("ok.txt", EntryKind::File, b"fine"),
        ],
    );
    let dest = scratch.0.join("out");
    let outcome = entries::salvage(&archive, &opts(Some(dest.clone()), Some("tar"))).unwrap();
    assert_eq!(
        outcome.entries[0].disposition,
        SalvageDisposition::SkippedUnwritable {
            reason: "its path is too long for this filesystem".into()
        }
    );
    assert_eq!(std::fs::read(dest.join("ok.txt")).unwrap(), b"fine");
}

/// Whether the volume holding `dir` treats `a` and `b` as one name: `a` is
/// created, and `b` is looked up. Self-detecting rather than assumed, so a
/// case-sensitive APFS volume, or a Linux tmpfs, answers for itself.
fn folds(dir: &Path, a: &str, b: &str) -> bool {
    let probe = dir.join("fold-probe");
    std::fs::create_dir_all(&probe).unwrap();
    std::fs::write(probe.join(a), b"probe").unwrap();
    let folded = std::fs::symlink_metadata(probe.join(b)).is_ok();
    std::fs::remove_dir_all(&probe).unwrap();
    folded
}

fn folds_case(dir: &Path) -> bool {
    folds(dir, "probe", "PROBE")
}

/// `probé` precomposed (U+00E9) against `probé` decomposed (U+0065 U+0301).
fn folds_normalisation(dir: &Path) -> bool {
    folds(dir, "probe\u{e9}", "probee\u{301}")
}

/// 0.10.2 §2: `first` and `second` are one name on this volume. Both
/// records must survive salvage: the first under its own name, the second
/// disambiguated by its scan position, never written over the first.
fn assert_a_folded_pair_both_survive(scratch: &Scratch, first: &str, second: &str) {
    let archive = conflict_tar(
        &scratch.0.join("fold.tar"),
        &[
            (first, EntryKind::File, b"the first spelling's bytes"),
            (
                second,
                EntryKind::File,
                b"the second spelling's bytes, longer",
            ),
        ],
    );
    let dest = scratch.0.join("out");
    let outcome = entries::salvage(&archive, &opts(Some(dest.clone()), Some("tar")))
        .expect("never a run-level error");
    assert_eq!(outcome.entries.len(), 2, "{:?}", outcome.entries);
    let (one, two) = (&outcome.entries[0], &outcome.entries[1]);

    assert_eq!(
        one.disposition,
        SalvageDisposition::Written(dest.join(first))
    );
    let disambiguated = dest.join(format!("{second}.salvaged-{}", two.scan_position));
    assert_eq!(
        two.disposition,
        SalvageDisposition::WrittenDisambiguated {
            path: disambiguated.clone(),
            taken_by: one.scan_position,
            partial: None,
        },
        "the second spelling folds onto the first: it is claimed, by identity"
    );
    assert_eq!(
        std::fs::read(dest.join(first)).unwrap(),
        b"the first spelling's bytes",
        "the first record's bytes must not have been written over"
    );
    assert_eq!(
        std::fs::read(&disambiguated).unwrap(),
        b"the second spelling's bytes, longer"
    );
    assert_eq!(
        std::fs::read_dir(&dest).unwrap().count(),
        2,
        "both records exist on disk"
    );
    assert_eq!(entries::salvage_exit_code(&outcome), 4);
}

/// 0.10.2 §2, the measured defect: on APFS, `README` then `readme` printed
/// "2 written" at exit 0 and left one file. macOS-gated, and returns early
/// on a case-sensitive volume, where the control below runs instead.
#[cfg(target_os = "macos")]
#[test]
fn a_case_pair_both_survive_salvage() {
    let scratch = Scratch::new("case-pair");
    if !folds_case(&scratch.0) {
        eprintln!("skipped: this volume distinguishes case");
        return;
    }
    assert_a_folded_pair_both_survive(&scratch, "README", "readme");
}

/// Review Focus 3: identity, not case-folding, so a normalisation-folding
/// volume is covered by the same check. Self-detecting: APFS folds
/// normalisation, a case-sensitive volume may or may not.
#[cfg(target_os = "macos")]
#[test]
fn unicode_normalisation_pair_both_survive_salvage() {
    let scratch = Scratch::new("nfd-pair");
    if !folds_normalisation(&scratch.0) {
        eprintln!("skipped: this volume distinguishes normalisation forms");
        return;
    }
    assert_a_folded_pair_both_survive(&scratch, "caf\u{e9}", "cafe\u{301}");
}

/// Review Focus 2: the second spelling is ALSO partial. It composes as
/// `readme.salvaged-N.partial`, and `README`'s whole bytes are intact.
#[cfg(target_os = "macos")]
#[test]
fn a_case_pair_with_a_partial_second_survives() {
    let scratch = Scratch::new("case-partial");
    if !folds_case(&scratch.0) {
        eprintln!("skipped: this volume distinguishes case");
        return;
    }
    let second: Vec<u8> = (0..300u32).map(|i| b'a' + (i % 26) as u8).collect();
    let whole = conflict_tar(
        &scratch.0.join("whole.tar"),
        &[
            ("README", EntryKind::File, b"the whole first record"),
            ("readme", EntryKind::File, &second),
        ],
    );
    let bytes = std::fs::read(&whole).unwrap();
    let at = bytes
        .windows(second.len())
        .position(|w| w == second.as_slice())
        .expect("the second payload is in the archive");
    let keep = 100;
    let archive = scratch.0.join("cut.tar");
    std::fs::write(&archive, &bytes[..at + keep]).unwrap();

    let dest = scratch.0.join("out");
    let outcome = entries::salvage(&archive, &opts(Some(dest.clone()), Some("tar")))
        .expect("never a run-level error");
    assert_eq!(outcome.entries.len(), 2, "{:?}", outcome.entries);
    let (one, two) = (&outcome.entries[0], &outcome.entries[1]);
    assert_eq!(
        one.disposition,
        SalvageDisposition::Written(dest.join("README"))
    );
    assert_eq!(two.status, SalvageStatus::Partial);
    let landed = dest.join(format!("readme.salvaged-{}.partial", two.scan_position));
    assert_eq!(
        two.disposition,
        SalvageDisposition::WrittenDisambiguated {
            path: landed.clone(),
            taken_by: one.scan_position,
            partial: Some(PartialCause::Truncated),
        }
    );
    assert_eq!(
        std::fs::read(dest.join("README")).unwrap(),
        b"the whole first record"
    );
    assert_eq!(std::fs::read(&landed).unwrap(), &second[..keep]);
    assert_eq!(std::fs::read_dir(&dest).unwrap().count(), 2);
    assert_eq!(entries::salvage_exit_code(&outcome), 4);
}

/// Review Focus 2, the `.partial` half: a partial `readme` would land on
/// `readme.partial`, which on a folding volume is the file an earlier
/// record, literally named `README.PARTIAL`, was just written to — though
/// no `readme` exists for the real-name check to find. The `.partial`
/// target is claimed by identity too, exactly as an exact-path claim of
/// it is.
#[cfg(target_os = "macos")]
#[test]
fn a_partial_whose_partial_name_folds_onto_a_written_file_survives() {
    let scratch = Scratch::new("case-partial-name");
    if !folds_case(&scratch.0) {
        eprintln!("skipped: this volume distinguishes case");
        return;
    }
    let second: Vec<u8> = (0..300u32).map(|i| b'a' + (i % 26) as u8).collect();
    let whole = conflict_tar(
        &scratch.0.join("whole.tar"),
        &[
            (
                "README.PARTIAL",
                EntryKind::File,
                b"a real entry with that name",
            ),
            ("readme", EntryKind::File, &second),
        ],
    );
    let bytes = std::fs::read(&whole).unwrap();
    let at = bytes
        .windows(second.len())
        .position(|w| w == second.as_slice())
        .expect("the second payload is in the archive");
    let keep = 100;
    let archive = scratch.0.join("cut.tar");
    std::fs::write(&archive, &bytes[..at + keep]).unwrap();

    let dest = scratch.0.join("out");
    let outcome = entries::salvage(&archive, &opts(Some(dest.clone()), Some("tar")))
        .expect("never a run-level error");
    let (one, two) = (&outcome.entries[0], &outcome.entries[1]);
    assert_eq!(
        one.disposition,
        SalvageDisposition::Written(dest.join("README.PARTIAL"))
    );
    let landed = dest.join(format!("readme.salvaged-{}.partial", two.scan_position));
    assert_eq!(
        two.disposition,
        SalvageDisposition::WrittenDisambiguated {
            path: landed.clone(),
            taken_by: one.scan_position,
            partial: Some(PartialCause::Truncated),
        }
    );
    assert_eq!(
        std::fs::read(dest.join("README.PARTIAL")).unwrap(),
        b"a real entry with that name"
    );
    assert_eq!(std::fs::read(&landed).unwrap(), &second[..keep]);
    assert_eq!(entries::salvage_exit_code(&outcome), 4);
}

/// The control: where the volume distinguishes case, `README` and `readme`
/// are two names, so two plain files at exit 0 — identity must not make
/// salvage disambiguate what never collided. Returns early where it folds.
#[test]
fn a_case_pair_is_two_plain_files_on_a_case_sensitive_volume() {
    let scratch = Scratch::new("case-control");
    if folds_case(&scratch.0) {
        eprintln!("skipped: this volume folds case");
        return;
    }
    let archive = conflict_tar(
        &scratch.0.join("pair.tar"),
        &[
            ("README", EntryKind::File, b"upper"),
            ("readme", EntryKind::File, b"lower"),
        ],
    );
    let dest = scratch.0.join("out");
    let outcome = entries::salvage(&archive, &opts(Some(dest.clone()), Some("tar"))).unwrap();
    assert_eq!(
        outcome
            .entries
            .iter()
            .map(|r| r.disposition.clone())
            .collect::<Vec<_>>(),
        vec![
            SalvageDisposition::Written(dest.join("README")),
            SalvageDisposition::Written(dest.join("readme")),
        ]
    );
    assert_eq!(std::fs::read(dest.join("README")).unwrap(), b"upper");
    assert_eq!(std::fs::read(dest.join("readme")).unwrap(), b"lower");
    assert_eq!(entries::salvage_exit_code(&outcome), 0);
}
