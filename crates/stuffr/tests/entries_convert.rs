//! `entries::convert_archive`: an archive read from one container and written
//! into another, under the write-side rules `pack` already uses.
//!
//! What is asserted here, at the library level where the payloads and the
//! fidelity report can be compared exactly:
//!
//! * every payload survives the conversion byte for byte, in both directions;
//! * what the target cannot hold is a warning with `pack`'s own wording, and a
//!   special file (fifo, device) is skipped — never written as an empty
//!   regular file;
//! * a warning the SOURCE reader raised reaches the conversion's report;
//! * a declared size the payload does not deliver is `Corrupt` (exit 5) and a
//!   ratio bomb is a resource limit (exit 6), with nothing left at the
//!   destination either way;
//! * names are copied verbatim — `convert` extracts nothing — and duplicate
//!   names are kept, in source order.
//!
//! The unknown-size (spill) path is tested in `entries.rs`'s own unit tests:
//! no reader in this build yields an entry without a declared size (a zip
//! with data descriptors is refused on a pipe at exit 3 before any entry is
//! read), so only a hand-rolled reader can reach it.
#![cfg(all(feature = "tar", feature = "zip"))]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use stuffr::entries::{self, ConvertOpts, Selection};
use stuffr::ops::{CompressOpts, Input, Output};
use stuffr::{DEFAULT_MAX_RATIO, EntryKind, Fidelity, FormatId};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

fn tmp_dir() -> PathBuf {
    let n = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("stuffr-convert-{}-{}", std::process::id(), n));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn fmt(id: &'static str) -> FormatId {
    FormatId::new(id)
}

/// Every entry of `archive`, in archive order, with its payload read back
/// through the public read verbs (`list` for the names, `cat --index` for the
/// bytes) — so a duplicate name is still read as its own entry.
fn entries_of(archive: &Path) -> Vec<(String, EntryKind, Vec<u8>)> {
    let (metas, _) =
        entries::list(Input::Path(archive.to_path_buf()), DEFAULT_MAX_RATIO, None).unwrap();
    metas
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let mut payload = Vec::new();
            entries::cat(
                Input::Path(archive.to_path_buf()),
                &Selection::Indices(vec![i]),
                DEFAULT_MAX_RATIO,
                None,
                &mut payload,
            )
            .unwrap();
            (m.name.clone(), m.kind.clone(), payload)
        })
        .collect()
}

/// `(name, payload)` for the regular files of `archive`, in archive order.
fn files_of(archive: &Path) -> Vec<(String, Vec<u8>)> {
    entries_of(archive)
        .into_iter()
        .filter(|(_, kind, _)| *kind == EntryKind::File)
        .map(|(name, _, payload)| (name, payload))
        .collect()
}

/// A tree of three files, one of them 300 KiB of non-repeating bytes, so a
/// payload that is truncated, padded or shuffled cannot compare equal.
fn three_file_tree(root: &Path) -> (PathBuf, Vec<(String, Vec<u8>)>) {
    let proj = root.join("proj");
    std::fs::create_dir_all(proj.join("sub")).unwrap();
    let big: Vec<u8> = (0..300 * 1024u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let files = vec![
        ("proj/a.txt".to_string(), b"alpha\n".to_vec()),
        ("proj/big.bin".to_string(), big),
        (
            "proj/sub/c.txt".to_string(),
            b"gamma, one level down\n".to_vec(),
        ),
    ];
    for (name, bytes) in &files {
        std::fs::write(root.join(name), bytes).unwrap();
    }
    (proj, files)
}

fn pack(paths: &[PathBuf], out: &Path, container: &'static str, codec: Option<&'static str>) {
    entries::create_archive(
        paths,
        Output::Path(out.to_path_buf()),
        fmt(container),
        codec.map(fmt),
        &CompressOpts::default(),
    )
    .unwrap();
}

/// One 512-byte ustar header, hand-built so a test can hold what stuffr's own
/// writer never emits: a fifo, a device, a name with `..` in it, a repeated
/// name. uid/gid are set, so the source is never short of ownership.
fn tar_header(name: &str, size: u64, typeflag: u8) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[100..108].copy_from_slice(b"0000644\0");
    h[108..116].copy_from_slice(b"0001750\0");
    h[116..124].copy_from_slice(b"0001750\0");
    h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    h[136..148].copy_from_slice(b"14000000000\0");
    h[148..156].copy_from_slice(b"        ");
    h[156] = typeflag;
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[329..337].copy_from_slice(b"0000000\0");
    h[337..345].copy_from_slice(b"0000000\0");
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

/// A tar of `(name, typeflag, payload)` members, hand-built.
fn hand_built_tar(members: &[(&str, u8, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, typeflag, payload) in members {
        out.extend_from_slice(&tar_header(name, payload.len() as u64, *typeflag));
        out.extend_from_slice(payload);
        let pad = (512 - payload.len() % 512) % 512;
        out.extend(std::iter::repeat_n(0u8, pad));
    }
    out.extend(std::iter::repeat_n(0u8, 1024));
    out
}

#[test]
fn tar_to_zip_keeps_every_payload() {
    let dir = tmp_dir();
    let (proj, want) = three_file_tree(&dir);
    let tar = dir.join("src.tar");
    pack(&[proj], &tar, "tar", None);

    let zip = dir.join("out.zip");
    let outcome = entries::convert_archive(
        Input::Path(tar),
        Output::Path(zip.clone()),
        fmt("zip"),
        None,
        &ConvertOpts::default(),
    )
    .unwrap();

    assert_eq!(outcome.format, fmt("zip"));
    assert_eq!(
        files_of(&zip),
        want,
        "every payload, byte for byte, in order"
    );
    assert!(
        outcome.fidelity.warnings.is_empty(),
        "zip holds directories, and the tar carried ownership: nothing to lose, got {:?}",
        outcome.fidelity.warnings
    );
}

#[cfg(any(feature = "xz-pure", feature = "xz-c"))]
#[test]
fn zip_to_tar_xz_keeps_every_payload() {
    let dir = tmp_dir();
    let (proj, want) = three_file_tree(&dir);
    let zip = dir.join("src.zip");
    pack(&[proj], &zip, "zip", None);

    let out = dir.join("out.tar.xz");
    let outcome = entries::convert_archive(
        Input::Path(zip),
        Output::Path(out.clone()),
        fmt("tar"),
        Some(fmt("xz")),
        &ConvertOpts::default(),
    )
    .unwrap();

    assert_eq!(outcome.format, fmt("tar"));
    assert_eq!(
        &std::fs::read(&out).unwrap()[..6],
        b"\xfd7zXZ\0",
        "an xz stream"
    );
    assert_eq!(files_of(&out), want);
}

#[cfg(all(unix, feature = "ar"))]
#[test]
fn a_symlink_into_a_container_without_symlinks_is_a_warning() {
    let dir = tmp_dir();
    let proj = dir.join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(proj.join("a.txt"), b"alpha").unwrap();
    std::os::unix::fs::symlink("a.txt", proj.join("link")).unwrap();
    let tar = dir.join("src.tar");
    pack(&[proj], &tar, "tar", None);

    let ar = dir.join("out.ar");
    let outcome = entries::convert_archive(
        Input::Path(tar),
        Output::Path(ar.clone()),
        fmt("ar"),
        None,
        &ConvertOpts::default(),
    )
    .unwrap();

    // `pack`'s own sentence, from the one helper both verbs plan through.
    let skipped = Fidelity::EntrySkipped {
        entry: "proj/link".into(),
        reason: "`ar` has no symlink entries; storing it as a regular file would \
                 materialise the link's target text as that file's contents"
            .into(),
    };
    assert!(
        outcome.fidelity.warnings.contains(&skipped),
        "{:?}",
        outcome.fidelity.warnings
    );
    let names: Vec<String> = entries_of(&ar).into_iter().map(|(n, _, _)| n).collect();
    assert_eq!(
        names,
        ["proj/a.txt"],
        "the link is not written in any shape"
    );
}

/// Review Focus 4. The brief named an encrypted zip entry, but no reader in
/// this build raises `EncryptedEntrySkipped` — an encrypted zip entry is a
/// hard `Unsupported` (exit 3). The read-side warning zip DOES raise is
/// `EntryCountMismatch`: two central-directory records under one name, which
/// the `zip` crate collapses. Built here by renaming `b.txt` to `a.txt` in
/// place (same length, so every offset still holds).
#[test]
fn a_read_side_warning_reaches_the_convert_report() {
    let dir = tmp_dir();
    std::fs::write(dir.join("a.txt"), b"first payload").unwrap();
    std::fs::write(dir.join("b.txt"), b"second payload").unwrap();
    let clean = dir.join("clean.zip");
    pack(&[dir.join("a.txt"), dir.join("b.txt")], &clean, "zip", None);
    let mut bytes = std::fs::read(&clean).unwrap();
    let mut renamed = 0;
    for i in 0..bytes.len() - 5 {
        if &bytes[i..i + 5] == b"b.txt" {
            bytes[i..i + 5].copy_from_slice(b"a.txt");
            renamed += 1;
        }
    }
    assert_eq!(
        renamed, 2,
        "the local header and the central directory record"
    );
    let shadowed = dir.join("shadowed.zip");
    std::fs::write(&shadowed, bytes).unwrap();

    let outcome = entries::convert_archive(
        Input::Path(shadowed),
        Output::Path(dir.join("out.tar")),
        fmt("tar"),
        None,
        &ConvertOpts::default(),
    )
    .unwrap();

    assert!(
        outcome
            .fidelity
            .warnings
            .iter()
            .any(|w| matches!(w, Fidelity::EntryCountMismatch { .. })),
        "the source reader's warning must reach the convert's own report: {:?}",
        outcome.fidelity.warnings
    );
    assert!(!outcome.fidelity.is_lossless());
}

#[test]
fn a_special_file_is_skipped_never_written_as_a_regular_file() {
    let dir = tmp_dir();
    let tar = dir.join("src.tar");
    std::fs::write(
        &tar,
        hand_built_tar(&[
            ("pipe", b'6', b""),
            ("dev/console", b'3', b""),
            ("keep.txt", b'0', b"kept"),
        ]),
    )
    .unwrap();

    let zip = dir.join("out.zip");
    let outcome = entries::convert_archive(
        Input::Path(tar),
        Output::Path(zip.clone()),
        fmt("zip"),
        None,
        &ConvertOpts::default(),
    )
    .unwrap();

    for name in ["pipe", "dev/console"] {
        let skipped = Fidelity::EntrySkipped {
            entry: name.into(),
            reason: "is a special file (device, fifo or socket); stuffr does not store those"
                .into(),
        };
        assert!(
            outcome.fidelity.warnings.contains(&skipped),
            "{name}: {:?}",
            outcome.fidelity.warnings
        );
    }
    assert_eq!(
        entries_of(&zip),
        [("keep.txt".to_string(), EntryKind::File, b"kept".to_vec())],
        "neither special file reaches the zip, not even as an empty regular file"
    );
}

#[test]
fn a_short_entry_is_corrupt_and_publishes_nothing() {
    let dir = tmp_dir();
    let payload: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
    let mut tar = hand_built_tar(&[("whole.txt", b'0', &payload)]);
    // Cut 200 bytes into the first member's payload.
    tar.truncate(512 + 200);
    let src = dir.join("cut.tar");
    std::fs::write(&src, tar).unwrap();

    let out = dir.join("out.zip");
    let err = entries::convert_archive(
        Input::Path(src),
        Output::Path(out.clone()),
        fmt("zip"),
        None,
        &ConvertOpts::default(),
    )
    .unwrap_err();

    assert_eq!(err.exit_code(), 5, "{err}");
    assert!(!out.exists(), "nothing is published on a corrupt source");
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        1,
        "no temp file is left beside the destination either"
    );
}

#[cfg(feature = "gzip")]
#[test]
fn a_ratio_bomb_is_exit_6() {
    let dir = tmp_dir();
    let zeros = dir.join("zeros.bin");
    std::fs::write(&zeros, vec![0u8; 4 * 1024 * 1024]).unwrap();
    let bomb = dir.join("bomb.tar.gz");
    pack(&[zeros], &bomb, "tar", Some("gzip"));

    let out = dir.join("out.zip");
    let err = entries::convert_archive(
        Input::Path(bomb),
        Output::Path(out.clone()),
        fmt("zip"),
        None,
        &ConvertOpts {
            max_ratio: 10,
            ..ConvertOpts::default()
        },
    )
    .unwrap_err();

    assert_eq!(err.exit_code(), 6, "{err}");
    assert!(!out.exists());
}

#[test]
fn names_are_copied_verbatim_including_unsafe_ones() {
    let dir = tmp_dir();
    let tar = dir.join("src.tar");
    std::fs::write(
        &tar,
        hand_built_tar(&[("../escape.txt", b'0', b"out"), ("dir/../x", b'0', b"back")]),
    )
    .unwrap();

    let zip = dir.join("out.zip");
    entries::convert_archive(
        Input::Path(tar),
        Output::Path(zip.clone()),
        fmt("zip"),
        None,
        &ConvertOpts::default(),
    )
    .unwrap();

    assert_eq!(
        files_of(&zip),
        [
            ("../escape.txt".to_string(), b"out".to_vec()),
            ("dir/../x".to_string(), b"back".to_vec()),
        ],
        "convert extracts nothing, so containment does not apply: names stay as they were"
    );
    assert!(!dir.parent().unwrap().join("escape.txt").exists());
}

#[cfg(feature = "cpio")]
#[test]
fn duplicate_names_are_kept_in_order() {
    let dir = tmp_dir();
    let tar = dir.join("src.tar");
    std::fs::write(
        &tar,
        hand_built_tar(&[("a.txt", b'0', b"first"), ("a.txt", b'0', b"second")]),
    )
    .unwrap();

    let out = dir.join("out.cpio");
    entries::convert_archive(
        Input::Path(tar),
        Output::Path(out.clone()),
        fmt("cpio"),
        None,
        &ConvertOpts::default(),
    )
    .unwrap();

    assert_eq!(
        files_of(&out),
        [
            ("a.txt".to_string(), b"first".to_vec()),
            ("a.txt".to_string(), b"second".to_vec()),
        ]
    );
}

/// Duplicates are kept wherever the target can hold them; the `zip` writer
/// cannot (`zip` 8.6.0 refuses `Duplicate filename`), and `convert` adds no
/// policy of its own — the writer's verdict stands, nothing is published.
#[test]
fn a_duplicate_name_into_zip_is_the_zip_writers_refusal() {
    let dir = tmp_dir();
    let tar = dir.join("src.tar");
    std::fs::write(
        &tar,
        hand_built_tar(&[("a.txt", b'0', b"first"), ("a.txt", b'0', b"second")]),
    )
    .unwrap();

    let out = dir.join("out.zip");
    let err = entries::convert_archive(
        Input::Path(tar),
        Output::Path(out.clone()),
        fmt("zip"),
        None,
        &ConvertOpts::default(),
    )
    .unwrap_err();

    assert_eq!(err.exit_code(), 5, "{err}");
    assert!(err.to_string().contains("a.txt"), "{err}");
    assert!(!out.exists());
}

/// The CLI opens its source once (stdin cannot be read twice) and picks the
/// mode from the chain; this is the entry point it then hands that source to.
#[test]
fn a_source_opened_first_converts_the_same() {
    let dir = tmp_dir();
    let (proj, want) = three_file_tree(&dir);
    let tar = dir.join("src.tar");
    pack(&[proj], &tar, "tar", None);

    let source = stuffr::ops::ConvertSource::open(Input::Path(tar), None).unwrap();
    assert_eq!(source.chain().container(), Some(fmt("tar")));
    let zip = dir.join("out.zip");
    entries::convert_archive_source(
        source,
        Output::Path(zip.clone()),
        fmt("zip"),
        None,
        &ConvertOpts::default(),
    )
    .unwrap();

    assert_eq!(files_of(&zip), want);
}

#[test]
fn a_plain_stream_is_not_an_archive() {
    let dir = tmp_dir();
    let src = dir.join("notes.txt");
    std::fs::write(&src, b"just text").unwrap();
    let out = dir.join("out.zip");

    let err = entries::convert_archive(
        Input::Path(src),
        Output::Path(out.clone()),
        fmt("zip"),
        None,
        &ConvertOpts::default(),
    )
    .unwrap_err();

    assert_ne!(err.exit_code(), 1, "{err}");
    assert!(!out.exists());
}
