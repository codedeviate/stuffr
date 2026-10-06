//! `entries::convert_archive`: an archive read from one container and written
//! into another, under the write-side rules `pack` already uses.
//!
//! What is asserted here, at the library level where the payloads and the
//! fidelity report can be compared exactly:
//!
//! * every payload survives the conversion byte for byte, in both directions;
//! * what the target cannot hold is a warning with `pack`'s own wording, and a
//!   special entry (fifo, device) is skipped — never written as an empty
//!   regular file; a hard link is a full copy of its target, or skipped;
//! * a warning the SOURCE reader raised reaches the conversion's report;
//! * a declared size the payload does not deliver is `Corrupt` (exit 5) and a
//!   ratio bomb is a resource limit (exit 6), with nothing left at the
//!   destination either way;
//! * names are copied verbatim — `convert` extracts nothing — and duplicate
//!   names are kept, in source order.
//!
//! A zip arriving on a pipe is spooled whole (its index is at the end), so a
//! zip streamed with data descriptors converts entry by entry; the pipe
//! tests here re-run this binary with a real pipe on stdin. The per-entry
//! unknown-size path is tested in `entries.rs`'s own unit tests: no reader in
//! this build yields an entry without a declared size, so only a hand-rolled
//! reader can reach it.
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
            // A link has no payload of its own, and `cat` of a link alone
            // needs its target selected too: its kind is what is compared.
            if matches!(m.kind, EntryKind::Hardlink { .. }) {
                return (m.name.clone(), m.kind.clone(), payload);
            }
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

/// A tar of one regular file `target` and one typeflag-`1` entry `name`
/// linking to it, hand-built (the link name is the field at 157..257).
fn hand_built_link_tar(name: &str, target: &str) -> Vec<u8> {
    let mut out = hand_built_tar(&[(target, b'0', b"hello")]);
    out.truncate(out.len() - 1024);
    let mut h = tar_header(name, 0, b'1');
    h[157..157 + target.len()].copy_from_slice(target.as_bytes());
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    out.extend_from_slice(&h);
    out.extend(std::iter::repeat_n(0u8, 1024));
    out
}

#[test]
fn tar_to_tar_keeps_hard_links_as_links() {
    let dir = tmp_dir();
    let src = dir.join("src.tar");
    std::fs::write(&src, hand_built_link_tar("a", "b")).unwrap();

    let out = dir.join("out.tar");
    let outcome = entries::convert_archive(
        Input::Path(src),
        Output::Path(out.clone()),
        fmt("tar"),
        None,
        &ConvertOpts::default(),
    )
    .unwrap();

    assert!(
        outcome.fidelity.warnings.is_empty(),
        "a link into tar loses nothing: {:?}",
        outcome.fidelity.warnings
    );
    assert_eq!(
        entries_of(&out),
        [
            ("b".to_string(), EntryKind::File, b"hello".to_vec()),
            (
                "a".to_string(),
                EntryKind::Hardlink { target: "b".into() },
                Vec::new()
            ),
        ],
        "the link survives as a link, never a 0-byte regular file"
    );
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
    // A hard link needs a target, or the reader refuses the archive as
    // corrupt: append a real one after the three specials.
    let mut bytes = std::fs::read(&tar).unwrap();
    bytes.truncate(bytes.len() - 1024);
    let mut link = hand_built_link_tar("hard", "keep.txt");
    bytes.extend_from_slice(&link.split_off(512 * 2)[..512]);
    bytes.extend(std::iter::repeat_n(0u8, 1024));
    std::fs::write(&tar, bytes).unwrap();

    let zip = dir.join("out.zip");
    let outcome = entries::convert_archive(
        Input::Path(tar),
        Output::Path(zip.clone()),
        fmt("zip"),
        None,
        &ConvertOpts::default(),
    )
    .unwrap();

    // `unpack`'s wording, "stored" for "created". The hard link is no
    // special: zip cannot store one, so it is written as a full copy.
    for (name, reason) in [
        ("pipe", "device nodes, fifos and sockets are not stored"),
        (
            "dev/console",
            "device nodes, fifos and sockets are not stored",
        ),
    ] {
        let skipped = Fidelity::EntrySkipped {
            entry: name.into(),
            reason: reason.into(),
        };
        assert!(
            outcome.fidelity.warnings.contains(&skipped),
            "{name}: {:?}",
            outcome.fidelity.warnings
        );
    }
    assert_eq!(outcome.fidelity.warnings.len(), 2);
    assert_eq!(
        entries_of(&zip),
        [
            ("keep.txt".to_string(), EntryKind::File, b"kept".to_vec()),
            ("hard".to_string(), EntryKind::File, b"kept".to_vec()),
        ],
        "no special entry reaches the zip, not even as an empty regular file"
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

/// Duplicates are kept wherever the target can hold them. `zip` cannot — its
/// writer refuses a second entry under a name already written
/// (`ContainerCaps::unique_names`) — so the FIRST entry of each name is kept
/// and every later one is skipped with a warning, instead of the whole
/// conversion failing on the writer's refusal.
#[test]
fn a_duplicate_name_into_zip_keeps_the_first_entry_and_warns() {
    let dir = tmp_dir();
    let tar = dir.join("src.tar");
    std::fs::write(
        &tar,
        hand_built_tar(&[
            ("a.txt", b'0', b"first"),
            ("a.txt", b'0', b"second"),
            ("b.txt", b'0', b"other"),
        ]),
    )
    .unwrap();

    let out = dir.join("out.zip");
    let outcome = entries::convert_archive(
        Input::Path(tar),
        Output::Path(out.clone()),
        fmt("zip"),
        None,
        &ConvertOpts::default(),
    )
    .unwrap();

    let skipped = Fidelity::EntrySkipped {
        entry: "a.txt".into(),
        reason: "an entry with this name was already written; `zip` holds one entry per name"
            .into(),
    };
    assert_eq!(outcome.fidelity.warnings, [skipped]);
    assert_eq!(
        files_of(&out),
        [
            ("a.txt".to_string(), b"first".to_vec()),
            ("b.txt".to_string(), b"other".to_vec()),
        ],
        "exactly one `a.txt`, carrying the first payload"
    );
}

/// A zip written the way a tool streaming to a pipe writes one: every entry's
/// local header carries zero sizes, the real ones following the data in a
/// data descriptor. A forward zip read cannot deliver such an entry at all.
fn data_descriptor_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write;
    let mut buf = Vec::new();
    {
        let mut w = zip::ZipWriter::new_stream(&mut buf);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, data) in entries {
            w.start_file(*name, opts).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap();
    }
    buf
}

/// The payloads of the descriptor zip the pipe tests send.
fn piped_zip_entries() -> Vec<(String, Vec<u8>)> {
    let big: Vec<u8> = (0..300 * 1024u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8)
        .collect();
    vec![
        ("a.txt".to_string(), b"alpha".to_vec()),
        ("big.bin".to_string(), big),
        ("c.txt".to_string(), b"gamma".to_vec()),
    ]
}

const PIPE_CHILD: &str = "STUFFR_TEST_CONVERT_PIPE_CHILD";

/// `Input::Stdin` is the library's only non-seekable source, and a test
/// process's own stdin is whatever the runner inherited, so the test re-runs
/// itself (`--exact NAME`) with the descriptor zip on a real pipe and the
/// destination in `PIPE_CHILD`; the child converts and asserts, the parent
/// asserts on what it left behind.
fn run_child_on_a_pipe(test: &str, dst: &Path) {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let entries = piped_zip_entries();
    let refs: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();
    let bytes = data_descriptor_zip(&refs);

    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--test-threads=1"])
        .env(PIPE_CHILD, dst)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    // A refusing child may stop reading early; a broken pipe is its answer,
    // not a failure of this write.
    let _ = stdin.write_all(&bytes);
    drop(stdin);
    let res = child.wait_with_output().unwrap();
    assert!(
        res.status.success(),
        "child failed:\n{}\n{}",
        String::from_utf8_lossy(&res.stdout),
        String::from_utf8_lossy(&res.stderr)
    );
}

/// The child half: convert stdin into `dst` under `spill`.
fn convert_stdin(dst: &str, spill: stuffr::SpillPolicy) -> stuffr::Result<stuffr::ops::Outcome> {
    entries::convert_archive(
        Input::Stdin,
        Output::Path(dst.into()),
        fmt("tar"),
        None,
        &ConvertOpts {
            spill,
            ..ConvertOpts::default()
        },
    )
}

/// Review Focus 3, at the library level: a descriptor zip on a pipe is spooled
/// (the `Spilled` rung, read through the central directory) rather than read
/// forward, and every entry comes out whole.
#[test]
fn a_descriptor_zip_on_a_pipe_converts_whole() {
    const NAME: &str = "a_descriptor_zip_on_a_pipe_converts_whole";
    if let Ok(dst) = std::env::var(PIPE_CHILD) {
        let outcome = convert_stdin(&dst, stuffr::SpillPolicy::default()).unwrap();
        assert_eq!(outcome.fidelity.rung, stuffr::Rung::Spilled);
        return;
    }
    let dir = tmp_dir();
    let dst = dir.join("out.tar");
    run_child_on_a_pipe(NAME, &dst);
    assert_eq!(
        files_of(&dst),
        piped_zip_entries(),
        "every payload, byte for byte"
    );
}

#[test]
fn a_descriptor_zip_on_a_pipe_with_spill_off_is_exit_6() {
    const NAME: &str = "a_descriptor_zip_on_a_pipe_with_spill_off_is_exit_6";
    if let Ok(dst) = std::env::var(PIPE_CHILD) {
        let err = convert_stdin(&dst, stuffr::SpillPolicy::Off).unwrap_err();
        assert_eq!(err.exit_code(), 6, "{err}");
        assert!(
            matches!(err, stuffr::Error::SpillLimitExceeded { .. }),
            "{err:?}"
        );
        return;
    }
    let dir = tmp_dir();
    let dst = dir.join("out.tar");
    run_child_on_a_pipe(NAME, &dst);
    assert!(!dst.exists(), "nothing is published");
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "no temp file either"
    );
}

#[test]
fn a_descriptor_zip_past_the_spill_cap_is_exit_6() {
    const NAME: &str = "a_descriptor_zip_past_the_spill_cap_is_exit_6";
    if let Ok(dst) = std::env::var(PIPE_CHILD) {
        let err = convert_stdin(&dst, stuffr::SpillPolicy::Memory { cap: 64 * 1024 }).unwrap_err();
        assert!(
            matches!(err, stuffr::Error::SpillLimitExceeded { limit } if limit == 64 * 1024),
            "{err:?}"
        );
        assert_eq!(err.exit_code(), 6);
        return;
    }
    let dir = tmp_dir();
    let dst = dir.join("out.tar");
    run_child_on_a_pipe(NAME, &dst);
    assert!(!dst.exists(), "nothing is published");
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "no temp file either"
    );
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

/// An ar archive in the BSD extended form (`#1/N`, the name right after the
/// header), which carries any byte in a member name — a NUL included.
#[cfg(feature = "ar")]
fn bsd_ar(members: &[(&[u8], &[u8])]) -> Vec<u8> {
    // Every name here is of EVEN length: the `ar` crate pads a `#1/N`
    // member by its PAYLOAD's parity, so an odd-length name with an odd total
    // would be framed differently than written.
    let mut out = b"!<arch>\n".to_vec();
    for (name, data) in members {
        let field = |s: String, w: usize| format!("{s:<w$}").into_bytes();
        out.extend(field(format!("#1/{}", name.len()), 16));
        out.extend(field("0".into(), 12));
        out.extend(field("0".into(), 6));
        out.extend(field("0".into(), 6));
        out.extend(field("100644".into(), 8));
        out.extend(field((name.len() + data.len()).to_string(), 10));
        out.extend(b"`\n");
        out.extend(*name);
        out.extend(*data);
        if out.len() % 2 == 1 {
            out.push(b'\n');
        }
    }
    out
}

/// Task 6's fuzz finding: tar ends a name at its first NUL, so an ar member
/// named `a\0bc.txt` used to land in the tar as `a`, reported as no loss at all.
/// The target cannot hold the name, so the entry is skipped with ONE warning
/// naming it, and every other entry arrives intact.
#[cfg(feature = "ar")]
#[test]
fn a_name_with_a_nul_is_skipped_into_tar_and_named() {
    let dir = tmp_dir();
    let src = dir.join("in.a");
    std::fs::write(
        &src,
        bsd_ar(&[
            (b"one1.txt", b"first\n"),
            (b"a\0bc.txt", b"nul\n"),
            (b"two2.txt", b"second\n"),
        ]),
    )
    .unwrap();
    let dst = dir.join("out.tar");
    let outcome = entries::convert_archive(
        Input::Path(src),
        Output::Path(dst.clone()),
        fmt("tar"),
        None,
        &ConvertOpts::default(),
    )
    .expect("one entry the target cannot hold is a warning, not a failure");
    let skipped: Vec<_> = outcome
        .fidelity
        .warnings
        .iter()
        .filter_map(|w| match w {
            Fidelity::EntrySkipped { entry, reason } => Some((entry.as_str(), reason.as_str())),
            _ => None,
        })
        .collect();
    assert_eq!(skipped.len(), 1, "{:?}", outcome.fidelity.warnings);
    assert_eq!(skipped[0].0, "a\0bc.txt");
    assert!(skipped[0].1.contains("NUL"), "{}", skipped[0].1);
    assert_eq!(
        files_of(&dst),
        vec![
            ("one1.txt".to_string(), b"first\n".to_vec()),
            ("two2.txt".to_string(), b"second\n".to_vec()),
        ]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A cpio archive, written by stuffr's own cpio writer, holding a regular
/// file and a symlink whose TARGET contains a NUL — which newc stores as the
/// entry's body, by length, so it round-trips. Every entry carries ownership,
/// mode and mtime, so a conversion owes no metadata warning for it.
#[cfg(feature = "cpio")]
fn cpio_with_a_nul_link_target(path: &Path) {
    use stuffr::{CreateOpts, EntryMeta, PlainSink};
    let full = |name: &str, kind: EntryKind, size: u64| EntryMeta {
        size: Some(size),
        mode: Some(0o644),
        uid: Some(1),
        gid: Some(1),
        mtime: Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000)),
        kind,
        ..EntryMeta::file(name)
    };
    let writer = stuffr::registry()
        .require_container_writer(fmt("cpio"))
        .unwrap();
    let file = std::fs::File::create(path).unwrap();
    let mut w = writer
        .create(PlainSink::new(Box::new(file)), &CreateOpts::default())
        .unwrap();
    w.add(&full("keep.txt", EntryKind::File, 5), &mut &b"kept\n"[..])
        .unwrap();
    let target = "t\0x";
    w.add(
        &full(
            "link",
            EntryKind::Symlink {
                target: target.into(),
            },
            target.len() as u64,
        ),
        &mut std::io::empty(),
    )
    .unwrap();
    w.finish().unwrap().finish().unwrap();
}

/// Fix round 2 (F2): tar stores a link target NUL-terminated, so a symlink
/// whose target holds a NUL is skipped with ONE warning naming it — not a
/// whole-conversion failure at the tar writer's backstop (exit 3) — and
/// every other entry arrives intact.
#[cfg(feature = "cpio")]
#[test]
fn a_link_target_with_a_nul_is_skipped_into_tar_and_named() {
    let dir = tmp_dir();
    let src = dir.join("in.cpio");
    cpio_with_a_nul_link_target(&src);
    let dst = dir.join("out.tar");
    let outcome = entries::convert_archive(
        Input::Path(src),
        Output::Path(dst.clone()),
        fmt("tar"),
        None,
        &ConvertOpts::default(),
    )
    .expect("one symlink the target cannot hold is a warning, not a failure");
    let skipped: Vec<_> = outcome
        .fidelity
        .warnings
        .iter()
        .filter_map(|w| match w {
            Fidelity::EntrySkipped { entry, reason } => Some((entry.as_str(), reason.as_str())),
            _ => None,
        })
        .collect();
    assert_eq!(skipped.len(), 1, "{:?}", outcome.fidelity.warnings);
    assert_eq!(skipped[0].0, "link");
    assert!(skipped[0].1.contains("symlink target"), "{}", skipped[0].1);
    let entries = entries_of(&dst);
    assert_eq!(
        entries,
        vec![("keep.txt".to_string(), EntryKind::File, b"kept\n".to_vec())]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The other half of F2: cpio stores the target by length, so the same
/// symlink converted into cpio keeps its exact target, with no warning.
#[cfg(feature = "cpio")]
#[test]
fn a_link_target_with_a_nul_survives_into_cpio() {
    let dir = tmp_dir();
    let src = dir.join("in.cpio");
    cpio_with_a_nul_link_target(&src);
    let dst = dir.join("out.cpio");
    let outcome = entries::convert_archive(
        Input::Path(src),
        Output::Path(dst.clone()),
        fmt("cpio"),
        None,
        &ConvertOpts::default(),
    )
    .unwrap();
    assert!(
        outcome.fidelity.warnings.is_empty(),
        "{:?}",
        outcome.fidelity.warnings
    );
    let (metas, _) = entries::list(Input::Path(dst.clone()), DEFAULT_MAX_RATIO, None).unwrap();
    let link = metas
        .iter()
        .find(|m| m.name == "link")
        .expect("the link is kept");
    assert_eq!(
        link.kind,
        EntryKind::Symlink {
            target: "t\0x".into()
        }
    );
    assert_eq!(
        files_of(&dst),
        vec![("keep.txt".to_string(), b"kept\n".to_vec())]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A `.tar.gz` shaped the way GNU tar writes one — the tar padded with zeros
/// to a whole 10240-byte record — beside a copy with one bit flipped inside
/// a stored member's payload. Returns `(clean, corrupt, payload)`.
///
/// The record padding is the point: the container stops reading at its
/// end-of-archive blocks, so without a drain the gzip trailer behind the
/// padding (CRC-32 and ISIZE) is never reached and the flip goes unseen.
/// stuffr's own writer emits no padding, so its `.tar.gz` ends right after
/// the end-of-archive blocks and hides the defect — hence the hand build.
///
/// Level 0 stores every deflate block verbatim, so the flip lands on a
/// payload byte without disturbing the deflate framing: the
/// stream still decodes in full, to the wrong bytes, and only the CRC can
/// tell. The premise is asserted, not assumed.
#[cfg(feature = "gzip")]
fn gnu_padded_tar_gz(dir: &Path) -> (PathBuf, PathBuf, Vec<u8>) {
    let mut x: u32 = 0x2545_f491;
    let payload: Vec<u8> = (0..4000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect();
    let mut tar = hand_built_tar(&[("t/f.txt", b'0', &payload)]);
    tar.resize(tar.len().div_ceil(10240) * 10240, 0);
    let plain = dir.join("gnu.tar");
    std::fs::write(&plain, &tar).unwrap();
    let clean = dir.join("clean.tar.gz");
    stuffr::ops::compress(
        Input::Path(plain),
        Output::Path(clean.clone()),
        &CompressOpts {
            format: Some(fmt("gzip")),
            level: Some(0),
            ..CompressOpts::default()
        },
    )
    .unwrap();

    let mut gz = std::fs::read(&clean).unwrap();
    let probe = &payload[1000..1032];
    let at = gz
        .windows(probe.len())
        .position(|w| w == probe)
        .expect("premise: level 0 stores the payload verbatim");
    gz[at + 16] ^= 0x01;
    let corrupt = dir.join("corrupt.tar.gz");
    std::fs::write(&corrupt, &gz).unwrap();

    let err = stuffr::ops::decompress(
        Input::Path(corrupt.clone()),
        Output::Path(dir.join("premise.tar")),
        &stuffr::ops::DecompressOpts::default(),
    )
    .unwrap_err();
    assert_eq!(
        err.exit_code(),
        5,
        "premise: the codec itself rejects the flip: {err}"
    );
    (clean, corrupt, payload)
}

/// C1 (Phase 5a final review): the codec beneath the container is read to
/// its end, so its own integrity check runs, and a conversion that fails it
/// publishes nothing.
#[cfg(feature = "gzip")]
#[test]
fn a_corrupt_codec_trailer_under_a_padded_tar_is_exit_5_and_publishes_nothing() {
    let dir = tmp_dir();
    let (_, corrupt, _) = gnu_padded_tar_gz(&dir);
    let out = dir.join("out.zip");
    let err = entries::convert_archive(
        Input::Path(corrupt),
        Output::Path(out.clone()),
        fmt("zip"),
        None,
        &ConvertOpts::default(),
    )
    .unwrap_err();
    assert_eq!(err.exit_code(), 5, "{err}");
    assert!(!out.exists(), "nothing is published on a corrupt source");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same check on the read verbs, which share `open_resolved`.
#[cfg(feature = "gzip")]
#[test]
fn the_read_verbs_check_the_codec_trailer_under_a_padded_tar() {
    let dir = tmp_dir();
    let (_, corrupt, _) = gnu_padded_tar_gz(&dir);
    let err = entries::test(Input::Path(corrupt.clone()), DEFAULT_MAX_RATIO, None).unwrap_err();
    assert_eq!(err.exit_code(), 5, "test: {err}");
    let err = entries::list(Input::Path(corrupt.clone()), DEFAULT_MAX_RATIO, None).unwrap_err();
    assert_eq!(err.exit_code(), 5, "list: {err}");
    let err = entries::cat(
        Input::Path(corrupt.clone()),
        &Selection::All,
        DEFAULT_MAX_RATIO,
        None,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(err.exit_code(), 5, "cat: {err}");
    let err = entries::extract(
        Input::Path(corrupt),
        &dir.join("x"),
        &Selection::All,
        &entries::ExtractOpts::default(),
    )
    .unwrap_err();
    assert_eq!(err.exit_code(), 5, "unpack: {err}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The clean twin still converts and tests clean: the drain costs a healthy
/// padded archive nothing.
#[cfg(feature = "gzip")]
#[test]
fn a_clean_padded_tar_gz_converts_and_tests_clean() {
    let dir = tmp_dir();
    let (clean, _, payload) = gnu_padded_tar_gz(&dir);
    entries::test(Input::Path(clean.clone()), DEFAULT_MAX_RATIO, None).unwrap();
    let out = dir.join("out.zip");
    let outcome = entries::convert_archive(
        Input::Path(clean),
        Output::Path(out.clone()),
        fmt("zip"),
        None,
        &ConvertOpts::default(),
    )
    .unwrap();
    assert!(
        outcome.fidelity.warnings.is_empty(),
        "{:?}",
        outcome.fidelity.warnings
    );
    assert_eq!(files_of(&out), vec![("t/f.txt".to_string(), payload)]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// M2 (Phase 5a final review): a directory is a usage error (exit 2), the
/// Phase 2c ruling `pack`'s codec path already applies — not the `Is a
/// directory` i/o error (exit 1) a read of it would raise.
#[test]
fn a_directory_input_is_a_usage_error() {
    let dir = tmp_dir();
    let tree = dir.join("proj");
    std::fs::create_dir_all(&tree).unwrap();
    let out = dir.join("out.zip");
    let err = entries::convert_archive(
        Input::Path(tree),
        Output::Path(out.clone()),
        fmt("zip"),
        None,
        &ConvertOpts::default(),
    )
    .unwrap_err();
    assert_eq!(err.exit_code(), 2, "{err}");
    assert!(err.to_string().contains("stuffr pack"), "{err}");
    assert!(!out.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A tar of a regular file `target` holding `payload`, then a typeflag-`1`
/// entry `name` linking to it.
fn link_tar(target: &str, payload: &[u8], name: &str) -> Vec<u8> {
    let mut out = hand_built_tar(&[(target, b'0', payload)]);
    out.truncate(out.len() - 1024);
    out.extend_from_slice(&link_header(name, target));
    out.extend(std::iter::repeat_n(0u8, 1024));
    out
}

/// A typeflag-`1` header for `name` linking to `target`.
fn link_header(name: &str, target: &str) -> [u8; 512] {
    let mut h = tar_header(name, 0, b'1');
    h[157..157 + target.len()].copy_from_slice(target.as_bytes());
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

/// The `EntrySkipped` warnings of a report, as `(entry, reason)`.
fn skips(warnings: &[Fidelity]) -> Vec<(String, String)> {
    warnings
        .iter()
        .filter_map(|w| match w {
            Fidelity::EntrySkipped { entry, reason } => Some((entry.clone(), reason.clone())),
            _ => None,
        })
        .collect()
}

fn convert(
    src: &Path,
    dst: &Path,
    container: &'static str,
    o: &ConvertOpts,
) -> stuffr::ops::Outcome {
    entries::convert_archive(
        Input::Path(src.to_path_buf()),
        Output::Path(dst.to_path_buf()),
        fmt(container),
        None,
        o,
    )
    .unwrap()
}

/// A tar link into a container without links becomes a regular file holding
/// exactly its target's bytes, and that is no loss.
#[test]
fn a_tar_hard_link_converts_to_zip_as_a_full_copy() {
    let dir = tmp_dir();
    let src = dir.join("src.tar");
    std::fs::write(&src, hand_built_link_tar("a", "b")).unwrap();
    let zip = dir.join("out.zip");
    let outcome = convert(&src, &zip, "zip", &ConvertOpts::default());
    assert!(
        outcome.fidelity.warnings.is_empty(),
        "a full copy loses nothing: {:?}",
        outcome.fidelity.warnings
    );
    assert_eq!(
        entries_of(&zip),
        [
            ("b".to_string(), EntryKind::File, b"hello".to_vec()),
            ("a".to_string(), EntryKind::File, b"hello".to_vec()),
        ]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// One `newc` member: `ino` and `nlink` say which names share a file.
#[cfg(feature = "cpio")]
fn newc_member(out: &mut Vec<u8>, name: &str, ino: u32, nlink: u32, data: &[u8]) {
    let mode = if name == "TRAILER!!!" { 0 } else { 0o100_644 };
    out.extend_from_slice(
        format!(
            "070701{ino:08X}{mode:08X}{:08X}{:08X}{nlink:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}",
            1,
            1,
            1_000_000_000u32,
            data.len(),
            0,
            0,
            0,
            0,
            name.len() + 1,
            0
        )
        .as_bytes(),
    );
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    out.extend_from_slice(data);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

/// A GNU-layout `newc` link group: `a1` and `a2` empty, `a` last with the
/// shared bytes, then a plain file `p`.
#[cfg(feature = "cpio")]
fn gnu_cpio_group(shared: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    newc_member(&mut out, "a1", 7, 3, b"");
    newc_member(&mut out, "a2", 7, 3, b"");
    newc_member(&mut out, "a", 7, 3, shared);
    newc_member(&mut out, "p", 8, 1, b"plain");
    newc_member(&mut out, "TRAILER!!!", 0, 1, b"");
    out
}

/// A cpio link group into zip: every name a full copy, in the order the
/// reader yields them (the data member, then its links), and no warning.
#[cfg(feature = "cpio")]
#[test]
fn a_cpio_group_converts_to_zip_as_full_copies() {
    let dir = tmp_dir();
    let src = dir.join("src.cpio");
    std::fs::write(&src, gnu_cpio_group(b"shared bytes")).unwrap();
    let zip = dir.join("out.zip");
    let outcome = convert(&src, &zip, "zip", &ConvertOpts::default());
    assert!(
        outcome.fidelity.warnings.is_empty(),
        "{:?}",
        outcome.fidelity.warnings
    );
    let shared = b"shared bytes".to_vec();
    assert_eq!(
        entries_of(&zip),
        [
            ("a".to_string(), EntryKind::File, shared.clone()),
            ("a1".to_string(), EntryKind::File, shared.clone()),
            ("a2".to_string(), EntryKind::File, shared),
            ("p".to_string(), EntryKind::File, b"plain".to_vec()),
        ]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A target larger than the cache's memory tier is not kept, so its link is
/// skipped, named with the pinned reason, and never written as an empty or
/// partial file. The target itself is unaffected.
#[test]
fn a_tar_link_whose_target_was_evicted_is_skipped_and_named() {
    let dir = tmp_dir();
    let src = dir.join("src.tar");
    let big: Vec<u8> = (0..2048u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&src, link_tar("b", &big, "a")).unwrap();
    let zip = dir.join("out.zip");
    let outcome = convert(
        &src,
        &zip,
        "zip",
        &ConvertOpts {
            spill: stuffr::SpillPolicy::Memory { cap: 1024 },
            ..ConvertOpts::default()
        },
    );
    assert_eq!(
        skips(&outcome.fidelity.warnings),
        [(
            "a".to_string(),
            "its hard-link target `b` was not kept for copying".to_string()
        )],
        "{:?}",
        outcome.fidelity.warnings
    );
    assert_eq!(outcome.fidelity.warnings.len(), 1);
    assert_eq!(
        entries_of(&zip),
        [("b".to_string(), EntryKind::File, big)],
        "no empty `a` beside the target"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Into tar, a link is stored as a link only to a target this run wrote. A
/// target the tar cannot hold (a fifo, which convert never stores) is
/// skipped, and so is its link, with the pinned reason: never a dangling
/// link. (A tar source cannot carry a NUL in a name, which is why the
/// skipped target here is a fifo; the NUL case, from cpio, is below.)
#[test]
fn a_tar_to_tar_link_whose_target_was_skipped_is_skipped() {
    let dir = tmp_dir();
    let src = dir.join("src.tar");
    let mut bytes = hand_built_tar(&[("k", b'0', b"kept"), ("f", b'6', b"")]);
    bytes.truncate(bytes.len() - 1024);
    bytes.extend_from_slice(&link_header("l", "f"));
    bytes.extend(std::iter::repeat_n(0u8, 1024));
    std::fs::write(&src, bytes).unwrap();
    let out = dir.join("out.tar");
    let outcome = convert(&src, &out, "tar", &ConvertOpts::default());
    let skipped = skips(&outcome.fidelity.warnings);
    assert_eq!(skipped.len(), 2, "{skipped:?}");
    assert_eq!(skipped[0].0, "f");
    assert_eq!(
        skipped[1],
        (
            "l".to_string(),
            "its hard-link target `f` was not written".to_string()
        )
    );
    assert_eq!(
        entries_of(&out),
        [("k".to_string(), EntryKind::File, b"kept".to_vec())]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The NUL case: a cpio group whose data member's name holds a NUL. tar
/// cannot hold that name, so the member is skipped, and its link — whose
/// TARGET is that name — is skipped too, never stored dangling.
#[cfg(feature = "cpio")]
#[test]
fn a_cpio_link_to_a_nul_named_target_is_skipped_into_tar() {
    let dir = tmp_dir();
    let src = dir.join("src.cpio");
    let mut bytes = Vec::new();
    newc_member(&mut bytes, "k", 9, 1, b"kept");
    newc_member(&mut bytes, "t\0x", 7, 2, b"payload");
    newc_member(&mut bytes, "l", 7, 2, b"");
    newc_member(&mut bytes, "TRAILER!!!", 0, 1, b"");
    std::fs::write(&src, bytes).unwrap();
    let out = dir.join("out.tar");
    let outcome = convert(&src, &out, "tar", &ConvertOpts::default());
    let skipped = skips(&outcome.fidelity.warnings);
    assert_eq!(skipped.len(), 2, "{skipped:?}");
    assert_eq!(skipped[0].0, "t\0x");
    assert_eq!(skipped[1].0, "l");
    assert_eq!(
        entries_of(&out),
        [("k".to_string(), EntryKind::File, b"kept".to_vec())]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// cpio into tar: the target stores links, so the group stays a group.
#[cfg(feature = "cpio")]
#[test]
fn cpio_to_tar_writes_links_as_links() {
    let dir = tmp_dir();
    let src = dir.join("src.cpio");
    std::fs::write(&src, gnu_cpio_group(b"shared bytes")).unwrap();
    let out = dir.join("out.tar");
    let outcome = convert(&src, &out, "tar", &ConvertOpts::default());
    assert!(
        outcome.fidelity.warnings.is_empty(),
        "{:?}",
        outcome.fidelity.warnings
    );
    let link = |name: &str| {
        (
            name.to_string(),
            EntryKind::Hardlink { target: "a".into() },
            Vec::new(),
        )
    };
    assert_eq!(
        entries_of(&out),
        [
            ("a".to_string(), EntryKind::File, b"shared bytes".to_vec()),
            link("a1"),
            link("a2"),
            ("p".to_string(), EntryKind::File, b"plain".to_vec()),
        ]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `cat` of a link writes its target's bytes when the target was selected
/// earlier in the same run, and is `EntryNotFound` naming the target when it
/// was not.
#[test]
fn cat_of_a_link_copies_its_selected_target_or_names_it() {
    let dir = tmp_dir();
    let src = dir.join("src.tar");
    std::fs::write(&src, hand_built_link_tar("a", "b")).unwrap();
    let mut out = Vec::new();
    entries::cat(
        Input::Path(src.clone()),
        &Selection::All,
        DEFAULT_MAX_RATIO,
        None,
        &mut out,
    )
    .unwrap();
    assert_eq!(out, b"hellohello");

    let mut out = Vec::new();
    let err = entries::cat(
        Input::Path(src),
        &Selection::Names(vec!["a".into()]),
        DEFAULT_MAX_RATIO,
        None,
        &mut out,
    )
    .unwrap_err();
    assert!(
        matches!(&err, stuffr::Error::EntryNotFound(t) if t == "b"),
        "{err:?}"
    );
    assert_eq!(err.exit_code(), 2);
    assert!(out.is_empty(), "nothing invented for the link");
    let _ = std::fs::remove_dir_all(&dir);
}
