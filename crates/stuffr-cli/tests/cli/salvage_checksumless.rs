use crate::common::*;
use std::io::Write;
use tar::Header;

// ---------------------------------------------------------------------
// Salvage Stage 3 Task 6: the checksumless damage catalogue, end to end.
//
// The fast half lives beside each scanner — `tar_salvage.rs`,
// `cpio_salvage.rs` and `ar_salvage.rs` each carry a `damage_catalogue`
// module that owns the agreement property and the full mutation table over
// every reference writer (BSD and GNU). What this file adds is what only a
// process can state: the ROW a user reads, the EXIT CODE a script branches
// on, and the BYTES left on disk. The middle row is the stage's point: none
// of these formats checksums its content, so a flipped payload byte is a
// silently wrong file, and the run must never print a tier that says the
// content was checked (`Intact`).
//
// Every expectation is the PRE-DAMAGE state: the input files, fed to the
// platform's own `tar`/`cpio`/`ar` (REQUIRED, never skipped), with damage
// placed by finding the input's own bytes in the writer's output — all three
// formats store payloads verbatim — never by asking stuffr where they are.
// ---------------------------------------------------------------------

/// tar: `Complete` (header self-check only), so a flipped payload byte is
/// written under its real name at EXIT 0 — the sharpest form of the row.
#[test]
fn damage_catalogue_tar_end_to_end() {
    checksumless_catalogue_end_to_end("tar", "Complete", 0);

    // Task 6 finding D1, at the binary: a GNU tar header whose magic is junk
    // (checksum resealed) is ONE header in the note, at its own offset, not
    // also its one-byte-late copy. `alpha.txt`'s name and payload both start
    // with `a`, the case where that copy agrees with itself. GNU tar is
    // `gtar` on macOS and `tar` on Linux.
    let dir = tmp_dir();
    let tree = dir.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    let inputs = checksumless_inputs();
    for (name, data) in &inputs {
        std::fs::write(tree.join(name), data).unwrap();
    }
    let gnu = which("gtar").unwrap_or_else(|| require_bin("tar"));
    let out = dir.join("gnu.tar");
    let mut args = vec![os(&"-cf"), os(&out)];
    args.extend(inputs.iter().map(|(n, _)| os(n)));
    run_tool(&gnu, &args, &tree, b"");
    let mut bytes = std::fs::read(&out).unwrap();
    bytes[257..263].copy_from_slice(b"bogus\0");
    bytes[148..156].copy_from_slice(b"        ");
    let sum: u32 = bytes[..512].iter().map(|&x| u32::from(x)).sum();
    bytes[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    let damaged = dir.join("junk-magic.tar");
    std::fs::write(&damaged, &bytes).unwrap();
    let out = run_output(&["salvage", damaged.to_str().unwrap(), "--list"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("saw 1 tar header(s)") && stderr.contains("offset(s) 0"),
        "one header at offset 0, not its late copy too: {stderr}"
    );
    assert!(!stderr.contains("offset(s) 0, 1"), "{stderr}");
}

/// cpio (`newc`): `Unattested`, exit 4 even when whole.
#[test]
fn damage_catalogue_cpio_end_to_end() {
    checksumless_catalogue_end_to_end("cpio", "Unattested", 4);
}

/// ar: `Unattested`, exit 4 even when whole.
#[test]
fn damage_catalogue_ar_end_to_end() {
    checksumless_catalogue_end_to_end("ar", "Unattested", 4);
}

/// 0.8.1: a GNU sparse header (`isextended` set) declaring `2^64 - 1024`
/// bytes. `tar` 0.4.46 advances its next-header offset by that size, checked,
/// to `2^64 - 512`, then adds one block per extension block unchecked
/// (`archive.rs:532`): a panic in a debug build (exit 101), a silent wrap in
/// release. `tar.rs`'s `CrateNextGuard` refuses the extension block first.
/// Every verb that reads it says Corrupt — exit 5, never 101 and never 1 —
/// and `salvage`, which never hands bytes to `tar::Archive`, is not exit
/// 101 or 1 either.
#[test]
fn a_tar_sparse_header_the_tar_crate_would_overflow_on_exits_5() {
    let dir = tmp_dir();
    let mut header = Header::new_gnu();
    header.set_path("sparse.bin").unwrap();
    header.set_mode(0o644);
    header.set_entry_type(tar::EntryType::GNUSparse);
    header.set_size(u64::MAX - 1023);
    header.as_gnu_mut().unwrap().set_is_extended(true);
    header.set_cksum();
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend_from_slice(tar::GnuExtSparseHeader::new().as_bytes());
    bytes.extend_from_slice(&[0u8; 1024]);
    assert_eq!(bytes.len(), 2048);
    let path = dir.join("overflow.tar");
    std::fs::write(&path, &bytes).unwrap();
    let p = path.to_str().unwrap();

    for args in [
        vec!["list", p],
        vec!["test", p],
        vec!["unpack", p, "-C", dir.join("out").to_str().unwrap()],
    ] {
        let out = run_output(&args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(5), "{args:?}: {stderr}");
        assert!(stderr.contains("past 2^64"), "{args:?}: {stderr}");
    }
    let out = run_with_stdin_output(&["list", "-"], &bytes);
    assert_eq!(
        out.status.code(),
        Some(5),
        "a pipe: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = run_output(&["salvage", p, "--list"]);
    let code = out.status.code();
    assert!(
        code.is_some_and(|c| c != 1 && c != 101),
        "salvage: {code:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The healthy shape the guard above stands in front of: a real GNU tar
/// `--sparse` archive of a file with a hole, its block map long enough to
/// need extension blocks, lists, tests and unpacks byte-identical. GNU tar
/// is `gtar` on macOS and `tar` on Linux. The fixture recipe — data runs
/// with zero runs between them, then a real hole to 64 MiB, archived with
/// `--hole-detection=raw` — is `tar.rs`'s
/// `a_gnu_tar_sparse_archive_reads_back_byte_identical`'s, where the reason
/// for each part is written down.
#[test]
fn a_gnu_tar_sparse_archive_lists_tests_and_unpacks_byte_identical() {
    let dir = tmp_dir();
    let mut data = vec![0u8; 12 * 16384 + 3000];
    for run in 0..12 {
        let at = run * 16384 + 4096;
        for (i, b) in data[at..at + 1000].iter_mut().enumerate() {
            *b = ((i * 7 + run) % 251) as u8 + 1;
        }
    }
    let len: u64 = 64 << 20;
    let src = dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    {
        let mut file = std::fs::File::create(src.join("holey.bin")).unwrap();
        file.write_all(&data).unwrap();
        file.set_len(len).unwrap();
        file.sync_all().unwrap();
    }
    let gnu = require_gnu_tar();
    let archive = dir.join("sparse.tar");
    run_tool(
        &gnu,
        &[
            os(&"--format=gnu"),
            os(&"--sparse"),
            os(&"--hole-detection=raw"),
            os(&"-cf"),
            os(&archive),
            os(&"holey.bin"),
        ],
        &src,
        b"",
    );
    let bytes = std::fs::read(&archive).unwrap();
    let header = Header::from_byte_slice(&bytes[..512]);
    assert!(
        header.entry_type().is_gnu_sparse(),
        "typeflag `S` — GNU tar did not see a hole in the file"
    );
    assert!(
        header.as_gnu().is_some_and(|gnu| gnu.is_extended()),
        "the map spills into extension blocks"
    );
    let p = archive.to_str().unwrap();

    let out = run_output(&["list", p]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("holey.bin") && stdout.contains(&len.to_string()),
        "{stdout}"
    );
    let out = run_output(&["test", p]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let dest = dir.join("out");
    let out = run_output(&["unpack", p, "-C", dest.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let got = std::fs::read(dest.join("holey.bin")).unwrap();
    assert_eq!(got.len() as u64, len);
    assert!(got[..data.len()] == data[..], "the data runs differ");
    assert!(
        got[data.len()..].iter().all(|&b| b == 0),
        "the hole unpacks as zeros"
    );
}
