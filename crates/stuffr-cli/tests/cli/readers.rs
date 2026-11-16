//! What the READERS deliver (bug hunt 2026-11-15, Task 4): pax sparse files
//! (finding 4), non-UTF-8 names (finding 20), the pax `mtime` record
//! (finding 25) and zip entry decoders under `--memory-limit` (finding 3).

use crate::common::*;

use std::io::Write;
use std::path::{Path, PathBuf};

/// A 64 MiB file with three data runs and holes between and after them —
/// big enough that APFS keeps the holes, so macOS tar maps them.
fn write_holey_file(dir: &Path) -> (PathBuf, Vec<u8>) {
    let len: usize = 64 << 20;
    let path = dir.join("holey.bin");
    let mut expected = vec![0u8; len];
    let mut file = std::fs::File::create(&path).unwrap();
    for (i, at) in [0usize, 20 << 20, 50 << 20].into_iter().enumerate() {
        let run: Vec<u8> = (0..5000).map(|j| ((j * 7 + i) % 251) as u8 + 1).collect();
        expected[at..at + run.len()].copy_from_slice(&run);
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(at as u64)).unwrap();
        file.write_all(&run).unwrap();
    }
    file.set_len(len as u64).unwrap();
    file.sync_all().unwrap();
    (path, expected)
}

/// `stuffr ARGS` with `input` on stdin, fed from a thread so a large
/// stdout cannot deadlock against it.
fn piped(args: &[&str], input: &[u8]) -> std::process::Output {
    use std::process::{Command, Stdio};
    let mut child = Command::new(STUFFR)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let input = input.to_vec();
    let feeder = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let out = child.wait_with_output().unwrap();
    feeder.join().unwrap();
    out
}

/// Every reading verb over `archive`, a pax sparse archive of `holey.bin`:
/// the real name, the real size, the real contents, on a file and a pipe,
/// and through `convert`.
fn assert_sparse_archive_reads_back(archive: &Path, expected: &[u8], label: &str) {
    let bytes = std::fs::read(archive).unwrap();
    assert!(
        bytes.windows(11).any(|w| w == b"GNU.sparse."),
        "{label}: the reference tool did not write a pax sparse entry"
    );
    let p = archive.to_str().unwrap();
    let ratio = ["--max-ratio", "1000000"];

    let out = run_output(&["list", p]);
    let listed = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(out.status.code(), Some(0), "{label}: {}", stderr_text(&out));
    assert!(
        listed.contains("holey.bin") && listed.contains(&expected.len().to_string()),
        "{label}: {listed}"
    );
    assert!(!listed.contains("GNUSparseFile"), "{label}: {listed}");
    let listed_piped = run_with_stdin(&["list", "-"], &bytes);
    assert_eq!(
        listed_piped, listed,
        "{label}: pipe and file list differently"
    );

    let out = run_output(&["test", "--strict-fidelity", ratio[0], ratio[1], p]);
    assert_eq!(out.status.code(), Some(0), "{label}: {}", stderr_text(&out));

    let dir = tmp_dir();
    let dest = dir.join("out");
    let d = dest.to_str().unwrap();
    let out = run_output(&[
        "unpack",
        "--strict-fidelity",
        ratio[0],
        ratio[1],
        "-C",
        d,
        p,
    ]);
    assert_eq!(out.status.code(), Some(0), "{label}: {}", stderr_text(&out));
    let got = std::fs::read(dest.join("holey.bin")).unwrap();
    assert!(got == expected, "{label}: unpacked contents differ");
    assert!(
        !dest.join("GNUSparseFile.0").exists(),
        "{label}: placeholder directory written"
    );

    let out = piped(&["cat", ratio[0], ratio[1], "-", "holey.bin"], &bytes);
    assert_eq!(out.status.code(), Some(0), "{label}: {}", stderr_text(&out));
    assert!(out.stdout == expected, "{label}: piped cat differs");

    let zip = dir.join("conv.zip");
    let out = run_output(&[
        "convert",
        ratio[0],
        ratio[1],
        "--strict-fidelity",
        p,
        "-o",
        zip.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(0), "{label}: {}", stderr_text(&out));
    let out = run_output(&["cat", zip.to_str().unwrap(), "holey.bin"]);
    assert!(out.stdout == expected, "{label}: converted contents differ");
}

/// Finding 4: GNU tar's three pax sparse layouts (0.0, 0.1, 1.0) read back
/// as the file, not as the placeholder name holding the map.
#[test]
fn gnu_tar_pax_sparse_archives_read_back_as_the_file() {
    let gnu = require_gnu_tar();
    let dir = tmp_dir();
    let src = dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    let (_, expected) = write_holey_file(&src);
    for version in ["0.0", "0.1", "1.0"] {
        let archive = dir.join(format!("sparse-{version}.tar"));
        run_tool(
            &gnu,
            &[
                os(&"--format=pax"),
                os(&"--sparse"),
                os(&"--hole-detection=raw"),
                os(&format!("--sparse-version={version}")),
                os(&"-cf"),
                os(&archive),
                os(&"holey.bin"),
            ],
            &src,
            b"",
        );
        assert_sparse_archive_reads_back(&archive, &expected, &format!("GNU tar {version}"));
    }
}

/// Finding 4 as found: macOS `/usr/bin/tar` writes pax sparse 1.0 for any
/// file with a hole. stuffr's extraction is byte-identical to its own.
#[cfg(target_os = "macos")]
#[test]
fn macos_tar_pax_sparse_archive_reads_back_as_bsdtar_extracts_it() {
    let dir = tmp_dir();
    let src = dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    let (_, expected) = write_holey_file(&src);
    let archive = dir.join("bsd.tar");
    let bsdtar = Path::new("/usr/bin/tar");
    run_tool(
        bsdtar,
        &[
            os(&"--format"),
            os(&"pax"),
            os(&"-cf"),
            os(&archive),
            os(&"holey.bin"),
        ],
        &src,
        b"",
    );
    assert_sparse_archive_reads_back(&archive, &expected, "bsdtar");
    let reference = dir.join("ref");
    std::fs::create_dir_all(&reference).unwrap();
    run_tool(bsdtar, &[os(&"-xf"), os(&archive)], &reference, b"");
    let theirs = std::fs::read(reference.join("holey.bin")).unwrap();
    assert!(theirs == expected, "bsdtar's own extraction differs");
}

/// A hostile map is exit 5, a huge real size over a byte of data is exit 6
/// once read (the ratio budget), and neither writes the placeholder.
#[test]
fn a_hostile_pax_sparse_map_is_refused() {
    let dir = tmp_dir();
    let build = |name: &str, realsize: &str, payload: &[u8]| -> PathBuf {
        let path = dir.join(name);
        let mut builder = tar::Builder::new(std::fs::File::create(&path).unwrap());
        builder
            .append_pax_extensions([
                ("GNU.sparse.major", &b"1"[..]),
                ("GNU.sparse.minor", b"0"),
                ("GNU.sparse.name", b"big"),
                ("GNU.sparse.realsize", realsize.as_bytes()),
            ])
            .unwrap();
        let mut header = tar::Header::new_ustar();
        header.set_size(payload.len() as u64);
        header.set_mode(0o644);
        builder
            .append_data(&mut header, "GNUSparseFile.0/big", payload)
            .unwrap();
        builder.finish().unwrap();
        path
    };
    let mut overlapping = b"2\n0\n10\n5\n10\n".to_vec();
    overlapping.resize(512, 0);
    overlapping.extend([b'd'; 20]);
    let bad = build("overlap.tar", "100", &overlapping);
    let mut tiny = b"1\n0\n1\n".to_vec();
    tiny.resize(512, 0);
    tiny.push(b'x');
    let huge = build("huge.tar", "1099511627776", &tiny);
    // Each verb on the file and on a pipe (task 4 review, minor 5): the
    // same verdict, and an unpack leaves no placeholder. A refused map
    // writes no `big` at all; the 1 TiB one is refused by the ratio budget
    // part-way, and entry-aware extraction is documented as not atomic
    // (`stuffr::entries::extract`, README): the one partial file it leaves
    // is bounded by that budget, never the declared size.
    for (archive, codes) in [(&bad, [5, 5, 5, 5]), (&huge, [0, 6, 6, 6])] {
        let bytes = std::fs::read(archive).unwrap();
        for (i, verb) in ["list", "test", "unpack", "cat"].into_iter().enumerate() {
            for pipe in [false, true] {
                let dest = dir.join(format!("out-{verb}-{pipe}"));
                let p = if pipe { "-" } else { archive.to_str().unwrap() };
                let args: Vec<&str> = match verb {
                    "unpack" => vec!["unpack", "-C", dest.to_str().unwrap(), p],
                    "cat" => vec!["cat", p, "big"],
                    _ => vec![verb, p],
                };
                let out = if pipe {
                    piped(&args, &bytes)
                } else {
                    run_output(&args)
                };
                assert_eq!(
                    out.status.code(),
                    Some(codes[i]),
                    "{verb} {} (pipe {pipe}): {}",
                    archive.display(),
                    stderr_text(&out)
                );
                assert!(!dest.join("GNUSparseFile.0").exists());
                let big = std::fs::metadata(dest.join("big")).map(|m| m.len());
                if codes[i] == 5 {
                    assert!(big.is_err(), "{verb}: a refused map wrote `big`");
                    assert!(out.stdout.is_empty(), "{verb}: a refused map wrote data");
                } else if let Ok(len) = big {
                    assert!(len <= 128 << 20, "{verb}: `big` grew to {len} bytes");
                }
                if verb == "cat" {
                    assert!(
                        out.stdout.len() <= 128 << 20,
                        "{verb}: {} bytes",
                        out.stdout.len()
                    );
                }
            }
        }
    }
}

/// `GNU.sparse.name` is the attacker's new way to name an entry: `../x`
/// and `/x` are held to the same path safety as any name, exit 7 on unpack
/// with nothing written outside the destination (task 4 review, minor 4).
#[test]
fn a_pax_sparse_name_is_held_to_path_safety() {
    let dir = tmp_dir();
    for (i, name) in ["../x", "/x", "a/../../x"].into_iter().enumerate() {
        let path = dir.join(format!("evil-{i}.tar"));
        let mut builder = tar::Builder::new(std::fs::File::create(&path).unwrap());
        builder
            .append_pax_extensions([
                ("GNU.sparse.major", &b"1"[..]),
                ("GNU.sparse.minor", b"0"),
                ("GNU.sparse.name", name.as_bytes()),
                ("GNU.sparse.realsize", b"4"),
            ])
            .unwrap();
        let mut payload = b"1\n0\n4\n".to_vec();
        payload.resize(512, 0);
        payload.extend_from_slice(b"evil");
        let mut header = tar::Header::new_ustar();
        header.set_size(payload.len() as u64);
        header.set_mode(0o644);
        builder
            .append_data(&mut header, "GNUSparseFile.0/x", &payload[..])
            .unwrap();
        builder.finish().unwrap();
        let dest = dir.join(format!("dest-{i}"));
        std::fs::create_dir_all(&dest).unwrap();
        let out = run_output(&[
            "unpack",
            "-C",
            dest.to_str().unwrap(),
            path.to_str().unwrap(),
        ]);
        assert_eq!(out.status.code(), Some(7), "{name}: {}", stderr_text(&out));
        assert!(
            !dir.join("x").exists(),
            "{name}: written outside the destination"
        );
        assert!(!dest.join("x").exists() && !dest.join("GNUSparseFile.0").exists());
    }
}

/// A GNU tar holding Latin-1 names `caf\xe9` (ONE) and `caf\xe8` (TWO!),
/// then `b` — what an ordinary pre-UTF-8 tarball looks like.
fn latin1_tar(dir: &Path) -> PathBuf {
    let path = dir.join("latin1.tar");
    let mut builder = tar::Builder::new(std::fs::File::create(&path).unwrap());
    for (name, data) in [
        (&b"caf\xe9"[..], &b"ONE"[..]),
        (b"caf\xe8", b"TWO!"),
        (b"b", b"x"),
    ] {
        let mut header = tar::Header::new_gnu();
        header.as_old_mut().name[..name.len()].copy_from_slice(name);
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(1_700_000_000);
        header.set_cksum();
        builder.append(&header, data).unwrap();
    }
    builder.finish().unwrap();
    path
}

/// Finding 20: a non-UTF-8 name is read lossily, and every read verb now
/// says so — `--strict-fidelity` exits 4 where it said "exact fidelity" /
/// "no fidelity loss" at exit 0, and the warning spells each stored name
/// so two that read alike stay apart.
#[test]
fn a_name_that_is_not_utf8_is_a_fidelity_loss_in_every_verb() {
    let dir = tmp_dir();
    let src = latin1_tar(&dir);
    let p = src.to_str().unwrap();
    for args in [
        vec!["list", "--strict-fidelity", p],
        vec!["test", "--strict-fidelity", p],
    ] {
        let out = run_output(&args);
        let err = stderr_text(&out);
        assert_eq!(out.status.code(), Some(4), "{args:?}: {err}");
        assert!(
            err.contains("caf\\xe9") && err.contains("caf\\xe8") && err.contains("not valid UTF-8"),
            "{args:?}: {err}"
        );
    }
    // `--json` keeps stdout to the entries; the warning goes to stderr.
    let out = run_output(&["list", "--json", p]);
    assert!(String::from_utf8_lossy(&out.stdout).starts_with('['));
    assert!(
        stderr_text(&out).contains("caf\\xe9"),
        "{}",
        stderr_text(&out)
    );

    let cpio = dir.join("n.cpio");
    let out = run_output(&[
        "convert",
        "--strict-fidelity",
        p,
        "-o",
        cpio.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(4), "{}", stderr_text(&out));
    assert!(stderr_text(&out).contains("not valid UTF-8"));

    // `unpack`: the two names collapse onto one path. Without --force the
    // second is the repeated-name refusal any tar gets (exit 2); with it,
    // the later one wins (tar's rule) and the run is not called clean.
    let dest = dir.join("x");
    let out = run_output(&[
        "unpack",
        "--force",
        "--strict-fidelity",
        "-C",
        dest.to_str().unwrap(),
        p,
    ]);
    assert_eq!(out.status.code(), Some(4), "{}", stderr_text(&out));
    assert!(stderr_text(&out).contains("caf\\xe9"));
}

/// The same for an `ar` member name, through `convert` to tar.
#[test]
fn an_ar_member_name_that_is_not_utf8_is_a_fidelity_loss() {
    let dir = tmp_dir();
    let mut bytes = b"!<arch>\n".to_vec();
    let mut id = [b' '; 16];
    id[..4].copy_from_slice(b"caf\xe9");
    bytes.extend_from_slice(&id);
    bytes.extend_from_slice(
        format!("{:<12}{:<6}{:<6}{:<8}{:<10}`\n", 0, 0, 0, 100644, 4).as_bytes(),
    );
    bytes.extend_from_slice(b"data");
    let src = dir.join("n.a");
    std::fs::write(&src, &bytes).unwrap();
    let dst = dir.join("n.tar");
    let out = run_output(&[
        "convert",
        "--strict-fidelity",
        src.to_str().unwrap(),
        "-o",
        dst.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(4), "{}", stderr_text(&out));
    assert!(
        stderr_text(&out).contains("caf\\xe9"),
        "{}",
        stderr_text(&out)
    );
}

/// A pax tar whose entries carry their real time only in the pax `mtime`
/// record, the header field left 0 — what Python's tarfile (PAX_FORMAT)
/// writes for a time before 1970 or from 2242.
fn pax_mtime_tar(dir: &Path, entries: &[(&str, &str)]) -> PathBuf {
    let path = dir.join("p.tar");
    let mut builder = tar::Builder::new(std::fs::File::create(&path).unwrap());
    for (name, mtime) in entries {
        builder
            .append_pax_extensions([("mtime", mtime.as_bytes())])
            .unwrap();
        let mut header = tar::Header::new_ustar();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_mtime(0);
        builder
            .append_data(&mut header, name, &b"data\n"[..])
            .unwrap();
    }
    builder.finish().unwrap();
    path
}

fn modified(path: &Path) -> i64 {
    let t = std::fs::metadata(path).unwrap().modified().unwrap();
    match t.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

/// Finding 25: the pax `mtime` record wins over the header field, as with
/// bsdtar (`neg.txt` -31536000; `big.txt` 20000000000 where the filesystem
/// holds it); `convert` to `ar`, which cannot hold a time before 1970, now
/// sees the real time and reports the clamp.
#[test]
fn the_pax_mtime_record_is_what_unpack_restores() {
    let dir = tmp_dir();
    let src = pax_mtime_tar(
        &dir,
        &[
            ("neg.txt", "-31536000"),
            ("big.txt", "20000000000"),
            ("frac.txt", "1700000000.5"),
        ],
    );
    let dest = dir.join("out");
    let out = run_output(&[
        "unpack",
        "-C",
        dest.to_str().unwrap(),
        src.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    assert_eq!(modified(&dest.join("neg.txt")), -31_536_000);
    assert_eq!(modified(&dest.join("frac.txt")), 1_700_000_000);
    // Past what some filesystems hold (ext4 stops in 2446): then the
    // restore itself is the reported loss, never a silent 1970.
    let big = modified(&dest.join("big.txt"));
    assert!(
        big >= 9_000_000_000 || stderr_text(&out).contains("big.txt"),
        "big.txt restored as {big}: {}",
        stderr_text(&out)
    );

    let ar = dir.join("p.a");
    let out = run_output(&[
        "convert",
        "--strict-fidelity",
        src.to_str().unwrap(),
        "-o",
        ar.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(4), "{}", stderr_text(&out));
    assert!(
        stderr_text(&out).contains("neg.txt"),
        "{}",
        stderr_text(&out)
    );
}

/// A pax `mtime` that cannot be read is an unknown mtime and a reported
/// loss under `--strict-fidelity`, never a silent 1970.
#[test]
fn an_unreadable_pax_mtime_is_a_fidelity_loss() {
    let dir = tmp_dir();
    let src = pax_mtime_tar(&dir, &[("a.txt", "yesterday")]);
    let out = run_output(&["test", "--strict-fidelity", src.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(4), "{}", stderr_text(&out));
    assert!(stderr_text(&out).contains("mtime"), "{}", stderr_text(&out));
}

/// A one-entry zip whose entry `x` uses `method`, with `data` as its
/// compressed payload and `usize_` as its declared uncompressed size; the
/// CRC is 0, so an entry that does decode fails its check (exit 5).
fn zip_with_method(method: u16, data: &[u8], usize_: u32) -> Vec<u8> {
    let le16 = |v: u16| v.to_le_bytes();
    let le32 = |v: u32| v.to_le_bytes();
    let name = b"x";
    let mut out = Vec::new();
    out.extend(b"PK\x03\x04");
    out.extend(le16(63));
    out.extend(le16(0));
    out.extend(le16(method));
    out.extend(le32(0)); // time, date
    out.extend(le32(0)); // crc
    out.extend(le32(data.len() as u32));
    out.extend(le32(usize_));
    out.extend(le16(name.len() as u16));
    out.extend(le16(0));
    out.extend(name);
    out.extend(data);
    let cd_at = out.len() as u32;
    out.extend(b"PK\x01\x02");
    out.extend(le16(63));
    out.extend(le16(63));
    out.extend(le16(0));
    out.extend(le16(method));
    out.extend(le32(0));
    out.extend(le32(0));
    out.extend(le32(data.len() as u32));
    out.extend(le32(usize_));
    out.extend(le16(name.len() as u16));
    out.extend([0u8; 12]); // extra, comment, disk, internal attrs
    out.extend(le32(0)); // external attrs
    out.extend(le32(0)); // local header offset
    out.extend(name);
    let cd_len = out.len() as u32 - cd_at;
    out.extend(b"PK\x05\x06");
    out.extend([0u8; 4]);
    out.extend(le16(1));
    out.extend(le16(1));
    out.extend(le32(cd_len));
    out.extend(le32(cd_at));
    out.extend(le16(0));
    out
}

/// `test --memory-limit LIMIT` over `zip`, from a file and from a pipe.
fn assert_zip_test_exits(dir: &Path, zip: &[u8], limit: &str, code: i32, label: &str) {
    let path = dir.join(format!("{label}.zip"));
    std::fs::write(&path, zip).unwrap();
    let out = run_output(&["test", "--memory-limit", limit, path.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(code),
        "{label} file: {}",
        stderr_text(&out)
    );
    let out = run_with_stdin_output(&["test", "--memory-limit", limit, "-"], zip);
    assert_eq!(
        out.status.code(),
        Some(code),
        "{label} pipe: {}",
        stderr_text(&out)
    );
    if code == 6 {
        assert!(
            stderr_text(&out).contains("--memory-limit"),
            "{}",
            stderr_text(&out)
        );
    }
}

/// Finding 3: a zip entry's PPMd model, LZMA dictionary, xz dictionary or
/// zstd window over `--memory-limit` is refused by its declaration (exit
/// 6), as a standalone `.lzma`/`.xz`/`.zst` is, on the indexed and the
/// forward rung — before the decoder allocates it (a 1 KB PPMd zip cost
/// 276 MB). A declaration within the limit is read as before.
#[test]
fn a_zip_entry_decoder_is_held_to_the_memory_limit() {
    let dir = tmp_dir();
    let junk = vec![0x5au8; 1024];
    // PPMd: order 8, 256 MiB model; then 1 MiB.
    let mut ppmd = (7u16 | (255 << 4)).to_le_bytes().to_vec();
    ppmd.extend(&junk);
    assert_zip_test_exits(
        &dir,
        &zip_with_method(98, &ppmd, 4096),
        "1M",
        6,
        "ppmd-256m",
    );
    let mut ppmd = 7u16.to_le_bytes().to_vec();
    ppmd.extend(&junk);
    assert_zip_test_exits(&dir, &zip_with_method(98, &ppmd, 4096), "1M", 5, "ppmd-1m");

    // LZMA: a 1 GiB dictionary for 1 GiB of output; then for 4 KiB of
    // output, which the decoder cuts the dictionary to.
    let mut lzma = vec![9, 20, 5, 0, 0x5d];
    lzma.extend((1u32 << 30).to_le_bytes());
    lzma.extend(&junk);
    assert_zip_test_exits(
        &dir,
        &zip_with_method(14, &lzma, 1 << 30),
        "1M",
        6,
        "lzma-1g",
    );
    assert_zip_test_exits(&dir, &zip_with_method(14, &lzma, 4096), "1M", 5, "lzma-4k");

    // xz: a stream whose first block declares a 64 MiB LZMA2 dictionary.
    let mut xz = vec![
        0xfd, b'7', b'z', b'X', b'Z', 0, 0, 4, 0xe6, 0xd6, 0xb4, 0x46,
    ];
    xz.extend([0x02, 0x00, 0x21, 0x01, 0x1c, 0x00, 0x00, 0x00, 0, 0, 0, 0]);
    xz.extend(&junk);
    assert_zip_test_exits(&dir, &zip_with_method(95, &xz, 4096), "1M", 6, "xz-64m");
    assert_zip_test_exits(&dir, &zip_with_method(95, &xz, 4096), "128M", 5, "xz-under");
}
