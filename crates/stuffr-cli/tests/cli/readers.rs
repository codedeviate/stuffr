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
    for (archive, verb_codes) in [
        (&bad, [("list", 5), ("test", 5), ("unpack", 5)]),
        (&huge, [("list", 0), ("test", 6), ("unpack", 6)]),
    ] {
        for (verb, code) in verb_codes {
            let dest = dir.join(format!("out-{verb}"));
            let p = archive.to_str().unwrap();
            let out = match verb {
                "unpack" => run_output(&["unpack", "-C", dest.to_str().unwrap(), p]),
                _ => run_output(&[verb, p]),
            };
            assert_eq!(
                out.status.code(),
                Some(code),
                "{verb} {}: {}",
                archive.display(),
                stderr_text(&out)
            );
            assert!(!dest.join("GNUSparseFile.0").exists());
        }
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
