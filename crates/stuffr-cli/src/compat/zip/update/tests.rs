use super::*;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use crate::compat::host::{InputReads, Sandbox};
use crate::compat::zip::Flavour;
use crate::compat::zip::sink::FILE_SIZE_LIMIT;

/// A scratch directory, removed on drop (`stuffr-zipupd-<pid>-<tag>-<n>`).
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d =
            std::env::temp_dir().join(format!("stuffr-zipupd-{}-{tag}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Scratch(d)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `zip args` in a sandbox over `dir` in `flavour`: (exit, stdout, stderr,
/// what each input read).
fn run(
    dir: &Path,
    flavour: Flavour,
    args: &[&str],
) -> (i32, String, String, BTreeMap<PathBuf, InputReads>) {
    let reads = Arc::new(Mutex::new(BTreeMap::new()));
    let stdout = Arc::new(Mutex::new(Vec::new()));
    let host = Host::Sandbox(Sandbox {
        dir: dir.to_path_buf(),
        stdin: Some(Vec::new()),
        stdout: stdout.clone(),
        budget: Arc::new(AtomicU64::new(u64::MAX)),
        reads: reads.clone(),
    });
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let env = |_: &str| None;
    let mut err = Vec::new();
    let code = crate::compat::zip::main(flavour, "zip", b"zip", &args, &env, host, &mut err);
    let out = stdout.lock().unwrap().clone();
    let reads = reads.lock().unwrap().clone();
    (
        code,
        String::from_utf8_lossy(&out).into_owned(),
        String::from_utf8_lossy(&err).into_owned(),
        reads,
    )
}

/// The names in `dir`, sorted.
fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// A directory with `a.txt`, a 200 KB `big` and an archive `t.zip` of
/// `a.txt`.
fn with_archive(tag: &str) -> Scratch {
    let s = Scratch::new(tag);
    std::fs::write(s.0.join("a.txt"), b"hello\n").unwrap();
    let mut big = Vec::new();
    let mut x: u32 = 1;
    for _ in 0..200_000 {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
        big.push((x >> 16) as u8);
    }
    std::fs::write(s.0.join("big"), big).unwrap();
    let (code, out, err, _) = run(&s.0, Flavour::Apple, &["t.zip", "a.txt"]);
    assert_eq!(code, 0, "{out} {err}");
    s
}

/// Review Focus 4: a write that fails while an archive is updated (a full
/// disk, a file size limit) ends the run as zip's `bfwrite` ends it, exit
/// 14; the old archive is byte for byte as it was and no temporary is left.
#[test]
fn a_failed_write_mid_update_keeps_the_old_archive() {
    for args in [
        &["t.zip", "big"][..],
        &["-0", "t.zip", "big"],
        &["-u", "t.zip", "a.txt", "big"],
        &["-g", "t.zip", "big"],
    ] {
        let s = with_archive("full");
        let old = std::fs::read(s.0.join("t.zip")).unwrap();
        FILE_SIZE_LIMIT.with(|l| l.set(Some(8 * 1024)));
        let (code, out, _, _) = run(&s.0, Flavour::Apple, args);
        FILE_SIZE_LIMIT.with(|l| l.set(None));
        assert_eq!(code, 14, "{args:?}: {out}");
        assert!(
            out.ends_with("zip error: Output file write failure (write error on zip file)\n"),
            "{args:?}: {out:?}"
        );
        assert_eq!(std::fs::read(s.0.join("t.zip")).unwrap(), old, "{args:?}");
        assert_eq!(names(&s.0), ["a.txt", "big", "t.zip"], "{args:?}");
    }
}

/// Every read of the old archive goes through `Host::track` (the fuzz
/// target's read bound): reading the directory and copying an entry are
/// counted against `t.zip`.
#[test]
fn the_old_archive_is_read_through_track() {
    let s = with_archive("track");
    let len = std::fs::metadata(s.0.join("t.zip")).unwrap().len();
    let (code, out, _, reads) = run(&s.0, Flavour::Apple, &["t.zip", "big"]);
    assert_eq!(code, 0, "{out}");
    let r = reads.get(&s.0.join("t.zip")).expect("t.zip was read");
    assert!(r.opens >= 2, "{r:?}");
    assert!(r.bytes >= len, "{r:?}");
}

/// Deviation 13: an end record cut short after its signature is read as
/// zeros (the C reads its uninitialised stack buffer): an empty archive, to
/// which a name is added.
#[test]
fn an_end_record_cut_short_reads_as_zeros() {
    let s = Scratch::new("cut");
    std::fs::write(s.0.join("a.txt"), b"hello\n").unwrap();
    std::fs::write(s.0.join("t.zip"), b"PK\x05\x06").unwrap();
    let (code, out, _, _) = run(&s.0, Flavour::Apple, &["t.zip", "a.txt"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(out, "  adding: a.txt (stored 0%)\n");
}

/// Deviation 13: `-g` grows a copy of the archive and renames it into
/// place, so a failing test leaves the archive as it was (zip writes into
/// the archive itself and, on the failure, rewrites its old central
/// directory there).
#[test]
fn growing_writes_a_copy() {
    let s = with_archive("grow");
    let old = std::fs::read(s.0.join("t.zip")).unwrap();
    let (code, out, _, _) = run(&s.0, Flavour::Apple, &["-T", "-g", "t.zip", "big"]);
    assert_eq!(code, 8, "{out}");
    assert_eq!(std::fs::read(s.0.join("t.zip")).unwrap(), old);
    assert_eq!(names(&s.0), ["a.txt", "big", "t.zip"]);
    let (code, out, _, _) = run(&s.0, Flavour::Apple, &["-g", "t.zip", "big"]);
    assert_eq!(code, 0, "{out}");
    let new = std::fs::read(s.0.join("t.zip")).unwrap();
    // the old entries stay where they were, the new one follows them
    let cenbeg = old.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
    assert_eq!(new[..cenbeg], old[..cenbeg]);
}

/// Deviation 16: a sandboxed run spawns nothing, so `-T` fails as without
/// `unzip` (and `-TT`'s command is not run); ruling Z3 for Ubuntu too.
#[test]
fn a_sandboxed_test_fails_in_both_flavours() {
    for f in [Flavour::Apple, Flavour::Ubuntu] {
        let s = with_archive("test");
        let (code, out, err, _) = run(&s.0, f, &["-T", "t.zip", "big"]);
        assert_eq!(code, 8, "{f:?} {out}");
        assert!(err.is_empty(), "{err}");
        assert!(out.contains("\ttest of t.zip FAILED\n") || out.contains("test of t.zip FAILED\n"));
        assert_eq!(names(&s.0), ["a.txt", "big", "t.zip"]);
    }
}

/// zip.c:check_unzip_version's `sscanf(buf, "UnZip %f ")`.
#[test]
fn the_unzip_version_is_read_as_sscanf_reads_it() {
    assert_eq!(
        scan_unzip_version(b"UnZip 6.00 of 20 April 2009\n"),
        Some(6.0)
    );
    assert_eq!(scan_unzip_version(b"UnZip5.52 x"), Some(5.52));
    assert_eq!(scan_unzip_version(b"UnZip  1e1x"), Some(10.0));
    assert_eq!(scan_unzip_version(b"UnZip .5"), Some(0.5));
    assert_eq!(scan_unzip_version(b"UnZip x"), None);
    assert_eq!(scan_unzip_version(b"unzip 6.00"), None);
    assert_eq!(scan_unzip_version(b""), None);
}
