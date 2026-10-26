use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use crate::compat::host::{Host, InputReads, Sandbox};
use crate::compat::zip::{EXIT_CODES, Flavour};

/// A scratch directory, removed on drop (`stuffr-zipsplit-<pid>-<tag>-<n>`).
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d =
            std::env::temp_dir().join(format!("stuffr-zipsplit-{}-{tag}-{n}", std::process::id()));
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

struct Ran {
    code: i32,
    out: String,
    reads: BTreeMap<PathBuf, InputReads>,
}

/// `zip args` in a sandbox over `dir`, standard input `stdin`, an output
/// budget of `budget` bytes.
fn run(dir: &Path, flavour: Flavour, args: &[&str], stdin: &[u8], budget: u64) -> Ran {
    let reads = Arc::new(Mutex::new(BTreeMap::new()));
    let stdout = Arc::new(Mutex::new(Vec::new()));
    let host = Host::Sandbox(Sandbox {
        dir: dir.to_path_buf(),
        stdin: Some(stdin.to_vec()),
        stdout: stdout.clone(),
        budget: Arc::new(AtomicU64::new(budget)),
        reads: reads.clone(),
    });
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let env = |_: &str| None;
    let mut err = Vec::new();
    let code = crate::compat::zip::main(flavour, "zip", b"zip", &args, &env, host, &mut err);
    let out = String::from_utf8_lossy(&stdout.lock().unwrap()).into_owned();
    let reads = reads.lock().unwrap().clone();
    Ran { code, out, reads }
}

/// Bytes that do not compress (xorshift).
fn noise(n: usize, mut seed: u64) -> Vec<u8> {
    (0..n)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed >> 24) as u8
        })
        .collect()
}

/// A directory with `a.txt` and 140000 bytes of `big`, split by the
/// sandbox's own zip into `s.z01`, `s.z02`, `s.zip`.
fn split_set(tag: &str, flavour: Flavour) -> Scratch {
    let s = Scratch::new(tag);
    std::fs::write(s.0.join("a.txt"), b"hello\n").unwrap();
    std::fs::write(s.0.join("big"), noise(140_000, 7)).unwrap();
    let r = run(
        &s.0,
        flavour,
        &["-X", "-s", "64k", "s.zip", "big", "a.txt"],
        b"",
        u64::MAX,
    );
    assert_eq!(r.code, 0, "{}", r.out);
    for p in ["s.z01", "s.z02", "s.zip"] {
        assert!(s.0.join(p).exists(), "{p}");
    }
    s
}

/// Every part of a split archive `-F`, `-FF` and a copy read is opened
/// through `Host::track`, and read about once.
#[test]
fn split_parts_are_read_through_track() {
    for flavour in [Flavour::Apple, Flavour::Ubuntu] {
        for args in [
            &["-F", "s.zip", "--out", "f.zip"][..],
            &["-FF", "s.zip", "--out", "f.zip"],
            &["s.zip", "--out", "f.zip"],
        ] {
            let s = split_set("track", flavour);
            let r = run(&s.0, flavour, args, b"", u64::MAX);
            assert_eq!(r.code, 0, "{flavour:?} {args:?}: {}", r.out);
            for p in ["s.z01", "s.z02", "s.zip"] {
                let k = s.0.join(p);
                let got = r
                    .reads
                    .get(&k)
                    .unwrap_or_else(|| panic!("{p} not read: {args:?}"));
                assert!(got.opens >= 1, "{p}");
                assert!(
                    got.bytes <= 4 * got.len + 0x40000,
                    "{flavour:?} {args:?} {p}: {} of {}",
                    got.bytes,
                    got.len
                );
            }
        }
    }
}

/// The end of standard input at a question about a missing part answers
/// `q` (ruling Z5); `-FF`'s single-disk question at the end is "no".
#[test]
fn questions_end_with_standard_input() {
    for flavour in [Flavour::Apple, Flavour::Ubuntu] {
        let s = split_set("eof", flavour);
        std::fs::remove_file(s.0.join("s.z02")).unwrap();
        let r = run(
            &s.0,
            flavour,
            &["-F", "s.zip", "--out", "f.zip"],
            b"",
            u64::MAX,
        );
        assert_eq!(r.code, 9, "{}", r.out);
        assert!(
            r.out
                .ends_with("zip error: Interrupted (Could not find split)\n"),
            "{}",
            r.out
        );
        let r = run(
            &s.0,
            flavour,
            &["-FF", "s.zip", "--out", "f.zip"],
            b"",
            u64::MAX,
        );
        assert_eq!(r.code, 9, "{}", r.out);
        // a damaged archive, a missing one
        std::fs::write(s.0.join("g.zip"), b"PK\x03\x04garbage").unwrap();
        for a in ["g.zip", "nosuch.zip"] {
            let r = run(&s.0, flavour, &["-FF", a, "--out", "f.zip"], b"", u64::MAX);
            assert_eq!(r.code, 0, "{a}: {}", r.out);
            assert!(r.out.contains("could not find split: "), "{a}: {}", r.out);
        }
    }
}

/// `-s`, `-sp` (answers from the sandbox's standard input) and an output
/// budget that runs out mid-split: every part made in the sandbox's
/// directory, no panic, an exit code of the family's.
#[test]
fn splits_are_written_in_a_sandbox() {
    for flavour in [Flavour::Apple, Flavour::Ubuntu] {
        let s = Scratch::new("write");
        std::fs::write(s.0.join("big"), noise(200_000, 3)).unwrap();
        let r = run(
            &s.0,
            flavour,
            &["-s", "64k", "-sp", "-sv", "t.zip", "big"],
            b"\n\n\n",
            u64::MAX,
        );
        assert_eq!(r.code, 0, "{}", r.out);
        assert_eq!(r.out.matches("Opening disk").count(), 3, "{}", r.out);
        for p in ["t.z01", "t.z02", "t.z03", "t.zip"] {
            assert!(s.0.join(p).exists(), "{p}");
        }
        for budget in [1000, 70_000, 150_000] {
            let s = Scratch::new("budget");
            std::fs::write(s.0.join("big"), noise(200_000, 3)).unwrap();
            let r = run(&s.0, flavour, &["-s", "64k", "t.zip", "big"], b"", budget);
            assert!(
                EXIT_CODES.contains(&r.code),
                "{budget}: {} {}",
                r.code,
                r.out
            );
            assert_ne!(r.code, 0, "{budget}");
        }
    }
}

/// `-FF` over hostile bytes ends: signatures everywhere, and a descriptor
/// search over thousands of descriptor signatures whose sizes never agree
/// (each a step back over what it read: work bounded by the input's
/// length times a read).
#[test]
fn ff_over_hostile_bytes_ends() {
    for flavour in [Flavour::Apple, Flavour::Ubuntu] {
        let s = Scratch::new("hostile");
        let mut sigs = Vec::new();
        for i in 0..20_000u32 {
            sigs.extend_from_slice(b"PK\x03\x04");
            sigs.extend_from_slice(&i.to_le_bytes());
        }
        std::fs::write(s.0.join("a.zip"), &sigs).unwrap();
        // a local header with a data descriptor, then descriptor signatures
        let mut d = b"PK\x03\x04\x14\x00\x08\x00\x08\x00".to_vec();
        d.extend_from_slice(&[0; 16]);
        d.extend_from_slice(&[1, 0, 0, 0]);
        d.push(b'x');
        for _ in 0..4096 {
            d.extend_from_slice(b"PK\x07\x08");
        }
        std::fs::write(s.0.join("d.zip"), &d).unwrap();
        for a in ["a.zip", "d.zip"] {
            for args in [
                &["-FF", "-q", a, "--out", "f.zip"][..],
                &["-FF", a, "--out", "f.zip"],
            ] {
                let r = run(&s.0, flavour, args, b"y\n", 8 << 20);
                assert!(EXIT_CODES.contains(&r.code), "{args:?}: {}", r.code);
            }
        }
    }
}
