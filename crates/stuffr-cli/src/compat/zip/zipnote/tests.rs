//! `zipnote` and `zipsplit` in a sandbox: the pieces of their ports, and
//! hostile archives (every truncation and a byte flipped at every offset)
//! that must end cleanly. The references are compared by
//! `tests/compat_zip_helpers.rs`.

use std::ffi::OsString;
use std::path::PathBuf;

use crate::compat::zip::{Flavour, run_in_counted};

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d =
            std::env::temp_dir().join(format!("stuffr-zipnote-{}-{tag}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Scratch(d)
    }

    fn names(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(&self.0)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(
    s: &Scratch,
    f: Flavour,
    name: &str,
    args: &[&str],
    stdin: &[u8],
) -> (i32, Vec<u8>, Vec<u8>) {
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let (c, o, e, _) = run_in_counted(f, &s.0, name, &args, stdin);
    (c, o, e)
}

const FLAVOURS: [Flavour; 2] = [Flavour::Apple, Flavour::Ubuntu];

/// A directory with `t.zip` of `a.txt`, `b.txt`, `c` (stored and deflated).
fn with_archive(tag: &str, f: Flavour) -> Scratch {
    let s = Scratch::new(tag);
    std::fs::write(s.0.join("a.txt"), b"hello\n").unwrap();
    let b: Vec<u8> = (1..=50)
        .flat_map(|i| format!("line {i} of the b file, some text to compress\n").into_bytes())
        .collect();
    std::fs::write(s.0.join("b.txt"), b).unwrap();
    std::fs::write(s.0.join("c"), b"c\n").unwrap();
    let (code, ..) = run(&s, f, "zip", &["-q", "t.zip", "a.txt", "b.txt", "c"], b"");
    assert_eq!(code, 0);
    s
}

#[test]
fn putclean_filters_and_escapes() {
    let mut o = Vec::new();
    super::putclean(&mut o, b"a@b\\c\td\r\x1b\ne");
    assert_eq!(
        o,
        b"a\\@b\\\\c\td\n"
            .iter()
            .copied()
            .chain(*b"e\n")
            .collect::<Vec<u8>>()
    );
    let mut o = Vec::new();
    super::putclean(&mut o, b"");
    assert!(o.is_empty(), "nothing for no text");
    let mut o = Vec::new();
    super::putclean(&mut o, b"x\n");
    assert_eq!(o, b"x\n");
    let mut o = Vec::new();
    super::putclean(&mut o, b"\x01");
    assert!(o.is_empty(), "filtered characters leave nothing to end");
}

#[test]
fn catalloc_unescapes_and_joins_with_crlf_after_text() {
    let mut c = Vec::new();
    super::catalloc(&mut c, b"");
    super::catalloc(&mut c, b"one \\@ \\\\ end\\");
    super::catalloc(&mut c, b"two");
    assert_eq!(c, b"one @ \\ end\\\r\ntwo");
}

#[test]
fn simple_splits_as_the_c_does() {
    let mut a = vec![5, 5, 5, 5];
    assert_eq!(super::super::zipsplit::simple_for_tests(&mut a, 10, 0), 2);
    assert_eq!(a, [0, 0, 1, 1]);
    let mut a = vec![6, 5, 4, 5];
    assert_eq!(super::super::zipsplit::simple_for_tests(&mut a, 10, 0), 3);
    assert_eq!(a, [0, 1, 1, 2]);
}

#[test]
fn a_missing_or_split_archive_is_the_signal_the_c_dies_of() {
    for f in FLAVOURS {
        let s = with_archive("miss", f);
        for name in ["zipnote", "zipsplit"] {
            let (code, o, e) = run(&s, f, name, &["nosuch.zip"], b"");
            assert_eq!(code, 9, "{name}");
            let (text, other) = if name == "zipnote" {
                (&e, &o)
            } else {
                (&o, &e)
            };
            assert_eq!(
                String::from_utf8_lossy(text),
                format!("\n{name} error: Interrupted (aborting)\n")
            );
            assert!(other.is_empty());
        }
    }
}

/// Every truncation and a flipped byte at every offset of a small archive:
/// no panic, no exit 1, no temporary or part left behind after a failure,
/// and the archive as it was unless the run succeeded.
#[test]
fn hostile_archives_end_cleanly() {
    for f in FLAVOURS {
        let base = with_archive("hostile", f);
        let good = std::fs::read(base.0.join("t.zip")).unwrap();
        let mut variants: Vec<Vec<u8>> = (0..good.len()).map(|n| good[..n].to_vec()).collect();
        for i in 0..good.len() {
            let mut v = good.clone();
            v[i] ^= 0xff;
            variants.push(v);
        }
        let jobs: [(&str, &[&str], &[u8]); 4] = [
            ("zipnote", &["t.zip"], b""),
            ("zipnote", &["-w", "t.zip"], b"@ a.txt\nnew\n@ (comment above this line)\n@ c\n@=d\n@ (comment above this line)\n@ (zip file comment below this line)\nz\n"),
            ("zipsplit", &["-t", "t.zip"], b""),
            ("zipsplit", &["-n", "400", "-i", "t.zip"], b""),
        ];
        for (n, v) in variants.iter().enumerate() {
            for (name, args, stdin) in jobs {
                let s = Scratch::new("h");
                std::fs::write(s.0.join("t.zip"), v).unwrap();
                let before = s.names();
                let (code, ..) = run(&s, f, name, args, stdin);
                assert_ne!(code, 1, "{name} {args:?} variant {n}");
                assert!(code <= 19, "{name} {args:?} variant {n}: {code}");
                let after = std::fs::read(s.0.join("t.zip")).unwrap();
                if name == "zipnote" && args[0] != "-w" || args.contains(&"-t") || code != 0 {
                    if name == "zipnote" {
                        assert_eq!(&after, v, "{name} {args:?} variant {n} changed it");
                    }
                    if code != 0 {
                        assert_eq!(s.names(), before, "{name} {args:?} variant {n}: left files");
                    }
                }
            }
        }
    }
}
