//! `zlib_c::RawDeflate`, the C-zlib raw-deflate encoder behind `zlib-c`.
//!
//! The Apple gzip personality's promise is byte-identical output on the C
//! tier, and `/usr/bin/gzip` is stock zlib 1.2.12 driven as
//! `deflateInit2(level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY)`. The fixture
//! `data/zlib_c/expected.txt` holds, for five inputs at levels 1-9, the
//! length and CRC32 of the raw deflate body `/usr/bin/gzip -n -c -<level>`
//! emitted (header and trailer stripped): `<input> <level> <len> <crc32>`.
//! Length plus CRC32 guards against an accidental difference, the only kind
//! this fixture exists for. The inputs are generated here, deterministically,
//! so nothing depends on the machine: no `/usr/share/dict`, no `/bin/ls`.
//!
//! On macOS `fixture_is_still_what_usr_bin_gzip_emits` regenerates the
//! fixture from the installed binary and compares, so the fixture is proven
//! current wherever the oracle exists; its failure message carries the full
//! regenerated text.
#![cfg(feature = "zlib-c")]

use std::io::{self, Write};
use stuffr_formats::zlib_c::RawDeflate;

/// splitmix64: a fixed, seeded generator, so every input is the same on every
/// machine and every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const WORDS: &[&str] = &[
    "the",
    "of",
    "and",
    "to",
    "in",
    "a",
    "is",
    "that",
    "for",
    "it",
    "as",
    "was",
    "with",
    "be",
    "by",
    "on",
    "not",
    "he",
    "this",
    "are",
    "or",
    "his",
    "from",
    "at",
    "which",
    "but",
    "have",
    "an",
    "had",
    "they",
    "you",
    "were",
    "their",
    "one",
    "all",
    "we",
    "can",
    "her",
    "has",
    "there",
    "been",
    "if",
    "more",
    "when",
    "will",
    "would",
    "who",
    "so",
    "no",
    "archive",
    "compress",
    "stream",
    "member",
    "header",
    "trailer",
    "deflate",
    "window",
    "match",
    "literal",
    "length",
    "distance",
    "huffman",
    "block",
    "static",
    "dynamic",
    "stored",
    "checksum",
    "adler",
    "crc",
    "level",
    "strategy",
    "buffer",
    "output",
    "input",
    "flush",
    "finish",
    "reset",
    "gzip",
    "zlib",
    "bzip2",
    "xz",
    "lzma",
    "tar",
    "cpio",
    "zip",
    "Apple",
    "GNU",
    "BSD",
    "Darwin",
    "Linux",
    "kernel",
    "file",
    "directory",
    "symlink",
    "mode",
    "owner",
    "mtime",
    "name",
];

/// A fixed pseudo-random word list: ~200 KB of words, spaces and lines.
fn text() -> Vec<u8> {
    let mut r = Rng(0x7465_7874);
    let mut out = Vec::new();
    while out.len() < 200_000 {
        let line = 3 + r.below(12);
        for i in 0..line {
            if i > 0 {
                out.push(b' ');
            }
            out.extend_from_slice(WORDS[r.below(WORDS.len())].as_bytes());
        }
        out.push(b'\n');
    }
    out
}

/// A fixed byte pattern shaped like a binary: 64-byte records with a
/// counter, zero padding and a low-entropy tail. 128 KiB.
fn binary() -> Vec<u8> {
    (0..128 * 1024usize)
        .map(|i| {
            let rec = (i / 64) as u32;
            match i % 64 {
                o @ 0..4 => rec.to_le_bytes()[o],
                4..24 => 0,
                24..40 => (0x48 + (i % 7)) as u8,
                _ => (((i * 31) ^ (i >> 7)) & 0x3f) as u8,
            }
        })
        .collect()
}

/// 50 KB of seeded random bytes: incompressible, so stored blocks.
fn random() -> Vec<u8> {
    let mut r = Rng(0x7261_6e64);
    (0..50_000).map(|_| r.next() as u8).collect()
}

fn abc() -> Vec<u8> {
    b"abc".repeat(100_000)
}

#[cfg(feature = "gzip")]
fn input(name: &str) -> Vec<u8> {
    match name {
        "text" => text(),
        "binary" => binary(),
        "random" => random(),
        "empty" => Vec::new(),
        "abc" => abc(),
        other => panic!("unknown fixture input {other}"),
    }
}

#[cfg(feature = "gzip")]
const INPUTS: [&str; 5] = ["text", "binary", "random", "empty", "abc"];

fn deflate(data: &[u8], level: u32) -> Vec<u8> {
    let mut d = RawDeflate::new(Vec::new(), level).expect("level 1..=9");
    d.write_all(data).unwrap();
    d.finish().unwrap()
}

#[cfg(feature = "gzip")]
fn crc32(data: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(data);
    c.sum()
}

#[cfg(feature = "gzip")]
fn line(name: &str, level: u32, body: &[u8]) -> String {
    format!("{name} {level} {} {:08x}", body.len(), crc32(body))
}

#[cfg(feature = "gzip")]
const EXPECTED: &str = include_str!("data/zlib_c/expected.txt");

#[cfg(feature = "gzip")]
#[test]
fn matches_apple_gzip_at_every_level() {
    let lines: Vec<&str> = EXPECTED.lines().collect();
    assert_eq!(lines.len(), 45, "five inputs at nine levels");
    for want in lines {
        let mut f = want.split(' ');
        let name = f.next().unwrap();
        let level: u32 = f.next().unwrap().parse().unwrap();
        let body = deflate(&input(name), level);
        assert_eq!(line(name, level, &body), want);
    }
}

#[test]
fn streams_in_small_writes() {
    for (data, level) in [(text(), 6), (binary(), 9), (random(), 1), (abc(), 4)] {
        let whole = deflate(&data, level);
        let mut d = RawDeflate::new(Vec::new(), level).unwrap();
        for b in &data {
            assert_eq!(d.write(std::slice::from_ref(b)).unwrap(), 1);
        }
        assert_eq!(d.finish().unwrap(), whole, "level {level}");
    }
}

#[test]
fn drop_without_finish_does_not_leak_or_crash() {
    let data = text();
    for i in 0..200usize {
        let mut d = RawDeflate::new(Vec::new(), 1 + (i % 9) as u32).unwrap();
        if i % 2 == 0 {
            d.write_all(&data[..(i * 997) % data.len()]).unwrap();
        }
        drop(d);
    }
    // And after a failed finish: the writer refuses, finish errors, and the
    // drop that follows still ends the stream exactly once.
    struct Refuses;
    impl Write for Refuses {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("refused"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut d = RawDeflate::new(Refuses, 6).unwrap();
    let _ = d.write_all(&data);
    assert!(d.finish().is_err());
}

#[test]
fn rejects_level_0_and_10() {
    for level in [0, 10, u32::MAX] {
        let e = RawDeflate::new(Vec::new(), level).err().expect("refused");
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "level {level}");
    }
}

/// Regenerates the fixture from `/usr/bin/gzip` and compares, so a stale
/// fixture is caught on any Mac. The message carries the regenerated text.
#[cfg(all(target_os = "macos", feature = "gzip"))]
#[test]
fn fixture_is_still_what_usr_bin_gzip_emits() {
    let mut fresh = String::new();
    for name in INPUTS {
        let data = input(name);
        for level in 1..=9u32 {
            let gz = usr_bin_gzip(&data, level);
            assert!(gz.len() >= 18, "{name} {level}: short output");
            assert_eq!(&gz[..4], &[0x1f, 0x8b, 8, 0], "{name} {level}: header");
            let body = &gz[10..gz.len() - 8];
            fresh.push_str(&line(name, level, body));
            fresh.push('\n');
        }
    }
    assert!(
        fresh == EXPECTED,
        "fixture is stale; /usr/bin/gzip now gives:\n{fresh}"
    );
}

#[cfg(all(target_os = "macos", feature = "gzip"))]
fn usr_bin_gzip(data: &[u8], level: u32) -> Vec<u8> {
    use std::process::{Command, Stdio};
    let mut child = Command::new("/usr/bin/gzip")
        .args(["-n", "-c", &format!("-{level}")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /usr/bin/gzip");
    let mut stdin = child.stdin.take().unwrap();
    let data = data.to_vec();
    let feeder = std::thread::spawn(move || stdin.write_all(&data));
    let out = child.wait_with_output().unwrap();
    feeder.join().unwrap().unwrap();
    assert!(out.status.success(), "/usr/bin/gzip -{level} failed");
    out.stdout
}
