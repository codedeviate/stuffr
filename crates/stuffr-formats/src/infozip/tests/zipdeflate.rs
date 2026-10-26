//! `deflate.c` and `trees.c` of Zip 3.0: the encoder against the references'
//! own deflate streams.
//!
//! The corpus is generated here (deterministically) and never committed;
//! `tests/data/infozip/zipdeflate/` holds the references' streams for the
//! inputs of at most 64 KiB and a `MANIFEST` of every entry's header fields.
//! Its README states how each was made (`dump_corpus` below writes the
//! inputs).

use std::io::Read;
use std::path::{Path, PathBuf};

use super::fixture;
use crate::infozip::{DeflateSummary, Stop, WSIZE, ZipDeflater, inflate};

/// xorshift64*: the corpus generator. Never change it: the committed
/// streams were made from its output.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A value in `lo..hi`.
    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + (self.next() % (hi - lo) as u64) as usize
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
    "compression",
    "window",
    "deflate",
    "literal",
    "distance",
    "length",
    "block",
    "tree",
    "Huffman",
    "stored",
    "static",
    "dynamic",
    "header",
    "zip",
];

/// Prose-like text: words, spaces, and a newline every 6–14 words.
fn text(rng: &mut Rng, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 16);
    let mut words = 0;
    let mut line = rng.range(6, 15);
    while out.len() < len {
        out.extend_from_slice(WORDS[rng.range(0, WORDS.len())].as_bytes());
        words += 1;
        if words == line {
            out.push(b'\n');
            words = 0;
            line = rng.range(6, 15);
        } else {
            out.push(b' ');
        }
    }
    out.truncate(len);
    out
}

/// A sorted word list, one per line, like `/usr/share/dict/words`.
fn dict(len: usize) -> Vec<u8> {
    let mut rng = Rng(2);
    let mut words = Vec::new();
    let mut total = 0;
    while total < len + len / 8 {
        let n = rng.range(3, 13);
        let w: String = (0..n)
            .map(|_| char::from(b'a' + rng.range(0, 26) as u8))
            .collect();
        total += w.len() + 1;
        words.push(w);
    }
    words.sort();
    words.dedup();
    let mut out = words.join("\n").into_bytes();
    out.truncate(len);
    out
}

fn random(seed: u64, len: usize) -> Vec<u8> {
    let mut rng = Rng(seed);
    (0..len).map(|_| (rng.next() >> 56) as u8).collect()
}

/// Text, random runs, copies of earlier stretches (near and far) and runs
/// of one byte. Every length is a prefix of every longer one.
fn mixed(len: usize) -> Vec<u8> {
    let mut rng = Rng(7);
    let mut out: Vec<u8> = Vec::with_capacity(len + 8192);
    while out.len() < len {
        match rng.range(0, 10) {
            0..=5 => {
                let n = rng.range(50, 3000);
                let t = text(&mut rng, n);
                out.extend_from_slice(&t);
            }
            6 | 7 => {
                let n = rng.range(10, 400);
                for _ in 0..n {
                    out.push((rng.next() >> 56) as u8);
                }
            }
            8 if !out.is_empty() => {
                let from = rng.range(0, out.len());
                let n = rng.range(100, 5000).min(out.len() - from);
                out.extend_from_within(from..from + n);
            }
            _ => {
                let n = rng.range(10, 600);
                let b = (rng.next() >> 56) as u8;
                out.resize(out.len() + n, b);
            }
        }
    }
    out.truncate(len);
    out
}

/// The corpus input `name`.
fn corpus(name: &str) -> Vec<u8> {
    match name {
        "empty" => Vec::new(),
        "one" => b"x".to_vec(),
        "text10k" => text(&mut Rng(1), 10 * 1024),
        "dict300k" => dict(300 * 1024),
        "random40k" => random(4, 40_000),
        "random2m" => random(3, 2 << 20),
        "zeros1m" => vec![0; 1 << 20],
        "big3m" => mixed(3 << 20),
        _ => {
            let n = name
                .strip_prefix("mixed-")
                .and_then(|n| n.parse().ok())
                .unwrap_or_else(|| panic!("no corpus input {name}"));
            mixed(n)
        }
    }
}

/// Every corpus input, small and large.
const SMALL: &[&str] = &[
    "empty",
    "one",
    "text10k",
    "random40k",
    "mixed-32767",
    "mixed-32768",
    "mixed-32769",
    "mixed-65535",
    "mixed-65536",
];
const LARGE: &[&str] = &["mixed-65537", "dict300k", "random2m", "zeros1m", "big3m"];

/// `compress` over `input` at `level`, with zip's stored-file fallback as
/// `seekable`.
fn deflate(input: &[u8], level: u8, seekable: bool) -> (Vec<u8>, DeflateSummary) {
    let mut d = ZipDeflater::new(level);
    d.set_store_fallback(seekable);
    let mut out = Vec::new();
    let s = d.compress(&mut &input[..], &mut out).expect("compress");
    (out, s)
}

fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
    }
    !c
}

/// Writes every corpus input to `$STUFFR_ZIPDEFLATE_CORPUS_OUT`, for the
/// references (README in the fixture directory).
#[test]
#[ignore = "writes the corpus for the fixture README's commands"]
fn dump_corpus() {
    let dir = PathBuf::from(
        std::env::var_os("STUFFR_ZIPDEFLATE_CORPUS_OUT").expect("STUFFR_ZIPDEFLATE_CORPUS_OUT"),
    );
    std::fs::create_dir_all(&dir).unwrap();
    for name in SMALL.iter().chain(LARGE) {
        std::fs::write(dir.join(name), corpus(name)).unwrap();
    }
}

/// One `MANIFEST` line: what a reference wrote for one input.
struct Golden {
    case: String,
    /// `file`: a named archive (seekable); `pipe`: the archive to a pipe
    /// (data descriptors, no stored fallback).
    seekable: bool,
    level: u8,
    method: u16,
    flags: u16,
    crc: u32,
    csize: u64,
    text: bool,
    data: Option<String>,
}

fn manifest() -> Option<Vec<Golden>> {
    let text = String::from_utf8(fixture("zipdeflate/MANIFEST")?).unwrap();
    let mut out = Vec::new();
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let f: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(f.len(), 9, "MANIFEST: {line}");
        out.push(Golden {
            case: f[0].to_owned(),
            seekable: match f[1] {
                "file" => true,
                "pipe" => false,
                m => panic!("MANIFEST mode {m}"),
            },
            level: f[2].parse().unwrap(),
            method: f[3].parse().unwrap(),
            flags: u16::from_str_radix(f[4], 16).unwrap(),
            crc: u32::from_str_radix(f[5], 16).unwrap(),
            csize: f[6].parse().unwrap(),
            text: f[7] == "1",
            data: (f[8] != "-").then(|| f[8].to_owned()),
        });
    }
    Some(out)
}

#[test]
fn matches_zip30_deflate_at_every_level() {
    let Some(goldens) = manifest() else { return };
    // Every small case, both modes' worth where recorded, every level.
    assert!(
        goldens.len() >= SMALL.len() * 9,
        "MANIFEST has {}",
        goldens.len()
    );
    for g in &goldens {
        let what = format!(
            "{} {} -{}",
            g.case,
            if g.seekable { "file" } else { "pipe" },
            g.level
        );
        let input = corpus(&g.case);
        let (out, s) = deflate(&input, g.level, g.seekable);
        let want = match &g.data {
            Some(name) => fixture(&format!("zipdeflate/{name}")).unwrap(),
            None => {
                assert_eq!(g.method, 0, "{what}: deflated without data");
                input.clone()
            }
        };
        assert!(
            out == want,
            "{what}: {} bytes, want {}",
            out.len(),
            want.len()
        );
        assert_eq!(s.stored, g.method == 0, "{what}: method");
        assert_eq!(s.out_bytes, g.csize, "{what}: csize");
        assert_eq!(s.in_bytes, input.len() as u64, "{what}: in_bytes");
        assert_eq!(s.crc32, g.crc, "{what}: crc");
        // An empty named file never reaches deflate: zipup.c stores it
        // (`q == 0`), so no lm_init sets its flags. With descriptors (the
        // pipe mode) zipup.c puts back the flags it wrote before deflating
        // (`z->flg = z->lflg`), so the archive has bits 1-2 clear although
        // lm_init set them: a zipup.c matter, not the encoder's.
        if g.seekable && (g.method == 8 || !input.is_empty()) {
            assert_eq!(s.gp_flags, g.flags & 6, "{what}: flags bits 1-2");
        }
        assert_eq!(s.text, g.text, "{what}: internal attributes");
    }
}

#[test]
fn round_trips_through_infozip_inflate() {
    let mut rng = Rng(0x5eed);
    for level in 1..=9u8 {
        let mut inputs = vec![Vec::new(), b"ab".to_vec()];
        for _ in 0..3 {
            let len = rng.range(0, 300 * 1024);
            let mut v = mixed(len + 1);
            // Vary the content: shift the prefix by a random amount.
            let cut = rng.range(0, v.len());
            v.rotate_left(cut);
            v.truncate(len);
            inputs.push(v);
        }
        inputs.push(random(level.into(), rng.range(0, 300 * 1024)));
        for input in &inputs {
            for seekable in [true, false] {
                let (out, s) = deflate(input, level, seekable);
                assert_eq!(s.out_bytes, out.len() as u64);
                assert_eq!(s.in_bytes, input.len() as u64);
                assert_eq!(s.crc32, crc32(input));
                let back = if s.stored {
                    out
                } else {
                    let mut back = Vec::new();
                    let mut window = vec![0; WSIZE];
                    let r = inflate(
                        &mut out.iter(),
                        false,
                        &mut window,
                        &mut |c: &[u8]| -> Result<(), ()> {
                            back.extend_from_slice(c);
                            Ok(())
                        },
                        &mut |_| {},
                    );
                    assert!(
                        matches!(r, Ok(())),
                        "-{level} len {}: {:?}",
                        input.len(),
                        r.err().map(|e| match e {
                            Stop::Code(c) => c,
                            _ => -1,
                        })
                    );
                    back
                };
                assert!(back == *input, "-{level} len {} differs", input.len());
            }
        }
    }
}

/// A one-byte-at-a-time reader: `compress` must fill as a regular file's
/// `read()` does, whatever the reader returns per call.
struct Trickle<'a>(&'a [u8]);

impl Read for Trickle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.0.is_empty() || buf.is_empty() {
            return Ok(0);
        }
        buf[0] = self.0[0];
        self.0 = &self.0[1..];
        Ok(1)
    }
}

#[test]
fn short_reads_do_not_change_the_stream() {
    let input = mixed(70_000);
    let (whole, _) = deflate(&input, 6, true);
    let mut d = ZipDeflater::new(6);
    let mut out = Vec::new();
    d.compress(&mut Trickle(&input), &mut out).unwrap();
    assert!(out == whole);
}

/// Records the size of every `write` (the C's `flush_outbuf` pieces).
struct Pieces(Vec<u8>, Vec<usize>);

impl std::io::Write for Pieces {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(buf);
        self.1.push(buf.len());
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// `set_one_read`: one `read` per request. Over a reader that answers each
/// request whole (a regular file) the stream is the filled one; over a
/// one-byte reader each request takes one byte, and the stream is still a
/// valid deflate of the same input with the same CRC and size.
#[test]
fn one_read_per_request() {
    let input = mixed(70_000);
    let (whole, ws) = deflate(&input, 6, true);
    let mut d = ZipDeflater::new(6);
    d.set_one_read(true);
    let mut out = Vec::new();
    let s = d.compress(&mut &input[..], &mut out).unwrap();
    assert!(out == whole);
    assert_eq!((s.crc32, s.in_bytes), (ws.crc32, ws.in_bytes));
    let mut d = ZipDeflater::new(6);
    d.set_one_read(true);
    let mut out = Vec::new();
    let s = d.compress(&mut Trickle(&input), &mut out).unwrap();
    assert_eq!((s.crc32, s.in_bytes), (ws.crc32, ws.in_bytes));
    let mut back = Vec::new();
    let mut window = vec![0; WSIZE];
    let r = inflate(
        &mut out.iter(),
        false,
        &mut window,
        &mut |c: &[u8]| -> Result<(), ()> {
            back.extend_from_slice(c);
            Ok(())
        },
        &mut |_| {},
    );
    assert!(matches!(r, Ok(())));
    assert!(back == input);
}

/// The output is written in trees.c's pieces: `out_buf` is 1024 bytes and
/// `PUTSHORT` flushes it at 1023, so no piece of coded data is longer than
/// 1024 bytes; a stored block's data is one piece of its own. The pieces
/// make the same stream.
#[test]
fn output_is_written_in_the_c_pieces() {
    let input = mixed(200_000);
    let (whole, _) = deflate(&input, 6, true);
    let mut d = ZipDeflater::new(6);
    let mut p = Pieces(Vec::new(), Vec::new());
    d.compress(&mut &input[..], &mut p).unwrap();
    assert!(p.0 == whole);
    assert!(p.1.len() > 10, "{:?}", p.1);
    assert!(p.1.iter().all(|&n| n > 0));
    let random = random(9, 100_000);
    let mut d = ZipDeflater::new(6);
    d.set_store_fallback(false);
    let mut p = Pieces(Vec::new(), Vec::new());
    d.compress(&mut &random[..], &mut p).unwrap();
    // incompressible: stored blocks, each block's data one write
    assert!(p.1.iter().any(|&n| n > 1024), "{:?}", p.1);
}

/// `set_encrypting`: a stored block's data is handed on in `out_size`
/// (1024-byte) pieces, as trees.c's `copy_block` copies it through
/// `out_buf` for zip's in-place encryption; the stream is the same.
#[test]
fn an_encrypted_entrys_stored_blocks_are_written_in_out_size_pieces() {
    let noise = random(9, 100_000);
    let mut plain = ZipDeflater::new(6);
    plain.set_store_fallback(false);
    let mut want = Pieces(Vec::new(), Vec::new());
    plain.compress(&mut &noise[..], &mut want).unwrap();
    let mut d = ZipDeflater::new(6);
    d.set_store_fallback(false);
    d.set_encrypting(true);
    let mut p = Pieces(Vec::new(), Vec::new());
    d.compress(&mut &noise[..], &mut p).unwrap();
    assert!(p.0 == want.0);
    assert!(p.1.iter().all(|&n| n <= 1024), "{:?}", p.1);
    // the stored file of a small input that does not pay: 1024, 1024, rest
    let small = random(3, 3000);
    let mut d = ZipDeflater::new(6);
    d.set_encrypting(true);
    let mut p = Pieces(Vec::new(), Vec::new());
    let s = d.compress(&mut &small[..], &mut p).unwrap();
    assert!(s.stored);
    assert!(p.0 == small);
    assert_eq!(p.1, vec![1024, 1024, 952]);
}

/// `slides` counts `fill_window`'s slides: none for a small input, one per
/// 32 KiB or so of a large one.
#[test]
fn slides_are_counted() {
    let (_, s) = deflate(&mixed(10_000), 6, true);
    assert_eq!(s.slides, 0);
    let (_, s) = deflate(&mixed(1_000_000), 6, true);
    assert!((25..=31).contains(&s.slides), "{}", s.slides);
}

#[test]
fn gp_flags_follow_lm_init() {
    for level in 1..=9u8 {
        let (_, s) = deflate(b"hello hello hello hello", level, true);
        let want = match level {
            1 | 2 => 4,
            8 | 9 => 2,
            _ => 0,
        };
        assert_eq!(s.gp_flags, want, "-{level}");
    }
}

/// The reference zip for the large cases: `/usr/bin/zip` on macOS, `zip` on
/// `PATH` elsewhere, and it must say Zip 3.0. Absent, the test skips
/// locally and panics under `CI`, where proving nothing must not pass.
fn require_reference_zip() -> Option<PathBuf> {
    let candidate = if cfg!(target_os = "macos") {
        Some(PathBuf::from("/usr/bin/zip"))
    } else {
        std::env::var_os("PATH").and_then(|p| {
            std::env::split_paths(&p)
                .map(|d| d.join("zip"))
                .find(|p| p.is_file())
        })
    };
    let ok = candidate.filter(|p| {
        std::process::Command::new(p)
            .arg("-v")
            .output()
            .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("This is Zip 3.0"))
    });
    if ok.is_none() {
        assert!(
            std::env::var_os("CI").is_none(),
            "no reference Zip 3.0 found: the large deflate cases proved nothing"
        );
        eprintln!("note: no reference Zip 3.0; skipping the large deflate cases");
    }
    ok
}

/// A scratch directory `stuffr-zipdeflate-<pid>-<tag>`, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir =
            std::env::temp_dir().join(format!("stuffr-zipdeflate-{}-{tag}", std::process::id()));
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

/// The first entry of `zip`: (flags, method, crc, data).
fn first_entry(zip: &[u8]) -> (u16, u16, u32, &[u8]) {
    let flags = u16::from_le_bytes([zip[6], zip[7]]);
    let method = u16::from_le_bytes([zip[8], zip[9]]);
    let crc = u32::from_le_bytes(zip[14..18].try_into().unwrap());
    (flags, method, crc, super::first_entry_data(zip))
}

fn reference_entry(zip_bin: &Path, dir: &Path, name: &str, level: u8) -> Vec<u8> {
    let archive = dir.join(format!("{name}-{level}.zip"));
    let _ = std::fs::remove_file(&archive);
    let st = std::process::Command::new(zip_bin)
        .current_dir(dir)
        .arg("-X")
        .arg("-q")
        .arg(format!("-{level}"))
        .arg(&archive)
        .arg(name)
        .status()
        .unwrap();
    assert!(st.success(), "{name} -{level}: zip {st}");
    let zip = std::fs::read(&archive).unwrap();
    let _ = std::fs::remove_file(&archive);
    zip
}

#[test]
fn the_reference_agrees_on_large_inputs() {
    let Some(zip_bin) = require_reference_zip() else {
        return;
    };
    let scratch = Scratch::new("large");
    for name in LARGE {
        let input = corpus(name);
        std::fs::write(scratch.0.join(name), &input).unwrap();
        for level in 1..=9u8 {
            let zip = reference_entry(&zip_bin, &scratch.0, name, level);
            let (flags, method, crc, data) = first_entry(&zip);
            let (out, s) = deflate(&input, level, true);
            let want: &[u8] = if method == 0 { &input } else { data };
            assert!(
                out == want,
                "{name} -{level}: {} bytes, want {}",
                out.len(),
                want.len()
            );
            assert_eq!(s.stored, method == 0, "{name} -{level}");
            assert_eq!(s.crc32, crc, "{name} -{level}");
            assert_eq!(s.gp_flags, flags & 6, "{name} -{level}");
        }
        let _ = std::fs::remove_file(scratch.0.join(name));
    }
}
