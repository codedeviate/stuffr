//! `lz4_opts`' unit tests. The C tier's bytes are pinned against the lz4
//! 1.10.0 CLI (and zstd 1.5.7's `--format=lz4`) through a vendored table of
//! digests, `tests/data/lz4_opts/ref.txt`; the binary fixtures beside it are
//! the reference's own output, which the pure tier must read. The `README`
//! there says how to regenerate both.

use super::*;

/// A fixed 64-bit LCG (Knuth's MMIX constants).
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) as u32
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
    "frame",
    "block",
    "stream",
    "lz4",
    "legacy",
    "checksum",
    "dictionary",
    "compress",
    "header",
    "linked",
    "independent",
];

/// `n` bytes of LCG word text.
fn text(n: usize, seed: u64) -> Vec<u8> {
    let mut g = Lcg(seed);
    let mut out = Vec::with_capacity(n + 16);
    while out.len() < n {
        let w = WORDS[g.next() as usize % WORDS.len()];
        out.extend_from_slice(w.as_bytes());
        out.push(if g.next().is_multiple_of(13) {
            b'\n'
        } else {
            b' '
        });
    }
    out.truncate(n);
    out
}

/// 64 KiB of pseudo-binary: runs, small integers, repeats.
fn bin() -> Vec<u8> {
    let mut g = Lcg(0xb1);
    let mut out = Vec::with_capacity(64 << 10);
    while out.len() < 64 << 10 {
        match g.next() % 4 {
            0 => out.extend(std::iter::repeat_n(
                (g.next() % 256) as u8,
                (g.next() % 40) as usize,
            )),
            1 => out.extend_from_slice(&(g.next() % 1000).to_le_bytes()),
            2 => {
                let back = (g.next() as usize % 4096).min(out.len());
                let len = (g.next() as usize % 64).min(back);
                let start = out.len() - back;
                for i in 0..len {
                    out.push(out[start + i]);
                }
            }
            _ => out.push((g.next() % 256) as u8),
        }
    }
    out.truncate(64 << 10);
    out
}

/// `n` LCG bytes: incompressible.
fn rand(n: usize, seed: u64) -> Vec<u8> {
    let mut g = Lcg(seed);
    (0..n).map(|_| (g.next() >> 7) as u8).collect()
}

/// The fixture table's inputs: spike S1's four, a 9 MiB text that is
/// streamed in three 4 MiB jobs, and exactly one job's worth (the smallest
/// input that is streamed rather than compressed in one shot).
fn inputs() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("text", text(300_000, 0x7e47)),
        ("bin", bin()),
        ("rand", rand(50_000, 0x5eed)),
        ("empty", Vec::new()),
        ("big", text(9 << 20, 0xb16)),
        ("four", text(FRAME_CHUNK, 0xf0)),
    ]
}

/// The `-D` dictionaries the fixtures name.
fn dictionary(name: &str) -> Vec<u8> {
    match name {
        "d100" => text(100 << 10, 0xd100),
        "d10" => text(10 << 10, 0xd10),
        _ => panic!("no dictionary {name}"),
    }
}

/// Encodes `data` through `o`, fed `chunk` bytes at a time.
fn encode_chunked(o: &EncodeOptions, data: &[u8], chunk: usize) -> Vec<u8> {
    let mut e = Encoder::new(o).unwrap();
    let mut out = Vec::new();
    for c in data.chunks(chunk.max(1)) {
        e.update(c, &mut out).unwrap();
    }
    e.finish(&mut out).unwrap();
    out
}

/// Encodes `data` through `o` in 64 KiB slices.
fn encode(o: &EncodeOptions, data: &[u8]) -> Vec<u8> {
    encode_chunked(o, data, 64 << 10)
}

/// SHA-256 (FIPS 180-4), small and slow, for the fixture's digests.
fn sha256(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for block in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, word) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

/// The reference `lz4` 1.10.0, if this machine has it.
#[cfg(unix)]
fn reference() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("STUFFR_LZ4_REFERENCE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/opt/homebrew/opt/lz4/bin/lz4".into());
    let v = std::process::Command::new(&path).arg("-V").output().ok()?;
    let banner =
        String::from_utf8_lossy(&v.stdout).into_owned() + &String::from_utf8_lossy(&v.stderr);
    banner.contains("lz4 v1.10.0").then_some(path)
}

/// `lz4 -q -c <args> FILE` (or `< pipe` when `file` is `None`, with
/// `input` written to its stdin); its stdout, or `None` if it failed.
#[cfg(unix)]
fn run_reference(
    lz4: &std::path::Path,
    args: &[&str],
    file: Option<&std::path::Path>,
    input: &[u8],
) -> Option<Vec<u8>> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut cmd = Command::new(lz4);
    cmd.args(["-q", "-c"])
        .args(args)
        .env_remove("LZ4_CLEVEL")
        .env_remove("LZ4_NBWORKERS")
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(f) = file {
        cmd.arg(f).stdin(Stdio::null());
    } else {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd.spawn().ok()?;
    let writer = child.stdin.take().map(|mut stdin| {
        let input = input.to_vec();
        std::thread::spawn(move || stdin.write_all(&input))
    });
    let out = child.wait_with_output().ok()?;
    if let Some(w) = writer {
        let _ = w.join();
    }
    out.status.success().then_some(out.stdout)
}

/// A scratch directory under the system temp dir, removed on drop.
#[cfg(unix)]
struct Scratch(std::path::PathBuf);

#[cfg(unix)]
impl Scratch {
    fn new(tag: &str) -> Scratch {
        let p = std::env::temp_dir().join(format!(
            "stuffr-lz4-opts-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Scratch(p)
    }
}

#[cfg(unix)]
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `lz4 -d -c` (with `-D dict` if given) over `input`; stdout, or None.
#[cfg(all(unix, not(feature = "lz4-c")))]
fn reference_decode(
    lz4: &std::path::Path,
    input: &[u8],
    dict: Option<&std::path::Path>,
) -> Option<Vec<u8>> {
    let mut args = vec!["-d"];
    let ds;
    if let Some(d) = dict {
        ds = d.to_str().unwrap().to_owned();
        args.extend(["-D", &ds]);
    }
    run_reference(lz4, &args, None, input)
}

/// The CLI flags the fixture table covers, compressing a file.
const FILE_FLAGS: &[&str] = &[
    "-1",
    "-9",
    "-12",
    "--fast=3",
    "-2",
    "-BD",
    "-B4",
    "-B5",
    "-B4 -BD",
    "-B4 -BD -9",
    "-B5 -BD",
    "-B6 -BD -BX",
    "-BD -12",
    "-B4 -BD --fast=4",
    "-B4 -BD -2 --content-size --no-frame-crc",
    "-BX",
    "-B4 -BX",
    "--no-frame-crc",
    "--content-size",
    "-12 --favor-decSpeed",
    "-l",
    "-l -9",
    "-l --fast=3",
    "-l -2",
    "-B32",
    "-B100000",
    "-D d100",
    "-9 -D d100",
    "-BD -D d100",
    "-B4 -D d100",
    "-B4 -BD -D d100",
    "-B4 -BD -9 -D d100",
    "-D d10",
    "-B4 -BD -D d10",
];

/// The flags the table covers with the input on a pipe, where the CLI
/// cannot know the content size.
const STDIN_FLAGS: &[&str] = &["-1", "-BD", "--content-size"];

/// zstd's `--format=lz4` levels the table covers (spike S4).
const ZSTD_LEVELS: &[i32] = &[1, 3, 9, 19];

/// What the lz4 CLI hands this module for `flags` over an input of `len`
/// bytes (`stdin`: from a pipe, so no content size).
fn options_for(flags: &str, len: usize, stdin: bool) -> EncodeOptions {
    let mut o = EncodeOptions::default();
    let mut it = flags.split_whitespace();
    while let Some(f) = it.next() {
        match f {
            "-BD" => o.block_linked = true,
            "-BX" => o.block_checksum = true,
            "-l" => o.legacy = true,
            "--no-frame-crc" => o.content_checksum = false,
            "--content-size" => o.content_size = (!stdin).then_some(len as u64),
            "--favor-decSpeed" => o.favor_dec_speed = true,
            "-D" => o.dictionary = Some(dictionary(it.next().unwrap())),
            _ if f.starts_with("--fast=") => o.level = -f[7..].parse::<i32>().unwrap(),
            _ if f.starts_with("-B") => {
                let n: u32 = f[2..].parse().unwrap();
                match BlockSizeId::from_id(n as u8).filter(|_| n <= 7) {
                    Some(id) => o.block_size = id,
                    None => o.block_bytes = Some(n),
                }
            }
            _ => o.level = f[1..].parse().unwrap(),
        }
    }
    o
}

/// What zstd's `--format=lz4 -LEVEL` writes for a file of `len` bytes, as
/// [`Encoder::new_plain`]'s options (spike S4).
#[cfg(feature = "lz4-c")]
fn zstd_options(level: i32, len: usize) -> EncodeOptions {
    EncodeOptions {
        level: level.min(12),
        block_size: BlockSizeId::Max64Kb,
        block_linked: true,
        content_size: Some(len as u64),
        ..EncodeOptions::default()
    }
}

/// Encodes `data` with [`Encoder::new_plain`], in `chunk`-byte slices.
fn encode_plain(o: &EncodeOptions, data: &[u8], chunk: usize) -> Vec<u8> {
    let mut e = Encoder::new_plain(o).unwrap();
    let mut out = Vec::new();
    for c in data.chunks(chunk.max(1)) {
        e.update(c, &mut out).unwrap();
    }
    e.finish(&mut out).unwrap();
    out
}

/// One row of `ref.txt`: `input|source|flags|sha256`, `source` one of
/// `file`, `stdin` and `zstd` (whose flags are its level).
#[cfg(feature = "lz4-c")]
struct Row {
    input: String,
    source: String,
    flags: String,
    sha: String,
}

/// The fixture table, parsed.
#[cfg(feature = "lz4-c")]
fn fixture_rows() -> Vec<Row> {
    let path = format!("{}/tests/data/lz4_opts/ref.txt", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split('|').collect();
            assert_eq!(f.len(), 4, "{l}");
            Row {
                input: f[0].into(),
                source: f[1].into(),
                flags: f[2].into(),
                sha: f[3].into(),
            }
        })
        .collect()
}

/// What this module writes for a fixture row.
#[cfg(feature = "lz4-c")]
fn encode_row(row: &Row, data: &[u8]) -> Vec<u8> {
    match row.source.as_str() {
        "zstd" => {
            let level: i32 = row.flags[1..].parse().unwrap();
            encode_plain(&zstd_options(level, data.len()), data, 64 << 10)
        }
        src => encode(&options_for(&row.flags, data.len(), src == "stdin"), data),
    }
}

/// The binary fixtures under `tests/data/lz4_opts/`: the reference's own
/// output, `lz4 -q -c <flags> <input>` (file name, input, flags).
const BINARY_FIXTURES: &[(&str, &str, &str)] = &[
    ("small.lz4", "small", ""),
    ("small-cs-bx.lz4", "small", "--content-size -BX"),
    ("small-nocrc.lz4", "small", "--no-frame-crc"),
    ("small-d10.lz4", "small", "-D d10"),
    ("small-legacy.lz4", "small", "-l"),
    ("multi-b4-bd.lz4", "multi", "-B4 -BD"),
    ("multi-b4-bd-d10.lz4", "multi", "-B4 -BD -D d10"),
    ("multi-b4-bx-9-cs.lz4", "multi", "-B4 -BX -9 --content-size"),
    ("rand-b4-bd.lz4", "rand66", "-B4 -BD"),
    ("empty.lz4", "empty", ""),
];

/// The binary fixtures' inputs.
fn fixture_input(name: &str) -> Vec<u8> {
    match name {
        "small" => text(20_000, 0x5a),
        "multi" => text(140_000, 0x3b),
        "rand66" => rand(66_000, 0x66),
        "empty" => Vec::new(),
        _ => panic!("no input {name}"),
    }
}

/// A binary fixture's bytes.
fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/data/lz4_opts/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Decodes all of `src` (one or more frames, skippable ones included)
/// through `d`, `chunk` bytes at a time: the output, or the first error.
/// Input that ends inside a frame is [`Lz4fError::FrameHeaderIncomplete`]
/// here (the CLI reports truncation its own way), never a short success.
fn decode_with(d: &mut Decoder, src: &[u8], chunk: usize) -> Result<Vec<u8>, Lz4Error> {
    let mut out = Vec::new();
    let mut pos = 0;
    let mut hint = 0;
    while pos < src.len() {
        let end = (pos + chunk).min(src.len());
        let (n, h) = d.decompress(&src[pos..end], &mut out)?;
        pos += n;
        hint = h;
    }
    if hint != 0 {
        return Err(Lz4fError::FrameHeaderIncomplete.into());
    }
    Ok(out)
}

/// Decodes `src` with options `o`, 64 KiB at a time.
fn decode(o: &DecodeOptions, src: &[u8]) -> Result<Vec<u8>, Lz4Error> {
    decode_with(&mut Decoder::new(o).unwrap(), src, 64 << 10)
}

/// Decodes a legacy frame whole.
fn decode_legacy(src: &[u8]) -> Result<Vec<u8>, Lz4Error> {
    let mut d = LegacyDecoder::new();
    let mut out = Vec::new();
    let (n, _) = d.decompress(src, &mut out)?;
    assert_eq!(n, src.len());
    assert!(d.at_block_boundary());
    Ok(out)
}

/// The liblz4 error a result carries.
fn lib_err<T: std::fmt::Debug>(r: Result<T, Lz4Error>) -> Lz4fError {
    match r {
        Err(Lz4Error::Lib(e)) => e,
        other => panic!("expected a liblz4 error, got {other:?}"),
    }
}

/// A frame header for `h` (the writer both tiers share).
fn header(h: &FrameHeader) -> Vec<u8> {
    let mut v = Vec::new();
    write_frame_header(h, &mut v);
    v
}

/// The header fields every crafted frame below starts from.
fn plain_header(block_size: BlockSizeId) -> FrameHeader {
    FrameHeader {
        block_size,
        block_linked: false,
        block_checksum: false,
        content_checksum: false,
        content_size: None,
        dict_id: None,
        header_len: 7,
    }
}

/// A skippable frame of `n` bytes with magic `0x184D2A50 + v`.
fn skippable(v: u32, n: usize) -> Vec<u8> {
    let mut f = (SKIPPABLE_MAGIC_START + v).to_le_bytes().to_vec();
    f.extend_from_slice(&(n as u32).to_le_bytes());
    f.extend((0..n).map(|i| i as u8));
    f
}

/// A 3-block frame (64 KiB blocks, block and content checksums, the
/// content size) and its content.
fn three_blocks() -> (Vec<u8>, Vec<u8>) {
    let data = text(2 * (64 << 10) + 5000, 0x3b10);
    let o = EncodeOptions {
        block_size: BlockSizeId::Max64Kb,
        block_checksum: true,
        content_size: Some(data.len() as u64),
        ..EncodeOptions::default()
    };
    (encode(&o, &data), data)
}

#[test]
fn error_codes_follow_lz4f_list_errors() {
    assert_eq!(Lz4fError::Generic.code(), 1);
    assert_eq!(Lz4fError::IoRead.code(), 23);
    for code in 1..=23 {
        assert_eq!(Lz4fError::from_code(code).code(), code);
    }
    assert_eq!(Lz4fError::from_code(0), Lz4fError::Generic);
    assert_eq!(Lz4fError::from_code(99), Lz4fError::Generic);
    assert_eq!(
        Lz4fError::FrameTypeUnknown.name(),
        "ERROR_frameType_unknown"
    );
    assert_eq!(
        Lz4Error::Lib(Lz4fError::ContentChecksumInvalid).to_string(),
        "ERROR_contentChecksum_invalid"
    );
}

#[test]
fn block_size_ids() {
    assert_eq!(BlockSizeId::for_bytes(32), BlockSizeId::Max64Kb);
    assert_eq!(BlockSizeId::for_bytes(65_536), BlockSizeId::Max64Kb);
    assert_eq!(BlockSizeId::for_bytes(65_537), BlockSizeId::Max256Kb);
    assert_eq!(BlockSizeId::for_bytes(262_144), BlockSizeId::Max256Kb);
    assert_eq!(BlockSizeId::for_bytes(300_000), BlockSizeId::Max1Mb);
    assert_eq!(BlockSizeId::for_bytes(1_048_577), BlockSizeId::Max4Mb);
    assert_eq!(BlockSizeId::for_bytes(5_000_000), BlockSizeId::Max4Mb);
    let o = EncodeOptions {
        block_size: BlockSizeId::Max64Kb,
        block_bytes: Some(100_000),
        ..EncodeOptions::default()
    };
    assert_eq!(o.block_size_id(), BlockSizeId::Max256Kb);
    assert_eq!(BlockSizeId::Max4Mb.optimal_for(0), BlockSizeId::Max64Kb);
    assert_eq!(
        BlockSizeId::Max4Mb.optimal_for(65_536),
        BlockSizeId::Max64Kb
    );
    assert_eq!(
        BlockSizeId::Max4Mb.optimal_for(300_000),
        BlockSizeId::Max1Mb
    );
    assert_eq!(
        BlockSizeId::Max4Mb.optimal_for(2 << 20),
        BlockSizeId::Max4Mb
    );
    assert_eq!(
        BlockSizeId::Max256Kb.optimal_for(2 << 20),
        BlockSizeId::Max256Kb
    );
    assert_eq!(BlockSizeId::Max64Kb.optimal_for(10), BlockSizeId::Max64Kb);
    for id in 4..=7 {
        assert_eq!(BlockSizeId::from_id(id).unwrap().id(), id);
    }
    assert_eq!(BlockSizeId::from_id(3), None);
    assert_eq!(BlockSizeId::from_id(8), None);
}

/// The one-shot rule (spike S1), on both tiers: an input shorter than one
/// 4 MiB job gets the smallest block size that holds it and, as a single
/// block, independence; one of exactly 4 MiB is streamed as asked.
#[test]
fn short_inputs_are_one_shot_frames() {
    let linked = EncodeOptions {
        block_linked: true,
        ..EncodeOptions::default()
    };
    let h = |o: &EncodeOptions, n: usize| {
        let f = encode(o, &text(n, 0x1));
        parse_frame_header(&f).unwrap().unwrap()
    };
    let small = h(&linked, 300_000);
    assert_eq!(small.block_size, BlockSizeId::Max1Mb);
    assert!(!small.block_linked);
    let under = h(&linked, FRAME_CHUNK - 1);
    assert_eq!(under.block_size, BlockSizeId::Max4Mb);
    assert!(!under.block_linked);
    let exact = h(&linked, FRAME_CHUNK);
    assert_eq!(exact.block_size, BlockSizeId::Max4Mb);
    assert!(exact.block_linked);
    // The true size, whatever the caller claimed.
    let sized = EncodeOptions {
        content_size: Some(12),
        ..EncodeOptions::default()
    };
    assert_eq!(h(&sized, 1000).content_size, Some(1000));
    // A multi-block one-shot frame stays linked.
    let b4 = EncodeOptions {
        block_size: BlockSizeId::Max64Kb,
        block_linked: true,
        ..EncodeOptions::default()
    };
    assert!(h(&b4, 200_000).block_linked);
    // Plain frames never shrink or unlink.
    let f = encode_plain(&linked, &text(1000, 0x2), 1 << 20);
    let p = parse_frame_header(&f).unwrap().unwrap();
    assert_eq!(p.block_size, BlockSizeId::Max4Mb);
    assert!(p.block_linked);
}

#[test]
fn output_does_not_depend_on_how_input_is_sliced() {
    let data = text(FRAME_CHUNK + (1 << 20) + 77, 0x51);
    for o in [
        EncodeOptions {
            block_linked: true,
            block_size: BlockSizeId::Max64Kb,
            ..EncodeOptions::default()
        },
        EncodeOptions {
            legacy: true,
            ..EncodeOptions::default()
        },
        EncodeOptions::default(),
    ] {
        let whole = encode_chunked(&o, &data, data.len());
        assert_eq!(encode_chunked(&o, &data, 7), whole);
        assert_eq!(encode_chunked(&o, &data, (1 << 20) + 3), whole);
        assert_eq!(encode_plain(&o, &data, 7), encode_plain(&o, &data, 1 << 22));
    }
}

#[test]
fn an_encoder_writes_frame_after_frame() {
    let o = EncodeOptions {
        content_size: Some(5000),
        ..EncodeOptions::default()
    };
    let a = text(5000, 0xa);
    let mut e = Encoder::new(&o).unwrap();
    let mut out = Vec::new();
    e.update(&a, &mut out).unwrap();
    e.finish(&mut out).unwrap();
    let first = out.len();
    e.update(&a, &mut out).unwrap();
    e.finish(&mut out).unwrap();
    assert_eq!(out[..first], out[first..]);
    let mut d = Decoder::new(&DecodeOptions::default()).unwrap();
    let mut got = Vec::new();
    let (n, hint) = d.decompress(&out, &mut got).unwrap();
    assert_eq!((n, hint), (first, 0), "stops exactly at the frame's end");
    let (n, hint) = d.decompress(&out[first..], &mut got).unwrap();
    assert_eq!((n, hint), (first, 0));
    assert_eq!(got, [&a[..], &a[..]].concat());
}

#[test]
fn round_trips_on_this_tier() {
    let data = text(FRAME_CHUNK + 300_000, 0x77);
    let dict = dictionary("d10");
    for flags in FILE_FLAGS {
        let mut o = options_for(flags, data.len(), false);
        if o.dictionary.is_some() {
            o.dictionary = Some(dict.clone());
        }
        let f = encode(&o, &data);
        let back = if o.legacy {
            decode_legacy(&f).unwrap()
        } else {
            decode(
                &DecodeOptions {
                    dictionary: o.dictionary.clone(),
                },
                &f,
            )
            .unwrap()
        };
        assert!(back == data, "{flags}");
    }
}

/// Cut at every byte of a 3-block frame: the decoder never reports the
/// frame finished. Feeding one byte at a time stands the decoder at every
/// cut in turn; fresh decoders at a sample of cuts confirm it.
#[test]
fn truncated_frames_are_errors() {
    let (f, data) = three_blocks();
    let h = parse_frame_header(&f).unwrap().unwrap();
    assert!(h.block_checksum && h.content_checksum && h.content_size.is_some());
    let mut d = Decoder::new(&DecodeOptions::default()).unwrap();
    let mut out = Vec::new();
    for (i, b) in f.iter().enumerate() {
        let (n, hint) = d.decompress(std::slice::from_ref(b), &mut out).unwrap();
        assert_eq!(n, 1);
        if i + 1 < f.len() {
            assert_ne!(hint, 0, "a frame cut after {} bytes looked complete", i + 1);
        } else {
            assert_eq!(hint, 0);
        }
    }
    assert!(out == data);
    for cut in (1..f.len())
        .step_by(997)
        .chain([f.len() - 1, f.len() - 4, 7, 11])
    {
        let r = decode_with(
            &mut Decoder::new(&DecodeOptions::default()).unwrap(),
            &f[..cut],
            4096,
        );
        assert!(r.is_err(), "a frame cut at {cut} decoded");
    }
    // The legacy frame: inside a block is not a boundary.
    let l = encode(
        &EncodeOptions {
            legacy: true,
            ..EncodeOptions::default()
        },
        &data,
    );
    let mut d = LegacyDecoder::new();
    let mut out = Vec::new();
    d.decompress(&l[..l.len() - 1], &mut out).unwrap();
    assert!(!d.at_block_boundary());
    d.decompress(&l[l.len() - 1..], &mut out).unwrap();
    assert!(d.at_block_boundary());
    assert!(out == data);
}

/// A block-size word larger than the header's block size is refused as
/// soon as the word is read, before any byte of the block is there to
/// gather (`ERROR_maxBlockSize_invalid`, as `LZ4F_decompress` gives it).
#[test]
fn block_size_word_over_the_max_refuses_before_allocating() {
    for (id, word) in [
        (BlockSizeId::Max64Kb, (64u32 << 10) + 1),
        (BlockSizeId::Max4Mb, 16 << 20),
        (BlockSizeId::Max4Mb, 0x7FFF_FFFF),
        (BlockSizeId::Max4Mb, 0x8000_0000 | ((4 << 20) + 1)),
    ] {
        let mut f = header(&plain_header(id));
        f.extend_from_slice(&word.to_le_bytes());
        let mut d = Decoder::new(&DecodeOptions::default()).unwrap();
        let e = lib_err(d.decompress(&f, &mut Vec::new()));
        assert_eq!(e, Lz4fError::MaxBlockSizeInvalid, "{id:?} {word:#x}");
    }
    // At the limit, the decoder waits for the block.
    let mut f = header(&plain_header(BlockSizeId::Max64Kb));
    f.extend_from_slice(&((64u32 << 10) | 0x8000_0000).to_le_bytes());
    let mut d = Decoder::new(&DecodeOptions::default()).unwrap();
    let (n, hint) = d.decompress(&f, &mut Vec::new()).unwrap();
    assert_eq!(n, f.len());
    assert_ne!(hint, 0);
    // A legacy word past LZ4_compressBound(8 MiB) is not a block: the
    // frame ends there, and the word is left for the caller.
    let mut l = LEGACY_MAGIC.to_le_bytes().to_vec();
    l.extend_from_slice(&(LEGACY_BLOCK_BOUND as u32 + 1).to_le_bytes());
    let mut d = LegacyDecoder::new();
    assert_eq!(d.decompress(&l, &mut Vec::new()).unwrap(), (4, 0));
    let mut l = LEGACY_MAGIC.to_le_bytes().to_vec();
    l.extend_from_slice(&(LEGACY_BLOCK_BOUND as u32).to_le_bytes());
    let mut d = LegacyDecoder::new();
    assert_eq!(
        d.decompress(&l, &mut Vec::new()).unwrap(),
        (8, LEGACY_BLOCK_BOUND)
    );
}

#[test]
fn a_legacy_frame_ends_at_the_next_magic() {
    let a = text(1000, 0xa1);
    let b = text(2000, 0xb2);
    let mut s = encode(
        &EncodeOptions {
            legacy: true,
            ..EncodeOptions::default()
        },
        &a,
    );
    let split = s.len();
    s.extend(encode(&EncodeOptions::default(), &b));
    let mut d = LegacyDecoder::new();
    let mut out = Vec::new();
    assert_eq!(d.decompress(&s, &mut out).unwrap(), (split, 0));
    assert!(out == a);
    assert_eq!(decode(&DecodeOptions::default(), &s[split..]).unwrap(), b);
    assert_eq!(
        lib_err(LegacyDecoder::new().decompress(&s[split..], &mut Vec::new())),
        Lz4fError::FrameTypeUnknown
    );
}

#[test]
fn bad_header_checksum() {
    let (mut f, _) = three_blocks();
    let hl = parse_frame_header(&f).unwrap().unwrap().header_len;
    f[hl - 1] ^= 1;
    assert_eq!(
        lib_err(decode(&DecodeOptions::default(), &f)),
        Lz4fError::HeaderChecksumInvalid
    );
    assert_eq!(
        lib_err(parse_frame_header(&f)),
        Lz4fError::HeaderChecksumInvalid
    );
}

#[test]
fn bad_block_checksum() {
    let (mut f, _) = three_blocks();
    let hl = parse_frame_header(&f).unwrap().unwrap().header_len;
    let first = (le32(&f, hl) & 0x7FFF_FFFF) as usize;
    // The first block's own checksum, then a byte of its data.
    let crc_at = hl + 4 + first;
    let mut g = f.clone();
    g[crc_at] ^= 0x40;
    assert_eq!(
        lib_err(decode(&DecodeOptions::default(), &g)),
        Lz4fError::BlockChecksumInvalid
    );
    f[hl + 4 + first / 2] ^= 0x40;
    assert_eq!(
        lib_err(decode(&DecodeOptions::default(), &f)),
        Lz4fError::BlockChecksumInvalid
    );
}

#[test]
fn bad_content_checksum() {
    let (mut f, _) = three_blocks();
    let n = f.len();
    f[n - 2] ^= 1;
    assert_eq!(
        lib_err(decode(&DecodeOptions::default(), &f)),
        Lz4fError::ContentChecksumInvalid
    );
}

#[test]
fn a_wrong_content_size_is_frame_size_wrong() {
    let data = text(3000, 0xc5);
    let mut h = plain_header(BlockSizeId::Max64Kb);
    h.content_size = Some(2999);
    let mut f = header(&h);
    f.extend_from_slice(&(3000u32 | 0x8000_0000).to_le_bytes());
    f.extend_from_slice(&data);
    f.extend_from_slice(&[0; 4]);
    assert_eq!(
        lib_err(decode(&DecodeOptions::default(), &f)),
        Lz4fError::FrameSizeWrong
    );
    // A content size of 0 is "unknown" to liblz4, never checked.
    h.content_size = Some(0);
    let mut f = header(&h);
    f.extend_from_slice(&(3000u32 | 0x8000_0000).to_le_bytes());
    f.extend_from_slice(&data);
    f.extend_from_slice(&[0; 4]);
    assert_eq!(decode(&DecodeOptions::default(), &f).unwrap(), data);
}

#[test]
fn header_faults_map_onto_lz4f_codes() {
    let good = header(&plain_header(BlockSizeId::Max64Kb));
    let mut cases: Vec<(Vec<u8>, Lz4fError)> = Vec::new();
    let mut wrong = good.clone();
    wrong[0] = 0;
    cases.push((wrong, Lz4fError::FrameTypeUnknown));
    let mut legacy = good.clone();
    legacy[..4].copy_from_slice(&LEGACY_MAGIC.to_le_bytes());
    cases.push((legacy, Lz4fError::FrameTypeUnknown));
    for (byte, mask, e) in [
        (4, 0x02, Lz4fError::ReservedFlagSet),
        (4, 0xC0, Lz4fError::HeaderVersionWrong),
        (5, 0x80, Lz4fError::ReservedFlagSet),
        (5, 0x01, Lz4fError::ReservedFlagSet),
        (5, 0x40, Lz4fError::MaxBlockSizeInvalid),
    ] {
        let mut f = good.clone();
        f[byte] ^= mask;
        cases.push((f, e));
    }
    for (f, e) in cases {
        assert_eq!(
            lib_err(decode(&DecodeOptions::default(), &f)),
            e,
            "{f:02x?}"
        );
        assert_eq!(lib_err(parse_frame_header(&f)), e, "{f:02x?}");
    }
    assert!(parse_frame_header(&good[..6]).unwrap().is_none());
    assert_eq!(
        lib_err(parse_frame_header(&[0, 0, 0, 0])),
        Lz4fError::FrameTypeUnknown
    );
}

#[test]
fn skippable_frames_are_consumed() {
    let data = text(5000, 0x5c);
    for v in [0, 15] {
        let s = skippable(v, 300);
        let mut d = Decoder::new(&DecodeOptions::default()).unwrap();
        let mut out = Vec::new();
        assert_eq!(d.decompress(&s, &mut out).unwrap(), (s.len(), 0));
        assert!(out.is_empty());
        // Byte by byte, then a real frame after it.
        let mut all = s.clone();
        let f = encode(&EncodeOptions::default(), &data);
        all.extend_from_slice(&f);
        let mut d = Decoder::new(&DecodeOptions::default()).unwrap();
        let mut ends = 0;
        for b in &all {
            let (n, hint) = d.decompress(std::slice::from_ref(b), &mut out).unwrap();
            assert_eq!(n, 1);
            ends += usize::from(hint == 0);
        }
        assert_eq!(ends, 2);
        assert!(out == data);
    }
    // An empty skippable frame.
    let s = skippable(3, 0);
    let mut d = Decoder::new(&DecodeOptions::default()).unwrap();
    assert_eq!(d.decompress(&s, &mut Vec::new()).unwrap(), (8, 0));
}

#[test]
fn parse_frame_header_reads_the_fixtures() {
    // (fixture, block size, linked, block checksum, content checksum,
    // content size, header length) — what LZ4F_getFrameInfo reports for
    // them (checked on the C tier by the test below).
    for (name, id, linked, bx, cc, size, len) in [
        ("small.lz4", 4, false, false, true, None, 7),
        ("small-cs-bx.lz4", 4, false, true, true, Some(20_000), 15),
        ("small-nocrc.lz4", 4, false, false, false, None, 7),
        ("small-d10.lz4", 4, false, false, true, None, 7),
        ("multi-b4-bd.lz4", 4, true, false, true, None, 7),
        ("multi-b4-bd-d10.lz4", 4, true, false, true, None, 7),
        (
            "multi-b4-bx-9-cs.lz4",
            4,
            false,
            true,
            true,
            Some(140_000),
            15,
        ),
        ("rand-b4-bd.lz4", 4, true, false, true, None, 7),
        ("empty.lz4", 4, false, false, true, None, 7),
    ] {
        let h = parse_frame_header(&fixture(name)).unwrap().unwrap();
        assert_eq!(
            h,
            FrameHeader {
                block_size: BlockSizeId::from_id(id).unwrap(),
                block_linked: linked,
                block_checksum: bx,
                content_checksum: cc,
                content_size: size,
                dict_id: None,
                header_len: len,
            },
            "{name}"
        );
    }
}

/// The reference's own frames decode on this tier.
#[test]
fn reads_the_reference_fixtures() {
    for (name, input, flags) in BINARY_FIXTURES {
        let f = fixture(name);
        let want = fixture_input(input);
        let got = if flags.contains("-l") {
            decode_legacy(&f).unwrap()
        } else {
            let dictionary = flags.contains("-D").then(|| dictionary("d10"));
            decode(&DecodeOptions { dictionary }, &f).unwrap()
        };
        assert!(got == want, "{name}");
        // And fed a byte at a time.
        if !flags.contains("-l") && f.len() < 30_000 {
            let dictionary = flags.contains("-D").then(|| dictionary("d10"));
            let mut d = Decoder::new(&DecodeOptions { dictionary }).unwrap();
            assert!(decode_with(&mut d, &f, 1).unwrap() == want, "{name}");
        }
    }
}

/// Regenerates `tests/data/lz4_opts/` from the reference lz4 1.10.0 and
/// zstd 1.5.7: `STUFFR_LZ4_OPTS_REGEN=<dir> cargo test -p stuffr-formats
/// --features lz4 lz4_opts::tests::regenerate_fixtures -- --ignored`, then
/// copy `<dir>/*` into `tests/data/lz4_opts/`.
#[cfg(unix)]
#[test]
#[ignore = "regenerates fixtures from the reference tools"]
fn regenerate_fixtures() {
    let out = std::path::PathBuf::from(
        std::env::var_os("STUFFR_LZ4_OPTS_REGEN").expect("STUFFR_LZ4_OPTS_REGEN"),
    );
    std::fs::create_dir_all(&out).unwrap();
    let lz4 = reference().expect("the reference lz4 1.10.0");
    let zstd = std::env::var_os("STUFFR_ZSTD_REFERENCE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/opt/homebrew/opt/zstd/bin/zstd".into());
    let dir = Scratch::new("regen");
    for d in ["d100", "d10"] {
        std::fs::write(dir.0.join(d), dictionary(d)).unwrap();
    }
    // `-D NAME` names a file in the scratch directory.
    let args_for = |flags: &str| -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        let mut it = flags.split_whitespace();
        while let Some(f) = it.next() {
            v.push(f.into());
            if f == "-D" {
                v.push(dir.0.join(it.next().unwrap()).to_str().unwrap().into());
            }
        }
        v
    };
    let mut table = String::from(REF_HEADER);
    for (name, data) in inputs() {
        let path = dir.0.join(name);
        std::fs::write(&path, &data).unwrap();
        for flags in FILE_FLAGS {
            let a = args_for(flags);
            let a: Vec<&str> = a.iter().map(String::as_str).collect();
            let f = run_reference(&lz4, &a, Some(&path), &data).unwrap();
            table += &format!("{name}|file|{flags}|{}\n", sha256(&f));
        }
        for flags in STDIN_FLAGS {
            let f = run_reference(&lz4, &[flags], None, &data).unwrap();
            table += &format!("{name}|stdin|{flags}|{}\n", sha256(&f));
        }
        if name != "four" {
            for level in ZSTD_LEVELS {
                let o = std::process::Command::new(&zstd)
                    .args(["-q", "--format=lz4", &format!("-{level}"), "-c"])
                    .arg(&path)
                    .output()
                    .unwrap();
                assert!(o.status.success());
                table += &format!("{name}|zstd|-{level}|{}\n", sha256(&o.stdout));
            }
        }
    }
    std::fs::write(out.join("ref.txt"), table).unwrap();
    for (file, input, flags) in BINARY_FIXTURES {
        let data = fixture_input(input);
        let path = dir.0.join(input);
        std::fs::write(&path, &data).unwrap();
        let a = args_for(flags);
        let a: Vec<&str> = a.iter().map(String::as_str).collect();
        let f = run_reference(&lz4, &a, Some(&path), &data).unwrap();
        std::fs::write(out.join(file), f).unwrap();
    }
}

/// `ref.txt`'s header, written by [`regenerate_fixtures`].
const REF_HEADER: &str = "\
# lz4_opts fixture: `<input>|<source>|<flags>|<sha256>`. Source `file`:
# the SHA-256 of `lz4 -q -c <flags> <input>` (lz4 1.10.0,
# /opt/homebrew/opt/lz4/bin/lz4, multithread); `stdin`: of
# `lz4 -q -c <flags> < pipe`; `zstd`: of `zstd -q --format=lz4 <level> -c
# <input>` (zstd 1.5.7). Inputs are `src/lz4_opts/tests.rs`' `inputs()`;
# `-D d100`/`-D d10` name its `dictionary()` files. Regenerate with
# `regenerate_fixtures` (see its doc and this directory's README).
";

#[cfg(feature = "lz4-c")]
mod c_tier {
    use super::*;

    #[test]
    fn liblz4_is_1_10_0() {
        assert_eq!(liblz4_version(), "1.10.0");
    }

    #[test]
    fn error_names_match_liblz4() {
        for code in 1..=23usize {
            // SAFETY: LZ4F_getErrorName returns a pointer into a static
            // table of NUL-terminated strings for any error code.
            let name = unsafe {
                std::ffi::CStr::from_ptr(lz4_sys::LZ4F_getErrorName(0usize.wrapping_sub(code)))
            };
            assert_eq!(Lz4fError::from_code(code).name(), name.to_str().unwrap());
        }
    }

    #[test]
    fn matches_the_reference_fixture() {
        let rows = fixture_rows();
        assert!(rows.len() > 200, "{} rows", rows.len());
        let mut bad = Vec::new();
        for (name, data) in inputs() {
            for row in rows.iter().filter(|r| r.input == name) {
                if sha256(&encode_row(row, &data)) != row.sha {
                    bad.push(format!("{}|{}|{}", row.input, row.source, row.flags));
                }
            }
        }
        assert!(bad.is_empty(), "differs from the reference: {bad:#?}");
    }

    /// Four rows re-derived from the reference itself, when it is here.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_fixture_is_the_reference() {
        let Some(lz4) = reference() else {
            return;
        };
        let rows = fixture_rows();
        let dir = Scratch::new("live");
        let inputs = inputs();
        for (input, source, flags) in [
            ("text", "file", "-9"),
            ("big", "file", "-B4 -BD"),
            ("text", "stdin", "--content-size"),
            ("rand", "file", "-BX"),
        ] {
            let data = &inputs.iter().find(|(n, _)| *n == input).unwrap().1;
            let path = dir.0.join(input);
            std::fs::write(&path, data).unwrap();
            let file = (source == "file").then_some(path.as_path());
            let args: Vec<&str> = flags.split(' ').collect();
            let live = run_reference(&lz4, &args, file, data).unwrap();
            let row = rows
                .iter()
                .find(|r| r.input == input && r.source == source && r.flags == flags)
                .unwrap();
            assert_eq!(sha256(&live), row.sha, "{input}|{source}|{flags}");
        }
    }

    #[test]
    fn dictionary_round_trips() {
        let data = text(FRAME_CHUNK + 200_000, 0xd1c7);
        for d in ["d100", "d10"] {
            let dict = dictionary(d);
            for flags in ["-1", "-9", "-BD", "-B4 -BD", "-B4 -BX --content-size"] {
                let o = EncodeOptions {
                    dictionary: Some(dict.clone()),
                    ..options_for(flags, data.len(), false)
                };
                for n in [data.len(), 30_000] {
                    let f = encode(&o, &data[..n]);
                    let with = DecodeOptions {
                        dictionary: Some(dict.clone()),
                    };
                    assert!(decode(&with, &f).unwrap() == data[..n], "{d} {flags}");
                    let without = decode(&DecodeOptions::default(), &f);
                    assert!(
                        without.as_deref().ok() != Some(&data[..n]),
                        "{d} {flags}: decoded without the dictionary"
                    );
                }
            }
        }
    }

    /// `parse_frame_header` against `LZ4F_getFrameInfo` over every header
    /// shape and every single-bit fault in them.
    #[test]
    fn parse_frame_header_matches_lz4f_get_frame_info() {
        let mut headers = Vec::new();
        for id in 4..=7 {
            for bits in 0..16u8 {
                for size in [None, Some(0), Some(12_345), Some(1 << 63)] {
                    for dict_id in [None, Some(0), Some(0xDEAD_BEEF)] {
                        headers.push(header(&FrameHeader {
                            block_size: BlockSizeId::from_id(id).unwrap(),
                            block_linked: bits & 1 != 0,
                            block_checksum: bits & 2 != 0,
                            content_checksum: bits & 4 != 0,
                            content_size: size,
                            dict_id,
                            header_len: 0,
                        }));
                    }
                }
            }
        }
        let mut all = headers.clone();
        for h in headers.iter().step_by(7) {
            for byte in 4..h.len() {
                for bit in 0..8 {
                    let mut f = h.clone();
                    f[byte] ^= 1 << bit;
                    all.push(f);
                }
            }
        }
        for f in &all {
            let ours = parse_frame_header(f);
            let theirs = c::Decoder::frame_info(f);
            match (ours, theirs) {
                (Ok(Some(o)), Ok((t, n))) => {
                    assert_eq!(u32::from(o.block_size.id()), t.block_size_id, "{f:02x?}");
                    assert_eq!(u32::from(!o.block_linked), t.block_mode, "{f:02x?}");
                    assert_eq!(u32::from(o.content_checksum), t.content_checksum_flag);
                    assert_eq!(u32::from(o.block_checksum), t.block_checksum_flag);
                    assert_eq!(o.content_size.unwrap_or(0), t.content_size);
                    assert_eq!(o.dict_id.unwrap_or(0), t.dict_id);
                    assert_eq!(o.header_len, n);
                }
                (Err(Lz4Error::Lib(o)), Err(Lz4Error::Lib(t))) => assert_eq!(o, t, "{f:02x?}"),
                // A flipped flag that lengthens the header: we ask for the
                // rest, LZ4F_getFrameInfo (given these bytes only) says so.
                (Ok(None), Err(Lz4Error::Lib(Lz4fError::FrameHeaderIncomplete))) => {}
                (o, t) => panic!("{f:02x?}: ours {o:?}, liblz4 {t:?}"),
            }
        }
        for (name, ..) in BINARY_FIXTURES
            .iter()
            .filter(|(n, ..)| !n.contains("legacy"))
        {
            let f = fixture(name);
            let o = parse_frame_header(&f).unwrap().unwrap();
            let (t, n) = c::Decoder::frame_info(&f).unwrap();
            assert_eq!(u32::from(o.block_size.id()), t.block_size_id, "{name}");
            assert_eq!(o.header_len, n, "{name}");
        }
    }
}

#[cfg(not(feature = "lz4-c"))]
mod pure_tier {
    use super::*;

    #[test]
    fn liblz4_version_is_the_c_tiers() {
        assert_eq!(liblz4_version(), "1.10.0");
    }

    /// Seeded cases over every option the pure tier accepts: each decodes
    /// on this tier, and with the reference lz4 when it is here.
    #[test]
    fn pure_round_trips_and_the_reference_reads_it() {
        #[cfg(unix)]
        let lz4 = reference();
        #[cfg(unix)]
        let dir = Scratch::new("pure");
        let mut g = Lcg(0x9e37);
        for case in 0..64 {
            let n = match case {
                0 => 0,
                1 => FRAME_CHUNK + 4321,
                2 => 2 * FRAME_CHUNK + 1,
                _ => g.next() as usize % 300_000,
            };
            let data = match g.next() % 3 {
                0 => text(n, u64::from(g.next())),
                1 => rand(n, u64::from(g.next())),
                _ => {
                    let mut b = bin();
                    b.resize(n, 0);
                    b
                }
            };
            let dict_name = ["d10", "d100"][g.next() as usize % 2];
            let o = EncodeOptions {
                level: [-5, 1, 2, 3, 9, 12][g.next() as usize % 6],
                block_size: BlockSizeId::from_id(4 + (g.next() % 4) as u8).unwrap(),
                block_bytes: (g.next().is_multiple_of(5)).then(|| 32 + g.next() % 5_000_000),
                block_linked: g.next().is_multiple_of(2),
                block_checksum: g.next().is_multiple_of(2),
                content_checksum: !g.next().is_multiple_of(4),
                content_size: (g.next().is_multiple_of(3)).then_some(n as u64),
                favor_dec_speed: g.next().is_multiple_of(4),
                dictionary: (g.next().is_multiple_of(3)).then(|| dictionary(dict_name)),
                legacy: g.next().is_multiple_of(8),
            };
            let plain = !o.legacy && g.next().is_multiple_of(6);
            let slice = 1 + g.next() as usize % (1 << 20);
            let f = if plain {
                encode_plain(&o, &data, slice)
            } else {
                encode_chunked(&o, &data, slice)
            };
            let back = if o.legacy {
                decode_legacy(&f).unwrap()
            } else {
                let dictionary = o.dictionary.clone().filter(|_| !o.legacy);
                decode(&DecodeOptions { dictionary }, &f).unwrap()
            };
            assert!(back == data, "case {case}: {o:?}");
            #[cfg(unix)]
            if let Some(lz4) = &lz4 {
                let dp = dir.0.join(dict_name);
                let dict = o.dictionary.as_ref().map(|d| {
                    std::fs::write(&dp, d).unwrap();
                    dp.as_path()
                });
                let theirs = reference_decode(lz4, &f, dict);
                assert!(theirs.as_deref() == Some(&data[..]), "case {case}: {o:?}");
            }
        }
    }
}
