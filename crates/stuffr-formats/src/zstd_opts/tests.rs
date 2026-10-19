//! `zstd_opts`'s unit tests. The C-tier ones pin libzstd's bytes against
//! zstd 1.5.7 through a vendored fixture, `tests/data/zstd_opts/ref.txt`;
//! the binary fixtures beside it are the reference's own output, generated
//! as `ref.txt`'s header says.

use super::*;

/// A fixed 64-bit LCG (Knuth's MMIX constants), so every input is the same
/// on every machine and every run.
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
    "stream",
    "block",
    "index",
    "filter",
    "chain",
    "dictionary",
    "compress",
    "archive",
    "header",
];

/// `n` bytes of word salad: LCG-chosen words, a newline every so often.
fn text(n: usize, seed: u64) -> Vec<u8> {
    let mut r = Lcg(seed);
    let mut out = Vec::with_capacity(n + 16);
    while out.len() < n {
        out.extend_from_slice(WORDS[r.next() as usize % WORDS.len()].as_bytes());
        out.push(if r.next().is_multiple_of(11) {
            b'\n'
        } else {
            b' '
        });
    }
    out.truncate(n);
    out
}

/// 64 KiB shaped like x86 code.
#[cfg(feature = "zstd-c")]
fn bin() -> Vec<u8> {
    let mut r = Lcg(0x0b1a);
    let mut out = Vec::with_capacity(65_536 + 8);
    const OPS: &[u8] = &[0x48, 0x89, 0x8b, 0xe8, 0x0f, 0xc3, 0x55, 0x5d, 0x31, 0x83];
    while out.len() < 65_536 {
        let op = OPS[r.next() as usize % OPS.len()];
        out.push(op);
        match op {
            0xe8 => out.extend_from_slice(&((r.next() % 4096) as i32 - 2048).to_le_bytes()),
            0xc3 | 0x55 | 0x5d => {}
            _ => {
                for _ in 0..(1 + r.next() % 3) {
                    out.push((r.next() & 0xff) as u8);
                }
            }
        }
    }
    out.truncate(65_536);
    out
}

/// `n` LCG bytes.
fn rand(n: usize, seed: u64) -> Vec<u8> {
    let mut r = Lcg(seed);
    (0..n).map(|_| (r.next() >> 16) as u8).collect()
}

/// The fixture's encoder inputs, by name.
#[cfg(feature = "zstd-c")]
fn inputs() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("text", text(300_000, 0x7e47)),
        ("bin", bin()),
        ("rand", rand(50_000, 0x5eed)),
        ("empty", Vec::new()),
    ]
}

/// The training set: 100 samples of 500..4500 bytes, named `s000`..`s099`.
#[cfg(feature = "zstd-c")]
fn samples() -> Vec<(String, Vec<u8>)> {
    let mut r = Lcg(0x5a);
    (0..100)
        .map(|i| {
            let n = 500 + (r.next() % 4000) as usize;
            (format!("s{i:03}"), text(n, 1000 + i))
        })
        .collect()
}

/// `--patch-from`'s two versions: `old`, and `new` edited from it.
fn patch_pair() -> (Vec<u8>, Vec<u8>) {
    let old = text(300_000, 0x7e47);
    let mut new = old.clone();
    new[1000..1100].copy_from_slice(&rand(100, 0x5eed));
    new.splice(50_000..50_000, text(5000, 9));
    new.truncate(280_000);
    new.extend_from_slice(&text(20_000, 3));
    (old, new)
}

/// What `dict4k.zst` holds: compressed by the reference with `-D dict4k.dict`.
fn dict_plain() -> Vec<u8> {
    text(3000, 0xd1c7)
}

/// A fixture file under `tests/data/zstd_opts/`.
fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/data/zstd_opts/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
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

#[test]
fn sha256_is_sha256() {
    assert_eq!(
        sha256(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

/// The reference `zstd` 1.5.7, if this machine has it.
#[cfg(unix)]
fn reference() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("STUFFR_ZSTD_REFERENCE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/opt/homebrew/opt/zstd/bin/zstd".into());
    let v = std::process::Command::new(&path).arg("-qV").output().ok()?;
    (String::from_utf8_lossy(&v.stdout).trim() == "1.5.7").then_some(path)
}

/// `zstd <args>` with `input` on stdin; its stdout, or `None` if it failed.
#[cfg(unix)]
fn run_reference(zstd: &std::path::Path, args: &[&str], input: &[u8]) -> Option<Vec<u8>> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new(zstd)
        .args(args)
        .env_remove("ZSTD_CLEVEL")
        .env_remove("ZSTD_NBTHREADS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let input = input.to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let out = child.wait_with_output().unwrap();
    let _ = writer.join().unwrap();
    out.status.success().then_some(out.stdout)
}

/// Encodes `data` as one frame the way `FIO_compressZstdFrame` feeds a
/// file: `ZSTD_CStreamInSize()` (128 KiB) at a time, the last with
/// [`EndOp::End`].
fn encode(o: &EncodeOptions, data: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new(o).unwrap();
    let mut out = Vec::new();
    if data.is_empty() {
        e.compress_stream(&[], &mut out, EndOp::End).unwrap();
        return out;
    }
    let mut chunks = data.chunks(128 << 10).peekable();
    while let Some(c) = chunks.next() {
        let end = if chunks.peek().is_none() {
            EndOp::End
        } else {
            EndOp::Continue
        };
        e.compress_stream(c, &mut out, end).unwrap();
    }
    out
}

/// Decodes every frame of `src` through `d`, feeding it `chunk` bytes at a
/// time as `FIO_decompressFrames` does; the frame count and output.
fn decode_with(d: &mut Decoder, src: &[u8], chunk: usize) -> Result<(usize, Vec<u8>), ZstdError> {
    let mut out = Vec::new();
    let mut pos = 0;
    let mut frames = 0;
    while pos < src.len() {
        d.reset();
        loop {
            let end = (pos + chunk).min(src.len());
            let (used, hint) = d.decompress_stream(&src[pos..end], &mut out)?;
            pos += used;
            if hint == 0 {
                frames += 1;
                break;
            }
            if used == 0 && end == src.len() && pos == src.len() {
                return Err(ZstdError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "premature end",
                )));
            }
        }
    }
    Ok((frames, out))
}

fn decode(o: &DecodeOptions, src: &[u8]) -> Result<Vec<u8>, ZstdError> {
    let mut d = Decoder::new(o)?;
    decode_with(&mut d, src, 128 << 10).map(|(_, out)| out)
}

/// The libzstd code of an error, or a panic naming what it was instead.
fn code_of<T: std::fmt::Debug>(r: Result<T, ZstdError>) -> u32 {
    match r {
        Err(ZstdError::Lib { code, .. }) => code,
        other => panic!("expected a libzstd error, got {other:?}"),
    }
}

/// A skippable frame of `n` bytes with magic variant `v`.
fn skippable(v: u32, n: usize) -> Vec<u8> {
    let mut f = (MAGIC_SKIPPABLE_START + v).to_le_bytes().to_vec();
    f.extend_from_slice(&(n as u32).to_le_bytes());
    f.extend(std::iter::repeat_n(0xAB, n));
    f
}

/// A frame header declaring a window of `(1 << log) * (8 + mantissa) / 8`
/// bytes and no content size, followed by an empty last raw block.
fn window_frame(log: u32, mantissa: u8) -> Vec<u8> {
    let mut f = MAGIC.to_le_bytes().to_vec();
    f.push(0x00); // descriptor: no FCS, not single-segment, no checksum
    f.push((((log - WINDOWLOG_ABSOLUTEMIN) as u8) << 3) | mantissa);
    f.extend_from_slice(&[0x01, 0x00, 0x00]); // last raw block, 0 bytes
    f
}

// ---------------------------------------------------------------- both tiers

#[test]
fn error_names_match() {
    assert_eq!(error_name(22), "Restored data doesn't match checksum");
    assert_eq!(error_name(20), "Data corruption detected");
    assert_eq!(
        error_name(16),
        "Frame requires too much memory for decoding"
    );
    assert_eq!(error_name(10), "Unknown frame descriptor");
    assert_eq!(error_name(32), "Dictionary mismatch");
    assert_eq!(error_name(30), "Dictionary is corrupted");
    assert_eq!(error_name(70), "Destination buffer is too small");
    assert_eq!(error_name(2), "Unspecified error code");
    #[cfg(feature = "zstd-c")]
    {
        use zstd::zstd_safe::zstd_sys as sys;
        // 120 is ZSTD_error_maxCode, which ZSTD_isError no longer counts.
        for code in 0..120u32 {
            // SAFETY: ZSTD_getErrorName takes any size_t and returns a
            // static NUL-terminated string.
            let name = unsafe {
                std::ffi::CStr::from_ptr(sys::ZSTD_getErrorName(0usize.wrapping_sub(code as usize)))
            };
            assert_eq!(error_name(code), name.to_str().unwrap(), "code {code}");
        }
    }
}

#[test]
fn dict_id_reads_the_header() {
    let dict = fixture("dict4k.dict");
    let id = u32::from_le_bytes([dict[4], dict[5], dict[6], dict[7]]);
    assert_ne!(id, 0);
    assert_eq!(dict_id(&dict), id);
    assert_eq!(dict_id(&dict[..8]), id);
    assert_eq!(dict_id(&dict[..7]), 0);
    assert_eq!(dict_id(b"raw content, no magic at all"), 0);
    #[cfg(feature = "zstd-c")]
    {
        use zstd::zstd_safe::zstd_sys as sys;
        // SAFETY: the pointer and length describe `dict`.
        let theirs = unsafe { sys::ZDICT_getDictID(dict.as_ptr().cast(), dict.len()) };
        assert_eq!(dict_id(&dict), theirs);
    }
}

#[test]
fn frame_header_reads_zstd_and_skippable_frames() {
    // The reference's frame for `dict_plain()`: 3000 bytes, dictionary ID,
    // checksum, single segment.
    let f = fixture("dict4k.zst");
    match frame_header(&f).unwrap() {
        FrameHeader::Zstd {
            content_size,
            dict_id: id,
            checksum,
            single_segment,
            window_size,
            ..
        } => {
            assert_eq!(content_size, Some(3000));
            assert_eq!(window_size, 3000);
            assert_eq!(id, dict_id(&fixture("dict4k.dict")));
            assert!(checksum && single_segment);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        frame_header(&skippable(3, 7)),
        Ok(FrameHeader::Skippable {
            variant: 3,
            content_size: 7
        })
    );
    assert_eq!(frame_header(&f[..2]), Err(FrameHeaderError::Incomplete(5)));
    assert_eq!(
        frame_header(&[0x5a, 0x2a]),
        Err(FrameHeaderError::Incomplete(5))
    );
    assert_eq!(
        frame_header(&skippable(0, 0)[..6]),
        Err(FrameHeaderError::Incomplete(8))
    );
    assert_eq!(
        frame_header(&[0x28, 0xb5, 0x2f, 0xfe]),
        Err(FrameHeaderError::Lib(code::PREFIX_UNKNOWN))
    );
    assert_eq!(
        frame_header(&[0x29]),
        Err(FrameHeaderError::Lib(code::PREFIX_UNKNOWN))
    );
    let mut reserved = window_frame(20, 0);
    reserved[4] |= 0x08;
    assert_eq!(
        frame_header(&reserved),
        Err(FrameHeaderError::Lib(code::FRAME_PARAMETER_UNSUPPORTED))
    );
    let mut huge = window_frame(20, 0);
    huge[5] = 22 << 3; // window log 32
    assert_eq!(
        frame_header(&huge),
        Err(FrameHeaderError::Lib(code::WINDOW_TOO_LARGE))
    );
    match frame_header(&window_frame(24, 4)).unwrap() {
        FrameHeader::Zstd {
            window_size,
            content_size,
            header_size,
            ..
        } => {
            assert_eq!(window_size, (1 << 24) + (1 << 23));
            assert_eq!(content_size, None);
            assert_eq!(header_size, 6);
        }
        other => panic!("{other:?}"),
    }
}

/// `frame_header` is `ZSTD_getFrameHeader`: every frame descriptor byte,
/// three window bytes, every length from 0 to the longest header, and
/// skippable frames, against libzstd.
#[cfg(feature = "zstd-c")]
#[test]
fn frame_header_agrees_with_libzstd() {
    use zstd::zstd_safe::zstd_sys as sys;
    let check = |src: &[u8]| {
        let mut raw = std::mem::MaybeUninit::<sys::ZSTD_FrameHeader>::zeroed();
        // SAFETY: `raw` is a writable `ZSTD_FrameHeader` and the pointer and
        // length describe `src`.
        let ret =
            unsafe { sys::ZSTD_getFrameHeader(raw.as_mut_ptr(), src.as_ptr().cast(), src.len()) };
        let ours = frame_header(src);
        // SAFETY: zero-initialised, and a plain C struct of integers.
        let theirs = unsafe { raw.assume_init() };
        // SAFETY: `ZSTD_isError` only inspects the value.
        if unsafe { sys::ZSTD_isError(ret) } != 0 {
            let code = 0usize.wrapping_sub(ret) as u32;
            assert_eq!(ours, Err(FrameHeaderError::Lib(code)), "{src:02x?}");
        } else if ret > 0 {
            assert_eq!(ours, Err(FrameHeaderError::Incomplete(ret)), "{src:02x?}");
        } else if theirs.frameType == sys::ZSTD_FrameType_e::ZSTD_skippableFrame {
            assert_eq!(
                ours,
                Ok(FrameHeader::Skippable {
                    variant: u32::from(src[0] & 15),
                    content_size: theirs.frameContentSize as u32,
                }),
                "{src:02x?}"
            );
        } else {
            let unknown = theirs.frameContentSize == u64::MAX;
            assert_eq!(
                ours,
                Ok(FrameHeader::Zstd {
                    header_size: theirs.headerSize as usize,
                    window_size: theirs.windowSize,
                    content_size: (!unknown).then_some(theirs.frameContentSize),
                    dict_id: theirs.dictID,
                    checksum: theirs.checksumFlag != 0,
                    single_segment: src[4] & 0x20 != 0,
                }),
                "{src:02x?}"
            );
        }
    };
    let tail = [
        0x93u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
    ];
    for fhd in 0..=255u8 {
        for window in [0u8, 0x2d, 0xf8] {
            let mut data = vec![0x28, 0xb5, 0x2f, 0xfd, fhd, window];
            data.extend_from_slice(&tail);
            for len in 0..=data.len() {
                check(&data[..len]);
            }
        }
    }
    for v in 0..16u8 {
        let data = [0x50 + v, 0x2a, 0x4d, 0x18, 9, 0, 0, 0, 1];
        for len in 0..=data.len() {
            check(&data[..len]);
        }
    }
    for bad in [
        [0x28u8, 0xb5, 0x2f, 0xfe, 0, 0, 0, 0],
        [0x4f, 0x2a, 0x4d, 0x18, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0],
    ] {
        for len in 0..=bad.len() {
            check(&bad[..len]);
        }
    }
}

/// Values `ZSTD_getCParams` returns, read once from libzstd 1.5.7; the C
/// tier checks the whole range in `default_cparams_match_getcparams`.
#[test]
fn default_cparams_pins() {
    let p = |w, c, h, s, l, t, st| CParams {
        window_log: w,
        chain_log: c,
        hash_log: h,
        search_log: s,
        min_match: l,
        target_length: t,
        strategy: st,
    };
    use Strategy::*;
    assert_eq!(default_cparams(3, None, 0), p(21, 16, 17, 1, 5, 0, Dfast));
    assert_eq!(
        default_cparams(0, Some(0), 0),
        p(21, 16, 17, 1, 5, 0, Dfast)
    );
    assert_eq!(
        default_cparams(19, None, 0),
        p(23, 24, 22, 7, 3, 256, Btultra2)
    );
    assert_eq!(default_cparams(-5, None, 0), p(19, 12, 13, 1, 6, 5, Fast));
    assert_eq!(default_cparams(99, None, 0), default_cparams(22, None, 0));
    assert_eq!(
        default_cparams(1, Some(1000), 0),
        p(10, 10, 11, 1, 5, 0, Fast)
    );
    assert_eq!(
        default_cparams(19, Some(100_000), 0),
        p(17, 18, 17, 5, 3, 256, Btultra2)
    );
    // The CLI's `--show-default-cparams -D missing`: a dictionary of
    // unknown size is `UTIL_FILESIZE_UNKNOWN`, and libzstd's sums wrap
    // (`zstd --show-default-cparams -D missing -c` of 5000 bytes).
    assert_eq!(
        default_cparams(3, Some(5000), usize::MAX),
        p(14, 14, 15, 2, 4, 0, Dfast)
    );
}

#[test]
fn checksum_mismatch_is_22() {
    let data = text(20_000, 22);
    let mut f = encode(&EncodeOptions::default(), &data);
    let last = f.len() - 1;
    f[last] ^= 0x01;
    assert_eq!(
        code_of(decode(&DecodeOptions::default(), &f)),
        code::CHECKSUM_WRONG
    );
    let ignore = DecodeOptions {
        ignore_checksum: true,
        ..DecodeOptions::default()
    };
    assert_eq!(decode(&ignore, &f).unwrap(), data);
}

#[test]
fn multi_frame_and_skippable() {
    let a = text(70_000, 1);
    let b = rand(9_000, 2);
    let mut stream = skippable(0, 5);
    stream.extend(encode(&EncodeOptions::default(), &a));
    stream.extend(skippable(15, 0));
    stream.extend(encode(&EncodeOptions::default(), &b));
    stream.extend(skippable(7, 300_000));
    for chunk in [1, 7, 4096, 128 << 10] {
        let mut d = Decoder::new(&DecodeOptions::default()).unwrap();
        let (frames, out) = decode_with(&mut d, &stream, chunk).unwrap();
        assert_eq!(frames, 5, "chunk {chunk}");
        assert_eq!(out.len(), a.len() + b.len(), "chunk {chunk}");
        assert!(
            out[..a.len()] == a[..] && out[a.len()..] == b[..],
            "chunk {chunk}"
        );
    }
    // A frame's end is never consumed past: the next frame's bytes stay.
    let mut d = Decoder::new(&DecodeOptions::default()).unwrap();
    let one = encode(&EncodeOptions::default(), &b);
    let mut two = one.clone();
    two.extend_from_slice(&one);
    let mut out = Vec::new();
    let mut pos = 0;
    loop {
        let (used, hint) = d.decompress_stream(&two[pos..], &mut out).unwrap();
        pos += used;
        if hint == 0 {
            break;
        }
    }
    assert_eq!(pos, one.len());
    assert_eq!(out, b);
}

#[test]
fn window_limit_refuses_before_allocating() {
    // About 1.9 GiB declared; a decoder that allocated it first would
    // abort or crawl, not return a code.
    let f = window_frame(30, 7);
    let o = DecodeOptions {
        max_window_size: 1 << 20,
        ..DecodeOptions::default()
    };
    assert_eq!(code_of(decode(&o, &f)), code::WINDOW_TOO_LARGE);
    let small = window_frame(20, 0);
    assert_eq!(decode(&o, &small).unwrap(), b"");
    assert_eq!(
        code_of(decode(&o, &window_frame(20, 1))),
        code::WINDOW_TOO_LARGE
    );
    // ZSTD_DCtx_setMaxWindowSize's own bounds.
    for bad in [(1 << 10) - 1, (1 << 31) + 1] {
        let o = DecodeOptions {
            max_window_size: bad,
            ..DecodeOptions::default()
        };
        assert_eq!(code_of(Decoder::new(&o)), code::PARAMETER_OUT_OF_BOUND);
    }
}

/// libzstd's single-pass shortcut is taken before its window check: a
/// single-segment frame whose content (its window) exceeds the limit but
/// fits `ZSTD_DStreamOutSize()` decodes when it arrives whole, and is
/// refused when streamed. Both tiers hold the same two expectations.
#[test]
fn the_single_pass_shortcut_skips_the_window_check() {
    let data = text(5000, 7);
    // Single segment, a 2-byte content size (value - 256), no checksum,
    // then one last raw block of the whole content.
    let mut f = MAGIC.to_le_bytes().to_vec();
    f.push(0x60);
    f.extend_from_slice(&((data.len() - 256) as u16).to_le_bytes());
    let bh = 1 | ((data.len() as u32) << 3);
    f.extend_from_slice(&bh.to_le_bytes()[..3]);
    f.extend_from_slice(&data);
    let o = DecodeOptions {
        max_window_size: 1 << 12,
        ..DecodeOptions::default()
    };
    assert_eq!(decode(&o, &f).unwrap(), data);
    for chunk in [1, 100, 4000] {
        let mut d = Decoder::new(&o).unwrap();
        assert_eq!(
            code_of(decode_with(&mut d, &f, chunk)),
            code::WINDOW_TOO_LARGE,
            "chunk {chunk}"
        );
    }
}

#[test]
fn formatted_dictionary_decodes() {
    let dict = fixture("dict4k.dict");
    let frame = fixture("dict4k.zst");
    let o = DecodeOptions {
        dictionary: Some(dict.clone()),
        ..DecodeOptions::default()
    };
    assert_eq!(decode(&o, &frame).unwrap(), dict_plain());
    // Without it, or with another, libzstd answers "Dictionary mismatch".
    assert_eq!(
        code_of(decode(&DecodeOptions::default(), &frame)),
        code::DICTIONARY_WRONG
    );
    let mut other = dict.clone();
    other[4] ^= 1;
    let o = DecodeOptions {
        dictionary: Some(other),
        ..DecodeOptions::default()
    };
    assert_eq!(code_of(decode(&o, &frame)), code::DICTIONARY_WRONG);
}

#[test]
fn patch_from_decodes() {
    let (old, new) = patch_pair();
    let frame = fixture("patch.zst");
    let o = DecodeOptions {
        prefix: Some(old.clone()),
        max_window_size: 1 << 31,
        ..DecodeOptions::default()
    };
    assert_eq!(decode(&o, &frame).unwrap(), new);
    // The prefix serves the first frame only, as libzstd's does.
    let mut twice = frame.clone();
    twice.extend_from_slice(&frame);
    assert_eq!(code_of(decode(&o, &twice)), code::CORRUPTION_DETECTED);
}

#[test]
fn raw_content_dictionary_decodes() {
    // `-D` with a file that lacks the dictionary magic is raw content,
    // as `--patch-from`'s prefix is, but for every frame.
    let (old, new) = patch_pair();
    let frame = fixture("patch.zst");
    let o = DecodeOptions {
        dictionary: Some(old),
        max_window_size: 1 << 31,
        ..DecodeOptions::default()
    };
    let mut twice = frame.clone();
    twice.extend_from_slice(&frame);
    let mut both = new.clone();
    both.extend_from_slice(&new);
    assert_eq!(decode(&o, &twice).unwrap(), both);
}

#[test]
fn a_corrupt_formatted_dictionary_is_refused() {
    let mut dict = fixture("dict4k.dict");
    dict.truncate(12);
    let o = DecodeOptions {
        dictionary: Some(dict),
        ..DecodeOptions::default()
    };
    // libzstd's ZSTD_createDDict fails, and ZSTD_DCtx_loadDictionary
    // reports that as an allocation failure.
    assert_eq!(code_of(Decoder::new(&o)), code::MEMORY_ALLOCATION);
}

#[test]
fn content_size_mismatch_codes() {
    // dict4k.zst is single-segment with a content size of 3000.
    let dict = fixture("dict4k.dict");
    let o = DecodeOptions {
        dictionary: Some(dict),
        ..DecodeOptions::default()
    };
    let frame = fixture("dict4k.zst");
    let FrameHeader::Zstd { header_size, .. } = frame_header(&frame).unwrap() else {
        panic!()
    };
    let fcs_at = header_size - 2;
    let mut less = frame.clone();
    less[fcs_at] -= 1;
    // Declaring less than decodes: libzstd's single-pass shortcut (the
    // whole frame in one call) finds the mismatch at the end...
    assert_eq!(code_of(decode(&o, &less)), code::CORRUPTION_DETECTED);
    // ...while streaming runs out of a buffer sized to the content.
    for chunk in [3, 100] {
        let mut d = Decoder::new(&o).unwrap();
        assert_eq!(
            code_of(decode_with(&mut d, &less, chunk)),
            code::DST_SIZE_TOO_SMALL
        );
    }
    // Declaring more is corruption either way.
    let mut more = frame.clone();
    more[fcs_at] += 1;
    assert_eq!(code_of(decode(&o, &more)), code::CORRUPTION_DETECTED);
    let mut d = Decoder::new(&o).unwrap();
    assert_eq!(
        code_of(decode_with(&mut d, &more, 100)),
        code::CORRUPTION_DETECTED
    );
}

// ------------------------------------------------------------------ C tier

#[cfg(feature = "zstd-c")]
mod c_tier {
    use super::*;
    use zstd::zstd_safe::zstd_sys as sys;

    /// The vendored table: `<input>|<zstd flags>|<sha256>`.
    const REF: &str = include_str!("../../tests/data/zstd_opts/ref.txt");

    #[test]
    fn libzstd_is_1_5_7() {
        assert_eq!(libzstd_version(), "1.5.7");
    }

    /// The [`EncodeOptions`] `zstd <flags>` builds for a file of `len`
    /// bytes, for the flags the fixture uses.
    fn options(flags: &str, len: usize) -> EncodeOptions {
        let mut o = EncodeOptions {
            pledged_size: Some(len as u64),
            workers: 3,
            ..EncodeOptions::default()
        };
        for f in flags.split_whitespace() {
            if let Some(n) = f.strip_prefix("--fast=") {
                o.level = -n.parse::<i32>().unwrap();
            } else if f == "--ultra" {
            } else if f == "--single-thread" {
                o.workers = 0;
            } else if let Some(n) = f.strip_prefix("-T") {
                o.workers = n.parse().unwrap();
            } else if f == "--no-check" {
                o.checksum = false;
            } else if f == "--no-content-size" {
                o.content_size = false;
            } else if f == "--rsyncable" {
                o.rsyncable = true;
            } else if let Some(n) = f.strip_prefix("--long=") {
                o.ldm = ParamSwitch::Enable;
                o.overrides.push((CParamKey::WindowLog, n.parse().unwrap()));
            } else if let Some(n) = f.strip_prefix("--target-compressed-block-size=") {
                o.target_cblock_size = n.parse().unwrap();
            } else if let Some(list) = f.strip_prefix("--zstd=") {
                for kv in list.split(',') {
                    let (k, v) = kv.split_once('=').unwrap();
                    let key = match k {
                        "wlog" => CParamKey::WindowLog,
                        "clog" => CParamKey::ChainLog,
                        "hlog" => CParamKey::HashLog,
                        "slog" => CParamKey::SearchLog,
                        "mml" => CParamKey::MinMatch,
                        "tlen" => CParamKey::TargetLength,
                        "strat" => CParamKey::Strategy,
                        _ => panic!("{k}"),
                    };
                    o.overrides.push((key, v.parse().unwrap()));
                }
            } else if let Some(n) = f.strip_prefix('-') {
                o.level = n.parse().unwrap();
            } else {
                panic!("flag {f}");
            }
        }
        o
    }

    /// The encoder rows of `ref.txt`.
    fn rows() -> Vec<(&'static str, &'static str, &'static str)> {
        REF.lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty() && !l.starts_with("train|"))
            .map(|l| {
                let mut it = l.split('|');
                (it.next().unwrap(), it.next().unwrap(), it.next().unwrap())
            })
            .collect()
    }

    #[test]
    fn matches_the_reference_fixture() {
        let inputs = inputs();
        let rows = rows();
        assert!(rows.len() >= 50, "{} rows", rows.len());
        for (name, flags, sha) in &rows {
            let data = &inputs.iter().find(|(n, _)| n == name).unwrap().1;
            let ours = encode(&options(flags, data.len()), data);
            assert_eq!(&sha256(&ours), sha, "{name} {flags}");
            assert_eq!(
                decode(&DecodeOptions::default(), &ours).unwrap(),
                *data,
                "{name} {flags}"
            );
        }
    }

    /// Four of the fixture's rows re-derived from the reference itself,
    /// where it is installed: the table is what zstd 1.5.7 writes.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_fixture_is_still_what_zstd_emits() {
        let Some(zstd) = reference() else {
            return;
        };
        let inputs = inputs();
        let dir = std::env::temp_dir().join(format!("stuffr-zstd-opts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, flags, sha) in rows().into_iter().filter(|(n, f, _)| {
            matches!(
                (*n, *f),
                ("text", "-3") | ("bin", "-19 --single-thread") | ("rand", "--fast=5")
            ) || f.contains("--zstd=")
        }) {
            let path = dir.join(name);
            let data = &inputs.iter().find(|(n, _)| *n == name).unwrap().1;
            std::fs::write(&path, data).unwrap();
            let mut args: Vec<&str> = flags.split_whitespace().collect();
            let p = path.to_str().unwrap();
            args.extend(["-q", "-c", p]);
            let theirs = run_reference(&zstd, &args, b"").unwrap();
            assert_eq!(sha256(&theirs), sha, "{name} {flags}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_cparams_match_getcparams() {
        let sizes = [
            None,
            Some(1000),
            Some(1u64 << 10),
            Some(100_000),
            Some(100 << 10),
            Some(300 << 10),
            Some(1 << 20),
        ];
        for level in -5..=22 {
            for src in sizes {
                for dict in [0usize, 110 << 10] {
                    // SAFETY: ZSTD_getCParams is a pure function of its
                    // arguments.
                    let c = unsafe { sys::ZSTD_getCParams(level, src.unwrap_or(0), dict) };
                    let ours = default_cparams(level, src, dict);
                    let theirs = (
                        c.windowLog,
                        c.chainLog,
                        c.hashLog,
                        c.searchLog,
                        c.minMatch,
                        c.targetLength,
                        c.strategy as u32,
                    );
                    let mine = (
                        ours.window_log,
                        ours.chain_log,
                        ours.hash_log,
                        ours.search_log,
                        ours.min_match,
                        ours.target_length,
                        ours.strategy as u32,
                    );
                    assert_eq!(mine, theirs, "level {level} src {src:?} dict {dict}");
                }
            }
        }
    }

    /// `DiB_shuffle` over `n` names: the order `dibio.c` loads them in.
    fn dib_shuffle(n: usize) -> Vec<usize> {
        let mut order: Vec<usize> = (0..n).collect();
        let mut seed: u32 = 0xFD2F_B528;
        for i in (1..n).rev() {
            seed = seed.wrapping_mul(2_654_435_761);
            seed ^= 2_246_822_519;
            seed = seed.rotate_left(13);
            let j = (seed >> 5) as usize % (i + 1);
            order.swap(i, j);
        }
        order
    }

    /// The samples as `DiB_loadFiles` lays them out.
    fn loaded() -> (Vec<u8>, Vec<usize>) {
        let s = samples();
        let mut buf = Vec::new();
        let mut sizes = Vec::new();
        for i in dib_shuffle(s.len()) {
            buf.extend_from_slice(&s[i].1);
            sizes.push(s[i].1.len());
        }
        (buf, sizes)
    }

    fn train_params(flags: &str) -> TrainParams {
        let algo = match flags {
            "--train" => TrainAlgo::Fastcover {
                k: 0,
                d: 8,
                f: 20,
                steps: 4,
                split: 0.75,
                accel: 1,
                shrink: None,
            },
            "--train-cover=k=64,d=8" => TrainAlgo::Cover {
                k: 64,
                d: 8,
                steps: 4,
                split: 1.0,
                shrink: None,
            },
            "--train --maxdict=4096" => TrainAlgo::Fastcover {
                k: 0,
                d: 8,
                f: 20,
                steps: 4,
                split: 0.75,
                accel: 1,
                shrink: None,
            },
            other => panic!("{other}"),
        };
        let optimize = !matches!(algo, TrainAlgo::Cover { .. });
        TrainParams {
            algo,
            optimize,
            max_dict: if flags.ends_with("4096") {
                4096
            } else {
                110 << 10
            },
            dict_id: 0,
            level: 3,
            threads: 1,
            notification: 0,
        }
    }

    /// The fastcover rows (`--train`, its optimising search, and the
    /// 4 KiB dictionary) are byte-identical to the reference's. The cover
    /// row is not pinned: `ZDICT_trainFromBuffer_cover` in libzstd 1.5.7
    /// gives one of two dictionaries for the same samples depending on the
    /// process — measured with the Homebrew CLI (always one), the Homebrew
    /// dylib called from another process (always the other), and this
    /// build (either, fixed per process). What it must do here is train a
    /// formatted dictionary that compresses and decodes.
    #[test]
    fn train_matches_the_reference() {
        let (buf, sizes) = loaded();
        let rows: Vec<_> = REF
            .lines()
            .filter_map(|l| l.strip_prefix("train|"))
            .map(|l| l.split_once('|').unwrap())
            .collect();
        assert_eq!(rows.len(), 3);
        for (flags, sha) in rows {
            let t = train(&buf, &sizes, &train_params(flags)).unwrap();
            if flags.starts_with("--train-cover") {
                assert_eq!((t.chosen_k, t.chosen_d, t.chosen_steps), (64, 8, 4));
                assert_eq!(t.dict.len(), 110 << 10);
                assert_ne!(dict_id(&t.dict), 0);
                let o = EncodeOptions {
                    dictionary: Some(t.dict.clone()),
                    ..EncodeOptions::default()
                };
                let f = encode(&o, &dict_plain());
                let d = DecodeOptions {
                    dictionary: Some(t.dict),
                    ..DecodeOptions::default()
                };
                assert_eq!(decode(&d, &f).unwrap(), dict_plain());
                continue;
            }
            assert_eq!(sha256(&t.dict), sha, "{flags}");
            if flags == "--train --maxdict=4096" {
                assert_eq!(t.dict, fixture("dict4k.dict"));
            }
            if flags == "--train" {
                assert_eq!((t.chosen_d, t.chosen_f, t.chosen_steps), (8, 20, 4));
                assert_ne!(t.chosen_k, 0);
                assert_eq!((t.chosen_accel, t.chosen_split), (1, 0.75));
            }
        }
        // Legacy runs too (over the guard band dibio.c appends).
        let p = TrainParams {
            algo: TrainAlgo::Legacy { selectivity: 9 },
            optimize: false,
            ..train_params("--train")
        };
        let t = train(&buf, &sizes, &p).unwrap();
        assert_ne!(dict_id(&t.dict), 0);
        // Sizes past the buffer are refused, never read.
        let mut bad = sizes.clone();
        bad[0] += buf.len();
        assert_eq!(
            code_of(train(&buf, &bad, &train_params("--train"))),
            code::SRC_SIZE_WRONG
        );
    }

    #[test]
    fn patch_from_round_trips() {
        let (old, new) = patch_pair();
        let o = EncodeOptions {
            prefix: Some(old.clone()),
            pledged_size: Some(new.len() as u64),
            ldm: ParamSwitch::Enable,
            overrides: vec![(CParamKey::WindowLog, 19)],
            ..EncodeOptions::default()
        };
        let f = encode(&o, &new);
        assert!(f.len() < new.len() / 10, "{} bytes", f.len());
        let d = DecodeOptions {
            prefix: Some(old.clone()),
            ..DecodeOptions::default()
        };
        assert_eq!(decode(&d, &f).unwrap(), new);
        assert_ne!(
            decode(&DecodeOptions::default(), &f).ok(),
            Some(new.clone())
        );
        #[cfg(unix)]
        if let Some(zstd) = reference() {
            let dir =
                std::env::temp_dir().join(format!("stuffr-zstd-patch-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let p = dir.join("old");
            std::fs::write(&p, &old).unwrap();
            let pf = format!("--patch-from={}", p.display());
            let back = run_reference(&zstd, &["-d", "-c", &pf], &f).unwrap();
            let _ = std::fs::remove_dir_all(&dir);
            assert_eq!(back, new);
        }
    }

    #[test]
    fn window_limit_refuses() {
        // An unknown size, fed in pieces, keeps the window log asked for
        // (one `End` call with everything would let libzstd size it).
        let o = EncodeOptions {
            overrides: vec![(CParamKey::WindowLog, 24)],
            ..EncodeOptions::default()
        };
        let data = text(2 << 20, 4);
        let f = encode(&o, &data);
        let small = DecodeOptions {
            max_window_size: 1 << 20,
            ..DecodeOptions::default()
        };
        assert_eq!(code_of(decode(&small, &f)), code::WINDOW_TOO_LARGE);
        let enough = DecodeOptions {
            max_window_size: 1 << 24,
            ..DecodeOptions::default()
        };
        assert_eq!(decode(&enough, &f).unwrap(), data);
    }

    #[test]
    fn dictionary_encode_round_trips() {
        let dict = fixture("dict4k.dict");
        let o = EncodeOptions {
            dictionary: Some(dict.clone()),
            pledged_size: Some(3000),
            ..EncodeOptions::default()
        };
        let ours = encode(&o, &dict_plain());
        // The reference's own frame for the same input and dictionary.
        assert_eq!(ours, fixture("dict4k.zst"));
    }

    /// `FIO_setSrcSizeHint` clamps to `INT_MAX`; a larger hint must not
    /// wrap negative (refused) or past 2^32 (other bytes).
    #[test]
    fn src_size_hint_clamps_to_int_max() {
        let data = text(300_000, 8);
        let with = |h: u64| {
            encode(
                &EncodeOptions {
                    src_size_hint: Some(h),
                    ..EncodeOptions::default()
                },
                &data,
            )
        };
        let max = with(i32::MAX as u64);
        assert_eq!(with(3 << 30), max);
        assert_eq!(with((1 << 32) + 1000), max);
        assert_eq!(decode(&DecodeOptions::default(), &max).unwrap(), data);
    }

    #[test]
    fn progression_and_level_changes() {
        let o = EncodeOptions {
            workers: 2,
            ..EncodeOptions::default()
        };
        let mut e = Encoder::new(&o).unwrap();
        let data = text(1 << 20, 5);
        let mut out = Vec::new();
        e.compress_stream(&data[..1 << 19], &mut out, EndOp::Continue)
            .unwrap();
        e.set_level(1).unwrap();
        let _ = e.to_flush_now();
        e.compress_stream(&data[1 << 19..], &mut out, EndOp::End)
            .unwrap();
        let p = e.progression();
        assert_eq!(p.ingested, data.len() as u64);
        assert_eq!(p.flushed, out.len() as u64);
        assert_eq!(decode(&DecodeOptions::default(), &out).unwrap(), data);
    }

    /// Regenerates every fixture into `$STUFFR_ZSTD_OPTS_REGEN` from the
    /// reference: `ref.txt`, `dict4k.dict`, `dict4k.zst` and `patch.zst`.
    #[cfg(unix)]
    #[test]
    fn regenerate_fixtures() {
        let Some(dir) = std::env::var_os("STUFFR_ZSTD_OPTS_REGEN") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        let zstd = reference().expect("the reference zstd 1.5.7");
        let work = dir.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let mut table = String::from(HEADER);
        let levels = ["--fast=5", "-1", "-3", "-9", "-19", "--ultra -22"];
        let inputs = inputs();
        for (name, data) in &inputs {
            let p = work.join(name);
            std::fs::write(&p, data).unwrap();
            for level in levels {
                for mode in ["", " --single-thread", " -T4"] {
                    let flags = format!("{level}{mode}");
                    let mut args: Vec<&str> = flags.split_whitespace().collect();
                    let ps = p.to_str().unwrap();
                    args.extend(["-q", "-c", ps]);
                    let out = run_reference(&zstd, &args, b"").unwrap();
                    table += &format!("{name}|{flags}|{}\n", sha256(&out));
                }
            }
        }
        for flags in [
            "-3 --single-thread --no-check",
            "-3 --single-thread --no-content-size",
            "-3 -T2 --rsyncable",
            "-19 --single-thread --long=24",
            "-3 --single-thread --zstd=wlog=18,clog=16,hlog=17,slog=3,mml=5,tlen=8,strat=5",
            "-6 --zstd=strat=9,tlen=64",
            "-3 --single-thread --target-compressed-block-size=1024",
        ] {
            let p = work.join("text");
            let mut args: Vec<&str> = flags.split_whitespace().collect();
            let ps = p.to_str().unwrap();
            args.extend(["-q", "-c", ps]);
            let out = run_reference(&zstd, &args, b"").unwrap();
            table += &format!("text|{flags}|{}\n", sha256(&out));
        }
        // Training: the samples as files s000..s099, given in that order.
        let sdir = work.join("samples");
        std::fs::create_dir_all(&sdir).unwrap();
        let names: Vec<String> = samples()
            .into_iter()
            .map(|(n, d)| {
                let p = sdir.join(&n);
                std::fs::write(&p, d).unwrap();
                p.to_str().unwrap().to_owned()
            })
            .collect();
        for flags in [
            "--train",
            "--train-cover=k=64,d=8",
            "--train --maxdict=4096",
        ] {
            let out = work.join("dict");
            let _ = std::fs::remove_file(&out);
            let mut args: Vec<&str> = flags.split_whitespace().collect();
            args.extend(["-q", "-f", "-o", out.to_str().unwrap()]);
            args.extend(names.iter().map(String::as_str));
            run_reference(&zstd, &args, b"").unwrap();
            let d = std::fs::read(&out).unwrap();
            table += &format!("train|{flags}|{}\n", sha256(&d));
            if flags.ends_with("4096") {
                std::fs::write(dir.join("dict4k.dict"), &d).unwrap();
            }
        }
        let dict = dir.join("dict4k.dict");
        let plain = work.join("plain");
        std::fs::write(&plain, dict_plain()).unwrap();
        let f = run_reference(
            &zstd,
            &[
                "-q",
                "-c",
                "-D",
                dict.to_str().unwrap(),
                plain.to_str().unwrap(),
            ],
            b"",
        )
        .unwrap();
        std::fs::write(dir.join("dict4k.zst"), f).unwrap();
        let (old, new) = patch_pair();
        std::fs::write(work.join("old"), old).unwrap();
        std::fs::write(work.join("new"), new).unwrap();
        let pf = format!("--patch-from={}", work.join("old").display());
        let f = run_reference(
            &zstd,
            &["-q", "-c", &pf, work.join("new").to_str().unwrap()],
            b"",
        )
        .unwrap();
        std::fs::write(dir.join("patch.zst"), f).unwrap();
        std::fs::write(dir.join("ref.txt"), table).unwrap();
        let _ = std::fs::remove_dir_all(&work);
        // SAFETY: the pointer and length describe the dictionary file read
        // back; ZDICT_getDictHeaderSize only reads it.
        let d = std::fs::read(dir.join("dict4k.dict")).unwrap();
        let hs = unsafe { sys::ZDICT_getDictHeaderSize(d.as_ptr().cast(), d.len()) };
        eprintln!("dict4k header: {hs} bytes: {:?}", &d[..hs]);
    }

    const HEADER: &str = "\
# zstd_opts fixture: `<input>|<zstd flags>|<sha256>`, the SHA-256 of
# `zstd <flags> -q -c <input>` (zstd 1.5.7, /opt/homebrew/opt/zstd/bin/zstd,
# a 12-core machine, so the default is 3 workers) over the inputs
# `src/zstd_opts/tests.rs` generates (`inputs()`: text, bin, rand, empty);
# and `train|<flags>|<sha256>`, the dictionary `zstd <flags> -o d s000 ..
# s099` writes over `samples()` saved as files. dict4k.dict is the
# `--maxdict=4096` dictionary, dict4k.zst `zstd -D dict4k.dict` over
# `dict_plain()`, patch.zst `zstd --patch-from=old new` over `patch_pair()`.
# The --train-cover row is the CLI's output, recorded but not asserted:
# libzstd 1.5.7's cover trainer gives one of two dictionaries for these
# samples depending on the process (see train_matches_the_reference).
# Regenerate everything with `STUFFR_ZSTD_OPTS_REGEN=<dir> cargo test
# -p stuffr-formats --all-features zstd_opts::tests::c_tier::regenerate_fixtures`,
# then copy <dir>/* here (macOS, the reference zstd 1.5.7 present).
";
}

// --------------------------------------------------------------- pure tier

#[cfg(all(feature = "zstd-pure", not(feature = "zstd-c")))]
mod pure_tier {
    /// `ZSTD_getFrameProgression` counts the frame in progress: a second
    /// frame starts from zero (the progress line of a second file) and
    /// the finished frame's figures stay until then.
    #[test]
    fn progression_restarts_with_each_frame() {
        let mut e = Encoder::new(&EncodeOptions::default()).unwrap();
        let data = text(4096, 3);
        let mut out = Vec::new();
        e.compress_stream(&data, &mut out, EndOp::End).unwrap();
        let first = e.progression();
        assert_eq!((first.ingested, first.consumed), (4096, 4096));
        assert_eq!(first.produced, out.len() as u64);
        let mut out2 = Vec::new();
        e.compress_stream(&data[..1000], &mut out2, EndOp::Continue)
            .unwrap();
        let mid = e.progression();
        assert_eq!((mid.ingested, mid.consumed, mid.produced), (1000, 0, 0));
        e.compress_stream(&data[1000..], &mut out2, EndOp::End)
            .unwrap();
        let second = e.progression();
        assert_eq!((second.ingested, second.consumed), (4096, 4096));
        assert_eq!(second.produced, out2.len() as u64);
    }

    use super::*;

    #[test]
    fn windowlog_max_follows_the_pointer_width() {
        let want = if usize::BITS == 32 { 30 } else { 31 };
        assert_eq!(WINDOWLOG_MAX, want);
    }

    #[test]
    fn libzstd_version_is_pinned() {
        assert_eq!(libzstd_version(), "1.5.7");
    }

    #[test]
    fn pure_round_trips_and_the_reference_reads_it() {
        #[cfg(unix)]
        let zstd = reference();
        let mut r = Lcg(0x64);
        for case in 0..64u64 {
            let n = match case % 4 {
                0 => r.next() as usize % 100,
                1 => r.next() as usize % 5000,
                2 => r.next() as usize % 300_000,
                _ => 128 << 10,
            };
            let data = if case % 3 == 0 {
                rand(n, case)
            } else {
                text(n, case)
            };
            let o = EncodeOptions {
                checksum: case % 5 != 0,
                level: (r.next() % 30) as i32 - 7,
                ..EncodeOptions::default()
            };
            let f = encode(&o, &data);
            let mut d = Decoder::new(&DecodeOptions::default()).unwrap();
            let chunk = 1 + r.next() as usize % 70_000;
            let (frames, out) = decode_with(&mut d, &f, chunk).unwrap();
            assert_eq!((frames, out.len()), (1, data.len()), "case {case}");
            assert!(out == data, "case {case}");
            #[cfg(unix)]
            if let Some(zstd) = &zstd {
                let back = run_reference(zstd, &["-d", "-c"], &f);
                assert!(back.as_deref() == Some(&data[..]), "case {case}");
            }
        }
    }

    #[test]
    fn no_check_strips_the_checksum() {
        let data = text(50_000, 6);
        let with = encode(&EncodeOptions::default(), &data);
        let without = encode(
            &EncodeOptions {
                checksum: false,
                ..EncodeOptions::default()
            },
            &data,
        );
        assert_ne!(with[4] & 0x04, 0);
        let mut expect = with[..with.len() - 4].to_vec();
        expect[4] &= !0x04;
        assert_eq!(without, expect);
        assert_eq!(decode(&DecodeOptions::default(), &without).unwrap(), data);
        // The adapter itself, fed a byte at a time.
        let mut sink = Vec::new();
        let mut s = pure::ChecksumStrip::new(&mut sink, false);
        for b in &with {
            std::io::Write::write_all(&mut s, std::slice::from_ref(b)).unwrap();
        }
        s.finish().unwrap();
        assert_eq!(sink, expect);
        #[cfg(unix)]
        if let Some(zstd) = reference() {
            assert_eq!(run_reference(&zstd, &["-d", "-c"], &without).unwrap(), data);
        }
    }

    #[test]
    fn dictionary_encode_is_unsupported() {
        for o in [
            EncodeOptions {
                dictionary: Some(fixture("dict4k.dict")),
                ..EncodeOptions::default()
            },
            EncodeOptions {
                prefix: Some(b"prefix".to_vec()),
                ..EncodeOptions::default()
            },
        ] {
            assert!(matches!(
                Encoder::new(&o),
                Err(ZstdError::Unsupported("dictionary"))
            ));
        }
        let p = TrainParams {
            algo: TrainAlgo::Legacy { selectivity: 9 },
            optimize: false,
            max_dict: 4096,
            dict_id: 0,
            level: 3,
            threads: 1,
            notification: 0,
        };
        assert!(matches!(
            train(b"abc", &[3], &p),
            Err(ZstdError::Unsupported("train"))
        ));
    }
}

/// Both tiers hold a frame to its pledged size, as libzstd does: more or
/// less input is `srcSize_wrong`; the right size, or none, compresses. A
/// frame whose first call ends it takes that call's size as its pledge
/// (`ZSTD_CCtx_init_compressStream2`), so the input is first given with
/// `Continue`, as `fileio.c` gives standard input.
#[test]
fn a_frame_is_held_to_its_pledged_size() {
    let data = text(5000, 31);
    let pledged = |n: u64| {
        let mut e = Encoder::new(&EncodeOptions {
            pledged_size: Some(n),
            ..EncodeOptions::default()
        })
        .unwrap();
        let mut out = Vec::new();
        e.compress_stream(&data, &mut out, EndOp::Continue)?;
        e.compress_stream(&[], &mut out, EndOp::End)
    };
    let one_call = |n: u64| {
        let mut e = Encoder::new(&EncodeOptions {
            pledged_size: Some(n),
            ..EncodeOptions::default()
        })
        .unwrap();
        e.compress_stream(&data, &mut Vec::new(), EndOp::End)
    };
    assert!(one_call(4999).is_ok() && one_call(5001).is_ok());
    assert!(pledged(5000).is_ok());
    assert_eq!(code_of(pledged(4999)), code::SRC_SIZE_WRONG);
    assert_eq!(code_of(pledged(5001)), code::SRC_SIZE_WRONG);
    // The pledge is for one frame: the next one is free again.
    let mut e = Encoder::new(&EncodeOptions::default()).unwrap();
    e.set_pledged_size(Some(5000)).unwrap();
    let mut out = Vec::new();
    e.compress_stream(&data, &mut out, EndOp::End).unwrap();
    e.compress_stream(&data[..10], &mut out, EndOp::End)
        .unwrap();
    assert_eq!(decode(&DecodeOptions::default(), &out).unwrap().len(), 5010);
}

/// `compress_stream_each` reports the calls `fileio.c` traces at display
/// level 6: the directive, the input taken and the bytes produced, adding
/// up to the frame.
#[test]
fn each_compress_call_is_reported() {
    let data = text(300_000, 32);
    let mut e = Encoder::new(&EncodeOptions::default()).unwrap();
    let mut out = Vec::new();
    let mut calls = Vec::new();
    for (i, c) in data.chunks(128 << 10).enumerate() {
        let end = if i == 2 { EndOp::End } else { EndOp::Continue };
        e.compress_stream_each(c, &mut out, end, &mut |call| calls.push(call))
            .unwrap();
    }
    assert!(!calls.is_empty());
    assert_eq!(calls.last().unwrap().end, EndOp::End);
    assert!(calls.iter().all(|c| c.input_pos <= c.input_size));
    assert_eq!(calls.iter().map(|c| c.produced).sum::<usize>(), out.len());
    assert_eq!(decode(&DecodeOptions::default(), &out).unwrap(), data);
}

/// `compress_stream2` is one call of `fileio.c`'s inner loop: driven the
/// way that loop drives it (until the input is taken and, at the end,
/// nothing is left to flush), it writes what `compress_stream` writes, and
/// on the C tier no call produces more than one output buffer.
#[test]
fn single_calls_make_the_same_frame() {
    let data = text(300_000, 34);
    let o = EncodeOptions {
        workers: 2,
        ..EncodeOptions::default()
    };
    let mut whole = Vec::new();
    let mut e = Encoder::new(&o).unwrap();
    let mut stepped = Vec::new();
    let chunks: Vec<&[u8]> = data.chunks(128 << 10).collect();
    for (i, c) in chunks.iter().enumerate() {
        let end = if i + 1 == chunks.len() {
            EndOp::End
        } else {
            EndOp::Continue
        };
        let mut pos = 0;
        let mut still = 1;
        while pos != c.len() || (end == EndOp::End && still != 0) {
            let before = stepped.len();
            still = e.compress_stream2(c, &mut pos, &mut stepped, end).unwrap();
            // ZSTD_CStreamOutSize(), a block's bound and its header, on
            // the C tier; the pure tier writes its frame in one call.
            assert!(cfg!(not(feature = "zstd-c")) || stepped.len() - before < 132 << 10);
        }
    }
    let mut e = Encoder::new(&o).unwrap();
    for (i, c) in chunks.iter().enumerate() {
        let end = if i + 1 == chunks.len() {
            EndOp::End
        } else {
            EndOp::Continue
        };
        e.compress_stream(c, &mut whole, end).unwrap();
    }
    assert_eq!(stepped, whole);
    assert_eq!(decode(&DecodeOptions::default(), &stepped).unwrap(), data);
}

/// A frame cut inside its checksum: the last block's output comes out
/// before the decoder asks for the rest, as libzstd's does
/// (`ZSTDds_checkChecksum`), so `fileio.c` writes it before saying
/// "premature end".
#[test]
fn the_last_block_is_out_before_its_checksum_is_read() {
    let data = text(3000, 33);
    let frame = encode(&EncodeOptions::default(), &data);
    let cut = &frame[..frame.len() - 2];
    let mut d = Decoder::new(&DecodeOptions::default()).unwrap();
    let mut out = Vec::new();
    let mut pos = 0;
    loop {
        let (used, hint) = d.decompress_stream(&cut[pos..], &mut out).unwrap();
        pos += used;
        assert_ne!(hint, 0, "the frame cannot end without its checksum");
        if used == 0 {
            assert_eq!(hint, 2, "the two missing checksum bytes");
            break;
        }
    }
    assert_eq!(out, data);
}
