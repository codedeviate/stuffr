//! `xz_opts`'s unit tests. The C-tier ones pin liblzma's bytes against
//! `xz -T1` through a vendored fixture, `tests/data/xz_opts/t1.txt`.

use super::*;

#[test]
fn preset_rejects_levels_above_nine() {
    assert!(Lzma::preset(10, false).is_none());
    assert!(Lzma::preset(10, true).is_none());
    let six = Lzma::preset(6, false).unwrap();
    assert_eq!((six.dict_size, six.nice_len, six.depth), (8 << 20, 64, 0));
    assert_eq!((six.mode, six.mf), (Mode::Normal, MatchFinder::Bt4));
}

/// A fixed 64-bit LCG (Knuth's MMIX constants), so every input is the same
/// on every machine and every run.
#[cfg_attr(not(feature = "xz-c"), allow(dead_code))] // the pure tier's tests come in Task 2
struct Lcg(u64);

#[cfg_attr(not(feature = "xz-c"), allow(dead_code))] // the pure tier's tests come in Task 2
impl Lcg {
    fn next(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) as u32
    }
}

#[cfg_attr(not(feature = "xz-c"), allow(dead_code))] // the pure tier's tests come in Task 2
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
#[cfg_attr(not(feature = "xz-c"), allow(dead_code))] // the pure tier's tests come in Task 2
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

/// 64 KiB shaped like x86 code: a few common opcodes, `call rel32` with
/// small displacements, ModRM-ish operand bytes.
#[cfg_attr(not(feature = "xz-c"), allow(dead_code))] // the pure tier's tests come in Task 2
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
#[cfg_attr(not(feature = "xz-c"), allow(dead_code))] // the pure tier's tests come in Task 2
fn rand(n: usize) -> Vec<u8> {
    let mut r = Lcg(0x5eed);
    (0..n).map(|_| (r.next() >> 16) as u8).collect()
}

/// The fixture's four inputs, by name.
#[cfg_attr(not(feature = "xz-c"), allow(dead_code))] // the pure tier's tests come in Task 2
fn inputs() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("text", text(300_000, 0x7e47)),
        ("bin", bin()),
        ("rand", rand(50_000)),
        ("empty", Vec::new()),
    ]
}

/// SHA-256 (FIPS 180-4), small and slow, for the fixture's digests; the
/// crate has no hash dependency and this test is the only user.
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
    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in block.chunks_exact(4).enumerate() {
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
        sha256(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[cfg(feature = "xz-c")]
mod c_tier {
    use super::*;

    /// The vendored table: `<input> <preset>[e] <sha256 of xz -T1 output>`.
    const T1: &str = include_str!("../../tests/data/xz_opts/t1.txt");

    fn preset_opts(level: u32, extreme: bool, threads: u32) -> EncodeOptions {
        EncodeOptions {
            filters: vec![Filter::Lzma2(Lzma::preset(level, extreme).unwrap())],
            threads,
            ..EncodeOptions::default()
        }
    }

    /// Encodes `input` in uneven pieces, so the result cannot lean on one
    /// `feed` call.
    fn encode(o: &EncodeOptions, input: &[u8]) -> Vec<u8> {
        let mut e = Encoder::new(o).unwrap();
        let mut out = Vec::new();
        for piece in input.chunks(7_919) {
            e.feed(piece, &mut out).unwrap();
        }
        e.finish(&mut out).unwrap();
        assert_eq!(
            e.progress(),
            Progress {
                in_bytes: input.len() as u64,
                out_bytes: out.len() as u64
            }
        );
        out
    }

    fn decode(o: &DecodeOptions, data: &[u8]) -> Result<Vec<u8>, XzError> {
        let mut d = Decoder::new(o)?;
        let mut out = Vec::new();
        for piece in data.chunks(4_093) {
            d.feed(piece, &mut out)?;
        }
        d.finish(&mut out)?;
        Ok(out)
    }

    fn table_line(name: &str, level: u32, extreme: bool, digest: &str) -> String {
        let e = if extreme { "e" } else { "" };
        format!("{name} {level}{e} {digest}")
    }

    #[test]
    fn liblzma_is_5_8_4() {
        assert_eq!(liblzma_version(), "5.8.4");
    }

    /// `liblzma-sys` compiles `tuklib_physmem.c`/`tuklib_cpucores.c`
    /// without any `TUKLIB_PHYSMEM_*`/`TUKLIB_CPUCORES_*` method, so on
    /// unix both fall through to "unknown". `xz`'s own build has them; the
    /// CLI's `hardware.rs` must not take its figures from here. If this
    /// starts failing, `liblzma-sys`'s `config.h` grew the defines.
    #[cfg(unix)]
    #[test]
    fn hardware_queries_are_unknown_in_this_build() {
        assert_eq!((physmem(), cputhreads()), (0, 0));
    }

    #[test]
    fn preset_is_lzma_lzma_preset() {
        for level in 0..=10 {
            for extreme in [false, true] {
                assert_eq!(
                    Lzma::preset(level, extreme),
                    c::lzma_preset_of_liblzma(level, extreme),
                    "level {level} extreme {extreme}"
                );
            }
        }
    }

    #[test]
    fn single_thread_matches_the_spike_fixture() {
        let want: Vec<&str> = T1
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .collect();
        let mut got = Vec::new();
        for (name, input) in inputs() {
            for extreme in [false, true] {
                for level in 0..=9 {
                    let out = encode(&preset_opts(level, extreme, 0), &input);
                    got.push(table_line(name, level, extreme, &sha256(&out)));
                }
            }
        }
        assert_eq!(got.len(), 80);
        assert_eq!(got, want, "regenerated table:\n{}", got.join("\n"));
    }

    #[test]
    fn round_trips_every_format() {
        let plain = text(100_000, 3);
        let lzma1 = Lzma::preset(2, false).unwrap();
        let cases = [
            (Format::Xz, vec![Filter::Lzma2(lzma1.clone())]),
            (Format::Lzma, vec![Filter::Lzma1(lzma1.clone())]),
            (
                Format::Raw,
                vec![
                    Filter::Delta { dist: 3 },
                    Filter::Bcj {
                        kind: Bcj::X86,
                        start: 16,
                    },
                    Filter::Lzma1Ext(lzma1.clone()),
                ],
            ),
            (Format::Raw, vec![Filter::Lzma2(lzma1)]),
        ];
        for (format, filters) in cases {
            let packed = encode(
                &EncodeOptions {
                    format,
                    filters: filters.clone(),
                    ..EncodeOptions::default()
                },
                &plain,
            );
            let o = DecodeOptions {
                format,
                raw_filters: filters,
                ..DecodeOptions::default()
            };
            assert_eq!(decode(&o, &packed).unwrap(), plain, "{format:?}");
            if format != Format::Raw {
                let auto = DecodeOptions { auto: true, ..o };
                assert_eq!(decode(&auto, &packed).unwrap(), plain, "auto {format:?}");
            }
        }
    }

    #[test]
    fn multithread_ignores_thread_count() {
        let input = text(1 << 20, 0x1d);
        let two = encode(&preset_opts(6, false, 2), &input);
        let eight = encode(&preset_opts(6, false, 8), &input);
        let one = encode(&preset_opts(6, false, 0), &input);
        assert_eq!(two, eight);
        assert_ne!(two, one);
        for threads in [1, 2] {
            let o = DecodeOptions {
                threads,
                memlimit_threading: u64::MAX,
                ..DecodeOptions::default()
            };
            assert_eq!(decode(&o, &two).unwrap(), input);
        }
    }

    #[test]
    fn encoder_memusage_is_liblzmas() {
        // `xz -T1 -6`'s encoder: 94 MiB (`xz -vv` says 94 MiB too).
        let mem = encoder_memusage(&preset_opts(6, false, 0)).unwrap();
        assert_eq!(mem.div_ceil(1 << 20), 94);
        // Threads multiply it.
        let mt = encoder_memusage(&preset_opts(6, false, 2)).unwrap();
        assert!(mt > 2 * mem, "{mt} vs {mem}");
        let nine = Lzma::preset(9, false).unwrap();
        assert_eq!(
            decoder_memusage(&[Filter::Lzma2(nine)])
                .unwrap()
                .div_ceil(1 << 20),
            65
        );
        // Delta cannot end a chain.
        assert_eq!(decoder_memusage(&[Filter::Delta { dist: 1 }]), None);
        assert_eq!(decoder_memusage(&[]), None);
        let refused = EncodeOptions {
            memlimit: 1 << 20,
            ..preset_opts(6, false, 0)
        };
        match Encoder::new(&refused) {
            Err(XzError::MemLimit { needed, limit }) => {
                assert_eq!((needed, limit), (mem, 1 << 20));
            }
            other => panic!("{other:?}"),
        }
    }

    /// `needed` is liblzma's `lzma_memusage` after the error, which is what
    /// `xz` prints. For `.xz` the threaded decoder (which `xz` uses at any
    /// thread count) reports 32 KiB, its own state without the refused
    /// Block's dictionary: `xz -d --memlimit=1MiB` on a preset-9 `.xz` says
    /// "1 MiB of memory is required. The limit is 1 MiB." (5.8.4, checked
    /// 2026-10-11). `.lzma` reports the dictionary: "65 MiB ... is
    /// required".
    #[test]
    fn decoder_reports_memlimit() {
        let packed = encode(&preset_opts(9, false, 0), b"tiny input");
        for threads in [1, 2] {
            let o = DecodeOptions {
                memlimit: 1 << 20,
                threads,
                memlimit_threading: 1 << 20,
                ..DecodeOptions::default()
            };
            match decode(&o, &packed) {
                Err(XzError::MemLimit { needed, limit }) => {
                    assert_eq!((needed, limit), (32_768, 1 << 20));
                }
                other => panic!("threads {threads}: {other:?}"),
            }
        }
        let lzma = encode(
            &EncodeOptions {
                format: Format::Lzma,
                filters: vec![Filter::Lzma1(Lzma::preset(9, false).unwrap())],
                ..EncodeOptions::default()
            },
            b"tiny input",
        );
        let o = DecodeOptions {
            format: Format::Lzma,
            memlimit: 1 << 20,
            ..DecodeOptions::default()
        };
        match decode(&o, &lzma) {
            Err(XzError::MemLimit { needed, limit }) => {
                assert_eq!(limit, 1 << 20);
                assert_eq!(needed.div_ceil(1 << 20), 65, "{needed}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn truncated_is_buf_error() {
        let plain = text(20_000, 5);
        let packed = encode(&EncodeOptions::default(), &plain);
        let cut = &packed[..packed.len() - 10];
        assert!(matches!(
            decode(&DecodeOptions::default(), cut),
            Err(XzError::BufError)
        ));
        // Everything decodable reached the output before the verdict.
        let mut d = Decoder::new(&DecodeOptions::default()).unwrap();
        let mut out = Vec::new();
        d.feed(cut, &mut out).unwrap();
        assert!(matches!(d.finish(&mut out), Err(XzError::BufError)));
        assert_eq!(out, plain);
    }

    #[test]
    fn corrupt_is_data_error() {
        let plain = text(20_000, 6);
        let mut packed = encode(&EncodeOptions::default(), &plain);
        let mid = packed.len() / 2;
        packed[mid] ^= 0x55;
        assert!(matches!(
            decode(&DecodeOptions::default(), &packed),
            Err(XzError::Data)
        ));
        // Trailing garbage after a `.lzma` stream is corrupt data too, but
        // `--single-stream` leaves it unconsumed instead.
        let lzma = encode(
            &EncodeOptions {
                format: Format::Lzma,
                filters: vec![Filter::Lzma1(Lzma::preset(1, false).unwrap())],
                ..EncodeOptions::default()
            },
            &plain,
        );
        let mut junk = lzma.clone();
        junk.extend_from_slice(b"junk");
        let o = DecodeOptions {
            format: Format::Lzma,
            ..DecodeOptions::default()
        };
        assert!(matches!(decode(&o, &junk), Err(XzError::Data)));
        let mut d = Decoder::new(&DecodeOptions {
            single_stream: true,
            ..o
        })
        .unwrap();
        let mut out = Vec::new();
        d.feed(&junk, &mut out).unwrap();
        d.finish(&mut out).unwrap();
        assert_eq!(out, plain);
        assert_eq!(d.progress().in_bytes, lzma.len() as u64);
    }

    /// An empty `.xz` stream whose flags name check ID 0x0F, which no
    /// liblzma supports: header, an empty index, footer, CRC32s fixed
    /// (computed once with `zlib.crc32`). `xz -t` on it: "Unsupported type of
    /// integrity check; not verifying file integrity", exit 2.
    const CHECK_0F: [u8; 32] = [
        0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, // magic
        0x00, 0x0f, // stream flags: check 0x0F
        0x6e, 0x0f, 0x66, 0xd1, // CRC32 of the flags
        0x00, 0x00, 0x00, 0x00, // index: indicator, 0 records, padding
        0x1c, 0xdf, 0x44, 0x21, // CRC32 of the index
        0x97, 0x6f, 0x21, 0xea, // CRC32 of backward size + flags
        0x01, 0x00, 0x00, 0x00, // backward size: (8 / 4) - 1
        0x00, 0x0f, // stream flags again
        0x59, 0x5a, // footer magic
    ];

    #[test]
    fn unsupported_check_warns() {
        let mut d = Decoder::new(&DecodeOptions::default()).unwrap();
        let mut out = Vec::new();
        d.feed(&CHECK_0F, &mut out).unwrap();
        d.finish(&mut out).unwrap();
        assert!(out.is_empty());
        assert_eq!(d.take_unsupported_check_warning(), Some(0x0f));
        assert_eq!(d.take_unsupported_check_warning(), None);
        // `--ignore-check` does not ask to be told.
        let mut d = Decoder::new(&DecodeOptions {
            ignore_check: true,
            ..DecodeOptions::default()
        })
        .unwrap();
        d.feed(&CHECK_0F, &mut out).unwrap();
        d.finish(&mut out).unwrap();
        assert_eq!(d.take_unsupported_check_warning(), None);
    }

    /// The block-list walk (`split_block`) and `lzma_filters_update`, over
    /// the input sizes they turn on: a list entry longer than
    /// `--block-size`, a chain change, the last entry repeating.
    fn block_list_opts(threads: u32) -> EncodeOptions {
        let delta = vec![
            Filter::Delta { dist: 4 },
            Filter::Lzma2(Lzma::preset(1, false).unwrap()),
        ];
        EncodeOptions {
            filters: vec![Filter::Lzma2(Lzma::preset(3, false).unwrap())],
            threads,
            block_size: 40_000,
            block_list: vec![(100_000, None), (30_000, Some(delta)), (25_000, None)],
            ..EncodeOptions::default()
        }
    }

    #[test]
    fn block_list_round_trips() {
        let plain = text(300_000, 9);
        for threads in [0, 2] {
            let packed = encode(&block_list_opts(threads), &plain);
            assert_eq!(decode(&DecodeOptions::default(), &packed).unwrap(), plain);
        }
    }

    /// The reference `xz` 5.8.4, if this machine has it.
    #[cfg(target_os = "macos")]
    fn reference() -> Option<std::path::PathBuf> {
        let path = std::env::var_os("STUFFR_XZ_REFERENCE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| "/opt/homebrew/opt/xz/bin/xz".into());
        let v = std::process::Command::new(&path)
            .arg("--version")
            .output()
            .ok()?;
        String::from_utf8_lossy(&v.stdout)
            .contains("5.8.4")
            .then_some(path)
    }

    /// `xz <args> -c` over `input` on stdin.
    #[cfg(target_os = "macos")]
    fn run_reference(xz: &std::path::Path, args: &[&str], input: &[u8]) -> Vec<u8> {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut child = Command::new(xz)
            .args(args)
            .arg("-c")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let input = input.to_vec();
        let writer = std::thread::spawn(move || stdin.write_all(&input));
        let out = child.wait_with_output().unwrap();
        writer.join().unwrap().unwrap();
        assert!(out.status.success(), "xz {args:?}");
        out.stdout
    }

    /// Re-derives a sample of the table through the real `xz`, so a stale
    /// fixture is noticed. With `STUFFR_XZ_OPTS_REGEN` set it re-derives all
    /// 80 rows and fails with the full table, which is how `t1.txt` was made.
    #[cfg(target_os = "macos")]
    #[test]
    fn fixture_is_still_what_xz_emits() {
        let Some(xz) = reference() else {
            eprintln!("skipped: no xz 5.8.4");
            return;
        };
        let all = std::env::var_os("STUFFR_XZ_OPTS_REGEN").is_some();
        let sample = [
            ("text", 6, false),
            ("bin", 0, true),
            ("rand", 9, false),
            ("empty", 3, true),
        ];
        let mut rows = Vec::new();
        for (name, input) in inputs() {
            for extreme in [false, true] {
                for level in 0..=9 {
                    if !all && !sample.contains(&(name, level, extreme)) {
                        continue;
                    }
                    let flag = format!("-{level}{}", if extreme { "e" } else { "" });
                    let out = run_reference(&xz, &["-T1", &flag], &input);
                    rows.push(table_line(name, level, extreme, &sha256(&out)));
                }
            }
        }
        if all {
            panic!("regenerated table:\n{}", rows.join("\n"));
        }
        for row in rows {
            assert!(T1.lines().any(|l| l == row), "stale fixture: {row}");
        }
    }

    /// `--block-size`, `--block-list` and `--filters1` byte-identical to
    /// the real `xz`, single- and multi-threaded.
    #[cfg(target_os = "macos")]
    #[test]
    fn block_list_matches_xz() {
        let Some(xz) = reference() else {
            eprintln!("skipped: no xz 5.8.4");
            return;
        };
        let plain = text(300_000, 9);
        for (threads, t) in [(0, "-T1"), (2, "-T2")] {
            let want = run_reference(
                &xz,
                &[
                    t,
                    "-3",
                    "--block-size=40000",
                    "--block-list=100000,1:30000,25000",
                    "--filters1=delta:dist=4 lzma2:preset=1",
                ],
                &plain,
            );
            assert!(
                encode(&block_list_opts(threads), &plain) == want,
                "{t}: differs from xz"
            );
        }
    }
}
