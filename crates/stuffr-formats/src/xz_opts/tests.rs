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

/// 64 KiB shaped like x86 code: a few common opcodes, `call rel32` with
/// small displacements, ModRM-ish operand bytes.
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
fn rand(n: usize) -> Vec<u8> {
    let mut r = Lcg(0x5eed);
    (0..n).map(|_| (r.next() >> 16) as u8).collect()
}

/// The fixture's four inputs, by name.
#[cfg(feature = "xz-c")]
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

/// The reference `xz` 5.8.4, if this machine has it.
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

#[cfg(any(target_os = "macos", all(unix, feature = "xz-pure")))]
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
#[cfg(any(target_os = "macos", all(unix, feature = "xz-pure")))]
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

    /// The chains the formula sweep runs every preset through.
    fn sweep_chains(l: &Lzma) -> Vec<Vec<Filter>> {
        vec![
            vec![Filter::Lzma2(l.clone())],
            vec![
                Filter::Bcj {
                    kind: Bcj::X86,
                    start: 0,
                },
                Filter::Lzma2(l.clone()),
            ],
            vec![Filter::Delta { dist: 4 }, Filter::Lzma2(l.clone())],
            vec![Filter::Lzma1(l.clone())],
        ]
    }

    /// `memusage`'s port against liblzma's own functions: every preset and
    /// `-e` through BCJ + LZMA2, delta + LZMA2 and LZMA1, single-threaded
    /// and at 1, 2 and 4 threads with block sizes 0 and 1 MiB; then the
    /// edges (every match finder, `nice_len` and dictionary bounds, bad
    /// `lc`/`lp`/`pb`, bad chains, a block list with two chains).
    #[test]
    fn memusage_formulas_match_liblzma() {
        let mut cases = 0;
        let mut check = |o: &EncodeOptions| {
            assert_eq!(
                memusage::encoder_memusage(o),
                encoder_memusage(o),
                "encoder {o:?}"
            );
            assert_eq!(
                memusage::decoder_memusage(&o.filters),
                decoder_memusage(&o.filters),
                "decoder {:?}",
                o.filters
            );
            cases += 1;
        };
        for level in 0..=9 {
            for extreme in [false, true] {
                let l = Lzma::preset(level, extreme).unwrap();
                for filters in sweep_chains(&l) {
                    for format in [Format::Raw, Format::Lzma, Format::Xz] {
                        check(&EncodeOptions {
                            format,
                            filters: filters.clone(),
                            ..EncodeOptions::default()
                        });
                    }
                    for threads in [1, 2, 4] {
                        for block_size in [0, 1 << 20] {
                            check(&EncodeOptions {
                                filters: filters.clone(),
                                threads,
                                block_size,
                                ..EncodeOptions::default()
                            });
                        }
                    }
                }
            }
        }
        let base = Lzma::preset(1, false).unwrap();
        let mfs = [
            MatchFinder::Hc3,
            MatchFinder::Hc4,
            MatchFinder::Bt2,
            MatchFinder::Bt3,
            MatchFinder::Bt4,
        ];
        let dicts = [
            0,
            4095,
            4096,
            4097,
            65_535,
            65_537,
            (1 << 24) + 3,
            (1 << 25) - 1,
            (1 << 30) + (1 << 29),
            (1 << 30) + (1 << 29) + 1,
            u32::MAX,
        ];
        for mf in mfs {
            for nice_len in [0, 1, 2, 3, 4, 5, 8, 273, 274] {
                for dict_size in dicts {
                    let l = Lzma {
                        mf,
                        nice_len,
                        dict_size,
                        ..base.clone()
                    };
                    for filters in [vec![Filter::Lzma1(l.clone())], vec![Filter::Lzma2(l)]] {
                        check(&EncodeOptions {
                            format: Format::Raw,
                            filters: filters.clone(),
                            ..EncodeOptions::default()
                        });
                        check(&EncodeOptions {
                            filters,
                            threads: 3,
                            ..EncodeOptions::default()
                        });
                    }
                }
            }
        }
        for (lc, lp, pb) in [
            (4, 0, 4),
            (5, 0, 2),
            (0, 5, 2),
            (3, 2, 2),
            (2, 2, 5),
            (9, 0, 0),
        ] {
            let l = Lzma {
                lc,
                lp,
                pb,
                ..base.clone()
            };
            for filters in [vec![Filter::Lzma1(l.clone())], vec![Filter::Lzma2(l)]] {
                check(&EncodeOptions {
                    format: Format::Raw,
                    filters,
                    ..EncodeOptions::default()
                });
            }
        }
        let lz = Filter::Lzma2(base.clone());
        let bcj = Filter::Bcj {
            kind: Bcj::Arm64,
            start: 8,
        };
        for filters in [
            vec![],
            vec![bcj.clone()],
            vec![lz.clone(), lz.clone()],
            vec![lz.clone(), bcj.clone()],
            vec![bcj.clone(), bcj.clone(), bcj.clone(), lz.clone()],
            vec![
                bcj.clone(),
                bcj.clone(),
                bcj.clone(),
                bcj.clone(),
                lz.clone(),
            ],
            vec![Filter::Delta { dist: 0 }, lz.clone()],
            vec![Filter::Delta { dist: 256 }, lz.clone()],
            vec![Filter::Delta { dist: 257 }, lz.clone()],
        ] {
            check(&EncodeOptions {
                format: Format::Raw,
                filters,
                ..EncodeOptions::default()
            });
        }
        let nine = vec![Filter::Lzma2(Lzma::preset(9, false).unwrap())];
        for threads in [0, 2] {
            for block_size in [0, 40_000] {
                check(&EncodeOptions {
                    threads,
                    block_size,
                    block_list: vec![(100_000, None), (30_000, Some(nine.clone())), (5, None)],
                    ..EncodeOptions::default()
                });
            }
        }
        for threads in [16_384, 16_385] {
            check(&EncodeOptions {
                threads,
                block_size: 1 << 20,
                ..EncodeOptions::default()
            });
        }
        assert!(cases > 1000, "{cases}");
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

    /// `.lz` through `Format::Lzip` and through `auto`'s magic sniff. As
    /// `xz` 5.8.4 does (checked 2026-10-11 against `lzip` 1.26 output:
    /// `xz -dc` of two members plus `junk` prints both and exits 0;
    /// `--single-stream` prints the first): members concatenate, trailing
    /// non-`.lz` bytes end the stream unconsumed, `single_stream` stops
    /// after the first member.
    #[cfg(feature = "lzip")]
    #[test]
    fn lzip_members_and_trailing_data() {
        let one = text(30_000, 11);
        let member = crate::lzip::encode_for_test(&one);
        let mut file = member.clone();
        file.extend_from_slice(&member);
        file.extend_from_slice(b"junk");
        let both = [one.clone(), one.clone()].concat();
        for auto in [false, true] {
            for (single_stream, want, used) in
                [(false, &both, 2 * member.len()), (true, &one, member.len())]
            {
                let o = DecodeOptions {
                    format: if auto { Format::Xz } else { Format::Lzip },
                    auto,
                    single_stream,
                    ..DecodeOptions::default()
                };
                let what = format!("auto {auto} single_stream {single_stream}");
                let mut d = Decoder::new(&o).unwrap();
                let mut out = Vec::new();
                // Pieces small enough that the sniff spans two feeds.
                for piece in file.chunks(3) {
                    d.feed(piece, &mut out).unwrap();
                }
                d.finish(&mut out).unwrap();
                assert!(out == *want, "{what}: {} bytes", out.len());
                assert_eq!(d.progress().in_bytes, used as u64, "{what}");
            }
        }
        // A cut member is still an unexpected end, not trailing data.
        let o = DecodeOptions {
            format: Format::Lzip,
            ..DecodeOptions::default()
        };
        let cut = &member[..member.len() - 3];
        assert!(matches!(decode(&o, cut), Err(XzError::BufError)));
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

/// One tier's [`Encoder`] and [`Decoder`] behind plain functions, so the
/// same cases run through either (`c` or `pure`).
#[cfg(feature = "xz-pure")]
macro_rules! codec_fns {
    ($tier:ident) => {
        /// Encodes `input` fed in `piece`-byte pieces.
        pub(super) fn encode(
            o: &EncodeOptions,
            input: &[u8],
            piece: usize,
        ) -> Result<Vec<u8>, XzError> {
            let mut e = crate::xz_opts::$tier::Encoder::new(o)?;
            let mut out = Vec::new();
            for p in input.chunks(piece.max(1)) {
                e.feed(p, &mut out)?;
            }
            e.finish(&mut out)?;
            assert_eq!(
                e.progress(),
                Progress {
                    in_bytes: input.len() as u64,
                    out_bytes: out.len() as u64
                }
            );
            Ok(out)
        }

        /// Decodes `data` fed in `piece`-byte pieces: the output, the
        /// verdict, the input used (`progress().in_bytes`), the warnings.
        pub(super) fn decode(
            o: &DecodeOptions,
            data: &[u8],
            piece: usize,
        ) -> (Vec<u8>, Result<(), XzError>, u64, Vec<u32>) {
            let mut out = Vec::new();
            let mut d = match crate::xz_opts::$tier::Decoder::new(o) {
                Ok(d) => d,
                Err(e) => return (out, Err(e), 0, Vec::new()),
            };
            let r = (|| {
                for p in data.chunks(piece.max(1)) {
                    d.feed(p, &mut out)?;
                }
                d.finish(&mut out)
            })();
            let mut warnings = Vec::new();
            while let Some(w) = d.take_unsupported_check_warning() {
                warnings.push(w);
            }
            (out, r, d.progress().in_bytes, warnings)
        }
    };
}

#[cfg(feature = "xz-pure")]
mod pure_codec {
    use super::*;
    codec_fns!(pure);
}

#[cfg(all(feature = "xz-pure", feature = "xz-c"))]
mod c_codec {
    use super::*;
    codec_fns!(c);
}

/// `EncodeOptions` drawn from `r`: every format, check, filter and thread
/// setting the pure tier maps, with dictionaries of at most 8 MiB so a
/// debug build stays quick.
#[cfg(feature = "xz-pure")]
fn random_options(r: &mut Lcg) -> EncodeOptions {
    let mut pick = |n: u32| r.next() % n;
    let mut l = Lzma::preset(pick(7), pick(2) == 1).unwrap();
    if pick(3) == 0 {
        l.dict_size = [4096, 65_536, 300_000, 1 << 20][pick(4) as usize];
    }
    if pick(3) == 0 {
        l.lc = pick(5);
        l.lp = pick(5 - l.lc);
        l.pb = pick(5);
    }
    if pick(3) == 0 {
        l.nice_len = 2 + pick(272);
        l.mf = [
            MatchFinder::Hc3,
            MatchFinder::Hc4,
            MatchFinder::Bt2,
            MatchFinder::Bt3,
            MatchFinder::Bt4,
        ][pick(5) as usize];
        l.mode = if pick(2) == 0 {
            Mode::Fast
        } else {
            Mode::Normal
        };
        l.depth = [0, 1, 10, 100][pick(4) as usize];
    }
    let kinds = [
        Bcj::X86,
        Bcj::PowerPc,
        Bcj::Ia64,
        Bcj::Arm,
        Bcj::ArmThumb,
        Bcj::Arm64,
        Bcj::Sparc,
        Bcj::RiscV,
    ];
    let mut pre = Vec::new();
    for _ in 0..pick(3) {
        pre.push(if pick(2) == 0 {
            Filter::Delta {
                dist: 1 + pick(256),
            }
        } else {
            Filter::Bcj {
                kind: kinds[pick(8) as usize],
                start: 16 * pick(4),
            }
        });
    }
    let check = [Check::None, Check::Crc32, Check::Crc64, Check::Sha256][pick(4) as usize];
    match pick(10) {
        0..=6 => {
            let mut filters = pre;
            filters.push(Filter::Lzma2(l.clone()));
            let mut block_list = Vec::new();
            if pick(4) == 0 {
                let other = vec![
                    Filter::Delta { dist: 2 },
                    Filter::Lzma2(Lzma::preset(1, false).unwrap()),
                ];
                block_list = vec![
                    (1 + u64::from(pick(40_000)), None),
                    (1 + u64::from(pick(20_000)), Some(other)),
                    (1 + u64::from(pick(30_000)), None),
                ];
            }
            EncodeOptions {
                format: Format::Xz,
                filters,
                check,
                threads: [0, 0, 0, 1, 2, 4][pick(6) as usize],
                block_size: [0, 0, 10_000, 65_536][pick(4) as usize],
                block_list,
                ..EncodeOptions::default()
            }
        }
        7 | 8 => EncodeOptions {
            format: Format::Lzma,
            filters: vec![Filter::Lzma1(l)],
            ..EncodeOptions::default()
        },
        _ => {
            let mut filters = pre;
            filters.push(match pick(3) {
                0 => Filter::Lzma1(l),
                1 => Filter::Lzma1Ext(l),
                _ => Filter::Lzma2(l),
            });
            EncodeOptions {
                format: Format::Raw,
                filters,
                ..EncodeOptions::default()
            }
        }
    }
}

/// The input for random case `i`.
#[cfg(feature = "xz-pure")]
fn random_input(r: &mut Lcg, i: u64) -> Vec<u8> {
    match i % 4 {
        0 => text(10_000 + r.next() as usize % 70_000, i),
        1 => bin(),
        2 => rand(1 + r.next() as usize % 20_000),
        _ => Vec::new(),
    }
}

/// How to decode what `o` encoded.
#[cfg(feature = "xz-pure")]
fn decode_options_for(o: &EncodeOptions) -> DecodeOptions {
    DecodeOptions {
        format: o.format,
        raw_filters: o.filters.clone(),
        ..DecodeOptions::default()
    }
}

/// The `.xz` Index's records, `(unpadded, uncompressed)`, read back from
/// the end of a single Stream.
#[cfg(feature = "xz-pure")]
fn xz_index(packed: &[u8]) -> Vec<(u64, u64)> {
    let n = packed.len();
    let backward = u32::from_le_bytes(packed[n - 8..n - 4].try_into().unwrap());
    let size = (backward as usize + 1) * 4;
    let index = &packed[n - 12 - size..n - 12];
    let mut pos = 1;
    let mut vli = || {
        let (mut v, mut shift) = (0u64, 0);
        loop {
            let b = index[pos];
            pos += 1;
            v |= u64::from(b & 0x7F) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                return v;
            }
        }
    };
    let count = vli();
    (0..count).map(|_| (vli(), vli())).collect()
}

#[cfg(feature = "xz-pure")]
mod pure_tier {
    use super::pure_codec::{decode, encode};
    use super::*;

    #[test]
    fn pure_liblzma_version_is_5_8_4() {
        assert_eq!(crate::xz_opts::pure::liblzma_version(), "5.8.4");
    }

    #[test]
    fn pure_encoder_and_decoder_are_send() {
        fn send<T: Send>() {}
        send::<crate::xz_opts::pure::Encoder>();
        send::<crate::xz_opts::pure::Decoder>();
    }

    /// 64 LCG-drawn option sets, each round-tripping through the pure
    /// decoder in uneven pieces, with the container fields the spec pins
    /// (the Stream Flags, so the check, at both ends), the bytes not
    /// depending on how the input was fed, and — when the reference `xz`
    /// 5.8.4 is found — eight representative outputs piped through
    /// `xz -dc`.
    #[test]
    fn pure_roundtrips_and_xz_reads_it() {
        let mut r = Lcg(0x7e57_0001);
        let mut samples: Vec<(EncodeOptions, Vec<u8>, Vec<u8>)> = Vec::new();
        for i in 0..64 {
            let o = random_options(&mut r);
            let input = random_input(&mut r, i);
            let piece = 1 + r.next() as usize % 9_000;
            let packed = encode(&o, &input, piece).unwrap_or_else(|e| panic!("{i} {o:?}: {e}"));
            if i % 4 == 0 {
                let whole = encode(&o, &input, input.len()).unwrap();
                assert!(whole == packed, "{i}: the bytes depend on the feeding");
            }
            let (out, res, used, _) = decode(
                &decode_options_for(&o),
                &packed,
                1 + r.next() as usize % 5_000,
            );
            res.unwrap_or_else(|e| panic!("{i} {o:?}: {e}"));
            assert!(out == input, "{i} {o:?}: round trip differs");
            assert_eq!(used, packed.len() as u64, "{i}");
            if o.format == Format::Xz {
                let flags = [0, o.check.id() as u8];
                assert_eq!(packed[6..8], flags, "{i}: header flags");
                let n = packed.len();
                assert_eq!(packed[n - 4..n - 2], flags, "{i}: footer flags");
            }
            if o.format != Format::Raw && !input.is_empty() && samples.len() < 8 {
                samples.push((o, input, packed));
            }
        }
        assert_eq!(samples.len(), 8);
        #[cfg(unix)]
        {
            let Some(xz) = reference() else {
                eprintln!("skipped the xz -dc leg: no xz 5.8.4 (set STUFFR_XZ_REFERENCE)");
                return;
            };
            for (o, input, packed) in samples {
                let format = if o.format == Format::Lzma {
                    "--format=lzma"
                } else {
                    "--format=xz"
                };
                let got = run_reference(&xz, &["-d", format], &packed);
                assert!(got == input, "xz -dc differs for {o:?}");
            }
        }
    }

    /// The single-threaded writer cuts Blocks where `coder.c` does:
    /// `--block-size`, then a block list (an entry longer than the size, a
    /// chain change, the last entry repeating).
    #[test]
    fn pure_block_boundaries_are_xzs() {
        let plain = text(300_000, 9);
        let delta = vec![
            Filter::Delta { dist: 4 },
            Filter::Lzma2(Lzma::preset(1, false).unwrap()),
        ];
        let o = EncodeOptions {
            filters: vec![Filter::Lzma2(Lzma::preset(3, false).unwrap())],
            block_size: 40_000,
            block_list: vec![(100_000, None), (30_000, Some(delta)), (25_000, None)],
            ..EncodeOptions::default()
        };
        let packed = encode(&o, &plain, 7_919).unwrap();
        let sizes: Vec<u64> = xz_index(&packed).iter().map(|&(_, u)| u).collect();
        let mut want = vec![40_000, 40_000, 20_000, 30_000];
        let mut left = 300_000 - 130_000;
        while left > 0 {
            want.push(left.min(25_000));
            left -= left.min(25_000);
        }
        assert_eq!(sizes, want);
        let (out, res, ..) = decode(&DecodeOptions::default(), &packed, 4_093);
        res.unwrap();
        assert!(out == plain);
        let o = EncodeOptions {
            block_size: 10_000,
            block_list: Vec::new(),
            ..o
        };
        let packed = encode(&o, &plain[..25_000], 3_001).unwrap();
        let sizes: Vec<u64> = xz_index(&packed).iter().map(|&(_, u)| u).collect();
        assert_eq!(sizes, [10_000, 10_000, 5_000]);
    }

    /// `flush` makes everything fed so far decodable, and the stream goes
    /// on; refused where liblzma refuses it.
    #[test]
    fn pure_flush_is_a_sync_flush() {
        use crate::xz_opts::pure::{Decoder, Encoder};
        let plain = text(50_000, 21);
        for format in [Format::Xz, Format::Raw] {
            let o = EncodeOptions {
                format,
                ..EncodeOptions::default()
            };
            let d = decode_options_for(&o);
            let mut e = Encoder::new(&o).unwrap();
            let mut packed = Vec::new();
            e.feed(&plain[..20_000], &mut packed).unwrap();
            e.flush(&mut packed).unwrap();
            let mut dec = Decoder::new(&d).unwrap();
            let mut out = Vec::new();
            dec.feed(&packed, &mut out).unwrap();
            assert!(out == plain[..20_000], "{format:?}: flushed data decodes");
            e.feed(&plain[20_000..], &mut packed).unwrap();
            e.finish(&mut packed).unwrap();
            let (out, res, ..) = decode(&d, &packed, 999);
            res.unwrap();
            assert!(out == plain);
        }
        let bcj = EncodeOptions {
            filters: vec![
                Filter::Bcj {
                    kind: Bcj::X86,
                    start: 0,
                },
                Filter::Lzma2(Lzma::preset(1, false).unwrap()),
            ],
            ..EncodeOptions::default()
        };
        let mut e = Encoder::new(&bcj).unwrap();
        let mut out = Vec::new();
        e.flush(&mut out).unwrap(); // between Blocks: nothing to flush
        e.feed(b"data", &mut out).unwrap();
        assert!(matches!(e.flush(&mut out), Err(XzError::Options)));
        let mt = EncodeOptions {
            threads: 2,
            ..EncodeOptions::default()
        };
        let mut e = Encoder::new(&mt).unwrap();
        assert!(matches!(e.flush(&mut out), Err(XzError::Prog)));
    }

    /// As the C tier's `decoder_reports_memlimit`: `.xz` says 32 KiB
    /// (liblzma's threaded decoder, at any thread count, before any Block
    /// ran), `.lzma` the dictionary.
    #[test]
    fn decoder_reports_memlimit() {
        let nine = Lzma::preset(9, false).unwrap();
        let packed = encode(
            &EncodeOptions {
                filters: vec![Filter::Lzma2(nine.clone())],
                ..EncodeOptions::default()
            },
            b"tiny input",
            100,
        )
        .unwrap();
        for threads in [1, 2] {
            let o = DecodeOptions {
                memlimit: 1 << 20,
                threads,
                memlimit_threading: 1 << 20,
                ..DecodeOptions::default()
            };
            match decode(&o, &packed, 4_093).1 {
                Err(XzError::MemLimit { needed, limit }) => {
                    assert_eq!((needed, limit), (32_768, 1 << 20));
                }
                other => panic!("threads {threads}: {other:?}"),
            }
        }
        // `auto` is liblzma's single-threaded decoder: the Block's figure.
        let auto = DecodeOptions {
            auto: true,
            memlimit: 1 << 20,
            ..DecodeOptions::default()
        };
        match decode(&auto, &packed, 4_093).1 {
            Err(XzError::MemLimit { needed, limit }) => {
                assert_eq!(limit, 1 << 20);
                assert_eq!(
                    needed,
                    decoder_memusage(&[Filter::Lzma2(nine.clone())]).unwrap()
                );
            }
            other => panic!("auto: {other:?}"),
        }
        let lzma = encode(
            &EncodeOptions {
                format: Format::Lzma,
                filters: vec![Filter::Lzma1(nine)],
                ..EncodeOptions::default()
            },
            b"tiny input",
            100,
        )
        .unwrap();
        let o = DecodeOptions {
            format: Format::Lzma,
            memlimit: 1 << 20,
            ..DecodeOptions::default()
        };
        match decode(&o, &lzma, 4_093).1 {
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
        let packed = encode(&EncodeOptions::default(), &plain, 7_919).unwrap();
        let cut = &packed[..packed.len() - 10];
        assert!(matches!(
            decode(&DecodeOptions::default(), cut, 4_093).1,
            Err(XzError::BufError)
        ));
        // Everything decodable reached the output before the verdict.
        let mut d = crate::xz_opts::pure::Decoder::new(&DecodeOptions::default()).unwrap();
        let mut out = Vec::new();
        d.feed(cut, &mut out).unwrap();
        assert!(matches!(d.finish(&mut out), Err(XzError::BufError)));
        assert_eq!(out, plain);
    }

    #[test]
    fn corrupt_is_data_error() {
        let plain = text(20_000, 6);
        let mut packed = encode(&EncodeOptions::default(), &plain, 7_919).unwrap();
        let mid = packed.len() / 2;
        packed[mid] ^= 0x55;
        assert!(matches!(
            decode(&DecodeOptions::default(), &packed, 4_093).1,
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
            7_919,
        )
        .unwrap();
        let mut junk = lzma.clone();
        junk.extend_from_slice(b"junk");
        let o = DecodeOptions {
            format: Format::Lzma,
            ..DecodeOptions::default()
        };
        for piece in [junk.len(), 4_093, 3] {
            assert!(
                matches!(decode(&o, &junk, piece).1, Err(XzError::Data)),
                "{piece}"
            );
            let single = DecodeOptions {
                single_stream: true,
                ..o.clone()
            };
            let (out, res, used, _) = decode(&single, &junk, piece);
            res.unwrap();
            assert!(out == plain, "{piece}");
            assert_eq!(used, lzma.len() as u64, "{piece}");
        }
    }

    #[test]
    fn unsupported_check_warns() {
        let (out, res, _, warnings) = decode(&DecodeOptions::default(), &CHECK_0F, 32);
        res.unwrap();
        assert!(out.is_empty());
        assert_eq!(warnings, [0x0f]);
        // `--ignore-check` does not ask to be told.
        let o = DecodeOptions {
            ignore_check: true,
            ..DecodeOptions::default()
        };
        let (_, res, _, warnings) = decode(&o, &CHECK_0F, 5);
        res.unwrap();
        assert!(warnings.is_empty());
    }

    /// `.lz` as the C tier's `lzip_members_and_trailing_data` pins it.
    #[cfg(feature = "lzip")]
    #[test]
    fn lzip_members_and_trailing_data() {
        let one = text(30_000, 11);
        let member = crate::lzip::encode_for_test(&one);
        let mut file = member.clone();
        file.extend_from_slice(&member);
        file.extend_from_slice(b"junk");
        let both = [one.clone(), one.clone()].concat();
        for auto in [false, true] {
            for (single_stream, want, used) in
                [(false, &both, 2 * member.len()), (true, &one, member.len())]
            {
                for piece in [3, 4_093, file.len()] {
                    let o = DecodeOptions {
                        format: if auto { Format::Xz } else { Format::Lzip },
                        auto,
                        single_stream,
                        ..DecodeOptions::default()
                    };
                    let what = format!("auto {auto} single_stream {single_stream} piece {piece}");
                    let (out, res, in_bytes, _) = decode(&o, &file, piece);
                    res.unwrap_or_else(|e| panic!("{what}: {e}"));
                    assert!(out == *want, "{what}: {} bytes", out.len());
                    assert_eq!(in_bytes, used as u64, "{what}");
                }
            }
        }
        let o = DecodeOptions {
            format: Format::Lzip,
            ..DecodeOptions::default()
        };
        let cut = &member[..member.len() - 3];
        assert!(matches!(decode(&o, cut, 4_093).1, Err(XzError::BufError)));
    }
}

/// The pure tier against liblzma itself, case by case: what one encodes
/// the other decodes, and for the same input both decoders reach the same
/// verdict — the same [`XzError`], the same `MemLimit { needed, limit }`,
/// the same warnings, and on success the same output and input used.
#[cfg(all(feature = "xz-pure", feature = "xz-c"))]
mod cross_tier {
    use super::*;

    /// A verdict as the CLI would print it.
    fn verdict(r: &Result<(), XzError>) -> String {
        match r {
            Ok(()) => "ok".to_owned(),
            Err(XzError::MemLimit { needed, limit }) => format!("memlimit {needed} {limit}"),
            Err(XzError::UnsupportedCheck(id)) => format!("unsupported check {id}"),
            Err(XzError::Mem { .. }) => "mem".to_owned(),
            Err(e) => e.to_string(),
        }
    }

    /// The window of [`agree`]'s one tolerated difference, in bytes before
    /// the end of the input.
    const END_WINDOW: u64 = 20;

    /// The verdict [`agree`] reports for a tolerated difference.
    const TOLERATED: &str = "corrupt in the last 20 bytes: BufError on the pure tier";

    /// Decodes `data` with both tiers in `piece`-byte feeds and asserts
    /// they agree; the verdict.
    fn agree(what: &str, o: &DecodeOptions, data: &[u8], piece: usize) -> String {
        let (c_out, c_res, c_used, c_warn) = c_codec::decode(o, data, piece);
        let (p_out, p_res, p_used, p_warn) = pure_codec::decode(o, data, piece);
        let (cv, pv) = (verdict(&c_res), verdict(&p_res));
        // The stated pure-tier deviation (the pure module doc): under a
        // raw, `.lzma` or `.lz` stream, corruption liblzma finds only once
        // it is within the last 20 bytes of the input (`lzma-rust2` starts
        // a symbol only with 20 bytes in hand) is, on the pure tier, the
        // input running out. Bounded by where liblzma stopped, and counted.
        let lzma1 = matches!(o.format, Format::Raw | Format::Lzma | Format::Lzip)
            || (o.auto && data.first() != Some(&0xFD));
        if lzma1
            && matches!(c_res, Err(XzError::Data))
            && matches!(p_res, Err(XzError::BufError))
            && c_used + END_WINDOW >= data.len() as u64
        {
            return TOLERATED.to_owned();
        }
        assert_eq!(pv, cv, "{what} (piece {piece}): pure vs liblzma");
        assert_eq!(p_warn, c_warn, "{what} (piece {piece}): warnings");
        if c_res.is_ok() {
            assert!(p_out == c_out, "{what} (piece {piece}): output differs");
            assert_eq!(p_used, c_used, "{what} (piece {piece}): input used");
        }
        cv
    }

    #[test]
    fn tiers_read_each_other() {
        let mut r = Lcg(0x7e57_0002);
        for i in 0..64 {
            let o = random_options(&mut r);
            let input = random_input(&mut r, i);
            let d = decode_options_for(&o);
            let from_c = c_codec::encode(&o, &input, 7_919).unwrap();
            let (out, res, used, _) = pure_codec::decode(&d, &from_c, 4_093);
            res.unwrap_or_else(|e| panic!("{i} {o:?}: pure reading C: {e}"));
            assert!(out == input, "{i} {o:?}: pure reading C");
            assert_eq!(used, from_c.len() as u64, "{i}");
            let from_pure = pure_codec::encode(&o, &input, 7_919).unwrap();
            let (out, res, used, _) = c_codec::decode(&d, &from_pure, 4_093);
            res.unwrap_or_else(|e| panic!("{i} {o:?}: C reading pure: {e}"));
            assert!(out == input, "{i} {o:?}: C reading pure");
            assert_eq!(used, from_pure.len() as u64, "{i}");
        }
    }

    /// What the single-threaded encoders write around the compressed data
    /// is the same: the Stream Header and Footer flags, the Block sizes
    /// (`--block-size`, `--block-list`), the `.lzma` header.
    #[test]
    fn container_fields_match_liblzma() {
        let plain = text(120_000, 31);
        let delta = vec![
            Filter::Delta { dist: 3 },
            Filter::Lzma2(Lzma::preset(0, false).unwrap()),
        ];
        for check in [Check::None, Check::Crc32, Check::Crc64, Check::Sha256] {
            for (block_size, block_list) in [
                (0, vec![]),
                (17_000, vec![]),
                (
                    0,
                    vec![(50_000, None), (1, Some(delta.clone())), (9_999, None)],
                ),
                (
                    20_000,
                    vec![(45_000, Some(delta.clone())), (u64::MAX, None)],
                ),
            ] {
                let o = EncodeOptions {
                    check,
                    block_size,
                    block_list,
                    ..EncodeOptions::default()
                };
                let c = c_codec::encode(&o, &plain, 7_919).unwrap();
                let p = pure_codec::encode(&o, &plain, 7_919).unwrap();
                assert_eq!(p[..12], c[..12], "{o:?}: Stream Header");
                assert_eq!(p[p.len() - 4..], c[c.len() - 4..], "{o:?}: Footer flags");
                let sizes = |x: &[u8]| xz_index(x).iter().map(|&(_, u)| u).collect::<Vec<_>>();
                assert_eq!(sizes(&p), sizes(&c), "{o:?}: Blocks");
            }
        }
        for dict_size in [4096, 5 << 20, 3 << 19, (1 << 20) + 1] {
            let o = EncodeOptions {
                format: Format::Lzma,
                filters: vec![Filter::Lzma1(Lzma {
                    dict_size,
                    ..Lzma::preset(1, false).unwrap()
                })],
                ..EncodeOptions::default()
            };
            let c = c_codec::encode(&o, &plain, 7_919).unwrap();
            let p = pure_codec::encode(&o, &plain, 7_919).unwrap();
            assert_eq!(p[..13], c[..13], "dict {dict_size}: .lzma header");
        }
    }

    /// `flush` is taken or refused (and how) as liblzma does it.
    #[test]
    fn flush_verdicts_match_liblzma() {
        let l2 = Filter::Lzma2(Lzma::preset(1, false).unwrap());
        let l1 = Filter::Lzma1(Lzma::preset(1, false).unwrap());
        let bcj = Filter::Bcj {
            kind: Bcj::Arm64,
            start: 0,
        };
        let delta = Filter::Delta { dist: 2 };
        let cases = [
            (Format::Xz, vec![l2.clone()], 0),
            (Format::Xz, vec![delta.clone(), l2.clone()], 0),
            (Format::Xz, vec![bcj.clone(), l2.clone()], 0),
            (Format::Xz, vec![l2.clone()], 2),
            (Format::Xz, vec![bcj.clone(), l2.clone()], 2),
            (Format::Lzma, vec![l1.clone()], 0),
            (Format::Raw, vec![l2.clone()], 0),
            (Format::Raw, vec![delta.clone(), l2], 0),
            (Format::Raw, vec![bcj, l1.clone()], 0),
            (Format::Raw, vec![l1], 0),
        ];
        for (format, filters, threads) in cases {
            let o = EncodeOptions {
                format,
                filters,
                threads,
                ..EncodeOptions::default()
            };
            for fed in [&b""[..], b"some data to flush"] {
                let mut c = crate::xz_opts::c::Encoder::new(&o).unwrap();
                let mut p = crate::xz_opts::pure::Encoder::new(&o).unwrap();
                let (mut co, mut po) = (Vec::new(), Vec::new());
                c.feed(fed, &mut co).unwrap();
                p.feed(fed, &mut po).unwrap();
                let cv = verdict(&c.flush(&mut co));
                let pv = verdict(&p.flush(&mut po));
                assert_eq!(pv, cv, "{o:?} after {} bytes", fed.len());
            }
        }
    }

    /// The encoders refuse the same option sets the same way.
    #[test]
    fn encoder_verdicts_match_liblzma() {
        let base = Lzma::preset(1, false).unwrap();
        let mut cases = Vec::new();
        for (kind, start) in [
            (Bcj::X86, 3),
            (Bcj::PowerPc, 2),
            (Bcj::Ia64, 8),
            (Bcj::Ia64, 32),
            (Bcj::ArmThumb, 1),
            (Bcj::RiscV, 6),
            (Bcj::Sparc, 4),
        ] {
            for format in [Format::Xz, Format::Raw] {
                cases.push(EncodeOptions {
                    format,
                    filters: vec![Filter::Bcj { kind, start }, Filter::Lzma2(base.clone())],
                    ..EncodeOptions::default()
                });
            }
        }
        for threads in [0, 2] {
            cases.push(EncodeOptions {
                filters: vec![Filter::Lzma1(base.clone())],
                threads,
                ..EncodeOptions::default()
            });
        }
        cases.push(EncodeOptions {
            format: Format::Lzip,
            ..EncodeOptions::default()
        });
        cases.push(EncodeOptions {
            format: Format::Lzma,
            ..EncodeOptions::default()
        });
        cases.push(EncodeOptions {
            filters: vec![Filter::Delta { dist: 0 }, Filter::Lzma2(base.clone())],
            ..EncodeOptions::default()
        });
        cases.push(EncodeOptions {
            memlimit: 1 << 20,
            ..EncodeOptions::default()
        });
        cases.push(EncodeOptions {
            threads: 2,
            memlimit: 50 << 20,
            ..EncodeOptions::default()
        });
        for o in cases {
            let c = crate::xz_opts::c::Encoder::new(&o).map(drop);
            let p = crate::xz_opts::pure::Encoder::new(&o).map(drop);
            assert_eq!(verdict(&p), verdict(&c), "{o:?}");
        }
    }

    /// liblzma's threaded encoder checks a chain only when a Block opens:
    /// a misaligned BCJ start makes an empty Stream of an empty input, and
    /// otherwise the Stream Header and then `LZMA_OPTIONS_ERROR`. The pure
    /// tier does the same.
    #[test]
    fn threaded_chains_are_checked_when_a_block_opens() {
        let o = EncodeOptions {
            filters: vec![
                Filter::Bcj {
                    kind: Bcj::Arm,
                    start: 1,
                },
                Filter::Lzma2(Lzma::preset(1, false).unwrap()),
            ],
            threads: 2,
            ..EncodeOptions::default()
        };
        let mut c = crate::xz_opts::c::Encoder::new(&o).unwrap();
        let mut p = crate::xz_opts::pure::Encoder::new(&o).unwrap();
        let (mut co, mut po) = (Vec::new(), Vec::new());
        c.finish(&mut co).unwrap();
        p.finish(&mut po).unwrap();
        assert_eq!(po, co, "the empty Stream");
        assert_eq!(co.len(), 32);
        let mut c = crate::xz_opts::c::Encoder::new(&o).unwrap();
        let mut p = crate::xz_opts::pure::Encoder::new(&o).unwrap();
        let (mut co, mut po) = (Vec::new(), Vec::new());
        let cr = c.feed(b"data", &mut co).and_then(|()| c.finish(&mut co));
        let pr = p.feed(b"data", &mut po).and_then(|()| p.finish(&mut po));
        assert_eq!(verdict(&pr), verdict(&cr));
        assert_eq!(verdict(&cr), verdict(&Err(XzError::Options)));
        assert_eq!(po, co, "the output before the refusal");
        assert_eq!(co.len(), 12);
    }

    /// Samples from liblzma's encoders, each with the options it decodes
    /// with.
    fn corpus() -> Vec<(String, DecodeOptions, Vec<u8>)> {
        let plain = text(3_000, 41);
        let x86 = bin()[..3_000].to_vec();
        let enc = |o: &EncodeOptions, input: &[u8]| c_codec::encode(o, input, 1_000).unwrap();
        // 64 KiB dictionaries: the pure decoder zeroes its whole window,
        // which a debug build pays for on every one of these decodes.
        let small = |level| Lzma {
            dict_size: 1 << 16,
            ..Lzma::preset(level, false).unwrap()
        };
        let base = EncodeOptions {
            filters: vec![Filter::Lzma2(small(1))],
            ..EncodeOptions::default()
        };
        let mut out = Vec::new();
        let mut add = |what: &str, o: DecodeOptions, data: Vec<u8>| {
            out.push((what.to_owned(), o, data));
        };
        let xz = DecodeOptions::default();
        add("xz", xz.clone(), enc(&base, &plain));
        add(
            "xz sha256 blocks",
            xz.clone(),
            enc(
                &EncodeOptions {
                    check: Check::Sha256,
                    block_size: 1_000,
                    ..base.clone()
                },
                &plain,
            ),
        );
        add(
            "xz none delta",
            xz.clone(),
            enc(
                &EncodeOptions {
                    check: Check::None,
                    filters: vec![Filter::Delta { dist: 2 }, Filter::Lzma2(small(0))],
                    ..base.clone()
                },
                &plain,
            ),
        );
        add(
            "xz crc32 x86",
            xz.clone(),
            enc(
                &EncodeOptions {
                    check: Check::Crc32,
                    filters: vec![
                        Filter::Bcj {
                            kind: Bcj::X86,
                            start: 0,
                        },
                        Filter::Lzma2(small(1)),
                    ],
                    ..base.clone()
                },
                &x86,
            ),
        );
        add(
            "xz threaded",
            xz.clone(),
            enc(
                &EncodeOptions {
                    threads: 2,
                    block_size: 1_200,
                    filters: vec![Filter::Lzma2(small(0))],
                    ..base.clone()
                },
                &plain,
            ),
        );
        let empty = enc(&base, b"");
        add("xz empty", xz.clone(), empty.clone());
        // A reserved Stream Flags bit, its CRC32 right: unsupported options.
        let mut reserved = empty;
        reserved[6] = 0x01;
        let crc = super::super::check::crc32(&reserved[6..8], 0);
        reserved[8..12].copy_from_slice(&crc.to_le_bytes());
        add("xz reserved flag", xz.clone(), reserved);
        // A Block Header naming Filter ID 0x22, its CRC32 right.
        let mut unknown = enc(&base, &plain);
        let size = (usize::from(unknown[12]) + 1) * 4;
        assert_eq!(unknown[14], 0x21, "LZMA2's Filter Flags first");
        unknown[14] = 0x22;
        let crc = super::super::check::crc32(&unknown[12..12 + size - 4], 0);
        unknown[12 + size - 4..12 + size].copy_from_slice(&crc.to_le_bytes());
        add("xz unknown filter", xz.clone(), unknown);
        add("xz check 0x0f", xz.clone(), CHECK_0F.to_vec());
        // Two Streams with Stream Padding between them; the first with a
        // small dictionary, so a limit refusing the second's says what the
        // first needed.
        let first = enc(
            &EncodeOptions {
                filters: vec![Filter::Lzma2(small(0))],
                ..base.clone()
            },
            &plain[..1_500],
        );
        let mut two = first;
        two.extend_from_slice(&[0; 8]);
        two.extend_from_slice(&enc(
            &EncodeOptions {
                filters: vec![Filter::Lzma2(Lzma::preset(0, false).unwrap())],
                ..EncodeOptions::default()
            },
            &plain[1_500..],
        ));
        add("xz two streams", xz.clone(), two);
        let lzma = DecodeOptions {
            format: Format::Lzma,
            ..DecodeOptions::default()
        };
        add(
            "lzma",
            lzma,
            enc(
                &EncodeOptions {
                    format: Format::Lzma,
                    filters: vec![Filter::Lzma1(small(2))],
                    ..base.clone()
                },
                &plain,
            ),
        );
        let raw2 = vec![Filter::Delta { dist: 1 }, Filter::Lzma2(small(1))];
        let raw1 = vec![Filter::Lzma1(small(1))];
        for (what, filters) in [("raw lzma2", raw2), ("raw lzma1", raw1)] {
            let data = enc(
                &EncodeOptions {
                    format: Format::Raw,
                    filters: filters.clone(),
                    ..base.clone()
                },
                &plain,
            );
            add(
                what,
                DecodeOptions {
                    format: Format::Raw,
                    raw_filters: filters,
                    ..DecodeOptions::default()
                },
                data,
            );
        }
        {
            // A version-1 `.lz` member by hand: liblzma's raw LZMA1 (lc 3,
            // lp 0, pb 2, end marker) under a 64 KiB dictionary (byte 0x10).
            let lzma = enc(
                &EncodeOptions {
                    format: Format::Raw,
                    filters: vec![Filter::Lzma1(small(1))],
                    ..EncodeOptions::default()
                },
                &plain,
            );
            let mut member = b"LZIP\x01\x10".to_vec();
            member.extend_from_slice(&lzma);
            member.extend_from_slice(&super::super::check::crc32(&plain, 0).to_le_bytes());
            member.extend_from_slice(&(plain.len() as u64).to_le_bytes());
            member.extend_from_slice(&(member.len() as u64 + 16).to_le_bytes());
            add(
                "lzip",
                DecodeOptions {
                    format: Format::Lzip,
                    ..DecodeOptions::default()
                },
                [member.clone(), member].concat(),
            );
        }
        out
    }

    /// The decoder variants each sample runs under.
    fn variants(o: &DecodeOptions) -> Vec<DecodeOptions> {
        let mut v = vec![
            o.clone(),
            DecodeOptions {
                single_stream: true,
                ..o.clone()
            },
            DecodeOptions {
                ignore_check: true,
                ..o.clone()
            },
        ];
        if o.format != Format::Raw {
            v.push(DecodeOptions {
                auto: true,
                ..o.clone()
            });
        }
        v
    }

    /// The same verdict from both decoders for every sample cut short at,
    /// and with a byte flipped at, a spread of offsets (every offset in the
    /// headers and the tail), with junk or padding after it, and under a
    /// ladder of memory limits.
    #[test]
    fn pure_verdicts_match_liblzma() {
        let mut seen = std::collections::BTreeMap::<String, u32>::new();
        let mut tally = |v: String| *seen.entry(v).or_default() += 1;
        for (what, o, data) in corpus() {
            let n = data.len();
            let mut offsets: Vec<usize> = (0..n.min(32)).collect();
            offsets.extend((n.saturating_sub(48)..n).filter(|&i| i >= 32));
            offsets.extend((32..n.saturating_sub(48)).step_by(331));
            for (k, d) in variants(&o).into_iter().enumerate() {
                let label = format!("{what} {d:?}");
                tally(agree(&label, &d, &data, n.max(1)));
                tally(agree(&label, &d, &data, 7));
                // The mutations under the plain options and `auto`; the
                // other variants differ only at the ends and in checks.
                let all = k == 0 || d.auto;
                for &i in offsets.iter().filter(|&&i| all || i < 16 || i + 16 >= n) {
                    tally(agree(&format!("{label} cut at {i}"), &d, &data[..i], 4_093));
                    // A flip in `.lzma`'s size field makes the size known,
                    // the end marker then the case the module doc lists.
                    if d.format == Format::Lzma && (5..13).contains(&i) {
                        continue;
                    }
                    let x = if i % 2 == 0 { 0x01 } else { 0x80 };
                    let mut bad = data.clone();
                    bad[i] ^= x;
                    tally(agree(&format!("{label} ^{x:#x} at {i}"), &d, &bad, 4_093));
                }
                for tail in [&b"junk"[..], &[0; 4], &[0; 3], &[0; 12], b"\xfd7zXZ\0"] {
                    let more = [data.clone(), tail.to_vec()].concat();
                    tally(agree(&format!("{label} + {tail:?}"), &d, &more, 5));
                    tally(agree(&format!("{label} + {tail:?}"), &d, &more, 4_093));
                }
                for memlimit in [1, 4_096, 32_768, 100_000, 300_000, 9 << 20] {
                    let m = DecodeOptions {
                        memlimit,
                        ..d.clone()
                    };
                    tally(agree(
                        &format!("{label} memlimit {memlimit}"),
                        &m,
                        &data,
                        4_093,
                    ));
                }
            }
        }
        // Make sure the sweep reached the verdicts it is about.
        for v in [
            "ok",
            "Unexpected end of input",
            "Compressed data is corrupt",
            "File format not recognized",
            "Unsupported options",
        ] {
            assert!(seen.contains_key(v), "never saw {v:?}: {seen:?}");
        }
        assert!(seen.keys().any(|k| k.starts_with("memlimit")), "{seen:?}");
        // Measured 2026-10-11: every one of these had liblzma stop within 16
        // bytes of the end. A change in the count means the sweep or the
        // deviation moved; look before updating it.
        assert_eq!(seen.get(TOLERATED), Some(&92), "{seen:?}");
    }
}

/// What [`Profile::Reference`] adds to [`Profile::LiblzmaSys`]:
/// `LZ_DICT_EXTRA` on x86 with SSE2, `clk_id` per `mythread_cond` where
/// `configure` defines `HAVE_CLOCK_GETTIME`.
#[test]
fn reference_profile_differs_where_configure_does() {
    let l = Lzma::preset(6, false).unwrap();
    let chain = [Filter::Lzma2(l)];
    let dec = |p| memusage::decoder_memusage_with(p, &chain).unwrap();
    let extra = if cfg!(target_arch = "x86_64") { 32 } else { 0 };
    assert_eq!(dec(Profile::Reference) - dec(Profile::LiblzmaSys), extra);
    let clock = cfg!(any(target_os = "linux", target_vendor = "apple"));
    for threads in [1, 4] {
        let o = EncodeOptions {
            threads,
            ..EncodeOptions::default()
        };
        let enc = |p| memusage::encoder_memusage_with(p, &o).unwrap();
        let want = if clock {
            8 * (u64::from(threads) + 1)
        } else {
            0
        };
        assert_eq!(enc(Profile::Reference) - enc(Profile::LiblzmaSys), want);
    }
}

/// [`Profile::Reference`]'s decoder figure is what the reference `xz`
/// prints: `--robot -lvv`'s `summary` memory usage for a `-6` and a `-9`
/// file (8454776 for `-6` on arm64).
#[cfg(target_os = "macos")]
#[test]
fn reference_profile_is_xzs_list_figure() {
    let Some(xz) = reference() else {
        eprintln!("skipped: no xz 5.8.4");
        return;
    };
    let dir = std::env::temp_dir().join(format!("stuffr-xz-opts-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for level in [6, 9] {
        let packed = run_reference(&xz, &["-T1", &format!("-{level}")], b"some input");
        let file = dir.join(format!("p{level}.xz"));
        std::fs::write(&file, &packed).unwrap();
        let out = std::process::Command::new(&xz)
            .args(["--robot", "-lvv"])
            .arg(&file)
            .output()
            .unwrap();
        let text = String::from_utf8(out.stdout).unwrap();
        let summary = text
            .lines()
            .find(|l| l.starts_with("summary\t"))
            .unwrap_or_else(|| panic!("no summary line:\n{text}"));
        let listed: u64 = summary.split('\t').nth(1).unwrap().parse().unwrap();
        let chain = [Filter::Lzma2(Lzma::preset(level, false).unwrap())];
        assert_eq!(
            memusage::decoder_memusage_with(Profile::Reference, &chain),
            Some(listed),
            "-{level}"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A header declaring a 4 GiB dictionary over a few bytes of known size
/// costs the pure tier a window of the size, not of the dictionary, and
/// decodes as before: `.lzma` with a known size, and an `.xz` Block whose
/// header carries its Uncompressed Size.
#[cfg(feature = "xz-pure")]
#[test]
fn pure_window_is_capped_at_the_declared_size() {
    use std::io::Write;
    let plain = text(5_000, 51);
    let decode = |o: &DecodeOptions, data: &[u8]| {
        let mut d = crate::xz_opts::pure::Decoder::new(o).unwrap();
        let mut out = Vec::new();
        d.feed(data, &mut out).unwrap();
        d.finish(&mut out).unwrap();
        (out, d.window())
    };
    // `.lzma`, size known (no end marker), dictionary patched to 0xFFFFFFFF.
    let opts = lzma_rust2::LzmaOptions::with_preset(1);
    let mut w =
        lzma_rust2::LzmaWriter::new(Vec::new(), &opts, true, false, Some(plain.len() as u64))
            .unwrap();
    w.write_all(&plain).unwrap();
    let mut lzma = w.finish().unwrap();
    lzma[1..5].copy_from_slice(&u32::MAX.to_le_bytes());
    let o = DecodeOptions {
        format: Format::Lzma,
        ..DecodeOptions::default()
    };
    let (out, window) = decode(&o, &lzma);
    assert!(out == plain);
    assert_eq!(window, 5_000);
    // `.xz`: one Block whose header records both sizes and declares LZMA2
    // dictionary byte 40 (0xFFFFFFFF), built by hand around raw LZMA2.
    let lzma2 = pure_codec::encode(
        &EncodeOptions {
            format: Format::Raw,
            filters: vec![Filter::Lzma2(Lzma::preset(1, false).unwrap())],
            ..EncodeOptions::default()
        },
        &plain,
        plain.len(),
    )
    .unwrap();
    let xz = xz_one_block(&lzma2, plain.len() as u64, 40);
    let (out, window) = decode(&DecodeOptions::default(), &xz);
    assert!(out == plain);
    assert_eq!(window, 5_000);
    // Without a declared size, the window is the dictionary's.
    let o = EncodeOptions {
        filters: vec![Filter::Lzma2(Lzma::preset(1, false).unwrap())],
        ..EncodeOptions::default()
    };
    let packed = pure_codec::encode(&o, &plain, plain.len()).unwrap();
    let (out, window) = decode(&DecodeOptions::default(), &packed);
    assert!(out == plain);
    assert_eq!(window, 1 << 20);
}

/// A one-Block `.xz` Stream (no check) around raw LZMA2 data, its Block
/// Header recording both sizes and LZMA2 dictionary byte `dict_prop`.
#[cfg(feature = "xz-pure")]
fn xz_one_block(lzma2: &[u8], uncompressed: u64, dict_prop: u8) -> Vec<u8> {
    use super::check::crc32;
    fn vli(mut v: u64, out: &mut Vec<u8>) {
        while v >= 0x80 {
            out.push((v as u8) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
    }
    let mut out = vec![0xFD, b'7', b'z', b'X', b'Z', 0, 0, 0];
    out.extend_from_slice(&crc32(&[0, 0], 0).to_le_bytes());
    let mut h = vec![0, 0xC0];
    vli(lzma2.len() as u64, &mut h);
    vli(uncompressed, &mut h);
    h.extend_from_slice(&[0x21, 0x01, dict_prop]);
    let size = (h.len() + 4 + 3) & !3;
    h[0] = (size / 4 - 1) as u8;
    h.resize(size - 4, 0);
    let crc = crc32(&h, 0);
    h.extend_from_slice(&crc.to_le_bytes());
    let unpadded = (h.len() + lzma2.len()) as u64;
    out.extend_from_slice(&h);
    out.extend_from_slice(lzma2);
    out.resize(out.len().next_multiple_of(4), 0);
    let start = out.len();
    out.push(0);
    vli(1, &mut out);
    vli(unpadded, &mut out);
    vli(uncompressed, &mut out);
    out.resize(start + (out.len() - start).next_multiple_of(4), 0);
    let crc = crc32(&out[start..], 0);
    out.extend_from_slice(&crc.to_le_bytes());
    let mut tail = (((out.len() - start) / 4 - 1) as u32)
        .to_le_bytes()
        .to_vec();
    tail.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&crc32(&tail, 0).to_le_bytes());
    out.extend_from_slice(&tail);
    out.extend_from_slice(b"YZ");
    out
}

/// `Decoder::finished` on each tier: false while a stream is open, true
/// once it ended, with the input after it left unconsumed under
/// `single_stream`.
macro_rules! finished_test {
    ($name:ident, $tier:path) => {
        #[test]
        fn $name() {
            use $tier as t;
            let mut packed = Vec::new();
            let mut enc = t::Encoder::new(&EncodeOptions::default()).unwrap();
            enc.feed(b"finished", &mut packed).unwrap();
            enc.finish(&mut packed).unwrap();
            let o = DecodeOptions {
                single_stream: true,
                ..DecodeOptions::default()
            };
            let mut dec = t::Decoder::new(&o).unwrap();
            let mut out = Vec::new();
            dec.feed(&packed[..packed.len() - 1], &mut out).unwrap();
            assert!(!dec.finished());
            dec.feed(&[packed[packed.len() - 1], 0, 0, 0, 0, b'j'], &mut out)
                .unwrap();
            assert!(dec.finished());
            assert_eq!(out, b"finished");
            assert_eq!(dec.progress().in_bytes, packed.len() as u64);
        }
    };
}

#[cfg(feature = "xz-c")]
finished_test!(c_decoder_says_when_the_stream_ended, crate::xz_opts::c);
#[cfg(feature = "xz-pure")]
finished_test!(
    pure_decoder_says_when_the_stream_ended,
    crate::xz_opts::pure
);
