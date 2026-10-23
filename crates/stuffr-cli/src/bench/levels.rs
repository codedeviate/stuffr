//! The level table for `stuffr bench`: which codecs are benchmarked and
//! which levels each one runs.
//!
//! A row is always run with `EncodeOpts::level = None`, so it gets the
//! encoder's own default; `Levels::default` is only the label shown for it.

use stuffr::FormatKind;

/// A codec's level row. `default` is `None` for codecs without levels;
/// `sweep` is ascending, includes `default`, and is empty for those codecs
/// (they get one row).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Levels {
    pub default: Option<i32>,
    pub sweep: &'static [i32],
}

const fn some(default: i32, sweep: &'static [i32]) -> Levels {
    Levels {
        default: Some(default),
        sweep,
    }
}

const NONE: Levels = Levels {
    default: None,
    sweep: &[],
};

/// The level row for `format`, or `None` for an unknown format.
///
/// Ranges are each codec's `check_encode_opts` range, except zstd, which
/// sweeps 1..=22 only: its negative "fast" levels reach -131072 and would
/// swamp the table.
pub fn levels_of(format: &str) -> Option<Levels> {
    Some(match format {
        "gzip" | "zlib" | "deflate" | "xz" | "lzma" | "lzip" => {
            some(6, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
        }
        "bzip2" => some(6, &[1, 2, 3, 4, 5, 6, 7, 8, 9]),
        "brotli" => some(11, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]),
        "zstd" => some(
            3,
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
            ],
        ),
        // `compress`'s level is its `maxbits` (9..=16); the default is 16.
        "compress" => some(16, &[9, 10, 11, 12, 13, 14, 15, 16]),
        "lz4" | "snappy" => NONE,
        _ => return None,
    })
}

/// Which implementation of `codec` this build benches: `"c"` (a C library)
/// or `"pure"` (Rust). Only zstd, xz and lzma have a C tier among the
/// registry's codecs. `zlib-c` and `lz4-c` do not count: they serve the
/// `gzip` and `lz4` compatibility links, while the gzip, zlib, deflate and
/// lz4 codecs bench runs stay on flate2's miniz_oxide and on lz4_flex in
/// every build. Each C tier is this crate's own passthrough feature of the
/// same name (`lzma-c` is on through `c-backed`, as `xz-c` is).
pub fn backend_of(codec: &str) -> &'static str {
    const C_TIER: [(&str, bool); 3] = [
        ("zstd", cfg!(feature = "zstd-c")),
        ("xz", cfg!(feature = "xz-c")),
        ("lzma", cfg!(feature = "lzma-c")),
    ];
    if C_TIER.iter().any(|&(name, on)| on && name == codec) {
        "c"
    } else {
        "pure"
    }
}

/// Every codec that can be benchmarked: a codec that writes and whose
/// encoder is not the weak pure-tier one, in capability-matrix order.
pub fn benchable_codecs() -> Vec<&'static str> {
    let reg = stuffr::registry();
    reg.matrix()
        .into_iter()
        .filter(|row| row.kind == FormatKind::Codec && row.write)
        .filter(|row| reg.codec(row.id).is_some_and(|c| !c.caps().weak_encoder))
        .map(|row| row.id.as_str())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use stuffr::{EncodeOpts, FormatId, FormatKind};

    #[derive(Clone)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn input() -> Vec<u8> {
        b"the quick brown fox jumps over the lazy dog. "
            .iter()
            .copied()
            .cycle()
            .take(4096)
            .collect()
    }

    fn encode(name: &'static str, level: Option<i32>) -> Vec<u8> {
        let codec = stuffr::registry()
            .codec(FormatId::new(name))
            .expect("codec registered");
        let buf = Buf(Arc::default());
        let opts = EncodeOpts {
            level,
            ..EncodeOpts::default()
        };
        let mut sink = codec.encoder(Box::new(buf.clone()), &opts).unwrap();
        sink.write_all(&input()).unwrap();
        sink.finish().unwrap();
        buf.0.lock().unwrap().clone()
    }

    #[test]
    fn every_benchable_codec_has_a_row() {
        for name in benchable_codecs() {
            assert!(levels_of(name).is_some(), "{name} has no level row");
        }
        assert!(levels_of("no-such-format").is_none());
    }

    #[test]
    fn the_default_label_is_the_encoders_default() {
        for name in benchable_codecs() {
            let l = levels_of(name).unwrap();
            if let Some(d) = l.default {
                assert_eq!(
                    encode(name, Some(d)),
                    encode(name, None),
                    "{name}: label {d} is not the encoder default"
                );
                assert!(l.sweep.contains(&d), "{name}: sweep omits its default");
            }
        }
    }

    #[test]
    fn every_sweep_level_is_accepted() {
        for name in benchable_codecs() {
            let codec = stuffr::registry().codec(FormatId::new(name)).unwrap();
            let l = levels_of(name).unwrap();
            assert!(
                l.sweep.windows(2).all(|w| w[0] < w[1]),
                "{name}: not ascending"
            );
            for &level in l.sweep {
                let opts = EncodeOpts {
                    level: Some(level),
                    ..EncodeOpts::default()
                };
                codec
                    .check_encode_opts(&opts)
                    .unwrap_or_else(|e| panic!("{name} rejects sweep level {level}: {e}"));
            }
        }
    }

    #[test]
    fn no_weak_encoder_is_benchable() {
        let reg = stuffr::registry();
        let benchable = benchable_codecs();
        for row in reg.matrix() {
            if reg.codec(row.id).is_some_and(|c| c.caps().weak_encoder) {
                assert!(
                    !benchable.contains(&row.id.as_str()),
                    "{} has a weak encoder",
                    row.id.as_str()
                );
            }
        }
    }

    #[test]
    fn the_backend_follows_the_build() {
        // The pure zstd encoder is the weak one: a pure zstd is never
        // benched, so a benched zstd is the C one.
        let zstd_weak = stuffr::registry()
            .codec(FormatId::new("zstd"))
            .is_some_and(|c| c.caps().weak_encoder);
        assert_eq!(backend_of("zstd") == "c", cfg!(feature = "zstd-c"));
        if cfg!(feature = "zstd-c") {
            assert!(!zstd_weak);
        }
        assert_eq!(backend_of("xz") == "c", cfg!(feature = "xz-c"));
        assert_eq!(backend_of("lzma") == "c", cfg!(feature = "lzma-c"));
        // Pure in every build, `zlib-c` and `lz4-c` included.
        for name in [
            "gzip", "zlib", "deflate", "lz4", "bzip2", "brotli", "snappy", "lzip", "compress",
        ] {
            assert_eq!(backend_of(name), "pure", "{name}");
        }
    }

    #[test]
    fn the_backend_follows_each_codecs_own_feature() {
        for (codec, on) in [
            ("zstd", cfg!(feature = "zstd-c")),
            ("xz", cfg!(feature = "xz-c")),
            ("lzma", cfg!(feature = "lzma-c")),
        ] {
            assert_eq!(backend_of(codec), if on { "c" } else { "pure" }, "{codec}");
        }
    }

    #[test]
    fn no_container_is_benchable() {
        let b = benchable_codecs();
        for c in ["tar", "zip", "ar", "cpio"] {
            assert!(!b.contains(&c), "{c} must not be benchable");
        }
        for row in stuffr::registry().matrix() {
            if row.kind == FormatKind::Container {
                assert!(!b.contains(&row.id.as_str()));
            }
        }
    }
}
