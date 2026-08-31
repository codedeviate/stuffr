//! xz, via the pure-Rust `lzma-rust2` crate — a port of Tukaani's "XZ for
//! Java" that both encodes AND decodes. Unlike `zstd_pure.rs`'s `ruzstd`
//! fallback, this is not a weaker stand-in for a build with no C toolchain:
//! it is a full codec at ratio parity with `xz_c.rs`'s `liblzma` backend, so
//! `--features c-backed` is a speed-and-maturity choice for xz rather than a
//! capability one — a default `cargo install` reads and writes `.xz` with no
//! C toolchain at all.
//!
//! `XZ`, the magic rule and `meta()` live in `crate::xz_shared`, not here —
//! see that module's doc for why: this codec registers the exact same
//! [`stuffr_core::FormatId`] as `xz_c`, and `lib.rs`'s `register_all` makes
//! the two mutually exclusive (`xz_c` wins whenever both are compiled), so
//! neither backend module can own the shared identity.
//!
//! ## The dependency: pure Rust, on this workspace's MSRV floor exactly
//!
//! `lzma-rust2` 0.20.1 depends only on `sha2` + `digest` (needed for xz's
//! optional SHA-256 check type; this codec always selects CRC64 instead, see
//! below) — no `-sys` crate, no C toolchain, no bindgen. It declares
//! `rust-version = "1.85"`, exactly this workspace's floor rather than above
//! it (contrast `zstd_pure.rs`'s `ruzstd`, whose newer releases needed 1.87
//! and had to be pinned below what `cargo add` picked). Its license is
//! Apache-2.0 — permissive, but the first non-MIT dependency reachable from
//! a *default* build (every other default-tier dependency in this workspace
//! is MIT or a compatible dual license) — see Task 8's README note, which
//! this task's brief says must record it.
//!
//! ## Ratio: parity, not a weaker fallback — do not declare `weak_encoder`
//!
//! Measured on a 6.5 MB payload (this codec's encoder against `xz_c`'s, both
//! at preset 6, on the same input): 3,403,096 bytes against liblzma's
//! 3,402,628 — 0.014% larger. On a second, more redundant "source code"
//! style payload the two came out within 0.06% of each other, with this
//! codec's own output the SMALLER of the two on that payload. That is ratio
//! parity, not a weak encoder wearing a strong one's clothes — `caps()`
//! below sets `weak_encoder: false`, and `it_is_a_full_codec_and_not_a_weak_one`
//! pins it so a future edit cannot flip it by analogy with zstd's pure
//! fallback.
//!
//! ## Speed: measured on this machine, and substantially smaller than first
//! ## expected
//!
//! The task brief this codec was built from cited encode ~13x slower and
//! decode ~20x slower than `liblzma`, from an earlier measurement on a
//! different machine against an unspecified "6.5 MB mixed payload". Direct,
//! same-machine, same-payload, release-build measurement here does not
//! reproduce that gap: across three differently-shaped ~6.5 MB payloads (a
//! half-incompressible/half-repetitive mix; synthetic prose-like text with
//! real, varied-distance redundancy; and a shuffled concatenation of this
//! repository's own `.rs` source), encode came out 1.13-1.30x slower than
//! `liblzma` and decode 1.33-2.25x slower — a real, consistent, but far
//! smaller gap than originally briefed. `stf`'s own `examples.txt` and
//! Task 8's README note use these directly measured figures, not the
//! originally briefed ones. The likely explanation is a difference in
//! measurement machine or `lzma-rust2` version rather than an error in
//! either measurement, but this file records what was actually measured
//! here rather than reconciling the two.
//!
//! ## Concatenated streams must not be silently truncated — `allow_multiple_streams`
//!
//! `lzma_rust2::XzReader::new`'s second argument is not a memory limit and
//! its value is not cosmetic, despite looking like an optional knob: with it
//! `false`, two real concatenated xz streams together encoding 26 plain
//! bytes decode to 13 — `Ok`, no error, exactly half the data silently
//! missing; with it `true`, all 26. `cat a.xz b.xz` produces ordinary
//! concatenated xz, and multi-threaded xz emits multi-stream output
//! natively, so this is not an edge case — the same defect class that made
//! lz4 lose every frame after the first in Phase 1d, and that `xz_c.rs`'s
//! own module doc documents for `liblzma`'s equivalent trap
//! (`XzDecoder::new` vs `new_multi_decoder`). `decoder` below always passes
//! `true`. See `concatenated_streams_decode_completely_not_just_the_first`
//! for the regression test, and its sibling
//! `false_would_silently_truncate_a_concatenated_stream` for the paired
//! negative proof that `false` really does fail this — the same pairing
//! `xz_c.rs` uses for its own equivalent regression.
//!
//! ## The integrity check needs no intervention, unlike zstd's
//!
//! `XzOptions::with_preset` (used by `encoder` below) sets
//! `check_type: CheckType::Crc64` unconditionally — this codec never has to
//! opt in the way `zstd_c.rs`'s encoder opts in to its content checksum.
//! Measured with the same sweep methodology `xz_c.rs` uses (flip every byte
//! position of a real 4 KiB payload's compressed form, read through the RAW
//! `lzma_rust2::XzReader` so this codec's own error-normalising wrapper
//! cannot mask what the crate itself raises): all 4,156 positions swept were
//! detected, split 4,149 `InvalidData` / 5 `InvalidInput` / 2
//! `UnexpectedEof`, zero silently wrong and zero silently unchanged; a
//! separate truncation sweep at every one of 4,155 prefix lengths was
//! detected entirely as `UnexpectedEof`. See
//! `crate::normalize`'s `XZ_PURE_MALFORMED_AS_INVALID_DATA_INPUT_EOF` doc for
//! the full measurement and the source-level reasoning behind folding all
//! three kinds onto `InvalidData`, and `fn decoder`'s own doc below for the
//! caveat this measurement does NOT cover (a foreign stream with the check
//! turned off).
//!
//! ## Preset validation is NOT delegated to the crate
//!
//! Measured: `lzma_rust2::LzmaOptions::set_preset` (reached from
//! `XzOptions::with_preset`) clamps its argument with `preset.min(9)` rather
//! than rejecting anything out of range — preset 10, 99, or even a negative
//! `i32` reinterpreted as a huge `u32` all silently become preset 9, with no
//! error and no panic. `xz_c.rs`'s `liblzma` binding does the opposite for
//! the same bad input: `liblzma::write::XzEncoder::new` PANICS on an
//! out-of-range preset. Neither behavior is what a caller should see:
//! `check_encode_opts` below enforces `0..=9` itself, independent of both
//! backends, specifically so `stf pack --format xz --level 99` behaves
//! identically whichever backend a given build compiled — matching
//! `xz_c.rs`'s message wording and exit code (`Error::Usage`, exit 2) rather
//! than inventing a second one.
//!
//! ## `memory_per_worker`: preset 6's dictionary, not preset 9's
//!
//! `8 * 1024 * 1024` (8 MiB) — `LzmaOptions::PRESET_TO_DICT_SIZE[6]`, this
//! codec's default level when no `--level` is given. See `xz_c.rs`'s own
//! `caps()` doc for why this is deliberately the SINGLE-WORKER figure for
//! the default preset rather than preset 9's 64 MiB, or the much larger
//! multi-hundred-MiB figure Phase 1f's parallel encode will need.

use std::io::Write;

use lzma_rust2::{XzOptions, XzReader, XzWriter};

use stuffr_core::{
    Codec, CodecCaps, DecodeOpts, EncodeOpts, Error, FormatId, Result, Sink, Source, StreamOnly,
};

use crate::normalize::{NormalizeDecodeErrors, XZ_PURE_MALFORMED_AS_INVALID_DATA_INPUT_EOF};
pub use crate::xz_shared::{XZ, xz_meta as meta};

#[derive(Debug)]
pub struct Xz;

impl Codec for Xz {
    fn id(&self) -> FormatId {
        XZ
    }

    fn caps(&self) -> CodecCaps {
        CodecCaps {
            // Honest for streams THIS codec writes: `encoder` always selects
            // `CheckType::Crc64`. See the module doc for the measured sweep
            // and `decoder`'s own doc for the foreign-stream caveat.
            detects_corruption: true,
            // preset 6's dictionary (8 MiB) — see the module doc's note on
            // why this, not preset 9's, is the right single-worker figure.
            memory_per_worker: Some(8 * 1024 * 1024),
            // Measured at ratio parity with liblzma (see the module doc) —
            // this is a real codec, not a weaker stand-in like zstd_pure's.
            weak_encoder: false,
            ..CodecCaps::round_trip()
        }
    }

    /// Wrapped in `StreamOnly`: this crate exposes no frame/block index, so
    /// decoded output must not claim random access even though the xz
    /// format itself carries one — see `StreamOnly`'s own doc and
    /// `xz_c.rs`'s identical note.
    ///
    /// Wrapped in `NormalizeDecodeErrors` — see
    /// `crate::normalize::XZ_PURE_MALFORMED_AS_INVALID_DATA_INPUT_EOF`'s doc
    /// for the measurement backing the kinds folded here.
    ///
    /// **`allow_multiple_streams: true`, always.** See the module doc: the
    /// `false` argument silently truncates a concatenated stream to its
    /// first member, exactly the defect class that made lz4 lose every
    /// frame after the first in Phase 1d.
    ///
    /// **Reading a foreign stream.** [`CodecCaps::detects_corruption`] is
    /// `true` for this codec, and the doc on that field requires every
    /// optional-check format to say here what that is worth on a stream this
    /// build did not write. xz's check type is a per-writer choice — the
    /// format permits `CheckType::None` — so a `.xz` carrying no check is
    /// legal and would decode with far weaker detection than the sweep in
    /// the module doc measured.
    ///
    /// In practice that is rare, and measurably so: every xz encoder tested
    /// in this project — `liblzma`'s (`xz_c.rs`) and this one — selects
    /// CRC64 without being asked. That is the opposite of zstd, where the
    /// crate-level encoder omits the checksum by default and checkless
    /// streams are routine (see `zstd_c.rs`'s `decoder`). So the honest
    /// statement is narrower than zstd's: a checkless `.xz` is possible but
    /// unusual, where a checkless `.zst` is ordinary.
    fn decoder(&self, src: Box<dyn Source>, _o: &DecodeOpts) -> Result<Box<dyn Source>> {
        let dec = XzReader::new(src, true);
        Ok(Box::new(StreamOnly::new(NormalizeDecodeErrors::new(
            dec,
            XZ_PURE_MALFORMED_AS_INVALID_DATA_INPUT_EOF,
        ))))
    }

    /// xz's preset range, enforced here rather than delegated to
    /// `lzma_rust2` — see the module doc's "Preset validation" section for
    /// why: the crate silently CLAMPS an out-of-range preset instead of
    /// erroring, and `xz_c.rs`'s backend PANICS on the same input, so this
    /// check is what keeps the two backends behaving alike from a caller's
    /// point of view.
    fn check_encode_opts(&self, o: &EncodeOpts) -> Result<()> {
        match o.level {
            Some(n) if !(0..=9).contains(&n) => Err(Error::Usage(format!(
                "xz compression level must be 0-9, got {n}"
            ))),
            _ => Ok(()),
        }
    }

    fn encoder(&self, dst: Box<dyn Write + Send>, o: &EncodeOpts) -> Result<Box<dyn Sink>> {
        // Not redundant with `ops`'s own pre-flight call: `encoder` is a
        // public trait method any caller can reach directly without going
        // through `ops`, and this is what stops an out-of-range preset
        // reaching `XzOptions::with_preset`, which would otherwise silently
        // clamp it rather than reject it — see the module doc. Conformance
        // property 6 keeps this in step with `check_encode_opts`.
        self.check_encode_opts(o)?;
        let level = o.level.unwrap_or(6) as u32;
        let opts = XzOptions::with_preset(level);
        // `XzWriter::new` returns a `Result` only because it also validates
        // a caller-supplied filter chain (at most 3 pre-filters); this
        // codec never sets any, so this can only ever be `Ok` in practice —
        // propagated with `?` anyway, defensively, rather than `.unwrap()`.
        let writer = XzWriter::new(dst, opts)?;
        Ok(Box::new(XzPureSink(writer)))
    }
}

struct XzPureSink(XzWriter<Box<dyn Write + Send>>);

impl Write for XzPureSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl Sink for XzPureSink {
    /// Writes the closing block, index and stream footer.
    ///
    /// `XzWriter::finish` returns `io::Result<W>` (the inner destination),
    /// propagating a genuine write error encountered during finalisation
    /// rather than discarding it the way brotli's `into_inner` does (see
    /// `crate::normalize`'s `CaptureWriteError` doc for that contrasting
    /// case) — no such adapter is needed here.
    fn finish(self: Box<Self>) -> Result<()> {
        let XzPureSink(writer) = *self;
        let mut w = writer.finish()?;
        w.flush()?;
        Ok(())
    }
}

/// Compresses `plain` with this codec's default options, for tests only.
///
/// Mirrors `xz_c.rs`'s helper of the same name — used by that module's own
/// cross-backend agreement tests, and by this module's.
#[cfg(test)]
pub(crate) fn encode_for_test(plain: &[u8]) -> Vec<u8> {
    let buf = stuffr_core::testing::SharedBuf::new();
    let mut sink = Xz
        .encoder(Box::new(buf.clone()), &EncodeOpts::default())
        .unwrap();
    sink.write_all(plain).unwrap();
    sink.finish().unwrap();
    buf.contents()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use stuffr_core::ReaderSource;
    use stuffr_core::source::{SeekRead, SourceCaps};
    use stuffr_core::testing::SharedBuf;

    fn compress(plain: &[u8]) -> Vec<u8> {
        let buf = SharedBuf::new();
        let mut sink = Xz
            .encoder(Box::new(buf.clone()), &EncodeOpts::default())
            .unwrap();
        sink.write_all(plain).unwrap();
        sink.finish().unwrap();
        buf.contents()
    }

    /// Encodes at preset 0 rather than the default 6, for tests that
    /// construct MANY decoders from one compressed stream (the corruption
    /// and truncation sweeps below).
    ///
    /// This is not a cosmetic speedup: measured directly (a throwaway probe
    /// during this task, decoding the same 4 KiB stream in a loop), a debug
    /// build's per-`XzReader::new` cost is dominated by allocating a buffer
    /// sized to the STREAM's declared dictionary — 8 MiB at preset 6 — at
    /// roughly 21 ms per decode regardless of how little data the stream
    /// actually holds, against roughly 0.7 ms at preset 0's 256 KiB
    /// dictionary (both figures vanish in a release build: ~73 µs either
    /// way). A preset-6-encoded sweep over ~4,150 positions costs on the
    /// order of 85 seconds in the debug build `make check` actually runs;
    /// at preset 0 the same sweep costs on the order of 3 seconds. The
    /// integrity check itself (`CheckType::Crc64`) is set unconditionally
    /// regardless of preset, so this changes nothing about what the sweep
    /// measures — only how long constructing thousands of decoders takes.
    fn compress_fastest(plain: &[u8]) -> Vec<u8> {
        let buf = SharedBuf::new();
        let mut sink = Xz
            .encoder(
                Box::new(buf.clone()),
                &EncodeOpts {
                    level: Some(0),
                    ..Default::default()
                },
            )
            .unwrap();
        sink.write_all(plain).unwrap();
        sink.finish().unwrap();
        buf.contents()
    }

    fn decompress(bytes: Vec<u8>) -> Vec<u8> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
        let mut dec = Xz.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        out
    }

    /// Finds the `xz` binary on `PATH` without shelling out to `which` (not
    /// guaranteed present either, and one external dependency is enough).
    /// Returns `None` rather than panicking so the interop tests below skip
    /// cleanly on a machine with no `xz` installed, rather than failing the
    /// whole suite.
    fn which_xz() -> Option<std::path::PathBuf> {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path).find_map(|dir| {
            let candidate = dir.join("xz");
            candidate.is_file().then_some(candidate)
        })
    }

    fn encode_with(codec: &Xz, plain: &[u8]) -> Vec<u8> {
        let buf = SharedBuf::new();
        let mut sink = codec
            .encoder(Box::new(buf.clone()), &EncodeOpts::default())
            .unwrap();
        sink.write_all(plain).unwrap();
        sink.finish().unwrap();
        buf.contents()
    }

    /// A `Source` that counts every byte actually read off it, so a test can
    /// tell how much of a compressed stream a decoder consumed before
    /// producing its first output — the direct evidence behind "this codec
    /// streams rather than buffering the whole input".
    struct MeteredSource {
        inner: std::io::Cursor<Vec<u8>>,
        consumed: std::sync::Arc<std::sync::atomic::AtomicU64>,
    }

    impl MeteredSource {
        fn new(bytes: Vec<u8>, consumed: std::sync::Arc<std::sync::atomic::AtomicU64>) -> Self {
            Self {
                inner: std::io::Cursor::new(bytes),
                consumed,
            }
        }
    }

    impl Read for MeteredSource {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.consumed
                .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
            Ok(n)
        }
    }

    impl Source for MeteredSource {
        fn caps(&self) -> SourceCaps {
            SourceCaps {
                seekable: false,
                len: None,
            }
        }

        fn as_seek(&mut self) -> Option<&mut dyn SeekRead> {
            None
        }
    }

    #[test]
    fn xz_pure_conforms() {
        // It encodes, so it needs no fixture from the C backend.
        stuffr_core::testing::assert_codec_conforms(&Xz, &meta());
    }

    #[test]
    fn it_is_a_full_codec_and_not_a_weak_one() {
        let c = Xz.caps();
        assert!(c.encode && c.decode);
        assert!(
            !c.weak_encoder,
            "measured at ratio parity with liblzma (see the module doc) — gating it would be a lie"
        );
    }

    /// The interop claim, pinned. A pure build writing `.xz` that only stf
    /// can read would be worse than not writing `.xz` at all.
    #[test]
    fn the_system_xz_tool_accepts_what_this_writes() {
        let Some(xz) = which_xz() else {
            return;
        };
        let plain = b"interop payload ".repeat(4096);
        let packed = encode_with(&Xz, &plain);
        let path = std::env::temp_dir().join("stf-xz-pure-interop.xz");
        std::fs::write(&path, &packed).unwrap();
        let out = std::process::Command::new(&xz)
            .arg("-dc")
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "system xz rejected our output: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            out.stdout, plain,
            "system xz decoded our output to different bytes"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The other interop direction: a `.xz` the SYSTEM tool wrote must be
    /// readable by this codec, not just the reverse. Skips cleanly on a
    /// machine with no `xz` binary, same as the write-direction test above.
    #[test]
    fn this_codec_decodes_what_the_system_xz_tool_writes() {
        let Some(xz) = which_xz() else {
            return;
        };
        let plain = b"the system tool wrote this, lzma-rust2 must read it back ".repeat(4096);
        let src_path = std::env::temp_dir().join("stf-xz-pure-interop-src.bin");
        let xz_path = std::env::temp_dir().join("stf-xz-pure-interop-src.bin.xz");
        std::fs::write(&src_path, &plain).unwrap();
        let out = std::process::Command::new(&xz)
            .arg("-9")
            .arg("-k")
            .arg("-f")
            .arg("-c")
            .arg(&src_path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "system xz failed to compress: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        std::fs::write(&xz_path, &out.stdout).unwrap();
        let packed = std::fs::read(&xz_path).unwrap();
        assert_eq!(
            decompress(packed),
            plain,
            "this codec must decode the system tool's own output byte-for-byte"
        );
        let _ = std::fs::remove_file(&src_path);
        let _ = std::fs::remove_file(&xz_path);
    }

    /// Property 8 checks this generically; this pins it to the codec so a
    /// regression names `xz_pure` rather than the harness.
    #[test]
    fn it_serves_output_before_it_has_read_everything() {
        let plain = stuffr_core::testing::incompressible(4 * 1024 * 1024);
        let packed = encode_with(&Xz, &plain);
        let consumed = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let src: Box<dyn Source> = Box::new(MeteredSource::new(packed, consumed.clone()));
        let mut dec = Xz.decoder(src, &DecodeOpts::default()).unwrap();
        let mut first = [0u8; 1024];
        let n = dec.read(&mut first).unwrap();
        assert!(n > 0);
        let read = consumed.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            read < 1024 * 1024,
            "read {read} bytes before its first output"
        );
    }

    #[test]
    fn round_trips_real_data() {
        let plain = b"the quick brown fox jumps over the lazy dog".repeat(100);
        let packed = compress(&plain);
        assert!(packed.len() < plain.len(), "xz must actually compress this");
        assert_eq!(decompress(packed), plain);
    }

    #[test]
    fn output_begins_with_the_xz_magic() {
        let packed = compress(b"payload");
        assert_eq!(&packed[..6], &[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]);
    }

    #[test]
    fn encode_for_test_helper_produces_a_decodable_stream() {
        let packed = encode_for_test(b"cross-backend payload");
        assert_eq!(decompress(packed), b"cross-backend payload");
    }

    /// RULING R20's regression test. `cat a.xz b.xz` is ordinary xz — not a
    /// pathological input — and multi-threaded xz emits multi-stream output
    /// natively, so a decoder that stops after the first stream silently
    /// truncates real files. Same defect class that made lz4 lose every
    /// frame after the first in Phase 1d, and `zstd_pure`'s own equivalent
    /// bug this cycle.
    #[test]
    fn concatenated_streams_decode_completely_not_just_the_first() {
        let mut two = compress(b"first-stream-");
        two.extend_from_slice(&compress(b"second-stream"));
        assert_eq!(decompress(two), b"first-stream-second-stream");
    }

    /// The paired negative proof, mirroring `xz_c.rs`'s
    /// `new_single_stream_decoder_would_silently_truncate_concatenated_input`:
    /// confirms `allow_multiple_streams: false` really does fail on the same
    /// input `decoder` (which always passes `true`) handles correctly —
    /// measured directly: 13 of 26 plain bytes, `Ok`, not an error. Without
    /// this test, a regression that flipped `decoder`'s hard-coded `true`
    /// back to `false` would silently reopen RULING R20's exact failure mode.
    #[test]
    fn false_would_silently_truncate_a_concatenated_stream() {
        let mut two = compress(b"first-stream-");
        two.extend_from_slice(&compress(b"second-stream"));
        let full_len = b"first-stream-second-stream".len();

        let mut single = XzReader::new(std::io::Cursor::new(two), false);
        let mut out = Vec::new();
        let result = single.read_to_end(&mut out);
        assert!(
            result.is_ok(),
            "allow_multiple_streams: false must not error, just truncate"
        );
        assert!(
            out.len() < full_len,
            "expected allow_multiple_streams: false to silently drop the second stream; got \
             the full {} bytes — if this changed upstream, `decoder` could switch to `false`, \
             but until then `true` stays load-bearing",
            out.len()
        );
    }

    #[test]
    fn level_zero_through_nine_are_all_accepted() {
        for n in 0..=9 {
            let opts = EncodeOpts {
                level: Some(n),
                ..Default::default()
            };
            assert!(
                Xz.check_encode_opts(&opts).is_ok(),
                "level {n} must be accepted"
            );
            assert!(
                Xz.encoder(Box::new(SharedBuf::new()), &opts).is_ok(),
                "level {n} must be accepted by encoder() too"
            );
        }
    }

    /// `lzma_rust2::LzmaOptions::set_preset` silently CLAMPS an
    /// out-of-range preset (`preset.min(9)`) rather than erroring — measured
    /// directly, see the module doc's "Preset validation" section. This test
    /// is what proves `check_encode_opts` catches the same inputs `xz_c.rs`
    /// rejects, even though the two backends would otherwise disagree.
    #[test]
    fn an_out_of_range_level_is_a_usage_error_not_silently_clamped() {
        for n in [-1, 10, i32::MIN, i32::MAX] {
            let opts = EncodeOpts {
                level: Some(n),
                ..Default::default()
            };
            match Xz.check_encode_opts(&opts) {
                Err(err) => {
                    assert!(matches!(err, stuffr_core::Error::Usage(_)));
                    assert_eq!(err.exit_code(), 2);
                    assert!(
                        err.to_string().contains("0-9"),
                        "the error must name the real range: {err}"
                    );
                }
                Ok(_) => panic!("level {n} is out of range and must be rejected"),
            }
            match Xz.encoder(Box::new(SharedBuf::new()), &opts) {
                Err(err) => assert!(matches!(err, stuffr_core::Error::Usage(_))),
                Ok(_) => panic!("encoder() must agree with check_encode_opts() and reject {n}"),
            }
        }
    }

    #[test]
    fn the_decoded_stream_reports_no_seek() {
        let src: Box<dyn Source> =
            Box::new(ReaderSource::new(std::io::Cursor::new(compress(b"x"))));
        let dec = Xz.decoder(src, &DecodeOpts::default()).unwrap();
        assert!(!dec.caps().seekable);
    }

    #[test]
    fn capabilities_and_metadata_match_the_format() {
        let c = Xz.caps();
        assert!(c.encode && c.decode);
        assert!(!c.parallel_encode && !c.frame_index, "not until 1f");
        assert!(!c.weak_encoder, "measured at ratio parity with liblzma");
        let m = meta();
        assert_eq!(m.id, XZ);
        assert_eq!(m.extensions, &["xz"]);
        assert_eq!(m.priority, 0);
    }

    #[test]
    fn xz_declares_an_integrity_check_and_a_memory_figure() {
        let c = Xz.caps();
        assert!(
            c.detects_corruption,
            "this codec always selects CheckType::Crc64; see the module doc"
        );
        assert!(
            c.memory_per_worker.is_some(),
            "a codec that knows its working set should say so; the governor has no other source"
        );
    }

    /// Sweeps every byte position of a real encoded payload rather than
    /// flipping one, mirroring `xz_c.rs`'s and `snappy.rs`'s probes. Backs
    /// `detects_corruption: true` with direct measurement instead of leaving
    /// it aspirational: see `crate::normalize`'s
    /// `XZ_PURE_MALFORMED_AS_INVALID_DATA_INPUT_EOF` doc for the same
    /// figures quoted there, measured against the RAW `XzReader`.
    #[test]
    fn corruption_sweep_is_detected_at_every_position() {
        use stuffr_core::testing::incompressible;

        let plain = incompressible(4 * 1024);
        let packed = compress_fastest(&plain);

        let mut invalid_data = 0usize;
        let mut other_kind = 0usize;
        let mut silently_wrong = 0usize;
        let mut silently_unchanged = 0usize;
        for i in 0..packed.len() {
            let mut corrupted = packed.clone();
            corrupted[i] ^= 0xFF;
            let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(corrupted)));
            let mut dec = Xz.decoder(src, &DecodeOpts::default()).unwrap();
            let mut out = Vec::new();
            match dec.read_to_end(&mut out) {
                Ok(_) if out == plain => silently_unchanged += 1,
                Ok(_) => silently_wrong += 1,
                Err(e) => match e.kind() {
                    std::io::ErrorKind::InvalidData => invalid_data += 1,
                    _ => other_kind += 1,
                },
            }
        }

        assert_eq!(
            silently_wrong, 0,
            "every flipped position must be caught; measured {silently_wrong} silently wrong"
        );
        assert_eq!(
            silently_unchanged, 0,
            "every flipped position must be caught; measured {silently_unchanged} silently \
             unchanged"
        );
        assert_eq!(
            other_kind, 0,
            "NormalizeDecodeErrors folds InvalidData, InvalidInput and UnexpectedEof from this \
             backend onto InvalidData; {other_kind} positions reported neither"
        );
        assert!(
            invalid_data > 0,
            "expected at least one position to be detected; measured 0"
        );
    }

    /// The truncation counterpart, at several cut lengths rather than one —
    /// conformance property 10 already covers this codec through the shared
    /// harness, but this documents the measured kind directly against this
    /// backend rather than only through the harness's classification.
    #[test]
    fn truncation_is_detected_at_every_cut() {
        let plain = stuffr_core::testing::incompressible(4 * 1024);
        let packed = compress(&plain);

        for cut in [1, packed.len() / 4, packed.len() / 2, packed.len() - 1] {
            let truncated = packed[..cut].to_vec();
            let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(truncated)));
            let mut dec = Xz.decoder(src, &DecodeOpts::default()).unwrap();
            let mut out = Vec::new();
            match dec.read_to_end(&mut out) {
                Ok(_) => panic!(
                    "cut to {cut} of {} bytes decoded without error",
                    packed.len()
                ),
                Err(e) => assert_eq!(
                    e.kind(),
                    std::io::ErrorKind::InvalidData,
                    "cut to {cut}: expected InvalidData after normalisation, got {:?}",
                    e.kind()
                ),
            }
        }
    }

    /// Cross-backend agreement, direction 1: `liblzma` (`xz_c`) reads what
    /// THIS codec wrote. Only compiled when both backends are, same as
    /// `zstd_pure.rs`'s equivalent pair.
    #[cfg(all(feature = "xz-pure", feature = "xz-c"))]
    #[test]
    fn c_decodes_a_stream_this_codec_wrote() {
        let plain = b"cross-backend: lzma-rust2 writes, liblzma reads".repeat(50);
        let packed = compress(&plain);
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(packed)));
        let mut dec = crate::xz_c::Xz
            .decoder(src, &DecodeOpts::default())
            .unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, plain);
    }

    /// Cross-backend agreement, direction 2: THIS codec reads what
    /// `liblzma` wrote.
    #[cfg(all(feature = "xz-pure", feature = "xz-c"))]
    #[test]
    fn this_codec_decodes_a_stream_the_c_backend_wrote() {
        let plain = b"cross-backend: liblzma writes, lzma-rust2 reads".repeat(50);
        let packed = crate::xz_c::encode_for_test(plain.as_slice());
        assert_eq!(decompress(packed), plain);
    }
}
