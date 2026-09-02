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
//! ## The dependency: pure Rust, below this workspace's MSRV floor
//!
//! `lzma-rust2` 0.20.1 depends only on `sha2` + `digest` (needed for xz's
//! optional SHA-256 check type; this codec always selects CRC64 instead, see
//! below) — no `-sys` crate, no C toolchain, no bindgen. It declares
//! `rust-version = "1.85"` — below this workspace's 1.88 floor, so it
//! imposes no constraint here (contrast `zstd_pure.rs`'s `ruzstd`, whose
//! newer releases needed 1.87 and had to be pinned below what `cargo add`
//! picked until the floor itself moved). Its license is
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
//! position of a real payload's compressed form, read through the RAW
//! `lzma_rust2::XzReader` so this codec's own error-normalising wrapper
//! cannot mask what the crate itself raises): every position swept is
//! detected, zero silently wrong and zero silently unchanged, split across
//! four raw kinds — `InvalidData`, `InvalidInput`, `Other`, `UnexpectedEof`
//! — and the split is NOT dominated by `InvalidData` the way a first,
//! incompressible-only sweep suggested (4,149 of 4,156 `InvalidData`, zero
//! `Other`): re-measured with a compressible payload, `Other` is the
//! PLURALITY outcome (99 of 164 positions), because corrupting a stream with
//! real LZ77 matches actually reaches the match-distance validation `Other`
//! comes from, which an incompressible stream's near-all-literal encoding
//! almost never does. A separate truncation sweep at every prefix length is
//! detected entirely as `UnexpectedEof`. See `crate::normalize`'s
//! `XZ_PURE_MALFORMED_AS_INVALID_DATA_INPUT_OTHER_EOF` doc for the full
//! measurement, both payload shapes, and the source-level reasoning behind
//! folding all four kinds onto `InvalidData`, and `fn decoder`'s own doc
//! below for the caveat this measurement does NOT cover (a foreign stream
//! with the check turned off).
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
//! ## `memory_per_worker`: preset 6's dictionary for `caps()`, level-aware for `acquire_many`
//!
//! `caps().memory_per_worker` declares `896 * 1024 * 1024` (896 MiB) — the
//! STATIC, conservative figure for preset 9, the highest this codec accepts.
//! `encoder` below instead calls `per_worker_bytes(level)`, defined near
//! `block_size_for`, which is level-aware and returns a much smaller figure
//! (128 MiB) at the default preset 6. See `per_worker_bytes`'s own doc for
//! the Task 7 measurement backing both numbers, and `xz_c.rs`'s identical
//! split for the sibling backend.
//!
//! ## Parallel encode: block size, and why the single-worker guard needs an
//! ## above-threshold payload to be testable
//!
//! `lzma_rust2::XzWriterMt::new` REFUSES to construct without a block size:
//! measured directly, calling it with `XzOptions::default()`'s `block_size:
//! None` returns `error_invalid_input("block size must be set")` rather than
//! picking a default the way liblzma's `lzma_stream_encoder_mt` does when
//! its own block size is left at `LZMA_VLI_UNKNOWN`. So this codec must pick
//! one, and `encoder` below sets it to **three times the preset's
//! dictionary size** — `block_size_for` — mirroring liblzma's own
//! documented convention for `lzma_stream_encoder_mt` rather than inventing
//! a figure. The crate floors the effective size at the dictionary itself
//! (`block_size.max(dict_size)`), so this codec only has to choose the
//! multiplier, not guard the floor. At the default preset (6, 8 MiB
//! dictionary) that is 24 MiB. **Task 7 measured `memory_per_worker` against
//! this 24 MiB figure and found the true per-worker cost roughly five times
//! larger** — 122.8 MiB, not 24 MiB, because a worker's memory holds the
//! match-finder's hash chains alongside the block buffer, not the block
//! alone. See `per_worker_bytes`'s doc, right after this function, for the
//! full measurement.
//!
//! **A payload at or below the block size yields ONE block, and this
//! backend's one-block MT output is BYTE-IDENTICAL to the single-threaded
//! writer's** — measured directly at the default preset: an 8 MiB payload
//! produces identical bytes whether `block_size` is set to 8 MiB or 24 MiB
//! (one block either way), and at preset 0 (768 KiB block size, three times
//! its 256 KiB dictionary), `XzWriterMt` with exactly one worker matches
//! `XzWriter` byte-for-byte at every size swept from 1 byte to 512 KiB. That
//! is a real difference from `xz_c.rs`'s `liblzma` backend, whose
//! `MtStreamBuilder` container differs from its single-threaded encoder's
//! output at every size measured there, down to one byte — so the same
//! "MT-with-one-worker against single-threaded" byte-equality test that
//! discriminates `xz_c`'s `granted.workers() > 1` guard at 512 KiB proves
//! nothing here at that size, because both paths would produce the same
//! bytes regardless of whether the guard is even present. **The guard-under-
//! test payload here must exceed the block size at the level under test** —
//! measured at preset 0's 768 KiB block size, a 1 MiB payload already
//! diverges (single-threaded 1,048,684 bytes against one-worker MT's
//! 1,048,716), which is what `a_grant_of_one_worker_still_round_trips` below
//! actually exercises.
//!
//! **Worker count, once above one, does not change the output bytes at
//! all** — measured directly: a 2 MiB preset-0 payload (which spans three
//! 768 KiB blocks) produces byte-identical output at one worker and at
//! four. Block boundaries are fixed by `block_size` alone; the worker count
//! only changes how many of those blocks compress concurrently, not what
//! they compress to. So unlike `zstd_c.rs`'s equivalent test, no payload
//! size exists at which this codec's own output could prove multiple
//! workers actually ran — `parallel_output_decodes_to_the_same_plaintext_as_single_threaded`
//! below proves correctness (a genuinely multi-block encode still decodes
//! to the original plaintext) rather than a byte-level parallelism signal,
//! and says so in its own comment.
//!
//! **The integrity check needs no `.check()` call on the MT path either.**
//! `XzOptions::with_preset` already selects `CheckType::Crc64`
//! unconditionally (see the section above), and `XzWriterMt` reads that same
//! field — measured directly on parallel output: stream header byte 7 is
//! `0x04` (CRC64), with nothing to opt into. This is the opposite of
//! `xz_c.rs`'s `liblzma` binding, whose `MtStreamBuilder` selects no check
//! type of its own and needs an explicit `.check(Check::Crc64)`; there is no
//! equivalent call to hunt for here.
//!
//! ## Decode memory bound: a dictionary pre-flight, not a bounded constructor
//!
//! `XzReader::new` allocates a dictionary buffer sized by the value the
//! *stream declares in its own header*, before any output is produced and
//! regardless of how small the file is. Measured peak RSS decoding a
//! **60-byte-class** `.xz` that declares preset 9's 64 MiB dictionary (a
//! locally crafted 68-byte equivalent, `xz -9` on a 1-byte payload):
//!
//! | decoder | peak RSS |
//! |---|---|
//! | baseline, no decode | 2.26 MB |
//! | this backend (`lzma-rust2`), unpatched | **69.35 MB** (68.45 MB measured directly here) |
//! | this backend, after the pre-flight below | ~1.7 MB (allocation never happens) |
//! | `xz_c` (liblzma) | 2.39 MB |
//!
//! liblzma grows its dictionary as needed and is unaffected by this at all;
//! this backend does not grow its buffer, so `lzma_rust2`'s `DICT_SIZE_MAX`
//! (`!15u32`, about 4 GiB) means a crafted file of a few dozen bytes can
//! demand an allocation of that order — roughly a millionfold amplification.
//! **`--max-ratio` does not cover this**: that guard counts decoded *output*
//! bytes, which for such a file is a handful, and the cost is paid in the
//! allocation before any output exists.
//!
//! Neither `XzReader` nor the lower-level push/pull `XzStream`'s bounded
//! `new_mem_limit` constructor is used to close this — the latter is real,
//! but reaching it from the `Read`-shaped `XzReader` this codec is built on
//! would mean a push-to-pull bridge, which Phase 1e measured and cancelled as
//! unworkable (see `lzma_pure.rs`'s module doc, "The push-to-pull bridge is
//! cancelled", for the two measurements that killed it). Instead,
//! [`declared_dictionary_bytes`] parses just enough of the stream header and
//! block header to read the LZMA2 filter's dictionary-size byte directly, and
//! `decoder` below checks it against [`DecodeOpts::memory_limit`] *before*
//! `XzReader::new` is ever called — a pre-flight, not a bounded constructor.
//!
//! **Verified against real `xz` output at four presets** (`-0`, `-3`, `-6`,
//! `-9`) and confirmed to match the documented preset dictionaries exactly —
//! see [`declared_dictionary_bytes`]'s own tests for the byte-level fixtures.
//! Two traps, both exercised by a test:
//!
//! 1. **A BCJ-filtered stream has TWO filters, LZMA2 last, not first.**
//!    `xz --x86 --lzma2=preset=6` measured directly: block header flags claim
//!    `filter_count = 2`, filter 1 is BCJ (id `0x04`, zero properties),
//!    filter 2 is LZMA2 (id `0x21`). A parser that reads only the first
//!    filter would read BCJ's (absent) properties as a dictionary code and
//!    produce nonsense. `declared_dictionary_bytes` walks the whole filter
//!    list and matches on id `0x21` specifically.
//! 2. **A block-header-size byte of `0` is the index indicator, not a block
//!    header.** An empty stream (`xz -9` on zero bytes) has no block at all;
//!    byte 12 (the first byte after the 12-byte stream header) is `0x00`
//!    there, and treating it as `(0+1)*4 = 4` bytes of block header would
//!    misparse the index that actually follows. `declared_dictionary_bytes`
//!    treats this as "cannot decide" (`None`), same as any other case it
//!    cannot confidently parse.
//!
//! **`None` means ALLOW, not refuse.** The block header is at most `(255 +
//! 1) * 4 = 1024` bytes past the 12-byte stream header, so everything needed
//! lies within the first 1036 bytes — comfortably inside the 4096-byte prefix
//! `stuffr`'s `ops::decompress_with` already fills via [`stuffr_core::probe`]
//! before any codec's `decoder()` runs (the same prefix
//! `lzip.rs`'s magic peek and `lzma_pure.rs`'s `peek_declared_need_kb` rely
//! on). A well-formed file can therefore always be decided; a prefix
//! genuinely too short to parse means a truncated header, which is
//! corruption belonging to the decode path (property 9/10's territory), not
//! to this resource check — refusing there would misreport a damaged file as
//! a memory refusal, the same mistake in the opposite direction from
//! `DecodeOpts::memory_limit`'s own exit-6-not-exit-5 rule.

use std::io::{BufRead, BufReader, Write};
use std::num::NonZeroU64;

use lzma_rust2::{XzOptions, XzReader, XzWriter, XzWriterMt};

use stuffr_core::{
    Codec, CodecCaps, CorruptionDetection, DecodeOpts, EncodeOpts, Error, FormatId, Result, Sink,
    Source, StreamOnly,
};

use crate::normalize::{NormalizeDecodeErrors, XZ_PURE_MALFORMED_AS_INVALID_DATA_INPUT_OTHER_EOF};
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
            detects_corruption: CorruptionDetection::WhenPresent,
            // Task 7 measurement: preset 9 (the highest this codec accepts)
            // derives a per-worker delta of ~833.0 MiB — see
            // `per_worker_bytes`'s doc for the full table. THIS FIELD is the
            // STATIC, conservative figure for the highest preset, rounded up
            // to 896 MiB — a static advertisement for callers that
            // introspect `caps()` without ever calling `encoder`. `encoder`
            // below calls `per_worker_bytes(level)` instead, which is
            // level-aware and uses a much smaller figure (128 MiB) at the
            // default preset 6. See the module doc's "memory_per_worker"
            // section.
            memory_per_worker: Some(896 * 1024 * 1024),
            // Measured at ratio parity with liblzma (see the module doc) —
            // this is a real codec, not a weaker stand-in like zstd_pure's.
            weak_encoder: false,
            // `lzma_rust2::XzWriterMt` is real: `encoder` below wires it to
            // a governor grant, using `block_size_for`'s three-times-the-
            // dictionary figure — see the module doc's "Parallel encode"
            // section for why that figure and for the refusal path (a grant
            // of one runs single-threaded, not an error).
            parallel_encode: true,
            ..CodecCaps::round_trip()
        }
    }

    /// Wrapped in `StreamOnly`: this crate exposes no frame/block index, so
    /// decoded output must not claim random access even though the xz
    /// format itself carries one — see `StreamOnly`'s own doc and
    /// `xz_c.rs`'s identical note.
    ///
    /// Wrapped in `NormalizeDecodeErrors` — see
    /// `crate::normalize::XZ_PURE_MALFORMED_AS_INVALID_DATA_INPUT_OTHER_EOF`'s doc
    /// for the measurement backing the kinds folded here.
    ///
    /// **`allow_multiple_streams: true`, always.** See the module doc: the
    /// `false` argument silently truncates a concatenated stream to its
    /// first member, exactly the defect class that made lz4 lose every
    /// frame after the first in Phase 1d.
    ///
    /// **Reading a foreign stream.** [`CodecCaps::detects_corruption`] is
    /// `CorruptionDetection::WhenPresent` for this codec, and the doc on that
    /// variant requires every optional-check format to say here what that is
    /// worth on a stream this
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
    ///
    /// **Memory pre-flight**: before `XzReader::new` ever runs, the block
    /// header's declared LZMA2 dictionary size is read out of the buffered
    /// prefix and checked against [`DecodeOpts::memory_limit`] — see the
    /// module doc's "Decode memory bound" section. `None` (cannot decide)
    /// means allow; the fill happens once, non-destructively, into the same
    /// `BufReader` that goes on to back the decoder, so nothing already
    /// buffered is re-read from the underlying source.
    fn decoder(&self, src: Box<dyn Source>, o: &DecodeOpts) -> Result<Box<dyn Source>> {
        let mut buffered = BufReader::new(src);
        if let Some(limit) = o.memory_limit {
            let prefix = buffered.fill_buf().unwrap_or(&[]);
            if let Some(declared) = declared_dictionary_bytes(prefix)
                && declared > limit
            {
                return Err(Error::ResourceLimit(format!(
                    "xz: header declares a dictionary needing {declared} bytes, but \
                     --memory-limit allows only {limit} bytes — raise --memory-limit to \
                     decode this file"
                )));
            }
        }
        let dec = XzReader::new(buffered, true);
        Ok(Box::new(StreamOnly::new(NormalizeDecodeErrors::new(
            dec,
            XZ_PURE_MALFORMED_AS_INVALID_DATA_INPUT_OTHER_EOF,
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

    /// Single-threaded by default; opts into `lzma_rust2::XzWriterMt` when
    /// the governor grants more than one worker. See the module doc's
    /// "Parallel encode" section for the block size chosen, the refusal
    /// path, and why no `.check()` call is needed on the MT path (unlike
    /// `xz_c.rs`'s `MtStreamBuilder`).
    fn encoder(&self, dst: Box<dyn Write + Send>, o: &EncodeOpts) -> Result<Box<dyn Sink>> {
        // Not redundant with `ops`'s own pre-flight call: `encoder` is a
        // public trait method any caller can reach directly without going
        // through `ops`, and this is what stops an out-of-range preset
        // reaching `XzOptions::with_preset`, which would otherwise silently
        // clamp it rather than reject it — see the module doc. Conformance
        // property 6 keeps this in step with `check_encode_opts`.
        self.check_encode_opts(o)?;
        let level = o.level.unwrap_or(6) as u32;

        // `filter(|n| *n > 0)`, not a bare unwrap_or_else: `--threads 0`
        // means AUTO, and passing 0 through as a request would ask for zero
        // workers. Mirrors `xz_c.rs`'s and `zstd_c.rs`'s `encoder`.
        let (writer, lease) = match &o.governor {
            Some(gov) => {
                let want = o
                    .threads
                    .filter(|n| *n > 0)
                    .unwrap_or_else(|| gov.workers());
                let granted = gov.acquire_many(want, per_worker_bytes(level));
                // A grant of one is single-threaded: `XzWriterMt::new(_, _,
                // 1)` is a different code path from `XzWriter::new` with
                // nothing to gain from it — `acquire_many` clamps rather
                // than failing, so a tight budget is a smaller grant here,
                // never an error. See the module doc's "Parallel encode"
                // section for the measurement backing this guard's test.
                let writer = if granted.workers() > 1 {
                    let mut opts = XzOptions::with_preset(level);
                    opts.set_block_size(Some(block_size_for(&opts)));
                    // `XzWriterMt::new` returns `lzma_rust2::Result`, which
                    // is `io::Result` under this crate's `std` feature (see
                    // `lib.rs`'s `pub(crate) use std::io::Error;`), so `?`
                    // converts the same way `XzWriter::new`'s does below.
                    XzPureWriter::Mt(Box::new(XzWriterMt::new(
                        dst,
                        opts,
                        granted.workers() as u32,
                    )?))
                } else {
                    // Not a single block by any special case: `block_size`
                    // is left `None`, so `XzWriter` never partitions.
                    XzPureWriter::St(Box::new(XzWriter::new(dst, XzOptions::with_preset(level))?))
                };
                (writer, Some(granted))
            }
            None => {
                let writer = XzWriter::new(dst, XzOptions::with_preset(level))?;
                (XzPureWriter::St(Box::new(writer)), None)
            }
        };
        Ok(Box::new(XzPureSink {
            writer,
            _lease: lease,
        }))
    }
}

/// This codec's block size for `XzWriterMt`: three times the preset's
/// dictionary size, mirroring liblzma's own documented convention for
/// `lzma_stream_encoder_mt` — see the module doc's "Parallel encode"
/// section for the full justification, the refusal-without-a-block-size
/// measurement it responds to, and the payload-size consequences.
/// `dict_size` is always positive (256 KiB at preset 0 through 64 MiB at
/// preset 9), so tripling it can never be zero.
fn block_size_for(opts: &XzOptions) -> NonZeroU64 {
    NonZeroU64::new(u64::from(opts.lzma_options.dict_size) * 3)
        .expect("a preset's dict_size is always positive")
}

/// Reads the LZMA2 filter's declared dictionary size out of `prefix`,
/// without constructing `XzReader` or allocating anything sized by it — see
/// the module doc's "Decode memory bound" section for why this exists and
/// what it was measured against.
///
/// `None` means "the prefix does not contain enough to decide" and MUST be
/// treated as allow, not refuse, by every caller — see
/// [`Codec::decoder`]'s doc. That covers a stream header shorter than 13
/// bytes, a magic mismatch, a block header whose declared length runs past
/// the end of `prefix`, a malformed varint, a filter list with no LZMA2
/// filter in it (a foreign filter chain this codec cannot characterize), and
/// the index indicator (trap 2 below) — none of these are this function's
/// job to call corrupt; that is the decode path's job. The magic is checked
/// (not just 13 bytes of *something*) so non-xz input under a
/// `--memory-limit` is left for the decode path's own detection to report as
/// `Corrupt` (exit 5), rather than this pre-flight racing ahead of it and
/// misreporting arbitrary bytes as a resource refusal (exit 6) whenever they
/// happen to decode to a large number.
///
/// Layout, byte-verified against real `xz` 5.8.3 output at presets `-0`,
/// `-3`, `-6` and `-9` (see this function's own tests): a 12-byte stream
/// header, then a block header whose first byte's real length is `(b + 1) *
/// 4`, then a flags byte whose low two bits give `filter_count - 1` and
/// whose `0x40`/`0x80` bits gate two optional size varints, then per filter
/// a varint id, a varint properties length, and that many property bytes.
///
/// Two traps, each pinned by a dedicated test:
///
/// 1. **Walk the whole filter list and match id `0x21` (LZMA2) — never
///    assume it is the first filter.** A BCJ-filtered file
///    (`xz --x86 --lzma2=preset=6`) has two filters, BCJ (id `0x04`, zero
///    properties) before LZMA2. Stopping at the first filter would read
///    BCJ's absent properties as a dictionary code.
/// 2. **A block-header-size byte of `0` is the index indicator, not a block
///    header** — an empty stream has no block at all, and treating that
///    byte as a length misparses the index that actually follows.
///
/// The block header is at most `(255 + 1) * 4 = 1024` bytes, so everything
/// needed always lies within the first `12 + 1024 = 1036` bytes — well
/// inside the 4096-byte prefix `ops::decompress_with` fills via
/// [`stuffr_core::probe`] before any codec's `decoder()` runs.
fn declared_dictionary_bytes(prefix: &[u8]) -> Option<u64> {
    const LZMA2_FILTER_ID: u64 = 0x21;
    const XZ_MAGIC: &[u8; 6] = &[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00];

    // Stream header (12 bytes) plus the block header's own size byte.
    if prefix.len() < 13 || !prefix.starts_with(XZ_MAGIC) {
        return None;
    }
    let block_header_size_byte = prefix[12];
    if block_header_size_byte == 0 {
        // Trap 2: the index indicator, not a block header — see this
        // function's doc.
        return None;
    }
    let block_header_len = (block_header_size_byte as usize + 1) * 4;
    if prefix.len() < 12 + block_header_len {
        return None;
    }
    let block = &prefix[12..12 + block_header_len];
    if block.len() < 2 {
        return None;
    }
    let flags = block[1];
    let filter_count = (flags & 0x03) as usize + 1;
    let mut pos = 2usize;
    if flags & 0x40 != 0 {
        read_xz_varint(block, &mut pos)?;
    }
    if flags & 0x80 != 0 {
        read_xz_varint(block, &mut pos)?;
    }
    // Trap 1: walk every filter, do not stop at the first one.
    for _ in 0..filter_count {
        let filter_id = read_xz_varint(block, &mut pos)?;
        let prop_len = read_xz_varint(block, &mut pos)? as usize;
        let props = block.get(pos..pos + prop_len)?;
        pos += prop_len;
        if filter_id == LZMA2_FILTER_ID {
            return lzma2_dict_size(*props.first()?);
        }
    }
    None
}

/// Reads one xz "variable length integer" (little-endian base-128, high bit
/// of each byte marking continuation) from `data` starting at `*pos`,
/// advancing `*pos` past it. `None` on a byte-starved or non-terminating
/// (more than 9 bytes) encoding — both fold into `declared_dictionary_bytes`'s
/// own "cannot decide" contract.
fn read_xz_varint(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for _ in 0..9 {
        let byte = *data.get(*pos)?;
        *pos += 1;
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
    }
    None
}

/// Decodes LZMA2's one-byte dictionary-size code, verified against real `xz`
/// output at presets `-0` (`0x0c` → 262,144), `-3` (`0x14` → 4,194,304), `-6`
/// (`0x16` → 8,388,608) and `-9` (`0x1c` → 67,108,864) — see this function's
/// tests. `None` for a code above LZMA2's defined range (0-40): a value the
/// spec never assigns is not something this function should guess a size
/// for. Shift never overflows for a valid code: the largest defined shift
/// (code 39) is 30 bits.
fn lzma2_dict_size(code: u8) -> Option<u64> {
    if code > 40 {
        return None;
    }
    if code == 40 {
        return Some(0xFFFF_FFFF);
    }
    let base: u64 = 2 | (u64::from(code) & 1);
    let shift = u32::from(code) / 2 + 11;
    Some(base << shift)
}

/// This codec's per-worker demand for `acquire_many` — level-aware, unlike
/// `caps().memory_per_worker`, which is a static, conservative figure for
/// callers that introspect `caps()` without ever calling `encoder`. `o.level`
/// is available right here, which `caps()` cannot see.
///
/// Measured directly (release build, `/usr/bin/time -l` on macOS, a
/// streamed, tiled-repetitive payload — content does not change dictionary
/// or match-finder memory, only encode speed, which is why a large payload
/// is affordable to measure at all), at 1, 2, 4 and 8 workers, deriving the
/// per-worker delta as `(rss_at_n - rss_at_1) / (n - 1)`:
///
/// | preset | payload | 1w | 2w | 4w | 8w | derived (n=8) |
/// |---|---|---|---|---|---|---|
/// | 6 (default) | 256 MiB | 86.9 MB | 468.2 MB | 662.0 MB | 988.0 MB | 122.8 MiB |
/// | 9 (highest) | 1536 MiB | 645.1 MB | 3025.8 MB | 4272.3 MB | 6759.6 MB | 833.0 MiB |
///
/// **Both figures are far above `block_size_for`'s `3 × dict_size` guess**
/// (24 MiB at preset 6, 192 MiB at preset 9) — trust the measurement, per
/// the brief. The gap matches this crate's match-finder cost for the
/// default BT4 finder, roughly `10.5 × dict_size` per thread, on top of the
/// block buffer itself: `10.5 × 8 MiB + 24 MiB ≈ 108 MiB` at preset 6 and
/// `10.5 × 64 MiB + 192 MiB ≈ 864 MiB` at preset 9 — both within a few
/// percent of the measured deltas above, and within a few MiB of `xz_c.rs`'s
/// independent measurement of the same two presets against `liblzma`
/// instead of this crate, which is why the figures below are the measured
/// ones, not the block-size guess.
///
/// Two tiers, thresholded at preset 7 (`lzma_encoder_presets.c`'s
/// `dict_pow2` table doubles the dictionary from there on — see
/// `xz_c.rs`'s identical threshold): presets 0-6 get the measured preset-6
/// figure (rounded up to 128 MiB), presets 7-9 get the measured preset-9
/// figure (rounded up to 896 MiB). Coarser than a per-preset table, and safe
/// in the direction that matters — every preset below 6 has a smaller
/// dictionary than 6 itself, and 7-8's true cost is well under 9's, so both
/// tiers over-declare rather than under-declare.
fn per_worker_bytes(level: u32) -> u64 {
    if level >= 7 {
        896 * 1024 * 1024 // 896 MiB: headroom over the measured ~833.0 MiB.
    } else {
        128 * 1024 * 1024 // 128 MiB: headroom over the measured ~122.8 MiB.
    }
}

/// Either writer this codec's `encoder` can produce, unified so `XzPureSink`
/// needs only one field regardless of which path was taken.
enum XzPureWriter {
    St(Box<XzWriter<Box<dyn Write + Send>>>),
    Mt(Box<XzWriterMt<Box<dyn Write + Send>>>),
}

impl Write for XzPureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            XzPureWriter::St(w) => w.write(buf),
            XzPureWriter::Mt(w) => w.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            XzPureWriter::St(w) => w.flush(),
            XzPureWriter::Mt(w) => w.flush(),
        }
    }
}

struct XzPureSink {
    writer: XzPureWriter,
    /// Held, not read. Dropping it returns the workers and bytes to the
    /// governor, and `Drop` runs on error paths too — which is why the
    /// lease lives here rather than in `encoder()`'s stack frame. Mirrors
    /// `zstd_c.rs`'s `ZstdSink` and `xz_c.rs`'s `XzSink`.
    _lease: Option<stuffr_core::LeaseSet>,
}

impl Write for XzPureSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

impl Sink for XzPureSink {
    /// Writes the closing block(s), index and stream footer. The governor
    /// lease (if any) is released when `self` drops at the end of this
    /// call.
    ///
    /// Both `XzWriter::finish` and `XzWriterMt::finish` return
    /// `io::Result<W>` (the inner destination), propagating a genuine write
    /// error encountered during finalisation rather than discarding it the
    /// way brotli's `into_inner` does (see `crate::normalize`'s
    /// `CaptureWriteError` doc for that contrasting case) — no such adapter
    /// is needed here.
    fn finish(self: Box<Self>) -> Result<()> {
        let XzPureSink { writer, _lease } = *self;
        let mut w = match writer {
            XzPureWriter::St(w) => w.finish()?,
            XzPureWriter::Mt(w) => w.finish()?,
        };
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

    use crate::xz_shared::which_xz;

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
        assert!(c.parallel_encode, "1f: lzma_rust2::XzWriterMt");
        assert!(!c.frame_index, "not until 1f");
        assert!(!c.weak_encoder, "measured at ratio parity with liblzma");
        let m = meta();
        assert_eq!(m.id, XZ);
        assert_eq!(m.extensions, &["xz"]);
        assert_eq!(m.priority, 0);
    }

    #[test]
    fn xz_declares_an_integrity_check_and_a_memory_figure() {
        let c = Xz.caps();
        assert_eq!(
            c.detects_corruption,
            CorruptionDetection::WhenPresent,
            "this codec always selects CheckType::Crc64; see the module doc"
        );
        assert!(
            c.memory_per_worker.is_some(),
            "a codec that knows its working set should say so; the governor has no other source"
        );
    }

    #[test]
    fn a_tight_memory_limit_clamps_the_worker_count() {
        // The declared figure is what the governor divides by, so a limit of
        // three workers' worth must yield at most three however many CPUs
        // the budget allows. Reads memory_per_worker rather than repeating
        // it: a test with its own copy of the constant stops tracking it.
        let per = Xz
            .caps()
            .memory_per_worker
            .expect("a parallel codec must declare one");
        let gov = stuffr_core::Governor::new(16, per * 3);
        assert!(
            gov.workers_for(per) <= 3,
            "16 CPU workers but only three workers' worth of memory: got {}",
            gov.workers_for(per)
        );
    }

    #[test]
    fn per_worker_bytes_is_level_aware() {
        // Guards against `per_worker_bytes` silently regressing to a
        // constant: preset 9 must demand more memory per worker than the
        // default preset 6, matching Task 7's measurement (~833.0 MiB
        // derived at preset 9 against ~122.8 MiB at preset 6).
        assert!(
            per_worker_bytes(9) > per_worker_bytes(6),
            "the highest preset must demand more memory per worker than the default"
        );
    }

    /// Sweeps every byte position of a real encoded payload rather than
    /// flipping one, mirroring `xz_c.rs`'s and `snappy.rs`'s probes. Backs
    /// `detects_corruption: CorruptionDetection::WhenPresent` with direct
    /// measurement instead of leaving it aspirational: see `crate::normalize`'s
    /// `XZ_PURE_MALFORMED_AS_INVALID_DATA_INPUT_OTHER_EOF` doc for the same
    /// figures quoted there, measured against the RAW `XzReader`.
    ///
    /// Run over BOTH an incompressible and a compressible payload, not just
    /// the former: a whole-branch review found that an incompressible-only
    /// version of this exact sweep passed with `other_kind == 0` while the
    /// fold list omitted `Other` entirely — the incompressible payload's
    /// encoded stream is almost pure literal copy and essentially never
    /// exercises the LZ77 match-distance validation `Other` comes from. The
    /// compressible sweep is the one that would have caught it; see
    /// `crate::normalize`'s doc for the measured split.
    #[test]
    fn corruption_sweep_is_detected_at_every_position() {
        use stuffr_core::testing::{compressible, incompressible};

        for (shape, plain) in [
            ("incompressible", incompressible(4 * 1024)),
            ("compressible", compressible(4 * 1024)),
        ] {
            let packed = compress_fastest(&plain);

            let mut invalid_data = 0usize;
            let mut other_kind = 0usize;
            let mut silently_wrong = 0usize;
            let mut silently_unchanged = 0usize;
            for i in 0..packed.len() {
                let mut corrupted = packed.clone();
                corrupted[i] ^= 0xFF;
                let src: Box<dyn Source> =
                    Box::new(ReaderSource::new(std::io::Cursor::new(corrupted)));
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
                "[{shape}] every flipped position must be caught; measured {silently_wrong} \
                 silently wrong"
            );
            assert_eq!(
                silently_unchanged, 0,
                "[{shape}] every flipped position must be caught; measured \
                 {silently_unchanged} silently unchanged"
            );
            assert_eq!(
                other_kind, 0,
                "[{shape}] NormalizeDecodeErrors folds InvalidData, InvalidInput, Other and \
                 UnexpectedEof from this backend onto InvalidData; {other_kind} positions \
                 reported neither"
            );
            assert!(
                invalid_data > 0,
                "[{shape}] expected at least one position to be detected; measured 0"
            );
        }
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

    // --- Parallel encode (Phase 1f Task 6) — see the module doc's
    // "Parallel encode" section for the measurements these tests rest on.

    #[test]
    fn parallel_encode_is_declared() {
        assert!(
            Xz.caps().parallel_encode,
            "xz_pure's lzma_rust2 backend has XzWriterMt"
        );
    }

    #[test]
    fn a_governor_grant_is_used_and_released() {
        // Property 12 covers this generically; pinned here so a regression
        // names this module rather than the harness.
        use std::sync::Arc;
        use stuffr_core::testing::incompressible;
        let gov = stuffr_core::Governor::new(4, 64 * 1024 * 1024);
        let buf = SharedBuf::new();
        let mut sink = Xz
            .encoder(
                Box::new(buf.clone()),
                &EncodeOpts {
                    governor: Some(Arc::clone(&gov)),
                    ..Default::default()
                },
            )
            .unwrap();
        sink.write_all(&incompressible(1024 * 1024)).unwrap();
        assert!(
            gov.outstanding() > 0,
            "the sink must hold its lease while encoding"
        );
        sink.finish().unwrap();
        assert_eq!(gov.outstanding(), 0, "finish must release the lease");
    }

    #[test]
    fn a_grant_of_one_worker_still_round_trips() {
        // THE REFUSAL PATH, and the one most likely to be written wrong.
        // `acquire_many` clamps rather than failing: a memory limit below
        // one worker's demand yields exactly one worker, and the codec must
        // run single-threaded rather than erroring or oversubscribing.
        //
        // Unlike `xz_c.rs`'s and `zstd_c.rs`'s equivalent tests, the payload
        // here MUST exceed the block size at the level under test — see the
        // module doc's "Parallel encode" section: below the block size,
        // `XzWriterMt` at one worker is byte-identical to `XzWriter`
        // regardless of whether the `granted.workers() > 1` guard is even
        // present, so a small payload could not catch a deleted guard. Level
        // 0's block size is 768 KiB (three times its 256 KiB dictionary);
        // 1 MiB clears it with headroom, and encoding at level 0 keeps this
        // fast (see `compress_fastest`'s doc for why).
        use std::sync::Arc;
        use stuffr_core::testing::incompressible;
        let plain = incompressible(1024 * 1024);
        // 1 byte of budget against a multi-MiB per-worker demand.
        let gov = stuffr_core::Governor::new(8, 1);
        let buf = SharedBuf::new();
        let mut sink = Xz
            .encoder(
                Box::new(buf.clone()),
                &EncodeOpts {
                    level: Some(0),
                    governor: Some(Arc::clone(&gov)),
                    ..Default::default()
                },
            )
            .unwrap();
        sink.write_all(&plain).unwrap();
        sink.finish().unwrap();
        assert_eq!(
            decompress(buf.contents()),
            plain,
            "a one-worker grant must still work"
        );

        // AND the bytes must match a no-governor, single-threaded encode at
        // the same level exactly.
        //
        // Measured (single-threaded len / one-worker-MT len at level 0 on
        // this 1 MiB payload, above the 768 KiB block size): 1,048,684 /
        // 1,048,716 — always unequal above the threshold, which is what
        // makes this assertion able to catch a deleted guard.
        assert_eq!(
            buf.contents(),
            compress_fastest(&plain),
            "a one-worker grant must produce byte-identical output to a \
             single-threaded encode. If this differs, the `granted.workers() \
             > 1` guard has been removed and the MT writer is being used for \
             a grant with nothing to parallelise."
        );
    }

    #[test]
    fn parallel_output_decodes_to_the_same_plaintext_as_single_threaded() {
        // Bytes may differ from a single-threaded encode — multi-threaded
        // xz splits input into blocks. DATA may not. Asserting the
        // plaintext rather than the bytes is the whole reason parallelism
        // is safe to offer.
        //
        // The 2 MiB payload, at level 0 (768 KiB block size), spans three
        // blocks — well above the threshold, so this is a genuinely
        // multi-block encode, not the single-block case the module doc
        // warns produces identical bytes regardless of worker count. What
        // this test CANNOT do, and does not attempt: prove multiple workers
        // actually ran. Measured directly (see the module doc), this
        // backend's output bytes do not change with worker count at all —
        // only `block_size` decides the block boundaries — so no byte
        // comparison in this module can serve as a parallelism signal the
        // way `zstd_c.rs`'s can. Correctness under a real multi-block encode
        // is the property this test proves instead.
        use stuffr_core::testing::incompressible;
        let plain = incompressible(2 * 1024 * 1024);
        let st = compress_fastest(&plain);
        let gov = stuffr_core::Governor::new(4, 256 * 1024 * 1024);
        let buf = SharedBuf::new();
        let mut sink = Xz
            .encoder(
                Box::new(buf.clone()),
                &EncodeOpts {
                    level: Some(0),
                    governor: Some(gov),
                    ..Default::default()
                },
            )
            .unwrap();
        sink.write_all(&plain).unwrap();
        sink.finish().unwrap();
        assert_eq!(decompress(buf.contents()), decompress(st));
    }

    /// Cross-backend arbiter for the parallel path specifically: a stream
    /// `XzWriterMt` produced must be readable by `xz_c.rs`'s `liblzma`
    /// binding too, not just by this codec's own decoder. Uses
    /// `EncodeOpts::default()` (level 6, 24 MiB block size) on a 2 MiB
    /// payload — below the block size, so this is a single-block MT stream;
    /// it proves format compatibility, not multi-block splitting (the test
    /// above already covers that).
    #[test]
    #[cfg(feature = "xz-c")]
    fn liblzma_reads_our_parallel_output() {
        use stuffr_core::testing::incompressible;
        let plain = incompressible(2 * 1024 * 1024);
        let gov = stuffr_core::Governor::new(4, 256 * 1024 * 1024);
        let buf = SharedBuf::new();
        let mut sink = Xz
            .encoder(
                Box::new(buf.clone()),
                &EncodeOpts {
                    governor: Some(gov),
                    ..Default::default()
                },
            )
            .unwrap();
        sink.write_all(&plain).unwrap();
        sink.finish().unwrap();
        let src: Box<dyn Source> =
            Box::new(ReaderSource::new(std::io::Cursor::new(buf.contents())));
        let mut dec = crate::xz_c::Xz
            .decoder(src, &DecodeOpts::default())
            .unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, plain);
    }

    // --- Dictionary pre-flight (Phase 1f Task 9) — see the module doc's
    // "Decode memory bound" section and `declared_dictionary_bytes`'s own
    // doc for the layout and both traps these tests pin.

    /// Byte-level fixtures captured directly from real `xz` 5.8.3 output
    /// (`xz -N -k -c` on a 1-byte payload, N = 0, 3, 6, 9) — pinned as
    /// literal bytes rather than shelled out to `xz`, so this test runs with
    /// no `xz` binary installed. Confirms the parser reproduces the
    /// documented preset dictionaries exactly, at four presets, matching the
    /// module doc's table.
    #[test]
    fn declared_dictionary_bytes_matches_documented_preset_sizes() {
        let preset0: &[u8] = &[
            0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46, 0x03, 0xc0,
            0x1d, 0x19, 0x21, 0x01, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9a, 0x6f, 0xb8, 0x9b,
        ];
        let preset3: &[u8] = &[
            0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46, 0x04, 0xc0,
            0x1d, 0x19, 0x21, 0x01, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xd4, 0x05, 0x73, 0x32,
        ];
        let preset6: &[u8] = &[
            0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46, 0x04, 0xc0,
            0x1d, 0x19, 0x21, 0x01, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xe9, 0xd5, 0x86, 0x36,
        ];
        let preset9: &[u8] = &[
            0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46, 0x04, 0xc0,
            0x1d, 0x19, 0x21, 0x01, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x20, 0x45, 0xa4, 0x21,
        ];
        assert_eq!(
            declared_dictionary_bytes(preset0),
            Some(262_144),
            "preset 0"
        );
        assert_eq!(
            declared_dictionary_bytes(preset3),
            Some(4_194_304),
            "preset 3"
        );
        assert_eq!(
            declared_dictionary_bytes(preset6),
            Some(8_388_608),
            "preset 6"
        );
        assert_eq!(
            declared_dictionary_bytes(preset9),
            Some(67_108_864),
            "preset 9"
        );
    }

    /// Trap 1, pinned: a BCJ-filtered stream (`xz --x86 --lzma2=preset=6`)
    /// has TWO filters, BCJ (id `0x04`, zero properties) before LZMA2 (id
    /// `0x21`) — captured directly from real output. A parser that reads
    /// only the first filter would read BCJ's absent properties as a
    /// dictionary code and produce nonsense; this must still recover
    /// preset 6's 8 MiB.
    #[test]
    fn declared_dictionary_bytes_skips_a_leading_bcj_filter() {
        let bcj_then_lzma2: &[u8] = &[
            0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46, 0x04, 0xc1,
            0x1d, 0x19, 0x04, 0x00, 0x21, 0x01, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x87, 0xc8, 0xe1, 0xe9,
        ];
        assert_eq!(
            declared_dictionary_bytes(bcj_then_lzma2),
            Some(8_388_608),
            "must walk past the BCJ filter to find LZMA2, not read BCJ's own \
             (absent) properties as a dictionary code"
        );
    }

    /// Trap 2, pinned: an empty stream has no block at all — the byte right
    /// after the 12-byte stream header is `0x00`, the index indicator, not
    /// a block-header-size byte. Captured from real `xz -9` on zero bytes.
    /// Treating it as a block header would misparse the index; this must
    /// return `None` ("cannot decide"), never a bogus size.
    #[test]
    fn declared_dictionary_bytes_treats_the_index_indicator_as_undecidable() {
        let empty_stream: &[u8] = &[
            0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46, 0x00,
        ];
        assert_eq!(
            declared_dictionary_bytes(empty_stream),
            None,
            "byte 12 is 0x00 (the index indicator), not a block header"
        );
    }

    /// `None` on a prefix too short to contain even the block header's own
    /// size byte — this is corruption's territory (property 9/10), not this
    /// check's; a too-short prefix must ALLOW, never refuse.
    #[test]
    fn declared_dictionary_bytes_is_none_on_a_too_short_prefix() {
        assert_eq!(declared_dictionary_bytes(&[]), None);
        assert_eq!(declared_dictionary_bytes(&[0xfd, 0x37, 0x7a]), None);
    }

    /// `None` when the block header's own declared length runs past what
    /// the prefix actually holds — a truncated header, not this check's to
    /// call corrupt.
    #[test]
    fn declared_dictionary_bytes_is_none_when_the_block_header_is_cut_short() {
        // Stream header + a size byte claiming 16 bytes of block header,
        // with only 4 actually present.
        let cut: &[u8] = &[
            0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46, 0x03, 0xc0,
            0x1d, 0x19,
        ];
        assert_eq!(declared_dictionary_bytes(cut), None);
    }

    /// The refusal path: preset 9's 64 MiB dictionary, under a 1 MiB limit,
    /// must be refused by `decoder()` itself — before `XzReader::new` (and
    /// its allocation) ever runs — and the refusal must be exit 6
    /// (`ResourceLimit`), NEVER exit 5: the file is not damaged, this build
    /// simply will not allocate that much.
    #[test]
    fn a_declared_dictionary_over_the_limit_is_refused_before_allocating() {
        let buf = SharedBuf::new();
        let mut sink = Xz
            .encoder(
                Box::new(buf.clone()),
                &EncodeOpts {
                    level: Some(9),
                    ..Default::default()
                },
            )
            .unwrap();
        sink.write_all(b"tiny payload").unwrap();
        sink.finish().unwrap();
        let packed = buf.contents();

        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(packed)));
        let err = match Xz.decoder(
            src,
            &DecodeOpts {
                memory_limit: Some(1024 * 1024),
                ..Default::default()
            },
        ) {
            Err(e) => e,
            Ok(_) => panic!("preset 9's 64 MiB dictionary must be refused under a 1 MiB limit"),
        };
        assert_eq!(
            err.exit_code(),
            6,
            "a memory refusal is ResourceLimit, not Corrupt: {err}"
        );
        assert!(
            err.to_string().contains("--memory-limit"),
            "the message must name the flag so the user can raise it: {err}"
        );
    }

    /// Matters more than the refusal above: over-strictness rejects valid
    /// files. A legitimate dictionary that fits under the limit must still
    /// decode.
    #[test]
    fn a_legitimate_dictionary_under_the_limit_still_decodes() {
        let plain = b"ordinary payload ".repeat(2000);
        let packed = encode_with(&Xz, &plain);
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(packed)));
        let mut dec = Xz
            .decoder(
                src,
                &DecodeOpts {
                    memory_limit: Some(64 * 1024 * 1024),
                    ..Default::default()
                },
            )
            .unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, plain);
    }

    /// `DecodeOpts::default()` has `memory_limit: None`. The CLI always sets
    /// a limit; a library caller who deliberately passes `None` keeps the
    /// old, unbounded behaviour.
    #[test]
    fn no_limit_means_no_bound_for_library_callers() {
        let plain = b"payload ".repeat(2000);
        let packed = encode_with(&Xz, &plain);
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(packed)));
        let mut dec = Xz.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, plain);
    }

    /// The test that matters more than the refusal: we are refusing on a
    /// resource policy, not on validity. A real `xz -9` stream on a tiny
    /// payload legitimately declares preset 9's 64 MiB dictionary — the
    /// reference tool decodes it without complaint — so refusing it here
    /// must be exit 6 (`ResourceLimit`), never exit 5 (`Corrupt`). Getting
    /// that backwards would tell users their archive is damaged when it is
    /// fine. Skips cleanly when `xz` is not on `PATH`.
    #[test]
    fn the_reference_tool_still_accepts_what_we_now_refuse() {
        let Some(xz) = which_xz() else {
            return;
        };
        let src_path = std::env::temp_dir().join("stf-xz-pure-preflight-src.bin");
        std::fs::write(&src_path, b"a").unwrap();
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
        let packed = out.stdout;

        let xz_path = std::env::temp_dir().join("stf-xz-pure-preflight-src.bin.xz");
        std::fs::write(&xz_path, &packed).unwrap();
        let reference = std::process::Command::new(&xz)
            .arg("-dc")
            .arg(&xz_path)
            .output()
            .unwrap();
        assert!(
            reference.status.success(),
            "sanity check on the reference tool itself: it must accept its own -9 output — \
             reference disagreed, so this test's own premise is wrong"
        );
        assert_eq!(reference.stdout, b"a");

        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(packed)));
        let err = match Xz.decoder(
            src,
            &DecodeOpts {
                memory_limit: Some(1024 * 1024),
                ..Default::default()
            },
        ) {
            Err(e) => e,
            Ok(_) => panic!("preset 9's dictionary must be refused under a 1 MiB limit"),
        };
        assert_eq!(
            err.exit_code(),
            6,
            "a legitimate, reference-tool-accepted file refused on a resource policy must be \
             ResourceLimit, never Corrupt: {err}"
        );

        let _ = std::fs::remove_file(&src_path);
        let _ = std::fs::remove_file(&xz_path);
    }
}
