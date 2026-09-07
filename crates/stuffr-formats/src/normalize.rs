//! Reconciling a backend's error behavior with this project's convention —
//! two adapters, one per direction.
//!
//! [`NormalizeDecodeErrors`] handles the READ side: `stuffr_core::Error::
//! from_decode_io` classifies `io::ErrorKind::InvalidData` as `Error::Corrupt`
//! (exit 5) and leaves every other kind as `Error::Io` (exit 1). That stays
//! one rule in one place only if each codec's decoder actually speaks
//! `InvalidData` for malformed input — and the backends do not agree with
//! each other. flate2 uses `InvalidInput` and `UnexpectedEof` and never
//! `InvalidData`; other crates differ again.
//!
//! So each codec declares the kinds ITS backend uses for malformed input, and
//! this wrapper folds exactly those onto `InvalidData`. Every other kind passes
//! through untouched, so a genuine disk failure reading the source stays an I/O
//! error rather than being reported as a corrupt archive.
//!
//! The declared kinds must be MEASURED against the crate, not assumed.
//! Conformance properties 9 and 10 fail loudly for a codec that gets it wrong.
//!
//! [`CaptureWriteError`] handles the WRITE side: a backend that discards a
//! destination's write error during its own finalisation step (brotli's
//! `CompressorWriter::into_inner` returns `W`, not `Result<W, _>` — see
//! `brotli.rs`) still genuinely attempted that write and got a real `Err`;
//! this adapter is the destination the backend writes to, so it sees that
//! `Err` before the backend has a chance to drop it, and hands it back to the
//! caller afterward. It recovers information the backend discards, rather
//! than inventing a new failure — the two adapters are symmetric in that
//! sense: one translates a KIND already carried by a real error, the other
//! preserves a real error a backend would otherwise throw away.
//!
//! Both types are ungated — unlike the codec modules they serve, they carry
//! no format dependency, so they compile in every feature combination,
//! including `features = ["zlib"]` alone with no `gzip` module in the tree at
//! all.

use std::io::{ErrorKind, Read, Write};

/// The `InvalidInput` + `UnexpectedEof` pair, measured independently across
/// two unrelated backends for malformed input.
///
/// flate2 (backing gzip, zlib and deflate): every decode failure is
/// `InvalidInput`, and a stream that runs out mid-member is `UnexpectedEof`.
///
/// bzip2 (over `libbz2-rs-sys`, a wholly different crate): measured via a
/// throwaway test compressing data, flipping a mid-stream byte, and printing
/// `e.kind()`, then repeating for a truncated stream — raising exactly this
/// same pair: `InvalidInput` ("bzip2: invalid data") for a corrupted stream
/// and `UnexpectedEof` ("decompression not finished but EOF reached") for a
/// truncated one.
///
/// The name describes the KINDS, not a backend, precisely because it is
/// already shared by two: a future codec whose measurement comes back
/// different still gets its own constant instead of being tempted to bend
/// this one to fit.
pub(crate) const MALFORMED_AS_INVALID_INPUT_EOF: &[ErrorKind] =
    &[ErrorKind::InvalidInput, ErrorKind::UnexpectedEof];

/// The `Other` + `UnexpectedEof` pair, measured independently against the
/// `snap` crate (backing `snappy.rs`) alone. It is deliberately its OWN
/// constant rather than a widening of [`MALFORMED_AS_INVALID_INPUT_EOF`]
/// above: `Other` is `std::io::ErrorKind`'s generic catch-all, and folding it
/// into the shared constant would apply it to every codec reusing that
/// constant (currently flate2 and bzip2), most of which never raise `Other`
/// for anything and would suddenly have a generic kind reclassified as
/// corrupt on their behalf. A future codec whose measurement also comes back
/// `Other` gets its own constant too, for the same reason — see that
/// constant's doc comment.
///
/// Measured directly against `snap` (see the `snappy_conformance_probe` test
/// in `snappy.rs`, sweeping every byte position of a real encoded payload,
/// not one flip): a corrupted `.sz` frame — a bad chunk CRC32C, a bad stream
/// identifier, an invalid chunk length, an unsupported chunk type — reaches
/// `read::FrameDecoder`'s caller via `snap::Error`'s `From<Error> for
/// io::Error` impl, which unconditionally wraps every variant as
/// `io::ErrorKind::Other`. A stream truncated mid-frame instead surfaces as
/// `UnexpectedEof`, raised by the inner `Read::read_exact` calls
/// `FrameDecoder` makes on its source — which the frame decoder does not
/// intercept or rewrap.
///
/// `Other` is safe to fold onto `InvalidData` HERE, for a reason specific to
/// this backend rather than assumed of the generic kind in general: every
/// decoder in this tree (this one included) passes an error surfaced by its
/// underlying source through unchanged — `read::FrameDecoder::read` only
/// ever constructs an `Other` error itself from `snap::Error`, via the
/// `From` impl above; every other `io::Error` it sees (including one a
/// misbehaving source hands it, e.g. `PermissionDenied`) is propagated by `?`
/// with its original kind intact, never rewrapped as `Other`. So `Other`
/// reaching this wrapper always means the `snap` decoder itself rejected the
/// bytes as malformed, never a genuine I/O failure underneath it — see the
/// negative test proving a real `PermissionDenied` still classifies as
/// `Error::Io` (exit 1), not `Error::Corrupt` (exit 5).
pub(crate) const SNAPPY_MALFORMED_AS_OTHER_EOF: &[ErrorKind] =
    &[ErrorKind::Other, ErrorKind::UnexpectedEof];

/// The `Other` + `UnexpectedEof` pair, measured independently against
/// `lz4_flex` 0.14 (backing `lz4.rs`) alone. Its own constant rather than a
/// widening of [`MALFORMED_AS_INVALID_INPUT_EOF`] — the pair `lz4.rs` used
/// to reuse — for the same reason every `Other`-folding constant in this
/// file is its own: `Other` is `std::io::ErrorKind`'s catch-all, and
/// widening a shared constant to admit it would apply the fold to flate2
/// and bzip2 too, on no evidence either backend ever raises it.
///
/// `lz4.rs`'s own doc used to claim the reuse was "correct" on the strength
/// of `lz4_conformance_probe_corruption_is_silent_at_almost_every_position`,
/// which compresses `incompressible(4 * 1024)` and does not even inspect
/// error KINDS, only whether the decode erred at all — a probe that
/// structurally could not have told `InvalidInput`, `Other` and
/// `UnexpectedEof` apart, let alone measured their split. A whole-branch
/// review measured the raw crate directly instead (`lz4_flex` 0.14, this
/// codec's own `FrameInfo`: `Max64KB` + `content_checksum(true)`): with a
/// COMPRESSIBLE payload (147 positions), `InvalidData: 62`, **`Other: 82`**,
/// `UnexpectedEof: 3` — `Other` at 56% of positions, not the zero the old
/// doc assumed. With an incompressible payload (4,115 positions), `Other`
/// really is 0 — confirming the old probe's shape, not its conclusion: it
/// measured a payload for which `Other` cannot occur and then generalised
/// that absence to the format. Through the CLI, corrupting a stream this
/// codec wrote reached a caller as `Error::Io` (exit 1) instead of
/// `Error::Corrupt` (exit 5) at 82 of 147 (compressible) and 106 of 1,556
/// (mixed corpus) swept positions, on both tiers identically (this codec has
/// only one backend).
///
/// `Other` is safe to fold onto `InvalidData` HERE, for the same structural
/// reason as `SNAPPY_MALFORMED_AS_OTHER_EOF` and `ZSTD_MALFORMED_AS_OTHER_EOF`:
/// traced directly against `lz4_flex::frame::decompress::FrameDecoder::
/// read_block` (`frame/decompress.rs`) and the crate's `impl From<Error> for
/// io::Error` (`frame/mod.rs`), a genuine error reading the underlying
/// SOURCE reaches the caller via `self.r.read_exact(..)?` / `self.r.read(..)?`
/// calls on the wrapped reader, propagated with their original kind intact —
/// `Error::IoError(e)` round-trips through the `From` impl's `IoError(e) =>
/// e` arm unchanged. `Other` is constructed ONLY from `Error::
/// DecompressionError` (a corrupted block's own LZ77 match/literal
/// validation — the `map_err(Error::DecompressionError)` call in
/// `read_block`, the direct analogue of `xz-pure`'s `LzDecoder::repeat`
/// "dist overflow" — see `XZ_PURE_MALFORMED_AS_INVALID_DATA_INPUT_OTHER_EOF`'s
/// doc), `Error::CompressionError`, `Error::SkippableFrame` or `Error::
/// DictionaryNotSupported`, none of which this codec's own `decoder` can
/// ever receive from a wrapped source's I/O — so `Other` reaching this
/// wrapper always means `lz4_flex` itself rejected the bytes, never a
/// genuine I/O failure underneath. `InvalidInput` is deliberately absent
/// from this list, unlike the constant it replaces: `lz4_flex` never raises
/// it (traced through the same `From` impl — every one of its variants maps
/// to either `Other` or `InvalidData` directly, never `InvalidInput`), so
/// including it would be a no-op at best and, per this file's own
/// discipline, an unevidenced claim at worst.
pub(crate) const LZ4_MALFORMED_AS_OTHER_EOF: &[ErrorKind] =
    &[ErrorKind::Other, ErrorKind::UnexpectedEof];

/// The `Other` + `UnexpectedEof` pair, measured independently against the
/// `zstd` crate (backing `zstd_c.rs`) alone. Its own constant for the same
/// reason `SNAPPY_MALFORMED_AS_OTHER_EOF` is not reused here: `Other` is
/// `std::io::ErrorKind`'s catch-all, and two unrelated crates both raising it
/// for malformed input is a coincidence of vocabulary, not evidence they mean
/// the same thing everywhere — folding this into snappy's constant would
/// apply it to snappy too, on no evidence at all.
///
/// Measured directly against `zstd` 0.13 with a throwaway probe (compress a
/// real payload, flip every byte position in turn, count detected vs silent —
/// not one flip): with the encoder's default settings — no content checksum,
/// since `zstd::stream::write::Encoder` requires an explicit
/// `include_checksum(true)` call to turn one on — a flipped byte went
/// UNDETECTED in 44 of 61 positions, decoding to different bytes with no
/// error at all. That is why `Zstd::encoder` in `zstd_c.rs` always turns the
/// checksum on: with it enabled, the same sweep detected all 65 of 65 flipped
/// positions. The corrupted case reaches the caller as `io::ErrorKind::Other`
/// (zstd's own message: "Restored data doesn't match checksum"), and a stream
/// truncated mid-frame reaches it as `UnexpectedEof` ("incomplete frame").
///
/// That 65-of-65 figure holds only for streams `Zstd::encoder` itself wrote.
/// The checksum is a per-writer option in the zstd frame format, not a
/// mandatory part of every valid stream — a `.zst` from another tool that
/// left it off is still fully valid zstd, and `Zstd::decoder` only partially
/// detects corruption in one: 17 of 61 in the sweep above (checksum-less),
/// 21 of 61 in an independently reproduced sweep on a different payload. See
/// `zstd_c.rs`'s `decoder` doc, where a caller actually meets this limit, and
/// `format.rs`'s `detects_corruption` doc for why this is a real distinction
/// and not specific to this one codec.
///
/// `Other` is safe to fold onto `InvalidData` HERE for the same structural
/// reason as `SNAPPY_MALFORMED_AS_OTHER_EOF`: traced directly against `zstd`
/// 0.13's `stream::zio::Reader::read` (`stream/zio/reader.rs`), the only place
/// a genuine error from the wrapped SOURCE reaches the caller is
/// `fill_buf(&mut self.reader)?`, propagated by `?` with its original kind
/// untouched; every other fallible call in that function
/// (`self.operation.run(..)?`, `self.operation.finish(..)?`) is zstd's own
/// decompression operation, whose errors are constructed exclusively by
/// `crate::map_error_code` (`lib.rs`) as `io::ErrorKind::Other` and never by
/// rewrapping a source error. So `Other` reaching this wrapper always means
/// zstd itself rejected the bytes, never a genuine I/O failure underneath —
/// see conformance property 11 (a real `PermissionDenied` still classifies as
/// `Error::Io`, exit 1) for the negative case this depends on.
///
/// Gated `#[cfg(feature = "zstd-c")]`: `zstd_c.rs` is the only consumer, and
/// a build with `zstd-pure` but not `zstd-c` has no `zstd_c` module at all,
/// which left this constant unused and warning under `-D warnings` (caught
/// once `make check` gained a pure-tier leg that actually builds that
/// combination — see the `Makefile`'s `test-pure` target).
#[cfg(feature = "zstd-c")]
pub(crate) const ZSTD_MALFORMED_AS_OTHER_EOF: &[ErrorKind] =
    &[ErrorKind::Other, ErrorKind::UnexpectedEof];

/// The `Other` + `UnexpectedEof` pair, measured independently against
/// `ruzstd` 0.8.1 (backing `zstd_pure.rs`) and still exercised green under
/// the crate's current, unpinned `"0.9"` range (see that module's own doc
/// for the unpin's history) — a wholly different
/// implementation of the same format, so this is its own constant rather
/// than a reuse of [`ZSTD_MALFORMED_AS_OTHER_EOF`] on the strength of a
/// shared format alone; see that constant's doc for the reasoning this
/// mirrors, and `zstd_pure.rs`'s corruption-sweep tests for the sweep this
/// was measured against, on both a stream `ruzstd` itself wrote and one the
/// C backend wrote.
///
/// `StreamingDecoder::read` (`ruzstd::decoding::streaming_decoder`) wraps
/// every error its own `decode_blocks` call raises as `io::Error::other`
/// (`std::io::ErrorKind::Other`) — unconditionally, regardless of what kind
/// of malformation `decode_blocks` detected. Construction
/// (`StreamingDecoder::new`, which parses the frame header eagerly) raises
/// a `FrameDecoderError` rather than an `io::Error` at all; `zstd_pure.rs`'s
/// `LazyRuzstdDecoder` defers that call to the first `read` and turns a
/// construction failure into `io::ErrorKind::InvalidData` directly — see
/// its own doc for why deferring is necessary at all. Only a genuine I/O
/// failure reading the underlying SOURCE (a real disk error, or the source
/// simply running out of bytes — `UnexpectedEof`, propagated by `?` with
/// its kind intact rather than reconstructed) reaches the caller as
/// anything other than `Other` or the `InvalidData` this module's own
/// `LazyRuzstdDecoder` already produces directly.
///
/// Gated `#[cfg(feature = "zstd-pure")]` for the mirror-image reason above:
/// a `zstd-c`-only build has no `zstd_pure` module, so this constant would
/// otherwise be unused there too.
#[cfg(feature = "zstd-pure")]
pub(crate) const RUZSTD_MALFORMED_AS_OTHER_EOF: &[ErrorKind] =
    &[ErrorKind::Other, ErrorKind::UnexpectedEof];

/// The `InvalidData` + `UnexpectedEof` pair, measured independently against
/// the `liblzma` crate (backing `xz_c.rs`) alone. Its own constant rather
/// than a reuse of [`MALFORMED_AS_INVALID_INPUT_EOF`] even though the target
/// kind after folding is the same: that constant's actual SOURCE kind is
/// `InvalidInput`, not `InvalidData` — a different pair of raw kinds that
/// only coincides with xz's in the `UnexpectedEof` half. Widening it to
/// admit `InvalidData` too would apply that fold to flate2 and bzip2 as
/// well, on no evidence either of them ever raises it.
///
/// Measured directly against `liblzma` 0.4.8 with a throwaway probe
/// (compress a 4 KiB incompressible payload, flip every byte position in
/// turn — not one flip; then, separately, truncate at every prefix length):
/// corruption was detected at all 4,156 positions swept, split 4,154
/// `InvalidData` / 2 `UnexpectedEof`, zero silently wrong and zero silently
/// unchanged; truncation was detected at all 4,155 cuts swept, entirely
/// `UnexpectedEof`. `detects_corruption: CorruptionDetection::WhenPresent`
/// in `xz_c.rs`'s `caps()` is direct evidence from this same sweep, not an
/// assumption — see RULING R15 in this cycle's task brief.
///
/// Traced directly against `liblzma_0_4_8::bufread::XzDecoder::read`
/// (`bufread.rs`): a genuine error reading the underlying SOURCE reaches the
/// caller via `self.obj.fill_buf()?`, propagated with its original kind
/// intact; every other fallible path in that function is this crate's own
/// classification, constructed directly rather than by rewrapping a source
/// error — `io::ErrorKind::UnexpectedEof` ("premature eof") when input ends
/// before the decoder reaches `Status::StreamEnd`, `io::ErrorKind::
/// InvalidData` ("corrupt xz stream") when a read makes no progress without
/// having reached eof, and liblzma's own richer `Error` enum (`Error::Data`,
/// `Error::Format`, ...) converted to `io::Error` by its `From` impl in
/// `stream.rs`, which already maps the two malformed-input variants
/// (`Error::Data`, `Error::Format`) to `InvalidData` itself — this codec's
/// fold is a near no-op for that half and does the real work only on the
/// `UnexpectedEof` half. So either kind reaching this wrapper always means
/// the xz decoder itself rejected the bytes, never a genuine I/O failure
/// underneath — the same structural guarantee `ZSTD_MALFORMED_AS_OTHER_EOF`
/// and `SNAPPY_MALFORMED_AS_OTHER_EOF` depend on, re-verified here against
/// this backend specifically rather than assumed to carry over.
///
/// Unlike zstd's content checksum, xz's integrity check is not something
/// this codec has to opt into: `xz_c.rs`'s `encoder` calls `liblzma::write::
/// XzEncoder::new`, which selects `Check::Crc64` unconditionally. The check
/// is still an optional field in the xz format itself (`Check::None` is
/// legal) — see `format.rs`'s `detects_corruption` doc — so a `.xz` written
/// by some other tool with no check at all is not covered by the sweep
/// above, which only measured a stream this codec's own encoder wrote.
///
/// Gated `#[cfg(feature = "xz-c")]`: `xz_c.rs` is the only consumer, and a
/// build with `xz-pure` but not `xz-c` has no `xz_c` module at all, which
/// would otherwise leave this constant unused and warning under `-D
/// warnings` — see `ZSTD_MALFORMED_AS_OTHER_EOF`'s doc for how this was
/// caught for zstd once `make check` gained the pure-tier leg.
#[cfg(feature = "xz-c")]
pub(crate) const XZ_MALFORMED_AS_INVALID_DATA_EOF: &[ErrorKind] =
    &[ErrorKind::InvalidData, ErrorKind::UnexpectedEof];

/// The `InvalidData` + `InvalidInput` + `Other` + `UnexpectedEof` QUADRUPLE,
/// measured independently against `lzma-rust2` 0.20.1 (backing `xz_pure.rs`)
/// alone — a different implementation of the same format from
/// [`XZ_MALFORMED_AS_INVALID_DATA_EOF`]'s `liblzma`, so its own constant for
/// the same reason every other constant here is its own, even though several
/// of its raw kinds coincide.
///
/// **Its own constant, not a reuse of
/// [`LZMA_PURE_MALFORMED_AS_INVALID_DATA_OTHER_EOF`]**, despite both backing
/// crates being `lzma-rust2` and both ultimately bottoming out in the same
/// `lz::LzDecoder` (see below): a shared dependency is not shared evidence,
/// and every other constant in this file already makes its own crate's case
/// on its own terms rather than borrowing a sibling's.
///
/// Originally measured with a 4 KiB INCOMPRESSIBLE payload only: corruption
/// was detected at all 4,156 positions swept, split 4,149 `InvalidData` / 5
/// `InvalidInput` / 2 `UnexpectedEof`, zero `Other` — and the fold list
/// below was drawn from exactly that split, omitting `Other` because the
/// sweep that produced it never raised one. That omission was wrong: an
/// incompressible payload's encoded stream is almost pure literal copy, so
/// corrupting it almost never lands inside the LZ77 match machinery where
/// `Other` originates. A whole-branch review re-measured with a
/// COMPRESSIBLE payload (164 positions) and found `Other` at 99 of them —
/// **60%**, not zero — reaching the caller as `Error::Io` (exit 1,
/// `"i/o error: dist overflow"`) instead of `Error::Corrupt` (exit 5),
/// identically confirmed against the mixed corpus (1,616 of 1,708, 95%) and
/// all-zeros (55 of 124) payloads. Conformance property 9, once it started
/// sweeping a compressible fixture too (see `conformance.rs`'s `compressible`
/// doc), reproduced this directly. Isolated against the raw crate alone
/// (`lzma_rust2` 0.20.1, `XzReader::new(_, true)`, compressible payload, 164
/// positions): `InvalidData: 52, InvalidInput: 9, Other: 99, UnexpectedEof:
/// 4` — `Other` is not a rare corner case for this backend, it is the
/// PLURALITY outcome.
///
/// **`Other` is safe to fold onto `InvalidData` here, for the same
/// structural reason [`LZMA_PURE_MALFORMED_AS_INVALID_DATA_OTHER_EOF`]'s doc
/// gives, because it is the SAME code path underneath a different
/// container**: `XzReader::read` (`src/xz/reader.rs`) drives its LZMA2
/// filter (`src/lzma2_reader.rs`), which decodes into the same
/// `lz::LzDecoder` the raw `LzmaReader` behind `lzma_pure.rs` also drives
/// (`src/lzma_reader.rs`) — traced directly to `LzDecoder::repeat`
/// (`src/lz/lz_decoder.rs:107-109`), whose `dist >= self.full` check
/// constructs `error_other("dist overflow")` (`Error::other`, `src/lib.rs`)
/// directly from the decoder's own internal state, never by rewrapping an
/// error from anywhere else. Every genuine error reading the underlying
/// SOURCE reaches `XzReader::read`'s caller via its own `self.reader.read
/// (buf)?` (`src/xz/reader.rs:410`) or one of `parse`/`read_exact`'s `?`
/// propagations elsewhere in the same file, with the original kind intact —
/// never reconstructed as `Other`. So `Other` reaching this wrapper always
/// means the LZMA2 core inside this xz stream rejected the bytes, never a
/// genuine I/O failure underneath — the same negative case conformance
/// property 11 covers for every other constant in this file.
///
/// The `InvalidInput` cases matter specifically: without folding that kind
/// too, some corrupted positions would reach a caller as a raw,
/// un-normalised `InvalidInput` rather than `Error::Corrupt` (exit 5) — a
/// real, if narrow, gap this constant closes. Traced directly against
/// `lzma_rust2`'s own `error_invalid_input` call sites (`src/lib.rs`;
/// reached from `src/xz/writer.rs`'s filter-count check and a couple of
/// header-parsing paths in `src/xz/reader.rs` and `src/xz/mod.rs`): every
/// one of them rejects a value read from the stream itself as structurally
/// invalid before any I/O on a wrapped SOURCE is attempted at that call
/// site, never a source's own error merely passed through.
///
/// Unlike zstd's content checksum, xz's integrity check is not something
/// this codec has to opt into: `XzOptions::with_preset` (`xz_pure.rs`'s
/// `encoder`) sets `check_type: CheckType::Crc64` unconditionally. See
/// `xz_c.rs`'s module doc and `format.rs`'s `detects_corruption` doc for
/// the same caveat that applies here too: the check is still a per-writer
/// field the xz format permits omitting (`CheckType::None` is legal), so a
/// `.xz` from some other tool with the check turned off is not covered by
/// the sweep above, which only measured a stream this codec's own encoder
/// wrote.
///
/// Gated `#[cfg(feature = "xz-pure")]`: `xz_pure.rs` is the only consumer,
/// and a build with `xz-c` but not `xz-pure` has no `xz_pure` module at
/// all, which would otherwise leave this constant unused and warning under
/// `-D warnings` — see `ZSTD_MALFORMED_AS_OTHER_EOF`'s doc for how this was
/// caught for zstd once `make check` gained the pure-tier leg.
#[cfg(feature = "xz-pure")]
pub(crate) const XZ_PURE_MALFORMED_AS_INVALID_DATA_INPUT_OTHER_EOF: &[ErrorKind] = &[
    ErrorKind::InvalidData,
    ErrorKind::InvalidInput,
    ErrorKind::Other,
    ErrorKind::UnexpectedEof,
];

/// The `InvalidData` + `UnexpectedEof` pair, measured independently against
/// `liblzma`'s LZMA1 "alone" decode path (backing `lzma_c.rs`) — the same
/// crate as [`XZ_MALFORMED_AS_INVALID_DATA_EOF`] but a different `Stream`
/// constructor (`new_lzma_decoder`/`new_lzma_encoder` rather than the
/// auto/easy xz ones) and a different container format entirely (no xz
/// stream header, no block index, no per-writer check type). Its own
/// constant rather than a reuse for the same reason every constant in this
/// file is its own: sharing a crate is not the same as sharing a measured
/// code path, and `lzma_c.rs` can be the only module compiled (an
/// `lzma-c`-without-`xz-c` build has no `xz_c` module at all) so reusing the
/// xz constant would leave it unreachable there anyway.
///
/// Measured directly against `liblzma` 0.4.8 with a throwaway probe (compress
/// a 4 KiB incompressible payload with `Stream::new_lzma_encoder`, flip every
/// byte position of the compressed stream in turn — a full sweep, not one
/// flip — then, separately, truncate at every prefix length): corruption was
/// detected at 4,166 of 4,170 positions swept, split 4,080 `InvalidData` /
/// 86 `UnexpectedEof`, zero silently wrong; the 4 undetected positions were
/// every byte of the header's declared dictionary-size field (offsets 1-4),
/// which this decoder never uses to validate output — only to size an
/// internal buffer — so corrupting it changes nothing observable for a
/// payload far smaller than either the true or the corrupted declared size.
/// Truncation was detected at all 4,169 cuts swept, entirely `UnexpectedEof`.
/// `detects_corruption: CorruptionDetection::Structural` in `lzma_c.rs`'s
/// `caps()` is direct evidence from this same sweep — see that module's doc
/// for why this holds despite
/// LZMA1 carrying no checksum field at all, unlike gzip/zlib/bzip2/snappy's
/// mandatory CRCs or even xz's per-writer check type.
///
/// Traced the same way as `XZ_MALFORMED_AS_INVALID_DATA_EOF`: a genuine
/// error reading the underlying SOURCE reaches the caller via
/// `BufRead::fill_buf`'s `?`, kind intact; every other fallible path is this
/// crate's own classification (`io::ErrorKind::UnexpectedEof` for "premature
/// eof", `io::ErrorKind::InvalidData` for "corrupt xz stream", or liblzma's
/// richer `Error` enum mapped to `InvalidData` by its own `From` impl) —
/// never a rewrapped source error. So either kind reaching this wrapper
/// always means the LZMA1 decoder itself rejected the bytes.
///
/// Gated `#[cfg(feature = "lzma-c")]`: `lzma_c.rs` is the only consumer, and
/// a build with `lzma-pure` but not `lzma-c` has no `lzma_c` module at all,
/// which would otherwise leave this constant unused and warning under
/// `-D warnings` — see `ZSTD_MALFORMED_AS_OTHER_EOF`'s doc for how this was
/// caught once `make check` gained the pure-tier leg.
#[cfg(feature = "lzma-c")]
pub(crate) const LZMA_MALFORMED_AS_INVALID_DATA_EOF: &[ErrorKind] =
    &[ErrorKind::InvalidData, ErrorKind::UnexpectedEof];

/// The `Other` + `InvalidInput` + `UnexpectedEof` TRIPLE, measured
/// independently against `lzma-rust2` 0.20.1's LZMA1 "alone" decode path
/// (backing `lzma_pure.rs`) — a different crate entirely from
/// [`LZMA_MALFORMED_AS_INVALID_DATA_EOF`] (which measures `liblzma`), so its
/// own constant for the same reason every other constant in this file is:
/// a different implementation of the same format is not evidence about
/// this one.
///
/// Measured directly with a throwaway probe against the raw
/// `lzma_rust2::LzmaReader` (compress a payload with this codec's own
/// encoder, flip every byte position of the compressed stream in turn — a
/// full sweep, not one flip — then, separately, truncate at every prefix
/// length), across THREE payload shapes (compressible text, incompressible
/// random data, all zeros): corruption was detected in every case but the
/// honest exception `lzma_pure.rs`'s module doc documents (the header's
/// dictionary-size field, plus this backend's own flush-tail bytes), split
/// almost entirely `Other` (`lzma_rust2`'s own generic error variant,
/// constructed internally rather than by rewrapping a source error — traced
/// against the crate's `decoder.rs` and `lzma_reader.rs`, whose fallible
/// paths raise `error_other`/`error_invalid_data` variants for a corrupted
/// range-coder state) with a small number of `InvalidInput` (the range
/// decoder's own "first byte is not zero" structural check in
/// `range_dec.rs`'s `new_stream`); truncation was detected as
/// `UnexpectedEof` for every cut inside the fixed 18-byte header-plus-prologue
/// (13-byte `.lzma` header, 5-byte range-coder prologue) and as `Other` for
/// deeper cuts, except a cut of exactly the stream's last byte — see
/// `lzma_pure.rs`'s module doc for why that one case needs
/// [`crate::lzma_pure`]'s own `GuardedReader` rather than anything this fold
/// list could cover, since the raw crate reports that one case as `Ok`, not
/// an error of any kind.
///
/// Traced the same way as this file's other constants: a genuine error
/// reading the underlying SOURCE reaches the caller via a `?` on the
/// wrapped reader's own `read`/`read_exact` call, kind intact; every other
/// fallible path is this crate's own classification, constructed directly
/// rather than by rewrapping a source error (see `lib.rs`'s `error_other`,
/// `error_invalid_input`, `error_eof` helpers, all `#[cfg(feature =
/// "std")]` constructors of a plain `std::io::Error`). So any of these three
/// kinds reaching this wrapper always means the LZMA1 decoder itself
/// rejected the bytes, never a genuine I/O failure underneath.
///
/// Gated `#[cfg(feature = "lzma-pure")]`: `lzma_pure.rs` is the only
/// consumer, and a build with `lzma-c` but not `lzma-pure` has no
/// `lzma_pure` module at all, which would otherwise leave this constant
/// unused and warning under `-D warnings` — see
/// `ZSTD_MALFORMED_AS_OTHER_EOF`'s doc for how this was caught once `make
/// check` gained the pure-tier leg.
#[cfg(feature = "lzma-pure")]
pub(crate) const LZMA_PURE_MALFORMED_AS_INVALID_DATA_OTHER_EOF: &[ErrorKind] = &[
    ErrorKind::Other,
    ErrorKind::InvalidInput,
    ErrorKind::UnexpectedEof,
];

/// Its OWN constant, not a widening of [`LZMA_PURE_MALFORMED_AS_INVALID_DATA_OTHER_EOF`]
/// or any other — sharing would make a kind mean "corrupt" for every codec
/// that shares it, which is exactly the mistake this file's module doc warns
/// against.
///
/// `lzip.rs`'s two OWN checks (magic verification and the trailing-bytes
/// check — see that module's doc) already raise `InvalidData` directly for
/// the failure modes `lzma_rust2::LzipReader` itself cannot detect, so they
/// need no folding here. This constant covers what is left: the raw kinds
/// the backend DOES recognize as malformed. `LzipReader`'s own CRC32/
/// data-size/member-size mismatches already construct `io::ErrorKind::
/// InvalidData` directly (`error_invalid_data`, per `lzma-rust2` 0.20.1's
/// `lib.rs`), so those need no folding either — what remains is corruption
/// inside the member's embedded LZMA1 body, decoded by the same
/// `lzma_rust2::LzmaReader` `lzma_pure.rs` uses, and measured (via
/// `lzip.rs`'s own `corruption_sweep_is_detected_everywhere`, a full sweep
/// of every byte position in a small one-member stream, not one flip) to
/// raise the identical `Other`/`InvalidInput`/`UnexpectedEof` set that
/// constant documents for the same underlying reason: same crate, same
/// LZMA1 decode path underneath a different outer format.
///
/// Gated `#[cfg(feature = "lzip")]`: `lzip.rs` is the only consumer, and a
/// build without it would otherwise leave this constant unused and warning
/// under `-D warnings` — see `ZSTD_MALFORMED_AS_OTHER_EOF`'s doc for how
/// that class of mistake was caught once `make check` gained the pure-tier
/// leg.
#[cfg(feature = "lzip")]
pub(crate) const LZIP_MALFORMED_AS_INVALID_DATA_OTHER_EOF: &[ErrorKind] = &[
    ErrorKind::Other,
    ErrorKind::InvalidInput,
    ErrorKind::UnexpectedEof,
];

/// tar's SINGLE malformed-input kind: `io::ErrorKind::Other`, on its own.
///
/// Its OWN constant rather than a reuse of one of the codec lists above, for
/// this file's usual reason — sharing a list makes a kind mean "corrupt" for
/// every format that shares it — and it is the shortest one here because
/// `tar 0.4.46` is unusually disciplined about error construction. TRACED
/// rather than sampled: every malformed-input error on the read path is
/// built by one private helper, `other(msg)` in the crate's `lib.rs`
/// (`Error::new(ErrorKind::Other, msg)`), across 42 call sites — the header
/// checksum mismatch, "failed to read entire block", "unexpected EOF during
/// skip", the GNU sparse-map consistency checks and the PAX/GNU extension
/// checks among them. `header.rs`'s own error paths re-wrap with
/// `io::Error::new(err.kind(), ..)`, which preserves that kind rather than
/// inventing another. The one exception is `InvalidData`, raised for a
/// non-UTF-8 path on Windows, and it needs no folding: it is already the
/// kind this list exists to produce.
///
/// The reason this matters for tar specifically is property 10. A genuine
/// source failure is never rewrapped by the crate: every read reaches the
/// caller through `?` on `&ArchiveInner`'s own `Read` impl with its kind
/// intact, so `Other` arriving from tar always means tar rejected the bytes,
/// never that the disk did. Widening this list — to `UnexpectedEof`, say,
/// which tar never raises here — would start relabelling source failures as
/// corruption.
///
/// Gated `#[cfg(feature = "tar")]`: `tar.rs` is the only consumer, and a
/// build without it would otherwise leave this constant unused and warning
/// under `-D warnings` — see `ZSTD_MALFORMED_AS_OTHER_EOF`'s doc for how
/// that class of mistake was caught once `make check` gained the pure-tier
/// leg.
#[cfg(feature = "tar")]
pub(crate) const TAR_MALFORMED_AS_OTHER: &[ErrorKind] = &[ErrorKind::Other];

pub(crate) struct NormalizeDecodeErrors<R> {
    inner: R,
    malformed: &'static [ErrorKind],
}

impl<R> NormalizeDecodeErrors<R> {
    pub(crate) fn new(inner: R, malformed: &'static [ErrorKind]) -> Self {
        Self { inner, malformed }
    }
}

impl<R: Read> Read for NormalizeDecodeErrors<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf).map_err(|e| {
            if self.malformed.contains(&e.kind()) {
                std::io::Error::new(ErrorKind::InvalidData, e.to_string())
            } else {
                e
            }
        })
    }
}

/// Recovers a write error that a backend discards during finalisation.
///
/// brotli's `CompressorWriter` emits its final block from `into_inner()`,
/// whose signature returns `W` rather than `Result<W, _>` — so a destination
/// that fails at exactly that moment has its error dropped on the floor, and
/// `write_all`/`flush` both report success beforehand. That is precisely the
/// silent truncation `Sink::finish` is contracted to surface (conformance
/// property 5).
///
/// This adapter sits between the backend and the real destination: every
/// `write`/`flush` call is forwarded unchanged, but the first `Err` either one
/// returns is kept here instead of only being returned to the backend (which,
/// for brotli's finalisation path, throws it away). `take_error` lets the
/// codec's `Sink::finish` recover it after the backend has finished
/// discarding it. The failure genuinely happened; this is recovering
/// information the backend dropped, not inventing one.
pub(crate) struct CaptureWriteError<W> {
    inner: W,
    first: Option<std::io::Error>,
}

impl<W> CaptureWriteError<W> {
    pub(crate) fn new(inner: W) -> Self {
        Self { inner, first: None }
    }

    /// Takes the first write/flush error observed, if any. `io::Error` is not
    /// `Clone`, so this consumes it — callers only ever need the first one.
    pub(crate) fn take_error(&mut self) -> Option<std::io::Error> {
        self.first.take()
    }

    /// Records `e` as the first observed error if none has been recorded yet,
    /// then hands back an equivalent error for the immediate caller.
    ///
    /// `io::Error` is not `Clone`, so both the stashed copy and the returned
    /// one are built from the same `(kind, message)` pair rather than sharing
    /// one value. Shared by `write` and `flush` — both call sites were
    /// otherwise identical but for which method's `Err` they were reacting
    /// to.
    fn record(&mut self, e: std::io::Error) -> std::io::Error {
        let kind = e.kind();
        let msg = e.to_string();
        if self.first.is_none() {
            self.first = Some(std::io::Error::new(kind, msg.clone()));
        }
        std::io::Error::new(kind, msg)
    }
}

impl<W: Write> Write for CaptureWriteError<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf).map_err(|e| self.record(e))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush().map_err(|e| self.record(e))
    }
}
