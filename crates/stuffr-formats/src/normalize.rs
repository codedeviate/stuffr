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
/// `ruzstd` 0.8.1 (backing `zstd_pure.rs` — see its module doc for why this
/// version specifically, not the newer ones) — a wholly different
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
