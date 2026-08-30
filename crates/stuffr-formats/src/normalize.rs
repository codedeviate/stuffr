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
