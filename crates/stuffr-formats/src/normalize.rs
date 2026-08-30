//! Normalising a backend's error vocabulary onto this project's convention.
//!
//! `stuffr_core::Error::from_decode_io` classifies `io::ErrorKind::InvalidData`
//! as `Error::Corrupt` (exit 5) and leaves every other kind as `Error::Io`
//! (exit 1). That stays one rule in one place only if each codec's decoder
//! actually speaks `InvalidData` for malformed input — and the backends do not
//! agree with each other. flate2 uses `InvalidInput` and `UnexpectedEof` and
//! never `InvalidData`; other crates differ again.
//!
//! So each codec declares the kinds ITS backend uses for malformed input, and
//! this wrapper folds exactly those onto `InvalidData`. Every other kind passes
//! through untouched, so a genuine disk failure reading the source stays an I/O
//! error rather than being reported as a corrupt archive.
//!
//! The declared kinds must be MEASURED against the crate, not assumed.
//! Conformance properties 9 and 10 fail loudly for a codec that gets it wrong.
//!
//! This type is ungated — unlike the codec modules it serves, it carries no
//! format dependency, so it compiles in every feature combination, including
//! `features = ["zlib"]` alone with no `gzip` module in the tree at all.

use std::io::{ErrorKind, Read};

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
