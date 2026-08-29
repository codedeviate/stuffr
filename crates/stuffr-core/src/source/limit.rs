//! Decompression-bomb protection.
//!
//! Two pieces rather than one, because the codec sits between them: [`Counting`]
//! wraps the source and tallies compressed bytes going in, and [`RatioGuard`]
//! is called by the copy loop with decompressed bytes coming out. Once output
//! outgrows input implausibly, the decode is refused.

use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{SeekRead, Source, SourceCaps};
use crate::error::{Error, Result};

/// Output below which the ratio is not enforced.
///
/// At stream start the input tally reflects a partially-filled buffer while
/// output can already be substantial, so a naive check trips on legitimate
/// files. No plausible bomb has done damage under a megabyte.
pub const RATIO_FLOOR: u64 = 1024 * 1024;

/// Default expansion ratio past which a decode is refused.
///
/// An order of magnitude above what a single codec can achieve: deflate's
/// structural ceiling is roughly 1032:1, because its maximum match is 258
/// bytes, and ordinary all-zeros input reaches 1014-1027:1. A limit at 1000
/// would therefore reject legitimate sparse files while being unable to catch
/// a single-member bomb, since deflate cannot produce one. The catastrophic
/// cases are nested and archive bombs reaching millions-to-one.
pub const DEFAULT_MAX_RATIO: u64 = 10_000;

/// A [`Source`] that tallies the bytes it has served.
///
/// Capabilities are forwarded unchanged, so wrapping does not push a read down
/// a ladder rung. A caller that seeks makes the tally approximate; that is
/// acceptable because the guard exists to catch pathological expansion, where
/// approximation is irrelevant.
pub struct Counting {
    inner: Box<dyn Source>,
    count: Arc<AtomicU64>,
}

impl Counting {
    /// Returns the wrapper and a handle to its running tally.
    pub fn new(inner: Box<dyn Source>) -> (Self, Arc<AtomicU64>) {
        let count = Arc::new(AtomicU64::new(0));
        (
            Self {
                inner,
                count: Arc::clone(&count),
            },
            count,
        )
    }
}

impl Read for Counting {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

impl Source for Counting {
    fn caps(&self) -> SourceCaps {
        self.inner.caps()
    }

    fn as_seek(&mut self) -> Option<&mut dyn SeekRead> {
        self.inner.as_seek()
    }
}

/// Counts bytes on their way out, so a caller can report `bytes_out` correctly
/// even for a destination with no length — stdout, notably.
///
/// The write-side twin of [`Counting`]. Both live here so Phase 2's containers,
/// which need to account for bytes in both directions per entry, find one
/// mechanism rather than re-inventing this one.
pub struct CountingWriter {
    inner: Box<dyn Write + Send>,
    count: Arc<AtomicU64>,
}

impl CountingWriter {
    /// Returns the wrapper and a handle to its running tally.
    pub fn new(inner: Box<dyn Write + Send>) -> (Self, Arc<AtomicU64>) {
        let count = Arc::new(AtomicU64::new(0));
        (
            Self {
                inner,
                count: Arc::clone(&count),
            },
            count,
        )
    }
}

impl Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.count.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Refuses a decode whose output outgrows its input implausibly.
///
/// Deliberately not a `Read` wrapper: `Read::read` can only return
/// `std::io::Error`, so a reader-based guard would box a typed error inside an
/// io error and force the caller to downcast it back. The copy loop calls
/// [`Self::record`] instead, and `Error::ResourceLimit` reaches `exit_code()`
/// as 6 without that round trip.
pub struct RatioGuard {
    input: Arc<AtomicU64>,
    produced: u64,
    max_ratio: u64,
}

impl RatioGuard {
    /// Creates a new guard watching input tally from `input` and limiting output to `max_ratio`.
    pub fn new(input: Arc<AtomicU64>, max_ratio: u64) -> Self {
        Self {
            input,
            produced: 0,
            max_ratio,
        }
    }

    /// Records `n` bytes of output, failing if the expansion is implausible.
    pub fn record(&mut self, n: usize) -> Result<()> {
        self.produced = self.produced.saturating_add(n as u64);
        if self.produced <= RATIO_FLOOR {
            return Ok(());
        }
        // `.max(1)` guards the division: a source that has served nothing yet
        // while output is already past the floor is itself the pathological case.
        let consumed = self.input.load(Ordering::Relaxed).max(1);
        let ratio = self.produced / consumed;
        if ratio > self.max_ratio {
            return Err(Error::ResourceLimit(format!(
                "expansion ratio {ratio}:1 exceeds the {}:1 limit \
                 ({consumed} bytes read, {} produced); raise --max-ratio if this is genuine",
                self.max_ratio, self.produced
            )));
        }
        Ok(())
    }

    /// Total output recorded so far.
    pub fn produced(&self) -> u64 {
        self.produced
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::ReaderSource;

    fn src(bytes: Vec<u8>) -> Box<dyn Source> {
        Box::new(ReaderSource::new(std::io::Cursor::new(bytes)))
    }

    #[test]
    fn counting_tallies_what_it_serves_and_passes_bytes_through() {
        let (mut c, count) = Counting::new(src(b"0123456789".to_vec()));
        let mut out = Vec::new();
        c.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"0123456789");
        assert_eq!(count.load(Ordering::Relaxed), 10);
    }

    #[test]
    fn counting_forwards_the_inner_capabilities() {
        // Wrapping must not change which ladder rung the source reaches.
        let (c, _) = Counting::new(src(b"x".to_vec()));
        assert!(!c.caps().seekable);
    }

    #[test]
    fn the_guard_ignores_everything_below_the_floor() {
        // At stream start the input tally reflects a partly-filled buffer while
        // output can already be substantial. Enforcing there fails legitimate
        // files, and nothing under a megabyte has done damage.
        let input = Arc::new(AtomicU64::new(1));
        let mut g = RatioGuard::new(Arc::clone(&input), 10);
        // 1 byte in, RATIO_FLOOR out — a 1_048_576:1 ratio, still not enforced.
        assert!(g.record(RATIO_FLOOR as usize).is_ok());
    }

    #[test]
    fn the_guard_refuses_a_pathological_expansion_past_the_floor() {
        let input = Arc::new(AtomicU64::new(1));
        let mut g = RatioGuard::new(Arc::clone(&input), 1000);
        assert!(g.record(RATIO_FLOOR as usize).is_ok());
        let err = g.record(1024).unwrap_err();
        assert!(matches!(err, Error::ResourceLimit(_)));
        assert_eq!(err.exit_code(), 6, "a bomb must exit 6, not 1");
        let msg = err.to_string();
        assert!(
            msg.contains("1000"),
            "the message must name the limit: {msg}"
        );
    }

    #[test]
    fn a_legitimate_ratio_passes_indefinitely() {
        // 4:1 is ordinary text compression and must never trip.
        let input = Arc::new(AtomicU64::new(0));
        let mut g = RatioGuard::new(Arc::clone(&input), 1000);
        for _ in 0..64 {
            input.fetch_add(64 * 1024, Ordering::Relaxed);
            g.record(256 * 1024).unwrap();
        }
    }

    #[test]
    fn a_zero_input_tally_does_not_divide_by_zero() {
        let input = Arc::new(AtomicU64::new(0));
        let mut g = RatioGuard::new(input, 1000);
        // Output past the floor with nothing counted in: must error, not panic.
        assert!(g.record(RATIO_FLOOR as usize + 1).is_err());
    }

    #[test]
    fn counting_writer_tallies_every_byte_including_a_short_write() {
        // A writer that accepts only part of each buffer, which write_all
        // handles by looping. The tally must follow what was ACCEPTED, not what
        // was offered, or bytes_out over-reports on any writer that short-writes.
        struct Short;
        impl std::io::Write for Short {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                Ok(b.len().min(3))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let (mut w, count) = CountingWriter::new(Box::new(Short));
        w.write_all(b"0123456789").unwrap();
        assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 10);
    }
}
