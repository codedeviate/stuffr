//! Marking a [`Source`] as sitting BELOW a codec decoder.
//!
//! # The problem this exists for
//!
//! `stuffr` answers two different questions with the same Rust type. A read
//! that fails because the bytes are malformed is the ARCHIVE's fault —
//! [`Error::Corrupt`], exit 5. A read that fails because the disk, the pipe or
//! the permission bits gave out is STUFFR's environment failing —
//! [`Error::Io`], exit 1, which this project reserves for "stuffr itself
//! failed". Both arrive as an [`io::Error`], and [`Error::from_decode_io`]
//! exists to make the first call correctly.
//!
//! What decides which one a given error is, is **not the error's kind** — it is
//! WHICH READ produced it. And until this module existed, the only thing that
//! recorded that was whether the human who wrote the `?` happened to remember.
//! Every `io::Error` on every read path funnels through one conversion — `impl
//! From<io::Error> for Error` — and that conversion could not see the
//! difference, so a bare `?` below a decoder was **wrong by default**.
//!
//! It was wrong in four places at once, found by enumerating the funnel rather
//! than by following a reproducer:
//!
//! * `spill.rs`'s two `src.read(..)?` calls — the ladder's rung 3, reached by
//!   every `needs_seek` container (`arj`, `zoo`) over a codec.
//! * `lha.rs`'s `PeekSource::fill(source, 1)?` in `Lha::open`.
//! * `cpio.rs`'s `fill_header_prefix()?` per-header read-ahead.
//! * `zip.rs`'s `read_fixed`/`skip`, whose `map_err(Error::from)` is the
//!   funnel spelled out longhand.
//!
//! Three of those carry doc comments asserting the raw-source reading ("a
//! genuine source failure keeps its own kind and exit code") — correct for a
//! raw source, false for a decoded one, and nothing in the type system
//! disagreed.
//!
//! # The mechanism
//!
//! [`DecodeSideSource`] wraps a codec's decoder output and tags every
//! `io::Error` it yields with a private marker payload, preserving the error's
//! [`io::ErrorKind`] and its `Display` text exactly. `From<io::Error> for
//! Error` then routes a tagged error through [`Error::from_decode_io`] and
//! leaves an untagged one as [`Error::Io`]. A bare `?` becomes correct on
//! BOTH sides of the line, and stays correct for code nobody has written yet.
//!
//! # Why this cannot lie in the opposite direction
//!
//! [`Error::from_decode_io`] folds exactly two kinds — `InvalidData` to
//! `Corrupt` and `OutOfMemory` to `ResourceLimit`. A real disk error, a
//! permission failure or a broken pipe propagating up THROUGH a decoder keeps
//! its own kind, so it is still [`Error::Io`] and still exit 1. The marker
//! cannot turn an environment failure into "the archive is corrupt"; it can
//! only stop a malformed-input report from claiming stuffr failed.
//!
//! The raw source is never marked. `resolve_chain_deep_with`'s own top-level
//! `probe(src)` call, `Input::open`, and `SpillSource`'s writes to its temp
//! file all read or write something that is nobody's decoder output, and all
//! three still answer [`Error::Io`]. That is pinned from both ends by
//! `probe.rs`'s `a_raw_source_io_error_of_the_identical_kind_stays_io_not_
//! corrupt` and by `cli.rs`'s `list_reports_a_directory_as_an_io_failure_not_
//! as_corrupt`.
//!
//! [`Error`]: crate::Error
//! [`Error::Corrupt`]: crate::Error::Corrupt
//! [`Error::Io`]: crate::Error::Io
//! [`Error::from_decode_io`]: crate::Error::from_decode_io

use std::fmt;
use std::io::{self, Read};

use super::{SeekRead, Source, SourceCaps};

/// The payload that marks an [`io::Error`] as having been raised below a
/// decoder.
///
/// Private on purpose: the only way to set it is [`mark_decode_side`] and the
/// only way to read it is [`is_decode_side`], so no caller outside this module
/// can forge or strip the distinction.
///
/// `Display` forwards to the wrapped error verbatim, which is what keeps every
/// user-facing message byte-identical to what it was before the marker
/// existed — `Error::Corrupt(e.to_string())` renders the decoder's own
/// complaint, not a wrapper's paraphrase of it.
#[derive(Debug)]
struct DecodeSideTag(io::Error);

impl fmt::Display for DecodeSideTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl std::error::Error for DecodeSideTag {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Tags `e` as having been raised by a read below a codec decoder.
///
/// Preserves [`io::Error::kind`] and the `Display` text. **Idempotent** — a
/// stream decoded through three codec layers is wrapped three times, and only
/// the innermost wrap allocates; the outer two hand the already-tagged error
/// straight back.
pub fn mark_decode_side(e: io::Error) -> io::Error {
    if is_decode_side(&e) {
        return e;
    }
    let kind = e.kind();
    io::Error::new(kind, DecodeSideTag(e))
}

/// Whether `e` came from a read below a codec decoder.
///
/// Consulted by `impl From<io::Error> for Error`, which is the single place
/// every `?` on a read path passes through.
pub fn is_decode_side(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<DecodeSideTag>())
}

/// A [`Source`] whose read failures are marked as decode-side.
///
/// Wrapped around a codec's decoder output by `probe.rs` — at both of the two
/// places a decoder is built, so the marking is a property of "a decoder ran",
/// not of which resolution route was taken.
///
/// `as_seek` FORWARDS rather than wrapping, and that is a deliberate gap with
/// a measured floor under it: a codec's decoder returns [`StreamOnly`], whose
/// `as_seek` is `None`, so no seek reaches the forwarded path from any
/// registered codec today. Wrapping it would need a second adapter around a
/// borrowed `&mut dyn SeekRead`, which is not expressible without boxing per
/// call. A codec that one day exposes a real seek table (seekable zstd, an xz
/// block index — the case [`Source::as_seek`] exists for) must revisit this.
///
/// [`StreamOnly`]: crate::source::StreamOnly
pub struct DecodeSideSource {
    inner: Box<dyn Source>,
}

impl DecodeSideSource {
    /// Wraps `inner`, which must be a codec decoder's output.
    ///
    /// Returns a `Box<dyn Source>` rather than `Self` because every caller
    /// immediately needs the trait object, and handing back the concrete type
    /// would invite a caller to keep it and lose the marking by passing the
    /// inner source on instead.
    pub fn wrap(inner: Box<dyn Source>) -> Box<dyn Source> {
        Box::new(Self { inner })
    }
}

impl Read for DecodeSideSource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf).map_err(mark_decode_side)
    }
}

impl Source for DecodeSideSource {
    fn caps(&self) -> SourceCaps {
        self.inner.caps()
    }

    fn as_seek(&mut self) -> Option<&mut dyn SeekRead> {
        self.inner.as_seek()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::source::ReaderSource;

    /// A source that yields `good` bytes and then fails with `kind` forever.
    struct FailsAfter {
        good: Vec<u8>,
        pos: usize,
        kind: io::ErrorKind,
    }

    impl Read for FailsAfter {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos < self.good.len() {
                let n = (self.good.len() - self.pos).min(buf.len());
                buf[..n].copy_from_slice(&self.good[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            Err(io::Error::new(self.kind, "the decoded bytes are malformed"))
        }
    }

    impl Source for FailsAfter {
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

    fn failing(kind: io::ErrorKind) -> Box<dyn Source> {
        Box::new(FailsAfter {
            good: b"prefix".to_vec(),
            pos: 0,
            kind,
        })
    }

    #[test]
    fn a_tagged_error_keeps_its_kind_and_message() {
        let raw = io::Error::new(io::ErrorKind::InvalidData, "block header is malformed");
        let expected = raw.to_string();
        let tagged = mark_decode_side(raw);

        assert_eq!(tagged.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            tagged.to_string(),
            expected,
            "the marker must be invisible in every user-facing message"
        );
        assert!(is_decode_side(&tagged));
    }

    /// A stream decoded through N codec layers is wrapped N times. Stacking
    /// tags would work, but each wrap allocates, and a caller comparing
    /// `kind()` through two layers of `Custom` would be reading a different
    /// error than the one the decoder raised.
    #[test]
    fn marking_is_idempotent() {
        let once = mark_decode_side(io::Error::new(io::ErrorKind::InvalidData, "boom"));
        let twice = mark_decode_side(once);
        let thrice = mark_decode_side(twice);

        assert!(is_decode_side(&thrice));
        assert_eq!(thrice.kind(), io::ErrorKind::InvalidData);
        assert_eq!(thrice.to_string(), "boom");
        // One unwrap reaches the ORIGINAL error, not a second tag.
        let inner = thrice.get_ref().expect("tagged errors carry a payload");
        let tag = inner
            .downcast_ref::<DecodeSideTag>()
            .expect("the payload is the tag");
        assert!(
            !is_decode_side(&tag.0),
            "a second wrap must not have stacked a tag inside the first"
        );
    }

    /// The hazard half. An identical error that never passed through a
    /// decoder carries no tag, so `?` still produces `Error::Io` — exit 1 —
    /// which is what a real disk or permission failure deserves.
    #[test]
    fn an_untagged_error_still_becomes_error_io() {
        let raw = io::Error::new(io::ErrorKind::InvalidData, "raw source said no");
        assert!(!is_decode_side(&raw));
        assert!(
            matches!(Error::from(raw), Error::Io(_)),
            "an unmarked InvalidData must stay Io; the marker, not the kind, is what decides"
        );
    }

    /// The funnel itself, exercised the way every real call site exercises it:
    /// a bare `?` on a read, with nothing at the call site that knows about
    /// classification. This is the property the whole module exists to buy.
    #[test]
    fn a_tagged_invalid_data_becomes_corrupt_through_a_bare_question_mark() {
        fn drain(src: &mut dyn Source) -> crate::error::Result<usize> {
            let mut sink = Vec::new();
            // A BARE `?`. No `from_decode_io`, no `map_err`, nothing the
            // author of this function had to remember.
            let n = src.read_to_end(&mut sink)?;
            Ok(n)
        }

        let mut wrapped = DecodeSideSource::wrap(failing(io::ErrorKind::InvalidData));
        match drain(wrapped.as_mut()) {
            Err(Error::Corrupt(msg)) => {
                assert!(msg.contains("malformed"), "decoder's own wording: {msg}");
                assert_eq!(Error::Corrupt(msg).exit_code(), 5);
            }
            other => panic!("expected Corrupt from a marked decode-side read, got {other:?}"),
        }
    }

    /// Finding B's half of the same funnel: `RatioGuardedSource` raises
    /// `OutOfMemory` specifically so `from_decode_io` maps it to
    /// `ResourceLimit` (exit 6). Below a container that conversion never ran,
    /// and a refused expansion bomb reported "stuffr failed".
    #[test]
    fn a_tagged_out_of_memory_becomes_resource_limit_through_a_bare_question_mark() {
        fn drain(src: &mut dyn Source) -> crate::error::Result<usize> {
            let mut sink = Vec::new();
            let n = src.read_to_end(&mut sink)?;
            Ok(n)
        }

        let mut wrapped = DecodeSideSource::wrap(failing(io::ErrorKind::OutOfMemory));
        match drain(wrapped.as_mut()) {
            Err(e @ Error::ResourceLimit(_)) => assert_eq!(e.exit_code(), 6),
            other => panic!("expected ResourceLimit, got {other:?}"),
        }
    }

    /// A kind `from_decode_io` does NOT fold must survive the marker intact.
    /// This is the guarantee that makes the marker safe to apply broadly: it
    /// narrows nothing and widens nothing beyond the two kinds the
    /// classification already owned.
    #[test]
    fn a_marked_environment_failure_is_still_an_io_failure() {
        let mut wrapped = DecodeSideSource::wrap(failing(io::ErrorKind::PermissionDenied));
        let mut sink = Vec::new();
        let err = Error::from(wrapped.read_to_end(&mut sink).unwrap_err());
        assert!(
            matches!(err, Error::Io(_)),
            "a permission failure under a decoder is still stuffr's environment failing: {err:?}"
        );
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn wrapping_passes_bytes_and_caps_through_unchanged() {
        let mut wrapped = DecodeSideSource::wrap(Box::new(ReaderSource::new(io::Cursor::new(
            b"payload".to_vec(),
        ))));
        assert_eq!(wrapped.caps(), SourceCaps::default());
        assert!(wrapped.as_seek().is_none());

        let mut out = Vec::new();
        wrapped.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"payload");
    }
}
