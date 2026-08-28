//! Adapter presenting a plain reader as a non-seekable [`Source`].

use std::io::Read;

use super::{SeekRead, Source, SourceCaps};

/// Wraps a plain reader as a non-seekable [`Source`].
///
/// Most codecs decode forward-only and have no index to expose, so this is what
/// they return from [`crate::Codec::decoder`]. A codec that *does* carry a seek
/// table — seekable zstd, an xz block index — returns something genuinely
/// seekable instead, which is the whole reason `decoder` returns a `Source`
/// rather than a bare reader: the capability survives the layer boundary and
/// the ladder can run between codec and container.
pub struct StreamOnly<R>(R);

impl<R: Read + Send> StreamOnly<R> {
    pub fn new(inner: R) -> Self {
        Self(inner)
    }
}

impl<R: Read + Send> Read for StreamOnly<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl<R: Read + Send> Source for StreamOnly<R> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn stream_only_passes_bytes_through_unchanged() {
        let mut s = StreamOnly::new(std::io::Cursor::new(b"payload".to_vec()));
        let mut out = Vec::new();
        s.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"payload");
    }

    #[test]
    fn stream_only_reports_no_seek_even_over_a_seekable_reader() {
        // A Cursor is seekable, but a codec decoding forward-only has no index
        // to expose, so its output must not claim random access it cannot back.
        let mut s = StreamOnly::new(std::io::Cursor::new(b"payload".to_vec()));
        assert!(!s.caps().seekable);
        assert_eq!(s.caps().len, None);
        assert!(s.as_seek().is_none());
    }
}
