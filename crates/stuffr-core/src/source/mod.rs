//! Input abstraction. A container never opens a file — it asks a `Source` what
//! it can do, and the ladder (see [`crate::ladder`]) supplies the best rung.

mod file;
pub mod limit;
mod reader;
pub mod spill;
pub mod stream_only;

pub use file::FileSource;
pub use limit::{Counting, CountingWriter, DEFAULT_MAX_RATIO, RATIO_FLOOR, RatioGuard};
pub use reader::{PeekSource, ReaderSource};
pub use spill::{SpillPolicy, SpillSource};
pub use stream_only::StreamOnly;

use std::io::{Read, Seek};

/// Blanket-implemented marker so `&mut dyn SeekRead` is usable as a trait object.
pub trait SeekRead: Read + Seek + Send {}
impl<T: Read + Seek + Send> SeekRead for T {}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct SourceCaps {
    pub seekable: bool,
    /// Total length if known. `None` for pipes.
    pub len: Option<u64>,
}

/// An input stream that reports its own capabilities.
pub trait Source: Read + Send {
    fn caps(&self) -> SourceCaps;

    /// Returns a seekable view, or `None` if this source cannot seek.
    fn as_seek(&mut self) -> Option<&mut dyn SeekRead>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn reader_source_is_not_seekable_and_has_unknown_length() {
        let mut s = ReaderSource::new(std::io::Cursor::new(b"hello".to_vec()));
        // A Cursor *is* seekable, but ReaderSource deliberately erases that:
        // it models "arrived on a pipe". Use FileSource for real seek.
        assert!(!s.caps().seekable);
        assert_eq!(s.caps().len, None);
        assert!(s.as_seek().is_none());

        let mut buf = Vec::new();
        s.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"hello");
    }

    #[test]
    fn file_source_is_seekable_and_knows_its_length() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut f, b"0123456789").unwrap();
        let mut s = FileSource::open(f.path()).unwrap();

        assert!(s.caps().seekable);
        assert_eq!(s.caps().len, Some(10));

        let seek = s.as_seek().expect("file must expose seek");
        seek.seek(std::io::SeekFrom::Start(4)).unwrap();
        let mut buf = [0u8; 3];
        seek.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"456");
    }

    #[test]
    fn peek_source_replays_the_prefix_it_consumed() {
        // This is the property the probe depends on: peeking must not consume.
        let inner: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(
            b"MAGIC-then-payload".to_vec(),
        )));
        let mut p = PeekSource::fill(inner, 5).unwrap();
        assert_eq!(p.prefix(), b"MAGIC");

        let mut all = Vec::new();
        p.read_to_end(&mut all).unwrap();
        assert_eq!(all, b"MAGIC-then-payload");
    }

    #[test]
    fn peek_source_tolerates_input_shorter_than_the_request() {
        let inner: Box<dyn Source> =
            Box::new(ReaderSource::new(std::io::Cursor::new(b"ab".to_vec())));
        let mut p = PeekSource::fill(inner, 4096).unwrap();
        assert_eq!(p.prefix(), b"ab");

        let mut all = Vec::new();
        p.read_to_end(&mut all).unwrap();
        assert_eq!(all, b"ab");
    }
}
