//! A [`Source`] over a borrowed, possibly non-`Send` reader.

use std::io::Read;

use super::{DecodeSideSource, SeekRead, Source, SourceCaps};
use crate::archive::{Codec, DecodeOpts};
use crate::error::{Error, Result};

/// A forward-only source over any reader that lives for `'a`.
///
/// What [`super::ReaderSource`] is for an owned, `Send` reader, this is for a
/// borrowed one: an archive member's reader (`Entry::reader`), a `&mut &[u8]`,
/// a `&mut File`. Not seekable and length unknown, like `ReaderSource`, even
/// over a reader that could seek: a decoder over it is told the truth about
/// what it may rely on.
pub struct BorrowedSource<'a> {
    inner: Box<dyn Read + 'a>,
}

impl<'a> BorrowedSource<'a> {
    pub fn new<R: Read + 'a>(r: R) -> Self {
        Self { inner: Box::new(r) }
    }
}

impl Read for BorrowedSource<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Source for BorrowedSource<'_> {
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

/// Decodes `r` with `codec`, borrowing `r` for as long as the decoder lives.
///
/// The one-call route for a caller holding a codec and a reader — notably an
/// archive member's reader, which is neither `'static` nor `Send`. Needs no
/// registry. A codec that cannot decode is refused with the same
/// [`Error::CapabilityUnavailable`] `Registry::require_decoder` raises (exit 3).
///
/// Errors come back already classified, as on every other decode path: an
/// `io::Error` from the decoder's construction is folded through
/// [`Error::from_decode_io`], and the returned source is a
/// [`DecodeSideSource`], so a malformed member read through it and converted
/// with a bare `?` is the same [`Error::Corrupt`] (exit 5) as anywhere else,
/// while a failure of `r` itself (a disk, a permission) stays [`Error::Io`].
pub fn decode_reader<'a, R: Read + 'a>(
    codec: &dyn Codec,
    r: R,
    o: &DecodeOpts,
) -> Result<Box<dyn Source + 'a>> {
    if !codec.caps().decode {
        return Err(Error::CapabilityUnavailable {
            format: codec.id(),
            available: "written",
            requested: "read",
        });
    }
    let decoded = codec
        .decoder(Box::new(BorrowedSource::new(r)), o)
        .map_err(|e| match e {
            Error::Io(io_err) => Error::from_decode_io(io_err),
            other => other,
        })?;
    Ok(DecodeSideSource::wrap(decoded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::MockCodec;

    #[test]
    fn a_borrowed_source_reads_a_local_borrow_and_never_claims_seek() {
        let bytes = b"hello".to_vec();
        let mut cursor = std::io::Cursor::new(&bytes[..]);
        let mut s = BorrowedSource::new(&mut cursor);
        assert!(
            !s.caps().seekable,
            "a Cursor can seek; the source must not say so"
        );
        assert_eq!(s.caps().len, None);
        assert!(s.as_seek().is_none());
        let mut out = Vec::new();
        s.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"hello");
    }

    #[test]
    fn decode_reader_decodes_through_a_non_send_borrow() {
        // `Rc` makes the reader `!Send`; the borrow makes it non-`'static`.
        struct NotSend<'b>(std::marker::PhantomData<std::rc::Rc<()>>, &'b [u8]);
        impl Read for NotSend<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.1.read(buf)
            }
        }
        let encoded: Vec<u8> = b"abc".iter().map(|b| b ^ 0xFF).collect();
        let mut out = Vec::new();
        decode_reader(
            &MockCodec,
            NotSend(std::marker::PhantomData, &encoded),
            &DecodeOpts::default(),
        )
        .unwrap()
        .read_to_end(&mut out)
        .unwrap();
        assert_eq!(out, b"abc");
    }
}
