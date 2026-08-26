use std::io::Read;

use super::{SeekRead, Source, SourceCaps};
use crate::error::Result;

/// A forward-only source. Models "arrived on a pipe" — it erases any seek
/// ability the underlying reader might happen to have, so tests can exercise
/// the non-seekable path deterministically.
pub struct ReaderSource {
    inner: Box<dyn Read + Send>,
}

impl ReaderSource {
    pub fn new<R: Read + Send + 'static>(inner: R) -> Self {
        Self {
            inner: Box::new(inner),
        }
    }
}

impl Read for ReaderSource {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Source for ReaderSource {
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

/// Wraps a source so a bounded prefix can be inspected and then replayed.
///
/// This is what makes magic-byte detection non-destructive on a pipe: the probe
/// reads the prefix, matches against it, and the consumer still sees byte zero.
pub struct PeekSource {
    inner: Box<dyn Source>,
    prefix: Vec<u8>,
    pos: usize,
}

impl PeekSource {
    /// Reads up to `n` bytes into the replay buffer. A short read is fine — the
    /// input may legitimately be smaller than the probe window.
    pub fn fill(mut inner: Box<dyn Source>, n: usize) -> Result<Self> {
        let mut prefix = vec![0u8; n];
        let mut filled = 0;
        while filled < n {
            match inner.read(&mut prefix[filled..])? {
                0 => break,
                k => filled += k,
            }
        }
        prefix.truncate(filled);
        Ok(Self {
            inner,
            prefix,
            pos: 0,
        })
    }

    pub fn prefix(&self) -> &[u8] {
        &self.prefix
    }
}

impl Read for PeekSource {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.prefix[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        self.inner.read(buf)
    }
}

impl Source for PeekSource {
    fn caps(&self) -> SourceCaps {
        // Buffering a prefix does not create seek ability.
        SourceCaps {
            seekable: false,
            len: None,
        }
    }

    fn as_seek(&mut self) -> Option<&mut dyn SeekRead> {
        None
    }
}
