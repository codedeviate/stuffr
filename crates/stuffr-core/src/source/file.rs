use std::fs::File;
use std::io::Read;
use std::path::Path;

use super::{GuardedSeek, SeekRead, Source, SourceCaps};
use crate::error::Result;

/// A seekable source backed by a real file. The Exact rung.
pub struct FileSource {
    /// Wrapped, never bare: a container seeks to positions the ARCHIVE
    /// declares, and a `u64` above `i64::MAX` reaches `lseek(2)` as a
    /// negative offset and comes back as an unclassified `EINVAL`. See
    /// [`GuardedSeek`]'s module doc.
    file: GuardedSeek<File>,
    len: u64,
}

impl FileSource {
    pub fn open(path: &Path) -> Result<Self> {
        Self::from_file(File::open(path)?)
    }

    pub fn from_file(file: File) -> Result<Self> {
        let len = file.metadata()?.len();
        Ok(Self {
            file: GuardedSeek::new(file),
            len,
        })
    }
}

impl Read for FileSource {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
}

impl Source for FileSource {
    fn caps(&self) -> SourceCaps {
        SourceCaps {
            seekable: true,
            len: Some(self.len),
        }
    }

    fn as_seek(&mut self) -> Option<&mut dyn SeekRead> {
        Some(&mut self.file)
    }
}
