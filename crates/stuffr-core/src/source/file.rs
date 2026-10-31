use std::fs::File;
use std::io::Read;
use std::path::Path;

use super::{GuardedSeek, SeekRead, Source, SourceCaps};
use crate::error::Result;

/// A source backed by an opened file. The Exact rung when it is a regular
/// file (or, on unix, a block device): those seek.
///
/// A path can name something else — a FIFO, a character device, a socket —
/// and `File::open` succeeds on all of them, but their first `lseek` fails
/// with `ESPIPE`. Claiming `seekable` for one sent a container straight to
/// its seek path, and `stuffr unpack fifo -C dir` answered "Illegal seek" at
/// exit 1 (the 2026-10-31 audit follow-ups). Such a file is now a stream,
/// exactly as standard input is: no length, no `as_seek`, so the stream
/// ladder reads it forward or spills it.
pub struct FileSource {
    /// Wrapped, never bare: a container seeks to positions the ARCHIVE
    /// declares, and a `u64` above `i64::MAX` reaches `lseek(2)` as a
    /// negative offset and comes back as an unclassified `EINVAL`. See
    /// [`GuardedSeek`]'s module doc.
    file: GuardedSeek<File>,
    /// The content's length: a regular file's size. `None` for anything
    /// else, whose metadata size is no content length (a FIFO says 0, and so
    /// does a block device on macOS).
    len: Option<u64>,
    /// Whether `file` can seek: a regular file or a block device.
    seekable: bool,
}

impl FileSource {
    pub fn open(path: &Path) -> Result<Self> {
        Self::from_file(File::open(path)?)
    }

    pub fn from_file(file: File) -> Result<Self> {
        let meta = file.metadata()?;
        let seekable = seeks(&meta.file_type());
        Ok(Self {
            file: GuardedSeek::new(file),
            len: meta.is_file().then_some(meta.len()),
            seekable,
        })
    }
}

/// Whether a file of this type seeks: a regular file, or a block device on
/// unix. A FIFO, character device or socket does not.
fn seeks(kind: &std::fs::FileType) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        kind.is_file() || kind.is_block_device()
    }
    #[cfg(not(unix))]
    {
        kind.is_file()
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
            seekable: self.seekable,
            len: self.len,
        }
    }

    fn as_seek(&mut self) -> Option<&mut dyn SeekRead> {
        if self.seekable {
            Some(&mut self.file)
        } else {
            None
        }
    }
}
