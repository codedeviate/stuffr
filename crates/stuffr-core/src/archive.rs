//! The two orthogonal traits, and the entry model they share.

use std::io::{Read, Write};
use std::time::SystemTime;

use crate::error::Result;
use crate::fidelity::FidelityReport;
use crate::format::{CodecCaps, ContainerCaps, FormatId};
use crate::source::Source;

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct DecodeOpts {
    /// Worker hint. The governor has final say; this is only a request.
    pub threads: Option<usize>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct EncodeOpts {
    /// Format-relative compression level. `None` means the format's default.
    pub level: Option<i32>,
    pub threads: Option<usize>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct OpenOpts {
    pub password: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct CreateOpts {
    pub level: Option<i32>,
    /// Codec for entry payloads, for containers with `per_entry_codec`.
    pub entry_codec: Option<FormatId>,
}

/// Phase 2 adds `Hardlink`, `CharDevice`, `BlockDevice`, `Fifo` and `Socket`
/// for tar and cpio; `#[non_exhaustive]` keeps that from breaking downstream
/// matches. Struct types deliberately do NOT carry this attribute — see
/// CONTRIBUTING.md.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub enum EntryKind {
    #[default]
    File,
    Dir,
    Symlink {
        target: String,
    },
    Other,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct EntryMeta {
    pub name: String,
    pub size: Option<u64>,
    pub compressed_size: Option<u64>,
    pub mtime: Option<SystemTime>,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub kind: EntryKind,
    /// Codec of this entry's payload, for `per_entry_codec` containers.
    pub codec: Option<FormatId>,
}

impl EntryMeta {
    pub fn file(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }
}

/// One entry, borrowed from the archive it came from.
pub struct Entry<'a> {
    meta: EntryMeta,
    reader: Box<dyn Read + Send + 'a>,
}

impl<'a> Entry<'a> {
    pub fn new(meta: EntryMeta, reader: Box<dyn Read + Send + 'a>) -> Self {
        Self { meta, reader }
    }

    pub fn meta(&self) -> &EntryMeta {
        &self.meta
    }

    pub fn reader(&mut self) -> &mut (dyn Read + Send + 'a) {
        &mut *self.reader
    }
}

/// Manual impl: `reader` is `Box<dyn Read + Send>`, which cannot derive
/// `Debug`. Needed so `Result<Entry<'_>, Error>::unwrap_err()` type-checks in
/// tests (`unwrap_err` requires the `Ok` side to be `Debug`).
impl std::fmt::Debug for Entry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("meta", &self.meta)
            .finish_non_exhaustive()
    }
}

/// A writer that needs an explicit, fallible completion step (trailers, CRCs).
pub trait Sink: Write + Send {
    fn finish(self: Box<Self>) -> Result<()>;
}

/// A byte-stream transform. Knows nothing about files, names, or entries.
pub trait Codec: Send + Sync {
    fn id(&self) -> FormatId;
    fn caps(&self) -> CodecCaps;
    /// Decodes `src`. Returns a [`Source`] rather than a bare reader so a codec
    /// carrying a frame index can advertise seekability to the layer above;
    /// forward-only codecs wrap their reader in [`crate::StreamOnly`].
    fn decoder(&self, src: Box<dyn Source>, o: &DecodeOpts) -> Result<Box<dyn Source>>;
    fn encoder(&self, dst: Box<dyn Write + Send>, o: &EncodeOpts) -> Result<Box<dyn Sink>>;
}

/// A structure of entries. May invoke codecs internally.
pub trait Container: Send + Sync {
    fn id(&self) -> FormatId;
    fn caps(&self) -> ContainerCaps;
    fn open(&self, src: Box<dyn Source>, o: &OpenOpts) -> Result<Box<dyn ArchiveRead>>;
    fn create(&self, dst: Box<dyn Write + Send>, o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>>;
}

pub trait ArchiveRead {
    /// Forward iteration. Available for every container on every input — this
    /// is the streaming path, and the reason `Entry` borrows.
    fn next_entry(&mut self) -> Result<Option<Entry<'_>>>;

    /// Random access. `Err(NotSeekable)` when the ladder could not supply seek.
    fn by_index(&mut self, index: usize) -> Result<Entry<'_>>;

    fn fidelity(&self) -> &FidelityReport;
}

pub trait ArchiveWrite {
    fn add(&mut self, meta: &EntryMeta, data: &mut dyn Read) -> Result<()>;
    fn finish(self: Box<Self>) -> Result<()>;
}
