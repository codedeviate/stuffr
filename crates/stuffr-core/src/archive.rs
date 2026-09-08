//! The two orthogonal traits, and the entry model they share.

use std::io::{Read, Write};
use std::time::SystemTime;

use crate::error::Result;
use crate::fidelity::FidelityReport;
use crate::format::{CodecCaps, ContainerCaps, FormatId};
use crate::source::Source;

#[derive(Clone, Default)]
pub struct DecodeOpts {
    /// Worker hint. The governor has final say; this is only a request.
    pub threads: Option<usize>,
    /// The shared worker/memory budget. `None` means single-threaded — a codec
    /// parallelises only if handed a governor, never from an ambient global.
    pub governor: Option<std::sync::Arc<crate::Governor>>,
    /// Cap on memory a decoder may ask the allocator for. `None` means
    /// unbounded, which is the library default; the CLI always sets a value.
    ///
    /// This exists because three pure codecs size a dictionary buffer from a
    /// value the *file declares in its own header*, before producing any
    /// output — measured at 69.35 MB peak RSS for a 60-byte `.xz`, and 538 MB
    /// for a crafted 114-byte `.lz` that decoded correctly, so the cost came
    /// purely from the declaration. `--max-ratio` cannot see it: that guard
    /// counts decoded output bytes and the allocation precedes any output.
    ///
    /// Exceeding it is [`crate::Error::ResourceLimit`] (exit 6), never
    /// `Corrupt` (exit 5) — the file is not damaged, this build simply will
    /// not allocate that much.
    pub memory_limit: Option<u64>,
}

impl std::fmt::Debug for DecodeOpts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecodeOpts")
            .field("threads", &self.threads)
            .field("governor", &self.governor.as_ref().map(|_| "Governor"))
            .field("memory_limit", &self.memory_limit)
            .finish()
    }
}

#[derive(Clone, Default)]
pub struct EncodeOpts {
    /// Format-relative compression level. `None` means the format's default.
    pub level: Option<i32>,
    /// Worker hint. The governor has final say; this is only a request.
    pub threads: Option<usize>,
    /// The shared worker/memory budget. `None` means single-threaded — a codec
    /// parallelises only if handed a governor, never from an ambient global.
    pub governor: Option<std::sync::Arc<crate::Governor>>,
}

impl std::fmt::Debug for EncodeOpts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncodeOpts")
            .field("level", &self.level)
            .field("threads", &self.threads)
            .field("governor", &self.governor.as_ref().map(|_| "Governor"))
            .finish()
    }
}

#[derive(Clone, Default)]
pub struct OpenOpts {
    pub password: Option<String>,
    /// The shared worker/memory budget. `None` means single-threaded — a
    /// container parallelises only if handed a governor, never from an
    /// ambient global. Needed so a container with `per_entry_codec` can build
    /// a `DecodeOpts` per entry, carrying the same governor forward.
    pub governor: Option<std::sync::Arc<crate::Governor>>,
}

impl std::fmt::Debug for OpenOpts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenOpts")
            .field("password", &self.password)
            .field("governor", &self.governor.as_ref().map(|_| "Governor"))
            .finish()
    }
}

#[derive(Clone, Default)]
pub struct CreateOpts {
    pub level: Option<i32>,
    /// Codec for entry payloads, for containers with `per_entry_codec`.
    pub entry_codec: Option<FormatId>,
    /// The shared worker/memory budget. `None` means single-threaded — a
    /// container parallelises only if handed a governor, never from an
    /// ambient global. Needed so a container with `per_entry_codec` can build
    /// an `EncodeOpts` per entry, carrying the same governor forward.
    pub governor: Option<std::sync::Arc<crate::Governor>>,
}

impl std::fmt::Debug for CreateOpts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateOpts")
            .field("level", &self.level)
            .field("entry_codec", &self.entry_codec)
            .field("governor", &self.governor.as_ref().map(|_| "Governor"))
            .finish()
    }
}

/// Phase 2 adds `Hardlink`, `CharDevice`, `BlockDevice`, `Fifo` and `Socket`
/// for tar and cpio; `#[non_exhaustive]` keeps that from breaking downstream
/// matches. Struct types deliberately do NOT carry this attribute — see the
/// `#[non_exhaustive]` section of CONTRIBUTING.md.
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
///
/// The reader is deliberately **not** `Send`. It was until Phase 2's first
/// real container, and the bound was unsound to require: `tar::Entry` holds
/// `&Archive<dyn Read>` over a `RefCell`, so it is `!Send` for any reader,
/// and every container built on the `tar` crate would have had to assert
/// `unsafe impl Send` for a property that is false — a lie that becomes UB
/// the day anything actually sends one.
///
/// Nothing needs it. An entry borrows the archive it came from
/// (`ArchiveRead::next_entry(&mut self) -> Entry<'_>`), so sending an entry
/// to another thread would mean sending the archive with it, and no caller in
/// this tree does either: entries are read on the thread that asked for
/// them. Dropping the bound is strictly more permissive, so a container whose
/// reader IS `Send` is unaffected.
pub struct Entry<'a> {
    meta: EntryMeta,
    reader: Box<dyn Read + 'a>,
}

impl<'a> Entry<'a> {
    pub fn new(meta: EntryMeta, reader: Box<dyn Read + 'a>) -> Self {
        Self { meta, reader }
    }

    pub fn meta(&self) -> &EntryMeta {
        &self.meta
    }

    pub fn reader(&mut self) -> &mut (dyn Read + 'a) {
        &mut *self.reader
    }
}

/// Manual impl: `reader` is `Box<dyn Read>`, which cannot derive `Debug`.
/// Needed so `Result<Entry<'_>, Error>::unwrap_err()` type-checks in tests
/// (`unwrap_err` requires the `Ok` side to be `Debug`).
impl std::fmt::Debug for Entry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("meta", &self.meta)
            .finish_non_exhaustive()
    }
}

/// A writer that needs an explicit, fallible completion step (trailers, CRCs).
///
/// `finish` must flush the underlying writer before returning, once every
/// trailer byte has been written to it. `Codec::encoder` takes the
/// destination `Box<dyn Write + Send>` by value, so once a caller has handed
/// it over, `finish` is the only code left holding it — the caller has no
/// remaining handle to flush afterwards. Skipping this is silent on an
/// unbuffered destination (a plain `File`) but loses the tail of the stream
/// on a buffered one: notably stdout's `LineWriter`, which only auto-flushes
/// on `\n` and may see none in a long run of binary output.
pub trait Sink: Write + Send {
    fn finish(self: Box<Self>) -> Result<()>;
}

/// A byte-stream transform. Knows nothing about files, names, or entries.
pub trait Codec: Send + Sync {
    fn id(&self) -> FormatId;
    fn caps(&self) -> CodecCaps;
    /// Validates encode options without touching the filesystem.
    ///
    /// `ops` calls this before opening any destination, so a rejected option
    /// costs nothing — no temp file created, no existing file disturbed. The
    /// default accepts everything, for codecs with no options to reject.
    ///
    /// With one codec this looks like ceremony. With nine, each carrying its
    /// own level range, "validate before touching the filesystem" has to be a
    /// contract rather than a habit: in Phase 1b an invalid level created and
    /// then deleted a file for nothing.
    fn check_encode_opts(&self, _o: &EncodeOpts) -> Result<()> {
        Ok(())
    }
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
    /// Opens an archive from a ladder-resolved source.
    ///
    /// Takes the whole [`crate::Resolved`] rather than just its source so the
    /// container knows which rung it was given — which is what makes
    /// `Rung::Degraded` implementable — and so it can seed its fidelity report
    /// from the ladder's rather than re-deriving the same facts.
    fn open(&self, resolved: crate::ladder::Resolved, o: &OpenOpts)
    -> Result<Box<dyn ArchiveRead>>;
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
