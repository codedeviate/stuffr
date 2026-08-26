//! Core abstractions for the `stf` toolkit.
//!
//! This crate deliberately depends on **no** compression format crate. That
//! constraint is what makes the stream ladder and the thread governor testable
//! against mock formats, with no C toolchain and no real archives.

pub mod archive;
pub mod error;
pub mod fidelity;
pub mod format;
pub mod ladder;
pub mod source;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use archive::{
    ArchiveRead, ArchiveWrite, Codec, Container, CreateOpts, DecodeOpts, EncodeOpts, Entry,
    EntryKind, EntryMeta, OpenOpts, Sink,
};
pub use error::{Error, Result};
pub use fidelity::{Fidelity, FidelityReport, MetaFields, Rung};
pub use format::{CodecCaps, ContainerCaps, FormatId, FormatKind, FormatMeta, MagicRule};
pub use ladder::{Resolved, StreamPolicy, resolve};
pub use source::{
    FileSource, PeekSource, ReaderSource, Source, SourceCaps, SpillPolicy, SpillSource,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
