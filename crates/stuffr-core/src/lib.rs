//! Core abstractions for the `stf` toolkit.
//!
//! This crate deliberately depends on **no** compression format crate. That
//! constraint is what makes the stream ladder and the thread governor testable
//! against mock formats, with no C toolchain and no real archives.

pub mod error;
pub mod fidelity;
pub mod format;
pub mod source;

pub use error::{Error, Result};
pub use fidelity::{Fidelity, FidelityReport, MetaFields, Rung};
pub use format::{CodecCaps, ContainerCaps, FormatId, FormatKind, FormatMeta, MagicRule};
pub use source::{
    FileSource, PeekSource, ReaderSource, Source, SourceCaps, SpillPolicy, SpillSource,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
