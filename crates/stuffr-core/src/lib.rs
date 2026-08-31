//! Core abstractions for the `stf` toolkit.
//!
//! This crate deliberately depends on **no** compression format crate. That
//! constraint is what makes the stream ladder and the thread governor testable
//! against mock formats, with no C toolchain and no real archives.

pub mod archive;
#[cfg(feature = "testing")]
pub mod conformance;
pub mod error;
pub mod fidelity;
pub mod format;
pub mod governor;
pub mod ladder;
pub mod probe;
pub mod registry;
pub mod source;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use archive::{
    ArchiveRead, ArchiveWrite, Codec, Container, CreateOpts, DecodeOpts, EncodeOpts, Entry,
    EntryKind, EntryMeta, OpenOpts, Sink,
};
pub use error::{Error, Result};
pub use fidelity::{Fidelity, FidelityReport, MetaFields, Rung};
pub use format::{
    CodecCaps, ContainerCaps, CorruptionDetection, FormatId, FormatKind, FormatMeta, MagicRule,
};
pub use governor::{BudgetInputs, Governor, LeaseSet, default_memory_limit, resolve_workers};
pub use ladder::{Resolved, StreamPolicy, resolve};
pub use probe::{Chain, PROBE_LEN, probe, resolve_chain};
pub use registry::{FormatRow, Registry};
pub use source::{
    Counting, CountingWriter, DEFAULT_MAX_RATIO, FileSource, PeekSource, RATIO_FLOOR, RatioGuard,
    ReaderSource, SeekRead, Source, SourceCaps, SpillPolicy, SpillSource, StreamOnly,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
