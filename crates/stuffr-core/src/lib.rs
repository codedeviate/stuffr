//! Core abstractions for the `stf` toolkit.
//!
//! This crate deliberately depends on **no** compression format crate. That
//! constraint is what makes the stream ladder and the thread governor testable
//! against mock formats, with no C toolchain and no real archives.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
