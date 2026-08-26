//! Facade crate: re-exports [`stuffr_core`] and the format implementations, and
//! owns the feature taxonomy. This is the crate downstream users add.

pub use stuffr_core as core;
pub use stuffr_core::VERSION;
