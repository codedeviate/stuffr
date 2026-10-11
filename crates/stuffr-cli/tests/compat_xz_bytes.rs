//! xz's compressed bytes, case by case: on the C tier (`xz-c`) every output
//! of stuffr as `xz` is compared byte for byte with XZ Utils 5.8.4's; on the
//! pure tier the reference decodes it and the container fields stuffr
//! controls are compared.
//!
//! Stub: Task 6 fills this in, once `compat_xz.rs`'s dispatch (Task 5) lets
//! stuffr run under the xz names.
