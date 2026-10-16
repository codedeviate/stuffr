//! lz4's compressed bytes, case by case: stuffr as `lz4`, `lz4c` against
//! lz4 1.10.0, over the spec's byte-identity catalogue. Filled by Task 4.
//!
//! On the C tier (`lz4-c`) every output is compared byte for byte. On the
//! pure tier the same cases run with `compare_output_bytes: false`: the
//! reference decodes stuffr's output to the input (spec deviation 6).
//!
//! This file is a stub (Task 2): the harness it will use is
//! `compat_harness` (`lz4_dir`, `Roundtrip::Lz4`) and
//! `compat_lz4_harness_selftest.rs` pins that harness against itself.

#[cfg(unix)]
mod compat_harness;
