#![no_main]
use libfuzzer_sys::fuzz_target;

// Deleted in Task 3. Exists only to prove the toolchain builds and runs
// before any invariant depends on it.
fuzz_target!(|data: &[u8]| {
    let _ = data.len();
});
