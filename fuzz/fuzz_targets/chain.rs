#![no_main]
use libfuzzer_sys::fuzz_target;
use stuffr::entries;
use stuffr::ops::{self, Input};
use stuffr_core::DEFAULT_MAX_RATIO;
use stuffr_core::testing::check_error_is_classified;

fuzz_target!(|data: &[u8]| {
    // No selector: arbitrary bytes go straight at format detection itself, so
    // `resolve_chain_deep` and the container dispatch inside `entries::list`
    // are exercised on every input — not just ones already shaped as one
    // registered format's payload. This is the layer Phase 2c's silent
    // wrong-format bug lived in.
    //
    // `ops::inspect` and `entries::list` both take `ops::Input`, which is
    // `Path(PathBuf) | Stdin` — there is no bytes variant — so the payload is
    // written to a temp file per iteration. Same throughput cost
    // `container.rs`'s seekable branch accepts, for the same reason: the
    // invariant must be reachable, and only a real (seekable) file lets
    // detection and the container open take the same path a real caller's
    // file input does.
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("input");
    std::fs::write(&path, data).expect("write temp input");

    if let Err(e) = ops::inspect(Input::Path(path.clone())) {
        check_error_is_classified(&e).expect("inspect error classification");
    }

    // Bounded for the same reason `codec.rs` bounds `DecodeOpts`: an
    // unbounded pre-flight allocation in a pure codec must not turn every
    // subsequent run into an OOM instead of a finding.
    let memory_limit = Some(64 * 1024 * 1024);
    if let Err(e) = entries::list(Input::Path(path), DEFAULT_MAX_RATIO, memory_limit) {
        check_error_is_classified(&e).expect("list error classification");
    }
});
