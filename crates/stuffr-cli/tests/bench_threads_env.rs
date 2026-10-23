//! Ruling B7, guarded in a process of its own: bench takes threads only
//! from `--threads`, never from `STUFFR_THREADS`. The variable has to be
//! set for the guard to mean anything, and setting it is only sound where
//! nothing else reads the environment, so this binary holds one test.

use stuffr::ops::{CompressOpts, resolved_budget};
use stuffr_cli::bench::measure::{Mode, OutputBound, Plan, governor_for};

#[test]
fn bench_ignores_stuffr_threads() {
    // SAFETY: this binary holds this single test, so no other thread reads
    // or writes the environment while it is changed.
    unsafe { std::env::set_var("STUFFR_THREADS", "4") };
    let memory_limit = 1 << 30;

    // The variable is live in this process: `pack` without `--threads`
    // would go multi-threaded.
    let pack = resolved_budget(&CompressOpts {
        threads: None,
        memory_limit: Some(memory_limit),
        ..Default::default()
    });
    assert!(
        pack.is_some(),
        "STUFFR_THREADS=4 did not reach resolved_budget"
    );

    let plan = Plan {
        mode: Mode::OneStream,
        repeat: 1,
        threads: None,
        memory_limit,
        output_bound: OutputBound::Standard,
    };
    assert!(
        governor_for(&plan).is_none(),
        "bench without --threads followed STUFFR_THREADS"
    );
}
