//! Central resource governance. Nothing in the codebase spawns a thread
//! outside the governor.

pub mod budget;

pub use budget::{BudgetInputs, DEFAULT_CAP, detect_cpu_budget, resolve_workers};

use std::sync::{Arc, Condvar, Mutex};

/// Floor for the memory budget: below this, even single-threaded work struggles.
pub const MEMORY_FLOOR: u64 = 256 * 1024 * 1024;

/// 25% of *available* RAM. Available rather than total, because the distinction
/// is exactly what matters on a host that is already loaded.
///
/// Reads `MemAvailable` from `/proc/meminfo` on Linux; elsewhere it falls back
/// to the floor, which is conservative by design.
pub fn default_memory_limit() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/meminfo") {
            for line in s.lines() {
                if let Some(rest) = line.strip_prefix("MemAvailable:") {
                    if let Some(kb) = rest.split_whitespace().next() {
                        if let Ok(kb) = kb.parse::<u64>() {
                            return ((kb * 1024) / 4).max(MEMORY_FLOOR);
                        }
                    }
                }
            }
        }
    }
    MEMORY_FLOOR
}

/// The single source of parallelism in the process.
///
/// Work units acquire [`Lease`]s rather than being handed a thread count, which
/// is what makes nested parallelism safe: an outer "8 entries at once" and an
/// inner "multi-threaded zstd" both draw from this one pool, so their product
/// can never exceed the budget.
pub struct Governor {
    workers: usize,
    memory_limit: u64,
    state: Mutex<usize>,
    cv: Condvar,
}

impl Governor {
    pub fn new(workers: usize, memory_limit: u64) -> Arc<Self> {
        Arc::new(Self {
            workers: workers.max(1),
            memory_limit,
            state: Mutex::new(0),
            cv: Condvar::new(),
        })
    }

    pub fn from_inputs(inputs: &BudgetInputs, memory_limit: u64) -> Arc<Self> {
        Self::new(resolve_workers(inputs), memory_limit)
    }

    pub fn workers(&self) -> usize {
        self.workers
    }

    pub fn memory_limit(&self) -> u64 {
        self.memory_limit
    }

    pub fn outstanding(&self) -> usize {
        *self.state.lock().expect("governor mutex poisoned")
    }

    /// Blocks until a lease is available.
    pub fn acquire(self: &Arc<Self>) -> Lease {
        let mut n = self.state.lock().expect("governor mutex poisoned");
        while *n >= self.workers {
            n = self.cv.wait(n).expect("governor mutex poisoned");
        }
        *n += 1;
        Lease {
            gov: Arc::clone(self),
        }
    }

    /// Returns `None` immediately if the pool is full.
    pub fn try_acquire(self: &Arc<Self>) -> Option<Lease> {
        let mut n = self.state.lock().expect("governor mutex poisoned");
        if *n >= self.workers {
            return None;
        }
        *n += 1;
        Some(Lease {
            gov: Arc::clone(self),
        })
    }

    /// How many workers a codec needing `per_worker_bytes` may use.
    ///
    /// Fewer, slower threads beat the OOM killer: multi-threaded xz at `-9`
    /// wants ~700 MiB per worker, and sixteen of those will kill a modest
    /// server long before CPU becomes the constraint.
    pub fn workers_for(&self, per_worker_bytes: u64) -> usize {
        if per_worker_bytes == 0 {
            return self.workers;
        }
        let by_memory = (self.memory_limit / per_worker_bytes) as usize;
        by_memory.clamp(1, self.workers)
    }
}

/// A permit to run one unit of work. Returns itself to the pool on drop.
pub struct Lease {
    gov: Arc<Governor>,
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut n = self.gov.state.lock().expect("governor mutex poisoned");
        *n = n.saturating_sub(1);
        self.gov.cv.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const GIB: u64 = 1024 * 1024 * 1024;

    #[test]
    fn leases_are_bounded_by_the_worker_count() {
        let g = Governor::new(2, GIB);
        let _a = g.try_acquire().expect("first lease");
        let _b = g.try_acquire().expect("second lease");
        assert!(g.try_acquire().is_none(), "third lease must not be issued");
        assert_eq!(g.outstanding(), 2);
    }

    #[test]
    fn dropping_a_lease_returns_it_to_the_pool() {
        let g = Governor::new(1, GIB);
        {
            let _a = g.try_acquire().expect("lease");
            assert!(g.try_acquire().is_none());
        }
        assert_eq!(g.outstanding(), 0);
        assert!(
            g.try_acquire().is_some(),
            "lease must be reusable after drop"
        );
    }

    #[test]
    fn nested_parallelism_cannot_exceed_the_budget() {
        // The N-squared guard. Outer "entries" and inner "codec threads" both
        // draw from one pool, so the product can never exceed `workers`.
        let g = Governor::new(4, GIB);
        let peak = Arc::new(AtomicUsize::new(0));
        let live = Arc::new(AtomicUsize::new(0));

        std::thread::scope(|s| {
            for _outer in 0..8 {
                let (g, peak, live) = (Arc::clone(&g), Arc::clone(&peak), Arc::clone(&live));
                s.spawn(move || {
                    for _inner in 0..8 {
                        let _lease = g.acquire();
                        let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        std::thread::yield_now();
                        live.fetch_sub(1, Ordering::SeqCst);
                    }
                });
            }
        });

        assert!(
            peak.load(Ordering::SeqCst) <= 4,
            "peak was {}",
            peak.load(Ordering::SeqCst)
        );
        assert!(peak.load(Ordering::SeqCst) >= 1);
        assert_eq!(g.outstanding(), 0, "every lease must be returned");
    }

    #[test]
    fn acquire_blocks_until_a_lease_frees_rather_than_failing() {
        let g = Governor::new(1, GIB);
        let held = g.try_acquire().expect("lease");
        let g2 = Arc::clone(&g);
        let h = std::thread::spawn(move || {
            let _l = g2.acquire();
            true
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(
            !h.is_finished(),
            "acquire must block while the pool is full"
        );
        drop(held);
        assert!(h.join().unwrap());
    }

    #[test]
    fn memory_clamp_reduces_workers_rather_than_oom_ing() {
        // xz -9 at ~700 MiB per worker against a 2 GiB limit: 2 workers, not 8.
        let g = Governor::new(8, 2 * GIB);
        assert_eq!(g.workers_for(700 * 1024 * 1024), 2);
    }

    #[test]
    fn memory_clamp_never_reports_fewer_than_one_worker() {
        // Better to run one over-budget worker than to make no progress.
        let g = Governor::new(8, 100);
        assert_eq!(g.workers_for(GIB), 1);
    }

    #[test]
    fn zero_demand_codecs_get_the_full_budget() {
        let g = Governor::new(8, GIB);
        assert_eq!(g.workers_for(0), 8);
    }

    #[test]
    fn memory_clamp_never_exceeds_the_cpu_budget() {
        let g = Governor::new(2, 1024 * GIB);
        assert_eq!(
            g.workers_for(1024),
            2,
            "plenty of RAM does not buy more CPUs"
        );
    }

    #[test]
    fn from_inputs_applies_the_conservative_default() {
        let i = BudgetInputs {
            detected: 16,
            ..Default::default()
        };
        assert_eq!(Governor::from_inputs(&i, GIB).workers(), 8);
    }

    #[test]
    fn default_memory_limit_is_sane() {
        let m = default_memory_limit();
        assert!(m >= 256 * 1024 * 1024, "floor keeps small hosts usable");
    }
}
