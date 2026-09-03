//! Central resource governance. Nothing in the codebase spawns a thread
//! outside the governor.

pub mod budget;
pub mod cgroup;

pub use budget::{BudgetInputs, DEFAULT_CAP, detect_cpu_budget, resolve_workers};

use std::sync::{Arc, Condvar, Mutex};

/// Floor for the memory budget: below this, even single-threaded work struggles.
pub const MEMORY_FLOOR: u64 = 256 * 1024 * 1024;

/// Combines the readings into the effective budget: 25% of the smallest
/// applicable figure, never below [`MEMORY_FLOOR`].
///
/// `available` is the host or cgroup-visible free memory; `cgroup_v2` and
/// `cgroup_v1` are container limits when present. Taking the minimum is the
/// fix: `/proc/meminfo` inside a container reports the host, so on its own it
/// computes a budget the container cannot honour.
pub fn effective_memory_limit(
    available: u64,
    cgroup_v2: Option<u64>,
    cgroup_v1: Option<u64>,
) -> u64 {
    let mut smallest = available;
    if let Some(v) = cgroup_v2 {
        smallest = smallest.min(v);
    }
    if let Some(v) = cgroup_v1 {
        smallest = smallest.min(v);
    }
    (smallest / 4).max(MEMORY_FLOOR)
}

/// 25% of *available* RAM. Available rather than total, because the distinction
/// is exactly what matters on a host that is already loaded.
///
/// Reads `MemAvailable` from `/proc/meminfo` on Linux, and checks for cgroup
/// limits (v2 and v1). Elsewhere it falls back to the floor, which is
/// conservative by design.
pub fn default_memory_limit() -> u64 {
    #[cfg(target_os = "linux")]
    {
        let available = if let Ok(s) = std::fs::read_to_string("/proc/meminfo") {
            cgroup::parse_meminfo_available(&s)
        } else {
            None
        };

        if let Some(avail) = available {
            // Try v2 at the process's own cgroup first (for nested slices), then the root.
            let v2 = {
                let mut limit = None;
                if let Ok(cgroup_contents) = std::fs::read_to_string("/proc/self/cgroup")
                    && let Some(path) = cgroup::parse_self_cgroup_v2_path(&cgroup_contents)
                {
                    let nested_path = format!("/sys/fs/cgroup{}/memory.max", path);
                    if let Ok(s) = std::fs::read_to_string(&nested_path) {
                        limit = cgroup::parse_cgroup_v2_memory_max(&s);
                    }
                }
                limit.or_else(|| {
                    std::fs::read_to_string("/sys/fs/cgroup/memory.max")
                        .ok()
                        .and_then(|s| cgroup::parse_cgroup_v2_memory_max(&s))
                })
            };

            // v1's hierarchy differs; only check the root. Nested v1 resolution was not
            // required by the brief and might not have a per-cgroup memory limit set.
            let v1 = std::fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes")
                .ok()
                .and_then(|s| cgroup::parse_cgroup_v1_memory_limit(&s));

            return effective_memory_limit(avail, v2, v1);
        }
    }
    MEMORY_FLOOR
}

#[derive(Default)]
struct GovState {
    workers_out: usize,
    bytes_out: u64,
}

/// The single source of parallelism in the process.
///
/// Work units acquire [`LeaseSet`]s rather than being handed a thread count,
/// which is what makes nested parallelism safe: an outer "8 entries at once"
/// and an inner "multi-threaded zstd" both draw from this one pool, so their
/// product can never exceed the budget.
pub struct Governor {
    workers: usize,
    memory_limit: u64,
    state: Mutex<GovState>,
    cv: Condvar,
}

impl Governor {
    pub fn new(workers: usize, memory_limit: u64) -> Arc<Self> {
        Arc::new(Self {
            workers: workers.max(1),
            memory_limit,
            state: Mutex::new(GovState::default()),
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
        self.state
            .lock()
            .expect("governor mutex poisoned")
            .workers_out
    }

    pub fn reserved_bytes(&self) -> u64 {
        self.state
            .lock()
            .expect("governor mutex poisoned")
            .bytes_out
    }

    /// Acquires up to `want` workers, and the memory they need, in one call.
    ///
    /// Grants `min(want, workers_free, memory_free / per_worker_bytes)`,
    /// blocking only while no worker slot is free at all, and never granting
    /// fewer than one — a single over-budget worker beats no progress.
    ///
    /// Granting the floor worker can push the reserved total past
    /// `memory_limit` — by less than one worker's demand *per grant*, but that
    /// bound does not sum across grants. Eight concurrent callers each asking
    /// for one worker will each see `cpu_free > 0`, each floor to 1, and each
    /// charge `per_worker_bytes`, so the reserved total can reach
    /// `workers × per_worker_bytes` regardless of `memory_limit`. The memory
    /// budget therefore bounds *voluntary* parallelism, not a hard ceiling on
    /// reserved bytes; the hard ceiling is the worker count. That
    /// over-commitment is the price of the progress guarantee — a caller that
    /// would otherwise wait forever runs over budget instead of never running.
    ///
    /// **Acquire once.** A unit takes its whole allocation in one call and does
    /// not acquire again while holding. Hold-and-wait is what deadlocks: four
    /// units each holding one lease and each blocking for a second would never
    /// progress. Getting fewer workers than asked is fine, the work runs
    /// slower; blocking for the full request would trade a deadlock for a stall.
    pub fn acquire_many(self: &Arc<Self>, want: usize, per_worker_bytes: u64) -> LeaseSet {
        let want = want.max(1);
        let mut st = self.state.lock().expect("governor mutex poisoned");
        loop {
            let cpu_free = self.workers.saturating_sub(st.workers_out);
            if cpu_free > 0 {
                let mem_free = self.memory_limit.saturating_sub(st.bytes_out);
                // `checked_div` rather than a manual zero-check-then-divide:
                // `per_worker_bytes == 0` means "no memory constraint", i.e. `want`.
                let by_mem = match mem_free.checked_div(per_worker_bytes) {
                    Some(n) => n as usize,
                    None => want,
                };
                // `.max(1)` cannot exceed cpu_free, which is at least 1 here.
                let grant = want.min(cpu_free).min(by_mem).max(1);
                let bytes = per_worker_bytes.saturating_mul(grant as u64);
                st.workers_out += grant;
                st.bytes_out = st.bytes_out.saturating_add(bytes);
                return LeaseSet {
                    gov: Arc::clone(self),
                    workers: grant,
                    bytes,
                };
            }
            st = self.cv.wait(st).expect("governor mutex poisoned");
        }
    }

    /// Blocks until at least one worker is available.
    pub fn acquire(self: &Arc<Self>) -> LeaseSet {
        self.acquire_many(1, 0)
    }

    /// Returns `None` immediately if the pool is full.
    pub fn try_acquire(self: &Arc<Self>) -> Option<LeaseSet> {
        let mut st = self.state.lock().expect("governor mutex poisoned");
        if st.workers_out >= self.workers {
            return None;
        }
        st.workers_out += 1;
        Some(LeaseSet {
            gov: Arc::clone(self),
            workers: 1,
            bytes: 0,
        })
    }

    /// How many workers a codec needing `per_worker_bytes` *could* use.
    ///
    /// A hint for sizing work before committing. It reserves nothing — two
    /// concurrent callers both get the same answer. Call [`Self::acquire_many`]
    /// to actually reserve.
    pub fn workers_for(&self, per_worker_bytes: u64) -> usize {
        if per_worker_bytes == 0 {
            return self.workers;
        }
        let by_memory = (self.memory_limit / per_worker_bytes) as usize;
        by_memory.clamp(1, self.workers)
    }
}

/// A granted allocation of workers and memory. Releases both on drop.
pub struct LeaseSet {
    gov: Arc<Governor>,
    workers: usize,
    bytes: u64,
}

impl LeaseSet {
    pub fn workers(&self) -> usize {
        self.workers
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl Drop for LeaseSet {
    fn drop(&mut self) {
        let mut st = self.gov.state.lock().expect("governor mutex poisoned");
        st.workers_out = st.workers_out.saturating_sub(self.workers);
        st.bytes_out = st.bytes_out.saturating_sub(self.bytes);
        // notify_all rather than notify_one: releasing several workers can
        // satisfy several waiters.
        self.gov.cv.notify_all();
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
        std::thread::sleep(std::time::Duration::from_millis(250));
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
    fn a_small_container_limit_is_clamped_up_to_the_floor() {
        // 512 MiB / 4 = 128 MiB, below MEMORY_FLOOR, so the floor wins.
        let host = 64 * 1024 * 1024 * 1024;
        assert_eq!(
            effective_memory_limit(host, Some(512 * 1024 * 1024), None),
            MEMORY_FLOOR
        );
    }

    #[test]
    fn a_container_limit_beats_a_larger_host_reading() {
        // The behaviour that matters: inside a container, /proc/meminfo reports
        // the HOST, so the host reading alone would give 16 GiB. The container
        // limit must win. Chosen large enough to clear MEMORY_FLOOR, so the
        // floor cannot mask the result the way it does at 512 MiB.
        let host = 64 * 1024 * 1024 * 1024;
        let container = 8 * 1024 * 1024 * 1024;
        assert_eq!(
            effective_memory_limit(host, Some(container), None),
            2 * 1024 * 1024 * 1024,
            "8 GiB container -> 2 GiB budget, not the 16 GiB the host would give"
        );
    }

    #[test]
    fn with_no_cgroup_limit_the_host_reading_stands() {
        let host = 64 * 1024 * 1024 * 1024;
        assert_eq!(
            effective_memory_limit(host, None, None),
            16 * 1024 * 1024 * 1024
        );
    }

    #[test]
    fn the_floor_applies_after_every_other_clamp() {
        assert_eq!(effective_memory_limit(1024, Some(2048), None), MEMORY_FLOOR);
    }

    #[test]
    fn default_memory_limit_is_sane() {
        let m = default_memory_limit();
        assert!(m >= 256 * 1024 * 1024, "floor keeps small hosts usable");
    }

    #[test]
    fn acquire_many_grants_what_is_available_rather_than_blocking_for_all() {
        let g = Governor::new(4, GIB);
        let a = g.acquire_many(3, 0);
        assert_eq!(a.workers(), 3);
        // Only one slot left, so a request for three yields one — not a wait.
        let b = g.acquire_many(3, 0);
        assert_eq!(b.workers(), 1);
        assert_eq!(g.outstanding(), 4);
    }

    #[test]
    fn acquire_many_reserves_memory_so_two_callers_cannot_both_take_the_budget() {
        // The bug this fixes: workers_for is pure arithmetic reserving nothing,
        // so two callers against 2 GiB were each told "you may use 2" and
        // together allocated 2.8 GiB.
        let g = Governor::new(8, 2 * GIB);
        let a = g.acquire_many(2, 700 * 1024 * 1024);
        assert_eq!(a.workers(), 2);

        // Memory pressure reduces the second caller's grant. THIS is the
        // composition property — without reservation it would also have got 2.
        let b = g.acquire_many(2, 700 * 1024 * 1024);
        assert_eq!(b.workers(), 1, "only one worker's memory remains");

        // Reservation is exact: three granted workers, three charges. Note the
        // total EXCEEDS memory_limit, and that is deliberate — b's worker was
        // granted by the floor, which trades over-commitment for a progress
        // guarantee.
        assert_eq!(g.reserved_bytes(), 3 * 700 * 1024 * 1024);

        // Over-commitment is real and deliberate, but bounded: the worker
        // count, not memory_limit, is the hard ceiling.
        assert!(g.reserved_bytes() <= g.memory_limit() + (g.workers() as u64) * 700 * 1024 * 1024);
    }

    #[test]
    fn a_lease_set_releases_both_resources_on_drop() {
        let g = Governor::new(4, GIB);
        {
            let _a = g.acquire_many(4, 100);
            assert_eq!(g.outstanding(), 4);
            assert_eq!(g.reserved_bytes(), 400);
        }
        assert_eq!(g.outstanding(), 0);
        assert_eq!(g.reserved_bytes(), 0);
    }

    #[test]
    fn one_worker_is_granted_even_when_memory_alone_would_allow_none() {
        // A single over-budget worker beats no progress, matching workers_for's
        // existing clamp.
        let g = Governor::new(8, 100);
        let a = g.acquire_many(4, GIB);
        assert_eq!(a.workers(), 1);
    }

    #[test]
    fn acquire_many_blocks_only_while_no_worker_slot_is_free() {
        let g = Governor::new(1, GIB);
        let held = g.acquire_many(1, 0);
        let g2 = Arc::clone(&g);
        let h = std::thread::spawn(move || g2.acquire_many(4, 0).workers());
        std::thread::sleep(std::time::Duration::from_millis(250));
        assert!(!h.is_finished(), "must wait while the pool is empty");
        drop(held);
        assert_eq!(h.join().unwrap(), 1);
    }

    #[test]
    fn single_shot_acquisition_does_not_deadlock_under_nested_demand() {
        // Eight units each wanting three workers from a pool of four. Under
        // repeated single acquire() with hold-and-wait this deadlocks; under
        // single-shot acquisition it completes.
        let g = Governor::new(4, GIB);
        std::thread::scope(|s| {
            for _ in 0..8 {
                let g = Arc::clone(&g);
                s.spawn(move || {
                    let set = g.acquire_many(3, 0);
                    assert!(set.workers() >= 1 && set.workers() <= 4);
                    std::thread::yield_now();
                });
            }
        });
        assert_eq!(g.outstanding(), 0);
    }
}
