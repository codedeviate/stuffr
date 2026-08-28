//! Thread budget resolution.
//!
//! The cgroup readers are split into pure functions over file *contents* so the
//! precedence and arithmetic are testable on any platform, including one with
//! no `/sys/fs/cgroup` at all.

/// Default cap on the auto budget. Protects a 128-core shared host from a
/// surprise 64-worker job.
pub const DEFAULT_CAP: usize = 8;

/// Parses cgroup v2 `cpu.max`, e.g. `"200000 100000"` → 2 CPUs.
/// `"max <period>"` means unlimited.
pub fn parse_cgroup_v2_cpu_max(s: &str) -> Option<usize> {
    let mut it = s.split_whitespace();
    let quota = it.next()?;
    let period: u64 = it.next()?.parse().ok()?;
    if quota == "max" || period == 0 {
        return None;
    }
    let quota: u64 = quota.parse().ok()?;
    Some(((quota / period).max(1)) as usize)
}

/// Parses cgroup v1 `cpu.cfs_quota_us` / `cpu.cfs_period_us`.
/// A quota of `-1` means unlimited.
pub fn parse_cgroup_v1_quota(quota: &str, period: &str) -> Option<usize> {
    let q: i64 = quota.trim().parse().ok()?;
    let p: i64 = period.trim().parse().ok()?;
    if q <= 0 || p <= 0 {
        return None;
    }
    Some((((q / p) as u64).max(1)) as usize)
}

#[cfg(target_os = "linux")]
fn cgroup_budget() -> Option<usize> {
    use std::fs::read_to_string;

    // Try v2 at the process's own cgroup first (for nested slices), then the root.
    if let Ok(cgroup_contents) = read_to_string("/proc/self/cgroup") {
        if let Some(path) = super::cgroup::parse_self_cgroup_v2_path(&cgroup_contents) {
            let nested_path = format!("/sys/fs/cgroup{}/cpu.max", path);
            if let Ok(s) = read_to_string(&nested_path) {
                if let Some(n) = parse_cgroup_v2_cpu_max(&s) {
                    return Some(n);
                }
            }
        }
    }

    if let Ok(s) = read_to_string("/sys/fs/cgroup/cpu.max") {
        if let Some(n) = parse_cgroup_v2_cpu_max(&s) {
            return Some(n);
        }
    }
    let q = read_to_string("/sys/fs/cgroup/cpu/cpu.cfs_quota_us").ok()?;
    let p = read_to_string("/sys/fs/cgroup/cpu/cpu.cfs_period_us").ok()?;
    parse_cgroup_v1_quota(&q, &p)
}

#[cfg(not(target_os = "linux"))]
fn cgroup_budget() -> Option<usize> {
    None
}

/// The detected CPU budget: the minimum of process affinity and any cgroup
/// quota. Never zero.
pub fn detect_cpu_budget() -> usize {
    let affinity = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    match cgroup_budget() {
        Some(q) => affinity.min(q).max(1),
        None => affinity.max(1),
    }
}

/// Every source of a worker count, in precedence order.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct BudgetInputs {
    /// `--threads N`. `Some(0)` means "auto", per the zstd/xz convention.
    pub cli: Option<usize>,
    /// `STF_THREADS`.
    pub env: Option<usize>,
    /// `./.stf.toml`.
    pub project_config: Option<usize>,
    /// `~/.config/stf/config.toml`.
    pub user_config: Option<usize>,
    /// From [`detect_cpu_budget`].
    pub detected: usize,
    /// `--turbo`: full detected budget, uncapped.
    pub turbo: bool,
}

/// Resolves the worker count. Never returns zero.
pub fn resolve_workers(i: &BudgetInputs) -> usize {
    // The first source that expresses an opinion wins, and `Some(0)` IS an
    // opinion: it means "use the auto budget". A lower-precedence source must
    // not override it — otherwise a stale STF_THREADS silently beats an
    // explicit `--threads 0`, which is precedence backwards.
    let explicit = [i.cli, i.env, i.project_config, i.user_config]
        .into_iter()
        .flatten()
        .next();

    if let Some(n) = explicit {
        if n != 0 {
            return n;
        }
        // Explicit auto: fall through, but do not consult lower-precedence
        // sources.
    }

    let detected = i.detected.max(1);
    if i.turbo {
        return detected;
    }
    (detected / 2).clamp(1, DEFAULT_CAP)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs(detected: usize) -> BudgetInputs {
        BudgetInputs {
            detected,
            ..Default::default()
        }
    }

    #[test]
    fn cgroup_v2_quota_becomes_a_cpu_count() {
        assert_eq!(parse_cgroup_v2_cpu_max("200000 100000"), Some(2));
        assert_eq!(
            parse_cgroup_v2_cpu_max("50000 100000"),
            Some(1),
            "half a CPU floors to 1"
        );
        assert_eq!(
            parse_cgroup_v2_cpu_max("650000 100000"),
            Some(6),
            "6.5 truncates to 6"
        );
    }

    #[test]
    fn cgroup_v2_unlimited_and_malformed_yield_none() {
        assert_eq!(parse_cgroup_v2_cpu_max("max 100000"), None);
        assert_eq!(parse_cgroup_v2_cpu_max(""), None);
        assert_eq!(parse_cgroup_v2_cpu_max("garbage"), None);
        assert_eq!(
            parse_cgroup_v2_cpu_max("200000 0"),
            None,
            "zero period is not divisible"
        );
    }

    #[test]
    fn cgroup_v1_quota_becomes_a_cpu_count() {
        assert_eq!(parse_cgroup_v1_quota("400000", "100000"), Some(4));
        assert_eq!(
            parse_cgroup_v1_quota("-1", "100000"),
            None,
            "-1 means unlimited"
        );
        assert_eq!(parse_cgroup_v1_quota("bad", "100000"), None);
        assert_eq!(parse_cgroup_v1_quota("400000", "0"), None);
    }

    #[test]
    fn default_is_half_the_budget_capped_at_eight() {
        assert_eq!(resolve_workers(&inputs(4)), 2);
        assert_eq!(resolve_workers(&inputs(16)), 8);
        assert_eq!(
            resolve_workers(&inputs(128)),
            8,
            "cap protects a big shared host"
        );
    }

    #[test]
    fn a_single_cpu_still_gets_one_worker() {
        // Floor of 1: half of 1 is 0, and 0 workers deadlocks on an empty pool.
        assert_eq!(resolve_workers(&inputs(1)), 1);
        assert_eq!(resolve_workers(&inputs(0)), 1);
    }

    #[test]
    fn turbo_takes_the_whole_detected_budget_uncapped() {
        let i = BudgetInputs {
            detected: 128,
            turbo: true,
            ..Default::default()
        };
        assert_eq!(resolve_workers(&i), 128);
    }

    #[test]
    fn explicit_cli_value_wins_over_everything_including_turbo() {
        let i = BudgetInputs {
            cli: Some(3),
            env: Some(9),
            project_config: Some(9),
            user_config: Some(9),
            detected: 64,
            turbo: true,
        };
        assert_eq!(resolve_workers(&i), 3);
    }

    #[test]
    fn threads_zero_means_auto_not_zero_workers() {
        // Matches the zstd/xz convention. Zero workers would be a deadlock.
        let i = BudgetInputs {
            cli: Some(0),
            detected: 8,
            ..Default::default()
        };
        assert_eq!(resolve_workers(&i), 4);
    }

    #[test]
    fn precedence_falls_through_env_then_project_then_user() {
        let base = BudgetInputs {
            detected: 64,
            ..Default::default()
        };
        assert_eq!(
            resolve_workers(&BudgetInputs {
                env: Some(5),
                ..base.clone()
            }),
            5
        );
        assert_eq!(
            resolve_workers(&BudgetInputs {
                project_config: Some(6),
                ..base.clone()
            }),
            6
        );
        assert_eq!(
            resolve_workers(&BudgetInputs {
                user_config: Some(7),
                ..base.clone()
            }),
            7
        );
        assert_eq!(
            resolve_workers(&BudgetInputs {
                env: Some(5),
                project_config: Some(6),
                user_config: Some(7),
                ..base
            }),
            5,
            "env beats both config files"
        );
    }

    #[test]
    fn explicit_one_is_honoured_exactly() {
        let i = BudgetInputs {
            cli: Some(1),
            detected: 64,
            ..Default::default()
        };
        assert_eq!(resolve_workers(&i), 1);
    }

    #[test]
    fn detection_never_returns_zero_on_this_machine() {
        assert!(detect_cpu_budget() >= 1);
    }

    #[test]
    fn an_explicit_zero_means_auto_and_is_not_overridden_by_lower_precedence() {
        // `--threads 0` says "use auto". A stale STF_THREADS or a leftover
        // config value must not silently win — that is precedence backwards,
        // and it would take more of a shared machine than the operator asked.
        let i = BudgetInputs {
            cli: Some(0),
            env: Some(5),
            project_config: Some(6),
            user_config: Some(7),
            detected: 8,
            turbo: false,
        };
        assert_eq!(
            resolve_workers(&i),
            4,
            "expected the auto budget, not the env var"
        );
    }

    #[test]
    fn an_explicit_zero_still_honours_turbo() {
        // "auto" plus --turbo is the full detected budget, uncapped.
        let i = BudgetInputs {
            cli: Some(0),
            detected: 32,
            turbo: true,
            ..Default::default()
        };
        assert_eq!(resolve_workers(&i), 32);
    }

    #[test]
    fn a_zero_from_a_middle_source_stops_the_search_too() {
        // The rule is uniform across sources, not special-cased to the CLI.
        let i = BudgetInputs {
            env: Some(0),
            project_config: Some(6),
            detected: 8,
            ..Default::default()
        };
        assert_eq!(resolve_workers(&i), 4);
    }

    #[test]
    fn turbo_never_resolves_to_zero_workers() {
        // Zero workers would deadlock Task 9's lease pool.
        let i = BudgetInputs {
            detected: 0,
            turbo: true,
            ..Default::default()
        };
        assert_eq!(resolve_workers(&i), 1);
    }
}
