//! Pure parsers over cgroup and meminfo file *contents*.
//!
//! Contents rather than paths, so the arithmetic is unit-testable on any
//! platform — including one with no `/sys/fs/cgroup` at all. The CPU readers in
//! [`super::budget`] follow the same shape.

/// `MemAvailable` from `/proc/meminfo`, in bytes. The field is in kB.
pub fn parse_meminfo_available(contents: &str) -> Option<u64> {
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

/// cgroup v2 `memory.max`, in bytes. `"max"` means unlimited.
pub fn parse_cgroup_v2_memory_max(contents: &str) -> Option<u64> {
    let s = contents.trim();
    if s.is_empty() || s == "max" {
        return None;
    }
    s.parse().ok()
}

/// cgroup v1 `memory.limit_in_bytes`.
///
/// v1 signals "unlimited" with a value near `u64::MAX` rather than a word, so
/// anything implausibly large is treated as no limit.
pub fn parse_cgroup_v1_memory_limit(contents: &str) -> Option<u64> {
    const IMPLAUSIBLE: u64 = 1 << 62;
    let v: u64 = contents.trim().parse().ok()?;
    if v >= IMPLAUSIBLE { None } else { Some(v) }
}

/// The unified-hierarchy path from `/proc/self/cgroup` — the third field of the
/// line beginning `0::`.
///
/// Without this the v2 readers consult only the cgroup root, so a process in a
/// nested systemd slice sees no quota at all.
pub fn parse_self_cgroup_v2_path(contents: &str) -> Option<String> {
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            let p = rest.trim();
            if !p.is_empty() {
                return Some(p.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    #[test]
    fn meminfo_available_is_parsed_from_kilobytes() {
        let s = "MemTotal:       65536000 kB\nMemAvailable:    1048576 kB\nCached: 1 kB\n";
        assert_eq!(parse_meminfo_available(s), Some(1024 * MIB));
    }

    #[test]
    fn meminfo_without_the_field_yields_none() {
        assert_eq!(parse_meminfo_available("MemTotal: 100 kB\n"), None);
        assert_eq!(parse_meminfo_available(""), None);
        assert_eq!(
            parse_meminfo_available("MemAvailable: notanumber kB\n"),
            None
        );
    }

    #[test]
    fn cgroup_v2_memory_max_is_bytes_and_max_means_unlimited() {
        assert_eq!(parse_cgroup_v2_memory_max("536870912\n"), Some(512 * MIB));
        assert_eq!(parse_cgroup_v2_memory_max("max\n"), None);
        assert_eq!(parse_cgroup_v2_memory_max("garbage"), None);
        assert_eq!(parse_cgroup_v2_memory_max(""), None);
    }

    #[test]
    fn cgroup_v1_unlimited_sentinel_yields_none() {
        // v1 writes a huge number rather than a word for "unlimited".
        assert_eq!(parse_cgroup_v1_memory_limit("536870912\n"), Some(512 * MIB));
        assert_eq!(parse_cgroup_v1_memory_limit("9223372036854771712\n"), None);
        assert_eq!(parse_cgroup_v1_memory_limit("-1"), None);
    }

    #[test]
    fn self_cgroup_v2_path_is_the_third_field_of_the_zero_line() {
        assert_eq!(
            parse_self_cgroup_v2_path("0::/user.slice/user-1000.slice/session-3.scope\n"),
            Some("/user.slice/user-1000.slice/session-3.scope".to_string())
        );
        // v1-only output has no 0:: line.
        assert_eq!(parse_self_cgroup_v2_path("12:cpu,cpuacct:/foo\n"), None);
        assert_eq!(parse_self_cgroup_v2_path(""), None);
    }
}
