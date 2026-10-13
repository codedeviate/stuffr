//! util.c: the parts of zstd's utilities the family needs. For now the
//! core counts (R3); file-list expansion arrives with Task 5.

/// util.c: `UTIL_countLogicalCores` and `UTIL_countPhysicalCores`, read
/// once per run (R3). The real process reads the machine as util.c does on
/// its platform; a sandboxed run sees [`Cores::SANDBOX`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cores {
    /// `UTIL_countLogicalCores()`.
    pub logical: u32,
    /// `UTIL_countPhysicalCores()`.
    pub physical: u32,
}

impl Cores {
    /// R3: the machine a sandboxed run sees.
    pub(crate) const SANDBOX: Cores = Cores {
        logical: 8,
        physical: 4,
    };

    /// The machine's counts, as util.c's `UTIL_countCores` reads them.
    pub(crate) fn detect() -> Cores {
        let (logical, physical) = count_cores();
        Cores {
            logical: logical.max(1),
            physical: physical.max(1),
        }
    }

    /// zstdcli.c: `ZSTDCLI_NBTHREADS_DEFAULT`, `MAX(1, MIN(4,
    /// UTIL_countLogicalCores() / 4))`.
    pub(crate) fn default_workers(self) -> u32 {
        (self.logical / 4).clamp(1, 4)
    }
}

/// util.c (`__APPLE__`): `sysctlbyname("hw.logicalcpu")` and
/// `"hw.physicalcpu"`, 1 when the entry is missing.
#[cfg(target_vendor = "apple")]
fn count_cores() -> (u32, u32) {
    fn read(name: &std::ffi::CStr) -> u32 {
        let mut n: i32 = 0;
        let mut size = std::mem::size_of::<i32>();
        // SAFETY: `name` is NUL-terminated, `n` is valid for `size` bytes,
        // and no new value is set.
        let r = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                (&mut n as *mut i32).cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if r == 0 && n > 0 { n as u32 } else { 1 }
    }
    (read(c"hw.logicalcpu"), read(c"hw.physicalcpu"))
}

/// util.c (`__linux__`): `sysconf(_SC_NPROCESSORS_ONLN)`, and for the
/// physical count that divided by `/proc/cpuinfo`'s `siblings` / `cpu
/// cores` ratio when hyperthreading shows.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn count_cores() -> (u32, u32) {
    // SAFETY: `sysconf` only reads system configuration.
    let online = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if online <= 0 {
        return (1, 1);
    }
    let logical = online as u32;
    let Ok(info) = std::fs::read_to_string("/proc/cpuinfo") else {
        return (logical, logical);
    };
    (logical, physical_from_cpuinfo(logical, &info))
}

/// util.c's `/proc/cpuinfo` walk: the last `siblings` and `cpu cores`
/// values (`atoi` of the text after `:`); a line without `:` stops the walk
/// and keeps `numCores`.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn physical_from_cpuinfo(online: u32, info: &str) -> u32 {
    fn atoi(s: &str) -> i64 {
        let s = s.trim_start();
        let (neg, digits) = match s.as_bytes().first() {
            Some(b'-') => (true, &s[1..]),
            Some(b'+') => (false, &s[1..]),
            _ => (false, s),
        };
        let n = digits
            .bytes()
            .take_while(u8::is_ascii_digit)
            .fold(0i64, |n, b| {
                n.saturating_mul(10).saturating_add(i64::from(b - b'0'))
            });
        if neg { -n } else { n }
    }
    let (mut siblings, mut cpu_cores) = (0i64, 0i64);
    for line in info.lines() {
        // fgets(buff, 80): a longer line is read in pieces, but the keys
        // only ever start a line, so only its first piece can match.
        let line = line.get(..79).unwrap_or(line);
        for (key, slot) in [("siblings", &mut siblings), ("cpu cores", &mut cpu_cores)] {
            if line.starts_with(key) {
                match line.find(':') {
                    Some(at) => *slot = atoi(&line[at + 1..]),
                    None => return online,
                }
            }
        }
    }
    let ratio = if siblings != 0 && cpu_cores != 0 && siblings > cpu_cores {
        siblings / cpu_cores
    } else {
        1
    };
    if ratio != 0 && i64::from(online) > ratio {
        (i64::from(online) / ratio) as u32
    } else {
        online
    }
}

/// util.c (the other POSIX systems): `sysconf(_SC_NPROCESSORS_ONLN)` for
/// both.
#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
fn count_cores() -> (u32, u32) {
    // SAFETY: `sysconf` only reads system configuration.
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    let n = if n > 0 { n as u32 } else { 1 };
    (n, n)
}

/// Elsewhere (Windows: util.c asks `GetLogicalProcessorInformation`): the
/// standard library's count for both.
#[cfg(not(unix))]
fn count_cores() -> (u32, u32) {
    let n = std::thread::available_parallelism().map_or(1, |n| n.get() as u32);
    (n, n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_worker_count_is_a_quarter_of_the_logical_cores_within_1_to_4() {
        let w = |logical| {
            Cores {
                logical,
                physical: 1,
            }
            .default_workers()
        };
        assert_eq!([w(1), w(4), w(8), w(12), w(16), w(64)], [1, 1, 2, 3, 4, 4]);
        assert_eq!(Cores::SANDBOX.default_workers(), 2);
    }

    #[test]
    fn detected_counts_are_positive() {
        let c = Cores::detect();
        assert!(c.logical >= 1 && c.physical >= 1, "{c:?}");
    }

    #[test]
    fn cpuinfo_divides_by_the_hyperthreading_ratio() {
        let ht = "processor\t: 0\nsiblings\t: 8\ncpu cores\t: 4\n";
        assert_eq!(physical_from_cpuinfo(16, ht), 8);
        assert_eq!(
            physical_from_cpuinfo(2, ht),
            2,
            "online not above the ratio"
        );
        assert_eq!(physical_from_cpuinfo(4, "processor\t: 0\n"), 4);
        assert_eq!(physical_from_cpuinfo(4, "siblings 8\n"), 4, "no colon");
        let no_ht = "siblings\t: 4\ncpu cores\t: 4\n";
        assert_eq!(physical_from_cpuinfo(4, no_ht), 4);
    }
}
