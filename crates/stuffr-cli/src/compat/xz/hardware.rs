//! `hardware.c` (the thread count and the memory usage limits) and the
//! `tuklib_physmem`/`tuklib_cpucores` detection it relies on, from XZ Utils
//! 5.8.4 (0BSD, `LICENSE-xz`).
//!
//! The machine is read here on both tiers (Ruling P1/P1a: the bundled
//! liblzma's `lzma_physmem`/`lzma_cputhreads` return 0 in this build). The
//! methods are the ones the reference's `configure` picks: physical memory
//! from `sysconf(_SC_PAGESIZE) * sysconf(_SC_PHYS_PAGES)` on every unix;
//! the thread count from `sched_getaffinity` on Linux, `sysctl(HW_NCPU)` on
//! Apple platforms, `sysconf(_SC_NPROCESSORS_ONLN)` elsewhere. Under
//! `Host::Sandbox` the machine is the fixed [`Hardware::SANDBOX`] (R3), so
//! fuzz runs are deterministic, and resource limits are not consulted.

use std::io::Write;

use super::args::OpMode;
use super::messages::{self as m, printf};

/// What the machine has: `lzma_cputhreads()` and `lzma_physmem()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Hardware {
    /// Processor threads available (0 when unknown).
    pub cpus: u32,
    /// Physical memory in bytes (0 when unknown).
    pub physmem: u64,
}

/// `ASSUME_RAM`: `configure`'s default guess, in MiB, when physical memory
/// cannot be read.
const ASSUME_RAM_MIB: u64 = 128;

/// The largest thread count xz accepts (`LZMA_THREADS_MAX` in liblzma's
/// common.h).
pub(crate) const THREADS_MAX: u64 = 16384;

impl Hardware {
    /// R3: what a sandboxed run sees, whatever the machine.
    pub(crate) const SANDBOX: Hardware = Hardware {
        cpus: 2,
        physmem: 4 << 30,
    };

    /// The machine's values (`tuklib_cpucores`, `tuklib_physmem`).
    pub(crate) fn detect() -> Hardware {
        Hardware {
            cpus: cpucores(),
            physmem: physmem(),
        }
    }
}

/// tuklib_physmem.c, the `TUKLIB_PHYSMEM_SYSCONF` method.
#[cfg(unix)]
fn physmem() -> u64 {
    // SAFETY: `sysconf` only reads system configuration.
    let (pagesize, pages) = unsafe {
        (
            libc::sysconf(libc::_SC_PAGESIZE),
            libc::sysconf(libc::_SC_PHYS_PAGES),
        )
    };
    if pagesize != -1 && pages != -1 {
        (pagesize as u64).wrapping_mul(pages as u64)
    } else {
        0
    }
}

#[cfg(not(unix))]
fn physmem() -> u64 {
    0
}

/// tuklib_cpucores.c, `TUKLIB_CPUCORES_SCHED_GETAFFINITY`.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn cpucores() -> u32 {
    // SAFETY: `cpu_set_t` is plain data that `CPU_ZERO`'s all-zero state
    // initialises; `sched_getaffinity` writes at most its size.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        if libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) == 0 {
            libc::CPU_COUNT(&set) as u32
        } else {
            0
        }
    }
}

/// tuklib_cpucores.c, `TUKLIB_CPUCORES_SYSCTL` with `HW_NCPU`.
#[cfg(target_vendor = "apple")]
fn cpucores() -> u32 {
    let mut name = [libc::CTL_HW, libc::HW_NCPU];
    let mut cpus: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();
    // SAFETY: `name` and `cpus` are valid for the sizes passed, and no new
    // value is set.
    let r = unsafe {
        libc::sysctl(
            name.as_mut_ptr(),
            2,
            (&mut cpus as *mut libc::c_int).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if r != -1 && size == std::mem::size_of::<libc::c_int>() && cpus > 0 {
        cpus as u32
    } else {
        0
    }
}

/// tuklib_cpucores.c, `TUKLIB_CPUCORES_SYSCONF`.
#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
fn cpucores() -> u32 {
    // SAFETY: `sysconf` only reads system configuration.
    let cpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if cpus > 0 { cpus as u32 } else { 0 }
}

#[cfg(not(unix))]
fn cpucores() -> u32 {
    0
}

/// hardware.c's state: the thread count and the memory usage limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Limits {
    /// `threads_max`.
    threads_max: u32,
    /// `threads_are_automatic`: `-T0`.
    threads_are_automatic: bool,
    /// `use_mt_mode_with_one_thread`: `-T0` or `-T+1`.
    use_mt_mode_with_one_thread: bool,
    /// `memlimit_compress` (0: the default, no limit).
    memlimit_compress: u64,
    /// `memlimit_decompress` (0: the default, no limit).
    memlimit_decompress: u64,
    /// `memlimit_mtdec` (0: [`Limits::memlimit_mt_default`]).
    memlimit_mtdec: u64,
    /// `memlimit_mt_default`: a quarter of the RAM, lowered under a resource
    /// limit.
    memlimit_mt_default: u64,
    /// `total_ram`.
    total_ram: u64,
    /// The processor threads `-T0` uses (`lzma_cputhreads()`).
    cputhreads: u32,
    /// Ruling P7: a sandboxed run's decoder never gets more than this,
    /// whatever `-M` says, so a fuzzed header cannot make the pure tier
    /// zero-fill gigabytes. `None` for the real process.
    decoder_cap: Option<u64>,
}

/// Ruling P7: the decompression memory limit of a sandboxed run.
pub(crate) const SANDBOX_DECODER_CAP: u64 = 256 << 20;

impl Limits {
    /// hardware.c: hardware_init, for `hw`; `rlimits` says whether the
    /// process's `RLIMIT_DATA`/`RLIMIT_AS` lower the multi-threaded default
    /// (the real process only), and `decoder_cap` is Ruling P7's.
    pub(crate) fn init(hw: Hardware, rlimits: bool, decoder_cap: Option<u64>) -> Limits {
        let total_ram = if hw.physmem == 0 {
            ASSUME_RAM_MIB * 1024 * 1024
        } else {
            hw.physmem
        };
        let mut memlimit_mt_default = total_ram / 4;
        if rlimits && let Some(cap) = rlimit_with_margin() {
            memlimit_mt_default = memlimit_mt_default.min(cap);
        }
        if usize::BITS == 32 {
            // A too high value may cause a 32-bit xz to run out of address
            // space.
            memlimit_mt_default = memlimit_mt_default.min(1400 << 20);
        }
        let mut l = Limits {
            threads_max: 1,
            threads_are_automatic: false,
            use_mt_mode_with_one_thread: false,
            memlimit_compress: 0,
            memlimit_decompress: 0,
            memlimit_mtdec: 0,
            memlimit_mt_default,
            total_ram,
            cputhreads: hw.cpus,
            decoder_cap,
        };
        // Threaded mode is the default since 5.6.0.
        l.threads_set(0);
        l
    }

    /// hardware.c: hardware_threads_set. `u32::MAX` is `-T+1`: one thread
    /// in multi-threaded mode.
    pub(crate) fn threads_set(&mut self, n: u32) {
        self.threads_are_automatic = false;
        self.use_mt_mode_with_one_thread = false;
        if n == 0 {
            self.threads_are_automatic = true;
            self.use_mt_mode_with_one_thread = true;
            self.threads_max = self.cputhreads.max(1);
        } else if n == u32::MAX {
            self.use_mt_mode_with_one_thread = true;
            self.threads_max = 1;
        } else {
            self.threads_max = n;
        }
    }

    /// hardware.c: hardware_threads_get.
    #[allow(dead_code)] // the coder (Task 6) reads it
    pub(crate) fn threads_get(&self) -> u32 {
        self.threads_max
    }

    /// hardware.c: hardware_threads_is_mt.
    #[allow(dead_code)] // the coder (Task 6) reads it
    pub(crate) fn threads_is_mt(&self) -> bool {
        self.threads_max > 1 || self.use_mt_mode_with_one_thread
    }

    /// hardware.c: hardware_memlimit_set. A percentage is of the RAM, in
    /// the C code's 64-bit arithmetic.
    pub(crate) fn memlimit_set(
        &mut self,
        value: u64,
        compress: bool,
        decompress: bool,
        mtdec: bool,
        percentage: bool,
    ) {
        let mut v = value;
        if percentage {
            v = v.wrapping_mul(self.total_ram) / 100;
        }
        if compress {
            self.memlimit_compress = v;
            if usize::BITS == 32 && v != u64::MAX {
                self.memlimit_compress = v.min(4020 << 20);
            }
        }
        if decompress {
            self.memlimit_decompress = v;
        }
        if mtdec {
            self.memlimit_mtdec = v;
        }
    }

    /// hardware.c: hardware_memlimit_get: the hard limit, `u64::MAX` for
    /// none. Under the sandbox the decoder's is capped (Ruling P7).
    #[allow(dead_code)] // the coder (Task 6) reads it
    pub(crate) fn memlimit_get(&self, mode: OpMode) -> u64 {
        let set = if mode == OpMode::Compress {
            self.memlimit_compress
        } else {
            self.memlimit_decompress
        };
        let limit = if set != 0 { set } else { u64::MAX };
        match (mode, self.decoder_cap) {
            (OpMode::Compress, _) | (_, None) => limit,
            (_, Some(cap)) => limit.min(cap),
        }
    }

    /// hardware.c: hardware_memlimit_mtenc_get.
    #[allow(dead_code)] // the coder (Task 6) reads it
    pub(crate) fn memlimit_mtenc_get(&self) -> u64 {
        if self.memlimit_mtenc_is_default() {
            self.memlimit_mt_default
        } else {
            self.memlimit_get(OpMode::Compress)
        }
    }

    /// hardware.c: hardware_memlimit_mtenc_is_default.
    #[allow(dead_code)] // the coder (Task 6) reads it
    pub(crate) fn memlimit_mtenc_is_default(&self) -> bool {
        self.memlimit_compress == 0 && self.threads_are_automatic
    }

    /// hardware.c: hardware_memlimit_mtdec_get, capped (Ruling P7) under the
    /// sandbox.
    pub(crate) fn memlimit_mtdec_get(&self) -> u64 {
        let mut v = if self.memlimit_mtdec != 0 {
            self.memlimit_mtdec
        } else {
            self.memlimit_mt_default
        };
        if self.memlimit_decompress != 0 && v > self.memlimit_decompress {
            v = self.memlimit_decompress;
        }
        match self.decoder_cap {
            Some(cap) => v.min(cap),
            None => v,
        }
    }

    /// hardware.c: hardware_memlimit_show (`--info-memory`), to `out`.
    pub(crate) fn show(&self, robot: bool, out: &mut dyn Write) {
        let cputhreads = self.cputhreads.max(1);
        let n = |v: u64| v.to_string().into_bytes();
        if robot {
            printf(
                out,
                m::INFO_MEMORY_ROBOT,
                &[
                    &n(self.total_ram),
                    &n(self.memlimit_compress),
                    &n(self.memlimit_decompress),
                    &n(self.memlimit_mtdec_get()),
                    &n(self.memlimit_mt_default),
                    &n(u64::from(cputhreads)),
                ],
            );
            return;
        }
        let width = m::INFO_LABELS.iter().map(|l| l.len()).max().unwrap_or(1);
        let pad = |l: &str| format!("{l:<width$}").into_bytes();
        let row = |out: &mut dyn Write, label: &str, value: u64| {
            if value == 0 || value == u64::MAX {
                printf(out, m::INFO_ROW_DISABLED, &[&pad(label)]);
            } else {
                printf(
                    out,
                    m::INFO_ROW_LIMIT,
                    &[&pad(label), &n(round_up_to_mib(value)), &n(value)],
                );
            }
        };
        printf(out, m::INFO_HARDWARE, &[]);
        row(out, m::INFO_LABELS[0], self.total_ram);
        printf(
            out,
            m::INFO_ROW_THREADS,
            &[&pad(m::INFO_LABELS[1]), &n(u64::from(cputhreads))],
        );
        printf(out, m::INFO_LIMITS, &[]);
        row(out, m::INFO_LABELS[2], self.memlimit_compress);
        row(out, m::INFO_LABELS[3], self.memlimit_decompress);
        row(out, m::INFO_LABELS[4], self.memlimit_mtdec_get());
        row(out, m::INFO_LABELS[5], self.memlimit_mt_default);
    }
}

/// util.c: round_up_to_mib.
pub(crate) fn round_up_to_mib(n: u64) -> u64 {
    (n >> 20) + u64::from(n & ((1 << 20) - 1) != 0)
}

/// hardware.c: hardware_init's resource-limit pass: the lowest of
/// `RLIMIT_DATA` and `RLIMIT_AS` that is set, less a 64 MiB margin (at
/// least 1).
#[cfg(unix)]
fn rlimit_with_margin() -> Option<u64> {
    const MARGIN: u64 = 64 << 20;
    let mut lowest: Option<u64> = None;
    for resource in [libc::RLIMIT_DATA, libc::RLIMIT_AS] {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `rl` is a valid `rlimit` for `getrlimit` to fill.
        if unsafe { libc::getrlimit(resource, &mut rl) } != 0 {
            continue;
        }
        // `RLIM_SAVED_CUR`/`RLIM_SAVED_MAX` equal `RLIM_INFINITY` where
        // they exist on the platforms stuffr builds for.
        if rl.rlim_cur == libc::RLIM_INFINITY {
            continue;
        }
        // `rlim_t` is not `u64` on every unix.
        #[allow(clippy::unnecessary_cast)]
        let cur = rl.rlim_cur as u64;
        let with_margin = if cur > MARGIN { cur - MARGIN } else { 1 };
        lowest = Some(lowest.map_or(with_margin, |l: u64| l.min(with_margin)));
    }
    lowest
}

#[cfg(not(unix))]
fn rlimit_with_margin() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits::init(Hardware::SANDBOX, false, None)
    }

    /// hardware.c's defaults: `-T0`, no compression or decompression
    /// limit, a quarter of the RAM for the multi-threaded ones.
    #[test]
    fn the_defaults_follow_hardware_init() {
        let l = limits();
        assert_eq!(l.threads_get(), 2);
        assert!(l.threads_is_mt() && l.memlimit_mtenc_is_default());
        assert_eq!(l.memlimit_get(OpMode::Compress), u64::MAX);
        assert_eq!(l.memlimit_get(OpMode::Decompress), u64::MAX);
        assert_eq!(l.memlimit_mtenc_get(), 1 << 30);
        assert_eq!(l.memlimit_mtdec_get(), 1 << 30);
        let unknown = Limits::init(
            Hardware {
                cpus: 0,
                physmem: 0,
            },
            false,
            None,
        );
        assert_eq!(unknown.threads_get(), 1);
        assert_eq!(unknown.memlimit_mtenc_get(), 32 << 20);
    }

    #[test]
    fn thread_counts_follow_hardware_threads_set() {
        let mut l = limits();
        l.threads_set(1);
        assert!(!l.threads_is_mt());
        l.threads_set(u32::MAX);
        assert_eq!((l.threads_get(), l.threads_is_mt()), (1, true));
        l.threads_set(4);
        assert!(l.threads_is_mt() && !l.memlimit_mtenc_is_default());
    }

    #[test]
    fn percentages_are_of_the_ram_and_mtdec_is_capped() {
        let mut l = limits();
        l.memlimit_set(50, true, true, true, true);
        assert_eq!(l.memlimit_get(OpMode::Compress), 2 << 30);
        l.memlimit_set(1 << 20, false, true, false, false);
        assert_eq!(l.memlimit_mtdec_get(), 1 << 20);
        l.memlimit_set(0, true, true, true, false);
        assert_eq!(l.memlimit_get(OpMode::Test), u64::MAX);
    }

    /// Ruling P7: the sandbox caps the decoder whatever `-M` says.
    #[test]
    fn the_sandbox_caps_the_decoder() {
        let mut l = Limits::init(Hardware::SANDBOX, false, Some(SANDBOX_DECODER_CAP));
        assert_eq!(l.memlimit_get(OpMode::Decompress), SANDBOX_DECODER_CAP);
        assert_eq!(l.memlimit_get(OpMode::Compress), u64::MAX);
        l.memlimit_set(u64::MAX, true, true, true, false);
        assert_eq!(l.memlimit_get(OpMode::List), SANDBOX_DECODER_CAP);
        assert_eq!(l.memlimit_mtdec_get(), SANDBOX_DECODER_CAP);
        l.memlimit_set(1 << 20, false, true, false, false);
        assert_eq!(l.memlimit_get(OpMode::Decompress), 1 << 20);
    }

    #[test]
    fn info_memory_renders_hardware_memlimit_show() {
        let mut l = limits();
        l.memlimit_set(1000, false, true, false, false);
        let mut out = Vec::new();
        l.show(false, &mut out);
        // Each label padded to the widest, 32 columns (recorded from
        // `xz --info-memory`).
        let row = |label: &str, value: &str| format!("  {label:<32}  {value}\n");
        let want = [
            "Hardware information:\n".to_string(),
            row(
                "Amount of physical memory (RAM):",
                "4096 MiB (4294967296 B)",
            ),
            row("Number of processor threads:", "2"),
            "\nMemory usage limits:\n".to_string(),
            row("Compression:", "Disabled"),
            row("Decompression:", "1 MiB (1000 B)"),
            row("Multi-threaded decompression:", "1 MiB (1000 B)"),
            row("Default for -T0:", "1024 MiB (1073741824 B)"),
        ]
        .concat();
        assert_eq!(String::from_utf8(out).unwrap(), want);
        let mut out = Vec::new();
        l.show(true, &mut out);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "4294967296\t0\t1000\t1000\t1073741824\t2\n"
        );
    }

    /// Ruling P1a: the detection equals the reference's own, as its
    /// `--robot --info-memory` prints it (physical memory, first field;
    /// threads, last). Skipped when the reference is absent.
    #[cfg(unix)]
    #[test]
    fn detection_matches_the_reference() {
        let exe = std::env::var_os("STUFFR_XZ_REFERENCE")
            .filter(|v| !v.is_empty())
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| "/opt/homebrew/opt/xz/bin/xz".into());
        if !exe.is_file() {
            assert!(
                std::env::var_os("CI").is_none(),
                "CI is set but there is no reference xz at {}",
                exe.display()
            );
            eprintln!("skipped: no reference xz at {}", exe.display());
            return;
        }
        let out = std::process::Command::new(&exe)
            .args(["--robot", "--info-memory"])
            .env_clear()
            .output()
            .unwrap();
        let text = String::from_utf8(out.stdout).unwrap();
        let fields: Vec<&str> = text.trim_end().split('\t').collect();
        assert_eq!(fields.len(), 6, "{text:?}");
        let hw = Hardware::detect();
        assert_eq!(hw.physmem.to_string(), fields[0], "physical memory");
        assert_eq!(hw.cpus.max(1).to_string(), fields[5], "threads");
        // The multi-threaded default too, which the resource limits shape.
        let l = Limits::init(hw, true, None);
        assert_eq!(l.memlimit_mt_default.to_string(), fields[4], "-T0 default");
    }
}
