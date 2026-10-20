//! Differential harness: run a real reference tool and stuffr invoked through
//! a symlink of the same name with identical arguments, input files, stdin,
//! tty state and environment, then compare everything observable.
//!
//! Unix only. The caller declares it as `#[cfg(unix)] mod compat_harness;`.
#![allow(dead_code)] // each test crate uses a different subset

pub mod interrupt;
pub mod unzip;
#[allow(unused_imports)] // only the unzip suites use it
pub use unzip::*;

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};

/// Where the reference tools live; also used to decompress stuffr's output.
pub const REFERENCE_DIR: &str = "/usr/bin";
/// The mtime every input file gets, so runs cannot differ by wall clock.
pub const INPUT_MTIME: u64 = 1_000_000_000;
const TIMEOUT: Duration = Duration::from_secs(30);

/// Apple's gzip (one program; the invoked name sets the mode).
pub const APPLE_GZIP_DIR: &str = "/usr/bin";

/// GNU gzip's directory on this platform: Linux `/usr/bin`, macOS the
/// keg-only Homebrew install (never `brew link`ed; addressed by path).
pub fn gnu_gzip_dir() -> &'static str {
    if cfg!(target_os = "macos") {
        "/opt/homebrew/opt/gzip/bin"
    } else {
        "/usr/bin"
    }
}

/// The installed GNU gzip's `(major, minor)`, parsed from the last word of
/// `gzip --version`'s first line (`gzip 1.12`). `None` when the binary is
/// absent or the line does not parse.
pub fn gnu_gzip_version() -> Option<(u32, u32)> {
    let exe = Path::new(gnu_gzip_dir()).join("gzip");
    let out = output(
        Command::new(exe)
            .arg("--version")
            .env_clear()
            .stdin(Stdio::null()),
    )
    .ok()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let word = text.lines().next()?.split_whitespace().last()?.to_owned();
    let mut it = word.split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    Some((major, minor))
}

const XZ_VERSION_LINE: &str = "XZ_VERSION=50080042";
const XZ_LINKS: [&str; 5] = ["unxz", "xzcat", "lzma", "unlzma", "lzcat"];

/// Whether `<dir>/xz --robot --version` says it is XZ Utils 5.8.4.
fn is_xz_5_8_4(dir: &Path) -> bool {
    output(
        Command::new(dir.join("xz"))
            .args(["--robot", "--version"])
            .env_clear()
            .stdin(Stdio::null()),
    )
    .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains(XZ_VERSION_LINE))
}

/// A directory holding `xz` and its five links. `xz` itself is `exe`; when
/// the links are not all beside it (a bare binary), they are made, as
/// symlinks to it, in a temporary directory that lives as long as the test
/// process's temp dir (a few inodes; never removed).
fn dir_with_links(exe: &Path) -> Option<PathBuf> {
    dir_with_links_for(exe, "xz", &XZ_LINKS)
}

/// [`dir_with_links`] for any tool: `exe` is the tool `main`, `links` the
/// names that must sit beside it.
fn dir_with_links_for(exe: &Path, main: &str, links: &[&str]) -> Option<PathBuf> {
    let parent = exe.parent()?;
    if links.iter().all(|l| parent.join(l).exists()) {
        return Some(parent.to_path_buf());
    }
    let dir = std::env::temp_dir().join(format!("stuffr-{main}-links-{}", std::process::id()));
    fs::create_dir_all(&dir).ok()?;
    let target = fs::canonicalize(exe).ok()?;
    for name in std::iter::once(main).chain(links.iter().copied()) {
        let l = dir.join(name);
        let _ = fs::remove_file(&l);
        std::os::unix::fs::symlink(&target, &l).ok()?;
    }
    Some(dir)
}

/// `xz` on `PATH`, like a shell's lookup.
fn xz_on_path() -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join("xz"))
        .find(|p| p.is_file())
}

/// The directory holding XZ Utils 5.8.4's `xz` and its links `unxz`,
/// `xzcat`, `lzma`, `unlzma` and `lzcat`.
///
/// Looked up in this order, the first one that is exactly 5.8.4 (`xz
/// --robot --version` prints `XZ_VERSION=50080042`) winning:
/// 1. `$STUFFR_XZ_REFERENCE`, the path of an `xz` (CI builds the release
///    tarball there; `make install` puts the five links beside it, and if
///    they are absent they are made in a temp dir);
/// 2. Homebrew's keg, `/opt/homebrew/opt/xz/bin`;
/// 3. `xz` on `PATH`.
///
/// `None` when there is none: a skip with a note locally, a panic under `CI`
/// (the rule of [`require_reference`]), so every test that skips on it would
/// otherwise pass vacuously. A tool of another release is no reference:
/// stuffr promises 5.8.4's bytes.
pub fn xz_dir() -> Option<&'static str> {
    static DIR: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    let found = DIR.get_or_init(|| {
        let candidates = [
            std::env::var_os("STUFFR_XZ_REFERENCE")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
            Some(PathBuf::from("/opt/homebrew/opt/xz/bin/xz")),
            xz_on_path(),
        ];
        for exe in candidates.into_iter().flatten() {
            if !exe.is_file() {
                continue;
            }
            let Some(dir) = dir_with_links(&exe) else {
                continue;
            };
            if is_xz_5_8_4(&dir) {
                return dir.to_str().map(str::to_owned);
            }
        }
        None
    });
    match found {
        Some(d) => Some(d.as_str()),
        None => {
            assert!(
                std::env::var_os("CI").is_none(),
                "CI is set but there is no XZ Utils 5.8.4 reference (looked at \
                 $STUFFR_XZ_REFERENCE, /opt/homebrew/opt/xz/bin, PATH)"
            );
            eprintln!("skipped: XZ Utils 5.8.4 not installed");
            None
        }
    }
}

/// Whether `s` is an xz elapsed time: `m:ss` or `h:mm:ss`.
fn is_xz_elapsed(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    let digits = |p: &str, n: Option<usize>| {
        !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && n.is_none_or(|n| p.len() == n)
    };
    match parts.as_slice() {
        [m, ss] => digits(m, None) && digits(ss, Some(2)),
        [h, mm, ss] => digits(h, None) && digits(mm, Some(2)) && digits(ss, Some(2)),
        _ => false,
    }
}

/// Whether `s` is an xz speed: `123 KiB/s`, `1.2 MiB/s` (K, M or G).
fn is_xz_speed(s: &str) -> bool {
    let Some((num, unit)) = s.split_once(' ') else {
        return false;
    };
    matches!(unit, "KiB/s" | "MiB/s" | "GiB/s")
        && !num.is_empty()
        && num.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && num.bytes().filter(|&b| b == b'.').count() <= 1
        && !num.starts_with('.')
        && !num.ends_with('.')
}

/// Split a progress line after the `= 0.611` ratio of its size block
/// (`<n> <unit> / <n> <unit> = <ratio>`). `None` when `line` has no such
/// block.
fn split_after_ratio(line: &str) -> Option<(&str, &str)> {
    let eq = line.find(" = ")?;
    if !line[..eq].contains(" / ") {
        return None;
    }
    let after = &line[eq + 3..];
    let end = after
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(after.len());
    let ratio = &after[..end];
    let ok = ratio.len() >= 2 && ratio.bytes().filter(|&b| b == b'.').count() == 1;
    ok.then(|| line.split_at(eq + 3 + end))
}

/// Replace the speed and elapsed-time fields of xz's `-v` progress lines
/// with `<speed>` and `<elapsed>`, and nothing else: they are the only part
/// of xz's output that depends on how fast the run was.
///
/// Both shapes of the final line are covered:
/// - stderr not a terminal (what the differential suite sees):
///   `name: 19.1 MiB / 19.1 MiB = 1.000, 3.9 MiB/s, 0:04`, the speed present
///   from 3 s and the time from 1 s (`message.c` `progress_flush`);
/// - the terminal format, `\r 100 %   1,234 B / 300.0 KiB = 0.004
///   1.2 MiB/s   0:00`, whose column padding follows the speed's width, so
///   its blanks are collapsed.
///
/// A line is touched only if it carries a size block (`a / b = ratio`) and
/// the field's whole text has xz's exact shape; the sizes, the ratio, the
/// name and every other line stay as they are.
pub fn normalise_xz_progress(stderr: &str) -> String {
    let mut out = String::with_capacity(stderr.len());
    for line in stderr.split_inclusive('\n') {
        let (body, nl) = match line.strip_suffix('\n') {
            Some(b) => (b, "\n"),
            None => (line, ""),
        };
        let Some((head, tail)) = split_after_ratio(body) else {
            out.push_str(line);
            continue;
        };
        out.push_str(head);
        if let Some(fields) = tail.strip_prefix(", ") {
            // Non-terminal: `, <speed>`, `, <elapsed>`, `, <speed>, <elapsed>`.
            let fs: Vec<&str> = fields.split(", ").collect();
            let ok = match fs.as_slice() {
                [t] => is_xz_elapsed(t),
                [s, t] => is_xz_speed(s) && is_xz_elapsed(t),
                _ => false,
            };
            if ok {
                for f in fs {
                    out.push_str(", ");
                    out.push_str(if is_xz_elapsed(f) {
                        "<elapsed>"
                    } else {
                        "<speed>"
                    });
                }
            } else {
                out.push_str(tail);
            }
        } else if tail.starts_with(' ') {
            // Terminal: blanks, speed, blanks, time, blanks.
            let toks: Vec<&str> = tail.split_whitespace().collect();
            let mut mapped: Vec<&str> = Vec::new();
            let mut i = 0;
            let mut ok = true;
            while i < toks.len() {
                if i + 1 < toks.len() && is_xz_speed(&format!("{} {}", toks[i], toks[i + 1])) {
                    mapped.push("<speed>");
                    i += 2;
                } else if is_xz_elapsed(toks[i]) {
                    mapped.push("<elapsed>");
                    i += 1;
                } else {
                    ok = false;
                    break;
                }
            }
            if ok {
                for m in mapped {
                    out.push(' ');
                    out.push_str(m);
                }
            } else {
                out.push_str(tail);
            }
        } else {
            out.push_str(tail);
        }
        out.push_str(nl);
    }
    out
}

const ZSTD_LINKS: [&str; 3] = ["unzstd", "zstdcat", "zstdmt"];
/// The formats `zstd -vV`'s `*** supports:` line must name for the
/// `--format=` cases to have an oracle.
const ZSTD_SUPPORTS: [&str; 4] = ["gzip", "lz4", "lzma", "xz"];

/// Whether `<dir>/zstd` is release 1.5.7 (`-qV` prints exactly `1.5.7`) built
/// with gzip, lz4, lzma and xz support (the second line of `-vV`).
fn is_zstd_1_5_7(dir: &Path) -> bool {
    let run = |arg: &str| {
        output(
            Command::new(dir.join("zstd"))
                .arg(arg)
                .env_clear()
                .stdin(Stdio::null()),
        )
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
    };
    if run("-qV").is_none_or(|v| v.trim_end() != "1.5.7") {
        return false;
    }
    let Some(v) = run("-vV") else { return false };
    let Some(line) = v.lines().find_map(|l| l.strip_prefix("*** supports: ")) else {
        return false;
    };
    let have: Vec<&str> = line.split(',').map(str::trim).collect();
    ZSTD_SUPPORTS.iter().all(|w| have.contains(w))
}

/// `zstd` on `PATH`, like a shell's lookup.
fn zstd_on_path() -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join("zstd"))
        .find(|p| p.is_file())
}

/// The directory holding zstd 1.5.7's `zstd` and its links `unzstd`,
/// `zstdcat` and `zstdmt`.
///
/// Looked up in this order, the first one that [`is_zstd_1_5_7`] accepts
/// winning:
/// 1. `$STUFFR_ZSTD_REFERENCE`, the path of a `zstd` (CI builds the release
///    tarball there; if the three links are not beside it they are made in a
///    temp dir);
/// 2. Homebrew's keg, `/opt/homebrew/opt/zstd/bin`;
/// 3. `zstd` on `PATH`.
///
/// `None` when there is none: a skip with a note locally, a panic under `CI`
/// (the rule of [`require_reference`]), so every test that skips on it would
/// otherwise pass vacuously. Another release is no reference: stuffr
/// promises 1.5.7's behaviour.
pub fn zstd_dir() -> Option<&'static str> {
    static DIR: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    let found = DIR.get_or_init(|| {
        let candidates = [
            std::env::var_os("STUFFR_ZSTD_REFERENCE")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
            Some(PathBuf::from("/opt/homebrew/opt/zstd/bin/zstd")),
            zstd_on_path(),
        ];
        for exe in candidates.into_iter().flatten() {
            if !exe.is_file() {
                continue;
            }
            let Some(dir) = dir_with_links_for(&exe, "zstd", &ZSTD_LINKS) else {
                continue;
            };
            if is_zstd_1_5_7(&dir) {
                return dir.to_str().map(str::to_owned);
            }
        }
        None
    });
    match found {
        Some(d) => Some(d.as_str()),
        None => {
            assert!(
                std::env::var_os("CI").is_none(),
                "CI is set but there is no zstd 1.5.7 reference with gzip, lz4, lzma and xz \
                 support (looked at $STUFFR_ZSTD_REFERENCE, /opt/homebrew/opt/zstd/bin, PATH)"
            );
            eprintln!("skipped: zstd 1.5.7 not installed");
            None
        }
    }
}

/// Whether the reference zstd's liblz4 is 1.10.x, so its `--format=lz4` bytes
/// are the ones stuffr promises. `zstd -vV` does not print liblz4's version,
/// so this probes the one difference that matters: lz4 1.10.0 added a mid-way
/// level 2 (1.9.x, ubuntu's `liblz4-dev`, treats 2 as 1), so on compressible
/// text `--format=lz4 -1` and `-2` are the same bytes only on an old liblz4.
///
/// `false` locally is a skip of the `--format=lz4` byte rows with a note;
/// under `CI` it panics (the rule of [`require_reference`]): the
/// `zstd-reference` action builds liblz4 1.10.0 statically for this. `false`
/// without a reference at all (nothing to compare against).
pub fn zstd_lz4_is_1_10() -> bool {
    static OK: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *OK.get_or_init(|| {
        let Some(dir) = zstd_dir() else { return false };
        let data = text(300_000, 7);
        let at = |level: &str| -> Option<Vec<u8>> {
            let mut child = spawn(
                Command::new(Path::new(dir).join("zstd"))
                    .args(["-c", "-q", "--format=lz4", level])
                    .env_clear()
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null()),
            )
            .ok()?;
            let mut stdin = child.stdin.take()?;
            let feed = data.clone();
            let writer = std::thread::spawn(move || stdin.write_all(&feed));
            let out = child.wait_with_output().ok()?;
            let _ = writer.join();
            out.status.success().then_some(out.stdout)
        };
        let ok = matches!((at("-1"), at("-2")), (Some(a), Some(b)) if a != b);
        if !ok {
            assert!(
                std::env::var_os("CI").is_none(),
                "CI is set but the reference zstd's liblz4 is not 1.10.x (`--format=lz4` \
                 levels 1 and 2 give the same bytes, as liblz4 1.9 does): zstd must be \
                 linked against liblz4 1.10.0, as the zstd-reference action builds it"
            );
            eprintln!(
                "skipped: the reference zstd's liblz4 is not 1.10.x (--format=lz4 byte rows)"
            );
        }
        ok
    })
}

/// Replace the timing fields of zstd's `-vv` completion line, `<name> :
/// Completed in 0.01 sec  (cpu load : 100%)` (`fileio.c`), with `<elapsed>`
/// and `<cpu>`, and nothing else: they are the only part of zstd's
/// non-benchmark output that depends on how fast the run was. The sizes,
/// ratio and every other line stay as they are, and so does a "Completed in"
/// whose fields do not have exactly this shape.
///
/// 1.5.7 prints no transfer speed outside `-b`, which stuffr does not port
/// (R13), so there is none to hide.
pub fn normalise_zstd_progress(stderr: &str) -> String {
    const HEAD: &str = "Completed in ";
    const MID: &str = " sec  (cpu load : ";
    let mut out = String::with_capacity(stderr.len());
    for line in stderr.split_inclusive('\n') {
        let replaced = line.find(HEAD).and_then(|at| {
            let (before, rest) = line.split_at(at + HEAD.len());
            let (secs, rest) = rest.split_once(MID)?;
            let (cpu, after) = rest.split_once("%)")?;
            let (whole, frac) = secs.split_once('.')?;
            let digits = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
            (digits(whole) && digits(frac) && digits(cpu))
                .then(|| format!("{before}<elapsed>{MID}<cpu>%){after}"))
        });
        out.push_str(replaced.as_deref().unwrap_or(line));
    }
    out
}

/// The `--trace` line of `zstd -H` (`usageAdvanced`, under `#ifndef
/// ZSTD_NOTRACE`), verbatim from the 1.5.7 reference.
pub const ZSTD_TRACE_HELP: &str =
    "  --trace LOG                   Log tracing information to LOG.\n";

/// The benchmark section of `zstd -H` (`usageAdvanced`, under `#ifndef
/// ZSTD_NOBENCH`; the blank line before it is inside the `#ifndef`),
/// verbatim from the 1.5.7 reference.
pub const ZSTD_BENCH_HELP: &str = concat!(
    "\nBenchmark options:\n",
    "  -b#                           Perform benchmarking with compression level #. [Default: 3]\n",
    "  -e#                           Test all compression levels up to #; starting level is `-b#`. [Default: 1]\n",
    "  -i#                           Set the minimum evaluation to time # seconds. [Default: 3]\n",
    "  -B#                           Cut file into independent chunks of size #. [Default: No chunking]\n",
    "  -S                            Output one benchmark result per input file. [Default: Consolidated result]\n",
    "  -D dictionary                 Benchmark using dictionary \n",
    "  --priority=rt                 Set process priority to real-time.\n",
);

/// R13: what the port's `-H` differs from the reference's by. Homebrew's
/// zstd is built without `ZSTD_NOBENCH` and `ZSTD_NOTRACE`, so its `-H`
/// lists `--trace` and the benchmark section; the port answers as a build
/// with both defined does. This removes exactly [`ZSTD_TRACE_HELP`] and
/// [`ZSTD_BENCH_HELP`], each once and only when present whole, so any other
/// difference, including a half-removed section, still fails the comparison.
/// Output without them (`-h`, a version, an error) is returned unchanged.
pub fn strip_bench_help(stdout: &str) -> String {
    let mut s = stdout.to_owned();
    for block in [ZSTD_TRACE_HELP, ZSTD_BENCH_HELP] {
        if let Some(at) = s.find(block) {
            s.replace_range(at..at + block.len(), "");
        }
    }
    s
}

const LZ4_LINKS: [&str; 3] = ["unlz4", "lz4cat", "lz4c"];

/// Whether `<dir>/lz4`'s `-V` says release 1.10.0 (`*** lz4 v1.10.0 64-bit
/// multithread, by Yann Collet ***`).
fn is_lz4_1_10_0(dir: &Path) -> bool {
    output(
        Command::new(dir.join("lz4"))
            .arg("-V")
            .env_clear()
            .stdin(Stdio::null()),
    )
    .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("v1.10.0"))
}

/// `lz4` on `PATH`, like a shell's lookup.
fn lz4_on_path() -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join("lz4"))
        .find(|p| p.is_file())
}

/// The directory holding lz4 1.10.0's `lz4` and its links `unlz4`, `lz4cat`
/// and `lz4c`.
///
/// Looked up in this order, the first one that [`is_lz4_1_10_0`] accepts
/// winning:
/// 1. `$STUFFR_LZ4_REFERENCE`, the path of an `lz4` (CI builds the release
///    tarball there; if the three links are not beside it they are made in a
///    temp dir);
/// 2. Homebrew's keg, `/opt/homebrew/opt/lz4/bin`;
/// 3. `lz4` on `PATH`.
///
/// `None` when there is none: a skip with a note locally, a panic under `CI`
/// (the rule of [`require_reference`]), so every test that skips on it would
/// otherwise pass vacuously. Another release is no reference: stuffr
/// promises 1.10.0's behaviour.
pub fn lz4_dir() -> Option<&'static str> {
    static DIR: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    let found = DIR.get_or_init(|| {
        let candidates = [
            std::env::var_os("STUFFR_LZ4_REFERENCE")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
            Some(PathBuf::from("/opt/homebrew/opt/lz4/bin/lz4")),
            lz4_on_path(),
        ];
        for exe in candidates.into_iter().flatten() {
            if !exe.is_file() {
                continue;
            }
            let Some(dir) = dir_with_links_for(&exe, "lz4", &LZ4_LINKS) else {
                continue;
            };
            if is_lz4_1_10_0(&dir) {
                return dir.to_str().map(str::to_owned);
            }
        }
        None
    });
    match found {
        Some(d) => Some(d.as_str()),
        None => {
            assert!(
                std::env::var_os("CI").is_none(),
                "CI is set but there is no lz4 1.10.0 reference \
                 (looked at $STUFFR_LZ4_REFERENCE, /opt/homebrew/opt/lz4/bin, PATH)"
            );
            eprintln!("skipped: lz4 1.10.0 not installed");
            None
        }
    }
}

/// A `\r`-refreshed progress segment of lz4's display level 2 (probe, 1.10.0,
/// stderr a file): `\rRead : <n> MiB   ==> <ratio>%   ` while compressing,
/// `\rDecompressed : <n> MiB  ` while decoding. Returns its length when
/// `s` opens with exactly one such segment. `racy` accepts a decode refresh
/// that more blanks follow on its line (see [`normalise_lz4_progress`]).
fn lz4_refresh_len(s: &str, racy: bool) -> Option<usize> {
    let digits = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
    let rest = s.strip_prefix('\r')?;
    let end = rest.find(['\r', '\n']).unwrap_or(rest.len());
    let seg = &rest[..end];
    if let Some(r) = seg.strip_prefix("Read : ") {
        let ok = r.strip_suffix("%   ").is_some_and(|r| {
            r.split_once(" MiB   ==> ").is_some_and(|(n, ratio)| {
                digits(n)
                    && (matches!(ratio, "inf" | "nan")
                        || ratio
                            .split_once('.')
                            .is_some_and(|(w, f)| digits(w) && digits(f)))
            })
        });
        return ok.then_some(1 + end);
    }
    let r = seg.strip_prefix("Decompressed : ")?;
    if racy {
        // The refresh is one write, `\rDecompressed : N MiB  ` (two blanks).
        // The other thread prints the message in pieces (`...invalid frame`
        // then ` \n`), so a refresh can land between them and the line then
        // reads `frame\rDecompressed : 0 MiB   \n`: the blanks beyond the
        // refresh's two are the message's own trailing blank, and are kept.
        let n = r.find(" MiB  ")?;
        return digits(&r[..n]).then_some(1 + "Decompressed : ".len() + n + " MiB  ".len());
    }
    r.strip_suffix(" MiB  ")
        .is_some_and(digits)
        .then_some(1 + end)
}

/// Whether a stderr holds a failure message of the decoder, lz4's
/// `Error N : ...` or `Stream followed by undecodable data`. On a failing
/// decode the refresh is drawn by one thread while the other prints the
/// message in several writes, so the refresh may come before the message,
/// after it, inside it (`Error 26 : \rDecompressed : 0 MiB  LZ4F ...`) or
/// not at all: 60 runs of `lz4 -t` over a cut header gave four different
/// stderrs (probe, 2026-10-16).
fn lz4_failed(stderr: &str) -> bool {
    stderr.contains("Stream followed by undecodable data")
        || stderr.match_indices("Error ").any(|(at, _)| {
            let rest = &stderr[at + "Error ".len()..];
            let n = rest.bytes().take_while(u8::is_ascii_digit).count();
            n > 0 && rest[n..].starts_with(" : ")
        })
}

/// Deviation 2 of the lz4 family, and only it. Three things depend on timing
/// or on the machine and are replaced:
/// - a run of `\r`-refreshed progress segments ([`lz4_refresh_len`]) becomes
///   one `\r<progress>`: how many refreshes a run prints depends on its
///   speed. On a failing decode ([`lz4_failed`]) the refreshes are removed
///   instead: the reference itself draws them at random places or not at
///   all;
/// - the fields of `Done in S s ==> T MiB/s  (cpu load : L%)` become
///   `<s>`, `<speed>`, `<cpu>`;
/// - N in `Using N threads for compression ` becomes `<n>` (the cores).
///
/// Every other byte stays, including the final summary, the 79-blank
/// clearing line and a refresh-looking text of another shape (one not led
/// by `\r`, or with other numbers' syntax).
pub fn normalise_lz4_progress(stderr: &str) -> String {
    normalise_lz4(stderr, false)
}

/// [`normalise_lz4_progress`] for a run whose refreshes depend on whether
/// 200 ms passed between two files or frames (the gate's clock spans them): a
/// loaded machine can draw the second one on one side only, which collapsing
/// cannot absorb. Every refresh segment is removed, on both sides; nothing
/// else changes (the cleared line, the summaries and every other byte stay).
pub fn normalise_lz4_progress_without_refreshes(stderr: &str) -> String {
    normalise_lz4(stderr, true)
}

fn normalise_lz4(stderr: &str, drop_refreshes: bool) -> String {
    let racy = lz4_failed(stderr) || drop_refreshes;
    let mut collapsed = String::with_capacity(stderr.len());
    let mut rest = stderr;
    while !rest.is_empty() {
        if let Some(n) = lz4_refresh_len(rest, racy) {
            let mut total = n;
            while let Some(m) = lz4_refresh_len(&rest[total..], racy) {
                total += m;
            }
            if !racy {
                collapsed.push_str("\r<progress>");
            }
            rest = &rest[total..];
        } else {
            let ch = rest.chars().next().unwrap();
            collapsed.push(ch);
            rest = &rest[ch.len_utf8()..];
        }
    }
    let mut out = String::with_capacity(collapsed.len());
    for line in collapsed.split_inclusive('\n') {
        out.push_str(&normalise_lz4_line(line));
    }
    out
}

/// The per-line half of [`normalise_lz4_progress`].
fn normalise_lz4_line(line: &str) -> String {
    let digits = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
    let decimal = |t: &str| {
        t.split_once('.')
            .is_some_and(|(w, f)| digits(w) && digits(f))
    };
    if let Some(rest) = line.strip_prefix("Using ")
        && let Some((n, tail)) = rest.split_once(" threads for compression ")
        && digits(n)
    {
        return format!("Using <n> threads for compression {tail}");
    }
    if let Some(rest) = line.strip_prefix("Done in ")
        && let Some((secs, rest)) = rest.split_once(" s ==> ")
        && let Some((speed, rest)) = rest.split_once(" MiB/s  (cpu load : ")
        && let Some((cpu, after)) = rest.split_once("%)")
        && decimal(secs)
        && decimal(speed)
        && digits(cpu)
    {
        return format!("Done in <s> s ==> <speed> MiB/s  (cpu load : <cpu>%){after}");
    }
    line.to_owned()
}

/// The `Read :` refreshes of `stderr`, one list per run of consecutive
/// refreshes (one file's compression), each as (MiB, ratio text).
/// Decompression refreshes are not returned: their figures are the
/// reference's own race (deviation 2).
pub fn lz4_read_refreshes(stderr: &str) -> Vec<Vec<(u64, String)>> {
    let mut runs = Vec::new();
    let mut rest = stderr;
    let mut cur: Vec<(u64, String)> = Vec::new();
    while !rest.is_empty() {
        if let Some(n) = lz4_refresh_len(rest, false) {
            let seg = &rest[1..n];
            if let Some(r) = seg.strip_prefix("Read : ")
                && let Some((mib, tail)) = r.split_once(" MiB   ==> ")
                && let Some(ratio) = tail.strip_suffix("%   ")
            {
                cur.push((mib.parse().unwrap(), ratio.to_owned()));
            }
            rest = &rest[n..];
        } else {
            if !cur.is_empty() {
                runs.push(std::mem::take(&mut cur));
            }
            let ch = rest.chars().next().unwrap();
            rest = &rest[ch.len_utf8()..];
        }
    }
    if !cur.is_empty() {
        runs.push(cur);
    }
    runs
}

/// Deviation 2 leaves which refreshes are drawn to timing, not their
/// figures: in each run of refreshes, a `Read : N MiB` both sides drew must
/// show the same ratio. Runs are matched by position; the normalised stderr
/// comparison already checks that both sides have the same runs.
pub fn assert_lz4_read_figures(c: &Case, r: &Run, s: &Run) {
    let (rr, sr) = (lz4_read_refreshes(&r.stderr), lz4_read_refreshes(&s.stderr));
    for (i, (a, b)) in rr.iter().zip(&sr).enumerate() {
        for (mib, ratio) in a {
            if let Some((_, theirs)) = b.iter().find(|(m, _)| m == mib) {
                assert_eq!(
                    ratio, theirs,
                    "{} {:?}: refresh run {i} at {mib} MiB: reference {ratio}%, stuffr {theirs}%",
                    c.name, c.args
                );
            }
        }
    }
}

/// How much a failed lz4 decode had written is the reference's own race: it
/// decodes on one thread and writes on another, and the failure exits the
/// process, so what reached the output (stdout or the named file) is nothing,
/// or everything decoded before the failing block (probe, 2026-10-16:
/// `lz4 -d` over a frame with 1, 4 or 100 trailing bytes, or cut at its
/// checksum, left 0 or 8800 bytes of 8800, run to run, in the reference
/// alone). The comparison therefore accepts, in a run that failed the same
/// way (same nonzero exit code), a stdout or a file that is a prefix of the
/// other side's, by truncating both to the shorter. A run that succeeded, a
/// failure with different exit codes, and bytes that are not a prefix are
/// untouched, so every real difference is still reported.
pub fn tolerate_lz4_partial_output(c: &Case, r: &mut Run, s: &mut Run) {
    fn common(a: &mut Vec<u8>, b: &mut Vec<u8>) {
        if a.starts_with(b) || b.starts_with(a) {
            let n = a.len().min(b.len());
            a.truncate(n);
            b.truncate(n);
        }
    }
    // Only a decode (`-d`, `-t`, `--decompress`, `--test`, `unlz4`, `lz4cat`)
    // has the race, and only a failure that comes after data: every exit
    // but 1, and 1 only for "Stream followed by undecodable data". A
    // deterministic failure (usage, a missing file, `--list`) writes
    // what it writes, exactly.
    let flags = |a: &&str| {
        a.strip_prefix('-')
            .filter(|t| !t.starts_with('-'))
            .is_some_and(|t| {
                t.chars()
                    .take_while(char::is_ascii_lowercase)
                    .any(|ch| ch == 'd' || ch == 't')
            })
    };
    let decode = matches!(c.name, "unlz4" | "lz4cat")
        || c.args
            .iter()
            .take_while(|a| **a != "--")
            .any(|a| flags(a) || matches!(*a, "--decompress" | "--uncompress" | "--test"));
    let after_data = r.code != 1 || r.stderr.contains("Stream followed by undecodable data");
    if !decode || !after_data || r.code == 0 || r.code != s.code {
        return;
    }
    common(&mut r.stdout, &mut s.stdout);
    for (name, (rb, _, _)) in r.tree.iter_mut() {
        if let Some((sb, _, _)) = s.tree.get_mut(name) {
            common(rb, sb);
        }
    }
}

/// The two stream kinds lz4 reads and writes: a modern frame (`04 22 4d 18`)
/// or a legacy one (`02 21 4c 18`).
fn lz4_stream_kind(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(&[0x04, 0x22, 0x4d, 0x18]) {
        Some("frame")
    } else if b.starts_with(&[0x02, 0x21, 0x4c, 0x18]) {
        Some("legacy")
    } else {
        None
    }
}

/// A difference in the kind of stream two compressed outputs are, if either
/// is recognised. Within a kind the header is not compared: its descriptor
/// follows from the options, and byte identity is promised only where the
/// case says so.
fn lz4_kind_mismatch(reference: &[u8], ours: &[u8]) -> Option<String> {
    let (r, s) = (lz4_stream_kind(reference), lz4_stream_kind(ours));
    (r != s && (r.is_some() || s.is_some())).then(|| {
        format!(
            "stream format differs: reference lz4 {}, stuffr lz4 {}",
            r.unwrap_or("none"),
            s.unwrap_or("none")
        )
    })
}

/// The `lz4 -dc` options that make the reference read what `c` wrote: the
/// dictionary named by `-D file` or `-Dfile` (probe: both spellings work),
/// written from the case's own files to a scratch file (the reference does
/// not run in the case's directory). A file the case does not list (one its
/// setup makes) is not passed, and the reference then says why it cannot
/// decode.
fn lz4_decode_args(c: &Case) -> Vec<String> {
    let named = lz4_dictionary_name(c);
    let mut v = Vec::new();
    if let Some((_, bytes)) = named.and_then(|n| c.files.iter().find(|(f, _)| *f == n)) {
        static N: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "stuffr-lz4-dict-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&path, bytes).expect("write the dictionary for the reference");
        v.push("-D".to_owned());
        v.push(path.display().to_string());
    }
    v
}

/// How compressed output is judged when its bytes are not promised
/// identical, and which tool decodes it.
#[derive(Clone, Copy, Debug)]
pub enum Roundtrip {
    /// bzip2 streams (`BZh`, `.bz2`), decoded by the reference `bzip2 -dc`.
    Bzip2,
    /// gzip members (`1f 8b`, `.gz`/`.tgz`/`-S`), decoded by `ref_gzip -dc`
    /// (an absolute path). The header up to the end of FNAME is compared
    /// byte-for-byte.
    Gzip { ref_gzip: &'static str },
    /// xz streams (`fd 37 7a 58 5a 00`, `.xz`/`.txz`; `.lzma`/`.tlz` and raw
    /// by name or `-S`), decoded by `ref_xz -dc` (an absolute path), with
    /// `--format=lzma|raw` added as the case's arguments or invoked name
    /// ask. The stream header (magic, stream flags) is compared byte for
    /// byte.
    Xz { ref_xz: &'static str },
    /// zstd frames (`28 b5 2f fd`, `.zst`/`.tzst`; `--format=` gzip, xz, lzma
    /// and lz4 write theirs by name), decoded by `ref_zstd -dc` (an absolute
    /// path), which detects the format itself; a case's `-D` and
    /// `--patch-from` file is passed on (see `zstd_decode_args`). The kind of
    /// stream (the magic) is compared, not the frame's own header.
    Zstd { ref_zstd: &'static str },
    /// lz4 frames (`04 22 4d 18`) and legacy frames (`02 21 4c 18`), `.lz4`,
    /// decoded by `ref_lz4 -dc` (an absolute path), plus the case's `-D`
    /// dictionary (see `lz4_decode_args`). The kind of stream (the magic) is
    /// compared, not the frame's own header.
    Lz4 { ref_lz4: &'static str },
}

pub struct Case<'a> {
    /// The invoked name, e.g. `"bunzip2"`.
    pub name: &'a str,
    pub args: Vec<&'a str>,
    /// Created in the working directory before running.
    pub files: Vec<(&'a str, Vec<u8>)>,
    /// Fed to stdin: through a pipe, or, with `tty_stdin`, typed at the
    /// terminal (framed with `\n` if needed, then ^D). A canonical-mode line
    /// is limited by `MAX_CANON` (1024 bytes on macOS), so keep tty input to
    /// about 1 KiB of plain text with no control characters.
    pub stdin: Option<Vec<u8>>,
    pub tty_stdin: bool,
    pub tty_stdout: bool,
    /// Extra environment. The environment is otherwise cleared and only
    /// `PATH` and `LANG` are set, so `BZIP2`/`BZIP` never leak in.
    pub env: Vec<(&'a str, &'a str)>,
    /// Byte identity of compressed output is promised. When false, stuffr's
    /// compressed outputs are instead round-tripped through the reference.
    pub compare_output_bytes: bool,
    /// What a compressed stdout should decompress to, when that is not the
    /// stdin (or every input file concatenated in order).
    pub expect_stdout_plain: Option<Vec<u8>>,
    /// Run in the working directory after `files` are created and before the
    /// program starts: symlinks, hard links, permission changes.
    pub setup: Option<fn(&Path)>,
    /// Which compressed format the comparison understands.
    pub roundtrip: Roundtrip,
    /// `TZ` for both sides; `None` is `UTC`, so no run depends on the
    /// machine's zone (unzip's times are local).
    pub tz: Option<&'a str>,
    /// The unzip family's flavour (`apple`, `ubuntu`), given to stuffr's
    /// side only, as `STUFFR_UNZIP_FLAVOR`: a suite compares stuffr in the
    /// reference's flavour whatever the platform's default is, and the
    /// reference never sees the variable.
    pub unzip_flavour: Option<&'a str>,
}

/// File bytes, mode (permission bits) and mtime (seconds).
pub type Tree = BTreeMap<String, (Vec<u8>, u32, i64)>;

pub struct Run {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: String,
    pub tree: Tree,
    /// Unix seconds when this run began (before its inputs were created).
    pub start: i64,
}

pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Held across every spawn in the harness and in the suites that hold a
/// descriptor no child may have (take it with [`spawn_lock`], spawn with
/// [`spawn`] or [`output`]). A child being spawned gets a copy of every
/// descriptor the process has, close-on-exec ones included until its exec
/// closes them: a pty master between `openpty` and its close-on-exec flag,
/// or `compat_xz.rs`'s late FIFO writer, whose `close` is then not the
/// last one, so the FIFO's reader is not at its end yet.
static SPAWN_LOCK: Mutex<()> = Mutex::new(());

/// [`SPAWN_LOCK`], for a descriptor that must not reach any child: hold it
/// from the descriptor's open to its close.
pub fn spawn_lock() -> std::sync::MutexGuard<'static, ()> {
    SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// `cmd.spawn()` under [`SPAWN_LOCK`].
pub fn spawn(cmd: &mut Command) -> std::io::Result<std::process::Child> {
    let _guard = spawn_lock();
    cmd.spawn()
}

/// `cmd.output()` with the spawn under [`SPAWN_LOCK`]: standard output and
/// error captured, standard input as `cmd` sets it.
pub fn output(cmd: &mut Command) -> std::io::Result<std::process::Output> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    spawn(cmd)?.wait_with_output()
}

/// The program each run in flight is running, by the run's work directory
/// (`execute` registers it after the spawn and removes it once it ends).
static CHILDREN: Mutex<Vec<(PathBuf, u32)>> = Mutex::new(Vec::new());

/// The process id of the program a run in `work` is running, once
/// spawned: for a case's setup thread that has to act on that program
/// (`compat_xz.rs`'s late FIFO writer stops it while it writes).
pub fn child_of(work: &Path) -> Option<u32> {
    let children = CHILDREN.lock().unwrap_or_else(|e| e.into_inner());
    children
        .iter()
        .find(|(w, _)| w == work)
        .map(|&(_, pid)| pid)
}

/// Removes a run's [`CHILDREN`] entry when the run ends, a timeout's
/// panic included.
struct Registered(PathBuf);
impl Drop for Registered {
    fn drop(&mut self) {
        let mut children = CHILDREN.lock().unwrap_or_else(|e| e.into_inner());
        children.retain(|(w, _)| *w != self.0);
    }
}

/// A scratch directory path that removes itself (tree and all) when dropped,
/// a panicking test's unwind included. The directory is NOT created: callers
/// (and `interrupt_with_input_env`, which removes and recreates it between
/// attempts) make it themselves. Any stale tree at the path is removed first.
pub struct ScratchDir(PathBuf);
impl ScratchDir {
    pub fn at(path: PathBuf) -> Self {
        let _ = fs::remove_dir_all(&path);
        ScratchDir(path)
    }
}
impl std::ops::Deref for ScratchDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}
impl AsRef<Path> for ScratchDir {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}
impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "stuffr-harness-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("work")).unwrap();
        Scratch(d)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Whether the reference tool `exe` is installed. When it is not, print
/// `skipped: <tool> not installed` and return false — except on CI (the
/// `CI` environment variable is set), where a missing reference is a
/// failure: every test that skips on it would otherwise pass vacuously.
pub fn require_reference(exe: &Path) -> bool {
    if exe.exists() {
        return true;
    }
    assert!(
        std::env::var_os("CI").is_none(),
        "CI is set but the reference tool {} is not installed",
        exe.display()
    );
    eprintln!("skipped: {} not installed", exe.display());
    false
}

/// Run the reference tool `tool_dir/<name>`. `None` when it is missing (see
/// [`require_reference`], which panics instead on CI).
pub fn reference(tool_dir: &str, c: &Case) -> Option<Run> {
    let exe = Path::new(tool_dir).join(c.name);
    if !require_reference(&exe) {
        return None;
    }
    let s = Scratch::new();
    Some(execute(&exe, &s, c, false))
}

/// Run stuffr through a symlink named `c.name`.
pub fn stuffr_as(c: &Case) -> Run {
    let s = Scratch::new();
    let bin = s.0.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let link = bin.join(c.name);
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stuffr"), &link).unwrap();
    execute(&link, &s, c, true)
}

/// Run `exe` on case `c` in a fresh scratch directory, as the reference
/// (`stuffr_side` false) or as stuffr (true: the side that gets
/// [`Case::unzip_flavour`]). For the harness's own tests, which need to see
/// what each side is given (`/usr/bin/env` as the program).
pub fn run_program(exe: &Path, c: &Case, stuffr_side: bool) -> Run {
    let s = Scratch::new();
    execute(exe, &s, c, stuffr_side)
}

fn execute(exe: &Path, s: &Scratch, c: &Case, stuffr_side: bool) -> Run {
    let (code, stdout, stderr, start) = spawn_case(exe, s, c, stuffr_side);
    Run {
        code,
        stdout,
        stderr,
        tree: snapshot(&s.0.join("work")),
        start,
    }
}

/// Create the case's inputs in `s`'s work directory, run `exe` there, and
/// return its exit code (minus the signal number if one killed it),
/// standard output, normalised standard error and start time.
fn spawn_case(exe: &Path, s: &Scratch, c: &Case, stuffr_side: bool) -> (i32, Vec<u8>, String, i64) {
    let work = s.0.join("work");
    let start = now_secs();
    for (name, bytes) in &c.files {
        let p = work.join(name);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&p, bytes).unwrap();
        let f = fs::OpenOptions::new().write(true).open(&p).unwrap();
        f.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(INPUT_MTIME))
            .unwrap();
    }
    if let Some(setup) = c.setup {
        setup(&work);
    }

    let guard = spawn_lock();
    let mut cmd = Command::new(exe);
    cmd.args(&c.args)
        .current_dir(&work)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .env("TZ", c.tz.unwrap_or("UTC"))
        .envs(c.env.iter().copied());
    if stuffr_side && let Some(f) = c.unzip_flavour {
        cmd.env("STUFFR_UNZIP_FLAVOR", f);
    }

    let mut stdin_master: Option<std::fs::File> = None;
    if c.tty_stdin {
        let (m, sl) = openpty();
        cmd.stdin(Stdio::from(sl));
        stdin_master = Some(std::fs::File::from(m));
    } else if c.stdin.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    // The child's terminal: our copy of the slave stays open until the
    // child has exited, so the master never reads a hang-up (EIO) while
    // the child's last bytes are still queued (macOS drops them then;
    // 0.15.0's tag run). Everything the child wrote is queued once its
    // write returned, so after it exits one read to EAGAIN takes it all.
    let mut tty_out: Option<(std::fs::File, OwnedFd)> = None;
    if c.tty_stdout {
        let (m, sl) = openpty();
        let keep = sl.try_clone().expect("dup pty slave");
        cmd.stdout(Stdio::from(sl));
        set_nonblocking(&m);
        tty_out = Some((std::fs::File::from(m), keep));
    } else {
        cmd.stdout(Stdio::piped());
    }
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().unwrap_or_else(|e| panic!("spawn {exe:?}: {e}"));
    drop(cmd); // closes our copies of the pty slaves
    drop(guard);
    CHILDREN
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((work.clone(), child.id()));
    let registered = Registered(work.clone());

    let writer = if let Some(m) = &stdin_master {
        // Type the input, then end-of-file. Canonical mode honours ^D only at
        // the start of a line, so add a newline unless the data ends in one.
        let mut data = c.stdin.clone().unwrap_or_default();
        if !data.is_empty() && !data.ends_with(b"\n") {
            data.push(b'\n');
        }
        data.push(0x04);
        let mut m = m.try_clone().unwrap();
        Some(std::thread::spawn(move || {
            let _ = m.write_all(&data); // child may exit early
        }))
    } else {
        child.stdin.take().map(|mut si| {
            let data = c.stdin.clone().unwrap_or_default();
            std::thread::spawn(move || {
                let _ = si.write_all(&data); // child may exit early
            })
        })
    };
    let out_t = child.stdout.take().map(drain);
    let err_t = child.stderr.take().map(drain);

    let mut tty_buf = Vec::new();
    let deadline = Instant::now() + TIMEOUT;
    let status = loop {
        if let Some((m, _)) = &mut tty_out {
            read_available(m, &mut tty_buf);
        }
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{exe:?} {:?} timed out after {TIMEOUT:?}", c.args);
        }
        // A pty queues only a few KiB, so a child writing more is blocked
        // until we read: wait for the master to be readable (at most 2 ms),
        // not for a fixed sleep.
        if let Some((m, _)) = &tty_out {
            wait_readable(m, 2);
        } else {
            std::thread::sleep(Duration::from_millis(2));
        }
    };
    drop(registered);
    if let Some((mut m, keep)) = tty_out.take() {
        read_available(&mut m, &mut tty_buf);
        drop(keep);
    }
    // Deliberately not joined: a child that never reads the terminal leaves
    // the writer blocked once the pty buffer is full, and joining would hang
    // the test. Dropping the handle detaches it; the thread ends when the
    // master (and its clone) close or the write fails.
    drop(writer);
    let stdout = match out_t {
        Some(t) => t.join().unwrap(),
        None => tty_buf,
    };
    drop(stdin_master);
    let stderr_raw = err_t.map(|t| t.join().unwrap()).unwrap_or_default();

    let stderr = normalise_stderr(&stderr_raw, exe, c.name);

    let code = status
        .code()
        .unwrap_or_else(|| -status.signal().unwrap_or(0));
    (code, stdout, stderr, start)
}

/// The only normalisation: the program path becomes the bare invoked name.
/// Only a whole occurrence is replaced, one followed by `:`, whitespace or
/// the end of the text, so a longer path that merely starts with the
/// program path (`/x/bzip2.bak`) is left alone.
pub fn normalise_stderr(raw: &[u8], exe: &Path, name: &str) -> String {
    let text = String::from_utf8_lossy(raw);
    let path = exe.to_str().unwrap();
    let mut out = String::with_capacity(text.len());
    let mut rest: &str = &text;
    while let Some(i) = rest.find(path) {
        let after = &rest[i + path.len()..];
        let whole = after
            .chars()
            .next()
            .is_none_or(|c| c == ':' || c.is_whitespace());
        out.push_str(&rest[..i]);
        out.push_str(if whole { name } else { path });
        rest = after;
    }
    out.push_str(rest);
    out
}

/// Read to end-of-file on a worker thread. A pty master reports hang-up as
/// 0 on macOS and as `EIO` on Linux, and only those two count as end of file.
/// `Interrupted` is retried; anything else panics, so the `join().unwrap()`
/// surfaces it rather than handing back a silently truncated stream.
fn drain<R: Read + Send + 'static>(mut r: R) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut v = Vec::new();
        let mut buf = [0u8; 65536];
        loop {
            match r.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => v.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) if e.raw_os_error() == Some(libc::EIO) => break, // Linux hang-up
                Err(e) => panic!("read failed: {e}"),
            }
        }
        v
    })
}

/// Reads everything queued on a non-blocking descriptor, up to EAGAIN.
fn read_available(r: &mut std::fs::File, into: &mut Vec<u8>) {
    let mut buf = [0u8; 65536];
    loop {
        match r.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => into.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return,
            Err(e) if e.raw_os_error() == Some(libc::EIO) => return,
            Err(e) => panic!("read failed: {e}"),
        }
    }
}

/// Waits until `fd` is readable, at most `ms` milliseconds.
fn wait_readable(fd: &impl AsRawFd, ms: i32) {
    let mut p = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd; a failed or interrupted poll only shortens the wait.
    unsafe { libc::poll(&mut p, 1, ms) };
}

/// `O_NONBLOCK` on `fd`.
fn set_nonblocking(fd: &OwnedFd) {
    // SAFETY: valid descriptor; F_GETFL/F_SETFL take and return flags.
    unsafe {
        let fl = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
        assert!(fl >= 0, "fcntl: {}", std::io::Error::last_os_error());
        let rc = libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK);
        assert_eq!(rc, 0, "fcntl: {}", std::io::Error::last_os_error());
    }
}

// glibc declares these `const`, the BSDs and macOS declare them mutable.
#[cfg(any(target_os = "linux", target_os = "android"))]
const NULL_TERMIOS: *const libc::termios = std::ptr::null();
#[cfg(any(target_os = "linux", target_os = "android"))]
const NULL_WINSIZE: *const libc::winsize = std::ptr::null();
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const NULL_TERMIOS: *mut libc::termios = std::ptr::null_mut();
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const NULL_WINSIZE: *mut libc::winsize = std::ptr::null_mut();

/// Open a pty pair, close-on-exec on both ends.
fn openpty() -> (OwnedFd, OwnedFd) {
    let (mut m, mut s) = (0, 0);
    // SAFETY: out-pointers are valid; the null name/termios/winsize are allowed.
    let rc = unsafe {
        libc::openpty(
            &mut m,
            &mut s,
            std::ptr::null_mut(),
            NULL_TERMIOS,
            NULL_WINSIZE,
        )
    };
    assert_eq!(rc, 0, "openpty failed: {}", std::io::Error::last_os_error());
    // SAFETY: openpty returned two fresh descriptors we now own.
    let (m, s) = unsafe { (OwnedFd::from_raw_fd(m), OwnedFd::from_raw_fd(s)) };
    for fd in [&m, &s] {
        // SAFETY: valid descriptor.
        let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
        assert_eq!(rc, 0, "fcntl: {}", std::io::Error::last_os_error());
    }
    // Typed input must not echo into the master's read queue, and `\r` must
    // not turn into `\n`; canonical mode stays on so ^D means end of file.
    // SAFETY: `t` is fully initialised by a successful tcgetattr.
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        assert_eq!(libc::tcgetattr(s.as_raw_fd(), &mut t), 0);
        t.c_lflag &= !(libc::ECHO | libc::ECHONL);
        t.c_iflag &= !libc::ICRNL;
        assert_eq!(libc::tcsetattr(s.as_raw_fd(), libc::TCSANOW, &t), 0);
    }
    (m, s)
}

fn snapshot(work: &Path) -> Tree {
    let mut t = Tree::new();
    walk(work, work, &mut t);
    t
}

fn walk(root: &Path, dir: &Path, t: &mut Tree) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for p in entries {
        let md = fs::symlink_metadata(&p).unwrap();
        let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
        let mode = md.mode() & 0o7777;
        if md.is_dir() {
            // Directory mtimes move with every entry; record mode only.
            t.insert(format!("{rel}/"), (Vec::new(), mode, 0));
            walk(root, &p, t);
        } else if std::os::unix::fs::FileTypeExt::is_fifo(&md.file_type()) {
            // Never opened: a read would wait for a writer.
            t.insert(rel, (b"<fifo>".to_vec(), mode, md.mtime()));
        } else if md.file_type().is_symlink() {
            let target = fs::read_link(&p).unwrap();
            t.insert(
                rel,
                (
                    target.to_string_lossy().into_owned().into_bytes(),
                    mode,
                    md.mtime(),
                ),
            );
        } else {
            // A file the case made unreadable is recorded, not fatal.
            let bytes = fs::read(&p).unwrap_or_else(|_| b"<unreadable>".to_vec());
            t.insert(rel, (bytes, mode, md.mtime()));
        }
    }
}

fn is_bz2_name(n: &str) -> bool {
    n.ends_with(".bz2") || n.ends_with(".tbz2") || n.ends_with(".tbz")
}

/// Decompress with the reference `bzip2 -dc`; `Err` carries its stderr.
pub fn ref_decompress(data: &[u8]) -> Result<Vec<u8>, String> {
    ref_decompress_with(&Roundtrip::Bzip2, data)
}

/// Decompress with the reference tool `rt` names; `Err` carries its stderr.
pub fn ref_decompress_with(rt: &Roundtrip, data: &[u8]) -> Result<Vec<u8>, String> {
    ref_decompress_args(rt, &[], data)
}

/// Decompress for case `c`: as [`ref_decompress_with`], with the reference
/// told the stream format (and raw filter chain) `c` compressed with.
pub fn ref_decompress_case(c: &Case, data: &[u8]) -> Result<Vec<u8>, String> {
    let extra = match c.roundtrip {
        Roundtrip::Xz { .. } => xz_decode_args(c),
        Roundtrip::Zstd { .. } => zstd_decode_args(c),
        Roundtrip::Lz4 { .. } => lz4_decode_args(c),
        _ => Vec::new(),
    };
    ref_decompress_args(&c.roundtrip, &extra, data)
}

/// The `xz -dc` options that make the reference read what `c` wrote: the
/// last `--format`/`-F` (else `lzma` when `c` is invoked as `lzma`, `unlzma`
/// or `lzcat`), and for `raw` the filter options of `c`, since a raw stream
/// carries no header to say which chain it is.
fn xz_decode_args(c: &Case) -> Vec<String> {
    const FILTERS: [&str; 10] = [
        "--filters=",
        "--lzma1",
        "--lzma2",
        "--delta",
        "--x86",
        "--arm",
        "--powerpc",
        "--ia64",
        "--sparc",
        "--riscv",
    ];
    let mut format: Option<String> = match c.name {
        "lzma" | "unlzma" | "lzcat" => Some("lzma".into()),
        _ => None,
    };
    let mut filters: Vec<String> = Vec::new();
    let mut it = c.args.iter();
    while let Some(a) = it.next() {
        if *a == "--" {
            break;
        }
        let value = if let Some(v) = a.strip_prefix("--format=") {
            Some(v.to_owned())
        } else if *a == "--format" || *a == "-F" {
            it.next().map(|v| (*v).to_owned())
        } else {
            a.strip_prefix("-F")
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
        };
        if let Some(v) = value {
            format = Some(v);
        } else if FILTERS.iter().any(|f| a.starts_with(f)) {
            filters.push((*a).to_owned());
        }
    }
    let mut v = Vec::new();
    match format.as_deref() {
        Some("lzma" | "alone") => v.push("--format=lzma".to_owned()),
        Some("raw") => {
            v.push("--format=raw".to_owned());
            v.extend(filters);
        }
        _ => {}
    }
    v
}

fn ref_decompress_args(rt: &Roundtrip, extra: &[String], data: &[u8]) -> Result<Vec<u8>, String> {
    let (exe, what) = match rt {
        Roundtrip::Bzip2 => (Path::new(REFERENCE_DIR).join("bzip2"), "bzip2"),
        Roundtrip::Gzip { ref_gzip } => (PathBuf::from(ref_gzip), "gzip"),
        Roundtrip::Xz { ref_xz } => (PathBuf::from(ref_xz), "xz"),
        Roundtrip::Zstd { ref_zstd } => (PathBuf::from(ref_zstd), "zstd"),
        Roundtrip::Lz4 { ref_lz4 } => (PathBuf::from(ref_lz4), "lz4"),
    };
    let mut child = spawn(
        Command::new(exe)
            .arg("-dc")
            .args(extra)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )
    .map_err(|e| format!("cannot run reference {what}: {e}"))?;
    let mut si = child.stdin.take().unwrap();
    let data = data.to_vec();
    let w = std::thread::spawn(move || {
        let _ = si.write_all(&data);
    });
    let o = child.wait_with_output().map_err(|e| e.to_string())?;
    let _ = w.join();
    if o.status.success() {
        Ok(o.stdout)
    } else {
        Err(String::from_utf8_lossy(&o.stderr).into_owned())
    }
}

/// Whether `b` opens with the compressed-stream magic of `rt`.
fn has_magic(rt: &Roundtrip, b: &[u8]) -> bool {
    match rt {
        Roundtrip::Bzip2 => b.starts_with(b"BZh"),
        Roundtrip::Gzip { .. } => b.starts_with(&[0x1f, 0x8b]),
        Roundtrip::Xz { .. } => b.starts_with(&XZ_MAGIC),
        Roundtrip::Zstd { .. } => zstd_stream_kind(b).is_some(),
        Roundtrip::Lz4 { .. } => lz4_stream_kind(b).is_some(),
    }
}

/// Whether case `c` compresses to standard output in a format with no
/// magic (`.lzma`, raw), so its stdout is judged by decoding it as
/// [`xz_decode_args`] says, as `.xz` output is. A case compresses when it
/// is invoked as `xz` or `lzma` and no word before `--` is `-d`, `-t`,
/// `-l`, their long forms, or a short cluster holding one of them.
fn xz_magicless_stdout(c: &Case) -> bool {
    if !matches!(c.roundtrip, Roundtrip::Xz { .. }) || !matches!(c.name, "xz" | "lzma") {
        return false;
    }
    let decodes = c.args.iter().take_while(|a| **a != "--").any(|a| {
        matches!(*a, "--decompress" | "--uncompress" | "--test" | "--list")
            || (a.starts_with('-')
                && !a.starts_with("--")
                && a[1..].chars().any(|ch| matches!(ch, 'd' | 't' | 'l')))
    });
    !decodes && !xz_decode_args(c).is_empty()
}

/// The magic of an `.xz` stream header. `.lzma` and raw streams have none:
/// they are recognised by name (`is_compressed_name`) or by what the case
/// does ([`xz_magicless_stdout`]).
const XZ_MAGIC: [u8; 6] = [0xfd, b'7', b'z', b'X', b'Z', 0];

/// Which stream format `b` opens as, by the magics `zstd` reads and writes:
/// `zstd`, `gzip`, `xz`, `lzma` or `lz4`. `.lzma` has no magic; zstd's
/// `FIO_decompressFrames` takes a stream opening `5d 00` (the properties
/// byte of `lc=3 lp=0 pb=2` and a dictionary size's low byte, what
/// `lzma_alone_encoder` writes at every preset) for one, and so does this.
fn zstd_stream_kind(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Some("zstd")
    } else if b.starts_with(&[0x1f, 0x8b]) {
        Some("gzip")
    } else if b.starts_with(&XZ_MAGIC) {
        Some("xz")
    } else if b.starts_with(&[0x5d, 0x00]) {
        Some("lzma")
    } else if b.starts_with(&[0x04, 0x22, 0x4d, 0x18]) {
        Some("lz4")
    } else {
        None
    }
}

/// A difference in the kind of stream two compressed outputs are (zstd frame
/// against gzip member, say), if either is recognised. Within a kind the
/// frame header is not compared: its descriptor follows from the content and
/// the options, and byte identity is promised only where the case says so.
fn zstd_kind_mismatch(reference: &[u8], ours: &[u8]) -> Option<String> {
    let (r, s) = (zstd_stream_kind(reference), zstd_stream_kind(ours));
    (r != s && (r.is_some() || s.is_some())).then(|| {
        format!(
            "stream format differs: reference {}, stuffr {}",
            r.unwrap_or("none"),
            s.unwrap_or("none")
        )
    })
}

/// The `zstd -dc` options that make the reference read what `c` wrote: the
/// dictionary or patch-from file named by `-D`, `-Dfile`, `--patch-from=f` or
/// `--patch-from f`, written from the case's own files to a scratch file (the
/// reference does not run in the case's directory), and `--long=31` so a
/// frame written with a large window is not refused for its size. A file the
/// case does not list (one its setup makes) is not passed, and the reference
/// then says why it cannot decode.
fn zstd_decode_args(c: &Case) -> Vec<String> {
    let mut named: Option<&str> = None;
    let mut it = c.args.iter();
    while let Some(a) = it.next() {
        if *a == "--" {
            break;
        }
        if let Some(v) = a.strip_prefix("--patch-from=") {
            named = Some(v);
        } else if *a == "--patch-from" || *a == "-D" {
            named = it.next().copied();
        } else if !a.starts_with("--")
            && let Some(v) = a.strip_prefix("-D").filter(|v| !v.is_empty())
        {
            named = Some(v);
        }
    }
    let mut v = vec!["--long=31".to_owned()];
    if let Some((_, bytes)) = named.and_then(|n| c.files.iter().find(|(f, _)| *f == n)) {
        static N: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "stuffr-zstd-dict-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&path, bytes).expect("write the dictionary for the reference");
        v.push(format!("-D{}", path.display()));
    }
    v
}

/// The `--suffix` operand of `args` (`--suffix=X`, `--suffix X`), if any.
fn zstd_suffix<'a>(args: &[&'a str]) -> Option<&'a str> {
    let mut found = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if *a == "--" {
            break;
        }
        if let Some(v) = a.strip_prefix("--suffix=") {
            found = Some(v);
        } else if *a == "--suffix" {
            found = it.next().copied();
        }
    }
    found
}

/// The `-S`/`--suffix` operand of `args`, if any: `-S X`, `-SX`, `--suffix X`,
/// `--suffix=X` (or an abbreviation, `--su=X`), and `S` inside a short cluster
/// (`-kS .z`, `-kS.z`). A cluster's `b` takes the rest of it as its own
/// operand, so an `S` after it is not an option. Options after `--` are
/// operands and do not count. When several are given the last wins, as in
/// both references.
pub fn gzip_custom_suffix<'a>(args: &[&'a str]) -> Option<&'a str> {
    let mut found = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if *a == "--" {
            break;
        }
        // `--suffix` or any unambiguous abbreviation of it (`--su`), with
        // its operand inline or next.
        if let Some(long) = a.strip_prefix("--") {
            let (name, inline) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (long, None),
            };
            if name.len() >= 2 && "suffix".starts_with(name) {
                found = inline.or_else(|| it.next().copied()).or(found);
            }
            continue;
        }
        let Some(cluster) = a.strip_prefix('-').filter(|c| !c.starts_with('-')) else {
            continue;
        };
        for (i, ch) in cluster.char_indices() {
            match ch {
                'S' => {
                    let rest = &cluster[i + 1..];
                    found = if rest.is_empty() {
                        it.next().copied().or(found)
                    } else {
                        Some(rest)
                    };
                    break;
                }
                // `-b N`: the rest of the cluster (or the next word) is N.
                'b' => {
                    if i + 1 == cluster.len() {
                        it.next();
                    }
                    break;
                }
                _ => {}
            }
        }
    }
    found
}

/// The suffix case `c` compresses with: `-S` in its arguments, or in
/// `$GZIP`, whose words come first (Apple's `prepend_gzip`).
fn case_suffix<'a>(c: &Case<'a>) -> Option<&'a str> {
    let mut words: Vec<&'a str> = c
        .env
        .iter()
        .filter(|(k, _)| *k == "GZIP")
        .flat_map(|(_, v)| v.split([' ', '\t']).filter(|w| !w.is_empty()))
        .collect();
    words.extend(c.args.iter().copied());
    gzip_custom_suffix(&words)
}

/// Whether tree entry `n` is a compressed output of this case.
fn is_compressed_name(c: &Case, n: &str) -> bool {
    match c.roundtrip {
        Roundtrip::Bzip2 => is_bz2_name(n),
        Roundtrip::Gzip { .. } => {
            n.ends_with(".gz")
                || n.ends_with(".tgz")
                || case_suffix(c).is_some_and(|s| !s.is_empty() && n.ends_with(s))
        }
        Roundtrip::Xz { .. } => {
            [".xz", ".txz", ".lzma", ".tlz"]
                .iter()
                .any(|s| n.ends_with(s))
                || gzip_custom_suffix(&c.args).is_some_and(|s| !s.is_empty() && n.ends_with(s))
        }
        Roundtrip::Zstd { .. } => {
            [
                ".zst", ".tzst", ".gz", ".tgz", ".xz", ".txz", ".lzma", ".tlz", ".lz4",
            ]
            .iter()
            .any(|s| n.ends_with(s))
                || zstd_suffix(&c.args).is_some_and(|s| !s.is_empty() && n.ends_with(s))
        }
        Roundtrip::Lz4 { .. } => n.ends_with(".lz4"),
    }
}

/// Length of the gzip header through the end of FNAME (the NUL included), or
/// of the fixed 10 bytes plus FEXTRA when there is no FNAME. `None` when the
/// bytes are not a well-formed gzip header that far.
fn gzip_header_through_fname(b: &[u8]) -> Option<usize> {
    if b.len() < 10 || b[0] != 0x1f || b[1] != 0x8b {
        return None;
    }
    let flg = b[3];
    let mut at = 10;
    if flg & 0x04 != 0 {
        let xlen = u16::from_le_bytes([*b.get(at)?, *b.get(at + 1)?]) as usize;
        at += 2 + xlen;
        if at > b.len() {
            return None;
        }
    }
    if flg & 0x08 != 0 {
        let nul = b.get(at..)?.iter().position(|&x| x == 0)?;
        at += nul + 1;
    }
    Some(at)
}

/// Difference in the gzip header up to the end of FNAME, if any.
fn gzip_header_mismatch(reference: &[u8], ours: &[u8]) -> Option<String> {
    let (rl, sl) = (
        gzip_header_through_fname(reference),
        gzip_header_through_fname(ours),
    );
    match (rl, sl) {
        (Some(rl), Some(sl)) if reference[..rl] == ours[..sl] => None,
        (Some(rl), Some(sl)) => Some(format!(
            "gzip header (through FNAME) differs:\n    reference: {}\n    stuffr:    {}",
            describe_bytes(&reference[..rl]),
            describe_bytes(&ours[..sl])
        )),
        _ => Some(format!(
            "gzip header (through FNAME) unreadable: reference {}, stuffr {}",
            if rl.is_some() { "ok" } else { "malformed" },
            if sl.is_some() { "ok" } else { "malformed" }
        )),
    }
}

/// The original a compressed output named `name` should decompress to.
fn original_for(c: &Case, name: &str) -> Option<Vec<u8>> {
    let base = match c.roundtrip {
        Roundtrip::Bzip2 => name.strip_suffix(".bz2").map(str::to_owned).or_else(|| {
            name.strip_suffix(".tbz2")
                .or(name.strip_suffix(".tbz"))
                .map(|b| format!("{b}.tar"))
        })?,
        Roundtrip::Gzip { .. } => name
            .strip_suffix(".gz")
            .map(str::to_owned)
            .or_else(|| name.strip_suffix(".tgz").map(|b| format!("{b}.tar")))
            .or_else(|| {
                case_suffix(c)
                    .filter(|s| !s.is_empty())
                    .and_then(|s| name.strip_suffix(s))
                    .map(str::to_owned)
            })?,
        Roundtrip::Xz { .. } => name
            .strip_suffix(".xz")
            .or_else(|| name.strip_suffix(".lzma"))
            .map(str::to_owned)
            .or_else(|| {
                name.strip_suffix(".txz")
                    .or_else(|| name.strip_suffix(".tlz"))
                    .map(|b| format!("{b}.tar"))
            })
            .or_else(|| {
                gzip_custom_suffix(&c.args)
                    .filter(|s| !s.is_empty())
                    .and_then(|s| name.strip_suffix(s))
                    .map(str::to_owned)
            })?,
        Roundtrip::Zstd { .. } => [".zst", ".gz", ".xz", ".lzma", ".lz4"]
            .iter()
            .find_map(|s| name.strip_suffix(s))
            .map(str::to_owned)
            .or_else(|| {
                [".tzst", ".tgz", ".txz", ".tlz"]
                    .iter()
                    .find_map(|s| name.strip_suffix(s))
                    .map(|b| format!("{b}.tar"))
            })
            .or_else(|| {
                zstd_suffix(&c.args)
                    .filter(|s| !s.is_empty())
                    .and_then(|s| name.strip_suffix(s))
                    .map(str::to_owned)
            })
            // A name `-o` gave carries no suffix; the case's one file is
            // then its original (below).
            .unwrap_or_default(),
        // An explicit output name (`lz4 a x.lz4`) may carry no `.lz4`; the
        // case's one file is then its original (below).
        Roundtrip::Lz4 { .. } => name.strip_suffix(".lz4").unwrap_or_default().to_owned(),
    };
    let found = c.files.iter().find(|(n, _)| *n == base);
    if found.is_none() && matches!(c.roundtrip, Roundtrip::Lz4 { .. }) {
        return lz4_original(c, name, &base);
    }
    // An xz output named after a link the case's setup made (`l.xz` from
    // `l` -> `a`, or `a.xz` from `a` -> `a.xz`) has the case's one file as
    // its original.
    let only = match (c.roundtrip, c.files.as_slice()) {
        (Roundtrip::Xz { .. } | Roundtrip::Zstd { .. }, [one]) => Some(one),
        _ => None,
    };
    found.or(only).map(|(_, b)| b.clone())
}

/// [`original_for`] for an lz4 output not named after a case file. lz4's
/// outputs may be named anything (`lz4 a x.lz4`, `lz4 -f a o` over an
/// existing `o`, `lz4 - out`): `stdin.lz4` is standard input's (`lz4 -m e
/// stdin`); otherwise the case's one file that is neither this output (a
/// file it replaced) nor the `-D` dictionary, or, when there is none,
/// standard input.
fn lz4_original(c: &Case, name: &str, base: &str) -> Option<Vec<u8>> {
    if base == "stdin" {
        return c.stdin.clone();
    }
    let dict = lz4_dictionary_name(c);
    let mut rest = c
        .files
        .iter()
        .filter(|(n, _)| *n != name && Some(*n) != dict);
    match (rest.next(), rest.next()) {
        (Some((_, b)), None) => Some(b.clone()),
        (None, _) => c.stdin.clone(),
        _ => None,
    }
}

/// The file `-D FILE` or `-DFILE` names in `c`'s arguments.
fn lz4_dictionary_name<'a>(c: &Case<'a>) -> Option<&'a str> {
    let mut named = None;
    let mut it = c.args.iter();
    while let Some(a) = it.next() {
        if *a == "--" {
            break;
        }
        if *a == "-D" {
            named = it.next().copied();
        } else if !a.starts_with("--")
            && let Some(v) = a.strip_prefix("-D").filter(|v| !v.is_empty())
        {
            named = Some(v);
        }
    }
    named
}

fn describe_bytes(b: &[u8]) -> String {
    let head: Vec<String> = b.iter().take(32).map(|x| format!("{x:02x}")).collect();
    format!(
        "{} bytes [{}{}]",
        b.len(),
        head.join(" "),
        if b.len() > 32 { " ..." } else { "" }
    )
}

fn first_diff(a: &[u8], b: &[u8]) -> String {
    match a.iter().zip(b).position(|(x, y)| x != y) {
        Some(i) => format!("first difference at offset {i}"),
        None => "one is a prefix of the other".to_owned(),
    }
}

/// Both outputs are bzip2 streams (`BZh<N>`) and the block-size digits differ.
fn block_digit_mismatch(reference: &[u8], ours: &[u8]) -> Option<String> {
    if reference.len() > 3 && reference.starts_with(b"BZh") && ours.len() > 3 {
        let (r, s) = (reference[3], ours[3]);
        if r != s {
            return Some(format!(
                "block-size digit differs: reference {:?} vs stuffr {:?}",
                r as char, s as char
            ));
        }
    }
    None
}

/// An mtime pair is acceptable when equal; otherwise a copied input mtime
/// (`INPUT_MTIME`) must match exactly, and freshly created files must each
/// lie within a couple of seconds of their own run's wall-clock window.
fn mtime_ok(r: i64, r_start: i64, s: i64, s_start: i64, now: i64) -> bool {
    if r == s {
        return true;
    }
    let pinned = INPUT_MTIME as i64;
    if r == pinned || s == pinned {
        return false;
    }
    let within = |t: i64, start: i64| t >= start - 2 && t <= now + 2;
    within(r, r_start) && within(s, s_start)
}

fn tool_name(rt: &Roundtrip) -> &'static str {
    match rt {
        Roundtrip::Bzip2 => "bzip2",
        Roundtrip::Gzip { .. } => "gzip",
        Roundtrip::Xz { .. } => "xz",
        Roundtrip::Zstd { .. } => "zstd",
        Roundtrip::Lz4 { .. } => "lz4",
    }
}

/// The format-specific part of comparing two compressed streams whose bytes
/// are not promised identical: bzip2's block-size digit, or gzip's header
/// through FNAME.
fn stream_mismatch(rt: &Roundtrip, reference: &[u8], ours: &[u8]) -> Option<String> {
    match rt {
        Roundtrip::Bzip2 => block_digit_mismatch(reference, ours),
        Roundtrip::Gzip { .. } => gzip_header_mismatch(reference, ours),
        Roundtrip::Xz { .. } => xz_header_mismatch(reference, ours),
        Roundtrip::Zstd { .. } => zstd_kind_mismatch(reference, ours),
        Roundtrip::Lz4 { .. } => lz4_kind_mismatch(reference, ours),
    }
}

/// Difference in an `.xz` stream header's magic and stream flags (the first
/// eight bytes: they carry the check type), if both are `.xz` streams. The
/// header's CRC32 follows from them, so it is not compared.
fn xz_header_mismatch(reference: &[u8], ours: &[u8]) -> Option<String> {
    if !(reference.starts_with(&XZ_MAGIC) && ours.starts_with(&XZ_MAGIC)) {
        return None;
    }
    let (r, s) = (reference.get(..8)?, ours.get(..8)?);
    (r != s).then(|| {
        format!(
            "xz stream header differs:\n    reference: {}\n    stuffr:    {}",
            describe_bytes(r),
            describe_bytes(s)
        )
    })
}

/// Full comparison of `r` (reference) against `s` (stuffr). Panics with every
/// difference listed, not just the first.
pub fn assert_same(c: &Case, r: &Run, s: &Run) {
    let mut d: Vec<String> = Vec::new();
    if r.code != s.code {
        d.push(format!(
            "exit code: reference {} vs stuffr {}",
            r.code, s.code
        ));
    }
    if r.stderr != s.stderr {
        d.push(format!(
            "stderr differs:\n  reference: {:?}\n  stuffr:    {:?}",
            r.stderr, s.stderr
        ));
    }

    // stdout
    // Compressed output is judged by decoding only where the bytes differ
    // from the reference's: the same bytes need no judging, whether a
    // stream, text a magicless case also prints (`lzma --version`), or a
    // failed run's partial output.
    let compressed = r.stdout != s.stdout
        && (has_magic(&c.roundtrip, &s.stdout) || (!s.stdout.is_empty() && xz_magicless_stdout(c)));
    if c.compare_output_bytes || !compressed {
        if r.stdout != s.stdout {
            d.push(format!(
                "stdout differs ({}):\n  reference: {}\n  stuffr:    {}",
                first_diff(&r.stdout, &s.stdout),
                describe_bytes(&r.stdout),
                describe_bytes(&s.stdout)
            ));
        }
    } else {
        let want = c
            .expect_stdout_plain
            .clone()
            .or_else(|| c.stdin.clone())
            .unwrap_or_else(|| c.files.iter().flat_map(|(_, b)| b.clone()).collect());
        if let Some(e) = stream_mismatch(&c.roundtrip, &r.stdout, &s.stdout) {
            d.push(format!("stdout {e}"));
        }
        match ref_decompress_case(c, &s.stdout) {
            Ok(got) if got == want => {}
            Ok(got) => d.push(format!(
                "stdout round-trip mismatch: want {}, got {}",
                describe_bytes(&want),
                describe_bytes(&got)
            )),
            Err(e) => d.push(format!(
                "reference {} rejects stuffr's stdout: {e}",
                tool_name(&c.roundtrip)
            )),
        }
    }

    // tree
    let now = now_secs();
    let names: std::collections::BTreeSet<&String> = r.tree.keys().chain(s.tree.keys()).collect();
    for n in names {
        match (r.tree.get(n), s.tree.get(n)) {
            (Some(_), None) => d.push(format!(
                "tree: {n} removed in stuffr (exists in reference only)"
            )),
            (None, Some(_)) => d.push(format!("tree: {n} added in stuffr (exists in stuffr only)")),
            (Some((rb, rm, rt)), Some((sb, sm, st))) => {
                if rm != sm {
                    d.push(format!("tree: {n} mode reference {rm:o} vs stuffr {sm:o}"));
                }
                if !mtime_ok(*rt, r.start, *st, s.start, now) {
                    d.push(format!("tree: {n} mtime reference {rt} vs stuffr {st}"));
                }
                if rb == sb {
                    continue;
                }
                if !c.compare_output_bytes
                    && (is_compressed_name(c, n) || has_magic(&c.roundtrip, sb))
                {
                    if let Some(e) = stream_mismatch(&c.roundtrip, rb, sb) {
                        d.push(format!("tree: {n} {e}"));
                    }
                    match (ref_decompress_case(c, sb), original_for(c, n)) {
                        (Ok(got), Some(want)) if got == want => {}
                        (Ok(got), Some(want)) => d.push(format!(
                            "tree: {n} round-trip mismatch: want {}, got {}",
                            describe_bytes(&want),
                            describe_bytes(&got)
                        )),
                        (Ok(_), None) => d.push(format!(
                            "tree: {n} decompresses but its original is unknown"
                        )),
                        (Err(e), _) => d.push(format!(
                            "tree: reference {} rejects stuffr's {n}: {e}",
                            tool_name(&c.roundtrip)
                        )),
                    }
                } else {
                    d.push(format!(
                        "tree: {n} bytes differ ({}):\n  reference: {}\n  stuffr:    {}",
                        first_diff(rb, sb),
                        describe_bytes(rb),
                        describe_bytes(sb)
                    ));
                }
            }
            (None, None) => unreachable!(),
        }
    }

    if !d.is_empty() {
        panic!(
            "{} {:?}: stuffr differs from the reference in {} way(s):\n{}",
            c.name,
            c.args,
            d.len(),
            d.iter()
                .map(|x| format!(" - {x}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

// ---- peak memory of a streaming decoder ----

/// Run stuffr as `name` on `file` (written with `input`) in a scratch
/// directory, with only `env` in the environment; check it exits 0 having
/// printed exactly `plain` and nothing on standard error; return its peak
/// memory in bytes. Shared by 0.11.0's `bzcat_streams_a_large_input` and
/// 0.12.0's `zcat_streams_a_large_input` (Ruling P6).
///
/// - **Linux:** the largest `RssAnon` in `/proc/<pid>/status`, sampled
///   every 5 ms, counting only samples taken once `/proc/<pid>/exe` is the
///   stuffr binary. Not `getrusage`: there a child's `ru_maxrss` includes
///   the parent's resident set at spawn, and this test process holds the
///   64 MiB input and its copies (CI measured 264-268 MiB). Not `VmHWM`
///   either: it also counts file-backed pages, the touched part of a debug
///   binary of hundreds of MiB among them (CI measured 220-233 MiB). The
///   claim under test is that the decoder holds neither the input nor the
///   output, which is anonymous memory, flat after the first block, so
///   sampling loses nothing. Before the exec completes `/proc/<pid>` can
///   still describe the spawning test process (CI measured 155 MiB of
///   RssAnon that way). The status at the peak and a timeline are printed.
/// - **Elsewhere:** the child's own `ru_maxrss` from `wait4`
///   ([`wait_with_maxrss`]; bytes on macOS, which spawns without copying
///   the parent).
pub fn decoder_peak_rss(
    name: &str,
    file: &str,
    input: &[u8],
    plain: &[u8],
    env: &[(&str, &str)],
) -> u64 {
    let (st, got, err, peak) = peak_rss_run(name, &[file], file, input, env);
    assert!(st.success(), "{st:?}: {err}");
    assert_eq!(err, "");
    assert!(got == plain, "decoded output differs");
    peak
}

/// Run stuffr as `name ARGS` in a scratch directory holding `file`
/// (written with `input`), with only `env` in the environment; return its
/// wait status, standard output, standard error and peak memory in bytes,
/// measured as [`decoder_peak_rss`] describes. For a run expected to fail
/// (0.14.0's `window_limit_refuses_before_allocating`).
pub fn peak_rss_run(
    name: &str,
    args: &[&str],
    file: &str,
    input: &[u8],
    env: &[(&str, &str)],
) -> (std::process::ExitStatus, Vec<u8>, String, u64) {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "stuffr-rss-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("bin")).unwrap();
    let link = dir.join("bin").join(name);
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stuffr"), &link).unwrap();
    fs::write(dir.join(file), input).unwrap();
    let mut child = spawn(
        Command::new(&link)
            .args(args)
            .current_dir(&dir)
            .env_clear()
            .envs(env.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )
    .unwrap();
    let mut out = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut v = Vec::new();
        out.read_to_end(&mut v).unwrap();
        v
    });
    let mut errs = child.stderr.take().unwrap();
    let err_reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = errs.read_to_string(&mut s);
        s
    });
    #[cfg(target_os = "linux")]
    let peak = linux_rss_anon_peak(&mut child);
    #[cfg(target_os = "linux")]
    let st = child.wait().unwrap();
    #[cfg(not(target_os = "linux"))]
    let (st, peak) = wait_with_maxrss(child);
    let got = reader.join().unwrap();
    let err = err_reader.join().unwrap();
    let _ = fs::remove_dir_all(&dir);
    #[cfg(not(target_os = "linux"))]
    eprintln!("peak child RSS: {:.1} MiB", peak as f64 / 1048576.0);
    (st, got, err, peak)
}

/// Run stuffr as `name ARGS` in a scratch directory holding `file`
/// (written with `input`), with only `env` in the environment and, when
/// `limit` is given, its data segment capped at that many bytes
/// (`RLIMIT_DATA`: the heap and every private writable mapping, so an
/// allocation is refused even if it is never touched); return the exit
/// code (`None`: killed by a signal, e.g. the abort of a refused
/// allocation), standard output and standard error.
///
/// For a run too short to be sampled: [`decoder_peak_rss`] samples Linux's
/// `RssAnon` every 5 ms, and a decoder that refuses a hostile header exits
/// within a millisecond or two (CI run 39166896170: never sampled), while
/// `wait4`'s `ru_maxrss` counts the spawning test process (see there).
/// "Answers the same under a cap of N bytes as without one" bounds the
/// anonymous memory as the sampled peak would, deterministically.
#[cfg(target_os = "linux")]
pub fn data_limited_run(
    name: &str,
    args: &[&str],
    file: &str,
    input: &[u8],
    env: &[(&str, &str)],
    limit: Option<u64>,
) -> (Option<i32>, Vec<u8>, String) {
    use std::os::unix::process::CommandExt;
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "stuffr-rlimit-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("bin")).unwrap();
    let link = dir.join("bin").join(name);
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stuffr"), &link).unwrap();
    fs::write(dir.join(file), input).unwrap();
    let mut cmd = Command::new(&link);
    cmd.args(args)
        .current_dir(&dir)
        .env_clear()
        .envs(env.iter().copied())
        .stdin(Stdio::null());
    if let Some(limit) = limit {
        let rl = libc::rlimit {
            rlim_cur: limit as libc::rlim_t,
            rlim_max: limit as libc::rlim_t,
        };
        // SAFETY: the closure runs in the child between fork and exec and
        // only calls `setrlimit`, which is async-signal-safe, on a value
        // copied into it; it allocates nothing and takes no lock.
        unsafe {
            cmd.pre_exec(move || {
                if libc::setrlimit(libc::RLIMIT_DATA, &rl) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
    }
    let o = output(&mut cmd).unwrap();
    let _ = fs::remove_dir_all(&dir);
    (
        o.status.code(),
        o.stdout,
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

/// Reap `child` with `wait4`, which reports that child's own resource use:
/// its exit status and its peak resident set in bytes (`ru_maxrss`, which
/// Linux counts in KiB). Not `getrusage(RUSAGE_CHILDREN)`, the largest of
/// every child this test process has reaped, which the other tests of the
/// binary run alongside.
pub fn wait_with_maxrss(child: std::process::Child) -> (std::process::ExitStatus, u64) {
    let pid = child.id() as libc::pid_t;
    let mut status = 0;
    // SAFETY: `ru` is a valid out-pointer and `status` a valid int; wait4
    // only writes them, for this child, which is reaped here (`child` is
    // consumed, so nothing waits on it again).
    let ru = unsafe {
        let mut ru: libc::rusage = std::mem::zeroed();
        while libc::wait4(pid, &mut status, 0, &mut ru) != pid {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINTR)
            );
        }
        ru
    };
    let unit = if cfg!(target_os = "linux") { 1024 } else { 1 };
    (
        std::process::ExitStatus::from_raw(status),
        ru.ru_maxrss as u64 * unit,
    )
}

/// The sampling loop of [`decoder_peak_rss`] on Linux: until `child`
/// exits, the largest `RssAnon` seen while it is stuffr.
#[cfg(target_os = "linux")]
fn linux_rss_anon_peak(child: &mut std::process::Child) -> u64 {
    let status = format!("/proc/{}/status", child.id());
    let exe_link = format!("/proc/{}/exe", child.id());
    let stuffr_exe = fs::canonicalize(env!("CARGO_BIN_EXE_stuffr")).unwrap();
    let mut peak = 0u64;
    let mut at_peak = String::new();
    let mut timeline = Vec::new();
    let t0 = Instant::now();
    while child.try_wait().unwrap().is_none() {
        let is_stuffr = fs::read_link(&exe_link).is_ok_and(|e| e == stuffr_exe);
        if let Ok(s) = fs::read_to_string(&status)
            && let Some(kb) = s
                .lines()
                .find_map(|l| l.strip_prefix("RssAnon:"))
                .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
        {
            if timeline.len() < 40 {
                timeline.push(format!(
                    "{}ms:{}{}k",
                    t0.elapsed().as_millis(),
                    if is_stuffr { "" } else { "(not stuffr)" },
                    kb
                ));
            }
            if is_stuffr && kb * 1024 > peak {
                peak = kb * 1024;
                at_peak = s
                    .lines()
                    .filter(|l| {
                        l.starts_with("Name") || l.starts_with("Vm") || l.starts_with("Rss")
                    })
                    .collect::<Vec<_>>()
                    .join("; ");
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    eprintln!("RssAnon timeline: {}", timeline.join(" "));
    assert!(
        peak > 0,
        "RssAnon was never sampled while the process was stuffr"
    );
    eprintln!("/proc status at the peak: {at_peak}");
    eprintln!("peak RssAnon: {:.1} MiB", peak as f64 / 1048576.0);
    peak
}

// ---- deterministic test data (no RNG dependency) ----

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// `n` pseudo-random bytes from `seed` (nonzero).
pub fn random(n: usize, seed: u64) -> Vec<u8> {
    let mut r = XorShift(seed);
    (0..n).map(|_| (r.next() >> 24) as u8).collect()
}

const WORDS: &[&str] = &[
    "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog", "stuffr", "gzip", "member",
    "deflate", "header", "and", "of", "a", "to", "in", "file",
];

/// Plain text: words, spaces and newlines only (safe to type at a tty).
pub fn text(n: usize, seed: u64) -> Vec<u8> {
    let mut r = XorShift(seed);
    let mut v = Vec::with_capacity(n + 16);
    while v.len() < n {
        v.extend_from_slice(WORDS[(r.next() % WORDS.len() as u64) as usize].as_bytes());
        v.push(if r.next().is_multiple_of(9) {
            b'\n'
        } else {
            b' '
        });
    }
    v.truncate(n);
    v
}

/// Text interleaved with runs of random bytes and long repeats.
pub fn mixed(n: usize, seed: u64) -> Vec<u8> {
    let mut r = XorShift(seed);
    let mut v = Vec::with_capacity(n + 4096);
    while v.len() < n {
        match r.next() % 3 {
            0 => v.extend(text(2048, r.next())),
            1 => v.extend(random(512, r.next() | 1)),
            _ => v.extend(std::iter::repeat_n(b'z', (r.next() % 3000) as usize)),
        }
    }
    v.truncate(n);
    v
}

/// A short period repeated to `n` bytes.
pub fn repetitive(n: usize) -> Vec<u8> {
    b"abcabcabd".iter().copied().cycle().take(n).collect()
}

// ---- running a group of differential cases ----

/// Cases left out on this reference, and why: counted as known oracle
/// skips by [`run_group`].
pub struct Skipped {
    pub count: usize,
    pub why: String,
}

impl Skipped {
    pub fn none() -> Self {
        Skipped {
            count: 0,
            why: String::new(),
        }
    }

    /// Record `n` more skipped cases, for `why`.
    pub fn add(&mut self, n: usize, why: &str) {
        self.count += n;
        if !self.why.is_empty() {
            self.why.push_str("; ");
        }
        self.why.push_str(why);
    }
}

/// The text of a caught panic.
pub fn panic_text(p: Box<dyn std::any::Any + Send>) -> String {
    p.downcast_ref::<String>()
        .cloned()
        .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default()
}

/// Run `one` over every case, a few at a time, and fail once listing every
/// case that differed (`one` panics with the differences, or returns false
/// when the reference is absent). Prints "N of M cases compared" (M
/// includes the known oracle skips, which are named); on CI every case not
/// skipped for a known reason must have run.
pub fn run_group(
    group: &str,
    cases: &[Case],
    skipped: Skipped,
    one: &(dyn Fn(&Case) -> bool + Sync),
) {
    let run_one = |c: &Case| -> Result<bool, String> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| one(c))).map_err(panic_text)
    };
    let workers = std::thread::available_parallelism().map_or(2, |n| n.get().min(8));
    let next = AtomicUsize::new(0);
    let mut results: Vec<(usize, Result<bool, String>)> = std::thread::scope(|sc| {
        let hs: Vec<_> = (0..workers)
            .map(|_| {
                sc.spawn(|| {
                    let mut out = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(c) = cases.get(i) else { break out };
                        out.push((i, run_one(c)));
                    }
                })
            })
            .collect();
        hs.into_iter().flat_map(|h| h.join().unwrap()).collect()
    });
    results.sort_by_key(|(i, _)| *i);
    let mut failures = Vec::new();
    let mut ran = 0;
    for (_, r) in results {
        match r {
            Ok(true) => ran += 1,
            Ok(false) => {}
            Err(p) => failures.push(p),
        }
    }
    let total = cases.len() + skipped.count;
    if skipped.count > 0 {
        println!(
            "{group}: {ran} of {total} cases compared, {} skipped: {}",
            skipped.count, skipped.why
        );
    } else {
        println!("{group}: {ran} of {total} cases compared");
    }
    if std::env::var_os("CI").is_some() {
        assert_eq!(
            ran,
            cases.len(),
            "{group}: CI is set but only {ran} of {} cases were compared",
            cases.len()
        );
    }
    assert!(
        failures.is_empty(),
        "{group}: {} of {} cases differ:\n\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n\n")
    );
}

// ---- Apple's gzip ----

/// The Apple gzip release the BSD personality reproduces: what its usage
/// text and `-V` print.
pub const APPLE_GZIP_VERSION_LINE: &str = "Apple gzip 487.0.1";

/// The installed Apple gzip's `-V` line (on standard error), `None` when
/// it is absent.
pub fn apple_gzip_version_line() -> Option<&'static str> {
    static V: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    V.get_or_init(|| {
        let out = output(
            Command::new(Path::new(APPLE_GZIP_DIR).join("gzip"))
                .arg("-V")
                .env_clear()
                .stdin(Stdio::null()),
        )
        .ok()?;
        let text = String::from_utf8_lossy(&out.stderr).into_owned();
        text.lines().next().map(str::to_owned)
    })
    .as_deref()
}

/// The length of an Apple `print_ratio` token (`%5s%%`: spaces, an
/// optional `-`, digits, `.`, one digit, `%`) at the start of `b`.
fn apple_ratio_at(b: &[u8]) -> Option<usize> {
    let mut i = b.iter().take_while(|&&c| c == b' ').count();
    if b.get(i) == Some(&b'-') {
        i += 1;
    }
    let d = b[i..].iter().take_while(|c| c.is_ascii_digit()).count();
    if d == 0 {
        return None;
    }
    i += d;
    (b.get(i) == Some(&b'.')
        && b.get(i + 1).is_some_and(u8::is_ascii_digit)
        && b.get(i + 2) == Some(&b'%'))
    .then_some(i + 3)
}

/// Blank Apple's `-v` ratios, which count compressed bytes: at a line's
/// start (standard input's line) and after `name:\t\t  ` or `name:\t  `.
/// Everything else in the line is kept.
pub fn blank_apple_ratios(s: &str) -> String {
    s.split_inclusive('\n')
        .map(|line| {
            let at = line.find(":\t").map(|i| {
                let tabs = line[i + 1..].bytes().take_while(|&b| b == b'\t').count();
                i + 1 + tabs
            });
            let start = at.unwrap_or(0);
            match apple_ratio_at(&line.as_bytes()[start..]) {
                Some(n) => format!("{}<ratio>{}", &line[..start], &line[start + n..]),
                None => line.to_owned(),
            }
        })
        .collect()
}

/// Apple's gzip stores the current time for standard input that is not a
/// regular file. Where both runs' standard output hold a member header at
/// the same offset whose times differ, each within its own run's
/// wall-clock window, take the reference's time, so the rest is compared
/// byte for byte (on the compatible tier only the first member's header is
/// compared, at offset 0, which this covers).
pub fn mask_stdin_mtimes(r: &Run, s: &mut Run) {
    let now = now_secs();
    let within = |t: u32, start: i64| (start - 2..=now + 2).contains(&i64::from(t));
    let n = r.stdout.len().min(s.stdout.len());
    let magic = [0x1f, 0x8b, 0x08];
    let mut k = 0;
    while k + 8 <= n {
        if r.stdout[k..k + 3] == magic && s.stdout[k..k + 3] == magic {
            let t = |b: &[u8]| u32::from_le_bytes([b[k + 4], b[k + 5], b[k + 6], b[k + 7]]);
            let (rt, st) = (t(&r.stdout), t(&s.stdout));
            if rt != st && within(rt, r.start) && within(st, s.start) {
                s.stdout[k + 4..k + 8].copy_from_slice(&r.stdout[k + 4..k + 8]);
            }
        }
        k += 1;
    }
}

/// Run case `c` against Apple's gzip and stuffr and compare (panicking
/// with every difference). Normalised first, and nothing else:
///
/// - the installed reference's version line becomes
///   [`APPLE_GZIP_VERSION_LINE`] when another macOS ships another release,
///   so its usage text is still compared;
/// - stuffr's `-V`/`-L` first line names stuffr (Ruling T9-1): `Apple gzip
///   (stuffr X) 487.0.1` is read as `Apple gzip 487.0.1`, the rest compared;
/// - standard input's stored time ([`mask_stdin_mtimes`]);
/// - on the compatible tier only (`!c.compare_output_bytes`), `-v`'s
///   ratios (Ruling T9-2).
///
/// When the installed release is not [`APPLE_GZIP_VERSION_LINE`]'s, each
/// difference is prefixed with both releases.
///
/// False when the reference is absent (skip; panics instead under `CI`).
pub fn apple_compare(c: &Case) -> bool {
    let Some(mut r) = reference(APPLE_GZIP_DIR, c) else {
        return false;
    };
    let mut s = stuffr_as(c);
    if let Some(line) = apple_gzip_version_line()
        && line != APPLE_GZIP_VERSION_LINE
        && line.starts_with("Apple gzip ")
    {
        r.stderr = r.stderr.replace(line, APPLE_GZIP_VERSION_LINE);
    }
    let ours = format!("Apple gzip (stuffr {}) ", env!("CARGO_PKG_VERSION"));
    if s.stderr.contains(&ours) {
        assert!(
            r.stderr.contains(APPLE_GZIP_VERSION_LINE),
            "stuffr printed its version line, the reference {:?}",
            r.stderr
        );
        s.stderr = s.stderr.replacen(&ours, "Apple gzip ", 1);
    }
    mask_stdin_mtimes(&r, &mut s);
    if !c.compare_output_bytes {
        r.stderr = blank_apple_ratios(&r.stderr);
        s.stderr = blank_apple_ratios(&s.stderr);
    }
    // Another release on this macOS: every difference says so, since it
    // may be the release's and not stuffr's.
    match apple_gzip_version_line().filter(|l| *l != APPLE_GZIP_VERSION_LINE) {
        None => assert_same(c, &r, &s),
        Some(release) => {
            let same = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_same(c, &r, &s);
            }));
            if let Err(p) = same {
                panic!(
                    "[the reference is {release}; this suite targets {APPLE_GZIP_VERSION_LINE}, \
                     so this difference may be the release's]\n{}",
                    panic_text(p)
                );
            }
        }
    }
    true
}

// ---- gzip-family fixtures, built here so both sides read the same bytes ----

/// A gzip member's header fields; `magic2` is `0x8b`, or `0x9e` for the
/// old magic.
#[derive(Clone, Copy)]
pub struct Member<'b> {
    pub data: &'b [u8],
    pub name: Option<&'b [u8]>,
    pub mtime: u32,
    pub extra: Option<&'b [u8]>,
    pub comment: Option<&'b [u8]>,
    pub hcrc: bool,
    pub magic2: u8,
}

pub fn plain_member(data: &[u8]) -> Member<'_> {
    Member {
        data,
        name: None,
        mtime: 0,
        extra: None,
        comment: None,
        hcrc: false,
        magic2: 0x8b,
    }
}

pub fn crc32(b: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(b);
    c.sum()
}

pub fn deflate_raw(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(6));
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// One member, the header written by hand (RFC 1952) over flate2's raw
/// deflate; `crc`/`isize` override the trailer.
pub fn member_with(m: Member, crc: Option<u32>, isize: Option<u32>) -> Vec<u8> {
    let mut flg = 0u8;
    for (on, bit) in [
        (m.hcrc, 2),
        (m.extra.is_some(), 4),
        (m.name.is_some(), 8),
        (m.comment.is_some(), 16),
    ] {
        if on {
            flg |= bit;
        }
    }
    let mut v = vec![0x1f, m.magic2, 8, flg];
    v.extend_from_slice(&m.mtime.to_le_bytes());
    v.extend_from_slice(&[0, 3]);
    if let Some(e) = m.extra {
        v.extend_from_slice(&(e.len() as u16).to_le_bytes());
        v.extend_from_slice(e);
    }
    for f in [m.name, m.comment].into_iter().flatten() {
        v.extend_from_slice(f);
        v.push(0);
    }
    if m.hcrc {
        let c = (crc32(&v) & 0xffff) as u16;
        v.extend_from_slice(&c.to_le_bytes());
    }
    v.extend(deflate_raw(m.data));
    v.extend_from_slice(&crc.unwrap_or_else(|| crc32(m.data)).to_le_bytes());
    v.extend_from_slice(&isize.unwrap_or(m.data.len() as u32).to_le_bytes());
    v
}

pub fn member(m: Member) -> Vec<u8> {
    member_with(m, None, None)
}

/// A member storing `name`.
pub fn gzm(data: &[u8], name: &[u8]) -> Vec<u8> {
    member(Member {
        name: Some(name),
        ..plain_member(data)
    })
}

/// The old Unix `pack` format: a canonical Huffman code in pack's
/// layout (level `i` holds codes of length `i + 1`, internal nodes take
/// a level's smallest codes, EOB is the last leaf), as
/// `stuffr-formats`' own `pack.rs` tests encode it.
pub fn pack(data: &[u8]) -> Vec<u8> {
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let mut syms: Vec<usize> = (0..256).filter(|&b| freq[b] > 0).collect();
    if syms.is_empty() {
        syms.push(0);
    }
    let n = syms.len() + 1;
    let mut w: Vec<u64> = syms.iter().map(|&b| freq[b]).collect();
    w.push(0);
    let mut parent = vec![usize::MAX; 2 * n];
    let mut live: Vec<usize> = (0..n).collect();
    while live.len() > 1 {
        live.sort_by_key(|&i| std::cmp::Reverse((w[i], i)));
        let a = live.pop().unwrap();
        let b = live.pop().unwrap();
        let p = w.len();
        w.push(w[a] + w[b]);
        parent[a] = p;
        parent[b] = p;
        live.push(p);
    }
    let len: Vec<usize> = (0..n)
        .map(|i| {
            let (mut d, mut c) = (0, i);
            while parent[c] != usize::MAX {
                c = parent[c];
                d += 1;
            }
            d
        })
        .collect();
    let maxlen = *len.iter().max().unwrap();
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by_key(|&i| (len[i], i == n - 1, i));
    let mut count = vec![0usize; maxlen];
    for &i in &order {
        count[len[i] - 1] += 1;
    }
    let mut inodes = vec![0u32; maxlen];
    for l in (0..maxlen - 1).rev() {
        inodes[l] = (inodes[l + 1] + count[l + 1] as u32) / 2;
    }
    let mut code = vec![0u32; n];
    let mut at = vec![0u32; maxlen];
    for &i in &order {
        let l = len[i] - 1;
        code[i] = inodes[l] + at[l];
        at[l] += 1;
    }
    let mut out = vec![0x1f, 0x1e];
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.push(maxlen as u8);
    for (l, &c) in count.iter().enumerate() {
        out.push(if l + 1 == maxlen { c - 2 } else { c } as u8);
    }
    for &i in &order {
        if i != n - 1 {
            out.push(syms[i] as u8);
        }
    }
    let mut pos = [usize::MAX; 256];
    for (k, &b) in syms.iter().enumerate() {
        pos[b] = k;
    }
    let (mut acc, mut nb) = (0u32, 0u32);
    let mut put = |c: u32, l: usize, out: &mut Vec<u8>| {
        for bit in (0..l).rev() {
            acc = (acc << 1) | ((c >> bit) & 1);
            nb += 1;
            if nb == 8 {
                out.push(acc as u8);
                acc = 0;
                nb = 0;
            }
        }
    };
    for &b in data {
        let k = pos[b as usize];
        put(code[k], len[k], &mut out);
    }
    put(code[n - 1], len[n - 1], &mut out);
    if nb > 0 {
        out.push((acc << (8 - nb)) as u8);
    }
    out
}

/// A zip entry: method 0 (stored) or 8 (deflated); any other method's
/// data is the plain bytes (GNU refuses those before reading). With
/// flag 8 the sizes and CRC follow in a signed data descriptor.
pub struct ZipEntry<'b> {
    pub name: &'b [u8],
    pub data: &'b [u8],
    pub method: u16,
    pub flags: u16,
}

/// [`zip_with`] at MS-DOS defaults (made by version 2.0 on MS-DOS, no
/// attributes, no time, no extra fields, no comment).
pub fn zip(entries: &[ZipEntry]) -> Vec<u8> {
    let specs: Vec<ZipEntrySpec> = entries
        .iter()
        .map(|e| ZipEntrySpec {
            method: e.method,
            flags: e.flags,
            version_made_by: 20,
            external_attr: 0,
            dos_time: 0,
            ..ZipEntrySpec::new(e.name, e.data)
        })
        .collect();
    zip_with(&specs, b"", b"")
}

/// One entry of [`zip_with`]: every header field a test may want to set.
#[derive(Clone, Copy)]
pub struct ZipEntrySpec<'a> {
    pub name: &'a [u8],
    /// The plain bytes: their CRC-32 and length go in the headers, and
    /// they are the entry's data unless `stored_data` is given.
    pub data: &'a [u8],
    pub method: u16,
    /// General-purpose flags. Bit 3 moves the CRC and sizes into a signed
    /// data descriptor after the data (zeros in the local header).
    pub flags: u16,
    /// The central header's "version made by" (high byte: the host, 3 =
    /// Unix, 0 = MS-DOS; low byte: the version, 30 = 3.0).
    pub version_made_by: u16,
    /// The central header's external attributes (Unix: the mode << 16).
    pub external_attr: u32,
    /// MS-DOS time in the low 16 bits, date in the high 16.
    pub dos_time: u32,
    /// The extra field, written in both the local and the central header.
    pub extra: &'a [u8],
    /// The entry's data as stored, for a method other than 0 and 8 (or a
    /// damaged or encrypted body): used verbatim. `None`: method 8
    /// deflates `data` (flate2), any other method stores `data` as is.
    pub stored_data: Option<&'a [u8]>,
}

/// 2020-01-02 03:04:06 as an MS-DOS time and date ([`ZipEntrySpec::new`]'s).
pub const DOS_TIME_2020: u32 =
    ((((2020 - 1980) << 9) | (1 << 5) | 2) << 16) | (3 << 11) | (4 << 5) | 3;

impl<'a> ZipEntrySpec<'a> {
    /// A stored entry made on Unix by Zip 3.0, mode 0644, dated
    /// [`DOS_TIME_2020`], no extra field. unzip takes a name ending in `/`
    /// for a directory and its mode from `external_attr`, so give such an
    /// entry a directory's (`0o40755 << 16`).
    pub fn new(name: &'a [u8], data: &'a [u8]) -> Self {
        ZipEntrySpec {
            name,
            data,
            method: 0,
            flags: 0,
            version_made_by: 0x031e,
            external_attr: 0o100644 << 16,
            dos_time: DOS_TIME_2020,
            extra: b"",
            stored_data: None,
        }
    }
}

/// A zip archive of `entries`, with the archive `comment`, after
/// `preamble` (a self-extractor stub, say). Offsets count from the end of
/// the preamble, as `cat stub a.zip` leaves them (no `zip -A`), so unzip
/// warns about the extra bytes at the beginning. Version needed is 2.0 for
/// every entry. No Zip64: every size and count must fit its field.
pub fn zip_with(entries: &[ZipEntrySpec], comment: &[u8], preamble: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    let u16_of = |n: usize| u16::try_from(n).expect("no Zip64 in zip_with");
    let u32_of = |n: usize| u32::try_from(n).expect("no Zip64 in zip_with");
    for e in entries {
        let body = match e.stored_data {
            Some(b) => b.to_vec(),
            None if e.method == 8 => deflate_raw(e.data),
            None => e.data.to_vec(),
        };
        let crc = crc32(e.data);
        let dd = e.flags & 8 != 0;
        let offset = u32_of(out.len());
        let (csize, usize_) = (u32_of(body.len()), u32_of(e.data.len()));
        let (time, date) = ((e.dos_time & 0xffff) as u16, (e.dos_time >> 16) as u16);
        let (lcrc, lc, lu) = if dd { (0, 0, 0) } else { (crc, csize, usize_) };
        out.extend_from_slice(b"PK\x03\x04");
        for v in [20u16, e.flags, e.method, time, date] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for v in [lcrc, lc, lu] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&u16_of(e.name.len()).to_le_bytes());
        out.extend_from_slice(&u16_of(e.extra.len()).to_le_bytes());
        out.extend_from_slice(e.name);
        out.extend_from_slice(e.extra);
        out.extend_from_slice(&body);
        if dd {
            out.extend_from_slice(b"PK\x07\x08");
            for v in [crc, csize, usize_] {
                out.extend_from_slice(&v.to_le_bytes());
            }
        }
        central.extend_from_slice(b"PK\x01\x02");
        for v in [e.version_made_by, 20, e.flags, e.method, time, date] {
            central.extend_from_slice(&v.to_le_bytes());
        }
        for v in [crc, csize, usize_] {
            central.extend_from_slice(&v.to_le_bytes());
        }
        // name, extra, comment lengths, disk number, internal attributes
        for v in [u16_of(e.name.len()), u16_of(e.extra.len()), 0, 0, 0] {
            central.extend_from_slice(&v.to_le_bytes());
        }
        central.extend_from_slice(&e.external_attr.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(e.name);
        central.extend_from_slice(e.extra);
    }
    let cd_at = u32_of(out.len());
    let cd_len = u32_of(central.len());
    out.extend(central);
    out.extend_from_slice(b"PK\x05\x06");
    let n = u16_of(entries.len());
    for v in [0u16, 0, n, n] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&cd_len.to_le_bytes());
    out.extend_from_slice(&cd_at.to_le_bytes());
    out.extend_from_slice(&u16_of(comment.len()).to_le_bytes());
    out.extend_from_slice(comment);
    let mut whole = preamble.to_vec();
    whole.extend(out);
    whole
}

pub fn zip1(data: &[u8], method: u16, flags: u16) -> Vec<u8> {
    zip(&[ZipEntry {
        name: b"plain",
        data,
        method,
        flags,
    }])
}

pub fn filter_through(exe: &str, args: &[&str], data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    if !require_reference(Path::new(exe)) {
        return None;
    }
    let mut child = spawn(
        Command::new(exe)
            .args(args)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped()),
    )
    .unwrap();
    let mut si = child.stdin.take().unwrap();
    let d = data.to_vec();
    let w = std::thread::spawn(move || {
        let _ = si.write_all(&d);
    });
    let out = child.wait_with_output().unwrap();
    w.join().unwrap();
    assert!(out.status.success(), "{exe} {args:?}");
    Some(out.stdout)
}

/// `data` compressed by stuffr's own `id` codec (`bzip2`, `xz`, `lzip`,
/// `compress`), at `level` or the format's default: inputs for the foreign
/// formats a `gunzip` reads, with no tool beyond the reference needed.
pub fn stuffr_encode(id: &'static str, data: &[u8], level: Option<i32>) -> Vec<u8> {
    let codec = stuffr::registry()
        .codec(stuffr::FormatId::new(id))
        .unwrap_or_else(|| panic!("{id} is not in this build"));
    let buf = stuffr::testing::SharedBuf::new();
    let opts = stuffr::EncodeOpts {
        level,
        ..Default::default()
    };
    let mut sink = codec.encoder(Box::new(buf.clone()), &opts).unwrap();
    sink.write_all(data).unwrap();
    sink.finish().unwrap();
    buf.contents()
}

// ---- zstd training material (0.14.0 Task 8) ----

/// 100 small JSON records, one per file under `samples/`: dibio.c's
/// one-sample-per-file training set, small enough that libzstd trains
/// in a few milliseconds (its own progress lines are timed by CPU
/// clock and stay silent below 0.15 s).
pub fn zstd_samples() -> Vec<(&'static str, Vec<u8>)> {
    static S: std::sync::OnceLock<Vec<(&'static str, Vec<u8>)>> = std::sync::OnceLock::new();
    S.get_or_init(|| {
        const WORDS: [&str; 24] = [
            "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota",
            "kappa", "lambda", "mu", "nu", "xi", "omicron", "pi", "rho", "sigma", "tau",
            "upsilon", "phi", "chi", "psi", "omega",
        ];
        let mut x: u32 = 12345;
        let mut rnd = move || {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345) & 0x7fff_ffff;
            x >> 8
        };
        (0..100)
            .map(|i| {
                let n = 20 + rnd() % 60;
                let body: Vec<&str> = (0..n).map(|_| WORDS[(rnd() % 24) as usize]).collect();
                let user = rnd() % 50;
                let status = ["ok", "fail", "pending"][(rnd() % 3) as usize];
                let rec = format!(
                    "{{\"id\":{i},\"user\":\"user{user}\",\"status\":\"{status}\",\"text\":\"{}\"}}\n",
                    body.join(" ")
                );
                (&*Box::leak(format!("samples/s{i:03}.json").into_boxed_str()), rec.into_bytes())
            })
            .collect()
    })
    .clone()
}

/// The reference's own dictionary over the samples, 4 KiB, written to
/// a scratch file (`None` without a reference).
pub fn zstd_trained_dictionary() -> Option<&'static [u8]> {
    static D: std::sync::OnceLock<Option<Vec<u8>>> = std::sync::OnceLock::new();
    D.get_or_init(|| {
        zstd_dir()?;
        let dir = ScratchDir::at(
            std::env::temp_dir().join(format!("stuffr-zstd-dict-{}", std::process::id())),
        );
        fs::create_dir_all(dir.join("samples")).unwrap();
        let mut args = vec!["-q".to_string(), "--train".into(), "--maxdict=4K".into()];
        for (n, b) in zstd_samples() {
            let p = dir.join(n);
            fs::write(&p, b).unwrap();
            args.push(p.to_str().unwrap().to_string());
        }
        let out = dir.join("dict");
        args.push("-o".into());
        args.push(out.to_str().unwrap().to_string());
        let st = std::process::Command::new(Path::new(zstd_dir()?).join("zstd"))
            .args(&args)
            .env_clear()
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(st.success());
        Some(fs::read(&out).unwrap())
    })
    .as_deref()
}
