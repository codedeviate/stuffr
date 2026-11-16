//! Interrupting a native write (bug hunt 2026-11-15, finding 10): the
//! hidden `.PID.N.NAME.tmp` an output is written through is removed when
//! SIGINT, SIGTERM or SIGHUP ends the run, and the process still dies of
//! the signal. Unix only.
//!
//! Not timing-dependent: the signal is sent only once the temp is on disk,
//! and the library creates and arms it with the signals held back, so a
//! signal that lands then always finds it armed. A run that finished before
//! the signal reached it is a miss, retried with a larger input (the
//! pattern of `tests/compat_harness/interrupt.rs`).
#![cfg(unix)]

use crate::common::*;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// Interrupt tests run one at a time: each keeps a CPU busy on purpose.
static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `mib` MiB that bzip2 cannot compress (xorshift), so its run is long.
fn incompressible(path: &Path, mib: usize) {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut v = Vec::with_capacity(mib << 20);
    while v.len() < mib << 20 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.extend_from_slice(&x.to_le_bytes());
    }
    std::fs::write(path, v).unwrap();
}

fn entries(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// Spawns `stuffr pack IN -o OUT` (`out_name` in `dir`), waits for its temp
/// to appear, sends `sig`; `None` when the run ended before the signal.
fn interrupt_pack(dir: &Path, out_name: &str, sig: i32) -> Option<(ExitStatus, Vec<String>)> {
    let input = dir.join("big");
    let output = dir.join(out_name);
    let mut cmd = Command::new(STUFFR);
    cmd.args([
        "pack",
        input.to_str().unwrap(),
        "-o",
        output.to_str().unwrap(),
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            for s in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
                libc::signal(s, libc::SIG_DFL);
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().unwrap();
    let suffix = format!(".{out_name}.tmp");
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if child.try_wait().unwrap().is_some() {
            return None;
        }
        if entries(dir)
            .iter()
            .any(|n| n.starts_with('.') && n.ends_with(&suffix))
        {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("stuffr pack never created its temp");
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    // SAFETY: kill on a child we spawned and have not reaped.
    unsafe { libc::kill(child.id() as i32, sig) };
    let hang_at = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        if Instant::now() >= hang_at {
            let _ = child.kill();
            let _ = child.wait();
            panic!("stuffr pack hung after signal {sig}");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    if status.success() {
        // Finished between the check and the signal: a miss.
        return None;
    }
    // Killed after the publish (directory fsync, summary line): the output
    // is complete and in place, and the run still dies of the signal. Also
    // a miss, to retry with more input (task 2 review, M1).
    if dir.join(out_name).exists() {
        return None;
    }
    Some((status, entries(dir)))
}

fn check(out_name: &str, sig: i32) {
    let _one = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tmp_dir();
    for mib in [8, 32, 128] {
        for name in entries(&dir) {
            std::fs::remove_file(dir.join(name)).unwrap();
        }
        incompressible(&dir.join("big"), mib);
        let Some((status, left)) = interrupt_pack(&dir, out_name, sig) else {
            continue;
        };
        assert_eq!(
            status.signal(),
            Some(sig),
            "the run must die of the signal: {status:?}"
        );
        assert_eq!(
            left,
            vec!["big".to_string()],
            "the temp (and no output) must be gone after signal {sig}"
        );
        return;
    }
    panic!("every attempt finished before signal {sig} reached it");
}

#[test]
fn sigint_removes_a_single_stream_temp() {
    check("out.bz2", libc::SIGINT);
}

#[test]
fn sigterm_removes_a_single_stream_temp() {
    check("out.bz2", libc::SIGTERM);
}

#[test]
fn sighup_removes_a_single_stream_temp() {
    check("out.bz2", libc::SIGHUP);
}

#[test]
fn sigterm_removes_a_container_temp() {
    check("out.tar.bz2", libc::SIGTERM);
}
