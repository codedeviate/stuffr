//! Pins the fresh-destination mode ruling (C2, revised by HOST-1) in
//! isolation: `umask` is a process-global setting, not a
//! per-thread one, so a test that changes it cannot safely share a process
//! with any other test that creates files and cares about the mode it gets —
//! which is most of `ops_compress.rs`. Cargo gives each file under `tests/`
//! its own process, so this one lives alone.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use stuffr::ops::{CompressOpts, Input, Output, compress};

unsafe extern "C" {
    #[link_name = "umask"]
    fn libc_umask(mode: u32) -> u32;
}

fn tmp(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("stuffr-umask-{}-{}", std::process::id(), name));
    p
}

/// Ruling C2 said a fresh destination lands at `0o666 & !umask`, what
/// `File::create` produces. Security audit HOST-1 replaced it for a
/// regular-file input: the output takes the INPUT's mode exactly, as gzip,
/// bzip2, xz and zstd do, and that copy is not masked by the umask either
/// (theirs is not). Only a stream input (stdin) still gets the umask
/// default. This file keeps its own process because it sets the umask.
#[test]
fn a_fresh_destination_takes_the_inputs_mode_not_the_umask() {
    let src = tmp("in.txt");
    let dst = tmp("out.gz");
    let _ = std::fs::remove_file(&dst);
    std::fs::write(&src, b"payload").unwrap();
    std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o666)).unwrap();

    // A concrete umask that would clear bits of the input's mode. Safe here
    // specifically because this file has no other test to race against.
    let old_umask = unsafe { libc_umask(0o022) };

    let result = compress(
        Input::Path(src.clone()),
        Output::Path(dst.clone()),
        &CompressOpts::default(),
    );

    unsafe {
        libc_umask(old_umask);
    }
    result.unwrap();

    let mode = std::fs::metadata(&dst).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o666,
        "a fresh destination takes the input's mode exactly, as gzip does: got {mode:o}"
    );

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);
}
