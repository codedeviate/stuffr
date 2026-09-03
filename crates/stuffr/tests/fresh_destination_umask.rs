//! Pins C2's ruling in isolation: `umask` is a process-global setting, not a
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

#[test]
fn a_fresh_destination_respects_the_umask_not_a_hardcoded_0600() {
    // C2's ruling: 0600-at-creation exists to close a race when carrying
    // permissions over from an existing destination. A brand-new destination
    // has nothing to protect, so its mode must be the user's own umask
    // policy — what `File::create` would produce — not a hardcoded 0600
    // gzip, zstd and xz would never impose.
    let src = tmp("in.txt");
    let dst = tmp("out.gz");
    let _ = std::fs::remove_file(&dst);
    std::fs::write(&src, b"payload").unwrap();

    // A concrete, non-default umask so this does not depend on whatever the
    // test runner's environment happens to have set. Safe here specifically
    // because this file has no other test to race against.
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
        mode,
        0o666 & !0o022,
        "a fresh destination must land at 0o666 & !umask, exactly what File::create would \
         produce, not a hardcoded 0600: got {mode:o}"
    );

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);
}
