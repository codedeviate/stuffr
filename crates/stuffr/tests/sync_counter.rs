//! Proves `publish`'s fsync block is actually on the path, and that
//! `sync: false` actually skips it — not just that the opts default is `true`
//! and a round trip still works either way, which is all
//! `sync_defaults_on_and_can_be_turned_off` (in `ops_compress.rs`) can show:
//! that test passes identically with the entire fsync block deleted from
//! `publish`.
//!
//! `sync_call_count` is a process-wide counter behind the `testing` feature
//! (see `ops::sync_call_count`), so both checks live in one `#[test]` here,
//! in a test file of their own: separate from every other test that also
//! calls `compress` (and would otherwise also bump the same counter,
//! confusing the "must NOT increment" half of this test with a false
//! failure). Cargo gives each file in `tests/` its own process, so no other
//! test's compress calls can touch this counter.
#![cfg(feature = "testing")]

use stuffr::ops::{CompressOpts, Input, Output, compress, sync_call_count};

fn tmp(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("stf-sync-counter-{}-{}", std::process::id(), name));
    p
}

#[test]
fn publish_syncs_by_default_and_skips_it_under_no_sync() {
    let plain = b"the quick brown fox ".repeat(100);

    // Default (sync: true): publish must call sync_all on the temp file.
    let src = tmp("default-in.txt");
    let dst = tmp("default-out.gz");
    let _ = std::fs::remove_file(&dst);
    std::fs::write(&src, &plain).unwrap();
    let before = sync_call_count();
    compress(
        Input::Path(src.clone()),
        Output::Path(dst.clone()),
        &CompressOpts::default(),
    )
    .unwrap();
    let after = sync_call_count();
    assert!(
        after > before,
        "publish must call sync_all on the temp file by default (before={before}, after={after})"
    );
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);

    // sync: false (--no-sync): publish must not call it at all.
    let src = tmp("nosync-in.txt");
    let dst = tmp("nosync-out.gz");
    let _ = std::fs::remove_file(&dst);
    std::fs::write(&src, &plain).unwrap();
    let opts = CompressOpts {
        sync: false,
        ..Default::default()
    };
    let before = sync_call_count();
    compress(Input::Path(src.clone()), Output::Path(dst.clone()), &opts).unwrap();
    let after = sync_call_count();
    assert_eq!(
        after, before,
        "sync: false must skip sync_all entirely (before={before}, after={after})"
    );
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);
}
