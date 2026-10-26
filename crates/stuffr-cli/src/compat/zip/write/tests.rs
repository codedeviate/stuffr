use super::*;

use crate::compat::host::Sandbox;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

fn sandbox() -> Host {
    Host::Sandbox(Sandbox {
        dir: std::env::temp_dir(),
        stdin: None,
        stdout: Arc::new(Mutex::new(Vec::new())),
        budget: Arc::new(AtomicU64::new(0)),
        reads: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
    })
}

/// An MS-DOS date and time (year, month, day, hour, minute, second).
fn dos(y: u32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> u32 {
    ((y - 1980) << 25) | (mo << 21) | (d << 16) | (h << 11) | (mi << 5) | (s >> 1)
}

/// The fallback (a sandbox, off unix) normalises as `mktime` does: month 0
/// is the December before, 13 to 15 the next year's January to March; a
/// day 0 the last of the month before. No panic anywhere in the fields'
/// ranges.
#[test]
fn dos2unixtime_fallback_normalises_as_mktime() {
    let h = sandbox();
    assert_eq!(dos2unixtime(&h, dos(2001, 9, 9, 1, 46, 40)), 1_000_000_000);
    assert_eq!(dos2unixtime(&h, dos(2020, 0, 1, 0, 0, 0)), 1_575_158_400);
    assert_eq!(dos2unixtime(&h, dos(2020, 13, 1, 0, 0, 0)), 1_609_459_200);
    assert_eq!(dos2unixtime(&h, dos(2020, 14, 1, 0, 0, 0)), 1_612_137_600);
    assert_eq!(dos2unixtime(&h, dos(2020, 15, 1, 0, 0, 0)), 1_614_556_800);
    assert_eq!(dos2unixtime(&h, dos(2020, 1, 0, 0, 0, 0)), 1_577_750_400);
    for d in [0u32, u32::MAX, 0x0021_0000, 0xffff_0000, 0x0000_ffff] {
        let _ = dos2unixtime(&h, d);
    }
}

/// `-c`/`-z` lines as the C's `strlen` sees them: cut at the first NUL,
/// the newline dropped; deviation 10, a line that starts with NUL is empty.
#[test]
fn comment_lines_end_at_their_first_nul() {
    assert_eq!(comment_line(b"ab\0cd\n".to_vec()), b"ab");
    assert_eq!(comment_line(b"ab\n".to_vec()), b"ab");
    assert_eq!(comment_line(b"ab".to_vec()), b"ab");
    assert_eq!(comment_line(b"\0x\n".to_vec()), b"");
    assert_eq!(comment_line(b"\n".to_vec()), b"");
    assert_eq!(cut_at_nul(b".\n\0z".to_vec()), b".\n");
}

/// `-o`'s stamp goes by the path (`utime`), so a read-only archive of its
/// owner is stamped.
#[cfg(unix)]
#[test]
fn stamp_reaches_a_read_only_file() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let p = std::env::temp_dir().join(format!("stuffr-zipstamp-{}-ro", std::process::id()));
    let _ = std::fs::remove_file(&p);
    std::fs::write(&p, b"x").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o444)).unwrap();
    set_times_by_path(&p, 1_000_000_000, std::time::UNIX_EPOCH);
    let md = std::fs::metadata(&p).unwrap();
    let _ = std::fs::remove_file(&p);
    assert_eq!(md.mtime(), 1_000_000_000);
}
