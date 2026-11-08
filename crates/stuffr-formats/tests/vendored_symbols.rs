//! Every vendored C library is built with its exported symbols prefixed
//! `stuffr_` (`c/<lib>/stuffr-prefix.h`, force-included by `build.rs`), so a
//! downstream graph that links another copy of the same library cannot
//! clash with ours. `build.rs` reports the archives it built.
#![cfg(all(unix, any(feature = "brotli-c", feature = "lz4-c")))]

use std::process::Command;

const ARCHIVES: &str = env!("STUFFR_VENDORED_ARCHIVES");

#[test]
fn vendored_archives_export_only_prefixed_symbols() {
    let macos = cfg!(target_os = "macos");
    let mut offenders = Vec::new();
    let mut archives = 0;
    // `build.rs` joins the paths with `:`, which is unix-only (as this test
    // is): a Windows path has a drive colon.
    for archive in ARCHIVES.split(':').filter(|a| !a.is_empty()) {
        archives += 1;
        let mut seen = 0;
        let mut nm = Command::new("nm");
        if macos {
            nm.arg("-gU");
        } else {
            nm.args(["-g", "--defined-only"]);
        }
        let out = nm.arg(archive).output().expect("running nm");
        assert!(out.status.success(), "nm {archive} failed");
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            // `<addr> <type> <name>`; member headers (`x.o:`) and blanks
            // have fewer fields.
            let f: Vec<&str> = line.split_whitespace().collect();
            let [_, ty, name] = f[..] else { continue };
            // Undefined (`U`) and local (lower-case) entries are not
            // exports; `-g` already drops locals, `-U`/`--defined-only`
            // the undefined ones. Skip `U` defensively.
            if ty == "U" {
                continue;
            }
            seen += 1;
            let name = if macos {
                name.strip_prefix('_').unwrap_or(name)
            } else {
                name
            };
            if !name.starts_with("stuffr_") {
                offenders.push(format!("{archive}: {name}"));
            }
        }
        // Each archive on its own: one that parses to nothing would
        // otherwise hide behind another's symbols.
        assert!(seen > 0, "no symbols found in {archive}");
    }
    let want = usize::from(cfg!(feature = "brotli-c")) + usize::from(cfg!(feature = "lz4-c"));
    assert_eq!(archives, want, "archives: {ARCHIVES}");
    assert!(
        offenders.is_empty(),
        "{} unprefixed exported symbol(s):\n{}",
        offenders.len(),
        offenders.join("\n")
    );
}
