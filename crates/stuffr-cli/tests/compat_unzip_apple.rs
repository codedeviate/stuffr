//! The unzip family's Apple flavour against its reference, this Mac's
//! `/usr/bin/unzip`, `zipinfo` and `funzip` (0.16.0). macOS only. The shared
//! rows are in `compat_unzip_common.rs`; the Apple-only differentials join
//! them from Task 8 on.
//!
//! The suite is verified against the build whose `unzip -v` is
//! `APPLE_UNZIP_IDENTITY` (R11). Another macOS may ship another build: then
//! every difference `compare_unzip` reports says so, and so does
//! `the_reference_is_apples_unzip`, without failing for it.

#[cfg(target_os = "macos")]
mod compat_harness;

#[cfg(target_os = "macos")]
mod macos {
    use super::compat_harness::*;

    /// The oracle is Apple's build: its banner, and the `-v` this suite was
    /// verified against (a different one is reported, not failed: R11).
    #[test]
    fn the_reference_is_apples_unzip() {
        if unzip_dir().is_none() {
            return;
        }
        let id = apple_unzip_identity().expect("unzip -v");
        assert_eq!(id.lines().next(), Some(APPLE_UNZIP_BANNER), "{id}");
        if id == APPLE_UNZIP_IDENTITY {
            println!("the installed /usr/bin/unzip is the recorded build");
        } else {
            println!(
                "note: the installed /usr/bin/unzip -v differs from the recorded build \
                 (R11); differences will be marked [apple drift?]:\n{id}"
            );
        }
        assert_eq!(platform_unzip_flavour(), "apple");
    }
}
