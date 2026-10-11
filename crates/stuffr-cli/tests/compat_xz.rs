//! The xz compatibility family against XZ Utils 5.8.4: stuffr invoked as
//! `xz`, `unxz`, `xzcat`, `lzma`, `unlzma` and `lzcat`, compared with the
//! reference through `compat_harness`.
//!
//! Stub: Task 5 (the `xz` dispatch and the family's `run`) fills in the
//! differential groups. Until then this file holds only the check that the
//! reference found is the one the family is specified against.

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod unix {
    use super::compat_harness::*;
    use std::process::Command;

    /// The reference is XZ Utils 5.8.4 exactly, and the five links beside
    /// `xz` exist. Skipped locally with a note when there is none; under `CI`
    /// `xz_dir` itself panics.
    #[test]
    fn reference_is_5_8_4() {
        let Some(dir) = xz_dir() else { return };
        let out = Command::new(format!("{dir}/xz"))
            .args(["--robot", "--version"])
            .env_clear()
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "XZ_VERSION=50080042\nLIBLZMA_VERSION=50080042\n"
        );
        for link in ["unxz", "xzcat", "lzma", "unlzma", "lzcat"] {
            assert!(
                std::path::Path::new(dir).join(link).exists(),
                "{dir}/{link} is missing"
            );
        }
    }
}
