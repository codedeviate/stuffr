//! The unzip family's Ubuntu flavour against its reference, apt's `unzip`
//! 6.0-28ubuntu4.1 on ubuntu 24.04 (0.16.0). Linux only: CI's ubuntu-latest
//! has the package, and `make compat-ubuntu` runs this suite in a Docker
//! image that has it (ruling R10). The shared rows are in
//! `compat_unzip_common.rs`; the Ubuntu-only differentials join them from
//! Task 13 (its build options) and Task 14 (its patches).

#[cfg(target_os = "linux")]
mod compat_harness;

#[cfg(target_os = "linux")]
mod linux {
    use super::compat_harness::*;

    /// The oracle is the pinned release: the package version, and the
    /// banner its usage opens with.
    #[test]
    fn the_reference_is_ubuntus_unzip_6_0_28ubuntu4_1() {
        if unzip_dir().is_none() {
            return;
        }
        assert_eq!(
            ubuntu_unzip_version().as_deref(),
            Some(UBUNTU_UNZIP_VERSION)
        );
        let r = unzip_reference(&unzip_case("unzip", vec![], vec![])).unwrap();
        let out = String::from_utf8_lossy(&r.stdout);
        assert_eq!(out.lines().next(), Some(UBUNTU_UNZIP_BANNER), "{out}");
        assert_eq!(platform_unzip_flavour(), "ubuntu");
    }
}
