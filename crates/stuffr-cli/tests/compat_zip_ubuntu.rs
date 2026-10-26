//! The zip family's Ubuntu flavour against its reference, apt's `zip`
//! 3.0-13ubuntu0.2 on ubuntu 24.04. Linux only: CI's ubuntu-24.04 has the
//! package and `make compat-ubuntu` runs this suite in a Docker image that
//! has it. The rows shared by both flavours are in `compat_zip_common.rs`;
//! this suite holds the matrices and the cases only Ubuntu's build has.
//!
//! Task 5 (0.19.0): which names zip would operate on ([`zip_scan_matrix`],
//! the same cases as Apple's suite), and what Ubuntu's `UNICODE_SUPPORT`
//! build does with names in messages.

#[cfg(target_os = "linux")]
mod compat_harness;

#[cfg(target_os = "linux")]
mod linux {
    use super::compat_harness::*;

    /// The oracle is the pinned release.
    #[test]
    fn the_reference_is_ubuntus_zip_3_0_13ubuntu0_2() {
        if zip_dir().is_none() {
            return;
        }
        assert_eq!(ubuntu_zip_version().as_deref(), Some(UBUNTU_ZIP_VERSION));
        assert_eq!(platform_zip_flavour(), "ubuntu");
    }

    /// Task 5: the scanning matrix, exit code, both streams and the tree.
    #[test]
    fn the_scan_matrix_matches_ubuntus_zip() {
        let cases = zip_scan_matrix("ubuntu");
        assert!(cases.len() >= 150, "{} cases", cases.len());
        run_group(
            "zip scan (ubuntu)",
            &cases,
            Skipped::none(),
            &assert_same_zip,
        );
    }

    /// A control byte in a name is shown as `^` and a letter (`^J`); the
    /// name stored is untouched.
    #[test]
    fn a_control_byte_in_a_name_is_shown_escaped() {
        let tree = ZipTree::standard()
            .file_at(b"new\nline", b"x", 0o644)
            .file_at(b"tab\there", b"x", 0o644);
        let mut c = zip_case("zip", &["-sf", "t.zip", "new\nline", "tab\there"], tree);
        c.zip_flavour = Some("ubuntu");
        if !assert_same_zip(&c) {
            return;
        }
        let ours = stuffr_zip(&c);
        let out = String::from_utf8_lossy(&ours.stdout);
        assert!(out.contains("  new^Jline\n  tab^Ihere\n"), "{out}");
    }

    /// Task 7: a signal during an update or a new archive, as the reference
    /// answers it (the record's signal table; Review Focus 4).
    #[test]
    fn interrupts_match_the_reference() {
        if zip_dir().is_none() {
            return;
        }
        zip_interrupts_match("ubuntu");
    }
}
