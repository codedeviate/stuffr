//! The zip family's Apple flavour against its reference, `/usr/bin/zip`
//! (Apple's Zip 3.0, macOS and the BSDs). The rows shared by both flavours
//! are in `compat_zip_common.rs`; this suite holds the matrices and the
//! cases only Apple's build has.
//!
//! Task 5 (0.19.0): which names zip would operate on, `-sf` over every shape
//! of operand, directory, link, pattern and date filter
//! ([`zip_scan_matrix`]), and what Apple's build alone does with names.

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod unix {
    use super::compat_harness::*;

    /// This suite is Apple's: other platforms' reference is Ubuntu's.
    fn apple_here() -> bool {
        if platform_zip_flavour() != "apple" {
            eprintln!("skipped: this platform's zip reference is not Apple's");
            return false;
        }
        true
    }

    /// Task 5: the scanning matrix, exit code, both streams and the tree.
    #[test]
    fn the_scan_matrix_matches_apples_zip() {
        if !apple_here() {
            return;
        }
        let cases = zip_scan_matrix("apple");
        assert!(cases.len() >= 150, "{} cases", cases.len());
        run_group(
            "zip scan (apple)",
            &cases,
            Skipped::none(),
            &assert_same_zip,
        );
    }

    /// A newline in a name is shown raw (Ubuntu shows `^J`).
    #[test]
    fn a_newline_in_a_name_is_shown_as_it_is() {
        if !apple_here() {
            return;
        }
        let tree = ZipTree::standard().file_at(b"new\nline", b"x", 0o644);
        let mut c = zip_case("zip", &["-sf", "t.zip", "new\nline"], tree);
        c.zip_flavour = Some("apple");
        assert!(assert_same_zip(&c));
        let ours = stuffr_zip(&c);
        assert!(
            String::from_utf8_lossy(&ours.stdout).contains("  new\nline\n"),
            "{}",
            String::from_utf8_lossy(&ours.stdout)
        );
    }

    /// Task 7: a signal during an update or a new archive, as the reference
    /// answers it (the record's signal table; Review Focus 4).
    #[test]
    fn interrupts_match_the_reference() {
        if !apple_here() {
            return;
        }
        zip_interrupts_match("apple");
    }
}
