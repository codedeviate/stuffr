//! The zip family's new archives against this platform's reference (Task 6
//! of 0.19.0): every byte zip writes (local and central headers, extra
//! fields, data descriptors, Zip64 records, comments, the deflate data at
//! every level), both streams and the exit code, over
//! [`zip_bytes_matrix`]. Apple's `/usr/bin/zip` on macOS, Ubuntu's apt
//! `zip` under `make compat-ubuntu` and CI's Linux jobs.

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod unix {
    use super::compat_harness::*;

    #[test]
    fn new_archives_are_byte_identical() {
        let cases = zip_bytes_matrix(platform_zip_flavour());
        assert!(cases.len() >= 100, "{} cases", cases.len());
        run_group(
            &format!("zip bytes ({})", platform_zip_flavour()),
            &cases,
            Skipped::none(),
            &assert_same_zip,
        );
    }
}
