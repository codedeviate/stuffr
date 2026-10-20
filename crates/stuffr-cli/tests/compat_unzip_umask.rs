//! MS-DOS-only attributes under several umasks (0.16.0 Task 10, Review
//! Focus 2): an entry made on a host without Unix modes gets `0444`, the
//! write bits unless MS-DOS's read-only bit, execute for a directory, less
//! the process's umask (unix.c's `mapattr()`). The umask is the process's,
//! so this suite is its own test binary with one test, which sets it for
//! each group while nothing else runs.
//!
//! macOS compares Apple's flavour with `/usr/bin/unzip`; Ubuntu's side
//! waits for Task 13 (R13).

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod unix {
    use super::compat_harness::*;

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "Task 13 (R13: Ubuntu's side)")]
    fn dos_attributes_under_several_umasks() {
        let dos = |name: &'static [u8], data: &'static [u8], attr: u32| ZipEntrySpec {
            version_made_by: 0x0014,
            external_attr: attr,
            ..ZipEntrySpec::new(name, data)
        };
        let unix_in_fat = |name: &'static [u8], mode: u32, attr: u32| ZipEntrySpec {
            version_made_by: 0x0014,
            external_attr: (mode << 16) | attr,
            ..ZipEntrySpec::new(name, b"pkzip for unix\n")
        };
        let z = zip_with(
            &[
                dos(b"DIR/", b"", 0x10),
                dos(b"DIR/PLAIN.TXT", b"plain\r\n", 0x20),
                dos(b"READONLY.TXT", b"read only\r\n", 0x21),
                dos(b"HIDDEN.SYS", b"hidden\r\n", 0x26),
                dos(b"NODIRBIT/", b"", 0x00),
                // MS-DOS attributes that agree with Unix ones kept above
                unix_in_fat(b"agree.sh", 0o100755, 0x20),
                unix_in_fat(b"disagree.txt", 0o100755, 0x21),
                ZipEntrySpec {
                    version_made_by: 0x0b14, // NTFS
                    external_attr: 0x20,
                    ..ZipEntrySpec::new(b"ntfs.txt", b"ntfs\n")
                },
                ZipEntrySpec {
                    version_made_by: 0x0714, // Macintosh
                    external_attr: 0x01,
                    ..ZipEntrySpec::new(b"mac.txt", b"mac\n")
                },
            ],
            b"",
            b"",
        );
        let files = vec![("dos.zip", z)];
        let saved = set_umask(0o022);
        for mask in [0o022, 0o077, 0o000, 0o027, 0o002] {
            set_umask(mask);
            let cases: Vec<Case> = [
                &["dos.zip"][..],
                &["-K", "dos.zip"],
                &["-d", "out", "dos.zip"],
            ]
            .iter()
            .map(|a| unzip_case("unzip", a.to_vec(), files.clone()))
            .collect();
            run_group(
                &format!("umask {mask:03o}"),
                &cases,
                Skipped::none(),
                &assert_same_unzip,
            );
        }
        set_umask(saved);
    }

    /// `umask(mask)`, the previous mask (`mode_t` is 16 bits on macOS, 32
    /// on Linux).
    #[allow(clippy::useless_conversion)]
    fn set_umask(mask: u32) -> u32 {
        // SAFETY: `umask` only swaps the process's mask; this test binary
        // has no other test running while it is changed.
        u32::from(unsafe { libc::umask(mask as libc::mode_t) })
    }
}
