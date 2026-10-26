//! The zip side of the differential harness against itself (0.19.0 Task
//! 1): the comparison must name a one-byte archive difference and a
//! standard-error difference, the banner mask must take only the banner,
//! the input tree must pin what zip stores (modes, mtimes, atimes, a
//! symlink's own times), stdin entries' "now" times must compare equal
//! within their runs, and `decrypt_equal` must see through the random
//! encryption headers and nothing else.
//!
//! Nothing here runs stuffr as `zip`: the comparisons are of hand-made
//! runs, and only the round trip runs the reference.

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod unix {
    use super::compat_harness::*;
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    fn scratch(tag: &str) -> ScratchDir {
        // Safe as `at`: pid in the name, and each caller passes its own tag
        // (none all digits).
        let d = ScratchDir::at(
            std::env::temp_dir().join(format!("stuffr-zip-selftest-{tag}-{}", std::process::id())),
        );
        fs::create_dir_all(&*d).unwrap();
        d
    }

    fn case() -> Case<'static> {
        zip_case("zip", &["t.zip", "a.txt"], ZipTree::standard())
    }

    /// A run with `stdout`, `stderr` and an archive `t.zip` of `archive`.
    fn run(stdout: &[u8], stderr: &str, archive: &[u8]) -> ZipRun {
        let mut tree = UnzipTree::new();
        tree.insert(
            b"t.zip".to_vec(),
            UnzipNode::File {
                bytes: archive.to_vec(),
                mode: 0o644,
                mtime: 1_000_000_000,
                quarantine: None,
            },
        );
        ZipRun {
            code: 0,
            stdout: stdout.to_vec(),
            stderr: stderr.as_bytes().to_vec(),
            tree,
            start: 1_800_000_000,
            end: 1_800_000_001,
            tty_mode: None,
        }
    }

    fn sample_archive() -> Vec<u8> {
        zip_with(&[ZipEntrySpec::new(b"a.txt", b"hello\n")], b"", b"")
    }

    #[test]
    fn a_one_byte_archive_difference_is_reported() {
        let c = case();
        let a = sample_archive();
        let r = run(b"  adding: a.txt (stored 0%)\n", "", &a);
        assert!(zip_differences(&c, &r, &run(b"  adding: a.txt (stored 0%)\n", "", &a)).is_empty());

        // the second byte of the stored data (which starts at 30 + 5)
        let mut b = a.clone();
        b[36] ^= 1;
        let d = zip_differences(&c, &r, &run(b"  adding: a.txt (stored 0%)\n", "", &b));
        assert_eq!(d.len(), 1, "{d:#?}");
        assert!(
            d[0].contains("archive t.zip differs")
                && d[0].contains("first difference at offset 36")
                && d[0].contains("local header at 0, +36"),
            "{d:#?}"
        );

        // one byte of the central directory's external attributes
        let cd = a.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        let mut b = a.clone();
        b[cd + 40] ^= 0x10;
        let d = zip_differences(&c, &r, &run(b"  adding: a.txt (stored 0%)\n", "", &b));
        assert_eq!(d.len(), 1, "{d:#?}");
        assert!(
            d[0].contains(&format!("central header at {cd}, +40")),
            "{d:#?}"
        );

        // an archive on standard output is compared the same way
        let mut b = a.clone();
        b[36] ^= 1;
        let d = zip_differences(&c, &run(&a, "", &a), &run(&b, "", &a));
        assert_eq!(d.len(), 1, "{d:#?}");
        assert!(
            d[0].starts_with(
                "stdout differs (first difference at offset 36, local header at 0, +36)"
            ),
            "{d:#?}"
        );
    }

    #[test]
    fn an_archive_on_stdout_is_not_masked_as_text() {
        // a temp-like name and a banner line inside archive bytes stay as
        // they are
        let mut a = b"PK\x03\x04 zi123456 ".to_vec();
        a.extend_from_slice(b"Zip 3.0 (July 5th 2008). Usage:\n");
        assert_eq!(mask_zip_output(&a, None, true), a);
        assert_eq!(
            mask_zip_output(b"x zi123456 y", None, false),
            b"x zi?????? y".to_vec()
        );
    }

    #[test]
    fn a_stderr_difference_is_reported() {
        let c = case();
        let a = sample_archive();
        let msg = "\tzip warning: name not matched: x\n";
        let r = run(b"", msg, &a);
        assert!(zip_differences(&c, &r, &run(b"", msg, &a)).is_empty());
        let d = zip_differences(
            &c,
            &r,
            &run(b"", "\tzip warning: name not matched: y\n", &a),
        );
        assert_eq!(d.len(), 1, "{d:#?}");
        assert!(d[0].starts_with("stderr differs"), "{d:#?}");
        // and the exit code, on its own
        let mut s = run(b"", msg, &a);
        s.code = 12;
        let d = zip_differences(&c, &r, &s);
        assert_eq!(d, ["exit code: reference 0 vs stuffr 12"]);
    }

    #[test]
    fn the_banner_mask_matches_only_the_banner() {
        let v = env!("CARGO_PKG_VERSION");
        let apple_ref = "Copyright (c) 1990-2008 Info-ZIP - Type 'zip \"-L\"' for software license.\n\
                         This is Zip 3.0 (July 5th 2008), by Info-ZIP, with modifications by Apple Inc.\n\
                         Please report bugs to Apple.\n";
        let apple_ours = format!(
            "Copyright (c) 1990-2008 Info-ZIP - Type 'zip \"-L\"' for software license.\n\
             This is Zip 3.0 (July 5th 2008), by stuffr {v} (altered; original by Info-ZIP, \
             with modifications by Apple Inc.).\n\
             Please report bugs to Apple.\n"
        );
        let masked = mask_zip_banners(apple_ref.as_bytes(), None);
        assert_eq!(
            String::from_utf8_lossy(&masked),
            "Copyright (c) 1990-2008 Info-ZIP - Type 'zip \"-L\"' for software license.\n\
             <banner>\nPlease report bugs to Apple.\n"
        );
        assert_eq!(
            mask_zip_banners(apple_ours.as_bytes(), Some("apple")),
            masked
        );
        // the other flavour's origin is not this flavour's banner
        assert_ne!(
            mask_zip_banners(apple_ours.as_bytes(), Some("ubuntu")),
            masked
        );
        // another version, or text around the line, is not a banner
        let other = apple_ours.replace(v, "0.0.1");
        assert_ne!(mask_zip_banners(other.as_bytes(), Some("apple")), masked);
        let around = apple_ours.replace("This is Zip", "x This is Zip");
        assert_ne!(mask_zip_banners(around.as_bytes(), Some("apple")), masked);
        let ref_around = apple_ref.replace("Apple Inc.\n", "Apple Inc. \n");
        assert_eq!(
            mask_zip_banners(ref_around.as_bytes(), None),
            ref_around.as_bytes()
        );

        // Ubuntu's banner and the help headers, both sides
        let ubuntu_ref = "This is ZipCloak 3.0 (July 5th 2008), by Info-ZIP.\n";
        let ubuntu_ours = format!(
            "This is ZipCloak 3.0 (July 5th 2008), by stuffr {v} (altered; Debian's build, \
             original by Info-ZIP).\n"
        );
        assert_eq!(mask_zip_banners(ubuntu_ref.as_bytes(), None), b"<banner>\n");
        assert_eq!(
            mask_zip_banners(ubuntu_ours.as_bytes(), Some("ubuntu")),
            b"<banner>\n"
        );
        let help_ref = "Zip 3.0 (July 5th 2008). Usage:\n";
        let help_ours = format!(
            "Zip 3.0 (July 5th 2008), by stuffr {v} (altered; original by Info-ZIP, with \
             modifications by Apple Inc.). Usage:\n"
        );
        assert_eq!(
            mask_zip_banners(help_ref.as_bytes(), None),
            b"<usage-banner>\n"
        );
        assert_eq!(
            mask_zip_banners(help_ours.as_bytes(), Some("apple")),
            b"<usage-banner>\n"
        );
        // a help header shaped like a -v banner is not the help header
        let wrong_shape = help_ours.replace("). Usage:", ").");
        assert_ne!(
            mask_zip_banners(wrong_shape.as_bytes(), Some("apple")),
            b"<usage-banner>\n"
        );
        let helper = format!(
            "ZipNote 3.0 (July 5th 2008), by stuffr {v} (altered; Debian's build, original by Info-ZIP)\n"
        );
        assert_eq!(
            mask_zip_banners(helper.as_bytes(), Some("ubuntu")),
            b"<usage-banner>\n"
        );
        assert_eq!(
            mask_zip_banners(b"ZipNote 3.0 (July 5th 2008)\n", None),
            b"<usage-banner>\n"
        );
    }

    #[test]
    fn temporary_names_are_masked_as_whole_components() {
        let t = b"zip error: Temporary file failure (nodir/zi4wYX6d)\n";
        assert_eq!(
            mask_temp_names(t),
            b"zip error: Temporary file failure (nodir/zi??????)\n"
        );
        assert_eq!(mask_temp_names(b"(ziAbCdEf)"), b"(zi??????)");
        for keep in [
            &b"zipsplit error: x\n"[..],
            b"zipcloak error: x\n",
            b"(zi4wYX6dx)",
            b"xzi4wYX6d ",
            b"zipnote warning: y\n",
        ] {
            assert_eq!(
                mask_temp_names(keep),
                keep,
                "{}",
                String::from_utf8_lossy(keep)
            );
        }
    }

    #[test]
    fn now_times_compare_equal_within_their_own_runs() {
        // 2027-01-15 08:00:00 UTC = 1800000000: DOS time 08:00:00, date
        // 2027-01-15
        let (t, d) = (8u16 << 11, ((2027 - 1980) << 9) | (1 << 5) | 15u16);
        let entry = |time: u32| {
            let mut e = ZipEntrySpec::new(b"-", b"hello\n");
            e.dos_time = time;
            zip_with(&[e], b"", b"")
        };
        let at = |t: u16, d: u16| u32::from(t) | (u32::from(d) << 16);
        let r = entry(at(t, d));
        // stuffr ran 3 s later, by its own clock: 08:00:04 (two-second steps)
        let s = entry(at(t | 2, d));
        let mut m = s.clone();
        mask_now_times(
            &r,
            (1_800_000_000, 1_800_000_001),
            &mut m,
            (1_800_000_003, 1_800_000_004),
        );
        assert_eq!(m, r);
        // outside its run's window: left alone
        let mut m = s.clone();
        mask_now_times(
            &r,
            (1_800_000_000, 1_800_000_001),
            &mut m,
            (1_800_000_100, 1_800_000_101),
        );
        assert_eq!(m, s);
        // a pinned time is never a "now"
        let pinned = entry(DOS_TIME_2020);
        let mut m = pinned.clone();
        mask_now_times(
            &r,
            (1_800_000_000, 1_800_000_001),
            &mut m,
            (1_800_000_003, 1_800_000_004),
        );
        assert_eq!(m, pinned);
    }

    /// `-lf`'s `Zip log opened <asctime>`: the wall-clock time in each
    /// run's own window compares equal (Task 9 fix round: the scan
    /// matrix's two `-lf` cases straddling a second); outside it, or any
    /// other text, is left alone.
    #[test]
    fn log_times_compare_equal_within_their_own_runs() {
        // 1800000000 = Fri Jan 15 08:00:00 2027 UTC
        let r = b"Zip log opened Fri Jan 15 08:00:00 2027\n\nend\n".to_vec();
        let s = b"Zip log opened Fri Jan 15 08:00:03 2027\n\nend\n".to_vec();
        let mut m = s.clone();
        mask_asctimes(
            &r,
            (1_800_000_000, 1_800_000_000),
            &mut m,
            (1_800_000_002, 1_800_000_003),
        );
        assert_eq!(m, r);
        let mut m = s.clone();
        mask_asctimes(
            &r,
            (1_800_000_000, 1_800_000_000),
            &mut m,
            (1_800_000_100, 1_800_000_101),
        );
        assert_eq!(m, s);
        let other = b"Zip log opened Fri Jan 15 08:00:03 2027\n\nENd\n".to_vec();
        let mut m = other.clone();
        mask_asctimes(
            &r,
            (1_800_000_000, 1_800_000_000),
            &mut m,
            (1_800_000_002, 1_800_000_003),
        );
        assert_eq!(&m[..40], &r[..40]);
        assert_eq!(&m[40..], &other[40..]);
    }

    #[test]
    fn the_tree_pins_modes_times_and_symlinks() {
        let d = scratch("tree");
        ZipTree::standard()
            .file_mode("x/ro.txt", b"r", 0o400)
            .times("a.txt", 1_100_000_000, 1_200_000_000)
            .symlink("l", "a.txt")
            .times("l", 1_300_000_000, 1_300_000_000)
            .dir_mode("closed", 0o000)
            .materialise(&d);
        let md = |p: &str| fs::symlink_metadata(d.join(p)).unwrap();
        assert_eq!(
            (md("a.txt").mtime(), md("a.txt").atime()),
            (1_100_000_000, 1_200_000_000)
        );
        assert_eq!(md("a.txt").mode() & 0o7777, 0o644);
        assert_eq!(md("b.txt").len(), 2240);
        assert_eq!(
            (md("d").mode() & 0o7777, md("d").mtime()),
            (0o755, 1_000_000_000)
        );
        assert_eq!(
            (md("d/c.txt").mtime(), md("d/c.txt").atime()),
            (1_000_000_000, INPUT_ATIME)
        );
        // an unlisted parent is made and pinned too
        assert_eq!(
            (md("x").mode() & 0o7777, md("x").mtime()),
            (0o755, 1_000_000_000)
        );
        assert_eq!(md("x/ro.txt").mode() & 0o7777, 0o400);
        assert!(md("l").file_type().is_symlink());
        assert_eq!(md("l").mtime(), 1_300_000_000);
        assert_eq!(fs::read_link(d.join("l")).unwrap(), Path::new("a.txt"));
        assert_eq!(md("closed").mode() & 0o7777, 0o000);
    }

    #[test]
    fn decrypt_equal_sees_through_the_headers_only() {
        let d = scratch("crypt");
        let body = b"the quick brown fox";
        let crc = crc32(body);
        let enc = |head: [u8; 11], pw: &[u8], plain: &[u8]| {
            let data = zipcrypto_with(pw, head, (crc >> 24) as u8, plain);
            let mut e = ZipEntrySpec::new(b"f.txt", body);
            e.flags = 1;
            e.stored_data = Some(&data);
            zip_with(&[e], b"", b"")
        };
        fs::write(d.join("a.zip"), enc([1; 11], b"pw", body)).unwrap();
        fs::write(d.join("b.zip"), enc([2; 11], b"pw", body)).unwrap();
        // the two archives differ (the headers), yet agree
        assert_ne!(
            fs::read(d.join("a.zip")).unwrap(),
            fs::read(d.join("b.zip")).unwrap()
        );
        decrypt_equal(&d.join("a.zip"), &d.join("b.zip"), "pw").unwrap();
        // a wrong password fails the check byte
        let e = decrypt_equal(&d.join("a.zip"), &d.join("b.zip"), "px").unwrap_err();
        assert!(e.contains("password check byte"), "{e}");
        // one byte of the encrypted data is a difference
        fs::write(d.join("c.zip"), enc([2; 11], b"pw", b"the quick brown fix")).unwrap();
        let e = decrypt_equal(&d.join("a.zip"), &d.join("c.zip"), "pw").unwrap_err();
        assert!(e.contains("differ outside the encryption headers"), "{e}");
        // and so is one outside it (the central directory's attributes)
        let mut b = fs::read(d.join("b.zip")).unwrap();
        let cd = b.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        b[cd + 40] ^= 1;
        fs::write(d.join("e.zip"), b).unwrap();
        let e = decrypt_equal(&d.join("a.zip"), &d.join("e.zip"), "pw").unwrap_err();
        assert!(e.contains("central header"), "{e}");
    }

    /// The reference reads the tree as the record says: the standard tree
    /// zipped gives the record's bytes but for the owner (the `ux` field),
    /// and two reference runs agree byte for byte.
    #[test]
    fn two_reference_runs_agree() {
        let c = zip_case("zip", &["-r", "t.zip", "."], ZipTree::standard());
        let Some(r) = zip_reference(&c) else {
            return;
        };
        let s = zip_reference(&c).unwrap();
        compare_zip(&c, &r, &s);
        let Some(UnzipNode::File { bytes, .. }) = r.tree.get(&b"t.zip"[..]) else {
            panic!("no t.zip: {:?}", r.stdout);
        };
        // a.txt's local header: version 10, stored, 2001-09-09 01:46:40
        // UTC, then the UT field with mtime 1e9 and atime 2e9 (INPUT_ATIME)
        let a = bytes.windows(5).position(|w| w == b"a.txt").unwrap() - 30;
        assert_eq!(
            &bytes[a + 4..a + 14],
            b"\x0a\x00\x00\x00\x00\x00\xd4\x0d\x29\x2b"
        );
        assert_eq!(
            &bytes[a + 35..a + 48],
            b"UT\x09\x00\x03\x00\xca\x9a\x3b\x00\x94\x35\x77"
        );
        // with standard input: the entry's time is the run's own
        let mut c = zip_case("zip", &["-"], ZipTree::new());
        c.stdin = Some(b"hello\n".to_vec());
        let (r, s) = (zip_reference(&c).unwrap(), zip_reference(&c).unwrap());
        compare_zip(&c, &r, &s);
    }
}
