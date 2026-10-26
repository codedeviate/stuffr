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

    /// The archives Task 11's rows read: bit 11 set, Unicode Path fields
    /// good, mismatched, of version 2, with no name, a bit-11 name that is
    /// not UTF-8, one with a newline.
    fn unicode_archives() -> Vec<(&'static str, Vec<u8>)> {
        fn up(iname: &[u8], utf8: &[u8], ver: u8, crc: Option<u32>) -> Vec<u8> {
            let mut h = flate2::Crc::new();
            h.update(iname);
            let crc = crc.unwrap_or(h.sum());
            let mut d = vec![ver];
            d.extend_from_slice(&crc.to_le_bytes());
            d.extend_from_slice(utf8);
            let mut f = 0x7075u16.to_le_bytes().to_vec();
            f.extend_from_slice(&(d.len() as u16).to_le_bytes());
            f.extend_from_slice(&d);
            f
        }
        let caf8 = "café.txt".as_bytes();
        let cafl = b"caf\xe9.txt";
        let e = |name: &'static [u8], flags: u16, extra: Vec<u8>| (name, flags, extra);
        let mk = |list: &[(&[u8], u16, Vec<u8>)]| {
            let specs: Vec<ZipEntrySpec> = list
                .iter()
                .map(|(n, f, x)| {
                    let mut s =
                        ZipEntrySpec::new(n, if n.starts_with(b"a.") { b"a\n" } else { b"x\n" });
                    s.flags = *f;
                    s.extra = x;
                    s
                })
                .collect();
            zip_with(&specs, b"", b"")
        };
        let a = || e(b"a.txt", 0, vec![]);
        vec![
            ("bit11", mk(&[e("café.txt".as_bytes(), 0x800, vec![]), a()])),
            (
                "upgood",
                mk(&[e(b"caf\xe9.txt", 0, up(cafl, caf8, 1, None)), a()]),
            ),
            (
                "upbad",
                mk(&[e(b"caf\xe9.txt", 0, up(cafl, caf8, 1, Some(1))), a()]),
            ),
            ("upv2", mk(&[e(b"caf\xe9.txt", 0, up(cafl, caf8, 2, None))])),
            (
                "upempty",
                mk(&[e("café.txt".as_bytes(), 0, up(caf8, b"", 1, None))]),
            ),
            ("bit11bad", mk(&[e(b"h\xe9.txt", 0x800, vec![]), a()])),
            ("bit11nl", mk(&[e(b"n\nl\xc3\xa9", 0x800, vec![])])),
            // a good central field over a local one whose checksum is wrong
            ("locbad", {
                let mut b = mk(&[e(b"caf\xe9.txt", 0, up(cafl, caf8, 1, None)), a()]);
                let at = 30 + cafl.len() + 5;
                b[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
                b
            }),
            // a good central field over a local one with no name (its data
            // length 5: the name bytes become padding the field skips)
            ("locempty", {
                let mut b = mk(&[e(b"caf\xe9.txt", 0, up(cafl, caf8, 1, None)), a()]);
                let at = 30 + cafl.len() + 2;
                b[at..at + 2].copy_from_slice(&5u16.to_le_bytes());
                b
            }),
        ]
    }

    /// Task 11: Ubuntu's `UNICODE_SUPPORT` and `BZIP2_SUPPORT` builds and
    /// its patch series, against the reference (Docker). Names that are not
    /// ASCII under `C`, `C.UTF-8` and `en_US.UTF-8` and with no
    /// `en_US.UTF-8` at all (`LOCPATH` pointing nowhere), the `-UN` modes,
    /// `-su`/`-sU`, archives holding UTF-8 names (bit 11) and Unicode Path
    /// fields, and the helpers over them (Review Focus 5 included).
    #[test]
    fn ubuntu_build_rows() {
        let caf = "café.txt";
        let names_tree = || {
            ZipTree::standard()
                .file_at(caf.as_bytes(), b"x", 0o644)
                .file_at(b"h\xe9.txt", b"x", 0o644)
                .file_at(b"d\x7fl", b"x", 0o644)
                .file_at(b"n\nl", b"x", 0o644)
                .file_at(b"s\xed\xa0\x80", b"x", 0o644)
                .file_at(b"b\xf4\x90\x80\x80", b"x", 0o644)
                .file_at("z\u{1f600}.txt".as_bytes(), b"x", 0o644)
                .file_at(b"-n", b"x", 0o644)
        };
        let locales: [&[(&'static str, &'static str)]; 4] = [
            &[("LC_ALL", "C")],
            &[("LC_ALL", "C.UTF-8")],
            &[("LC_ALL", "en_US.UTF-8")],
            &[("LOCPATH", "/nonexistent"), ("LC_ALL", "C.UTF-8")],
        ];
        let mut cases = Vec::new();
        let push = |cases: &mut Vec<Case<'static>>,
                    args: &[&'static str],
                    tree: ZipTree,
                    stdin: Option<&[u8]>,
                    env: &[(&'static str, &'static str)]| {
            let mut c = zip_case(args[0], &args[1..], tree);
            c.zip_flavour = Some("ubuntu");
            c.stdin = stdin.map(<[u8]>::to_vec);
            c.env = env.to_vec();
            cases.push(c);
        };
        // names on the command line, and on standard input (-@) for those
        // that are not UTF-8
        let listed = b"h\xe9.txt\nd\x7fl\nn\nl\ns\xed\xa0\x80\nb\xf4\x90\x80\x80\n".as_slice();
        for env in locales {
            for args in [
                &["zip", "t.zip", "café.txt"][..],
                &["zip", "t.zip", "z\u{1f600}.txt", "a.txt"],
                &["zip", "-v", "t.zip", "café.txt"],
                &["zip", "-UN=u", "t.zip", "café.txt"],
                &["zip", "-UN=e", "t.zip", "café.txt"],
                &["zip", "-UN=n", "t.zip", "café.txt"],
                &["zip", "-su", "t.zip", "café.txt"],
                &["zip", "-sU", "t.zip", "café.txt"],
                &["zip", "-UN=e", "-sf", "t.zip", "café.txt", "a.txt"],
                &["zip", "t.zip", "--", "-n"],
                &["zip", "-r", "t.zip", "."],
                &["zip", "-", "café.txt"],
            ] {
                push(&mut cases, args, names_tree(), None, env);
            }
            for args in [
                &["zip", "t.zip", "-@"][..],
                &["zip", "-sf", "t.zip", "-@"],
                &["zip", "-UN=e", "-sf", "t.zip", "-@"],
                &["zip", "-UN=u", "t.zip", "-@"],
                &["zip", "-UN=u", "-sf", "t.zip", "-@"],
            ] {
                push(&mut cases, args, names_tree(), Some(listed), env);
            }
            for one in [&b"d\x7fl\n"[..], b"n\nl\n", b"b\xf4\x90\x80\x80\n"] {
                push(
                    &mut cases,
                    &["zip", "-UN=e", "-sf", "t.zip", "-@"],
                    names_tree(),
                    Some(one),
                    env,
                );
            }
        }
        // archives holding Unicode names
        for (an, bytes) in unicode_archives() {
            // the archive is named after its kind, so a failure says which
            let file: &'static str = Box::leak(format!("{an}.zip").into_boxed_str());
            let tree = || {
                ZipTree::standard()
                    .file_at(file.as_bytes(), &bytes, 0o644)
                    .file_at(caf.as_bytes(), b"new\n", 0o644)
            };
            let rows: &[&[&'static str]] = &[
                &["zip", "-sf", "t.zip"],
                &["zip", "-su", "t.zip"],
                &["zip", "-sU", "t.zip"],
                &["zip", "-su-", "-lf", "log", "t.zip"],
                &["zip", "-sU", "-lf", "log", "t.zip"],
                &["zip", "-UN=e", "-sf", "t.zip"],
                &["zip", "-UN=e", "-su", "t.zip"],
                &["zip", "-UN=e", "-sU", "t.zip"],
                &["zip", "-UN=n", "-sf", "t.zip"],
                &["zip", "-UN=i", "-sf", "t.zip"],
                &["zip", "-UN=w", "-sf", "t.zip"],
                &["zip", "-UN=q", "-sf", "t.zip"],
                &["zip", "t.zip", "b.txt"],
                &["zip", "-UN=n", "t.zip", "b.txt"],
                &["zip", "-UN=q", "t.zip", "b.txt"],
                &["zip", "-UN=e", "t.zip", "b.txt"],
                &["zip", "-UN=u", "t.zip", "b.txt"],
                &["zip", "t.zip", "café.txt"],
                &["zip", "-UN=e", "t.zip", "café.txt"],
                &["zip", "-d", "t.zip", "café.txt"],
                &["zip", "-d", "t.zip", "caf*"],
                &["zip", "-U", "t.zip", "caf*", "--out", "o.zip"],
                &["zip", "-v", "-U", "t.zip", "café.txt", "--out", "o.zip"],
                &["zip", "-v", "t.zip", "b.txt"],
                &["zip", "-", "t.zip"],
                &["zip", "-F", "t.zip", "--out", "f.zip"],
                &["zip", "-FF", "t.zip", "--out", "f.zip"],
                &["zip", "-T", "t.zip"],
                &["zipnote", "t.zip"],
                &["zipsplit", "t.zip"],
                &["zipsplit", "-n", "65536", "-b", "d", "t.zip"],
                &["zip", "-UN=q", "t.zip", "café.txt"],
                &["zip", "-UN=q", "-U", "t.zip", "caf*", "--out", "o.zip"],
                &["zip", "-U", "t.zip", "*", "--out", "-"],
                &["zip", "t.zip", "b.txt", "--out", "-"],
            ];
            for args in rows {
                let args: Vec<&'static str> = args
                    .iter()
                    .map(|&a| if a == "t.zip" { file } else { a })
                    .collect();
                push(&mut cases, &args, tree(), None, &[]);
            }
            // zipnote -w renaming the first entry
            let rename = b"@ caf\xc3\xa9.txt\n@=new.txt\n@ (comment above this line)\n";
            push(
                &mut cases,
                &["zipnote", "-w", file],
                tree(),
                Some(rename),
                &[],
            );
        }
        // -Z bzip2: stuffr's encoder at zip's block size; the store
        // fallback (an input of one buffer that does not shrink, archive
        // seekable), the text test over the stale input buffer, -0
        let noise = |n: usize, seed: u32| {
            let mut x = seed;
            (0..n)
                .map(|_| {
                    x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
                    (x >> 16) as u8
                })
                .collect::<Vec<u8>>()
        };
        let big: Vec<u8> = (0..3000)
            .flat_map(|i| format!("row {i} qwerty asdf\n").into_bytes())
            .collect();
        let bz_tree = || {
            ZipTree::standard()
                .file_at(b"big.txt", &big, 0o644)
                .file_at(b"r10k", noise(10_000, 1), 0o644)
                .file_at(b"r16k", noise(16_384, 2), 0o644)
                .file_at(b"r16k1", noise(16_383, 3), 0o644)
                .file_at(b"r300k", noise(300_000, 4), 0o644)
                .file_at(b"e.txt", b"", 0o644)
        };
        for args in [
            &["zip", "-1", "-Z", "bzip2", "t.zip", "b.txt", "big.txt"][..],
            &["zip", "-9", "-Z", "bzip2", "t.zip", "b.txt", "big.txt"],
            &["zip", "-Z", "b", "t.zip", "a.txt", "e.txt", "d"],
            &[
                "zip", "-Z", "bzip2", "t.zip", "big.txt", "a.txt", "r10k", "b.txt",
            ],
            &["zip", "-Z", "bzip2", "t.zip", "r16k", "r16k1", "r10k"],
            &["zip", "-0", "-Z", "bzip2", "t.zip", "b.txt"],
            &["zip", "-v", "-Z", "bzip2", "t.zip", "b.txt", "big.txt"],
            &[
                "zip", "-dd", "-ds", "32k", "-Z", "bzip2", "t.zip", "r300k", "big.txt",
            ],
            &["zip", "-fd", "-Z", "bzip2", "t.zip", "a.txt", "b.txt"],
            &["zip", "-fd", "-Z", "bzip2", "t.zip", "big.txt", "r300k"],
            &[
                "zip", "-n", ".txt", "-Z", "bzip2", "t.zip", "a.txt", "big.txt",
            ],
            &["zip", "-Z", "bzip2", "-", "a.txt", "b.txt"],
            &["zip", "-l", "-Z", "bzip2", "t.zip", "b.txt", "r10k"],
            &["zip", "-ll", "-Z", "bzip2", "t.zip", "big.txt"],
            &["zip", "-Z", "bzip2", "-s", "64k", "t.zip", "r300k"],
            &["zip", "-Z", "bzip2", "-r", "t.zip", "."],
        ] {
            push(&mut cases, args, bz_tree(), None, &[]);
        }
        push(
            &mut cases,
            &["zip", "-Z", "bzip2", "t.zip", "-"],
            bz_tree(),
            Some(&big),
            &[],
        );
        assert!(cases.len() >= 200, "{} cases", cases.len());
        run_group(
            "zip ubuntu build",
            &cases,
            Skipped::none(),
            &assert_same_zip,
        );
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
