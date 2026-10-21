//! The unzip family's Ubuntu flavour against its reference, apt's `unzip`
//! 6.0-28ubuntu4.1 on ubuntu 24.04 (0.16.0). Linux only: CI's ubuntu-latest
//! has the package, and `make compat-ubuntu` runs this suite in a Docker
//! image that has it (ruling R10). The shared rows are in
//! `compat_unzip_common.rs`; this suite holds the differentials of Ubuntu's
//! own build options (Task 13: `ubuntu_build_rows`) and, from Task 14, of
//! its patches.

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

    // ---- archives ----

    /// The locales deviation 6 promises identity under, glibc's `.utf8`
    /// spellings of them, and the settings `nl_langinfo(CODESET)` decides
    /// between (`LC_CTYPE` over `LANG`, `LC_ALL` over both, a locale that
    /// does not exist).
    const LOCALES: &[&[(&str, &str)]] = &[
        &[("LANG", "C")],
        &[("LANG", "C.UTF-8")],
        &[("LANG", "en_US.UTF-8")],
        &[("LANG", "en_US.utf8")],
        &[("LANG", "C.utf8")],
        &[("LC_CTYPE", "en_US.UTF-8")],
        &[("LC_ALL", "C"), ("LANG", "en_US.UTF-8")],
        &[("LANG", "xx_XX.UTF-8")],
    ];

    /// The three locales of deviation 6.
    const PROMISED: &[&[(&str, &str)]] = &[
        &[("LANG", "C")],
        &[("LANG", "C.UTF-8")],
        &[("LANG", "en_US.UTF-8")],
    ];

    fn block(id: u16, data: &[u8]) -> Vec<u8> {
        extra_block(id, data)
    }

    /// An Info-ZIP `UT` block (mtime only): any extra field, so the
    /// Unicode build looks at the name again.
    fn ut() -> Vec<u8> {
        block(0x5455, &[1, 0x26, 0x6b, 0x0d, 0x5e])
    }

    /// A Unicode Path block (`0x7075`, version `ver`) whose checksum is the
    /// CRC of `crc_of`, holding `name`.
    fn unipath(crc_of: &[u8], name: &[u8], ver: u8) -> Vec<u8> {
        let mut d = vec![ver];
        d.extend_from_slice(&crc32(crc_of).to_le_bytes());
        d.extend_from_slice(name);
        block(0x7075, &d)
    }

    fn with_extra<'a>(name: &'a [u8], data: &'a [u8], extra: &'a [u8]) -> ZipEntrySpec<'a> {
        ZipEntrySpec {
            extra,
            ..ZipEntrySpec::new(name, data)
        }
    }

    fn utf8_flagged<'a>(name: &'a [u8], extra: &'a [u8]) -> ZipEntrySpec<'a> {
        ZipEntrySpec {
            flags: 0x800,
            extra,
            ..ZipEntrySpec::new(name, b"x")
        }
    }

    /// Names: high bytes and DEL (`NO_WORKING_ISPRINT`), valid and invalid
    /// UTF-8, control bytes.
    fn names_zip() -> Vec<u8> {
        zip_with(
            &[
                ZipEntrySpec::new(b"c\x80\xa0\xad\xe9\xff\x7f.txt", b"x"),
                ZipEntrySpec::new("caf\u{e9}.txt".as_bytes(), b"x"),
                ZipEntrySpec::new(b"bad\xc3(.txt", b"y"),
                ZipEntrySpec::new("\u{1f600}.txt".as_bytes(), b"z"),
                ZipEntrySpec::new(b"ctl\x01\x1f.txt", b"w"),
            ],
            b"",
            b"",
        )
    }

    /// General-purpose bit 11: without an extra field (left as stored),
    /// with one (converted), a 4-byte character, a name that is not UTF-8
    /// ("Unicode filename corrupt", the listing ends).
    fn gp11_zip() -> Vec<u8> {
        let ut = ut();
        zip_with(
            &[
                utf8_flagged("caf\u{e9}.txt".as_bytes(), b""),
                utf8_flagged("caf\u{e9}x.txt".as_bytes(), &ut),
                utf8_flagged("\u{1f600}.txt".as_bytes(), &ut),
                utf8_flagged(b"bad\xc3(.txt", &ut),
            ],
            b"",
            b"",
        )
    }

    /// Unicode Path blocks: good, bad checksum, version 2, empty (the
    /// stored name is UTF-8), a 4-byte character, not UTF-8 (fatal for a
    /// listing), a directory.
    fn unipath_zip() -> Vec<u8> {
        let b = [
            unipath(b"plain.txt", "\u{fc}n\u{ef}.txt".as_bytes(), 1),
            unipath(b"other", "\u{fc}n.txt".as_bytes(), 1),
            unipath(b"v2.txt", "\u{fc}v.txt".as_bytes(), 2),
            unipath("caf\u{e9}.txt".as_bytes(), b"", 1),
            unipath(b"emo.txt", "\u{1f600}.txt".as_bytes(), 1),
            unipath(b"inv.txt", b"x\xc3(.txt", 1),
            unipath(b"dir/a.txt", "d\u{ef}r/\u{e4}.txt".as_bytes(), 1),
        ];
        zip_with(
            &[
                with_extra(b"plain.txt", b"x", &b[0]),
                with_extra(b"bad.txt", b"x", &b[1]),
                with_extra(b"v2.txt", b"x", &b[2]),
                with_extra("caf\u{e9}.txt".as_bytes(), b"x", &b[3]),
                with_extra(b"emo.txt", b"x", &b[4]),
                with_extra(b"inv.txt", b"x", &b[5]),
                with_extra(b"dir/a.txt", b"x", &b[6]),
            ],
            b"",
            b"",
        )
    }

    /// Unicode Path oddities: two blocks (the later good one wins, a later
    /// bad one keeps the earlier), a name with a NUL (the checksum is the
    /// C string's), a 5-byte character (an escape cut short under `C`),
    /// names past `FILNAMSIZ`, and entries with no name (the last name
    /// read is used). A block shorter than its five fixed bytes reads past
    /// the field in the C (T13-5): pinned stuffr-only, in
    /// `extract::tests::unicode_rulings`.
    fn unipath_odd_zips() -> Vec<(&'static str, Vec<u8>)> {
        let m1 = [
            unipath(b"m.txt", "\u{fc}1.txt".as_bytes(), 1),
            unipath(b"other", "\u{fc}2.txt".as_bytes(), 1),
        ]
        .concat();
        let m2 = [
            unipath(b"m.txt", "\u{fc}1.txt".as_bytes(), 1),
            unipath(b"m.txt", "\u{fc}3.txt".as_bytes(), 1),
        ]
        .concat();
        let nul = unipath(b"ab", "\u{fc}b.txt".as_bytes(), 1);
        let five = unipath(b"f.txt", b"\xfb\xbf\xbf\xbf\xbf", 1);
        let long_u8 = "\u{e9}".repeat(2100).into_bytes(); // 4200 bytes
        let long_name = [long_u8.as_slice(), b".txt"].concat();
        let b200 = vec![b'b'; 200];
        let a4500 = vec![b'a'; 4500];
        let long_path = unipath(&b200, &long_u8, 1);
        let ut = ut();
        let stale_up = unipath(b"first.txt", "\u{fc}.txt".as_bytes(), 1);
        vec![
            (
                "multi.zip",
                zip_with(
                    &[
                        with_extra(b"m.txt", b"x", &m1),
                        with_extra(b"m.txt", b"y", &m2),
                    ],
                    b"",
                    b"",
                ),
            ),
            (
                "nul.zip",
                zip_with(&[with_extra(b"ab\0cd", b"x", &nul)], b"", b""),
            ),
            (
                "five.zip",
                zip_with(&[with_extra(b"f.txt", b"x", &five)], b"", b""),
            ),
            (
                "long.zip",
                zip_with(
                    &[
                        utf8_flagged(&long_name, &ut),
                        ZipEntrySpec::new(&a4500, b"y"),
                        with_extra(&b200, b"z", &long_path),
                    ],
                    b"",
                    b"",
                ),
            ),
            (
                "stale.zip",
                zip_with(
                    &[
                        ZipEntrySpec::new(b"first.txt", b"x"),
                        utf8_flagged(b"", &ut),
                        with_extra(b"", b"z", &stale_up),
                    ],
                    b"",
                    b"",
                ),
            ),
        ]
    }

    /// A stored entry whose local and central headers differ: `(name,
    /// local flags, central flags, local extra, central extra)`.
    type Split<'a> = (&'a [u8], u16, u16, &'a [u8], &'a [u8]);

    /// Stored entries whose local and central headers differ.
    fn split_zip(entries: &[Split]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cd = Vec::new();
        let data = b"x";
        let crc = crc32(data);
        for &(name, lflags, cflags, lextra, cextra) in entries {
            let off = out.len() as u32;
            out.extend_from_slice(b"PK\x03\x04\x14\x00");
            out.extend_from_slice(&lflags.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&DOS_TIME_2020.to_le_bytes());
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&1u32.to_le_bytes());
            out.extend_from_slice(&1u32.to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&(lextra.len() as u16).to_le_bytes());
            out.extend_from_slice(name);
            out.extend_from_slice(lextra);
            out.extend_from_slice(data);
            cd.extend_from_slice(b"PK\x01\x02\x1e\x03\x14\x00");
            cd.extend_from_slice(&cflags.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&DOS_TIME_2020.to_le_bytes());
            cd.extend_from_slice(&crc.to_le_bytes());
            cd.extend_from_slice(&1u32.to_le_bytes());
            cd.extend_from_slice(&1u32.to_le_bytes());
            cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
            cd.extend_from_slice(&(cextra.len() as u16).to_le_bytes());
            cd.extend_from_slice(&[0; 8]);
            cd.extend_from_slice(&(0o100644u32 << 16).to_le_bytes());
            cd.extend_from_slice(&off.to_le_bytes());
            cd.extend_from_slice(name);
            cd.extend_from_slice(cextra);
        }
        let cd_at = out.len() as u32;
        let n = entries.len() as u16;
        out.extend_from_slice(&cd);
        out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_at.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    /// Local and central headers that disagree: bit 11 (GP11FlagsDiffer)
    /// and the Unicode Path block (only local, only central, different).
    fn split_zips() -> Vec<(&'static str, Vec<u8>)> {
        let ut = ut();
        let cafe = "caf\u{e9}.txt".as_bytes();
        let l = unipath(b"plain.txt", "\u{fc}l.txt".as_bytes(), 1);
        let c = unipath(b"plain.txt", "\u{fc}c.txt".as_bytes(), 1);
        vec![
            (
                "gp11diff.zip",
                split_zip(&[
                    (cafe, 0, 0x800, &ut, &ut),
                    (b"plain.txt", 0x800, 0, &ut, &ut),
                ]),
            ),
            ("uplocal.zip", split_zip(&[(b"plain.txt", 0, 0, &l, b"")])),
            ("upcentral.zip", split_zip(&[(b"plain.txt", 0, 0, b"", &c)])),
            ("upboth.zip", split_zip(&[(b"plain.txt", 0, 0, &l, &c)])),
        ]
    }

    /// bzip2 (method 12, `USE_BZIP2`): good, damaged and odd entries, one
    /// buffer and many.
    fn bzip2_zips() -> Vec<(&'static str, Vec<u8>)> {
        let line = b"bzip2 sample line for stuffr fixtures\n".repeat(200);
        let mut seed = 13u64;
        let random: Vec<u8> = (0..60000)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed as u8
            })
            .collect();
        let big = random.repeat(2);
        let bz = |d: &[u8]| stuffr_encode("bzip2", d, None);
        let small = bz(&line);
        let large = bz(&big);
        let flip = |b: &[u8], at: usize, x: u8| {
            let mut v = b.to_vec();
            v[at] ^= x;
            v
        };
        let magic = |b: &[u8]| [b"XZh9".as_slice(), &b[4..]].concat();
        let one = |name: &'static [u8], data: &[u8], body: &[u8]| {
            zip_with(
                &[ZipEntrySpec {
                    method: 12,
                    stored_data: Some(body),
                    ..ZipEntrySpec::new(name, data)
                }],
                b"",
                b"",
            )
        };
        let hello = b"hello\n".repeat(30);
        let two = zip_with(
            &[
                ZipEntrySpec {
                    method: 12,
                    stored_data: Some(&small),
                    ..ZipEntrySpec::new(b"s.txt", &line)
                },
                ZipEntrySpec {
                    method: 12,
                    stored_data: Some(&bz(&hello)),
                    ..ZipEntrySpec::new(b"t.txt", &hello)
                },
            ],
            b"",
            b"",
        );
        let enc_body = zipcrypto(b"secret", (crc32(&line) >> 24) as u8, &small);
        let enc = zip_with(
            &[ZipEntrySpec {
                method: 12,
                flags: 1,
                stored_data: Some(&enc_body),
                ..ZipEntrySpec::new(b"s.txt", &line)
            }],
            b"",
            b"",
        );
        let big_enc_body = zipcrypto(b"secret", (crc32(&big) >> 24) as u8, &large);
        let big_enc = zip_with(
            &[ZipEntrySpec {
                method: 12,
                flags: 1,
                stored_data: Some(&big_enc_body),
                ..ZipEntrySpec::new(b"big.bin", &big)
            }],
            b"",
            b"",
        );
        let mut v = vec![
            ("ok.zip", one(b"s.txt", &line, &small)),
            ("flip.zip", one(b"s.txt", &line, &flip(&small, 40, 0x55))),
            ("magic.zip", one(b"s.txt", &line, &magic(&small))),
            (
                "crc.zip",
                zip_with(
                    &[ZipEntrySpec {
                        method: 12,
                        stored_data: Some(&small),
                        ..ZipEntrySpec::new(b"s.txt", b"not the data")
                    }],
                    b"",
                    b"",
                ),
            ),
            ("two.zip", two),
            ("big.zip", one(b"big.bin", &big, &large)),
            (
                "bigflip.zip",
                one(b"big.bin", &big, &flip(&large, 30000, 0xff)),
            ),
            ("bigmagic.zip", one(b"big.bin", &big, &magic(&large))),
            (
                "trail.zip",
                one(
                    b"s.txt",
                    &line,
                    &[small.as_slice(), &b"junk".repeat(10)].concat(),
                ),
            ),
            ("empty.zip", one(b"e.txt", b"", &bz(b""))),
            ("zero.zip", one(b"z.txt", b"abc", b"")),
            ("enc.zip", enc),
            ("bigenc.zip", big_enc),
        ];
        // The fixture whose README records Ubuntu's `-t` answer.
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../stuffr-formats/tests/data/infozip/bzip2.zip");
        if let Ok(b) = std::fs::read(&fixture) {
            v.push(("bzip2.zip", b));
        }
        v
    }

    /// A SparkFS block (`ACORN_FTYPE_NFS`'s `-F`): `ARC0` (or another id),
    /// the load address and 12 (or 16) more bytes.
    fn spark(load: u32, long: bool, id: &[u8; 4]) -> Vec<u8> {
        let mut d = id.to_vec();
        d.extend_from_slice(&load.to_le_bytes());
        d.extend_from_slice(&[0; 12]);
        if long {
            d.extend_from_slice(&[0; 4]);
        }
        block(0x4341, &d)
    }

    /// Names with and without commas and SparkFS blocks.
    fn acorn_zip() -> Vec<u8> {
        let ok = spark(0xFFFF_FB00, false, b"ARC0");
        let typed = spark(0xFFF1_2300, false, b"ARC0");
        let untyped = spark(0x0000_1234, false, b"ARC0");
        let long = spark(0xFFFA_AA00, true, b"ARC0");
        let wrong = spark(0xFFFF_FB00, false, b"ARC1");
        let short = block(0x4341, b"ARC0\0\0\0\0");
        let names: &[(&[u8], &[u8])] = &[
            (b"plain", &ok),
            (b"typed,ffb", &typed),
            (b"noft", &untyped),
            (b"d,abc/in", &long),
            (b"wrongid", &wrong),
            (b"shortblk", &short),
            (b"two,12,abcd", &ok),
            (b"x;1", &ok),
            (b"dir,f/n,1a", &ok),
            (b"q,FFF", &ok),
            (b"r,ff", &ok),
            (b"..", &ok),
            (b"s,abc;2", &ok),
            (b"u,abcde", &ok),
            (b"t,abc,def", &ok),
            (b"none", b""),
        ];
        let specs: Vec<ZipEntrySpec> = names.iter().map(|(n, e)| with_extra(n, b"a", e)).collect();
        zip_with(&specs, b"", b"")
    }

    /// Paths for `-W`.
    fn wild_zip() -> Vec<u8> {
        zip_with(
            &[
                ZipEntrySpec::new(b"a.txt", b"1"),
                ZipEntrySpec::new(b"d/a.txt", b"2"),
                ZipEntrySpec::new(b"d/e/a.txt", b"3"),
                ZipEntrySpec::new(b"d/b.c", b"4"),
                ZipEntrySpec::new(b"[x].txt", b"5"),
            ],
            b"",
            b"",
        )
    }

    /// Dates from 1980 to 2107 (the DOS range), for `DF_YMD` listings.
    fn dates_zip() -> Vec<u8> {
        let at = |y: u32, mo: u32, d: u32| ((((y - 1980) << 9) | (mo << 5) | d) << 16) | (13 << 11);
        let dates = [
            at(1980, 1, 1),
            at(1999, 12, 31),
            at(2026, 10, 21),
            at(2107, 12, 31),
        ];
        let names = [b"a".as_slice(), b"b", b"c", b"d"];
        let specs: Vec<ZipEntrySpec> = names
            .iter()
            .zip(dates)
            .map(|(n, dos_time)| ZipEntrySpec {
                dos_time,
                ..ZipEntrySpec::new(n, b"x")
            })
            .collect();
        zip_with(&specs, b"", b"")
    }

    /// MS-DOS times (no `UT` block) a zone's rules treat apart: winter,
    /// summer, the spring-forward gap, 2037, 2100.
    fn zone_times_zip() -> Vec<u8> {
        let at = |y: u32, mo: u32, d: u32, h: u32, mi: u32| {
            ((((y - 1980) << 9) | (mo << 5) | d) << 16) | (h << 11) | (mi << 5)
        };
        let times = [
            (b"winter.txt".as_slice(), at(2020, 1, 15, 12, 0)),
            (b"summer.txt", at(2020, 7, 15, 12, 0)),
            (b"gap.txt", at(2020, 3, 8, 2, 30)),
            (b"late.txt", at(2037, 7, 1, 0, 0)),
            (b"far.txt", at(2100, 7, 1, 0, 0)),
        ];
        let specs: Vec<ZipEntrySpec> = times
            .iter()
            .map(|&(n, dos_time)| ZipEntrySpec {
                dos_time,
                ..ZipEntrySpec::new(n, b"x")
            })
            .collect();
        zip_with(&specs, b"", b"")
    }

    /// `ux` owners (`IZ_HAVE_UXUIDGID`, `-X`): this user's, and root's.
    fn owners_zip() -> Vec<u8> {
        // SAFETY: getuid() and getgid() cannot fail.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let ux = |u: u32, g: u32| {
            let mut d = vec![1, 4];
            d.extend_from_slice(&u.to_le_bytes());
            d.push(4);
            d.extend_from_slice(&g.to_le_bytes());
            block(0x7875, &d)
        };
        let (mine, root) = (ux(uid, gid), ux(0, 0));
        zip_with(
            &[
                with_extra(b"mine.txt", b"m", &mine),
                with_extra(b"root.txt", b"r", &root),
            ],
            b"",
            b"",
        )
    }

    /// Symbolic links (`NO_LCHMOD`: their modes are not set).
    fn links_zip() -> Vec<u8> {
        zip_with(
            &[
                ZipEntrySpec::new(b"t.txt", b"target"),
                ZipEntrySpec {
                    external_attr: 0o120777 << 16,
                    ..ZipEntrySpec::new(b"l", b"t.txt")
                },
                ZipEntrySpec {
                    external_attr: 0o120700 << 16,
                    ..ZipEntrySpec::new(b"l2", b"t.txt")
                },
            ],
            b"",
            b"",
        )
    }

    fn case<'a>(
        name: &'a str,
        args: &[&'a str],
        files: &[(&'a str, Vec<u8>)],
        env: &[(&'a str, &'a str)],
    ) -> Case<'a> {
        let mut c = unzip_case(name, args.to_vec(), files.to_vec());
        c.env = env.to_vec();
        c
    }

    fn check(group: &str, cases: &[Case]) {
        run_group(group, cases, Skipped::none(), &assert_same_unzip);
    }

    /// Ubuntu's build options (Task 13), against its binary: the `-v`
    /// screen's "char coding" per locale; names (`NO_WORKING_ISPRINT`,
    /// `UNICODE_SUPPORT` with `UTF8_MAYBE_NATIVE` and `UNICODE_WCHAR`) in
    /// listings, zipinfo, tests and extraction per locale; bzip2 entries
    /// (`USE_BZIP2`); Acorn filetypes (`ACORN_FTYPE_NFS`); `-W`
    /// (`WILD_STOP_AT_DIR`); `DF_YMD` dates; owners (`IZ_HAVE_UXUIDGID`)
    /// and symlinks (`NO_LCHMOD`). The probes behind each are in
    /// `.claude/rules/compat.md`, "Task 13 probes".
    #[test]
    fn ubuntu_build_rows() {
        // -v per locale
        let cases: Vec<Case> = LOCALES
            .iter()
            .map(|env| case("unzip", &["-v"], &[], env))
            .collect();
        check("-v per locale", &cases);

        // names per locale
        let mut files = vec![
            ("names.zip", names_zip()),
            ("gp11.zip", gp11_zip()),
            ("up.zip", unipath_zip()),
        ];
        files.extend(unipath_odd_zips());
        files.extend(split_zips());
        let mut cases = Vec::new();
        for (i, env) in LOCALES.iter().enumerate() {
            for (z, _) in &files {
                let ops: &[&[&str]] = if i < PROMISED.len() {
                    &[&["-l"], &["-t"], &[], &["-Z"], &["-Z", "-1"], &["-Z", "-v"]]
                } else {
                    &[&["-l"], &[]]
                };
                for op in ops {
                    let mut args = op.to_vec();
                    args.push(z);
                    cases.push(case("unzip", &args, &files, env));
                }
            }
        }
        check("names per locale", &cases);

        // -U and -UU, and names matched in their converted form
        let mut cases = Vec::new();
        for env in PROMISED {
            for args in [
                &["-U", "-l", "up.zip"][..],
                &["-UU", "-l", "up.zip"],
                &["-U", "-l", "gp11.zip"],
                &["-UU", "-t", "gp11.zip"],
                &["-U-U", "-l", "gp11.zip"],
                &["-U", "gp11.zip"],
                &["-U", "-t", "long.zip"],
                &["-Z", "-U", "gp11.zip"],
                &["-Z", "-UU", "gp11.zip"],
                &["-l", "up.zip", "#U00fc*"],
                &["-l", "up.zip", "\u{fc}*"],
                &["-Z", "up.zip", "#U00fc*"],
                &["-Z", "up.zip", "plain*"],
                &["-p", "up.zip", "#U00fcn#U00ef.txt"],
                &["-c", "gp11.zip"],
                &["-qt", "gp11diff.zip"],
            ] {
                cases.push(case("unzip", args, &files, env));
            }
        }
        check("-U and matching", &cases);

        // bzip2
        let bz = bzip2_zips();
        let mut cases = Vec::new();
        for f in &bz {
            let z = f.0;
            let own = std::slice::from_ref(f);
            for op in [
                &["-t"][..],
                &[],
                &["-p"],
                &["-tq"],
                &["-q"],
                &["-l"],
                &["-v"],
            ] {
                let mut args = op.to_vec();
                args.push(z);
                cases.push(case("unzip", &args, own, &[]));
            }
            cases.push(case("unzip", &["-P", "secret", "-t", z], own, &[]));
            cases.push(case("unzip", &["-P", "secret", z], own, &[]));
            cases.push(case("zipinfo", &["-v", z], own, &[]));
            if z == "ok.zip" {
                cases.push(case("unzip", &["-c", z], own, &[]));
            }
            if z == "enc.zip" {
                cases.push(case("unzip", &["-P", "wrong", "-t", z], own, &[]));
            }
        }
        check("bzip2", &cases);

        // Acorn filetypes
        let files = vec![("acorn.zip", acorn_zip())];
        let cases: Vec<Case> = [
            &["acorn.zip"][..],
            &["-F", "acorn.zip"],
            &["-F", "-d", "out", "acorn.zip"],
            &["-FV", "acorn.zip"],
            &["-F-F", "acorn.zip"],
            &["-Fj", "acorn.zip"],
            &["-F", "-:", "acorn.zip"],
            &["-Fl", "acorn.zip"],
            &["-Ft", "acorn.zip"],
            &["-Fv", "acorn.zip"],
        ]
        .iter()
        .map(|a| case("unzip", a, &files, &[]))
        // zipinfo has no `-F`: its usage, with the `-O`/`-I` lines of
        // 20-unzip60-alt-iconv-utf8.patch
        .chain([case("zipinfo", &["-F", "acorn.zip"], &files, &[])])
        .collect();
        check("Acorn filetypes", &cases);

        // -W
        let files = vec![("w.zip", wild_zip())];
        let mut cases = Vec::new();
        for pat in [
            "*.txt", "*/*.txt", "**.txt", "d/**", "d/*", "?/a.txt", "d?a.txt", "*", "**", "[ad]*",
            "d/[a-c]*", "*/*/*",
        ] {
            cases.push(case("unzip", &["-W", "-l", "w.zip", pat], &files, &[]));
            cases.push(case("unzip", &["-l", "w.zip", pat], &files, &[]));
            cases.push(case("zipinfo", &["-W", "-1", "w.zip", pat], &files, &[]));
        }
        for args in [
            &["-W-W", "-l", "w.zip", "*.txt"][..],
            &["-W", "w.zip", "*.c", "-x", "d/*"],
            &["-W", "w.zip", "*", "-x", "*.txt"],
            &["-W", "w.zip", "d/*"],
            &["-WC", "-l", "w.zip", "D/*"],
        ] {
            cases.push(case("unzip", args, &files, &[]));
        }
        check("-W", &cases);

        // DF_YMD
        let files = vec![("dates.zip", dates_zip())];
        let cases: Vec<Case> = [&["-l"][..], &["-v"], &["-lq"], &["-M", "-l"]]
            .iter()
            .map(|op| {
                let mut args = op.to_vec();
                args.push("dates.zip");
                case("unzip", &args, &files, &[])
            })
            .chain([
                case("zipinfo", &["-l", "dates.zip"], &files, &[]),
                case("zipinfo", &["-T", "dates.zip"], &files, &[]),
            ])
            .collect();
        check("DF_YMD", &cases);

        // DOS times off UTC: Linux's `dos_to_unix_time()` (no `BSD4_4`)
        // adds `timezone` and takes an hour off in summer time. POSIX zone
        // strings: the image has no tzdata.
        let files = vec![("tz.zip", zone_times_zip())];
        let mut cases = Vec::new();
        for tz in [
            "EST5EDT,M3.2.0,M11.1.0",
            "CET-1CEST,M3.5.0,M10.5.0/3",
            "LHST-10:30LHDT-11,M10.1.0,M4.1.0",
            "<+0545>-5:45",
        ] {
            for args in [
                &["tz.zip"][..],
                &["-T", "tz.zip"],
                &["-l", "tz.zip"],
                &["-Z", "-T", "tz.zip"],
            ] {
                let mut c = case("unzip", args, &files, &[]);
                c.tz = Some(tz);
                cases.push(c);
            }
        }
        check("DOS times off UTC", &cases);

        // owners and symlinks
        let files = vec![("ux.zip", owners_zip()), ("ln.zip", links_zip())];
        let cases: Vec<Case> = [
            &["ux.zip"][..],
            &["-X", "ux.zip"],
            &["-Xq", "ux.zip"],
            &["-XX", "ux.zip"],
            &["ln.zip"],
            &["-X", "ln.zip"],
            &["-K", "ln.zip"],
        ]
        .iter()
        .map(|a| case("unzip", a, &files, &[]))
        .collect();
        check("owners and symlinks", &cases);
    }

    // ---- the patch series (Task 14) ----

    /// An OS/2 EA block (`0x0009`) whose stored data is `n` bytes and whose
    /// uncompressed size says `ucsize`: 12-cve-2014-9636 wants them equal.
    fn os2_ea(n: usize, ucsize: u32) -> Vec<u8> {
        let d = vec![b'E'; n];
        let mut eb = ucsize.to_le_bytes().to_vec();
        eb.extend_from_slice(&0u16.to_le_bytes());
        eb.extend_from_slice(&crc32(&d).to_le_bytes());
        eb.extend_from_slice(&d);
        block(0x0009, &eb)
    }

    /// An encrypted entry whose body is `len` bytes: shorter than the
    /// 12-byte encryption header for 14-cve-2015-7696 (deflated) and
    /// 16-fix-integer-underflow-csiz-decrypted (stored).
    fn short_crypt(name: &[u8], method: u16, len: usize) -> ZipEntrySpec<'_> {
        const BODY: &[u8] = &[0x11; 12];
        ZipEntrySpec {
            method,
            flags: 1,
            stored_data: Some(&BODY[..len]),
            ..ZipEntrySpec::new(name, b"ab")
        }
    }

    /// The CVE fixes' own triggers (09, 10, 11, 12, 14, 16, 18, 19), each
    /// followed by plain entries so what the fix leaves for the next entry
    /// shows too.
    fn cve_zips() -> Vec<(&'static str, Vec<u8>)> {
        let plain = |name: &'static [u8], data: &'static [u8]| ZipEntrySpec::new(name, data);
        let (ea_ok, ea_apple, ea_bad, ea_zero) = (
            os2_ea(10, 10),
            os2_ea(10, 16),
            os2_ea(10, 30),
            os2_ea(10, 0),
        );
        let vms_short = block(0x000c, &[1, 2]);
        let vms_bad = block(0x000c, &[1, 2, 3, 4, 5, 6]);
        let z64_short = block(0x0001, &[1, 2, 3, 4]);
        let ea = |extra: &[u8]| {
            zip_with(
                &[ZipEntrySpec {
                    extra,
                    ..ZipEntrySpec::new(b"a.txt", b"hi\n")
                }],
                b"",
                b"",
            )
        };
        let z64 = ZipEntrySpec {
            extra: &z64_short,
            ..ZipEntrySpec::new(b"z.txt", b"x")
        };
        let methods = zip_with(
            &[
                ZipEntrySpec {
                    method: 1000,
                    ..plain(b"m.txt", b"x")
                },
                ZipEntrySpec {
                    method: 65535,
                    ..plain(b"n.txt", b"y")
                },
                ZipEntrySpec {
                    method: 999,
                    ..plain(b"o.txt", b"z")
                },
            ],
            b"",
            b"",
        );
        let crypt = |first: ZipEntrySpec| {
            zip_with(
                &[
                    first,
                    plain(b"b.txt", b"bye\n"),
                    plain(b"c.txt", b"three\n"),
                ],
                b"",
                b"",
            )
        };
        vec![
            ("ea_ok.zip", ea(&ea_ok)),
            ("ea_apple.zip", ea(&ea_apple)),
            ("ea_bad.zip", ea(&ea_bad)),
            ("ea_zero.zip", ea(&ea_zero)),
            ("vms_short.zip", ea(&vms_short)),
            ("vms_bad.zip", ea(&vms_bad)),
            (
                "z64_short.zip",
                zip_with(&[z64, plain(b"b.txt", b"b")], b"", b""),
            ),
            ("methods.zip", methods),
            ("crypt_defl.zip", crypt(short_crypt(b"a.txt", 8, 5))),
            ("crypt_stor.zip", crypt(short_crypt(b"a.txt", 0, 5))),
            ("crypt_stor0.zip", crypt(short_crypt(b"a.txt", 0, 0))),
            ("crypt_stor11.zip", crypt(short_crypt(b"a.txt", 0, 11))),
            (
                "crypt_last.zip",
                zip_with(
                    &[plain(b"b.txt", b"bye\n"), short_crypt(b"a.txt", 8, 5)],
                    b"",
                    b"",
                ),
            ),
        ]
    }

    /// The bytes `zip_with` stores for `e`.
    fn body_of(e: &ZipEntrySpec) -> Vec<u8> {
        match e.stored_data {
            Some(b) => b.to_vec(),
            None if e.method == 8 => deflate_raw(e.data),
            None => e.data.to_vec(),
        }
    }

    /// `e`'s local header and data as `zip_with` writes them (a bit-3
    /// entry's CRC and sizes zero), without its data descriptor.
    fn local_bytes(e: &ZipEntrySpec) -> Vec<u8> {
        let body = body_of(e);
        let dd = e.flags & 8 != 0;
        let (crc, cs, us) = if dd {
            (0, 0, 0)
        } else {
            (crc32(e.data), body.len() as u32, e.data.len() as u32)
        };
        let (time, date) = ((e.dos_time & 0xffff) as u16, (e.dos_time >> 16) as u16);
        let mut o = b"PK\x03\x04".to_vec();
        for v in [20u16, e.flags, e.method, time, date] {
            o.extend_from_slice(&v.to_le_bytes());
        }
        for v in [crc, cs, us] {
            o.extend_from_slice(&v.to_le_bytes());
        }
        o.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
        o.extend_from_slice(&(e.extra.len() as u16).to_le_bytes());
        o.extend_from_slice(e.name);
        o.extend_from_slice(e.extra);
        o.extend(body);
        o
    }

    /// `e`'s data descriptor: signed (`PK\7\8` first) or not.
    fn descriptor(e: &ZipEntrySpec, signed: bool) -> Vec<u8> {
        let mut d = if signed {
            b"PK\x07\x08".to_vec()
        } else {
            Vec::new()
        };
        for v in [crc32(e.data), body_of(e).len() as u32, e.data.len() as u32] {
            d.extend_from_slice(&v.to_le_bytes());
        }
        d
    }

    /// A hand-laid archive (patches 22-24): local entries in order, central
    /// records pointing anywhere, the directory where `put_central` puts it
    /// (after the entries by default), then the end record.
    #[derive(Default)]
    struct Raw {
        out: Vec<u8>,
        central: Vec<u8>,
        n: u16,
        /// Where the directory was put, and its length.
        cd: Option<(u32, u32)>,
    }

    impl Raw {
        /// `e` and `tail` (its descriptor, if any) at the end; its offset.
        fn local(&mut self, e: &ZipEntrySpec, tail: &[u8]) -> u32 {
            let at = self.out.len() as u32;
            self.out.extend(local_bytes(e));
            self.out.extend_from_slice(tail);
            at
        }

        /// A central record for `e` pointing at `offset`.
        fn central(&mut self, e: &ZipEntrySpec, offset: u32) {
            let (time, date) = ((e.dos_time & 0xffff) as u16, (e.dos_time >> 16) as u16);
            let c = &mut self.central;
            c.extend_from_slice(b"PK\x01\x02");
            for v in [e.version_made_by, 20, e.flags, e.method, time, date] {
                c.extend_from_slice(&v.to_le_bytes());
            }
            for v in [crc32(e.data), body_of(e).len() as u32, e.data.len() as u32] {
                c.extend_from_slice(&v.to_le_bytes());
            }
            for v in [e.name.len() as u16, e.extra.len() as u16, 0, 0, 0] {
                c.extend_from_slice(&v.to_le_bytes());
            }
            c.extend_from_slice(&e.external_attr.to_le_bytes());
            c.extend_from_slice(&offset.to_le_bytes());
            c.extend_from_slice(e.name);
            c.extend_from_slice(e.extra);
            self.n += 1;
        }

        /// The central directory written here, ahead of what follows.
        fn put_central(&mut self) {
            let c = std::mem::take(&mut self.central);
            self.cd = Some((self.out.len() as u32, c.len() as u32));
            self.out.extend(c);
        }

        /// The archive, its directory after the entries unless already put.
        fn finish(mut self) -> Vec<u8> {
            if self.cd.is_none() {
                self.put_central();
            }
            let (cd_at, cd_len) = self.cd.unwrap_or_default();
            let mut z = self.out;
            z.extend(end_record(self.n, cd_len, cd_at));
            z
        }
    }

    /// A classic end record.
    fn end_record(n: u16, cd_len: u32, cd_at: u32) -> Vec<u8> {
        let mut e = b"PK\x05\x06".to_vec();
        for v in [0u16, 0, n, n] {
            e.extend_from_slice(&v.to_le_bytes());
        }
        e.extend_from_slice(&cd_len.to_le_bytes());
        e.extend_from_slice(&cd_at.to_le_bytes());
        e.extend_from_slice(&0u16.to_le_bytes());
        e
    }

    /// `v` written little-endian at `z[at..at + 4]`.
    fn put_u32(z: &mut [u8], at: usize, v: u32) {
        z[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// A Zip64 archive of one entry (and a second central record pointing
    /// at `second`, if given): its Zip64 end record and locator (`disks` in
    /// the locator's total), then a classic end record whose counts and
    /// directory fields defer to them.
    fn zip64_zip(disks: u32, second: Option<u32>) -> Vec<u8> {
        let a = ZipEntrySpec::new(b"a.txt", b"hello\n");
        let mut r = Raw::default();
        r.local(&a, b"");
        r.central(&a, 0);
        if let Some(off) = second {
            r.central(&ZipEntrySpec::new(b"z.txt", b"x"), off);
        }
        let n = u64::from(r.n);
        let cd_at = r.out.len() as u64;
        let cd_len = r.central.len() as u64;
        r.put_central();
        let mut z = r.out;
        let rec_at = z.len() as u64;
        z.extend_from_slice(b"PK\x06\x06");
        z.extend_from_slice(&44u64.to_le_bytes());
        for v in [0x031eu16, 45] {
            z.extend_from_slice(&v.to_le_bytes());
        }
        for v in [0u32, 0] {
            z.extend_from_slice(&v.to_le_bytes());
        }
        for v in [n, n, cd_len, cd_at] {
            z.extend_from_slice(&v.to_le_bytes());
        }
        z.extend_from_slice(b"PK\x06\x07");
        z.extend_from_slice(&0u32.to_le_bytes());
        z.extend_from_slice(&rec_at.to_le_bytes());
        z.extend_from_slice(&disks.to_le_bytes());
        z.extend_from_slice(b"PK\x05\x06");
        for v in [0u16, 0, 0xffff, 0xffff] {
            z.extend_from_slice(&v.to_le_bytes());
        }
        for v in [0xffff_ffffu32, 0xffff_ffff] {
            z.extend_from_slice(&v.to_le_bytes());
        }
        z.extend_from_slice(&0u16.to_le_bytes());
        z
    }

    /// The shapes of CVE-2019-13232's patches (22-24): overlapped entries
    /// (David Fifield's construction at a small size, both directory
    /// orders; entries sharing one local header; entries pointing into the
    /// directory or the end records; an entry running into the directory),
    /// what must not be one (a preamble, a misplaced directory, data
    /// descriptors signed and unsigned), descriptors missing (23's skip
    /// then reads the next entry's header), an empty directory, a deflate
    /// stream that reads past its entry (22), and Zip64 end records.
    fn bomb_zips() -> Vec<(&'static str, Vec<u8>)> {
        let plain = ZipEntrySpec::new;
        let mut v = Vec::new();

        // Fifield: an entry whose stored data is another entry
        let inner = plain(b"b.txt", b"inner data\n");
        let quoted = local_bytes(&inner);
        let outer = plain(b"a.txt", &quoted);
        let inner_at = 30 + outer.name.len() as u32;
        for (name, first_outer) in [("fifield.zip", true), ("fifield2.zip", false)] {
            let mut r = Raw::default();
            r.local(&outer, b"");
            if first_outer {
                r.central(&outer, 0);
                r.central(&inner, inner_at);
            } else {
                r.central(&inner, inner_at);
                r.central(&outer, 0);
            }
            v.push((name, r.finish()));
        }
        // the full shape: each stored entry quotes the next one's header
        let kernel = vec![b'K'; 64];
        let names: [&[u8]; 4] = [b"k0.txt", b"k1.txt", b"k2.txt", b"k3.txt"];
        let mut blobs = vec![local_bytes(&plain(names[3], &kernel))];
        for i in (0..3).rev() {
            let quote = local_bytes(&ZipEntrySpec::new(names[i], &blobs[0]));
            blobs.insert(0, quote);
        }
        let mut r = Raw {
            out: blobs[0].clone(),
            ..Raw::default()
        };
        let mut at = 0u32;
        for (i, name) in names.into_iter().enumerate() {
            let data: &[u8] = if i == 3 { &kernel } else { &blobs[i + 1] };
            r.central(&plain(name, data), at);
            at += 30 + name.len() as u32;
        }
        v.push(("fifield_full.zip", r.finish()));
        // three entries sharing one deflated local header
        let a5 = vec![b'A'; 5000];
        let shared = ZipEntrySpec {
            method: 8,
            ..plain(b"f0.txt", &a5)
        };
        let mut r = Raw::default();
        r.local(&shared, b"");
        for name in [b"f0.txt", b"f1.txt", b"f2.txt"] {
            r.central(&ZipEntrySpec { name, ..shared }, 0);
        }
        v.push(("shared.zip", r.finish()));
        // entries pointing into the directory and into the end record
        let a = plain(b"a.txt", b"hello\n");
        let c = plain(b"c.txt", b"x");
        let la = local_bytes(&a).len() as u32;
        let cd_len = 2 * 46 + 10;
        for (name, target) in [("into_cd.zip", la), ("into_eocd.zip", la + cd_len)] {
            let mut r = Raw::default();
            r.local(&a, b"");
            r.central(&a, 0);
            r.central(&c, target);
            v.push((name, r.finish()));
        }
        // an entry whose stored size runs into the directory
        let mut z = zip_with(&[a], b"", b"");
        put_u32(&mut z, 18, 40);
        put_u32(&mut z, la as usize + 20, 40);
        v.push(("runs_into_cd.zip", z));
        // the directory between the entries (24: not a bomb)
        let b = plain(b"b.txt", b"second\n");
        let mut r = Raw::default();
        r.local(&a, b"");
        r.central(&a, 0);
        r.central(&b, la + cd_len);
        r.put_central();
        r.local(&b, b"");
        v.push(("cdmid.zip", r.finish()));
        // an empty directory claimed by the end record
        let mut z = zip_with(&[a], b"", b"");
        let eocd = z.len() - 22;
        put_u32(&mut z, eocd + 12, 0);
        v.push(("cdsize0.zip", z));
        v.push(("pre.zip", zip_with(&[a, b], b"", b"#!/bin/sh\nexit 0\n")));
        // data descriptors
        let s = ZipEntrySpec { flags: 8, ..a };
        let hello = b"hello hello hello\n";
        let d = ZipEntrySpec {
            method: 8,
            flags: 8,
            ..plain(b"a.txt", hello)
        };
        for (name, first, tail) in [
            ("dd_sig.zip", s, descriptor(&s, true)),
            ("dd_nosig.zip", s, descriptor(&s, false)),
            ("dd_none.zip", s, Vec::new()),
            ("dd_defl.zip", d, descriptor(&d, true)),
            ("dd_defl_none.zip", d, Vec::new()),
        ] {
            let mut r = Raw::default();
            let at = r.local(&first, &tail);
            r.central(&first, at);
            let bat = r.local(&b, b"");
            r.central(&b, bat);
            v.push((name, r.finish()));
        }
        let mut r = Raw::default();
        r.local(&a, b"");
        r.central(&a, 0);
        let sb = ZipEntrySpec { flags: 8, ..b };
        let bat = r.local(&sb, b"");
        r.central(&sb, bat);
        v.push(("dd_none_last.zip", r.finish()));
        // T14-2: a taken Unicode Path block sets `G.zip64`, so the skip
        // after a signed descriptor reads 8 more bytes, into the next
        // entry's header (an overlap); a block whose checksum fails is not
        // taken, and the skip reads the descriptor only
        for (name, crc_of) in [
            ("dd_unipath.zip", &b"a.txt"[..]),
            ("dd_unipath_bad.zip", b"x"),
        ] {
            let up = unipath(crc_of, b"a.txt", 1);
            let e = ZipEntrySpec {
                flags: 8,
                extra: &up,
                ..a
            };
            let mut r = Raw::default();
            let at = r.local(&e, &descriptor(&e, true));
            r.central(&e, at);
            let bat = r.local(&b, b"");
            r.central(&b, bat);
            v.push((name, r.finish()));
        }
        // 22: a deflate stream cut in half, then entries in the same buffer
        let text = b"hello world ".repeat(20);
        let full = deflate_raw(&text);
        let cut = full[..full.len() / 2].to_vec();
        let over = ZipEntrySpec {
            method: 8,
            stored_data: Some(&cut),
            ..plain(b"a.txt", &text)
        };
        let three = plain(b"c.txt", b"three\n");
        v.push(("overread.zip", zip_with(&[over, b, three], b"", b"")));
        let over_dd = ZipEntrySpec { flags: 8, ..over };
        let mut r = Raw::default();
        r.local(&over_dd, &descriptor(&over_dd, true));
        r.central(&over_dd, 0);
        let bat = r.local(&b, b"");
        r.central(&b, bat);
        v.push(("overread_dd.zip", r.finish()));
        // Zip64 end records: their spans start the cover (and stay set for
        // a later archive of a wildcard run, ruling T14-3: a plain archive
        // with 20 bytes before its end record, "gb.zip")
        v.push(("z64rec.zip", zip64_zip(1, None)));
        let one = zip_with(&[a], b"", b"");
        let eocd = one.len() - 22;
        v.push(("gb.zip", [&one[..eocd], &[b'#'; 20], &one[eocd..]].concat()));
        let z64_hit = la + 2 * 46 + 10;
        v.push(("z64rec_hit.zip", zip64_zip(1, Some(z64_hit))));
        v
    }

    /// An entry made on `host` (its version 2.0, or `ver`), MS-DOS
    /// attributes only.
    fn dos_entry<'a>(name: &'a [u8], host: u16, ver: u16) -> ZipEntrySpec<'a> {
        ZipEntrySpec {
            version_made_by: (host << 8) | ver,
            external_attr: 0x20,
            ..ZipEntrySpec::new(name, b"1")
        }
    }

    /// 20-unzip60-alt-iconv-utf8.patch's inputs: names with high bytes from
    /// MS-DOS (2.0, and PKZIP 2.5, whose local name is ISO), Windows NT (2.0
    /// and 5.0: the patch makes every NT version OEM), OS/2 and Unix; a name
    /// whose conversion overflows `FILNAMSIZ` (left as stored) and one that
    /// just fits; a name that is not UTF-8; a directory; comments.
    fn iconv_zips() -> Vec<(&'static str, Vec<u8>)> {
        let long = vec![0x82u8; 3000];
        let mid = vec![0x82u8; 2000];
        let dir = ZipEntrySpec {
            external_attr: 0x10,
            ..dos_entry(b"d\x82r/", 0, 20)
        };
        vec![
            (
                "dos.zip",
                zip_with(
                    &[
                        dos_entry(b"\x82t\xe9.txt", 0, 20),
                        dos_entry(b"\x8e\x99\x9a.txt", 11, 20),
                        dos_entry(b"\x8e\x99\x9a5.txt", 11, 50),
                        ZipEntrySpec::new(b"\xe9plain.txt", b"4"),
                        dos_entry(b"\x80\x81hpfs.txt", 6, 20),
                        dos_entry(b"pk25\x82.txt", 0, 25),
                    ],
                    b"caf\x82 archive comment",
                    b"",
                ),
            ),
            ("long.zip", zip_with(&[dos_entry(&long, 0, 20)], b"", b"")),
            ("mid.zip", zip_with(&[dos_entry(&mid, 0, 20)], b"", b"")),
            (
                "unix.zip",
                zip_with(
                    &[
                        ZipEntrySpec::new(b"\xc0\xc1\xe9.txt", b"1"),
                        ZipEntrySpec::new(b"plain.txt", b"2"),
                    ],
                    b"",
                    b"",
                ),
            ),
            (
                "bad.zip",
                zip_with(&[dos_entry(b"bad\xc3(.txt", 0, 20)], b"", b""),
            ),
            (
                "dir.zip",
                zip_with(&[dir, dos_entry(b"d\x82r/f\x82.txt", 0, 20)], b"", b""),
            ),
        ]
    }

    /// 17-restore-unix-timestamps-accurately's inputs: `UT`, `ux`, `Ux` and
    /// old `UX` blocks in each order, locally and in the central directory.
    fn times_zip() -> Vec<u8> {
        let ut = block(
            0x5455,
            &[&[1u8][..], &1_500_000_000u32.to_le_bytes()].concat(),
        );
        let ux3 = block(
            0x7875,
            &[
                &[1u8, 4][..],
                &1000u32.to_le_bytes(),
                &[4],
                &1000u32.to_le_bytes(),
            ]
            .concat(),
        );
        let ux2 = block(
            0x7855,
            &[&1000u16.to_le_bytes()[..], &1000u16.to_le_bytes()].concat(),
        );
        let old = |owner: bool| {
            let mut d = [
                1_400_000_000u32.to_le_bytes(),
                1_300_000_000u32.to_le_bytes(),
            ]
            .concat();
            if owner {
                d.extend_from_slice(&[0xe8, 3, 0xe8, 3]);
            }
            block(0x5855, &d)
        };
        let (old_full, old_short) = (old(true), old(false));
        let cat = |a: &[u8], b: &[u8]| [a, b].concat();
        let blocks = [
            cat(&ut, &ux3),
            cat(&ux3, &ut),
            cat(&old_full, &ux2),
            cat(&old_full, &ux3),
            cat(&ux2, &old_full),
            cat(&ut, &ux2),
            old_full.clone(),
            cat(&old_short, &ux3),
            cat(&ux3, &ux2),
            cat(&ux2, &ux3),
        ];
        let names: [&[u8]; 10] = [
            b"ut_ux.txt",
            b"ux_ut.txt",
            b"old_Ux.txt",
            b"old_ux.txt",
            b"Ux_old.txt",
            b"ut_Ux.txt",
            b"old.txt",
            b"oldshort_ux.txt",
            b"ux_Ux.txt",
            b"Ux_ux.txt",
        ];
        let entries: Vec<ZipEntrySpec> = names
            .iter()
            .zip(&blocks)
            .map(|(n, b)| with_extra(n, b"1", b))
            .collect();
        zip_with(&entries, b"", b"")
    }

    /// 21-fix-warning-messages-on-big-files's inputs: Zip64 sizes with byte
    /// 5 set, in the local and the central header alike.
    fn byte5_zip() -> Vec<u8> {
        let sizes =
            |us: u64, cs: u64| block(0x0001, &[us.to_le_bytes(), cs.to_le_bytes()].concat());
        let (a, b) = (
            sizes(0x0000_0100_0000_0001, 1),
            sizes(1, 0x0000_0300_0000_0001),
        );
        let mut z = zip_with(
            &[
                with_extra(b"a.txt", b"x", &a),
                with_extra(b"b.txt", b"y", &b),
            ],
            b"",
            b"",
        );
        // the classic fields defer to the extra field: ucsize of a, both of b
        let la = 30 + 5 + a.len() + 1;
        put_u32(&mut z, 22, 0xffff_ffff);
        put_u32(&mut z, la + 18, 0xffff_ffff);
        put_u32(&mut z, la + 22, 0xffff_ffff);
        let eocd = z.len() - 22;
        let cd = u32::from_le_bytes(z[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
        put_u32(&mut z, cd + 24, 0xffff_ffff);
        let cb = cd + 46 + 5 + a.len();
        put_u32(&mut z, cb + 20, 0xffff_ffff);
        put_u32(&mut z, cb + 24, 0xffff_ffff);
        z
    }

    /// ruling: T14-3. find_ecrec() never clears `have_ecr64`, so in a
    /// wildcard run the Zip64 end record's spans of an earlier archive start
    /// a later plain archive's cover: "overlapped components" (exit 12) in
    /// place of its tests and its "didn't find end-of-central-dir signature"
    /// note. A differential, and the reference checked archive by archive
    /// in whatever order its readdir gave (ext4 reads a one-block directory
    /// in hash order, with a per-file-system seed; unzip takes one archive
    /// operand, so no run fixes the order).
    #[test]
    fn zip64_flags_outlive_their_archive() {
        let a = ZipEntrySpec::new(b"a.txt", b"hello\n");
        let one = zip_with(&[a], b"", b"");
        let eocd = one.len() - 22;
        let gap = [&one[..eocd], &[b'#'; 20], &one[eocd..]].concat();
        let files: Vec<(&str, Vec<u8>)> = stale_zip64_names()
            .into_iter()
            .map(|n| {
                let z = if n.starts_with('z') {
                    zip64_zip(1, None)
                } else {
                    gap.clone()
                };
                (n, z)
            })
            .collect();
        let cases: Vec<Case> = [&["-t", "*.zip"][..], &["-l", "*.zip"], &["*.zip"]]
            .iter()
            .map(|a| case("unzip", a, &files, &[]))
            .collect();
        if let Some(r) = unzip_reference(&cases[0]) {
            let out = String::from_utf8_lossy(&r.stdout);
            let blocks = stale_blocks(&out);
            assert_eq!(blocks.len(), 3, "{out}");
            for (stale, text) in blocks {
                assert_eq!(text.contains("overlapped components"), stale, "{out}");
                assert_eq!(text.contains("note:"), !stale, "{out}");
            }
        }
        check("zip64_flags_outlive_their_archive", &cases);
    }

    /// Ubuntu's patch series (Task 14), against its binary, one group per
    /// patch or set of patches. The probes behind each are in
    /// `.claude/rules/compat.md`, "Task 14 probes".
    #[test]
    fn ubuntu_patch_rows() {
        // 09, 10, 11, 12, 14, 16, 18, 19: the CVE fixes' triggers
        let files = cve_zips();
        let mut cases = Vec::new();
        for (z, _) in &files {
            for op in [
                &["-t"][..],
                &["-tq"],
                &[],
                &["-l"],
                &["-v"],
                &["-Z"],
                &["-P", "x", "-t"],
            ] {
                let mut args = op.to_vec();
                args.push(z);
                cases.push(case("unzip", &args, &files, &[]));
            }
        }
        for op in [&["-m"][..], &["-v"]] {
            let mut args = op.to_vec();
            args.push("methods.zip");
            cases.push(case("zipinfo", &args, &files, &[]));
        }
        check("CVE fixes", &cases);

        // 22, 23, 24: CVE-2019-13232
        let files = bomb_zips();
        let mut cases = Vec::new();
        for (z, _) in &files {
            for op in [&["-t"][..], &["-tq"], &[], &["-p"], &["-l"]] {
                let mut args = op.to_vec();
                args.push(z);
                cases.push(case("unzip", &args, &files, &[]));
            }
        }
        for args in [
            &["fifield.zip", "b.txt"][..],
            &["-t", "pre.zip", "a.txt"],
            &["-t", "fifield2.zip", "-x", "b.txt"],
            &["-t", "*.zip"],
            &["-qt", "*.zip"],
            &["-t", "f*.zip"],
        ] {
            cases.push(case("unzip", args, &files, &[]));
        }
        check("CVE-2019-13232", &cases);
        // T14-2 is exercised: Ubuntu's own answers
        for (z, code) in [("dd_unipath.zip", 12), ("dd_unipath_bad.zip", 0)] {
            if let Some(r) = unzip_reference(&case("unzip", &["-t", z], &files, &[])) {
                assert_eq!(r.code, code, "{z}: {}", String::from_utf8_lossy(&r.stdout));
            }
        }

        // 20-unzip60-alt-iconv-utf8: -O/-I, the default OEM_CP per locale
        let files = iconv_zips();
        let mut cases = Vec::new();
        for env in PROMISED.iter().chain(&LOCALES[6..]) {
            for args in [
                &["-l", "dos.zip"][..],
                &["-O", "CP866", "-l", "dos.zip"],
                &["-O", "CP437", "-l", "dos.zip"],
                &["-O", "cp1251", "-v", "dos.zip"],
                &["-I", "ISO-8859-5", "-l", "unix.zip"],
                &["-l", "unix.zip"],
                &["-O", "UTF-8", "-l", "bad.zip"],
                &["-O", "UTF-16", "-l", "dos.zip"],
                &["-O", "CP866", "-l", "long.zip"],
                &["-O", "CP866", "-l", "mid.zip"],
                &["-O", "CP866", "-z", "dos.zip"],
                &["-O", "CP866", "dos.zip"],
                &["-O", "CP866", "-t", "dos.zip"],
                &["-O", "CP866", "dir.zip"],
                &["-O", "CP866", "-I", "ISO-8859-5", "-l", "dos.zip"],
                &["-O", "CP866", "-O", "CP437", "-l", "dos.zip"],
                &["-OCP866", "-l", "dos.zip"],
                &["-lOCP866", "dos.zip"],
                &["-OCP866q", "-l", "dos.zip"],
                &["-O", "", "-l", "dos.zip"],
                &["-O", "BOGUS", "-l", "dos.zip"],
                &["-O", "CP866xxxxxxxxxxxxxxxxxxx", "-l", "dos.zip"],
                &["-O", "CP866xxxxxxxxxxxxxxxxxxxxxxxx", "-l", "dos.zip"],
                &["-x", "-O", "CP866", "dos.zip"],
                &["-Z", "-O", "CP866", "dos.zip"],
            ] {
                cases.push(case("unzip", args, &files, env));
            }
            for args in [
                &["-O", "CP866", "dos.zip"][..],
                &["dos.zip"],
                &["-I", "ISO-8859-5", "-1", "unix.zip"],
                &["-O", "CP866", "-v", "dos.zip"],
                &["-1O", "CP866", "dos.zip"],
            ] {
                cases.push(case("zipinfo", args, &files, env));
            }
            let mut c = case("unzip", &["-l", "dos.zip"], &files, env);
            c.env.push(("UNZIP", "-OCP866"));
            cases.push(c);
        }
        for args in [
            &["-O"][..],
            &["-O", "-l", "dos.zip"],
            &["-O-l", "dos.zip"],
            &["-I"],
            &["-I", "-l", "dos.zip"],
            &["-I-", "dos.zip"],
            &["--O", "CP866", "-l", "dos.zip"],
            &["--I", "CP866", "-l", "dos.zip"],
            &["-t", "-O"],
            &["-hh"],
        ] {
            cases.push(case("unzip", args, &files, &[]));
        }
        for args in [
            &["-O"][..],
            &["-O", "-1", "dos.zip"],
            &["--O", "x", "dos.zip"],
            &["-I-x", "dos.zip"],
            &[],
        ] {
            cases.push(case("zipinfo", args, &files, &[]));
        }
        check("20-unzip60-alt-iconv-utf8", &cases);

        // the rest: 17 (times), 21 (byte 5), handle_windows_zip64 (a Zip64
        // locator counting 0 disks), and 04 and 08 (in Apple's tree too)
        let pkw = |iattr_bit: bool| ZipEntrySpec {
            version_made_by: 0x0014,
            external_attr: 0x00ab_0021,
            ..ZipEntrySpec::new(if iattr_bit { b"v.txt" } else { b"w.txt" }, b"x")
        };
        let mut pkw_zip = zip_with(&[pkw(true), pkw(false)], b"", b"");
        let eocd = pkw_zip.len() - 22;
        let cd = u32::from_le_bytes(pkw_zip[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
        pkw_zip[cd + 36] = 4; // internal attributes bit 2: PKWARE verification
        let big_ver = ZipEntrySpec {
            version_made_by: 0x03ff,
            ..ZipEntrySpec::new(b"v255.txt", b"x")
        };
        let files = vec![
            ("times.zip", times_zip()),
            ("byte5.zip", byte5_zip()),
            ("z64_d0.zip", zip64_zip(0, None)),
            ("z64_d1.zip", zip64_zip(1, None)),
            ("z64_d2.zip", zip64_zip(2, None)),
            ("pkw.zip", pkw_zip),
            ("ver.zip", zip_with(&[big_ver], b"", b"")),
        ];
        let mut cases = Vec::new();
        for (z, _) in &files {
            for op in [&["-l"][..], &["-v"], &["-t"], &[], &["-X"]] {
                let mut args = op.to_vec();
                args.push(z);
                cases.push(case("unzip", &args, &files, &[]));
            }
            for op in [&["-l"][..], &["-v"], &["-T"]] {
                let mut args = op.to_vec();
                args.push(z);
                cases.push(case("zipinfo", &args, &files, &[]));
            }
        }
        cases.push(case("unzip", &["-T", "times.zip"], &files, &[]));
        check("17, 21, handle_windows_zip64, 04, 08", &cases);
    }
}
