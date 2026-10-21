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
        .collect();
        // (zipinfo has no `-F`: its usage, whose `-O`/`-I` lines are
        // 20-unzip60-alt-iconv-utf8.patch's, Task 14)
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
}
