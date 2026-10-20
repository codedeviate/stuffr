//! The unzip family's Apple flavour against its reference, this Mac's
//! `/usr/bin/unzip`, `zipinfo` and `funzip` (0.16.0). macOS only. The shared
//! rows are in `compat_unzip_common.rs`; the Apple-only differentials join
//! them from Task 8 on.
//!
//! The suite is verified against the build whose `unzip -v` is
//! `APPLE_UNZIP_IDENTITY` (R11). Another macOS may ship another build: then
//! every difference `compare_unzip` reports says so, and so does
//! `the_reference_is_apples_unzip`, without failing for it.
//!
//! Task 8's tests list archives (`-l`, `-v`, `-z`, `-T`); Task 10 adds the
//! extraction halves of `archives_from_other_makers` and `awkward_names`
//! (plan Review Focus 2 and 5), and `-t` of `zip64_and_many_entries` (3).

#[cfg(target_os = "macos")]
mod compat_harness;

#[cfg(target_os = "macos")]
mod macos {
    use super::compat_harness::*;
    use std::path::Path;
    use std::process::Command;

    /// The oracle is Apple's build: its banner, and the `-v` this suite was
    /// verified against (a different one is reported, not failed: R11).
    #[test]
    fn the_reference_is_apples_unzip() {
        if unzip_dir().is_none() {
            return;
        }
        let id = apple_unzip_identity().expect("unzip -v");
        assert_eq!(id.lines().next(), Some(APPLE_UNZIP_BANNER), "{id}");
        if id == APPLE_UNZIP_IDENTITY {
            println!("the installed /usr/bin/unzip is the recorded build");
        } else {
            println!(
                "note: the installed /usr/bin/unzip -v differs from the recorded build \
                 (R11); differences will be marked [apple drift?]:\n{id}"
            );
        }
        assert_eq!(platform_unzip_flavour(), "apple");
    }

    /// A string that lives as long as the cases built from it.
    fn leak(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }

    /// One listing: the arguments (`@` is where the archive goes, else it
    /// is last), extra environment, the zone.
    type Run = (
        &'static [&'static str],
        &'static [(&'static str, &'static str)],
        Option<&'static str>,
    );

    /// Every `(args, env, tz)` over the archive `name` holding `bytes`.
    fn listings(name: &'static str, bytes: &[u8], runs: &[Run]) -> Vec<Case<'static>> {
        runs.iter()
            .map(|(args, env, tz)| {
                let mut a: Vec<&'static str> = args.to_vec();
                a.insert(a.iter().position(|x| *x == "@").unwrap_or(a.len()), name);
                a.retain(|x| *x != "@");
                let mut c = unzip_case("unzip", a, vec![(name, bytes.to_vec())]);
                c.env = env.to_vec();
                c.tz = *tz;
                c
            })
            .collect()
    }

    /// The listings every archive here gets: short, long, quiet, quieter,
    /// `-z`, `-T` (which dates the archive), under a UTF-8 locale and in a
    /// zone with summer time.
    fn every_listing(name: &'static str, bytes: &[u8]) -> Vec<Case<'static>> {
        const UTF8: &[(&str, &str)] = &[("LANG", "en_US.UTF-8")];
        listings(
            name,
            bytes,
            &[
                (&["-l"], &[], None),
                (&["-v"], &[], None),
                (&["-lq"], &[], None),
                (&["-vqq"], &[], None),
                (&["-z"], &[], None),
                (&["-T"], &[], None),
                (&["-l"], UTF8, None),
                (&["-v"], &[], Some("America/New_York")),
                (&["-T"], &[], Some("Australia/Lord_Howe")),
            ],
        )
    }

    fn compare(group: &str, cases: &[Case]) {
        run_group(group, cases, Skipped::none(), &assert_same_unzip);
    }

    /// A scratch directory of its own for archives a test makes with
    /// Apple's own tools.
    fn workdir(tag: &str) -> ScratchDir {
        let d = ScratchDir::at(
            std::env::temp_dir().join(format!("stuffr-unzip-{tag}-{}", std::process::id())),
        );
        std::fs::create_dir_all(&*d).unwrap();
        d
    }

    /// Make `rel` under `dir` holding `data`, dated 2021-02-03 04:05:06 UTC.
    fn file_at(dir: &Path, rel: &str, data: &[u8]) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, data).unwrap();
        let f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
        f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_612_325_106))
            .unwrap();
    }

    /// `cmd` run in `dir`, which must succeed.
    fn run_tool(dir: &Path, cmd: &mut Command) {
        let out = cmd.current_dir(dir).env("TZ", "UTC").output().unwrap();
        assert!(out.status.success(), "{cmd:?}: {out:?}");
    }

    /// Review Focus 2, the listing half: archives as other makers write
    /// them. Windows (backslash names, MS-DOS attributes only, an OEM code
    /// page name, a volume label), streamed entries with data descriptors
    /// (bit 3), UTF-8 names (bit 11), a self-extractor stub ("extra bytes
    /// at beginning"), Info-ZIP's own zip (`UT`/`ux` extra fields: local
    /// times) and Finder's `ditto -c -k --sequesterRsrc` (`__MACOSX/`
    /// AppleDouble entries). Task 10 extracts them.
    #[test]
    fn archives_from_other_makers() {
        let text = b"the quick brown fox jumps over the lazy dog\n".repeat(40);
        let dos = |name: &'static [u8], data: &'static [u8], attr: u32| ZipEntrySpec {
            version_made_by: 0x0014,
            external_attr: attr,
            ..ZipEntrySpec::new(name, data)
        };
        let windows = zip_with(
            &[
                dos(b"WINDIR\\", b"", 0x10),
                dos(b"WINDIR\\Sub\\File.TXT", b"in a folder\r\n", 0x20),
                dos(b"README.TXT", b"read me\r\n", 0x21),
                dos(b"caf\x82 men\x81.txt", b"cp850\r\n", 0x20),
                dos(b"DISKLABE.L01", b"", 0x08),
            ],
            b"made on Windows\r\n",
            b"",
        );
        let streamed = zip_with(
            &[
                ZipEntrySpec {
                    method: 8,
                    flags: 8,
                    ..ZipEntrySpec::new(b"streamed.txt", &text)
                },
                ZipEntrySpec {
                    flags: 8,
                    ..ZipEntrySpec::new(b"stored-streamed.txt", b"plain\n")
                },
            ],
            b"",
            b"",
        );
        let utf8 = zip_with(
            &[
                ZipEntrySpec {
                    flags: 0x800,
                    ..ZipEntrySpec::new("café.txt".as_bytes(), b"utf-8\n")
                },
                ZipEntrySpec {
                    flags: 0x800,
                    ..ZipEntrySpec::new("日本/語.txt".as_bytes(), b"nihongo\n")
                },
            ],
            b"",
            b"",
        );
        let mut stub = b"MZ\x90\x00".to_vec();
        stub.resize(4096, 0x90);
        let sfx = zip_with(
            &[ZipEntrySpec {
                method: 8,
                ..ZipEntrySpec::new(b"setup.ini", &text)
            }],
            b"",
            &stub,
        );

        // Info-ZIP's zip and Finder's ditto, run here (macOS's own tools).
        let w = workdir("makers");
        let src = w.join("src");
        file_at(&src, "top.txt", &text);
        file_at(&src, "sub/inner.txt", b"inner\n");
        let rsrc = src.join("fork.txt");
        file_at(&src, "fork.txt", b"has a resource fork\n");
        run_tool(
            &src,
            Command::new("/usr/bin/xattr")
                .args(["-w", "com.example.note", "kept by ditto"])
                .arg(&rsrc),
        );
        run_tool(
            &src,
            Command::new("/usr/bin/zip").args([
                "-q",
                "-r",
                "../infozip.zip",
                "top.txt",
                "sub",
                "fork.txt",
            ]),
        );
        run_tool(
            &w,
            Command::new("/usr/bin/ditto").args([
                "-c",
                "-k",
                "--sequesterRsrc",
                "src",
                "ditto.zip",
            ]),
        );
        let infozip = std::fs::read(w.join("infozip.zip")).unwrap();
        let ditto = std::fs::read(w.join("ditto.zip")).unwrap();
        assert!(
            ditto.windows(9).any(|x| x == b"__MACOSX/"),
            "ditto --sequesterRsrc made no __MACOSX/ entry"
        );

        let mut cases = Vec::new();
        for (name, bytes) in [
            ("windows.zip", &windows),
            ("streamed.zip", &streamed),
            ("utf8.zip", &utf8),
            ("sfx.zip", &sfx),
            ("infozip.zip", &infozip),
            ("ditto.zip", &ditto),
        ] {
            cases.extend(every_listing(name, bytes));
        }
        cases.extend(listings(
            "windows.zip",
            &windows,
            &[
                (&["-lL", "@"], &[], None),
                (&["-lLL", "@"], &[], None),
                (&["-l", "@", "WINDIR*"], &[], None),
                (&["-lC", "@", "readme.txt"], &[], None),
            ],
        ));
        cases.extend(listings(
            "ditto.zip",
            &ditto,
            &[(&["-l", "@", "-x", "__MACOSX/*"], &[], None)],
        ));
        compare("archives_from_other_makers", &cases);
    }

    /// `n` empty stored entries `e00000`, `e00001`, ... under a Zip64 end
    /// record (and its locator) whose classic counts are all ones, as Zip
    /// writes an archive of more than 65,535 entries. Built here, never
    /// committed.
    fn zip64_many(n: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for i in 0..n {
            let name = format!("e{i:05}");
            let offset = out.len() as u32;
            out.extend_from_slice(b"PK\x03\x04");
            for v in [20u16, 0, 0, 0x2183, 0x5022] {
                out.extend_from_slice(&v.to_le_bytes());
            }
            out.extend_from_slice(&[0; 12]);
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            central.extend_from_slice(b"PK\x01\x02");
            for v in [0x031eu16, 20, 0, 0, 0x2183, 0x5022] {
                central.extend_from_slice(&v.to_le_bytes());
            }
            central.extend_from_slice(&[0; 12]);
            for v in [name.len() as u16, 0, 0, 0, 0] {
                central.extend_from_slice(&v.to_le_bytes());
            }
            central.extend_from_slice(&(0o100644u32 << 16).to_le_bytes());
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_at = out.len() as u64;
        let cd_len = central.len() as u64;
        out.extend(central);
        let rec64_at = out.len() as u64;
        out.extend_from_slice(b"PK\x06\x06");
        out.extend_from_slice(&44u64.to_le_bytes());
        for v in [45u16, 45] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&[0; 8]); // this disk, the directory's disk
        for v in [n as u64, n as u64, cd_len, cd_at] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(b"PK\x06\x07");
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&rec64_at.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(b"PK\x05\x06");
        for v in [0u16, 0, 0xffff, 0xffff] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for v in [0xffff_ffffu32, 0xffff_ffff] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    /// A Zip64 extra block (`0x0001`) of `values` (8 bytes each).
    fn zip64_extra(values: &[u64]) -> Vec<u8> {
        let mut v = vec![1, 0];
        v.extend_from_slice(&((values.len() * 8) as u16).to_le_bytes());
        for x in values {
            v.extend_from_slice(&x.to_le_bytes());
        }
        v
    }

    /// `z` with the central header of its first entry given `csize` and
    /// `ucsize` (offsets 20 and 24 from the `PK\1\2`).
    fn with_central_sizes(mut z: Vec<u8>, csize: u32, ucsize: u32) -> Vec<u8> {
        let at = z.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        z[at + 20..at + 24].copy_from_slice(&csize.to_le_bytes());
        z[at + 24..at + 28].copy_from_slice(&ucsize.to_le_bytes());
        z
    }

    /// Review Focus 3, the listing half: 70,000 entries under a Zip64 end
    /// record (the count past 65,535), `zip -fz`'s Zip64 archive, 64-bit
    /// sizes from the extra field, and a Zip64 archive behind a stub. The
    /// totals and summary lines are the reference's. Task 10 tests them.
    #[test]
    fn zip64_and_many_entries() {
        let many = zip64_many(70_000);
        let w = workdir("zip64");
        file_at(&w, "one.txt", b"forced zip64\n");
        file_at(&w, "two.txt", &b"0123456789".repeat(500));
        run_tool(
            &w,
            Command::new("/usr/bin/zip").args(["-q", "-fz", "fz.zip", "one.txt", "two.txt"]),
        );
        let fz = std::fs::read(w.join("fz.zip")).unwrap();
        // 5 GB and 3 GB as Zip64 sizes; `0x0000_ff00_0000_0007` (byte 5 set),
        // which upstream's makeint64() reads as 7.
        let big = with_central_sizes(
            zip_with(
                &[ZipEntrySpec {
                    extra: &zip64_extra(&[5_000_000_000, 3_000_000_000]),
                    ..ZipEntrySpec::new(b"big.bin", b"x")
                }],
                b"",
                b"",
            ),
            0xffff_ffff,
            0xffff_ffff,
        );
        let byte5 = with_central_sizes(
            zip_with(
                &[ZipEntrySpec {
                    extra: &zip64_extra(&[0x0000_ff00_0000_0007]),
                    ..ZipEntrySpec::new(b"byte5.bin", b"x")
                }],
                b"",
                b"",
            ),
            1,
            0xffff_ffff,
        );
        let short_extra = with_central_sizes(
            zip_with(
                &[ZipEntrySpec {
                    extra: b"\x01\x00\x04\x00abcd",
                    ..ZipEntrySpec::new(b"short.bin", b"x")
                }],
                b"",
                b"",
            ),
            1,
            0xffff_ffff,
        );
        let mut pre = b"#!/bin/sh\nexit 0\n".to_vec();
        pre.extend_from_slice(&fz);

        let mut cases = listings(
            "many.zip",
            &many,
            &[
                (&["-l"], &[], None),
                (&["-v"], &[], None),
                (&["-lqq"], &[], None),
                (&["-l", "@", "e6999*"], &[], None),
                (&["-l", "@", "-x", "e0*"], &[], None),
                (&["-T"], &[], None),
            ],
        );
        for (name, bytes) in [
            ("fz.zip", &fz),
            ("big.zip", &big),
            ("byte5.zip", &byte5),
            ("short.zip", &short_extra),
            ("pre.zip", &pre),
        ] {
            cases.extend(listings(
                name,
                bytes,
                &[
                    (&["-l"], &[], None),
                    (&["-v"], &[], None),
                    (&["-lq"], &[], None),
                ],
            ));
        }
        // Not vacuous: the reference lists every entry of many.zip, and
        // stuffr agrees (below).
        if let Some(r) = unzip_reference(&cases[0]) {
            let out = String::from_utf8_lossy(&r.stdout);
            assert!(
                out.ends_with("        0                     70000 files\n"),
                "{out:.300}"
            );
            assert_eq!((r.code, out.lines().count()), (0, 70_005));
        }
        compare("zip64_and_many_entries", &cases);
    }

    /// Review Focus 5, the listing half: names that differ only in case
    /// (and `-C`), control bytes and a newline (`^J`), escape sequences,
    /// high bytes under `C` and a UTF-8 locale, `../`, `/`, an empty name,
    /// a NUL inside a name, names past `FILNAMSIZ`, and the wildcards that
    /// select among them. Task 10 extracts them.
    #[test]
    fn awkward_names() {
        let names: &[&[u8]] = &[
            b"A",
            b"a",
            b"nl\nname",
            b"ctl\x01\x7f\x80\xe9\xad.txt",
            b"esc\x1b[31mred",
            b"../up",
            b"../",
            b"/",
            b"",
            b"dir/",
            b"dir/[x].txt",
            b"star*name",
            b"nul\x00hidden",
        ];
        let long = [b"n".repeat(1030), b"\x01tail".to_vec()].concat();
        let mut specs: Vec<ZipEntrySpec> =
            names.iter().map(|n| ZipEntrySpec::new(n, b"x")).collect();
        specs.push(ZipEntrySpec::new(&long, b"y"));
        let z = zip_with(&specs, b"", b"");
        const UTF8: &[(&str, &str)] = &[("LANG", "en_US.UTF-8")];
        const CUTF8: &[(&str, &str)] = &[("LANG", "C.UTF-8")];
        let cases = listings(
            "names.zip",
            &z,
            &[
                (&["-l"], &[], None),
                (&["-v"], &[], None),
                (&["-l"], UTF8, None),
                (&["-v"], CUTF8, None),
                (&["-l", "@", "a"], &[], None),
                (&["-l", "@", "A"], &[], None),
                (&["-lC", "@", "a"], &[], None),
                (&["-lC", "@", "A", "-x", "a"], &[], None),
                (&["-lL"], &[], None),
                (&["-lLL"], &[], None),
                (&["-l", "@", "dir/*"], &[], None),
                (&["-l", "@", "dir/\\[x\\].txt"], &[], None),
                (&["-l", "@", "dir/[[]x]*"], &[], None),
                (&["-l", "@", "star\\*name"], &[], None),
                (&["-l", "@", "[!a-z]*"], &[], None),
                (&["-l", "@", "?"], &[], None),
                (&["-l", "@", "nul"], &[], None),
                (&["-l", "@", "*tail"], &[], None),
            ],
        );
        // 16,000 stars: the C recurses once per star; stuffr keeps the
        // stars on a heap stack (Task 8 fix round 1).
        let mut cases = cases;
        let stars = leak("*".repeat(16_000));
        cases.push(unzip_case(
            "unzip",
            vec!["-l", "names.zip", stars],
            vec![("names.zip", z.clone())],
        ));
        let starsx = leak(format!("{}a", "*".repeat(16_000)));
        cases.push(unzip_case(
            "unzip",
            vec!["-lq", "names.zip", starsx],
            vec![("names.zip", z.clone())],
        ));
        compare("awkward_names", &cases);
    }

    /// The end record and directory as damage leaves them: counts that do
    /// not match, an offset or size that is wrong (missing bytes, the
    /// Atari/ZIPSPLIT compensation, the `zip -go` NULL offset), a disk
    /// number, a comment past the end, a directory cut by the end of the
    /// file, a corrupt Zip64 extra field, `UT` and `UX` times (one past
    /// 2038), entry comments with control bytes, an end record near a
    /// block boundary and behind a long preamble, and the archive name the
    /// C appends `.zip` and `.ZIP` to.
    #[test]
    fn damaged_end_records_and_directories() {
        let two = || {
            zip_with(
                &[
                    ZipEntrySpec::new(b"a.txt", b"alpha\n"),
                    ZipEntrySpec::new(b"b.txt", b"bravo\n"),
                ],
                b"",
                b"",
            )
        };
        let base = two();
        let eocd = base.len() - 22;
        let field = |z: &[u8], at: usize| {
            u32::from_le_bytes(z[eocd + at..eocd + at + 4].try_into().unwrap())
        };
        let (cd_len, cd_at) = (field(&base, 12), field(&base, 16));
        // `base` with the end record's (disk, cd disk, count, count, cd size,
        // cd offset) replaced.
        let with_eocd = |vals: (u16, u16, u16, u16, u32, u32), pre: &[u8]| {
            let mut z = pre.to_vec();
            z.extend_from_slice(&base[..eocd + 4]);
            for v in [vals.0, vals.1, vals.2, vals.3] {
                z.extend_from_slice(&v.to_le_bytes());
            }
            z.extend_from_slice(&vals.4.to_le_bytes());
            z.extend_from_slice(&vals.5.to_le_bytes());
            z.extend_from_slice(&0u16.to_le_bytes());
            z
        };
        let mut cmt_past = base.clone();
        let n = cmt_past.len();
        cmt_past[n - 2..].copy_from_slice(&100u16.to_le_bytes());
        // A `PK\1\2` just before the end record, the directory said to
        // start there: its header runs into the end record and the file's end.
        let mut partial = b"PK\x01\x02PK\x05\x06".to_vec();
        for v in [0u16, 0, 1, 1] {
            partial.extend_from_slice(&v.to_le_bytes());
        }
        partial.extend_from_slice(&4u32.to_le_bytes());
        partial.extend_from_slice(&0u32.to_le_bytes());
        partial.extend_from_slice(&0u16.to_le_bytes());
        let ut = |t: u32| [&b"UT\x05\x00\x01"[..], &t.to_le_bytes()].concat();
        let (ut1, ut2) = (ut(1_600_000_000), ut(0x9000_0000));
        let ux = [
            &b"UX\x08\x00"[..],
            &1_500_000_000u32.to_le_bytes(),
            &1_400_000_000u32.to_le_bytes(),
        ]
        .concat();
        let times = zip_with(
            &[
                ZipEntrySpec {
                    extra: &ut1,
                    ..ZipEntrySpec::new(b"u1", b"x")
                },
                ZipEntrySpec {
                    extra: &ut2,
                    ..ZipEntrySpec::new(b"u2-pre-2038-dos-time", b"x")
                },
                ZipEntrySpec {
                    extra: &ut2,
                    dos_time: 0x7500_0000 | (DOS_TIME_2020 & 0xffff),
                    ..ZipEntrySpec::new(b"u3-2046", b"x")
                },
                ZipEntrySpec {
                    extra: b"UT\x01\x00\x01",
                    ..ZipEntrySpec::new(b"u4-cut", b"x")
                },
                ZipEntrySpec {
                    extra: &ux,
                    ..ZipEntrySpec::new(b"ux", b"x")
                },
            ],
            b"",
            b"",
        );
        let entry_comment = {
            // zip_with writes no entry comment: add one to the first entry.
            let z = zip_with(&[ZipEntrySpec::new(b"a", b"x")], b"z", b"");
            let at = z.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
            let comment: &[u8] = b"fc\x1b\x13\r\n\x80\x01";
            let mut out = z[..at + 46 + 1].to_vec(); // header and its 1-byte name
            out[at + 32..at + 34].copy_from_slice(&(comment.len() as u16).to_le_bytes());
            out.extend_from_slice(comment);
            let tail = &z[at + 46 + 1..];
            let mut tail = tail.to_vec();
            // the end record: the directory grew by the comment
            let size = u32::from_le_bytes(tail[12..16].try_into().unwrap()) + comment.len() as u32;
            tail[12..16].copy_from_slice(&size.to_le_bytes());
            out.extend(tail);
            out
        };
        // The end record's signature 22 bytes before a block boundary plus
        // 10: its search crosses the boundary.
        let bare = zip_with(&[ZipEntrySpec::new(b"a.txt", b"alpha\n")], b"", b"");
        let block = zip_with(
            &[ZipEntrySpec::new(b"a.txt", b"alpha\n")],
            &vec![b'x'; 8192 * 2 + 10 - bare.len()],
            b"",
        );
        let mut cases = Vec::new();
        for (name, bytes) in [
            ("count3.zip", with_eocd((0, 0, 3, 3, cd_len, cd_at), b"")),
            ("count1.zip", with_eocd((0, 0, 1, 1, cd_len, cd_at), b"")),
            ("cdoff.zip", with_eocd((0, 0, 2, 2, cd_len, cd_at + 5), b"")),
            (
                "cdlong.zip",
                with_eocd((0, 0, 2, 2, cd_len + 10, cd_at), b""),
            ),
            (
                "cdshort.zip",
                with_eocd((0, 0, 2, 2, cd_len - 10, cd_at), b""),
            ),
            (
                "nulloff.zip",
                with_eocd((0, 0, 2, 2, cd_len, 0), &[b'X'; 30]),
            ),
            ("disk1.zip", with_eocd((1, 0, 2, 2, cd_len, cd_at), b"")),
            ("disk01.zip", with_eocd((0, 1, 2, 2, cd_len, cd_at), b"")),
            (
                "cdcut.zip",
                with_eocd((0, 0, 2, 2, cd_len, eocd as u32 - 30), b""),
            ),
            ("cmtpast.zip", cmt_past.clone()),
            ("partial.zip", partial.clone()),
            ("times.zip", times.clone()),
            ("entrycmt.zip", entry_comment.clone()),
            ("block.zip", block.clone()),
            ("bigpre.zip", [vec![b'P'; 70_000], base.clone()].concat()),
        ] {
            let name = leak(name.to_owned());
            cases.extend(listings(
                name,
                &bytes,
                &[(&["-v"], &[], None), (&["-lq"], &[], None)],
            ));
            // partial.zip's date is the end record's bytes, month 0: `-T`
            // reads `ydays[-1]` there (ruled, `rulings_on_undefined_behaviour`).
            if name != "partial.zip" {
                cases.extend(listings(name, &bytes, &[(&["-T"], &[], None)]));
            }
        }
        cases.extend(listings(
            "times.zip",
            &times,
            &[
                (&["-l"], &[], Some("America/New_York")),
                (&["-l"], &[], Some("Asia/Kolkata")),
            ],
        ));
        // A script: executable, no end record ("may be a plain executable").
        let mut exe = unzip_case(
            "unzip",
            vec!["-l", "run"],
            vec![("run", b"#!/bin/sh\n".to_vec())],
        );
        exe.setup = Some(|d| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(d.join("run"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        });
        cases.push(exe);
        // Unreadable: `open()` fails after `stat()` succeeded.
        let mut unreadable =
            unzip_case("unzip", vec!["-l", "u.zip"], vec![("u.zip", base.clone())]);
        unreadable.setup = Some(|d| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(d.join("u.zip"), std::fs::Permissions::from_mode(0o000))
                .unwrap();
        });
        cases.push(unreadable);
        // `.zip`, then `.ZIP`, after a name that is not there.
        cases.push(unzip_case(
            "unzip",
            vec!["-l", "up"],
            vec![("up.ZIP", base.clone())],
        ));
        cases.push(unzip_case(
            "unzip",
            vec!["-l", "*.zip", "-x", "b.txt"],
            vec![("x.zip", base.clone()), ("y.zip", base.clone())],
        ));
        cases.push(unzip_case(
            "unzip",
            vec!["-T", "*.zip"],
            vec![("x.zip", base.clone()), ("y.zip", times)],
        ));
        compare("damaged_end_records_and_directories", &cases);
    }

    /// The rulings on upstream undefined behaviour this task makes, pinned
    /// on stuffr alone (the reference has no defined answer to compare).
    #[test]
    fn rulings_on_undefined_behaviour() {
        // ruling: list.c's `methbuf` overflow (Apple dies with SIGTRAP, exit
        // 133): a method above 999 prints as Ubuntu's CVE-2014-9913 patch
        // prints it.
        let m = zip_with(
            &[
                ZipEntrySpec {
                    method: 1000,
                    ..ZipEntrySpec::new(b"m1000", b"x")
                },
                ZipEntrySpec {
                    method: 65535,
                    ..ZipEntrySpec::new(b"m65535", b"x")
                },
            ],
            b"",
            b"",
        );
        let run = stuffr_unzip(&unzip_case(
            "unzip",
            vec!["-v", "m.zip"],
            vec![("m.zip", m)],
        ));
        let out = String::from_utf8_lossy(&run.stdout);
        assert_eq!(run.code, 0, "{out}");
        assert!(
            out.contains("       1  Unk03E8       1   0% 01-02-2020 03:04 8cdc1683  m1000\n"),
            "{out}"
        );
        assert!(
            out.contains("       1  UnkFFFF       1   0% 01-02-2020 03:04 8cdc1683  m65535\n"),
            "{out}"
        );

        // ruling (T8-3): a central header cut short by the end of a short
        // archive (its `PK\1\2` just before the end record, which sits in the
        // last 22-25 bytes) reads zeros past the file: under 8 KiB, so
        // find_ecrec() reads it whole, and `byterec`'s unread bytes are the
        // C's uninitialised stack.
        for (n, entry) in [
            (
                0usize,
                Some("       0  Stored        0   0% 00-01-1980 00:00 00000004  \n"),
            ),
            (
                1,
                Some(" 6488065  Stored        0 100% 00-01-1980 00:00 00000004  \n"),
            ),
            (
                2,
                Some("1667432450  Stored        0 100% 00-01-1980 00:00 00000004  \n"),
            ),
            (3, None),
        ] {
            let mut z = b"PK\x01\x02PK\x05\x06".to_vec();
            for v in [0u16, 0, 1, 1] {
                z.extend_from_slice(&v.to_le_bytes());
            }
            z.extend_from_slice(&4u32.to_le_bytes());
            z.extend_from_slice(&0u32.to_le_bytes());
            z.extend_from_slice(&(n as u16).to_le_bytes());
            z.extend(std::iter::repeat_n(b'c', n));
            let run = stuffr_unzip(&unzip_case(
                "unzip",
                vec!["-v", "p.zip"],
                vec![("p.zip", z)],
            ));
            let comment = if n == 0 {
                String::new()
            } else {
                format!("{}\n", "c".repeat(n))
            };
            let want = format!(
                "Archive:  p.zip\n{comment} Length   Method    Size  Cmpr    Date    Time   CRC-32   Name\n\
                 --------  ------  ------- ---- ---------- ----- --------  ----\n{}",
                entry.unwrap_or("")
            );
            assert_eq!(
                (
                    run.code,
                    String::from_utf8_lossy(&run.stdout).into_owned(),
                    run.stderr.as_str()
                ),
                (51, want, ""),
                "comment of {n} bytes"
            );
        }

        // ruling (T8-5): a comment block ending in CRs makes the C's CR
        // loop step past its terminator; what it prints is the block up to
        // its first NUL with the CRs taken out.
        let z = zip_with(&[ZipEntrySpec::new(b"a", b"x")], b"ab\r\0xyz\r", b"");
        let run = stuffr_unzip(&unzip_case(
            "unzip",
            vec!["-z", "cr.zip"],
            vec![("cr.zip", z)],
        ));
        assert_eq!(
            (run.code, &run.stdout[..]),
            (0, &b"Archive:  cr.zip\nab\n"[..])
        );

        // ruling (T8-7): a wildcard whose directory part names a real
        // directory in 1100 bytes: `opendir` refuses it (past PATH_MAX), so
        // the raw spec is tried; `matchname` keeps its first FILNAMSIZ - 1
        // bytes, and the `.zip`/`.ZIP` the C appends past the array's end
        // are kept whole.
        let dir = format!("d/{}", "./".repeat(549));
        assert_eq!(dir.len(), 1100);
        let wild = leak(format!("{dir}*.zip"));
        let a = zip_with(&[ZipEntrySpec::new(b"a.txt", b"x")], b"", b"");
        let run = stuffr_unzip(&unzip_case("unzip", vec!["-l", wild], vec![("d/a.zip", a)]));
        let want = format!(
            "unzip:  cannot find or open {wild}, {wild}.zip or {}.ZIP.\n\nNo zipfiles found.\n",
            &wild[..1023]
        );
        assert_eq!((run.code, run.stdout.len(), run.stderr), (9, 0, want));

        // ruling: dos_to_unix_time()'s `ydays[]` read outside the table for
        // months 0, 14 and 15: month 0 is January, 14 and 15 a whole year on.
        for (month, want) in [
            (0u32, 1_577_836_800i64),
            (13, 1_609_459_200),
            (15, 1_609_459_200),
        ] {
            let t = ((40 << 9) | (month << 5) | 1) << 16;
            let z = zip_with(
                &[ZipEntrySpec {
                    dos_time: t,
                    ..ZipEntrySpec::new(b"m", b"x")
                }],
                b"",
                b"",
            );
            let run = stuffr_unzip(&unzip_case(
                "unzip",
                vec!["-qT", "t.zip"],
                vec![("t.zip", z)],
            ));
            assert_eq!(run.code, 0, "month {month}: {}", run.stderr);
            match run.tree.get(&b"t.zip"[..]) {
                Some(UnzipNode::File { mtime, .. }) => assert_eq!(*mtime, want, "month {month}"),
                other => panic!("month {month}: {other:?}"),
            }
        }
    }
}
