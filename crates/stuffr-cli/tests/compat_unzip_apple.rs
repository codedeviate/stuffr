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
#[path = "compat_unzip_apple/task10.rs"]
mod task10;

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
        // The extraction half (Task 10): each archive tested, extracted
        // (into `.`, a new `-d`, junked, `-a`), and Windows' names folded.
        // Without the CP850 name: on APFS its ISO 8859-1 bytes are no UTF-8
        // name (`EILSEQ`), and Apple's unzip then writes through the
        // previous entry's closed stream (T10-11, pinned stuffr-only in
        // compat_unzip_safety).
        let windows = zip_with(
            &[
                dos(b"WINDIR\\", b"", 0x10),
                dos(b"WINDIR\\Sub\\File.TXT", b"in a folder\r\n", 0x20),
                dos(b"README.TXT", b"read me\r\n", 0x21),
                dos(b"HIDDEN.SYS", b"hidden\r\n", 0x27),
                dos(b"DISKLABE.L01", b"", 0x08),
            ],
            b"made on Windows\r\n",
            b"",
        );
        for (name, bytes) in [
            ("windows.zip", &windows),
            ("streamed.zip", &streamed),
            ("utf8.zip", &utf8),
            ("sfx.zip", &sfx),
            ("infozip.zip", &infozip),
            ("ditto.zip", &ditto),
        ] {
            cases.extend(listings(
                name,
                bytes,
                &[
                    (&["-t"], &[], None),
                    (&[], &[], None),
                    (&["-d", "out"], &[], None),
                    (&["-j"], &[], None),
                    (&["-a"], &[], None),
                    (&["-q"], &[], None),
                    (&[], &[], Some("America/New_York")),
                    (&[], &[("LANG", "en_US.UTF-8")], None),
                ],
            ));
        }
        cases.extend(listings(
            "windows.zip",
            &windows,
            &[
                (&["-L"], &[], None),
                (&["-LL"], &[], None),
                (&["-aa"], &[], None),
            ],
        ));
        cases.extend(listings(
            "ditto.zip",
            &ditto,
            &[(&["@", "-x", "__MACOSX/*"], &[], None)],
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
                    // Task 10: tested, and the small ones extracted
                    (&["-t"], &[], None),
                    (&["-tq"], &[], None),
                    (&[], &[], None),
                ],
            ));
        }
        // Task 10: the 70,000 entries tested (extracting them would make
        // 70,000 files per side: tested only).
        cases.extend(listings(
            "many.zip",
            &many,
            &[(&["-tq"], &[], None), (&["-t", "@", "e6999*"], &[], None)],
        ));
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

    /// A Zip64 archive of one stored entry: its Zip64 end record and
    /// locator, then a classic end record whose counts and directory fields
    /// defer to them (so `is_zip64_archive` is set).
    fn zip64_zip() -> Vec<u8> {
        let one = zip_with(&[ZipEntrySpec::new(b"a.txt", b"hello\n")], b"", b"");
        let eocd = one.len() - 22;
        let word = |at: usize| u32::from_le_bytes(one[at..at + 4].try_into().unwrap()) as u64;
        let (cd_len, cd_at) = (word(eocd + 12), word(eocd + 16));
        let mut z = one[..eocd].to_vec();
        let rec_at = z.len() as u64;
        z.extend_from_slice(b"PK\x06\x06");
        z.extend_from_slice(&44u64.to_le_bytes());
        for v in [0x031eu16, 45] {
            z.extend_from_slice(&v.to_le_bytes());
        }
        z.extend_from_slice(&[0; 8]);
        for v in [1u64, 1, cd_len, cd_at] {
            z.extend_from_slice(&v.to_le_bytes());
        }
        z.extend_from_slice(b"PK\x06\x07");
        z.extend_from_slice(&0u32.to_le_bytes());
        z.extend_from_slice(&rec_at.to_le_bytes());
        z.extend_from_slice(&1u32.to_le_bytes());
        z.extend_from_slice(b"PK\x05\x06");
        for v in [0u16, 0, 0xffff, 0xffff] {
            z.extend_from_slice(&v.to_le_bytes());
        }
        z.extend_from_slice(&[0xff; 8]);
        z.extend_from_slice(&0u16.to_le_bytes());
        z
    }

    /// A plain archive with 20 bytes between its directory and its end
    /// record ("extra bytes", then "didn't find end-of-central-dir
    /// signature at end of central dir").
    fn gap_zip() -> Vec<u8> {
        let one = zip_with(&[ZipEntrySpec::new(b"a.txt", b"hello\n")], b"", b"");
        let eocd = one.len() - 22;
        let mut z = one[..eocd].to_vec();
        z.extend_from_slice(&[b'#'; 20]);
        z.extend_from_slice(&one[eocd..]);
        z
    }

    /// ruling: T14-3. find_ecrec() never clears `have_ecr64` and
    /// `is_zip64_archive`, so in a wildcard run a plain archive after a
    /// Zip64 one loses its "didn't find end-of-central-dir signature at
    /// end of central dir" note. A differential (both sides read the
    /// directory in the same order), and the reference checked archive by
    /// archive in whatever order its readdir gave: the note exactly where
    /// no Zip64 archive came first. (unzip takes one archive operand and
    /// expands a wildcard in readdir order, so no run fixes the order.)
    #[test]
    fn zip64_flags_outlive_their_archive() {
        let files: Vec<(&str, Vec<u8>)> = stale_zip64_names()
            .into_iter()
            .map(|n| {
                (
                    n,
                    if n.starts_with('z') {
                        zip64_zip()
                    } else {
                        gap_zip()
                    },
                )
            })
            .collect();
        let cases: Vec<Case> = [&["-t", "*.zip"][..], &["-l", "*.zip"], &["-v", "*.zip"]]
            .iter()
            .map(|a| unzip_case("unzip", a.to_vec(), files.clone()))
            .collect();
        if let Some(r) = unzip_reference(&cases[0]) {
            let out = String::from_utf8_lossy(&r.stdout);
            let blocks = stale_blocks(&out);
            assert_eq!(blocks.len(), 3, "{out}");
            for (stale, text) in blocks {
                assert_eq!(text.contains("note:"), !stale, "{out}");
            }
        }
        compare("zip64_flags_outlive_their_archive", &cases);
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
        // The extraction half (Task 10): `A` and `a` meet on a
        // case-insensitive volume (the question, answered or not), control
        // bytes are dropped from the made names (`-^` keeps them), `../`
        // and `/` stripped, the empty name refused. Without the names APFS
        // refuses (high bytes that are no UTF-8, a component past 255
        // bytes): Apple's unzip then writes through the previous entry's
        // closed stream (T10-11, pinned stuffr-only).
        let z: Vec<u8> = zip_with(
            &names
                .iter()
                .filter(|n| !n.starts_with(b"ctl"))
                .map(|n| ZipEntrySpec {
                    // a directory the harness can walk afterwards
                    external_attr: if n.ends_with(b"/") {
                        0o40755 << 16
                    } else {
                        0o100644 << 16
                    },
                    ..ZipEntrySpec::new(n, b"x")
                })
                .collect::<Vec<_>>(),
            b"",
            b"",
        );
        let ex = listings(
            "names.zip",
            &z,
            &[
                (&[], &[], None),
                (&["-t"], &[], None),
                (&["-o"], &[], None),
                (&["-n"], &[], None),
                (&["-^"], &[], None),
                (&["-j"], &[], None),
                (&["-L"], &[], None),
                (&["-d", "x"], &[], None),
                (&["@", "a"], &[], None),
                (&["-C", "@", "a"], &[], None),
                (&["-p"], &[], None),
                (&[], UTF8, None),
            ],
        );
        cases.extend(ex);
        for stdin in [&b"y\n"[..], b"n\n", b"r\nother\n", b"A\n"] {
            let mut c = unzip_case("unzip", vec!["names.zip"], vec![("names.zip", z.clone())]);
            c.stdin = Some(stdin.to_vec());
            cases.push(c);
        }
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

        // ruling (P23, replacing T8-6's wrap): `cfactor`'s `+ 5` at INT_MIN
        // and INT_MAX is unsigned arithmetic, as both references print it
        // (`ratios_at_the_int_limits` compares them).
        for (k, want) in [
            (0i64, "    1000  Stored 2147484648 -214748365% "),
            (1, "    1000  Stored 2147484649  214748365% "),
            (4, "    1000  Stored 2147484652  214748364% "),
        ] {
            let z = central_only(
                &[CentralSpec {
                    csize: ((1i64 << 31) + 1000 + k) as u32,
                    ucsize: 1000,
                    ..CentralSpec::new(b"w")
                }],
                None,
                b"",
            );
            let run = stuffr_unzip(&unzip_case(
                "unzip",
                vec!["-v", "r.zip"],
                vec![("r.zip", z)],
            ));
            let out = String::from_utf8_lossy(&run.stdout);
            assert!(out.contains(want), "k {k}: {out}");
        }

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

    // ---- zipinfo (Task 9) ----

    /// zipinfo's formats, each alone and in the combinations that change
    /// what the others print: `-1 -2 -s -m -l -v`, `-h`/`-t` (forced on,
    /// forced off), `-T`, `-z`, and `unzip -Z`.
    const ZI_FORMATS: &[&[&str]] = &[
        &[],
        &["-1"],
        &["-2"],
        &["-s"],
        &["-m"],
        &["-l"],
        &["-v"],
        &["-h"],
        &["-t"],
        &["-T"],
        &["-z"],
        &["-hst"],
        &["-2ht"],
        &["-1ht"],
        &["-mT"],
        &["-lT"],
        &["-vT"],
        &["-vt"],
        &["-v-h"],
        &["-s-t"],
        &["-s-h-t"],
        &["-mz"],
        &["-vz"],
        &["-ht"],
    ];

    /// One zipinfo run per `(args, env, tz)` over the archive `name`; `@`
    /// marks where the archive goes (else it is last). `prog` is
    /// `zipinfo`, or `unzip` with `-Z` first in `args`.
    fn zi_runs(
        prog: &'static str,
        name: &'static str,
        bytes: &[u8],
        runs: &[Run],
    ) -> Vec<Case<'static>> {
        runs.iter()
            .map(|(args, env, tz)| {
                let mut a: Vec<&'static str> = args.to_vec();
                a.insert(a.iter().position(|x| *x == "@").unwrap_or(a.len()), name);
                a.retain(|x| *x != "@");
                let mut c = unzip_case(prog, a, vec![(name, bytes.to_vec())]);
                c.env = env.to_vec();
                c.tz = *tz;
                c
            })
            .collect()
    }

    /// Every format of [`ZI_FORMATS`] over `name`.
    fn zi_every_format(name: &'static str, bytes: &[u8]) -> Vec<Case<'static>> {
        let runs: Vec<Run> = ZI_FORMATS.iter().map(|a| (*a, &[][..], None)).collect();
        zi_runs("zipinfo", name, bytes, &runs)
    }

    /// The archives zipinfo is mostly pointed at, made by this Mac's own
    /// `zip` (a tree with a directory and a symlink, `UT`/`ux` fields, an
    /// archive comment, an entry comment, a deflated file), an encrypted
    /// `zip -P` archive, `zip -fz`'s Zip64 one and Finder's `ditto` (with
    /// `__MACOSX/`), each in every format; with include and exclude
    /// patterns, `-C`, a wildcard archive name, `unzip -Z` and `ZIPINFO`.
    #[test]
    fn zipinfo_formats() {
        let w = workdir("zipinfo");
        let src = w.join("src");
        let text = b"the quick brown fox jumps over the lazy dog\n".repeat(80);
        file_at(&src, "a.txt", b"alpha\n");
        file_at(&src, "big.txt", &text);
        file_at(&src, "dir/inner.bin", &[0u8, 1, 2, 3, 255]);
        file_at(&src, "dir/sub/deep.txt", b"deep\n");
        std::os::unix::fs::symlink("a.txt", src.join("link")).unwrap();
        run_tool(
            &src,
            Command::new("/usr/bin/zip").args([
                "-q",
                "-r",
                "-y",
                "../tree.zip",
                "a.txt",
                "big.txt",
                "dir",
                "link",
            ]),
        );
        let mut zc = Command::new("/usr/bin/zip");
        zc.args(["-q", "-z", "../tree.zip"]);
        let out = zc
            .current_dir(&src)
            .env("TZ", "UTC")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut ch| {
                use std::io::Write;
                ch.stdin
                    .take()
                    .unwrap()
                    .write_all(b"a comment\nfor the archive\n")?;
                ch.wait()
            })
            .unwrap();
        assert!(out.success());
        let mut zc = Command::new("/usr/bin/zip");
        let out = zc
            .args(["-q", "-c", "../tree.zip", "a.txt"])
            .current_dir(&src)
            .env("TZ", "UTC")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut ch| {
                use std::io::Write;
                ch.stdin.take().unwrap().write_all(b"entry comment\n")?;
                ch.wait()
            })
            .unwrap();
        assert!(out.success());
        run_tool(
            &src,
            Command::new("/usr/bin/zip").args([
                "-q",
                "-P",
                "secret",
                "../enc.zip",
                "a.txt",
                "big.txt",
            ]),
        );
        run_tool(
            &src,
            Command::new("/usr/bin/zip").args(["-q", "-fz", "../fz.zip", "a.txt", "big.txt"]),
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
        let tree = std::fs::read(w.join("tree.zip")).unwrap();
        let enc = std::fs::read(w.join("enc.zip")).unwrap();
        let fz = std::fs::read(w.join("fz.zip")).unwrap();
        let ditto = std::fs::read(w.join("ditto.zip")).unwrap();
        // A hand-made encrypted entry (flag bit 0, header check on the CRC)
        // beside a plain one, and an archive comment with CRs and escapes.
        let plain = b"secret data\n";
        let body = zipcrypto(b"pw", (crc32(plain) >> 24) as u8, plain);
        let mixed = zip_with(
            &[
                ZipEntrySpec {
                    flags: 1,
                    stored_data: Some(&body),
                    ..ZipEntrySpec::new(b"s.txt", plain)
                },
                ZipEntrySpec {
                    method: 8,
                    ..ZipEntrySpec::new(b"p.txt", &text)
                },
            ],
            b"mixed\r\narchive\x1b[1m comment",
            b"",
        );
        let sfx = zip_with(
            &[ZipEntrySpec::new(b"setup.ini", b"x\n")],
            b"",
            &[0x90; 300],
        );
        // Totals whose ratio is INT_MIN tenths (1000 bytes stored in 2^31 +
        // 1000): both references print `-214748364.8%`.
        let intmin = central_only(
            &[CentralSpec {
                csize: (1 << 31) + 1000,
                ucsize: 1000,
                ..CentralSpec::new(b"w")
            }],
            None,
            b"",
        );

        let mut cases = Vec::new();
        for (name, bytes) in [
            ("tree.zip", &tree),
            ("enc.zip", &enc),
            ("fz.zip", &fz),
            ("ditto.zip", &ditto),
            ("mixed.zip", &mixed),
            ("sfx.zip", &sfx),
            ("intmin.zip", &intmin),
        ] {
            cases.extend(zi_every_format(name, bytes));
        }
        const UTF8: &[(&str, &str)] = &[("LANG", "en_US.UTF-8")];
        cases.extend(zi_runs(
            "zipinfo",
            "tree.zip",
            &tree,
            &[
                (&["@", "a.txt"], &[], None),
                (&["-v", "@", "a.txt"], &[], None),
                (&["@", "dir/*"], &[], None),
                (&["-1", "@", "*", "-x", "dir/*"], &[], None),
                (&["-h", "@", "a.txt"], &[], None),
                (&["-t", "@", "a.txt", "nomatch"], &[], None),
                (&["@", "nomatch"], &[], None),
                (&["-v", "@", "nomatch"], &[], None),
                (&["@", "*", "-x", "nomatch", "dir/*"], &[], None),
                (&["-C", "@", "A.TXT"], &[], None),
                (&["@", "A.TXT"], &[], None),
                (&["-2", "@", "a.txt", "-x", "a.txt"], &[], None),
                (&["-v"], &[], Some("America/New_York")),
                (&["-s"], &[], Some("Australia/Lord_Howe")),
                (&["-T"], &[], Some("Asia/Kolkata")),
                (&["-v"], UTF8, None),
                (&["-s"], &[("ZIPINFO", "-1")], None),
                (&["-s"], &[("ZIPINFO", "-v")], None),
                (&[], &[("ZIPINFOOPT", "-2t")], None),
            ],
        ));
        cases.extend(zi_runs(
            "unzip",
            "tree.zip",
            &tree,
            &[
                (&["-Z"], &[], None),
                (&["-Z1"], &[], None),
                (&["-Zv"], &[], None),
                (&["-Z", "-m"], &[], None),
                (&["-Zl", "@", "dir/*"], &[], None),
                (&["-Z", "-2ht"], &[], None),
                (&["-Z"], &[("UNZIP", "-l")], None),
                (&["-Z"], &[("ZIPINFO", "-T")], None),
            ],
        ));
        // A wildcard archive name: a blank line between archives, and the
        // summary.
        for args in [
            vec!["*.zip"],
            vec!["-1", "*.zip"],
            vec!["-v", "*.zip"],
            vec!["-t", "*.zip"],
        ] {
            cases.push(unzip_case(
                "zipinfo",
                args,
                vec![("x.zip", tree.clone()), ("y.zip", mixed.clone())],
            ));
        }
        // 70,000 entries under a Zip64 end record: the count past 65,535,
        // the totals, `-v`'s end-record report.
        let many = zip64_many(70_000);
        let many_cases = zi_runs(
            "zipinfo",
            "many.zip",
            &many,
            &[
                (&["-t"], &[], None),
                (&["-1"], &[], None),
                (&["-s"], &[], None),
                (&["-h"], &[], None),
                (&["-v", "@", "e6999[89]"], &[], None),
                (
                    &["-m", "@", "-x", "e0*", "e1*", "e2*", "e3*", "e4*", "e5*"],
                    &[],
                    None,
                ),
            ],
        );
        // Not vacuous: the reference lists all 70,000.
        if let Some(r) = unzip_reference(&many_cases[0]) {
            let out = String::from_utf8_lossy(&r.stdout);
            assert_eq!(
                (r.code, out.as_ref()),
                (
                    0,
                    "70000 files, 0 bytes uncompressed, 0 bytes compressed:  0.0%\n"
                )
            );
        }
        cases.extend(many_cases);
        compare("zipinfo_formats", &cases);
    }

    /// The `-s`/`-m`/`-l`/`-v` attributes of every host zipinfo knows (and
    /// the numbers past them) under Unix, MS-DOS and odd modes; MS-DOS
    /// entries whose Unix mode agrees with their attributes (zi_short()
    /// then shows the Unix letters), executable extensions, volume
    /// labels, the local-only `UX` mark (bit 15); every version byte; every
    /// method number and option bit; encryption, text and EBCDIC marks;
    /// sizes that expand or wrap.
    #[test]
    fn zipinfo_hosts_and_attributes() {
        let mut hosts = Vec::new();
        let attrs: [u32; 16] = [
            0o100644 << 16,
            (0o040755 << 16) | 0x10,
            0x21,
            0x10,
            0o120777 << 16,
            0o104755 << 16,
            0o102745 << 16,
            0o101777 << 16,
            0o106000 << 16,
            0x08,
            0xffff_ffff,
            0o060600 << 16,
            0o020600 << 16,
            0o010600 << 16,
            0o140600 << 16,
            0,
        ];
        for h in (0u16..32).chain([40, 255]) {
            for a in attrs {
                hosts.push(CentralSpec {
                    version_made_by: (h << 8) | 30,
                    external_attr: a,
                    ..CentralSpec::new(format!("h{h}_{a:o}.txt").as_bytes())
                });
            }
        }
        let hosts = central_only(&hosts, None, b"");
        let dos = |name: &str, host: u16, attr: u32| CentralSpec {
            version_made_by: (host << 8) | 20,
            external_attr: attr,
            ..CentralSpec::new(name.as_bytes())
        };
        let fat = central_only(
            &[
                dos("C.EXE", 0, (0o100644 << 16) | 0x20),
                dos("r.bat", 0, (0o100444 << 16) | 0x01),
                dos("d/", 0, (0o040755 << 16) | 0x10),
                dos("p.Com", 0, 0x20),
                dos("p.co", 0, 0x20),
                dos("p.cmdx", 0, 0x27),
                dos("VOL", 0, 0x08),
                dos("nt.btm", 11, 0x22),
                dos("nt2", 11, 0xff),
                dos("acorn", 13, 0x8000),
                dos("ux8000", 3, 0x8000 | (0o100644 << 16)),
                dos("ux0c", 3, 0xc000 | (0o100644 << 16)),
                dos("fat8", 0, 0x8000),
                dos("fatc", 0, 0xc000),
                dos("hpfs", 6, 0xc000),
                dos("vms-none", 2, 0),
                dos("vms-all", 2, 0o777 << 16),
                dos("vms-some", 2, 0o754 << 16),
                dos("amiga", 1, 0o6377 << 16),
                dos("theos", 18, 0x5abc << 16),
                dos("theos-dir", 18, 0x4000 << 16),
                dos("theos-chr", 18, 0x2fff << 16),
            ],
            None,
            b"",
        );
        let mut vers = Vec::new();
        for hv in [0u16, 9, 10, 63, 99] {
            for h in [0u16, 1, 2, 3, 18, 14] {
                vers.push(CentralSpec {
                    version_made_by: (h << 8) | hv,
                    version_needed: (h << 8) | hv,
                    ..CentralSpec::new(format!("v{h}_{hv}").as_bytes())
                });
            }
        }
        for vne in [0x1f14u16, 0x1414, 0x2014, 0xff14, 0x0014, 0x0314] {
            vers.push(CentralSpec {
                version_needed: vne,
                ..CentralSpec::new(format!("vne{vne:x}").as_bytes())
            });
        }
        // Version 2.55 on Unix: patch 08's `%2u.%u` (Apple's tree too).
        vers.push(CentralSpec {
            version_made_by: 0x03ff,
            ..CentralSpec::new(b"u255")
        });
        let vers = central_only(&vers, None, b"");
        let mut meth = Vec::new();
        for method in (0u16..21).chain([95, 96, 97, 98, 99, 999]) {
            for flags in [0u16, 2, 4, 6, 1, 8, 9] {
                meth.push(CentralSpec {
                    method,
                    flags,
                    csize: 3,
                    ucsize: 23,
                    ..CentralSpec::new(format!("m{method}_{flags}").as_bytes())
                });
            }
        }
        let meth = central_only(&meth, None, b"");
        let sized = |name: &str, flags: u16, csize: u32, ucsize: u32, iattr: u16| CentralSpec {
            flags,
            csize,
            ucsize,
            internal_attr: iattr,
            ..CentralSpec::new(name.as_bytes())
        };
        let flags = central_only(
            &[
                sized("e1", 1, 14, 2, 0),
                sized("e2", 1, 5, 10, 0),
                sized("e3", 9, 14, 2, 1),
                sized("t1", 0, 1, 1, 1),
                sized("t2", 0, 1, 1, 2),
                sized("t3", 0, 1, 1, 3),
                sized("big", 0, 10, 5000, 0),
                sized("exp", 0, 1000, 1, 0),
                sized("huge", 0, 5, 4_000_000, 0),
                sized("hugeexp", 0, 4_000_000, 5, 0),
                sized("zero", 0, 0, 0, 0),
                sized("desc", 8, 1, 1, 0),
            ],
            None,
            b"",
        );
        let mut cases = Vec::new();
        for (name, bytes) in [
            ("hosts.zip", &hosts),
            ("fat.zip", &fat),
            ("vers.zip", &vers),
            ("meth.zip", &meth),
            ("flags.zip", &flags),
        ] {
            let runs: &[Run] = &[
                (&["-s"], &[], None),
                (&["-m"], &[], None),
                (&["-l"], &[], None),
                (&["-v"], &[], None),
            ];
            cases.extend(zi_runs("zipinfo", name, bytes, runs));
        }
        compare("zipinfo_hosts_and_attributes", &cases);
    }

    /// `-v`'s analysis of every extra-field block zipinfo has a layout
    /// for, each long enough and too short for it (the hex fallback),
    /// blocks it has no layout for (up to 24 bytes whole, else the first
    /// 20), a block longer than what is left, bytes too few for a block
    /// header, Macintosh type and creator codes that print and do not
    /// (under `C` and a UTF-8 locale), the `UT` times (also in other
    /// zones), and the extra field's effect on the next entry's "extra
    /// bytes preceding" figure.
    #[test]
    fn zipinfo_extra_fields() {
        let b = extra_block;
        let le = |v: u32| v.to_le_bytes().to_vec();
        let cat = |parts: &[&[u8]]| parts.concat();
        let ut_m = b(0x5455, &cat(&[b"\x01", &le(1_600_000_000)]));
        let blocks: Vec<Vec<u8>> = vec![
            ut_m.clone(),
            b(
                0x5455,
                &cat(&[
                    b"\x07",
                    &le(1_600_000_000),
                    &le(1_600_000_001),
                    &le(1_600_000_002),
                ]),
            ),
            b(0x5455, &cat(&[b"\x06", &le(1_600_000_000)])),
            b(0x5455, b""),
            b(
                0x5855,
                &cat(&[&le(1_500_000_000), &le(1_400_000_000), b"\xf5\x01\x14\x00"]),
            ),
            b(0x7855, b"\xf5\x01\x14\x00"),
            b(0x7875, b"\x01\x04\xf5\x01\x00\x00\x04\x14\x00\x00\x00"),
            cat(&[
                &ut_m,
                &b(0x7875, b"\x01\x04\xf5\x01\x00\x00\x04\x14\x00\x00\x00"),
            ]),
            b(0x0009, &cat(&[&le(1234), b"\x00\x01\x02"])),
            b(0x4c41, &le(77)),
            b(0x4453, &cat(&[&le(99), b"\x00"])),
            b(0x4453, b"\x01\x02"),
            b(0x4d49, &cat(&[b"VFAB", b"\x02\x00\xf4\x01", &[0; 8]])),
            b(
                0x4d49,
                &cat(&[b"VMSV", b"\x09\x00\xf4\x01", &[0; 4], b"V7.3xx"]),
            ),
            b(
                0x4d49,
                &cat(&[b"VMSV", b"\x01\x00\xf4\x01", &[0; 4], b"V7\x003"]),
            ),
            b(
                0x4d49,
                &cat(&[b"VMSV", b"\x01\x00\xf4\x01", &[0; 4], b"V7"]),
            ),
            b(0x4d49, b"QQQQ\x03\x00\xf4\x01"),
            b(0x4d49, b"VALL\x03\x00"),
            b(
                0x7075,
                &cat(&[b"\x01", &le(0xdead_beef), "café".as_bytes()]),
            ),
            b(
                0x7075,
                &cat(&[
                    b"\x01",
                    &le(0x1234_5678),
                    b"abcdefghijklmnopqrstuvwxyz0123456789",
                ]),
            ),
            b(0x6375, &cat(&[b"\x01", &le(1), b"cm"])),
            b(0x6375, b"\x01\x02"),
            b(0x334d, &cat(&[&le(4000), b"\x0d\x00TEXTttxt", &[0; 10]])),
            b(
                0x334d,
                &cat(&[&le(4000), b"\x00\x00\x01\x02\x03\x04ttxt", &[0; 10]]),
            ),
            b(0x334d, &cat(&[&le(4000), b"\x01\x00\xe9ABCttxt", &[0; 10]])),
            b(0x334d, &cat(&[&le(4000), b"\x01\x00\xadABCttxt", &[0; 10]])),
            b(0x334d, &le(4000)),
            b(0x2605, &cat(&[b"ZPIT\x05Hello", b"TEXTttxt"])),
            b(0x2605, &cat(&[b"ZPIT\x05He\x00lo", b"TEXTttxt"])),
            b(0x2605, b"ZPIT\x09He"),
            b(0x2605, &cat(&[b"ZXIT\x05Hello", b"TEXTttxt"])),
            b(0x2705, &cat(&[b"ZPITAPPLaplt", &[0; 4]])),
            b(0x2705, b"ZPITAPP"),
            b(0x07c8, &cat(&[b"JLEETEXTttxt", &[0; 19], b"\x01", &[0; 8]])),
            b(0x07c8, &cat(&[b"JLEETEXTttxt", &[0; 19], b"\x00", &[0; 8]])),
            b(0x07c8, b"JLEE"),
            b(
                0x4d63,
                &cat(&[b"dZipTEXTttxt", &[0; 20], b"\x07SmartFn", &[0; 24]]),
            ),
            b(
                0x4d63,
                &cat(&[b"dZipTEXTttxt", &[0; 20], b"\x1f", &[b'A'; 31]]),
            ),
            b(0x4d63, b"dZip"),
            b(0x6542, &cat(&[&le(300), b"\x01zz"])),
            b(0x6542, &cat(&[&le(300), b"\x00"])),
            b(0x7441, &cat(&[&le(300), b"\x01"])),
            b(0x7441, b"\x01"),
            b(0xfb4a, b"SMS2rest"),
            b(0xfb4a, b"SM"),
            b(0x5356, b"FCI\x00\x2a"),
            b(0x4154, &cat(&[b"\x00\x65", &[0; 16], b"\x00\x00"])),
            b(0x4154, &cat(&[b"\x00\x07", &[0; 16], b"\x40\x00"])),
            b(0x4154, &cat(&[b"\x00\x64", &[0; 16], b"\x00\x00"])),
            b(0x4154, &cat(&[b"\x00\x64", &[0; 16], b"\x60\x00"])),
            b(0x4154, b"\x00\x64"),
            b(
                0x4b46,
                &cat(&[&(0u8..16).collect::<Vec<u8>>(), b"\x00\x00\x00"]),
            ),
            b(0x4b46, &(0u8..10).collect::<Vec<u8>>()),
            b(0x1234, &(0u8..24).collect::<Vec<u8>>()),
            b(0x1234, &(0u8..25).collect::<Vec<u8>>()),
            b(0x1234, b""),
            b(0x0007, b"av"),
            b(0x000a, &[0; 32]),
            b(0x000c, b"vms"),
            b(0x000d, b"pkunix"),
            b(0x4341, b"abc"),
            b(0x756e, b"abcd"),
            b(0x6854, b"ab"),
            b(0x470f, b"mvs"),
            b(0x4704, b"cms"),
            ut_m[..ut_m.len() - 2].to_vec(),
            cat(&[b"\x34\x12\x64\x00", b"abc"]),
            cat(&[&ut_m, b"\x01\x02\x03"]),
            b"\x01".to_vec(),
            b"\x01\x02\x03\x04".to_vec(),
        ];
        let mut entries: Vec<CentralSpec> = blocks
            .iter()
            .enumerate()
            .map(|(i, x)| CentralSpec {
                extra: x.clone(),
                offset: (i as u32) * 7,
                ..CentralSpec::new(format!("x{i:02}").as_bytes())
            })
            .collect();
        // Zip64 sizes and offsets in the extra field, corrupt and whole.
        let z64 = |vals: &[u64]| {
            b(
                0x0001,
                &vals
                    .iter()
                    .flat_map(|v| v.to_le_bytes())
                    .collect::<Vec<u8>>(),
            )
        };
        entries.extend([
            CentralSpec {
                extra: z64(&[5_000_000_000, 3_000_000_000]),
                csize: 0xffff_ffff,
                ucsize: 0xffff_ffff,
                ..CentralSpec::new(b"z1")
            },
            CentralSpec {
                extra: z64(&[5, 6, 0x1_0000_0000]),
                csize: 0xffff_ffff,
                ucsize: 0xffff_ffff,
                offset: 0xffff_ffff,
                ..CentralSpec::new(b"z2")
            },
            CentralSpec {
                extra: z64(&[0x1_0000_0005]),
                offset: 0xffff_ffff,
                ..CentralSpec::new(b"z3")
            },
            CentralSpec {
                extra: [z64(&[5, 6, 7]), le(3)].concat(),
                csize: 0xffff_ffff,
                ucsize: 0xffff_ffff,
                offset: 0xffff_ffff,
                disk: 0xffff,
                ..CentralSpec::new(b"z5")
            },
            CentralSpec {
                comment: b"entry comment\r\nline 2\x1b".to_vec(),
                ..CentralSpec::new(b"c1")
            },
            CentralSpec {
                comment: b"\x82caf\x82".to_vec(),
                version_made_by: 0x0014,
                external_attr: 0x20,
                ..CentralSpec::new(b"c2")
            },
        ]);
        let ef = central_only(&entries, None, b"");
        // Gaps between entries ("extra bytes preceding"), an offset of 4.
        let gap = |name: &str, offset: u32, csize: u32| CentralSpec {
            offset,
            csize,
            ..CentralSpec::new(name.as_bytes())
        };
        let gaps = central_only(
            &[
                gap("g1", 0, 1),
                gap("g2", 100, 1),
                gap("g3", 4, 1),
                gap("g4", 0xffff_fff0, 1),
                gap("g5", 0, 1),
            ],
            None,
            b"",
        );
        let off4 = central_only(&[gap("o", 4, 1)], None, b"");
        let ut = |t: u32| b(0x5455, &cat(&[b"\x01", &le(t)]));
        let times = central_only(
            &[
                CentralSpec {
                    dos_time: 0,
                    ..CentralSpec::new(b"dos0")
                },
                CentralSpec {
                    dos_time: (40 << 25) | (13 << 21) | (1 << 16),
                    ..CentralSpec::new(b"dosm13")
                },
                CentralSpec {
                    dos_time: 0xffff_ffff,
                    ..CentralSpec::new(b"dosmax")
                },
                CentralSpec {
                    extra: ut(0x9000_0000),
                    dos_time: 0x7500_0000 | (DOS_TIME_2020 & 0xffff),
                    ..CentralSpec::new(b"ut2038")
                },
                CentralSpec {
                    extra: ut(0x9000_0000),
                    ..CentralSpec::new(b"utneg")
                },
                CentralSpec {
                    extra: ut(0),
                    ..CentralSpec::new(b"ut0")
                },
                CentralSpec {
                    extra: ut(0x7fff_ffff),
                    ..CentralSpec::new(b"utmax")
                },
            ],
            None,
            b"",
        );
        const UTF8: &[(&str, &str)] = &[("LANG", "en_US.UTF-8")];
        let mut cases = zi_runs(
            "zipinfo",
            "ef.zip",
            &ef,
            &[
                (&["-v"], &[], None),
                (&["-v"], UTF8, None),
                (&["-s"], &[], None),
                (&["-l"], &[], None),
                (&["-v", "@", "x2*"], &[], None),
                (&["-v", "@", "-x", "x1*"], &[], None),
            ],
        );
        for (name, bytes) in [("gaps.zip", &gaps), ("times.zip", &times)] {
            cases.extend(zi_runs(
                "zipinfo",
                name,
                bytes,
                &[
                    (&["-v"], &[], None),
                    (&["-s"], &[], None),
                    (&["-T"], &[], None),
                    (&["-v"], &[], Some("America/New_York")),
                    (&["-s"], &[], Some("Australia/Lord_Howe")),
                    (&["-v", "@", "g[24]"], &[], None),
                ],
            ));
        }
        // The previous archive's last offset of 4 starts the next one's
        // `endprev` at 4 (zipinfo.c reads the stale `G.crec`).
        for args in [vec!["-v", "*.zip"], vec!["-v", "*.zip", "g*"]] {
            cases.push(unzip_case(
                "zipinfo",
                args,
                vec![("a1.zip", off4.clone()), ("a2.zip", gaps.clone())],
            ));
        }
        compare("zipinfo_extra_fields", &cases);
    }

    /// zipinfo over a damaged directory: an extra field, name or comment
    /// running into the end record, too many or too few entries, a header
    /// cut short, a corrupt Zip64 field on a listed entry (`-v` then stops
    /// with `PK_ERR`), each in the formats whose loop handles the error
    /// differently, with the damaged entry selected and not; plus the end
    /// record damage Task 8's suite covers, in zipinfo's verbose report.
    #[test]
    fn zipinfo_damaged_directories() {
        let ut = extra_block(
            0x5455,
            &[&b"\x01"[..], &1_600_000_000u32.to_le_bytes()].concat(),
        );
        let a = CentralSpec {
            extra: ut,
            ..CentralSpec::new(b"a")
        };
        let claims = |name: &[u8], n: u16, e: u16, c: u16| CentralSpec {
            lengths: Some((n, e, c)),
            ..CentralSpec::new(name)
        };
        let corrupt64 = CentralSpec {
            extra: extra_block(1, b"abcd"),
            ucsize: 0xffff_ffff,
            ..CentralSpec::new(b"a")
        };
        let mut cut = central_only(&[CentralSpec::new(b"a")], Some(2), b"");
        let eocd = cut.len() - 22;
        cut.splice(eocd..eocd, *b"PK\x01\x02");
        let n = (cut.len() - 22 - 16) as u32;
        let at = cut.len() - 10;
        cut[at..at + 4].copy_from_slice(&n.to_le_bytes());
        let mut cases = Vec::new();
        for (name, bytes) in [
            (
                "exshort.zip",
                central_only(&[a.clone(), claims(b"b", 1, 300, 0)], None, b""),
            ),
            (
                "nameshort.zip",
                central_only(&[a.clone(), claims(b"b", 300, 0, 0)], None, b""),
            ),
            (
                "cmtshort.zip",
                central_only(&[a.clone(), claims(b"b", 1, 0, 300)], None, b""),
            ),
            (
                "count3.zip",
                central_only(&[a.clone(), CentralSpec::new(b"b")], Some(3), b""),
            ),
            (
                "count1.zip",
                central_only(&[a.clone(), CentralSpec::new(b"b")], Some(1), b""),
            ),
            (
                "z64.zip",
                central_only(&[corrupt64.clone(), CentralSpec::new(b"b")], None, b""),
            ),
            ("cut.zip", cut.clone()),
            (
                "comment.zip",
                central_only(std::slice::from_ref(&a), None, b"archive comment"),
            ),
            ("empty.zip", central_only(&[], None, b"")),
            ("emptycmt.zip", central_only(&[], None, b"only a comment")),
        ] {
            let name = leak(name.to_owned());
            cases.extend(zi_runs(
                "zipinfo",
                name,
                &bytes,
                &[
                    (&["-s"], &[], None),
                    (&["-v"], &[], None),
                    (&["-1"], &[], None),
                    (&["-2"], &[], None),
                    (&["-m"], &[], None),
                    (&["-h"], &[], None),
                    (&["-t"], &[], None),
                    (&["-z"], &[], None),
                    (&["-s", "@", "b"], &[], None),
                    (&["-v", "@", "b"], &[], None),
                    (&["-1", "@", "b"], &[], None),
                    (&["-t", "@", "a"], &[], None),
                ],
            ));
        }
        // End records Task 8 damaged, here in zipinfo's report: a
        // preamble, missing bytes, a disk number, a NULL offset.
        let base = zip_with(
            &[
                ZipEntrySpec::new(b"a.txt", b"alpha\n"),
                ZipEntrySpec::new(b"b.txt", b"bravo\n"),
            ],
            b"",
            b"",
        );
        let e = base.len() - 22;
        let mut disk = base.clone();
        disk[e + 4..e + 6].copy_from_slice(&1u16.to_le_bytes());
        let mut disk2 = base.clone();
        disk2[e + 6..e + 8].copy_from_slice(&1u16.to_le_bytes());
        let mut off5 = base.clone();
        let o = u32::from_le_bytes(off5[e + 16..e + 20].try_into().unwrap()) + 5;
        off5[e + 16..e + 20].copy_from_slice(&o.to_le_bytes());
        let mut nulloff = vec![b'X'; 30];
        let mut b0 = base.clone();
        b0[e + 16..e + 20].copy_from_slice(&0u32.to_le_bytes());
        nulloff.extend(b0);
        for (name, bytes) in [
            ("pre.zip", [vec![b'P'; 40], base.clone()].concat()),
            ("disk1.zip", disk),
            ("disk01.zip", disk2),
            ("off5.zip", off5),
            ("nulloff.zip", nulloff),
            ("notzip.zip", b"not a zip at all".to_vec()),
        ] {
            let name = leak(name.to_owned());
            cases.extend(zi_runs(
                "zipinfo",
                name,
                &bytes,
                &[
                    (&["-v"], &[], None),
                    (&["-s"], &[], None),
                    (&["-1"], &[], None),
                ],
            ));
        }
        compare("zipinfo_damaged_directories", &cases);
    }

    /// Review Focus 5, zipinfo's part: names that differ only in case (and
    /// `-C`), a newline and control bytes (`^J`), an escape sequence, high
    /// bytes under `C` and a UTF-8 locale, `../`, `/`, an empty name, a NUL
    /// inside a name, a name past `FILNAMSIZ`, in every one-line format
    /// and `-v`, and the patterns that pick among them.
    #[test]
    fn zipinfo_awkward_names() {
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
        let cases = zi_runs(
            "zipinfo",
            "names.zip",
            &z,
            &[
                (&["-1"], &[], None),
                (&["-2"], &[], None),
                (&["-s"], &[], None),
                (&["-m"], &[], None),
                (&["-l"], &[], None),
                (&["-v"], &[], None),
                (&["-s"], UTF8, None),
                (&["-v"], CUTF8, None),
                (&["-1"], UTF8, None),
                (&["-1", "@", "a"], &[], None),
                (&["-1", "@", "A"], &[], None),
                (&["-1C", "@", "a"], &[], None),
                (&["-1C", "@", "A", "-x", "a"], &[], None),
                (&["-s", "@", "dir/*"], &[], None),
                (&["-s", "@", "dir/\\[x\\].txt"], &[], None),
                (&["-s", "@", "star\\*name"], &[], None),
                (&["-s", "@", "[!a-z]*"], &[], None),
                (&["-s", "@", "?"], &[], None),
                (&["-s", "@", "nul"], &[], None),
                (&["-v", "@", "*tail"], &[], None),
                (&["-1", "@", "nomatch", "-x", "nomatch2"], &[], None),
            ],
        );
        compare("zipinfo_awkward_names", &cases);
    }

    /// The rulings on zipinfo.c's undefined behaviour, pinned on stuffr
    /// alone. On the `attribs[16]` and `methbuf[5]` overflows Apple's
    /// build dies by `__sprintf_chk` (SIGTRAP, exit 133) and Ubuntu's by
    /// FORTIFY (`*** buffer overflow detected ***`), except where Ubuntu's
    /// CVE-2016-9844 patch prints `03E8`; the SmartZip and INT_MIN answers
    /// are what both references happened to print (probe: `zipinfo -s`,
    /// `-v`, `-t` of each archive here, both references).
    #[test]
    fn zipinfo_rulings() {
        let one = |spec: CentralSpec, args: &[&'static str]| {
            let z = central_only(&[spec], None, b"");
            let mut a = args.to_vec();
            a.push("r.zip");
            let run = stuffr_unzip(&unzip_case("zipinfo", a, vec![("r.zip", z)]));
            assert_eq!((run.code, run.stderr.as_str()), (0, ""), "{args:?}");
            String::from_utf8(run.stdout).unwrap()
        };
        let line = |out: &str| out.lines().nth(2).unwrap_or_default().to_owned();
        // ruling: `attribs[16]` overflowed by a version of 10.0 or more
        // (MS-DOS template, VMS, Amiga, Theos): the whole version shows.
        let host = |name: &[u8], made_by: u16, attr: u32| CentralSpec {
            version_made_by: made_by,
            external_attr: attr,
            ..CentralSpec::new(name)
        };
        assert_eq!(
            line(&one(host(b"f", 0x0064, 0x20), &["-s"])),
            "-rw-a--     10.0 fat        1 b- stor 20-Jan-02 03:04 f"
        );
        assert_eq!(
            line(&one(host(b"f", 0x00ff, 0x21), &["-s"])),
            "-r--a--     25.5 fat        1 b- stor 20-Jan-02 03:04 f"
        );
        assert_eq!(
            line(&one(host(b"v", 0x0264, 0), &["-s"])),
            ",,          10.0 vms        1 b- stor 20-Jan-02 03:04 v"
        );
        assert_eq!(
            line(&one(host(b"a", 0x0164, 0o100644 << 16), &["-s"])),
            "?h-p--w--   10.0 ami        1 b- stor 20-Jan-02 03:04 a"
        );
        assert_eq!(
            line(&one(host(b"t", 0x1264, 0x8000 << 16), &["-m"])),
            "SHMWREXWR   10.0 ths        1 b-  0% stor 20-Jan-02 03:04 t"
        );
        // ruling: `methbuf[5]` overflowed by a method above 999: Ubuntu's
        // CVE-2016-9844 form, four hex digits.
        let m = |method: u16| CentralSpec {
            method,
            ..CentralSpec::new(b"m")
        };
        assert_eq!(
            line(&one(m(1000), &["-s"])),
            "-rw-r--r--  3.0 unx        1 b- 03E8 20-Jan-02 03:04 m"
        );
        assert_eq!(
            line(&one(m(65535), &["-l"])),
            "-rw-r--r--  3.0 unx        1 b-        1 FFFF 20-Jan-02 03:04 m"
        );
        assert_eq!(
            line(&one(m(999), &["-s"])),
            "-rw-r--r--  3.0 unx        1 b- u999 20-Jan-02 03:04 m"
        );
        // ruling: SmartZip's length byte above 31 (`filenameBuf[ef_ptr[32]]`
        // outside the array): the 31 bytes copied, to their first NUL.
        let smart = |len: u8, name: &[u8]| {
            let mut d = b"dZipTEXTttxt".to_vec();
            d.extend_from_slice(&[0; 20]);
            d.push(len);
            let mut n = name.to_vec();
            n.resize(31, 0);
            d.extend_from_slice(&n);
            CentralSpec {
                extra: extra_block(0x4d63, &d),
                ..CentralSpec::new(b"s")
            }
        };
        let out = one(smart(40, &[b'B'; 31]), &["-v"]);
        assert!(
            out.contains(&format!(
                "    The Mac long filename is {}.\n",
                "B".repeat(31)
            )),
            "{out}"
        );
        let out = one(smart(200, b"short\0rest"), &["-v"]);
        assert!(
            out.contains("    The Mac long filename is short.\n"),
            "{out}"
        );
        // ruling: the totals' `-cfactor` of INT_MIN (1000 bytes stored in
        // 2^31 + 1000: ratio() is INT_MIN tenths) prints its magnitude, as
        // both references do (`zipinfo_formats` compares it too).
        let wrap = CentralSpec {
            csize: (1 << 31) + 1000,
            ucsize: 1000,
            ..CentralSpec::new(b"w")
        };
        let out = one(wrap, &["-t"]);
        assert_eq!(
            out,
            "1 file, 1000 bytes uncompressed, 2147484648 bytes compressed:  -214748364.8%\n"
        );
        // ruling: `-m`'s `ratio() + 5` at INT_MAX wraps (both references'
        // answer too): `b--214748364%`.
        let top = CentralSpec {
            csize: (1 << 31) + 1001,
            ucsize: 1000,
            ..CentralSpec::new(b"w")
        };
        assert_eq!(
            line(&one(top, &["-m"])),
            "-rw-r--r--  3.0 unx     1000 b--214748364% stor 20-Jan-02 03:04 w"
        );
    }

    /// The ratios at the limits of an `int`: 1000 bytes stored in 2^31 +
    /// 1000 + k, where ratio() is INT_MIN (k = 0), INT_MAX (k = 1) and the
    /// `+ 5` overflows (k up to 5), in unzip's `-v`/`-l` (P23: unsigned)
    /// and zipinfo's `-m`, `-s` and totals (T9: `-m` wraps, the totals
    /// print the magnitude). Both references print these alike.
    #[test]
    fn ratios_at_the_int_limits() {
        let mut cases = Vec::new();
        for k in [-6i64, -1, 0, 1, 2, 3, 4, 5, 6] {
            let z = central_only(
                &[CentralSpec {
                    csize: ((1i64 << 31) + 1000 + k) as u32,
                    ucsize: 1000,
                    ..CentralSpec::new(b"w")
                }],
                None,
                b"",
            );
            let name = leak(format!("r{k}.zip"));
            cases.extend(listings(
                name,
                &z,
                &[(&["-v"], &[], None), (&["-l"], &[], None)],
            ));
            cases.extend(zi_runs(
                "zipinfo",
                name,
                &z,
                &[
                    (&["-m"], &[], None),
                    (&["-t"], &[], None),
                    (&["-v"], &[], None),
                ],
            ));
        }
        compare("ratios_at_the_int_limits", &cases);
    }
}
