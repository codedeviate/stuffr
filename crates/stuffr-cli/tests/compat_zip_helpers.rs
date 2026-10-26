//! `zipnote` and `zipsplit` against this platform's reference (0.19.0
//! Task 10): exit code, both streams, and every byte of the tree (the
//! archives rewritten, the parts and the index zipsplit makes).
//!
//! Apple's `zipnote -w` always fails (exit 10, a double `fclose`: ruling
//! Z4), so on macOS its working runs are not compared with the reference:
//! `zipnote_w_is_the_same_in_both_flavours` runs them in stuffr's two
//! flavours and requires the same bytes, and the Ubuntu leg
//! (`make compat-ubuntu`) compares them with Ubuntu's own, whose patch 07
//! made `-w` work.

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod unix {
    use super::compat_harness::*;

    /// An archive of stored `entries`, made by `zip_with` (MS-DOS defaults),
    /// its entries' comments and the archive's comment added to the central
    /// directory (`zip_with` writes none).
    fn archive(entries: &[(&[u8], &[u8])], comments: &[&[u8]], zcomment: &[u8]) -> Vec<u8> {
        let specs: Vec<ZipEntrySpec> = entries
            .iter()
            .map(|(n, d)| ZipEntrySpec::new(n, d))
            .collect();
        with_comments(&zip_with(&specs, b"", b""), comments, zcomment)
    }

    fn le16(b: &[u8], at: usize) -> usize {
        usize::from(u16::from_le_bytes([b[at], b[at + 1]]))
    }

    fn le32(b: &[u8], at: usize) -> usize {
        u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]) as usize
    }

    /// `zip` with the central headers' comments (in order, none past the
    /// list's end) and the archive's comment replaced.
    fn with_comments(zip: &[u8], comments: &[&[u8]], zcomment: &[u8]) -> Vec<u8> {
        let eocd = zip
            .windows(4)
            .rposition(|w| w == b"PK\x05\x06")
            .expect("an end record");
        let n = le16(zip, eocd + 10);
        let cd = le32(zip, eocd + 16);
        let mut out = zip[..cd].to_vec();
        let mut at = cd;
        for i in 0..n {
            let (nam, ext) = (le16(zip, at + 28), le16(zip, at + 30));
            let end = at + 46 + nam + ext;
            let mut rec = zip[at..end].to_vec();
            let c = comments.get(i).copied().unwrap_or(b"");
            rec[32..34].copy_from_slice(&(c.len() as u16).to_le_bytes());
            rec.extend_from_slice(c);
            out.extend_from_slice(&rec);
            at = end + le16(zip, at + 32);
        }
        let cd_size = out.len() - cd;
        let mut end = zip[eocd..eocd + 22].to_vec();
        end[12..16].copy_from_slice(&(cd_size as u32).to_le_bytes());
        end[20..22].copy_from_slice(&(zcomment.len() as u16).to_le_bytes());
        out.extend_from_slice(&end);
        out.extend_from_slice(zcomment);
        out
    }

    /// One case: its inputs, and whether Apple's reference gets as far as
    /// the bug of `zipnote -w` (it does not when the run ends before the
    /// temporary archive is written).
    struct Note {
        case: Case<'static>,
        /// The run writes the archive: Apple's reference fails.
        writes: bool,
    }

    fn note(args: &[&'static str], tree: ZipTree, stdin: Option<&[u8]>, writes: bool) -> Note {
        let mut c = zip_case("zipnote", args, tree);
        c.stdin = stdin.map(<[u8]>::to_vec);
        Note { case: c, writes }
    }

    const COMMENTS: &[&[u8]] = &[
        b"first comment\nsecond line",
        b"has @ and \\ and\ttab\r\nCRLF and \x1b[0m esc",
        b"",
        b"no newline at end",
        b"ends with newline\n",
        b"@starts with at",
        b"with nul\0hidden",
    ];

    fn commented() -> ZipTree {
        ZipTree::standard().file(
            "t.zip",
            archive(
                &[
                    (b"a.txt", b"hello\n"),
                    (b"b.txt", b"bee\n"),
                    (b"d/c.txt", b"c\n"),
                    (b"e", b"e\n"),
                    (b"f", b"f\n"),
                    (b"g", b"g\n"),
                    (b"h", b"h\n"),
                ],
                COMMENTS,
                b"the archive\ncomment @ here \\",
            ),
        )
    }

    fn plain() -> ZipTree {
        ZipTree::standard().file(
            "t.zip",
            archive(
                &[(b"a.txt", b"hello\n"), (b"b.txt", b"bee\n"), (b"c", b"c\n")],
                &[],
                b"",
            ),
        )
    }

    /// The listing of `commented()`, as the references print it.
    fn listing() -> Vec<u8> {
        let mut o = Vec::new();
        for n in ["a.txt", "b.txt", "d/c.txt", "e", "f", "g", "h"] {
            o.extend_from_slice(format!("@ {n}\n@ (comment above this line)\n").as_bytes());
        }
        o.extend_from_slice(b"@ (zip file comment below this line)\n");
        o
    }

    fn note_cases() -> Vec<Note> {
        let mut v = vec![
            note(&["t.zip"], plain(), None, false),
            note(&["-q", "t.zip"], plain(), None, false),
            note(&["t"], plain(), None, false),
            note(&["t.zip"], commented(), None, false),
            note(&["-q", "t.zip"], commented(), None, false),
            note(&["nosuch.zip"], plain(), None, false),
            note(&["nosuch"], plain(), None, false),
            note(&["t.zip", "a.txt"], plain(), None, false),
            note(&["-x", "t.zip"], plain(), None, false),
            note(&["-b"], plain(), None, false),
            note(&["t.zip", "-b"], plain(), None, false),
            note(&["-b", "d", "-b", "d", "t.zip"], plain(), None, false),
            note(&["-"], plain(), None, false),
            note(&[], plain(), None, false),
            note(&["-h"], plain(), None, false),
            note(&["-L"], plain(), None, false),
            // a file that is not an archive, an empty file, an empty archive
            note(
                &["g.zip"],
                ZipTree::standard().file("g.zip", b"garbage, not a zip"),
                None,
                false,
            ),
            note(
                &["e.zip"],
                ZipTree::standard().file("e.zip", b""),
                None,
                false,
            ),
            note(
                &["e.zip"],
                ZipTree::standard()
                    .file("e.zip", b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
                None,
                false,
            ),
            note(
                &["-w", "e.zip"],
                ZipTree::standard()
                    .file("e.zip", b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
                Some(b""),
                false,
            ),
            // a directory named like the archive, a cut archive
            note(&["t.zip"], ZipTree::standard().dir("t.zip"), None, false),
        ];
        for f in [
            "bad-central",
            "bad-version",
            "comment-cut",
            "cut-central",
            "cut-data",
            "descriptors",
            "descriptors-cut",
            "extra-cut",
            "intact",
            "junk",
            "preamble",
        ] {
            let name: &'static str = Box::leak(format!("{f}.zip").into_boxed_str());
            let tree = ZipTree::standard().file(name, zip_data(name));
            v.push(note(&[name], tree.clone(), None, false));
            let writes = ["bad-version", "descriptors", "intact"].contains(&f);
            v.push(note(
                &["-w", name],
                tree,
                Some(b"@ a.txt\nx\n@ (comment above this line)\n"),
                writes,
            ));
        }
        // -w: input that ends the run before anything is written
        for (args, tree, input) in [
            (&["-w", "t.zip"][..], plain(), &b"garbage\n"[..]),
            (&["-w", "t.zip"][..], plain(), &b"@\n"[..]),
            (&["-w", "t.zip"][..], plain(), &b"@x\n"[..]),
            (&["-w", "t.zip"][..], plain(), &b"\n"[..]),
            (&["-w", "t.zip"][..], plain(), &b"@ nosuch\n"[..]),
            // out of order: b.txt is gone once a.txt..c were passed
            (
                &["-w", "t.zip"][..],
                plain(),
                &b"@ c\nx\n@ (comment above this line)\n@ a.txt\ny\n@ (comment above this line)\n"
                    [..],
            ),
        ] {
            v.push(note(args, tree, Some(input), false));
        }
        // -w: the archive cannot be written, nor its directory
        v.push(note(
            &["-w", "t.zip"],
            ZipTree::standard().file_mode(
                "t.zip",
                archive(&[(b"a.txt", b"hello\n")], &[], b""),
                0o444,
            ),
            Some(b"@ a.txt\nnew\n@ (comment above this line)\n"),
            false,
        ));
        v.push(note(
            &["-w", "-b", "nodir", "t.zip"],
            plain(),
            Some(b"@ a.txt\nnew\n@ (comment above this line)\n"),
            false,
        ));
        v.push(note(
            &["-w", "-b", "ro", "t.zip"],
            plain().dir_mode("ro", 0o555),
            Some(b"@ a.txt\nnew\n@ (comment above this line)\n"),
            false,
        ));
        v.push(note(
            &["-w", "nosuch.zip"],
            plain(),
            Some(b"@ a.txt\n"),
            false,
        ));
        // -w that writes the archive
        let mut round = listing();
        round.extend_from_slice(b"the archive\ncomment @ here \\\\\n");
        let writes: Vec<(&[&'static str], ZipTree, Vec<u8>)> = vec![
            (&["-w", "t.zip"], plain(), b"".to_vec()),
            (&["-w", "t.zip"], plain(), b"@ a.txt\nok\n@ x\n".to_vec()),
            (&["-w", "t.zip"], commented(), b"".to_vec()),
            (&["-w", "t"], plain(), b"@ a.txt\nnew\n@ (comment above this line)\n".to_vec()),
            (&["-w", "-q", "t.zip"], plain(), b"@ a.txt\nnew\n@ (comment above this line)\n".to_vec()),
            (&["-qw", "t.zip"], plain(), b"@ a.txt\nnew\n@ (comment above this line)\n".to_vec()),
            (&["-w", "-b", "d", "t.zip"], plain(), b"@ b.txt\nonly b\n@ (comment above this line)\n".to_vec()),
            (&["-w", "t.zip"], commented(), round),
            (
                &["-w", "t.zip"],
                plain(),
                b"@ a.txt\nline one\nline two\n@ (comment above this line)\n@ b.txt\n@ (comment above this line)\n@ c\nlast\n@ (comment above this line)\n@ (zip file comment below this line)\nnew archive comment\nsecond\n".to_vec(),
            ),
            // missing entries are allowed, in order
            (
                &["-w", "t.zip"],
                plain(),
                b"@ c\nthe last only\n@ (comment above this line)\n".to_vec(),
            ),
            // comments from nothing: empty lines first, then text (no CR LF
            // after an empty first line), escapes, CR LF input, a lone
            // trailing backslash
            (
                &["-w", "t.zip"],
                plain(),
                b"@ a.txt\n\n\ntext\n\\@at\n\\\\two\\\\\nback\\\n@ (comment above this line)\n@ b.txt\nwith\r\ncrlf\r\n@ (comment above this line)\n".to_vec(),
            ),
            // the zip file comment cleared, then set from nothing
            (
                &["-w", "t.zip"],
                commented(),
                b"@ (zip file comment below this line)\n".to_vec(),
            ),
            (
                &["-w", "t.zip"],
                plain(),
                b"@ (zip file comment below this line)\n\n\nafter blanks\n".to_vec(),
            ),
            // no end marker: the last comment runs to the end of the input
            (
                &["-w", "t.zip"],
                plain(),
                b"@ a.txt\nunended".to_vec(),
            ),
            (
                &["-w", "t.zip"],
                plain(),
                b"@ a.txt\nunended\n@ (comment above this line)\n@ (zip file comment below this line)\nzc no newline".to_vec(),
            ),
            // renames
            (
                &["-w", "t.zip"],
                plain(),
                b"@ a.txt\n@=renamed.txt\nand a comment\n@ (comment above this line)\n".to_vec(),
            ),
            (
                &["-w", "t.zip"],
                plain(),
                b"@ a.txt\n@=\n@ (comment above this line)\n".to_vec(),
            ),
            (
                &["-w", "t.zip"],
                plain(),
                b"@ a.txt\n@=a/very/long/new/name/that/goes/on/and/on/and/on/and/on/and/on/and/on/and/on.txt\n@ (comment above this line)\n@ b.txt\n@=b.txt\n@ (comment above this line)\n@ c\n@=b.txt\nx\n@ (comment above this line)\n".to_vec(),
            ),
            (
                &["-w", "t.zip"],
                plain(),
                b"@ a.txt\n@=one\n@=two\n@ (comment above this line)\n".to_vec(),
            ),
            // a line too long for zipnote's buffer ends the input; the rest
            // of that line is read as lines
            (
                &["-w", "t.zip"],
                plain(),
                {
                    let mut v = b"@ a.txt\nshort\n".to_vec();
                    v.extend(std::iter::repeat_n(b'x', 5000));
                    v.extend_from_slice(b"\n@ (comment above this line)\n@ b.txt\nafter\n@ (comment above this line)\n");
                    v
                },
            ),
            // a comment line of exactly the buffer's size, either side
            (
                &["-w", "t.zip"],
                plain(),
                {
                    let mut v = b"@ a.txt\n".to_vec();
                    v.extend(std::iter::repeat_n(b'y', 2045));
                    v.extend_from_slice(b"\n@ (comment above this line)\n");
                    v
                },
            ),
            (
                &["-w", "t.zip"],
                plain(),
                {
                    let mut v = b"@ a.txt\n".to_vec();
                    v.extend(std::iter::repeat_n(b'y', 2046));
                    v.extend_from_slice(b"\n@ (comment above this line)\n");
                    v
                },
            ),
            // a NUL in a line cuts it
            (
                &["-w", "t.zip"],
                plain(),
                b"@ a.txt\nbefore\0after\n@ (comment above this line)\n".to_vec(),
            ),
            // a long comment, past what the end record can hold
            (
                &["-w", "t.zip"],
                plain(),
                {
                    let mut v = b"@ (zip file comment below this line)\n".to_vec();
                    for _ in 0..40 {
                        v.extend(std::iter::repeat_n(b'z', 1999));
                        v.push(b'\n');
                    }
                    v
                },
            ),
        ];
        for (args, tree, input) in writes {
            v.push(note(args, tree, Some(&input), true));
        }
        v
    }

    /// Whether the reference is Apple's (`zipnote -w` fails in it).
    fn apple() -> bool {
        platform_zip_flavour() == "apple"
    }

    #[test]
    fn zipnote_matches_the_reference() {
        let all = note_cases();
        let total = all.len();
        let (cases, skipped): (Vec<_>, Vec<_>) =
            all.into_iter().partition(|n| !(apple() && n.writes));
        let cases: Vec<Case> = cases.into_iter().map(|n| n.case).collect();
        assert!(cases.len() >= 30, "{} cases", cases.len());
        run_group(
            &format!("zipnote ({})", platform_zip_flavour()),
            &cases,
            Skipped {
                count: skipped.len(),
                why: "Apple's zipnote -w always fails (ruling Z4, stuffr-only test)".into(),
            },
            &assert_same_zip,
        );
        assert!(total >= 50, "{total} cases in all");
    }

    /// Ruling Z4 (deviation 26): `zipnote -w` works as Ubuntu's (patch 07)
    /// in both flavours: the runs of the matrix that write the archive end
    /// in exit 0 in each, with the same tree, and a second listing gives
    /// back what was written.
    #[test]
    fn zipnote_w_is_the_same_in_both_flavours() {
        let (mut n, mut ok) = (0, 0);
        for c in note_cases().into_iter().filter(|n| n.writes) {
            let mut a = c.case.clone();
            a.zip_flavour = Some("apple");
            let mut u = c.case.clone();
            u.zip_flavour = Some("ubuntu");
            let (ra, ru) = (stuffr_zip(&a), stuffr_zip(&u));
            assert_eq!(ra.code, ru.code, "{:?}", c.case.args);
            if ra.code == 0 {
                ok += 1;
            }
            let d = zip_differences(&c.case, &ra, &ru);
            assert!(d.is_empty(), "{:?}: {}", c.case.args, d.join("\n"));
            n += 1;
        }
        assert!(n >= 20 && ok >= 15, "{n} runs, {ok} written");
    }

    /// The Apple reference's bug, recorded: `-w` ends in exit 10 with the
    /// archive untouched and no temporary left (the harness's tree shows
    /// no `zi??????`), where stuffr writes the archive.
    #[test]
    fn apples_zipnote_w_fails_and_stuffr_does_not() {
        if !apple() {
            return;
        }
        let c = note(
            &["-w", "t.zip"],
            plain(),
            Some(b"@ a.txt\nnew\n@ (comment above this line)\n"),
            true,
        );
        let r = zip_reference(&c.case).expect("Apple's zipnote");
        assert_eq!(r.code, 10);
        assert_eq!(
            String::from_utf8_lossy(&mask_temp_names(&r.stderr)),
            "zipnote error: Bad file descriptor\nzipnote error: Temporary file failure (zi??????)\n"
        );
        let s = stuffr_zip(&c.case);
        assert_eq!(s.code, 0);
    }

    // ---- zipsplit ----

    /// `(name, size)` entries of stored random data.
    fn sized(sizes: &[usize]) -> Vec<(Vec<u8>, Vec<u8>)> {
        sizes
            .iter()
            .enumerate()
            .map(|(i, &n)| (format!("r{}", i + 1).into_bytes(), random(n, 11 + i as u64)))
            .collect()
    }

    fn zipped(entries: &[(Vec<u8>, Vec<u8>)], comments: &[&[u8]]) -> Vec<u8> {
        let specs: Vec<ZipEntrySpec> = entries
            .iter()
            .map(|(n, d)| ZipEntrySpec::new(n, d))
            .collect();
        with_comments(&zip_with(&specs, b"", b""), comments, b"")
    }

    fn tree_of(name: &str, zip: Vec<u8>) -> ZipTree {
        ZipTree::standard().file(name, zip)
    }

    fn split_case(args: &[&'static str], tree: ZipTree, stdin: Option<&[u8]>) -> Case<'static> {
        let mut c = zip_case("zipsplit", args, tree);
        c.stdin = stdin.map(<[u8]>::to_vec);
        c
    }

    fn split_cases() -> Vec<Case<'static>> {
        let mixed = zipped(
            &sized(&[
                30000, 200, 5000, 12000, 7000, 7000, 3000, 25000, 100, 100, 18000, 9000,
            ]),
            &[b"a comment", b"", b"another one"],
        );
        let same = zipped(&sized(&[4000; 14]), &[]);
        let many = zipped(&sized(&[120; 40]), &[]);
        let mut v = vec![
            split_case(&["-t", "t.zip"], tree_of("t.zip", mixed.clone()), None),
            split_case(
                &["-n", "40000", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                None,
            ),
            split_case(
                &["-n", "40000", "-t", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                None,
            ),
            split_case(
                &["-n", "40000", "-s", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                None,
            ),
            split_case(
                &["-n", "40000", "-i", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                None,
            ),
            split_case(
                &["-n", "40000", "-ti", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                None,
            ),
            split_case(
                &["-n", "40000", "-r", "20000", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                None,
            ),
            split_case(
                &["-n", "40000", "-r", "-500", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                None,
            ),
            split_case(
                &["-n", "40000", "-r", "900000", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                None,
            ),
            split_case(
                &["-n", "40000", "-r", "20000", "-i", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                None,
            ),
            split_case(
                &["-n", "40000", "-r", "x", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                None,
            ),
            split_case(
                &["-n", "32000", "-q", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                None,
            ),
            split_case(&["-n", "32000", "t"], tree_of("t.zip", mixed.clone()), None),
            split_case(
                &["-n", "31000", "-t", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                None,
            ),
            split_case(
                &["-n", "26000", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                None,
            ),
            split_case(
                &["-n", "26000", "-s", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                None,
            ),
            split_case(
                &["-n", "31000", "-b", "o", "t.zip"],
                tree_of("t.zip", mixed.clone()).dir("o"),
                None,
            ),
            split_case(
                &["-b", "o/", "-n", "31000", "t.zip"],
                tree_of("t.zip", mixed.clone()).dir("o"),
                None,
            ),
            split_case(
                &["-b", "", "-n", "31000", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                None,
            ),
            split_case(
                &["-n", "31000", "-b", "nodir", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                None,
            ),
            split_case(
                &["-n", "31000", "-b", "ro", "t.zip"],
                tree_of("t.zip", mixed.clone()).dir_mode("ro", 0o555),
                None,
            ),
            split_case(
                &["-n", "31000", "-i", "-b", "nodir", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                None,
            ),
            // equal sizes: the order of ties
            split_case(
                &["-n", "20000", "t.zip"],
                tree_of("t.zip", same.clone()),
                None,
            ),
            split_case(
                &["-n", "20000", "-i", "t.zip"],
                tree_of("t.zip", same.clone()),
                None,
            ),
            split_case(
                &["-n", "9000", "t.zip"],
                tree_of("t.zip", same.clone()),
                None,
            ),
            split_case(
                &["-n", "9000", "-s", "t.zip"],
                tree_of("t.zip", same.clone()),
                None,
            ),
            // many parts: two digits
            split_case(
                &["-n", "100", "t.zip"],
                tree_of("t.zip", zipped(&sized(&[1; 12]), &[])),
                None,
            ),
            split_case(
                &["-n", "400", "t.zip"],
                tree_of("t.zip", many.clone()),
                None,
            ),
            split_case(
                &["-n", "400", "-i", "t.zip"],
                tree_of("t.zip", many.clone()),
                None,
            ),
            split_case(
                &["-n", "1000", "-t", "t.zip"],
                tree_of("t.zip", many.clone()),
                None,
            ),
            // names: cut to eight characters with the digits
            split_case(
                &["-n", "40000", "longarchivename.zip"],
                tree_of("longarchivename.zip", mixed.clone()),
                None,
            ),
            split_case(
                &["-n", "40000", "arch1.zip"],
                tree_of("arch1.zip", mixed.clone()),
                None,
            ),
            split_case(
                &["-n", "40000", "arc_1.zip"],
                tree_of("arc_1.zip", mixed.clone()),
                None,
            ),
            split_case(
                &["-n", "40000", "1.zip"],
                tree_of("1.zip", mixed.clone()),
                None,
            ),
            split_case(
                &["-n", "40000", ".zip"],
                tree_of(".zip", mixed.clone()),
                None,
            ),
            split_case(
                &["-n", "40000", "noext"],
                tree_of("noext", mixed.clone()),
                None,
            ),
            split_case(
                &["-n", "40000", "d/in.zip"],
                tree_of("d/in.zip", mixed.clone()),
                None,
            ),
            split_case(
                &["-n", "40000", "a.b.zip"],
                tree_of("a.b.zip", mixed.clone()),
                None,
            ),
            split_case(
                &["-n", "9000", "ninechars.zip"],
                tree_of("ninechars.zip", same.clone()),
                None,
            ),
            // an output that already exists is overwritten
            split_case(
                &["-n", "40000", "t.zip"],
                tree_of("t.zip", mixed.clone())
                    .file("t1.zip", b"old")
                    .file("zipsplit.idx", b"old"),
                None,
            ),
            // -p: the questions answered, then the end of the input
            split_case(
                &["-n", "40000", "-p", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                Some(b"\n\n\n\n"),
            ),
            split_case(
                &["-n", "40000", "-p", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                Some(b""),
            ),
            split_case(
                &["-n", "40000", "-pi", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                Some(b"a\nb\n"),
            ),
            split_case(
                &["-n", "40000", "-pt", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                Some(b"\n"),
            ),
            split_case(
                &["-n", "40000", "-p", "-b", "nodir", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                Some(b"\nn\n"),
            ),
            split_case(
                &["-n", "40000", "-p", "-b", "nodir", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                Some(b"\ny\nn\n"),
            ),
            // entries too big, errors in the arguments
            split_case(
                &["-n", "1000", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                None,
            ),
            split_case(
                &["-n", "1000", "-t", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                None,
            ),
            split_case(
                &["-n", "100", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                None,
            ),
            split_case(
                &["-n", "50", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                None,
            ),
            split_case(
                &["-n", "abc", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                None,
            ),
            split_case(&["-n"], tree_of("t.zip", mixed.clone()), None),
            split_case(
                &["-nb", "o", "t.zip"],
                tree_of("t.zip", mixed.clone()),
                None,
            ),
            split_case(&["-x", "t.zip"], tree_of("t.zip", mixed.clone()), None),
            split_case(&["t.zip", "u.zip"], tree_of("t.zip", mixed.clone()), None),
            split_case(&["-"], tree_of("t.zip", mixed.clone()), None),
            split_case(&["-n", "40000"], tree_of("t.zip", mixed.clone()), None),
            split_case(&[], tree_of("t.zip", mixed.clone()), None),
            split_case(&["-h"], tree_of("t.zip", mixed.clone()), None),
            split_case(&["-L"], tree_of("t.zip", mixed.clone()), None),
            // missing, not an archive, empty, a split archive
            split_case(&["nosuch.zip"], tree_of("t.zip", mixed.clone()), None),
            split_case(&["-t", "nosuch"], tree_of("t.zip", mixed.clone()), None),
            split_case(
                &["g.zip"],
                ZipTree::standard().file("g.zip", b"not a zip"),
                None,
            ),
            split_case(
                &["e.zip"],
                ZipTree::standard()
                    .file("e.zip", b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
                None,
            ),
            split_case(
                &["-t", "s.zip"],
                with_parts(
                    ZipTree::standard(),
                    &zip_split_set(platform_zip_flavour()),
                    &[],
                ),
                None,
            ),
            split_case(
                &["s.zip"],
                with_parts(
                    ZipTree::standard(),
                    &zip_split_set(platform_zip_flavour()),
                    &[],
                ),
                None,
            ),
        ];
        // real zip's archives: deflated entries, descriptors, a stream
        for (flavour_args, names) in [
            (&["-X", "-9"][..], &["a.txt", "b.txt", "d/c.txt"][..]),
            (&["-X", "-fd"][..], &["a.txt", "b.txt"][..]),
            (&["-X", "-0"][..], &["a.txt", "b.txt", "d/c.txt"][..]),
        ] {
            let mut args = flavour_args.to_vec();
            args.push("t.zip");
            args.extend_from_slice(names);
            let zip = zip_made(platform_zip_flavour(), &ZipTree::standard(), &args, "t.zip");
            for a in [
                &["-n", "300", "t.zip"][..],
                &["-n", "700", "-i", "t.zip"][..],
                &["-t", "t.zip"][..],
            ] {
                v.push(split_case(a, tree_of("t.zip", zip.clone()), None));
            }
        }
        v
    }

    #[test]
    fn zipsplit_matches_the_reference() {
        let cases = split_cases();
        assert!(cases.len() >= 70, "{} cases", cases.len());
        run_group(
            &format!("zipsplit ({})", platform_zip_flavour()),
            &cases,
            Skipped::none(),
            &assert_same_zip,
        );
    }

    /// The rows of the recorded table that Task 10 makes comparable.
    #[test]
    fn zipsplit_is_the_same_in_both_flavours() {
        let mut n = 0;
        for c in split_cases() {
            // the help names the flavour's build
            if c.args.is_empty() || c.args.contains(&"-h") {
                continue;
            }
            let mut a = c.clone();
            a.zip_flavour = Some("apple");
            let mut u = c.clone();
            u.zip_flavour = Some("ubuntu");
            let (ra, ru) = (stuffr_zip(&a), stuffr_zip(&u));
            let d = zip_differences(&c, &ra, &ru);
            assert!(d.is_empty(), "{:?}: {}", c.args, d.join("\n"));
            n += 1;
        }
        assert!(n >= 65, "{n} runs");
    }

    /// Ruling Z27: zipsplit interrupted while it writes its second part
    /// removes the index and every part made, as the C's handler does
    /// through `ziperr`: INT, TERM, ABRT, BUS, ILL and SEGV print
    /// `Interrupted (aborting)` after the run's output and exit 9; HUP
    /// kills it and leaves them. Both sides must agree (output, exit,
    /// what is left). The second part is a 64 MiB (then 256 MiB) stored
    /// entry, so the signal lands while it is being copied.
    #[test]
    fn zipsplit_interrupts_match_the_reference() {
        use super::compat_harness::interrupt::*;
        use std::os::unix::process::ExitStatusExt;
        let _serial = interrupt_lock();
        let Some(dir) = zip_dir() else {
            return;
        };
        let reference = std::path::Path::new(dir).join("zipsplit");
        if !require_reference(&reference) {
            return;
        }
        let stuffr = std::path::PathBuf::from(env!("CARGO_BIN_EXE_stuffr"));
        let flavour = platform_zip_flavour();
        let env = [("STUFFR_ZIP_FLAVOR", flavour), ("LANG", "C"), ("TZ", "UTC")];
        let rows: [(i32, bool); 8] = [
            (libc::SIGINT, false),
            (libc::SIGINT, true),
            (libc::SIGTERM, true),
            (libc::SIGABRT, false),
            (libc::SIGBUS, true),
            (libc::SIGILL, false),
            (libc::SIGSEGV, true),
            (libc::SIGHUP, true),
        ];
        for (sig, index) in rows {
            let mut seen = Vec::new();
            for exe in [&reference, &stuffr] {
                let s = ScratchDir::unique("zipsplit-intr");
                let mut got = None;
                for mib in [64usize, 256] {
                    let _ = std::fs::remove_dir_all(&*s);
                    std::fs::create_dir_all(&*s).unwrap();
                    let big = big_input(mib);
                    let zip = zip_with(
                        &[
                            ZipEntrySpec::new(b"a", b"hi"),
                            ZipEntrySpec::new(b"big", &big),
                        ],
                        b"",
                        b"",
                    );
                    std::fs::write(s.join("t.zip"), zip).unwrap();
                    // the first part holds `a` alone, the second `big`
                    let n = (big.len() + 142).to_string();
                    let mut args = vec!["-n", &n, "-s"];
                    if index {
                        args.push("-i");
                    }
                    args.push("t.zip");
                    let d: &std::path::Path = &s;
                    let ready = |name: &str| {
                        name == "t2.zip"
                            && std::fs::metadata(d.join(name)).map_or(0, |m| m.len()) > 100_000
                    };
                    match interrupt_listing_stdout(
                        exe,
                        "zipsplit",
                        &args,
                        d,
                        &env,
                        Inherit::Default,
                        sig,
                        &ready,
                    ) {
                        Some(r) if !r.status.success() => {
                            got = Some(r);
                            break;
                        }
                        _ => {}
                    }
                }
                let Some(r) = got else {
                    assert!(
                        exe == &reference && take_reference_hung(),
                        "signal {sig}: no run"
                    );
                    continue;
                };
                let left: Vec<String> = r
                    .left
                    .iter()
                    .filter(|n| n.as_str() != "t.zip")
                    .cloned()
                    .collect();
                seen.push((r.status.code(), r.status.signal(), r.stdout, r.stderr, left));
            }
            if seen.len() != 2 {
                continue;
            }
            if sig == libc::SIGHUP {
                // killed: the C's buffered standard output (a pipe) is lost
                // with it, stuffr's is written as it goes
                seen[0].2.clear();
                seen[1].2.clear();
            }
            assert_eq!(seen[0], seen[1], "signal {sig}, index {index}");
            let (code, signal, stdout, _, left) = &seen[1];
            if sig == libc::SIGHUP {
                assert_eq!(*signal, Some(sig));
                assert!(left.iter().any(|n| n == "t2.zip"), "{left:?}");
            } else {
                assert_eq!(*code, Some(9), "signal {sig}");
                assert!(
                    String::from_utf8_lossy(stdout)
                        .ends_with("creating: t2.zip\n\nzipsplit error: Interrupted (aborting)\n"),
                    "{}",
                    String::from_utf8_lossy(stdout)
                );
                assert!(left.is_empty(), "left behind: {left:?}");
            }
        }
    }

    /// Write failures (`ulimit -f`): at every limit from mid-stream to just past the end of
    /// the first part, with and without `-p` and `-i`, stuffr and the
    /// reference agree on exit, both streams and what is left: `write error
    /// on zip file` from the middle of a copy, `-p`'s "redo entire disk?"
    /// and `Output file write failure (<part>)` where the error surfaces
    /// when the part is closed (zipsplit's files are stdio's, 4096-byte
    /// buffers).
    #[test]
    #[allow(clippy::manual_is_multiple_of)]
    fn zipsplit_write_failures_match_the_reference() {
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        let Some(dir) = zip_dir() else {
            return;
        };
        let reference = std::path::Path::new(dir).join("zipsplit");
        if !require_reference(&reference) {
            return;
        }
        let links = ScratchDir::unique("zipsplit-link");
        std::fs::create_dir_all(&*links).unwrap();
        let stuffr = links.join("zipsplit");
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stuffr"), &stuffr).unwrap();
        // two entries in a part each of its own, and three in one part
        // (where a redo reads offsets zipcopy has overwritten)
        let two = zip_with(
            &[
                ZipEntrySpec::new(b"r1", &random(60_000, 1)),
                ZipEntrySpec::new(b"r2", &random(60_000, 2)),
            ],
            b"",
            b"",
        );
        let three = zip_with(
            &[
                ZipEntrySpec::new(b"r1", &random(20_000, 1)),
                ZipEntrySpec::new(b"r2", &random(20_000, 2)),
                ZipEntrySpec::new(b"r3", &random(20_000, 3)),
            ],
            b"",
            b"",
        );
        // sh's `ulimit -f` counts 512-byte blocks in dash, 1024-byte ones in
        // macOS's sh: the limits are the same bytes
        let unit: u64 = if cfg!(target_os = "linux") { 512 } else { 1024 };
        let mut compared = 0;
        for (limit, pause, index, input, answers) in (96..=120)
            .map(|l| l * 512 / unit)
            .filter(|l| l * unit % 512 == 0)
            .flat_map(|l| {
                [
                    (l, false, false, &two, &b"\n\n\n\n\nn\n"[..]),
                    (l, true, false, &two, &b"\n\n\n\n\nn\n"[..]),
                    (l, true, true, &two, &b"\n\n\n\n\nn\n"[..]),
                    (l, true, false, &three, &b"\n\n\n\n\nn\n"[..]),
                    // yes, twice: the disk is made again from the offsets the
                    // first pass left in the entries
                    (l, true, false, &three, &b"\ny\n\ny\n\nn\n"[..]),
                    (l, true, true, &two, &b"\ny\n\ny\n\nn\n"[..]),
                ]
            })
        {
            let mut seen = Vec::new();
            for exe in [&reference, &stuffr] {
                let s = ScratchDir::unique("zipsplit-full");
                std::fs::create_dir_all(&*s).unwrap();
                std::fs::write(s.join("t.zip"), input).unwrap();
                let mut args = vec!["-n".to_owned(), "70000".to_owned()];
                if pause {
                    args.push("-p".into());
                }
                if index {
                    args.push("-i".into());
                }
                args.push("t.zip".into());
                let mut cmd = Command::new("sh");
                cmd.arg("-c")
                    .arg(format!(
                        "trap '' XFSZ; ulimit -f {limit}; exec \"$0\" \"$@\""
                    ))
                    .arg(exe)
                    .args(&args)
                    .env("STUFFR_ZIP_FLAVOR", platform_zip_flavour())
                    .env("LANG", "C")
                    .current_dir(&*s)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                let mut child = spawn(&mut cmd).unwrap();
                let mut sin = child.stdin.take().unwrap();
                let _ = sin.write_all(answers);
                drop(sin);
                let o = child.wait_with_output().unwrap();
                let mut left: Vec<String> = std::fs::read_dir(&*s)
                    .unwrap()
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect();
                left.sort();
                seen.push((o.status.code(), o.stdout, o.stderr, left));
            }
            assert_eq!(
                seen[0], seen[1],
                "limit {limit} blocks, -p {pause}, -i {index}, answers {answers:?}"
            );
            compared += 1;
        }
        assert!(compared >= 70, "{compared}");
    }
}
