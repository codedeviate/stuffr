//! The zip family's archives against this platform's reference (Tasks 6
//! and 7 of 0.19.0): every byte zip writes (local and central headers,
//! extra fields, data descriptors, Zip64 records, comments, the deflate
//! data at every level), both streams and the exit code, over
//! [`zip_bytes_matrix`] (new archives), [`zip_update_matrix`] (archives
//! already at the path) and [`zip_encrypted_matrix`] (`-P`, compared
//! outside the encryption headers). Apple's `/usr/bin/zip` on macOS, Ubuntu's apt
//! `zip` under `make compat-ubuntu` and CI's Linux jobs.

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod unix {
    use super::compat_harness::*;
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::{Command, Stdio};

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

    /// Task 7: updates. Ubuntu's failing `-T` runs are left out: its
    /// reference double-frees there (ruling Z3, pinned in
    /// `compat_zip_common`).
    #[test]
    fn updates_are_byte_identical() {
        let f = platform_zip_flavour();
        let cases = zip_update_matrix(f, f == "apple");
        assert!(cases.len() >= 150, "{} cases", cases.len());
        run_group(
            &format!("zip updates ({f})"),
            &cases,
            Skipped::none(),
            &assert_same_zip,
        );
    }

    /// Task 9: archives encrypted with `-P`, compared outside the 12-byte
    /// encryption headers (zip's random bytes) and decrypted: every other
    /// byte, both streams, the exit code and the tree, each header's check
    /// byte holding.
    #[test]
    fn encrypted_archives_decrypt_and_match_outside_the_headers() {
        let f = platform_zip_flavour();
        let cases = zip_encrypted_matrix(f);
        assert!(cases.len() >= 25, "{} cases", cases.len());
        run_group(
            &format!("zip encrypted ({f})"),
            &cases,
            Skipped::none(),
            &|c: &Case| assert_same_zip_decrypted(c, ZIP_PASSWORD),
        );
    }

    /// Task 8: `-F` and `-FF` over damaged archives and split sets, with
    /// the answers to zip's questions.
    #[test]
    fn fix_modes_match_the_reference() {
        let f = platform_zip_flavour();
        let cases = zip_fix_matrix(f);
        assert!(cases.len() >= 80, "{} cases", cases.len());
        run_group(
            &format!("zip fix ({f})"),
            &cases,
            Skipped::none(),
            &assert_same_zip,
        );
    }

    /// Task 8: split archives written (`-s`, `-sp`, `-sb`, `-sv`), and the
    /// split archives zip refuses to change.
    #[test]
    fn splits_are_byte_identical() {
        let f = platform_zip_flavour();
        let mut cases = zip_split_matrix(f);
        if f == "apple" {
            // `-sp` at the end of standard input: Apple's build goes on as
            // with ENTER, which is ruling Z5's answer (Ubuntu's asks again
            // for ever: pinned stuffr-only below)
            let mut c = zip_case(
                "zip",
                &["-s", "64k", "-sp", "t.zip", "big"],
                ZipTree::standard().file("big", random(200_000, 7)),
            );
            c.stdin = Some(Vec::new());
            cases.push(c);
        }
        assert!(cases.len() >= 30, "{} cases", cases.len());
        run_group(
            &format!("zip splits ({f})"),
            &cases,
            Skipped::none(),
            &assert_same_zip,
        );
    }

    /// Ruling Z22's sort: entries with equal names (more than 7, where
    /// Apple's `qsort` is no longer stable) met before a central header,
    /// then entries with new names and more central headers: `-FF` finds
    /// the same one of the equal entries for each central header as the
    /// reference, whose `qsort` runs over all entries each time.
    #[test]
    fn ff_matches_equal_names_as_the_reference_does() {
        fn local(name: &[u8], data: &[u8]) -> Vec<u8> {
            let crc = crc32(data);
            let mut b = b"PK\x03\x04\x0a\x00\x00\x00\x00\x00".to_vec();
            b.extend_from_slice(&0x2b29_0dd4u32.to_le_bytes());
            b.extend_from_slice(&crc.to_le_bytes());
            b.extend_from_slice(&(data.len() as u32).to_le_bytes());
            b.extend_from_slice(&(data.len() as u32).to_le_bytes());
            b.extend_from_slice(&(name.len() as u16).to_le_bytes());
            b.extend_from_slice(&[0, 0]);
            b.extend_from_slice(name);
            b.extend_from_slice(data);
            b
        }
        fn central(name: &[u8], comment: &[u8], atx: u32) -> Vec<u8> {
            let mut b = b"PK\x01\x02\x1e\x03\x0a\x00\x00\x00\x00\x00".to_vec();
            b.extend_from_slice(&0x2b29_0dd4u32.to_le_bytes());
            b.extend_from_slice(&[0; 12]);
            b.extend_from_slice(&(name.len() as u16).to_le_bytes());
            b.extend_from_slice(&[0, 0]);
            b.extend_from_slice(&(comment.len() as u16).to_le_bytes());
            b.extend_from_slice(&[0, 0, 0, 0]);
            b.extend_from_slice(&atx.to_le_bytes());
            b.extend_from_slice(&[0; 4]);
            b.extend_from_slice(name);
            b.extend_from_slice(comment);
            b
        }
        fn crc32(d: &[u8]) -> u32 {
            let mut c = !0u32;
            for &x in d {
                c ^= u32::from(x);
                for _ in 0..8 {
                    c = if c & 1 != 0 {
                        (c >> 1) ^ 0xedb8_8320
                    } else {
                        c >> 1
                    };
                }
            }
            !c
        }
        let mut cases = Vec::new();
        for dups in [7usize, 9, 13, 20] {
            let mut b = Vec::new();
            for i in 0..dups {
                b.extend_from_slice(&local(b"dup.txt", format!("data {i}\n").as_bytes()));
            }
            b.extend_from_slice(&local(b"aaa.txt", b"a\n"));
            for (j, c) in [&b"one"[..], b"two"].iter().enumerate() {
                b.extend_from_slice(&central(b"dup.txt", c, 0x81a4_0000 + j as u32));
            }
            // new names, then the central directory again
            for n in [&b"b.txt"[..], b"c.txt", b"zzz.txt", b"dup.tx"] {
                b.extend_from_slice(&local(n, b"new\n"));
            }
            for (j, c) in [&b"three"[..], b"four"].iter().enumerate() {
                b.extend_from_slice(&central(b"dup.txt", c, 0x81ed_0000 + j as u32));
            }
            // and once more with one more equal name
            b.extend_from_slice(&local(b"dup.txt", b"late\n"));
            b.extend_from_slice(&central(b"dup.txt", b"five", 0x81b6_0000));
            let mut c = zip_case(
                "zip",
                &["-FF", "in.zip", "--out", "f.zip"],
                ZipTree::standard().file("in.zip", b),
            );
            c.stdin = Some(b"y\n".to_vec());
            cases.push(c);
        }
        run_group(
            &format!("zip -FF equal names ({})", platform_zip_flavour()),
            &cases,
            Skipped::none(),
            &assert_same_zip,
        );
    }

    /// Rulings Z5 and Z19, stuffr only, both flavours: the end of standard
    /// input at a question about a part to read answers `q`, at `-sp`'s
    /// question ENTER; `-FF` copies a local extra field into the central one
    /// up to its first NUL, zeros after.
    #[test]
    fn fix_and_split_rulings_hold_in_both_flavours() {
        for flavour in ["apple", "ubuntu"] {
            let run = |args: &[&'static str], tree: ZipTree, stdin: &[u8]| {
                let mut c = zip_case("zip", args, tree);
                c.zip_flavour = Some(flavour);
                c.stdin = Some(stdin.to_vec());
                stuffr_zip(&c)
            };
            let cut = || ZipTree::standard().file("in.zip", zip_data("cut-central.zip"));
            // -FF: the questions end as `q` does
            let eof = run(&["-FF", "in.zip", "--out", "f.zip"], cut(), b"");
            let q = run(&["-FF", "in.zip", "--out", "f.zip"], cut(), b"n\nq\n");
            assert_eq!(eof.code, 0, "{flavour}");
            assert_eq!(eof.code, q.code, "{flavour}");
            assert_eq!(eof.stdout, q.stdout, "{flavour}");
            let text = String::from_utf8_lossy(&eof.stdout);
            assert!(
                text.ends_with(
                    "or ENTER  (try reading this split again): \tzip warning: could not find split: in.z01\n\tzip warning: zip file empty\n"
                ),
                "{flavour}: {text}"
            );
            let f = |r: &ZipRun| match r.tree.get(&b"f.zip"[..]) {
                Some(UnzipNode::File { bytes, .. }) => bytes.clone(),
                other => panic!("{flavour}: f.zip is {other:?}"),
            };
            assert_eq!(f(&eof).len(), 22, "{flavour}: an empty archive");
            // -F, a part missing: as `q` (exit 9, could not find split)
            let set = zip_split_set(flavour);
            let missing = || with_parts(zip_split_tree(), &set, &["s.z02"]);
            let eof = run(&["-F", "s.zip", "--out", "f.zip"], missing(), b"");
            let q = run(&["-F", "s.zip", "--out", "f.zip"], missing(), b"q\n");
            assert_eq!((eof.code, &eof.stdout), (q.code, &q.stdout), "{flavour}");
            assert_eq!(eof.code, 9, "{flavour}");
            assert!(
                String::from_utf8_lossy(&eof.stdout)
                    .ends_with("\nzip error: Interrupted (Could not find split)\n"),
                "{flavour}"
            );
            // -sp: the end of standard input is ENTER
            let big = || ZipTree::standard().file("big", random(200_000, 7));
            let args = &["-s", "64k", "-sp", "t.zip", "big"][..];
            let eof = run(args, big(), b"");
            let enter = run(args, big(), b"\n\n\n\n");
            assert_eq!(eof.code, 0, "{flavour}");
            assert_eq!(
                (eof.code, &eof.stdout),
                (enter.code, &enter.stdout),
                "{flavour}"
            );
            for part in ["t.z01", "t.z02", "t.z03", "t.zip"] {
                assert!(eof.tree.contains_key(part.as_bytes()), "{flavour}: {part}");
            }
            // ruling Z19: the central extra field is the local one up to its
            // first NUL, then zeros
            let r = run(
                &["-FF", "in.zip", "--out", "f.zip"],
                ZipTree::standard().file("in.zip", zip_data("extra-cut.zip")),
                b"y\n",
            );
            assert_eq!(r.code, 0, "{flavour}");
            let b = f(&r);
            let cen = b
                .windows(4)
                .position(|w| w == b"PK\x01\x02")
                .expect("a central header");
            let nam = usize::from(u16::from_le_bytes([b[cen + 28], b[cen + 29]]));
            let ext = usize::from(u16::from_le_bytes([b[cen + 30], b[cen + 31]]));
            assert_eq!((nam, ext), (5, 28), "{flavour}");
            let extra = &b[cen + 46 + nam..cen + 46 + nam + ext];
            assert_eq!(&extra[..4], b"UT\x09\x00", "{flavour}");
            assert!(extra[4..].iter().all(|&x| x == 0), "{flavour}: {extra:?}");
        }
    }

    /// `zip - names` with standard output a file that is not at its start:
    /// appended to (`>>`, `O_APPEND`) and positioned after other output
    /// (`{ printf pre; zip - ...; } > file`). zip rewrites a local header at
    /// the offset it counted from 0 and probes with the stream's own
    /// position: both references and stuffr write the same bytes (Task 6's
    /// carried bug: the probe used to seek to the counted offset).
    #[test]
    fn standard_output_past_its_start_is_written_as_zip_writes_it() {
        let Some(dir) = zip_dir() else {
            return;
        };
        let reference = Path::new(dir).join("zip");
        if !require_reference(&reference) {
            return;
        }
        let stuffr = std::path::PathBuf::from(env!("CARGO_BIN_EXE_stuffr"));
        let tree = zip_bytes_tree();
        let names = ["a.txt", "b.txt", "big.txt", "r.bin", "s.bin"];
        for append in [true, false] {
            let mut got = Vec::new();
            for exe in [&reference, &stuffr] {
                let s = ScratchDir::unique("zip-stdout-pos");
                std::fs::create_dir_all(&*s).unwrap();
                tree.materialise(&s);
                let out_path = s.join("out");
                std::fs::write(&out_path, b"EXISTING\n").unwrap();
                let out = if append {
                    std::fs::OpenOptions::new()
                        .append(true)
                        .open(&out_path)
                        .unwrap()
                } else {
                    let mut f = std::fs::OpenOptions::new()
                        .write(true)
                        .open(&out_path)
                        .unwrap();
                    std::io::Seek::seek(&mut f, std::io::SeekFrom::End(0)).unwrap();
                    f
                };
                let mut cmd = Command::new(exe);
                cmd.arg0("zip")
                    .arg("-")
                    .args(names)
                    .current_dir(&*s)
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .env("LANG", "C")
                    .env("TZ", "UTC")
                    .env("STUFFR_ZIP_FLAVOR", platform_zip_flavour())
                    .stdin(Stdio::null())
                    .stdout(out)
                    .stderr(Stdio::piped());
                let o = output_keep_stdout(&mut cmd);
                got.push((o.0, o.1, std::fs::read(&out_path).unwrap()));
            }
            assert_eq!(got[0].0, got[1].0, "exit, append {append}");
            assert_eq!(got[0].1, got[1].1, "stderr, append {append}");
            assert!(got[0].2 == got[1].2, "bytes differ, append {append}");
        }
    }

    /// `cmd` run with its standard output as set: (exit code, stderr).
    fn output_keep_stdout(cmd: &mut Command) -> (Option<i32>, Vec<u8>) {
        let child = spawn(cmd).unwrap();
        let o = child.wait_with_output().unwrap();
        (o.status.code(), o.stderr)
    }
}
