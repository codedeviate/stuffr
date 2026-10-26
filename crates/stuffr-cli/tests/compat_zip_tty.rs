//! The zip family at a terminal (0.19.0 Task 9), on every unix, against
//! this platform's reference (Apple's `/usr/bin/{zip,zipcloak}` on macOS,
//! Ubuntu's under `make compat-ubuntu`) with stuffr in that flavour: the
//! password prompts on the controlling terminal (`Case::tty_ctl`: the
//! answers typed there, the prompts on standard error) for `zip -e` and
//! `zipcloak` (encrypt, `-d`, `-O`, a wrong password, entries already
//! encrypted), their refusals (two answers that differ, an empty one, a
//! line too long), and SIGINT at a prompt (exit 9, `Interrupted
//! (aborting)`, the terminal's echo back, the temporary removed).
//!
//! Every stream, exit code and file is compared; an encrypted archive is
//! compared outside its 12-byte headers and decrypted
//! (`assert_same_zip_decrypted`): zip's header bytes are random.

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod unix {
    use super::compat_harness::*;

    /// A case typed at the controlling terminal: `keys`, a line at a time,
    /// each once the program waits for it.
    fn typed(
        name: &'static str,
        args: &[&'static str],
        tree: ZipTree,
        keys: &[u8],
    ) -> Case<'static> {
        let mut c = zip_case(name, args, tree);
        c.tty_ctl = true;
        c.stdin = Some(keys.to_vec());
        c
    }

    const PLAIN: &[u8] = b"hello\n";

    /// A password whose check byte fails [`with_encrypted`]'s header
    /// (zipcloak's one-byte check lets one in 256 through).
    fn wrong_password() -> String {
        let body = zipcrypto(ZIP_PASSWORD.as_bytes(), (crc32(PLAIN) >> 24) as u8, PLAIN);
        let want = (crc32(PLAIN) >> 24) as u8;
        (0..)
            .map(|i| format!("w{i}"))
            .find(|pw| {
                let mut k = ZipKeys::new(pw.as_bytes());
                body[..12].iter().fold(0, |_, &c| k.decrypt(c)) != want
            })
            .unwrap()
    }

    /// The standard tree plus `t.zip`, `zip t.zip a.txt b.txt` (a stored
    /// and a deflated entry), made once by stuffr in `flavour` (byte-
    /// identical to the reference's).
    fn with_plain(flavour: &str) -> ZipTree {
        let std = ZipTree::standard();
        let t = zip_made(flavour, &std, &["t.zip", "a.txt", "b.txt"], "t.zip");
        std.file("t.zip", t)
    }

    fn compare(group: &str, cases: &[Case]) {
        run_group(group, cases, Skipped::none(), &|c: &Case| {
            assert_same_zip_decrypted(c, ZIP_PASSWORD)
        });
    }

    /// `zip -e`: `Enter password: ` and `Verify password: ` on standard
    /// error (each line read with echo off, a newline after it), stored
    /// and deflated entries with their data descriptors, an archive on a
    /// pipe (the prompts and the messages on standard error), forced
    /// descriptors, an update, and a first answer too long for the buffer
    /// (`(line too long--try again)`, asked again).
    #[test]
    fn zip_e_prompts_and_encrypts_as_zip_does() {
        let f = platform_zip_flavour();
        let long = [vec![b'p'; 81], b"\npw\npw\n".to_vec()].concat();
        let cases = vec![
            typed(
                "zip",
                &["-e", "t.zip", "a.txt", "b.txt"],
                ZipTree::standard(),
                b"pw\npw\n",
            ),
            typed(
                "zip",
                &["-e", "-", "a.txt", "b.txt"],
                ZipTree::standard(),
                b"pw\npw\n",
            ),
            typed(
                "zip",
                &["-e", "-fd", "t.zip", "a.txt", "b.txt"],
                ZipTree::standard(),
                b"pw\npw\n",
            ),
            typed(
                "zip",
                &["-e", "-0", "t.zip", "a.txt", "b.txt"],
                ZipTree::standard(),
                b"pw\npw\n",
            ),
            typed(
                "zip",
                &["-e", "-r", "t.zip", "d"],
                ZipTree::standard(),
                b"pw\npw\n",
            ),
            typed(
                "zip",
                &["-e", "t.zip", "d/c.txt"],
                with_plain(f),
                b"pw\npw\n",
            ),
            typed("zip", &["-e", "t.zip", "a.txt"], ZipTree::standard(), &long),
        ];
        compare("zip -e", &cases);
    }

    /// zip's refusals at the prompt: two answers that differ (`password
    /// verification failed`), an empty first answer (`zero length password
    /// not allowed`, the second prompt never shown); exit 16, nothing
    /// written.
    #[test]
    fn zip_e_refuses_as_zip_does() {
        let cases = vec![
            typed(
                "zip",
                &["-e", "t.zip", "a.txt"],
                ZipTree::standard(),
                b"pw\npx\n",
            ),
            typed("zip", &["-e", "t.zip", "a.txt"], ZipTree::standard(), b"\n"),
            typed(
                "zip",
                &["-e", "-", "a.txt"],
                ZipTree::standard(),
                b"pw\npx\n",
            ),
        ];
        compare("zip -e refusals", &cases);
    }

    /// zipcloak at a terminal: encrypt (twice asked), `-O` (the archive
    /// left, another written), `-d` (once asked; the right password
    /// decrypts, a wrong one copies each entry, `wrong password--just
    /// copying`, exit 0), entries already encrypted copied, and the
    /// refusals: two answers that differ, an empty password (after both
    /// prompts), every entry encrypted (before any prompt).
    #[test]
    fn zipcloak_matches_the_reference() {
        let f = platform_zip_flavour();
        let wrong = format!("{}\n", wrong_password());
        let enc = || with_encrypted(&[(b"a.txt", true), (b"b.txt", true)]);
        let mixed = || with_encrypted(&[(b"a.txt", true), (b"b.txt", false)]);
        let cases = vec![
            typed("zipcloak", &["t.zip"], with_plain(f), b"pw\npw\n"),
            typed(
                "zipcloak",
                &["-O", "o.zip", "t.zip"],
                with_plain(f),
                b"pw\npw\n",
            ),
            typed(
                "zipcloak",
                &["-b", "d", "t.zip"],
                with_plain(f),
                b"pw\npw\n",
            ),
            typed("zipcloak", &["-d", "t.zip"], enc(), b"pw\n"),
            typed(
                "zipcloak",
                &["-d", "-O", "o.zip", "t.zip"],
                mixed(),
                b"pw\n",
            ),
            typed("zipcloak", &["-d", "t.zip"], enc(), wrong.as_bytes()),
            typed("zipcloak", &["t.zip"], mixed(), b"pw\npw\n"),
            typed("zipcloak", &["t.zip"], with_plain(f), b"pw\npx\n"),
            typed("zipcloak", &["t.zip"], with_plain(f), b"\n\n"),
            typed("zipcloak", &["t.zip"], enc(), b""),
        ];
        compare("zipcloak", &cases);
    }

    /// `zipcloak -d` of what `zipcloak` encrypted gives the original
    /// archive back byte for byte, on stuffr's side and the reference's.
    #[test]
    fn zipcloak_d_gives_the_archive_back() {
        let f = platform_zip_flavour();
        let plain = with_plain(f);
        let original = zip_made(
            f,
            &ZipTree::standard(),
            &["t.zip", "a.txt", "b.txt"],
            "t.zip",
        );
        let enc_case = typed("zipcloak", &["t.zip"], plain, b"pw\npw\n");
        let s = stuffr_zip(&enc_case);
        assert_eq!(s.code, 0, "{:?}", String::from_utf8_lossy(&s.stdout));
        let Some(UnzipNode::File { bytes, .. }) = s.tree.get(&b"t.zip"[..]) else {
            panic!("no t.zip");
        };
        let back = typed(
            "zipcloak",
            &["-d", "t.zip"],
            ZipTree::standard().file("t.zip", bytes.clone()),
            b"pw\n",
        );
        let d = stuffr_zip(&back);
        assert_eq!(d.code, 0);
        let Some(UnzipNode::File { bytes, .. }) = d.tree.get(&b"t.zip"[..]) else {
            panic!("no t.zip");
        };
        assert!(*bytes == original, "stuffr: not the original archive");
        if let Some(r) = zip_reference(&back) {
            let Some(UnzipNode::File { bytes, .. }) = r.tree.get(&b"t.zip"[..]) else {
                panic!("reference: no t.zip");
            };
            assert!(*bytes == original, "reference: not the original archive");
        }
    }

    /// Hostile encrypted entries decrypted with the right password: the
    /// first entry's central compressed size below, at and just past the
    /// 12-byte header (zipbare's size goes negative: the data is read to
    /// the end of the archive, `Unexpected end of zip file`; at 12 the entry
    /// is decrypted empty), against the reference. Every read ends at the
    /// archive's end, and the harness caps files and streams.
    #[test]
    fn hostile_encrypted_entries_answer_as_the_reference() {
        let base = encrypted_zip(&[(b"a.txt", true), (b"b.txt", true)]);
        let le32 =
            |b: &[u8], at: usize| u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
        let cd = le32(&base, base.len() - 22 + 16) as usize;
        let mut cases = Vec::new();
        for siz in [0u32, 5, 11, 12, 13] {
            let mut b = base.clone();
            b[cd + 20..cd + 24].copy_from_slice(&siz.to_le_bytes());
            let tree = ZipTree::standard().file("t.zip", b);
            cases.push(typed("zipcloak", &["-d", "t.zip"], tree.clone(), b"pw\n"));
            cases.push(typed(
                "zipcloak",
                &["-d", "-O", "o.zip", "t.zip"],
                tree,
                b"pw\n",
            ));
        }
        run_group(
            "hostile encrypted entries",
            &cases,
            Skipped::none(),
            &assert_same_zip,
        );
    }

    /// Deviation 24 on a split archive under `-O`, recorded: zipcloak's
    /// `readlocal()` does not find the first entry in the last part, and
    /// the reference goes on with an uninitialised local header (Ubuntu's
    /// dies of SIGSEGV in Docker, its warning lost in its stdio buffer when
    /// standard output is a pipe). Only the line before the undefined
    /// behaviour is compared; stuffr's end is pinned in
    /// `zipcloak::tests::a_split_archive_under_o_ends_at_its_first_entry`.
    #[test]
    fn a_split_archive_under_o_is_not_found_as_the_reference_says() {
        let tree = with_parts(ZipTree::standard(), &zip_split_set("apple"), &[]);
        let c = typed("zipcloak", &["-O", "o.zip", "s.zip"], tree, b"pw\npw\n");
        let want = "encrypting: big\nzipcloak warning: Did not find entry for big\n";
        let s = stuffr_zip(&c);
        assert_eq!(s.code, 3);
        assert!(String::from_utf8_lossy(&s.stdout).starts_with(want));
        if let Some(r) = zip_reference(&c) {
            // the reference's warning is still in its stdio buffer when it
            // dies (standard output is a pipe here): only the first line,
            // flushed by zipcloak's own fflush, reaches it
            let out = String::from_utf8_lossy(&r.stdout);
            assert!(out.starts_with("encrypting: big\n"), "reference: {out:?}");
            assert_ne!(r.code, 0, "reference: {out:?}");
            assert!(!r.tree.contains_key(&b"o.zip"[..]), "reference wrote o.zip");
        }
    }

    /// SIGINT while a prompt waits (echo off): zip's handler puts the
    /// terminal back and ends the run, `Interrupted (aborting)`, exit 9;
    /// zipcloak's removes its temporary too.
    #[test]
    fn an_interrupt_at_a_prompt_restores_echo_and_exits_9() {
        let f = platform_zip_flavour();
        let mut cases = vec![
            typed("zip", &["-e", "t.zip", "a.txt"], ZipTree::standard(), b""),
            typed(
                "zip",
                &["-e", "t.zip", "a.txt"],
                ZipTree::standard(),
                b"pw\n",
            ),
            typed("zipcloak", &["t.zip"], with_plain(f), b""),
            typed(
                "zipcloak",
                &["-d", "t.zip"],
                with_encrypted(&[(b"a.txt", true)]),
                b"",
            ),
        ];
        for c in &mut cases {
            c.tty_signal = Some(libc::SIGINT);
        }
        run_group(
            "interrupt at a prompt",
            &cases,
            Skipped::none(),
            &|c: &Case| {
                let ran = assert_same_zip(c);
                let s = stuffr_zip(c);
                assert_eq!((s.code, s.tty_mode), (9, Some((true, true))));
                ran
            },
        );
    }
}
