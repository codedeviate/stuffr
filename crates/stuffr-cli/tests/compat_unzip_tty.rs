//! The unzip family at a terminal (0.16.0 Task 11), on every unix, against
//! this platform's reference (Apple's `/usr/bin/unzip` on macOS, Ubuntu's
//! on Linux: `make compat-ubuntu`) with stuffr in that flavour: the
//! password prompt on the controlling terminal (R12, `Case::tty_ctl`) and
//! its retries, Review Focus 4's password mixes, the overwrite question
//! and `[r]ename` at a terminal, `-M`'s pager, the `^S` pause in a comment,
//! and interrupts (exit 80, the partial file kept, the terminal's echo put
//! back; funzip, which has no handler, dies of the signal). The rulings only stuffr can show are pinned at the end.
//!
//! Each case's archive is built here, so both sides read the same bytes;
//! the terminal's mode after each run is compared too.

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod unix {
    use super::compat_harness::interrupt::{self, Inherit};
    use super::compat_harness::*;
    use std::path::Path;

    /// One entry: its name, its password (`None`: not encrypted) and its
    /// plain bytes (stored).
    type Entry<'a> = (&'a [u8], Option<&'a [u8]>, &'a [u8]);

    /// An archive of stored entries, the encrypted ones with traditional
    /// PKWARE encryption whose check byte is the CRC's high byte.
    fn archive(entries: &[Entry]) -> Vec<u8> {
        let bodies: Vec<Option<Vec<u8>>> = entries
            .iter()
            .map(|(_, pw, plain)| pw.map(|pw| zipcrypto(pw, (crc32(plain) >> 24) as u8, plain)))
            .collect();
        let specs: Vec<ZipEntrySpec> = entries
            .iter()
            .zip(&bodies)
            .map(|((name, _, plain), body)| match body {
                Some(b) => ZipEntrySpec {
                    flags: 1,
                    stored_data: Some(b),
                    ..ZipEntrySpec::new(name, plain)
                },
                None => ZipEntrySpec::new(name, plain),
            })
            .collect();
        zip_with(&specs, b"", b"")
    }

    fn enc() -> Vec<u8> {
        archive(&[(b"s.txt", Some(b"secret"), b"secret text\n")])
    }

    /// Plain, encrypted, plain.
    fn mix() -> Vec<u8> {
        archive(&[
            (b"p.txt", None, b"plain text\n"),
            (b"s.txt", Some(b"secret"), b"secret text\n"),
            (b"t.txt", None, b"other text\n"),
        ])
    }

    /// Two entries with different passwords.
    fn two() -> Vec<u8> {
        archive(&[
            (b"s.txt", Some(b"secret"), b"secret text\n"),
            (b"t.txt", Some(b"other"), b"other text\n"),
        ])
    }

    /// One step of the keys `zipcrypto` encrypts with.
    fn update(k: &mut [u32; 3], p: u8) {
        k[0] = crc32_byte(k[0], p);
        k[1] = k[1]
            .wrapping_add(k[0] & 0xff)
            .wrapping_mul(134_775_813)
            .wrapping_add(1);
        k[2] = crc32_byte(k[2], (k[1] >> 24) as u8);
    }

    /// The header's last byte decrypted with `password` (testkey's check).
    fn check_under(password: &[u8], header: &[u8]) -> u8 {
        let mut k = [0x1234_5678u32, 0x2345_6789, 0x3456_7890];
        for &p in password {
            update(&mut k, p);
        }
        let mut last = 0;
        for &c in &header[..12] {
            let t = (k[2] | 2) & 0xffff;
            let p = c ^ ((t.wrapping_mul(t ^ 1) >> 8) & 0xff) as u8;
            update(&mut k, p);
            last = p;
        }
        last
    }

    /// Review Focus 4's last shape: a wrong password whose header check
    /// passes (one in 256 does), so the CRC fails instead. Returns the
    /// archive and that password.
    fn fooled() -> (Vec<u8>, String) {
        let plain: &[u8] = b"secret text\n";
        let body = zipcrypto(b"secret", (crc32(plain) >> 24) as u8, plain);
        let check = (crc32(plain) >> 24) as u8;
        let wrong = (0..10_000)
            .map(|i| format!("pw{i}"))
            .find(|pw| check_under(pw.as_bytes(), &body) == check)
            .expect("a wrong password passing the check");
        (archive(&[(b"s.txt", Some(b"secret"), plain)]), wrong)
    }

    /// Sixty small entries: a listing longer than a 24-line screen.
    fn many() -> Vec<u8> {
        let names: Vec<String> = (0..60).map(|i| format!("f{i:02}.txt")).collect();
        let data: Vec<Vec<u8>> = (0..60).map(|i| vec![b'x'; i]).collect();
        let specs: Vec<ZipEntrySpec> = names
            .iter()
            .zip(&data)
            .map(|(n, d)| ZipEntrySpec::new(n.as_bytes(), d))
            .collect();
        zip_with(&specs, b"", b"")
    }

    /// An archive comment with two `^S` pauses (one before a line end).
    fn comment_pauses() -> Vec<u8> {
        zip_with(
            &[ZipEntrySpec::new(b"c.txt", b"hi")],
            b"line one\x13\nline two\x13more\nend",
            b"",
        )
    }

    /// A case typed at the controlling terminal.
    fn typed<'a>(args: Vec<&'a str>, files: Vec<(&'a str, Vec<u8>)>, keys: &[u8]) -> Case<'a> {
        let mut c = unzip_case("unzip", args, files);
        c.tty_ctl = true;
        c.stdin = Some(keys.to_vec());
        c
    }

    fn piped<'a>(args: Vec<&'a str>, files: Vec<(&'a str, Vec<u8>)>, stdin: &[u8]) -> Case<'a> {
        let mut c = unzip_case("unzip", args, files);
        c.stdin = Some(stdin.to_vec());
        c
    }

    /// Two existing files the archive `ow.zip` holds newer copies of.
    fn existing(w: &Path) {
        std::fs::write(w.join("a.txt"), b"old\n").unwrap();
        std::fs::write(w.join("b.txt"), b"old\n").unwrap();
    }

    fn ow() -> Vec<(&'static str, Vec<u8>)> {
        vec![(
            "ow.zip",
            zip_with(
                &[
                    ZipEntrySpec::new(b"a.txt", b"new a\n"),
                    ZipEntrySpec::new(b"b.txt", b"new b\n"),
                ],
                b"",
                b"",
            ),
        )]
    }

    /// Review Focus 4: passwords in practice. Wrong then right at the
    /// re-prompt, three wrong, an empty answer, `-P ''`, mixed encrypted
    /// and plain entries, two passwords in one archive (prompted and under
    /// one `-P`), a wrong password whose header check passes (the CRC
    /// fails), and a line too long for the buffer.
    #[test]
    fn password_mixes() {
        let (fool, wrong) = fooled();
        let wrong_line = format!("{wrong}\n");
        let long_then_right = [vec![b'p'; 81], b"\nsecret\n".to_vec()].concat();
        let e = || vec![("enc.zip", enc())];
        let m = || vec![("mix.zip", mix())];
        let t = || vec![("two.zip", two())];
        let f = || vec![("fool.zip", fool.clone())];
        let cases = vec![
            typed(vec!["-t", "enc.zip"], e(), b"secret\n"),
            typed(vec!["-t", "enc.zip"], e(), b"wrong\nsecret\n"),
            typed(vec!["-t", "enc.zip"], e(), b"wrong\nbad\nworse\n"),
            typed(vec!["-t", "enc.zip"], e(), b"\n"),
            typed(vec!["-t", "enc.zip"], e(), &long_then_right),
            typed(vec!["enc.zip"], e(), b"secret\n"),
            typed(vec!["-t", "mix.zip"], m(), b"secret\n"),
            typed(vec!["-d", "out", "mix.zip"], m(), b"wrong\nsecret\n"),
            typed(vec!["-t", "mix.zip"], m(), b"\n"),
            typed(vec!["-t", "two.zip"], t(), b"secret\nother\n"),
            typed(vec!["-t", "two.zip"], t(), b"other\nsecret\nother\n"),
            typed(vec!["-t", "two.zip"], t(), b"secret\n\n"),
            typed(vec!["-t", "two.zip"], t(), b"\n"),
            typed(vec!["-t", "fool.zip"], f(), wrong_line.as_bytes()),
            unzip_case("unzip", vec!["-P", "", "-t", "mix.zip"], m()),
            unzip_case("unzip", vec!["-P", "", "mix.zip"], m()),
            unzip_case("unzip", vec!["-P", "secret", "-t", "two.zip"], t()),
            unzip_case("unzip", vec!["-P", "secret", "-d", "o", "two.zip"], t()),
            unzip_case("unzip", vec!["-P", &wrong, "-t", "fool.zip"], f()),
            unzip_case("unzip", vec!["-P", &wrong, "fool.zip"], f()),
            // no terminal to ask on (R7's answer on a real host)
            unzip_case("unzip", vec!["-t", "mix.zip"], m()),
        ];
        run_group(
            "password_mixes",
            &cases,
            Skipped::none(),
            &assert_same_unzip,
        );
    }

    /// The overwrite question answered at the terminal (it reads standard
    /// input, the terminal here), `[r]ename` with a new name included, and
    /// the `^S` pause in an archive comment while extracting (any key goes
    /// on, `q` ends the run with exit 0), at the terminal and piped.
    #[test]
    fn questions_at_the_terminal() {
        let cs = || vec![("cs.zip", comment_pauses())];
        let mut cases = vec![
            typed(vec!["ow.zip"], ow(), b"r\nc.txt\nn\n"),
            typed(vec!["ow.zip"], ow(), b"y\nN\n"),
            typed(vec!["ow.zip"], ow(), b"A\n"),
            typed(vec!["ow.zip"], ow(), b"x\nr\n\nn\nn\n"),
            typed(vec!["-o", "cs.zip"], cs(), &[b'x', TTY_BREAK, b' ']),
            typed(vec!["-o", "cs.zip"], cs(), b"q"),
            piped(vec!["-o", "cs.zip"], cs(), b"xy"),
            piped(vec!["-o", "cs.zip"], cs(), b"xq"),
            piped(vec!["-o", "cs.zip"], cs(), b""),
            // listing and testing never pause
            // (`-z`: `-l` lists dates, which Ubuntu writes year first: Task 13)
            unzip_case("unzip", vec!["-z", "cs.zip"], cs()),
            unzip_case("unzip", vec!["-t", "cs.zip"], cs()),
        ];
        for c in &mut cases[..4] {
            c.setup = Some(existing);
        }
        run_group(
            "questions_at_the_terminal",
            &cases,
            Skipped::none(),
            &assert_same_unzip,
        );
    }

    /// `-M` with standard output a terminal: a screen is its 24 rows less
    /// two (`TIOCGWINSZ` of a fresh pty gives 0, read as 24); space shows
    /// the next screen, Enter (or `\r`) one more line, `q` ends the run
    /// (exit 0). (Other keys are ignored: the typist cannot type past one,
    /// as nothing is printed.) `-t` lists no dates, so both flavours print
    /// the same lines.
    #[test]
    fn the_pager() {
        let mz = || vec![("many.zip", many())];
        let keys = |k: &[u8]| -> Vec<u8> { k.iter().flat_map(|&b| [b, TTY_BREAK]).collect() };
        let mut cases = vec![
            typed(vec!["-M", "-t", "many.zip"], mz(), &keys(b" \nq")),
            typed(vec!["-M", "-t", "many.zip"], mz(), &keys(b"  ")),
            typed(vec!["-M", "-t", "many.zip"], mz(), &keys(b"\n\r q")),
            // standard output not a terminal: no pager
            typed(vec!["-M", "-t", "many.zip"], mz(), b""),
        ];
        for c in &mut cases[..3] {
            c.tty_stdout = true;
        }
        // the pager reading a pipe (no terminal mode to change)
        let mut c = piped(vec!["-M", "-t", "many.zip"], mz(), b" q");
        c.tty_stdout = true;
        cases.push(c);
        run_group("the_pager", &cases, Skipped::none(), &assert_same_unzip);
    }

    /// SIGINT while the password prompt waits (echo off): exit 80, nothing
    /// more printed, and the terminal's echo is back on.
    #[test]
    fn an_interrupt_at_the_prompt_restores_echo_and_exits_80() {
        let mut c = typed(vec!["-t", "enc.zip"], vec![("enc.zip", enc())], b"");
        c.tty_signal = Some(libc::SIGINT);
        let mut t = typed(vec!["-t", "enc.zip"], vec![("enc.zip", enc())], b"wrong\n");
        t.tty_signal = Some(libc::SIGTERM);
        run_group("interrupt_at_prompt", &[c, t], Skipped::none(), &|c| {
            let ran = assert_same_unzip(c);
            if ran {
                let s = stuffr_unzip(c);
                assert_eq!((s.code, s.tty_mode), (80, Some((true, true))));
            }
            ran
        });
    }

    /// funzip installs no signal handler: SIGINT at its password prompt
    /// kills it, and the reference leaves the terminal's echo off. stuffr
    /// dies of the same signal with the terminal put back (deviation 8).
    #[test]
    fn an_interrupt_at_funzips_prompt_kills_it_with_echo_back() {
        let mut c = unzip_case("funzip", vec!["enc.zip"], vec![("enc.zip", enc())]);
        c.tty_ctl = true;
        c.stdin = Some(Vec::new());
        c.tty_signal = Some(libc::SIGINT);
        let s = stuffr_unzip(&c);
        assert_eq!(
            (s.code, s.tty_mode),
            (-libc::SIGINT, Some((true, true))),
            "{}",
            s.stderr
        );
        assert_eq!(s.stderr, "Enter password: ");
        if let Some(r) = unzip_reference(&c) {
            assert_eq!((r.code, r.tty_mode), (-libc::SIGINT, Some((false, true))));
            assert_eq!(r.stderr, s.stderr);
        }
    }

    /// ruling: T11-1. A signal while the pager reads a key: both end with
    /// exit 80; the reference's `echon()` turns echo back on but leaves
    /// canonical mode off ("not perfect: still CBREAK", ttyio.c), stuffr
    /// puts the terminal back as it was.
    #[test]
    fn an_interrupt_in_the_pager_restores_the_whole_mode() {
        let mut c = typed(
            vec!["-M", "-t", "many.zip"],
            vec![("many.zip", many())],
            b"",
        );
        c.tty_stdout = true;
        c.tty_signal = Some(libc::SIGINT);
        let s = stuffr_unzip(&c);
        assert_eq!(
            (s.code, s.tty_mode),
            (80, Some((true, true))),
            "{}",
            s.stderr
        );
        assert!(s.stderr.ends_with("--More--(22)"), "{:?}", s.stderr);
        if let Some(r) = unzip_reference(&c) {
            assert_eq!((r.code, r.tty_mode), (80, Some((true, false))));
            assert_eq!(r.stderr, s.stderr);
        }
    }

    /// The brief's interrupt pin: SIGINT, SIGTERM (and a sent SIGABRT)
    /// during an extraction
    /// end the run with exit 80 and print nothing; the partial file stays
    /// (unzip writes it in place, with no temporary to remove). As
    /// `signal()` does, an inherited ignore of SIGINT is overridden.
    #[test]
    fn an_interrupt_leaves_the_partial_file_and_exits_80() {
        let _lock = interrupt::interrupt_lock();
        let Some(dir) = unzip_dir() else { return };
        let reference = Path::new(dir).join("unzip");
        let stuffr = Path::new(env!("CARGO_BIN_EXE_stuffr"));
        let flavour = platform_unzip_flavour();
        let input = |mib: usize| interrupt::stored_zip(b"big.bin", interrupt::big_input(mib));
        let scratch =
            std::env::temp_dir().join(format!("stuffr-unzip-intr-{}", std::process::id()));
        let (mut ran, mut hung) = (0, 0);
        for (sig, inherit) in [
            (libc::SIGINT, Inherit::Default),
            (libc::SIGTERM, Inherit::Default),
            // another process's SIGABRT (P28: our own still crashes)
            (libc::SIGABRT, Inherit::Default),
            (libc::SIGINT, Inherit::IgnoreInt),
        ] {
            for (exe, env) in [
                (reference.as_path(), vec![]),
                (stuffr, vec![("STUFFR_UNZIP_FLAVOR", flavour)]),
            ] {
                let d = ScratchDir::at(scratch.join("run"));
                let big = |n: &str| n == "big.bin";
                let ready = interrupt::has_data(&d, &big);
                let Some(r) = interrupt::interrupt_with_input_env(
                    exe,
                    "unzip",
                    &["big.zip"],
                    &d,
                    &env,
                    "big.zip",
                    &input,
                    inherit,
                    sig,
                    &ready,
                ) else {
                    hung += 1; // a reference that hung after the signal
                    continue;
                };
                ran += 1;
                let what = format!("{exe:?} signal {sig}");
                assert_eq!(r.status.code(), Some(80), "{what}: {:?}", r.status);
                assert_eq!(String::from_utf8_lossy(&r.stderr), "", "{what}");
                assert_eq!(r.left, ["big.bin", "big.zip"], "{what}");
                let got = std::fs::metadata(d.join("big.bin")).unwrap().len();
                let zip = std::fs::metadata(d.join("big.zip")).unwrap().len();
                assert!(got > 0 && got < zip, "{what}: partial file of {got} bytes");
            }
        }
        let _ = std::fs::remove_dir_all(&scratch);
        assert_eq!(ran + hung, 8);
        assert!(ran >= 4, "only {ran} runs compared");
    }

    // ---- rulings only stuffr can show ----

    /// ruling: T11-4. `-M` whose keyboard is at its end: the reference
    /// spins for ever waiting for an accepted key; stuffr stops pausing for
    /// the rest of the run.
    #[test]
    fn a_pager_at_the_end_of_its_input_stops_pausing() {
        let mut c = piped(
            vec!["-M", "-t", "many.zip"],
            vec![("many.zip", many())],
            b"",
        );
        c.tty_stdout = true;
        let s = stuffr_unzip(&c);
        assert_eq!(s.code, 0, "{}", s.stderr);
        let hide = "\r                                                         \r";
        assert_eq!(s.stderr, format!("--More--(22){hide}"));
        let out = String::from_utf8_lossy(&s.stdout);
        assert!(out.contains("testing: f59.txt"), "{out}");
    }

    /// ruling: T11-5. An entry whose filtered name with the archive's
    /// exceeds `2*FILNAMSIZ` bytes: Apple's build dies in `__sprintf_chk`;
    /// both flavours ask "Enter password: " as Ubuntu's patch does. 1020
    /// `^A` bytes (2040 shown) and `lon3.zip` fit Apple's 2048 exactly; one
    /// more byte does not.
    #[test]
    fn a_prompt_too_long_for_its_buffer_asks_plainly() {
        let fits = vec![1u8; 1020];
        let over = [vec![1u8; 1020], b"A".to_vec()].concat();
        for (name, zip, wants_names) in [(&fits, "lon3.zip", true), (&over, "lon4.zip", false)] {
            let a = archive(&[(name, Some(b"pw"), b"hello")]);
            let mut c = typed(vec!["-t", zip], vec![(zip, a)], b"pw\n");
            c.unzip_flavour = Some("apple");
            let s = stuffr_unzip(&c);
            assert_eq!(s.code, 0, "{}", s.stderr);
            let asked = s.stderr.lines().next().unwrap_or("").to_owned();
            if wants_names {
                assert!(asked.starts_with(&format!("[{zip}] ^A^A")), "{asked:.60}");
            } else {
                assert_eq!(asked, "Enter password: ");
            }
        }
    }

    /// ruling: T11-3, end to end. The controlling terminal hangs up (its
    /// master closes) while the password prompt waits, with SIGHUP ignored
    /// so the read sees it: the reference stores its stale byte for ever,
    /// stuffr answers as with no terminal, "unable to get password", exit 5.
    #[test]
    fn a_terminal_that_hangs_up_at_the_prompt_is_no_terminal() {
        use std::io::Read;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};
        let dir = std::env::temp_dir().join(format!("stuffr-unzip-hup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("enc.zip"), enc()).unwrap();
        let guard = spawn_lock();
        let (mut m, mut s) = (-1, -1);
        // SAFETY: openpty fills two descriptors we then own; the name, mode
        // and size may be null.
        let rc = unsafe {
            libc::openpty(
                &mut m,
                &mut s,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, 0);
        // SAFETY: both were just returned by openpty.
        let (master, slave) = unsafe { (OwnedFd::from_raw_fd(m), OwnedFd::from_raw_fd(s)) };
        // SAFETY: fcntl on a descriptor we own; the child must not keep the
        // master open.
        unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_stuffr"));
        cmd.arg0("unzip")
            .args(["-t", "enc.zip"])
            .current_dir(&dir)
            .env_clear()
            .env("LANG", "C")
            .env("STUFFR_UNZIP_FLAVOR", platform_unzip_flavour())
            .stdin(Stdio::from(slave))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: only async-signal-safe calls between fork and exec.
        unsafe {
            cmd.pre_exec(|| {
                libc::signal(libc::SIGHUP, libc::SIG_IGN);
                if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().unwrap();
        drop(cmd); // our copy of the slave
        drop(guard);
        let mut err = child.stderr.take().unwrap();
        let mut seen = Vec::new();
        let mut buf = [0u8; 256];
        while !seen.ends_with(b"password: ") {
            let n = err.read(&mut buf).unwrap();
            assert!(n > 0, "no prompt: {:?}", String::from_utf8_lossy(&seen));
            seen.extend_from_slice(&buf[..n]);
        }
        drop(master); // the terminal hangs up
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let status = loop {
            if let Some(st) = child.try_wait().unwrap() {
                break st;
            }
            if std::time::Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("stuffr kept waiting on a hung-up terminal");
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        };
        let mut out = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut out)
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(status.code(), Some(5), "{status:?}");
        assert!(
            out.contains("   skipping: s.txt                   unable to get password\n"),
            "{out}"
        );
        assert_eq!(String::from_utf8_lossy(&seen), "[enc.zip] s.txt password: ");
    }
}
