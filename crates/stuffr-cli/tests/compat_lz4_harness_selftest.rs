//! The lz4 side of the differential harness against itself: `assert_same`
//! must notice each single kind of difference and name it, the progress
//! normaliser must hide deviation 2's fields (timing, refreshes, thread
//! count) and nothing else, and the reference lookup must accept only
//! lz4 1.10.0.
//!
//! Every run here is REFERENCE-shaped: stuffr is not run as `lz4` (the
//! binary answers to that name from Task 3 on), so the sensitivity tests
//! build two `Run`s by hand, or run the real `lz4` twice.

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod unix {
    use super::compat_harness::*;
    use std::path::Path;

    /// The stderr of `lz4 -v -T3 -f a x.lz4` over 8800 bytes of one repeated
    /// line, recorded from the 1.10.0 reference with stderr a file (probe,
    /// 2026-10-16): the banner, the thread line, one `\r`-refreshed `Read :`
    /// line, the 79-blank clearing line, the summary and `Done in`.
    const V_COMPRESS: &str = "*** lz4 v1.10.0 64-bit multithread, by Yann Collet ***\n\
Using 3 threads for compression \n\
\rRead : 0 MiB   ==> 1.25%   \r                                                                               \rCompressed 8800 bytes into 110 bytes ==> 1.25%\n\
Done in 0.00 s ==> 20.94 MiB/s  (cpu load : 67%)\n";

    /// `lz4 -v -d b.lz4 bo`, same recording: one `Decompressed :` refresh.
    const V_DECOMPRESS: &str = "*** lz4 v1.10.0 64-bit multithread, by Yann Collet ***\n\
\rDecompressed : 0 MiB  \r                                                                               \rb.lz4                          : decoded 8800 bytes \n";

    fn lz4() -> Option<&'static str> {
        lz4_dir()
    }

    fn case<'a>(dir: &str, args: Vec<&'a str>) -> Case<'a> {
        Case {
            name: "lz4",
            args,
            files: vec![(
                "a",
                b"the quick brown fox jumps over the lazy dog\n".repeat(40),
            )],
            stdin: None,
            tty_stdin: false,
            tty_stdout: false,
            env: vec![],
            compare_output_bytes: true,
            expect_stdout_plain: None,
            setup: None,
            roundtrip: Roundtrip::Lz4 {
                ref_lz4: Box::leak(format!("{dir}/lz4").into_boxed_str()),
            },
        }
    }

    fn run(code: i32, stderr: &str) -> Run {
        Run {
            code,
            stdout: Vec::new(),
            stderr: stderr.to_owned(),
            tree: Tree::new(),
            start: now_secs(),
        }
    }

    fn verdict(c: &Case, r: &Run, s: &Run) -> Option<String> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| assert_same(c, r, s)))
            .err()
            .map(panic_text)
    }

    #[test]
    fn reference_is_1_10_0() {
        let Some(dir) = lz4() else {
            assert!(
                std::env::var_os("CI").is_none(),
                "lz4_dir returned None under CI instead of panicking"
            );
            return;
        };
        let o = std::process::Command::new(format!("{dir}/lz4"))
            .arg("-V")
            .env_clear()
            .output()
            .unwrap();
        let v = String::from_utf8_lossy(&o.stdout).into_owned();
        assert!(v.contains("v1.10.0"), "{v:?}");
        for link in ["unlz4", "lz4cat", "lz4c"] {
            assert!(Path::new(dir).join(link).exists(), "{dir}/{link}");
        }
    }

    #[test]
    fn normalise_hides_only_timing_and_threads() {
        let a = normalise_lz4_progress(V_COMPRESS);
        assert_eq!(
            a,
            "*** lz4 v1.10.0 64-bit multithread, by Yann Collet ***\n\
Using <n> threads for compression \n\
\r<progress>\r                                                                               \rCompressed 8800 bytes into 110 bytes ==> 1.25%\n\
Done in <s> s ==> <speed> MiB/s  (cpu load : <cpu>%)\n"
        );
        // Another speed, duration, load, thread count and a longer run of
        // refreshes normalise equal...
        let other = "*** lz4 v1.10.0 64-bit multithread, by Yann Collet ***\n\
Using 12 threads for compression \n\
\rRead : 0 MiB   ==> 0.50%   \rRead : 3 MiB   ==> 41.00%   \rRead : 7 MiB   ==> inf%   \r                                                                               \rCompressed 8800 bytes into 110 bytes ==> 1.25%\n\
Done in 12.34 s ==> 1957.89 MiB/s  (cpu load : 367%)\n";
        assert_eq!(a, normalise_lz4_progress(other));
        // ...including the decompress refresh.
        assert_eq!(
            normalise_lz4_progress(V_DECOMPRESS),
            "*** lz4 v1.10.0 64-bit multithread, by Yann Collet ***\n\
\r<progress>\r                                                                               \rb.lz4                          : decoded 8800 bytes \n"
        );
        // A one-character change anywhere else does not normalise away: the
        // sizes, the ratio, the name, the blank clearing line, the banner.
        for (from, to) in [
            ("110 bytes", "111 bytes"),
            ("==> 1.25%\n", "==> 1.26%\n"),
            ("8800 bytes", "8801 bytes"),
            ("1.10.0", "1.10.1"),
            (
                "\r                                                                               \r",
                "\r                                                                              \r",
            ),
            ("Compressed", "compressed"),
        ] {
            assert_ne!(
                a,
                normalise_lz4_progress(&V_COMPRESS.replace(from, to)),
                "{from:?} -> {to:?} was hidden"
            );
        }
        assert_ne!(
            normalise_lz4_progress(V_DECOMPRESS),
            normalise_lz4_progress(&V_DECOMPRESS.replace("8800", "8801"))
        );
        // The refresh must be there to collapse: dropping it shows.
        assert_ne!(
            a,
            normalise_lz4_progress(&V_COMPRESS.replace("\rRead : 0 MiB   ==> 1.25%   ", ""))
        );
        // Text that only looks like a field is untouched: another shape of
        // `Done in`, a thread line for another purpose, a `Read :` that is
        // not a refresh (not led by `\r`).
        let odd = "Done in soon\nDone in 1.5 s ==> x MiB/s  (cpu load : 4%)\n\
Using N threads for compression \nUsing 3 threads for decompression \n\
lz4: Read : 0 MiB   ==> 1.25%   \n";
        assert_eq!(normalise_lz4_progress(odd), odd);
    }

    /// Probed 2026-10-16: sixty runs of `lz4 -t` over a header cut at five
    /// bytes printed these stderrs (and more), the refresh drawn before the
    /// message, after it, inside it or not at all. All are one failure.
    #[test]
    fn a_failing_decode_hides_where_the_refresh_fell() {
        let message = "Error 26 : LZ4F frame decoding could not complete: invalid frame \n";
        for seen in [
            "\rDecompressed : 0 MiB  Error 26 : LZ4F frame decoding could not complete: invalid frame \n",
            "Error 26 : LZ4F frame decoding could not complete: invalid frame \n\rDecompressed : 0 MiB  ",
            "Error 26 : \rDecompressed : 0 MiB  LZ4F frame decoding could not complete: invalid frame \n",
            "Error 26 : LZ4F frame decoding could not complete: invalid frame\rDecompressed : 0 MiB   \n",
            message,
        ] {
            assert_eq!(normalise_lz4_progress(seen), message, "{seen:?}");
        }
        // The message itself is still compared, and so is the exit path's
        // other text.
        assert_ne!(
            normalise_lz4_progress(&message.replace("26", "27")),
            message
        );
        let with_name = format!("Decoding file t_hdr \n\rDecompressed : 0 MiB  {message}");
        assert_eq!(
            normalise_lz4_progress(&with_name),
            format!("Decoding file t_hdr \n{message}")
        );
        // `Stream followed by undecodable data` is a failure too.
        assert_eq!(
            normalise_lz4_progress(
                "\rDecompressed : 0 MiB  Stream followed by undecodable data at position 103 \n"
            ),
            "Stream followed by undecodable data at position 103 \n"
        );
        // A success keeps its one refresh: dropping it shows.
        assert_ne!(
            normalise_lz4_progress(V_DECOMPRESS),
            normalise_lz4_progress(&V_DECOMPRESS.replace("\rDecompressed : 0 MiB  ", ""))
        );
    }

    /// The reference's partial output after a failed decode is a race
    /// (0 or all of what decoded): only a prefix, only in a run that failed
    /// the same way, is tolerated.
    #[test]
    fn partial_output_is_tolerated_only_as_a_prefix_of_a_same_failure() {
        let mk = |code: i32, out: &[u8], file: &[u8]| {
            let mut r = run(code, "");
            r.stdout = out.to_vec();
            r.tree.insert("o".into(), (file.to_vec(), 0o644, 0));
            r
        };
        let verdict_of = |mut r: Run, mut s: Run| {
            tolerate_lz4_partial_output(&mut r, &mut s);
            let c = case("/nonexistent", vec!["-d", "x.lz4"]);
            verdict(&c, &r, &s)
        };
        // Nothing against everything, in either direction, and a shorter
        // prefix, are the same failure.
        assert_eq!(verdict_of(mk(34, b"", b""), mk(34, b"abc", b"abc")), None);
        assert_eq!(verdict_of(mk(34, b"abc", b"abc"), mk(34, b"", b"")), None);
        assert_eq!(
            verdict_of(mk(34, b"ab", b"a"), mk(34, b"abc", b"abc")),
            None
        );
        // Bytes that are not a prefix differ.
        let m = verdict_of(mk(34, b"abd", b"abc"), mk(34, b"abc", b"abc"))
            .expect("a stdout that is no prefix passed");
        assert!(m.contains("stdout differs"), "{m}");
        let m = verdict_of(mk(34, b"abc", b"abd"), mk(34, b"abc", b"abc"))
            .expect("a file that is no prefix passed");
        assert!(m.contains("bytes differ"), "{m}");
        // A success is compared exactly, and so are two different failures.
        assert!(verdict_of(mk(0, b"", b""), mk(0, b"abc", b"abc")).is_some());
        let m = verdict_of(mk(34, b"", b""), mk(26, b"abc", b"abc")).unwrap();
        assert!(m.contains("exit code: reference 34 vs stuffr 26"), "{m}");
        // A file the other side lacks is still reported.
        let mut s = mk(34, b"", b"");
        s.tree.clear();
        assert!(verdict_of(mk(34, b"", b""), s).is_some());
    }

    #[test]
    fn assert_same_sees_one_byte_of_stderr() {
        let Some(dir) = lz4() else { return };
        let c = case(dir, vec!["no-such-file"]);
        let msg = "Compressed filename will be : no-such-file.lz4 \n\
no-such-file: No such file or directory \n";
        let r = run(1, msg);
        assert_eq!(verdict(&c, &r, &run(1, msg)), None);
        let s = run(1, &msg.replace("directory \n", "directory\n"));
        let m = verdict(&c, &r, &s).expect("assert_same missed a one-byte stderr difference");
        assert!(m.contains("stderr differs"), "{m}");
        assert!(m.contains("in 1 way(s)"), "{m}");
    }

    #[test]
    fn assert_same_sees_the_exit_code() {
        let Some(dir) = lz4() else { return };
        let c = case(dir, vec!["no-such-file"]);
        let r = run(26, "Error 26 : x\n");
        let s = run(34, "Error 26 : x\n");
        let m = verdict(&c, &r, &s).expect("assert_same missed an exit code difference");
        assert!(m.contains("exit code: reference 26 vs stuffr 34"), "{m}");
        assert!(m.contains("in 1 way(s)"), "{m}");
    }

    /// Through the real reference: a clean `-f a x.lz4` run twice is the
    /// same, and with bytes not promised an output of another kind of
    /// stream (a legacy frame where a modern one was promised) or one the
    /// reference cannot decode is caught.
    #[test]
    fn lz4_outputs_are_judged_by_decoding() {
        let Some(dir) = lz4() else { return };
        let mut c = case(dir, vec!["-q", "-f", "a", "x.lz4"]);
        c.compare_output_bytes = false;
        let r = reference(dir, &c).unwrap();
        let s = reference(dir, &c).unwrap();
        assert_eq!(verdict(&c, &r, &s), None);
        // A stuffr output that is not a valid frame.
        let mut bad = reference(dir, &c).unwrap();
        let (bytes, mode, mtime) = bad.tree.get("x.lz4").cloned().unwrap();
        let mut broken = bytes.clone();
        let n = broken.len();
        broken[n - 6] ^= 0xff;
        bad.tree.insert("x.lz4".into(), (broken, mode, mtime));
        let msg = verdict(&c, &r, &bad).expect("a corrupt x.lz4 was accepted");
        assert!(
            msg.contains("reference lz4 rejects stuffr's x.lz4"),
            "{msg}"
        );
        // A legacy frame where a modern one was promised.
        let mut legacy = reference(dir, &c).unwrap();
        let (_, mode, mtime) = legacy.tree.get("x.lz4").cloned().unwrap();
        let lc = case(dir, vec!["-q", "-f", "-l", "a", "x.lz4"]);
        let l = reference(dir, &lc).unwrap();
        let (lbytes, _, _) = l.tree.get("x.lz4").cloned().unwrap();
        legacy.tree.insert("x.lz4".into(), (lbytes, mode, mtime));
        let msg = verdict(&c, &r, &legacy).expect("a legacy frame passed for a modern one");
        assert!(
            msg.contains("stream format differs: reference lz4 frame, stuffr lz4 legacy"),
            "{msg}"
        );
    }
}
