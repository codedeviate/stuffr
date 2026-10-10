//! Differential tests: stuffr invoked as `bzip2recover` against the real
//! bzip2recover 1.0.8. Every case compares the `rec*` file names, bytes and
//! modes, stderr and the exit code.
//!
//! **Debian's reference.** Debian and Ubuntu patch bzip2recover with
//! `bzip2recover-race-open-output.diff`, which opens each output with
//! `open(O_WRONLY|O_CREAT|O_EXCL, 0600)` instead of `fopen(.., "wb")`. That
//! makes the outputs mode 0600 whatever the umask, and refuses (`can't
//! write`, exit 1) an output name that already exists, where upstream
//! truncates it or writes through a symlink. stuffr keeps upstream's
//! behaviour. [`debian_reference`] probes for the patch; on such a reference
//! the cases with a pre-existing output are skipped with a note naming the
//! patch, and the reference's 0600 output modes are checked and then set to
//! stuffr's before comparing. That is a deviation of the test oracle, not of
//! stuffr.

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod differential {
    use super::compat_harness::*;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::sync::OnceLock;

    // ---- deterministic data ----

    struct XorShift(u64);
    impl XorShift {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }

    fn random(n: usize, seed: u64) -> Vec<u8> {
        let mut r = XorShift(seed);
        (0..n).map(|_| (r.next() >> 24) as u8).collect()
    }

    const WORDS: &[&str] = &[
        "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog", "stuffr", "bzip2", "block",
        "sorting", "recover", "damaged", "file",
    ];

    fn text(n: usize, seed: u64) -> Vec<u8> {
        let mut r = XorShift(seed);
        let mut v = Vec::with_capacity(n + 16);
        while v.len() < n {
            v.extend_from_slice(WORDS[(r.next() % WORDS.len() as u64) as usize].as_bytes());
            v.push(if r.next().is_multiple_of(9) {
                b'\n'
            } else {
                b' '
            });
        }
        v.truncate(n);
        v
    }

    /// Text with runs of random bytes, so blocks are not all alike.
    fn mixed(n: usize, seed: u64) -> Vec<u8> {
        let mut r = XorShift(seed);
        let mut v = Vec::with_capacity(n + 4096);
        while v.len() < n {
            if r.next().is_multiple_of(2) {
                v.extend(text(4096, r.next()));
            } else {
                v.extend(random(700, r.next() | 1));
            }
        }
        v.truncate(n);
        v
    }

    /// Compress with the reference bzip2; `None` when it is missing (a
    /// panic on CI, see `require_reference`).
    fn ref_bz(data: &[u8], level: &str) -> Option<Vec<u8>> {
        let exe = Path::new(REFERENCE_DIR).join("bzip2");
        if !require_reference(&exe) {
            return None;
        }
        let mut child = Command::new(exe)
            .args(["-c", level])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut si = child.stdin.take().unwrap();
        let d = data.to_vec();
        let w = std::thread::spawn(move || {
            use std::io::Write;
            let _ = si.write_all(&d);
        });
        let out = child.wait_with_output().unwrap();
        w.join().unwrap();
        assert!(out.status.success());
        Some(out.stdout)
    }

    const BLOCK_MAGIC: [u8; 6] = [0x31, 0x41, 0x59, 0x26, 0x53, 0x59];
    const END_MAGIC: [u8; 6] = [0x17, 0x72, 0x45, 0x38, 0x50, 0x90];

    /// `BZh9` and then `n` block magics back to back.
    fn packed_magics(n: usize) -> Vec<u8> {
        let mut v = b"BZh9".to_vec();
        for _ in 0..n {
            v.extend_from_slice(&BLOCK_MAGIC);
        }
        v
    }

    fn case<'a>(args: &[&'a str], files: Vec<(&'a str, Vec<u8>)>) -> Case<'a> {
        Case {
            name: "bzip2recover",
            args: args.to_vec(),
            files,
            stdin: None,
            tty_stdin: false,
            tty_stdout: false,
            env: vec![],
            compare_output_bytes: true,
            expect_stdout_plain: None,
            setup: None,
        }
    }

    fn with_setup<'a>(mut c: Case<'a>, setup: fn(&Path)) -> Case<'a> {
        c.setup = Some(setup);
        c
    }

    // ---- Debian's bzip2recover-race-open-output.diff ----

    /// Whether the reference carries Debian's
    /// `bzip2recover-race-open-output.diff`: it refuses an output name that
    /// already exists. `None` when the reference is missing.
    fn debian_reference() -> Option<bool> {
        static PROBE: OnceLock<Option<bool>> = OnceLock::new();
        *PROBE.get_or_init(|| {
            let exe = Path::new(REFERENCE_DIR).join("bzip2recover");
            if !require_reference(&exe) {
                return None;
            }
            let bz = ref_bz(b"probe", "-9")?;
            let dir =
                std::env::temp_dir().join(format!("stuffr-recover-probe-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("x.bz2"), bz).unwrap();
            std::fs::write(dir.join("rec00001x.bz2"), b"old").unwrap();
            let st = Command::new(&exe)
                .arg("x.bz2")
                .current_dir(&dir)
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            let _ = std::fs::remove_dir_all(&dir);
            let debian = !st.success();
            if debian {
                println!(
                    "note: the reference bzip2recover carries Debian's \
                     bzip2recover-race-open-output.diff (O_EXCL, mode 0600)"
                );
            }
            Some(debian)
        })
    }

    /// On a Debian reference, check its outputs are 0600 and give them
    /// stuffr's (upstream's) modes before comparing.
    fn debian_modes(r: &mut Run, s: &mut Run) {
        if debian_reference() != Some(true) {
            return;
        }
        for (name, (_, mode, _)) in r.tree.iter_mut() {
            let base = name.rsplit('/').next().unwrap_or(name);
            if !base.starts_with("rec") || name.ends_with('/') {
                continue;
            }
            assert_eq!(*mode, 0o600, "Debian reference output {name} is not 0600");
            if let Some((_, m, _)) = s.tree.get(name) {
                *mode = *m;
            }
        }
    }

    // ---- the group runner ----

    fn panic_text(p: Box<dyn std::any::Any + Send>) -> String {
        p.downcast_ref::<String>()
            .cloned()
            .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default()
    }

    /// Run every case against the reference and stuffr, a few at a time, and
    /// fail once listing every case that differed. Prints "N of M cases
    /// compared"; on CI every case must have run.
    fn check_all(group: &str, cases: &[Case]) {
        let one = |c: &Case| -> Result<bool, String> {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let Some(mut r) = reference(REFERENCE_DIR, c) else {
                    return false;
                };
                let mut s = stuffr_as(c);
                debian_modes(&mut r, &mut s);
                assert_same(c, &r, &s);
                true
            }))
            .map_err(panic_text)
        };
        let workers = std::thread::available_parallelism().map_or(2, |n| n.get().min(8));
        let next = std::sync::atomic::AtomicUsize::new(0);
        let mut results: Vec<(usize, Result<bool, String>)> = std::thread::scope(|sc| {
            let hs: Vec<_> = (0..workers)
                .map(|_| {
                    sc.spawn(|| {
                        let mut out = Vec::new();
                        loop {
                            let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let Some(c) = cases.get(i) else { break out };
                            out.push((i, one(c)));
                        }
                    })
                })
                .collect();
            hs.into_iter().flat_map(|h| h.join().unwrap()).collect()
        });
        results.sort_by_key(|(i, _)| *i);
        let mut failures = Vec::new();
        let mut ran = 0;
        for (_, r) in results {
            match r {
                Ok(true) => ran += 1,
                Ok(false) => {}
                Err(p) => failures.push(p),
            }
        }
        println!("{group}: {ran} of {} cases compared", cases.len());
        if std::env::var_os("CI").is_some() {
            assert_eq!(
                ran,
                cases.len(),
                "{group}: CI is set but only {ran} of {} cases were compared",
                cases.len()
            );
        }
        assert!(
            failures.is_empty(),
            "{group}: {} of {} cases differ:\n\n{}",
            failures.len(),
            cases.len(),
            failures.join("\n\n")
        );
    }

    // ---- setups ----

    fn mkdir_sub(d: &Path) {
        std::fs::create_dir_all(d.join("sub")).unwrap();
    }
    fn unreadable(d: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(d.join("d.bz2"), std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    fn first_output_is_a_directory(d: &Path) {
        std::fs::create_dir(d.join("rec00001d.bz2")).unwrap();
    }
    fn second_output_is_a_directory(d: &Path) {
        std::fs::create_dir(d.join("rec00002d.bz2")).unwrap();
    }
    fn first_output_exists(d: &Path) {
        std::fs::write(
            d.join("rec00001d.bz2"),
            b"an older, longer file to truncate",
        )
        .unwrap();
    }
    fn first_output_is_a_symlink(d: &Path) {
        std::fs::write(d.join("target"), b"old target").unwrap();
        std::os::unix::fs::symlink("target", d.join("rec00001d.bz2")).unwrap();
    }
    fn first_output_dangles(d: &Path) {
        std::os::unix::fs::symlink("nowhere", d.join("rec00001d.bz2")).unwrap();
    }

    // ---- groups ----

    /// A healthy stream of several blocks: more than 300 KiB at `-1`.
    fn multi() -> Option<Vec<u8>> {
        ref_bz(&mixed(420_000, 11), "-1")
    }

    #[test]
    fn operands() {
        let Some(bz) = multi() else { return };
        let small = ref_bz(&text(2000, 3), "-9").unwrap();
        let long_1979 = "a/".repeat(989) + "b";
        let long_1980 = "a/".repeat(990);
        let long_3000 = "x".repeat(3000);
        assert_eq!((long_1979.len(), long_1980.len()), (1979, 1980));
        let d = || vec![("d.bz2", bz.clone())];
        let cases = vec![
            case(&[], d()),
            case(&["d.bz2", "d.bz2"], d()),
            case(&["d.bz2", "missing.bz2"], d()),
            case(&["missing.bz2"], d()),
            case(&[""], d()),
            case(&["--help"], d()),
            case(&["-h"], d()),
            case(&["-"], d()),
            case(&["--", "d.bz2"], d()),
            with_setup(case(&["sub"], d()), mkdir_sub),
            with_setup(case(&["d.bz2"], d()), unreadable),
            case(&[&long_1979], d()),
            case(&[&long_1980], d()),
            case(&[&long_3000], d()),
            // Naming: the split at the last '/', and the `.bz2` suffix rule.
            case(&["sub/d.bz2"], vec![("sub/d.bz2", bz.clone())]),
            case(
                &["./sub/deeper/x.bz2"],
                vec![("sub/deeper/x.bz2", small.clone())],
            ),
            case(&["d.dat"], vec![("d.dat", small.clone())]),
            case(&["bz2"], vec![("bz2", small.clone())]),
            case(&[".bz2"], vec![(".bz2", small.clone())]),
            case(&["x.BZ2"], vec![("x.BZ2", small.clone())]),
            case(&["my file.bz2"], vec![("my file.bz2", small.clone())]),
            case(&["d.tbz2"], vec![("d.tbz2", small.clone())]),
        ];
        check_all("operands", &cases);
    }

    #[test]
    fn recover() {
        let Some(bz) = multi() else { return };
        let small = ref_bz(&text(2000, 3), "-9").unwrap();
        let empty_stream = ref_bz(b"", "-9").unwrap();
        let n = bz.len();
        let mut concat = small.clone();
        concat.extend_from_slice(&bz);
        let mut garbage = bz.clone();
        garbage.extend_from_slice(b"trailing garbage after the stream\n");
        let mut damaged = bz.clone();
        for b in &mut damaged[n / 2..n / 2 + 16] {
            *b ^= 0x5a;
        }
        // Break the second block's magic: two blocks merge into one.
        let mut lost_boundary = bz.clone();
        let second = (81..(n - 6) * 8)
            .find(|&bit| bit_magic_at(&bz, bit))
            .expect("a second block magic");
        lost_boundary[(second + 24) / 8] ^= 0x10;
        let mut synthetic = b"BZh9".to_vec();
        for _ in 0..3 {
            synthetic.extend_from_slice(&BLOCK_MAGIC);
            synthetic.extend_from_slice(&[0u8; 17]);
        }
        let mut synthetic_end = synthetic.clone();
        synthetic_end.extend_from_slice(&END_MAGIC);
        synthetic_end.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let mut short_blocks = b"BZh9".to_vec();
        for k in [1usize, 10, 16, 17, 18] {
            short_blocks.extend_from_slice(&BLOCK_MAGIC);
            short_blocks.extend(std::iter::repeat_n(0xffu8, k));
        }
        short_blocks.extend_from_slice(&END_MAGIC);
        // A block magic off the byte grid: shifted by 3 bits.
        let mut unaligned = vec![0u8; 3];
        unaligned.extend(shift_bits(&small, 3));

        let mut files: Vec<(&str, Vec<u8>)> = vec![
            ("healthy multi-block", bz.clone()),
            ("healthy one block", small.clone()),
            ("empty stream", empty_stream),
            ("concatenated", concat),
            ("trailing garbage", garbage),
            ("damaged middle", damaged),
            ("lost boundary", lost_boundary),
            ("synthetic", synthetic),
            ("synthetic with end", synthetic_end),
            ("short blocks", short_blocks),
            ("unaligned", unaligned),
            ("not bzip2", text(5000, 9)),
            ("random", random(65536, 5)),
            ("empty", Vec::new()),
            ("one byte", b"B".to_vec()),
            // The cap: back-to-back magics each count as a block.
            ("49999 magics", packed_magics(49_999)),
            ("50000 magics", packed_magics(50_000)),
            ("50001 magics", packed_magics(50_001)),
            ("50002 magics", packed_magics(50_002)),
        ];
        for cut in [
            1,
            3,
            4,
            5,
            10,
            13,
            14,
            20,
            100,
            5000,
            n / 3,
            n / 2,
            n - 10,
            n - 4,
            n - 1,
        ] {
            files.push(("truncated", bz[..cut].to_vec()));
        }
        let cases: Vec<Case> = files
            .into_iter()
            .map(|(_, data)| case(&["d.bz2"], vec![("d.bz2", data)]))
            .collect();
        check_all("recover", &cases);
    }

    /// Whether a block magic starts at bit `i` of `data`.
    fn bit_magic_at(data: &[u8], i: usize) -> bool {
        let bit = |k: usize| (data[k / 8] >> (7 - k % 8)) & 1;
        if i + 48 > data.len() * 8 {
            return false;
        }
        let mut v = 0u64;
        for k in i..i + 48 {
            v = (v << 1) | bit(k) as u64;
        }
        v == 0x3141_5926_5359
    }

    /// `data` delayed by `k` bits (the leading bits zero).
    fn shift_bits(data: &[u8], k: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() + 1);
        let mut carry = 0u8;
        for &b in data {
            out.push(carry | (b >> k));
            carry = b << (8 - k);
        }
        out.push(carry);
        out
    }

    /// Outputs that cannot be created, or that already exist.
    #[test]
    fn outputs() {
        let Some(bz) = multi() else { return };
        let Some(debian) = debian_reference() else {
            return;
        };
        let d = || vec![("d.bz2", bz.clone())];
        let mut cases = vec![
            with_setup(case(&["d.bz2"], d()), first_output_is_a_directory),
            with_setup(case(&["d.bz2"], d()), second_output_is_a_directory),
        ];
        let upstream_only = vec![
            with_setup(case(&["d.bz2"], d()), first_output_exists),
            with_setup(case(&["d.bz2"], d()), first_output_is_a_symlink),
            with_setup(case(&["d.bz2"], d()), first_output_dangles),
        ];
        if debian {
            println!(
                "outputs: skipped {} pre-existing-output cases: the reference \
                 carries Debian's bzip2recover-race-open-output.diff",
                upstream_only.len()
            );
        } else {
            cases.extend(upstream_only);
        }
        check_all("outputs", &cases);
    }

    /// At 50000 blocks bzip2recover 1.0.8 writes one element past its
    /// `bEnd` array when the last block has no end marker. With the macOS
    /// layout that lands on `rbStart[0]`, so block 1 is not written. The
    /// layout is the compiler's, so this is pinned on macOS only.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_block_cap_overflow_as_measured_on_macos() {
        let mut v = b"BZh9".to_vec();
        let z = [0u8; 20];
        v.extend_from_slice(&z);
        for _ in 0..2 {
            v.extend_from_slice(&BLOCK_MAGIC);
            v.extend_from_slice(&z);
        }
        v.extend(packed_magics(49_998).split_off(4));
        v.extend_from_slice(&z);
        let short = {
            let mut s = v.clone();
            s.truncate(s.len() - 20);
            s.push(0);
            s
        };
        let cases = vec![
            case(&["d.bz2"], vec![("d.bz2", v)]),
            case(&["d.bz2"], vec![("d.bz2", short)]),
        ];
        check_all("block cap overflow", &cases);
    }

    /// Every output decompresses with the reference bzip2, and together
    /// they hold the original data: the recovered blocks are real streams.
    #[test]
    fn recovered_blocks_decompress_to_the_original() {
        let Some(bz) = multi() else { return };
        let c = case(&["d.bz2"], vec![("d.bz2", bz)]);
        let s = stuffr_as(&c);
        assert_eq!(s.code, 0, "{}", s.stderr);
        let recs: Vec<_> = s
            .tree
            .iter()
            .filter(|(n, _)| n.starts_with("rec"))
            .collect();
        assert!(recs.len() >= 4, "only {} blocks", recs.len());
        let mut all = Vec::new();
        for (_, (bytes, _, _)) in recs {
            all.extend(ref_decompress(bytes).unwrap());
        }
        assert_eq!(all, mixed(420_000, 11));
    }
}
