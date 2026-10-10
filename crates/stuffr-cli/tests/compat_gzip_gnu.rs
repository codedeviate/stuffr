//! Differential tests: stuffr invoked as `gzip`, `gunzip`, `zcat` and `gzcat`
//! with `STUFFR_GZIP_FLAVOR=gnu`, against the real GNU gzip (1.15 from the
//! Homebrew keg on macOS, the distribution's on Linux).
//!
//! Part 1 (0.12.0 Task 7): arguments, messages and compression. Part 2
//! (Task 8) adds decompression, `-t`, `-l` and `-r`.
//!
//! Compressed bytes are not promised identical (GNU's deflate is its own),
//! so every case round-trips stuffr's output through the reference and
//! compares the header through FNAME. For the same reason `-v`'s ratio,
//! which counts compressed bytes, is blanked on both sides before comparing;
//! `ratio_of_an_empty_input_is_exact` checks the one ratio both agree on.
//!
//! **The oracle's version.** Linux CI has 1.12, this suite targets 1.15.
//! Cases whose reference behaviour changed in between (the survey in
//! `.claude/rules/compat.md`, "gzip family") are skipped on an older
//! reference and counted as known oracle skips, as 0.11.0's
//! `compat_bzip2recover.rs` does for Debian.

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod differential {
    use super::compat_harness::*;
    use std::path::Path;
    use std::sync::OnceLock;
    use std::time::{Duration, UNIX_EPOCH};

    // ---- the reference ----

    fn ref_gzip() -> &'static str {
        static P: OnceLock<String> = OnceLock::new();
        P.get_or_init(|| format!("{}/gzip", gnu_gzip_dir()))
    }

    /// GNU's `PATH`: its `gunzip`/`zcat` scripts exec `gzip` from `PATH`,
    /// and on macOS `/usr/bin/gzip` is Apple's.
    fn gnu_path() -> &'static str {
        static P: OnceLock<String> = OnceLock::new();
        P.get_or_init(|| format!("{}:/usr/bin:/bin", gnu_gzip_dir()))
    }

    /// The reference's version, `(0, 0)` when it is absent (every case is
    /// then skipped by `reference` anyway).
    fn version() -> (u32, u32) {
        static V: OnceLock<(u32, u32)> = OnceLock::new();
        *V.get_or_init(|| gnu_gzip_version().unwrap_or((0, 0)))
    }

    fn case<'a>(name: &'a str, args: &[&'a str], files: Vec<(&'a str, Vec<u8>)>) -> Case<'a> {
        Case {
            name,
            args: args.to_vec(),
            files,
            stdin: None,
            tty_stdin: false,
            tty_stdout: false,
            env: vec![("STUFFR_GZIP_FLAVOR", "gnu"), ("PATH", gnu_path())],
            compare_output_bytes: false,
            expect_stdout_plain: None,
            setup: None,
            roundtrip: Roundtrip::Gzip {
                ref_gzip: ref_gzip(),
            },
        }
    }

    fn gz<'a>(args: &[&'a str], files: Vec<(&'a str, Vec<u8>)>) -> Case<'a> {
        case("gzip", args, files)
    }

    fn fed<'a>(mut c: Case<'a>, stdin: &[u8]) -> Case<'a> {
        c.stdin = Some(stdin.to_vec());
        c
    }

    fn with_setup(mut c: Case<'_>, setup: fn(&Path)) -> Case<'_> {
        c.setup = Some(setup);
        c
    }

    fn with_env<'a>(mut c: Case<'a>, k: &'a str, v: &'a str) -> Case<'a> {
        c.env.push((k, v));
        c
    }

    fn expect<'a>(mut c: Case<'a>, plain: &[u8]) -> Case<'a> {
        c.expect_stdout_plain = Some(plain.to_vec());
        c
    }

    fn kib_text() -> Vec<u8> {
        text(1024, 7)
    }

    /// The same case under another invoked name (the reference has no
    /// `gzcat`; GNU's `zcat` is what stuffr's `gzcat` follows).
    fn renamed<'a>(c: &Case<'a>, name: &'a str) -> Case<'a> {
        Case {
            name,
            args: c.args.clone(),
            files: c.files.clone(),
            stdin: c.stdin.clone(),
            tty_stdin: c.tty_stdin,
            tty_stdout: c.tty_stdout,
            env: c.env.clone(),
            compare_output_bytes: c.compare_output_bytes,
            expect_stdout_plain: c.expect_stdout_plain.clone(),
            setup: c.setup,
            roundtrip: c.roundtrip,
        }
    }

    fn reference_name(name: &str) -> &str {
        if name == "gzcat" { "zcat" } else { name }
    }

    // ---- normalisation ----

    /// The length of a ratio token at the start of `b`: optional spaces, an
    /// optional `-`, then `Inf%` or digits `.` one digit `%`. Only at a line
    /// start or after a tab, which is where gzip prints it.
    fn ratio_at(b: &[u8]) -> Option<usize> {
        let mut i = 0;
        while b.get(i) == Some(&b' ') {
            i += 1;
        }
        if b.get(i) == Some(&b'-') {
            i += 1;
        }
        if b[i..].starts_with(b"Inf%") {
            return Some(i + 4);
        }
        let d = b[i..].iter().take_while(|c| c.is_ascii_digit()).count();
        if d == 0 {
            return None;
        }
        i += d;
        if b.get(i) == Some(&b'.')
            && b.get(i + 1).is_some_and(u8::is_ascii_digit)
            && b.get(i + 2) == Some(&b'%')
        {
            Some(i + 3)
        } else {
            None
        }
    }

    fn blank_both(r: &mut Run, s: &mut Run) {
        r.stderr = blank_lines(&r.stderr);
        s.stderr = blank_lines(&s.stderr);
    }

    /// `-v`'s ratio (`%5.1f%%`, or ` -Inf%`) counts compressed bytes, which
    /// are not promised: blank each, with its padding, where a ratio can
    /// stand: at a line's start (standard input's `-v` line) and after the
    /// first tab.
    fn blank_lines(s: &str) -> String {
        s.split_inclusive('\n')
            .map(|line| match line.split_once('\t') {
                Some((head, tail)) => format!("{head}\t{}", blank_ratios_at_start(tail)),
                None => blank_ratios_at_start(line),
            })
            .collect()
    }

    fn blank_ratios_at_start(s: &str) -> String {
        match ratio_at(s.as_bytes()) {
            Some(n) => format!("<ratio>%{}", &s[n..]),
            None => s.to_owned(),
        }
    }

    /// The scripts' `--help` names their own path (`Usage: $0 ...`), which
    /// differs between the two runs by construction: both become `$0`.
    fn script_usage(run: &mut Run) {
        if run.stdout.starts_with(b"Usage: /")
            && let Some(sp) = run.stdout[7..].iter().position(|&b| b == b' ')
        {
            let mut v = b"Usage: $0".to_vec();
            v.extend_from_slice(&run.stdout[7 + sp..]);
            run.stdout = v;
        }
    }

    /// stuffr's version line names stuffr (`NAME (stuffr X) 1.15`); swap it
    /// for the reference's after checking both, so the rest is compared.
    fn version_line(r: &mut Run, s: &mut Run) {
        let ours_end = match s.stdout.iter().position(|&b| b == b'\n') {
            Some(n) => n + 1,
            None => return,
        };
        let ours = String::from_utf8_lossy(&s.stdout[..ours_end]).into_owned();
        let tag = format!(" (stuffr {}) 1.15\n", env!("CARGO_PKG_VERSION"));
        let Some(prog) = ours.strip_suffix(&tag) else {
            return;
        };
        let theirs_end = r
            .stdout
            .iter()
            .position(|&b| b == b'\n')
            .map_or(0, |n| n + 1);
        let theirs = String::from_utf8_lossy(&r.stdout[..theirs_end]).into_owned();
        let want = match prog {
            "gzip" => "gzip 1.15\n".to_owned(),
            p => format!("{} (gzip) 1.15\n", reference_name(p)),
        };
        assert_eq!(theirs, want, "the reference's version line");
        let mut v = theirs.into_bytes();
        v.extend_from_slice(&s.stdout[ours_end..]);
        s.stdout = v;
    }

    // ---- the group runner ----

    fn panic_text(p: Box<dyn std::any::Any + Send>) -> String {
        p.downcast_ref::<String>()
            .cloned()
            .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default()
    }

    /// Cases left out on this reference, and why.
    struct Skipped {
        count: usize,
        why: String,
    }

    fn none_skipped() -> Skipped {
        Skipped {
            count: 0,
            why: String::new(),
        }
    }

    /// Keep the cases this reference can judge: those built by `newer` need
    /// at least `min`; on an older reference they become a counted skip.
    fn gated<'a>(
        mut cases: Vec<Case<'a>>,
        newer: Vec<Case<'a>>,
        min: (u32, u32),
        why: &str,
        skipped: &mut Skipped,
    ) -> Vec<Case<'a>> {
        if version() >= min || version() == (0, 0) {
            cases.extend(newer);
        } else {
            skipped.count += newer.len();
            if !skipped.why.is_empty() {
                skipped.why.push_str("; ");
            }
            skipped.why.push_str(&format!(
                "{} on a {}.{} reference ({why}, {}.{}+)",
                newer.len(),
                version().0,
                version().1,
                min.0,
                min.1
            ));
        }
        cases
    }

    fn check_all(group: &str, cases: &[Case]) {
        check_all_skipping(group, cases, none_skipped());
    }

    /// Run every case against the reference and stuffr, a few at a time, and
    /// fail once listing every case that differed. Prints "N of M cases
    /// compared" (M includes the known oracle skips, which are named); on CI
    /// every case not skipped for a known reason must have run.
    fn check_all_skipping(group: &str, cases: &[Case], skipped: Skipped) {
        let one = |c: &Case| -> Result<bool, String> {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let refc = renamed(c, reference_name(c.name));
                let Some(mut r) = reference(gnu_gzip_dir(), &refc) else {
                    return false;
                };
                let mut s = stuffr_as(c);
                script_usage(&mut r);
                script_usage(&mut s);
                version_line(&mut r, &mut s);
                blank_both(&mut r, &mut s);
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
        let total = cases.len() + skipped.count;
        if skipped.count > 0 {
            println!(
                "{group}: {ran} of {total} cases compared, {} skipped: {}",
                skipped.count, skipped.why
            );
        } else {
            println!("{group}: {ran} of {total} cases compared");
        }
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

    // ---- setups (run in the working directory before the program) ----

    fn set_mode(d: &Path, name: &str, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(d.join(name), std::fs::Permissions::from_mode(mode)).unwrap();
    }
    /// `l.txt` (created as a copy, so the harness knows its bytes) becomes a
    /// symlink to `a.txt`, which holds the same bytes.
    fn link_l_txt(d: &Path) {
        std::fs::remove_file(d.join("l.txt")).unwrap();
        std::os::unix::fs::symlink("a.txt", d.join("l.txt")).unwrap();
    }
    /// `h.txt` becomes a hard link to `a.txt` (same bytes).
    fn hard_link_h(d: &Path) {
        std::fs::remove_file(d.join("h.txt")).unwrap();
        std::fs::hard_link(d.join("a.txt"), d.join("h.txt")).unwrap();
    }
    /// `h.txt` and `i.txt` both become hard links to `a.txt`.
    fn two_hard_links(d: &Path) {
        hard_link_h(d);
        std::fs::remove_file(d.join("i.txt")).unwrap();
        std::fs::hard_link(d.join("a.txt"), d.join("i.txt")).unwrap();
    }
    fn subdir(d: &Path) {
        std::fs::create_dir(d.join("d")).unwrap();
    }
    fn unreadable(d: &Path) {
        set_mode(d, "a.txt", 0o000);
    }
    fn mode_640(d: &Path) {
        set_mode(d, "a.txt", 0o640);
    }
    /// An mtime gzip cannot store (1960).
    fn ancient(d: &Path) {
        let t = UNIX_EPOCH - Duration::from_secs(10 * 365 * 86_400);
        std::fs::File::options()
            .write(true)
            .open(d.join("a.txt"))
            .unwrap()
            .set_modified(t)
            .unwrap();
    }

    // ---- groups ----

    /// Every option `gzip --help` lists that compresses, alone, in long form
    /// and in clusters; `--` and `-`; unknown, ambiguous and abbreviated long
    /// options; `-S`'s argument rules; the undocumented letters the binary
    /// accepts; and the order in which stops happen. `-d`, `-l` and `-t` are
    /// Task 8's (they decompress).
    #[test]
    fn flags() {
        let t = kib_text();
        let a = || vec![("a.txt", t.clone())];
        let mut cases = Vec::new();
        for args in [
            &["a.txt"][..],
            &["-c", "a.txt"],
            &["--stdout", "a.txt"],
            &["--to-stdout", "a.txt"],
            &["--std", "a.txt"],
            &["-f", "a.txt"],
            &["--force", "a.txt"],
            &["-k", "a.txt"],
            &["--keep", "a.txt"],
            &["-n", "a.txt"],
            &["--no-name", "a.txt"],
            &["-N", "a.txt"],
            &["--name", "a.txt"],
            &["-q", "a.txt"],
            &["--quiet", "a.txt"],
            &["--silent", "a.txt"],
            &["-r", "a.txt"],
            &["--recursive", "a.txt"],
            &["--rsyncable", "a.txt"],
            &["--synchronous", "a.txt"],
            &["--sync", "a.txt"],
            &["-v", "a.txt"],
            &["--verbose", "a.txt"],
            &["-vv", "a.txt"],
            &["-1", "a.txt"],
            &["--fast", "a.txt"],
            &["--fa", "a.txt"],
            &["-9", "a.txt"],
            &["--best", "a.txt"],
            &["-S", ".x", "a.txt"],
            &["-S.x", "a.txt"],
            &["--suffix", ".x", "a.txt"],
            &["--suffix=.x", "a.txt"],
            &["--su=.x", "a.txt"],
            &["-S", "_", "a.txt"],
            &["-S", "abcdefghijklmnopqrstuvwxyzabcd", "a.txt"],
            &["-S", "abcdefghijklmnopqrstuvwxyzabcde", "a.txt"],
            &["-S", "", "a.txt"],
            &["--suffix=", "a.txt"],
            &["-S"],
            &["--suffix"],
            &["--su"],
            // clusters
            &["-9cv", "a.txt"],
            &["-cv9", "a.txt"],
            &["-kf", "a.txt"],
            &["-kv", "a.txt"],
            &["-ckv", "a.txt"],
            &["-kS.y", "a.txt"],
            &["-kS", ".y", "a.txt"],
            &["-kS"],
            &["-nN", "-c", "a.txt"],
            &["-Nn", "-c", "a.txt"],
            &["-qv", "a.txt"],
            &["-vq", "a.txt"],
            &["-v", "--silent", "a.txt"],
            // operands and options interleave
            &["a.txt", "-k"],
            &["a.txt", "-c"],
            &["--", "a.txt"],
            &["-c", "--", "a.txt"],
            // unknown, ambiguous, malformed
            &["-x"],
            &["-kx", "a.txt"],
            &["-e", "a.txt"],
            &["--bogus"],
            &["--bogus=1", "a.txt"],
            &["--s", "a.txt"],
            &["--s=x"],
            &["--n", "a.txt"],
            &["--v", "a.txt"],
            &["--l"],
            &["--=x"],
            &["--he=x"],
            &["--stdout=", "a.txt"],
            &["--bi"],
            &["-?"],
            &["-Z", "a.txt"],
            &["-kZ", "a.txt"],
            &["--lzw", "a.txt"],
            &["--lz", "a.txt"],
            // the undocumented letters
            &["-a", "a.txt"],
            &["--ascii", "a.txt"],
            &["-qa", "a.txt"],
            &["-a", "-q", "a.txt"],
            &["-a", "-S", "", "a.txt"],
            &["-a", "-x"],
            &["-b", "3", "a.txt"],
            &["-b3", "a.txt"],
            &["-b", "", "a.txt"],
            &["-b", "x", "a.txt"],
            &["-b", "-3", "a.txt"],
            &["--bits=x", "a.txt"],
            &["-b"],
            &["-cm", "a.txt"],
            &["-cM", "a.txt"],
            &["-cnM", "a.txt"],
            &["-cNm", "a.txt"],
            // stops happen in argv order
            &["-x", "-h"],
            &["--bogus", "-h"],
            &["-Z", "-x"],
            &["-x", "-Z"],
            &["-S", "", "-x"],
            &["-S", "", "-Z"],
        ] {
            cases.push(gz(args, a()));
        }
        // An operand named like an option, after `--`.
        cases.push(gz(&["-k", "--", "-c"], vec![("-c", t.clone())]));
        // `-` and no operand read standard input.
        cases.push(fed(gz(&["-"], a()), &t));
        cases.push(fed(gz(&[], a()), &t));
        cases.push(fed(gz(&["-c", "-"], a()), &t));
        cases.push(fed(gz(&["--", "-"], a()), &t));
        cases.push(fed(gz(&["-b", "0"], a()), &t));
        cases.push(fed(gz(&["---presume-input-tty"], a()), &t));
        cases.push(fed(gz(&["---presume-input-tty", "-q"], a()), &t));
        cases.push(fed(gz(&["---p", "-f"], a()), &t));
        cases.push(fed(gz(&["---presume-input-tty", "-c", "a.txt"], a()), &t));
        // POSIXLY_CORRECT: the first operand ends the options.
        cases.push(with_env(
            gz(&["-c", "a.txt", "-v"], a()),
            "POSIXLY_CORRECT",
            "1",
        ));
        let mut skipped = none_skipped();
        // NEWS 1.14: a suffix holding `/` is refused (survey row 2).
        let slash = vec![
            gz(&["-S", "x/y", "a.txt"], a()),
            gz(&["-S", "x/y", "-c", "a.txt"], a()),
            gz(&["-S", "x/y", "-S", ".z", "a.txt"], a()),
            gz(&["-S", "x/y", "-x"], a()),
        ];
        let cases = gated(
            cases,
            slash,
            (1, 14),
            "a `/` suffix is refused",
            &mut skipped,
        );
        check_all_skipping("flags", &cases, skipped);
    }

    /// `-h`, `--help`, `-H`, `-L`, `-V` and `--version`: printed on standard
    /// output, exit 0, at the point they appear. The version and licence
    /// name stuffr on the first line; the rest is compared. The text is
    /// 1.15's (its copyright year among it), so an older reference is a
    /// documented skip.
    #[test]
    fn help_version_and_license() {
        let t = kib_text();
        let a = || vec![("a.txt", t.clone())];
        let mut texts = Vec::new();
        for args in [
            &["-h"][..],
            &["--help"],
            &["-H"],
            &["--h"],
            &["--he"],
            &["-hV"],
            &["-h", "-x"],
            &["-c", "-h", "a.txt"],
            &["-L"],
            &["--license"],
            &["--lic"],
            &["-LV"],
            &["-V"],
            &["--version"],
            &["--vers"],
            &["-Vh"],
            &["-V", "-x"],
            &["--version", "-h"],
            &["-V", "a.txt"],
            &["-dV"],
        ] {
            texts.push(gz(args, a()));
        }
        let mut skipped = none_skipped();
        let cases = gated(
            Vec::new(),
            texts,
            (1, 15),
            "help and version text is 1.15's",
            &mut skipped,
        );
        check_all_skipping("help_version_and_license", &cases, skipped);
    }

    /// Levels 1-9 and the default over six inputs, file to file with `-v`
    /// (header through FNAME compared: XFL is 4 at `-1`, 2 at `-9`, else 0;
    /// OS 3); the same through a pipe; `-n`/`-N`.
    #[test]
    fn compress() {
        let inputs: Vec<(&str, Vec<u8>)> = vec![
            ("empty", vec![]),
            ("one", b"x".to_vec()),
            ("text", kib_text()),
            ("mixed", mixed(1 << 20, 11)),
            ("random", random(1 << 20, 12)),
            ("repetitive", repetitive(4 << 20)),
        ];
        let levels = ["", "-1", "-2", "-3", "-4", "-5", "-6", "-7", "-8", "-9"];
        let mut cases = Vec::new();
        for (name, data) in &inputs {
            for l in levels {
                let mut args = vec!["-v"];
                if !l.is_empty() {
                    args.push(l);
                }
                args.push(name);
                cases.push(gz(&args, vec![(name, data.clone())]));
            }
        }
        // Through a pipe: no name, time 0.
        for (_, data) in &inputs[..4] {
            for l in ["-1", "-6", "-9"] {
                cases.push(fed(gz(&["-v", l], vec![]), data));
            }
        }
        let t = kib_text();
        for args in [
            &["-c", "a.txt"][..],
            &["-cn", "a.txt"],
            &["-cN", "a.txt"],
            &["-n", "a.txt"],
            &["-N", "a.txt"],
            &["-nk", "a.txt"],
        ] {
            cases.push(gz(args, vec![("a.txt", t.clone())]));
        }
        check_all("compress", &cases);
    }

    /// Standard input and several operands: `-c` with several files, standard
    /// input among files (named `stdin` once a file was compressed), several
    /// operands with one failing, and the exit code across them.
    #[test]
    fn operands() {
        let (a, b) = (kib_text(), text(700, 3));
        let ab = || vec![("a.txt", a.clone()), ("b.txt", b.clone())];
        let input = text(300, 9);
        let both = [a.clone(), input.clone()].concat();
        let cases = vec![
            gz(&["-c", "a.txt", "b.txt"], ab()),
            gz(&["-cv", "a.txt", "b.txt"], ab()),
            gz(&["a.txt", "b.txt"], ab()),
            gz(&["-v", "a.txt", "b.txt"], ab()),
            gz(&["a.txt", "nonexist", "b.txt"], ab()),
            gz(&["nonexist", "a.txt"], ab()),
            gz(&["-q", "nonexist", "a.txt"], ab()),
            with_setup(gz(&["-v", "a.txt", "d", "nonexist"], ab()), subdir),
            with_setup(gz(&["nonexist", "d"], ab()), subdir),
            with_setup(gz(&["d", "a.txt"], ab()), subdir),
            // Standard input after a file is stored as `stdin`; before any,
            // unnamed. `-n` keeps it unnamed.
            fed(gz(&["a.txt", "-"], ab()), &input),
            fed(gz(&["-v", "a.txt", "-"], ab()), &input),
            fed(gz(&["-n", "a.txt", "-"], ab()), &input),
            fed(gz(&["-N", "-"], ab()), &input),
            fed(gz(&["-", "a.txt"], ab()), &input),
            expect(fed(gz(&["-c", "a.txt", "-"], ab()), &input), &both),
            expect(
                fed(gz(&["-c", "-", "a.txt"], ab()), &input),
                &[input.clone(), a.clone()].concat(),
            ),
            expect(fed(gz(&["-c", "nonexist", "-"], ab()), &input), &input),
            with_setup(
                expect(fed(gz(&["-c", "d", "-"], ab()), &input), &input),
                subdir,
            ),
            expect(fed(gz(&["-", "-"], ab()), &input), &input),
        ];
        check_all("operands", &cases);
    }

    /// Existing outputs, suffixed inputs, links, directories, unreadable
    /// inputs, and what is copied onto the output.
    #[test]
    fn files() {
        let t = kib_text();
        let a = || vec![("a.txt", t.clone())];
        let with_gz = || vec![("a.txt", t.clone()), ("a.txt.gz", b"old".to_vec())];
        let linked = || vec![("a.txt", t.clone()), ("l.txt", t.clone())];
        let hard = || vec![("a.txt", t.clone()), ("h.txt", t.clone())];
        let hard2 = || {
            vec![
                ("a.txt", t.clone()),
                ("h.txt", t.clone()),
                ("i.txt", t.clone()),
            ]
        };
        let mut cases = vec![
            // an existing output
            gz(&["a.txt"], with_gz()),
            gz(&["-f", "a.txt"], with_gz()),
            gz(&["-k", "a.txt"], with_gz()),
            gz(&["-q", "a.txt"], with_gz()),
            gz(&["-v", "a.txt"], with_gz()),
            expect(gz(&["-c", "a.txt"], with_gz()), &t),
            // an input that already has a suffix
            gz(&["a.gz"], vec![("a.gz", t.clone())]),
            gz(&["-q", "a.gz"], vec![("a.gz", t.clone())]),
            gz(&["-v", "a.gz"], vec![("a.gz", t.clone())]),
            gz(&["-f", "a.gz"], vec![("a.gz", t.clone())]),
            gz(&["-c", "a.gz"], vec![("a.gz", t.clone())]),
            gz(&["A.GZ"], vec![("A.GZ", t.clone())]),
            gz(
                &["a.tgz", "b.taz"],
                vec![("a.tgz", t.clone()), ("b.taz", t.clone())],
            ),
            gz(
                &["a-z", "b_Z", "c.z"],
                vec![("a-z", t.clone()), ("b_Z", t.clone()), ("c.z", t.clone())],
            ),
            gz(
                &["a.bz2", "f_gz"],
                vec![("a.bz2", t.clone()), ("f_gz", t.clone())],
            ),
            gz(&[".gz"], vec![(".gz", t.clone())]),
            gz(
                &["-S", ".x", "a.x", "b.gz"],
                vec![("a.x", t.clone()), ("b.gz", t.clone())],
            ),
            gz(&["-S", "Z", "b.gz"], vec![("b.gz", t.clone())]),
            gz(&["-S", "z", "b.gz"], vec![("b.gz", t.clone())]),
            // symbolic links: refused unless -f; followed by -c
            with_setup(gz(&["l.txt"], linked()), link_l_txt),
            with_setup(gz(&["-k", "l.txt"], linked()), link_l_txt),
            with_setup(gz(&["-f", "l.txt"], linked()), link_l_txt),
            with_setup(expect(gz(&["-c", "l.txt"], linked()), &t), link_l_txt),
            // hard links: refused unless -f or -c
            with_setup(gz(&["h.txt"], hard()), hard_link_h),
            with_setup(gz(&["-k", "h.txt"], hard()), hard_link_h),
            with_setup(gz(&["-q", "h.txt"], hard()), hard_link_h),
            with_setup(gz(&["-f", "h.txt"], hard()), hard_link_h),
            with_setup(expect(gz(&["-c", "h.txt"], hard()), &t), hard_link_h),
            with_setup(gz(&["a.txt"], hard2()), two_hard_links),
            // a directory, with and without -r
            with_setup(gz(&["d"], a()), subdir),
            with_setup(gz(&["-q", "d"], a()), subdir),
            with_setup(gz(&["-f", "d"], a()), subdir),
            with_setup(gz(&["-c", "d"], a()), subdir),
            gz(&["-r", "d"], vec![("d/x.txt", t.clone())]),
            gz(&["-rv", "d/"], vec![("d/x.txt", t.clone())]),
            gz(
                &["-rq", "d"],
                vec![
                    ("d/x.txt", t.clone()),
                    ("d/y.txt", t.clone()),
                    ("d/s/z.txt", t.clone()),
                ],
            ),
            // unreadable and missing
            with_setup(gz(&["a.txt"], a()), unreadable),
            with_setup(gz(&["-c", "a.txt"], a()), unreadable),
            with_setup(gz(&["-f", "a.txt"], a()), unreadable),
            gz(&["nonexist"], a()),
            gz(&["-c", "nonexist"], a()),
            // a character device: not a regular file, unless -c
            gz(&["/dev/null"], a()),
            expect(gz(&["-c", "/dev/null"], a()), b""),
            // mode and times are copied onto the output
            with_setup(gz(&["a.txt"], a()), mode_640),
            with_setup(gz(&["-k", "a.txt"], a()), mode_640),
            // a time gzip cannot store: 0 in the header, and a warning
            with_setup(gz(&["a.txt"], a()), ancient),
            with_setup(gz(&["-v", "a.txt"], a()), ancient),
            with_setup(expect(gz(&["-c", "a.txt"], a()), &t), ancient),
            with_setup(gz(&["-q", "a.txt"], a()), ancient),
        ];
        // A terminal on standard input: the overwrite question.
        for answer in [&b"y\n"[..], b"n\n", b"Y\n", b"\n", b"yes\n"] {
            let mut c = gz(&["a.txt"], with_gz());
            c.stdin = Some(answer.to_vec());
            c.tty_stdin = true;
            cases.push(c);
        }
        let mut skipped = none_skipped();
        // NEWS 1.15: names with unusual characters are quoted (row 7).
        let q = |n: &'static str| vec![(n, t.clone())];
        let quoted = vec![
            gz(&["-v", "a b"], q("a b")),
            gz(&["a b.gz"], q("a b.gz")),
            gz(&["no such"], a()),
            gz(
                &["it's"],
                vec![("it's.gz", b"old".to_vec()), ("it's", t.clone())],
            ),
            gz(&["-c", "x=y", "a:b"], a()),
            with_setup(gz(&["e f"], a()), |d| {
                std::fs::create_dir(d.join("e f")).unwrap()
            }),
            gz(
                &["-S", " b", "a"],
                vec![("a", t.clone()), ("a b", b"old".to_vec())],
            ),
        ];
        let cases = gated(cases, quoted, (1, 15), "names are quoted", &mut skipped);
        check_all_skipping("files", &cases, skipped);
    }

    /// A terminal on standard output refuses standard input (and ends the
    /// run there), unless `-f`; files compressed with `-c` are written.
    #[test]
    fn terminal_stdout() {
        let t = kib_text();
        let a = || vec![("a.txt", t.clone())];
        let mut cases = Vec::new();
        // Empty input, so the bytes (identical in both: a two-byte body) pass
        // through the terminal unchanged.
        for args in [
            &[][..],
            &["-q"],
            &["-c"],
            &["-"],
            &["-f"],
            &["-cf", "-"],
            &["-", "a.txt"],
            &["-c", "-", "a.txt"],
            &["a.txt", "-"],
            &["-v", "-"],
        ] {
            let mut c = fed(gz(args, a()), b"");
            c.tty_stdout = true;
            if args.contains(&"-f") || args.contains(&"-cf") {
                c.expect_stdout_plain = Some(Vec::new());
            }
            cases.push(c);
        }
        check_all("terminal_stdout", &cases);
    }

    /// `$GZIP` in 1.14 and later: only `-1`..`-9`, `--fast`, `--best`,
    /// `--rsyncable` and `--synchronous` act; everything else, errors
    /// included, is ignored silently. 1.12 honours every option there
    /// (survey row 3), so the group is a documented skip on it.
    #[test]
    fn gzip_env() {
        let t = kib_text();
        let a = || vec![("a.txt", t.clone())];
        let mut env_cases = Vec::new();
        for v in [
            "-9",
            "-1",
            "--fast",
            "--best",
            "--fa",
            "-v -k",
            "-c",
            "-k9",
            "-x",
            "--bogus",
            "-1x9",
            "-- -1",
            "a.txt -1",
            "-S -1",
            "-Z",
            "-h",
            "-V",
            "-d",
            "  -1\t",
            "-n",
            "--rsyncable",
        ] {
            env_cases.push(with_env(gz(&["-v", "a.txt"], a()), "GZIP", v));
        }
        // The command line wins over the environment.
        env_cases.push(with_env(gz(&["-1", "a.txt"], a()), "GZIP", "-9"));
        env_cases.push(with_env(fed(gz(&["-c"], vec![]), &t), "GZIP", "-9"));
        let mut skipped = none_skipped();
        let cases = gated(
            Vec::new(),
            env_cases,
            (1, 14),
            "GZIP sets the level only",
            &mut skipped,
        );
        check_all_skipping("gzip_env", &cases, skipped);
    }

    /// Each name on standard input or an argument path that does not
    /// decompress; GNU's prefix is `gzip:` under every name (its `gunzip` and
    /// `zcat` are scripts running `gzip`). The scripts' own `--help` and
    /// `--version` (only as the first argument) are 1.15's text.
    /// Decompression itself is Task 8's.
    #[test]
    fn dispatch() {
        let t = kib_text();
        let a = || vec![("a.txt", t.clone())];
        let mut cases = vec![fed(gz(&[], a()), &t), fed(gz(&["-v"], a()), &t)];
        for name in ["gunzip", "zcat", "gzcat"] {
            for args in [
                &["-x"][..],
                &["--bogus"],
                &["-S", "", "a.txt"],
                &["-Z"],
                &["-b", "x"],
                &["-z", "a.txt"],
                &["-S"],
            ] {
                cases.push(case(name, args, a()));
            }
        }
        let mut texts = Vec::new();
        for name in ["gunzip", "zcat", "gzcat"] {
            for args in [
                &["--help"][..],
                &["--help", "-x"],
                &["--version"],
                &["--version", "--help"],
                &["-h"],
                &["--he"],
                &["-V"],
                &["-L"],
                &["-q", "--version"],
            ] {
                texts.push(case(name, args, a()));
            }
        }
        let mut skipped = none_skipped();
        let cases = gated(
            cases,
            texts,
            (1, 15),
            "help and version text is 1.15's",
            &mut skipped,
        );
        check_all_skipping("dispatch", &cases, skipped);
    }

    /// The one `-v` ratio both deflaters agree on: an empty input's body is
    /// two bytes in each, so 1.15's ` -Inf%` is compared exactly (1.12
    /// printed `0.0%`, survey row 9).
    #[test]
    fn ratio_of_an_empty_input_is_exact() {
        let cases = vec![
            gz(&["-v", "e"], vec![("e", vec![])]),
            gz(&["-cv", "e"], vec![("e", vec![])]),
            fed(gz(&["-v"], vec![]), b""),
        ];
        let mut skipped = none_skipped();
        let cases = gated(Vec::new(), cases, (1, 15), "-Inf%", &mut skipped);
        // No blanking here: a dedicated runner.
        for c in &cases {
            let Some(r) = reference(gnu_gzip_dir(), c) else {
                return;
            };
            let s = stuffr_as(c);
            assert!(r.stderr.contains(" -Inf%"), "{}", r.stderr);
            assert_same(c, &r, &s);
        }
        println!(
            "ratio_of_an_empty_input_is_exact: {} compared, {} skipped {}",
            cases.len(),
            skipped.count,
            skipped.why
        );
    }

    /// The ratio blanking touches only ratios.
    #[test]
    fn blanking_touches_only_ratios() {
        assert_eq!(
            blank_lines("a:\t 54.2% -- replaced with a.gz\n"),
            "a:\t<ratio>% -- replaced with a.gz\n"
        );
        assert_eq!(
            blank_lines("a:\t-200.0% -- created a.gz\n"),
            "a:\t<ratio>% -- created a.gz\n"
        );
        assert_eq!(blank_lines(" -Inf%\n"), "<ratio>%\n");
        assert_eq!(
            blank_lines("gzip: 12.5%: No such file\n"),
            "gzip: 12.5%: No such file\n"
        );
        assert_eq!(
            blank_lines("gzip: a.gz already exists;\tnot overwritten\n"),
            "gzip: a.gz already exists;\tnot overwritten\n"
        );
    }
}
