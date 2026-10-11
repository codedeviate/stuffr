//! Differential tests: stuffr invoked as `gzip`, `gunzip`, `zcat` and `gzcat`
//! with `STUFFR_GZIP_FLAVOR=gnu`, against the real GNU gzip (1.15 from the
//! Homebrew keg on macOS, the distribution's on Linux).
//!
//! Part 1 (0.12.0 Task 7): arguments, messages and compression. Part 2
//! (Task 8): decompression, `-t`, `-l` and `-r`, over inputs built here
//! (gzip members by hand over flate2's raw deflate, pack by a small
//! encoder, zip by hand, `.Z` by the system's `compress`), so both sides
//! read the same bytes and every ratio is compared exactly.
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

    /// Ruling T7-2: `-V`, `-L` and the scripts' `--version` print stuffr's
    /// own notice, not GNU's text, so their stdout is not compared byte for
    /// byte. When stuffr's first line names stuffr (`NAME (stuffr X) 1.15`),
    /// check the reference printed its version line, both stderrs are
    /// empty and stuffr's text has more than that line; then take the
    /// reference's stdout so `assert_same` compares everything else (exit
    /// code, stderr, files).
    fn version_text(r: &mut Run, s: &mut Run) {
        let Some(end) = s.stdout.iter().position(|&b| b == b'\n') else {
            return;
        };
        let ours = String::from_utf8_lossy(&s.stdout[..=end]).into_owned();
        let tag = format!(" (stuffr {}) 1.15\n", env!("CARGO_PKG_VERSION"));
        let Some(prog) = ours.strip_suffix(&tag) else {
            return;
        };
        let theirs = String::from_utf8_lossy(&r.stdout);
        let want = match prog {
            "gzip" => "gzip 1.15\n".to_owned(),
            p => format!("{} (gzip) 1.15\n", reference_name(p)),
        };
        assert!(
            theirs.starts_with(&want),
            "the reference's version: {theirs:?}"
        );
        assert!(
            s.stdout.len() > end + 1,
            "stuffr's notice is only its first line"
        );
        assert_eq!((r.stderr.as_str(), s.stderr.as_str()), ("", ""));
        s.stdout = r.stdout.clone();
    }

    // ---- the group runner ----

    fn none_skipped() -> Skipped {
        Skipped::none()
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
            skipped.add(
                newer.len(),
                &format!(
                    "{} on a {}.{} reference ({why}, {}.{}+)",
                    newer.len(),
                    version().0,
                    version().1,
                    min.0,
                    min.1
                ),
            );
        }
        cases
    }

    fn check_all(group: &str, cases: &[Case]) {
        check_all_skipping(group, cases, none_skipped());
    }

    /// Run every case against the reference and stuffr ([`run_group`]),
    /// blanking `-v`'s ratios.
    fn check_all_skipping(group: &str, cases: &[Case], skipped: Skipped) {
        check_all_with(group, cases, skipped, true);
    }

    /// [`check_all_skipping`] without blanking `-v`'s ratios: for
    /// decompression, whose inputs are the same bytes on both sides, so
    /// every ratio is compared exactly.
    fn check_exact(group: &str, cases: &[Case], skipped: Skipped) {
        check_all_with(group, cases, skipped, false);
    }

    fn check_all_with(group: &str, cases: &[Case], skipped: Skipped, blank: bool) {
        let one = |c: &Case| -> bool {
            let refc = renamed(c, reference_name(c.name));
            let Some(mut r) = reference(gnu_gzip_dir(), &refc) else {
                return false;
            };
            let mut s = stuffr_as(c);
            script_usage(&mut r);
            script_usage(&mut s);
            version_text(&mut r, &mut s);
            if blank {
                blank_both(&mut r, &mut s);
            }
            assert_same(c, &r, &s);
            true
        };
        run_group(group, cases, skipped, &one);
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
    fn setuid(d: &Path) {
        set_mode(d, "a.txt", 0o4755);
    }
    fn setuid_hard_linked(d: &Path) {
        setuid(d);
        hard_link_h(d);
    }
    fn sticky(d: &Path) {
        set_mode(d, "a.txt", 0o1644);
    }
    fn sticky_gz(d: &Path) {
        set_mode(d, "a.gz", 0o1644);
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
    /// output, exit 0, at the point they appear. Help is compared byte for
    /// byte; the version and licence are stuffr's own (Ruling T7-2), so
    /// only their first line, exit code and empty stderr are checked
    /// (`version_text`). Both need a 1.15 reference (help's text, the
    /// `gzip 1.15` line), so an older one is a documented skip.
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
        // Set-user-ID inputs are refused, `-f` or not; sticky ones unless
        // `-f` (which drops the sticky bit from the output); `-c` takes
        // both. Set-group-ID is left out: an ordinary user's chmod may not
        // set it (macOS clears it for a group the user is not in).
        cases.extend([
            with_setup(gz(&["a.txt"], a()), setuid),
            with_setup(gz(&["-f", "a.txt"], a()), setuid),
            with_setup(gz(&["-q", "a.txt"], a()), setuid),
            with_setup(gz(&["-k", "a.txt"], a()), setuid),
            with_setup(expect(gz(&["-c", "a.txt"], a()), &t), setuid),
            with_setup(gz(&["a.txt"], hard()), setuid_hard_linked),
            with_setup(gz(&["a.txt"], a()), sticky),
            with_setup(gz(&["-f", "a.txt"], a()), sticky),
            with_setup(gz(&["-q", "a.txt"], a()), sticky),
            with_setup(gz(&["-fq", "a.txt"], a()), sticky),
            with_setup(expect(gz(&["-c", "a.txt"], a()), &t), sticky),
            with_setup(gz(&["a.gz"], vec![("a.gz", t.clone())]), sticky_gz),
        ]);
        // An output that is a directory: under `-f` GNU unlinks it first,
        // which fails (`Operation not permitted` on macOS); the run goes on
        // (fix round 1).
        for args in [&["a.txt", "b.txt"][..], &["-f", "a.txt", "b.txt"]] {
            cases.push(gz(
                args,
                vec![
                    ("a.txt", t.clone()),
                    ("a.txt.gz/f", Vec::new()),
                    ("b.txt", t.clone()),
                ],
            ));
        }
        // Under `-r` the "already has a suffix" note needs `-v`.
        let tree = |extra: Vec<(&'static str, Vec<u8>)>| {
            let mut v = vec![("d/a.txt", t.clone()), ("d/b.gz", t.clone())];
            v.extend(extra);
            v
        };
        cases.extend([
            gz(&["-r", "d"], tree(vec![])),
            gz(&["-rv", "d"], tree(vec![])),
            gz(&["-r", "d"], tree(vec![("d/e/c.tgz", t.clone())])),
            gz(&["-r", "d"], tree(vec![("d/a.txt.gz", b"old".to_vec())])),
            gz(&["-r", "b.gz"], vec![("b.gz", t.clone())]),
            gz(&["-rv", "b.gz"], vec![("b.gz", t.clone())]),
            gz(&["-rf", "b.gz"], vec![("b.gz", t.clone())]),
            gz(
                &["-r", "a.txt", "b.gz"],
                vec![("a.txt", t.clone()), ("b.gz", t.clone())],
            ),
        ]);
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

    /// Ruling T7-3: the mask is narrow. A difference anywhere else on a
    /// `-v` line survives it, and `assert_same` still reports it.
    #[test]
    fn blanking_keeps_every_other_difference() {
        let base = "a:\t 54.2% -- replaced with a.gz\n";
        for other in [
            "a:\t 54.2% -- replaced with b.gz\n",
            "a:\t 54.2% -- created a.gz\n",
            "b:\t 54.2% -- replaced with a.gz\n",
            "a: 54.2% -- replaced with a.gz\n",
            "a:\t 54.2%% -- replaced with a.gz\n",
            "a:\t 54.2% -- replaced with a.gz\nextra\n",
            "a:\t 54.2 -- replaced with a.gz\n",
        ] {
            assert_ne!(blank_lines(base), blank_lines(other), "{other:?}");
        }
        // Only the number is masked: ratios of any value and width agree.
        assert_eq!(
            blank_lines(base),
            blank_lines("a:\t-133.3% -- replaced with a.gz\n")
        );
        // Through the whole comparison.
        let c = gz(&["-v", "a.txt"], vec![("a.txt", b"x".to_vec())]);
        let run = |err: &str| Run {
            code: 0,
            stdout: Vec::new(),
            stderr: err.to_owned(),
            tree: Tree::new(),
            start: now_secs(),
        };
        let (mut r, mut s) = (run(base), run("a:\t-12.0% -- replaced with b.gz\n"));
        blank_both(&mut r, &mut s);
        let res =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| assert_same(&c, &r, &s)));
        let msg = panic_text(res.expect_err("a different name must be caught"));
        assert!(
            msg.contains("stderr differs") && msg.contains("in 1 way(s)"),
            "{msg}"
        );
        let (mut r, mut s) = (run(base), run("a:\t-12.0% -- replaced with a.gz\n"));
        blank_both(&mut r, &mut s);
        assert_same(&c, &r, &s);
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

    // ======== part 2: decompression, -t, -l, -r (Task 8) ========

    // ---- fixtures: the harness's (`compat_harness`, shared with the BSD suite) ----

    /// The system `compress` (ncompress): Homebrew's keg on macOS (Apple's
    /// `/usr/bin/compress` is another program), `/usr/bin/compress` on
    /// Linux (CI installs `ncompress`).
    fn ref_compress(data: &[u8], args: &[&str]) -> Option<Vec<u8>> {
        let exe = if cfg!(target_os = "macos") {
            "/opt/homebrew/opt/ncompress/bin/compress"
        } else {
            "/usr/bin/compress"
        };
        filter_through(exe, args, data)
    }

    /// The reference gzip as a filter (`-c`, plus `args`).
    fn ref_gzip_c(data: &[u8], args: &[&str]) -> Option<Vec<u8>> {
        let mut a = vec!["-c"];
        a.extend_from_slice(args);
        filter_through(ref_gzip(), &a, data)
    }

    /// A decompression case: outputs are compared byte for byte.
    fn dz<'a>(name: &'a str, args: &[&'a str], files: Vec<(&'a str, Vec<u8>)>) -> Case<'a> {
        let mut c = case(name, args, files);
        c.compare_output_bytes = true;
        c
    }

    fn txt() -> Vec<u8> {
        text(20_000, 21)
    }

    // ---- groups ----

    /// Every name and suffix that decompresses (`.gz .z -gz -z _z .tgz
    /// .taz` in any case, `-S`'s), and an unknown one; an operand found by
    /// adding a suffix; `-N` (name and time restored), `-n` and neither;
    /// multi-member input; existing outputs; `-k`, `-f`, `-v`, `-q`.
    #[test]
    fn decompress() {
        let t = txt();
        let g = || gzm(&t, b"orig.txt");
        let mut cases = Vec::new();
        for (file, args) in [
            ("a.gz", &[][..]),
            ("a.z", &[]),
            ("a-gz", &[]),
            ("a-z", &[]),
            ("a_z", &[]),
            ("a.tgz", &[]),
            ("a.taz", &[]),
            ("a.GZ", &[]),
            ("a.Tgz", &[]),
            ("a_Z", &[]),
            ("a.x", &["-S", ".x"]),
            ("a.x", &["--suffix=.x"]),
            ("a.x", &[]),
            ("a.gzip", &[]),
            ("a.bz2", &[]),
            (".gz", &[]),
        ] {
            for name in ["gunzip", "gzip"] {
                let mut args = args.to_vec();
                if name == "gzip" {
                    args.insert(0, "-d");
                }
                args.push(file);
                cases.push(dz(name, &args, vec![(file, g())]));
            }
            cases.push(dz("zcat", &[file], vec![(file, g())]));
        }
        for args in [
            &["-d", "a.gz"][..],
            &["-dv", "a.gz"],
            &["-dq", "a.gz"],
            &["-dk", "a.gz"],
            &["-dkv", "a.gz"],
            &["-dN", "a.gz"],
            &["-dNv", "a.gz"],
            &["-dn", "a.gz"],
            &["-dnN", "a.gz"],
            &["-dNn", "a.gz"],
            &["-dc", "a.gz"],
            &["-dcv", "a.gz"],
            &["-dckv", "a.gz"],
            &["-dcN", "a.gz"],
            &["--decompress", "a.gz"],
            &["--uncompress", "a.gz"],
            &["--stdout", "-d", "a.gz"],
            &["-dq", "a.x"],
            &["-dv", "a.x"],
        ] {
            cases.push(dz("gzip", args, vec![("a.gz", g()), ("a.x", g())]));
        }
        for name in ["gunzip", "zcat", "gzcat"] {
            for args in [&["a.gz"][..], &["-v", "a.gz"], &["-N", "a.gz"], &["-"]] {
                cases.push(fed(dz(name, args, vec![("a.gz", g())]), &g()));
            }
        }
        // -N with a stored time, and with none (the input's is kept).
        let stamped = member(Member {
            name: Some(b"stamped.txt"),
            mtime: 1_234_567_890,
            ..plain_member(&t)
        });
        let unstamped = member(Member {
            name: Some(b"unstamped.txt"),
            ..plain_member(&t)
        });
        for args in [
            &["-dN", "s.gz"][..],
            &["-d", "s.gz"],
            &["-dkN", "s.gz", "u.gz"],
        ] {
            cases.push(dz(
                "gzip",
                args,
                vec![("s.gz", stamped.clone()), ("u.gz", unstamped.clone())],
            ));
        }
        // Several members: the first's name, the last stored time.
        let multi = [
            member(Member {
                name: Some(b"first"),
                mtime: 1_234_567_890,
                ..plain_member(b"one\n")
            }),
            member(Member {
                name: Some(b"second"),
                mtime: 1_300_000_000,
                ..plain_member(&t)
            }),
            member(plain_member(b"three\n")),
        ]
        .concat();
        for args in [
            &["-d", "m.gz"][..],
            &["-dN", "m.gz"],
            &["-dv", "m.gz"],
            &["-dc", "m.gz"],
        ] {
            cases.push(dz("gzip", args, vec![("m.gz", multi.clone())]));
        }
        cases.push(fed(dz("zcat", &[], vec![]), &multi));
        // An operand that does not exist is looked for with a suffix.
        for (args, files) in [
            (&["-d", "a"][..], vec![("a.gz", g())]),
            (&["-d", "a"], vec![("a.z", g())]),
            (&["-d", "a"], vec![("a-z", g())]),
            (&["-dc", "a"], vec![("a-gz", g())]),
            (
                &["-d", "-S", ".x", "a"],
                vec![("a.x", g()), ("a.gz", gzm(b"other", b"o"))],
            ),
            (&["-d", "a.tar"], vec![("a.tgz", g())]),
            (&["-d", "nonexist"], vec![]),
            (&["-dc", "nonexist"], vec![]),
            (&["-d", "-S", "z", "g"], vec![]),
            (&["-d", "x.gz"], vec![]),
            (&["-t", "a"], vec![("a.gz", g())]),
            (&["-l", "a"], vec![("a.gz", g())]),
        ] {
            cases.push(dz("gzip", args, files));
        }
        // An existing output.
        for args in [
            &["-d", "a.gz"][..],
            &["-df", "a.gz"],
            &["-dq", "a.gz"],
            &["-dv", "a.gz"],
            &["-dk", "a.gz"],
            &["-dN", "a.gz"],
        ] {
            cases.push(dz(
                "gzip",
                args,
                vec![
                    ("a.gz", g()),
                    ("a", b"old".to_vec()),
                    ("orig.txt", b"old".to_vec()),
                ],
            ));
        }
        for answer in [&b"y\n"[..], b"n\n"] {
            let mut c = dz(
                "gzip",
                &["-d", "a.gz"],
                vec![("a.gz", g()), ("a", b"old".to_vec())],
            );
            c.stdin = Some(answer.to_vec());
            c.tty_stdin = true;
            cases.push(c);
        }
        // Links and modes, as compression checks them.
        cases.extend([
            with_setup(
                dz("gzip", &["-d", "l.gz"], vec![("a.gz", g()), ("l.gz", g())]),
                |d| {
                    std::fs::remove_file(d.join("l.gz")).unwrap();
                    std::os::unix::fs::symlink("a.gz", d.join("l.gz")).unwrap();
                },
            ),
            with_setup(
                dz("gzip", &["-df", "l.gz"], vec![("a.gz", g()), ("l.gz", g())]),
                |d| {
                    std::fs::remove_file(d.join("l.gz")).unwrap();
                    std::os::unix::fs::symlink("a.gz", d.join("l.gz")).unwrap();
                },
            ),
            with_setup(
                dz("gzip", &["-d", "h.gz"], vec![("a.gz", g()), ("h.gz", g())]),
                |d| {
                    std::fs::remove_file(d.join("h.gz")).unwrap();
                    std::fs::hard_link(d.join("a.gz"), d.join("h.gz")).unwrap();
                },
            ),
            with_setup(dz("gzip", &["-d", "a.gz"], vec![("a.gz", g())]), |d| {
                set_mode(d, "a.gz", 0o640)
            }),
            with_setup(dz("gzip", &["-d", "a.gz"], vec![("a.gz", g())]), |d| {
                set_mode(d, "a.gz", 0o4755)
            }),
            with_setup(dz("gzip", &["-df", "a.gz"], vec![("a.gz", g())]), |d| {
                set_mode(d, "a.gz", 0o1644)
            }),
            with_setup(dz("gzip", &["-d", "d"], vec![("a.gz", g())]), subdir),
        ]);
        // An output that is a directory: refused, and under `-f` unlinked
        // first, which fails (fix round 1); the run goes on.
        for args in [
            &["-d", "a.gz", "b.gz"][..],
            &["-df", "a.gz", "b.gz"],
            &["-dfv", "a.gz", "b.gz"],
        ] {
            cases.push(dz(
                "gzip",
                args,
                vec![("a.gz", g()), ("a/f", Vec::new()), ("b.gz", g())],
            ));
        }
        check_exact("decompress", &cases, none_skipped());
    }

    /// Every row of the spec's divergence table, as GNU 1.15 behaves.
    #[test]
    fn probe_table() {
        let t = txt();
        let good = gzm(&t, b"a");
        let crc_bad = member_with(plain_member(&t), Some(0x1234_5678), None);
        let len_bad = member_with(plain_member(&t), None, Some(5));
        let cut = good[..good.len() / 2].to_vec();
        let cut_trailer = good[..good.len() - 3].to_vec();
        let junk = [good.clone(), b"junk".to_vec()].concat();
        let nuls = [good.clone(), vec![0; 100]].concat();
        let mixed_tail = [good.clone(), b"\0\0x".to_vec()].concat();
        let corrupt = {
            let mut b = member(plain_member(&t));
            b[10..14].copy_from_slice(&[0xff; 4]);
            b
        };
        let mut cases = Vec::new();
        for (file, bytes) in [
            ("junk.gz", &junk),
            ("nuls.gz", &nuls),
            ("mixed.gz", &mixed_tail),
            ("crc.gz", &crc_bad),
            ("len.gz", &len_bad),
            ("cut.gz", &cut),
            ("trailer.gz", &cut_trailer),
            ("corrupt.gz", &corrupt),
            ("notgz.gz", &t),
        ] {
            for args in [
                &["-dc"][..],
                &["-dcv"],
                &["-dcq"],
                &["-d"],
                &["-dv"],
                &["-dcf"],
            ] {
                let mut a = args.to_vec();
                a.push(file);
                cases.push(dz("gzip", &a, vec![(file, bytes.clone())]));
            }
            cases.push(fed(dz("zcat", &[], vec![]), bytes));
        }
        // An unknown option under each name.
        for name in ["gunzip", "zcat", "gzcat"] {
            cases.push(dz(name, &["-x", "a.gz"], vec![("a.gz", good.clone())]));
        }
        // A terminal on standard output: decompressed output is written.
        for (name, args) in [
            ("zcat", &["a.gz"][..]),
            ("gunzip", &["-c", "a.gz"]),
            ("gzip", &["-d"]),
        ] {
            let mut c = fed(
                dz(name, args, vec![("a.gz", gzm(b"hi there\n", b"a"))]),
                &good,
            );
            c.tty_stdout = true;
            cases.push(c);
        }
        // A terminal on standard input is refused under -d and -t (the run
        // stops there), unless -f; -l reads it.
        for (name, args) in [
            ("gunzip", &[][..]),
            ("gzip", &["-d"]),
            ("gzip", &["-dq"]),
            ("gzip", &["-t"]),
            ("zcat", &[]),
            ("gzip", &["-d", "-", "a.gz"]),
            ("gzip", &["-d", "nonexist", "-"]),
            ("gzip", &["-l"]),
            ("gzip", &["-d", "---presume-input-tty"]),
        ] {
            let mut c = dz(name, args, vec![("a.gz", good.clone())]);
            c.stdin = Some(Vec::new());
            c.tty_stdin = true;
            cases.push(c);
        }
        // `---presume-input-tty` refuses a pipe too, unless -f.
        cases.push(fed(
            dz("gzip", &["-d", "---presume-input-tty"], vec![]),
            &good,
        ));
        cases.push(fed(
            dz("gzip", &["-df", "---presume-input-tty"], vec![]),
            &good,
        ));
        let mut skipped = none_skipped();
        // `-l` on two members: 1.12 and 1.13 report the last member only
        // (survey row 1).
        let two = [good.clone(), gzm(b"second\n", b"b")].concat();
        let lists = vec![
            dz("gzip", &["-l", "two.gz"], vec![("two.gz", two.clone())]),
            dz("gzip", &["-lv", "two.gz"], vec![("two.gz", two.clone())]),
        ];
        let cases = gated(cases, lists, (1, 14), "-l on several members", &mut skipped);
        check_exact("probe_table", &cases, skipped);
    }

    /// The formats GNU's `gunzip` reads besides gzip: `.Z`, pack, the first
    /// entry of a zip (stored or deflated), the old gzip magic; and the
    /// ones it refuses (`.bz2`, `.xz`, `.zst`, other zip methods,
    /// encryption). LZH is a documented gap (`lzh_is_a_documented_gap`).
    #[test]
    fn foreign_formats() {
        let t = txt();
        let Some(z) = ref_compress(&t, &["-c"]) else {
            return;
        };
        let z12 = ref_compress(&t, &["-c", "-b12"]).unwrap();
        let mut zbad = z.clone();
        zbad[3] = 0xff;
        zbad[4] = 0xff;
        let mut zbits = z.clone();
        zbits[2] = (zbits[2] & 0xe0) | 17;
        let mut zflags = z.clone();
        zflags[2] |= 0x60;
        let zcut = z[..z.len() / 3].to_vec();
        let p = pack(&t);
        let mut p_long = p.clone();
        p_long[5] ^= 1;
        let p_cut = p[..p.len() / 2].to_vec();
        // Apple decodes this table as BAAAAAAA; GNU finds too few leaves.
        let p_apple = b"\x1f\x1e\x00\x00\x00\x08\x03\x01\x00\x00AB\x80".to_vec();
        let p_many = b"\x1f\x1e\x00\x00\x00\x01\x02\x01\x01ABC\x00".to_vec();
        let p_levels = b"\x1f\x1e\x00\x00\x00\x01\x1a".to_vec();
        let p_junk = [p.clone(), b"junk".to_vec()].concat();
        let p_two = [p.clone(), pack(b"again\n")].concat();
        let stored = zip1(&t, 0, 0);
        let deflated = zip1(&t, 8, 0);
        let two = zip(&[
            ZipEntry {
                name: b"one",
                data: &t,
                method: 8,
                flags: 0,
            },
            ZipEntry {
                name: b"two",
                data: b"second entry\n",
                method: 8,
                flags: 0,
            },
        ]);
        let encrypted = zip1(&t, 8, 1);
        let bzip2_method = zip1(&t, 12, 0);
        let empty_entry = zip1(b"", 8, 0);
        let mut zip_crc = deflated.clone();
        zip_crc[14] ^= 0xff;
        let zip_cut = deflated[..deflated.len() / 3].to_vec();
        let old = member(Member {
            magic2: 0x9e,
            name: Some(b"old"),
            ..plain_member(&t)
        });
        let gz_then = |tail: &[u8]| [gzm(b"first\n", b"f"), tail.to_vec()].concat();
        let mut cases = Vec::new();
        let inputs: Vec<(&str, Vec<u8>)> = vec![
            ("a.Z", z.clone()),
            ("b12.Z", z12),
            ("bad.Z", zbad),
            ("bits.Z", zbits),
            ("flags.Z", zflags),
            ("cut.Z", zcut),
            ("p.z", p.clone()),
            ("long.z", p_long),
            ("cut.z", p_cut),
            ("apple.z", p_apple),
            ("many.z", p_many),
            ("levels.z", p_levels),
            ("junk.z", p_junk),
            ("two.z", p_two),
            ("stored.zip", stored),
            ("deflated.zip", deflated),
            ("two.zip", two),
            ("enc.zip", encrypted),
            ("bz.zip", bzip2_method),
            ("empty.zip", empty_entry),
            ("crc.zip", zip_crc),
            ("cut.zip", zip_cut),
            ("old.gz", old),
            ("gzZ.gz", gz_then(&z)),
            ("gzp.gz", gz_then(&p)),
            ("gzzip.gz", gz_then(&zip1(b"x", 8, 0))),
            ("a.bz2", b"BZh91AY&SY\x00\x00\x00\x00".to_vec()),
            ("a.xz", b"\xfd7zXZ\x00\x00\x04\xe6\xd6\xb4\x46".to_vec()),
            ("a.zst", b"\x28\xb5\x2f\xfd\x00\x00\x00\x00".to_vec()),
        ];
        for (file, bytes) in &inputs {
            for args in [
                &["-dc"][..],
                &["-dcv"],
                &["-t"],
                &["-l"],
                &["-lv"],
                &["-dcf"],
            ] {
                let mut a = args.to_vec();
                a.push(file);
                cases.push(dz("gzip", &a, vec![(file, bytes.clone())]));
            }
            cases.push(fed(dz("zcat", &[], vec![]), bytes));
        }
        // To a file, where the suffix allows it.
        for (args, file) in [
            (&["-d"][..], "a.Z"),
            (&["-dv"], "a.Z"),
            (&["-d"], "bad.Z"),
            (&["-d"], "bits.Z"),
            (&["-dk"], "bits.Z"),
            (&["-d"], "flags.Z"),
            (&["-d"], "p.z"),
            (&["-d"], "long.z"),
            (&["-d", "-S", ".zip"], "deflated.zip"),
            (&["-dv", "-S", ".zip"], "two.zip"),
            (&["-d", "-S", ".zip"], "enc.zip"),
            (&["-d"], "old.gz"),
            (&["-dN"], "old.gz"),
        ] {
            let mut a = args.to_vec();
            a.push(file);
            let bytes = inputs.iter().find(|(n, _)| *n == file).unwrap().1.clone();
            cases.push(dz("gzip", &a, vec![(file, bytes), ("z.gz", gzm(&t, b"z"))]));
            // And a good file after it: whether the run went on.
            let mut b = a.clone();
            b.push("z.gz");
            let bytes = inputs.iter().find(|(n, _)| *n == file).unwrap().1.clone();
            cases.push(dz("gzip", &b, vec![(file, bytes), ("z.gz", gzm(&t, b"z"))]));
        }
        let mut skipped = none_skipped();
        // NEWS 1.15: zip data descriptors and the "not a valid zip file"
        // wording (survey row 6); `-Inf%` for an empty output (row 9).
        let newer = vec![
            dz("gzip", &["-dc", "dd.zip"], vec![("dd.zip", zip1(&t, 8, 8))]),
            dz(
                "gzip",
                &["-dc", "dds.zip"],
                vec![("dds.zip", zip1(&t, 0, 8))],
            ),
            dz(
                "gzip",
                &["-dc", "pk.zip"],
                vec![("pk.zip", b"PK\x03\x04".to_vec())],
            ),
            dz("gzip", &["-dcv", "e.zip"], vec![("e.zip", zip1(b"", 8, 0))]),
        ];
        let cases = gated(cases, newer, (1, 15), "zip data descriptors", &mut skipped);
        check_exact("foreign_formats", &cases, skipped);
    }

    /// LZH (`1f a0`, `compress -H`) has no decoder in stuffr: GNU decodes
    /// it, stuffr says "not in gzip format" (a first member) or reports
    /// trailing garbage (a later one). Reference-free: this pins the gap.
    #[test]
    fn lzh_is_a_documented_gap() {
        let lzh = [&[0x1f, 0xa0][..], &[0u8; 20]].concat();
        let c = dz("gzip", &["-dc", "a.lzh"], vec![("a.lzh", lzh.clone())]);
        let s = stuffr_as(&c);
        assert_eq!(s.code, 1);
        assert_eq!(s.stderr, "\ngzip: a.lzh: not in gzip format\n");
        assert!(s.stdout.is_empty());
        let after = [gzm(b"hi\n", b"h"), lzh].concat();
        let c = dz("gzip", &["-dc", "b.gz"], vec![("b.gz", after)]);
        let s = stuffr_as(&c);
        assert_eq!(s.code, 2);
        assert_eq!(s.stdout, b"hi\n");
        assert_eq!(
            s.stderr,
            "\ngzip: b.gz: decompression OK, trailing garbage ignored\n"
        );
    }

    /// `-t` on good, bad, cut-short and trailing-garbage inputs, alone and
    /// several at once (a CRC error does not stop `-t`; a cut-short input
    /// does).
    #[test]
    fn test_option() {
        let t = txt();
        let good = gzm(&t, b"a");
        let crc = member_with(plain_member(&t), Some(1), None);
        let cut = good[..good.len() / 2].to_vec();
        let junk = [good.clone(), b"junk".to_vec()].concat();
        let notgz = t.clone();
        let all = || {
            vec![
                ("good.gz", good.clone()),
                ("crc.gz", crc.clone()),
                ("cut.gz", cut.clone()),
                ("junk.gz", junk.clone()),
                ("notgz", notgz.clone()),
            ]
        };
        let mut cases = Vec::new();
        for f in ["good.gz", "crc.gz", "cut.gz", "junk.gz", "notgz"] {
            for args in [&["-t"][..], &["-tv"], &["-tq"], &["--test"], &["-tf"]] {
                let mut a = args.to_vec();
                a.push(f);
                cases.push(dz("gzip", &a, all()));
            }
            let bytes = all().into_iter().find(|(n, _)| *n == f).unwrap().1;
            cases.push(fed(dz("gzip", &["-tv"], vec![]), &bytes));
        }
        for args in [
            &["-tv", "good.gz", "crc.gz", "junk.gz", "notgz", "good.gz"][..],
            &["-t", "good.gz", "cut.gz", "good.gz"],
            &["-tv", "good.gz", "nonexist", "good.gz"],
            &["-tv", "-", "good.gz"],
            &["-tv", "good.gz", "-"],
        ] {
            cases.push(fed(dz("gzip", args, all()), &junk));
        }
        for name in ["gunzip", "zcat"] {
            cases.push(dz(name, &["-tv", "good.gz", "crc.gz"], all()));
        }
        check_exact("test_option", &cases, none_skipped());
    }

    /// `-l`, `-lv`, `-lq`: single and several inputs, standard input, a
    /// file that is not gzip, inputs that do not decode cleanly (no line;
    /// totals instead), `-N`'s name and time, and a member whose ISIZE lies
    /// (as a size past 4 GiB would read): GNU decodes, so it is a length
    /// error, not a wrong figure.
    #[test]
    fn list() {
        let t = txt();
        let good = gzm(&t, b"stored-name");
        let small = member(Member {
            name: Some(b"s"),
            mtime: 1_234_567_890,
            ..plain_member(b"x")
        });
        // The brief's ">4 GiB ISIZE wraparound", made cheap. A true
        // wraparound needs a member over 4 GiB, whose ISIZE (length mod
        // 2^32) is honest, and GNU 1.12+ lists the decoded count, not the
        // field; decoding 4 GiB per side is too slow for this suite. Any
        // member small enough to build has length < 2^32, so the only way
        // to make ISIZE disagree with the data is to make it lie, and
        // len + 1 is the smallest lie: it pins that GNU (and stuffr)
        // decode and report a length error instead of trusting the field.
        let lies = member_with(plain_member(&t), None, Some(t.len() as u32 + 1));
        let crc = member_with(plain_member(&t), Some(1), None);
        let junk = [small.clone(), b"junk".to_vec()].concat();
        let nuls = [small.clone(), vec![0; 10]].concat();
        let files = || {
            vec![
                ("good.gz", good.clone()),
                ("small.gz", small.clone()),
                ("lies.gz", lies.clone()),
                ("crc.gz", crc.clone()),
                ("junk.gz", junk.clone()),
                ("nuls.gz", nuls.clone()),
                ("plain", t.clone()),
                ("d/x.tgz", good.clone()),
            ]
        };
        let mut cases = Vec::new();
        for flags in [
            &["-l"][..],
            &["-lv"],
            &["-lq"],
            &["-lN"],
            &["-lvN"],
            &["--list"],
        ] {
            for ops in [
                &["good.gz"][..],
                &["small.gz"],
                &["good.gz", "small.gz"],
                &["lies.gz"],
                &["crc.gz"],
                &["good.gz", "crc.gz", "small.gz"],
                &["junk.gz"],
                &["good.gz", "junk.gz"],
                &["good.gz", "nuls.gz", "small.gz"],
                &["nuls.gz", "good.gz"],
                &["plain"],
                &["plain", "good.gz"],
                &["good.gz", "nonexist"],
                &["d/x.tgz"],
                &["good.gz", "-"],
                &["-", "good.gz", "small.gz"],
            ] {
                let mut a = flags.to_vec();
                a.extend_from_slice(ops);
                cases.push(fed(dz("gzip", &a, files()), &small));
            }
            cases.push(fed(dz("gzip", flags, vec![]), &good));
        }
        for name in ["gunzip", "zcat"] {
            cases.push(dz(name, &["-l", "good.gz", "small.gz"], files()));
        }
        // Standard input that fails: refused at its header, the run stops;
        // later, it is not listed and prints no totals of its own.
        for stdin in [&t, &junk, &crc] {
            for args in [
                &["-l", "good.gz", "-", "small.gz"][..],
                &["-l", "-", "good.gz"],
            ] {
                cases.push(fed(dz("gzip", args, files()), stdin));
            }
        }
        check_exact("list", &cases, none_skipped());
    }

    /// `-r` over a tree of plain files, `.gz` files, a symbolic link to a
    /// file and one to a directory: compressed (`gzip -r`, compared by
    /// round trip) and decompressed (`gunzip -r`, byte for byte), and
    /// `-t`/`-l`/`-c` under `-r` (which skip names without a suffix, except
    /// `-c`).
    #[test]
    fn recursive() {
        let t = txt();
        let tree = || {
            vec![
                ("d/a.gz", gzm(&t, b"a")),
                ("d/b.txt", b"plain\n".to_vec()),
                ("d/s/c.gz", gzm(b"see\n", b"c")),
                ("d/s/t.tgz", gzm(b"tar\n", b"t")),
                ("e/x.gz", gzm(b"ex\n", b"x")),
                ("e/y.txt", b"why\n".to_vec()),
            ]
        };
        fn links(d: &Path) {
            std::os::unix::fs::symlink("a.gz", d.join("d/l.gz")).unwrap();
            std::os::unix::fs::symlink("../e", d.join("d/ld")).unwrap();
        }
        let mut cases = Vec::new();
        for args in [
            &["-dr", "d"][..],
            &["-drv", "d"],
            &["-drk", "d"],
            &["-drf", "d"],
            &["-tr", "d"],
            &["-trv", "d"],
            &["-lr", "d"],
            &["-lrv", "d"],
            &["-dcr", "d/s"],
            &["-dr", "d/b.txt"],
            &["-drv", "d/b.txt"],
            &["-dr", "d", "e"],
            &["-dr", "e/x"],
        ] {
            cases.push(with_setup(dz("gzip", args, tree()), links));
            cases.push(dz("gzip", args, tree()));
        }
        cases.push(with_setup(dz("gunzip", &["-r", "d"], tree()), links));
        // Compressing the same tree (`.gz` files skipped silently, links
        // refused); the outputs are compared by round trip.
        for args in [&["-r", "d"][..], &["-rv", "d"]] {
            let mut c = with_setup(dz("gzip", args, tree()), links);
            c.compare_output_bytes = false;
            cases.push(c);
        }
        check_exact("recursive", &cases, none_skipped());
    }

    /// Review focus 1: `gunzip -N` never writes outside the operand's
    /// directory. A stored `../x`, `/tmp/stuffr-escape-<pid>` or `a/b` is
    /// written as its last component beside the input, as GNU does; both
    /// trees must agree and the absolute target must not exist afterwards.
    #[test]
    fn a_header_name_with_a_path_never_escapes_the_directory() {
        let escape = format!("/tmp/stuffr-escape-{}", std::process::id());
        let _ = std::fs::remove_file(&escape);
        let t = txt();
        let names: [&[u8]; 3] = [b"../x", escape.as_bytes(), b"a/b"];
        let mut cases = Vec::new();
        for stored in names {
            let m = member(Member {
                name: Some(stored),
                mtime: 1_234_567_890,
                ..plain_member(&t)
            });
            for args in [
                &["-dN", "s/in.gz"][..],
                &["-dNv", "s/in.gz"],
                &["-dNk", "s/in.gz"],
                &["-dNf", "s/in.gz"],
                &["-lN", "s/in.gz"],
            ] {
                cases.push(dz("gzip", args, vec![("s/in.gz", m.clone())]));
            }
            cases.push(dz("gunzip", &["-N", "in.gz"], vec![("in.gz", m.clone())]));
        }
        // Names with no last component (fix round 1). GNU's base of an
        // all-slash name is empty, so the output is the operand's
        // directory; under `-f` it unlinks what is there first and reports
        // that failure (`Operation not permitted` for a directory on
        // macOS), never writing anywhere.
        for (stored, args, op) in [
            (&b"/"[..], &["-dN"][..], "s/in.gz"),
            (b"/", &["-dNf"], "s/in.gz"),
            (b"//", &["-dN"], "s/in.gz"),
            (b"", &["-dNf"], "s/in.gz"),
            (b"", &["-dNfv"], "s/in.gz"),
            (b".", &["-dNf"], "a.gz"),
            (b"..", &["-dNf"], "a.gz"),
            (b"..", &["-dNfv"], "a.gz"),
            (b"..", &["-dN"], "a.gz"),
        ] {
            let m = member(Member {
                name: Some(stored),
                ..plain_member(&t)
            });
            let mut a = args.to_vec();
            a.push(op);
            cases.push(dz("gzip", &a, vec![(op, m)]));
        }
        check_exact("header_name_escape", &cases, none_skipped());
        assert!(
            !Path::new(&escape).exists(),
            "{escape} was written outside the directory"
        );
        // And on stuffr's side alone, whatever the reference did.
        for stored in names {
            let m = member(Member {
                name: Some(stored),
                ..plain_member(b"payload\n")
            });
            let c = dz("gzip", &["-dN", "s/in.gz"], vec![("s/in.gz", m)]);
            let s = stuffr_as(&c);
            assert_eq!(s.code, 0, "{}", s.stderr);
            let last = stored.rsplit(|&b| b == b'/').next().unwrap();
            let want = format!("s/{}", String::from_utf8_lossy(last));
            let keys: Vec<&String> = s.tree.keys().collect();
            assert_eq!(keys, [&"s/".to_owned(), &want], "{stored:?}");
        }
        assert!(!Path::new(&escape).exists());
    }

    /// Ruling T8-4: under `-dNf`, a stored name equal to the input's own
    /// makes GNU replace the input with the output and then remove it, so
    /// both are lost. stuffr prints what GNU prints and exits as it does,
    /// but never removes the input when the published output is the input,
    /// so the decoded file survives. Streams compared with GNU; the file is
    /// asserted on stuffr's side.
    #[test]
    fn a_stored_name_equal_to_the_input_keeps_the_output() {
        let t = txt();
        let m = gzm(&t, b"a.gz");
        for args in [&["-dNf", "a.gz"][..], &["-dNfv", "a.gz"]] {
            let c = dz("gzip", args, vec![("a.gz", m.clone())]);
            let s = stuffr_as(&c);
            if let Some(r) = reference(gnu_gzip_dir(), &c) {
                assert_eq!(
                    (r.code, &r.stdout, &r.stderr),
                    (s.code, &s.stdout, &s.stderr)
                );
                assert!(r.tree.is_empty(), "GNU kept {:?}", r.tree.keys());
            }
            assert_eq!(s.code, 0, "{}", s.stderr);
            assert_eq!(s.tree.len(), 1, "{:?}", s.tree.keys());
            assert_eq!(s.tree["a.gz"].0, t, "the decoded file must survive");
        }
    }

    /// Ruling T8-5: the same with a corrupt or cut-short body. GNU unlinks
    /// the existing output (the input itself) before decoding, so the
    /// failure leaves nothing. stuffr prints and exits as GNU does but
    /// skips that unlink when the output is the input, so the input
    /// survives unchanged.
    #[test]
    fn a_corrupt_input_named_by_its_own_stored_name_survives() {
        let t = txt();
        let good = gzm(&t, b"a.gz");
        let crc = member_with(
            Member {
                name: Some(b"a.gz"),
                ..plain_member(&t)
            },
            Some(1),
            None,
        );
        let cut = good[..good.len() / 2].to_vec();
        for bytes in [crc, cut] {
            for args in [&["-dNf", "a.gz"][..], &["-dNfv", "a.gz"]] {
                let c = dz("gzip", args, vec![("a.gz", bytes.clone())]);
                let s = stuffr_as(&c);
                if let Some(r) = reference(gnu_gzip_dir(), &c) {
                    assert_eq!(
                        (r.code, &r.stdout, &r.stderr),
                        (s.code, &s.stdout, &s.stderr)
                    );
                    assert!(r.tree.is_empty(), "GNU kept {:?}", r.tree.keys());
                }
                assert_eq!(s.code, 1, "{}", s.stderr);
                assert_eq!(s.tree.len(), 1, "{:?}", s.tree.keys());
                assert_eq!(s.tree["a.gz"].0, bytes, "the input must survive unchanged");
            }
        }
    }

    /// Review focus 2: `gunzip a.gz b.gz c.gz` with `b.gz` corrupt keeps
    /// `b.gz`, leaves no partial `b`, and exits with the worst code. GNU
    /// ends the run at a CRC error or a cut-short input (so `c.gz` is left
    /// alone) and goes on after one that is not gzip.
    #[test]
    fn a_corrupt_input_leaves_no_output_and_keeps_the_input() {
        let t = txt();
        let good = gzm(&t, b"a");
        let crc = member_with(plain_member(&t), Some(1), None);
        let cut = good[..good.len() * 2 / 3].to_vec();
        let mut cases = Vec::new();
        let mut middles = Vec::new();
        for (what, bytes) in [("crc", crc), ("cut", cut), ("notgz", t.clone())] {
            middles.push((what, bytes.clone()));
            for args in [
                &["-d"][..],
                &["-dv"],
                &["-dk"],
                &["-df"],
                &["-dq"],
                &["-t"],
                &["-dc"],
            ] {
                let mut a = args.to_vec();
                a.extend(["a.gz", "b.gz", "c.gz"]);
                cases.push(dz(
                    "gzip",
                    &a,
                    vec![
                        ("a.gz", good.clone()),
                        ("b.gz", bytes.clone()),
                        ("c.gz", good.clone()),
                    ],
                ));
            }
        }
        check_exact("corrupt_middle", &cases, none_skipped());
        // stuffr alone: the corrupt input is intact and has no output, no
        // temporary file is left, and `a` was written whole.
        for (what, bytes) in middles {
            let c = dz(
                "gzip",
                &["-d", "a.gz", "b.gz", "c.gz"],
                vec![
                    ("a.gz", good.clone()),
                    ("b.gz", bytes.clone()),
                    ("c.gz", good.clone()),
                ],
            );
            let s = stuffr_as(&c);
            assert_eq!(s.code, 1, "{what}: {}", s.stderr);
            assert_eq!(s.tree["b.gz"].0, bytes, "{what}: b.gz changed");
            assert!(!s.tree.contains_key("b"), "{what}: a partial b was left");
            assert_eq!(s.tree["a"].0, t, "{what}");
            assert!(
                s.tree.keys().all(|k| !k.contains(".stuffr-")),
                "{what}: a temporary file was left: {:?}",
                s.tree.keys()
            );
        }
    }

    /// Review focus 3: `zcat` streams a 64 MiB input in bounded memory
    /// (0.11.0's `bzcat_streams_a_large_input` measurement, shared through
    /// the harness). The decoder holds a 64 KiB window, a 64 KiB input
    /// buffer and a 64 KiB output buffer whatever the size; 64 MiB is the
    /// ceiling (the output alone would exceed it if it were held).
    #[test]
    fn zcat_streams_a_large_input() {
        const N: usize = 64 << 20;
        let plain = mixed(N, 43);
        let Some(z) = ref_gzip_c(&plain, &["-1"]) else {
            return;
        };
        let peak = decoder_peak_rss(
            "zcat",
            "big.gz",
            &z,
            &plain,
            &[("STUFFR_GZIP_FLAVOR", "gnu")],
        );
        assert!(
            peak < 64 << 20,
            "peak memory {peak} bytes is not under 64 MiB"
        );
    }

    /// Review focus 3, fix rounds 1 and 2: notes are said as they arise,
    /// never collected per input. 750,000 empty-body members, each with an
    /// empty FEXTRA (22 bytes apiece, 16.5 MB), once kept a 16-byte note
    /// per member until the input ended; GNU 1.15 decodes such a stream in
    /// about 2 MiB. Measured on macOS (`/usr/bin/time -l`, debug build, two
    /// runs each): before the fix 18.0 and 19.4 MiB, after it 7.9 MiB both
    /// times (the suite's other children peak near 8.8 MiB, which
    /// `getrusage` also counts). The 13 MiB bound leaves at least 4 MiB on
    /// either side. At 500,000 members the gap was 14.7-16.0 against 7.9,
    /// too narrow for a 3 MiB margin both ways.
    #[test]
    fn zcat_of_many_extra_field_members_is_bounded() {
        const MEMBERS: usize = 750_000;
        let one: [u8; 22] = [
            0x1f, 0x8b, 8, 4, 0, 0, 0, 0, 0, 3, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let input = one.repeat(MEMBERS);
        let peak = decoder_peak_rss(
            "zcat",
            "many.gz",
            &input,
            b"",
            &[("STUFFR_GZIP_FLAVOR", "gnu")],
        );
        assert!(
            peak < 24 << 20,
            "peak memory {peak} bytes is not under 24 MiB"
        );
    }

    /// Run `exe big.gz` with standard output a pipe whose read end is
    /// closed after the first read; how the process ended. Standard error
    /// must stay empty.
    fn closed_pipe_status(exe: &Path, dir: &Path) -> std::process::ExitStatus {
        use std::io::Read;
        use std::process::{Command, Stdio};
        let mut child = Command::new(exe)
            .arg("big.gz")
            .current_dir(dir)
            .env_clear()
            .env("PATH", gnu_path())
            .env("STUFFR_GZIP_FLAVOR", "gnu")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = child.stdout.take().unwrap();
        let mut buf = [0u8; 4096];
        let _ = out.read(&mut buf).unwrap();
        drop(out);
        let st = child.wait().unwrap();
        let mut err = String::new();
        let _ = child.stderr.take().unwrap().read_to_string(&mut err);
        assert_eq!(err, "", "{exe:?} wrote to stderr");
        st
    }

    /// Review focus 3: `zcat big.gz | head` ends stuffr by SIGPIPE, with
    /// nothing on standard error, as it ends GNU's (whose `zcat` execs
    /// `gzip`, so the signal is the process's own).
    #[test]
    fn zcat_into_a_closed_pipe() {
        use std::os::unix::process::ExitStatusExt;
        let plain = text(4 << 20, 53);
        let dir = std::env::temp_dir().join(format!("stuffr-zcat-pipe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        let link = dir.join("bin").join("zcat");
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stuffr"), &link).unwrap();
        std::fs::write(dir.join("big.gz"), gzm(&plain, b"big")).unwrap();
        let ours = closed_pipe_status(&link, &dir);
        assert_eq!(
            ours.signal(),
            Some(libc::SIGPIPE),
            "stuffr as zcat: {ours:?}"
        );
        let reference = Path::new(gnu_gzip_dir()).join("zcat");
        if require_reference(&reference) {
            let theirs = closed_pipe_status(&reference, &dir);
            assert_eq!(
                theirs.signal(),
                Some(libc::SIGPIPE),
                "reference: {theirs:?}"
            );
        } else {
            println!("skipped the reference half: GNU zcat not installed");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Review focus 5: an empty file, a member with an empty body, a member
    /// followed by an empty one, an empty one followed by a member, and a
    /// member with FEXTRA, FCOMMENT and FHCRC (also with a wrong FHCRC),
    /// through `-d`, `-t` and `-l`.
    #[test]
    fn odd_members() {
        let t = txt();
        let empty_body = member(plain_member(b""));
        let all_fields = member(Member {
            name: Some(b"n"),
            comment: Some(b"a comment"),
            extra: Some(b"AB\x02\x00xy"),
            hcrc: true,
            mtime: 1_234_567_890,
            ..plain_member(&t)
        });
        let mut bad_hcrc = all_fields.clone();
        let at = 10 + 2 + 6 + 2 + 10; // fixed, XLEN, extra, "n\0", comment
        bad_hcrc[at] ^= 0xff;
        let inputs: Vec<(&str, Vec<u8>)> = vec![
            ("empty.gz", Vec::new()),
            ("ebody.gz", empty_body.clone()),
            ("cat.gz", [gzm(&t, b"a"), empty_body.clone()].concat()),
            ("cat2.gz", [empty_body.clone(), gzm(&t, b"a")].concat()),
            ("fields.gz", all_fields),
            ("badhcrc.gz", bad_hcrc),
        ];
        let mut cases = Vec::new();
        let mut later = Vec::new();
        for (file, bytes) in &inputs {
            for args in [
                &["-d"][..],
                &["-dv"],
                &["-dc"],
                &["-dcv"],
                &["-dN"],
                &["-t"],
                &["-tv"],
            ] {
                let mut a = args.to_vec();
                a.push(file);
                let c = dz("gzip", &a, vec![(file, bytes.clone())]);
                // An empty output's ratio is `-Inf%` (1.15, survey row 9).
                if *file == "ebody.gz" && args.iter().any(|a| a.contains('v')) {
                    later.push(c);
                } else {
                    cases.push(c);
                }
            }
            for args in [&["-l"][..], &["-lv"]] {
                let mut a = args.to_vec();
                a.push(file);
                // -l on several members (row 1) or an empty output (row 9).
                later.push(dz("gzip", &a, vec![(file, bytes.clone())]));
            }
            cases.push(fed(dz("zcat", &[], vec![]), bytes));
        }
        let mut skipped = none_skipped();
        let cases = gated(cases, later, (1, 15), "-l of these, -Inf%", &mut skipped);
        check_exact("odd_members", &cases, skipped);
    }
}
