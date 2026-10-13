//! The zstd compatibility family against zstd 1.5.7: stuffr invoked as
//! `zstd`, `unzstd`, `zstdcat` and `zstdmt`, compared with the reference
//! (stdout, stderr, exit code, the file tree) through `compat_harness`,
//! every case under `LC_ALL=C`.
//!
//! Part 1 (Task 4): the argument surface. Options refused and their
//! messages, the help texts, `-V`, `ZSTD_CLEVEL`/`ZSTD_NBTHREADS`, and every
//! option accepted. An accepted option is compared both through a run that
//! stops after the whole command line is read ([`STOP`] adds `-D` and
//! `--patch-from` together, which zstdcli.c refuses after parsing, the
//! thread count, the level limit and the console checks, so every warning
//! on the way is compared too) and compressing for real.
//!
//! Part 2 (Task 5): compressing. Every level over six inputs; the thread
//! and parameter options; standard streams, existing outputs and the
//! overwrite prompt at a terminal (R14), links, directories, `-o`, the
//! output directories and `--filelist`; Review Focus 2; SIGINT (R6).
//!
//! The normalisations: the banner (`-V`, `-H`, `-v`'s welcome line),
//! which names stuffr (spec deviation 1; checked exactly before it is
//! masked); in `-H` the reference's benchmark section and `--trace` line,
//! which a `ZSTD_NOBENCH`/`ZSTD_NOTRACE` build does not print (R13;
//! `strip_bench_help` removes exactly those blocks); and `-vv`'s timing
//! fields (spec deviation 2, `normalise_zstd_progress`). On the C tier the
//! compressed bytes are compared exactly; on the pure tier (spec deviation
//! 7) they are judged by the reference decoding them, and the
//! tier's own figures are blanked (`pure_tier_*`). The texts of the refused
//! benchmark and trace options, which the reference accepts, are pinned by
//! `cli.rs`'s unit tests.

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod unix {
    use super::compat_harness::*;

    /// The C tier promises zstd's frames byte for byte; the pure tier's are
    /// judged by the reference decoding them (spec deviation 7).
    const EXACT: bool = cfg!(feature = "zstd-c");

    fn ref_zstd() -> &'static str {
        static P: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        P.get_or_init(|| format!("{}/zstd", zstd_dir().unwrap_or("/nonexistent")))
    }

    fn text() -> Vec<u8> {
        b"the quick brown fox jumps over the lazy dog\n".repeat(40)
    }

    // ---- cases ----

    fn case<'a>(name: &'a str, args: &[&'a str]) -> Case<'a> {
        Case {
            name,
            args: args.to_vec(),
            files: vec![("a", text()), ("d", text()), ("p", text())],
            stdin: None,
            tty_stdin: false,
            tty_stdout: false,
            env: vec![("LC_ALL", "C")],
            compare_output_bytes: EXACT,
            expect_stdout_plain: None,
            setup: None,
            roundtrip: Roundtrip::Zstd {
                ref_zstd: ref_zstd(),
            },
        }
    }

    fn zstd<'a>(args: &[&'a str]) -> Case<'a> {
        case("zstd", args)
    }

    fn with_env<'a>(mut c: Case<'a>, k: &'a str, v: &'a str) -> Case<'a> {
        c.env.push((k, v));
        c
    }

    fn fed<'a>(mut c: Case<'a>, stdin: Vec<u8>) -> Case<'a> {
        c.stdin = Some(stdin);
        c
    }

    /// Appended to a command line, ends the run once every option is
    /// read: zstdcli.c refuses `-D` with `--patch-from` (exit 1) after the
    /// thread count, the console checks and the level limit.
    const STOP: [&str; 4] = ["-D", "d", "--patch-from=p", "a"];

    /// `args` followed by [`STOP`].
    fn stopped<'a>(name: &'a str, args: &[&'a str]) -> Case<'a> {
        let mut all = args.to_vec();
        all.extend(STOP);
        case(name, &all)
    }

    // ---- normalisation ----

    /// zstdcli.c's `WELCOME_MESSAGE`, as the reference prints it.
    const REFERENCE_BANNER: &str = "*** Zstandard CLI (64-bit) v1.5.7, by Yann Collet ***\n";

    /// Spec deviation 1: stuffr's banner.
    fn our_banner() -> String {
        format!(
            "*** Zstandard CLI (stuffr {}; zstd 1.5.7 compatible) (64-bit) v1.5.7, by Yann Collet ***\n",
            env!("CARGO_PKG_VERSION")
        )
    }

    /// Each side's banner, exactly, becomes `<banner>`: a banner where the
    /// other side has none, or a banner that is not exactly the expected
    /// one, still differs.
    fn mask_banners(r: &mut Run, s: &mut Run) {
        let ours = our_banner();
        let mask = |t: &str, banner: &str| t.replace(banner, "<banner>\n");
        r.stderr = mask(&r.stderr, REFERENCE_BANNER);
        s.stderr = mask(&s.stderr, &ours);
        if let Ok(t) = std::str::from_utf8(&r.stdout) {
            r.stdout = mask(t, REFERENCE_BANNER).into_bytes();
        }
        if let Ok(t) = std::str::from_utf8(&s.stdout) {
            s.stdout = mask(t, &ours).into_bytes();
        }
    }

    /// Run every case against the reference and stuffr.
    fn check(group: &str, cases: &[Case]) {
        let one = |c: &Case| -> bool {
            let Some(dir) = zstd_dir() else { return false };
            let Some(mut r) = reference(dir, c) else {
                return false;
            };
            let mut s = stuffr_as(c);
            if pure_dictionary_refusal(c, &r, &s) {
                return true;
            }
            pure_tier_frames(c, &r, &mut s);
            pure_tier_error_names(&mut r);
            // R13: the reference's `-H` lists the benchmark and `--trace`.
            if let Ok(t) = std::str::from_utf8(&r.stdout) {
                r.stdout = strip_bench_help(t).into_bytes();
            }
            mask_banners(&mut r, &mut s);
            // Spec deviation 2: `-vv`'s "Completed in" timing fields.
            r.stderr = normalise_zstd_progress(&r.stderr);
            s.stderr = normalise_zstd_progress(&s.stderr);
            pure_tier_sizes(&mut r, &mut s);
            assert_same(c, &r, &s);
            true
        };
        run_group(group, cases, Skipped::none(), &one);
    }

    /// Spec deviation 7 on the pure tier: the compressed sizes and ratios
    /// in the summaries are those of stuffr's own frames, so on both sides
    /// they become `<ratio>` and `<size>` (the input size, the names and
    /// every other byte still compared). Nothing changes on the C tier.
    fn pure_tier_sizes(r: &mut Run, s: &mut Run) {
        if !EXACT {
            r.stderr = blank_compressed_sizes(&r.stderr);
            s.stderr = blank_compressed_sizes(&s.stderr);
        }
    }

    /// Whether `c` compresses with a dictionary or a prefix (`-D`,
    /// `--patch-from`).
    fn compresses_with_dictionary(c: &Case) -> bool {
        let words = c.args.iter().take_while(|a| **a != "--");
        let mut dict = false;
        for a in words {
            if *a == "-D" || a.starts_with("--patch-from") {
                dict = true;
            }
            if matches!(
                *a,
                "-d" | "-t" | "-l" | "--decompress" | "--test" | "--list"
            ) {
                return false;
            }
        }
        dict && c.name != "unzstd" && c.name != "zstdcat"
    }

    /// Spec deviation 7 on the pure tier: compressing with `-D` or
    /// `--patch-from` is refused (`EXM_THROW(1)`) where the reference's
    /// dictionary would be loaded, after everything it prints before
    /// compressing. True when `c` is such a case (and the expectation was
    /// checked); never on the C tier, nor when the reference refuses.
    fn pure_dictionary_refusal(c: &Case, r: &Run, s: &Run) -> bool {
        // A run the reference refuses before compressing is compared as
        // any other.
        if EXACT || r.code != 0 || !compresses_with_dictionary(c) {
            return false;
        }
        let want = format!(
            "{}zstd: error 1 : dictionary compression is not available in this build (stuffr pure tier) \n",
            r.stderr
        );
        assert_eq!(
            (s.code, s.stderr.as_str()),
            (1, want.as_str()),
            "{:?}",
            c.args
        );
        assert!(s.stdout.is_empty(), "{:?}: stdout written", c.args);
        true
    }

    /// Spec deviation 7 on the pure tier: a compressed output (standard
    /// output, or a file) whose bytes differ from the reference's is judged
    /// by the reference decoding both; the same text makes them equal for
    /// the comparison, whatever the name (the harness alone judges only the
    /// names it can map back to an input). Nothing changes on the C tier,
    /// where the bytes are promised.
    fn pure_tier_frames(c: &Case, r: &Run, s: &mut Run) {
        if EXACT {
            return;
        }
        let same = |ours: &[u8], theirs: &[u8]| {
            !ours.is_empty()
                && ours != theirs
                && matches!(
                    (ref_decompress_case(c, ours), ref_decompress_case(c, theirs)),
                    (Ok(a), Ok(b)) if a == b
                )
        };
        if same(&s.stdout, &r.stdout) {
            s.stdout = r.stdout.clone();
        }
        for (name, (rb, _, _)) in &r.tree {
            if let Some((sb, _, _)) = s.tree.get_mut(name)
                && same(sb, rb)
            {
                *sb = rb.clone();
            }
        }
    }

    /// Spec deviation 7 on the pure tier: where a corrupt frame fails in
    /// libzstd's block decoder on its output buffer, the pure tier's
    /// decoder (`ruzstd`, its own checks) names the corruption instead.
    /// Measured on `decompress_frames`' `windowbit` input (a stream frame
    /// with its single-segment flag set: the window shrinks to a one-byte
    /// content size). The reference's name becomes the pure tier's; the
    /// rest of the run is compared as usual.
    fn pure_tier_error_names(r: &mut Run) {
        if !EXACT {
            r.stderr = r.stderr.replace(
                "Decoding error (36) : Destination buffer is too small",
                "Decoding error (36) : Data corruption detected",
            );
        }
    }

    /// fileio.c's summary lines with the ratio and compressed size blanked:
    /// `NAME :RATIO%   (IN => OUT, DST) ` and `N files compressed : RATIO%
    /// (IN => OUT)`.
    fn blank_compressed_sizes(stderr: &str) -> String {
        let mut out = String::with_capacity(stderr.len());
        for line in stderr.split_inclusive('\n') {
            let blanked = (|| {
                let pct = line.find("%   (").or_else(|| {
                    line.find(" files compressed : ")
                        .and_then(|at| line[at..].find("% (").map(|p| at + p))
                })?;
                let colon = line[..pct].rfind(':')?;
                let arrow = pct + line[pct..].find(" => ")?;
                let end = arrow
                    + line[arrow..]
                        .find(", ")
                        .or_else(|| line[arrow..].find(')'))?;
                Some(format!(
                    "{}<ratio>{}<size>{}",
                    &line[..=colon],
                    &line[pct..arrow + 4],
                    &line[end..]
                ))
            })();
            out.push_str(&blank_progress(blanked.as_deref().unwrap_or(line)));
        }
        out
    }

    /// The pure tier's own compressed figures elsewhere: the progress
    /// line's ` ==> N%`, and `-vvvv`'s `output generated N bytes`.
    fn blank_progress(line: &str) -> String {
        let mut out = String::new();
        let mut rest = line;
        for (head, tail) in [(" ==> ", "%"), ("output generated ", " bytes")] {
            while let Some(at) = rest.find(head) {
                let after = &rest[at + head.len()..];
                let Some(end) = after.find(tail) else { break };
                if !after[..end].trim().bytes().all(|b| b.is_ascii_digit()) {
                    break;
                }
                out.push_str(&rest[..at + head.len()]);
                out.push_str("<n>");
                rest = &after[end..];
            }
        }
        out.push_str(rest);
        out
    }

    // ---- flags: refused ----

    /// Options the reference refuses, each with its message and exit 1, and
    /// nothing written: unknown options, numbers that overflow or carry
    /// junk, missing and separated arguments, malformed parameter strings.
    #[test]
    fn flags_refused() {
        let cases: Vec<Case> = [
            // Unknown.
            &["-Y"][..],
            &["--frob"],
            &["--frob=1"],
            &["-qY"],
            &["-qqY"],
            &["-vY"],
            &["-kY", "a"],
            &["-T5x"],
            &["-Mx"],
            &["-1KiBx"],
            &["-Y", "-h"],
            &["--best"],
            &["--no-name"],
            &["--fastx"],
            &["--fast=0"],
            &["--longx"],
            &["--long5"],
            &["--train-coverx"],
            &["--format=bz2"],
            &["--rsyncable=1"],
            &["--ultra=1"],
            // Overflow.
            &["-T99999999999"],
            &["-M99999999999"],
            &["-99999999999"],
            &["-4294967296"],
            &["-5000000K"],
            &["-4096M"],
            &["--memory=99999999999"],
            &["--memory=4096M"],
            &["--threads=4294967296"],
            &["--block-size=99999999999999999999"],
            &["--stream-size=18446744073709551616"],
            &["--fast=99999999999"],
            &["--long=99999999999"],
            &["--zstd=wlog=99999999999"],
            &["--adapt=min=99999999999"],
            &["--train-cover=k=99999999999"],
            &["-qq", "-T99999999999"],
            // Junk after a number.
            &["--memory=1Q"],
            &["--memory=1KBx"],
            &["--threads=x"],
            &["--block-size=1Q"],
            &["--stream-size=1x"],
            &["--size-hint=1 "],
            &["--target-compressed-block-size=x"],
            &["--maxdict=x"],
            &["--dictID=1x"],
            // Missing and separated arguments.
            &["-o"],
            &["-ofoo"],
            &["-o", "-c"],
            &["-D"],
            &["-Dfoo"],
            &["--memory"],
            &["--memory", "-5"],
            &["--memlimit-decompress=5"],
            &["--threads"],
            &["--block-size"],
            &["--maxdict"],
            &["--dictID"],
            &["--stream-size"],
            &["--size-hint"],
            &["--target-compressed-block-size"],
            &["--output-dir-flat"],
            &["--output-dir-mirror"],
            &["--auto-threads"],
            &["--auto-threads", "-T0"],
            &["--filelist"],
            &["--patch-from"],
            &["-qq", "-o"],
            // Empty output directories.
            &["--output-dir-flat="],
            &["--output-dir-mirror="],
            &["--output-dir-flat", ""],
            // Malformed parameter strings.
            &["--zstd="],
            &["--zstd=foo=1"],
            &["--zstd=wlog=1,"],
            &["--zstd=wlog=x"],
            &["--zstd=wlog"],
            &["-vv", "--zstd=foo=1"],
            &["--adapt="],
            &["--adapt=min=5,max=1"],
            &["--adapt=lo=1"],
            &["--adapt=min=1x"],
            &["-vv", "--adapt=min=5,max=1"],
            &["--train-cover=x"],
            &["--train-cover=k=1,"],
            &["--train-cover=f=2"],
            &["--train-cover=shrinkx"],
            &["--train-fastcover=accel=x"],
            &["--train-legacy=x"],
            &["--train-legacy=s=5x"],
            // fileio.c's setters after the arguments: FIO_setBlockSize takes
            // `(int)blockSize`, so 4 GiB is no block size and 4 GiB + 1 is
            // one; adapt and rsyncable refuse a single thread (EXM_THROW).
            &["--single-thread", "--block-size=4294967296", "--adapt", "a"],
            &["--single-thread", "--block-size=4294967297", "--adapt", "a"],
            &["--single-thread", "-B1K", "--zstd=ovlog=3", "--adapt", "a"],
            &["--single-thread", "--rsyncable", "a"],
            &["--single-thread", "-B1K", "--rsyncable"],
            // `-p` pauses after a refusal (zstdcli.c's `_end`), not after
            // an overflow (`exit`).
            &["-p", "--frob"],
            &["-p", "-T99999999999"],
        ]
        .iter()
        .map(|a| zstd(a))
        .collect();
        check("flags_refused", &cases);
    }

    // ---- help and version ----

    #[test]
    fn help_and_version() {
        let mut cases: Vec<Case> = [
            &["-h"][..],
            &["-H"],
            &["--help"],
            &["-V"],
            &["--version"],
            &["-vV"],
            &["-qV"],
            &["-qqV"],
            &["-Vv"],
            &["-hV"],
            &["-Vh"],
            &["-q", "-h"],
            &["-qq", "-H"],
            &["-v", "-H"],
            &["-19", "-H"],
            &["-h", "--frob"],
            &["a", "-h"],
            &["-p", "-h"],
        ]
        .iter()
        .map(|a| zstd(a))
        .collect();
        for name in ["unzstd", "zstdcat", "zstdmt"] {
            for args in [&["-h"][..], &["-H"], &["-V"], &["-vV"], &["-qV"]] {
                cases.push(case(name, args));
            }
        }
        check("help_and_version", &cases);
    }

    /// The reference's `-vvV` lines naming the libraries it links (zlib,
    /// lz4, lzma), in order, removed when present whole: ruling T4-a keeps
    /// them out of stuffr's output and its POSIX lines in.
    fn strip_library_lines(stdout: &str) -> String {
        let lines: Vec<&str> = stdout.split_inclusive('\n').collect();
        let at = lines.windows(3).position(|w| {
            w[0].starts_with("zlib version ")
                && w[1].starts_with("lz4 version ")
                && w[2].starts_with("lzma version ")
        });
        match at {
            Some(i) => [&lines[..i], &lines[i + 3..]].concat().concat(),
            None => stdout.to_owned(),
        }
    }

    /// `-vvV` under every name: everything but the three library lines.
    #[test]
    fn verbose_version_without_the_library_lines() {
        let mut cases: Vec<Case> = Vec::new();
        for name in ["zstd", "unzstd", "zstdcat", "zstdmt"] {
            cases.push(case(name, &["-vvV"]));
            cases.push(case(name, &["-vvvV"]));
        }
        let one = |c: &Case| -> bool {
            let Some(dir) = zstd_dir() else { return false };
            let Some(mut r) = reference(dir, c) else {
                return false;
            };
            let mut s = stuffr_as(c);
            let text = String::from_utf8(r.stdout.clone()).unwrap();
            if c.name != "zstdcat" {
                assert!(text.contains("zlib version "), "{text}");
            }
            r.stdout = strip_library_lines(&text).into_bytes();
            mask_banners(&mut r, &mut s);
            assert_same(c, &r, &s);
            true
        };
        run_group(
            "verbose_version_without_the_library_lines",
            &cases,
            Skipped::none(),
            &one,
        );
    }

    /// The help texts and `-V` differ from the reference by exactly what
    /// R13 and spec deviation 1 say, checked without the comparison's
    /// normalisation.
    #[test]
    fn help_differs_only_by_the_bench_section_and_the_banner() {
        let Some(dir) = zstd_dir() else { return };
        let c = zstd(&["-H"]);
        let Some(r) = reference(dir, &c) else { return };
        let s = stuffr_as(&c);
        let reference = String::from_utf8(r.stdout).unwrap();
        assert!(reference.contains(ZSTD_BENCH_HELP) && reference.contains(ZSTD_TRACE_HELP));
        let want = strip_bench_help(&reference).replacen(REFERENCE_BANNER, &our_banner(), 1);
        assert_eq!(String::from_utf8(s.stdout).unwrap(), want);
        let c = zstd(&["-qV"]);
        assert_eq!(stuffr_as(&c).stdout, b"1.5.7\n");
        let c = zstd(&["-vV"]);
        let s = String::from_utf8(stuffr_as(&c).stdout).unwrap();
        assert_eq!(
            s,
            format!(
                "{}*** supports: zstd, zstd legacy v0.5+, gzip, lz4, lzma, xz \n",
                our_banner()
            )
        );
    }

    // ---- the environment ----

    #[test]
    fn environment() {
        let mut cases: Vec<Case> = Vec::new();
        for v in [
            "19",
            "-5",
            "+3",
            "abc",
            "99",
            "",
            " 3",
            "3x",
            "-",
            "99999999999",
            "4294967295",
        ] {
            cases.push(with_env(zstd(&["-h"]), "ZSTD_CLEVEL", v));
            cases.push(with_env(zstd(&["-q", "-V"]), "ZSTD_CLEVEL", v));
        }
        // The level limit's warning, ZSTD_CLEVEL above 19.
        for v in ["99", "20", "19", "-99999"] {
            cases.push(with_env(
                zstd(&["-d", "--show-default-cparams"]),
                "ZSTD_CLEVEL",
                v,
            ));
        }
        // ZSTD_NBTHREADS is read after the arguments, for a default count.
        for v in ["2", "x", "99999999999", "", "0", "3x"] {
            cases.push(with_env(stopped("zstd", &[]), "ZSTD_NBTHREADS", v));
            cases.push(with_env(stopped("zstd", &["-vvvv"]), "ZSTD_NBTHREADS", v));
            cases.push(with_env(stopped("zstd", &["-q"]), "ZSTD_NBTHREADS", v));
            cases.push(with_env(stopped("zstd", &["-T1"]), "ZSTD_NBTHREADS", v));
            cases.push(with_env(stopped("zstd", &["-d"]), "ZSTD_NBTHREADS", v));
        }
        cases.push(with_env(zstd(&["--adapt"]), "ZSTD_NBTHREADS", "0"));
        check("environment", &cases);
    }

    /// ZSTD_CLEVEL and ZSTD_NBTHREADS compressing.
    #[test]
    fn environment_compressing() {
        let mut cases: Vec<Case> = Vec::new();
        for v in ["19", "-5", "abc", "99", "1"] {
            cases.push(with_env(fed(zstd(&[]), text()), "ZSTD_CLEVEL", v));
            cases.push(with_env(zstd(&["-k", "a"]), "ZSTD_CLEVEL", v));
        }
        for v in ["2", "x", "99999999999", "0"] {
            cases.push(with_env(fed(zstd(&["-vv"]), text()), "ZSTD_NBTHREADS", v));
        }
        check("environment_compressing", &cases);
    }

    // ---- flags: accepted ----

    /// Every option in `zstd -H`, and the hidden ones, alone; each run
    /// stops at [`STOP`] once the command line is read.
    #[test]
    fn flags_parse() {
        let mut cases: Vec<Case> = Vec::new();
        for args in ACCEPTED {
            cases.push(stopped("zstd", args));
        }
        for name in ["unzstd", "zstdcat", "zstdmt"] {
            cases.push(stopped(name, &[]));
            cases.push(stopped(name, &["-v"]));
        }
        check("flags_parse", &cases);
    }

    /// The options of `zstd -H` and the hidden ones zstdcli.c accepts,
    /// each spelled the ways it can be.
    const ACCEPTED: &[&[&str]] = &[
        &["-o", "out"],
        &["-o=out"],
        &["-k"],
        &["--keep"],
        &["--rm"],
        &["-1"],
        &["-19"],
        &["-20"],
        &["-22"],
        &["-1000"],
        &["-3000000000"],
        &["-1K"],
        &["-d"],
        &["--decompress"],
        &["--uncompress"],
        &["-z"],
        &["--compress"],
        &["-t"],
        &["--test"],
        &["-f"],
        &["--force"],
        &["-c"],
        &["--stdout"],
        &["-v"],
        &["-vv"],
        &["-vvv"],
        &["-vvvv"],
        &["-q"],
        &["-qq"],
        &["--verbose"],
        &["--quiet"],
        &["--progress"],
        &["--no-progress"],
        &["--asyncio"],
        &["--no-asyncio"],
        &["--check"],
        &["--no-check"],
        &["-C"],
        &["--ultra"],
        &["--ultra", "-20"],
        &["--ultra", "-23"],
        &["--fast"],
        &["--fast=5"],
        &["--fast=99999999"],
        &["--fast=5x"],
        &["--adapt"],
        &["--adapt=min=1,max=19"],
        &["--adapt=max=3"],
        &["--long"],
        &["--long=27"],
        &["--long=31"],
        &["--long=x"],
        &["-T0"],
        &["-T0", "-vvvv"],
        &["-T0", "--auto-threads=logical", "-vvvv"],
        &["-T0", "--auto-threads", "physical", "-vvvv"],
        &["-T0", "--single-thread", "-vvvv"],
        &["-T1"],
        &["-T4"],
        &["-T", "-vvvv"],
        &["-T4294967295", "-vvvv"],
        &["--threads=2"],
        &["--threads", "2"],
        &["--single-thread"],
        &["-B1K"],
        &["-B4"],
        &["--block-size=1K"],
        &["--rsyncable"],
        &["--exclude-compressed"],
        &["--stream-size=10"],
        &["--size-hint=100"],
        &["--target-compressed-block-size=1K"],
        &["--no-dictID"],
        &["--compress-literals"],
        &["--no-compress-literals"],
        &["--row-match-finder"],
        &["--no-row-match-finder"],
        &["--format=zstd"],
        &["--format=gzip"],
        &["--format=xz"],
        &["--format=lzma"],
        &["--format=lz4"],
        &["--mmap-dict"],
        &["--no-mmap-dict"],
        &["-M10"],
        &["-M"],
        &["--memory=10M"],
        &["--memory", "10MiB"],
        &["--memory="],
        &["--memlimit=1KB"],
        &["--sparse"],
        &["--no-sparse"],
        &["--pass-through"],
        &["--no-pass-through"],
        &["--content-size"],
        &["--no-content-size"],
        &["--show-default-cparams"],
        &[
            "--zstd=windowLog=20,chainLog=16,hashLog=17,searchLog=1,minMatch=5,targetLength=0,strategy=2",
        ],
        &["--zstd=wlog=20,clog=16,hlog=17,slog=1,mml=5,tlen=8,strat=9"],
        &["--zstd=overlapLog=3,ldmHashLog=20,ldmMinMatch=32,ldmBucketSizeLog=4,ldmHashRateLog=6"],
        &["--zstd=ovlog=3,lhlog=20,lmml=32,lblog=4,lhrlog=6"],
        &["--zstd=strat=12"],
        &["--max"],
        &["--priority=rt"],
        &["-n"],
        &["-S"],
        &["-s5"],
        &["-P50"],
        &["-p5"],
        &["-p"],
        &["--output-dir-flat=o"],
        &["--output-dir-flat", "o"],
        &["--output-dir-mirror=o"],
        &["--maxdict=4K"],
        &["--dictID=5"],
        &["--fake-stdin-is-console"],
        &["--fake-stdout-is-console"],
        &["--fake-stderr-is-console"],
        // Aggregated.
        &["-19kfcqv"],
        &["-dkT2"],
        &["-1kM5v"],
        &["-3kM5kT2"],
        &["-T2M"],
        &["-1K2"],
        &["-cdfkvvq"],
        &["-zt"],
        &["-of", "out"],
    ];

    /// `--format=` for the foreign formats, which Task 6 brings.
    fn foreign_format(args: &[&str]) -> bool {
        args.iter()
            .any(|a| a.starts_with("--format=") && *a != "--format=zstd")
    }

    /// Every accepted option compressing (or decompressing) for real, but
    /// the foreign formats (below).
    #[test]
    fn flags_accepted() {
        let mut cases: Vec<Case> = Vec::new();
        for args in ACCEPTED.iter().filter(|a| !foreign_format(a)) {
            cases.push(fed(zstd(args), text()));
            let mut with_file = args.to_vec();
            with_file.extend(["-k", "a"]);
            cases.push(zstd(&with_file));
        }
        // `--` makes the rest operands, `-h` and STOP's words included.
        cases.push(zstd(&["-k", "--", "-h", "a"]));
        cases.push(zstd(&["-k", "--", "-x"]));
        check("flags_accepted", &cases);
    }

    /// The `--format=` options of [`ACCEPTED`] for gzip, xz, lzma and lz4.
    #[test]
    #[ignore = "Task 6 (formats.rs)"]
    fn flags_accepted_foreign_formats() {
        let mut cases: Vec<Case> = Vec::new();
        for args in ACCEPTED.iter().filter(|a| foreign_format(a)) {
            cases.push(fed(zstd(args), text()));
            let mut with_file = args.to_vec();
            with_file.extend(["-k", "a"]);
            cases.push(zstd(&with_file));
        }
        check("flags_accepted_foreign_formats", &cases);
    }

    /// The level limit's warning, compressing.
    #[test]
    fn levels_above_19_warn() {
        let cases: Vec<Case> = [
            &["-20"][..],
            &["-22"],
            &["--ultra", "-20"],
            &["--ultra", "-23"],
            &["--long", "-22"],
            &["--patch-from=p", "-22"],
            &["--max"],
        ]
        .iter()
        .map(|a| fed(zstd(a), text()))
        .collect();
        check("levels_above_19_warn", &cases);
    }

    // ---- --show-default-cparams ----

    /// `--show-default-cparams` refused when decompressing.
    #[test]
    fn show_default_cparams_refused_decompressing() {
        let cases: Vec<Case> = [
            &["-d", "--show-default-cparams"][..],
            &["-d", "--show-default-cparams", "a"],
            &["--show-default-cparams", "-dq"],
            &["--show-default-cparams", "-dqq"],
        ]
        .iter()
        .map(|a| zstd(a))
        .collect();
        check("show_default_cparams_refused_decompressing", &cases);
    }

    /// The spec's levels and sizes (1, 3, 19, 22; `--ultra`, `--long`,
    /// `--patch-from` and `-D`).
    #[test]
    fn show_default_cparams() {
        let sized = |name: &'static str, n: usize| (name, vec![b'x'; n]);
        let mut cases: Vec<Case> = Vec::new();
        for level in ["-1", "-3", "-19", "--fast=5"] {
            cases.push(fed(zstd(&["--show-default-cparams", level]), text()));
            let mut c = zstd(&["--show-default-cparams", level, "-c", "s1", "s200k", "s1m"]);
            c.files = vec![
                sized("s1", 1),
                sized("s200k", 200_000),
                sized("s1m", 1 << 20),
            ];
            cases.push(c);
        }
        for args in [
            &["--show-default-cparams", "--ultra", "-22", "-c", "s1m"][..],
            &["--show-default-cparams", "--long", "-c", "s1m"],
            &[
                "--show-default-cparams",
                "--patch-from=d",
                "-19",
                "-c",
                "s1m",
            ],
            &["--show-default-cparams", "-D", "d", "-c", "s1m"],
            &["--show-default-cparams", "-D", "missing", "-c", "s1m"],
        ] {
            let mut c = zstd(args);
            c.files = vec![sized("s1m", 1 << 20), sized("d", 112_640)];
            cases.push(c);
        }
        check("show_default_cparams", &cases);
    }

    // ---- names ----

    /// Each of the four names over standard input.
    #[test]
    fn names_on_stdin() {
        let Some(dir) = zstd_dir() else { return };
        let packed = std::process::Command::new(format!("{dir}/zstd"))
            .args(["-c", "/dev/null"])
            .output()
            .unwrap()
            .stdout;
        let cases = vec![
            fed(case("zstd", &[]), text()),
            fed(case("zstdmt", &[]), text()),
            fed(case("unzstd", &[]), packed.clone()),
            fed(case("zstdcat", &[]), packed),
            fed(case("zstdcat", &[]), text()),
        ];
        check("names_on_stdin", &cases);
    }

    // ==== part 2 (Task 5): compressing, decompressing and testing ====

    use std::fs;
    use std::path::Path;

    /// A case over `files` only.
    fn with_files<'a>(name: &'a str, args: &[&'a str], files: Vec<(&'a str, Vec<u8>)>) -> Case<'a> {
        let mut c = case(name, args);
        c.files = files;
        c
    }

    fn with_setup<'a>(mut c: Case<'a>, setup: fn(&Path)) -> Case<'a> {
        c.setup = Some(setup);
        c
    }

    fn on_tty<'a>(mut c: Case<'a>, typed: &[u8]) -> Case<'a> {
        c.tty_stdin = true;
        c.stdin = Some(typed.to_vec());
        c
    }

    /// `data` compressed by the reference with `args` (empty when there is
    /// no reference; every case then skips).
    fn packed(args: &[&str], data: &[u8]) -> Vec<u8> {
        if zstd_dir().is_none() {
            return Vec::new();
        }
        let mut a = args.to_vec();
        a.push("-c");
        filter_through(ref_zstd(), &a, data).unwrap_or_default()
    }

    /// The level catalogue: `--fast=5`, -3 (`--fast=3`), 1-19, and
    /// `--ultra` 20 and 22.
    fn levels() -> Vec<Vec<&'static str>> {
        const DIGITS: [&str; 19] = [
            "-1", "-2", "-3", "-4", "-5", "-6", "-7", "-8", "-9", "-10", "-11", "-12", "-13",
            "-14", "-15", "-16", "-17", "-18", "-19",
        ];
        let mut v = vec![vec!["--fast=5"], vec!["--fast=3"]];
        v.extend(DIGITS.iter().map(|d| vec![*d]));
        v.push(vec!["--ultra", "-20"]);
        v.push(vec!["--ultra", "-22"]);
        v
    }

    /// The inputs: empty, 1 B, 1 KiB of text, 1 MiB mixed, 1 MiB random,
    /// 4 MiB repetitive.
    fn inputs() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("empty", Vec::new()),
            ("one", b"x".to_vec()),
            ("text", super::compat_harness::text(1024, 11)),
            ("mixed", mixed(1 << 20, 12)),
            ("random", random(1 << 20, 13)),
            ("rep", repetitive(4 << 20)),
        ]
    }

    // ---- compressing ----

    /// Every level over every input, file to file (`-k`, the summary
    /// printed).
    #[test]
    fn compress_levels() {
        let mut cases = Vec::new();
        for (name, data) in inputs() {
            for level in levels() {
                let mut a = level.clone();
                a.extend(["-k", name]);
                cases.push(with_files("zstd", &a, vec![(name, data.clone())]));
            }
        }
        check("compress_levels", &cases);
    }

    /// The thread options, file to file and standard input to standard
    /// output, and `zstdmt`.
    #[test]
    fn compress_threads() {
        let data = mixed(1 << 20, 21);
        let mut cases = Vec::new();
        for args in [
            &["-T1"][..],
            &["-T4"],
            &["-T0"],
            &["-T0", "--auto-threads=logical"],
            &["--single-thread"],
            &["-T2", "-19"],
            &[],
        ] {
            let mut a = args.to_vec();
            a.extend(["-k", "m"]);
            cases.push(with_files("zstd", &a, vec![("m", data.clone())]));
            cases.push(fed(zstd(args), data.clone()));
            cases.push(fed(case("zstdmt", args), data.clone()));
        }
        check("compress_threads", &cases);
    }

    /// The parameter options, file to file and from standard input, and
    /// `--stream-size` right and wrong.
    #[test]
    fn compress_parameters() {
        let data = mixed(1 << 20, 22);
        let size = data.len().to_string();
        let right: &'static str = Box::leak(format!("--stream-size={size}").into_boxed_str());
        let wrong: &'static str =
            Box::leak(format!("--stream-size={}", data.len() + 1).into_boxed_str());
        let short: &'static str =
            Box::leak(format!("--stream-size={}", data.len() - 1).into_boxed_str());
        let mut cases = Vec::new();
        for args in [
            &["--long"][..],
            &["--long=27"],
            &["--long", "-19"],
            &["--rsyncable"],
            &["--rsyncable", "-T1"],
            &["--no-check"],
            &["--check"],
            &["--no-content-size"],
            &["--size-hint=1000"],
            &["--size-hint=100000000"],
            &["--target-compressed-block-size=1500"],
            &["--target-compressed-block-size=200000"],
            &["--zstd=wlog=20,clog=18"],
            &["--zstd=wlog=20,clog=16,hlog=17,slog=3,mml=5,tlen=16,strat=6"],
            &["--zstd=strat=12"],
            &["--zstd=mml=9"],
            &["--zstd=tlen=200000"],
            &["-B1M"],
            &["-B1M", "-T2"],
            &["--zstd=ovlog=5", "-T2"],
            &["--zstd=ovlog=12", "-T2"],
            &["--long", "--zstd=lhlog=20,lmml=64,lblog=3,lhrlog=5"],
            &["--long", "--zstd=lhrlog=30"],
            &["--row-match-finder"],
            &["--no-row-match-finder"],
            &["--compress-literals"],
            &["--no-compress-literals"],
            &["--no-dictID"],
            &["-v", "--zstd=ovlog=5"],
            &[right],
        ] {
            let mut a = args.to_vec();
            a.extend(["-k", "m"]);
            cases.push(with_files("zstd", &a, vec![("m", data.clone())]));
            cases.push(fed(zstd(args), data.clone()));
        }
        for args in [
            &[right][..],
            &[wrong],
            &[short],
            &[right, "-T1"],
            &[wrong, "-T1"],
        ] {
            cases.push(fed(zstd(args), data.clone()));
            let mut v = args.to_vec();
            v.push("-v");
            cases.push(fed(zstd(&v), data.clone()));
        }
        check("compress_parameters", &cases);
    }

    /// Standard streams, several files, keeping and removing, existing
    /// outputs and their prompt (R14), and an input already compressed.
    #[test]
    fn compress_streams_and_outputs() {
        let t = text();
        let two = || vec![("a", t.clone()), ("b", t.repeat(3))];
        let existing = || vec![("a", t.clone()), ("a.zst", b"old".to_vec())];
        let cases = vec![
            fed(zstd(&[]), t.clone()),
            fed(zstd(&["-"]), t.clone()),
            fed(zstd(&["-", "-o", "out"]), t.clone()),
            fed(zstd(&["-c", "-"]), t.clone()),
            with_files("zstd", &["-c", "a", "b"], two()),
            with_files("zstd", &["-cv", "a", "b"], two()),
            with_files("zstd", &["a", "b"], two()),
            with_files("zstd", &["-v", "a", "b"], two()),
            with_files("zstd", &["-k", "a"], two()),
            with_files("zstd", &["--rm", "a", "b"], two()),
            with_files("zstd", &["--rm", "-v", "a"], two()),
            with_files("zstd", &["--rm", "-c", "a"], two()),
            with_files("zstd", &["--rm", "-vvv", "-c", "a"], two()),
            // An existing output: -f replaces it, without -f the prompt
            // reads standard input (here empty), -q refuses.
            with_files("zstd", &["-f", "a"], existing()),
            with_files("zstd", &["a"], existing()),
            with_files("zstd", &["-q", "a"], existing()),
            with_files("zstd", &["-v", "a"], existing()),
            fed(with_files("zstd", &["a"], existing()), b"y\n".to_vec()),
            fed(with_files("zstd", &["a"], existing()), b"n\n".to_vec()),
            on_tty(with_files("zstd", &["a"], existing()), b"y\n"),
            on_tty(with_files("zstd", &["a"], existing()), b"n\n"),
            on_tty(with_files("zstd", &["a"], existing()), b"Yes please\n"),
            on_tty(with_files("zstd", &["-q", "a"], existing()), b"y\n"),
            // Standard input is an input: the prompt cannot ask.
            fed(
                with_files("zstd", &["-", "-o", "a.zst"], existing()),
                t.clone(),
            ),
            // An input already compressed is compressed again.
            with_files("zstd", &["a.zst"], vec![("a.zst", packed(&[], &t))]),
            with_files(
                "zstd",
                &["-v", "a.zst", "a"],
                vec![("a.zst", packed(&[], &t)), ("a", t.clone())],
            ),
            with_files(
                "zstd",
                &["--exclude-compressed", "a.zst", "a", "b.gz", "c.7z"],
                vec![
                    ("a.zst", packed(&[], &t)),
                    ("a", t.clone()),
                    ("b.gz", t.clone()),
                    ("c.7z", t.clone()),
                ],
            ),
            with_files(
                "zstd",
                &["-vvvv", "--exclude-compressed", "a.zst"],
                vec![("a.zst", packed(&[], &t))],
            ),
            // The same file as input and output, one input.
            with_files("zstd", &["-f", "a", "-o", "a"], two()),
            with_files(
                "zstd",
                &["-df", "a.zst", "-o", "a.zst"],
                vec![("a.zst", packed(&[], &t))],
            ),
        ];
        check("compress_streams_and_outputs", &cases);
    }

    fn link_a(d: &Path) {
        std::os::unix::fs::symlink("a", d.join("l")).unwrap();
    }

    fn link_nowhere(d: &Path) {
        std::os::unix::fs::symlink("nowhere", d.join("l")).unwrap();
    }

    fn make_dirs(d: &Path) {
        fs::create_dir_all(d.join("dir/sub")).unwrap();
        fs::write(d.join("dir/x"), b"x in dir\n".repeat(30)).unwrap();
        fs::write(d.join("dir/sub/y"), b"y in sub\n".repeat(30)).unwrap();
        fs::create_dir_all(d.join("empty")).unwrap();
    }

    fn make_dirs_and_out(d: &Path) {
        make_dirs(d);
        fs::create_dir_all(d.join("o")).unwrap();
    }

    fn unreadable(d: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join("u"), fs::Permissions::from_mode(0o000)).unwrap();
    }

    fn mode_0640(d: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join("a"), fs::Permissions::from_mode(0o640)).unwrap();
    }

    /// Links, directories, unreadable and non-regular inputs, `-o`, the
    /// output directories, `--filelist`, and the metadata copied.
    #[test]
    fn compress_inputs_and_names() {
        let t = text();
        let a = || vec![("a", t.clone())];
        let ab = || vec![("a", t.clone()), ("b", t.repeat(2))];
        let root = unsafe { libc::geteuid() } == 0;
        let mut cases = vec![
            with_setup(with_files("zstd", &["l"], a()), link_a),
            with_setup(with_files("zstd", &["-f", "l"], a()), link_a),
            with_setup(with_files("zstd", &["l", "a"], a()), link_a),
            with_setup(with_files("zstd", &["-f", "l"], a()), link_nowhere),
            with_setup(with_files("zstd", &["dir"], a()), make_dirs),
            with_setup(with_files("zstd", &["-r", "dir"], a()), make_dirs),
            with_setup(
                with_files("zstd", &["-r", "-v", "dir", "a"], a()),
                make_dirs,
            ),
            with_setup(with_files("zstd", &["-r", "empty"], a()), make_dirs),
            with_setup(with_files("zstd", &["-r", "-c", "dir"], a()), make_dirs),
            with_setup(with_files("zstd", &["-r", "--rm", "dir"], a()), make_dirs),
            with_files("zstd", &["missing"], a()),
            with_files("zstd", &["-v", "missing", "a"], a()),
            // -o with one and with two inputs.
            with_files("zstd", &["-o", "out", "a"], ab()),
            with_files("zstd", &["a", "-o", "out", "-v"], ab()),
            with_files("zstd", &["-o", "out", "a", "b"], ab()),
            with_files("zstd", &["-f", "-o", "out", "a", "b"], ab()),
            with_files("zstd", &["-q", "-o", "out", "a", "b"], ab()),
            with_files("zstd", &["--rm", "-f", "-o", "out", "a", "b"], ab()),
            fed(
                with_files("zstd", &["-o", "out", "a", "b"], ab()),
                b"y\n".to_vec(),
            ),
            on_tty(with_files("zstd", &["-o", "out", "a", "b"], ab()), b"y\n"),
            on_tty(with_files("zstd", &["-o", "out", "a", "b"], ab()), b"n\n"),
            with_files("zstd", &["-o", "sub/out", "a"], ab()),
            with_files("zstd", &["-o", "/dev/null", "a"], ab()),
            with_files("zstd", &["-o", ".", "a"], ab()),
            // The output directories.
            with_setup(
                with_files("zstd", &["--output-dir-flat=o", "a", "dir/x"], a()),
                make_dirs,
            ),
            with_setup(
                with_files("zstd", &["--output-dir-flat", "o", "a", "dir/x"], a()),
                make_dirs_and_out,
            ),
            with_setup(
                with_files("zstd", &["--output-dir-flat=o/", "-r", "dir"], a()),
                make_dirs_and_out,
            ),
            with_setup(
                with_files("zstd", &["--output-dir-flat=o", "a", "dir/sub/../x"], a()),
                make_dirs_and_out,
            ),
            with_setup(
                with_files("zstd", &["--output-dir-mirror=m", "-r", "dir", "a"], a()),
                make_dirs,
            ),
            with_setup(
                with_files("zstd", &["--output-dir-mirror=m", "-r", "./dir"], a()),
                make_dirs,
            ),
            with_setup(
                with_files("zstd", &["--output-dir-mirror=m", "dir/../a"], a()),
                make_dirs,
            ),
            // --filelist.
            with_files(
                "zstd",
                &["--filelist=list"],
                vec![
                    ("a", t.clone()),
                    ("b", t.clone()),
                    ("list", b"a\nb\n".to_vec()),
                ],
            ),
            with_files(
                "zstd",
                &["--filelist", "list", "a"],
                vec![("a", t.clone()), ("b", t.clone()), ("list", b"b".to_vec())],
            ),
            with_files(
                "zstd",
                &["--filelist=list"],
                vec![("a", t.clone()), ("list", b"a\n\nmissing\n".to_vec())],
            ),
            with_files(
                "zstd",
                &["--filelist=list"],
                vec![("a", t.clone()), ("list", Vec::new())],
            ),
            with_files("zstd", &["--filelist=missing"], a()),
            with_files(
                "zstd",
                &["--filelist=list", "--filelist=list2"],
                vec![
                    ("a", t.clone()),
                    ("b", t.clone()),
                    ("list", b"a\n".to_vec()),
                    ("list2", b"b\n".to_vec()),
                ],
            ),
            // Mode and modification time follow the input.
            with_setup(with_files("zstd", &["a"], a()), mode_0640),
            with_setup(with_files("zstd", &["-o", "x", "a"], a()), mode_0640),
            with_setup(with_files("zstd", &["-c", "a"], a()), mode_0640),
        ];
        if !root {
            cases.push(with_setup(
                with_files(
                    "zstd",
                    &["u", "a"],
                    vec![("u", t.clone()), ("a", t.clone())],
                ),
                unreadable,
            ));
        }
        check("compress_inputs_and_names", &cases);
    }

    /// Standard output a terminal: refused for standard input, allowed with
    /// `-f` and for a named input; standard input a terminal: refused.
    #[test]
    fn compress_terminals() {
        let t = text();
        let mut cases = vec![
            fed(zstd(&[]), t.clone()),
            fed(zstd(&["-f"]), t.clone()),
            fed(zstd(&["-c", "-"]), t.clone()),
            with_files("zstd", &["-c", "a"], vec![("a", t.clone())]),
            on_tty(zstd(&[]), b"hi\n"),
            on_tty(zstd(&["-o", "out"]), b"hi\n"),
            on_tty(zstd(&["-f", "-o", "out"]), b"hi\n"),
        ];
        for c in cases.iter_mut().take(4) {
            c.tty_stdout = true;
        }
        let one = |c: &Case| -> bool {
            let Some(dir) = zstd_dir() else { return false };
            let Some(mut r) = reference(dir, c) else {
                return false;
            };
            let mut s = stuffr_as(c);
            // Compressed bytes through a terminal's line discipline (`\n`
            // becomes `\r\n`) cannot be decoded back: on the pure tier,
            // whose frames are its own, they are not compared.
            if !EXACT && c.tty_stdout {
                r.stdout.clear();
                s.stdout.clear();
            }
            pure_tier_frames(c, &r, &mut s);
            assert_same(c, &r, &s);
            true
        };
        run_group("compress_terminals", &cases, Skipped::none(), &one);
    }

    /// Review Focus 2: 48 MiB compressed with the host's default worker
    /// count (R3), `-T1` and `zstdmt`: the C tier's bytes are the
    /// reference's; and a 2-worker run equals a 3-worker run.
    #[test]
    fn default_threading_matches_on_a_large_input() {
        let big = super::compat_harness::text(48 << 20, 93);
        let cases = vec![
            with_files("zstd", &["-q", "-c", "big"], vec![("big", big.clone())]),
            with_files(
                "zstd",
                &["-q", "-c", "-T1", "big"],
                vec![("big", big.clone())],
            ),
            with_files("zstdmt", &["-q", "-c", "big"], vec![("big", big.clone())]),
        ];
        check("default_threading_matches_on_a_large_input", &cases);
        if !EXACT {
            return;
        }
        let two = stuffr_as(&with_files(
            "zstd",
            &["-q", "-c", "-T2", "big"],
            vec![("big", big.clone())],
        ));
        let three = stuffr_as(&with_files(
            "zstd",
            &["-q", "-c", "-T3", "big"],
            vec![("big", big)],
        ));
        assert_eq!((two.code, three.code), (0, 0));
        assert!(two.stdout == three.stdout, "-T2 and -T3 differ");
    }

    /// Spec deviation 3: the one output of several inputs (`-o`) that is
    /// one of them. zstd opens it without its same-file check, truncates
    /// it and compresses the emptied input; stuffr refuses it as
    /// `FIO_openDstFile` refuses an output that is its input, and loses
    /// nothing.
    #[test]
    fn an_output_that_is_an_input_is_never_lost() {
        let t = text();
        let c = with_files(
            "zstd",
            &["-f", "a", "b", "-o", "a"],
            vec![("a", t.clone()), ("b", t.repeat(3))],
        );
        if let Some(dir) = zstd_dir()
            && let Some(r) = reference(dir, &c)
        {
            assert_eq!(r.code, 0);
            assert_ne!(r.tree["a"].0, t, "the reference kept the input");
        }
        let s = stuffr_as(&c);
        assert_eq!(s.code, 1);
        assert_eq!(
            s.stderr,
            "zstd: WARNING: all input files will be processed and concatenated into a single output file: a \n\
             The concatenated output CANNOT regenerate original file names nor directory structure. \n\
             zstd: Refusing to open an output file which will overwrite the input file \n"
        );
        assert_eq!(s.tree["a"].0, t);
        assert_eq!(s.tree.len(), 2);
        let d = with_files(
            "zstd",
            &["-df", "a.zst", "b.zst", "-o", "a.zst"],
            vec![("a.zst", packed(&[], &t)), ("b.zst", packed(&[], &t))],
        );
        let s = stuffr_as(&d);
        assert_eq!(s.code, 19);
        assert!(s.stderr.ends_with("zstd: Refusing to open an output file which will overwrite the input file \nzstd: error 19 : cannot open a.zst \n"), "{}", s.stderr);
        assert_eq!(s.tree["a.zst"].0, packed(&[], &t));
    }

    // ---- interrupts ----

    /// SIGINT during `zstd -19 big` (zstd's INThandler, R6): both exit 2
    /// having printed a newline, `big` intact, no output left.
    #[test]
    fn an_interrupt_leaves_no_partial_output() {
        use interrupt::*;
        let _serial = interrupt_lock();
        let Some(dir) = zstd_dir() else { return };
        let tag = std::process::id();
        let input = |mib: usize| big_input(mib).to_vec();
        let ref_dir =
            ScratchDir::at(std::env::temp_dir().join(format!("stuffr-zstd-int-ref-{tag}")));
        let our_dir = ScratchDir::at(std::env::temp_dir().join(format!("stuffr-zstd-int-{tag}")));
        // The output open (and so armed: zstd arms it at once, stuffr
        // creates it armed), and 300 ms of compressing since.
        let after = |named: fn(&str) -> bool| {
            let seen = std::cell::Cell::new(None::<std::time::Instant>);
            move |n: &str| {
                named(n) && {
                    let t = seen.get().unwrap_or_else(std::time::Instant::now);
                    seen.set(Some(t));
                    t.elapsed() >= std::time::Duration::from_millis(300)
                }
            }
        };
        let ready_ref = after(|n| n == "big.zst");
        let ready_ours = after(|n| n.starts_with(".stuffr-zstd-"));
        let args = ["-19", "big"];
        let ours = interrupt_with_input(
            Path::new(env!("CARGO_BIN_EXE_stuffr")),
            "zstd",
            &args,
            &our_dir,
            "big",
            &input,
            Inherit::Default,
            libc::SIGINT,
            &ready_ours,
        )
        .expect("stuffr cannot hang: it panics");
        assert_eq!(ours.status.code(), Some(2), "stuffr: {:?}", ours.status);
        assert_eq!(ours.stderr, b"\n");
        assert_eq!(ours.left, ["big"]);
        let size = fs::metadata(our_dir.join("big")).unwrap().len() as usize;
        assert!(
            fs::read(our_dir.join("big")).unwrap() == input(size >> 20),
            "big changed"
        );
        let Some(theirs) = interrupt_with_input(
            &Path::new(dir).join("zstd"),
            "zstd",
            &args,
            &ref_dir,
            "big",
            &input,
            Inherit::Default,
            libc::SIGINT,
            &ready_ref,
        ) else {
            return;
        };
        assert_eq!(
            theirs.status.code(),
            Some(2),
            "reference: {:?}",
            theirs.status
        );
        assert_eq!(theirs.stderr, b"\n");
        assert_eq!(theirs.left, ["big"]);
    }
}
