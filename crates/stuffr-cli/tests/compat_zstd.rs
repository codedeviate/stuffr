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
//! Part 2 (Task 5): compressing, decompressing and testing. Every level
//! over six inputs and every compressed output decoded three ways; the
//! thread and parameter options; standard streams, existing outputs and
//! the overwrite prompt at a terminal (R14), links, directories, `-o`, the
//! output directories and `--filelist`; frames concatenated, skippable,
//! truncated, corrupted and followed by garbage; pass-through, sparse
//! output and legacy frames (R12); Review Focus 1-5; SIGINT (R6).
//!
//! Part 5 (Task 8): `--train`, `--train-cover`, `--train-fastcover` and
//! `--train-legacy` over 100 one-record files, with their parameter
//! strings, `--maxdict`, `--dictID`, `-o`, `-B#`, `-M#` and the refusals.
//! The dictionary is compared byte for byte, except a cover dictionary
//! (ruling T1-a), which the reference must be able to use; libzstd's own
//! CPU-timed progress and dibio.c's wall-clock `Loading` lines past the
//! first are removed on both sides (`strip_trainer_progress`). The pure
//! tier answers as a `ZSTD_NODICT` build (`pure_nodict`). Then `-D` (the
//! reference's trained dictionary, raw content, the wrong one, none, a
//! missing or oversized one, `-l` naming its ID), `--patch-from` both ways
//! (levels, `--long`, `--memory`, a stream, an old file far larger than
//! the new one's window and the reverse), and `--adapt` (R10: exit code,
//! round trip and `-q`'s empty standard error only).
//!
//! Part 4 (Task 7): `-l`, `-lv` and `-lvv` over frames the reference made
//! and frames built here byte by byte (every content-size and dictionary-ID
//! field width, skippable frames, block types, reserved bits, and every
//! prefix of a multi-frame file).
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
            compare_output_bytes: exact_for(args),
            expect_stdout_plain: None,
            setup: None,
            roundtrip: Roundtrip::Zstd {
                ref_zstd: ref_zstd(),
            },
        }
    }

    /// Whether the output of a case with `args` is promised byte for byte:
    /// zstd frames on the C tier (`zstd-c`), `--format=gzip` with C zlib
    /// (`zlib-c`; spike S2 measured zlib's bytes identical to the
    /// reference's), `--format=xz|lzma` with liblzma (`xz-c`, 5.8.4 on both
    /// sides); `--format=lz4` never (R11: `lz4_flex`, not liblz4). The last
    /// `--format=` counts.
    fn exact_for(args: &[&str]) -> bool {
        let format = args
            .iter()
            .take_while(|a| **a != "--")
            .filter_map(|a| a.strip_prefix("--format="))
            .last()
            .unwrap_or("zstd");
        match format {
            "gzip" => cfg!(feature = "zlib-c"),
            "xz" | "lzma" => cfg!(feature = "xz-c"),
            "lz4" => false,
            _ => EXACT,
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
            let Some(mut r) = nodict_reference(dir, c) else {
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
            pure_tier_lzma_decoding(c, &mut r, &mut s);
            // Spec deviation 2: `-vv`'s "Completed in" timing fields.
            r.stderr = normalise_zstd_progress(&r.stderr);
            s.stderr = normalise_zstd_progress(&s.stderr);
            pure_tier_sizes(c, &mut r, &mut s);
            assert_same(c, &r, &s);
            true
        };
        run_group(group, cases, Skipped::none(), &one);
    }

    /// Spec deviation 7 on the pure tier, and `--format=lz4` on either
    /// (R11): the compressed sizes and ratios in the summaries are those of
    /// stuffr's own frames, so on both sides they become `<ratio>` and
    /// `<size>` (the input size, the names and every other byte still
    /// compared). Nothing changes where the bytes are promised.
    fn pure_tier_sizes(c: &Case, r: &mut Run, s: &mut Run) {
        if !EXACT || !c.compare_output_bytes {
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
            let cluster = a.len() > 1 && a.starts_with('-') && !a.starts_with("--");
            if matches!(*a, "--decompress" | "--uncompress" | "--test" | "--list")
                || (cluster && a[1..].bytes().any(|b| matches!(b, b'd' | b't' | b'l')))
            {
                return false;
            }
        }
        dict && c.name != "unzstd" && c.name != "zstdcat"
    }

    /// Spec deviation 7 on the pure tier: compressing with `-D` or
    /// `--patch-from` is refused (`EXM_THROW(1)`) where the reference's
    /// dictionary would be loaded, after everything it prints before
    /// compressing: stuffr's standard error is whole lines the reference
    /// printed first (all of them at the levels that print nothing after
    /// compressing), then the refusal. True when `c` is such a case (and
    /// the expectation was checked); never on the C tier, nor when the
    /// reference refuses.
    fn pure_dictionary_refusal(c: &Case, r: &Run, s: &Run) -> bool {
        // A run the reference refuses before compressing is compared as
        // any other.
        if EXACT || r.code != 0 || !compresses_with_dictionary(c) {
            return false;
        }
        const REFUSAL: &str = "zstd: error 1 : dictionary compression is not available in this build (stuffr pure tier) \n";
        assert_eq!(s.code, 1, "{:?}", c.args);
        let Some(before) = s.stderr.strip_suffix(REFUSAL) else {
            panic!("{:?}: no refusal in {:?}", c.args, s.stderr);
        };
        let before = before.replace(&our_banner(), REFERENCE_BANNER);
        assert!(
            r.stderr.starts_with(&before) && (before.is_empty() || before.ends_with('\n')),
            "{:?}: {:?} is not what the reference printed first ({:?})",
            c.args,
            before,
            r.stderr
        );
        if !c.args.iter().any(|a| a.starts_with("-v")) {
            assert_eq!(before, r.stderr, "{:?}", c.args);
        }
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

    /// Whether `c` decodes exactly one input and it is xz or lzma: its one
    /// file named so, or (no files) standard input opening with either's
    /// magic. A case over several inputs never qualifies, so the tolerance
    /// below cannot cover another format's output.
    fn decodes_lzma(c: &Case) -> bool {
        match c.files.as_slice() {
            [(n, _)] => n.ends_with(".xz") || n.ends_with(".lzma"),
            [] => c
                .stdin
                .as_ref()
                .is_some_and(|d| d.starts_with(&[0xfd, b'7']) || d.starts_with(&[0x5d, 0])),
            _ => false,
        }
    }

    /// The pure tier's liblzma port (`xz_opts::pure`; the xz family's P6
    /// and P9, this family's module doc): an xz or lzma frame that fails
    /// to decode can have written a strict prefix of what liblzma writes
    /// before the error, and corruption in the last bytes of a `.lzma`
    /// reads as the input ending (`premature lzma end` where liblzma says
    /// `lzma_code decoding error 9`), answered as an input that ends there
    /// is: the jobs decoded before it are written, where liblzma's failing
    /// call loses them (so the reference's output is then a prefix of
    /// ours). Both are accepted there, in failing runs only; the exit code
    /// and every other byte are still compared. Nothing changes with
    /// `xz-c`.
    fn pure_tier_lzma_decoding(c: &Case, r: &mut Run, s: &mut Run) {
        if cfg!(feature = "xz-c") || r.code == 0 || s.code != r.code || !decodes_lzma(c) {
            return;
        }
        if s.stdout.len() < r.stdout.len() && r.stdout.starts_with(&s.stdout) {
            s.stdout = r.stdout.clone();
        }
        let theirs = ": lzma_code decoding error 9 \n";
        let ours = ": premature lzma end \n";
        if r.stderr.contains(theirs) && s.stderr == r.stderr.replace(theirs, ours) {
            r.stderr = s.stderr.clone();
            if s.stdout.starts_with(&r.stdout) {
                s.stdout = r.stdout.clone();
            }
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

    fn mode_0444(d: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join("a"), fs::Permissions::from_mode(0o444)).unwrap();
    }

    fn zst_0400(d: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join("a.zst"), fs::Permissions::from_mode(0o400)).unwrap();
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
            // A read-only input: its mode reaches the output before the
            // times do, which are still set (util.c's UTIL_utime is by
            // path).
            with_setup(with_files("zstd", &["-q", "a"], a()), mode_0444),
            with_setup(with_files("zstd", &["a", "-o", "x"], a()), mode_0444),
            with_setup(
                with_files("zstd", &["-dq", "a.zst"], vec![("a.zst", packed(&[], &t))]),
                zst_0400,
            ),
            with_setup(
                with_files(
                    "unzstd",
                    &["a.zst", "-o", "x"],
                    vec![("a.zst", packed(&[], &t))],
                ),
                zst_0400,
            ),
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

    // ---- decompressing and testing ----

    /// A name with `.zst` added, leaked for a `Case`'s lifetime.
    fn zst(name: &str) -> &'static str {
        Box::leak(format!("{name}.zst").into_boxed_str())
    }

    /// Every compression case's reference output through `unzstd`,
    /// `zstdcat` and `zstd -t`.
    #[test]
    fn decompress_every_level() {
        let mut cases = Vec::new();
        for (name, data) in inputs() {
            for level in levels() {
                let z = zst(name);
                let frame = packed(&level, &data);
                cases.push(with_files("unzstd", &["-k", z], vec![(z, frame.clone())]));
                cases.push(with_files("zstdcat", &[z], vec![(z, frame.clone())]));
                cases.push(with_files("zstd", &["-t", z], vec![(z, frame)]));
            }
        }
        check("decompress_every_level", &cases);
    }

    /// `n` with bit `bit` of byte `at` flipped.
    fn flipped(mut v: Vec<u8>, at: usize, bit: u8) -> Vec<u8> {
        v[at] ^= 1 << bit;
        v
    }

    /// A skippable frame of `payload`.
    fn skippable(variant: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0x50 + variant, 0x2a, 0x4d, 0x18];
        v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        v.extend_from_slice(payload);
        v
    }

    /// Concatenated and skippable frames, empty and short inputs, truncated
    /// and corrupted frames, trailing garbage, unknown headers and
    /// pass-through, each through `unzstd`, `zstdcat` and `-t`.
    #[test]
    fn decompress_frames() {
        let t = text();
        let one = packed(&[], &t);
        let two = packed(&["-19"], &t.repeat(2));
        let len = one.len();
        let mut concat = one.clone();
        concat.extend_from_slice(&two);
        let mut skip = skippable(0, b"abcd");
        skip.extend_from_slice(&one);
        skip.extend(skippable(15, &[]));
        let mut garbage = one.clone();
        garbage.extend_from_slice(b"garbage");
        let mut garbage3 = one.clone();
        garbage3.extend_from_slice(b"gar");
        let inputs: Vec<(&'static str, Vec<u8>)> = vec![
            ("concat", concat),
            ("skip", skip),
            ("skiponly", skippable(3, b"hidden")),
            ("empty", Vec::new()),
            ("one", b"x".to_vec()),
            ("cut1", one[..1].to_vec()),
            ("cut5", one[..5].to_vec()),
            ("cut6", one[..6].to_vec()),
            ("cutlast", one[..len - 1].to_vec()),
            ("headerbit", flipped(one.clone(), 4, 3)),
            ("windowbit", flipped(one.clone(), 4, 5)),
            ("blockbit", flipped(one.clone(), len / 2, 2)),
            ("checkbit", flipped(one.clone(), len - 1, 0)),
            ("garbage", garbage),
            ("garbage3", garbage3),
            ("abc", b"abc".to_vec()),
            ("plain", t.clone()),
            ("nocheck", packed(&["--no-check"], &t)),
            ("nosize", packed(&["--no-content-size"], &t)),
        ];
        let mut cases = Vec::new();
        for (name, data) in &inputs {
            let z = zst(name);
            let files = vec![(z, data.clone())];
            cases.push(with_files("unzstd", &["-k", z], files.clone()));
            cases.push(with_files("zstdcat", &[z], files.clone()));
            cases.push(with_files("zstd", &["-t", z], files.clone()));
            cases.push(with_files("zstd", &["-dv", "-c", z], files.clone()));
            cases.push(fed(zstd(&["-d"]), data.clone()));
        }
        // Pass-through: zstdcat's default, -dcf, --pass-through, and its
        // refusal.
        for args in [
            &["-dcf", "plain"][..],
            &["-dc", "--pass-through", "plain"],
            &["-dcf", "--no-pass-through", "plain"],
            &["-df", "plain.zst"],
            &["-dcf", "plain", "concat.zst", "abc"],
        ] {
            cases.push(with_files(
                "zstd",
                args,
                vec![
                    ("plain", t.clone()),
                    ("plain.zst", t.clone()),
                    ("concat.zst", inputs[0].1.clone()),
                    ("abc", b"abc".to_vec()),
                ],
            ));
        }
        cases.push(with_files(
            "zstdcat",
            &["plain", "abc"],
            vec![("plain", t.clone()), ("abc", b"abc".to_vec())],
        ));
        cases.push(fed(case("zstdcat", &[]), t.clone()));
        cases.push(fed(
            zstd(&["-t", "--no-check"]),
            flipped(one.clone(), len - 1, 0),
        ));
        cases.push(fed(zstd(&["-d", "-C"]), flipped(one.clone(), len - 1, 0)));
        check("decompress_frames", &cases);
    }

    /// Sparse output: zeros skipped (`--sparse`), written (`--no-sparse`),
    /// and the platform default; the bytes and size the same, and
    /// `--sparse` to a pipe refused as the reference refuses it.
    #[test]
    fn decompress_sparse() {
        let mut zeros = vec![0u8; 3 << 20];
        zeros[100_000] = 1;
        zeros[(1 << 20) + 5] = 7;
        let tail = vec![0u8; 200_001];
        let mut cases = Vec::new();
        for (name, data) in [("zeros", zeros), ("tail", tail), ("text", text())] {
            let z = zst(name);
            let frame = packed(&[], &data);
            for args in [
                &[][..],
                &["--sparse"],
                &["--no-sparse"],
                &["-c", "--no-sparse"],
                &["-c", "--sparse"],
            ] {
                let mut a = vec!["-d", "-k"];
                a.extend(args.iter().copied());
                a.push(z);
                cases.push(with_files("zstd", &a, vec![(z, frame.clone())]));
            }
            // Overwriting an existing file, where the automatic setting
            // applies.
            cases.push(with_files(
                "zstd",
                &["-d", "-f", z],
                vec![(z, frame.clone()), (name, b"old".to_vec())],
            ));
        }
        check("decompress_sparse", &cases);
    }

    /// R12: legacy zstd frames (v0.4 to v0.8) from zstd 1.5.7's own
    /// `tests/legacy.c` (BSD, its `COMPRESSED` array, 917 bytes, vendored
    /// as `tests/fixtures/zstd_legacy/legacy_c.zst`): five frames at offsets
    /// 0 (v0.4), 198 (v0.5), 382 (v0.6), 560 (v0.7) and 738 (v0.8, the
    /// current format). The reference, built with `ZSTD_LEGACY_SUPPORT=5`,
    /// decodes v0.5 and later; the C tier answers alike. The pure tier has
    /// no legacy decoder (spec deviation 7) and says what a zstd built
    /// without legacy support says.
    fn legacy_frames() -> Vec<(&'static str, Vec<u8>)> {
        let all = include_bytes!("fixtures/zstd_legacy/legacy_c.zst");
        assert_eq!(all.len(), 917);
        vec![
            ("v04.zst", all[..198].to_vec()),
            ("v05.zst", all[198..382].to_vec()),
            ("v06.zst", all[382..560].to_vec()),
            ("v07.zst", all[560..738].to_vec()),
            ("v08.zst", all[738..].to_vec()),
            ("v05to08.zst", all[198..].to_vec()),
        ]
    }

    #[test]
    fn decompress_legacy_frames() {
        let mut cases = Vec::new();
        for (name, data) in legacy_frames() {
            for args in [&["-d", "-k"][..], &["-dc"], &["-t"]] {
                let mut a = args.to_vec();
                a.push(name);
                cases.push(with_files("zstd", &a, vec![(name, data.clone())]));
            }
        }
        if EXACT {
            check("decompress_legacy_frames", &cases);
            return;
        }
        // The pure tier: v0.8 (the current format) decodes as on the C
        // tier; a legacy frame is an unsupported format.
        let legacy_name = |c: &Case| c.args.last().is_some_and(|n| *n != "v08.zst");
        let (legacy, current): (Vec<Case>, Vec<Case>) = cases.into_iter().partition(legacy_name);
        check("decompress_legacy_frames", &current);
        for c in &legacy {
            let s = stuffr_as(c);
            let name = c.args.last().unwrap();
            assert_eq!(s.code, 1, "{:?}", c.args);
            assert!(s.stdout.is_empty(), "{:?}", c.args);
            // v05to08 fails at its first frame, as the reference fails at
            // v0.4.
            assert_eq!(
                s.stderr,
                format!("zstd: {name}: unsupported format \n"),
                "{:?}",
                c.args
            );
        }
    }

    // ---- Review Focus 1-5 ----

    /// Review Focus 1: a 64 MiB stream decodes in bounded memory.
    #[test]
    fn zstdcat_streams_a_large_input() {
        const N: usize = 64 << 20;
        let plain = mixed(N, 91);
        if zstd_dir().is_none() {
            return;
        }
        let frame = packed(&["-1"], &plain);
        let peak = decoder_peak_rss("zstdcat", "big.zst", &frame, &plain, &[("LC_ALL", "C")]);
        assert!(
            peak < 64 << 20,
            "peak memory {peak} bytes is not under 64 MiB"
        );
    }

    fn closed_pipe_status(exe: &Path, dir: &Path) -> std::process::ExitStatus {
        use std::io::Read;
        use std::process::{Command, Stdio};
        let mut child = spawn(
            Command::new(exe)
                .arg("big.zst")
                .current_dir(dir)
                .env_clear()
                .env("LC_ALL", "C")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )
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

    /// Review Focus 1: `zstdcat big.zst | head` ends stuffr by SIGPIPE with
    /// nothing said, as it ends zstd.
    #[test]
    fn zstdcat_into_a_closed_pipe() {
        use std::os::unix::process::ExitStatusExt;
        let Some(dir) = zstd_dir() else { return };
        let plain = text().repeat(4000);
        let work = ScratchDir::at(
            std::env::temp_dir().join(format!("stuffr-zstdcat-pipe-{}", std::process::id())),
        );
        fs::create_dir_all(work.join("bin")).unwrap();
        let link = work.join("bin").join("zstdcat");
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stuffr"), &link).unwrap();
        fs::write(work.join("big.zst"), packed(&[], &plain)).unwrap();
        let ours = closed_pipe_status(&link, &work);
        let theirs = closed_pipe_status(&Path::new(dir).join("zstdcat"), &work);
        assert_eq!(
            theirs.signal(),
            Some(libc::SIGPIPE),
            "reference: {theirs:?}"
        );
        assert_eq!(
            ours.signal(),
            theirs.signal(),
            "stuffr as zstdcat: {ours:?}"
        );
    }

    /// Review Focus 3: a frame with a 2 GiB window (`--long=31` over
    /// standard input) is refused without `--long`/`--memory`, with the
    /// hint, before any window is allocated; with them it decodes.
    #[test]
    fn window_limit_refuses_before_allocating() {
        let t = text();
        let frame = packed(&["--long=31"], &t);
        let cases = vec![
            with_files("zstd", &["-d", "w.zst"], vec![("w.zst", frame.clone())]),
            with_files("zstd", &["-dc", "w.zst"], vec![("w.zst", frame.clone())]),
            with_files("zstd", &["-t", "w.zst"], vec![("w.zst", frame.clone())]),
            with_files(
                "zstd",
                &["-d", "--long=31", "w.zst"],
                vec![("w.zst", frame.clone())],
            ),
            with_files(
                "zstd",
                &["-d", "--long=30", "w.zst"],
                vec![("w.zst", frame.clone())],
            ),
            with_files(
                "zstd",
                &["-d", "--memory=2048MB", "w.zst"],
                vec![("w.zst", frame.clone())],
            ),
            with_files(
                "zstd",
                &["-d", "-M2047MB", "w.zst"],
                vec![("w.zst", frame.clone())],
            ),
            with_files(
                "zstd",
                &["-d", "--memory=1", "w.zst"],
                vec![("w.zst", frame.clone())],
            ),
            fed(zstd(&["-d"]), frame.clone()),
        ];
        check("window_limit_refuses_before_allocating", &cases);
        if zstd_dir().is_none() {
            return;
        }
        // Peak memory while refusing, the frame offered many times so a
        // sampling measurement sees the run.
        let mut args = vec!["-dc"];
        args.extend(std::iter::repeat_n("w.zst", 200));
        let (st, out, err, peak) = peak_rss_run("zstd", &args, "w.zst", &frame, &[("LC_ALL", "C")]);
        assert_eq!(st.code(), Some(1), "{err}");
        assert!(out.is_empty());
        assert!(
            err.contains("Window size larger than maximum : 2147483648 > 134217728"),
            "{err}"
        );
        assert!(
            peak < 32 << 20,
            "peak memory {peak} bytes is not under 32 MiB"
        );
    }

    /// Review Focus 4: several files where one fails, with the same
    /// messages, summary and exit code, and the good outputs made.
    #[test]
    fn several_files_one_failing() {
        let t = text();
        let good = packed(&[], &t);
        let bad = flipped(good.clone(), good.len() / 2, 2);
        let zfiles = || {
            vec![
                ("a.zst", good.clone()),
                ("bad.zst", bad.clone()),
                ("c.zst", packed(&["-9"], &t.repeat(2))),
            ]
        };
        let pfiles = || vec![("a", t.clone()), ("c", t.repeat(2))];
        let cases = vec![
            with_files("zstd", &["-d", "a.zst", "bad.zst", "c.zst"], zfiles()),
            with_files("zstd", &["-dv", "a.zst", "bad.zst", "c.zst"], zfiles()),
            with_files("zstd", &["-dq", "a.zst", "bad.zst", "c.zst"], zfiles()),
            with_files(
                "zstd",
                &["-d", "--rm", "a.zst", "bad.zst", "c.zst"],
                zfiles(),
            ),
            with_files("zstd", &["-t", "a.zst", "bad.zst", "c.zst"], zfiles()),
            with_files("zstd", &["-dc", "a.zst", "bad.zst", "c.zst"], zfiles()),
            with_files(
                "zstd",
                &["-d", "-o", "out", "a.zst", "bad.zst", "c.zst"],
                zfiles(),
            ),
            with_files(
                "zstd",
                &["-d", "-f", "-o", "out", "a.zst", "bad.zst", "c.zst"],
                zfiles(),
            ),
            with_files(
                "zstd",
                &["-d", "-f", "--rm", "-o", "out", "a.zst", "bad.zst", "c.zst"],
                zfiles(),
            ),
            with_files("zstd", &["-d", "missing.zst", "a.zst"], zfiles()),
            with_files("zstd", &["a", "missing", "c"], pfiles()),
            with_files("zstd", &["-v", "a", "missing", "c"], pfiles()),
            with_files("zstd", &["--rm", "a", "missing", "c"], pfiles()),
            with_files("zstd", &["-o", "out", "a", "missing", "c"], pfiles()),
            with_files("zstd", &["-f", "-o", "out", "a", "missing", "c"], pfiles()),
            with_files("zstd", &["-c", "a", "missing", "c"], pfiles()),
        ];
        check("several_files_one_failing", &cases);
    }

    /// Review Focus 5: the suffix rules.
    #[test]
    fn suffix_rules() {
        let t = text();
        let z = packed(&[], &t);
        let files = || {
            vec![
                ("a.tzst", z.clone()),
                ("b.zst", z.clone()),
                ("c.zstd", z.clone()),
                ("d", z.clone()),
                ("e.ZST", z.clone()),
                (".zst", z.clone()),
                ("f.tar.zst", z.clone()),
            ]
        };
        let mut cases = Vec::new();
        for name in [
            "a.tzst",
            "b.zst",
            "c.zstd",
            "d",
            "e.ZST",
            ".zst",
            "f.tar.zst",
        ] {
            cases.push(with_files("unzstd", &[name], files()));
            cases.push(with_files(
                "zstd",
                &["-d", "-k", "--output-dir-flat=o", name],
                files(),
            ));
        }
        cases.push(with_files("unzstd", &["d", "b.zst"], files()));
        cases.push(with_files("unzstd", &["-o", "out", "d"], files()));
        cases.push(with_files("zstd", &["b.zst"], files()));
        cases.push(with_files(
            "zstd",
            &["--exclude-compressed", "b.zst", "a.tzst"],
            files(),
        ));
        cases.push(fed(zstd(&["-d"]), z.clone()));
        check("suffix_rules", &cases);
    }

    /// Review Focus 5's gzip leg: `unzstd a.gz` decodes by magic.
    #[test]
    fn suffix_rules_foreign() {
        let t = text();
        let gz = gzm(&t, b"a");
        let cases = vec![
            with_files("unzstd", &["a.gz"], vec![("a.gz", gz.clone())]),
            with_files("unzstd", &["a.tgz"], vec![("a.tgz", gz.clone())]),
            with_files("zstdcat", &["a.gz"], vec![("a.gz", gz)]),
        ];
        check("suffix_rules_foreign", &cases);
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

    // ==== part 3 (Task 6): gzip, xz, lzma and lz4 ====

    /// The foreign formats `--format=` names.
    const FOREIGN: [&str; 4] = ["gzip", "xz", "lzma", "lz4"];

    fn leak(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }

    /// `--format=f`.
    fn format_arg(f: &str) -> &'static str {
        leak(format!("--format={f}"))
    }

    /// The suffix `--format=f` writes (fileio.c's `*_EXTENSION`).
    fn ext(f: &str) -> &'static str {
        match f {
            "gzip" => ".gz",
            "xz" => ".xz",
            "lzma" => ".lzma",
            _ => ".lz4",
        }
    }

    /// The levels each format is driven at: 1, 3 and 19 (clamped to 9 by
    /// gzip, xz and lzma), 0 (gzip's stored blocks, xz's preset 0), and
    /// `--fast=1`/`--fast=3`: zlib's `Z_DEFAULT_COMPRESSION` and its
    /// refusal of -3 (`deflateInit2 error -2`, exit 71); preset 0 for xz
    /// and lzma (negative levels clamp up).
    fn foreign_levels() -> [&'static str; 6] {
        ["-1", "-3", "-19", "-0", "--fast=1", "--fast=3"]
    }

    /// The inputs of part 3: empty, 1 KiB of text, and 1 MiB mixed (eight
    /// read jobs, sixteen 64 KiB lz4 blocks).
    fn foreign_inputs() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("empty", Vec::new()),
            ("text", super::compat_harness::text(1024, 21)),
            ("mixed", mixed(1 << 20, 22)),
        ]
    }

    /// `--format=gzip|xz|lzma|lz4` at every level of [`foreign_levels`]
    /// over every input: file to file (the summary printed), to standard
    /// output, and standard input to standard output.
    #[test]
    fn foreign_compress() {
        let mut cases = Vec::new();
        for f in FOREIGN {
            for level in foreign_levels() {
                for (name, data) in foreign_inputs() {
                    let fa = format_arg(f);
                    cases.push(with_files(
                        "zstd",
                        &[fa, level, "-k", name],
                        vec![(name, data.clone())],
                    ));
                    cases.push(with_files(
                        "zstd",
                        &[fa, level, "-c", name],
                        vec![(name, data.clone())],
                    ));
                    cases.push(fed(with_files("zstd", &[fa, level], Vec::new()), data));
                }
            }
        }
        // Several files (the totals), `--rm`, `-o`, the content checksum
        // switches lz4 reads, and the format's own suffix with `-S`-less
        // names already carrying it.
        let t = text();
        for f in FOREIGN {
            let fa = format_arg(f);
            for args in [
                &[fa, "-k", "a", "d"][..],
                &[fa, "--rm", "a"],
                &[fa, "-k", "--no-check", "a"],
                &[fa, "-k", "-C", "a"],
                &[fa, "-vv", "-k", "a"],
                &[fa, "-q", "-k", "a", "d", "-c"],
            ] {
                cases.push(with_files(
                    "zstd",
                    args,
                    vec![("a", t.clone()), ("d", t.repeat(3))],
                ));
            }
        }
        for f in FOREIGN {
            cases.push(with_files(
                "zstd",
                &[format_arg(f), "-k", "a", "-o", "out"],
                vec![("a", t.clone())],
            ));
        }
        check("foreign_compress", &cases);
    }

    /// The LZ4 frame descriptor (FLG, BD, the content size and the header
    /// checksum) is the reference's, byte for byte, though the blocks
    /// after it are `lz4_flex`'s (R11): 64 KiB linked blocks, the content
    /// size when the input's is known and non-zero, and a content checksum
    /// only for `checksumFlag` 1 (`-C` sets 2, which liblz4 reads as no
    /// checksum).
    #[test]
    fn lz4_frame_descriptor_matches() {
        let Some(_) = zstd_dir() else { return };
        let t = text();
        for (args, stdin) in [
            (&["--format=lz4", "-c", "a"][..], false),
            (&["--format=lz4", "-c", "--no-check", "a"], false),
            (&["--format=lz4", "-c", "-C", "a"], false),
            (&["--format=lz4", "-c", "e"], false),
            (&["--format=lz4", "-c"], true),
        ] {
            let mut c = with_files("zstd", args, vec![("a", t.clone()), ("e", Vec::new())]);
            if stdin {
                c.stdin = Some(t.clone());
            }
            let Some(r) = reference(zstd_dir().unwrap(), &c) else {
                return;
            };
            let s = stuffr_as(&c);
            let header = |b: &[u8]| {
                let flg = b[4];
                let len = 7 + if flg & 8 != 0 { 8 } else { 0 } + if flg & 1 != 0 { 4 } else { 0 };
                b[..len].to_vec()
            };
            assert_eq!(
                header(&s.stdout),
                header(&r.stdout),
                "{args:?}: the frame descriptor differs"
            );
            assert_eq!(s.code, r.code, "{args:?}");
            assert_eq!(s.stderr, r.stderr, "{args:?}");
        }
    }

    /// `data` in `f` written by the reference with `extra` options.
    fn foreign_packed(f: &str, extra: &[&str], data: &[u8]) -> Vec<u8> {
        let mut a = vec![format_arg(f), "-q"];
        a.extend_from_slice(extra);
        packed(&a, data)
    }

    /// A gzip member with a header CRC (`FHCRC`), right (`good`) or not.
    fn gz_with_hcrc(data: &[u8], good: bool) -> Vec<u8> {
        let mut v = member(Member {
            hcrc: true,
            name: Some(b"n"),
            ..plain_member(data)
        });
        if !good {
            // The CRC16 follows the name's NUL at 10 + 2.
            v[12] ^= 0x55;
        }
        v
    }

    /// Every format by magic, through `unzstd`, `zstdcat`, `zstd -t`,
    /// `zstd -dv -c` and `zstd -d` from standard input: the reference's own
    /// output at two levels; other encoders' (a named gzip member with and
    /// without a header CRC, `lz4_flex`'s independent blocks); members
    /// followed by other members, by zstd frames, by stream padding and by
    /// garbage; and each format truncated (in its header, halfway, one
    /// byte short) and corrupted (halfway, in its trailing check, and in
    /// each header field the decoder checks).
    #[test]
    fn foreign_decompress() {
        let t = text();
        let big = mixed(1 << 20, 23);
        let zst_frame = packed(&[], &t);
        let mut inputs: Vec<(&'static str, Vec<u8>)> = Vec::new();
        for f in FOREIGN {
            let one = foreign_packed(f, &[], &t);
            let big_one = foreign_packed(f, &["-19"], &big);
            let n = one.len();
            let bn = big_one.len();
            let name = |what: &str| leak(format!("{what}{}", ext(f)));
            let mut two = one.clone();
            two.extend_from_slice(&foreign_packed(f, &["-1"], &t.repeat(2)));
            let mut then_zst = one.clone();
            then_zst.extend_from_slice(&zst_frame);
            let mut zst_then = zst_frame.clone();
            zst_then.extend_from_slice(&one);
            let mut padded = one.clone();
            padded.extend_from_slice(&[0, 0, 0, 0]);
            let mut garbage = one.clone();
            garbage.extend_from_slice(b"garbage");
            let mut garbage3 = one.clone();
            garbage3.extend_from_slice(b"gar");
            let head = match f {
                "gzip" => 4,
                "xz" => 8,
                "lzma" => 6,
                _ => 6,
            };
            inputs.extend([
                (name("one"), one.clone()),
                (name("big"), big_one.clone()),
                (name("two"), two),
                (name("thenzst"), then_zst),
                (name("zstthen"), zst_then),
                (name("padded"), padded),
                (name("garbage"), garbage),
                (name("garbage3"), garbage3),
                (name("cuthead"), one[..head].to_vec()),
                (name("cuthalf"), one[..n / 2].to_vec()),
                (name("cutlast"), one[..n - 1].to_vec()),
                (name("bigcut"), big_one[..bn / 2].to_vec()),
                (name("midbit"), flipped(one.clone(), n / 2, 2)),
                (name("checkbit"), flipped(one.clone(), n - 2, 0)),
                (name("bigmidbit"), flipped(big_one.clone(), bn / 2, 2)),
            ]);
        }
        inputs.extend([
            ("named.gz", gzm(&t, b"a")),
            ("hcrc.gz", gz_with_hcrc(&t, true)),
            ("badhcrc.gz", gz_with_hcrc(&t, false)),
            ("method.gz", {
                let mut v = gzm(&t, b"a");
                v[2] = 7;
                v
            }),
            ("reserved.gz", flipped(gzm(&t, b"a"), 3, 5)),
            ("badlen.gz", member_with(plain_member(&t), None, Some(1))),
            ("flex.lz4", stuffr_encode("lz4", &big, None)),
            (
                "lz4reserved.lz4",
                flipped(foreign_packed("lz4", &[], &t), 4, 1),
            ),
            (
                "lz4version.lz4",
                flipped(foreign_packed("lz4", &[], &t), 4, 7),
            ),
            ("lz4bd.lz4", flipped(foreign_packed("lz4", &[], &t), 5, 4)),
            ("lz4hc.lz4", {
                let v = foreign_packed("lz4", &[], &t);
                if v.is_empty() {
                    v
                } else {
                    // The header checksum ends the descriptor.
                    let flg = v[4];
                    let at =
                        6 + if flg & 8 != 0 { 8 } else { 0 } + if flg & 1 != 0 { 4 } else { 0 };
                    flipped(v, at, 0)
                }
            }),
        ]);
        let mut cases = Vec::new();
        for (name, data) in &inputs {
            let name: &'static str = name;
            let files = vec![(name, data.clone())];
            cases.push(with_files("unzstd", &["-k", name], files.clone()));
            cases.push(with_files("zstdcat", &[name], files.clone()));
            cases.push(with_files("zstd", &["-t", name], files.clone()));
            cases.push(with_files("zstd", &["-dv", "-c", name], files.clone()));
            cases.push(fed(with_files("zstd", &["-d"], Vec::new()), data.clone()));
        }
        // Several files, the totals and one failing.
        let files: Vec<(&'static str, Vec<u8>)> = inputs
            .iter()
            .filter(|(n, _)| n.starts_with("one."))
            .cloned()
            .collect();
        let names: Vec<&str> = files.iter().map(|(n, _)| *n).collect();
        let mut args = vec!["-dk"];
        args.extend(names.iter().copied());
        cases.push(with_files("zstd", &args, files.clone()));
        let mut args = vec!["-dc", "-v"];
        args.extend(names.iter().copied());
        cases.push(with_files("zstd", &args, files.clone()));
        let mut args = vec!["-t"];
        args.extend(names.iter().copied());
        args.push("cuthalf.gz");
        let mut more = files;
        more.extend(inputs.iter().filter(|(n, _)| *n == "cuthalf.gz").cloned());
        cases.push(with_files("zstd", &args, more));
        check("foreign_decompress", &cases);
    }

    /// Deflate bits, least significant first, as RFC 1951 packs them.
    #[derive(Default)]
    struct Bits {
        out: Vec<u8>,
        acc: u64,
        n: u32,
    }

    impl Bits {
        /// `n` bits of `v`, least significant first (header fields, extra
        /// bits).
        fn put(&mut self, v: u32, n: u32) {
            self.acc |= u64::from(v) << self.n;
            self.n += n;
            while self.n >= 8 {
                self.out.push(self.acc as u8);
                self.acc >>= 8;
                self.n -= 8;
            }
        }

        /// A Huffman code of `len` bits, most significant first.
        fn code(&mut self, code: u32, len: u32) {
            let rev = code.reverse_bits() >> (32 - len);
            self.put(rev, len);
        }

        fn done(mut self) -> Vec<u8> {
            if self.n > 0 {
                self.out.push(self.acc as u8);
            }
            self.out
        }
    }

    /// A gzip member around `deflate` (no name, the trailer of `plain`).
    fn gz_around(deflate: &[u8], plain: &[u8]) -> Vec<u8> {
        let mut v = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
        v.extend_from_slice(deflate);
        v.extend_from_slice(&crc32(plain).to_le_bytes());
        v.extend_from_slice(&(plain.len() as u32).to_le_bytes());
        v
    }

    /// What flate2 (miniz_oxide) makes of [`distance_too_far`]'s deflate
    /// data: the literal, then three bytes of its zero-filled window.
    const FAR_AS_MINIZ_READS_IT: &[u8] = b"a\0\0\0";

    /// A fixed-Huffman block: one literal `a`, then a match of length 3 at
    /// distance 5, which reaches before the output's start (zlib: "invalid
    /// distance too far back"), then the end of block. The trailer is the
    /// CRC and size of [`FAR_AS_MINIZ_READS_IT`], so miniz_oxide completes
    /// the member; only a decoder that refuses the distance fails it.
    fn distance_too_far() -> Vec<u8> {
        let mut b = Bits::default();
        b.put(1, 1); // BFINAL
        b.put(1, 2); // BTYPE 01, fixed
        b.code(0x30 + u32::from(b'a'), 8); // literal 'a'
        b.code(1, 7); // length symbol 257: 3
        b.code(4, 5); // distance code 4: 5-6
        b.put(0, 1); // its extra bit: 5
        b.code(0, 7); // end of block
        gz_around(&b.done(), FAR_AS_MINIZ_READS_IT)
    }

    /// A dynamic block whose literal/length code gives the end-of-block
    /// symbol no length (zlib: "invalid code -- missing end-of-block"),
    /// followed by literals.
    fn missing_end_of_block() -> Vec<u8> {
        let mut b = Bits::default();
        b.put(1, 1); // BFINAL
        b.put(2, 2); // BTYPE 10, dynamic
        b.put(0, 5); // HLIT: 257 codes
        b.put(0, 5); // HDIST: 1 code
        b.put(14, 4); // HCLEN: 18 code-length codes
        // Code-length code lengths in RFC 1951's order (16, 17, 18, 0, 8,
        // 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1): 18 gets 1 bit, 0
        // and 1 get 2.
        for l in [0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2] {
            b.put(l, 3);
        }
        // Canonical: 18 = `0`, 0 = `10`, 1 = `11`.
        let zeros = |b: &mut Bits, n: u32| {
            b.code(0, 1);
            b.put(n - 11, 7);
        };
        zeros(&mut b, 97); // symbols 0-96
        b.code(3, 2); // 'a': 1
        b.code(3, 2); // 'b': 1
        zeros(&mut b, 138); // 99-236
        zeros(&mut b, 20); // 237-256, the end of block included
        b.code(2, 2); // the one distance code: 0
        for _ in 0..64 {
            b.code(0, 1); // 'a'
            b.code(1, 1); // 'b'
        }
        gz_around(&b.done(), &b"ab".repeat(64))
    }

    /// Two members zlib refuses and flate2 (miniz_oxide) does not: a
    /// distance before the output's start, and a code with no end of
    /// block. With C zlib (`zlib-c`) stuffr answers exactly as the
    /// reference does (`inflate error -3`, exit 1, nothing written). Off
    /// it, the stated pure-tier deviation: where the reference says
    /// `inflate error -3` and writes nothing, the pure tier may write bytes
    /// and then fail (`premature gz end`), or, when the trailer's CRC and
    /// size match what miniz_oxide decoded, succeed with exit 0 and that
    /// output. `far.gz`'s trailer is built to match, so it shows the
    /// exit-0 shape; `noeob.gz` fails.
    #[test]
    fn gzip_streams_zlib_refuses() {
        let inputs = [
            ("far.gz", distance_too_far()),
            ("noeob.gz", missing_end_of_block()),
        ];
        let mut cases = Vec::new();
        for (name, data) in &inputs {
            let name: &'static str = name;
            let files = vec![(name, data.clone())];
            cases.push(with_files("zstdcat", &[name], files.clone()));
            cases.push(with_files("zstd", &["-t", name], files.clone()));
            cases.push(with_files("unzstd", &["-k", name], files.clone()));
            cases.push(fed(with_files("zstd", &["-d"], Vec::new()), data.clone()));
        }
        if cfg!(feature = "zlib-c") {
            check("gzip_streams_zlib_refuses", &cases);
            return;
        }
        for c in &cases {
            let s = stuffr_as(c);
            let name = c.args.last().filter(|_| !c.files.is_empty()).copied();
            let shown = name.unwrap_or("/*stdin*\\");
            let far = c.files.first().is_none_or(|(n, _)| *n == "far.gz")
                && c.stdin.as_deref().is_none_or(|d| d == distance_too_far());
            if far {
                assert_eq!(s.code, 0, "{} {:?}: {}", c.name, c.args, s.stderr);
                assert!(!s.stderr.contains("zstd: "), "{:?}: {:?}", c.args, s.stderr);
                if c.name == "zstdcat" || c.args == ["-d"] {
                    assert_eq!(s.stdout, FAR_AS_MINIZ_READS_IT, "{:?}", c.args);
                }
                if c.name == "unzstd" {
                    assert_eq!(s.tree["far"].0, FAR_AS_MINIZ_READS_IT);
                }
            } else {
                assert_eq!(s.code, 1, "{} {:?}: {}", c.name, c.args, s.stderr);
                assert!(
                    s.stderr == format!("zstd: {shown}: inflate error -3 \n")
                        || s.stderr == format!("zstd: {shown}: premature gz end \n"),
                    "{} {:?}: {:?}",
                    c.name,
                    c.args,
                    s.stderr
                );
            }
            if let Some(dir) = zstd_dir()
                && let Some(r) = reference(dir, c)
            {
                assert_eq!(r.code, 1, "reference: {:?}", r.stderr);
                assert_eq!(r.stderr, format!("zstd: {shown}: inflate error -3 \n"));
                assert!(r.stdout.is_empty());
            }
        }
    }

    /// A `.lzma` frame followed by a zstd frame, the `.lzma` ending at
    /// every offset around the 256-byte pieces its decoder is fed, in the
    /// first read job and in a later one: the frame after it is read from
    /// its first byte. (The pure tier's LZMA decoder reads up to 40 bytes
    /// ahead and may report the end only a piece later.)
    #[test]
    fn lzma_followed_by_a_frame() {
        if zstd_dir().is_none() {
            return;
        }
        let next = packed(&[], b"TAIL\n");
        let mut sizes = std::collections::BTreeSet::new();
        let mut cases = Vec::new();
        let mut add = |data: Vec<u8>, sizes: &mut std::collections::BTreeSet<usize>| {
            sizes.insert(data.len());
            let mut v = data;
            v.extend_from_slice(&next);
            cases.push(with_files("zstdcat", &["l.lzma"], vec![("l.lzma", v)]));
        };
        // In the first read job: ends around 256, 512 and 768.
        for (k, n) in (180..=300).chain(420..=500).chain(680..=760).enumerate() {
            add(
                foreign_packed("lzma", &[], &random(n, 400 + k as u64)),
                &mut sizes,
            );
        }
        for edge in [256, 512, 768] {
            let near = (edge - 13..edge).filter(|z| sizes.contains(z)).count();
            assert!(near >= 8, "{near} sizes in the 13 below {edge}: {sizes:?}");
        }
        // In the third read job: ends in the last 13 bytes of one of its
        // 256-byte pieces (the job starts at 2 x `ZSTD_DStreamInSize()`).
        let mut later = 0;
        let mut n = 299_800;
        while later < 3 && n < 300_600 {
            let data = foreign_packed("lzma", &[], &random(n, n as u64));
            let at = data.len() - 2 * DSTREAM_IN_SIZE_REF;
            if (243..=255).contains(&(at % 256)) {
                later += 1;
                add(data, &mut sizes);
            }
            n += 7;
        }
        assert_eq!(later, 3, "no later-job sizes found");
        check("lzma_followed_by_a_frame", &cases);
    }

    /// `ZSTD_DStreamInSize()`: one read job.
    const DSTREAM_IN_SIZE_REF: usize = (128 << 10) + 3;

    /// 128 MiB of zeros as xz (preset 3, a 4 MiB dictionary) and as gzip
    /// -9 decode in bounded memory: each decoder call fills one 128 KiB
    /// buffer, as fileio.c's loops do, however well the data compressed
    /// (a whole read job's output held at once was 128 MiB here). The
    /// reference stays under the same bound.
    #[test]
    fn foreign_frames_decode_in_bounded_memory() {
        const N: usize = 128 << 20;
        if zstd_dir().is_none() {
            return;
        }
        let plain = vec![0u8; N];
        for (f, level, file) in [("xz", "-3", "zeros.xz"), ("gzip", "-9", "zeros.gz")] {
            let packed_ = foreign_packed(f, &[level], &plain);
            let peak = decoder_peak_rss("zstdcat", file, &packed_, &plain, &[("LC_ALL", "C")]);
            assert!(
                peak < 48 << 20,
                "{f}: peak memory {peak} bytes is not under 48 MiB"
            );
        }
    }

    // ---- --list ----

    /// A block: `kind` 0 raw, 1 RLE (`size` regenerated bytes, one payload
    /// byte), 2 compressed, 3 reserved; `payload` is what follows the
    /// 3-byte header.
    fn block(kind: u32, last: bool, size: u32, payload: &[u8]) -> Vec<u8> {
        let h = u32::from(last) | (kind << 1) | (size << 3);
        let mut v = h.to_le_bytes()[..3].to_vec();
        v.extend_from_slice(payload);
        v
    }

    /// A frame from its parts: magic, descriptor, window byte (absent for
    /// a single segment), dictionary-ID bytes, content-size bytes, blocks
    /// and checksum bytes. Nothing is checked, as `-l` checks nothing.
    fn hand(
        fhd: u8,
        window: Option<u8>,
        did: &[u8],
        fcs: &[u8],
        blocks: &[u8],
        check: &[u8],
    ) -> Vec<u8> {
        let mut v = vec![0x28, 0xb5, 0x2f, 0xfd, fhd];
        v.extend(window);
        v.extend_from_slice(did);
        v.extend_from_slice(fcs);
        v.extend_from_slice(blocks);
        v.extend_from_slice(check);
        v
    }

    /// A skippable frame (variant `n`) with `len` bytes of content.
    fn skip_frame(n: u8, len: usize) -> Vec<u8> {
        let mut v = vec![0x50 + n, 0x2a, 0x4d, 0x18];
        v.extend_from_slice(&(len as u32).to_le_bytes());
        v.extend(std::iter::repeat_n(0xa5, len));
        v
    }

    fn listed<'a>(args: &[&'a str], files: Vec<(&'a str, Vec<u8>)>) -> Case<'a> {
        with_files("zstd", args, files)
    }

    /// The three verbosities over `files`, each as `-l` with `extra`.
    fn list_all<'a>(files: &[(&'a str, Vec<u8>)], extra: &[&'a str]) -> Vec<Case<'a>> {
        let names: Vec<&str> = files.iter().map(|(n, _)| *n).collect();
        let mut v = Vec::new();
        for verbosity in [&["-l"][..], &["-lv"], &["-lvv"], &["-lq"]] {
            let mut args = verbosity.to_vec();
            args.extend_from_slice(extra);
            args.extend_from_slice(&names);
            v.push(listed(&args, files.to_vec()));
        }
        v
    }

    /// Frames the reference made: one, several, with and without a
    /// checksum or content size, long-window, empty, with a skippable
    /// frame before, between and after.
    #[test]
    fn list_reference_frames() {
        let t = super::compat_harness::text(5000, 21);
        let big = mixed(300_000, 22);
        let one = packed(&[], &t);
        let sized = packed(&["--stream-size=5000"], &t);
        let unchecked = packed(&["--no-check"], &t);
        let mut multi = packed(&[], &t);
        multi.extend(packed(&["--no-check"], &big));
        multi.extend(packed(&["--stream-size=5000"], &t));
        let mut skipped = skip_frame(0, 5);
        skipped.extend(&one);
        skipped.extend(skip_frame(15, 0));
        skipped.extend(&sized);
        skipped.extend(skip_frame(7, 100));
        let mut cases = Vec::new();
        for (name, f) in [
            ("one.zst", one.clone()),
            ("sized.zst", sized.clone()),
            ("unchecked.zst", unchecked),
            ("long.zst", packed(&["--long=27", "--stream-size=5000"], &t)),
            ("big.zst", packed(&["-19", "--stream-size=300000"], &big)),
            ("empty.zst", packed(&[], b"")),
            ("emptysized.zst", packed(&["--stream-size=0"], b"")),
            ("multi.zst", multi.clone()),
            ("skipped.zst", skipped.clone()),
            ("onlyskip.zst", skip_frame(3, 40)),
        ] {
            cases.extend(list_all(&[(name, f)], &[]));
        }
        cases.extend(list_all(&[("one.zst", one), ("sized.zst", sized)], &[]));
        cases.extend(list_all(
            &[
                ("multi.zst", multi),
                ("skipped.zst", skipped),
                ("e.zst", packed(&[], b"")),
            ],
            &[],
        ));
        check("list_reference_frames", &cases);
    }

    /// Dictionary IDs in a file: one, none, and differing frames (the
    /// warning without a newline).
    #[test]
    fn list_dictionary_ids() {
        let blocks = block(0, true, 3, b"abc");
        let f1 = hand(0x22, None, &[7], &[3], &blocks, &[]);
        let f2 = hand(0x22, None, &[9], &[3], &blocks, &[]);
        let none = hand(0x20, None, &[], &[3], &blocks, &[]);
        let mut cases = Vec::new();
        let mut same = f1.clone();
        same.extend(&f1);
        let mut differ = f1.clone();
        differ.extend(&f2);
        let mut back = f1.clone();
        back.extend(&none);
        let mut zero_then = none.clone();
        zero_then.extend(&f1);
        for (name, f) in [
            ("same.zst", same),
            ("differ.zst", differ),
            ("back.zst", back),
            ("zero.zst", zero_then),
        ] {
            cases.extend(list_all(&[(name, f)], &[]));
        }
        check("list_dictionary_ids", &cases);
    }

    /// Every width of the content-size and dictionary-ID fields, with and
    /// without a window byte, with and without a checksum, and the
    /// descriptors `ZSTD_getFrameHeader` refuses.
    #[test]
    fn list_header_fields() {
        let raw = block(0, true, 5, b"hello");
        let mut cases = Vec::new();
        let mut n = 0;
        let mut add = |f: Vec<u8>, cases: &mut Vec<Case<'static>>| {
            n += 1;
            let name: &'static str = Box::leak(format!("h{n}.zst").into_boxed_str());
            cases.extend(list_all(&[(name, f)], &[]));
        };
        // Content-size flag 0 (none, or one byte when single-segment), 1
        // (two bytes, plus 256), 2 (four), 3 (eight).
        for flag in 0u8..4 {
            for single in [false, true] {
                for did in [0u8, 1, 2, 3] {
                    let fcs_len =
                        [0usize, 2, 4, 8][usize::from(flag)] + usize::from(single && flag == 0);
                    let fcs: Vec<u8> = (0..fcs_len).map(|i| if i == 0 { 5 } else { 0 }).collect();
                    let did_bytes: Vec<u8> = (0..[0, 1, 2, 4][usize::from(did)])
                        .map(|i| 3 + i as u8)
                        .collect();
                    let fhd = (flag << 6) | (u8::from(single) << 5) | did;
                    let window = if single { None } else { Some(0x28) };
                    add(hand(fhd, window, &did_bytes, &fcs, &raw, &[]), &mut cases);
                    add(
                        hand(fhd | 4, window, &did_bytes, &fcs, &raw, &[1, 2, 3, 4]),
                        &mut cases,
                    );
                }
            }
        }
        // Content sizes that read as zstd's "unknown" and "error" markers,
        // and a very large one.
        for big in [u64::MAX, u64::MAX - 1, u64::MAX - 2, 1 << 40, 1 << 62] {
            add(
                hand(0xe0, None, &[], &big.to_le_bytes(), &raw, &[]),
                &mut cases,
            );
        }
        // A window mantissa and exponent grid, up to the limit and past it.
        for w in [0u8, 7, 8, 0x50, 0xb0, 0xb8, 0xf8, 0xff] {
            add(hand(0x00, Some(w), &[], &[], &raw, &[]), &mut cases);
        }
        // The reserved bit, the unused bit pattern.
        add(hand(0x08, Some(0), &[], &[], &raw, &[]), &mut cases);
        add(hand(0x2c, None, &[], &[5], &raw, &[1, 2, 3, 4]), &mut cases);
        check("list_header_fields", &cases);
    }

    /// `UTIL_makeHumanReadableSize` through declared content sizes: every
    /// unit boundary and the precision steps, at each verbosity (`-lvv`
    /// prints plain bytes).
    #[test]
    fn list_human_readable_sizes() {
        let raw = block(0, true, 1, b"a");
        let mut cases = Vec::new();
        let mut sizes: Vec<u64> = vec![0, 1, 9, 10, 99, 100, 999, 1000];
        for shift in [10u32, 20, 30, 40, 50, 60] {
            let u = 1u64 << shift;
            let m = |k: u64| u.saturating_mul(k);
            for d in [
                u - 1,
                u,
                u + 1,
                u + u / 2,
                m(10) - 1,
                m(10),
                m(100) - 1,
                m(100),
                m(999),
            ] {
                sizes.push(d);
            }
        }
        sizes.push((1 << 53) - 1);
        sizes.push(1 << 53);
        sizes.push((1 << 53) + 1);
        sizes.push(u64::MAX - 2);
        for (i, size) in sizes.iter().enumerate() {
            let name: &'static str = Box::leak(format!("z{i}.zst").into_boxed_str());
            let f = hand(0xe0, None, &[], &size.to_le_bytes(), &raw, &[]);
            cases.extend(list_all(&[(name, f)], &[]));
        }
        // And as a compressed size: a skippable frame of that many bytes
        // is too big to make, so the total of two files stands in.
        check("list_human_readable_sizes", &cases);
    }

    /// Block types, sizes and the ends of a frame: raw, RLE, compressed,
    /// reserved; many blocks; a block longer than the file; a block of
    /// 2 MiB - 1; no last block.
    #[test]
    fn list_blocks() {
        let mut cases = Vec::new();
        let mut n = 0;
        let mut add = |f: Vec<u8>, cases: &mut Vec<Case<'static>>| {
            n += 1;
            let name: &'static str = Box::leak(format!("b{n}.zst").into_boxed_str());
            cases.extend(list_all(&[(name, f)], &[]));
        };
        let h = |blocks: &[u8], check: bool| {
            hand(
                if check { 0x24 } else { 0x20 },
                None,
                &[],
                &[10],
                blocks,
                if check { &[9, 8, 7, 6] } else { &[] },
            )
        };
        add(h(&block(0, true, 0, b""), false), &mut cases);
        add(h(&block(1, true, 100_000, b"x"), true), &mut cases);
        add(h(&block(2, true, 3, b"abc"), true), &mut cases);
        add(h(&block(3, true, 3, b"abc"), true), &mut cases);
        let mut many = block(0, false, 2, b"ab");
        many.extend(block(1, false, 7, b"z"));
        many.extend(block(2, true, 1, b"q"));
        add(h(&many, true), &mut cases);
        // No last block: the next header is the frame's own bytes, then EOF.
        add(h(&block(0, false, 2, b"ab"), false), &mut cases);
        // Longer than the file, and right at the end.
        add(h(&block(0, true, 1000, b"ab"), false), &mut cases);
        add(h(&block(0, true, 4, b"abcd"), true), &mut cases);
        add(h(&block(2, true, (1 << 21) - 1, b""), false), &mut cases);
        // Followed by garbage that is, or is not, a frame.
        let mut tail = h(&block(0, true, 2, b"ab"), false);
        tail.extend_from_slice(b"\x28\xb5\x2f");
        add(tail, &mut cases);
        let mut tail = h(&block(0, true, 2, b"ab"), true);
        tail.extend_from_slice(b"garbage that is not a frame at all");
        add(tail, &mut cases);
        check("list_blocks", &cases);
    }

    /// Skippable frames: every variant, sizes around the read size, sizes
    /// that run past the file, and sizes whose 32-bit sum wraps (zstd steps
    /// back; a frame that would never advance is an error here where zstd
    /// loops forever, so that one size is not compared).
    #[test]
    fn list_skippable_frames() {
        let mut cases = Vec::new();
        let mut n = 0;
        let mut add = |f: Vec<u8>, cases: &mut Vec<Case<'static>>| {
            n += 1;
            let name: &'static str = Box::leak(format!("s{n}.zst").into_boxed_str());
            cases.extend(list_all(&[(name, f)], &[]));
        };
        for v in 0..16u8 {
            add(skip_frame(v, 11), &mut cases);
        }
        for len in [0usize, 1, 9, 10, 11, 12, 13, 17, 18, 100] {
            add(skip_frame(0, len), &mut cases);
        }
        let mut ends = skip_frame(1, 3);
        ends.extend(skip_frame(2, 0));
        ends.extend(skip_frame(3, 20));
        add(ends, &mut cases);
        for size in [
            100u32,
            0xffff_fff0,
            0xffff_ffff,
            0xffff_fff9,
            0xffff_fffd,
            0xffff_fffe,
        ] {
            let mut f = vec![0x5a, 0x2a, 0x4d, 0x18];
            f.extend_from_slice(&size.to_le_bytes());
            f.extend_from_slice(&[0x11; 40]);
            add(f, &mut cases);
        }
        // A skippable frame cut inside its own header (5 to 7 bytes: zstd
        // reads the size field's missing bytes from its buffer), first in
        // the file and after a frame whose header filled the buffer.
        let whole = skip_frame(2, 3);
        for len in 0..8 {
            add(whole[..len].to_vec(), &mut cases);
            let mut after = hand(
                0xe4,
                None,
                &[],
                &[0, 0, 0, 0, 0, 0, 0, 0],
                &block(0, true, 1, b"a"),
                &[1, 2, 3, 4],
            );
            after.extend_from_slice(&whole[..len]);
            add(after, &mut cases);
        }
        // A wrapped size that lands inside the next header.
        let mut f = vec![0x50, 0x2a, 0x4d, 0x18, 0xfd, 0xff, 0xff, 0xff];
        f.extend_from_slice(&[0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0]);
        add(f, &mut cases);
        check("list_skippable_frames", &cases);
    }

    /// Every prefix of a file of two frames and a skippable frame, with
    /// and without checksums: the truncation messages at each byte.
    #[test]
    fn list_every_prefix() {
        let blocks = {
            let mut b = block(0, false, 3, b"abc");
            b.extend(block(1, true, 9, b"z"));
            b
        };
        let mut whole = hand(0x64, Some(0x10), &[], &[2, 0], &blocks, &[1, 2, 3, 4]);
        whole.extend(skip_frame(2, 6));
        whole.extend(hand(0x23, None, &[1, 2, 3, 4], &[7], &blocks, &[]));
        let mut cases = Vec::new();
        for len in 0..=whole.len() {
            let name: &'static str = Box::leak(format!("p{len}.zst").into_boxed_str());
            cases.push(listed(&["-l", name], vec![(name, whole[..len].to_vec())]));
            cases.push(listed(&["-lv", name], vec![(name, whole[..len].to_vec())]));
        }
        check("list_every_prefix", &cases);
    }

    /// Prefixes of a file the reference made.
    #[test]
    fn list_truncated_reference_file() {
        let t = super::compat_harness::text(3000, 31);
        let mut whole = packed(&["--stream-size=3000"], &t);
        whole.extend(packed(&[], &t));
        let mut cases = Vec::new();
        for len in (0..whole.len()).step_by(3) {
            let name: &'static str = Box::leak(format!("t{len}.zst").into_boxed_str());
            cases.push(listed(&["-l", name], vec![(name, whole[..len].to_vec())]));
        }
        check("list_truncated_reference_file", &cases);
    }

    /// Operands that are not frames, are not files, or are standard input.
    #[test]
    fn list_refusals() {
        let z = packed(&[], &text());
        let gz = member(plain_member(&text()));
        let mut cases = Vec::new();
        for args in [
            &["-l", "nothing.zst"][..],
            &["-lv", "nothing.zst"],
            &["-l", "dir"],
            &["-lv", "dir"],
            &["-l", "-"],
            &["-lv", "-"],
            &["-l", "a.zst", "-"],
            &["-l"],
            &["-lv"],
            &["-lq"],
            &["-lqq", "nothing.zst", "a.zst", "dir", "gz"],
            &["-l", "gz"],
            &["-lv", "gz"],
            &["-l", "text"],
            &["-lvv", "text", "a.zst", "gz", "nothing.zst", "a.zst"],
            &["--list", "a.zst", "b.zst"],
            &["--list", "-r", "dir"],
            &["-l", "--", "-v"],
            &["-lf", "a.zst"],
            &["-lc", "a.zst"],
            &["-l", "-o", "x", "a.zst"],
            &["-l", "-k", "--rm", "a.zst"],
            &["-l", "--no-progress", "a.zst"],
            &["-l", "-T2", "-3", "a.zst"],
            &["-ld", "a.zst"],
            &["-lt", "a.zst"],
            &["-ldl", "a.zst"],
        ] {
            let mut c = listed(
                args,
                vec![
                    ("a.zst", z.clone()),
                    ("b.zst", z.clone()),
                    ("gz", gz.clone()),
                    ("text", text()),
                    ("dir/inner.zst", z.clone()),
                ],
            );
            c.stdin = Some(z.clone());
            cases.push(c);
        }
        check("list_refusals", &cases);
    }

    /// `-l` over a symbolic link and a link to a link (the operand filter
    /// runs first), and a FIFO is "not a file".
    #[test]
    fn list_links() {
        fn links(dir: &Path) {
            std::os::unix::fs::symlink("a.zst", dir.join("l.zst")).unwrap();
            std::os::unix::fs::symlink("l.zst", dir.join("ll.zst")).unwrap();
            std::os::unix::fs::symlink("nothing", dir.join("dangling.zst")).unwrap();
        }
        let z = packed(&[], &text());
        let mut cases = Vec::new();
        for args in [
            &["-l", "l.zst"][..],
            &["-l", "ll.zst", "a.zst"],
            &["-l", "dangling.zst"],
            &["-lf", "l.zst"],
            &["-l", "--no-force", "l.zst"],
        ] {
            cases.push(with_setup(listed(args, vec![("a.zst", z.clone())]), links));
        }
        check("list_links", &cases);
    }

    /// Many files: the totals line, a file with no content size among
    /// them, one without a checksum, and one that fails.
    #[test]
    fn list_totals() {
        let t = super::compat_harness::text(4000, 41);
        let sized = packed(&["--stream-size=4000"], &t);
        let streamed = packed(&[], &t);
        let unchecked = packed(&["--no-check", "--stream-size=4000"], &t);
        let files = vec![
            ("sized.zst", sized),
            ("streamed.zst", streamed),
            ("unchecked.zst", unchecked),
            ("skip.zst", skip_frame(1, 50)),
            ("bad.zst", b"not zstd, at all, really".to_vec()),
            ("cut.zst", packed(&[], &t)[..30].to_vec()),
        ];
        let mut cases = Vec::new();
        for names in [
            &["sized.zst", "sized.zst"][..],
            &["sized.zst", "unchecked.zst"],
            &["sized.zst", "streamed.zst"],
            &["sized.zst", "skip.zst", "unchecked.zst"],
            &["sized.zst", "bad.zst", "sized.zst"],
            &["sized.zst", "cut.zst", "sized.zst"],
            &["bad.zst", "cut.zst"],
            &["sized.zst", "bad.zst"],
        ] {
            for v in ["-l", "-lv", "-lvv", "-lq"] {
                let mut args = vec![v];
                args.extend_from_slice(names);
                cases.push(listed(&args, files.clone()));
            }
        }
        check("list_totals", &cases);
    }

    // ---- part 5 (Task 8): training, dictionaries, --patch-from, --adapt ----

    fn samples() -> Vec<(&'static str, Vec<u8>)> {
        zstd_samples()
    }

    fn sample_names() -> Vec<&'static str> {
        samples().iter().map(|(n, _)| *n).collect()
    }

    /// A `--train*` case over every sample, `args` first.
    fn training<'a>(args: &[&'a str]) -> Case<'a> {
        let mut all = args.to_vec();
        all.extend(sample_names());
        with_files("zstd", &all, samples())
    }

    /// Whether `c` trains with the cover algorithm (ruling T1-a).
    fn trains_cover(c: &Case) -> bool {
        c.args.iter().any(|a| a.starts_with("--train-cover"))
    }

    /// The dictionary file `c` writes: `-o NAME`, else `dictionary`.
    fn dictionary_name<'a>(c: &Case<'a>) -> &'a str {
        c.args
            .iter()
            .position(|a| *a == "-o")
            .and_then(|i| c.args.get(i + 1).copied())
            .unwrap_or("dictionary")
    }

    /// Ruling T1-a (spec deviation 6): libzstd's cover sort breaks ties by
    /// pointer address, so a cover dictionary is promised valid and usable
    /// by the reference, not byte for byte. Ours must be a formatted
    /// dictionary the reference compresses and decompresses every sample
    /// with; then it stands for the reference's, and the sizes in the
    /// "Save dictionary" line are blanked on both sides.
    fn cover_structural(c: &Case, r: &mut Run, s: &mut Run) {
        let name = dictionary_name(c);
        let (Some((rb, _, _)), Some((sb, _, _))) = (r.tree.get(name), s.tree.get(name)) else {
            return;
        };
        let (rb, sb) = (rb.clone(), sb.clone());
        if rb != sb {
            assert_eq!(
                &sb[..4],
                &[0x37, 0xa4, 0x30, 0xec],
                "{:?}: not a dictionary",
                c.args
            );
            let dir = ScratchDir::at(std::env::temp_dir().join(format!(
                "stuffr-zstd-cover-{}-{}",
                std::process::id(),
                c.args.len() * 1000 + sb.len() % 1000
            )));
            fs::create_dir_all(&*dir).unwrap();
            let d = dir.join("d");
            fs::write(&d, &sb).unwrap();
            let d = d.to_str().unwrap();
            for (_, sample) in samples().iter().step_by(7) {
                let z = filter_through(ref_zstd(), &["-q", "-c", "-D", d], sample).unwrap();
                let back = filter_through(ref_zstd(), &["-q", "-dc", "-D", d], &z).unwrap();
                assert_eq!(&back, sample, "{:?}: the reference cannot use ours", c.args);
            }
            s.tree.get_mut(name).unwrap().0 = rb;
        }
        let blank = |t: &str| {
            let mut out = String::new();
            for line in t.split_inclusive('\n') {
                match line.strip_prefix("Save dictionary of size ") {
                    Some(rest) => {
                        let tail = rest.trim_start_matches(|ch: char| ch.is_ascii_digit());
                        out.push_str("Save dictionary of size <n>");
                        out.push_str(tail);
                    }
                    None => out.push_str(line),
                }
            }
            out
        };
        r.stderr = blank(&r.stderr);
        s.stderr = blank(&s.stderr);
    }

    /// zstdcli.c built with `ZSTD_NODICT` (the pure tier, spec deviation
    /// 7): `--train` says so, exit 1.
    const NODICT: &str = "training mode not available \n";

    /// The pure tier's training: `--train-cover`, `--train-fastcover` and
    /// `--train-legacy` are no options there, so the reference's answer
    /// to the same option under another name (`--Xrain-…`, also unknown)
    /// is the expectation, the name put back; `--train` itself prints
    /// [`NODICT`]. Nothing is written either way.
    fn pure_nodict(dir: &str, c: &Case) -> bool {
        if c.args.iter().any(|a| a.starts_with("--train-")) {
            let Some(mut r) = nodict_reference(dir, c) else {
                return false;
            };
            let mut s = stuffr_as(c);
            mask_banners(&mut r, &mut s);
            assert_same(c, &r, &s);
            return true;
        }
        let s = stuffr_as(c);
        assert_eq!(s.code, 1, "{:?}", c.args);
        if c.args.iter().any(|a| *a == "-qq" || *a == "-qqq") {
            assert_eq!(s.stderr, "", "{:?}", c.args);
        } else if c.args.iter().any(|a| a.starts_with("-v")) {
            assert!(s.stderr.ends_with(NODICT), "{:?}: {:?}", c.args, s.stderr);
        } else {
            assert_eq!(s.stderr, NODICT, "{:?}", c.args);
        }
        assert!(s.stdout.is_empty(), "{:?}", c.args);
        let names: Vec<&str> = s
            .tree
            .keys()
            .map(String::as_str)
            .filter(|n| !n.ends_with('/'))
            .collect();
        let mut inputs: Vec<&str> = c.files.iter().map(|(n, _)| *n).collect();
        inputs.sort_unstable();
        assert_eq!(names, inputs, "{:?}: wrote something", c.args);
        true
    }

    /// The reference's run of `c`, as a zstd built with `ZSTD_NODICT`
    /// answers it on the pure tier (spec deviation 7): the first
    /// `--train-cover`, `--train-fastcover` or `--train-legacy` option is
    /// unknown there, so the reference runs with it renamed to an unknown
    /// `--Xrain-…` and the name is put back in its standard error. On the
    /// C tier, and without such an option, the reference's own run.
    fn nodict_reference(dir: &str, c: &Case) -> Option<Run> {
        let Some(i) = c
            .args
            .iter()
            .position(|a| a.starts_with("--train-"))
            .filter(|_| !EXACT)
        else {
            return reference(dir, c);
        };
        let mut args = c.args.clone();
        args[i] = leak(format!("--Xrain-{}", &c.args[i]["--train-".len()..]));
        let renamed = Case {
            name: c.name,
            args,
            files: c.files.clone(),
            stdin: c.stdin.clone(),
            tty_stdin: c.tty_stdin,
            tty_stdout: c.tty_stdout,
            env: c.env.clone(),
            compare_output_bytes: c.compare_output_bytes,
            expect_stdout_plain: None,
            setup: c.setup,
            roundtrip: c.roundtrip,
        };
        let mut r = reference(dir, &renamed)?;
        r.stderr = r.stderr.replace("--Xrain-", "--train-");
        Some(r)
    }

    /// libzstd's trainers draw their own progress, `\r%u%%       ` (cover,
    /// fastcover) and `\r%4.2f %% \r` (legacy), whenever 0.15 s of CPU
    /// time has passed since the last one (`clock()`), so how many appear
    /// varies from run to run of the reference itself (spec deviation 2's
    /// timing). Every such token is removed, on both sides. dibio.c's own
    /// `Loading %s...       \r` is drawn the same way by wall clock (a sixth
    /// of a second) after the first, so only the first of a run of them is
    /// kept. The rest of standard error is compared.
    fn strip_trainer_progress(t: &str) -> String {
        let b = t.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        let mut after_loading = false;
        while i < b.len() {
            if b[i..].starts_with(b"Loading ")
                && let Some(end) = b[i..].iter().position(|c| *c == b'\r' || *c == b'\n')
                && b[i + end] == b'\r'
                && b[i..i + end].ends_with(b"...       ")
            {
                if !after_loading {
                    out.extend_from_slice(&b[i..=i + end]);
                }
                after_loading = true;
                i += end + 1;
                continue;
            }
            after_loading = false;
            if b[i] == b'\r' {
                let digits = b[i + 1..].iter().take_while(|c| c.is_ascii_digit()).count();
                let at = i + 1 + digits;
                if digits > 0 && b[at..].starts_with(b"%       ") {
                    i = at + 8;
                    continue;
                }
                // `%4.2f %% \r`: optional padding, digits, '.', two digits.
                let pad = b[i + 1..].iter().take_while(|c| **c == b' ').count();
                let at = i + 1 + pad;
                let whole = b[at..].iter().take_while(|c| c.is_ascii_digit()).count();
                let at = at + whole;
                if whole > 0
                    && b.len() >= at + 3
                    && b[at] == b'.'
                    && b[at + 1].is_ascii_digit()
                    && b[at + 2].is_ascii_digit()
                    && b[at + 3..].starts_with(b" % \r")
                {
                    i = at + 3 + 4;
                    continue;
                }
            }
            out.push(b[i]);
            i += 1;
        }
        String::from_utf8(out).unwrap()
    }

    /// Training cases against the reference: on the C tier everything is
    /// compared, the dictionary byte for byte (cover: structurally, ruling
    /// T1-a); on the pure tier, [`pure_nodict`].
    fn check_train(group: &str, cases: &[Case]) {
        let one = |c: &Case| -> bool {
            let Some(dir) = zstd_dir() else { return false };
            if !EXACT {
                return pure_nodict(dir, c);
            }
            let Some(mut r) = reference(dir, c) else {
                return false;
            };
            let mut s = stuffr_as(c);
            r.stderr = strip_trainer_progress(&r.stderr);
            s.stderr = strip_trainer_progress(&s.stderr);
            if trains_cover(c) {
                cover_structural(c, &mut r, &mut s);
            }
            mask_banners(&mut r, &mut s);
            assert_same(c, &r, &s);
            true
        };
        run_group(group, cases, Skipped::none(), &one);
    }

    /// `--train` and its three algorithms with their parameter strings,
    /// over 100 one-record files; `-r` on their directory.
    #[test]
    fn train_algorithms() {
        let mut cases = Vec::new();
        for args in [
            &["--train"][..],
            &["--train-fastcover"],
            &["--train-fastcover=k=64,d=8,f=20,accel=2"],
            &["--train-fastcover=k=64,d=6,steps=2,split=50"],
            &["--train-fastcover=shrink"],
            &["--train-legacy"],
            &["--train-legacy=s=5"],
            &["--train-cover"],
            &["--train-cover=k=64,d=8"],
            &["--train-cover=shrink"],
            &["--train-cover=k=48,d=6,shrink=2"],
            &["-19", "--train"],
            &["--fast=3", "--train-fastcover=k=64,d=8"],
            &["--train", "-T1"],
        ] {
            cases.push(training(args));
        }
        cases.push(with_files("zstd", &["--train", "-r", "samples"], samples()));
        check_train("train_algorithms", &cases);
    }

    /// `--maxdict`, `--dictID`, `-o`, `-B#`, `-M#`, the display levels.
    #[test]
    fn train_options() {
        let mut cases = Vec::new();
        for args in [
            &["--train", "--maxdict=4K"][..],
            &["--train", "--maxdict=2000", "--train-legacy"],
            &["--train", "--dictID=1234"],
            &["--train-legacy", "--dictID=4294967295"],
            &["--train", "-o", "mydict"],
            &["--train", "-M16K"],
            &["--train", "--memory=1MB"],
            &["--train", "-q"],
            &["--train", "-qq"],
            &["--train-legacy", "-qqq"],
            &["--train", "-v", "-T1"],
            &["--train-legacy", "-v"],
            &["--train", "-vvvv", "-T1"],
            &["--train", "-B300"],
            &["--train-legacy", "-B200"],
        ] {
            cases.push(training(args));
        }
        // -B# over three large files: each one is many samples.
        let big = vec![
            ("big1", super::compat_harness::text(64 << 10, 81)),
            ("big2", super::compat_harness::text(48 << 10, 82)),
            ("big3", super::compat_harness::text(20 << 10, 83)),
        ];
        for args in [
            &["--train", "-B4K", "big1", "big2", "big3"][..],
            &["--train", "-B4K", "--maxdict=8K", "big1", "big2", "big3"],
            &["--train", "big1", "big2", "big3"],
        ] {
            cases.push(with_files("zstd", args, big.clone()));
        }
        // A sample over 256 KiB: loaded as its first 128 KiB, with the
        // warnings (`-v`: the per-file note).
        for v in ["-q", "-v"] {
            let mut files = samples();
            files.push(("huge", super::compat_harness::text(300 << 10, 84)));
            let mut args = vec!["--train", v, "-T1", "huge"];
            args.extend(sample_names());
            cases.push(with_files("zstd", &args, files));
        }
        check_train("train_options", &cases);
    }

    /// The refusals: too few samples, empty and missing ones, a bad
    /// parameter string, no samples at all, an output that cannot be
    /// opened.
    #[test]
    fn train_refused() {
        let s = samples();
        let few = vec![s[0].clone(), s[1].clone(), ("empty", Vec::new())];
        let mut cases = vec![
            with_files(
                "zstd",
                &["--train", "samples/s000.json", "samples/s001.json"],
                few.clone(),
            ),
            with_files(
                "zstd",
                &["--train", "-qq", "samples/s000.json", "samples/s001.json"],
                few.clone(),
            ),
            with_files(
                "zstd",
                &[
                    "--train",
                    "-v",
                    "samples/s000.json",
                    "empty",
                    "samples/s001.json",
                ],
                few.clone(),
            ),
            with_files("zstd", &["--train"], Vec::new()),
            // Unmeasurable samples count in dibio.c's totals (size -1).
            with_files(
                "zstd",
                &["--train", "m1", "m2", "m3", "m4", "m5", "m6"],
                Vec::new(),
            ),
            with_files(
                "zstd",
                &[
                    "--train",
                    "m1",
                    "samples/s000.json",
                    "samples/s001.json",
                    "samples/s002.json",
                    "samples/s003.json",
                ],
                few.clone(),
            ),
        ];
        for args in [
            &["--train-fastcover=k=64,q=1"][..],
            &["--train-legacy=s=5,x"],
            &["--train-cover=k=64,d=8,steps"],
            &["--train", "-o", "samples"],
            &["--train-cover=k=8,d=16"],
            &["--train", "--maxdict=10"],
        ] {
            cases.push(training(args));
        }
        check_train("train_refused", &cases);
    }

    /// `data` compressed by the reference with the dictionary `dict` (`-D`
    /// or, with `patch`, `--patch-from`), plus `args`.
    fn packed_with(dict: &[u8], patch: bool, args: &[&str], data: &[u8]) -> Vec<u8> {
        if zstd_dir().is_none() {
            return Vec::new();
        }
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = ScratchDir::at(std::env::temp_dir().join(format!(
            "stuffr-zstd-packed-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )));
        fs::create_dir_all(&*dir).unwrap();
        let d = dir.join("d");
        fs::write(&d, dict).unwrap();
        let d = d.to_str().unwrap();
        let mut a: Vec<&str> = args.to_vec();
        if patch {
            // A stream needs its size for --patch-from.
            a.push(leak(format!("--patch-from={d}")));
            a.push(leak(format!("--stream-size={}", data.len())));
        } else {
            a.extend(["-D", d]);
        }
        a.extend(["-q", "-c"]);
        filter_through(ref_zstd(), &a, data).unwrap_or_default()
    }

    /// The dictionary files the `-D` cases use: the reference's trained
    /// dictionary, the same with another ID (the wrong one), and raw
    /// content.
    fn dict_files() -> Vec<(&'static str, Vec<u8>)> {
        let d = zstd_trained_dictionary().unwrap_or_default().to_vec();
        let mut wrong = d.clone();
        if wrong.len() >= 8 {
            wrong[4..8].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        }
        let msg = super::compat_harness::text(30_000, 85);
        let z = packed_with(&d, false, &[], &msg);
        let zraw = packed_with(&msg[..4000], false, &[], &msg);
        vec![
            ("dict", d),
            ("wrong", wrong),
            ("raw", msg[..4000].to_vec()),
            ("msg", msg),
            ("msg.zst", z),
            ("raw.zst", zraw),
        ]
    }

    /// `-D`: compressing and decompressing with a trained and a raw
    /// dictionary; the wrong dictionary, none, a missing one, one too
    /// large; `-l` naming its ID. The pure tier refuses to compress with a
    /// dictionary (the pinned refusal, in `check`) and decodes with one.
    #[test]
    fn dictionaries() {
        let files = dict_files();
        let mut cases = Vec::new();
        for args in [
            &["-D", "dict", "-c", "msg"][..],
            &["-q", "-D", "dict", "-o", "m.zst", "msg"],
            &["-19", "-D", "dict", "-c", "msg"],
            &["--no-dictID", "-D", "dict", "-c", "msg"],
            &["-D", "raw", "-c", "msg"],
            &["-D", "dict", "-c", "-T2", "msg"],
            &["-D", "dict", "-v", "-c", "msg"],
            &["-D", "dict", "-vvvv", "-c", "msg"],
            &["-d", "-D", "dict", "msg.zst"],
            &["-dc", "-D", "dict", "msg.zst"],
            &["-t", "-D", "dict", "msg.zst"],
            &["-dc", "-D", "raw", "raw.zst"],
            &["-dc", "-D", "wrong", "msg.zst"],
            &["-dc", "msg.zst"],
            &["-D", "missing", "-c", "msg"],
            &["-dc", "-D", "missing", "msg.zst"],
            &["-D", "samples", "-c", "msg"],
            &["-l", "msg.zst"],
            &["-lv", "msg.zst"],
            &["-lv", "raw.zst"],
        ] {
            let mut f = files.clone();
            if args.contains(&"samples") {
                f.push(("samples/x", b"x".to_vec()));
            }
            cases.push(with_files("zstd", args, f));
        }
        check("dictionaries", &cases);
    }

    /// An input that is the dictionary itself is skipped, after the
    /// dictionary is loaded; the pure tier refuses at the loading, before
    /// any input (spec deviation 7).
    #[test]
    fn input_is_the_dictionary() {
        let cases = vec![
            with_files("zstd", &["-D", "msg", "msg"], vec![("msg", text())]),
            with_files(
                "zstd",
                &["-D", "msg", "msg", "a"],
                vec![("msg", text()), ("a", text())],
            ),
        ];
        if EXACT {
            check("input_is_the_dictionary", &cases);
            return;
        }
        for c in &cases {
            let s = stuffr_as(c);
            assert_eq!(s.code, 1, "{:?}", c.args);
            assert_eq!(
                s.stderr,
                "zstd: error 1 : dictionary compression is not available in this build (stuffr pure tier) \n",
                "{:?}",
                c.args
            );
        }
    }

    /// A frame made with raw content decoded with a formatted dictionary
    /// of no ID: libzstd decodes garbage and the checksum catches it. The
    /// pure tier's decoder meets the corruption first and names it so
    /// (ruling T5-b); the exit code and the rest are compared.
    #[test]
    fn dictionary_of_the_wrong_content() {
        let files = dict_files();
        let c = with_files("zstd", &["-dc", "-D", "dict", "raw.zst"], files);
        let one = |c: &Case| -> bool {
            let Some(dir) = zstd_dir() else { return false };
            let Some(mut r) = reference(dir, c) else {
                return false;
            };
            let s = stuffr_as(c);
            if !EXACT {
                r.stderr = r.stderr.replace(
                    "Decoding error (36) : Restored data doesn't match checksum",
                    "Decoding error (36) : Data corruption detected",
                );
                // The pure decoder stops at the corruption, libzstd at the
                // checksum after the last block: ours is a prefix.
                assert!(r.stdout.starts_with(&s.stdout), "{:?}", c.args);
                r.stdout.clone_from(&s.stdout);
            }
            assert_same(c, &r, &s);
            true
        };
        run_group(
            "dictionary_of_the_wrong_content",
            &[c],
            Skipped::none(),
            &one,
        );
    }

    /// A dictionary over fileio.c's 32 MiB `DICTSIZE_MAX`.
    #[test]
    fn dictionary_too_large() {
        let big = vec![0u8; (32 << 20) + 1];
        let cases = vec![
            with_files(
                "zstd",
                &["-D", "big", "-c", "msg"],
                vec![("big", big.clone()), ("msg", text())],
            ),
            with_files(
                "zstd",
                &["-dc", "-D", "big", "msg"],
                vec![("big", big), ("msg", text())],
            ),
        ];
        check("dictionary_too_large", &cases);
    }

    /// An old file and a new one that differs from it in a few places.
    fn patch_pair(n: usize, seed: u64) -> (Vec<u8>, Vec<u8>) {
        let old = super::compat_harness::text(n, seed);
        let mut new = old.clone();
        for (i, at) in [n / 7, n / 3, n / 2, n * 5 / 6].iter().enumerate() {
            new.splice(*at..*at, format!(" <edit {i}> ").into_bytes());
        }
        new.truncate(new.len() - n / 50);
        (old, new)
    }

    /// `--patch-from` both ways: the levels, `--long`, `--memory`, a
    /// stream, an old file far bigger than the new one's window and the
    /// other way round, and the display levels that print its notes.
    #[test]
    fn patch_from() {
        let (old, new) = patch_pair(200_000, 86);
        let (bigold, small) = (
            super::compat_harness::text(1 << 20, 87),
            super::compat_harness::text(4000, 88),
        );
        let z = packed_with(&old, true, &[], &new);
        let zl = packed_with(&old, true, &["--long=24", "-19"], &new);
        let zs = packed_with(&bigold, true, &[], &small);
        let files = vec![
            ("old", old),
            ("new", new.clone()),
            ("new.zst", z),
            ("long.zst", zl),
            ("bigold", bigold),
            ("small", small),
            ("small.zst", zs),
        ];
        let mut cases = Vec::new();
        for args in [
            &["-q", "--patch-from=old", "-o", "p.zst", "new"][..],
            &["--patch-from=old", "-c", "new"],
            &["-q", "--patch-from", "old", "-o", "p.zst", "new"],
            &["-1", "--patch-from=old", "-c", "new"],
            &["-19", "--patch-from=old", "-c", "new"],
            &["--long", "--patch-from=old", "-c", "new"],
            &["--long=24", "-19", "--patch-from=old", "-c", "new"],
            &["-M1MB", "--patch-from=old", "-c", "new"],
            &["--memory=512KB", "--patch-from=old", "-c", "new"],
            &["-vvvv", "-19", "--patch-from=old", "-c", "new"],
            &["-v", "--patch-from=old", "-c", "new"],
            &["--patch-from=bigold", "-c", "small"],
            &["-19", "--patch-from=bigold", "-c", "small"],
            &["-1", "--patch-from=small", "-c", "bigold"],
            &["--patch-from=missing", "-c", "new"],
            &["-d", "--patch-from=old", "new.zst", "-o", "out"],
            &["-dc", "--patch-from=old", "new.zst"],
            &["-dc", "--patch-from=old", "long.zst"],
            &["-dc", "--patch-from=old", "--memory=1MB", "long.zst"],
            &["-dc", "--patch-from=bigold", "small.zst"],
            &["-dc", "--patch-from=small", "new.zst"],
            &["-dc", "new.zst"],
            &["-t", "--patch-from=old", "new.zst"],
        ] {
            let mut c = with_files("zstd", args, files.clone());
            if args.contains(&"new.zst") || args.contains(&"long.zst") {
                c.expect_stdout_plain = Some(new.clone());
            }
            cases.push(c);
        }
        // A stream needs --stream-size.
        cases.push(fed(
            with_files("zstd", &["--patch-from=old", "-c"], files.clone()),
            new.clone(),
        ));
        let ss = leak(format!("--stream-size={}", new.len()));
        cases.push(fed(
            with_files("zstd", &["--patch-from=old", "-c", ss], files.clone()),
            new,
        ));
        check("patch_from", &cases);
    }

    /// `--adapt` (R10): the level moves with timing, so only the exit
    /// code, the round trip and `-q`'s empty standard error are compared.
    #[test]
    fn adapt() {
        let big = super::compat_harness::text(6 << 20, 89);
        let mut cases = Vec::new();
        for args in [
            &["-q", "--adapt", "-c", "big"][..],
            &["-q", "--adapt=min=1,max=19", "-c", "big"],
            &["-q", "--adapt", "-T2", "-k", "big"],
            &["-q", "--adapt=min=3,max=5", "-T4", "-c", "big"],
            &["-q", "--adapt", "-c", "small"],
        ] {
            let mut c = with_files("zstd", args, vec![("big", big.clone()), ("small", text())]);
            c.compare_output_bytes = false;
            c.expect_stdout_plain = Some(if args.contains(&"big") {
                big.clone()
            } else {
                text()
            });
            cases.push(c);
        }
        check("adapt", &cases);
    }
}
