//! The xz compatibility family against XZ Utils 5.8.4: stuffr invoked as
//! `xz`, `unxz`, `xzcat`, `lzma`, `unlzma` and `lzcat`, compared with the
//! reference through `compat_harness`, every case under `LC_ALL=C`.
//!
//! Part 4 (Task 8): `-v`/`-vv` with standard error not a terminal
//! (`flags_accepted_verbose`, and `-vv` in `memlimit_reduces_threads_like_xz`):
//! the line xz prints as each file ends, and before an error. The speed
//! and elapsed time are left out of the comparison (`progress_line`); the
//! terminal forms and the signals' lines are message.rs's unit tests
//! (Ruling R4, `tests/fixtures/xz_progress/`). `--info-memory` and its
//! robot form are `info_memory`, here since Task 5.
//!
//! Part 3 (Task 7): `--list` at every verbosity and under `--robot`, over
//! the reference's own streams and over hand-made ones (`made_xz`) whose
//! Block Headers and Indexes no encoder writes: every filter, every check
//! ID, sizes that only a crafted Index declares, and corrupt ones.
//!
//! Part 2 (Task 6): compression, decompression and testing over files and
//! streams; the compressed bytes themselves are `compat_xz_bytes.rs`'s.
//!
//! Part 1 (0.13.0 Task 5): the argument surface. Options refused and their
//! messages, the help texts, `--version`, `XZ_DEFAULTS`/`XZ_OPT`, the six
//! names, and the parse-time half of the suffix rules, with the cases that
//! run the coder (every option accepted, each name over standard input,
//! the suffix rules met while processing a file).
//!
//! The only normalisations: the program path in the help texts' `Usage:`
//! line (each side prints its own `argv[0]`; the harness already does this
//! for standard error), and `--version`'s first line, which names stuffr
//! (checked exactly before it is masked).

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod unix {
    use super::compat_harness::*;
    use std::process::{Command, Stdio};

    // ---- the reference ----

    /// The reference is XZ Utils 5.8.4 exactly, and the five links beside
    /// `xz` exist. Skipped locally with a note when there is none; under `CI`
    /// `xz_dir` itself panics.
    #[test]
    fn reference_is_5_8_4() {
        let Some(dir) = xz_dir() else { return };
        let out = output(
            Command::new(format!("{dir}/xz"))
                .args(["--robot", "--version"])
                .env_clear()
                .stdin(Stdio::null()),
        )
        .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "XZ_VERSION=50080042\nLIBLZMA_VERSION=50080042\n"
        );
        for link in ["unxz", "xzcat", "lzma", "unlzma", "lzcat"] {
            assert!(
                std::path::Path::new(dir).join(link).exists(),
                "{dir}/{link} is missing"
            );
        }
    }

    fn ref_xz() -> &'static str {
        static P: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        P.get_or_init(|| format!("{}/xz", xz_dir().unwrap_or("/nonexistent")))
    }

    /// Bytes the reference makes of `data` with `args` (`-c` added).
    fn reference_output(args: &[&str], data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut child = spawn(
            Command::new(ref_xz())
                .arg("-c")
                .args(args)
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )
        .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let data = data.to_vec();
        let t = std::thread::spawn(move || stdin.write_all(&data));
        let out = child.wait_with_output().unwrap();
        t.join().unwrap().unwrap();
        assert!(
            out.status.success(),
            "reference xz -c {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    }

    fn text() -> Vec<u8> {
        b"the quick brown fox jumps over the lazy dog\n".repeat(40)
    }

    // ---- cases ----

    fn case<'a>(name: &'a str, args: &[&'a str]) -> Case<'a> {
        Case {
            name,
            args: args.to_vec(),
            files: vec![("a", text())],
            stdin: None,
            tty_stdin: false,
            tty_stdout: false,
            env: vec![("LC_ALL", "C")],
            compare_output_bytes: false,
            expect_stdout_plain: None,
            setup: None,
            roundtrip: Roundtrip::Xz { ref_xz: ref_xz() },
        }
    }

    fn xz<'a>(args: &[&'a str]) -> Case<'a> {
        case("xz", args)
    }

    fn with_env<'a>(mut c: Case<'a>, k: &'a str, v: &'a str) -> Case<'a> {
        c.env.push((k, v));
        c
    }

    fn fed<'a>(mut c: Case<'a>, stdin: Vec<u8>) -> Case<'a> {
        c.stdin = Some(stdin);
        c
    }

    fn with_file<'a>(mut c: Case<'a>, name: &'a str, bytes: Vec<u8>) -> Case<'a> {
        c.files.push((name, bytes));
        c
    }

    // ---- normalisation ----

    /// The help texts' `Usage: <argv[0]> [OPTION]...` names each side's own
    /// program path; make it the invoked name.
    fn usage_line(stdout: &mut Vec<u8>, name: &str) {
        const HEAD: &[u8] = b"Usage: ";
        const TAIL: &[u8] = b" [OPTION]... [FILE]...\n";
        if let Some(rest) = stdout.strip_prefix(HEAD)
            && let Some(end) = rest.windows(TAIL.len()).position(|w| w == TAIL)
        {
            let mut v = HEAD.to_vec();
            v.extend_from_slice(name.as_bytes());
            v.extend_from_slice(&rest[end..]);
            *stdout = v;
        }
    }

    /// `--version`'s first line: the reference's and stuffr's, each checked
    /// exactly, then both masked so the rest is compared.
    fn version_line(r: &mut Run, s: &mut Run) {
        let first = |v: &[u8]| v.split(|&b| b == b'\n').next().unwrap_or_default().to_vec();
        if first(&r.stdout) != b"xz (XZ Utils) 5.8.4" {
            return;
        }
        let ours = format!(
            "xz (stuffr {}; XZ Utils 5.8.4 compatible)",
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(
            String::from_utf8_lossy(&first(&s.stdout)),
            ours,
            "stuffr's --version first line"
        );
        for run in [r, s] {
            let n = first(&run.stdout).len();
            run.stdout.splice(..n, *b"<version line>");
        }
    }

    /// Run every case against the reference and stuffr.
    fn check(group: &str, cases: &[Case]) {
        check_tolerating(group, cases, 0);
    }

    /// The pure tier: `lzma-rust2` drops what the decoder call that fails
    /// had decoded, so before the same failure (a corrupt spot, or a raw,
    /// `.lzma` or `.lz` stream cut short) stuffr writes less partial
    /// output than xz; the exit code and messages are the same.
    const PURE: bool = !cfg!(feature = "xz-c");

    /// Whether stuffr's run `s` differs from the reference's `r` only by
    /// that shorter partial output: both failed alike, and stuffr's
    /// standard output is a strict prefix of the reference's. Under `-v`
    /// the progress line's figures then differ too (the decoder stopped
    /// elsewhere), so they are masked for this comparison.
    fn short_partial_output(r: &Run, s: &Run) -> bool {
        PURE && r.code != 0
            && r.code == s.code
            && progress_figures(&r.stderr, true) == progress_figures(&s.stderr, true)
            && s.stdout.len() < r.stdout.len()
            && r.stdout.starts_with(&s.stdout)
    }

    /// The `-v` line as compared: the speed and elapsed time are not
    /// promised (`normalise_xz_progress`), and whether they appear at all
    /// depends on how long each program took (1 s and 3 s), so they are
    /// left out; how they are written is pinned by message.rs's unit tests
    /// against message.c's own output. On the pure tier the compressed
    /// size and ratio are masked too ([`progress_figures`]).
    fn progress_line(stderr: &str) -> String {
        let s = normalise_xz_progress(stderr)
            .replace(", <speed>", "")
            .replace(", <elapsed>", "");
        if PURE { progress_figures(&s, false) } else { s }
    }

    /// The `-v` line's figures masked (`NAME: [P %, ]C / U = R...`): the
    /// compressed size and the ratio, and with `all` the percentage and
    /// the uncompressed size too. The pure tier's compressed bytes are
    /// compatible, not identical, so their count and ratio differ there.
    fn progress_figures(stderr: &str, all: bool) -> String {
        let mask = |line: &str| -> Option<String> {
            let slash = line.find(" / ")?;
            let colon = line[..slash].rfind(": ")? + 2;
            let (head, rest) = line.split_at(colon);
            let (pct, sizes) = match rest.find(" %, ") {
                Some(i) if i < slash - colon => (Some(&rest[..i]), &rest[i + 4..]),
                _ => (None, rest),
            };
            let (_, after) = sizes.split_once(" / ")?;
            let (u, op, after) = match (after.split_once(" = "), after.split_once(" > ")) {
                (Some((u, a)), _) => (u, " = ", a),
                (None, Some((u, a))) => (u, " > ", a),
                _ => return None,
            };
            let end = after.find(',').unwrap_or(after.len());
            let mut out = head.to_string();
            if let Some(p) = pct {
                out += if all { "<pct>" } else { p };
                out += " %, ";
            }
            out += "<compressed> / ";
            out += if all { "<uncompressed>" } else { u };
            out += op;
            out += "<ratio>";
            out += &after[end..];
            Some(out)
        };
        let mut out = String::new();
        for line in stderr.split_inclusive('\n') {
            let (body, nl) = line.strip_suffix('\n').map_or((line, ""), |b| (b, "\n"));
            out += &mask(body).unwrap_or_else(|| body.to_string());
            out += nl;
        }
        out
    }

    /// [`check`], with exactly `pure_short` cases on the pure tier allowed
    /// [`short_partial_output`] (the rest of each is still compared); none
    /// on the C tier.
    fn check_tolerating(group: &str, cases: &[Case], pure_short: usize) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let short = AtomicUsize::new(0);
        let one = |c: &Case| -> bool {
            let Some(dir) = xz_dir() else { return false };
            let Some(mut r) = reference(dir, c) else {
                return false;
            };
            let mut s = stuffr_as(c);
            usage_line(&mut r.stdout, c.name);
            usage_line(&mut s.stdout, c.name);
            version_line(&mut r, &mut s);
            for run in [&mut r, &mut s] {
                run.stderr = progress_line(&run.stderr);
            }
            if short_partial_output(&r, &s) {
                short.fetch_add(1, Ordering::Relaxed);
                s.stdout = r.stdout.clone();
                s.stderr = r.stderr.clone();
            }
            assert_same(c, &r, &s);
            true
        };
        run_group(group, cases, Skipped::none(), &one);
        if xz_dir().is_some() {
            let want = if PURE { pure_short } else { 0 };
            assert_eq!(
                short.load(Ordering::Relaxed),
                want,
                "{group}: cases with a shorter partial output"
            );
        }
    }

    // ---- flags: refused ----

    /// Options the reference refuses, each with its message and exit 1, and
    /// nothing written: unknown, ambiguous, missing and invalid arguments.
    #[test]
    fn flags_refused() {
        let mut cases: Vec<Case> = [
            // getopt's own.
            &["-Y"][..],
            &["--frob"],
            &["--frob=1"],
            &["--fil"],
            &["--de"],
            &["--mem=1"],
            &["--=x"],
            &["-k-"],
            &["-:"],
            &["-?"],
            &["--help=x"],
            &["--no-sync=1"],
            &["-r"],
            &["-q", "-Y"],
            &["-qq", "--frob"],
            &["-Y", "-h"],
            // Missing arguments.
            &["-T"],
            &["-M"],
            &["-S"],
            &["-F"],
            &["-C"],
            &["-kT"],
            &["--threads"],
            &["--thr"],
            &["--memlimit"],
            &["--memory"],
            &["--memlimit-compress"],
            &["--memlimit-decompress"],
            &["--memlimit-mt-decompress"],
            &["--block-size"],
            &["--block-list"],
            &["--flush-timeout"],
            &["--check"],
            &["--format"],
            &["--suffix"],
            &["--filters"],
            &["--filters1"],
            &["--filters9"],
            // Invalid arguments.
            &["-T", "x"],
            &["-T", "-1"],
            &["-T", "16385"],
            &["-T", "5x"],
            &["-T", "5Kib"],
            &["-T", "5MiB"],
            &["-T", ""],
            &["-T", "+"],
            &["-T99999999999999999999"],
            &["-qq", "-T", "x"],
            &["-M", "101%"],
            &["-M", "0%"],
            &["-M", "x"],
            &["-M", "18446744073709551616"],
            &["--memlimit-compress=5x%"],
            &["--memlimit-decompress=1y"],
            &["--memlimit-mt-decompress=%"],
            &["--block-size=x"],
            &["--block-size=9223372036854775808"],
            &["--block-list="],
            &["--block-list=,1"],
            &["--block-list=0,1"],
            &["--block-list=1:"],
            &["--block-list=x"],
            &["--block-list=a:1"],
            &["--block-list=12:3"],
            &["--flush-timeout=-1"],
            &["--check=crc16"],
            &["-C", "CRC32"],
            &["-F", "foo"],
            &["-F", "XZ"],
            &["-F", "lzip"],
            &["-F", "raw", "a"],
            &["-F", "raw", "--files=a"],
            &["--suffix="],
            &["-S", "a/b"],
            &["--lzma1=x"],
            &["--lzma2=dict="],
            &["--lzma2=dict=1"],
            &["--lzma2=dict=1x"],
            &["--lzma2=preset=x"],
            &["--lzma2=preset=9ee"],
            &["--lzma2=preset=9f"],
            &["--lzma2=preset="],
            &["--lzma2=lc=5"],
            &["--lzma2=lc=4,lp=1"],
            &["--lzma2=mode=slow"],
            &["--lzma2=mf=bt9"],
            &["--lzma2=foo=1"],
            &["--lzma2==1"],
            &["--lzma2=nice=1"],
            &["--lzma2=depth=4294967296"],
            &["--x86=start=x"],
            &["--x86=foo=1"],
            &["--arm64=start=4294967296"],
            &["--delta=dist=0"],
            &["--delta=dist"],
            &["--delta=dist=257"],
            &["--x86", "--x86", "--x86", "--x86", "--x86"],
            &["--filters="],
            &["--filters=   "],
            &["--filters=x86"],
            &["--filters=lzma2 x86"],
            &["--filters=foo"],
            &["--filters=lzma2:dict=1"],
            &["--filters=lzma2:dict=4Kq"],
            &["--filters=lzma2:lc=1k"],
            &["--filters=x86 x86 x86 x86 lzma2"],
            &["--filters=9x"],
            &["--filters=9 x"],
            &["--filters=lzma2--x86"],
            &["--filters=lzma2:mode=fast,mf=hc9"],
            &["--filters=lzma2:=4"],
            &["--filters=lzma2:dicta=4"],
            &["--filters=x86 --"],
            &["--filters=abcdefghijklm"],
            &["--filters1=lzma1"],
            &["--filters3=x86"],
            &["--filters9=lzma2:dict=1x"],
            &["-q", "--filters=foo"],
            &["-qq", "--filters=foo"],
            &["--files=nonexistent"],
            &["--files", "--files0"],
            // main.c's refusals before any input.
            &["--robot"],
            &["--robot", "-d"],
            &["--robot", "-t", "a"],
        ]
        .iter()
        .map(|a| xz(a))
        .collect();
        // A terminal on standard output refuses compression there.
        for args in [&[][..], &["-c", "a"], &["-"]] {
            let mut c = xz(args);
            c.tty_stdout = true;
            cases.push(c);
        }
        check("flags_refused", &cases);
    }

    /// Every option `xz --long-help` lists, alone and clustered, over a file
    /// and over standard input (`-v` and `-l` are in
    /// [`flags_accepted_verbose_and_list`]).
    #[test]
    fn flags_accepted() {
        let packed = reference_output(&[], &text());
        let lzma = reference_output(&["-F", "lzma"], &text());
        let mut cases: Vec<Case> = [
            &["-z", "-k", "a"][..],
            &["--compress", "-c", "a"],
            &["-k", "a"],
            &["-f", "-k", "a"],
            &["-c", "a"],
            &["--stdout", "a"],
            &["--to-stdout", "a"],
            &["--no-sync", "a"],
            &["--no-sparse", "-k", "a"],
            &["-S", ".foo", "a"],
            &["--suffix=.foo", "-k", "a"],
            &["-F", "xz", "-k", "a"],
            &["-F", "lzma", "-k", "a"],
            &["-F", "alone", "-c", "a"],
            &["-F", "raw", "-c", "a"],
            &["-F", "auto", "-c", "a"],
            &["-C", "none", "-c", "a"],
            &["-C", "crc32", "-c", "a"],
            &["-C", "crc64", "-c", "a"],
            &["-C", "sha256", "-c", "a"],
            &["-0", "-c", "a"],
            &["-1", "-c", "a"],
            &["-5", "-c", "a"],
            &["-9", "-c", "a"],
            &["--fast", "-c", "a"],
            &["--best", "-c", "a"],
            &["-e", "-c", "a"],
            &["--extreme", "-c", "a"],
            &["-T0", "-c", "a"],
            &["-T1", "-c", "a"],
            &["-T2", "-c", "a"],
            &["-T+1", "-c", "a"],
            &["--threads=max", "-c", "a"],
            &["--block-size=1KiB", "-c", "a"],
            &["--block-list=1KiB,0", "-c", "a"],
            &["--flush-timeout=100", "-c", "a"],
            &["-M", "1GiB", "-c", "a"],
            &["--memlimit=50%", "-c", "a"],
            &["--memory=1GiB", "-c", "a"],
            &["--memlimit-compress=1GiB", "-c", "a"],
            &["--memlimit-decompress=1GiB", "-c", "a"],
            &["--memlimit-mt-decompress=1GiB", "-c", "a"],
            &["--no-adjust", "-c", "a"],
            &["--filters=lzma2", "-c", "a"],
            &["--filters=x86 lzma2:preset=1", "-c", "a"],
            &["--filters1=x86 lzma2", "--block-list=1:1KiB,0", "-c", "a"],
            &["--lzma2=preset=1", "-c", "a"],
            &["--lzma1", "-F", "lzma", "-c", "a"],
            &["--x86", "--lzma2", "-c", "a"],
            &["--powerpc", "--lzma2", "-c", "a"],
            &["--ia64", "--lzma2", "-c", "a"],
            &["--arm", "--lzma2", "-c", "a"],
            &["--armthumb", "--lzma2", "-c", "a"],
            &["--arm64", "--lzma2", "-c", "a"],
            &["--sparc", "--lzma2", "-c", "a"],
            &["--riscv", "--lzma2", "-c", "a"],
            &["--delta=dist=4", "--lzma2", "-c", "a"],
            &["-q", "-c", "a"],
            &["-Q", "-c", "a"],
            &["--no-warn", "-c", "a"],
            &["-9ekc", "a"],
            // BSD: `-k-x` is `-k --x86`, refused by the coder's chain
            // check; glibc: an invalid option.
            &["-k-x"],
            &["-c", "--", "a"],
            &["-c", "-"],
            &["-"],
            &[],
            &["--files=a"],
        ]
        .iter()
        .map(|a| fed(xz(a), text()))
        .collect();
        for args in [
            &["-d", "-k", "a.xz"][..],
            &["--decompress", "-c", "a.xz"],
            &["--uncompress", "-c", "a.xz"],
            &["-t", "a.xz"],
            &["--test", "a.xz"],
            &["-d", "--single-stream", "-c", "a.xz"],
            &["-d", "--ignore-check", "-c", "a.xz"],
            &["-d", "--no-sparse", "-k", "a.xz"],
        ] {
            cases.push(with_file(xz(args), "a.xz", packed.clone()));
        }
        cases.push(with_file(
            xz(&["-d", "-F", "lzma", "-c", "a.lzma"]),
            "a.lzma",
            lzma,
        ));
        check("flags_accepted", &cases);
    }

    /// `-v` and `-vv` with standard error not a terminal (R4): the line
    /// xz prints for each file as it ends, and before an error said while
    /// a file is coded (again at its end), across compression,
    /// decompression, testing, standard input, pass-through, several files,
    /// `--files`, the `.lzma` and raw formats and threads. The speed and
    /// elapsed fields are normalised (`normalise_xz_progress`); every case
    /// is sized to finish far under a second, where neither is printed.
    #[test]
    fn flags_accepted_verbose() {
        let plain = text();
        let big = mixed(200_000, 17);
        let packed = reference_output(&[], &plain);
        let big_xz = reference_output(&["-T2", "--block-size=40000"], &big);
        let lzma = reference_output(&["-F", "lzma"], &plain);
        let cut = packed[..100].to_vec();
        let mut mid = big_xz.clone();
        let at = mid.len() / 2;
        mid[at] ^= 0x55;
        let mut trailing = packed.clone();
        trailing.extend_from_slice(b"junk");
        let mut cases: Vec<Case> = [
            &["-v", "-c", "a"][..],
            &["--verbose", "-k", "a"],
            &["-vv", "-c", "a"],
            &["-v", "-v", "-k", "a"],
            &["-v", "-q", "-c", "a"],
            &["-v", "-0", "-T1", "-c", "a"],
            &["-v", "-T2", "--block-size=1KiB", "-c", "a"],
            &["-v", "-F", "lzma", "-c", "a"],
            &["-v", "-F", "raw", "-c", "a"],
            &["-v", "-c", "missing", "a"],
            &["-v", "-c", "-"],
            &["-v"],
        ]
        .iter()
        .map(|a| fed(xz(a), plain.clone()))
        .collect();
        cases.push(with_file(xz(&["-v", "-k", "a", "big"]), "big", big.clone()));
        cases.push(with_file(
            xz(&["-vv", "-T1", "-k", "big"]),
            "big",
            big.clone(),
        ));
        cases.push(with_file(
            fed(xz(&["-v", "-k", "--files"]), b"a\nbig\n".to_vec()),
            "big",
            big.clone(),
        ));
        cases.push(with_file(xz(&["-v", "-c", "e"]), "e", Vec::new()));
        cases.push(with_file(xz(&["-v", "-k", "a"]), "a.xz", packed.clone()));
        for args in [
            &["-dkv", "a.xz"][..],
            &["-dcv", "a.xz"],
            &["-tv", "a.xz"],
            &["-tvv", "a.xz"],
            &["-dcv", "big.xz"],
            &["-dcv", "-T1", "big.xz"],
            &["-tv", "a.xz", "big.xz", "a.xz"],
            // `cut.xz` at `-T1`: in liblzma's threaded decoder a Block
            // cut short is decoded by a worker the main thread does not
            // wait for, so the figures at "Unexpected end of input" are
            // whatever that worker had published (stream_decoder_mt.c) —
            // timing, in xz itself and the C tier alike. CI saw
            // xz print no line at all, and stuffr "51 B / 8 B".
            &["-dcv", "-T1", "cut.xz"],
            &["-tv", "-T1", "a.xz", "cut.xz", "big.xz"],
            &["-dcv", "-T1", "mid.xz"],
            &["-dcv", "e.xz"],
            &["-dcv", "trailing.xz"],
            &["-dcv", "--single-stream", "trailing.xz"],
            &["-dcfv", "a"],
            &["-dcfv", "a.xz", "a"],
            &["-dcv", "a"],
            &["-dcv", "-F", "lzma", "a.lzma"],
            &["-dcv", "a.lzma"],
        ] {
            let mut c = with_file(xz(args), "a.xz", packed.clone());
            c.files.push(("big.xz", big_xz.clone()));
            c.files.push(("cut.xz", cut.clone()));
            c.files.push(("mid.xz", mid.clone()));
            c.files.push(("e.xz", Vec::new()));
            c.files.push(("trailing.xz", trailing.clone()));
            c.files.push(("a.lzma", lzma.clone()));
            cases.push(c);
        }
        cases.push(fed(xz(&["-dv"]), packed.clone()));
        cases.push(fed(xz(&["-tv", "-"]), packed.clone()));
        cases.push(fed(xz(&["-dcfv"]), plain.clone()));
        cases.push(fed(case("xzcat", &["-v"]), packed.clone()));
        cases.push(with_file(
            case("unxz", &["-v", "-k", "a.xz"]),
            "a.xz",
            packed.clone(),
        ));
        cases.push(with_file(
            case("lzcat", &["-v", "a.lzma"]),
            "a.lzma",
            lzma.clone(),
        ));
        // The pure tier: corruption mid-Block (`mid.xz`) stops its decoder
        // elsewhere (Ruling P9), so the output and the line's figures there
        // are short.
        check_tolerating("flags_accepted_verbose", &cases, 1);
    }

    /// `-l` and `--list` (list.c, Task 7).
    #[test]
    fn flags_accepted_list() {
        let packed = reference_output(&[], &text());
        let cases: Vec<Case> = [&["-l", "a.xz"][..], &["--list", "a.xz"]]
            .iter()
            .map(|a| with_file(xz(a), "a.xz", packed.clone()))
            .collect();
        check("flags_accepted_list", &cases);
    }

    // ---- help and version ----

    /// The help texts, `--filters-help` and `--version` (whose first line
    /// names stuffr), in argv order with the other options.
    #[test]
    fn help() {
        let cases: Vec<Case> = [
            ("xz", &["-h"][..]),
            ("xz", &["--help"]),
            ("xz", &["--he"]),
            ("xz", &["-H"]),
            ("xz", &["--long-help"]),
            ("xz", &["--filters-help"]),
            ("xz", &["--robot", "--filters-help"]),
            ("xz", &["--filters-help", "--robot"]),
            ("xz", &["-V"]),
            ("xz", &["--version"]),
            ("xz", &["--robot", "--version"]),
            ("xz", &["--robot", "-V", "-h"]),
            ("xz", &["-h", "-Y"]),
            ("xz", &["-h", "-H"]),
            ("xz", &["-qq", "-h"]),
            ("xz", &["-v", "--version"]),
            ("xz", &["-9", "-T", "4", "--lzma2=dict=1MiB", "-H"]),
            ("unxz", &["-h"]),
            ("xzcat", &["-H"]),
            ("lzma", &["--version"]),
            ("unlzma", &["--robot", "--version"]),
            ("lzcat", &["--filters-help"]),
        ]
        .iter()
        .map(|(n, a)| case(n, a))
        .collect();
        check("help", &cases);
    }

    /// `--info-memory` and its robot form: the machine's memory and thread
    /// count (both runs share the machine) and the limits as set.
    #[test]
    fn info_memory() {
        let cases: Vec<Case> = [
            &["--info-memory"][..],
            &["--robot", "--info-memory"],
            &["-M", "1GiB", "--info-memory"],
            &["--memlimit-decompress=50%", "--robot", "--info-memory"],
            &[
                "--memlimit-mt-decompress=1MiB",
                "--memlimit-decompress=1000",
                "--info-memory",
            ],
            &["-T1", "--memlimit-compress=max", "--info-memory"],
        ]
        .iter()
        .map(|a| xz(a))
        .collect();
        check("info_memory", &cases);
    }

    // ---- the environment ----

    /// `XZ_DEFAULTS` then `XZ_OPT`, before argv; their errors and stops.
    #[test]
    fn env_refused_or_stopped() {
        let cases = vec![
            with_env(xz(&[]), "XZ_DEFAULTS", "-Y"),
            with_env(xz(&[]), "XZ_OPT", "--frob"),
            with_env(xz(&[]), "XZ_OPT", "-T"),
            with_env(xz(&[]), "XZ_OPT", "-T x"),
            with_env(xz(&[]), "XZ_DEFAULTS", "--lzma2=x"),
            with_env(xz(&["-Y"]), "XZ_OPT", "-q"),
            with_env(with_env(xz(&[]), "XZ_DEFAULTS", "-qq"), "XZ_OPT", "-T x"),
            with_env(xz(&[]), "XZ_OPT", "-h"),
            with_env(xz(&[]), "XZ_DEFAULTS", "\t-H\n"),
            with_env(xz(&["-Y"]), "XZ_OPT", "-h"),
            with_env(xz(&["-h"]), "XZ_OPT", "-Y"),
            with_env(xz(&["--files"]), "XZ_OPT", "--files"),
            with_env(xz(&[]), "XZ_OPT", "--files=nonexistent"),
            with_env(with_env(xz(&[]), "XZ_DEFAULTS", "-T1 -9"), "XZ_OPT", "-V"),
        ];
        check("env_refused_or_stopped", &cases);
    }

    /// The environment's options take effect (and an operand there is
    /// ignored).
    #[test]
    fn env_applies() {
        let cases = vec![
            fed(with_env(xz(&[]), "XZ_DEFAULTS", "-9"), text()),
            fed(with_env(xz(&[]), "XZ_OPT", "-T1"), text()),
            fed(
                with_env(with_env(xz(&[]), "XZ_DEFAULTS", "-9"), "XZ_OPT", "-T1"),
                text(),
            ),
            fed(with_env(xz(&["-1"]), "XZ_DEFAULTS", "-9"), text()),
            with_env(xz(&["-k", "a"]), "XZ_OPT", "-0 b"),
            fed(with_env(xz(&[]), "XZ_OPT", "--files"), b"a\n".to_vec()),
            with_env(xz(&["a"]), "XZ_OPT", "--files=a"),
            with_env(xz(&["-c", "a", "-k"]), "POSIXLY_CORRECT", "1"),
            with_env(xz(&["-c", "a", "-Y"]), "POSIXLY_CORRECT", "1"),
            fed(with_env(xz(&["-F", "lzip"]), "XZ_OPT", "-d"), text()),
        ];
        check("env_applies", &cases);
    }

    // ---- the six names ----

    /// Each name refusing an option: its own name in the messages.
    #[test]
    fn names_refuse() {
        let mut cases = vec![
            case("unxz", &["-Y"]),
            case("xzcat", &["--frob"]),
            case("lzma", &["-T", "x"]),
            case("unlzma", &["-F", "foo"]),
            case("lzcat", &["--fil"]),
            case("unxz", &["--robot"]),
            case("lzma", &["-F", "lzip"]),
        ];
        // A terminal on standard input refuses decompression from it.
        for (name, args) in [
            ("unxz", &[][..]),
            ("xzcat", &["-"]),
            ("unlzma", &["-q"]),
            ("xz", &["-t"]),
        ] {
            let mut c = case(name, args);
            c.tty_stdin = true;
            cases.push(c);
        }
        check("names_refuse", &cases);
    }

    /// Each name over standard input.
    #[test]
    fn names_on_stdin() {
        let packed = reference_output(&[], &text());
        let lzma = reference_output(&["-F", "lzma"], &text());
        let cases = vec![
            fed(case("xz", &[]), text()),
            fed(case("unxz", &[]), packed.clone()),
            fed(case("xzcat", &[]), packed.clone()),
            fed(case("lzma", &[]), text()),
            fed(case("unlzma", &[]), lzma.clone()),
            fed(case("lzcat", &[]), lzma),
            fed(case("xzcat", &["-"]), packed.clone()),
            fed(case("unlzma", &[]), packed),
        ];
        check("names_on_stdin", &cases);
    }

    // ---- Review Focus 4 ----

    /// The parse-time half of the suffix rules: an empty `--suffix` and one
    /// holding a `/` are refused, exit 1.
    #[test]
    fn suffix_rules_at_parse_time() {
        let cases = vec![
            xz(&["--suffix=", "a"]),
            xz(&["-S", "", "a"]),
            case("unxz", &["--suffix=", "a"]),
            xz(&["-S", "x/y", "a"]),
            xz(&["-S", "/", "a"]),
        ];
        check("suffix_rules_at_parse_time", &cases);
    }

    /// Review Focus 4, the rest: `xz a.xz` and `unxz a` warn and skip (exit
    /// 2), `unxz a.txz` and `unlzma a.tlz` make `a.tar`, `unxz --suffix=.foo
    /// a.foo` makes `a`.
    #[test]
    fn suffix_rules() {
        let packed = reference_output(&[], &text());
        let lzma = reference_output(&["-F", "lzma"], &text());
        let cases = vec![
            with_file(xz(&["a.xz"]), "a.xz", packed.clone()),
            with_file(xz(&["-k", "a.txz"]), "a.txz", packed.clone()),
            with_file(case("lzma", &["a.lzma"]), "a.lzma", lzma.clone()),
            with_file(xz(&["-S", ".foo", "a.foo"]), "a.foo", text()),
            case("unxz", &["a"]),
            case("unxz", &["-q", "a"]),
            case("unxz", &["-Q", "a"]),
            with_file(case("unxz", &["a.txz"]), "a.txz", packed.clone()),
            with_file(case("unlzma", &["a.tlz"]), "a.tlz", lzma.clone()),
            with_file(
                case("unxz", &["--suffix=.foo", "a.foo"]),
                "a.foo",
                packed.clone(),
            ),
            with_file(case("unxz", &["a.lzma"]), "a.lzma", lzma),
            with_file(case("unxz", &["a", "a.xz"]), "a.xz", packed),
        ];
        check("suffix_rules", &cases);
    }

    // ==== Part 2 (Task 6): the coder and file handling ====

    use std::fs;
    use std::path::Path;

    /// A case over exactly `files`, nothing else.
    fn dcase<'a>(name: &'a str, args: &[&'a str], files: Vec<(&'a str, Vec<u8>)>) -> Case<'a> {
        let mut c = case(name, args);
        c.files = files;
        c
    }

    fn chmod(p: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        // A non-root user may not set the sticky bit on a file on some
        // systems; the case then runs on an ordinary file, alike for both.
        let _ = fs::set_permissions(p, fs::Permissions::from_mode(mode));
    }

    fn symlink_l_to_a(d: &Path) {
        std::os::unix::fs::symlink("a", d.join("l")).unwrap();
    }
    fn hard_link_h_to_a(d: &Path) {
        fs::hard_link(d.join("a"), d.join("h")).unwrap();
    }
    fn dir_d(d: &Path) {
        fs::create_dir(d.join("d")).unwrap();
    }
    fn a_unreadable(d: &Path) {
        chmod(&d.join("a"), 0o000);
    }
    fn a_mode_640(d: &Path) {
        chmod(&d.join("a"), 0o640);
    }
    fn a_setuid(d: &Path) {
        chmod(&d.join("a"), 0o4755);
    }
    fn a_setgid(d: &Path) {
        chmod(&d.join("a"), 0o2755);
    }
    fn a_sticky(d: &Path) {
        chmod(&d.join("a"), 0o1644);
    }

    fn with_setup<'a>(mut c: Case<'a>, setup: fn(&Path)) -> Case<'a> {
        c.setup = Some(setup);
        c
    }

    /// What the case's compressed standard output holds, when that is not
    /// its input files.
    fn expect_plain(mut c: Case<'_>, plain: Vec<u8>) -> Case<'_> {
        c.expect_stdout_plain = Some(plain);
        c
    }

    fn on_tty<'a>(mut c: Case<'a>) -> Case<'a> {
        c.tty_stdout = true;
        c
    }

    /// Compression over files and streams: what is written where, what is
    /// removed, what is refused, and the attributes copied (the file tree
    /// with modes and mtimes is compared). The compressed bytes themselves
    /// are `compat_xz_bytes.rs`'s.
    #[test]
    fn compress_files() {
        let b = || ("b", b"another file\n".repeat(30));
        let cases = vec![
            xz(&["a"]),
            xz(&["-k", "a"]),
            xz(&["-c", "a"]),
            xz(&["-ck", "a"]),
            with_file(xz(&["-c", "a", "b"]), b().0, b().1),
            with_file(xz(&["a", "b"]), b().0, b().1),
            xz(&["a", "missing"]),
            xz(&["missing", "a"]),
            xz(&["-q", "missing"]),
            xz(&["-qq", "missing", "a"]),
            xz(&[""]),
            with_file(xz(&["a"]), "a.xz", b"old".to_vec()),
            with_file(xz(&["-q", "a"]), "a.xz", b"old".to_vec()),
            with_file(xz(&["-f", "a"]), "a.xz", b"old".to_vec()),
            with_file(xz(&["-kf", "a"]), "a.xz", b"old".to_vec()),
            with_setup(xz(&["-f", "a"]), |d| {
                fs::create_dir(d.join("a.xz")).unwrap()
            }),
            with_setup(xz(&["a"]), |d| {
                std::os::unix::fs::symlink("nowhere", d.join("a.xz")).unwrap();
            }),
            fed(xz(&[]), text()),
            fed(xz(&["-"]), text()),
            fed(xz(&["-c", "-"]), text()),
            fed(xz(&["-", "-"]), text()),
            fed(xz(&["-k", "-", "a"]), text()),
            expect_plain(xz(&["-c", "/dev/null"]), Vec::new()),
            xz(&["/dev/null"]),
            xz(&["-S", ".foo", "a"]),
            xz(&["--suffix=.foo", "-k", "a"]),
            xz(&["-F", "raw", "-S", ".raw", "a"]),
            case("lzma", &["a"]),
            case("lzma", &["-k", "-S", ".l", "a"]),
            // Symbolic links: skipped unless -f, -k or -c.
            with_setup(xz(&["l"]), symlink_l_to_a),
            with_setup(xz(&["-f", "l"]), symlink_l_to_a),
            with_setup(xz(&["-k", "l"]), symlink_l_to_a),
            with_setup(xz(&["-c", "l"]), symlink_l_to_a),
            // Hard links: skipped unless -f, -k or -c.
            with_setup(xz(&["a"]), hard_link_h_to_a),
            with_setup(xz(&["-f", "a"]), hard_link_h_to_a),
            with_setup(xz(&["-k", "a"]), hard_link_h_to_a),
            with_setup(xz(&["-c", "h"]), hard_link_h_to_a),
            // Directories, whatever the flags.
            with_setup(xz(&["d"]), dir_d),
            with_setup(xz(&["-c", "d"]), dir_d),
            with_setup(xz(&["-f", "d", "a"]), dir_d),
            // Unreadable, and the mode and mtime copied.
            with_setup(xz(&["a"]), a_unreadable),
            with_setup(xz(&["-c", "a"]), a_unreadable),
            with_setup(xz(&["a"]), a_mode_640),
            with_setup(xz(&["-k", "a"]), a_mode_640),
            // Set-id and sticky: skipped unless -f or -k, the bits dropped.
            with_setup(xz(&["a"]), a_setuid),
            with_setup(xz(&["-f", "a"]), a_setuid),
            with_setup(xz(&["-k", "a"]), a_setuid),
            with_setup(xz(&["-c", "a"]), a_setuid),
            with_setup(xz(&["a"]), a_setgid),
            with_setup(xz(&["a"]), a_sticky),
            with_setup(xz(&["-f", "a"]), a_sticky),
            // A terminal on standard output, with and without -f.
            on_tty(xz(&["-f", "-c", "a"])),
            on_tty(fed(xz(&["-f"]), text())),
            on_tty(fed(xz(&["-c", "-f", "-"]), text())),
            on_tty(xz(&["-k", "a"])),
            // --files and --files0, from a file and from standard input.
            with_file(
                with_file(xz(&["--files=list"]), "list", b"a\nb\n".to_vec()),
                b().0,
                b().1,
            ),
            expect_plain(
                with_file(xz(&["-c", "--files0=list0"]), "list0", b"a\0".to_vec()),
                text(),
            ),
            with_file(xz(&["--files=list", "-k", "a"]), "list", b"a\n".to_vec()),
            with_file(xz(&["--files=list"]), "list", b"a\nmissing\n".to_vec()),
            fed(xz(&["--files"]), b"a\n".to_vec()),
            fed(xz(&["--files0", "-k"]), b"a\0".to_vec()),
            fed(xz(&["--files", "-"]), b"a\n".to_vec()),
            fed(xz(&["--files"]), b"\n\na\n".to_vec()),
            // --flush-timeout over a pipe: the bytes are compatible (when
            // a flush happens depends on the clock).
            fed(xz(&["--flush-timeout=100"]), text()),
            fed(xz(&["--flush-timeout=100", "-T1"]), text()),
            fed(xz(&["--flush-timeout=100", "--x86", "--lzma2"]), text()),
            fed(
                xz(&["--flush-timeout=100", "--delta", "--lzma2", "-T1"]),
                text(),
            ),
            // The chain checks made before any input.
            xz(&["-k-x"]),
            xz(&["--x86", "a"]),
            xz(&["-T1", "--x86", "a"]),
            xz(&["-F", "lzma", "--lzma2", "a"]),
            xz(&["--lzma1", "a"]),
            xz(&["--block-list=1:10,0", "a"]),
            xz(&["-F", "raw", "-c", "a"]),
            xz(&["-F", "raw", "-q", "-c", "a"]),
        ];
        check("compress_files", &cases);
    }

    /// A FIFO `p` whose writer comes 300 ms after the setup runs, writes a
    /// line and goes. The writer gives up after 25 s if nothing ever reads:
    /// the clock starts at setup, not at the process's start, so under a
    /// loaded gate the reader may open the FIFO late, and a writer that
    /// had given up would leave it waiting until the harness's 30 s timeout
    /// (`compat_harness::TIMEOUT`, private, so the figure is repeated here).
    ///
    /// On macOS `poll` on a FIFO reports data but never that the last
    /// writer has gone, and xz reads with `O_NONBLOCK`, polling with no
    /// timeout after `EAGAIN` (file_io.c: io_read, io_wait). So the
    /// reference waits for ever if, at its read after the line, the FIFO
    /// still has a writer. Two things made that happen, so the writer
    /// - stops the reader (`SIGSTOP`) for its write and close, and only
    ///   then continues it: the reader could read the line between the
    ///   `write` and the `close`; and
    /// - holds the harness's spawn lock from its open to its close: a
    ///   child another case spawned in that span got a copy of the
    ///   descriptor (close-on-exec only closes it at the exec), so the
    ///   writer's `close` was not the last.
    ///
    /// stuffr is immune (its reads block once the open's wait is over);
    /// both runs are written to the same way.
    fn late_fifo_writer(d: &Path) {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::OpenOptionsExt;
        use std::time::{Duration, Instant};
        let p = d.join("p");
        let c = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        let work = d.to_path_buf();
        std::thread::spawn(move || {
            use std::io::Write;
            std::thread::sleep(Duration::from_millis(300));
            let deadline = Instant::now() + Duration::from_secs(25);
            // The program reading `p`, registered just after its spawn.
            let pid = loop {
                if let Some(pid) = child_of(&work) {
                    break libc::pid_t::try_from(pid).unwrap();
                }
                if Instant::now() >= deadline {
                    return;
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            let (lock, mut f) = loop {
                let lock = spawn_lock();
                let w = fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(&p);
                match w {
                    Ok(f) => break (lock, f),
                    Err(_) if Instant::now() < deadline => {
                        drop(lock);
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return,
                }
            };
            // SAFETY: a signal to this process's own child, which has `p`
            // open (the open above succeeded), then a wait for it to stop.
            // WNOWAIT leaves its state to the harness's wait, which does not
            // report stops anyway.
            let stopped = unsafe {
                let mut info: libc::siginfo_t = std::mem::zeroed();
                libc::kill(pid, libc::SIGSTOP) == 0
                    && libc::waitid(
                        libc::P_PID,
                        pid as libc::id_t,
                        &mut info,
                        libc::WSTOPPED | libc::WEXITED | libc::WNOWAIT,
                    ) == 0
                    && info.si_code == libc::CLD_STOPPED
            };
            if !stopped {
                return; // it ended without the line: the comparison says so
            }
            let _ = f.write_all(b"hello-data\n");
            drop(f);
            drop(lock);
            // SAFETY: continue the child stopped above.
            unsafe { libc::kill(pid, libc::SIGCONT) };
        });
    }

    /// file_io.c's io_wait: an input that is not a regular file is read
    /// only once there is input, so a FIFO opened before its writer
    /// yields the writer's data, not an empty input.
    #[test]
    fn a_fifo_waits_for_its_writer() {
        let cases = vec![
            expect_plain(
                with_setup(dcase("xz", &["-c", "p"], vec![]), late_fifo_writer),
                b"hello-data\n".to_vec(),
            ),
            with_setup(dcase("xz", &["-dcf", "p"], vec![]), late_fifo_writer),
            with_setup(dcase("xz", &["-t", "p"], vec![]), late_fifo_writer),
        ];
        check("a_fifo_waits_for_its_writer", &cases);
    }

    /// The reference's `.xz` streams for the decompression cases, by name.
    fn streams() -> Vec<(&'static str, Vec<u8>)> {
        let plain = text();
        let big = mixed(300_000, 71);
        let mut v = Vec::new();
        for (name, args, data) in [
            ("p6", &[][..], &plain),
            ("p0", &["-0"], &plain),
            ("p9e", &["-9e", "-T1"], &plain),
            ("crc32", &["-C", "crc32"], &plain),
            ("sha256", &["-C", "sha256"], &plain),
            ("none", &["-C", "none"], &plain),
            ("mt", &["-T4", "--block-size=64KiB"], &big),
            ("st", &["-T1", "--block-size=64KiB"], &big),
            (
                "list",
                &[
                    "--block-list=10KiB,1:20KiB,0",
                    "--filters1=delta:dist=4 lzma2",
                ],
                &big,
            ),
            ("x86", &["--x86", "--lzma2"], &big),
            ("arm64", &["--arm64", "--lzma2"], &big),
            ("delta", &["--delta=dist=2", "--lzma2"], &big),
            ("empty", &[], &Vec::new()),
        ] {
            v.push((name, reference_output(args, data)));
        }
        v
    }

    /// Flip bit 0 of byte `at` (from the end when negative).
    fn flipped(data: &[u8], at: isize) -> Vec<u8> {
        let mut v = data.to_vec();
        let i = if at < 0 {
            (v.len() as isize + at) as usize
        } else {
            at as usize
        };
        v[i] ^= 1;
        v
    }

    /// A stream whose check ID is 2 (reserved, 4 bytes like CRC32's): made
    /// from a CRC32 stream by rewriting both copies of the flags and their
    /// CRC32s.
    fn unsupported_check() -> Vec<u8> {
        let mut s = reference_output(&["-C", "crc32"], &text());
        let n = s.len();
        s[7] = 2;
        let crc = crc32(&s[6..8]).to_le_bytes();
        s[8..12].copy_from_slice(&crc);
        // Footer: CRC32 (4), Backward Size (4), flags (2), magic (2).
        s[n - 3] = 2;
        let crc = crc32(&s[n - 8..n - 2]).to_le_bytes();
        s[n - 12..n - 8].copy_from_slice(&crc);
        s
    }

    /// Decompression and testing: every stream through `unxz`, `xzcat` and
    /// `-t`; concatenation and padding; `--single-stream` and trailing
    /// garbage; empty, short, cut and corrupt inputs; checks; `.lzma`, raw
    /// and lzip; existing outputs; thread counts.
    #[test]
    fn decompress_and_test() {
        let plain = text();
        let p6 = reference_output(&[], &plain);
        let mut cases = Vec::new();
        for (name, s) in streams() {
            let _ = name;
            for (tool, args) in [
                ("unxz", &["-k", "a.xz"][..]),
                ("unxz", &["a.xz"]),
                ("xzcat", &["a.xz"]),
                ("xz", &["-t", "a.xz"]),
                ("xz", &["-dc", "-T1", "a.xz"]),
            ] {
                cases.push(dcase(tool, args, vec![("a.xz", s.clone())]));
            }
        }
        let two = [p6.clone(), reference_output(&["-0"], b"second\n")].concat();
        let pad = |n: usize| [p6.clone(), vec![0; n]].concat();
        let junk = [p6.clone(), b"junk".to_vec()].concat();
        let mut inputs: Vec<(&str, Vec<u8>)> = vec![
            ("two", two.clone()),
            ("pad4", pad(4)),
            ("pad3", pad(3)),
            ("pad5", pad(5)),
            ("pad8", pad(8)),
            ("padmid", [p6.clone(), vec![0; 4], p6.clone()].concat()),
            ("junk", junk),
            ("zeros", vec![0; 12]),
            ("empty", Vec::new()),
            ("one", b"x".to_vec()),
            ("cut1", p6[..1].to_vec()),
            ("cut12", p6[..12].to_vec()),
            ("cut13", p6[..13].to_vec()),
            ("cutlast", p6[..p6.len() - 1].to_vec()),
            ("header", flipped(&p6, 6)),
            ("headercrc", flipped(&p6, 9)),
            ("block", flipped(&p6, (p6.len() / 2) as isize)),
            ("index", flipped(&p6, -17)),
            ("footer", flipped(&p6, -1)),
            ("backward", flipped(&p6, -8)),
            ("check2", unsupported_check()),
        ];
        inputs.push(("checkmid", [unsupported_check(), p6.clone()].concat()));
        for (name, data) in &inputs {
            let file: &'static str = Box::leak(format!("{name}.xz").into_boxed_str());
            for (tool, args) in [
                ("xzcat", &[][..]),
                ("unxz", &["-k"]),
                ("xz", &["-t"]),
                ("xzcat", &["--single-stream"]),
                ("xzcat", &["--ignore-check"]),
                ("xz", &["-dcf"]),
            ] {
                let mut a = args.to_vec();
                a.push(file);
                cases.push(dcase(tool, &a, vec![(file, data.clone())]));
            }
        }
        // Several operands, one failing; existing outputs.
        cases.push(dcase(
            "unxz",
            &["-k", "a.xz", "b.xz", "c.xz"],
            vec![
                ("a.xz", p6.clone()),
                ("b.xz", flipped(&p6, (p6.len() / 2) as isize)),
                ("c.xz", two.clone()),
            ],
        ));
        cases.push(dcase(
            "unxz",
            &["a.xz"],
            vec![("a.xz", p6.clone()), ("a", b"old".to_vec())],
        ));
        cases.push(dcase(
            "unxz",
            &["-f", "a.xz"],
            vec![("a.xz", p6.clone()), ("a", b"old".to_vec())],
        ));
        cases.push(dcase(
            "unxz",
            &["a.xz"],
            vec![("a.xz", b"not xz".to_vec()), ("a", b"old".to_vec())],
        ));
        cases.push(dcase("xzcat", &["-", "a.xz"], vec![("a.xz", p6.clone())]));
        cases.push(dcase("unxz", &["a"], vec![("a", plain.clone())]));
        cases.push(dcase("xzcat", &["-f", "a"], vec![("a", plain.clone())]));
        cases.push(dcase(
            "xzcat",
            &["-qf", "a", "b.xz"],
            vec![("a", plain.clone()), ("b.xz", p6.clone())],
        ));
        cases.push(dcase("xz", &["-tf", "a"], vec![("a", plain.clone())]));
        cases.push(fed(dcase("unxz", &[], vec![]), p6.clone()));
        cases.push(fed(dcase("unxz", &["-"], vec![]), two.clone()));
        cases.push(fed(dcase("xz", &["-t"], vec![]), p6.clone()));
        cases.push(fed(dcase("xzcat", &["--single-stream"], vec![]), two));
        cases.push(fed(dcase("xz", &["-dcf"], vec![]), plain.clone()));
        cases.push(with_setup(
            dcase("unxz", &["l.xz"], vec![("a.xz", p6.clone())]),
            |d| std::os::unix::fs::symlink("a.xz", d.join("l.xz")).unwrap(),
        ));
        cases.push(on_tty(dcase(
            "xzcat",
            &["a.xz"],
            vec![("a.xz", p6.clone())],
        )));
        // The pure tier: block.xz to standard output, four ways.
        check_tolerating("decompress_and_test", &cases, 4);
    }

    /// `.lzma` through `unlzma`, `lzcat` and detection; raw with its
    /// chain; lzip through `--format=lzip` and detection.
    #[test]
    fn lzma_raw_and_lzip() {
        let plain = text();
        let lzma = reference_output(&["-F", "lzma"], &plain);
        let raw1 = reference_output(&["-F", "raw", "--lzma1=preset=0"], &plain);
        let raw_preset = reference_output(&["-F", "raw"], &plain);
        let lz = stuffr_encode("lzip", &plain, None);
        let mut cases = Vec::new();
        for (tool, args) in [
            ("unlzma", &["-k", "a.lzma"][..]),
            ("unlzma", &["a.lzma"]),
            ("lzcat", &["a.lzma"]),
            ("unlzma", &["-t", "a.lzma"]),
            ("xz", &["-d", "-k", "a.lzma"]),
            ("xz", &["-dc", "-F", "lzma", "a.lzma"]),
            ("xz", &["-dc", "-F", "xz", "a.lzma"]),
            ("xz", &["-dc", "-F", "lzip", "a.lzma"]),
            ("unxz", &["-k", "a.lzma"]),
        ] {
            cases.push(dcase(tool, args, vec![("a.lzma", lzma.clone())]));
        }
        for (name, data) in [
            ("cut.lzma", lzma[..lzma.len() - 1].to_vec()),
            ("cut13.lzma", lzma[..13].to_vec()),
            ("junk.lzma", [lzma.clone(), b"junk".to_vec()].concat()),
            ("two.lzma", [lzma.clone(), lzma.clone()].concat()),
            ("dict.lzma", {
                let mut v = lzma.clone();
                v[1..5].copy_from_slice(&(3u32 << 20).to_le_bytes());
                v
            }),
            ("baddict.lzma", {
                let mut v = lzma.clone();
                v[1..5].copy_from_slice(&((1u32 << 20) + 1).to_le_bytes());
                v
            }),
        ] {
            cases.push(dcase("lzcat", &[name], vec![(name, data.clone())]));
            cases.push(dcase("unlzma", &["-k", name], vec![(name, data)]));
        }
        for (tool, args) in [
            ("xz", &["-dc", "-F", "raw", "--lzma1=preset=0", "a.raw"][..]),
            ("xz", &["-t", "-F", "raw", "--lzma1=preset=0", "a.raw"]),
            ("xz", &["-dc", "-F", "raw", "--lzma2=preset=0", "a.raw"]),
            (
                "xz",
                &[
                    "-d",
                    "-F",
                    "raw",
                    "-S",
                    ".raw",
                    "--lzma1=preset=0",
                    "-k",
                    "a.raw",
                ],
            ),
            ("xz", &["-d", "-F", "raw", "--lzma1=preset=0", "a.raw"]),
            ("xz", &["-dc", "a.raw"]),
        ] {
            cases.push(dcase(tool, args, vec![("a.raw", raw1.clone())]));
        }
        cases.push(dcase(
            "xz",
            &["-dc", "-F", "raw", "a.raw"],
            vec![("a.raw", raw_preset.clone())],
        ));
        cases.push(dcase(
            "xz",
            &["-dcq", "-F", "raw", "a.raw"],
            vec![("a.raw", raw_preset)],
        ));
        let two = [lz.clone(), lz.clone()].concat();
        for (name, data) in [
            ("a.lz", lz.clone()),
            ("two.lz", two),
            ("junk.lz", [lz.clone(), b"junk".to_vec()].concat()),
            ("cut.lz", lz[..lz.len() - 1].to_vec()),
        ] {
            for (tool, args) in [
                ("xz", &["-dc", "--format=lzip"][..]),
                ("xz", &["-dc"]),
                ("xz", &["-t"]),
                ("unxz", &["-k"]),
                ("xz", &["-dc", "--single-stream"]),
                ("xz", &["-dc", "-F", "lzma"]),
            ] {
                let mut a = args.to_vec();
                a.push(name);
                cases.push(dcase(tool, &a, vec![(name, data.clone())]));
            }
        }
        // The pure tier: cut.lzma through lzcat.
        check_tolerating("lzma_raw_and_lzip", &cases, 1);
    }

    /// Sparse output: a megabyte of zeros between text, and zeros at the
    /// end (the hole closed by its last byte); `--no-sparse`; standard
    /// output. The bytes and sizes are compared.
    #[test]
    fn sparse_output() {
        let mut holes = text();
        holes.extend(vec![0u8; 1 << 20]);
        holes.extend(text());
        let mut tail = text();
        tail.extend(vec![0u8; 64 << 10]);
        let mut cases = Vec::new();
        for data in [holes, tail, vec![0u8; 256 << 10]] {
            let s = reference_output(&[], &data);
            for args in [
                &["-k", "s.xz"][..],
                &["--no-sparse", "-k", "s.xz"],
                &["-c", "s.xz"],
                &["s.xz"],
            ] {
                cases.push(dcase("unxz", args, vec![("s.xz", s.clone())]));
            }
        }
        check("sparse_output", &cases);
    }

    /// Thread counts and memory limits when decoding: refusals with the
    /// memory needed (in MiB, or bytes under 1 MiB), the output never
    /// opened.
    #[test]
    fn decoder_limits() {
        let plain = text();
        let p9 = reference_output(&["-9", "-T1"], &plain);
        let mt = reference_output(&["-T4", "--block-size=1KiB"], &plain);
        let lzma9 = reference_output(&["-F", "lzma", "-9"], &plain);
        let raw = reference_output(&["-F", "raw", "--lzma1=dict=64MiB"], &plain);
        let mut cases = Vec::new();
        for (args, name, data) in [
            (&["-dc", "--memlimit=1MiB"][..], "a.xz", &p9),
            (&["-t", "-M", "10MiB"], "a.xz", &p9),
            (&["-d", "-M", "1000"], "a.xz", &p9),
            (&["-dk", "--memlimit-decompress=2MiB"], "a.xz", &p9),
            (&["-dc", "-M", "1MiB", "-T4"], "a.xz", &mt),
            (&["-dc", "-T4"], "a.xz", &mt),
            (&["-dc", "-T1"], "a.xz", &mt),
            (
                &["-dc", "--memlimit-mt-decompress=1MiB", "-T4"],
                "a.xz",
                &mt,
            ),
            (&["-dc", "-M", "1MiB"], "a.lzma", &lzma9),
            (&["-dc", "-M", "100MiB"], "a.lzma", &lzma9),
            (
                &["-dc", "-F", "raw", "--lzma1=dict=64MiB", "-M", "1MiB"],
                "a.raw",
                &raw,
            ),
            (&["-dc", "-F", "raw", "--lzma1=dict=64MiB"], "a.raw", &raw),
        ] {
            let mut a = args.to_vec();
            a.push(name);
            cases.push(dcase("xz", &a, vec![(name, data.clone())]));
        }
        cases.push(dcase(
            "xz",
            &["-d", "-M", "1MiB", "a.xz"],
            vec![("a.xz", p9.clone()), ("a", b"old".to_vec())],
        ));
        cases.push(dcase(
            "xz",
            &["-df", "-M", "1MiB", "a.xz"],
            vec![("a.xz", p9), ("a", b"old".to_vec())],
        ));
        check("decoder_limits", &cases);
    }

    /// stuffr's own peak memory for `args` over `input` as `name` (from a
    /// file `f`), in bytes (`wait4`'s figure for the process), its exit
    /// code and its standard error.
    fn own_peak(name: &str, args: &[&str], f: &str, input: &[u8]) -> (u64, Option<i32>, String) {
        use std::io::Read;
        let dir =
            std::env::temp_dir().join(format!("stuffr-xz-peak-{}-{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("bin")).unwrap();
        let link = dir.join("bin").join(name);
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stuffr"), &link).unwrap();
        fs::write(dir.join(f), input).unwrap();
        let mut child = spawn(
            Command::new(&link)
                .args(args)
                .arg(f)
                .current_dir(&dir)
                .env_clear()
                .env("LC_ALL", "C")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped()),
        )
        .unwrap();
        let mut errs = child.stderr.take().unwrap();
        let reader = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = errs.read_to_string(&mut s);
            s
        });
        let (status, peak) = wait_with_maxrss(child);
        let err = reader.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
        let code = status.code();
        (peak, code, err)
    }

    /// Review Focus 3: a header that declares more memory than the limit is
    /// refused before the decoder allocates: a `.lzma` declaring a
    /// 4 GiB dictionary under `-M 100MiB` (said as xz says it, and the
    /// process stays small on both tiers), and the differential cases.
    #[test]
    fn decoder_memlimit_refuses_before_allocating() {
        let mut hostile = reference_output(&["-F", "lzma", "-0"], &text());
        hostile[1..5].copy_from_slice(&u32::MAX.to_le_bytes());
        let cases = vec![
            dcase(
                "xz",
                &["-dc", "-M", "100MiB", "h.lzma"],
                vec![("h.lzma", hostile.clone())],
            ),
            dcase(
                "unlzma",
                &["-M", "100MiB", "h.lzma"],
                vec![("h.lzma", hostile.clone())],
            ),
            dcase(
                "unlzma",
                &["-t", "-M", "4GiB", "h.lzma"],
                vec![("h.lzma", hostile.clone())],
            ),
        ];
        check("decoder_memlimit_refuses_before_allocating", &cases);
        let (peak, code, err) = own_peak("xz", &["-dc", "-M", "100MiB"], "h.lzma", &hostile);
        assert_eq!(code, Some(1), "{err}");
        // The program name is the full argv[0].
        assert!(
            err.contains("/xz: h.lzma: Memory usage limit reached\n")
                && err.ends_with("/xz: 4097 MiB of memory is required. The limit is 100 MiB.\n"),
            "{err:?}"
        );
        assert!(peak < 64 << 20, "peak memory {peak} bytes");
    }

    /// Review Focus 2: the memory limit lowers the thread count first (the
    /// output unchanged), then falls back to single-threaded mode (with a
    /// warning), then lowers the dictionary, or refuses under
    /// `--no-adjust`; `-vv` shows each step, then the progress line.
    #[test]
    fn memlimit_reduces_threads_like_xz() {
        let data = mixed(200_000, 81);
        let mut cases = Vec::new();
        for args in [
            &["-T4", "-9", "--memlimit-compress=1500MiB", "-c"][..],
            &["-T4", "-6", "--memlimit-compress=400MiB", "-c"],
            &["-T4", "-9", "--memlimit-compress=300MiB", "-c"],
            &[
                "-T4",
                "-9",
                "--memlimit-compress=300MiB",
                "--no-adjust",
                "-c",
            ],
            &["-T4", "-6", "--memlimit-compress=50MiB", "-c"],
            &["-T0", "-9", "--memlimit-compress=300MiB", "-c"],
            &["-T+1", "-9", "--memlimit-compress=300MiB", "-c"],
            &["-T1", "-9", "-M", "100MiB", "-c"],
            &["-T1", "-9", "-M", "100MiB", "--no-adjust", "-c"],
            &["-T1", "-M", "1MiB", "-c"],
            &["-T1", "--lzma2=dict=200MiB", "-M", "1GiB", "-c"],
            &["-T1", "--x86", "--lzma2=dict=64MiB", "-M", "100MiB", "-c"],
            &[
                "-T1",
                "--block-list=1:1000,0",
                "--filters1=lzma2:dict=64MiB",
                "-M",
                "100MiB",
                "-c",
            ],
            &["-T1", "--delta", "-M", "1KiB", "-c"],
            &["-F", "lzma", "-9", "-M", "100MiB", "-c"],
            &["-F", "raw", "-9", "-M", "100MiB", "-c"],
        ] {
            cases.push(fed(xz(args), data.clone()));
            let mut vv = args.to_vec();
            vv.insert(0, "-vv");
            cases.push(fed(xz(&vv), data.clone()));
        }
        let one = |c: &Case| -> bool {
            let Some(dir) = xz_dir() else { return false };
            let Some(mut r) = reference(dir, c) else {
                return false;
            };
            let mut s = stuffr_as(c);
            for run in [&mut r, &mut s] {
                run.stderr = progress_line(&run.stderr);
            }
            assert_same(c, &r, &s);
            true
        };
        run_group(
            "memlimit_reduces_threads_like_xz",
            &cases,
            Skipped::none(),
            &one,
        );
    }

    /// Review Focus 1: `xzcat` streams a 64 MiB output in bounded memory:
    /// the decoder holds its dictionary (1 MiB at `-0`), a chunk of input
    /// and a chunk of output, never the stream. Linux measures anonymous
    /// memory; elsewhere the process's own peak (`wait4`).
    #[test]
    fn xzcat_streams_a_large_input() {
        const N: usize = 64 << 20;
        let plain = mixed(N, 91);
        if xz_dir().is_none() {
            return;
        }
        let packed = reference_output(&["-0", "-T1"], &plain);
        let peak = decoder_peak_rss("xzcat", "big.xz", &packed, &plain, &[("LC_ALL", "C")]);
        assert!(
            peak < 64 << 20,
            "peak memory {peak} bytes is not under 64 MiB"
        );
    }

    fn closed_pipe_status(exe: &Path, dir: &Path) -> std::process::ExitStatus {
        use std::io::Read;
        let mut child = spawn(
            Command::new(exe)
                .arg("big.xz")
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

    /// Review Focus 1: `xzcat big.xz | head` ends stuffr by SIGPIPE with
    /// nothing said, as it ends xz (a parent that does not ignore SIGPIPE;
    /// one that does is a documented deviation).
    #[test]
    fn xzcat_into_a_closed_pipe() {
        use std::os::unix::process::ExitStatusExt;
        let Some(dir) = xz_dir() else { return };
        let plain = text().repeat(4000);
        let work = std::env::temp_dir().join(format!("stuffr-xzcat-pipe-{}", std::process::id()));
        let _ = fs::remove_dir_all(&work);
        fs::create_dir_all(work.join("bin")).unwrap();
        let link = work.join("bin").join("xzcat");
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stuffr"), &link).unwrap();
        fs::write(work.join("big.xz"), reference_output(&[], &plain)).unwrap();
        let ours = closed_pipe_status(&link, &work);
        let theirs = closed_pipe_status(&Path::new(dir).join("xzcat"), &work);
        let _ = fs::remove_dir_all(&work);
        assert_eq!(
            theirs.signal(),
            Some(libc::SIGPIPE),
            "reference: {theirs:?}"
        );
        assert_eq!(ours.signal(), theirs.signal(), "stuffr as xzcat: {ours:?}");
    }

    /// Run `exe ARGS` in `work` and interrupt it after `after`; its wait
    /// status and whether it was still running then.
    fn interrupted(
        exe: &Path,
        args: &[&str],
        work: &Path,
        after: std::time::Duration,
    ) -> (std::process::ExitStatus, bool) {
        let mut child = spawn(
            Command::new(exe)
                .args(args)
                .current_dir(work)
                .env_clear()
                .env("LC_ALL", "C")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
        )
        .unwrap();
        std::thread::sleep(after);
        let running = child.try_wait().unwrap().is_none();
        // SAFETY: kill only sends a signal to our own child.
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) };
        (child.wait().unwrap(), running)
    }

    /// A scratch directory holding `files` (and the stuffr links).
    fn scratch(tag: &str, files: &[(&str, &[u8])]) -> std::path::PathBuf {
        let work = std::env::temp_dir().join(format!("stuffr-xz-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&work);
        fs::create_dir_all(work.join("bin")).unwrap();
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stuffr"), work.join("bin").join("xz"))
            .unwrap();
        for (n, b) in files {
            fs::write(work.join(n), b).unwrap();
        }
        work
    }

    /// The names in `dir`, `bin` left out.
    fn names_in(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != "bin")
            .collect();
        v.sort();
        v
    }

    /// Ruling P3: 16 MiB of random data at `-9e -T1` runs over a second
    /// here, so SIGINT at 400 ms meets both tools mid-file. Both die of
    /// SIGINT, the input is intact and no output (or temporary) is left.
    #[test]
    fn an_interrupt_leaves_no_partial_output() {
        use std::os::unix::process::ExitStatusExt;
        let Some(dir) = xz_dir() else { return };
        let data = random(16 << 20, 97);
        let at = std::time::Duration::from_millis(400);
        let args = ["-T1", "-9e", "a"];
        let reference_dir = scratch("int-ref", &[("a", &data)]);
        let (theirs, ran) = interrupted(&Path::new(dir).join("xz"), &args, &reference_dir, at);
        let their_names = names_in(&reference_dir);
        let _ = fs::remove_dir_all(&reference_dir);
        let work = scratch("int", &[("a", &data)]);
        let (ours, ours_ran) = interrupted(&work.join("bin").join("xz"), &args, &work, at);
        let our_names = names_in(&work);
        let intact = fs::read(work.join("a")).map(|b| b == data);
        let _ = fs::remove_dir_all(&work);
        assert!(ours_ran, "stuffr finished before the interrupt");
        assert_eq!(ours.signal(), Some(libc::SIGINT), "stuffr: {ours:?}");
        assert_eq!(our_names, ["a"], "stuffr left {our_names:?}");
        assert!(matches!(intact, Ok(true)), "the input changed");
        if !ran {
            println!("skipped the reference half: it finished before the interrupt");
            return;
        }
        assert_eq!(theirs.signal(), ours.signal(), "reference: {theirs:?}");
        assert_eq!(their_names, our_names);
    }

    /// Review Focus 5 (spec deviation 4): `xz -f a` where `a` is the output
    /// `a.xz` under another name (a symbolic link to it, or a hard link).
    /// Finished, both tools end alike: `a.xz` compressed, the link left
    /// ("moved") or removed. Interrupted, xz has already removed `a.xz` and
    /// loses the data; stuffr has not, and keeps it.
    #[test]
    fn an_output_linked_to_the_input_never_loses_it() {
        let plain = text();
        let cases = vec![
            with_setup(
                dcase("xz", &["-f", "a"], vec![("a.xz", plain.clone())]),
                |d| {
                    std::os::unix::fs::symlink("a.xz", d.join("a")).unwrap();
                },
            ),
            with_setup(
                dcase("xz", &["-f", "a"], vec![("a.xz", plain.clone())]),
                |d| {
                    fs::hard_link(d.join("a.xz"), d.join("a")).unwrap();
                },
            ),
            with_setup(
                dcase(
                    "unxz",
                    &["-f", "a.xz"],
                    vec![("a.xz", reference_output(&[], &plain))],
                ),
                |d| fs::hard_link(d.join("a.xz"), d.join("a")).unwrap(),
            ),
        ];
        check("an_output_linked_to_the_input_never_loses_it", &cases);

        use std::os::unix::process::ExitStatusExt;
        let data = random(16 << 20, 98);
        let at = std::time::Duration::from_millis(400);
        for hard in [false, true] {
            let work = scratch(if hard { "link-h" } else { "link-s" }, &[("a.xz", &data)]);
            if hard {
                fs::hard_link(work.join("a.xz"), work.join("a")).unwrap();
            } else {
                std::os::unix::fs::symlink("a.xz", work.join("a")).unwrap();
            }
            let (st, ran) = interrupted(
                &work.join("bin").join("xz"),
                &["-f", "-T1", "-9e", "a"],
                &work,
                at,
            );
            let kept = fs::read(work.join("a.xz")).map(|b| b == data);
            let names = names_in(&work);
            let _ = fs::remove_dir_all(&work);
            assert!(ran, "stuffr finished before the interrupt");
            assert_eq!(st.signal(), Some(libc::SIGINT));
            assert!(matches!(kept, Ok(true)), "hard {hard}: the input was lost");
            assert_eq!(names, ["a", "a.xz"], "hard {hard}");
        }
    }

    /// `unxz [-f] a.xz` over `a.xz` holding `xz` beside an existing `a`, in
    /// a fresh directory: standard error with `exe`'s path cut to its last
    /// component, the exit code, and what `a` then holds (`None`: gone).
    fn unxz_over_existing(
        exe: &Path,
        tag: &str,
        force: bool,
        xz: &[u8],
    ) -> (String, Option<i32>, Option<Vec<u8>>) {
        let work = scratch(tag, &[("a.xz", xz), ("a", b"existing\n")]);
        let mut cmd = Command::new(exe);
        if force {
            cmd.arg("-f");
        }
        let out = output(
            cmd.arg("a.xz")
                .current_dir(&work)
                .env_clear()
                .env("LC_ALL", "C")
                .stdin(Stdio::null()),
        )
        .unwrap();
        let kept = fs::read(work.join("a")).ok();
        let _ = fs::remove_dir_all(&work);
        let err = String::from_utf8_lossy(&out.stderr).replace(&*exe.to_string_lossy(), "unxz");
        (err, out.status.code(), kept)
    }

    /// The header probe (`coder.rs`, the `mod.rs` deviation list). Byte 30
    /// of a `-T1` stream is the first LZMA2 chunk's first range-coder byte;
    /// flipped, xz 5.8.4 finds the corruption only after it has opened the
    /// output:
    ///
    /// - without `-f`: xz says "a: File exists", exits 1 and keeps `a`;
    /// - with `-f`: xz says "a.xz: Compressed data is corrupt", exits 1 and
    ///   has removed the existing `a`.
    ///
    /// On the C tier (`xz-c`) stuffr makes xz's own probe call and agrees
    /// exactly. On the pure tier it is a pinned, expected deviation (the
    /// harness has no expected-deviation mechanism, so its observed outcome
    /// is asserted on its own): it finds the corruption before opening the
    /// output, saying "Compressed data is corrupt" without `-f` too, and
    /// keeps `a` with `-f`.
    #[test]
    fn header_probe_matches_on_c_tier_and_deviation_is_pinned_on_pure() {
        let Some(dir) = xz_dir() else { return };
        let mut xz = reference_output(&["-T1"], &text());
        assert_eq!(&xz[24..31], [0xe0, 0x06, 0xdf, 0x00, 0x3b, 0x5d, 0x00]);
        xz[30] ^= 0xff;
        let existing = Some(b"existing\n".to_vec());
        let corrupt = "unxz: a.xz: Compressed data is corrupt\n".to_string();
        let reference = Path::new(dir).join("unxz");
        let link =
            std::env::temp_dir().join(format!("stuffr-xz-probe-link-{}", std::process::id()));
        let _ = fs::remove_dir_all(&link);
        fs::create_dir_all(&link).unwrap();
        let ours = link.join("unxz");
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stuffr"), &ours).unwrap();

        let theirs_plain = unxz_over_existing(&reference, "probe-ref", false, &xz);
        let theirs_forced = unxz_over_existing(&reference, "probe-ref-f", true, &xz);
        let ours_plain = unxz_over_existing(&ours, "probe", false, &xz);
        let ours_forced = unxz_over_existing(&ours, "probe-f", true, &xz);
        let _ = fs::remove_dir_all(&link);

        assert_eq!(
            theirs_plain,
            (
                "unxz: a: File exists\n".to_string(),
                Some(1),
                existing.clone()
            ),
            "reference, without -f"
        );
        assert_eq!(
            theirs_forced,
            (corrupt.clone(), Some(1), None),
            "reference, with -f"
        );
        if cfg!(feature = "xz-c") {
            // The C tier makes xz's own probe: the same text, exit and files.
            assert_eq!(ours_plain, theirs_plain, "stuffr (C tier), without -f");
            assert_eq!(ours_forced, theirs_forced, "stuffr (C tier), with -f");
        } else {
            assert_eq!(
                ours_plain,
                (corrupt.clone(), Some(1), existing.clone()),
                "stuffr (pure tier), without -f"
            );
            assert_eq!(
                ours_forced,
                (corrupt, Some(1), existing),
                "stuffr (pure tier), with -f"
            );
        }
    }

    // ==== Part 3 (Task 7): --list ====

    /// An `.xz` variable-length integer.
    fn vli(mut n: u64) -> Vec<u8> {
        let mut v = Vec::new();
        while n >= 0x80 {
            v.push(n as u8 | 0x80);
            n >>= 7;
        }
        v.push(n as u8);
        v
    }

    /// `lzma_check_size` by check ID.
    const CHECK_SIZES: [usize; 16] = [0, 4, 4, 4, 8, 8, 8, 16, 16, 16, 32, 32, 32, 64, 64, 64];

    const VLI_MAX: u64 = u64::MAX / 2;

    /// One Block of a hand-made `.xz`: its header's filter flags, the sizes
    /// its header records (if any), its Compressed Data's length and the
    /// uncompressed size its Index record declares. The data is filler:
    /// `--list` never decodes it.
    #[derive(Clone)]
    struct Blk {
        filters: Vec<(u64, Vec<u8>)>,
        header_sizes: Option<(u64, u64)>,
        data: usize,
        uncompressed: u64,
    }

    fn blk(filters: Vec<(u64, Vec<u8>)>) -> Blk {
        Blk {
            filters,
            header_sizes: None,
            data: 24,
            uncompressed: 1000,
        }
    }

    fn lzma2(props: u8) -> (u64, Vec<u8>) {
        (0x21, vec![props])
    }

    fn x86() -> (u64, Vec<u8>) {
        (0x04, Vec::new())
    }

    fn delta(dist: u8) -> (u64, Vec<u8>) {
        (0x03, vec![dist - 1])
    }

    /// A Stream of `blocks` with check `check`; `records`, when given,
    /// replaces the Index's records (unpadded, uncompressed) the Blocks
    /// would give, so an Index can disagree with its Blocks.
    fn made_stream(check: u8, blocks: &[Blk], records: Option<Vec<(u64, u64)>>) -> Vec<u8> {
        let mut s = vec![0xFD, b'7', b'z', b'X', b'Z', 0, 0, check];
        s.extend(crc32(&[0, check]).to_le_bytes());
        let csize = CHECK_SIZES[usize::from(check & 15)];
        let mut recs = Vec::new();
        for b in blocks {
            let mut hdr = vec![0u8, (b.filters.len() as u8).wrapping_sub(1) & 3];
            if let Some((c, u)) = b.header_sizes {
                hdr[1] |= 0xC0;
                hdr.extend(vli(c));
                hdr.extend(vli(u));
            }
            for (id, props) in &b.filters {
                hdr.extend(vli(*id));
                hdr.extend(vli(props.len() as u64));
                hdr.extend(props);
            }
            while !hdr.len().is_multiple_of(4) {
                hdr.push(0);
            }
            hdr[0] = (hdr.len() / 4) as u8;
            hdr.extend(crc32(&hdr).to_le_bytes());
            let start = s.len();
            s.extend(&hdr);
            s.extend(vec![0x55; b.data]);
            while !(s.len() - start).is_multiple_of(4) {
                s.push(0);
            }
            s.extend((0..csize).map(|i| (i * 7 + 3) as u8));
            recs.push(((hdr.len() + b.data + csize) as u64, b.uncompressed));
        }
        let recs = records.unwrap_or(recs);
        let mut index = vec![0u8];
        index.extend(vli(recs.len() as u64));
        for (unpadded, uncompressed) in recs {
            index.extend(vli(unpadded));
            index.extend(vli(uncompressed));
        }
        while !index.len().is_multiple_of(4) {
            index.push(0);
        }
        index.extend(crc32(&index).to_le_bytes());
        s.extend(&index);
        let backward = ((index.len() / 4 - 1) as u32).to_le_bytes();
        let mut tail = backward.to_vec();
        tail.extend([0, check]);
        s.extend(crc32(&tail).to_le_bytes());
        s.extend(tail);
        s.extend(b"YZ");
        s
    }

    fn made_xz(check: u8, blocks: &[Blk]) -> Vec<u8> {
        made_stream(check, blocks, None)
    }

    /// Every list form of `a.xz`, as `tool`.
    const LIST_FORMS: [&[&str]; 6] = [
        &["-l"],
        &["-lv"],
        &["-lvv"],
        &["--robot", "-l"],
        &["--robot", "-lv"],
        &["--robot", "-lvv"],
    ];

    fn list_case(args: &[&'static str], files: Vec<(&'static str, Vec<u8>)>) -> Case<'static> {
        dcase("xz", args, files)
    }

    /// Each input under every list form.
    fn every_form(inputs: &[(&'static str, Vec<u8>)]) -> Vec<Case<'static>> {
        let mut cases = Vec::new();
        for (name, data) in inputs {
            let file: &'static str = Box::leak(format!("{name}.xz").into_boxed_str());
            for form in LIST_FORMS {
                let mut a = form.to_vec();
                a.push(file);
                cases.push(list_case(&a, vec![(file, data.clone())]));
            }
        }
        cases
    }

    /// The reference's own streams: one Stream, several, padded, many
    /// Blocks (threaded, `--block-size`, `--block-list`), every check the
    /// encoder writes, every filter, an empty Stream, each under every list
    /// form; then several files with their totals.
    #[test]
    fn list_reference_streams() {
        let plain = text();
        let p6 = reference_output(&[], &plain);
        let p0 = reference_output(&["-0"], b"second\n");
        let mut inputs = streams();
        inputs.push(("two", [p6.clone(), p0.clone()].concat()));
        inputs.push(("padded", [p6.clone(), vec![0; 8]].concat()));
        inputs.push((
            "padmid",
            [p6.clone(), vec![0; 4], p0.clone(), vec![0; 12]].concat(),
        ));
        inputs.push(("crc32", reference_output(&["-C", "crc32"], &plain)));
        inputs.push(("p9", reference_output(&["-9", "-T1"], &mixed(70_000, 5))));
        inputs.push((
            "big",
            reference_output(&["-T1", "--block-size=40000"], &random(300_000, 4)),
        ));
        let mut cases = every_form(&inputs);
        // Several files: totals in every form, and a failing one between.
        let files = || {
            vec![
                ("a.xz", p6.clone()),
                ("b.xz", [p6.clone(), vec![0; 4], p0.clone()].concat()),
                ("c.xz", reference_output(&["-C", "sha256"], &plain)),
                ("bad.xz", flipped(&p6, -17)),
            ]
        };
        for form in LIST_FORMS {
            for operands in [
                &["a.xz", "b.xz", "c.xz"][..],
                &["a.xz", "bad.xz", "c.xz"],
                &["a.xz", "missing.xz", "b.xz"],
                &["bad.xz"],
                &["a.xz", "a.xz"],
            ] {
                let mut a = form.to_vec();
                a.extend(operands);
                cases.push(list_case(&a, files()));
            }
        }
        check("list_reference_streams", &cases);
    }

    /// What `--list` refuses: `.lzma` and other formats, standard input,
    /// empty, short and non-`.xz` files, a directory; symbolic and hard
    /// links (followed: `--list` forces `--force`); `-q`; names read with
    /// `--files`.
    #[test]
    fn list_refusals_and_operands() {
        let plain = text();
        let p6 = reference_output(&[], &plain);
        let lzma = reference_output(&["-F", "lzma"], &plain);
        let a = || vec![("a.xz", p6.clone())];
        let mut cases = vec![
            dcase("lzma", &["-l", "a.lzma"], vec![("a.lzma", lzma.clone())]),
            dcase("unlzma", &["-l", "a.lzma"], vec![("a.lzma", lzma.clone())]),
            dcase("xz", &["-l", "a.lzma"], vec![("a.lzma", lzma.clone())]),
            dcase("xz", &["-l", "-F", "lzma", "a.xz"], a()),
            dcase("xz", &["-l", "-F", "raw", "a.xz"], a()),
            dcase("xz", &["-l", "-F", "lzip", "a.xz"], a()),
            dcase("xz", &["-l", "-F", "xz", "a.xz"], a()),
            dcase("xzcat", &["-l", "a.xz"], a()),
            dcase("unxz", &["-lv", "a.xz"], a()),
            dcase("xz", &["-l", "-F", "lzma", "missing"], a()),
            dcase("xz", &["-lq", "missing", "a.xz"], a()),
            dcase("xz", &["-lqq", "missing"], a()),
            dcase("xz", &["-l", "a"], vec![("a", plain.clone())]),
            dcase("xz", &["-l", "e.xz"], vec![("e.xz", Vec::new())]),
            dcase("xz", &["-lv", "e.xz"], vec![("e.xz", Vec::new())]),
            dcase("xz", &["-l", "s.xz"], vec![("s.xz", p6[..23].to_vec())]),
            dcase("xz", &["-l", "s.xz"], vec![("s.xz", p6[..24].to_vec())]),
            dcase("xz", &["-l", "z.xz"], vec![("z.xz", vec![0; 64])]),
            dcase("xz", &["-l", ""], a()),
            dcase("xz", &["-l", "-c", "-k", "a.xz"], a()),
            with_setup(dcase("xz", &["-l", "d"], a()), dir_d),
            with_setup(
                dcase("xz", &["-l", "l"], vec![("a", p6.clone())]),
                symlink_l_to_a,
            ),
            with_setup(
                dcase("xz", &["-l", "h"], vec![("a", p6.clone())]),
                hard_link_h_to_a,
            ),
            with_setup(dcase("xz", &["-l", "a"], vec![("a", p6.clone())]), a_setuid),
            with_setup(
                dcase("xz", &["-l", "a"], vec![("a", p6.clone())]),
                a_unreadable,
            ),
            with_setup(dcase("xz", &["-l", "p"], a()), |d| {
                let path =
                    std::ffi::CString::new(d.join("p").as_os_str().as_encoded_bytes()).unwrap();
                // SAFETY: a valid C string.
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o644) }, 0);
            }),
        ];
        for form in LIST_FORMS {
            // Standard input, alone and among files; never read.
            cases.push(fed(dcase("xz", form, a()), p6.clone()));
            let mut args = form.to_vec();
            args.extend(["-", "a.xz"]);
            cases.push(fed(dcase("xz", &args, a()), p6.clone()));
            // Names from --files: the count is unknown.
            let mut args = form.to_vec();
            args.extend(["--files=names", "a.xz"]);
            let mut files = a();
            files.push(("names", b"a.xz\nmissing\n\na.xz\n".to_vec()));
            cases.push(dcase("xz", &args, files));
            // Nothing listed at all.
            let mut args = form.to_vec();
            args.push("--files=empty");
            cases.push(dcase("xz", &args, vec![("empty", Vec::new())]));
        }
        cases.push(on_tty_stdin(dcase("xz", &["-l"], a())));
        cases.push(on_tty_stdin(dcase("xz", &["-l", "-F", "lzma"], a())));
        check("list_refusals_and_operands", &cases);
    }

    fn on_tty_stdin<'a>(mut c: Case<'a>) -> Case<'a> {
        c.tty_stdin = true;
        c
    }

    /// Corrupt and cut-short files: each spot of the Stream Header, the
    /// Index and the Stream Footer, Stream Padding of a wrong size, a
    /// Block Header (seen only at `-vv`), and truncations.
    #[test]
    fn list_corrupt_and_truncated() {
        let p6 = reference_output(&[], &text());
        let two = [p6.clone(), reference_output(&["-0"], b"second\n")].concat();
        let n = p6.len() as isize;
        let mut inputs: Vec<(&'static str, Vec<u8>)> = vec![
            ("magic", flipped(&p6, 0)),
            ("hflags", flipped(&p6, 6)),
            ("hcrc", flipped(&p6, 9)),
            ("block", flipped(&p6, 13)),
            ("index", flipped(&p6, -17)),
            ("indicator", flipped(&p6, -24)),
            ("fcrc", flipped(&p6, -12)),
            ("backward", flipped(&p6, -8)),
            ("fflags", flipped(&p6, -4)),
            ("fcheck", flipped(&p6, -3)),
            ("fmagic", flipped(&p6, -1)),
            ("cut1", p6[..p6.len() - 1].to_vec()),
            ("cut4", p6[..p6.len() - 4].to_vec()),
            ("cut12", p6[..p6.len() - 12].to_vec()),
            ("cuthalf", p6[..(n / 2) as usize & !3].to_vec()),
            ("pad3", [p6.clone(), vec![0; 3]].concat()),
            ("pad5", [p6.clone(), vec![0; 5]].concat()),
            ("junk", [p6.clone(), b"junk".to_vec()].concat()),
            ("second", flipped(&two, -(n + 30))),
            ("secondhdr", flipped(&two, p6.len() as isize + 7)),
            ("zeros", [vec![0; 12], p6.clone()].concat()),
        ];
        // Stream Header of the second Stream changed to another check.
        let mut other = two.clone();
        other[p6.len() + 7] = 1;
        let crc = crc32(&other[p6.len() + 6..p6.len() + 8]).to_le_bytes();
        other[p6.len() + 8..p6.len() + 12].copy_from_slice(&crc);
        inputs.push(("checkdiff", other));
        let mut cases = every_form(&inputs);
        for args in [
            &["-lvv", "a.xz", "block.xz", "a.xz"][..],
            &["-l", "a.xz", "cut1.xz"],
        ] {
            cases.push(list_case(
                args,
                vec![
                    ("a.xz", p6.clone()),
                    ("block.xz", flipped(&p6, 13)),
                    ("cut1.xz", p6[..p6.len() - 1].to_vec()),
                ],
            ));
        }
        check("list_corrupt_and_truncated", &cases);
    }

    /// Hand-made Streams: every check ID (the reserved ones listed as
    /// `Unknown-N`), every filter and option form a Block Header can hold,
    /// sizes in the headers, the minimum versions, sizes past TiB, ratios
    /// over 9.999, and the Block Header and Index refusals.
    #[test]
    fn list_made_streams() {
        let l = || blk(vec![lzma2(22)]);
        let mut inputs: Vec<(&'static str, Vec<u8>)> = Vec::new();
        for check in 0..16u8 {
            let name: &'static str = Box::leak(format!("check{check}").into_boxed_str());
            inputs.push((name, made_xz(check, &[l(), l()])));
        }
        let with = |filters: Vec<(u64, Vec<u8>)>| made_xz(1, &[blk(filters)]);
        inputs.extend([
            ("noblocks", made_xz(4, &[])),
            ("x86delta", with(vec![x86(), delta(4), lzma2(18)])),
            ("x86start", with(vec![(0x04, vec![16, 0, 0, 0]), lzma2(18)])),
            ("x86zero", with(vec![(0x04, vec![0, 0, 0, 0]), lzma2(18)])),
            ("ppc", with(vec![(0x05, vec![]), lzma2(18)])),
            ("ia64", with(vec![(0x06, vec![]), lzma2(18)])),
            ("arm", with(vec![(0x07, vec![]), lzma2(18)])),
            ("thumb", with(vec![(0x08, vec![]), lzma2(18)])),
            ("sparc", with(vec![(0x09, vec![]), lzma2(18)])),
            ("arm64", with(vec![(0x0A, vec![0, 1, 0, 0]), lzma2(18)])),
            ("riscv", with(vec![(0x0B, vec![]), lzma2(18)])),
            ("four", with(vec![x86(), delta(1), delta(255), lzma2(1)])),
            // Chains liblzma refuses to decode, but lists.
            ("lzfirst", with(vec![lzma2(18), x86()])),
            ("bcjonly", with(vec![x86()])),
            ("twolz", with(vec![lzma2(18), lzma2(18)])),
            // Header refusals.
            ("unknown", with(vec![(0x99, vec![]), lzma2(18)])),
            ("reserved", with(vec![(1 << 62, vec![1]), lzma2(18)])),
            ("lzma1", with(vec![(0x4000_0000_0000_0001, vec![0; 5])])),
            ("propsize", with(vec![(0x04, vec![1, 2, 3]), lzma2(18)])),
            ("lzprops", with(vec![(0x21, vec![1, 2])])),
            ("dict41", with(vec![lzma2(41)])),
            ("dictbits", with(vec![lzma2(0x40)])),
            ("deltaprops", with(vec![(0x03, vec![])])),
        ]);
        let mut sized = l();
        sized.header_sizes = Some((24, 1000));
        let mut wrongc = l();
        wrongc.header_sizes = Some((25, 1000));
        let mut wrongu = l();
        wrongu.header_sizes = Some((24, 999));
        let mut empty = l();
        empty.uncompressed = 0;
        let mut huge = l();
        huge.uncompressed = 1 << 50;
        let mut tiny = l();
        tiny.uncompressed = 1;
        tiny.data = 4000;
        inputs.extend([
            ("sizes", made_xz(4, &[sized.clone(), sized.clone()])),
            ("somesizes", made_xz(4, &[sized.clone(), l()])),
            ("wrongc", made_xz(4, &[wrongc])),
            ("wrongu", made_xz(4, &[wrongu])),
            ("emptyblock", made_xz(4, &[empty.clone()])),
            (
                "emptyx86",
                made_xz(
                    4,
                    &[blk(vec![x86(), lzma2(18)]), {
                        let mut e = blk(vec![x86(), lzma2(18)]);
                        e.uncompressed = 0;
                        e
                    }],
                ),
            ),
            ("huge", made_xz(4, &[huge.clone(), huge])),
            ("tiny", made_xz(0, &[tiny])),
            (
                "versions",
                [
                    made_xz(4, &[empty]),
                    made_xz(1, &[blk(vec![(0x0A, vec![]), lzma2(18)])]),
                    made_xz(10, &[blk(vec![(0x0B, vec![]), lzma2(18)])]),
                ]
                .concat(),
            ),
        ]);
        // Index refusals and oddities.
        let one = [l()];
        let unpadded = 12 + 24 + 8;
        inputs.extend([
            ("unpadded4", made_stream(4, &one, Some(vec![(4, 1000)]))),
            ("unpadded5", made_stream(4, &one, Some(vec![(5, 1000)]))),
            (
                "toolong",
                made_stream(4, &one, Some(vec![(unpadded + 4, 1000)])),
            ),
            (
                "tooshort",
                made_stream(4, &one, Some(vec![(unpadded - 4, 1000)])),
            ),
            ("norecords", made_stream(4, &one, Some(vec![]))),
            (
                "uvlimax",
                made_stream(4, &one, Some(vec![(unpadded, VLI_MAX), (8, 1)])),
            ),
            ("bigrec", made_stream(4, &one, Some(vec![(1 << 40, 1)]))),
        ]);
        // Index bytes themselves: padding, count, a non-minimal integer.
        let mut padbyte = made_xz(4, &one);
        let at = padbyte.len() - 12 - 4 - 1;
        padbyte[at] = 1;
        inputs.push(("indexpad", padbyte));
        // Blocks as short as their Check, or shorter: at `-vv` list.c reads
        // `Total Size - check size` header bytes, which is 0 (one per wrap
        // class: 8, 16, 32 and 64 bytes) or wraps to 1024; or a few bytes.
        for (check, unpadded) in [
            (4u8, 5u64),
            (5, 8),
            (6, 6),
            (7, 13),
            (9, 16),
            (10, 29),
            (12, 32),
            (13, 61),
            (15, 64),
            (10, 5),
            (15, 33),
            (4, 12),
            (1, 5),
            (0, 5),
        ] {
            let name: &'static str = Box::leak(format!("short{check}-{unpadded}").into_boxed_str());
            inputs.push((name, short_block(check, unpadded)));
        }
        let cases = every_form(&inputs);
        check("list_made_streams", &cases);
    }

    /// A Stream of one Block whose Index record says `unpadded` (so the
    /// Block takes `ceil4(unpadded)` bytes, filler here, before the Index):
    /// a Block too short to hold its own header and check.
    fn short_block(check: u8, unpadded: u64) -> Vec<u8> {
        let mut s = made_stream(check, &[], Some(vec![(unpadded, 1000)]));
        let total = ((unpadded + 3) & !3) as usize;
        s.splice(12..12, std::iter::repeat_n(0x55, total));
        s
    }

    /// Memory: `-M` below what the Indexes need (`Memory usage limit
    /// reached` and the figure needed, through two Streams), and the totals
    /// that overflow.
    #[test]
    fn list_memory_limits_and_overflow() {
        let l = || blk(vec![lzma2(22)]);
        let one = made_xz(4, &[l()]);
        let two = [made_xz(4, &[l()]), made_xz(4, &[l()])].concat();
        let many = made_xz(4, &vec![l(); 600]);
        let mut big = l();
        big.uncompressed = VLI_MAX - 1;
        let big = made_xz(4, &[big]);
        let mut cases = Vec::new();
        for (m, f) in [
            ("-M1", "one.xz"),
            ("-M8719", "one.xz"),
            ("-M8720", "one.xz"),
            ("-M9000", "two.xz"),
            ("-M17439", "two.xz"),
            ("-M17440", "two.xz"),
            ("-M17007", "many.xz"),
            ("-M2MiB", "many.xz"),
            ("--memlimit-decompress=1", "one.xz"),
            ("--memlimit-compress=1", "one.xz"),
        ] {
            for v in ["-l", "-lvv", "-ql"] {
                cases.push(list_case(
                    &[v, m, f],
                    vec![
                        ("one.xz", one.clone()),
                        ("two.xz", two.clone()),
                        ("many.xz", many.clone()),
                    ],
                ));
            }
        }
        for form in LIST_FORMS {
            for operands in [
                &["big.xz", "big.xz"][..],
                &["big.xz", "big.xz", "big.xz", "one.xz"],
                &["bigbig.xz"],
            ] {
                let mut a = form.to_vec();
                a.extend(operands);
                cases.push(list_case(
                    &a,
                    vec![
                        ("one.xz", one.clone()),
                        ("big.xz", big.clone()),
                        ("bigbig.xz", [big.clone(), big.clone()].concat()),
                    ],
                ));
            }
        }
        check("list_memory_limits_and_overflow", &cases);
    }

    /// Review Focus 3: the "Memory needed" figures of `-lvv` and
    /// `--robot -lvv` are the reference build's, on both tiers: every
    /// LZMA2 dictionary size a header can declare, behind each kind of
    /// filter, and across several files' totals.
    #[test]
    fn list_memory_needed_matches() {
        let mut files: Vec<(&'static str, Vec<u8>)> = Vec::new();
        for props in 0..=40u8 {
            let name: &'static str = Box::leak(format!("d{props}.xz").into_boxed_str());
            files.push((name, made_xz(4, &[blk(vec![lzma2(props)])])));
        }
        files.push(("x86.xz", made_xz(4, &[blk(vec![x86(), lzma2(30)])])));
        files.push((
            "delta.xz",
            made_xz(4, &[blk(vec![delta(7), lzma2(20)]), blk(vec![lzma2(26)])]),
        ));
        files.push((
            "chain.xz",
            made_xz(4, &[blk(vec![x86(), delta(2), (0x0A, vec![]), lzma2(12)])]),
        ));
        files.push(("p9.xz", reference_output(&["-9", "-T1"], &text())));
        files.push(("p0.xz", reference_output(&["-0"], &text())));
        let names: Vec<&'static str> = files.iter().map(|(n, _)| *n).collect();
        let mut cases = Vec::new();
        for form in [&["-lvv"][..], &["--robot", "-lvv"]] {
            for n in &names {
                let mut a = form.to_vec();
                a.push(n);
                cases.push(list_case(&a, files.clone()));
            }
            let mut a = form.to_vec();
            a.extend(names.iter().copied());
            cases.push(list_case(&a, files.clone()));
        }
        check("list_memory_needed_matches", &cases);
    }
}
