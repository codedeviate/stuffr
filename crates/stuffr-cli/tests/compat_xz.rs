//! The xz compatibility family against XZ Utils 5.8.4: stuffr invoked as
//! `xz`, `unxz`, `xzcat`, `lzma`, `unlzma` and `lzcat`, compared with the
//! reference through `compat_harness`, every case under `LC_ALL=C`.
//!
//! Part 1 (0.13.0 Task 5): the argument surface. Options refused and their
//! messages, the help texts, `--version`, `XZ_DEFAULTS`/`XZ_OPT`, the six
//! names, and the parse-time half of the suffix rules. The cases that run
//! the coder (every option accepted, each name over standard input, the
//! suffix rules met while processing a file) are written here too and
//! ignored until the coder arrives (Task 6); `--info-memory` was planned
//! for Task 8 but runs now.
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
        let out = Command::new(format!("{dir}/xz"))
            .args(["--robot", "--version"])
            .env_clear()
            .output()
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
        let mut child = Command::new(ref_xz())
            .arg("-c")
            .args(args)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let data = data.to_vec();
        let t = std::thread::spawn(move || stdin.write_all(&data));
        let out = child.wait_with_output().unwrap();
        t.join().unwrap().unwrap();
        assert!(out.status.success(), "reference xz -c {args:?} failed");
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
        let one = |c: &Case| -> bool {
            let Some(dir) = xz_dir() else { return false };
            let Some(mut r) = reference(dir, c) else {
                return false;
            };
            let mut s = stuffr_as(c);
            usage_line(&mut r.stdout, c.name);
            usage_line(&mut s.stdout, c.name);
            version_line(&mut r, &mut s);
            assert_same(c, &r, &s);
            true
        };
        run_group(group, cases, Skipped::none(), &one);
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
    /// and over standard input. Needs the coder.
    #[test]
    #[ignore = "Task 6"]
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
            &["-v", "-c", "a"],
            &["--verbose", "-k", "a"],
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
            &["-l", "a.xz"],
            &["--list", "a.xz"],
            &["-dkv", "a.xz"],
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
    /// ignored). Needs the coder.
    #[test]
    #[ignore = "Task 6"]
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

    /// Each name over standard input. Needs the coder.
    #[test]
    #[ignore = "Task 6"]
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
    /// a.foo` makes `a`. Needs the coder.
    #[test]
    #[ignore = "Task 6"]
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
}
