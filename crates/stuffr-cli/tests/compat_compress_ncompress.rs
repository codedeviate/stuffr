//! Differential tests: stuffr invoked as `compress` and `uncompress` with
//! `STUFFR_COMPRESS_FLAVOR=ncompress`, against ncompress 5.0
//! ([`ncompress_dir`](compat_harness::ncompress_dir)): Ubuntu's `5.0-1` on
//! Linux (`make compat-ubuntu`; `uncompress` is `/usr/bin/uncompress.real`
//! there), Homebrew's 5.0 on macOS.
//!
//! Every row comes from the measurement record of 0.18.0 Task 1
//! (`compress-measurements.md`: the surface table, the `-b` parse table,
//! the validity table) and is compared against the live reference: exit
//! code, standard error, standard output and the working directory
//! afterwards (bytes, modes, times). Compressed bytes are promised
//! identical wherever the reference's stream is valid, so nothing is
//! round-tripped; the one invalid stream (deviation N1) is asserted in
//! `deviations`.
//!
//! **Platforms (ruling E6).** The personality is Ubuntu's build on every
//! platform. On Linux the suite compares against that build and masks
//! nothing. On macOS Homebrew's build differs from Ubuntu's in exactly
//! three measured ways, and each is masked where it shows, with a comment:
//! symbolic-link operands (`symlink_operands`), the `-V` text
//! (`mask_homebrew`), and the corrupt-input debug line with the output
//! written before it (`mask_homebrew`).

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
#[test]
fn ncompress_is_a_reference_only_on_macos_and_linux() {
    println!("skipped: the ncompress suite needs ncompress 5.0 (Homebrew or apt)");
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod compat_harness;

/// Cases, fixtures and the comparison every group shares.
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod common {
    pub use super::compat_harness::*;
    use std::io::Write;
    use std::path::Path;
    use std::process::{Command, Stdio};

    /// stuffr's side runs as the ncompress personality whatever the
    /// platform default; the reference ignores the variable.
    pub const FLAVOR: (&str, &str) = ("STUFFR_COMPRESS_FLAVOR", "ncompress");

    pub fn case<'a>(name: &'a str, args: &[&'a str], files: Vec<(&'a str, Vec<u8>)>) -> Case<'a> {
        Case {
            name,
            args: args.to_vec(),
            files,
            stdin: None,
            tty_stdin: false,
            tty_stdout: false,
            tty_ctl: false,
            tty_signal: None,
            env: vec![FLAVOR],
            compare_output_bytes: true,
            expect_stdout_plain: None,
            setup: None,
            roundtrip: Roundtrip::Exact,
            tz: None,
            unzip_flavour: None,
        }
    }

    /// `case` with `stdin` piped in.
    pub fn piped<'a>(name: &'a str, args: &[&'a str], stdin: Vec<u8>) -> Case<'a> {
        let mut c = case(name, args, vec![]);
        c.stdin = Some(stdin);
        c
    }

    /// `c` with `setup` run in its directory before the program starts.
    pub fn set<'a>(mut c: Case<'a>, setup: fn(&Path)) -> Case<'a> {
        c.setup = Some(setup);
        c
    }

    /// `c` with standard input a terminal on which `typed` is typed (then
    /// end of file).
    pub fn at_tty<'a>(mut c: Case<'a>, typed: &[u8]) -> Case<'a> {
        c.tty_stdin = true;
        c.stdin = Some(typed.to_vec());
        c
    }

    /// The reference on `c`: `compress`, or `uncompress` under the name that
    /// decompresses (`uncompress.real` on Ubuntu). `None` without one.
    pub fn reference_run(c: &Case) -> Option<Run> {
        let dir = ncompress_dir()?;
        Some(run_program(&ncompress_exe(dir, c.name), c, false))
    }

    /// Whether the reference is Homebrew's build (macOS), which differs
    /// from Ubuntu's in the three ways the module doc lists.
    pub fn homebrew() -> bool {
        cfg!(target_os = "macos")
    }

    /// The masks of ruling E6 (macOS only; on Linux the reference is the
    /// build stuffr follows and nothing is masked).
    pub fn mask_homebrew(r: &mut Run, s: &mut Run) {
        if !homebrew() {
            return;
        }
        // Mask 1 of 3, the `-V` text: Homebrew's build is compiled with
        // `-DLSTAT` and stdio's 1024-byte `BUFSIZ`, so its compile-option
        // lines read `FAST, LSTAT, ` and `IBUFSIZ=1024, OBUFSIZ=1024`;
        // Ubuntu's (stuffr's) read `FAST, ` and `IBUFSIZ=8192,
        // OBUFSIZ=8192`. The two lines after `Compile options:` are masked
        // on both sides; every other line is compared.
        for run in [&mut *r, &mut *s] {
            if run.stdout.starts_with(b"Compress version: ") {
                let text = String::from_utf8_lossy(&run.stdout).into_owned();
                let mut lines: Vec<&str> = text.split('\n').collect();
                if let Some(at) = lines.iter().position(|l| *l == "Compile options:")
                    && lines.len() > at + 2
                {
                    lines[at + 1] = "<compile options>";
                    lines[at + 2] = "<buffer sizes>";
                }
                run.stdout = lines.join("\n").into_bytes();
            }
        }
        // Mask 2 of 3, the corrupt-input debug line: `insize:N posbits:N
        // inbuf:...` reports the input buffer's state, which depends on
        // IBUFSIZ (1024 on Homebrew, 8192 on Ubuntu), and the output that
        // reached standard output before the abort is whole OBUFSIZ pieces
        // (29 696 bytes on Homebrew, 24 576 on Ubuntu for the record's
        // concatenated stream). The line is masked on both sides. Both
        // detect the bad code at the same place, so stuffr's output must be
        // whole 8192-byte pieces, a prefix of Homebrew's whole 1024-byte
        // pieces, less than one 8192-byte piece shorter.
        let corrupt = |run: &Run| run.stderr.contains("uncompress: corrupt input\n");
        if corrupt(r) && corrupt(s) {
            for run in [&mut *r, &mut *s] {
                run.stderr = run
                    .stderr
                    .split_inclusive('\n')
                    .map(|l| {
                        if l.starts_with("insize:") {
                            "insize:<buffer state>\n"
                        } else {
                            l
                        }
                    })
                    .collect();
            }
            let (rn, sn) = (r.stdout.len(), s.stdout.len());
            if sn % 8192 == 0 && sn <= rn && rn - sn < 8192 && r.stdout[..sn] == s.stdout[..] {
                r.stdout.truncate(sn);
            }
        }
    }

    /// One row: the reference and stuffr on the same case, every
    /// difference reported. False when the reference is absent.
    pub fn compare(c: &Case) -> bool {
        let Some(mut r) = reference_run(c) else {
            return false;
        };
        let mut s = stuffr_as(c);
        mask_homebrew(&mut r, &mut s);
        assert_same(c, &r, &s);
        true
    }

    pub fn group(name: &str, cases: &[Case]) {
        run_group(name, cases, Skipped::none(), &compare);
    }

    /// `exe args` as a filter: `input` on standard input; exit code,
    /// standard output, standard error.
    pub fn filter(exe: &Path, args: &[&str], input: &[u8]) -> (i32, Vec<u8>, String) {
        filter_as(exe, FLAVOR.1, args, input)
    }

    /// [`filter`] with `STUFFR_COMPRESS_FLAVOR` set to `flavour`.
    fn filter_as(exe: &Path, flavour: &str, args: &[&str], input: &[u8]) -> (i32, Vec<u8>, String) {
        let mut cmd = Command::new(exe);
        cmd.args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C")
            .env(FLAVOR.0, flavour)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = spawn(&mut cmd).expect("spawn the filter");
        let mut si = child.stdin.take().unwrap();
        let data = input.to_vec();
        let writer = std::thread::spawn(move || {
            let _ = si.write_all(&data);
        });
        let out = child.wait_with_output().unwrap();
        writer.join().unwrap();
        (
            out.status.code().unwrap_or(-1),
            out.stdout,
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    /// ncompress's `compress` as a filter (exit, standard output, standard
    /// error); the directory must exist.
    pub fn nc(dir: &str, args: &[&str], input: &[u8]) -> (i32, Vec<u8>, String) {
        filter(&ncompress_exe(dir, "compress"), args, input)
    }

    /// stuffr as `compress` (ncompress personality) as a filter.
    pub fn ours(args: &[&str], input: &[u8]) -> (i32, Vec<u8>, String) {
        ours_as("ncompress", args, input)
    }

    /// stuffr as `compress` in its Apple personality, as a filter.
    pub fn ours_apple(args: &[&str], input: &[u8]) -> (i32, Vec<u8>, String) {
        ours_as("apple", args, input)
    }

    fn ours_as(flavour: &str, args: &[&str], input: &[u8]) -> (i32, Vec<u8>, String) {
        let d = ScratchDir::unique("ncompress-bin");
        std::fs::create_dir_all(&*d).unwrap();
        let link = d.join("compress");
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stuffr"), &link).unwrap();
        filter_as(&link, flavour, args, input)
    }

    /// The inputs of the record: `f` (text, compresses), `a` and `b`
    /// (text), `r` (random, grows), `s` (300 bytes of text: never fills the
    /// 9-bit table), and ncompress's `.Z` of `f`, `a`, `b`.
    pub struct Fx {
        pub dir: &'static str,
        pub f: Vec<u8>,
        pub a: Vec<u8>,
        pub b: Vec<u8>,
        pub r: Vec<u8>,
        pub s: Vec<u8>,
        pub fz: Vec<u8>,
        pub az: Vec<u8>,
        pub bz: Vec<u8>,
    }

    /// [`Fx`], or `None` (after `ncompress_dir`'s note) without the
    /// reference.
    pub fn fixtures() -> Option<Fx> {
        let dir = ncompress_dir()?;
        let f = text(50_000, 0x0018_0001);
        let a = text(30_000, 0x0018_0002);
        let b = text(30_000, 0x0018_0003);
        let r = random(4096, 0x0018_0004);
        let s = text(300, 0x0018_0005);
        let z = |d: &[u8]| {
            let (code, out, err) = nc(dir, &["-c"], d);
            assert_eq!(code, 0, "{err}");
            out
        };
        let (fz, az, bz) = (z(&f), z(&a), z(&b));
        assert!(fz.starts_with(&[0x1f, 0x9d, 0x90]), "ncompress's .Z of f");
        Some(Fx {
            dir,
            f,
            a,
            b,
            r,
            s,
            fz,
            az,
            bz,
        })
    }

    /// A name only a test needs once, kept for the run.
    pub fn leak(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod differential {
    use super::common::*;
    use std::path::Path;

    fn sym_fz_to_f(d: &Path) {
        std::os::unix::fs::symlink("f", d.join("f.Z")).unwrap();
    }
    fn hard_fz_to_f(d: &Path) {
        std::fs::hard_link(d.join("f"), d.join("f.Z")).unwrap();
    }
    fn hard_g_to_f(d: &Path) {
        std::fs::hard_link(d.join("f"), d.join("g")).unwrap();
    }
    fn sym_f_to_fz(d: &Path) {
        std::os::unix::fs::symlink("f.Z", d.join("f")).unwrap();
    }
    fn hard_f_to_fz(d: &Path) {
        std::fs::hard_link(d.join("f.Z"), d.join("f")).unwrap();
    }
    fn dangling_fz(d: &Path) {
        std::os::unix::fs::symlink("t", d.join("f.Z")).unwrap();
    }
    fn dangling_f(d: &Path) {
        std::os::unix::fs::symlink("t", d.join("f")).unwrap();
    }
    fn mkdir_dir(d: &Path) {
        std::fs::create_dir(d.join("dir")).unwrap();
    }
    fn mkdir_fz(d: &Path) {
        std::fs::create_dir(d.join("f.Z")).unwrap();
    }
    fn mode(p: &Path, m: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    }
    fn f_000(d: &Path) {
        mode(&d.join("f"), 0o000);
    }
    fn fz_000(d: &Path) {
        mode(&d.join("f.Z"), 0o000);
    }
    fn ro_555(d: &Path) {
        mode(&d.join("ro"), 0o555);
    }
    fn f_640(d: &Path) {
        mode(&d.join("f"), 0o640);
    }
    fn f_4755(d: &Path) {
        mode(&d.join("f"), 0o4755);
    }
    fn fz_600(d: &Path) {
        mode(&d.join("f.Z"), 0o600);
    }

    /// Flags anywhere on the line, clusters, `--` and a lone `-`; `-h` and
    /// `-V` print to standard output and exit 0 at once; an unknown flag is
    /// `Unknown flag: 'x'; ` and the usage, exit 1; `-n`, `-s`, `-q`, `-r`,
    /// `-k`, `-F` are accepted. (`uncompress`'s usage rows are
    /// `deviations::n2_*` on Linux, where Ubuntu's names `uncompress.real`.)
    #[test]
    fn flags_and_usage_match_ncompress() {
        let Some(x) = fixtures() else { return };
        let mut cases = Vec::new();
        for flag in [
            "-x",
            "-h",
            "--help",
            "-V",
            "--version",
            "-q",
            "-s",
            "-k",
            "-n",
            "-C",
            "-F",
            "-r",
            "-R",
            "-?",
            "-B",
            "-cx",
            "-vq",
            "-qv",
            "-Vx",
            "-xV",
            "-hx",
        ] {
            cases.push(piped("compress", &[flag], x.f.clone()));
        }
        for flag in ["-V", "-r", "--", "-q", "-k"] {
            cases.push(piped("uncompress", &[flag], x.fz.clone()));
        }
        if homebrew() {
            // Homebrew's `uncompress` names itself `uncompress`, as stuffr's.
            for flag in ["-x", "-h", "-b"] {
                cases.push(piped("uncompress", &[flag], x.fz.clone()));
            }
        }
        // `-d` before a bad option: the usage still names the program.
        cases.push(piped("compress", &["-d", "-x"], x.fz.clone()));
        cases.push(case("compress", &["-k", "f"], vec![("f", x.f.clone())]));
        cases.push(case("compress", &["-q", "r"], vec![("r", x.r.clone())]));
        cases.push(case("compress", &["--", "-f"], vec![("-f", x.f.clone())]));
        cases.push(case(
            "compress",
            &["--", "-f", "--", "a"],
            vec![("-f", x.f.clone()), ("a", x.a.clone())],
        ));
        cases.push(piped("compress", &["-"], x.f.clone()));
        cases.push(piped("uncompress", &["-"], x.fz.clone()));
        cases.push(case("compress", &["-V", "f"], vec![("f", x.f.clone())]));
        cases.push(case("compress", &["f", "-V"], vec![("f", x.f.clone())]));
        cases.push(case("compress", &["-cv", "f"], vec![("f", x.f.clone())]));
        cases.push(case(
            "compress",
            &["-vc", "--", "f"],
            vec![("f", x.f.clone())],
        ));
        // Flags anywhere: `-c` after the operand still applies.
        cases.push(case("compress", &["f", "-c"], vec![("f", x.f.clone())]));
        cases.push(case("compress", &["f", "-x"], vec![("f", x.f.clone())]));
        cases.push(case(
            "compress",
            &["-k", "-v", "f"],
            vec![("f", x.f.clone())],
        ));
        cases.push(case(
            "uncompress",
            &["-k", "f.Z"],
            vec![("f.Z", x.fz.clone())],
        ));
        cases.push(case(
            "compress",
            &["-d", "-k", "f.Z"],
            vec![("f.Z", x.fz.clone())],
        ));
        group("flags", &cases);
    }

    /// Compressing and decompressing files, standard input and output.
    #[test]
    fn basics_match_ncompress() {
        let Some(x) = fixtures() else { return };
        let f = || vec![("f", x.f.clone())];
        let fz = || vec![("f.Z", x.fz.clone())];
        let ab = || vec![("a", x.a.clone()), ("b", x.b.clone())];
        let abz = || vec![("a.Z", x.az.clone()), ("b.Z", x.bz.clone())];
        let cases = vec![
            case("compress", &["f"], f()),
            case("compress", &["-v", "f"], f()),
            piped("compress", &["-v"], x.f.clone()),
            piped("compress", &[], x.f.clone()),
            case("compress", &["-c", "f"], f()),
            case("compress", &["-cv", "f"], f()),
            // Two streams back to back, as ncompress writes them.
            case("compress", &["-c", "a", "b"], ab()),
            case("compress", &["a", "b"], ab()),
            case("compress", &["-v", "a", "b"], ab()),
            case("compress", &["-d", "f.Z"], fz()),
            case("compress", &["-dc", "f.Z"], fz()),
            case("compress", &["-dv", "f.Z"], fz()),
            case("uncompress", &["f.Z"], fz()),
            case("uncompress", &["-v", "f.Z"], fz()),
            piped("uncompress", &[], x.fz.clone()),
            piped("uncompress", &["-v"], x.fz.clone()),
            piped("uncompress", &["-c"], x.fz.clone()),
            case("uncompress", &["-c", "f.Z"], fz()),
            case("uncompress", &["-c", "a.Z", "b.Z"], abz()),
            case("uncompress", &["a.Z", "b.Z"], abz()),
            case("uncompress", &["-v", "a.Z", "b.Z"], abz()),
            case("uncompress", &["f"], fz()),
            case(
                "uncompress",
                &["f"],
                vec![("f", x.f.clone()), ("f.Z", x.fz.clone())],
            ),
            case(
                "uncompress",
                &["-f", "f"],
                vec![("f", x.f.clone()), ("f.Z", x.fz.clone())],
            ),
            case("uncompress", &["-c", "f"], fz()),
            case("compress", &["-c", "-b", "12", "f"], f()),
            case("compress", &["-b", "12", "f"], f()),
            case("compress", &["-b12", "-v", "f"], f()),
        ];
        group("basics", &cases);
    }

    /// Review Focus 1 without a question: an existing output is refused
    /// (`NAME already exists.` and `NAME not overwritten`, exit 1) unless
    /// `-f`, which removes it first; `-c` never looks. With standard input
    /// a terminal ncompress asks on standard error and reads the answer
    /// there; only `y` as the first byte overwrites.
    #[test]
    fn existing_outputs_match_ncompress() {
        let Some(x) = fixtures() else { return };
        let both = || vec![("f", x.f.clone()), ("f.Z", x.fz.clone())];
        let cases = vec![
            case("compress", &["f"], both()),
            case("compress", &["-v", "f"], both()),
            case("compress", &["-f", "f"], both()),
            case("compress", &["-c", "f"], both()),
            case("uncompress", &["f.Z"], both()),
            case("uncompress", &["-v", "f.Z"], both()),
            case("uncompress", &["-f", "f.Z"], both()),
            case("uncompress", &["-c", "f.Z"], both()),
            set(
                case("compress", &["-f", "f"], vec![("f", x.f.clone())]),
                mkdir_fz,
            ),
            set(case("compress", &["f"], vec![("f", x.f.clone())]), mkdir_fz),
            set(
                case("compress", &["f"], vec![("f", x.f.clone())]),
                dangling_fz,
            ),
            set(
                case("compress", &["-f", "f"], vec![("f", x.f.clone())]),
                dangling_fz,
            ),
            set(
                case("uncompress", &["f.Z"], vec![("f.Z", x.fz.clone())]),
                dangling_f,
            ),
            at_tty(case("compress", &["f"], both()), b"y\n"),
            at_tty(case("compress", &["f"], both()), b"n\n"),
            at_tty(case("compress", &["f"], both()), b"yes please\n"),
            at_tty(case("compress", &["f"], both()), b"\n"),
            at_tty(case("compress", &["f"], both()), b"Y\n"),
            at_tty(case("compress", &["-v", "f"], both()), b"y\n"),
            at_tty(case("uncompress", &["f.Z"], both()), b"y\n"),
            at_tty(case("uncompress", &["f.Z"], both()), b"n\n"),
            at_tty(case("uncompress", &["f.Z"], both()), b"\n"),
            at_tty(
                case(
                    "compress",
                    &["a", "b"],
                    vec![
                        ("a", x.a.clone()),
                        ("a.Z", x.az.clone()),
                        ("b", x.b.clone()),
                        ("b.Z", x.bz.clone()),
                    ],
                ),
                b"n\ny\n",
            ),
        ];
        group("existing outputs", &cases);
    }

    /// Review Focus 1, a question answered by the end of the input: `read`
    /// returns 0 and ncompress `perror`s `stdin` with whatever `errno` is.
    #[test]
    fn an_unanswered_question_matches_ncompress() {
        let Some(x) = fixtures() else { return };
        let both = || vec![("f", x.f.clone()), ("f.Z", x.fz.clone())];
        let cases = vec![
            at_tty(case("compress", &["f"], both()), b""),
            at_tty(case("uncompress", &["f.Z"], both()), b""),
            // A first byte, then the end of the input before the newline.
            at_tty(case("compress", &["f"], both()), b"y"),
        ];
        group("unanswered question", &cases);
    }

    /// Review Focus 4: neither tool refuses a terminal. Compressed data is
    /// written to a terminal standard output, and a terminal standard
    /// input is read.
    #[test]
    fn terminals_match_ncompress() {
        let Some(x) = fixtures() else { return };
        let tty_out = |mut c: Case<'static>| {
            c.tty_stdout = true;
            c
        };
        let tty_in = |mut c: Case<'static>| {
            c.tty_stdin = true;
            c
        };
        let cases = vec![
            tty_out(piped("compress", &[], x.f.clone())),
            tty_out(piped("uncompress", &[], x.fz.clone())),
            tty_out(case("compress", &["-c", "f"], vec![("f", x.f.clone())])),
            tty_out(case(
                "uncompress",
                &["-c", "f.Z"],
                vec![("f.Z", x.fz.clone())],
            )),
            tty_in(case("compress", &[], vec![])),
            tty_in(case("uncompress", &[], vec![])),
            tty_in(case("compress", &["-c"], vec![])),
            tty_in(case("compress", &["-v"], vec![])),
            piped("compress", &["-c", "-"], x.a.clone()),
        ];
        run_group("terminals", &cases, Skipped::none(), &|c: &Case| {
            let Some(mut r) = reference_run(c) else {
                return false;
            };
            let mut s = stuffr_as(c);
            if c.tty_stdout {
                r.stdout = without_terminal_crs(&r.stdout);
                s.stdout = without_terminal_crs(&s.stdout);
            }
            assert_same(c, &r, &s);
            true
        });
    }

    /// What a terminal standard output shows, without the carriage returns
    /// its driver puts before each newline (ONLCR), which a busy macOS
    /// driver sometimes repeats: the program's bytes are compared exactly.
    /// Not a Homebrew mask: applied to both sides on every platform.
    fn without_terminal_crs(b: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(b.len());
        for &c in b {
            if c == b'\n' {
                while out.last() == Some(&b'\r') {
                    out.pop();
                }
            }
            out.push(c);
        }
        out
    }

    /// Review Focus 2: an output not smaller than its input is removed,
    /// exit 2 (`No compression -- NAME unchanged` only under `-v`), unless
    /// `-f`; standard input gives exit 2 too; `-c` on a file is never
    /// checked; an empty input is a 3-byte header.
    #[test]
    fn no_saving_matches_ncompress() {
        let Some(x) = fixtures() else { return };
        let r = || vec![("r", x.r.clone())];
        let e = || vec![("e", Vec::new())];
        let one = || vec![("one", b"x".to_vec())];
        let cases = vec![
            case("compress", &["r"], r()),
            case("compress", &["-v", "r"], r()),
            case("compress", &["-f", "r"], r()),
            case("compress", &["-f", "-v", "r"], r()),
            piped("compress", &[], x.r.clone()),
            piped("compress", &["-v"], x.r.clone()),
            piped("compress", &["-f"], x.r.clone()),
            piped("compress", &["-c"], x.r.clone()),
            case("compress", &["-c", "r"], r()),
            case("compress", &["e"], e()),
            case("compress", &["-v", "e"], e()),
            case("compress", &["-f", "e"], e()),
            case("compress", &["-f", "-v", "e"], e()),
            case("compress", &["-c", "e"], e()),
            piped("compress", &[], Vec::new()),
            piped("compress", &["-v"], Vec::new()),
            case("compress", &["-f", "-v", "one"], one()),
            case("compress", &["one"], one()),
            case(
                "compress",
                &["r", "f"],
                vec![("r", x.r.clone()), ("f", x.f.clone())],
            ),
            case(
                "compress",
                &["f", "r"],
                vec![("r", x.r.clone()), ("f", x.f.clone())],
            ),
            case(
                "compress",
                &["-v", "r", "f"],
                vec![("r", x.r.clone()), ("f", x.f.clone())],
            ),
            case(
                "uncompress",
                &["-v", "r.Z"],
                vec![("r.Z", nc(x.dir, &["-c"], &x.r).1)],
            ),
        ];
        group("no saving", &cases);
    }

    /// Links (not as operands; those are `symlink_operands`): ncompress
    /// removes an existing output before creating its own, so a link in the
    /// output's place never costs the input, and a compress input with
    /// other hard links is refused without `-f`.
    #[test]
    fn links_match_ncompress() {
        let Some(x) = fixtures() else { return };
        let f = || vec![("f", x.f.clone())];
        let fz = || vec![("f.Z", x.fz.clone())];
        let cases = vec![
            set(case("compress", &["f"], f()), sym_fz_to_f),
            set(case("compress", &["-f", "f"], f()), sym_fz_to_f),
            set(case("compress", &["f"], f()), hard_fz_to_f),
            set(case("compress", &["-f", "f"], f()), hard_fz_to_f),
            set(case("compress", &["f"], f()), hard_g_to_f),
            set(case("compress", &["-v", "f"], f()), hard_g_to_f),
            set(case("compress", &["-f", "f"], f()), hard_g_to_f),
            set(case("compress", &["-c", "f"], f()), hard_g_to_f),
            set(case("uncompress", &["f.Z"], fz()), sym_f_to_fz),
            set(case("uncompress", &["-f", "f.Z"], fz()), sym_f_to_fz),
            set(case("uncompress", &["-f", "f.Z"], fz()), hard_f_to_fz),
            set(case("uncompress", &["f.Z"], fz()), hard_f_to_fz),
            set(case("uncompress", &["-c", "f.Z"], fz()), sym_f_to_fz),
        ];
        group("links", &cases);
    }

    /// Missing operands, directories, names with and without `.Z`, devices,
    /// `-r`.
    #[test]
    fn odd_operands_match_ncompress() {
        let Some(x) = fixtures() else { return };
        let long = leak("n".repeat(1100));
        let long_z = leak(format!("{}.Z", "n".repeat(1100)));
        let tree = || {
            vec![
                ("dir/a", x.a.clone()),
                ("dir/sub/b", x.b.clone()),
                ("dir/c.Z", x.az.clone()),
            ]
        };
        let ztree = || {
            vec![
                ("dir/a.Z", x.az.clone()),
                ("dir/sub/b.Z", x.bz.clone()),
                ("dir/c", x.f.clone()),
            ]
        };
        let cases = vec![
            case("compress", &["nope"], vec![]),
            case("compress", &["-v", "nope"], vec![]),
            case("uncompress", &["nope"], vec![]),
            case("uncompress", &["nope.Z"], vec![]),
            case("uncompress", &["-c", "nope"], vec![]),
            case("uncompress", &["f"], vec![("f", x.f.clone())]),
            case("uncompress", &["-v", "f"], vec![("f", x.f.clone())]),
            case("uncompress", &["-c", "f"], vec![("f", x.f.clone())]),
            case("compress", &["f.Z"], vec![("f.Z", x.fz.clone())]),
            case("compress", &["-c", "f.Z"], vec![("f.Z", x.fz.clone())]),
            case(
                "compress",
                &["f.Z", "a"],
                vec![("f.Z", x.fz.clone()), ("a", x.a.clone())],
            ),
            case("compress", &["a.Z.Z"], vec![]),
            case("compress", &["x.Zz"], vec![("x.Zz", x.a.clone())]),
            case("uncompress", &["x.z"], vec![("x.z", x.az.clone())]),
            set(case("compress", &["dir"], vec![]), mkdir_dir),
            set(case("compress", &["-v", "dir"], vec![]), mkdir_dir),
            set(case("compress", &["-c", "dir"], vec![]), mkdir_dir),
            set(case("compress", &["-r", "dir"], vec![]), mkdir_dir),
            set(case("uncompress", &["dir"], vec![]), mkdir_dir),
            set(case("uncompress", &["-r", "dir"], vec![]), mkdir_dir),
            case("compress", &["-r", "dir"], tree()),
            case("compress", &["-r", "dir/sub"], tree()),
            case("compress", &["-rv", "dir/sub"], tree()),
            case("compress", &["-r", "dir/"], tree()),
            case("uncompress", &["-r", "dir"], ztree()),
            case("uncompress", &["-rv", "dir/sub"], ztree()),
            case("uncompress", &["-rc", "dir/sub"], ztree()),
            case("compress", &["-c", "/dev/null"], vec![]),
            case("compress", &["/dev/null"], vec![]),
            case("uncompress", &["-c", "/dev/null"], vec![]),
            case("uncompress", &["/dev/null"], vec![]),
            case("uncompress", &[".Z"], vec![(".Z", x.fz.clone())]),
            case("compress", &[""], vec![]),
            case("uncompress", &[""], vec![]),
            case("compress", &[long], vec![]),
            case("uncompress", &[long], vec![]),
            case("uncompress", &[long_z], vec![]),
        ];
        group("odd operands", &cases);
    }

    /// Review Focus 3: a non-`.Z`, cut-short, damaged or odd `.Z` given to
    /// `uncompress`. The `-f` cases where ncompress deletes the input are
    /// `deviations::n4_*`.
    #[test]
    fn bad_input_matches_ncompress() {
        let Some(x) = fixtures() else { return };
        let half = x.fz[..x.fz.len() / 2].to_vec();
        let mut b17 = x.fz.clone();
        b17[2] = 0x91;
        let mut junk = x.fz.clone();
        junk.extend_from_slice(&[0xff, 0xff, 0xff]);
        let mut cat = x.az.clone();
        cat.extend_from_slice(&x.bz);
        let mut noblock = x.fz.clone();
        noblock[2] &= 0x7f;
        let mut flip = x.fz.clone();
        flip[100] ^= 0xff;
        // The first code past 255: `oldcode:-1 code:511`.
        let first_wide = vec![0x1f, 0x9d, 0x90, 0xff, 0x03, 0x00];
        // A code past the next free entry right after the first.
        let second_wide = vec![0x1f, 0x9d, 0x90, 0x41, 0xfe, 0x07, 0x00];
        let hdr = vec![0x1f, 0x9d, 0x90];
        // Apple's `-b 8` output (a header of 8 bits and 9-bit literals), as
        // stuffr's Apple personality writes it byte for byte (Task 2):
        // ncompress's decoder reads it (ruling E1).
        let b8 = {
            let d = ScratchDir::unique("ncompress-b8");
            std::fs::create_dir_all(&*d).unwrap();
            let link = d.join("compress");
            std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stuffr"), &link).unwrap();
            let mut cmd = std::process::Command::new(&link);
            cmd.args(["-b", "8"])
                .env_clear()
                .env("STUFFR_COMPRESS_FLAVOR", "apple")
                .stdin(std::process::Stdio::piped());
            let mut child = spawn(cmd.stdout(std::process::Stdio::piped())).unwrap();
            {
                use std::io::Write;
                child.stdin.take().unwrap().write_all(&x.a).unwrap();
            }
            let out = child.wait_with_output().unwrap();
            assert!(
                out.status.success(),
                "stuffr compress -b 8: {:?}",
                out.status
            );
            assert_eq!(out.stdout[2], 0x88);
            out.stdout
        };
        let cases = vec![
            case(
                "uncompress",
                &["bad.Z"],
                vec![("bad", x.f.clone()), ("bad.Z", x.f.clone())],
            ),
            piped("uncompress", &[], x.f.clone()),
            case(
                "uncompress",
                &["-c", "bad.Z"],
                vec![("bad", x.f.clone()), ("bad.Z", x.f.clone())],
            ),
            case("uncompress", &["bad.Z"], vec![("bad.Z", x.f.clone())]),
            case("uncompress", &["-v", "bad.Z"], vec![("bad.Z", x.f.clone())]),
            case("uncompress", &["trunc.Z"], vec![("trunc.Z", half.clone())]),
            case(
                "uncompress",
                &["-c", "trunc.Z"],
                vec![("trunc.Z", half.clone())],
            ),
            piped("uncompress", &[], half.clone()),
            piped("uncompress", &[], x.fz[..x.fz.len() - 1].to_vec()),
            piped("uncompress", &[], vec![0x1f, 0x9d]),
            piped("uncompress", &[], vec![0x1f]),
            piped("uncompress", &[], vec![0x1f, 0x9d, 0x90, 0x41]),
            case("uncompress", &["two.Z"], vec![("two.Z", vec![0x1f, 0x9d])]),
            case("uncompress", &["e.Z"], vec![("e.Z", Vec::new())]),
            case("uncompress", &["-v", "e.Z"], vec![("e.Z", Vec::new())]),
            // Not a deviation: a 0-byte `.Z` becomes a 0-byte output and
            // nothing is lost.
            case("uncompress", &["-f", "e.Z"], vec![("e.Z", Vec::new())]),
            case("uncompress", &["-c", "e.Z"], vec![("e.Z", Vec::new())]),
            piped("uncompress", &[], Vec::new()),
            case("uncompress", &["hdr.Z"], vec![("hdr.Z", hdr.clone())]),
            case("uncompress", &["-f", "hdr.Z"], vec![("hdr.Z", hdr.clone())]),
            case("uncompress", &["-c", "hdr.Z"], vec![("hdr.Z", hdr.clone())]),
            piped("uncompress", &[], hdr.clone()),
            case("uncompress", &["b17.Z"], vec![("b17.Z", b17.clone())]),
            case("uncompress", &["-c", "b17.Z"], vec![("b17.Z", b17.clone())]),
            piped("uncompress", &[], b17.clone()),
            case("uncompress", &["junk.Z"], vec![("junk.Z", junk.clone())]),
            case(
                "uncompress",
                &["-c", "junk.Z"],
                vec![("junk.Z", junk.clone())],
            ),
            case(
                "uncompress",
                &["-f", "junk.Z"],
                vec![("junk.Z", junk.clone())],
            ),
            case("uncompress", &["cat.Z"], vec![("cat.Z", cat.clone())]),
            case("uncompress", &["-c", "cat.Z"], vec![("cat.Z", cat.clone())]),
            case(
                "uncompress",
                &["-c", "noblock.Z"],
                vec![("noblock.Z", noblock.clone())],
            ),
            piped("uncompress", &[], flip.clone()),
            piped("uncompress", &[], first_wide.clone()),
            case("uncompress", &["w.Z"], vec![("w.Z", first_wide.clone())]),
            piped("uncompress", &[], second_wide.clone()),
            case("uncompress", &["w2.Z"], vec![("w2.Z", second_wide.clone())]),
            piped("uncompress", &[], b8.clone()),
            // Several operands, a corrupt one in the middle: the run stops
            // there (`abort_compress` exits).
            case(
                "uncompress",
                &["a.Z", "w.Z", "b.Z"],
                vec![
                    ("a.Z", x.az.clone()),
                    ("w.Z", first_wide.clone()),
                    ("b.Z", x.bz.clone()),
                ],
            ),
        ];
        group("bad input", &cases);
    }

    /// Several operands, one failing: the run goes on, and the exit code is
    /// the last one set (an error 1, "no saving" 2; success lowers neither).
    #[test]
    fn several_operands_match_ncompress() {
        let Some(x) = fixtures() else { return };
        let three = || {
            vec![
                ("a.Z", x.az.clone()),
                ("b.Z", x.bz.clone()),
                ("bad.Z", x.f.clone()),
            ]
        };
        let mut with_bad = three();
        with_bad.push(("bad", x.f.clone()));
        let mut c_with_bad = three();
        c_with_bad.push(("bad", x.f.clone()));
        let fr = || vec![("f", x.f.clone()), ("r", x.r.clone())];
        let cases = vec![
            case("uncompress", &["a.Z", "bad.Z", "b.Z"], three()),
            case("uncompress", &["a.Z", "bad.Z", "b.Z"], with_bad),
            case("uncompress", &["-c", "a.Z", "bad.Z", "b.Z"], c_with_bad),
            case(
                "compress",
                &["a", "nope", "b"],
                vec![("a", x.a.clone()), ("b", x.b.clone())],
            ),
            case(
                "compress",
                &["-v", "a", "nope", "b"],
                vec![("a", x.a.clone()), ("b", x.b.clone())],
            ),
            case(
                "uncompress",
                &["a.Z", "nope.Z", "b.Z"],
                vec![("a.Z", x.az.clone()), ("b.Z", x.bz.clone())],
            ),
            case("compress", &["r", "nope"], fr()),
            case("compress", &["nope", "r"], fr()),
            case("compress", &["-v", "f", "r", "nope"], fr()),
            case("compress", &["-v", "r", "f"], fr()),
            case("compress", &["r", "f"], fr()),
            case("compress", &["f", "r"], fr()),
        ];
        group("several operands", &cases);
    }

    /// Permission errors, and the input's mode on the output.
    #[test]
    fn permissions_match_ncompress() {
        let Some(x) = fixtures() else { return };
        let cases = vec![
            set(case("compress", &["f"], vec![("f", x.f.clone())]), f_000),
            set(
                case("uncompress", &["f.Z"], vec![("f.Z", x.fz.clone())]),
                fz_000,
            ),
            set(
                case("compress", &["ro/f"], vec![("ro/f", x.f.clone())]),
                ro_555,
            ),
            set(
                case("uncompress", &["ro/g.Z"], vec![("ro/g.Z", x.fz.clone())]),
                ro_555,
            ),
            set(case("compress", &["f"], vec![("f", x.f.clone())]), f_640),
            set(case("compress", &["f"], vec![("f", x.f.clone())]), f_4755),
            set(
                case("uncompress", &["f.Z"], vec![("f.Z", x.fz.clone())]),
                fz_600,
            ),
        ];
        group("permissions", &cases);
    }

    /// The `-b` parse table: `atoi`, then clamped to 9..=16; a missing value
    /// is `Missing maxbits` and the usage, exit 1, wherever it is on the
    /// line; `uncompress` ignores `-b`. Values that clamp to 9 write the
    /// stream of deviation N1, so they are compared here on an input that
    /// never fills the 9-bit table (`s`, 300 bytes), where the reference's
    /// stream is still valid, and on a large one in `deviations`.
    #[test]
    fn bit_counts_parse_as_ncompress() {
        let Some(x) = fixtures() else { return };
        let mut cases = Vec::new();
        for v in ["12", "16", "17", "100", "12x", " 12", "+12", "4294967308"] {
            cases.push(piped("compress", &["-b", v], x.f.clone()));
        }
        for v in [
            "-1",
            "0",
            "1",
            "7",
            "8",
            "9",
            "abc",
            "",
            "99999999999999999999",
            "-99999999999999999999",
        ] {
            cases.push(piped("compress", &["-b", v], x.s.clone()));
        }
        for a in ["-b12", "-b17", "-cb12", "-b12c"] {
            cases.push(piped("compress", &[a], x.f.clone()));
        }
        for a in ["-b9", "-babc", "-b-1", "-b0", "-bv"] {
            cases.push(piped("compress", &[a], x.s.clone()));
        }
        cases.push(piped("compress", &["-b"], x.f.clone()));
        cases.push(piped("compress", &["-c", "-b"], x.f.clone()));
        cases.push(piped("compress", &["-b", "9", "-b", "12"], x.f.clone()));
        cases.push(piped("compress", &["-b", "12", "-b", "9"], x.s.clone()));
        cases.push(piped("compress", &["-b", "-v"], x.s.clone()));
        cases.push(piped("compress", &["-b", "--"], x.s.clone()));
        cases.push(case("compress", &["f", "-b"], vec![("f", x.f.clone())]));
        cases.push(case(
            "compress",
            &["-b", "17", "f"],
            vec![("f", x.f.clone())],
        ));
        cases.push(case(
            "compress",
            &["-b", "-1", "s"],
            vec![("s", x.s.clone())],
        ));
        cases.push(case("compress", &["-b", "17", "nope"], vec![]));
        for v in ["17", "9", "abc"] {
            cases.push(piped("uncompress", &["-b", v], x.fz.clone()));
        }
        cases.push(case(
            "uncompress",
            &["-b", "17", "f.Z"],
            vec![("f.Z", x.fz.clone())],
        ));
        group("bit counts", &cases);
    }

    /// The validity table: at every `-b` from 10 to 16 ncompress's stream
    /// is valid, so its bytes are promised, on text, random and all-zero
    /// input, large enough to fill the table and reach the ratio checks and
    /// their CLEAR codes. At `-b 9` they are promised only up to the point
    /// the table fills (deviation N1), so `-b 9` rows here are short.
    #[test]
    fn every_bit_count_writes_ncompress_bytes() {
        let Some(x) = fixtures() else { return };
        let inputs = [
            text(1 << 20, 0x0018_0010),
            random(1 << 20, 0x0018_0011),
            vec![0u8; 1 << 20],
        ];
        let mut cases = Vec::new();
        for bits in ["10", "11", "12", "13", "14", "15", "16"] {
            for input in &inputs {
                cases.push(piped("compress", &["-b", bits], input.clone()));
            }
        }
        cases.push(piped("compress", &["-b", "9"], x.s.clone()));
        cases.push(piped("compress", &["-b", "9"], vec![0u8; 2000]));
        cases.push(piped("compress", &["-b", "9"], random(200, 0x0018_0012)));
        // And a file, so the output's name, mode and times are compared.
        cases.push(case(
            "compress",
            &["-b", "11", "t"],
            vec![("t", inputs[0].clone())],
        ));
        // Every stream decodes as ncompress decodes it.
        for bits in ["10", "13", "16"] {
            for input in &inputs {
                let (_, z, _) = nc(x.dir, &["-b", bits], input);
                cases.push(piped("uncompress", &[], z));
            }
        }
        group("every bit count", &cases);
    }

    /// Mask 3 of 3 (ruling E6), symbolic links as operands. Ubuntu builds
    /// ncompress without `-DLSTAT` (Debian's `fix-softlinks.patch`), so a
    /// link operand is followed: `compress l` writes `l.Z` and removes the
    /// link, exit 0. Homebrew's build has `-DLSTAT` and refuses it (`l is
    /// not a directory or a regular file - ignored`, exit 1). On Linux these
    /// rows are compared like any other; on macOS the reference's refusal is
    /// asserted as measured, and stuffr's answer as Ubuntu's.
    #[test]
    fn symlink_operands() {
        let Some(x) = fixtures() else { return };
        fn sym_l_to_f(d: &Path) {
            std::os::unix::fs::symlink("f", d.join("l")).unwrap();
        }
        fn sym_lz_to_fz(d: &Path) {
            std::os::unix::fs::symlink("f.Z", d.join("l.Z")).unwrap();
        }
        fn sym_dir(d: &Path) {
            std::os::unix::fs::symlink("dir", d.join("ld")).unwrap();
        }
        let f = || vec![("f", x.f.clone())];
        let fz = || vec![("f.Z", x.fz.clone())];
        let cases = vec![
            set(case("compress", &["l"], f()), sym_l_to_f),
            set(case("compress", &["-c", "l"], f()), sym_l_to_f),
            set(case("uncompress", &["l.Z"], fz()), sym_lz_to_fz),
            set(case("uncompress", &["l"], fz()), sym_lz_to_fz),
            set(case("uncompress", &["-c", "l.Z"], fz()), sym_lz_to_fz),
            set(
                case("compress", &["-r", "ld"], vec![("dir/a", x.a.clone())]),
                sym_dir,
            ),
        ];
        if !homebrew() {
            group("symbolic-link operands", &cases);
            return;
        }
        for c in &cases {
            let Some(r) = reference_run(c) else { return };
            let s = stuffr_as(c);
            let why = format!("{} {:?}", c.name, c.args);
            let operand = *c.args.last().unwrap();
            // `lstat`: the link itself; a missing name to decompress is
            // tried with `.Z` and refused in other words.
            let mut refusal = if c.name == "uncompress" && !operand.ends_with(".Z") {
                format!("{operand}.Z: Not a regular file.\n")
            } else {
                format!("{operand} is not a directory or a regular file - ignored\n")
            };
            if c.args.contains(&"-r") {
                refusal.push_str("no files processed after recursive search\n");
            }
            assert_eq!(
                (r.code, r.stderr.as_str()),
                (1, refusal.as_str()),
                "Homebrew, {why}"
            );
            assert_eq!((s.code, s.stderr.as_str()), (0, ""), "stuffr, {why}");
            let names: Vec<&str> = s.tree.keys().map(String::as_str).collect();
            match (c.name, c.args.as_slice()) {
                ("compress", ["l"]) => {
                    assert_eq!(names, ["f", "l.Z"], "{why}");
                    assert!(s.tree["l.Z"].0 == x.fz && s.tree["f"].0 == x.f, "{why}");
                }
                ("compress", ["-c", "l"]) => assert!(s.stdout == x.fz, "{why}"),
                ("uncompress", ["l.Z"] | ["l"]) => {
                    assert_eq!(names, ["f.Z", "l"], "{why}");
                    assert!(s.tree["l"].0 == x.f, "{why}");
                }
                ("uncompress", ["-c", "l.Z"]) => assert!(s.stdout == x.f, "{why}"),
                ("compress", ["-r", "ld"]) => {
                    // Ubuntu's `stat` walks the linked directory.
                    assert_eq!(names, ["dir/", "dir/a.Z", "ld"], "{why}");
                    assert!(s.tree["dir/a.Z"].0 == x.az, "{why}");
                }
                _ => unreachable!("{why}"),
            }
        }
    }
}

/// The deviations of `compat/compress/ncompress/mod.rs`, each asserted in
/// its stated direction: the reference's measured behaviour on one side,
/// the correct one on stuffr's.
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod deviations {
    use super::common::*;

    fn names(run: &Run) -> Vec<&str> {
        run.tree.keys().map(String::as_str).collect()
    }

    /// The index of the first byte where `a` and `b` differ.
    fn first_diff(a: &[u8], b: &[u8]) -> usize {
        a.iter()
            .zip(b)
            .position(|(x, y)| x != y)
            .unwrap_or(a.len().min(b.len()))
    }

    /// N1: at maxbits 9 (`-b 9`, and every value that clamps to 9: `0`,
    /// negatives, `1` to `8`, non-numbers, the empty string) ncompress's
    /// encoder writes entry 512 in 9 bits and never widens, so once the
    /// table fills its stream is undecodable, by its own decoder too.
    /// stuffr writes the compress 4.0 stream: the table stops at entry 511
    /// and the codes widen to 10 bits, which every decoder reads, ncompress's
    /// included. The bytes before the table fills are the reference's.
    #[test]
    fn n1_maxbits_9_streams_are_valid() {
        let Some(x) = fixtures() else { return };
        let big = text(1 << 20, 0x0018_0030);
        let rnd = random(1 << 20, 0x0018_0031);
        let zeros = vec![0u8; 1 << 20];
        let mut rows: Vec<(Vec<&str>, &[u8])> = Vec::new();
        for v in ["9", "-1", "0", "1", "8", "abc", ""] {
            rows.push((vec!["-b", v], &x.f));
        }
        rows.push((vec!["-b9"], &x.f));
        for input in [&big, &rnd, &zeros] {
            rows.push((vec!["-b", "9"], input));
        }
        for (args, input) in rows {
            let why = format!("{args:?} on {} bytes", input.len());
            // Exit 2 where the stream is not smaller than the input.
            let (code, theirs, _) = nc(x.dir, &args, input);
            assert!(matches!(code, 0 | 2), "reference, {why}");
            assert_eq!(theirs[2], 0x89, "reference, {why}");
            let (rc, _, err) = nc(x.dir, &["-d"], &theirs);
            assert_eq!(rc, 1, "reference reads its own stream? {why}");
            assert!(err.ends_with("uncompress: corrupt input\n"), "{why}: {err}");
            let (rc, mine, err) = ours(&args, input);
            assert_eq!(
                (rc, mine[2], err.as_str()),
                (code, 0x89, ""),
                "stuffr, {why}"
            );
            let (rc, back, err) = nc(x.dir, &["-d"], &mine);
            assert_eq!(
                (rc, err.as_str()),
                (0, ""),
                "ncompress reads stuffr's, {why}"
            );
            assert!(
                back == *input,
                "ncompress decodes stuffr's to the input, {why}"
            );
            let (rc, back, _) = ours(&["-d"], &mine);
            assert_eq!(rc, 0, "{why}");
            assert!(back == *input, "stuffr decodes its own, {why}");
            let (rc, back, _) = ours_apple(&["-d"], &mine);
            assert_eq!(rc, 0, "{why}");
            assert!(
                back == *input,
                "stuffr's Apple personality decodes it, {why}"
            );
            // Both write the first 256 codes in 9 bits (the 256th after
            // entry 511 is the last 9-bit one): the streams agree on every
            // byte before the 257th code, at bit 24 + 256 * 9.
            assert!(
                first_diff(&theirs, &mine) >= 3 + 256 * 9 / 8,
                "{why}: the streams part at byte {}",
                first_diff(&theirs, &mine)
            );
        }
        // The same through a file.
        let c = case("compress", &["-b", "9", "f"], vec![("f", x.f.clone())]);
        let s = stuffr_as(&c);
        assert_eq!((s.code, s.stderr.as_str(), names(&s)), (0, "", vec!["f.Z"]));
        let (rc, back, _) = nc(x.dir, &["-d"], &s.tree["f.Z"].0);
        assert!(rc == 0 && back == x.f, "a file -b 9 stream decodes");
    }

    /// N2: `uncompress` decompresses under that name on every platform
    /// (ruling E5). Ubuntu's binary decompresses only as
    /// `uncompress.real` (Debian's `uncompress-real.patch`), so its
    /// messages that name the program say `uncompress.real` where stuffr's
    /// say `uncompress`; everything else is the same. Homebrew's build is
    /// upstream's and names itself `uncompress` (compared in
    /// `differential::flags_and_usage_match_ncompress`).
    #[test]
    fn n2_uncompress_names_itself_uncompress() {
        let Some(x) = fixtures() else { return };
        for flag in ["-x", "-h", "-b", "-k", "-xk"] {
            let c = piped("uncompress", &[flag], x.fz.clone());
            let Some(r) = reference_run(&c) else { return };
            let s = stuffr_as(&c);
            let real =
                |t: &[u8]| String::from_utf8_lossy(t).replace("uncompress.real", "uncompress");
            if homebrew() {
                assert!(!r.stderr.contains("uncompress.real"), "{flag}");
            } else if flag != "-k" {
                let text = format!("{}{}", r.stderr, String::from_utf8_lossy(&r.stdout));
                assert!(text.contains("Usage: uncompress.real "), "{flag}: {text}");
            }
            assert_eq!(s.code, r.code, "{flag}");
            assert_eq!(s.stderr, real(r.stderr.as_bytes()), "{flag}");
            assert_eq!(
                String::from_utf8_lossy(&s.stdout),
                real(&r.stdout),
                "{flag}"
            );
        }
    }

    /// N4: `uncompress -f` on a file the decoder refuses at its header (not
    /// a `.Z`, more than 16 bits). ncompress prints the refusal, then takes
    /// the empty output for a success: it removes the input and leaves a
    /// 0-byte output, exit 1 or 4. stuffr prints the same refusal, exit 1
    /// or 4, removes its empty output and keeps the input.
    #[test]
    fn n4_a_refused_input_is_kept_under_f() {
        let Some(x) = fixtures() else { return };
        let mut b17 = x.fz.clone();
        b17[2] = 0x91;
        let rows: [(Vec<u8>, &[&str], i32, &str); 5] = [
            (x.f.clone(), &["-f"], 1, "bad.Z: not in compressed format\n"),
            (
                x.f.clone(),
                &["-fv"],
                1,
                "bad.Z: bad.Z: not in compressed format\n",
            ),
            (
                b17.clone(),
                &["-f"],
                4,
                "bad.Z: compressed with 17 bits, can only handle 16 bits\n",
            ),
            (vec![0x1f], &["-f"], 1, "bad.Z: not in compressed format\n"),
            (
                vec![0x1f, 0x9d],
                &["-f"],
                1,
                "bad.Z: not in compressed format\n",
            ),
        ];
        for (data, flags, code, msg) in rows {
            let mut args = flags.to_vec();
            args.push("bad.Z");
            let c = case("uncompress", &args, vec![("bad.Z", data.clone())]);
            let Some(r) = reference_run(&c) else { return };
            let s = stuffr_as(&c);
            let why = format!("{args:?}, {} bytes", data.len());
            assert_eq!(r.code, code, "reference, {why}");
            assert!(
                r.stderr.starts_with(msg),
                "reference, {why}: {:?}",
                r.stderr
            );
            assert_eq!(names(&r), ["bad"], "reference lost the input, {why}");
            assert!(r.tree["bad"].0.is_empty(), "{why}");
            assert_eq!((s.code, s.stderr.as_str()), (code, msg), "stuffr, {why}");
            assert_eq!(names(&s), ["bad.Z"], "stuffr keeps the input, {why}");
            assert!(s.tree["bad.Z"].0 == data, "{why}");
        }
    }
}

/// Review Focus 5 (ruling E3): ncompress's `abort_compress` handles SIGINT
/// (unless ignored at start), SIGTERM and SIGHUP: the partial output is
/// removed and the process exits 1. SIGQUIT keeps its default action: the
/// process dies of it and the partial output (mode 0600) stays.
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod interrupts {
    use super::common::*;
    use super::compat_harness::interrupt::*;
    use std::collections::HashMap;
    use std::os::unix::process::ExitStatusExt;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};

    const ENV: &[(&str, &str)] = &[FLAVOR];

    /// ncompress's `.Z` of `big_input(mib)`, made once per size.
    fn big_z(mib: usize) -> Vec<u8> {
        static CACHE: OnceLock<Mutex<HashMap<usize, Vec<u8>>>> = OnceLock::new();
        let cache = CACHE.get_or_init(Mutex::default);
        let mut map = cache.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(mib)
            .or_insert_with(|| {
                let dir = ncompress_dir().expect("the reference is present");
                let exe = ncompress_exe(dir, "compress");
                // `-f`: a random input grows, which is exit 2 without it.
                big_input_through(exe.to_str().unwrap(), &["-cf"], mib)
                    .expect("the reference is present")
            })
            .clone()
    }

    /// The program and the `argv[0]` it runs as: stuffr as `name`, or the
    /// reference program that answers to `name` (`uncompress.real` on
    /// Ubuntu, which only decompresses under that name).
    fn exe(mine: bool, name: &str) -> (PathBuf, String) {
        if mine {
            return (
                PathBuf::from(env!("CARGO_BIN_EXE_stuffr")),
                name.to_string(),
            );
        }
        let p = ncompress_exe(ncompress_dir().unwrap(), name);
        let n = p.file_name().unwrap().to_string_lossy().into_owned();
        (p, n)
    }

    #[test]
    fn a_handled_signal_removes_the_partial_output_and_exits_1() {
        let _serial = interrupt_lock();
        if ncompress_dir().is_none() {
            return;
        }
        type Make<'a> = &'a dyn Fn(usize) -> Vec<u8>;
        let plain: Make = &big_input;
        let packed: Make = &big_z;
        let rows: [(&str, &str, &str, Make); 2] = [
            ("compress", "big", "big.Z", plain),
            ("uncompress", "big.Z", "big", packed),
        ];
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            for (name, input, partial, make) in rows {
                for mine in [false, true] {
                    let dir = ScratchDir::unique("ncompress-intr");
                    let named = |n: &str| n == partial;
                    let ready = has_data(&dir, &named);
                    let (exe, arg0) = exe(mine, name);
                    // `-f`: a random input grows, and only `-f` keeps the
                    // run going to the end, so the signal finds it busy.
                    let Some(r) = interrupt_with_input_env(
                        &exe,
                        &arg0,
                        &["-f", input],
                        &dir,
                        ENV,
                        input,
                        make,
                        Inherit::Default,
                        sig,
                        &ready,
                    ) else {
                        continue;
                    };
                    let why = format!("mine={mine} {name} signal {sig}");
                    assert_eq!(r.status.code(), Some(1), "{why}: {:?}", r.status);
                    assert_eq!(r.left, [input.to_string()], "{why}");
                    let got = std::fs::read(dir.join(input)).unwrap();
                    assert!(
                        [64, 256].iter().any(|&m| make(m) == got),
                        "{why}: the input changed"
                    );
                    assert!(r.stderr.is_empty(), "{why}: {:?}", r.stderr);
                }
            }
        }
    }

    #[test]
    fn sigquit_kills_and_leaves_the_partial_output() {
        let _serial = interrupt_lock();
        if ncompress_dir().is_none() {
            return;
        }
        type Make<'a> = &'a dyn Fn(usize) -> Vec<u8>;
        let plain: Make = &big_input;
        let packed: Make = &big_z;
        let rows: [(&str, &str, &str, Make); 2] = [
            ("compress", "big", "big.Z", plain),
            ("uncompress", "big.Z", "big", packed),
        ];
        for (name, input, partial, make) in rows {
            for mine in [false, true] {
                let dir = ScratchDir::unique("ncompress-quit");
                let named = |n: &str| n == partial;
                let ready = has_data(&dir, &named);
                let (exe, arg0) = exe(mine, name);
                let Some(r) = interrupt_with_input_env(
                    &exe,
                    &arg0,
                    &["-f", input],
                    &dir,
                    ENV,
                    input,
                    make,
                    Inherit::Default,
                    libc::SIGQUIT,
                    &ready,
                ) else {
                    continue;
                };
                let why = format!("mine={mine} {name}");
                assert_eq!(r.status.signal(), Some(libc::SIGQUIT), "{why}");
                let mut want = vec![input.to_string(), partial.to_string()];
                want.sort();
                assert_eq!(r.left, want, "{why}");
                use std::os::unix::fs::PermissionsExt;
                let m = std::fs::metadata(dir.join(partial)).unwrap();
                assert_eq!(m.permissions().mode() & 0o777, 0o600, "{why}");
                assert!(r.stderr.is_empty(), "{why}: {:?}", r.stderr);
            }
        }
    }

    /// `compress -c` given SIGTERM exits 1; only its input is left.
    #[test]
    fn a_signal_to_a_filter_exits_1() {
        let _serial = interrupt_lock();
        if ncompress_dir().is_none() {
            return;
        }
        for mine in [false, true] {
            let (exe, arg0) = exe(mine, "compress");
            // A run that finished before the signal (no result, or exit 0
            // after "ready") is a miss: retry with a larger input.
            let mut hit = None;
            let mut hung = false;
            for mib in [64, 256] {
                let dir = ScratchDir::unique("ncompress-intr-c");
                std::fs::create_dir_all(&*dir).unwrap();
                std::fs::write(dir.join("big"), big_input(mib)).unwrap();
                // Ready once compressed bytes arrive: both programs install
                // their handlers before writing any.
                let r = interrupt_once_stdout_has_data(
                    &exe,
                    &arg0,
                    &["-c", "big"],
                    &dir,
                    ENV,
                    Inherit::Default,
                    libc::SIGTERM,
                );
                hung |= take_reference_hung();
                if let Some(r) = r.filter(|r| !r.status.success()) {
                    hit = Some(r);
                    break;
                }
            }
            let Some(r) = hit else {
                if hung {
                    eprintln!(
                        "note: the compress reference hung after the signal; comparison skipped"
                    );
                    continue;
                }
                panic!("mine={mine}: compress -c: no run reached the signal at 64 and 256 MiB");
            };
            assert_eq!(r.status.code(), Some(1), "mine={mine}: {:?}", r.status);
            assert_eq!(r.left, ["big"], "mine={mine}");
        }
    }

    /// An INT ignored at start stays ignored: the run finishes, exit 0.
    #[test]
    fn an_ignored_interrupt_stays_ignored() {
        let _serial = interrupt_lock();
        if ncompress_dir().is_none() {
            return;
        }
        let block = text(4 << 20, 0x0018_0020);
        for mine in [false, true] {
            let (exe, arg0) = exe(mine, "compress");
            // A run that ends before the signal lands is a miss: retry with
            // a larger input, fail only when every size misses.
            let mut hit = None;
            let mut hung = false;
            for mib in [64, 256] {
                let big: Vec<u8> = block.iter().copied().cycle().take(mib << 20).collect();
                let dir = ScratchDir::unique("ncompress-intr-ign");
                std::fs::create_dir_all(&*dir).unwrap();
                std::fs::write(dir.join("big"), &big).unwrap();
                let ready = has_data(&dir, &|n: &str| n == "big.Z");
                let r = interrupt_env(
                    &exe,
                    &arg0,
                    &["big"],
                    &dir,
                    ENV,
                    Inherit::IgnoreInt,
                    libc::SIGINT,
                    &ready,
                );
                hung |= take_reference_hung();
                if let Some(r) = r {
                    hit = Some(r);
                    break;
                }
            }
            let Some(r) = hit else {
                if hung {
                    eprintln!(
                        "note: the compress reference hung after the signal; comparison skipped"
                    );
                    continue;
                }
                panic!("mine={mine}: compress: no run reached the signal at 64 and 256 MiB");
            };
            assert!(r.status.success(), "mine={mine}: {:?}", r.status);
            assert_eq!(r.left, ["big.Z"], "mine={mine}");
        }
    }
}
