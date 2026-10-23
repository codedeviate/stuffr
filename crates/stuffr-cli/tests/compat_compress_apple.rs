//! Differential tests: stuffr invoked as `compress` and `uncompress` with
//! `STUFFR_COMPRESS_FLAVOR=apple`, against Apple's own `/usr/bin/compress`
//! (file_cmds-487.0.1; `uncompress` is the same binary).
//!
//! Every row comes from the measurement record of 0.18.0 Task 1
//! (`compress-measurements.md`: the surface table, the `-b` parse table,
//! the validity table) and is compared against the live reference: exit
//! code, standard error, standard output and the working directory
//! afterwards (bytes, modes, times). Compressed bytes are promised
//! identical everywhere (no tier split: there is no C LZW), so nothing is
//! round-tripped.
//!
//! The deviations of `compat/compress/apple/mod.rs` are asserted in their
//! stated direction, with Apple's measured behaviour as the reference's
//! expected value (`deviations`).
//!
//! **macOS only.** The reference exists nowhere else; elsewhere one test
//! says so instead of the file compiling to nothing.

#[cfg(not(target_os = "macos"))]
#[test]
fn apple_compress_is_the_reference_and_exists_only_on_macos() {
    println!("skipped: the Apple compress suite needs /usr/bin/compress, which only macOS has");
}

#[cfg(target_os = "macos")]
mod compat_harness;

/// Cases, fixtures and the comparison every group shares.
#[cfg(target_os = "macos")]
mod common {
    pub use super::compat_harness::*;
    use std::io::Write;
    use std::path::Path;
    use std::process::{Command, Stdio};

    /// Where `compress` and `uncompress` live.
    pub const DIR: &str = "/usr/bin";

    /// stuffr's side runs as the Apple personality whatever the platform
    /// default; the reference ignores the variable.
    pub const FLAVOR: (&str, &str) = ("STUFFR_COMPRESS_FLAVOR", "apple");

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

    /// One row: the reference and stuffr on the same case, every
    /// difference reported. False when the reference is absent.
    pub fn compare(c: &Case) -> bool {
        let Some(r) = reference(DIR, c) else {
            return false;
        };
        let s = stuffr_as(c);
        assert_same(c, &r, &s);
        true
    }

    pub fn group(name: &str, cases: &[Case]) {
        run_group(name, cases, Skipped::none(), &compare);
    }

    /// Apple's `compress` as a filter: `args`, `input` on standard input,
    /// standard output returned.
    pub fn apple(args: &[&str], input: &[u8]) -> Vec<u8> {
        let mut cmd = Command::new(Path::new(DIR).join("compress"));
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = spawn(&mut cmd).expect("spawn /usr/bin/compress");
        let mut si = child.stdin.take().unwrap();
        let data = input.to_vec();
        let writer = std::thread::spawn(move || {
            let _ = si.write_all(&data);
        });
        let out = child.wait_with_output().unwrap();
        writer.join().unwrap();
        out.stdout
    }

    /// The inputs of the record: `f` (text, compresses), `a` and `b`
    /// (text), `r` (random, grows), and Apple's `.Z` of `f`, `a`, `b`.
    pub struct Fx {
        pub f: Vec<u8>,
        pub a: Vec<u8>,
        pub b: Vec<u8>,
        pub r: Vec<u8>,
        pub fz: Vec<u8>,
        pub az: Vec<u8>,
        pub bz: Vec<u8>,
    }

    /// [`Fx`], or `None` (after `require_reference`'s note) without the
    /// reference.
    pub fn fixtures() -> Option<Fx> {
        if !require_reference(&Path::new(DIR).join("compress")) {
            return None;
        }
        let f = text(50_000, 0x0018_0001);
        let a = text(30_000, 0x0018_0002);
        let b = text(30_000, 0x0018_0003);
        let r = random(4096, 0x0018_0004);
        let fz = apple(&["-c"], &f);
        let az = apple(&["-c"], &a);
        let bz = apple(&["-c"], &b);
        assert!(fz.starts_with(&[0x1f, 0x9d, 0x90]), "Apple's .Z of f");
        Some(Fx {
            f,
            a,
            b,
            r,
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

#[cfg(target_os = "macos")]
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
    fn sym_l_to_f(d: &Path) {
        std::os::unix::fs::symlink("f", d.join("l")).unwrap();
    }
    fn sym_f_to_fz(d: &Path) {
        std::os::unix::fs::symlink("f.Z", d.join("f")).unwrap();
    }
    fn sym_lz_to_fz(d: &Path) {
        std::os::unix::fs::symlink("f.Z", d.join("l.Z")).unwrap();
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

    /// The usage, flags and version rows: every option Apple's getopt
    /// (`b:cdfv`) refuses prints `illegal option` with the full `argv[0]`
    /// and the usage line, exit 1; `--` and `-` behave as getopt says.
    #[test]
    fn flags_and_usage_match_apple() {
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
            "-bx",
        ] {
            cases.push(piped("compress", &[flag], x.f.clone()));
        }
        for flag in ["-x", "-h", "-V", "-r", "--"] {
            cases.push(piped("uncompress", &[flag], x.fz.clone()));
        }
        // `-d` before a bad option: the usage names `uncompress`.
        cases.push(piped("compress", &["-d", "-x"], x.fz.clone()));
        cases.push(piped("uncompress", &["-b"], x.fz.clone()));
        cases.push(case("compress", &["-k", "f"], vec![("f", x.f.clone())]));
        cases.push(case("compress", &["-q", "r"], vec![("r", x.r.clone())]));
        cases.push(case("compress", &["--", "-f"], vec![("-f", x.f.clone())]));
        cases.push(piped("compress", &["-"], x.f.clone()));
        cases.push(piped("uncompress", &["-"], x.fz.clone()));
        cases.push(case("compress", &["-V", "f"], vec![("f", x.f.clone())]));
        cases.push(case("compress", &["-cv", "f"], vec![("f", x.f.clone())]));
        cases.push(case(
            "compress",
            &["-vc", "--", "f"],
            vec![("f", x.f.clone())],
        ));
        // getopt stops at the first operand: `-c` after it is a file.
        cases.push(case("compress", &["f", "-c"], vec![("f", x.f.clone())]));
        group("flags", &cases);
    }

    /// Compressing and decompressing files, standard input and output.
    #[test]
    fn basics_match_apple() {
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
            // `-` sets `cat` for the operands after it.
            {
                let mut c = case("compress", &["-", "a"], vec![("a", x.a.clone())]);
                c.stdin = Some(x.b.clone());
                c
            },
            {
                let mut c = case("compress", &["a", "-"], vec![("a", x.a.clone())]);
                c.stdin = Some(x.b.clone());
                c
            },
            {
                let mut c = case("uncompress", &["-", "a.Z"], vec![("a.Z", x.az.clone())]);
                c.stdin = Some(x.bz.clone());
                c
            },
            case("compress", &["-c", "-b", "12", "f"], f()),
            case("compress", &["-b", "12", "f"], f()),
        ];
        group("basics", &cases);
    }

    /// Review Focus 1 without a terminal: an existing output is refused
    /// (`already exists`, exit 1, both files kept) unless `-f`; `-c` never
    /// looks; a directory or a dangling link in the output's place.
    #[test]
    fn existing_outputs_match_apple() {
        let Some(x) = fixtures() else { return };
        let both = || vec![("f", x.f.clone()), ("f.Z", x.fz.clone())];
        let cases = vec![
            case("compress", &["f"], both()),
            case("compress", &["-v", "f"], both()),
            case("compress", &["-f", "f"], both()),
            case("compress", &["-c", "f"], both()),
            case("uncompress", &["f.Z"], both()),
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
                case("uncompress", &["f.Z"], vec![("f.Z", x.fz.clone())]),
                dangling_f,
            ),
            // Standard input is a terminal but standard error is not: no
            // question, the refusal.
            {
                let mut c = case("compress", &["f"], both());
                c.tty_stdin = true;
                c.stdin = Some(b"y\n".to_vec());
                c
            },
            {
                let mut c = case("uncompress", &["f.Z"], both());
                c.tty_stdin = true;
                c.stdin = Some(b"y\n".to_vec());
                c
            },
        ];
        group("existing outputs", &cases);
    }

    /// Review Focus 4: neither tool refuses a terminal. Compressed data is
    /// written to a terminal standard output, and a terminal standard
    /// input is read (an immediate end of file).
    #[test]
    fn terminals_match_apple() {
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
            // A pipe is read as it comes.
            piped("compress", &["-c", "-"], x.a.clone()),
        ];
        run_group("terminals", &cases, Skipped::none(), &|c: &Case| {
            let Some(mut r) = reference(DIR, c) else {
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
    /// its driver puts before each newline (ONLCR). macOS's driver, its
    /// output queue full in the middle of that, sometimes repeats or drops
    /// the `\r`: 20 of 200 runs of `/usr/bin/uncompress` alone under load
    /// showed `\r\r\n` (the record's "tty saw" counts also varied by a few
    /// bytes run to run). The program's bytes are compared exactly; only
    /// the terminal's additions are left out.
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
    /// exit 2 (the message only under `-v`), unless `-f`; not checked for
    /// standard output; an empty input writes nothing at all.
    #[test]
    fn no_saving_matches_apple() {
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
            case("compress", &["-c", "r"], r()),
            case("compress", &["e"], e()),
            case("compress", &["-v", "e"], e()),
            case("compress", &["-f", "e"], e()),
            case("compress", &["-f", "-v", "e"], e()),
            case("compress", &["-c", "e"], e()),
            piped("compress", &[], Vec::new()),
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
                vec![("r.Z", apple(&["-c"], &x.r))],
            ),
        ];
        group("no saving", &cases);
    }

    /// Links where Apple's own behaviour keeps the data (the `-f` cases
    /// where it does not are `deviations::a2_*`).
    #[test]
    fn links_match_apple() {
        let Some(x) = fixtures() else { return };
        let f = || vec![("f", x.f.clone())];
        let fz = || vec![("f.Z", x.fz.clone())];
        let cases = vec![
            set(case("compress", &["f"], f()), sym_fz_to_f),
            set(case("compress", &["f"], f()), hard_fz_to_f),
            set(case("compress", &["f"], f()), hard_g_to_f),
            set(case("compress", &["-f", "f"], f()), hard_g_to_f),
            set(case("compress", &["l"], f()), sym_l_to_f),
            set(case("compress", &["-c", "l"], f()), sym_l_to_f),
            set(case("uncompress", &["f.Z"], fz()), sym_f_to_fz),
            set(case("uncompress", &["l.Z"], fz()), sym_lz_to_fz),
            set(case("uncompress", &["-c", "f.Z"], fz()), sym_f_to_fz),
        ];
        group("links", &cases);
    }

    /// Missing operands, directories, names with and without `.Z`, devices.
    #[test]
    fn odd_operands_match_apple() {
        let Some(x) = fixtures() else { return };
        let long = leak("n".repeat(1100));
        let long_z = leak(format!("{}.Z", "n".repeat(1100)));
        let cases = vec![
            case("compress", &["nope"], vec![]),
            case("uncompress", &["nope"], vec![]),
            case("uncompress", &["nope.Z"], vec![]),
            case("uncompress", &["-c", "nope"], vec![]),
            case("uncompress", &["f"], vec![("f", x.f.clone())]),
            case("uncompress", &["-v", "f"], vec![("f", x.f.clone())]),
            case("uncompress", &["-c", "f"], vec![("f", x.f.clone())]),
            case("compress", &["f.Z"], vec![("f.Z", x.fz.clone())]),
            case("compress", &["-c", "f.Z"], vec![("f.Z", x.fz.clone())]),
            case("compress", &["a.Z.Z"], vec![]),
            case("compress", &["x.Zz"], vec![("x.Zz", x.a.clone())]),
            set(case("compress", &["dir"], vec![]), mkdir_dir),
            set(case("compress", &["-v", "dir"], vec![]), mkdir_dir),
            set(case("compress", &["-c", "dir"], vec![]), mkdir_dir),
            set(case("compress", &["-r", "dir"], vec![]), mkdir_dir),
            set(case("uncompress", &["dir"], vec![]), mkdir_dir),
            set(case("uncompress", &["-r", "dir"], vec![]), mkdir_dir),
            case("compress", &["-c", "/dev/null"], vec![]),
            case("compress", &["/dev/null"], vec![]),
            case("uncompress", &["-c", "/dev/null"], vec![]),
            case("uncompress", &[".Z"], vec![(".Z", x.fz.clone())]),
            case("compress", &[long], vec![]),
            case("uncompress", &[long], vec![]),
            case("uncompress", &[long_z], vec![]),
        ];
        group("odd operands", &cases);
    }

    /// Review Focus 3: a non-`.Z`, cut-short, damaged or odd `.Z` given to
    /// `uncompress`. The valid-but-refused cases are `deviations::a1_*` and
    /// `deviations::a3_*`.
    #[test]
    fn bad_input_matches_apple() {
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
        // The first code is never checked: 0x1ff is written as its low
        // byte; then a code past the next free entry.
        let first_wide = vec![0x1f, 0x9d, 0x90, 0xff, 0x03, 0x00];
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
            case("uncompress", &["-f", "bad.Z"], vec![("bad.Z", x.f.clone())]),
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
            case("uncompress", &["e.Z"], vec![("e.Z", Vec::new())]),
            case("uncompress", &["-f", "e.Z"], vec![("e.Z", Vec::new())]),
            piped("uncompress", &[], Vec::new()),
            case("uncompress", &["b17.Z"], vec![("b17.Z", b17.clone())]),
            piped("uncompress", &[], b17.clone()),
            piped("uncompress", &[], junk.clone()),
            case("uncompress", &["junk.Z"], vec![("junk.Z", junk.clone())]),
            piped("uncompress", &[], cat.clone()),
            case("uncompress", &["cat.Z"], vec![("cat.Z", cat.clone())]),
            case("uncompress", &["-c", "cat.Z"], vec![("cat.Z", cat.clone())]),
            case("uncompress", &["-f", "cat.Z"], vec![("cat.Z", cat.clone())]),
            piped("uncompress", &[], noblock.clone()),
            piped("uncompress", &[], flip.clone()),
            piped("uncompress", &[], first_wide.clone()),
            case("uncompress", &["w.Z"], vec![("w.Z", first_wide.clone())]),
        ];
        group("bad input", &cases);
    }

    /// Several operands, one failing: the run goes on, and the exit code is
    /// the last one set (an error 1, "no saving" 2; success lowers neither).
    #[test]
    fn several_operands_match_apple() {
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
    fn permissions_match_apple() {
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

    /// The `-b` parse table: `strtol` in base 10 (leading blanks and a
    /// sign accepted, trailing junk refused, the value truncated to an
    /// `int`), `zopen`'s range check (`0..=16`, 0 meaning 16) as
    /// `Invalid argument` naming the output (or, decompressing, the input),
    /// and getopt's handling of a missing value. Apple's `-b 1` to `-b 8`
    /// bytes are reproduced (ruling E1).
    #[test]
    fn bit_counts_parse_as_apple() {
        let Some(x) = fixtures() else { return };
        let mut cases = Vec::new();
        for v in [
            "-1",
            "0",
            "1",
            "2",
            "7",
            "8",
            "9",
            "12",
            "16",
            "17",
            "100",
            "abc",
            "",
            "12x",
            " 12",
            "+12",
            " ",
            "+",
            "-0",
            "4294967312",
            "99999999999999999999",
            "-99999999999999999999",
        ] {
            cases.push(piped("compress", &["-b", v], x.f.clone()));
        }
        for a in ["-b9", "-b17", "-babc", "-b-1", "-b0", "-cb12", "-b"] {
            cases.push(piped("compress", &[a], x.f.clone()));
        }
        cases.push(piped("compress", &["-b", "9", "-b", "12"], x.f.clone()));
        cases.push(case("compress", &["f", "-b"], vec![("f", x.f.clone())]));
        cases.push(case(
            "compress",
            &["-b", "17", "f"],
            vec![("f", x.f.clone())],
        ));
        cases.push(case(
            "compress",
            &["-b", "-1", "f"],
            vec![("f", x.f.clone())],
        ));
        cases.push(case(
            "compress",
            &["-b", "8", "f"],
            vec![("f", x.f.clone())],
        ));
        cases.push(case("compress", &["-b", "17", "nope"], vec![]));
        cases.push(piped("uncompress", &["-b", "17"], x.fz.clone()));
        cases.push(piped("uncompress", &["-b", "9"], x.fz.clone()));
        cases.push(piped("uncompress", &["-b", "abc"], x.fz.clone()));
        cases.push(case(
            "uncompress",
            &["-b", "17", "f.Z"],
            vec![("f.Z", x.fz.clone())],
        ));
        cases.push(case("uncompress", &["-b", "17", "nope.Z"], vec![]));
        group("bit counts", &cases);
    }

    /// The validity table: at every `-b` from 9 to 16 Apple's stream is
    /// valid, so its bytes are promised, on text, random and all-zero
    /// input, large enough to fill the table and reach the ratio checks
    /// and their CLEAR codes.
    #[test]
    fn every_bit_count_writes_apples_bytes() {
        let Some(_) = fixtures() else { return };
        let inputs = [
            text(1 << 20, 0x0018_0010),
            random(1 << 20, 0x0018_0011),
            vec![0u8; 1 << 20],
        ];
        let mut cases = Vec::new();
        for bits in ["9", "10", "11", "12", "13", "14", "15", "16"] {
            for input in &inputs {
                cases.push(piped("compress", &["-b", bits], input.clone()));
            }
        }
        // And a file, so the output's name, mode and times are compared.
        cases.push(case(
            "compress",
            &["-b", "11", "t"],
            vec![("t", inputs[0].clone())],
        ));
        group("every bit count", &cases);
    }
}

/// The deviations of `compat/compress/apple/mod.rs`, each asserted in its
/// stated direction: the reference's measured behaviour on one side, the
/// correct one on stuffr's.
#[cfg(target_os = "macos")]
mod deviations {
    use super::common::*;
    use std::path::Path;

    fn sym_fz_to_f(d: &Path) {
        std::os::unix::fs::symlink("f", d.join("f.Z")).unwrap();
    }
    fn hard_fz_to_f(d: &Path) {
        std::fs::hard_link(d.join("f"), d.join("f.Z")).unwrap();
    }
    fn sym_f_to_fz(d: &Path) {
        std::os::unix::fs::symlink("f.Z", d.join("f")).unwrap();
    }
    fn hard_f_to_fz(d: &Path) {
        std::fs::hard_link(d.join("f.Z"), d.join("f")).unwrap();
    }

    /// Both sides of `c`, or `None` without the reference.
    fn both(c: &Case) -> Option<(Run, Run)> {
        let r = reference(DIR, c)?;
        Some((r, stuffr_as(c)))
    }

    fn names(run: &Run) -> Vec<&str> {
        run.tree.keys().map(String::as_str).collect()
    }

    /// A1 (with ruling E1): a valid stream whose header asks for 1 to 11
    /// bits. Apple's own `-b 1`, `-b 8`, `-b 9`, `-b 10` and `-b 11` output
    /// is refused by its `uncompress` (`Inappropriate file type or
    /// format`, exit 1, nothing written); stuffr decodes it.
    #[test]
    fn a1_low_maxbits_streams_decode() {
        let Some(x) = fixtures() else { return };
        for bits in ["1", "8", "9", "10", "11"] {
            let z = apple(&["-b", bits], &x.f);
            assert_eq!(z[2], 0x80 | bits.parse::<u8>().unwrap(), "-b {bits}");
            let c = piped("uncompress", &[], z.clone());
            let Some((r, s)) = both(&c) else { return };
            assert_eq!(
                (r.code, r.stderr.as_str(), r.stdout.len()),
                (
                    1,
                    "uncompress: /dev/stdin: Inappropriate file type or format\n",
                    0
                ),
                "reference, -b {bits} on standard input"
            );
            assert_eq!((s.code, s.stderr.as_str()), (0, ""), "stuffr, -b {bits}");
            assert!(s.stdout == x.f, "stuffr decodes -b {bits}");

            let c = case("uncompress", &["x.Z"], vec![("x.Z", z.clone())]);
            let Some((r, s)) = both(&c) else { return };
            assert_eq!(
                (r.code, r.stderr.as_str(), names(&r)),
                (
                    1,
                    "uncompress: x.Z: Inappropriate file type or format\n",
                    vec!["x.Z"]
                ),
                "reference, -b {bits} file"
            );
            assert_eq!(
                (s.code, s.stderr.as_str(), names(&s)),
                (0, "", vec!["x"]),
                "stuffr, -b {bits} file"
            );
            let (bytes, mode, mtime) = &s.tree["x"];
            assert!(*bytes == x.f, "-b {bits}: x holds the input");
            assert_eq!((*mode, *mtime), (0o644, INPUT_MTIME as i64), "-b {bits}");
        }
    }

    /// A2: `compress -f f` when `f.Z` is a link to `f`, and `uncompress -f
    /// f.Z` when `f` is a link to `f.Z`. Apple opens the output for
    /// writing over the input and loses the data (exit 0 for compress,
    /// `Invalid argument` exit 1 for uncompress); stuffr writes the output
    /// under a temporary name and puts it in place when complete, so the
    /// data survives, compressed or decompressed, with the same silence
    /// and exit 0.
    #[test]
    fn a2_an_output_linked_to_the_input_keeps_the_data() {
        let Some(x) = fixtures() else { return };
        for (setup, what) in [
            (sym_fz_to_f as fn(&Path), "f.Z -> f"),
            (hard_fz_to_f, "f.Z hard link of f"),
        ] {
            let mut c = case("compress", &["-f", "f"], vec![("f", x.f.clone())]);
            c.setup = Some(setup);
            let Some((r, s)) = both(&c) else { return };
            assert_eq!((r.code, r.stderr.as_str()), (0, ""), "reference, {what}");
            assert_eq!(names(&r), ["f.Z"], "reference, {what}");
            assert!(r.tree["f.Z"].0 != x.fz, "reference kept the data? {what}");
            assert_eq!(
                (s.code, s.stderr.as_str(), names(&s)),
                (0, "", vec!["f.Z"]),
                "stuffr, {what}"
            );
            assert!(s.tree["f.Z"].0 == x.fz, "stuffr's f.Z, {what}");
            assert_eq!(s.tree["f.Z"].2, INPUT_MTIME as i64, "{what}");
        }
        for (setup, what) in [
            (sym_f_to_fz as fn(&Path), "f -> f.Z"),
            (hard_f_to_fz, "f hard link of f.Z"),
        ] {
            let mut c = case("uncompress", &["-f", "f.Z"], vec![("f.Z", x.fz.clone())]);
            c.setup = Some(setup);
            let Some((r, s)) = both(&c) else { return };
            assert_eq!(
                (r.code, r.stderr.as_str()),
                (1, "uncompress: f.Z: Invalid argument\n"),
                "reference, {what}"
            );
            assert!(
                r.tree.get("f.Z").is_none_or(|e| e.0 != x.fz),
                "reference kept the data? {what}"
            );
            assert_eq!(
                (s.code, s.stderr.as_str(), names(&s)),
                (0, "", vec!["f"]),
                "stuffr, {what}"
            );
            assert!(s.tree["f"].0 == x.f, "stuffr's f, {what}");
        }
    }

    /// A3: the header-only stream `1f 9d 90` (what ncompress writes for an
    /// empty input) is a valid stream of nothing. Apple refuses it with a
    /// stale `errno` (`No such file or directory` from the output's
    /// `stat`, or `Undefined error: 0`), exit 1; stuffr decodes it to an
    /// empty output.
    #[test]
    fn a3_a_header_only_stream_decodes_to_nothing() {
        let Some(_) = fixtures() else { return };
        let hdr = vec![0x1f, 0x9d, 0x90];
        let rows: [(Case, &str, &[&str], &[&str]); 4] = [
            (
                case("uncompress", &["hdr.Z"], vec![("hdr.Z", hdr.clone())]),
                "uncompress: hdr.Z: No such file or directory\n",
                &["hdr.Z"],
                &["hdr"],
            ),
            (
                case("uncompress", &["-f", "hdr.Z"], vec![("hdr.Z", hdr.clone())]),
                "uncompress: hdr.Z: No such file or directory\n",
                &["hdr.Z"],
                &["hdr"],
            ),
            (
                case("uncompress", &["-c", "hdr.Z"], vec![("hdr.Z", hdr.clone())]),
                "uncompress: hdr.Z: Undefined error: 0\n",
                &["hdr.Z"],
                &["hdr.Z"],
            ),
            (
                piped("uncompress", &[], hdr.clone()),
                "uncompress: /dev/stdin: Undefined error: 0\n",
                &[],
                &[],
            ),
        ];
        for (c, ref_err, ref_files, our_files) in rows {
            let Some((r, s)) = both(&c) else { return };
            assert_eq!(
                (r.code, r.stderr.as_str(), names(&r).as_slice()),
                (1, ref_err, ref_files),
                "reference, {:?}",
                c.args
            );
            assert_eq!(
                (
                    s.code,
                    s.stderr.as_str(),
                    names(&s).as_slice(),
                    s.stdout.len()
                ),
                (0, "", our_files, 0),
                "stuffr, {:?}",
                c.args
            );
            if let Some((bytes, _, mtime)) = s.tree.get("hdr") {
                assert!(bytes.is_empty());
                assert_eq!(*mtime, INPUT_MTIME as i64);
            }
        }
    }
}

/// Review Focus 1 at a terminal: Apple asks `overwrite NAME? ` on standard
/// error only when standard error is a terminal, reads the answer from
/// standard input (`rpmatch` of its first byte), and on a no prints the
/// refusal too. The harness cannot make standard error a terminal, so these
/// rows run both programs on a pty of their own (echo off, so the tty shows
/// only what the program writes) and compare the exit code, what the
/// terminal saw and the directory.
#[cfg(target_os = "macos")]
mod prompts {
    use super::common::*;
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    struct Seen {
        code: i32,
        tty: Vec<u8>,
        files: Vec<(String, Vec<u8>)>,
    }

    /// `exe` as `name` with `args` over `files`; standard error on a pty,
    /// standard input on it too (`answer` typed ahead) or `/dev/null`.
    fn run(
        exe: &Path,
        name: &str,
        args: &[&str],
        files: &[(&str, &[u8])],
        answer: Option<&[u8]>,
    ) -> Seen {
        let scratch = ScratchDir::unique("compress-pty");
        let work = scratch.join("work");
        std::fs::create_dir_all(&work).unwrap();
        for (n, b) in files {
            std::fs::write(work.join(n), b).unwrap();
        }
        let guard = spawn_lock();
        let (mut m, mut s) = (0, 0);
        // SAFETY: openpty writes the two descriptors it opens.
        let rc = unsafe {
            libc::openpty(
                &mut m,
                &mut s,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, 0, "openpty");
        // SAFETY: both descriptors were just opened and are ours alone.
        let (master, slave) = unsafe { (OwnedFd::from_raw_fd(m), OwnedFd::from_raw_fd(s)) };
        for fd in [m, s] {
            // SAFETY: fcntl on descriptors we own.
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        }
        // Echo off: the terminal shows only what the program writes.
        // SAFETY: termios is plain data filled by tcgetattr.
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: tcgetattr/tcsetattr on the slave we own.
        unsafe {
            assert_eq!(libc::tcgetattr(slave.as_raw_fd(), &mut t), 0);
            t.c_lflag &= !libc::ECHO;
            assert_eq!(libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &t), 0);
        }
        let mut cmd = Command::new(exe);
        cmd.arg0(name)
            .args(args)
            .current_dir(&work)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C")
            .env(FLAVOR.0, FLAVOR.1)
            .stdout(Stdio::null())
            .stderr(Stdio::from(slave.try_clone().unwrap()));
        if answer.is_some() {
            cmd.stdin(Stdio::from(slave.try_clone().unwrap()));
        } else {
            cmd.stdin(Stdio::null());
        }
        let mut child = cmd.spawn().expect("spawn");
        drop(cmd);
        drop(guard);
        let mut master = std::fs::File::from(master);
        if let Some(a) = answer {
            use std::io::Write;
            master.write_all(a).unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(st) = child.try_wait().unwrap() {
                break st;
            }
            assert!(Instant::now() < deadline, "{exe:?} {args:?} timed out");
            std::thread::sleep(Duration::from_millis(5));
        };
        // Everything the child wrote is queued; our slave copy keeps the
        // master from reading a hang-up first.
        // SAFETY: fcntl on the master we own.
        unsafe {
            let fl = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
            libc::fcntl(master.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
        let mut tty = Vec::new();
        let mut buf = [0u8; 4096];
        while let Ok(n) = master.read(&mut buf) {
            if n == 0 {
                break;
            }
            tty.extend_from_slice(&buf[..n]);
        }
        drop(slave);
        let mut names: Vec<_> = std::fs::read_dir(&work)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        let files = names
            .into_iter()
            .map(|n| {
                let b = std::fs::read(work.join(&n)).unwrap();
                (n, b)
            })
            .collect();
        let code = status
            .code()
            .unwrap_or_else(|| -status.signal().unwrap_or(0));
        Seen { code, tty, files }
    }

    fn ours(name: &str) -> (ScratchDir, PathBuf) {
        let d = ScratchDir::unique("compress-bin");
        std::fs::create_dir_all(&*d).unwrap();
        let link = d.join(name);
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stuffr"), &link).unwrap();
        (d, link)
    }

    #[test]
    fn the_overwrite_question_matches_apple() {
        let Some(x) = fixtures() else { return };
        let both: [(&str, &[u8]); 2] = [("f", &x.f), ("f.Z", &x.fz)];
        // Name, arguments, what is typed (`None`: standard input is
        // `/dev/null`), what the terminal shows.
        type Row<'a> = (&'a str, &'a [&'a str], Option<&'a [u8]>, &'a str);
        let rows: [Row; 10] = [
            ("compress", &["f"], Some(b"y\n"), "overwrite f.Z? "),
            (
                "compress",
                &["f"],
                Some(b"n\n"),
                "overwrite f.Z? compress: f.Z already exists\r\n",
            ),
            ("compress", &["f"], Some(b"yes\n"), "overwrite f.Z? "),
            (
                "compress",
                &["f"],
                Some(b"\n"),
                "overwrite f.Z? compress: f.Z already exists\r\n",
            ),
            (
                "compress",
                &["f"],
                None,
                "overwrite f.Z? compress: f.Z already exists\r\n",
            ),
            ("uncompress", &["f.Z"], Some(b"y\n"), "overwrite f? "),
            (
                "uncompress",
                &["f.Z"],
                Some(b"n\n"),
                "overwrite f? uncompress: f already exists\r\n",
            ),
            ("uncompress", &["f.Z"], Some(b"Yes\n"), "overwrite f? "),
            (
                "uncompress",
                &["f.Z"],
                Some(b"\n"),
                "overwrite f? uncompress: f already exists\r\n",
            ),
            (
                "uncompress",
                &["f.Z"],
                None,
                "overwrite f? uncompress: f already exists\r\n",
            ),
        ];
        for (name, args, answer, seen) in rows {
            let r = run(&Path::new(DIR).join(name), name, args, &both, answer);
            let (_keep, link) = ours(name);
            let s = run(&link, name, args, &both, answer);
            let why = format!("{name} {args:?} answering {answer:?}");
            assert_eq!(String::from_utf8_lossy(&r.tty), seen, "reference, {why}");
            assert_eq!(
                (s.code, String::from_utf8_lossy(&s.tty)),
                (r.code, String::from_utf8_lossy(&r.tty)),
                "{why}"
            );
            assert!(s.files == r.files, "{why}: the directories differ");
        }
    }
}

/// Review Focus 5 (ruling E3): Apple's compress installs no signal handler,
/// so INT, TERM, HUP and QUIT kill it by their default action and leave the
/// partial output beside the intact input; an INT ignored at start stays
/// ignored and the run finishes.
#[cfg(target_os = "macos")]
mod interrupts {
    use super::common::*;
    use super::compat_harness::interrupt::*;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, OnceLock};

    const ENV: &[(&str, &str)] = &[FLAVOR];

    /// Apple's `.Z` of `big_input(mib)`, made once per size.
    fn big_z(mib: usize) -> Vec<u8> {
        static CACHE: OnceLock<Mutex<HashMap<usize, Vec<u8>>>> = OnceLock::new();
        let cache = CACHE.get_or_init(Mutex::default);
        let mut map = cache.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(mib)
            .or_insert_with(|| {
                big_input_through(&format!("{DIR}/compress"), &["-c"], mib)
                    .expect("the reference is present")
            })
            .clone()
    }

    fn exe(mine: bool, name: &str) -> PathBuf {
        if mine {
            PathBuf::from(env!("CARGO_BIN_EXE_stuffr"))
        } else {
            Path::new(DIR).join(name)
        }
    }

    #[test]
    fn a_signal_leaves_the_partial_output_and_kills() {
        let _serial = interrupt_lock();
        if !require_reference(&Path::new(DIR).join("compress")) {
            return;
        }
        type Make<'a> = &'a dyn Fn(usize) -> Vec<u8>;
        let plain: Make = &big_input;
        let packed: Make = &big_z;
        let rows: [(&str, &str, &str, Make); 2] = [
            ("compress", "big", "big.Z", plain),
            ("uncompress", "big.Z", "big", packed),
        ];
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
            for (name, input, partial, make) in rows {
                let mut seen = Vec::new();
                for mine in [false, true] {
                    let dir = ScratchDir::unique("compress-intr");
                    let named = |n: &str| n == partial;
                    let ready = has_data(&dir, &named);
                    let Some(r) = interrupt_with_input_env(
                        &exe(mine, name),
                        name,
                        &[input],
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
                    assert!(killed_by(&r, sig), "{why}: {:?}", r.status);
                    let mut want = vec![input.to_string(), partial.to_string()];
                    want.sort();
                    assert_eq!(r.left, want, "{why}");
                    // The input is intact: the bytes of the attempt that ran
                    // (64 MiB, or the retry's 256).
                    let got = std::fs::read(dir.join(input)).unwrap();
                    assert!(
                        [64, 256].iter().any(|&m| make(m) == got),
                        "{why}: the input changed"
                    );
                    assert!(r.stderr.is_empty(), "{why}: {:?}", r.stderr);
                    seen.push(r.left);
                }
                if seen.len() == 2 {
                    assert_eq!(seen[0], seen[1], "{name} signal {sig}");
                }
            }
        }
    }

    /// Deviation A2 under a signal: `compress -f big` with `big.Z` a link to
    /// `big` writes a temporary (`.stuffr-compress-*.tmp`); INT, TERM and
    /// HUP remove it and kill the run, leaving the input and the link as
    /// they were. stuffr only: Apple has already emptied `big` by then.
    #[test]
    fn a2_temporary_is_removed_on_a_signal() {
        let _serial = interrupt_lock();
        let data = big_input(64);
        for (sig, hard) in [
            (libc::SIGINT, true),
            (libc::SIGTERM, true),
            (libc::SIGHUP, true),
            (libc::SIGINT, false),
        ] {
            let dir = ScratchDir::unique("compress-intr-a2");
            std::fs::create_dir_all(&*dir).unwrap();
            std::fs::write(dir.join("big"), &data).unwrap();
            if hard {
                std::fs::hard_link(dir.join("big"), dir.join("big.Z")).unwrap();
            } else {
                std::os::unix::fs::symlink("big", dir.join("big.Z")).unwrap();
            }
            let named = |n: &str| n.starts_with(".stuffr-compress-");
            let ready = has_data(&dir, &named);
            let why = format!("signal {sig}, hard link {hard}");
            let r = interrupt_env(
                &exe(true, "compress"),
                "compress",
                &["-f", "big"],
                &dir,
                ENV,
                Inherit::Default,
                sig,
                &ready,
            )
            .unwrap_or_else(|| panic!("{why}: compress finished before the signal"));
            assert!(killed_by(&r, sig), "{why}: {:?}", r.status);
            assert_eq!(r.left, ["big", "big.Z"], "{why}: the temporary was left");
            assert!(
                std::fs::read(dir.join("big")).unwrap() == data,
                "{why}: big changed"
            );
            if hard {
                use std::os::unix::fs::MetadataExt;
                let (a, b) = (
                    std::fs::metadata(dir.join("big")).unwrap(),
                    std::fs::metadata(dir.join("big.Z")).unwrap(),
                );
                assert_eq!((a.dev(), a.ino()), (b.dev(), b.ino()), "{why}");
            } else {
                let t = std::fs::read_link(dir.join("big.Z")).unwrap();
                assert_eq!(t, Path::new("big"), "{why}");
            }
        }
    }

    /// `compress -c` killed by SIGTERM leaves only its input.
    #[test]
    fn a_signal_to_a_filter_kills_it() {
        let _serial = interrupt_lock();
        if !require_reference(&Path::new(DIR).join("compress")) {
            return;
        }
        for mine in [false, true] {
            let dir = ScratchDir::unique("compress-intr-c");
            std::fs::create_dir_all(&*dir).unwrap();
            std::fs::write(dir.join("big"), big_input(64)).unwrap();
            // Ready once compressed bytes arrive: the run is under way.
            let Some(r) = interrupt_once_stdout_has_data(
                &exe(mine, "compress"),
                "compress",
                &["-c", "big"],
                &dir,
                ENV,
                Inherit::Default,
                libc::SIGTERM,
            ) else {
                panic!("mine={mine}: compress -c finished before the signal");
            };
            assert!(killed_by(&r, libc::SIGTERM), "mine={mine}: {:?}", r.status);
            assert_eq!(r.left, ["big"], "mine={mine}");
        }
    }

    /// An INT ignored at start stays ignored: the run finishes, exit 0
    /// (on text, which compresses: random input would end in "no saving").
    #[test]
    fn an_ignored_interrupt_stays_ignored() {
        let _serial = interrupt_lock();
        if !require_reference(&Path::new(DIR).join("compress")) {
            return;
        }
        let block = text(4 << 20, 0x0018_0020);
        let big: Vec<u8> = block.iter().copied().cycle().take(32 << 20).collect();
        for mine in [false, true] {
            let dir = ScratchDir::unique("compress-intr-ign");
            std::fs::create_dir_all(&*dir).unwrap();
            std::fs::write(dir.join("big"), &big).unwrap();
            let ready = has_data(&dir, &|n: &str| n == "big.Z");
            let Some(r) = interrupt_env(
                &exe(mine, "compress"),
                "compress",
                &["big"],
                &dir,
                ENV,
                Inherit::IgnoreInt,
                libc::SIGINT,
                &ready,
            ) else {
                panic!("mine={mine}: compress finished before the signal");
            };
            assert!(r.status.success(), "mine={mine}: {:?}", r.status);
            assert_eq!(r.left, ["big.Z"], "mine={mine}");
        }
    }
}
