//! Differential tests: stuffr invoked as `gzip`, `gunzip`, `zcat` and `gzcat`
//! with `STUFFR_GZIP_FLAVOR=bsd`, against Apple's own `/usr/bin/gzip`.
//!
//! Part 1 (0.12.0 Task 9): arguments, messages and compression. Part 2
//! (Task 10) adds decompression, `-t` and `-l`.
//!
//! On the C tier (`zlib-c`) Apple's compressed bytes are promised, so every
//! output, `-v`'s ratio included, is compared byte for byte (Ruling T9-2).
//! On the compatible tier (miniz) the output is round-tripped through the
//! reference instead, its header compared through FNAME, and the ratio
//! blanked. `compat_harness::apple_compare` lists the only normalisations.
//!
//! **macOS only.** The reference exists nowhere else. Ruling P7: the
//! differential module is gated, not the file, so that elsewhere one test
//! says so instead of the file compiling to nothing.

#[cfg(not(target_os = "macos"))]
#[test]
fn apple_gzip_is_the_reference_and_exists_only_on_macos() {
    println!("skipped: the BSD gzip suite needs Apple's /usr/bin/gzip, which only macOS has");
}

#[cfg(target_os = "macos")]
mod compat_harness;

#[cfg(target_os = "macos")]
mod differential {
    use super::compat_harness::*;
    use std::path::Path;
    use std::time::{Duration, UNIX_EPOCH};

    /// The C tier promises Apple's bytes.
    const EXACT: bool = cfg!(feature = "zlib-c");

    fn case<'a>(name: &'a str, args: &[&'a str], files: Vec<(&'a str, Vec<u8>)>) -> Case<'a> {
        Case {
            name,
            args: args.to_vec(),
            files,
            stdin: None,
            tty_stdin: false,
            tty_stdout: false,
            env: vec![("STUFFR_GZIP_FLAVOR", "bsd")],
            compare_output_bytes: EXACT,
            expect_stdout_plain: None,
            setup: None,
            roundtrip: Roundtrip::Gzip {
                ref_gzip: "/usr/bin/gzip",
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

    fn tty_out(mut c: Case<'_>) -> Case<'_> {
        c.tty_stdout = true;
        c
    }

    fn typed<'a>(mut c: Case<'a>, input: &[u8]) -> Case<'a> {
        c.tty_stdin = true;
        c.stdin = Some(input.to_vec());
        c
    }

    fn kib_text() -> Vec<u8> {
        text(1024, 7)
    }

    fn check_all(group: &str, cases: &[Case]) {
        run_group(group, cases, Skipped::none(), &apple_compare);
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
    fn dangling_l_txt(d: &Path) {
        std::os::unix::fs::symlink("nowhere", d.join("l.txt")).unwrap();
    }
    /// `h.txt` becomes a hard link to `a.txt` (same bytes).
    fn hard_link_h(d: &Path) {
        std::fs::remove_file(d.join("h.txt")).unwrap();
        std::fs::hard_link(d.join("a.txt"), d.join("h.txt")).unwrap();
    }
    fn two_hard_links(d: &Path) {
        hard_link_h(d);
        std::fs::remove_file(d.join("i.txt")).unwrap();
        std::fs::hard_link(d.join("a.txt"), d.join("i.txt")).unwrap();
    }
    fn subdir(d: &Path) {
        std::fs::create_dir(d.join("d")).unwrap();
    }
    fn output_is_a_dir(d: &Path) {
        std::fs::create_dir(d.join("a.txt.gz")).unwrap();
    }
    fn output_dangles(d: &Path) {
        std::os::unix::fs::symlink("nowhere", d.join("a.txt.gz")).unwrap();
    }
    fn output_links_to_b(d: &Path) {
        std::os::unix::fs::symlink("b.txt", d.join("a.txt.gz")).unwrap();
    }
    fn unreadable(d: &Path) {
        set_mode(d, "a.txt", 0o000);
    }
    fn mode_640(d: &Path) {
        set_mode(d, "a.txt", 0o640);
    }
    fn read_only(d: &Path) {
        set_mode(d, "a.txt", 0o444);
    }
    fn setuid(d: &Path) {
        set_mode(d, "a.txt", 0o4755);
    }
    fn sticky(d: &Path) {
        set_mode(d, "a.txt", 0o1644);
    }
    /// An mtime before 1970, which the header's 32 bits cannot hold.
    fn ancient(d: &Path) {
        let t = UNIX_EPOCH - Duration::from_secs(10 * 365 * 86_400);
        std::fs::File::options()
            .write(true)
            .open(d.join("a.txt"))
            .unwrap()
            .set_modified(t)
            .unwrap();
    }
    /// `d/l` becomes a symlink to `x`, and `d/h` (a case file holding
    /// `d/x`'s bytes) a hard link to `d/x`.
    fn links_in_d(d: &Path) {
        std::os::unix::fs::symlink("x", d.join("d/l")).unwrap();
        std::fs::remove_file(d.join("d/h")).unwrap();
        std::fs::hard_link(d.join("d/x"), d.join("d/h")).unwrap();
    }
    /// `l` is a symlink to the directory `d`.
    fn link_to_d(d: &Path) {
        std::os::unix::fs::symlink("d", d.join("l")).unwrap();
    }

    // ---- groups ----

    /// Every option in Apple's `OPT_LIST` and `longopts`, alone, in long
    /// form, abbreviated and in clusters; `--` and `-`; Apple libc's
    /// `getopt_long` errors (each followed by the usage text, exit 0); `-S`'s
    /// argument rules; and the order in which stops happen. `-d`, `-l` and
    /// `-t` decompress and are Task 10's, except where an earlier stop
    /// decides the run.
    #[test]
    fn flags() {
        let t = kib_text();
        let a = || vec![("a.txt", t.clone())];
        let long31 = "abcdefghijklmnopqrstuvwxyzabcde";
        let long30 = "abcdefghijklmnopqrstuvwxyzabcd";
        let mut cases = Vec::new();
        for args in [
            &["a.txt"][..],
            &["-c", "a.txt"],
            &["--stdout", "a.txt"],
            &["--to-stdout", "a.txt"],
            &["--std", "a.txt"],
            &["--to", "a.txt"],
            &["-f", "a.txt"],
            &["--force", "a.txt"],
            &["--fo", "a.txt"],
            &["-k", "a.txt"],
            &["--keep", "a.txt"],
            &["-n", "a.txt"],
            &["--no-name", "a.txt"],
            &["--no", "a.txt"],
            &["-N", "a.txt"],
            &["--name", "a.txt"],
            &["--na", "a.txt"],
            &["-q", "a.txt"],
            &["--quiet", "a.txt"],
            &["-r", "a.txt"],
            &["--recursive", "a.txt"],
            &["-v", "a.txt"],
            &["--verbose", "a.txt"],
            &["--verb", "a.txt"],
            &["-vv", "a.txt"],
            &["-1", "a.txt"],
            &["--fast", "a.txt"],
            &["--fa", "a.txt"],
            &["-9", "a.txt"],
            &["--best", "a.txt"],
            &["--b", "a.txt"],
            &["-3", "-7", "a.txt"],
            &["-S", ".x", "a.txt"],
            &["-S.x", "a.txt"],
            &["--suffix", ".x", "a.txt"],
            &["--suffix=.x", "a.txt"],
            &["--su=.x", "a.txt"],
            &["--su", ".x", "a.txt"],
            &["-S", "_", "a.txt"],
            &["-S", long30, "a.txt"],
            &["-S", long31, "a.txt"],
            &["-S", "", "a.txt"],
            &["--suffix=", "a.txt"],
            &["-S", ".x", "-S", ".y", "a.txt"],
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
            // operands and options interleave (getopt permutes)
            &["a.txt", "-k"],
            &["a.txt", "-c"],
            &["--", "a.txt"],
            &["-c", "--", "a.txt"],
            &["-k", "a.txt", "--", "-c"],
            // unknown, ambiguous, malformed: usage, exit 0
            &["-x"],
            &["-kx", "a.txt"],
            &["a.txt", "-x"],
            &["-e", "a.txt"],
            &["--bogus"],
            &["--bogus=1", "a.txt"],
            &["--s", "a.txt"],
            &["--s=x"],
            &["--n", "a.txt"],
            &["--v", "a.txt"],
            &["--ve", "a.txt"],
            &["--l"],
            &["--li"],
            &["--f", "a.txt"],
            &["--t", "a.txt"],
            &["--=x"],
            &["--help=x"],
            &["--he=x"],
            &["--fast=1", "a.txt"],
            &["--fa=1", "a.txt"],
            &["--stdout=", "a.txt"],
            &["---"],
            &["---x"],
            &["-?"],
            &["-:"],
            &["-W"],
            &["-W", "stdout"],
            &["-Z", "a.txt"],
            &["-b", "3", "a.txt"],
            &["-H"],
            &["-m", "a.txt"],
            &["-M", "a.txt"],
            &["--lzw", "a.txt"],
            &["--rsyncable", "a.txt"],
            &["--silent", "a.txt"],
            &["--synchronous", "a.txt"],
            &["-c-", "a.txt"],
            &["-c-x", "a.txt"],
            &["-c-stdout", "a.txt"],
            &["-k-fast", "a.txt"],
            &["-c-suffix", ".z", "a.txt"],
            // `-a`: accepted, a note at the option, nothing else
            &["-a", "a.txt"],
            &["--ascii", "a.txt"],
            &["-qa", "a.txt"],
            &["-a", "-x"],
            &["-a", "-a", "-c", "a.txt"],
            // stops happen in argv order, during parsing
            &["-x", "-h"],
            &["-h", "-x"],
            &["-V", "-x"],
            &["-x", "-V"],
            &["-S", long31, "-x"],
            &["-x", "-S", long31],
            &["-a", "-V"],
            &["-S", long31, "-V"],
            &["-V", "-S", long31],
            &["-q", "-S", long31, "a.txt"],
            &["-d", "-x"],
            &["-t", "--bogus"],
            &["-l", "-h"],
        ] {
            cases.push(gz(args, a()));
        }
        // An operand named like an option, after `--`.
        cases.push(gz(&["-k", "--", "-c"], vec![("-c", t.clone())]));
        // `-` and no operand read standard input.
        for args in [
            &["-"][..],
            &[],
            &["-c", "-"],
            &["--", "-"],
            &["-n"],
            &["-N"],
            &["-1"],
            &["-9"],
            &["-v"],
            &["-vn"],
            &["-k"],
            &["-f"],
            &["-r"],
            &["-S", ".x"],
        ] {
            cases.push(fed(gz(args, vec![]), &t));
        }
        // POSIXLY_CORRECT (any value, empty too): the first operand ends the
        // options, and a bad short option is "illegal".
        for v in ["1", ""] {
            cases.push(with_env(
                gz(&["-c", "a.txt", "-v"], a()),
                "POSIXLY_CORRECT",
                v,
            ));
        }
        cases.push(with_env(gz(&["-x"], a()), "POSIXLY_CORRECT", "1"));
        cases.push(with_env(gz(&["--bogus"], a()), "POSIXLY_CORRECT", "1"));
        cases.push(with_env(
            gz(&["-k", "--", "a.txt"], a()),
            "POSIXLY_CORRECT",
            "1",
        ));
        check_all("flags", &cases);
    }

    /// `-h`/`--help` (usage), `-V`/`--version` and `-L`/`--license`: all on
    /// standard error, exit 0, at the point they appear. Usage is compared
    /// byte for byte; `-V` and `-L` name stuffr on their first line (Ruling
    /// T9-1) and the rest is compared.
    #[test]
    fn help_version_and_license() {
        let t = kib_text();
        let a = || vec![("a.txt", t.clone())];
        let mut cases = Vec::new();
        for args in [
            &["-h"][..],
            &["--help"],
            &["--h"],
            &["--he"],
            &["-hV"],
            &["-Vh"],
            &["-h", "-x"],
            &["-c", "-h", "a.txt"],
            &["a.txt", "-h"],
            &["-L"],
            &["--license"],
            &["--lic"],
            &["-LV"],
            &["-VL"],
            &["-V"],
            &["--version"],
            &["--vers"],
            &["-V", "-x"],
            &["--version", "-h"],
            &["-V", "a.txt"],
            &["a.txt", "-V"],
            &["-dV"],
            &["-qV"],
        ] {
            cases.push(gz(args, a()));
        }
        check_all("help_version_and_license", &cases);
    }

    /// Levels 1-9 and the default over six inputs, file to file with `-v`
    /// (XFL is 4 at `-1`, 2 at `-9`, else 0; OS 3); the same through a
    /// pipe, which stores the current time; `-n`/`-N`.
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
            &["-nv", "a.txt"],
        ] {
            cases.push(gz(args, vec![("a.txt", t.clone())]));
        }
        check_all("compress", &cases);
    }

    /// Several operands and standard input among them: Apple stores no name
    /// for standard input wherever it comes; a failing operand sets exit 1
    /// and the run goes on.
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
            gz(&["a.txt", "a.txt"], ab()),
            with_setup(gz(&["-v", "a.txt", "d", "nonexist"], ab()), subdir),
            with_setup(gz(&["nonexist", "d"], ab()), subdir),
            with_setup(gz(&["d", "a.txt"], ab()), subdir),
            fed(gz(&["a.txt", "-"], ab()), &input),
            fed(gz(&["-v", "a.txt", "-"], ab()), &input),
            fed(gz(&["-n", "a.txt", "-"], ab()), &input),
            fed(gz(&["-N", "-"], ab()), &input),
            fed(gz(&["-", "a.txt"], ab()), &input),
            fed(gz(&["-", "-"], ab()), &input),
            expect(fed(gz(&["-c", "a.txt", "-"], ab()), &input), &both),
            expect(
                fed(gz(&["-c", "-", "a.txt"], ab()), &input),
                &[input.clone(), a.clone()].concat(),
            ),
            // A failed output creation closes standard input (`fclose`), so
            // a later `-` cannot be stat'ed.
            fed(
                with_setup(gz(&["-f", "a.txt", "-"], ab()), output_is_a_dir),
                &input,
            ),
            fed(
                with_setup(gz(&["-f", "a.txt", "b.txt", "-"], ab()), output_is_a_dir),
                &input,
            ),
            fed(with_setup(gz(&["a.txt", "-"], ab()), unreadable), &input),
        ];
        check_all("operands", &cases);
    }

    /// The checks an operand meets, as `handle_pathname` and `file_compress`
    /// make them, and what is copied to the output.
    #[test]
    fn files() {
        let t = kib_text();
        let a = || vec![("a.txt", t.clone())];
        let al = || vec![("a.txt", t.clone()), ("l.txt", t.clone())];
        let ah = || vec![("a.txt", t.clone()), ("h.txt", t.clone())];
        let ahi = || {
            vec![
                ("a.txt", t.clone()),
                ("h.txt", t.clone()),
                ("i.txt", t.clone()),
            ]
        };
        let with_out = || vec![("a.txt", t.clone()), ("a.txt.gz", b"old".to_vec())];
        let ab = || vec![("a.txt", t.clone()), ("b.txt", b"other".to_vec())];
        let mut cases = Vec::new();
        // Symbolic links: refused unless -f or -c, which follow; -f removes
        // the link, not its target.
        for args in [
            &["l.txt"][..],
            &["-f", "l.txt"],
            &["-c", "l.txt"],
            &["-k", "l.txt"],
            &["-fk", "l.txt"],
            &["-q", "l.txt"],
            &["-fv", "l.txt"],
        ] {
            let c = with_setup(gz(args, al()), link_l_txt);
            cases.push(if args[0] == "-c" { expect(c, &t) } else { c });
        }
        for args in [&["l.txt"][..], &["-f", "l.txt"], &["-c", "l.txt"]] {
            cases.push(with_setup(gz(args, a()), dangling_l_txt));
        }
        // Hard links: "N other links" (always plural) unless -f.
        for args in [&["h.txt"][..], &["-f", "h.txt"], &["-q", "h.txt"]] {
            cases.push(with_setup(gz(args, ah()), hard_link_h));
        }
        cases.push(expect(
            with_setup(gz(&["-c", "h.txt"], ah()), hard_link_h),
            &t,
        ));
        cases.push(with_setup(gz(&["h.txt"], ahi()), two_hard_links));
        // Directories without -r.
        for args in [&["d"][..], &["-q", "d"], &["-f", "d"], &["-c", "d"]] {
            cases.push(with_setup(gz(args, a()), subdir));
        }
        // Unreadable and missing inputs.
        for args in [&["a.txt"][..], &["-q", "a.txt"], &["-c", "a.txt"]] {
            cases.push(with_setup(gz(args, a()), unreadable));
        }
        cases.push(gz(&["nonexist"], a()));
        cases.push(gz(&["-q", "nonexist"], a()));
        // An existing output: skipped (exit 1) unless -f, which unlinks it
        // first; a directory there cannot be unlinked, a dangling link
        // makes the exclusive create fail, a link to a file is replaced.
        for args in [
            &["a.txt"][..],
            &["-f", "a.txt"],
            &["-q", "a.txt"],
            &["-k", "a.txt"],
        ] {
            cases.push(gz(args, with_out()));
        }
        cases.push(expect(gz(&["-c", "a.txt"], with_out()), &t));
        for args in [&["a.txt"][..], &["-f", "a.txt"], &["-q", "a.txt"]] {
            cases.push(with_setup(gz(args, a()), output_is_a_dir));
            cases.push(with_setup(gz(args, a()), output_dangles));
            cases.push(with_setup(gz(args, ab()), output_links_to_b));
        }
        // The suffix table: exact, case-sensitive, matched against the
        // whole operand (so `d/.gz` has one and `.gz` does not).
        let suffixed = [
            "b.gz", "b.GZ", "b.tgz", "c.bz2", "d.Z", "e.xz", "f.lz", "g.tbz2", "h_z", "i.taz",
            "j.z", "k-gz", "l-z", "m.tbz", "n.Gz", "o.zip", "p.gzip", ".gz",
        ];
        for n in suffixed {
            cases.push(gz(&[n], vec![(n, t.clone())]));
        }
        cases.push(gz(&["-f", "b.gz"], vec![("b.gz", t.clone())]));
        cases.push(gz(&["-v", "-f", "b.tgz"], vec![("b.tgz", t.clone())]));
        cases.push(gz(&["d/.gz"], vec![("d/.gz", t.clone())]));
        cases.push(gz(&["-S", ".x", "b.x"], vec![("b.x", t.clone())]));
        cases.push(gz(&["-S", ".x", "b.gz"], vec![("b.gz", t.clone())]));
        cases.push(gz(&["-S", "", "b.gz"], vec![("b.gz", t.clone())]));
        cases.push(gz(&["-S", "", "b.txt"], vec![("b.txt", t.clone())]));
        cases.push(gz(
            &["-q", "b.gz", "a.txt"],
            vec![("b.gz", t.clone()), ("a.txt", t.clone())],
        ));
        // Modes, owner and times are copied; set-user-ID is kept, the
        // sticky bit dropped; the input's time goes in the header.
        for setup in [mode_640 as fn(&Path), read_only, setuid, sticky, ancient] {
            cases.push(with_setup(gz(&["a.txt"], a()), setup));
            cases.push(with_setup(gz(&["-c", "a.txt"], a()), setup));
        }
        cases.push(with_setup(gz(&["-k", "a.txt"], a()), setuid));
        cases.push(gz(&["-k", "a.txt"], a()));
        // Names: a space, 251 bytes (`.gz` makes 254) and 253 (256, too
        // long for the output).
        let n251 = "n".repeat(251);
        let n253 = "m".repeat(253);
        let n251: &'static str = Box::leak(n251.into_boxed_str());
        let n253: &'static str = Box::leak(n253.into_boxed_str());
        cases.push(gz(&["a b"], vec![("a b", t.clone())]));
        cases.push(gz(&["-v", n251], vec![(n251, t.clone())]));
        cases.push(gz(&[n253], vec![(n253, t.clone())]));
        // A suffix with a slash names a directory that is not there.
        cases.push(gz(&["-S", "x/y", "a.txt"], a()));
        check_all("files", &cases);
    }

    /// `-r`: `fts` order (the directory's own), each child named
    /// `ROOT/NAME` as given (`d/` makes `d//x`), symbolic links and other
    /// non-regular entries skipped silently, a symbolic link as the root
    /// walked as itself (nothing), and the suffix note shown.
    #[test]
    fn recursive() {
        let t = kib_text();
        let tree = || {
            vec![
                ("d/x", t.clone()),
                ("d/y.gz", t.clone()),
                ("d/e/z", text(500, 2)),
                ("d/w", text(300, 5)),
                ("a.txt", t.clone()),
            ]
        };
        let mut cases = Vec::new();
        for args in [
            &["-r", "d"][..],
            &["-rv", "d"],
            &["-rv", "d/"],
            &["-rv", "d//"],
            &["-rv", "./d"],
            &["-rq", "d"],
            &["-rk", "d"],
            &["-r", "a.txt"],
            &["-rv", "a.txt", "d"],
            &["-rf", "d"],
            &["-rS", ".x", "d"],
        ] {
            cases.push(gz(args, tree()));
        }
        let linked = || {
            let mut v = tree();
            v.push(("d/h", t.clone()));
            v
        };
        cases.push(with_setup(gz(&["-rv", "d"], linked()), links_in_d));
        cases.push(with_setup(gz(&["-rfv", "d"], linked()), links_in_d));
        // To standard output: one regular file, so the stream's order is
        // known on the compatible tier too.
        for args in [&["-rc", "d"][..], &["-rcv", "d"]] {
            cases.push(expect(
                gz(args, vec![("d/x", t.clone()), ("d/e.gz", t.clone())]),
                &[t.clone(), t.clone()].concat(),
            ));
        }
        for args in [&["-r", "l"][..], &["-rf", "l"], &["-rc", "l"], &["-f", "l"]] {
            cases.push(with_setup(gz(args, tree()), link_to_d));
        }
        cases.push(gz(
            &["-rv", "d"],
            vec![("d/x", t.clone()), ("d/x.gz", b"old".to_vec())],
        ));
        check_all("recursive", &cases);
    }

    /// A terminal on standard output refuses only standard input (exit 1,
    /// the run goes on); a terminal on standard input is asked about an
    /// existing output, `fgets` reading at most 8 bytes of the answer.
    #[test]
    fn terminals() {
        let t = kib_text();
        let a = || vec![("a.txt", t.clone())];
        let input = text(200, 4);
        let with_out = || vec![("a.txt", t.clone()), ("a.txt.gz", b"old".to_vec())];
        let two_out = || {
            vec![
                ("a.txt", t.clone()),
                ("a.txt.gz", b"old".to_vec()),
                ("b.txt", t.clone()),
                ("b.txt.gz", b"old".to_vec()),
            ]
        };
        let mut cases = vec![
            tty_out(fed(gz(&[], a()), &input)),
            tty_out(fed(gz(&["-q"], a()), &input)),
            tty_out(fed(gz(&["-v"], a()), &input)),
            tty_out(fed(gz(&["-", "a.txt"], a()), &input)),
            tty_out(fed(gz(&["a.txt", "-"], a()), &input)),
        ];
        // Compressed bytes on a terminal arrive translated (`\n` as
        // `\r\n`), so only the C tier, which compares them byte for byte,
        // can judge them.
        let mut skipped = Skipped::none();
        let on_tty = vec![
            tty_out(gz(&["-c", "a.txt"], a())),
            tty_out(fed(gz(&["-f"], a()), &input)),
        ];
        if EXACT {
            cases.extend(on_tty);
        } else {
            skipped.add(
                on_tty.len(),
                "2 compressed to a terminal (byte-compared on the C tier only)",
            );
        }
        for answer in [&b"y\n"[..], b"Y\n", b"yes\n", b"n\n", b"\n", b"", b"x\n"] {
            cases.push(typed(gz(&["a.txt"], with_out()), answer));
        }
        cases.push(typed(gz(&["-q", "a.txt"], with_out()), b"n\n"));
        cases.push(typed(gz(&["-k", "a.txt"], with_out()), b"y\n"));
        for answer in [&b"n\ny\n"[..], b"y\nn\n", b"yes please\n", b"nyyyyyyyyy\n"] {
            cases.push(typed(gz(&["a.txt", "b.txt"], two_out()), answer));
        }
        // Standard input a terminal: compressed, never refused.
        cases.push(typed(gz(&[], a()), b"typed at a terminal\n"));
        run_group("terminals", &cases, skipped, &apple_compare);
    }

    /// `$GZIP` (`prepend_gzip`): split on spaces and tabs, put before the
    /// arguments, parsed by the same getopt with its errors and stops.
    #[test]
    fn gzip_env() {
        let t = kib_text();
        let a = || vec![("a.txt", t.clone())];
        let mut cases = Vec::new();
        for (v, args) in [
            ("-9", &["a.txt"][..]),
            ("-1", &["-c", "a.txt"]),
            ("-v -k", &["a.txt"]),
            ("-c", &["a.txt"]),
            ("-x", &["a.txt"]),
            ("  -1   -n\t-c ", &["a.txt"]),
            ("-S .z", &["a.txt"]),
            ("-V", &["a.txt"]),
            ("-- -c", &["a.txt"]),
            ("", &["a.txt"]),
            (" ", &["-c", "a.txt"]),
            ("-q", &["nonexist"]),
            ("-1\n-9", &["a.txt"]),
            ("-c a.txt", &[]),
            ("--fast", &["-9", "a.txt"]),
            ("-a", &["-c", "a.txt"]),
        ] {
            cases.push(with_env(gz(args, a()), "GZIP", v));
        }
        // `-S` takes the first operand as its suffix: standard input (empty)
        // is compressed.
        cases.push(expect(with_env(gz(&["a.txt"], a()), "GZIP", "-S"), b""));
        check_all("gzip_env", &cases);
    }

    /// The other names: every message carries the invoked name
    /// (`getprogname`), and the usage line too. Their decompression is
    /// Task 10's; here only what stops before it.
    #[test]
    fn dispatch() {
        let t = kib_text();
        let a = || vec![("a.txt", t.clone())];
        let long31 = "abcdefghijklmnopqrstuvwxyzabcde";
        let mut cases = Vec::new();
        for name in ["gzip", "gunzip", "zcat", "gzcat"] {
            for args in [
                &["-h"][..],
                &["-V"],
                &["-L"],
                &["-x"],
                &["--bogus"],
                &["-S", long31],
                &["-a", "-h"],
            ] {
                cases.push(case(name, args, a()));
            }
        }
        cases.push(fed(gz(&[], vec![]), &t));
        check_all("dispatch", &cases);
    }

    /// `print_ratio`'s edges through `-v`: empty input (-99.9%: the output
    /// more than doubles it), one byte, inputs that barely compress, and
    /// sizes past the 32-bit reduction (`in > 0x100000`).
    #[test]
    fn ratio() {
        let mut cases = Vec::new();
        for (name, data) in [
            ("e", vec![]),
            ("one", b"q".to_vec()),
            ("ten", b"0123456789".to_vec()),
            ("r40", random(40, 3)),
            ("r4k", random(4096, 4)),
            ("t2m", text(2 << 20, 5)),
            ("z3m", vec![0u8; 3 << 20]),
        ] {
            cases.push(gz(&["-v", name], vec![(name, data.clone())]));
            cases.push(gz(&["-cv", name], vec![(name, data.clone())]));
            cases.push(fed(gz(&["-v"], vec![]), &data));
        }
        check_all("ratio", &cases);
    }
}
