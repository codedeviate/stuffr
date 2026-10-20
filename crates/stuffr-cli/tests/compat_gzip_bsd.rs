//! Differential tests: stuffr invoked as `gzip`, `gunzip`, `zcat` and `gzcat`
//! with `STUFFR_GZIP_FLAVOR=bsd`, against Apple's own `/usr/bin/gzip`.
//!
//! Part 1 (0.12.0 Task 9): arguments, messages and compression. Part 2
//! (Task 10): decompression, `-t`, `-l` and `-r`, the foreign formats, and
//! the review focus pins.
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

    /// The C tier decodes xz with liblzma, as Apple does.
    const LIBLZMA: bool = cfg!(feature = "xz-c");

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
            tz: None,
            unzip_flavour: None,
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
    /// `a.txt` (a case file holding `a.txt.gz`'s bytes) becomes a symlink
    /// to `a.txt.gz`: the output is the input itself.
    fn input_is_the_output(d: &Path) {
        std::fs::remove_file(d.join("a.txt")).unwrap();
        std::os::unix::fs::symlink("a.txt.gz", d.join("a.txt")).unwrap();
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
        // The output is the input itself (`a.txt` -> `a.txt.gz`): with -f
        // gzip replaces it and keeps the link; without, it is not a regular
        // file.
        let same = || vec![("a.txt.gz", t.clone()), ("a.txt", t.clone())];
        for args in [
            &["-f", "a.txt"][..],
            &["-fv", "a.txt"],
            &["-fk", "a.txt"],
            &["a.txt"],
        ] {
            cases.push(with_setup(gz(args, same()), input_is_the_output));
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

    // ---- part 2: decompression, -t, -l and -r (Task 10) ----
    //
    // Inputs are built here (gzip members by hand over flate2's raw
    // deflate, pack by a small encoder, bzip2, xz, lzip and `.Z` by
    // stuffr's own encoders), so both sides read the same bytes and every
    // output, ratio included, is compared exactly.

    /// A decompression case: outputs are plain, compared byte for byte.
    fn dz<'a>(name: &'a str, args: &[&'a str], files: Vec<(&'a str, Vec<u8>)>) -> Case<'a> {
        let mut c = case(name, args, files);
        c.compare_output_bytes = true;
        c
    }

    fn check_exact(group: &str, cases: &[Case], skipped: Skipped) {
        run_group(group, cases, skipped, &apple_compare);
    }

    fn txt() -> Vec<u8> {
        text(20_000, 21)
    }

    /// Several of gzip's 64 KiB buffers long, so what reaches standard
    /// output before a failure shows its buffer boundaries.
    fn big_txt() -> Vec<u8> {
        text(300_000, 22)
    }

    fn with_tty_stdin<'a>(mut c: Case<'a>, input: &[u8]) -> Case<'a> {
        c.tty_stdin = true;
        c.stdin = Some(input.to_vec());
        c
    }

    /// `a.gz` (a case file) becomes a symlink to `b.gz`.
    fn a_gz_links_to_b(d: &Path) {
        std::fs::remove_file(d.join("a.gz")).unwrap();
        std::os::unix::fs::symlink("b.gz", d.join("a.gz")).unwrap();
    }
    /// `h.gz` becomes a hard link to `a.gz`.
    fn h_gz_hard_links_a(d: &Path) {
        std::fs::remove_file(d.join("h.gz")).unwrap();
        std::fs::hard_link(d.join("a.gz"), d.join("h.gz")).unwrap();
    }
    fn a_gz_640(d: &Path) {
        set_mode(d, "a.gz", 0o640);
    }
    fn a_gz_setuid(d: &Path) {
        set_mode(d, "a.gz", 0o4755);
    }
    fn a_gz_sticky(d: &Path) {
        set_mode(d, "a.gz", 0o1644);
    }
    fn a_gz_unreadable(d: &Path) {
        set_mode(d, "a.gz", 0o000);
    }
    fn dir_a(d: &Path) {
        std::fs::create_dir(d.join("a")).unwrap();
    }

    /// Every name and suffix that decompresses (`.gz .z -gz -z _z .taz
    /// .tgz .bz2 .tbz .tbz2 .Z .xz .lz`, case-sensitive, and `-S`'s), and
    /// unknown ones; `zcat`'s `.Z` (Unix 2003 mode, unless `COMMAND_MODE`
    /// says `legacy` or `-f`); an operand found by adding `.gz`; `-N`, `-n`
    /// and neither; several members; existing outputs; links and modes.
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
            ("a.tbz2", &[]),
            ("a.bz2", &[]),
            ("a.Z", &[]),
            ("a.xz", &[]),
            ("a.lz", &[]),
            ("a.GZ", &[]),
            ("a_Z", &[]),
            ("a.x", &["-S", ".x"]),
            ("a.x", &["--suffix=.x"]),
            ("a.x", &[]),
            ("a.gzip", &[]),
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
            cases.push(dz("gzcat", &[file], vec![(file, g())]));
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
            &["-df", "a.gz"],
            &["--decompress", "a.gz"],
            &["--uncompress", "a.gz"],
            &["--stdout", "-d", "a.gz"],
            &["-dq", "a.x"],
            &["-dv", "a.x"],
            &["-df", "a.x"],
            &["-dv", "a.gz", "a.x", "a.gz"],
        ] {
            cases.push(dz("gzip", args, vec![("a.gz", g()), ("a.x", g())]));
        }
        for name in ["gunzip", "zcat", "gzcat"] {
            for args in [&["a.gz"][..], &["-v", "a.gz"], &["-N", "a.gz"], &["-"], &[]] {
                cases.push(fed(dz(name, args, vec![("a.gz", g())]), &g()));
            }
        }
        cases.push(fed(dz("gzip", &["-dv"], vec![]), &g()));
        cases.push(fed(
            dz("gzip", &["-dcv", "-", "a.gz"], vec![("a.gz", g())]),
            &g(),
        ));
        // `zcat` (not `gzcat`) adds `.Z` to an operand not ending in it,
        // unless -f or `COMMAND_MODE=legacy` (any case); nothing else
        // retries.
        let zfiles = || {
            vec![
                ("a.gz", g()),
                ("b.Z", g()),
                ("c", g()),
                ("c.Z", gzm(b"cz\n", b"c")),
            ]
        };
        for (args, env) in [
            (&["a.gz"][..], None),
            (&["b.Z"], None),
            (&["b"], None),
            (&["c"], None),
            (&["-f", "a.gz"], None),
            (&["-v", "a.gz", "b.Z"], None),
            (&["a.gz"], Some("legacy")),
            (&["a.gz"], Some("LEGACY")),
            (&["a.gz"], Some("unix2003")),
            (&["a.gz"], Some("bogus")),
            (&["c"], Some("legacy")),
        ] {
            let c = dz("zcat", args, zfiles());
            cases.push(match env {
                Some(v) => with_env(c, "COMMAND_MODE", v),
                None => c,
            });
            cases.push(dz("gzcat", args, zfiles()));
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
        let unnamed = member(Member {
            mtime: 1_234_567_890,
            ..plain_member(&t)
        });
        // `-N` reads the name at offset 10 whatever FEXTRA says, so with
        // FEXTRA the "name" is the extra field's bytes.
        let extra_named = member(Member {
            name: Some(b"real.txt"),
            extra: Some(b"AB\x04\x00wxyz"),
            mtime: 1_234_567_890,
            ..plain_member(&t)
        });
        let slash_extra = member(Member {
            name: Some(b"real.txt"),
            extra: Some(b"/\x00ab"),
            ..plain_member(&t)
        });
        for args in [
            &["-dN", "s.gz"][..],
            &["-d", "s.gz"],
            &["-dkN", "s.gz", "u.gz"],
            &["-dN", "n.gz"],
            &["-dNv", "d/s.gz"],
            &["-dNc", "s.gz"],
            &["-dN", "x.gz"],
            &["-lN", "x.gz"],
            &["-dN", "y.gz"],
        ] {
            cases.push(dz(
                "gzip",
                args,
                vec![
                    ("s.gz", stamped.clone()),
                    ("u.gz", unstamped.clone()),
                    ("n.gz", unnamed.clone()),
                    ("d/s.gz", stamped.clone()),
                    ("x.gz", extra_named.clone()),
                    ("y.gz", slash_extra.clone()),
                ],
            ));
        }
        // Several members: decoded in turn.
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
        cases.push(fed(dz("gzcat", &[], vec![]), &multi));
        // An operand that does not exist is looked for with `.gz` (or
        // `-S`'s) added, and nothing else.
        for (args, files) in [
            (&["-d", "a"][..], vec![("a.gz", g())]),
            (&["-d", "a"], vec![("a.z", g())]),
            (&["-dc", "a"], vec![("a-gz", g())]),
            (
                &["-d", "-S", ".x", "a"],
                vec![("a.x", g()), ("a.gz", gzm(b"other", b"o"))],
            ),
            (&["-d", "a.tar"], vec![("a.tgz", g())]),
            (&["-d", "nonexist"], vec![]),
            (&["-dc", "nonexist"], vec![]),
            (&["-dq", "nonexist"], vec![]),
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
            &["-dNf", "a.gz"],
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
        for answer in [&b"y\n"[..], b"n\n", b"Yes\n", b""] {
            cases.push(with_tty_stdin(
                dz(
                    "gzip",
                    &["-d", "a.gz"],
                    vec![("a.gz", g()), ("a", b"old".to_vec())],
                ),
                answer,
            ));
        }
        // Links, modes and directories, as compression checks them.
        let ab = || vec![("a.gz", g()), ("b.gz", gzm(b"bee\n", b"b"))];
        cases.extend([
            with_setup(dz("gzip", &["-d", "a.gz"], ab()), a_gz_links_to_b),
            with_setup(dz("gzip", &["-df", "a.gz"], ab()), a_gz_links_to_b),
            with_setup(dz("gzip", &["-dc", "a.gz"], ab()), a_gz_links_to_b),
            with_setup(
                dz("gzip", &["-d", "h.gz"], vec![("a.gz", g()), ("h.gz", g())]),
                h_gz_hard_links_a,
            ),
            with_setup(
                dz("gzip", &["-df", "h.gz"], vec![("a.gz", g()), ("h.gz", g())]),
                h_gz_hard_links_a,
            ),
            with_setup(
                dz("gzip", &["-dc", "h.gz"], vec![("a.gz", g()), ("h.gz", g())]),
                h_gz_hard_links_a,
            ),
            with_setup(dz("gzip", &["-d", "a.gz"], vec![("a.gz", g())]), a_gz_640),
            with_setup(
                dz("gzip", &["-d", "a.gz"], vec![("a.gz", g())]),
                a_gz_setuid,
            ),
            with_setup(
                dz("gzip", &["-d", "a.gz"], vec![("a.gz", g())]),
                a_gz_sticky,
            ),
            with_setup(
                dz("gzip", &["-d", "a.gz"], vec![("a.gz", g())]),
                a_gz_unreadable,
            ),
            with_setup(dz("gzip", &["-d", "d"], vec![("a.gz", g())]), subdir),
            with_setup(dz("gzip", &["-dc", "d"], vec![("a.gz", g())]), subdir),
        ]);
        // An output that is a directory: refused, and under -f unlinked
        // first, which fails; the run goes on.
        for args in [
            &["-d", "a.gz", "b.gz"][..],
            &["-df", "a.gz", "b.gz"],
            &["-dfv", "a.gz", "b.gz"],
        ] {
            cases.push(with_setup(
                dz("gzip", args, vec![("a.gz", g()), ("b.gz", g())]),
                dir_a,
            ));
        }
        // `-S ''` makes the empty suffix match any name, so the output is
        // the input itself: refused, or with -f replaced by its contents.
        for args in [
            &["-d", "-S", "", "plain"][..],
            &["-df", "-S", "", "plain"],
            &["-dfv", "-S", "", "plain"],
            &["-dc", "-S", "", "plain"],
        ] {
            cases.push(dz("gzip", args, vec![("plain", g())]));
        }
        check_exact("decompress", &cases, Skipped::none());
    }

    /// Every row of the spec's divergence table in Apple's column, and
    /// the inputs around them: nothing of a cut-short member reaches
    /// standard output (only whole 64 KiB buffers of a long one); a CRC
    /// error writes the data, then says so on two lines; trailing bytes,
    /// NULs included, are a warning with exit 2; an unknown option is
    /// usage with exit 0 under every name; `-l` reports the last member's
    /// size; a terminal on standard output is no obstacle to
    /// decompression, one on standard input is.
    #[test]
    fn probe_table() {
        let t = txt();
        let bt = big_txt();
        let good = gzm(&t, b"a");
        let crc_bad = member_with(plain_member(&t), Some(0x1234_5678), None);
        let len_bad = member_with(plain_member(&t), None, Some(5));
        let cut = good[..good.len() / 2].to_vec();
        let cut_trailer = good[..good.len() - 3].to_vec();
        let cut_len = good[..good.len() - 4].to_vec();
        let cut_header = good[..6].to_vec();
        let junk = [good.clone(), b"junk".to_vec()].concat();
        let nuls = [good.clone(), vec![0; 100]].concat();
        let one_nul = [good.clone(), vec![0]].concat();
        let mixed_tail = [good.clone(), b"\0\0x".to_vec()].concat();
        let lone_1f = [good.clone(), vec![0x1f]].concat();
        let bad_magic2 = [good.clone(), b"\x1f\x00junk".to_vec()].concat();
        let bad_method = [good.clone(), b"\x1f\x8b\x07\x00".to_vec()].concat();
        let corrupt = {
            let mut b = member(plain_member(&t));
            b[10..14].copy_from_slice(&[0xff; 4]);
            b
        };
        let big = gzm(&bt, b"big");
        let big_cut = big[..big.len() * 2 / 3].to_vec();
        let big_crc = member_with(plain_member(&bt), Some(7), None);
        let big_corrupt = {
            let mut b = big.clone();
            let at = b.len() * 3 / 4;
            b[at..at + 8].copy_from_slice(&[0xff; 8]);
            b
        };
        let mut cases = Vec::new();
        for (file, bytes) in [
            ("junk.gz", &junk),
            ("nuls.gz", &nuls),
            ("onenul.gz", &one_nul),
            ("mixed.gz", &mixed_tail),
            ("lone1f.gz", &lone_1f),
            ("magic2.gz", &bad_magic2),
            ("method.gz", &bad_method),
            ("crc.gz", &crc_bad),
            ("len.gz", &len_bad),
            ("cut.gz", &cut),
            ("trailer.gz", &cut_trailer),
            ("cutlen.gz", &cut_len),
            ("header.gz", &cut_header),
            ("corrupt.gz", &corrupt),
            ("notgz.gz", &t),
            ("big.gz", &big),
            ("bigcut.gz", &big_cut),
            ("bigcrc.gz", &big_crc),
            ("bigbad.gz", &big_corrupt),
        ] {
            for args in [
                &["-dc"][..],
                &["-dcv"],
                &["-dcq"],
                &["-d"],
                &["-dv"],
                &["-dk"],
                &["-dcf"],
                &["-df"],
            ] {
                let mut a = args.to_vec();
                a.push(file);
                cases.push(dz("gzip", &a, vec![(file, bytes.clone())]));
            }
            cases.push(fed(dz("gzcat", &[], vec![]), bytes));
            cases.push(fed(dz("gzip", &["-dcv"], vec![]), bytes));
        }
        // An unknown option under each name: usage, exit 0.
        for name in ["gzip", "gunzip", "zcat", "gzcat"] {
            cases.push(dz(name, &["-x", "a.gz"], vec![("a.gz", good.clone())]));
            cases.push(dz(name, &["-Z", "a.gz"], vec![("a.gz", good.clone())]));
        }
        // A terminal on standard output: decompressed output is written.
        for (name, args) in [
            ("gzcat", &["a.gz"][..]),
            ("gunzip", &["-c", "a.gz"]),
            ("gzip", &["-d"]),
            ("gzip", &["-dc", "-"]),
        ] {
            let mut c = fed(
                dz(name, args, vec![("a.gz", gzm(b"hi there\n", b"a"))]),
                &good,
            );
            c.tty_stdout = true;
            cases.push(c);
        }
        // A terminal on standard input is refused under -d and -t (the run
        // goes on), unless -f; -l reads it.
        for (name, args) in [
            ("gunzip", &[][..]),
            ("gzip", &["-d"]),
            ("gzip", &["-dq"]),
            ("gzip", &["-t"]),
            ("gzcat", &[]),
            ("gzip", &["-d", "-", "a.gz"]),
            ("gzip", &["-d", "nonexist", "-"]),
            ("gzip", &["-l"]),
            ("gzip", &["-df"]),
        ] {
            cases.push(with_tty_stdin(
                dz(name, args, vec![("a.gz", good.clone())]),
                b"",
            ));
        }
        // `-l` on two members: the last member's size.
        let two = [good.clone(), gzm(b"second\n", b"b")].concat();
        cases.push(dz("gzip", &["-l", "two.gz"], vec![("two.gz", two.clone())]));
        cases.push(dz("gzip", &["-lv", "two.gz"], vec![("two.gz", two)]));
        check_exact("probe_table", &cases, Skipped::none());
    }

    /// The formats Apple's `gunzip` reads besides gzip, each worded as its
    /// decoder words a failure (`unbzip2.c`, `unxz.c`, `unlz.c`,
    /// `unpack.c`, `zuncompress.c`), and the ones it refuses (`.zst`,
    /// `.lz4`, zip: "not in gzip format").
    #[test]
    fn foreign_formats() {
        let t = txt();
        let bt = big_txt();
        // bzip2: whole, two streams, cut, a block CRC broken, trailing
        // garbage.
        let bz = stuffr_encode("bzip2", &t, None);
        let bz_two = [bz.clone(), stuffr_encode("bzip2", b"again\n", None)].concat();
        let bz_cut = bz[..bz.len() / 2].to_vec();
        let mut bz_crc = bz.clone();
        bz_crc[10] ^= 0xff; // the block CRC
        let bz_junk = [bz.clone(), b"junk".to_vec()].concat();
        let bz_big = stuffr_encode("bzip2", &bt, Some(1));
        let mut bz_big_bad = bz_big.clone();
        let at = bz_big.len() * 3 / 4;
        bz_big_bad[at] ^= 0x55;
        // xz: whole, two streams, padding, cut, trailing garbage short and
        // long, a broken header, too short, a wrong magic byte.
        let xz = stuffr_encode("xz", &t, None);
        let xz_two = [xz.clone(), stuffr_encode("xz", b"again\n", None)].concat();
        let xz_pad = [xz.clone(), vec![0; 4]].concat();
        let xz_cut_footer = xz[..xz.len() - 3].to_vec();
        let xz_cut = xz[..xz.len() / 2].to_vec();
        let xz_junk = [xz.clone(), b"junk".to_vec()].concat();
        let xz_long_junk = [xz.clone(), b"junk that is long enough".to_vec()].concat();
        let mut xz_hdr = xz.clone();
        xz_hdr[8] ^= 0xff; // the stream header's CRC32
        let xz_short = xz[..7].to_vec();
        let mut xz_magic = xz.clone();
        xz_magic[4] = b'Q';
        // lzip: whole, two members (Apple reads the first), cut, a broken
        // trailer, a bad version, a bad dictionary size, trailing junk.
        let lz = stuffr_encode("lzip", &t, None);
        let lz_two = [lz.clone(), stuffr_encode("lzip", b"again\n", None)].concat();
        let lz_cut = lz[..lz.len() / 2].to_vec();
        let lz_cut_trailer = lz[..lz.len() - 5].to_vec();
        let mut lz_crc = lz.clone();
        let n = lz.len();
        lz_crc[n - 20] ^= 0xff;
        let mut lz_version = lz.clone();
        lz_version[4] = 2;
        let mut lz_dict = lz.clone();
        lz_dict[5] = 0x1f; // 2 GiB, past MAX_DICTIONARY_SIZE
        let lz_junk = [lz.clone(), b"junk".to_vec()].concat();
        // Fraction bits: unlz.c takes quarters off, lzip sixteenths.
        let mut lz_frac = lz.clone();
        lz_frac[5] |= 1 << 5;
        let mut lz_frac4 = lz.clone();
        lz_frac4[5] |= 4 << 5;
        // Five quarters take more than there is: unlz.c's unsigned
        // subtraction wraps and the header is refused.
        let mut lz_frac5 = lz.clone();
        lz_frac5[5] |= 5 << 5;
        let mut lz_frac7 = lz.clone();
        lz_frac7[5] = 31 | (7 << 5);
        let mut lz_bad = lz.clone();
        let at = lz.len() / 2;
        lz_bad[at..at + 4].copy_from_slice(&[0xff; 4]);
        // .Z: whole at 16 and 12 bits, 9 bits (refused below 12), cut, a
        // broken header, bad codes early and late (output comes in 64 KiB
        // pieces, the failing piece lost).
        let z = stuffr_encode("compress", &t, None);
        let z12 = stuffr_encode("compress", &t, Some(12));
        let z9 = stuffr_encode("compress", &t, Some(9));
        let z_cut = z[..z.len() / 3].to_vec();
        let z_hdr = b"\x1f\x9d".to_vec();
        let z_one = b"\x1f\x9d\x90\x41".to_vec();
        let zb = stuffr_encode("compress", &bt, None);
        let z_bad = |at: usize| {
            let mut b = zb.clone();
            b[at..at + 6].copy_from_slice(&[0xff; 6]);
            b
        };
        // pack: the cases unpack.c words differently.
        let p = pack(&t);
        let p_cut = p[..p.len() / 2].to_vec();
        let p_apple = b"\x1f\x1e\x00\x00\x00\x08\x03\x01\x00\x00AB\x80".to_vec();
        let p_levels_cut = b"\x1f\x1e\x00\x00\x00\x08\x03\x01".to_vec();
        let p_symbols_cut = b"\x1f\x1e\x00\x00\x00\x08\x03\x01\x00\x00A".to_vec();
        let p_no_bits = b"\x1f\x1e\x00\x00\x00\x08\x03\x01\x00\x00AB".to_vec();
        let p_past = b"\x1f\x1e\x00\x00\x00\x04\x03\x01\x00\x00AB\x80\x00".to_vec();
        let p_short = b"\x1f\x1e\x00\x00\x00\x0a\x03\x01\x00\x00AB\x80".to_vec();
        let p_insane = b"\x1f\x1e\x00\x00\x00\x08\x1a".to_vec();
        let p_table = [&b"\x1f\x1e\x00\x00\x00\x08\x02\xff\xff"[..], &[0; 600]].concat();
        let p_junk = [p.clone(), b"junk".to_vec()].concat();
        let old = member(Member {
            magic2: 0x9e,
            name: Some(b"old"),
            ..plain_member(&t)
        });
        let gz_then = |tail: &[u8]| [gzm(b"first\n", b"f"), tail.to_vec()].concat();
        let inputs: Vec<(&str, Vec<u8>)> = vec![
            ("a.bz2", bz.clone()),
            ("two.bz2", bz_two),
            ("cut.bz2", bz_cut.clone()),
            ("crc.bz2", bz_crc.clone()),
            ("junk.bz2", bz_junk),
            ("bigbad.bz2", bz_big_bad.clone()),
            ("a.xz", xz.clone()),
            ("two.xz", xz_two),
            ("pad.xz", xz_pad),
            ("footer.xz", xz_cut_footer),
            ("cut.xz", xz_cut.clone()),
            ("junk.xz", xz_junk),
            ("longjunk.xz", xz_long_junk),
            ("hdr.xz", xz_hdr),
            ("short.xz", xz_short),
            ("magic.xz", xz_magic),
            ("a.lz", lz.clone()),
            ("two.lz", lz_two),
            ("cut.lz", lz_cut.clone()),
            ("trailer.lz", lz_cut_trailer),
            ("crc.lz", lz_crc),
            ("version.lz", lz_version),
            ("dict.lz", lz_dict),
            ("junk.lz", lz_junk),
            ("frac.lz", lz_frac),
            ("frac4.lz", lz_frac4),
            ("frac5.lz", lz_frac5),
            ("frac7.lz", lz_frac7),
            ("bad.lz", lz_bad.clone()),
            ("a.Z", z.clone()),
            ("b12.Z", z12),
            ("b9.Z", z9),
            ("cut.Z", z_cut),
            ("hdr.Z", z_hdr),
            ("one.Z", z_one),
            ("early.Z", z_bad(500)),
            ("late.Z", z_bad(zb.len() * 3 / 4)),
            ("p.z", p.clone()),
            ("cut.z", p_cut.clone()),
            ("apple.z", p_apple),
            ("levels.z", p_levels_cut.clone()),
            ("symbols.z", p_symbols_cut),
            ("nobits.z", p_no_bits),
            ("past.z", p_past),
            ("short.z", p_short),
            ("insane.z", p_insane),
            ("table.z", p_table),
            ("junk.z", p_junk),
            ("old.gz", old.clone()),
            ("gzZ.gz", gz_then(&z)),
            ("gzp.gz", gz_then(&p)),
            ("gzbz.gz", gz_then(&bz)),
            ("gzold.gz", gz_then(&old)),
            ("a.zst", b"\x28\xb5\x2f\xfd\x00\x00\x00\x00".to_vec()),
            ("a.lz4", b"\x04\x22\x4d\x18\x64\x40\xa7\x00".to_vec()),
            ("a.zip", zip1(&t, 8, 0)),
        ];
        // Off the C tier, xz is stuffr's pure decoder, not Apple's
        // liblzma: what it has decoded when a stream fails, and whether
        // short trailing bytes are a cut-short stream, are its own.
        let pure_xz = |file: &str| !LIBLZMA && ["cut.xz", "junk.xz", "longjunk.xz"].contains(&file);
        let mut not_on_this_tier = 0;
        let mut cases = Vec::new();
        for (file, bytes) in &inputs {
            let mut these = Vec::new();
            for args in [
                &["-dc"][..],
                &["-dcv"],
                &["-dcq"],
                &["-t"],
                &["-tv"],
                &["-l"],
                &["-lv"],
                &["-dcf"],
            ] {
                let mut a = args.to_vec();
                a.push(file);
                these.push(dz("gzip", &a, vec![(file, bytes.clone())]));
            }
            these.push(fed(dz("gzcat", &[], vec![]), bytes));
            these.push(fed(dz("gzip", &["-tv"], vec![]), bytes));
            if pure_xz(file) {
                // -l reads the index only, and agrees.
                let (keep, skip): (Vec<_>, Vec<_>) = these
                    .into_iter()
                    .partition(|c| c.args.iter().any(|a| a.starts_with("-l")));
                not_on_this_tier += skip.len();
                cases.extend(keep);
            } else {
                cases.extend(these);
            }
        }
        // To a file, alone and with a good file after it: whether the run
        // goes on, and what is left of the output.
        for (args, file) in [
            (&["-d"][..], "a.bz2"),
            (&["-dv"], "a.bz2"),
            (&["-d"], "cut.bz2"),
            (&["-d"], "crc.bz2"),
            (&["-dk"], "bigbad.bz2"),
            (&["-d"], "a.xz"),
            (&["-dv"], "a.xz"),
            (&["-d"], "cut.xz"),
            (&["-d"], "hdr.xz"),
            (&["-d"], "a.lz"),
            (&["-dv"], "a.lz"),
            (&["-d"], "cut.lz"),
            (&["-d"], "bad.lz"),
            (&["-d"], "a.Z"),
            (&["-dv"], "a.Z"),
            (&["-d"], "b9.Z"),
            (&["-d"], "late.Z"),
            (&["-d"], "cut.Z"),
            (&["-d", "-S", ".z"], "p.z"),
            (&["-d", "-S", ".z"], "cut.z"),
            (&["-d", "-S", ".z"], "levels.z"),
            (&["-d"], "old.gz"),
            (&["-dN"], "old.gz"),
            (&["-d"], "gzZ.gz"),
            (&["-d"], "a.zst"),
            (&["-df"], "a.zst"),
            (&["-dfv"], "a.zst"),
        ] {
            if pure_xz(file) {
                not_on_this_tier += 2;
                continue;
            }
            let bytes = || inputs.iter().find(|(n, _)| *n == file).unwrap().1.clone();
            let mut a = args.to_vec();
            a.push(file);
            cases.push(dz(
                "gzip",
                &a,
                vec![(file, bytes()), ("z.gz", gzm(&t, b"z"))],
            ));
            let mut b = a.clone();
            b.push("z.gz");
            cases.push(dz(
                "gzip",
                &b,
                vec![(file, bytes()), ("z.gz", gzm(&t, b"z"))],
            ));
        }
        // `-l` across formats: xz's line has no header of its own and no
        // part in the totals.
        let all = || {
            vec![
                ("a.xz", xz.clone()),
                ("a.gz", gzm(&t, b"a")),
                ("a.bz2", bz.clone()),
                ("b.gz", gzm(b"bee\n", b"b")),
            ]
        };
        for args in [
            &["-l", "a.xz", "a.gz", "a.bz2", "b.gz"][..],
            &["-lv", "a.gz", "a.xz", "b.gz"],
            &["-lq", "a.xz", "a.gz"],
            &["-lt", "a.xz", "a.gz"],
            &["-ltv", "a.xz", "a.gz"],
        ] {
            cases.push(dz("gzip", args, all()));
        }
        // The stale `errno` unpack.c appends to "File appears to be
        // truncated": what the last failed call left.
        for (args, stdin) in [
            (&["-dc", "levels.z"][..], None),
            (&["-d", "-S", ".z", "levels.z"], None),
            (&["-dc", "nonexist", "levels.z"], None),
            (&["-dc"], Some(p_levels_cut.clone())),
            (&["-dcf"], Some(p_levels_cut.clone())),
        ] {
            let c = dz("gzip", args, vec![("levels.z", p_levels_cut.clone())]);
            cases.push(match stdin {
                Some(s) => fed(c, &s),
                None => c,
            });
        }
        let mut skipped = Skipped::none();
        if not_on_this_tier > 0 {
            skipped.add(
                not_on_this_tier,
                "xz streams that fail, decoded by the pure tier's xz (liblzma on the C tier)",
            );
        }
        check_exact("foreign_formats", &cases, skipped);
    }

    /// Implementer ruling: a pack EOB before the header's length makes
    /// unpack.c output the byte one past its symbol table (undefined
    /// behaviour; Apple's binary was seen to print a stray byte and exit
    /// 0). stuffr stops there as at a stream cut short: the bytes decoded,
    /// "Premature EOF", exit 2. Reference-free.
    #[test]
    fn a_pack_eob_before_its_length_is_premature_eof() {
        let t = txt();
        let mut p = pack(&t);
        p[5] ^= 1; // 20001: one more than the stream holds
        let c = dz("gzip", &["-dc", "long.z"], vec![("long.z", p)]);
        let s = stuffr_as(&c);
        assert_eq!(s.code, 2);
        assert_eq!(s.stderr, "gzip: Premature EOF\n");
        assert!(s.stdout == t, "the decoded bytes come first");
    }

    /// `-t` on good, bad, cut-short and trailing-garbage inputs, alone and
    /// several at once: nothing is written for gzip, and `-v` says OK or
    /// NOT OK per input.
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
                ("long-name.gz", good.clone()),
            ]
        };
        let mut cases = Vec::new();
        for f in [
            "good.gz",
            "crc.gz",
            "cut.gz",
            "junk.gz",
            "notgz",
            "long-name.gz",
        ] {
            for args in [
                &["-t"][..],
                &["-tv"],
                &["-tq"],
                &["--test"],
                &["-tf"],
                &["-tc"],
            ] {
                let mut a = args.to_vec();
                a.push(f);
                cases.push(dz("gzip", &a, all()));
            }
            let bytes = all().into_iter().find(|(n, _)| *n == f).unwrap().1;
            cases.push(fed(dz("gzip", &["-tv"], vec![]), &bytes));
            cases.push(fed(dz("gzip", &["-t"], vec![]), &bytes));
        }
        for args in [
            &["-tv", "good.gz", "crc.gz", "junk.gz", "notgz", "good.gz"][..],
            &["-t", "good.gz", "cut.gz", "good.gz"],
            &["-tv", "good.gz", "nonexist", "good.gz"],
            &["-tv", "-", "good.gz"],
            &["-tv", "good.gz", "-"],
            &["-tvq", "good.gz", "crc.gz"],
        ] {
            cases.push(fed(dz("gzip", args, all()), &junk));
        }
        for name in ["gunzip", "gzcat"] {
            cases.push(dz(name, &["-tv", "good.gz", "crc.gz"], all()));
        }
        check_exact("test_option", &cases, Skipped::none());
    }

    /// `-l`, `-lv`, `-lq`: the last eight bytes of each file are read and
    /// nothing is decoded, so a corrupt member is listed from its trailer,
    /// standard input (a pipe) lists 0, and a file not gzip is refused.
    /// Totals after more than one operand, unless `-q`; `-v`'s header is
    /// printed even under `-q`.
    #[test]
    fn list() {
        let t = txt();
        let good = gzm(&t, b"stored-name");
        let small = member(Member {
            name: Some(b"s"),
            mtime: 1_234_567_890,
            ..plain_member(b"x")
        });
        let lies = member_with(plain_member(&t), None, Some(t.len() as u32 + 1));
        let crc = member_with(plain_member(&t), Some(1), None);
        let junk = [small.clone(), b"junk".to_vec()].concat();
        let nuls = [small.clone(), vec![0; 10]].concat();
        let tiny = b"\x1f\x8b\x08\x00\x00".to_vec();
        let files = || {
            vec![
                ("good.gz", good.clone()),
                ("small.gz", small.clone()),
                ("lies.gz", lies.clone()),
                ("crc.gz", crc.clone()),
                ("junk.gz", junk.clone()),
                ("nuls.gz", nuls.clone()),
                ("tiny.gz", tiny.clone()),
                ("plain", t.clone()),
                ("d/x.tgz", good.clone()),
                ("noext", good.clone()),
            ]
        };
        let mut cases = Vec::new();
        for flags in [
            &["-l"][..],
            &["-lv"],
            &["-lq"],
            &["-lqv"],
            &["-lN"],
            &["-lvN"],
            &["--list"],
            &["-lf"],
            &["-lc"],
        ] {
            for ops in [
                &["good.gz"][..],
                &["small.gz"],
                &["good.gz", "small.gz"],
                &["lies.gz"],
                &["crc.gz"],
                &["junk.gz"],
                &["good.gz", "nuls.gz", "small.gz"],
                &["tiny.gz"],
                &["plain"],
                &["plain", "good.gz"],
                &["good.gz", "nonexist"],
                &["d/x.tgz"],
                &["noext"],
                &["good.gz", "-"],
                &["-", "good.gz", "small.gz"],
            ] {
                let mut a = flags.to_vec();
                a.extend_from_slice(ops);
                // Standard input's date is the pipe's: only -l without -v.
                if a.contains(&"-") && flags.iter().any(|f| f.contains('v')) {
                    continue;
                }
                cases.push(fed(dz("gzip", &a, files()), &small));
            }
            if !flags.iter().any(|f| f.contains('v')) {
                cases.push(fed(dz("gzip", flags, vec![]), &good));
            }
        }
        for name in ["gunzip", "gzcat"] {
            cases.push(dz(name, &["-l", "good.gz", "small.gz"], files()));
        }
        cases.push(fed(dz("gzip", &["-l"], vec![]), &t));
        check_exact("list", &cases, Skipped::none());
    }

    /// `-r` decompressing: `fts` order, every regular file handed to the
    /// decompressor (so a name without a suffix is "unknown suffix"),
    /// symbolic links skipped; and `-t`/`-l`/`-c` under `-r`.
    #[test]
    fn recursive_decompress() {
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
            &["-drq", "d"],
            &["-tr", "d"],
            &["-trv", "d"],
            &["-lr", "d"],
            &["-lrv", "d"],
            &["-dcr", "d/s"],
            &["-dr", "d/b.txt"],
            &["-drv", "d/"],
            &["-dr", "d", "e"],
            &["-dr", "e/x"],
        ] {
            cases.push(with_setup(dz("gzip", args, tree()), links));
            cases.push(dz("gzip", args, tree()));
        }
        cases.push(with_setup(dz("gunzip", &["-r", "d"], tree()), links));
        cases.push(with_setup(dz("gunzip", &["-rf", "d/ld"], tree()), links));
        check_exact("recursive_decompress", &cases, Skipped::none());
    }

    /// Review focus 1: `gunzip -N` never writes outside the operand's
    /// directory. Apple keeps a stored name's last component and puts it
    /// beside the input; both trees must agree and the absolute target
    /// must not exist afterwards.
    #[test]
    fn a_header_name_with_a_path_never_escapes_the_directory() {
        let escape = format!("/tmp/stuffr-escape-bsd-{}", std::process::id());
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
                &["-lNv", "s/in.gz"],
            ] {
                cases.push(dz("gzip", args, vec![("s/in.gz", m.clone())]));
            }
            cases.push(dz("gunzip", &["-N", "in.gz"], vec![("in.gz", m.clone())]));
        }
        // Names with no last component: the output is the operand's
        // directory, or the directory itself.
        for (stored, args, op) in [
            (&b"/"[..], &["-dN"][..], "s/in.gz"),
            (b"/", &["-dNf"], "s/in.gz"),
            (b"//", &["-dN"], "s/in.gz"),
            (b"x/", &["-dN"], "s/in.gz"),
            (b"", &["-dNf"], "s/in.gz"),
            (b".", &["-dNf"], "a.gz"),
            (b"..", &["-dNf"], "a.gz"),
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
        check_exact("header_name_escape", &cases, Skipped::none());
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

    /// Rulings T8-4/T8-5, carried over: when the output is the input itself
    /// (a stored name equal to the input's, or `-S ''`), Apple unlinks it
    /// under `-f` and decodes from the open descriptor, so a good input is
    /// replaced by its contents and a bad one is lost. stuffr prints and
    /// exits as Apple does but replaces the input only with the finished
    /// output: a good one is compared with Apple, a bad one survives.
    #[test]
    fn an_output_that_is_the_input_survives_a_failure() {
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
        check_exact(
            "output_is_input",
            &[
                dz("gzip", &["-dNf", "a.gz"], vec![("a.gz", good.clone())]),
                dz("gzip", &["-dNfv", "a.gz"], vec![("a.gz", good.clone())]),
                dz("gzip", &["-dNfk", "a.gz"], vec![("a.gz", good.clone())]),
            ],
            Skipped::none(),
        );
        for bytes in [crc, cut] {
            for args in [
                &["-dNf", "a.gz"][..],
                &["-dNfv", "a.gz"],
                &["-df", "-S", "", "a.gz"],
            ] {
                let c = dz("gzip", args, vec![("a.gz", bytes.clone())]);
                let s = stuffr_as(&c);
                if let Some(r) = reference(APPLE_GZIP_DIR, &c) {
                    assert_eq!(
                        (r.code, &r.stdout, &r.stderr),
                        (s.code, &s.stdout, &s.stderr),
                        "{args:?}"
                    );
                }
                assert_eq!(s.code, 1, "{}", s.stderr);
                assert_eq!(s.tree.len(), 1, "{:?}", s.tree.keys());
                assert_eq!(s.tree["a.gz"].0, bytes, "the input must survive unchanged");
            }
        }
    }

    /// Review focus 2: `gunzip a.gz b.gz c.gz` with `b.gz` corrupt keeps
    /// `b.gz`, leaves no partial `b`, and goes on to `c.gz` (gzip failures
    /// are warnings, exit 1). A foreign decoder's failure ends the run with
    /// exit 2 and leaves what it wrote (Apple's `maybe_errx`), the input
    /// kept: reproduced, since nothing is lost.
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
        let bz = stuffr_encode("bzip2", &t, None);
        for args in [&["-d"][..], &["-dk"]] {
            let mut a = args.to_vec();
            a.extend(["a.gz", "b.bz2", "c.gz"]);
            cases.push(dz(
                "gzip",
                &a,
                vec![
                    ("a.gz", good.clone()),
                    ("b.bz2", bz[..bz.len() / 2].to_vec()),
                    ("c.gz", good.clone()),
                ],
            ));
        }
        check_exact("corrupt_middle", &cases, Skipped::none());
        // stuffr alone: the corrupt input is intact and has no output, no
        // temporary file is left, and `a` and `c` were written whole.
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
            assert_eq!(s.tree["c"].0, t, "{what}");
            assert!(
                s.tree.keys().all(|k| !k.contains(".stuffr-")),
                "{what}: a temporary file was left: {:?}",
                s.tree.keys()
            );
        }
    }

    /// Review focus 3 for Apple: `gzcat big.gz | head` ends stuffr by
    /// SIGPIPE, with nothing on standard error, as it ends Apple's.
    #[test]
    fn zcat_into_a_closed_pipe() {
        use std::io::Read;
        use std::os::unix::process::ExitStatusExt;
        use std::process::{Command, Stdio};
        let plain = text(4 << 20, 53);
        let dir = std::env::temp_dir().join(format!("stuffr-gzcat-pipe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        let link = dir.join("bin").join("gzcat");
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stuffr"), &link).unwrap();
        std::fs::write(dir.join("big.gz"), gzm(&plain, b"big")).unwrap();
        let status = |exe: &Path| {
            let mut child = Command::new(exe)
                .arg("big.gz")
                .current_dir(&dir)
                .env_clear()
                .env("STUFFR_GZIP_FLAVOR", "bsd")
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
        };
        let ours = status(&link);
        assert_eq!(
            ours.signal(),
            Some(libc::SIGPIPE),
            "stuffr as gzcat: {ours:?}"
        );
        let reference = Path::new(APPLE_GZIP_DIR).join("gzcat");
        if require_reference(&reference) {
            let theirs = status(&reference);
            assert_eq!(
                theirs.signal(),
                Some(libc::SIGPIPE),
                "reference: {theirs:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Review focus 5: an empty file, a member with an empty body, a member
    /// followed by an empty one and the reverse, a member with FEXTRA,
    /// FCOMMENT and FHCRC (Apple skips the header CRC unchecked, so a
    /// wrong one decodes), and reserved flag bits (ignored), through `-d`,
    /// `-t` and `-l`.
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
        let mut reserved = gzm(&t, b"r");
        reserved[3] |= 0xe0;
        let inputs: Vec<(&str, Vec<u8>)> = vec![
            ("empty.gz", Vec::new()),
            ("three.gz", b"\x1f\x8b\x08".to_vec()),
            ("ebody.gz", empty_body.clone()),
            ("cat.gz", [gzm(&t, b"a"), empty_body.clone()].concat()),
            ("cat2.gz", [empty_body.clone(), gzm(&t, b"a")].concat()),
            ("fields.gz", all_fields),
            ("badhcrc.gz", bad_hcrc),
            ("reserved.gz", reserved),
        ];
        let mut cases = Vec::new();
        for (file, bytes) in &inputs {
            for args in [
                &["-d"][..],
                &["-dv"],
                &["-dc"],
                &["-dcv"],
                &["-dN"],
                &["-df"],
                &["-t"],
                &["-tv"],
                &["-l"],
                &["-lv"],
            ] {
                let mut a = args.to_vec();
                a.push(file);
                cases.push(dz("gzip", &a, vec![(file, bytes.clone())]));
            }
            cases.push(fed(dz("gzcat", &[], vec![]), bytes));
            cases.push(fed(dz("gzip", &["-dcf"], vec![]), bytes));
        }
        check_exact("odd_members", &cases, Skipped::none());
    }

    /// Residual of the final review's item 1: an input given with `-f` as
    /// a symbolic link to the output's own name (`a.gz -> a`, `l ->
    /// l.gz`). Apple's `unlink_input` `stat`s the name, which by then
    /// leads to the fresh output, not the input, so the link is kept (GNU
    /// removes it). Pinned against `/usr/bin/gzip`; the compressed output
    /// is compared by name and decoded here.
    #[test]
    fn an_input_linked_to_its_output_name_keeps_the_link() {
        fn a_gz_to_a(d: &Path) {
            std::os::unix::fs::symlink("a", d.join("a.gz")).unwrap();
        }
        fn l_to_l_gz(d: &Path) {
            std::os::unix::fs::symlink("l.gz", d.join("l")).unwrap();
        }
        let t = txt();
        let cases: Vec<Case> = [&["-df", "a.gz"][..], &["-dfv", "a.gz"], &["-dfk", "a.gz"]]
            .into_iter()
            .map(|args| with_setup(dz("gzip", args, vec![("a", gzm(&t, b"a"))]), a_gz_to_a))
            .collect();
        check_exact("input_linked_to_its_output", &cases, Skipped::none());
        for args in [&["-f", "l"][..], &["-fk", "l"]] {
            let c = with_setup(gz(args, vec![("l.gz", t.clone())]), l_to_l_gz);
            let s = stuffr_as(&c);
            if let Some(r) = reference("/usr/bin", &c) {
                assert_eq!(
                    (r.code, &r.stdout, &r.stderr),
                    (s.code, &s.stdout, &s.stderr)
                );
                let names = |t: &Tree| t.keys().cloned().collect::<Vec<_>>();
                assert_eq!(names(&r.tree), names(&s.tree), "{args:?}");
            }
            assert_eq!(s.code, 0, "{}", s.stderr);
            let decoded = ref_decompress_with(&c.roundtrip, &s.tree["l.gz"].0);
            assert_eq!(decoded.unwrap(), t, "{args:?}");
        }
    }

    /// A member whose CRC32 and ISIZE are both wrong: Apple's
    /// `gz_uncompress` checks the CRC first and reports only that (GNU
    /// says both). Also as the first of two members, under `-k`, `-v`
    /// and `-l` (which reads the trailer and lists the wrong ISIZE).
    #[test]
    fn crc_and_length_both_wrong() {
        let t = txt();
        let both = member_with(plain_member(&t), Some(1), Some(99));
        let good = gzm(b"good\n", b"g");
        let multi = [both.clone(), good.clone()].concat();
        let mut cases = Vec::new();
        for args in [
            &["-d", "b.gz", "g.gz"][..],
            &["-dv", "b.gz", "g.gz"],
            &["-dc", "b.gz", "g.gz"],
            &["-dk", "b.gz", "g.gz"],
            &["-t", "b.gz", "g.gz"],
            &["-tv", "b.gz", "g.gz"],
            &["-l", "b.gz", "g.gz"],
            &["-d", "m.gz"],
            &["-dc", "m.gz"],
            &["-t", "m.gz"],
        ] {
            cases.push(dz(
                "gzip",
                args,
                vec![
                    ("b.gz", both.clone()),
                    ("g.gz", good.clone()),
                    ("m.gz", multi.clone()),
                ],
            ));
        }
        cases.push(fed(dz("gzcat", &[], vec![]), &both));
        check_exact("crc_and_length_both_wrong", &cases, Skipped::none());
    }

    /// Final review, item 2: Apple reads a stored name or comment of any
    /// length (`gz_uncompress`'s state machine reads past them), and `-N`
    /// takes the name from offset 10 into a `PATH_MAX` buffer. A 1.5 MiB
    /// FNAME and FCOMMENT (with FHCRC) through `-d`, `-t`, `-l` and `-N`,
    /// and stored names on either side of 1024 bytes.
    #[test]
    fn long_header_fields() {
        let t = txt();
        let big = vec![b'n'; 1536 * 1024];
        let inputs = [
            (
                "name.gz",
                member(Member {
                    name: Some(&big),
                    mtime: 1_234_567_890,
                    ..plain_member(&t)
                }),
            ),
            (
                "comment.gz",
                member(Member {
                    name: Some(b"short"),
                    comment: Some(&big),
                    ..plain_member(&t)
                }),
            ),
            (
                "hcrc.gz",
                member(Member {
                    name: Some(&big),
                    comment: Some(&big),
                    hcrc: true,
                    ..plain_member(&t)
                }),
            ),
            ("n1023.gz", gzm(&t, &[b'n'; 1023])),
            ("n1024.gz", gzm(&t, &[b'n'; 1024])),
        ];
        let mut cases = Vec::new();
        for (file, bytes) in &inputs {
            for args in [
                &["-dc"][..],
                &["-t"],
                &["-tv"],
                &["-l"],
                &["-lv"],
                &["-d"],
                &["-dk"],
                &["-dN"],
                &["-dNv"],
                &["-lN"],
            ] {
                let mut a = args.to_vec();
                a.push(file);
                cases.push(dz("gzip", &a, vec![(file, bytes.clone())]));
            }
        }
        check_exact("long_header_fields", &cases, Skipped::none());
    }
}

/// 0.13.1 Task 3: an interrupted run removes its partial output on SIGINT,
/// the one signal Apple's gzip handles, and dies of it; on any other signal
/// it dies and leaves the partial output.
#[cfg(target_os = "macos")]
mod interrupts {
    use super::compat_harness::interrupt::*;
    use super::compat_harness::{APPLE_GZIP_DIR, ScratchDir, require_reference};
    use std::path::Path;

    const ENV: &[(&str, &str)] = &[("STUFFR_GZIP_FLAVOR", "bsd")];

    fn ours() -> &'static Path {
        Path::new(env!("CARGO_BIN_EXE_stuffr"))
    }

    fn scratch(tag: &str, mine: bool) -> ScratchDir {
        ScratchDir::at(std::env::temp_dir().join(format!(
            "stuffr-bsd-intr-{}-{tag}-{}",
            std::process::id(),
            if mine { "ours" } else { "ref" }
        )))
    }

    /// `args` over `file` (made by `make`), interrupted with `sig`; ours
    /// (`mine`) or Apple's. `partial` is the reference's partial output.
    #[allow(clippy::too_many_arguments)]
    fn run(
        mine: bool,
        tag: &str,
        args: &[&str],
        file: &str,
        make: &dyn Fn(usize) -> Vec<u8>,
        inherit: Inherit,
        sig: i32,
        partial: &str,
    ) -> Option<Interrupted> {
        let (exe, env) = if mine {
            (ours().to_path_buf(), ENV)
        } else {
            let exe = Path::new(APPLE_GZIP_DIR).join("gzip");
            if !require_reference(&exe) {
                return None;
            }
            (exe, &[][..])
        };
        let dir = scratch(tag, mine);
        let named = |n: &str| {
            if mine {
                n.starts_with(".stuffr-gzip-")
            } else {
                n == partial
            }
        };
        let ready = has_data(&dir, &named);
        interrupt_with_input_env(
            &exe, "gzip", args, &dir, env, file, make, inherit, sig, &ready,
        )
    }

    #[test]
    fn apple_gzip_removes_its_partial_output_on_int() {
        let _serial = interrupt_lock();
        let plain = |m: usize| big_input(m).to_vec();
        let gz = |m: usize| stored_gzip(big_input(fast_size(m)));
        for mine in [true, false] {
            type Make<'a> = &'a dyn Fn(usize) -> Vec<u8>;
            let cases: [(&[&str], &str, Make, &str); 2] = [
                (&["-9", "a"], "a", &plain, "a.gz"),
                (&["-d", "a.gz"], "a.gz", &gz, "a"),
            ];
            for (args, file, make, partial) in cases {
                let Some(r) = run(
                    mine,
                    "int",
                    args,
                    file,
                    make,
                    Inherit::Default,
                    libc::SIGINT,
                    partial,
                ) else {
                    continue;
                };
                assert!(
                    killed_by(&r, libc::SIGINT),
                    "mine={mine} {args:?}: {:?}",
                    r.status
                );
                assert_eq!(r.left, [file], "mine={mine} {args:?}");
            }
        }
    }

    #[test]
    fn apple_gzip_leaves_its_partial_output_on_term() {
        let _serial = interrupt_lock();
        let plain = |m: usize| big_input(m).to_vec();
        for mine in [true, false] {
            let Some(r) = run(
                mine,
                "term",
                &["-9", "a"],
                "a",
                &plain,
                Inherit::Default,
                libc::SIGTERM,
                "a.gz",
            ) else {
                continue;
            };
            assert!(killed_by(&r, libc::SIGTERM), "mine={mine}: {:?}", r.status);
            assert_eq!(r.left.len(), 2, "mine={mine}: {:?}", r.left);
            assert!(r.left.contains(&"a".to_string()), "{:?}", r.left);
        }
    }

    #[test]
    fn apple_gzip_keeps_an_inherited_ignored_int() {
        let _serial = interrupt_lock();
        for mine in [true, false] {
            let (exe, env) = if mine {
                (ours().to_path_buf(), ENV)
            } else {
                let exe = Path::new(APPLE_GZIP_DIR).join("gzip");
                if !require_reference(&exe) {
                    continue;
                }
                (exe, &[][..])
            };
            let dir = scratch("ign", mine);
            for mib in [64, 256] {
                let _ = std::fs::remove_dir_all(&dir);
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(dir.join("a"), big_input(mib)).unwrap();
                let named = |n: &str| {
                    if mine {
                        n.starts_with(".stuffr-gzip-")
                    } else {
                        n == "a.gz"
                    }
                };
                let ready = has_data(&dir, &named);
                if let Some(r) = interrupt_env(
                    &exe,
                    "gzip",
                    &["-9", "a"],
                    &dir,
                    env,
                    Inherit::IgnoreInt,
                    libc::SIGINT,
                    &ready,
                ) {
                    assert!(r.status.success(), "mine={mine}: {:?}", r.status);
                    break;
                }
            }
            if take_reference_hung() {
                eprintln!("note: gzip reference hung after the signal; comparison skipped");
                continue;
            }
            assert_eq!(listing(&dir), ["a.gz"], "mine={mine}");
        }
    }
}
