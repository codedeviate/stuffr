//! Task 10's Apple differentials: testing and extraction (`extract.c`,
//! `fileio.c`'s output side, `unix.c`'s names, modes, times and symlinks),
//! the beneath walk where Apple's `AT_RESOLVE_BENEATH` refuses, and
//! quarantine. Every case runs `/usr/bin/unzip` and stuffr (Apple flavour)
//! in fresh directories and compares exit code, both streams and the whole
//! work tree (contents, modes, mtimes, symlink targets, quarantine).
//!
//! Apple's own atf tests (`zip-33/unzip/tests/{basic,beneath,quarantine}.sh`)
//! are here as cases over archives built to the same shape.

use super::compat_harness::*;
use std::os::unix::fs::symlink;
use std::path::Path;

/// A string that lives as long as the cases built from it.
fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn compare(group: &str, cases: &[Case]) {
    run_group(group, cases, Skipped::none(), &assert_same_unzip);
}

/// A case of `unzip args` over `files`.
fn case(args: &[&'static str], files: &[(&'static str, Vec<u8>)]) -> Case<'static> {
    unzip_case("unzip", args.to_vec(), files.to_vec())
}

/// `c` with `stdin` piped in.
fn fed(mut c: Case<'static>, stdin: &[u8]) -> Case<'static> {
    c.stdin = Some(stdin.to_vec());
    c
}

/// `c` with `setup` run in the work directory first.
fn prepared(mut c: Case<'static>, setup: fn(&Path)) -> Case<'static> {
    c.setup = Some(setup);
    c
}

/// An `UT` extra block holding modification time `t` (and nothing else).
fn ut(t: u32) -> Vec<u8> {
    let mut d = vec![1u8];
    d.extend_from_slice(&t.to_le_bytes());
    extra_block(0x5455, &d)
}

/// A Unix symlink entry `name -> target`.
fn link_entry<'a>(name: &'a [u8], target: &'a [u8]) -> ZipEntrySpec<'a> {
    ZipEntrySpec {
        external_attr: 0o120755 << 16,
        ..ZipEntrySpec::new(name, target)
    }
}

/// A Unix entry of `mode` (type bits included).
fn mode_entry<'a>(name: &'a [u8], data: &'a [u8], mode: u32) -> ZipEntrySpec<'a> {
    ZipEntrySpec {
        external_attr: mode << 16,
        ..ZipEntrySpec::new(name, data)
    }
}

/// `p`'s modification and access times set to `t`.
fn touch(p: &Path, t: u64) {
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(p)
        .or_else(|_| std::fs::File::open(p))
        .unwrap();
    let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(t);
    f.set_times(std::fs::FileTimes::new().set_modified(t).set_accessed(t))
        .unwrap();
}

/// The fixture `name` of `stuffr-formats/tests/data/infozip/` (P8: `None`
/// when the directory is absent, a panic when it is there without `name`).
fn infozip_fixture(name: &str) -> Option<Vec<u8>> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../stuffr-formats/tests/data/infozip");
    if !dir.is_dir() {
        return None;
    }
    Some(std::fs::read(dir.join(name)).unwrap_or_else(|e| panic!("{name}: {e}")))
}

/// `z` with general-purpose bit 0 of internal attributes (text) set on every
/// central directory entry, as Info-ZIP's zip marks text files.
fn text_flagged(mut z: Vec<u8>) -> Vec<u8> {
    let mut i = 0;
    while i + 46 <= z.len() {
        if z[i..i + 4] == *b"PK\x01\x02" {
            z[i + 36] |= 1;
            i += 46;
        } else {
            i += 1;
        }
    }
    z
}

/// `z` with every central and local size field of the first entry raised
/// by `more` (its data then runs past what the archive holds).
fn sizes_raised(mut z: Vec<u8>, more: u32) -> Vec<u8> {
    let bump = |z: &mut Vec<u8>, at: usize| {
        let v = u32::from_le_bytes(z[at..at + 4].try_into().unwrap()) + more;
        z[at..at + 4].copy_from_slice(&v.to_le_bytes());
    };
    // local header: csize at 18
    bump(&mut z, 18);
    let cd = (0..z.len() - 4)
        .find(|&i| z[i..i + 4] == *b"PK\x01\x02")
        .unwrap();
    bump(&mut z, cd + 20);
    z
}

const TEXT: &[u8] = b"the quick brown fox jumps over the lazy dog\n";

// ---- methods, -t -p -c -a ----

/// Every method the fixtures hold (shrink, implode in its four shapes,
/// deflate64) and the two zip_with makes (stored, deflate), each tested,
/// piped, shown and extracted, plus `-a`/`-aa` over text with CR LF, lone
/// CRs and `^Z`, flagged as text and not.
#[test]
fn extraction_methods_and_text_conversion() {
    let text = TEXT.repeat(300);
    let crlf = b"line one\r\nline two\rline three\nend\x1a\r\n".repeat(50);
    let made = zip_with(
        &[
            ZipEntrySpec::new(b"stored.txt", &text),
            ZipEntrySpec {
                method: 8,
                ..ZipEntrySpec::new(b"deflated.txt", &text)
            },
            ZipEntrySpec::new(b"crlf.txt", &crlf),
            ZipEntrySpec {
                method: 8,
                ..ZipEntrySpec::new(b"crlf-deflated.txt", &crlf)
            },
            ZipEntrySpec::new(b"empty.txt", b""),
            ZipEntrySpec::new(b"bin.dat", &[0u8, 13, 10, 13, 255, 26, 10]),
        ],
        b"",
        b"",
    );
    let flagged = text_flagged(made.clone());
    let mut archives: Vec<(&'static str, Vec<u8>)> =
        vec![("made.zip", made), ("flagged.zip", flagged)];
    for f in [
        "shrink-commons.zip",
        "shrink-full-table.zip",
        "implode-4k-2trees.zip",
        "implode-8k-3trees.zip",
        "implode-hand-4k-2trees.zip",
        "implode-hand-4k-3trees.zip",
        "implode-hand-8k-2trees.zip",
        "implode-hand-8k-3trees.zip",
        "deflate64-lorem.zip",
    ] {
        if let Some(b) = infozip_fixture(f) {
            archives.push((leak(f.to_owned()), b));
        }
    }
    let runs: &[&[&'static str]] = &[
        &[],
        &["-t"],
        &["-tq"],
        &["-tqq"],
        &["-p"],
        &["-c"],
        &["-q"],
        &["-qq"],
        &["-a"],
        &["-aa"],
        &["-ca"],
        &["-caa"],
        &["-pa"],
        &["-d", "out"],
        &["-ad", "out"],
    ];
    let mut cases = Vec::new();
    for (name, bytes) in &archives {
        for r in runs {
            let mut a = r.to_vec();
            a.push(name);
            cases.push(case(&a, &[(name, bytes.clone())]));
        }
    }
    compare("extraction_methods_and_text_conversion", &cases);
}

// ---- options ----

fn older_and_newer(w: &Path) {
    // `old.txt` older than its entry (2020-01-02), `new.txt` newer
    std::fs::write(w.join("old.txt"), b"was here\n").unwrap();
    touch(&w.join("old.txt"), 1_500_000_000);
    std::fs::write(w.join("new.txt"), b"was here\n").unwrap();
    touch(&w.join("new.txt"), 1_700_000_000);
}

fn existing_out_dir(w: &Path) {
    std::fs::create_dir(w.join("out")).unwrap();
}

/// `-j -d -x -C -L -n -o -f -u -B -K -X -D -DD` and their mixes, over a
/// tree with directories, modes, `UT` times and existing files older and
/// newer than their entries.
#[test]
fn extraction_options() {
    let ut_dir = ut(1_600_000_000);
    let ut_file = ut(1_600_000_100);
    let z = zip_with(
        &[
            ZipEntrySpec {
                extra: &ut_dir,
                ..mode_entry(b"Dir/", b"", 0o40750)
            },
            ZipEntrySpec {
                extra: &ut_file,
                ..mode_entry(b"Dir/Sub/File.TXT", b"in a folder\n", 0o100640)
            },
            mode_entry(b"suid.sh", b"#!/bin/sh\n", 0o106755),
            mode_entry(b"sticky/", b"", 0o41777),
            ZipEntrySpec::new(b"old.txt", b"from the archive\n"),
            ZipEntrySpec::new(b"new.txt", b"from the archive\n"),
            ZipEntrySpec::new(b"fresh.txt", b"not there before\n"),
        ],
        b"",
        b"",
    );
    let files = [("o.zip", z)];
    let runs: &[&[&'static str]] = &[
        &["o.zip"],
        &["-j", "o.zip"],
        &["-d", "out", "o.zip"],
        &["-d", "out/", "o.zip"],
        &["-d", "two/levels", "o.zip"],
        &["o.zip", "-x", "*.txt"],
        &["o.zip", "dir/*"],
        &["-C", "o.zip", "dir/*"],
        &["-L", "o.zip"],
        &["-LL", "o.zip"],
        &["-n", "o.zip"],
        &["-o", "o.zip"],
        &["-f", "o.zip"],
        &["-fo", "o.zip"],
        &["-u", "o.zip"],
        &["-uo", "o.zip"],
        &["-B", "o.zip"],
        &["-oB", "o.zip"],
        &["-K", "o.zip"],
        &["-X", "o.zip"],
        &["-D", "o.zip"],
        &["-DD", "o.zip"],
        &["-q", "-o", "o.zip"],
        &["-o", "-d", "out", "o.zip", "Dir/*"],
    ];
    let mut cases = Vec::new();
    for r in runs {
        for (setup, stdin) in [
            (None, None),
            (Some(older_and_newer as fn(&Path)), None),
            (Some(older_and_newer as fn(&Path)), Some(&b"y\nn\n"[..])),
        ] {
            let mut c = case(r, &files);
            c.setup = setup;
            c.stdin = stdin.map(<[u8]>::to_vec);
            cases.push(c);
        }
    }
    cases.push(prepared(
        case(&["-d", "out", "o.zip"], &files),
        existing_out_dir,
    ));
    cases.push(prepared(
        case(&["-f", "-d", "out", "o.zip"], &files),
        existing_out_dir,
    ));
    cases.push(case(&["-f", "-d", "missing", "o.zip"], &files));
    compare("extraction_options", &cases);
}

// ---- names and attributes ----

/// Directories and their deferred attributes, symlinks (made last),
/// symlink-then-file chains, `../`, absolute, dot and empty names.
#[test]
fn names_and_attributes() {
    let ut_dir = ut(1_600_000_000);
    let tree = zip_with(
        &[
            ZipEntrySpec {
                extra: &ut_dir,
                ..mode_entry(b"d/", b"", 0o40700)
            },
            mode_entry(b"d/f.txt", b"f\n", 0o100600),
            mode_entry(b"ro/", b"", 0o40555),
            mode_entry(b"ro/x.txt", b"x\n", 0o100444),
            link_entry(b"lnk", b"d/f.txt"),
            link_entry(b"dangling", b"nowhere"),
            link_entry(b"out", b"../outside/file"),
            link_entry(b"chain", b"d"),
            ZipEntrySpec::new(b"chain/g.txt", b"through the link\n"),
            link_entry(b"empty-link", b""),
            mode_entry(b"implied/deep/file.txt", b"made on the way\n", 0o100644),
        ],
        b"",
        b"",
    );
    let names = zip_with(
        &[
            ZipEntrySpec::new(b"../up.txt", b"up\n"),
            ZipEntrySpec::new(b"/abs.txt", b"abs\n"),
            ZipEntrySpec::new(b"//twice.txt", b"twice\n"),
            ZipEntrySpec::new(b"x/../../y.txt", b"y\n"),
            ZipEntrySpec::new(b"./dot.txt", b"dot\n"),
            ZipEntrySpec::new(b"a/./b.txt", b"b\n"),
            ZipEntrySpec::new(b"..", b"dotdot\n"),
            ZipEntrySpec::new(b".", b"dot\n"),
            ZipEntrySpec::new(b"a/..", b"a dotdot\n"),
            ZipEntrySpec::new(b"semi;1", b"vms\n"),
            ZipEntrySpec::new(b"semi;x", b"not vms\n"),
            ZipEntrySpec::new(b"ctl\x01\x7f.txt", b"control\n"),
        ],
        b"",
        b"",
    );
    // Only `../` (a directory above the root): `-:` would make Apple chmod
    // the directory above the root (T10-10, pinned in compat_unzip_safety);
    // without it the component is dropped.
    let updir = zip_with(&[mode_entry(b"../", b"", 0o40755)], b"", b"");
    let mut cases = vec![
        case(&["updir.zip"], &[("updir.zip", updir.clone())]),
        case(&["-d", "dst", "updir.zip"], &[("updir.zip", updir)]),
    ];
    for (name, z) in [("tree.zip", &tree), ("names.zip", &names)] {
        for r in [
            &[][..],
            &["-o"],
            &["-K"],
            &["-D"],
            &["-DD"],
            &["-j"],
            &["-:"],
            &["-^"],
            &["-V"],
            &["-d", "dst"],
            &["-q"],
        ] {
            let mut a = r.to_vec();
            a.push(name);
            cases.push(case(&a, &[(name, z.clone())]));
        }
    }
    compare("names_and_attributes", &cases);
}

// ---- damage and passwords ----

/// A bad CRC, an entry cut short, unsupported methods (only, and mixed
/// with a good entry), and passwords right and wrong.
#[test]
fn damage_and_passwords() {
    let crc = zip_with(
        &[ZipEntrySpec {
            stored_data: Some(b"alphA\n"),
            ..ZipEntrySpec::new(b"a.txt", b"alpha\n")
        }],
        b"",
        b"",
    );
    let text = TEXT.repeat(100);
    let cut_deflate = sizes_raised(
        zip_with(
            &[ZipEntrySpec {
                method: 8,
                ..ZipEntrySpec::new(b"cut.txt", &text)
            }],
            b"",
            b"",
        ),
        50,
    );
    let cut_stored = sizes_raised(
        zip_with(&[ZipEntrySpec::new(b"cut.txt", &text)], b"", b""),
        50,
    );
    let m7 = zip_with(
        &[ZipEntrySpec {
            method: 7,
            ..ZipEntrySpec::new(b"t.txt", b"tokenized\n")
        }],
        b"",
        b"",
    );
    let mixed = zip_with(
        &[
            ZipEntrySpec {
                method: 7,
                ..ZipEntrySpec::new(b"t.txt", b"tokenized\n")
            },
            ZipEntrySpec {
                method: 3,
                ..ZipEntrySpec::new(b"r.txt", b"reduced\n")
            },
            ZipEntrySpec {
                method: 99,
                ..ZipEntrySpec::new(b"aes.txt", b"aes\n")
            },
            ZipEntrySpec::new(b"good.txt", b"good\n"),
        ],
        b"",
        b"",
    );
    let plain = b"secret data\n";
    let body = zipcrypto(b"secret", (crc32(plain) >> 24) as u8, plain);
    let enc = zip_with(
        &[
            ZipEntrySpec {
                flags: 1,
                stored_data: Some(&body),
                ..ZipEntrySpec::new(b"s.txt", plain)
            },
            ZipEntrySpec::new(b"plain.txt", b"not secret\n"),
        ],
        b"",
        b"",
    );
    let deflated = deflate_raw(&text);
    let dbody = zipcrypto(b"pw", (crc32(&text) >> 24) as u8, &deflated);
    let enc_deflate = zip_with(
        &[ZipEntrySpec {
            flags: 1,
            method: 8,
            stored_data: Some(&dbody),
            ..ZipEntrySpec::new(b"d.txt", &text)
        }],
        b"",
        b"",
    );
    // P10: the check byte's sources are mixed. The central header's bit 3
    // picks the local DOS time's high byte, else the local CRC's (the
    // central CRC when the LOCAL header has bit 3). Every combination of the
    // two headers' bit 3, with the header's check byte taken from the time
    // or from the CRC: the reference says which pass.
    let mut p10: Vec<(&'static str, Vec<u8>)> = Vec::new();
    let time_byte = ((DOS_TIME_2020 & 0xffff) >> 8) as u8;
    let crc_byte = (crc32(plain) >> 24) as u8;
    for (local8, central8) in [(false, false), (true, false), (false, true), (true, true)] {
        for (src, check) in [("time", time_byte), ("crc", crc_byte)] {
            let body = zipcrypto(b"secret", check, plain);
            let mut z = zip_with(
                &[ZipEntrySpec {
                    flags: 1,
                    stored_data: Some(&body),
                    ..ZipEntrySpec::new(b"s.txt", plain)
                }],
                b"",
                b"",
            );
            let cd = (0..z.len() - 4)
                .find(|&i| z[i..i + 4] == *b"PK\x01\x02")
                .unwrap();
            if local8 {
                z[6] |= 8;
            }
            if central8 {
                z[cd + 8] |= 8;
            }
            let name = leak(format!(
                "p10-l{}-c{}-{src}.zip",
                u8::from(local8),
                u8::from(central8)
            ));
            p10.push((name, z));
        }
    }
    let mut cases = Vec::new();
    for (name, z) in &p10 {
        for r in [&["-t", "-P", "secret"][..], &["-P", "secret"]] {
            let mut a = r.to_vec();
            a.push(name);
            cases.push(case(&a, &[(name, z.clone())]));
        }
    }
    // Not vacuous: each header source passes somewhere and fails elsewhere.
    let codes: Vec<i32> = cases
        .iter()
        .step_by(2)
        .filter_map(|c| unzip_reference(c).map(|r| r.code))
        .collect();
    if !codes.is_empty() {
        assert!(codes.contains(&0) && codes.contains(&82), "{codes:?}");
    }
    for (name, z) in [
        ("crc.zip", &crc),
        ("cutd.zip", &cut_deflate),
        ("cuts.zip", &cut_stored),
        ("m7.zip", &m7),
        ("mixed.zip", &mixed),
    ] {
        for r in [&[][..], &["-t"], &["-p"], &["-q"], &["-tq"], &["-o"]] {
            let mut a = r.to_vec();
            a.push(name);
            cases.push(case(&a, &[(name, z.clone())]));
        }
    }
    for (name, z) in [("enc.zip", &enc), ("encd.zip", &enc_deflate)] {
        for r in [
            &["-P", "secret"][..],
            &["-P", "wrong"],
            &["-P", "pw"],
            &["-P", ""],
            &["-t", "-P", "secret"],
            &["-t", "-P", "wrong"],
            &["-t", "-P", "pw"],
            &["-p", "-P", "pw"],
            &["-q", "-P", "wrong"],
        ] {
            let mut a = r.to_vec();
            a.push(name);
            cases.push(case(&a, &[(name, z.clone())]));
        }
    }
    compare("damage_and_passwords", &cases);
}

// ---- Review Focus 1 ----

fn existing_files(w: &Path) {
    for n in ["a.txt", "b.txt", "c.txt"] {
        std::fs::write(w.join(n), b"existing\n").unwrap();
        touch(&w.join(n), 1_500_000_000);
    }
}

fn existing_files_newer(w: &Path) {
    for n in ["a.txt", "b.txt", "c.txt"] {
        std::fs::write(w.join(n), b"existing\n").unwrap();
        touch(&w.join(n), 1_700_000_000);
    }
}

fn outside_link(w: &Path) {
    std::fs::create_dir_all(w.join("outside")).unwrap();
    std::fs::create_dir_all(w.join("dst")).unwrap();
    symlink("../outside", w.join("dst/sub")).unwrap();
}

fn outside_link_existing(w: &Path) {
    outside_link(w);
    std::fs::write(w.join("outside/f.txt"), b"outside\n").unwrap();
}

/// Review Focus 1: extracting into a tree that already has things in it.
/// Piped answers `n`, `y`, `A`, `N`, `r` and a new name, an invalid answer,
/// an empty line, the end of input; `-n -o -f -u` against older and newer
/// files; a directory symlink pointing outside the root; a `-d` target that
/// does not exist yet.
#[test]
fn extracts_into_an_existing_tree() {
    let z = zip_with(
        &[
            ZipEntrySpec::new(b"a.txt", b"from the archive\n"),
            ZipEntrySpec::new(b"b.txt", b"from the archive\n"),
            ZipEntrySpec::new(b"c.txt", b"from the archive\n"),
            ZipEntrySpec::new(b"sub/f.txt", b"into the subdirectory\n"),
        ],
        b"",
        b"",
    );
    let files = [("e.zip", z)];
    let mut cases = Vec::new();
    for setup in [existing_files as fn(&Path), existing_files_newer] {
        for stdin in [
            &b""[..],
            b"n\nn\nn\n",
            b"y\nn\ny\n",
            b"A\n",
            b"N\n",
            b"n\nA\n",
            b"r\nrenamed.txt\nn\nn\n",
            b"r\nsub2/renamed.txt\nN\n",
            b"r\n\nlater.txt\nN\n",
            b"x\ny\nn\nn\n",
            b"\ny\ny\ny\n",
            b"yes please\nn\n",
            b"y\n",
        ] {
            cases.push(fed(prepared(case(&["e.zip"], &files), setup), stdin));
        }
        for r in [
            &["-n", "e.zip"][..],
            &["-o", "e.zip"],
            &["-f", "e.zip"],
            &["-fo", "e.zip"],
            &["-u", "e.zip"],
            &["-uo", "e.zip"],
            &["-B", "e.zip"],
        ] {
            cases.push(prepared(case(r, &files), setup));
        }
        cases.push(fed(
            prepared(case(&["-u", "e.zip"], &files), setup),
            b"y\ny\ny\n",
        ));
    }
    for setup in [outside_link as fn(&Path), outside_link_existing] {
        for r in [&["-d", "dst", "e.zip"][..], &["-o", "-d", "dst", "e.zip"]] {
            cases.push(prepared(case(r, &files), setup));
            cases.push(fed(prepared(case(r, &files), setup), b"y\n"));
        }
    }
    cases.push(case(&["-d", "not/yet", "e.zip"], &files));
    cases.push(case(&["-d", "notyet", "e.zip"], &files));
    compare("extracts_into_an_existing_tree", &cases);
}

// ---- Apple's atf tests ----

/// `basic.in`'s shape: `hello.txt`, `dir/`, `dir/file.txt`, Info-ZIP's `UT`
/// times.
fn basic_zip() -> Vec<u8> {
    let (t1, t2) = (ut(1_745_837_027), ut(1_745_837_010));
    zip_with(
        &[
            ZipEntrySpec {
                extra: &t1,
                ..ZipEntrySpec::new(b"hello.txt", b"Hello, world!\n")
            },
            ZipEntrySpec {
                extra: &t2,
                ..mode_entry(b"dir/", b"", 0o40755)
            },
            ZipEntrySpec {
                extra: &t2,
                ..ZipEntrySpec::new(b"dir/file.txt", b"Text\n")
            },
        ],
        b"",
        b"",
    )
}

fn basic_dst(w: &Path) {
    std::fs::create_dir(w.join("dst")).unwrap();
}

fn basic_dst_direxist(w: &Path) {
    std::fs::create_dir_all(w.join("dst/dir")).unwrap();
}

fn basic_fileexist(w: &Path) {
    std::fs::create_dir(w.join("dir")).unwrap();
    std::fs::write(w.join("dir/file.txt"), b"Subtext\n").unwrap();
}

fn basic_backupexist(w: &Path) {
    basic_fileexist(w);
    std::fs::write(w.join("dir/file.txt~"), b"Context\n").unwrap();
}

/// basic.sh: basic_cwd, basic_dst, basic_dst_direxist, basic_fileexist
/// (`A`), _replace (`-o`), _noreplace (`-n`), _backup (`-B`),
/// _backupexist, _replacebackup (`-oB`).
#[test]
fn apples_basic_sh() {
    let files = [("basic.zip", basic_zip())];
    let cases = vec![
        case(&["basic.zip"], &files),
        prepared(case(&["-d", "dst", "basic.zip"], &files), basic_dst),
        prepared(
            case(&["-d", "dst", "basic.zip"], &files),
            basic_dst_direxist,
        ),
        fed(
            prepared(case(&["basic.zip"], &files), basic_fileexist),
            b"A\n",
        ),
        prepared(case(&["-o", "basic.zip"], &files), basic_fileexist),
        prepared(case(&["-n", "basic.zip"], &files), basic_fileexist),
        prepared(case(&["-B", "basic.zip"], &files), basic_fileexist),
        prepared(case(&["-B", "basic.zip"], &files), basic_backupexist),
        prepared(case(&["-oB", "basic.zip"], &files), basic_backupexist),
    ];
    compare("apples_basic_sh", &cases);
}

fn beneath_allow(w: &Path) {
    std::fs::create_dir_all(w.join("dst/bar")).unwrap();
    symlink("bar", w.join("dst/link")).unwrap();
}

fn beneath_dead(w: &Path) {
    std::fs::create_dir_all(w.join("dst")).unwrap();
    symlink("dead", w.join("dst/link")).unwrap();
}

fn beneath_refuse(w: &Path) {
    std::fs::create_dir_all(w.join("dst")).unwrap();
    std::fs::create_dir_all(w.join("bar")).unwrap();
    symlink("../bar", w.join("dst/link")).unwrap();
}

fn beneath_absolute(w: &Path) {
    std::fs::create_dir_all(w.join("dst/bar")).unwrap();
    symlink(w.join("dst/bar"), w.join("dst/link")).unwrap();
}

fn beneath_cwd(w: &Path) {
    std::fs::create_dir_all(w.join("out")).unwrap();
    symlink("out", w.join("inside")).unwrap();
    symlink("../..", w.join("link")).unwrap();
}

/// beneath.sh: beneath_allow (a symlink inside the root is followed),
/// beneath_dead ("cannot enter", `No such file or directory`),
/// beneath_refuse (outside: "cannot enter", `Permission denied`),
/// beneath_create (the root is made); and the same with an absolute link
/// inside the root, without `-d`, and deeper paths through the links.
#[test]
fn apples_beneath_sh() {
    let z = zip_with(
        &[ZipEntrySpec::new(b"link/file.txt", b"Hello, world!\n")],
        b"",
        b"",
    );
    let deep = zip_with(
        &[
            ZipEntrySpec::new(b"link/sub/file.txt", b"deeper\n"),
            mode_entry(b"link/newdir/", b"", 0o40755),
            ZipEntrySpec::new(b"inside/ok.txt", b"through an inside link\n"),
        ],
        b"",
        b"",
    );
    let mut cases = Vec::new();
    for (name, bytes) in [("beneath.zip", z), ("deep.zip", deep)] {
        let files = [(name, bytes)];
        for setup in [
            beneath_allow as fn(&Path),
            beneath_dead,
            beneath_refuse,
            beneath_absolute,
        ] {
            cases.push(prepared(case(&["-d", "dst", name], &files), setup));
            cases.push(prepared(case(&["-o", "-d", "dst", name], &files), setup));
        }
        cases.push(case(&["-d", "dst", name], &files)); // beneath_create
        cases.push(prepared(case(&[name], &files), beneath_cwd));
    }
    compare("apples_beneath_sh", &cases);
}

/// quarantine.sh's archive: `dir/subdir/file` and `dir/subdir/link ->
/// file`.
fn quarantine_zip() -> Vec<u8> {
    zip_with(
        &[
            ZipEntrySpec::new(b"dir/subdir/file", b"Hello, world!\n"),
            link_entry(b"dir/subdir/link", b"file"),
            mode_entry(b"dir2/", b"", 0o40755),
        ],
        b"",
        b"",
    )
}

fn qtn_test(w: &Path) {
    set_quarantine(&w.join("q.zip"), b"0082;688909f7;Test;");
}

fn qtn_safari(w: &Path) {
    set_quarantine(
        &w.join("q.zip"),
        b"0001;5f000000;Safari;ABCDEF01-2345-6789-ABCD-EF0123456789",
    );
}

fn qtn_dropped(w: &Path) {
    set_quarantine(&w.join("q.zip"), b"4000;5f000000;Safari;");
}

fn qtn_three_fields(w: &Path) {
    set_quarantine(&w.join("q.zip"), b"0181;5f000000;Safari");
}

fn qtn_existing_dst(w: &Path) {
    qtn_test(w);
    std::fs::create_dir(w.join("dst")).unwrap();
}

/// quarantine.sh's `quarantine`: the archive's quarantine reaches every
/// file, directory and symlink made, and a `-d` root made; not a root that
/// was there. P7's rewrite (`0001` becomes `0081`, a dropped value, a value
/// of three fields).
#[test]
fn quarantine_propagates() {
    let files = [("q.zip", quarantine_zip())];
    let mut cases = Vec::new();
    for setup in [
        qtn_test as fn(&Path),
        qtn_safari,
        qtn_dropped,
        qtn_three_fields,
        qtn_existing_dst,
    ] {
        cases.push(prepared(case(&["q.zip", "-d", "dst"], &files), setup));
        cases.push(prepared(case(&["q.zip"], &files), setup));
    }
    compare("quarantine_propagates", &cases);
}

/// quarantine.sh's `no_quarantine`: without one on the archive nothing
/// gets one.
#[test]
fn no_quarantine_without_one() {
    let files = [("q.zip", quarantine_zip())];
    compare(
        "no_quarantine_without_one",
        &[
            case(&["q.zip", "-d", "dst"], &files),
            prepared(case(&["q.zip", "-d", "dst"], &files), existing_out_dir),
        ],
    );
}

/// The quarantine sweep's rewritten flags, pinned stuffr-only (P7): `0001`
/// becomes `0081` on what is extracted.
#[test]
fn quarantine_0001_becomes_0081() {
    let files = [("q.zip", quarantine_zip())];
    let s = stuffr_unzip(&prepared(case(&["q.zip", "-d", "dst"], &files), qtn_safari));
    assert_eq!(s.code, 0, "{}", s.stderr);
    let want = b"0081;5f000000;Safari;ABCDEF01-2345-6789-ABCD-EF0123456789".to_vec();
    for rel in [
        &b"dst"[..],
        b"dst/dir",
        b"dst/dir/subdir/file",
        b"dst/dir/subdir/link",
    ] {
        let q = match s.tree.get(rel).unwrap() {
            UnzipNode::File { quarantine, .. }
            | UnzipNode::Dir { quarantine, .. }
            | UnzipNode::Symlink { quarantine, .. } => quarantine.clone(),
        };
        assert_eq!(q.as_ref(), Some(&want), "{}", String::from_utf8_lossy(rel));
    }
}
