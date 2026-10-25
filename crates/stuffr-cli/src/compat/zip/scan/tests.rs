use super::*;

fn cx() -> Cx {
    Cx {
        no_wild: false,
        allow_regex: true,
        wild_stop_at_dir: false,
    }
}

fn ex(x: &str) -> Option<String> {
    ex2in(x.as_bytes(), true, false).map(|v| String::from_utf8(v).unwrap())
}

#[test]
fn ex2in_strips_what_zip_strips() {
    assert_eq!(ex("a.txt").as_deref(), Some("a.txt"));
    assert_eq!(ex("/a.txt").as_deref(), Some("a.txt"));
    assert_eq!(ex("///a.txt").as_deref(), Some("a.txt"));
    assert_eq!(ex("./a.txt").as_deref(), Some("a.txt"));
    assert_eq!(ex("././a.txt").as_deref(), Some("a.txt"));
    assert_eq!(ex("/./a.txt").as_deref(), Some("a.txt"));
    assert_eq!(ex("../a.txt").as_deref(), Some("../a.txt"));
    assert_eq!(ex("d/./a.txt").as_deref(), Some("d/./a.txt"));
    assert_eq!(ex("d/").as_deref(), Some("d/"));
    assert_eq!(ex("./").as_deref(), Some(""));
    assert_eq!(ex("").as_deref(), Some(""));
    // a UNC name loses its host and share
    assert_eq!(ex("//host/share/x/y").as_deref(), Some("x/y"));
    assert_eq!(ex("//host/share/").as_deref(), Some(""));
    // `//` and `///x` are not UNC
    assert_eq!(ex("//").as_deref(), Some(""));
    assert_eq!(ex("///x").as_deref(), Some("x"));
}

/// The C dereferences NULL for a UNC name with nothing after the share
/// (deviation 8): `None`, which callers answer as the crash is.
#[test]
fn ex2in_has_no_name_for_a_bare_unc_host_or_share() {
    for x in ["//host", "//host/", "//host/share", "//tmp"] {
        assert_eq!(ex(x), None, "{x}");
    }
}

#[test]
fn ex2in_without_paths_keeps_the_last_component() {
    let j = |x: &str| String::from_utf8(ex2in(x.as_bytes(), false, false).unwrap()).unwrap();
    assert_eq!(j("d/c.txt"), "c.txt");
    assert_eq!(j("a.txt"), "a.txt");
    assert_eq!(j("d/"), "");
    assert_eq!(j("./d/e/"), "");
    assert_eq!(j("/x/y"), "y");
}

#[test]
fn msname_makes_upper_case_8_3_names() {
    let d = |x: &str| String::from_utf8(ex2in(x.as_bytes(), true, true).unwrap()).unwrap();
    assert_eq!(d("b.txt"), "B.TXT");
    assert_eq!(d("d/c.txt"), "D/C.TXT");
    assert_eq!(d("My File.tar.gz"), "MYFILE.TAR");
    assert_eq!(d("long_filename.text"), "LONG_FIL.TEX");
    assert_eq!(d(".hidden"), "HIDDEN");
    assert_eq!(d("a+b,c;d=e[f]g|h"), "ABCDEFGH");
    assert_eq!(d("dir.x/sub dir/f"), "DIR.X/SUBDIR/F");
    assert_eq!(d("no_dot_but_long_name"), "NO_DOT_B");
}

fn m(p: &str, s: &str) -> bool {
    shmatch(p.as_bytes(), s.as_bytes(), cx())
}

#[test]
fn shmatch_follows_recmatch() {
    assert!(m("*.txt", "a.txt"));
    assert!(m("*.txt", "d/c.txt"), "a star crosses slashes by default");
    assert!(!m("*.txt", "a.txt.bak"));
    assert!(m("a?c", "abc"));
    assert!(!m("a?c", "ac"));
    assert!(m("a*", "a"));
    assert!(m("*", ""));
    assert!(m("", ""));
    assert!(!m("", "a"));
    assert!(m("d/*", "d/c.txt"));
    assert!(m("*a*b*", "xaxbx"));
    assert!(!m("*a*b*", "xbxax"));
    // brackets
    assert!(m("[a-c].txt", "b.txt"));
    assert!(!m("[a-c].txt", "d.txt"));
    assert!(m("[!a-c].txt", "d.txt"));
    assert!(m("[^a-c].txt", "d.txt"));
    // the C finds the closing bracket from the first character, so `[]x]`
    // is the set `[` + `]x]`: a bad set that matches nothing
    assert!(!m("[]x]", "]"));
    // a trailing `-` makes no range and matches nothing (as the reference)
    assert!(!m("[a-]", "-"));
    assert!(!m("[a-]", "a"));
    assert!(m("[-a]", "-"));
    assert!(m("[a\\]]", "]"));
    assert!(!m("[a", "a"), "a bad set matches nothing");
    assert!(!m("[abc", "a"));
    // escapes
    assert!(m("\\*", "*"));
    assert!(!m("\\*", "a"));
    assert!(m("a\\?", "a?"));
    assert!(!m("a\\", "a"), "a `\\` at the end is a syntax error");
}

#[test]
fn a_star_that_is_the_last_wildcard_compares_the_end_literally() {
    assert!(m("*.t?t", "a.txt"));
    assert!(m("*xt", "a.txt"));
    assert!(!m("*xt", "a.txtx"));
    assert!(!m("*longer", "short"));
}

#[test]
fn wild_stop_at_dir_keeps_a_star_inside_one_component() {
    let ws = Cx {
        wild_stop_at_dir: true,
        ..cx()
    };
    let w = |p: &str, s: &str| shmatch(p.as_bytes(), s.as_bytes(), ws);
    assert!(w("*.txt", "a.txt"));
    assert!(!w("*.txt", "d/c.txt"));
    assert!(w("**.txt", "d/c.txt"));
    assert!(w("d/*", "d/c.txt"));
    assert!(!w("d/*", "d/e/c.txt"));
    assert!(w("d/**", "d/e/c.txt"));
    assert!(w("d/*/c.txt", "d/e/c.txt"));
    assert!(!w("a?c", "a/c"));
    assert!(w("*", "abc"));
    assert!(!w("*", "a/c"));
}

#[test]
fn nw_turns_off_stars_brackets_and_escapes_but_not_question_marks() {
    let nw = Cx {
        no_wild: true,
        ..cx()
    };
    let w = |p: &str, s: &str| shmatch(p.as_bytes(), s.as_bytes(), nw);
    assert!(w("*", "*"));
    assert!(!w("*", "abc"));
    assert!(w("[a]", "[a]"));
    assert!(w("a\\b", "a\\b"));
    assert!(w("a?c", "abc"), "`?` is still a wildcard (the C's order)");
    let re = Cx {
        allow_regex: false,
        ..cx()
    };
    assert!(shmatch(b"[a]", b"[a]", re));
    assert!(!shmatch(b"[a]", b"a", re));
}

fn pats(list: &[(u8, &str)]) -> Vec<Filter> {
    list.iter()
        .map(|&(flag, p)| Filter {
            flag,
            pattern: p.as_bytes().to_vec(),
        })
        .collect()
}

fn f(list: &[(u8, &str)], name: &str) -> bool {
    filter(&pats(list), cx(), name.as_bytes())
}

#[test]
fn filter_gives_x_precedence_and_needs_a_match_in_i_and_in_r() {
    assert!(f(&[], "anything"));
    // -x alone excludes what it matches
    assert!(f(&[(b'x', "*.o")], "a.c"));
    assert!(!f(&[(b'x', "*.o")], "a.o"));
    // -i alone includes only what it matches
    assert!(f(&[(b'i', "*.c")], "a.c"));
    assert!(!f(&[(b'i', "*.c")], "a.o"));
    // -x wins over -i
    assert!(!f(&[(b'i', "*.c"), (b'x', "a*")], "a.c"));
    assert!(f(&[(b'i', "*.c"), (b'x', "a*")], "b.c"));
    // -R and -i both need a match
    assert!(f(&[(b'R', "*.c"), (b'i', "src/*")], "src/a.c"));
    assert!(!f(&[(b'R', "*.c"), (b'i', "src/*")], "lib/a.c"));
    assert!(!f(&[(b'R', "*.c"), (b'i', "src/*")], "src/a.h"));
    // an empty pattern is skipped
    assert!(f(&[(b'x', "")], "a"));
    assert!(!f(&[(b'i', "")], "a"));
}

#[test]
fn an_r_pattern_is_tested_against_the_last_components_of_the_name() {
    // one component: the last one of the name
    assert!(f(&[(b'R', "c.txt")], "d/c.txt"));
    assert!(f(&[(b'R', "c.txt")], "a/b/c.txt"));
    assert!(!f(&[(b'R', "c.txt")], "d/c.txt.bak"));
    // two components: the last two
    assert!(f(&[(b'R', "d/c.txt")], "a/d/c.txt"));
    assert!(!f(&[(b'R', "d/c.txt")], "c.txt"));
    assert!(f(&[(b'R', "*/*.txt")], "x/d/c.txt"));
    // a pattern with more components than the name is tried whole
    assert!(!f(&[(b'R', "a/b/c")], "b/c"));
}

#[test]
fn the_display_name_of_ubuntu_escapes_control_bytes_apple_shows_them() {
    // `display` needs a run; the rule is the bytes below a space
    let esc = |b: &[u8]| {
        let mut out = Vec::new();
        for &c in b {
            if c < b' ' {
                out.push(b'^');
                out.push(b'@' + c);
            } else {
                out.push(c);
            }
        }
        out
    };
    assert_eq!(esc(b"new\nline"), b"new^Jline");
    assert_eq!(esc(b"tab\there"), b"tab^Ihere");
    assert_eq!(esc(b"\x7f\xe9"), b"\x7f\xe9");
}

fn sorted_by_key(keys: &[u8]) -> Vec<usize> {
    let mut v: Vec<usize> = (0..keys.len()).collect();
    bsd_qsort(&mut v, &|a, b| keys[a].cmp(&keys[b]));
    v
}

#[test]
fn the_bsd_qsort_sorts() {
    // a small linear congruential generator: no dependency, a fixed seed
    let mut s: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (s >> 33) as usize
    };
    for _ in 0..300 {
        let n = next() % 150;
        let m = 1 + next() % 8;
        let keys: Vec<u8> = (0..n).map(|_| (next() % m) as u8).collect();
        let order = sorted_by_key(&keys);
        let got: Vec<u8> = order.iter().map(|&i| keys[i]).collect();
        let mut want = keys.clone();
        want.sort_unstable();
        assert_eq!(got, want, "{keys:?}");
        // a permutation
        let mut seen = order.clone();
        seen.sort_unstable();
        assert_eq!(seen, (0..n).collect::<Vec<_>>());
    }
}

/// Below eight elements the BSD sort is an insertion sort: stable. Ubuntu's
/// is stable at every size.
#[test]
fn small_arrays_keep_equal_keys_in_order_and_ubuntu_always_does() {
    let keys = [0u8, 0, 1, 0, 0, 0, 0];
    assert_eq!(sorted_by_key(&keys), [0, 1, 3, 4, 5, 6, 2]);
    let many: Vec<u8> = (0..200u32).map(|i| (i * 7 % 5) as u8).collect();
    let mut v: Vec<usize> = (0..many.len()).collect();
    qsort(flavour::Flavour::Ubuntu, &mut v, &|a, b| {
        many[a].cmp(&many[b])
    });
    let mut want: Vec<usize> = (0..many.len()).collect();
    want.sort_by_key(|&i| many[i]);
    assert_eq!(v, want);
}

/// macOS's `qsort`, recorded: for `[0,0,1,0,0,0,0,0,0,0,0,0]` and the
/// 14-element array of the port's calibration. The three-way partition
/// leaves the equal keys in the order libc left them.
#[test]
fn the_bsd_qsort_matches_macos_on_recorded_arrays() {
    // key arrays and macOS's `qsort` permutation of their indexes (a
    // `struct { int key; int idx; }` sorted on `key`), from a C program
    let cases: [(&[u8], &[usize]); 2] = [
        (&[0, 0, 1, 0, 0, 0, 0], &[0, 1, 3, 4, 5, 6, 2]),
        (
            &[1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 2, 1, 2],
            &[4, 9, 5, 11, 12, 2, 3, 14, 0, 1, 6, 7, 8, 10, 13, 16, 17, 15],
        ),
    ];
    for (keys, want) in cases {
        assert_eq!(sorted_by_key(keys), want, "{keys:?}");
    }
}

struct Scratch(std::path::PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A tree as deep as the system lets a path be (up to 1500 single-letter
/// levels; macOS stops near 500, Linux near 2000) is walked on a thread
/// with the default 2 MiB stack, in a debug build, without overflowing.
#[test]
fn a_very_deep_tree_does_not_overflow_the_stack() {
    let root =
        Scratch(std::env::temp_dir().join(format!("stuffr-zipscan-{}-deep", std::process::id())));
    let _ = std::fs::remove_dir_all(&root.0);
    std::fs::create_dir_all(&root.0).unwrap();
    let mut rel = std::path::PathBuf::new();
    let mut levels = 0;
    for _ in 0..1500 {
        rel.push("d");
        if std::fs::create_dir(root.0.join(&rel)).is_err() {
            break;
        }
        levels += 1;
    }
    assert!(levels > 200, "only {levels} levels");
    let dir = root.0.clone();
    let h = std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(move || {
            let args = ["-sf", "-r", "t.zip", "d"]
                .map(std::ffi::OsString::from)
                .to_vec();
            super::super::run_in(&dir, "zip", args, b"", flavour::Flavour::Ubuntu)
        })
        .unwrap();
    let (code, out, _) = h.join().expect("the walk overflowed or panicked");
    assert_eq!(code, 0);
    assert!(
        String::from_utf8_lossy(&out).contains("Total "),
        "{}",
        String::from_utf8_lossy(&out)
    );
}
