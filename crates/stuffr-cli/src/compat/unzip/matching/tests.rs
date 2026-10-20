//! `match.c`'s semantics, case by case.

use super::{at, isshexp, iswild, matches, namecmp, recmatch, to_lower};

fn m(p: &str, s: &str) -> bool {
    matches(p.as_bytes(), s.as_bytes(), false, false)
}

#[test]
fn star_matches_any_run_including_slashes() {
    assert!(m("*", ""));
    assert!(m("*", "a/b/c"));
    assert!(m("*.txt", "dir/a.txt"));
    assert!(m("a*", "a"));
    assert!(!m("*.txt", "a.txz"));
    assert!(m("a*b*c", "aXXbYYc"));
    assert!(!m("a*b*c", "aXXbYY"));
    // The literal tail is compared from the end.
    assert!(m("*abc", "abcabc"));
    assert!(!m("*abcd", "abc"));
}

#[test]
fn a_double_star_needs_a_byte_without_wild_stop_at_dir() {
    // `**` recurses over the bytes of a non-empty rest only: "a**" does not
    // match "a" (the loop never tries the empty rest), "a*" does.
    assert!(m("a*", "a"));
    assert!(!m("a**", "a"));
    assert!(m("a**", "ab"));
}

#[test]
fn question_mark_is_one_byte() {
    assert!(m("?", "a"));
    assert!(!m("?", ""));
    assert!(!m("?", "ab"));
    assert!(m("a?c", "a/c"));
}

#[test]
fn brackets_sets_ranges_and_complements() {
    assert!(m("[abc]", "b"));
    assert!(!m("[abc]", "d"));
    assert!(m("[a-c]x", "bx"));
    assert!(!m("[a-c]x", "dx"));
    assert!(m("[!a-c]", "d"));
    assert!(m("[^a-c]", "d"));
    assert!(!m("[!a-c]", "b"));
    // A leading `-` is literal; so is an escaped one.
    assert!(m("[-a]", "-"));
    assert!(m("[a\\-c]", "-"));
    assert!(!m("[a\\-c]", "b"));
    // A reversed range matches nothing of it.
    assert!(!m("[c-a]", "b"));
    // Unterminated: nothing matches.
    assert!(!m("[abc", "a"));
    assert!(!m("[abc", "[abc"));
    // A set needs a byte.
    assert!(!m("[a]", ""));
    // `]` first closes an empty set: `[]` then a literal `]`... is a set
    // that matches nothing, followed by the rest.
    assert!(!m("[]]", "]"));
}

#[test]
fn backslash_makes_the_next_byte_literal() {
    assert!(m("\\*", "*"));
    assert!(!m("\\*", "a"));
    assert!(m("a\\?", "a?"));
    assert!(!m("a\\?", "ab"));
    // A trailing backslash is a syntax error: no match.
    assert!(!m("a\\", "a"));
    assert!(!m("a\\", "a\\"));
}

#[test]
fn case_folding_is_ascii_only() {
    assert!(!m("ABC", "abc"));
    assert!(matches(b"ABC", b"abc", true, false));
    assert!(matches(b"*.TXT", b"a.txt", true, false));
    assert!(matches(b"[A-C]", b"b", true, false));
    // High bytes are never folded (probe: `LANG=en_US.UTF-8 unzip -LL -l`
    // keeps 0xc0..0xde).
    assert!(!matches(b"\xc9", b"\xe9", true, false));
}

#[test]
fn wild_stop_at_dir_keeps_star_and_question_mark_inside_a_component() {
    let w = |p: &str, s: &str| matches(p.as_bytes(), s.as_bytes(), false, true);
    assert!(!w("*", "a/b"));
    assert!(w("*/b", "a/b"));
    assert!(w("**", "a/b"));
    assert!(w("**.txt", "d/e/f.txt"));
    assert!(!w("*.txt", "d/f.txt"));
    assert!(!w("a?b", "a/b"));
    assert!(w("a?b", "axb"));
    // A `*` followed by an escaped separator continues the match.
    assert!(w("*\\/b", "a/b"));
    // Without the flag the same patterns cross `/`.
    assert!(m("*", "a/b"));
    assert!(m("a?b", "a/b"));
}

#[test]
fn names_are_c_strings() {
    // A NUL ends the name, as G.filename is a C string.
    assert!(m("ab", "ab\0cd"));
    assert!(m("ab", "ab\0"));
}

#[test]
fn iswild_finds_unescaped_wildcards() {
    assert!(iswild(b"*.zip"));
    assert!(iswild(b"a?"));
    assert!(iswild(b"[ab]"));
    assert!(!iswild(b"a.zip"));
    assert!(!iswild(b"\\*.zip"));
    assert!(iswild(b"\\\\*"));
    assert!(!iswild(b"a\\"));
}

/// The first port, recursive as the C is at every call (Task 8's
/// commit): the oracle the stack-free [`recmatch`] is checked against.
/// 1 if `s` matches `p`, 0 if it does not, 2 if it cannot (the C's "give
/// up", which `match()` reads as no match). `p` and `s` hold no NUL.
fn recursive(mut p: &[u8], mut s: &[u8], ic: bool, sepc: u8) -> i32 {
    let case = |x: u8| if ic { to_lower(x) } else { x };
    loop {
        // Get first character, the pattern for new recmatch calls follows
        let c = at(p, 0);
        p = p.get(1..).unwrap_or(&[]);

        // If that was the end of the pattern, match if string empty too
        if c == 0 {
            return i32::from(at(s, 0) == 0);
        }

        // '?' matches any character (but not an empty string)
        if c == b'?' {
            // ubuntu: -DWILD_STOP_AT_DIR (with -W it won't match '/')
            if at(s, 0) != 0 && (sepc == 0 || at(s, 0) != sepc) {
                s = &s[1..];
                continue;
            }
            return 0;
        }

        // '*' matches any number of characters, including zero
        if c == b'*' {
            // ubuntu: -DWILD_STOP_AT_DIR
            if sepc != 0 {
                // check for single "*" or double "**"
                if at(p, 0) != b'*' {
                    // single "*": this doesn't match the dirsep character
                    while at(s, 0) != 0 && at(s, 0) != sepc {
                        let r = recursive(p, s, ic, sepc);
                        if r != 0 {
                            return r;
                        }
                        s = &s[1..];
                    }
                    // end of pattern: matched if at end of string, else
                    // continue
                    if at(p, 0) == 0 {
                        return i32::from(at(s, 0) == 0);
                    }
                    // continue to match if at sepc in pattern, else give up
                    if at(p, 0) == sepc || (at(p, 0) == b'\\' && at(p, 1) == sepc) {
                        continue;
                    }
                    return 2;
                }
                // "**": this matches slashes
                p = &p[1..];
                // and continue with the non-W_flag code variant
            }
            if at(p, 0) == 0 {
                return 1;
            }
            if isshexp(p).is_none() {
                // Optimization for rest of pattern being a literal string:
                // compare the literal string tail.
                if s.len() < p.len() {
                    // remaining literal string from pattern is longer than
                    // rest of test string, there can't be a match
                    return 0;
                }
                let srest = &s[s.len() - p.len()..];
                return i32::from(if ic {
                    namecmp(p, srest) == 0
                } else {
                    p == srest
                });
            }
            // pattern contains more wildcards, continue with recursion...
            while at(s, 0) != 0 {
                let r = recursive(p, s, ic, sepc);
                if r != 0 {
                    return r;
                }
                s = &s[1..];
            }
            return 2; // 2 means give up--match will return false
        }

        // Parse and process the list of characters and ranges in brackets
        if c == b'[' {
            if at(s, 0) == 0 {
                // need a character to match
                return 0;
            }
            let r = at(p, 0) == b'!' || at(p, 0) == b'^'; // see if reverse
            if r {
                p = &p[1..];
            }
            // find closing bracket
            let mut q = 0usize;
            let mut e = false;
            while at(p, q) != 0 {
                if e {
                    e = false;
                } else if at(p, q) == b'\\' {
                    e = true;
                } else if at(p, q) == b']' {
                    break;
                }
                q += 1;
            }
            if at(p, q) != b']' {
                // nothing matches if bad syntax
                return 0;
            }
            // go through the list
            let mut cr: u32 = 0; // start of a range
            let mut e = at(p, 0) == b'-';
            let cc = u32::from(case(at(s, 0)));
            for i in 0..q {
                let pi = at(p, i);
                if !e && pi == b'\\' {
                    // set escape flag if \
                    e = true;
                } else if !e && pi == b'-' {
                    // set start of range if -
                    cr = u32::from(at(p, i.wrapping_sub(1)));
                } else {
                    if at(p, i + 1) != b'-' {
                        // compare range
                        let mut c = if cr != 0 { cr } else { u32::from(pi) };
                        while c <= u32::from(pi) {
                            // `Case(c)` of an unsigned int: its low byte
                            if u32::from(case(c as u8)) == cc {
                                if r {
                                    return 0;
                                }
                                p = &p[q + 1..];
                                s = &s[1..];
                                return recursive(p, s, ic, sepc);
                            }
                            c += 1;
                        }
                    }
                    cr = 0; // clear range, escape flags
                    e = false;
                }
            }
            // bracket match failed
            if r {
                p = &p[q + 1..];
                s = &s[1..];
                continue;
            }
            return 0;
        }

        // if escape ('\\'), just compare next character
        let c = if c == b'\\' {
            let n = at(p, 0);
            if n == 0 {
                // if \ at end, then syntax error
                return 0;
            }
            p = &p[1..];
            n
        } else {
            c
        };

        // just a character--compare it
        if case(c) == case(at(s, 0)) && at(s, 0) != 0 {
            s = &s[1..];
            continue;
        }
        // `Case(c) == Case(*s)` with `*s` the terminator: `c` is never 0
        // here, so this is a mismatch.
        return 0;
    }
}

/// The stack-free `recmatch` gives the recursive port's 0, 1 or 2 for every
/// pattern and name of a small alphabet that holds every syntax byte
/// (xorshift, fixed seed): 200,000 pairs, both case modes, both
/// separator modes.
#[test]
fn the_stack_free_recmatch_answers_as_the_recursive_one() {
    const ALPHA: &[u8] = b"**??[]!^-\\/aabAB";
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut counts = [0usize; 3];
    for _ in 0..200_000 {
        let pl = (next() % 9) as usize;
        let sl = (next() % 7) as usize;
        let p: Vec<u8> = (0..pl)
            .map(|_| ALPHA[(next() % ALPHA.len() as u64) as usize])
            .collect();
        let s: Vec<u8> = (0..sl)
            .map(|_| b"aab/AB-]"[(next() % 8) as usize])
            .collect();
        let ic = next() % 2 == 0;
        let sepc = if next() % 2 == 0 { b'/' } else { 0 };
        let want = recursive(&p, &s, ic, sepc);
        assert_eq!(
            recmatch(&p, &s, ic, sepc),
            want,
            "pattern {:?} name {:?} ic {ic} sepc {sepc}",
            String::from_utf8_lossy(&p),
            String::from_utf8_lossy(&s)
        );
        counts[want as usize] += 1;
    }
    // Every answer occurs, so the comparison is not vacuous.
    assert!(counts.iter().all(|&n| n > 1000), "{counts:?}");
}

/// 16,000 stars (the most an argument under unzip's 16,224-byte limit
/// holds with room for a name) on a 2 MiB stack: no recursion, and Apple's
/// answer (probe: `unzip -l a.zip "<16000 stars>"` lists `a.txt`, exit 0;
/// with `-W`-style separators the same).
#[test]
fn sixteen_thousand_stars_need_no_stack() {
    let stars = vec![b'*'; 16_000];
    let ok = std::thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(move || {
            (
                matches(&stars, b"a.txt", false, false),
                matches(&stars, b"dir/a.txt", false, true),
                matches(&[&stars[..], b"a.txt"].concat(), b"a.txt", false, false),
                // A bracket after every star: the stack is the stars'.
                matches(&b"*[a]".repeat(4000), &[b'a'; 4000], false, false),
            )
        })
        .unwrap()
        .join()
        .unwrap();
    assert_eq!(ok, (true, true, true, true));
}
