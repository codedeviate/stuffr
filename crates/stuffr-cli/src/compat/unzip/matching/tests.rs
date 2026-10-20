//! `match.c`'s semantics, case by case.

use super::{iswild, matches};

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
