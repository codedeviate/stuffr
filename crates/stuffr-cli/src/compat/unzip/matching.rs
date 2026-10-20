//! `match.c`: unzip's wildcards (`match()`, `recmatch()`, `isshexp()`,
//! `namecmp()`, `iswild()`).
//!
//! Strings are C strings: a name or pattern ends at its first NUL, as the
//! C sees it (an archive name holding a NUL is shorter than its length
//! field says, `fileio.c`'s `do_string()`). Neither build defines `_MBCS`,
//! so a character is a byte (`CLEN(p)` is 1), and `ToLower` is unix's
//! `isupper(c) ? tolower(c) : c`, which is ASCII-only under every locale
//! deviation 6 admits (probe: `LANG=en_US.UTF-8 unzip -LL -l` keeps
//! `0xc0..0xde`).
//!
//! `recmatch` recurses only at `*` here: the C's other recursive calls are
//! tail calls (a literal, `?`, a bracket), which are a loop. So the depth is
//! the pattern's number of stars, as deep as the C's, and the result is the
//! C's for every input.

/// unix `ToLower`: `isupper(c) ? tolower(c) : c` in the C locale.
fn to_lower(c: u8) -> u8 {
    c.to_ascii_lowercase()
}

/// The byte at `i` of a C string held in `s`: past the end, or past a
/// NUL, it is the terminator.
fn at(s: &[u8], i: usize) -> u8 {
    s.get(i).copied().unwrap_or(0)
}

/// `s` up to its first NUL (the C string it holds).
fn c_str(s: &[u8]) -> &[u8] {
    match s.iter().position(|&b| b == 0) {
        Some(n) => &s[..n],
        None => s,
    }
}

// port: match.c:match
/// `match(string, pattern, ignore_case, sepc)`: whether `name` matches the
/// wildcard `pattern`. `ignore_case` is `-C` (and zipinfo's `-C`);
/// `stop_at_dir` is `WILD_STOP_AT_DIR` with `uO.W_flag` set (`sepc` `/`;
/// Ubuntu's `-W`, `flavour::wild_stop_at_dir`), else `sepc` is 0, which is
/// the code a build without `WILD_STOP_AT_DIR` runs.
///
/// `*` matches any run of bytes, `?` one byte, `[...]` a set (`[!...]` or
/// `[^...]` its complement, `a-z` a range), and `\` makes the next byte
/// literal; with `stop_at_dir`, `*` and `?` do not match `/` and `**` does.
pub(crate) fn matches(pattern: &[u8], name: &[u8], ignore_case: bool, stop_at_dir: bool) -> bool {
    let sepc = if stop_at_dir { b'/' } else { 0 };
    recmatch(c_str(pattern), c_str(name), ignore_case, sepc) == 1
}

// port: match.c:recmatch
/// 1 if `s` matches `p`, 0 if it does not, 2 if it cannot (the C's "give
/// up", which `match()` reads as no match). `p` and `s` hold no NUL.
fn recmatch(mut p: &[u8], mut s: &[u8], ic: bool, sepc: u8) -> i32 {
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
                        let r = recmatch(p, s, ic, sepc);
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
                let r = recmatch(p, s, ic, sepc);
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
                                return recmatch(p, s, ic, sepc);
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

// port: match.c:isshexp
/// The index of the first wildcard character (`?`, `*`, `[`) not escaped
/// by `\`, if `p` holds one.
fn isshexp(p: &[u8]) -> Option<usize> {
    let mut i = 0;
    while at(p, i) != 0 {
        let c = at(p, i);
        if c == b'\\' && at(p, i + 1) != 0 {
            i += 1;
        } else if c == b'?' || c == b'*' || c == b'[' {
            return Some(i);
        }
        i += 1;
    }
    None
}

// port: match.c:namecmp
/// `strcmp` ignoring ASCII case.
fn namecmp(s1: &[u8], s2: &[u8]) -> i32 {
    let mut i = 0;
    loop {
        let (a, b) = (at(s1, i), at(s2, i));
        let d = i32::from(to_lower(a)) - i32::from(to_lower(b));
        if d != 0 || a == 0 || b == 0 {
            return d;
        }
        i += 1;
    }
}

// port: match.c:iswild
/// Whether `p` holds a wildcard (`?`, `*`, `[`) not escaped by `\`.
pub(crate) fn iswild(p: &[u8]) -> bool {
    isshexp(c_str(p)).is_some()
}

#[cfg(test)]
mod tests;
