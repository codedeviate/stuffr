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
//! `recmatch` does not recurse: the C's recursion at each `*` is an
//! explicit stack of open `*` loops (at most one per star, so bounded by
//! the pattern's length), and its other recursive calls are tail calls,
//! which are a loop. The 0/1/2 answers propagate as the C's do, so the
//! result is the C's for every input, and a pattern of 16,000 stars needs
//! no deeper stack than one star.

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
/// 1 if `s` matches `pat`, 0 if it does not, 2 if it cannot (the C's "give
/// up", which `match()` reads as no match). `pat` and `s` hold no NUL.
///
/// The C recurses at each `*`: a loop over the positions of `s`, calling
/// itself on the rest of the pattern and returning the first nonzero
/// answer. Every caller returns a nonzero answer as it gets it, so the
/// first 1 or 2 anywhere is the whole match's answer; only a 0 sends a
/// `*` on to its next position. That is a depth-first search, kept here
/// as an explicit stack of the open `*` loops ([`Star`]), one per star at
/// most, so no pattern can exhaust the thread's stack. Its other recursive
/// calls (a literal, `?`, a bracket, `WILD_STOP_AT_DIR`'s continuation)
/// are tail calls: the loop goes on in place.
fn recmatch(pat: &[u8], s: &[u8], ic: bool, sepc: u8) -> i32 {
    let case = |x: u8| if ic { to_lower(x) } else { x };
    let mut stack: Vec<Star> = Vec::new();
    // The call being evaluated: pattern from `pi`, string from `si`.
    let (mut pi, mut si) = (0usize, 0usize);
    'call: loop {
        let r: i32 = 'eval: loop {
            // Get first character, the pattern for new recmatch calls
            // follows
            let c = at(pat, pi);
            pi += 1;

            // If that was the end of the pattern, match if string empty too
            if c == 0 {
                break 'eval i32::from(at(s, si) == 0);
            }

            // '?' matches any character (but not an empty string)
            if c == b'?' {
                // ubuntu: -DWILD_STOP_AT_DIR (with -W it won't match '/')
                if at(s, si) != 0 && (sepc == 0 || at(s, si) != sepc) {
                    si += 1;
                    continue 'eval;
                }
                break 'eval 0;
            }

            // '*' matches any number of characters, including zero
            if c == b'*' {
                // ubuntu: -DWILD_STOP_AT_DIR
                if sepc != 0 {
                    // check for single "*" or double "**"
                    if at(pat, pi) != b'*' {
                        // single "*": this doesn't match the dirsep
                        // character: for each position before one, try the
                        // rest of the pattern there
                        if at(s, si) != 0 && at(s, si) != sepc {
                            stack.push(Star {
                                p: pi,
                                s: si,
                                component: true,
                            });
                            continue 'eval;
                        }
                        match after_component(pat, s, pi, si, sepc) {
                            None => continue 'eval,
                            Some(r) => break 'eval r,
                        }
                    }
                    // "**": this matches slashes
                    pi += 1;
                    // and continue with the non-W_flag code variant
                }
                if at(pat, pi) == 0 {
                    break 'eval 1;
                }
                let p = &pat[pi..];
                if isshexp(p).is_none() {
                    // Optimization for rest of pattern being a literal
                    // string: compare the literal string tail.
                    let rest = &s[si.min(s.len())..];
                    if rest.len() < p.len() {
                        // remaining literal string from pattern is longer
                        // than rest of test string, there can't be a match
                        break 'eval 0;
                    }
                    let srest = &rest[rest.len() - p.len()..];
                    break 'eval i32::from(if ic {
                        namecmp(p, srest) == 0
                    } else {
                        p == srest
                    });
                }
                // pattern contains more wildcards, continue with
                // recursion... (for each position of the string)
                if at(s, si) != 0 {
                    stack.push(Star {
                        p: pi,
                        s: si,
                        component: false,
                    });
                    continue 'eval;
                }
                break 'eval 2; // 2 means give up--match will return false
            }

            // Parse and process the list of characters and ranges in
            // brackets
            if c == b'[' {
                if at(s, si) == 0 {
                    // need a character to match
                    break 'eval 0;
                }
                let r = at(pat, pi) == b'!' || at(pat, pi) == b'^'; // see if reverse
                if r {
                    pi += 1;
                }
                let p = &pat[pi.min(pat.len())..];
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
                    break 'eval 0;
                }
                // go through the list
                let mut cr: u32 = 0; // start of a range
                let mut e = at(p, 0) == b'-';
                let cc = u32::from(case(at(s, si)));
                let mut hit = false;
                'set: for i in 0..q {
                    let pc = at(p, i);
                    if !e && pc == b'\\' {
                        // set escape flag if \
                        e = true;
                    } else if !e && pc == b'-' {
                        // set start of range if -
                        cr = u32::from(at(p, i.wrapping_sub(1)));
                    } else {
                        if at(p, i + 1) != b'-' {
                            // compare range
                            let mut c = if cr != 0 { cr } else { u32::from(pc) };
                            while c <= u32::from(pc) {
                                // `Case(c)` of an unsigned int: its low byte
                                if u32::from(case(c as u8)) == cc {
                                    hit = true;
                                    break 'set;
                                }
                                c += 1;
                            }
                        }
                        cr = 0; // clear range, escape flags
                        e = false;
                    }
                }
                if hit == r {
                    // a member under `[!...]`, or bracket match failed
                    break 'eval 0;
                }
                // `recmatch(q + 1, s + 1)`: a tail call
                pi += q + 1;
                si += 1;
                continue 'eval;
            }

            // if escape ('\\'), just compare next character
            let c = if c == b'\\' {
                let n = at(pat, pi);
                if n == 0 {
                    // if \ at end, then syntax error
                    break 'eval 0;
                }
                pi += 1;
                n
            } else {
                c
            };

            // just a character--compare it (`c` is never 0 here, so the
            // string's end is a mismatch)
            if at(s, si) != 0 && case(c) == case(at(s, si)) {
                si += 1;
                continue 'eval;
            }
            break 'eval 0;
        };
        if r != 0 {
            // every open `*` loop returns it as it gets it
            return r;
        }
        // A 0: the innermost open `*` loop tries its next position.
        loop {
            let Some(top) = stack.last_mut() else {
                return 0;
            };
            top.s += 1;
            let Star {
                p,
                s: at_s,
                component,
            } = *top;
            if component {
                if at(s, at_s) != 0 && at(s, at_s) != sepc {
                    (pi, si) = (p, at_s);
                    continue 'call;
                }
                stack.pop();
                match after_component(pat, s, p, at_s, sepc) {
                    None => {
                        (pi, si) = (p, at_s);
                        continue 'call;
                    }
                    Some(0) => continue,
                    Some(r) => return r,
                }
            }
            if at(s, at_s) != 0 {
                (pi, si) = (p, at_s);
                continue 'call;
            }
            return 2;
        }
    }
}

/// An open `*` loop of [`recmatch`]: the pattern after the star, the
/// position it tries now, and whether it is `WILD_STOP_AT_DIR`'s single
/// star (which stops at the separator).
#[derive(Clone, Copy)]
struct Star {
    p: usize,
    s: usize,
    component: bool,
}

/// What `WILD_STOP_AT_DIR`'s single `*` answers once its loop has reached
/// a separator or the end at `si`: the end of the pattern matches the end
/// of the string; a separator next in the pattern continues the match
/// there (a tail call: `None`); anything else gives up (2).
fn after_component(pat: &[u8], s: &[u8], pi: usize, si: usize, sepc: u8) -> Option<i32> {
    // end of pattern: matched if at end of string, else continue
    if at(pat, pi) == 0 {
        return Some(i32::from(at(s, si) == 0));
    }
    // continue to match if at sepc in pattern, else give up
    if at(pat, pi) == sepc || (at(pat, pi) == b'\\' && at(pat, pi + 1) == sepc) {
        None
    } else {
        Some(2)
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
