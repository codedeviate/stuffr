//! Scanning names: which files zip would operate on.
//!
//! Ports of `fileio.c` (`newname`, `filter`, `check_dup`, `msname`),
//! `util.c` (`recmatch`, `shmatch`, `isshexp`) and `unix/unix.c`
//! (`procname`, `ex2in`, `in2ex`, `filetime`), and of the stretch of
//! `zip.c:main` that drives them: reading no old archive (Task 7 reads
//! one), scanning the names and `-R`, applying `-i`/`-x`, removing
//! duplicates, dropping what is missing, too old or the archive itself, and
//! `-sf`'s listing.
//!
//! **Everything that touches an operand goes through `Host`** (`Host::path`
//! resolves it, a sandbox's included): scanning only `stat`s and lists
//! directories, it opens and reads nothing, so there is nothing for
//! `Host::track` to count yet; Task 6 opens the files it archives through
//! `track`.
//!
//! The old archive's entries (`zfiles`) do not exist yet: a name that is not
//! on disk is simply not matched (`ZE_MISS`), and `proc_archive_name` is
//! Task 7's. The places that will gain them say `Task 7`.
//!
//! Deviations (module docs of `mod.rs`, 7 and 8): the "Scanning files"
//! progress message after five seconds (`newname`) is not made, and a name
//! that is `//host` or `//host/share` and nothing more (the C dereferences a
//! NULL `t` in `ex2in` and dies of SIGSEGV) gets the answer of that crash
//! without it.

use std::ffi::OsStr;
use std::io;
use std::path::PathBuf;

use super::cli::{Action, Filter, ZE_ABORT, ZE_OK, ZE_OPEN, ZE_PARMS};
use super::flavour;
use super::messages::{self as m, printf};
use super::unix::{
    S_IFDIR, S_IFIFO, S_IFLNK, S_IFREG, UnixMeta, meta_of, stdin_meta, unix2dostime,
};
use super::{Exit, Zr};

/// ziperr.h:ZE_LOGIC
const ZE_LOGIC: i32 = 5;
/// ziperr.h:ZE_NONE
const ZE_NONE: i32 = 12;
/// ziperr.h:ZE_NAME
const ZE_NAME: i32 = 13;

/// What a name found on disk is, by the `stat` zip made of it (`lstat`
/// under `-y`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FoundKind {
    /// A regular file (or anything the C's mode tests take for one).
    File,
    /// A directory (its name ends in `/`).
    Dir,
    /// A symbolic link kept as a link (`-y`).
    Symlink,
    /// A FIFO read under `-FI`.
    Fifo,
    /// Standard input, the name `-`.
    Stdin,
}

/// One input zip will add: a `struct flist` after the whole scan.
// `kind`, `meta`, `dostime`, `dosflag`: zipup stats each name again, as
// the C does; Task 7's updates compare the scan's times with the archive's.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct Found {
    /// The path to open (`Host::path` of the name, a directory's trailing
    /// `/` removed): inputs are opened through `Host::track` at this path.
    pub(crate) disk: PathBuf,
    /// The name as the command line or the directory walk gave it
    /// (`f->name`, which messages and `-m` use).
    pub(crate) name: Vec<u8>,
    /// The name stored in the archive (`f->zname`, equal to `f->iname` on
    /// unix).
    pub(crate) zname: Vec<u8>,
    /// The name as messages show it (`f->oname`).
    pub(crate) oname: Vec<u8>,
    pub(crate) kind: FoundKind,
    pub(crate) meta: UnixMeta,
    /// `filetime()`'s return: the modification time as a DOS date and time.
    pub(crate) dostime: u64,
    /// The size zip counts: a regular file's, `None` for anything else (the
    /// C's -1).
    pub(crate) usize: Option<u64>,
    /// `-k` (MS-DOS names and attributes) applied to this name.
    pub(crate) dosflag: bool,
}

/// A name `newname` accepted, before its `stat`.
struct Listed {
    name: Vec<u8>,
    iname: Vec<u8>,
    oname: Vec<u8>,
    dosflag: bool,
}

/// The state of one scan (the C's file-level statics).
struct Scan {
    listed: Vec<Listed>,
    /// `zipstate`/`zipstatb`: `None` until a name needs it, then the
    /// archive's `stat` (`Some(None)`: it does not exist, or goes to
    /// standard output).
    zip_stat: Option<Option<std::fs::Metadata>>,
    /// The error of the last failed `stat` (the C's stale `errno`, which
    /// `ziperr(ZE_OPEN, ...)` shows for `-MM`).
    last_err: Option<io::Error>,
}

// ---- util.c: names and patterns ----

/// unix.c:ex2in: the external name `x` as the archive stores it: a UNC
/// `//host/share/` part, leading `/` and any `./` dropped; the last
/// component only without paths (`-j`); upper-cased 8.3 under `-k`. `None`
/// for a name that is `//host` or `//host/share` and nothing more: the C
/// dereferences a NULL there and dies of SIGSEGV (deviation 8, see
/// [`crashed`]).
// port: unix/unix.c:ex2in
pub(crate) fn ex2in(x: &[u8], pathput: bool, dosify: bool) -> Option<Vec<u8>> {
    let at = |i: usize| x.get(i).copied().unwrap_or(0);
    let mut t: usize;
    if x.starts_with(b"//") && at(2) != 0 && at(2) != b'/' {
        // strip "//host/share/"
        let mut n = 2;
        while at(n) != 0 && at(n) != b'/' {
            n += 1; // host name
        }
        if at(n) != 0 {
            n += 1;
            while at(n) != 0 && at(n) != b'/' {
                n += 1; // `share` name
            }
        }
        if at(n) != 0 {
            t = n + 1;
        } else {
            // the C leaves `t` NULL here and dereferences it
            return None;
        }
    } else {
        t = 0;
    }
    while at(t) == b'/' {
        t += 1; // a relative path
    }
    while at(t) == b'.' && at(t + 1) == b'/' {
        t += 2; // redundant leading "./"
    }
    let mut n = x[t.min(x.len())..].to_vec();
    if !pathput {
        n = last(&n).to_vec();
    }
    if dosify {
        msname(&mut n);
    }
    Some(n)
}

/// What the references answer when `ex2in` dereferences NULL: SIGSEGV, which
/// zip's handler turns into a blank line and `Interrupted (aborting)`, exit
/// 9. stuffr gives that answer without the dereference (deviation 8, as
/// `-O` with no archive name does: deviation 6).
pub(crate) fn crashed(z: &mut Zr) -> Exit {
    z.mesg_write(b"\n");
    z.ziperr(ZE_ABORT, m::ABORTING.as_bytes())
}

/// fileio.c:last: the last path component (empty for a name ending `/`).
fn last(p: &[u8]) -> &[u8] {
    match p.iter().rposition(|&b| b == b'/') {
        Some(i) => &p[i + 1..],
        None => p,
    }
}

/// fileio.c:msname: every path component reduced to an upper-case 8.3 name.
// port: fileio.c:msname
fn msname(n: &mut Vec<u8>) {
    let mut q = Vec::with_capacity(n.len());
    let mut f = 0;
    for &c in n.iter() {
        if matches!(
            c,
            b' ' | b':'
                | b'"'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'<'
                | b'='
                | b'>'
                | b'?'
                | b'['
                | b']'
                | b'|'
        ) {
            continue; // char is discarded
        } else if c == b'/' {
            q.push(c);
            f = 0; // new component
        } else if c == b'.' {
            if f == 0 {
                continue; // leading dots are discarded
            } else if f < 9 {
                q.push(c);
                f = 9; // now in file type
            } else {
                f = 12; // now just excess characters
            }
        } else if f < 12 && f != 8 {
            f += 1; // until end of name or type
            q.push(c.to_ascii_uppercase());
        }
    }
    *n = q;
}

/// What the matcher reads of the options.
#[derive(Clone, Copy)]
struct Cx {
    no_wild: bool,
    allow_regex: bool,
    wild_stop_at_dir: bool,
}

/// util.c:isshexp: whether `p` holds `?`, `*` or `[` not escaped.
fn isshexp(p: &[u8]) -> bool {
    let mut i = 0;
    while i < p.len() {
        if p[i] == b'\\' && i + 1 < p.len() {
            i += 1;
        } else if matches!(p[i], b'?' | b'*' | b'[') {
            return true;
        }
        i += 1;
    }
    false
}

/// util.c:recmatch: 1 when the sh pattern `p` matches `s`, 0 or 2 when it
/// does not or the pattern is wrong (2 means give up). Indices stand for the
/// C's pointers; past the end reads as the terminating NUL. Case is never
/// folded on unix (`case_map` is the identity).
// port: util.c:recmatch
fn recmatch(p: &[u8], mut pi: usize, s: &[u8], mut si: usize, cx: Cx) -> i32 {
    let pc = |i: usize| p.get(i).copied().unwrap_or(0);
    let sc = |i: usize| s.get(i).copied().unwrap_or(0);
    let mut c = pc(pi);
    pi += 1;
    // end of the pattern: a match if the string ends too
    if c == 0 {
        return i32::from(sc(si) == 0);
    }
    // `?` matches any character, not an empty string
    if c == b'?' {
        return if cx.wild_stop_at_dir {
            if sc(si) != 0 && sc(si) != b'/' {
                recmatch(p, pi, s, si + 1, cx)
            } else {
                0
            }
        } else if sc(si) != 0 {
            recmatch(p, pi, s, si + 1, cx)
        } else {
            0
        };
    }
    // `*` matches any number of characters, including zero
    if !cx.no_wild && c == b'*' {
        if cx.wild_stop_at_dir {
            if pc(pi) != b'*' {
                // a single `*` does not match slashes
                let mut s2 = si;
                while sc(s2) != 0 && sc(s2) != b'/' {
                    let r = recmatch(p, pi, s, s2, cx);
                    if r != 0 {
                        return r;
                    }
                    s2 += 1;
                }
                if pc(pi) == 0 {
                    return i32::from(sc(s2) == 0);
                }
                return if pc(pi) == b'/' || (pc(pi) == b'\\' && pc(pi + 1) == b'/') {
                    recmatch(p, pi, s, s2, cx)
                } else {
                    2
                };
            }
            // `**` matches `/` too
            pi += 1;
        }
        if pc(pi) == 0 {
            return 1;
        }
        let rest = p.get(pi..).unwrap_or(&[]);
        let srest = s.get(si..).unwrap_or(&[]);
        if !isshexp(rest) {
            // the rest of the pattern is a literal: compare it with the
            // end of the string
            if rest.len() > srest.len() {
                return 0;
            }
            return i32::from(&srest[srest.len() - rest.len()..] == rest);
        }
        // more wildcards: try every position
        while sc(si) != 0 {
            let r = recmatch(p, pi, s, si, cx);
            if r != 0 {
                return r;
            }
            si += 1;
        }
        return 2;
    }
    // a list of characters and ranges in brackets
    if !cx.no_wild && cx.allow_regex && c == b'[' {
        if sc(si) == 0 {
            return 0; // needs a character to match
        }
        let r = pc(pi) == b'!' || pc(pi) == b'^';
        pi += usize::from(r);
        let mut q = pi;
        let mut e = false;
        while pc(q) != 0 {
            if e {
                e = false;
            } else if pc(q) == b'\\' {
                e = true;
            } else if pc(q) == b']' {
                break;
            }
            q += 1;
        }
        if pc(q) != b']' {
            return 0; // nothing matches a bad syntax
        }
        let mut range_start = 0u8;
        e = pc(pi) == b'-';
        while pi < q {
            if !e && pc(pi) == b'\\' {
                e = true;
            } else if !e && pc(pi) == b'-' {
                range_start = pc(pi.wrapping_sub(1));
            } else {
                let cc = sc(si);
                let mut uc = range_start;
                if pc(pi + 1) != b'-' {
                    uc = if uc != 0 { uc } else { pc(pi) };
                    while uc <= pc(pi) {
                        if uc == cc {
                            return if r {
                                0
                            } else {
                                recmatch(p, q + 1, s, si + 1, cx)
                            };
                        }
                        // an `unsigned char`: 255 wraps to 0
                        uc = uc.wrapping_add(1);
                    }
                }
                range_start = 0;
                e = false;
            }
            pi += 1;
        }
        return if r {
            recmatch(p, q + 1, s, si + 1, cx)
        } else {
            0
        };
    }
    // an escape: just compare the next character
    if !cx.no_wild && c == b'\\' {
        c = pc(pi);
        pi += 1;
        if c == 0 {
            return 0; // `\` at the end is a syntax error
        }
    }
    // a plain character
    if c == sc(si) {
        recmatch(p, pi, s, si + 1, cx)
    } else {
        0
    }
}

/// util.c:shmatch
fn shmatch(p: &[u8], s: &[u8], cx: Cx) -> bool {
    recmatch(p, 0, s, 0, cx) == 1
}

/// fileio.c:filter: whether `name` is selected by the `-R`, `-i` and `-x`
/// lists (`-x` wins; with both `-R` and `-i` a name needs a match in each).
// port: fileio.c:filter
fn filter(patterns: &[Filter], cx: Cx, name: &[u8]) -> bool {
    if patterns.is_empty() {
        return true;
    }
    let icount = patterns.iter().filter(|f| f.flag == b'i').count();
    let rcount = patterns.iter().filter(|f| f.flag == b'R').count();
    // without -i or -R patterns every name matches their "select rules"
    let mut imatch = icount == 0;
    let mut rmatch = rcount == 0;
    for pat in patterns {
        if pat.pattern.is_empty() {
            continue; // it can happen...
        }
        let mut p = name;
        match pat.flag {
            b'R' => {
                if rmatch {
                    continue; // one match is enough
                }
                // a pattern of N path components is tested against the
                // last N components of the name
                let mut slashes = pat.pattern.iter().filter(|&&b| b == b'/').count() as i64;
                slashes -= name.iter().filter(|&&b| b == b'/').count() as i64;
                if slashes < 0 {
                    // the name has M > N components: skip the first M - N
                    for (i, &b) in name.iter().enumerate() {
                        if b == b'/' {
                            slashes += 1;
                            if slashes == 0 {
                                p = &name[i + 1..];
                                break;
                            }
                        }
                    }
                }
            }
            b'i' if imatch => continue,
            _ => {}
        }
        if shmatch(&pat.pattern, p, cx) {
            match pat.flag {
                // the -x match takes precedence over everything else
                b'x' => return false,
                b'R' => rmatch = true,
                _ => imatch = true,
            }
        }
    }
    imatch && rmatch
}

/// What a name looks like in zip's messages (`local_to_display_string`):
/// Ubuntu shows a byte below a space as `^` and the letter, Apple as is.
fn display(z: &Zr, iname: &[u8]) -> Vec<u8> {
    if !flavour::shows_newline_escaped(z.flavour) {
        return iname.to_vec();
    }
    let mut out = Vec::with_capacity(iname.len() * 2);
    for &b in iname {
        if b < b' ' {
            out.push(b'^');
            out.push(b'@' + b);
        } else {
            out.push(b);
        }
    }
    out
}

// ---- the scan ----

impl Scan {
    fn new() -> Scan {
        Scan {
            listed: Vec::new(),
            zip_stat: None,
            last_err: None,
        }
    }

    /// `stat` or, under `-y`, `lstat` (`LSSTAT`) of `n`; an empty name does
    /// not exist (a sandbox would otherwise resolve it to its directory).
    fn lsstat(&mut self, z: &Zr, n: &[u8]) -> Option<(UnixMeta, std::fs::Metadata)> {
        let r = if n.is_empty() {
            Err(io::Error::from_raw_os_error(2))
        } else if z.o.linkput {
            std::fs::symlink_metadata(z.host.path(n))
        } else {
            std::fs::metadata(z.host.path(n))
        };
        match r {
            Ok(md) => Some((meta_of(&md), md)),
            Err(e) => {
                self.last_err = Some(e);
                None
            }
        }
    }

    /// unix.c:procname: process a name to operate on: `Ok(true)` when it
    /// matched something (`ZE_OK`), `Ok(false)` when not (`ZE_MISS`).
    // port: unix/unix.c:procname
    fn procname(&mut self, z: &mut Zr, n: &[u8]) -> Result<bool, Exit> {
        if n == b"-" {
            // compressing stdin
            self.newname(z, n)?;
            return Ok(true);
        }
        let Some((meta, _)) = self.lsstat(z, n) else {
            // Not a file or directory: Task 7 searches the shell
            // expression in the archive's entries here.
            return Ok(false);
        };
        let mode = meta.mode;
        // The C's tests are bit masks, so a socket (0140000) counts as a
        // file and a block device (0060000) as a directory.
        if (mode & S_IFREG) == S_IFREG || (mode & S_IFLNK) == S_IFLNK {
            // add or remove the name of a file
            self.newname(z, n)?;
        } else if (mode & S_IFDIR) == S_IFDIR {
            // add a trailing / to the directory name
            let mut p: Vec<u8> = Vec::new();
            if n != b"." {
                p.extend_from_slice(n);
                if p.last() != Some(&b'/') {
                    p.push(b'/');
                }
                if z.o.dirnames {
                    self.newname(z, &p)?;
                }
            }
            // recurse into the directory
            if z.o.recurse != 0
                && let Ok(rd) = std::fs::read_dir(z.host.path(n))
            {
                for e in rd {
                    let Ok(e) = e else { break };
                    let mut a = p.clone();
                    a.extend_from_slice(&os_bytes(&e.file_name()));
                    if !self.procname(z, &a)? {
                        z.zipwarn(m::NAME_NOT_MATCHED.as_bytes(), &a);
                    }
                }
            }
        } else if (mode & S_IFIFO) == S_IFIFO {
            if z.o.allow_fifo {
                // a FIFO (named pipe) is a normal file
                if z.o.noisy {
                    z.zipwarn(m::READING_FIFO.as_bytes(), n);
                }
                self.newname(z, n)?;
            } else {
                z.zipwarn(m::IGNORING_FIFO.as_bytes(), n);
                return Ok(true);
            }
        } else {
            z.zipwarn(m::IGNORING_SPECIAL.as_bytes(), n);
        }
        Ok(true)
    }

    /// fileio.c:newname: add the name of an existing disk file to the list
    /// (or leave it out: filters, the archive itself).
    // port: fileio.c:newname
    fn newname(&mut self, z: &mut Zr, name: &[u8]) -> Result<(), Exit> {
        let dosflag = z.o.dosify;
        let Some(iname) = ex2in(name, z.o.pathput, z.o.dosify) else {
            return Err(crashed(z));
        };
        // discard directory names with `zip -rj`
        if iname.is_empty() {
            if z.o.pathput && z.o.recurse == 0 {
                return Err(z.ziperr(ZE_LOGIC, m::EMPTY_NAME.as_bytes()));
            }
            return Ok(());
        }
        // the name as it would be with `-j` and `-k` off, for the filters
        let undosm = if dosflag || !z.o.pathput {
            ex2in(name, true, false).unwrap_or_default()
        } else {
            iname.clone()
        };
        let oname = display(z, &iname);
        // Task 7: a name already in the archive is marked there instead
        // (`zsearch`), and listed in the found list only if it is not.
        let cx = cx_of(z);
        if z.o.filters.is_empty() || filter(&z.o.filters, cx, &undosm) {
            // Do not add the zip file to itself ("zip -m foo ../dir/foo.zip").
            if self.is_the_zip_file(z, name) {
                if z.o.verbose > 0 {
                    z.mesg_write(m::MATCHES_ZIP.as_bytes());
                }
                return Ok(());
            }
            self.listed.push(Listed {
                name: name.to_vec(),
                iname,
                oname,
                dosflag,
            });
        }
        Ok(())
    }

    /// Whether `name` is the archive being written: the same `stat` (mode,
    /// inode, device, owner, size, times; not the access time, zip is
    /// reading the file).
    fn is_the_zip_file(&mut self, z: &Zr, name: &[u8]) -> bool {
        if self.zip_stat.is_none() {
            let zipfile = z.o.zipfile.clone().unwrap_or_default();
            self.zip_stat = Some(if zipfile == b"-" || zipfile.is_empty() {
                None
            } else {
                std::fs::metadata(z.host.path(&zipfile)).ok()
            });
        }
        let Some(Some(zm)) = &self.zip_stat else {
            return false;
        };
        if name.is_empty() {
            return false;
        }
        match std::fs::metadata(z.host.path(name)) {
            Ok(nm) => same_stat(zm, &nm),
            Err(_) => false,
        }
    }
}

#[cfg(unix)]
fn same_stat(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.mode() == b.mode()
        && a.ino() == b.ino()
        && a.dev() == b.dev()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
        && a.size() == b.size()
        && a.mtime() == b.mtime()
        && a.ctime() == b.ctime()
}

#[cfg(not(unix))]
fn same_stat(_a: &std::fs::Metadata, _b: &std::fs::Metadata) -> bool {
    false
}

/// A directory entry's name as the bytes zip's `readdir` gave.
fn os_bytes(s: &OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        s.as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        s.to_string_lossy().into_owned().into_bytes()
    }
}

fn cx_of(z: &Zr) -> Cx {
    Cx {
        no_wild: z.o.no_wild,
        allow_regex: z.o.allow_regex,
        wild_stop_at_dir: z.o.wild_stop_at_dir,
    }
}

/// unix.c:filetime for a name on disk (zip's `-` is standard input): the
/// `stat` (`lstat` under `-y`) of the name without a trailing `/`, its
/// attributes, DOS time and counted size. `None` when it does not exist
/// (the C returns 0).
// port: unix/unix.c:filetime
fn filetime(z: &Zr, name: &[u8]) -> Option<(UnixMeta, u64, Option<u64>, FoundKind)> {
    let meta = if name == b"-" {
        stdin_meta(z)?
    } else {
        let stripped = name.strip_suffix(b"/").unwrap_or(name);
        if stripped.is_empty() {
            return None;
        }
        let r = if z.o.linkput {
            std::fs::symlink_metadata(z.host.path(stripped))
        } else {
            std::fs::metadata(z.host.path(stripped))
        };
        meta_of(&r.ok()?)
    };
    let ty = meta.file_type();
    let usize = (ty == S_IFREG).then_some(meta.size);
    let kind = if name == b"-" {
        FoundKind::Stdin
    } else if ty == S_IFLNK {
        FoundKind::Symlink
    } else if ty == S_IFDIR {
        FoundKind::Dir
    } else if ty == S_IFIFO {
        FoundKind::Fifo
    } else {
        FoundKind::File
    };
    Some((meta, unix2dostime(z, meta.mtime), usize, kind))
}

/// `qsort` as the flavour's C library has it. The two sorts of
/// [`check_dup`] put equal keys next to each other in an order the C leaves
/// open, and which of two equal names is dropped, and which of two equal
/// internal names is reported first, follows from it: Ubuntu's glibc sorts
/// with a stable merge sort; Apple's libc with the BSD quicksort
/// (Bentley and McIlroy: median of three or nine, equal keys swapped to the
/// ends, an insertion sort below eight elements), ported here and checked
/// against macOS's own `qsort` on 4000 random arrays with many equal keys:
/// the same permutation for 3994 of them (its threshold is 8, not the BSD
/// source's 7, and it has no insertion-sort shortcut after a pass without
/// swaps). The six it orders differently, three equal keys among 66 to 140
/// elements or two among 14, are a known gap: which of two equal names is
/// dropped then can differ from macOS's.
fn qsort(f: flavour::Flavour, v: &mut [usize], cmp: &dyn Fn(usize, usize) -> std::cmp::Ordering) {
    match f {
        flavour::Flavour::Ubuntu => v.sort_by(|&a, &b| cmp(a, b)),
        #[cfg(target_os = "macos")]
        flavour::Flavour::Apple => macos_qsort(v, cmp),
        #[cfg(not(target_os = "macos"))]
        flavour::Flavour::Apple => bsd_qsort(v, cmp),
    }
}

/// The platform's own `qsort_r` (ruling Z12): on macOS the Apple flavour
/// sorts exactly as the reference does.
#[cfg(target_os = "macos")]
fn macos_qsort(v: &mut [usize], cmp: &dyn Fn(usize, usize) -> std::cmp::Ordering) {
    type Cmp<'a> = &'a dyn Fn(usize, usize) -> std::cmp::Ordering;
    extern "C" fn shim(
        thunk: *mut libc::c_void,
        a: *const libc::c_void,
        b: *const libc::c_void,
    ) -> libc::c_int {
        // SAFETY: `thunk` is the `&Cmp` made below, alive for the whole
        // `qsort_r` call; `a` and `b` point at two `usize` elements of `v`.
        let (cmp, a, b) = unsafe {
            (
                &*(thunk as *const Cmp),
                *(a as *const usize),
                *(b as *const usize),
            )
        };
        match cmp(a, b) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        }
    }
    let mut thunk: Cmp = cmp;
    // SAFETY: `v` is a valid slice of `usize`; `shim` reads only elements of
    // it and the thunk, both live for the call; Apple's argument order.
    unsafe {
        libc::qsort_r(
            v.as_mut_ptr().cast(),
            v.len(),
            std::mem::size_of::<usize>(),
            (&mut thunk as *mut Cmp).cast(),
            Some(shim),
        );
    }
}

// port: FreeBSD libc stdlib/qsort.c (the algorithm of Apple's libc)
#[cfg_attr(target_os = "macos", allow(dead_code))] // tests only there
fn bsd_qsort(mut a: &mut [usize], cmp: &dyn Fn(usize, usize) -> std::cmp::Ordering) {
    use std::cmp::Ordering::{Equal, Greater, Less};
    let c = |x: usize, y: usize| -> i32 {
        match cmp(x, y) {
            Less => -1,
            Equal => 0,
            Greater => 1,
        }
    };
    loop {
        let n = a.len();
        if n < 8 {
            // insertion sort
            for pm in 1..n {
                let mut pl = pm;
                while pl > 0 && c(a[pl - 1], a[pl]) > 0 {
                    a.swap(pl, pl - 1);
                    pl -= 1;
                }
            }
            return;
        }
        let med3 = |a: &[usize], x: usize, y: usize, z: usize| -> usize {
            if c(a[x], a[y]) < 0 {
                if c(a[y], a[z]) < 0 {
                    y
                } else if c(a[x], a[z]) < 0 {
                    z
                } else {
                    x
                }
            } else if c(a[y], a[z]) > 0 {
                y
            } else if c(a[x], a[z]) < 0 {
                x
            } else {
                z
            }
        };
        let mut pm = n / 2;
        if n > 7 {
            let mut pl = 0;
            let mut pn = n - 1;
            if n > 40 {
                let d = n / 8;
                pl = med3(a, pl, pl + d, pl + 2 * d);
                pm = med3(a, pm - d, pm, pm + d);
                pn = med3(a, pn - 2 * d, pn - d, pn);
            }
            pm = med3(a, pl, pm, pn);
        }
        a.swap(0, pm);
        let mut pa = 1;
        let mut pb = 1;
        let mut pc = n - 1;
        let mut pd = n - 1;
        loop {
            while pb <= pc {
                let r = c(a[pb], a[0]);
                if r > 0 {
                    break;
                }
                if r == 0 {
                    a.swap(pa, pb);
                    pa += 1;
                }
                pb += 1;
            }
            while pb <= pc {
                let r = c(a[pc], a[0]);
                if r < 0 {
                    break;
                }
                if r == 0 {
                    a.swap(pc, pd);
                    pd -= 1;
                }
                pc -= 1;
            }
            if pb > pc {
                break;
            }
            a.swap(pb, pc);
            pb += 1;
            pc -= 1;
        }
        let pn = n;
        let mut r = pa.min(pb - pa);
        vecswap(a, 0, pb - r, r);
        r = (pd - pc).min(pn - pd - 1);
        vecswap(a, pb, pn - r, r);
        let left = pb - pa;
        let right = pd - pc;
        if left > 1 {
            bsd_qsort(&mut a[..left], cmp);
        }
        if right > 1 {
            // iterate on the right part (the C's `goto loop`)
            let whole = a;
            a = &mut whole[pn - right..];
        } else {
            return;
        }
    }
}

fn vecswap(a: &mut [usize], i: usize, j: usize, n: usize) {
    for k in 0..n {
        a.swap(i + k, j + k);
    }
}

/// fileio.c:check_dup: the found list must have no name twice (one of the
/// two is dropped) and no two names that are the same inside the archive
/// (a warning and `ZE_PARMS`).
// port: fileio.c:check_dup
fn check_dup(z: &mut Zr, listed: &mut Vec<Listed>) -> Result<(), Exit> {
    if listed.is_empty() {
        return Ok(());
    }
    // sorted by name as given; of equal names `s[j]`, the later in the
    // sorted order, is removed
    let mut order: Vec<usize> = (0..listed.len()).collect();
    qsort(z.flavour, &mut order, &|a, b| {
        listed[a].name.cmp(&listed[b].name)
    });
    let mut keep = vec![true; listed.len()];
    for w in order.windows(2) {
        if listed[w[0]].name == listed[w[1]].name {
            keep[w[1]] = false;
        }
    }
    // then by internal name, to find two names that collide
    let mut valid: Vec<usize> = order.into_iter().filter(|&i| keep[i]).collect();
    qsort(z.flavour, &mut valid, &|a, b| {
        listed[a].iname.cmp(&listed[b].iname)
    });
    for w in valid.windows(2) {
        let (a, b) = (&listed[w[0]], &listed[w[1]]);
        if a.iname == b.iname {
            let mut e = Vec::new();
            printf(&mut e, m::DUP_FIRST, &[&a.name]);
            e.extend_from_slice(m::DUP_INDENT.as_bytes());
            printf(&mut e, m::DUP_SECOND, &[&b.name]);
            e.extend_from_slice(m::DUP_INDENT.as_bytes());
            printf(&mut e, m::DUP_REPEATED, &[&b.iname]);
            if !z.o.pathput {
                e.extend_from_slice(m::DUP_JUNK.as_bytes());
            }
            z.zipwarn(&e, b"");
            return Err(z.ziperr(ZE_PARMS, m::CANNOT_REPEAT.as_bytes()));
        }
    }
    let mut i = 0;
    listed.retain(|_| {
        i += 1;
        keep[i - 1]
    });
    Ok(())
}

/// zip.c:main, from the scan of the names to the listing of what is
/// found: the names and `-R`, the filters, the duplicates, and the `stat`
/// that drops names that are missing, outside `-t`/`-tt`, or the archive.
/// What is left is what zip would add, in the order it found it.
// port: zip.c:main
pub(crate) fn collect(z: &mut Zr) -> Result<Vec<Found>, Exit> {
    let mut sc = Scan::new();
    // zip used as a filter: `procname("-", 0)`
    if z.o.filter_mode {
        sc.procname(z, b"-")?;
    }
    // Process the file arguments from the command line. Task 7: for -U
    // they name archive entries instead (`proc_archive_name`).
    let names = std::mem::take(&mut z.o.names);
    if !names.is_empty() && z.o.action != Action::Archive {
        if z.o.show_what_doing {
            z.mesg_write(m::SD_SCANNING_FILES.as_bytes());
        }
        for n in &names {
            if !sc.procname(z, n)? {
                miss(z, &mut sc, n, n)?;
            }
        }
    }
    z.o.names = names;
    // recurse from the current directory for -R
    if z.o.recurse == 2 && !sc.procname(z, b".")? {
        miss_r(z, &mut sc)?;
    }
    if z.o.show_what_doing {
        z.mesg_write(m::SD_APPLYING_FILTERS.as_bytes());
        z.mesg_write(m::SD_CHECKING_DUPS.as_bytes());
    }
    // remove duplicates in the found list
    check_dup(z, &mut sc.listed)?;

    // Task 7: the entries of the old archive are checked against the disk
    // here ("Scanning files to update").
    if z.o.show_what_doing {
        z.mesg_write(m::SD_SCANNING_TO_UPDATE.as_bytes());
        let mut line = Vec::new();
        printf(
            &mut line,
            m::SD_FCOUNT,
            &[sc.listed.len().to_string().as_bytes()],
        );
        z.mesg_write(&line);
    }

    // Remove entries from the found list that do not exist or are too old.
    let (before, after) = (z.o.before, z.o.after);
    let zipfile = z.o.zipfile.clone().unwrap_or_default();
    let mut found = Vec::new();
    for l in std::mem::take(&mut sc.listed) {
        if matches!(z.o.action, Action::Delete | Action::Freshen) {
            continue;
        }
        let Some((meta, tf, usize, kind)) = filetime(z, &l.name) else {
            continue; // tf == 0: not on disk
        };
        if tf < before || (after != 0 && tf >= after) || (l.iname == zipfile && !z.o.zip_to_stdout)
        {
            continue;
        }
        found.push(Found {
            disk: z.host.path(l.name.strip_suffix(b"/").unwrap_or(&l.name)),
            name: l.name,
            zname: l.iname,
            oname: l.oname,
            kind,
            meta,
            dostime: tf,
            usize,
            dosflag: l.dosflag,
        });
    }
    Ok(found)
}

/// zip.c:main: a name that matched nothing, in the loop over the names:
/// a warning, and with `-MM` the run ends.
fn miss(z: &mut Zr, sc: &mut Scan, shown: &[u8], n: &[u8]) -> Result<(), Exit> {
    z.zipwarn(m::NAME_NOT_MATCHED.as_bytes(), shown);
    if z.o.bad_open_is_error {
        return Err(open_error(z, sc, n));
    }
    Ok(())
}

/// zip.c:main: `-R` found nothing.
fn miss_r(z: &mut Zr, sc: &mut Scan) -> Result<(), Exit> {
    z.zipwarn(m::NAME_NOT_MATCHED.as_bytes(), m::FOR_R_NAME.as_bytes());
    if z.o.bad_open_is_error {
        return Err(open_error(z, sc, m::R_NAME.as_bytes()));
    }
    Ok(())
}

/// `ZIPERR(ZE_OPEN, name)` with the system's last answer (`errno`: the
/// `stat` that failed).
fn open_error(z: &mut Zr, sc: &mut Scan, name: &[u8]) -> Exit {
    let e = sc
        .last_err
        .take()
        .unwrap_or_else(|| io::Error::from_raw_os_error(2));
    z.ziperr_os(ZE_OPEN, name, &e)
}

/// zip.c:main, `-sf`: the heading, one line per name, the totals. Always
/// ends the run.
// port: zip.c:main (show_files)
pub(crate) fn show_files(z: &mut Zr, found: &[Found]) -> Exit {
    let sf = z.o.show_files;
    let mut count = 0u64;
    let mut bytes = 0u64;
    let listing = matches!(sf, 1 | 3 | 5);
    if z.o.noisy && listing {
        if z.mesg_line_started {
            z.mesg_write(b"\n");
            z.mesg_line_started = false;
        }
        z.mesg_write(heading(z).as_bytes());
    }
    if z.log.is_some() {
        if z.log_line_started {
            z.log_write(b"\n");
            z.log_line_started = false;
        }
        z.log_write(heading(z).as_bytes());
    }
    // Task 7: the archive's marked entries are listed first.
    for f in found {
        count += 1;
        bytes += f.usize.unwrap_or(0);
        // Task 11: `-sU` with Ubuntu's escaped Unicode names
        let mut line = Vec::new();
        printf(&mut line, m::SF_ENTRY, &[&f.oname]);
        if z.o.noisy && listing {
            z.mesg_write(&line);
        }
        if z.log.is_some() {
            z.log_write(&line);
        }
    }
    if z.o.noisy || z.log.is_none() {
        let mut line = Vec::new();
        printf(
            &mut line,
            m::SF_TOTAL,
            &[count.to_string().as_bytes(), bytes.to_string().as_bytes()],
        );
        z.mesg_write(&line);
    }
    if z.log.is_some() {
        let mut line = Vec::new();
        printf(
            &mut line,
            m::SF_TOTAL,
            &[count.to_string().as_bytes(), bytes.to_string().as_bytes()],
        );
        z.log_write(&line);
    }
    super::cli::finish(z, ZE_OK)
}

/// The heading of `-sf`'s listing for the action.
fn heading(z: &Zr) -> &'static str {
    if z.o.kk == 3 {
        // -sf alone
        m::ARCHIVE_CONTAINS
    } else {
        match z.o.action {
            Action::Delete => m::WOULD_DELETE,
            Action::Freshen => m::WOULD_FRESHEN,
            Action::Archive => m::WOULD_COPY,
            _ => m::WOULD_ADD,
        }
    }
}

/// zip.c:main from reading the old archive to the first byte written: what
/// zip does with the names it was given. Returns the exit code the run
/// ends with.
pub(crate) fn run(z: &mut Zr) -> Exit {
    // Task 8: -F and -FF
    if z.o.fix != 0 {
        return z.not_built();
    }
    if z.o.show_what_doing {
        z.mesg_write(m::SD_READING_ARCHIVE.as_bytes());
    }
    let zipfile = z.o.zipfile.clone().unwrap_or_default();
    // read the zip file if it exists (zipfile.c:readzipfile)
    if !zipfile.is_empty() && zipfile != b"-" {
        match std::fs::metadata(z.host.path(&zipfile)) {
            // Task 7 reads the old archive.
            Ok(_) => return z.not_built(),
            Err(e) => {
                if !z.o.zip_to_stdout && z.o.in_path != z.o.out_path {
                    // if -O is used then in_path must exist
                    return z.ziperr_os(ZE_OPEN, &zipfile, &e);
                }
            }
        }
    }
    // no input zip file and showing contents
    if z.o.show_files != 0 && (z.o.kk == 3 || z.o.action == Action::Archive) {
        // the stale errno of the failed open
        return z.ziperr_os(ZE_OPEN, &zipfile, &io::Error::from_raw_os_error(2));
    }
    // zcount is 0 here
    if z.o.action != Action::Add || z.o.grow {
        z.zipwarn(&zipfile, m::NOT_FOUND_OR_EMPTY.as_bytes());
    }
    let found = match collect(z) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if z.o.show_files != 0 {
        return show_files(z, &found);
    }
    // Make sure there is something left to do (no old entries are marked).
    if found.is_empty() && !z.o.diff_mode && !z.o.allow_empty_archive {
        if matches!(z.o.action, Action::Update | Action::Freshen) {
            return super::cli::finish(z, ZE_NONE);
        } else if z.o.latest || z.o.fix != 0 || z.o.adjust || z.o.junk_sfx {
            return z.ziperr(ZE_NAME, &zipfile);
        } else if z.o.recurse != 0 && z.o.filters.is_empty() && z.o.first_listarg > 0 {
            let mut hint = m::TRY_ZIP.as_bytes().to_vec();
            let first = usize::try_from(z.o.first_listarg).unwrap_or(0);
            for a in z.o.args.iter().take(first).skip(1) {
                hint.push(b' ');
                hint.extend_from_slice(a);
            }
            hint.extend_from_slice(m::TRY_DOT_I.as_bytes());
            for a in z.o.args.iter().skip(first) {
                hint.push(b' ');
                hint.extend_from_slice(a);
            }
            return z.ziperr(ZE_NONE, &hint);
        }
        return z.ziperr(ZE_NONE, &zipfile);
    }
    super::write::write_new(z, found)
}

#[cfg(test)]
mod tests;
