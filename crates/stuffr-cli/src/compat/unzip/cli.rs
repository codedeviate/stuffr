//! The command line: `unzip.c`'s `unzip()` front half and `uz_opts()`,
//! `zipinfo.c`'s `zi_opts()`, `envargs.c`, and the texts the command line
//! alone prints (`usage()`, `help_extended()`, `show_version_info()`).
//!
//! Every function follows its C function line by line (R5), so the two
//! read side by side. Arguments are bytes, as `char *argv[]` is; on Windows
//! they are the arguments' encoded bytes (R8: built, not promised).
//!
//! Two shapes carry C's pointer games:
//!
//! - `argv` is a vector whose element 0 stands for the program name, so an
//!   index here is the C's `argv` offset and `argc` counts as the C's does;
//! - the operand loop's `*pp = NULL` (which ends `G.pfnames` early) is a
//!   `None` in a vector of options; the lists unzip matches are the counted
//!   prefixes C's `G.filespecs`/`G.xfilespecs` describe.

use std::ffi::OsString;

use super::flavour;
use super::messages::{self as m, printf};
use super::{MSG_STDERR, PK_COOL, PK_OK, PK_PARAM, Uz};

/// What the command line asks for once it has parsed: the archive operand,
/// the names to include and exclude, and the extraction directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Parsed {
    /// `G.wildzipfn`: the archive operand, as given (it may be a wildcard).
    pub archive: OsString,
    /// `G.pfnames[0..G.filespecs]`: the names to process; empty is every
    /// entry (`fnames`, unzip's default `*`).
    pub include: Vec<OsString>,
    /// `G.pxnames[0..G.xfilespecs]`: the names after `-x`.
    pub exclude: Vec<OsString>,
    /// `uO.exdir`: the `-d` directory, from the options before the archive
    /// or the operands after it.
    pub exdir: Option<OsString>,
}

/// The options: `unzip.h`'s `UzpOpts` (`uO`) as Apple's and Ubuntu's Unix
/// builds have it, one field per member, plus the two option flags kept in
/// `G` (`M_flag`) or in globals of Ubuntu's iconv patch (`ISO_CP`,
/// `OEM_CP`). Counting flags are `i32`, as C's `int`; the defaults are
/// `globalsCtor()`'s (zero, except `lflag`, see [`Options::new`]).
///
/// This task only sets them; the archive tasks (8–14) read them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct Options {
    /// `-d DIR`: `uO.exdir`, the extraction root.
    pub exdir: Option<Vec<u8>>,
    /// `-P PASSWORD`: `uO.pwdarg`, the decryption password.
    pub pwdarg: Option<Vec<u8>>,
    /// `-Z`, or invoked as `zipinfo`: `uO.zipinfo_mode`.
    pub zipinfo_mode: bool,
    /// `-a` (counted; `-aa` is 2, capped there): `uO.aflag`, text
    /// conversion. `-b` clears it.
    pub aflag: i32,
    /// `-B` (`UNIXBACKUP`): `uO.B_flag`, back up files before overwriting.
    pub b_flag: bool,
    /// `-c` (and `-p`): `uO.cflag`, extract to standard output.
    pub cflag: bool,
    /// `-C`: `uO.C_flag`, match names case-insensitively.
    pub c_flag: bool,
    /// `-D` (counted; `-DD`): `uO.D_flag`, skip restoring directory (any)
    /// timestamps.
    pub d_flag: i32,
    /// `-f`: `uO.fflag`, freshen existing files only (sets `uflag` too).
    pub fflag: bool,
    /// `-F` (`ACORN_FTYPE_NFS`, Ubuntu): `uO.acorn_nfs_ext`, NFS filetype
    /// extensions.
    pub acorn_nfs_ext: bool,
    /// zipinfo `-h`: `uO.hflag`, the header line.
    pub hflag: bool,
    /// `-j`: `uO.jflag`, junk paths.
    pub jflag: bool,
    /// `-K`: `uO.K_flag`, keep setuid/setgid/sticky bits.
    pub k_flag: bool,
    /// zipinfo's `-1 -2 -s -m -l -v`: `uO.lflag`, the listing format (`-1`
    /// at start: none given; `-2` after a negation).
    pub lflag: i32,
    /// `-L` (counted; `-LL`): `uO.L_flag`, lowercase names.
    pub l_flag: i32,
    /// `-n`: `uO.overwrite_none`, never overwrite.
    pub overwrite_none: bool,
    /// `-o` (counted): `uO.overwrite_all`, overwrite without asking.
    pub overwrite_all: i32,
    /// `-q` (counted; `-p` adds 999): `uO.qflag`, quieter.
    pub qflag: i32,
    /// unzip `-t` (test) or zipinfo `-t` (totals): `uO.tflag`. While set,
    /// messages meant for standard error go to standard output
    /// (`UzpMessagePrnt`).
    pub tflag: bool,
    /// unzip `-T` (`TIMESTAMP`: date the archive) or zipinfo `-T` (decimal
    /// times): `uO.T_flag`.
    pub t_flag: bool,
    /// `-u` (and `-f`): `uO.uflag`, update.
    pub uflag: bool,
    /// `-U` (counted, `UNICODE_SUPPORT`, Ubuntu): `uO.U_flag`, escape
    /// non-ASCII (`-UU`: ignore Unicode fields).
    pub u_flag: i32,
    /// `-l`/`-v` (counted; a first `-v` is 2): `uO.vflag`, list (verbosely);
    /// alone, `-v` is the version screen.
    pub vflag: i32,
    /// `-V`: `uO.V_flag`, keep VMS version numbers.
    pub v_flag: bool,
    /// `-W` (`WILD_STOP_AT_DIR`, Ubuntu): `uO.W_flag`, wildcards stop at
    /// `/`.
    pub w_flag: bool,
    /// `-X` (counted, `RESTORE_UIDGID`): `uO.X_flag`, restore owner and
    /// group.
    pub x_flag: i32,
    /// unzip `-z` (counted) or zipinfo `-z`: `uO.zflag`, the archive comment.
    pub zflag: i32,
    /// `-:` (counted): `uO.ddotflag`, allow `../` components.
    pub ddotflag: i32,
    /// `-^` (counted): `uO.cflxflag`, allow control characters in names.
    pub cflxflag: i32,
    /// `-M`: `G.M_flag`, page output through the built-in "more" (cleared
    /// when standard output is not a terminal).
    pub m_flag: bool,
    /// `-I CHARSET` (Ubuntu's `20-unzip60-alt-iconv-utf8.patch`): `ISO_CP`,
    /// the encoding of names from Unix and other archives (Task 14).
    pub iso_cp: Option<Vec<u8>>,
    /// `-O CHARSET` (the same patch): `OEM_CP`, the encoding of names from
    /// DOS, Windows and OS/2 archives (Task 14).
    pub oem_cp: Option<Vec<u8>>,
}

impl Options {
    /// globals.c:globalsCtor()'s options: all zero but `uO.lflag = -1`.
    pub(crate) fn new() -> Options {
        Options {
            lflag: -1,
            ..Options::default()
        }
    }
}

/// zipinfo.c's `LFLAG`: the default listing format, `-s`.
const LFLAG: i32 = 3;

/// unzpriv.h's `WSIZE` (64 KiB with `USE_DEFLATE64`), through which
/// unzip.c bounds an argument's length.
const WSIZE: usize = stuffr::infozip::WSIZE;

/// `ISspace()`: C's `isspace` in the C locale (deviation 6).
fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// Bytes back to an argument.
pub(crate) fn os(b: &[u8]) -> OsString {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        OsString::from_vec(b.to_vec())
    }
    #[cfg(not(unix))]
    {
        OsString::from(String::from_utf8_lossy(b).into_owned())
    }
}

/// An argument as the bytes C's `argv` holds.
pub(crate) fn bytes(a: &std::ffi::OsStr) -> Vec<u8> {
    a.as_encoded_bytes().to_vec()
}

/// The environment variable `name`'s value as bytes; `None` when unset.
fn getenv(uz: &Uz, name: &str) -> Option<Vec<u8>> {
    (uz.env)(name).map(|v| bytes(&v))
}

// port: envargs.c:envargs
/// The arguments with the options in `envstr` (or, when that is unset,
/// empty or only blanks, `envstr2`) inserted after the program name. `argv`
/// holds the program name first, as C's does.
///
/// A value is split at blanks; an argument starting with `"` runs to the
/// next unescaped `"` (or the end), and inside it every `\` is dropped and
/// the byte after it kept (`AMIGA || UNIX`). `count_args` only sizes C's
/// vector, so it has no counterpart here.
pub(crate) fn envargs(uz: &Uz, argv: Vec<Vec<u8>>, envstr: &str, envstr2: &str) -> Vec<Vec<u8>> {
    let skip_blanks = |v: Vec<u8>| -> Vec<u8> {
        let start = v.iter().position(|&b| !is_space(b)).unwrap_or(v.len());
        v[start..].to_vec()
    };
    let mut envptr = getenv(uz, envstr).map(skip_blanks);
    if envptr.as_ref().is_none_or(|v| v.is_empty()) {
        envptr = getenv(uz, envstr2).map(skip_blanks);
    }
    let buf = match envptr {
        Some(v) if !v.is_empty() => v,
        _ => return argv,
    };

    // C's `bufptr`: past the end reads as the string's NUL.
    let at = |i: usize| buf.get(i).copied().unwrap_or(0);
    let mut out: Vec<Vec<u8>> = Vec::with_capacity(argv.len() + 4);
    let mut args = argv.into_iter();
    // copy the program name first, that's always true
    out.extend(args.next());
    let mut p = 0usize;
    loop {
        let mut ch;
        if at(p) == b'"' {
            p += 1;
            let start = p;
            ch = at(p);
            while ch != 0 && ch != b'"' {
                if ch == b'\\' && at(p + 1) != 0 {
                    p += 1; // advance to char after backslash
                }
                p += 1;
                ch = at(p);
            }
            let mut arg = buf[start..p.min(buf.len())].to_vec();
            if ch != 0 {
                p += 1; // overwrite trailing "
            }
            // remove escape characters
            let mut from = 0;
            while let Some(j) = arg[from..].iter().position(|&b| b == b'\\') {
                let j = from + j;
                arg.remove(j);
                from = if j < arg.len() { j + 1 } else { j };
                if from >= arg.len() {
                    break;
                }
            }
            out.push(arg);
        } else {
            let start = p;
            ch = at(p);
            while ch != 0 && !is_space(ch) {
                p += 1;
                ch = at(p);
            }
            out.push(buf[start..p].to_vec());
            if ch != 0 {
                p += 1;
            }
        }
        ch = at(p);
        while ch != 0 && is_space(ch) {
            p += 1;
            ch = at(p);
        }
        if ch == 0 {
            break;
        }
    }
    // now save old argc and copy in the old args
    out.extend(args);
    out
}

/// The program's arguments as C's `argv`: a stand-in for the program name
/// first (nothing reads it), then `args`.
fn c_argv(args: &[OsString]) -> Vec<Vec<u8>> {
    std::iter::once(Vec::new())
        .chain(args.iter().map(|a| bytes(a)))
        .collect()
}

// port: unzip.c:unzip
/// Everything `unzip()` does before `process_zipfiles()`, in UnZip mode:
/// `G.noargs`, the `UNZIP`/`UNZIPOPT` options, the argument-length check,
/// [`uz_opts`] and the operands. `Err(code)` ends the run with `code`
/// (usage, help, the version screen or a parameter error, already
/// printed).
pub(crate) fn parse_unzip(uz: &mut Uz, args: &[OsString]) -> Result<Parsed, i32> {
    parse(uz, args, false)
}

// port: unzip.c:unzip
/// [`parse_unzip`] in ZipInfo mode (`zipinfo`, or `unzip -Z`): the
/// `ZIPINFO`/`ZIPINFOOPT` options and [`zi_opts`].
pub(crate) fn parse_zipinfo(uz: &mut Uz, args: &[OsString]) -> Result<Parsed, i32> {
    parse(uz, args, true)
}

/// unzip.c:unzip, from `G.noargs` to the operand loop.
fn parse(uz: &mut Uz, args: &[OsString], zipinfo: bool) -> Result<Parsed, i32> {
    uz.noargs = args.is_empty(); // no options, no zipfile, no anything
    uz.o.zipinfo_mode = zipinfo;
    let argv = if zipinfo {
        envargs(uz, c_argv(args), "ZIPINFO", "ZIPINFOOPT")
    } else {
        envargs(uz, c_argv(args), "UNZIP", "UNZIPOPT")
    };

    // Check the length of all passed command line parameters: the Info()
    // message system formats into the sliding window, so every argument
    // must be shorter than WSIZE/4 (and ca. 2 standard line widths).
    for (i, a) in argv.iter().enumerate().skip(1) {
        if a.len() > (WSIZE >> 2) - 160 {
            let n = i.to_string();
            uz.info_fmt(0x401, m::CMD_LINE_PARAM_TOO_LONG, &[n.as_bytes()]);
            return Err(PK_PARAM);
        }
    }
    let at = if zipinfo {
        zi_opts(uz, &argv)?
    } else {
        uz_opts(uz, &argv)?
    };
    operands(uz, &argv[at..])
}

// port: unzip.c:unzip
/// The operand loop: `G.wildzipfn`, then `-d` (unless one came before the
/// archive) and `-x` among the names after it. `argv[0]` is the archive.
fn operands(uz: &mut Uz, argv: &[Vec<u8>]) -> Result<Parsed, i32> {
    let archive = os(&argv[0]);
    // `*pp = NULL` ends a list early: `None`.
    let mut v: Vec<Option<&[u8]>> = argv[1..].iter().map(|a| Some(&a[..])).collect();
    let argc = v.len();
    let mut filespecs = argc;
    let mut xfilespecs = 0usize;
    // `G.pfnames`/`G.pxnames` as offsets into `v`; `None` is `fnames`, the
    // defaults.
    let mut pfnames: Option<usize> = None;
    let mut pxnames: Option<usize> = None;
    let mut exdir = uz.o.exdir.clone();

    if argc > 0 {
        let mut in_files = false;
        let mut in_xfiles = false;
        uz.process_all_files = false;
        pfnames = Some(0);
        let mut pp = 0usize;
        while let Some(Some(cur)) = v.get(pp).copied() {
            if exdir.is_none() && cur.starts_with(b"-d") {
                let firstarg = pp == 0;
                let mut dir = cur[2..].to_vec();
                if in_files {
                    // ... zipfile ... -d exdir ...
                    v[pp] = None; // terminate G.pfnames
                    filespecs = pp - pfnames.unwrap_or(0);
                    in_files = false;
                } else if in_xfiles {
                    v[pp] = None; // terminate G.pxnames
                    xfilespecs = pp - pxnames.unwrap_or(0);
                    // "... -x xlist -d exdir":  nothing left
                }
                // first check for "-dexdir", then for "-d exdir"
                if dir.is_empty() {
                    pp += 1;
                    match v.get(pp).copied().flatten() {
                        Some(next) => dir = next.to_vec(),
                        None => {
                            uz.info(0x401, m::MUST_GIVE_EXDIR.as_bytes());
                            // don't extract here by accident
                            return Err(PK_PARAM);
                        }
                    }
                }
                exdir = Some(dir);
                if firstarg {
                    // ... zipfile -d exdir ...
                    if v.get(pp + 1).copied().flatten().is_some() {
                        pfnames = Some(pp + 1);
                        filespecs = argc - (pp + 1); // for now...
                    } else {
                        uz.process_all_files = true;
                        pfnames = None;
                        filespecs = 0;
                        break;
                    }
                }
            } else if !in_xfiles {
                if cur == b"-x" {
                    in_xfiles = true;
                    if pfnames == Some(pp) {
                        pfnames = None; // defaults
                        filespecs = 0;
                    } else if in_files {
                        v[pp] = None; // terminate G.pfnames
                        filespecs = pp - pfnames.unwrap_or(0); // adjust count
                        in_files = false;
                    }
                    pxnames = Some(pp + 1); // excluded-names ptr starts after -x
                    xfilespecs = argc - (pp + 1); // anything left
                } else {
                    in_files = true;
                }
            }
            pp += 1;
        }
    } else {
        uz.process_all_files = true; // for speed
    }
    uz.o.exdir = exdir;

    if uz.o.exdir.is_some() && !uz.extract_flag {
        // -d ignored
        uz.info(0x401, m::NOT_EXTRACTING.as_bytes());
    }
    // ubuntu: -DUNICODE_SUPPORT (`UNICODE_WCHAR`): `-U` once escapes all
    // non-ASCII.
    if flavour::unicode_support(uz.flavour) && uz.o.u_flag == 1 {
        uz.unicode_escape_all = true;
    }

    // The counted prefixes. A counted list can hold a `NULL`: in `a.zip f1
    // -d dir f2 -x e` the `-d` cuts `G.pfnames` at `f1`, `f2` restarts
    // `in_files` on the same list, and `-x` recounts it to 4, so C matches
    // against `[f1, NULL, dir, f2]`.
    // ruling: P20: that is upstream undefined behaviour (Apple's unzip lists
    // `f1`, then says `error:  zipfile probably corrupt (segmentation
    // violation)`, exit 3), so it is not reproduced: a list ends at its
    // first hole, which is what Apple acts on before it crashes, and what
    // follows the hole is dropped (`exdir` keeps its value). The `-x` list
    // cannot hold one (after `-x` only `-d` cuts it, and nothing recounts
    // it), but the same rule applies to it.
    let list = |start: Option<usize>, n: usize| -> Vec<OsString> {
        start.map_or_else(Vec::new, |s| {
            v[s..(s + n).min(v.len())]
                .iter()
                .map_while(|a| a.map(os))
                .collect()
        })
    };
    Ok(Parsed {
        archive,
        include: list(pfnames, filespecs),
        exclude: list(pxnames, xfilespecs),
        exdir: uz.o.exdir.as_deref().map(os),
    })
}

// port: unzip.c:uz_opts
/// UnZip mode's options, over `argv` (the program name first). Returns the
/// index of the archive operand; `Err(code)` when the run ends here.
fn uz_opts(uz: &mut Uz, argv: &[Vec<u8>]) -> Result<usize, i32> {
    let f = uz.flavour;
    let mut error = false;
    // Not reset between arguments: `--` then `-q` lowers `-q`, as in C.
    let mut negative: i32 = 0;
    let mut showhelp = 0;
    let mut argc = argv.len() as i64;
    let mut p = 0usize;

    loop {
        p += 1;
        argc -= 1;
        if !(argc > 0 && argv.get(p).is_some_and(|a| a.first() == Some(&b'-'))) {
            break;
        }
        let arg = &argv[p];
        let mut s = 1usize;
        while s < arg.len() {
            let c = arg[s];
            s += 1;
            match c {
                b'-' => negative += 1,
                b'a' => {
                    if negative != 0 {
                        uz.o.aflag = (uz.o.aflag - negative).max(0);
                        negative = 0;
                    } else {
                        uz.o.aflag += 1;
                    }
                }
                b'b' => {
                    if negative != 0 {
                        negative = 0; // do nothing:  "-b" is default
                    } else {
                        uz.o.aflag = 0;
                    }
                }
                // UNIXBACKUP
                b'B' => {
                    if negative != 0 {
                        uz.o.b_flag = false;
                        negative = 0;
                    } else {
                        uz.o.b_flag = true;
                    }
                }
                b'c' => {
                    if negative != 0 {
                        uz.o.cflag = false;
                        negative = 0;
                    } else {
                        uz.o.cflag = true;
                    }
                }
                b'C' => {
                    // -C:  match filenames case-insensitively
                    if negative != 0 {
                        uz.o.c_flag = false;
                        negative = 0;
                    } else {
                        uz.o.c_flag = true;
                    }
                }
                b'd' => {
                    if negative != 0 {
                        // negative not allowed with -d exdir
                        uz.info(0x401, m::MUST_GIVE_EXDIR.as_bytes());
                        return Err(PK_PARAM); // don't extract here by accident
                    }
                    if uz.o.exdir.is_some() {
                        uz.info(0x401, m::ONLY_ONE_EXDIR.as_bytes());
                        return Err(PK_PARAM); // GRR:  stupid restriction?
                    }
                    // first check for "-dexdir", then for "-d exdir"
                    let mut exdir = arg[s..].to_vec();
                    if exdir.is_empty() {
                        if argc > 1 {
                            argc -= 1;
                            p += 1;
                            exdir = argv[p].clone();
                            if exdir.first() == Some(&b'-') {
                                uz.info(0x401, m::MUST_GIVE_EXDIR.as_bytes());
                                return Err(PK_PARAM);
                            }
                        } else {
                            uz.info(0x401, m::MUST_GIVE_EXDIR.as_bytes());
                            return Err(PK_PARAM);
                        }
                    }
                    uz.o.exdir = Some(exdir);
                    // point s at end of exdir to avoid misinterpretation
                    // of exdir characters as more options
                    s = arg.len();
                }
                b'D' => {
                    // -D: Skip restoring dir (or any) timestamp.
                    if negative != 0 {
                        uz.o.d_flag = (uz.o.d_flag - negative).max(0);
                        negative = 0;
                    } else {
                        uz.o.d_flag += 1;
                    }
                }
                b'e' => {} // just ignore -e, -x options (extract)
                b'f' => {
                    // "freshen" (extract only newer files)
                    if negative != 0 {
                        uz.o.fflag = false;
                        uz.o.uflag = false;
                        negative = 0;
                    } else {
                        uz.o.fflag = true;
                        uz.o.uflag = true;
                    }
                }
                // ubuntu: -DACORN_FTYPE_NFS
                b'F' if flavour::acorn_ftype_nfs(f) => {
                    if negative != 0 {
                        uz.o.acorn_nfs_ext = false;
                        negative = 0;
                    } else {
                        uz.o.acorn_nfs_ext = true;
                    }
                }
                b'h' => {
                    // just print help message and quit
                    if showhelp == 0 {
                        showhelp = if arg.get(s) == Some(&b'h') { 2 } else { 1 };
                    }
                }
                b'j' => {
                    // junk pathnames/directory structure
                    if negative != 0 {
                        uz.o.jflag = false;
                        negative = 0;
                    } else {
                        uz.o.jflag = true;
                    }
                }
                // ATH_BEO_UNX
                b'K' => {
                    if negative != 0 {
                        uz.o.k_flag = false;
                        negative = 0;
                    } else {
                        uz.o.k_flag = true;
                    }
                }
                b'l' => {
                    if negative != 0 {
                        uz.o.vflag = (uz.o.vflag - negative).max(0);
                        negative = 0;
                    } else {
                        uz.o.vflag += 1;
                    }
                }
                b'L' => {
                    // convert (some) filenames to lowercase
                    if negative != 0 {
                        uz.o.l_flag = (uz.o.l_flag - negative).max(0);
                        negative = 0;
                    } else {
                        uz.o.l_flag += 1;
                    }
                }
                // MORE
                b'M' => {
                    // send all screen output through "more" fn.
                    if negative != 0 {
                        uz.o.m_flag = false;
                        negative = 0;
                    } else {
                        uz.o.m_flag = true;
                    }
                }
                b'n' => {
                    // don't overwrite any files
                    if negative != 0 {
                        uz.o.overwrite_none = false;
                        negative = 0;
                    } else {
                        uz.o.overwrite_none = true;
                    }
                }
                b'o' => {
                    // OK to overwrite files without prompting
                    if negative != 0 {
                        uz.o.overwrite_all = (uz.o.overwrite_all - negative).max(0);
                        negative = 0;
                    } else {
                        uz.o.overwrite_all += 1;
                    }
                }
                b'p' => {
                    // pipes:  extract to stdout, no messages
                    if negative != 0 {
                        uz.o.cflag = false;
                        uz.o.qflag = (uz.o.qflag - 999).max(0);
                        negative = 0;
                    } else {
                        uz.o.cflag = true;
                        uz.o.qflag += 999;
                    }
                }
                // CRYPT
                b'P' => {
                    if negative != 0 {
                        // negative not allowed with -P passwd
                        uz.info(0x401, m::MUST_GIVE_PASSWD.as_bytes());
                        return Err(PK_PARAM); // don't extract here by accident
                    }
                    // A second -P is ignored, and the rest of its argument
                    // read as options ("eventually support multiple
                    // passwords?").
                    if uz.o.pwdarg.is_none() {
                        // first check for "-Ppasswd", then for "-P passwd"
                        let mut pwd = arg[s..].to_vec();
                        if pwd.is_empty() {
                            if argc > 1 {
                                argc -= 1;
                                p += 1;
                                pwd = argv[p].clone();
                                if pwd.first() == Some(&b'-') {
                                    uz.info(0x401, m::MUST_GIVE_PASSWD.as_bytes());
                                    return Err(PK_PARAM);
                                }
                            } else {
                                uz.info(0x401, m::MUST_GIVE_PASSWD.as_bytes());
                                return Err(PK_PARAM);
                            }
                        }
                        uz.o.pwdarg = Some(pwd);
                        // point s at end of passwd
                        s = arg.len();
                    }
                }
                b'q' => {
                    // quiet:  fewer comments/messages
                    if negative != 0 {
                        uz.o.qflag = (uz.o.qflag - negative).max(0);
                        negative = 0;
                    } else {
                        uz.o.qflag += 1;
                    }
                }
                b't' => {
                    if negative != 0 {
                        uz.o.tflag = false;
                        negative = 0;
                    } else {
                        uz.o.tflag = true;
                    }
                }
                // TIMESTAMP
                b'T' => {
                    if negative != 0 {
                        uz.o.t_flag = false;
                        negative = 0;
                    } else {
                        uz.o.t_flag = true;
                    }
                }
                b'u' => {
                    // update (extract only new and newer files)
                    if negative != 0 {
                        uz.o.uflag = false;
                        negative = 0;
                    } else {
                        uz.o.uflag = true;
                    }
                }
                b'U' => {
                    if flavour::unicode_support(f) {
                        // ubuntu: -DUNICODE_SUPPORT: escape UTF-8, or
                        // disable UTF-8 support
                        if negative != 0 {
                            uz.o.u_flag = (uz.o.u_flag - negative).max(0);
                            negative = 0;
                        } else {
                            uz.o.u_flag += 1;
                        }
                    } else if negative != 0 {
                        // obsolete; to be removed in version 6.0
                        uz.o.l_flag = 1;
                        negative = 0;
                    } else {
                        uz.o.l_flag = 0;
                    }
                }
                b'v' => {
                    // verbose
                    if negative != 0 {
                        uz.o.vflag = (uz.o.vflag - negative).max(0);
                        negative = 0;
                    } else if uz.o.vflag != 0 {
                        uz.o.vflag += 1;
                    } else {
                        uz.o.vflag = 2;
                    }
                }
                b'V' => {
                    // Version (retain VMS/DEC-20 file versions)
                    if negative != 0 {
                        uz.o.v_flag = false;
                        negative = 0;
                    } else {
                        uz.o.v_flag = true;
                    }
                }
                // ubuntu: -DWILD_STOP_AT_DIR
                b'W' if flavour::wild_stop_at_dir(f) => {
                    // Wildcard interpretation (stop at '/'?)
                    if negative != 0 {
                        uz.o.w_flag = false;
                        negative = 0;
                    } else {
                        uz.o.w_flag = true;
                    }
                }
                b'x' => {} // extract:  default
                // RESTORE_UIDGID
                b'X' => {
                    // restore owner/protection info (need privs?)
                    if negative != 0 {
                        uz.o.x_flag = (uz.o.x_flag - negative).max(0);
                        negative = 0;
                    } else {
                        uz.o.x_flag += 1;
                    }
                }
                b'z' => {
                    // display only the archive comment
                    if negative != 0 {
                        uz.o.zflag = (uz.o.zflag - negative).max(0);
                        negative = 0;
                    } else {
                        uz.o.zflag += 1;
                    }
                }
                b'Z' => {
                    // should have been first option (ZipInfo)
                    uz.info(0x401, m::Z_FIRST.as_bytes());
                    error = true;
                }
                b':' => {
                    // allow "parent dir" path components
                    if negative != 0 {
                        uz.o.ddotflag = (uz.o.ddotflag - negative).max(0);
                        negative = 0;
                    } else {
                        uz.o.ddotflag += 1;
                    }
                }
                // UNIX
                b'^' => {
                    // allow control chars in filenames
                    if negative != 0 {
                        uz.o.cflxflag = (uz.o.cflxflag - negative).max(0);
                        negative = 0;
                    } else {
                        uz.o.cflxflag += 1;
                    }
                }
                _ => error = true,
            }
        }
    }

    // Check for nonsensical combinations of options.
    if showhelp > 0 {
        // just print help message and quit
        if showhelp == 2 {
            help_extended(uz);
            return Err(PK_OK);
        }
        return Err(usage(uz, false));
    }

    let o = &uz.o;
    if (o.cflag && (o.tflag || o.uflag)) || (o.tflag && o.uflag) || (o.fflag && o.overwrite_none) {
        uz.info(0x401, m::INVALID_OPTIONS.as_bytes());
        error = true;
    }
    if uz.o.aflag > 2 {
        uz.o.aflag = 2;
    }
    if uz.o.overwrite_all != 0 && uz.o.overwrite_none {
        uz.info(0x401, m::IGNORE_O_OPTION.as_bytes());
        uz.o.overwrite_all = 0;
    }
    // MORE: stdout redirected: "more" func. useless
    if uz.o.m_flag && !uz.host.stdout_is_tty() {
        uz.o.m_flag = false;
    }

    let no_zipfile = argc == 0;
    argc -= 1;
    if no_zipfile || error {
        if uz.o.vflag >= 2 && argc == -1 {
            // "unzip -v"
            show_version_info(uz);
            return Err(PK_OK);
        }
        if !uz.noargs && !error {
            error = true; // had options (not -h or -v) but no zipfile
        }
        return Err(usage(uz, error));
    }

    let o = &uz.o;
    uz.extract_flag = !(o.cflag || o.tflag || o.vflag != 0 || o.zflag != 0 || o.t_flag);
    Ok(p)
}

// port: zipinfo.c:zi_opts
/// ZipInfo mode's options, over `argv` (the program name first). Returns
/// the index of the archive operand; `Err(code)` when the run ends here.
fn zi_opts(uz: &mut Uz, argv: &[Vec<u8>]) -> Result<usize, i32> {
    let f = uz.flavour;
    let mut error = false;
    let mut negative: i32 = 0;
    // diff options => diff defaults
    let (mut hflag_slmv, mut hflag_2) = (true, false);
    let (mut tflag_slm, mut tflag_2v) = (true, false);
    let (mut explicit_h, mut explicit_t) = (false, false);

    uz.extract_flag = false; // zipinfo does not extract to disk
    let mut argc = argv.len() as i64;
    let mut p = 0usize;

    loop {
        argc -= 1;
        if argc <= 0 {
            break;
        }
        p += 1;
        if argv[p].first() != Some(&b'-') {
            break;
        }
        let arg = &argv[p];
        let mut s = 1usize;
        while s < arg.len() {
            let c = arg[s];
            s += 1;
            match c {
                b'-' => negative += 1,
                b'1' => {
                    // shortest listing:  JUST filenames
                    if negative != 0 {
                        uz.o.lflag = -2;
                        negative = 0;
                    } else {
                        uz.o.lflag = 1;
                    }
                }
                b'2' => {
                    // just filenames, plus headers if specified
                    if negative != 0 {
                        uz.o.lflag = -2;
                        negative = 0;
                    } else {
                        uz.o.lflag = 2;
                    }
                }
                b'C' => {
                    // -C:  match filenames case-insensitively
                    if negative != 0 {
                        uz.o.c_flag = false;
                        negative = 0;
                    } else {
                        uz.o.c_flag = true;
                    }
                }
                b'h' => {
                    // header line
                    if negative != 0 {
                        hflag_2 = false;
                        hflag_slmv = false;
                        negative = 0;
                    } else {
                        hflag_2 = true;
                        hflag_slmv = true;
                        explicit_h = true;
                        if uz.o.lflag == -1 {
                            uz.o.lflag = 0;
                        }
                    }
                }
                b'l' => {
                    // longer form of "ls -l" type listing
                    if negative != 0 {
                        uz.o.lflag = -2;
                        negative = 0;
                    } else {
                        uz.o.lflag = 5;
                    }
                }
                b'm' => {
                    // medium form of "ls -l" type listing
                    if negative != 0 {
                        uz.o.lflag = -2;
                        negative = 0;
                    } else {
                        uz.o.lflag = 4;
                    }
                }
                // MORE
                b'M' => {
                    // send output through built-in "more"
                    if negative != 0 {
                        uz.o.m_flag = false;
                        negative = 0;
                    } else {
                        uz.o.m_flag = true;
                    }
                }
                b's' => {
                    // default:  shorter "ls -l" type listing
                    if negative != 0 {
                        uz.o.lflag = -2;
                        negative = 0;
                    } else {
                        uz.o.lflag = 3;
                    }
                }
                b't' => {
                    // totals line
                    if negative != 0 {
                        tflag_2v = false;
                        tflag_slm = false;
                        negative = 0;
                    } else {
                        tflag_2v = true;
                        tflag_slm = true;
                        explicit_t = true;
                        if uz.o.lflag == -1 {
                            uz.o.lflag = 0;
                        }
                    }
                }
                b'T' => {
                    // use (sortable) decimal time format
                    if negative != 0 {
                        uz.o.t_flag = false;
                        negative = 0;
                    } else {
                        uz.o.t_flag = true;
                    }
                }
                // ubuntu: -DUNICODE_SUPPORT
                b'U' if flavour::unicode_support(f) => {
                    // escape UTF-8, or disable UTF-8 support
                    if negative != 0 {
                        uz.o.u_flag = (uz.o.u_flag - negative).max(0);
                        negative = 0;
                    } else {
                        uz.o.u_flag += 1;
                    }
                }
                b'v' => {
                    // turbo-verbose listing
                    if negative != 0 {
                        uz.o.lflag = -2;
                        negative = 0;
                    } else {
                        uz.o.lflag = 10;
                    }
                }
                // ubuntu: -DWILD_STOP_AT_DIR
                b'W' if flavour::wild_stop_at_dir(f) => {
                    // Wildcard interpretation (stop at '/'?)
                    if negative != 0 {
                        uz.o.w_flag = false;
                        negative = 0;
                    } else {
                        uz.o.w_flag = true;
                    }
                }
                b'z' => {
                    // print zipfile comment
                    if negative != 0 {
                        uz.o.zflag = 0;
                        negative = 0;
                    } else {
                        uz.o.zflag = 1;
                    }
                }
                b'Z' => {} // ZipInfo mode:  ignore
                _ => error = true,
            }
        }
    }
    let no_zipfile = argc == 0;
    argc -= 1;
    if no_zipfile || error {
        return Err(usage(uz, error));
    }

    // MORE: stdout redirected: "more" func useless
    if uz.o.m_flag && !uz.host.stdout_is_tty() {
        uz.o.m_flag = false;
    }

    // if no listing options given (or all negated), or if only -h/-t given
    // with individual files specified, use default listing format
    if uz.o.lflag < 0 || (argc > 0 && uz.o.lflag == 0) {
        uz.o.lflag = LFLAG;
    }

    // set header and totals flags to default or specified values
    match uz.o.lflag {
        // 0:  can only occur if either -t or -h explicitly given;
        // therefore set both flags equal to normally false value
        0 | 2 => {
            uz.o.hflag = hflag_2;
            uz.o.tflag = tflag_2v;
        }
        1 => {
            // only filenames, *always*
            uz.o.hflag = false;
            uz.o.tflag = false;
            uz.o.zflag = 0;
        }
        3..=5 => {
            uz.o.hflag = if argc > 0 && !explicit_h {
                false
            } else {
                hflag_slmv
            };
            uz.o.tflag = if argc > 0 && !explicit_t {
                false
            } else {
                tflag_slm
            };
        }
        10 => {
            uz.o.hflag = hflag_slmv;
            uz.o.tflag = tflag_2v;
        }
        _ => {}
    }
    Ok(p)
}

// port: unzip.c:usage
/// The usage screen of the current mode, to standard output, or with
/// `error` to standard error (standard output while `-t` is set, as every
/// message). Returns `PK_PARAM` with `error`, else `PK_COOL`.
pub(crate) fn usage(uz: &mut Uz, error: bool) -> i32 {
    let flag = if error { MSG_STDERR } else { 0 };
    let f = uz.flavour;
    let version = env!("CARGO_PKG_VERSION").as_bytes();
    if uz.o.zipinfo_mode {
        uz.info_fmt(flag, flavour::zipinfo_banner(f), &[version]);
        uz.info(flag, m::ZIPINFO_USAGE_LINE1.as_bytes());
        uz.info(flag, m::ZIPINFO_USAGE_LINE2.as_bytes());
        let mut line3 = m::ZIPINFO_USAGE_LINE3.to_owned();
        // ubuntu: 20-unzip60-alt-iconv-utf8.patch
        if flavour::iconv_charsets(f) {
            line3.push_str(m::ZIPINFO_USAGE_ICONV);
        }
        uz.info(flag, line3.as_bytes());
    } else {
        // UnZip mode
        let mut line1 = Vec::new();
        printf(&mut line1, flavour::unzip_banner(f), &[version]);
        line1.extend_from_slice(flavour::unzip_banner_rest(f).as_bytes());
        uz.info(flag, &line1);
        uz.info(flag, m::UNZIP_USAGE_LINE2.as_bytes());
        uz.info(flag, m::UNZIP_USAGE_LINE3.as_bytes());
        let mut line4 = m::UNZIP_USAGE_LINE4_HEAD.to_owned();
        // ubuntu: -DUNICODE_SUPPORT
        if flavour::unicode_support(f) {
            line4.push_str(m::UNZIP_USAGE_LINE4_UNICODE);
        }
        line4.push_str(m::UNZIP_USAGE_LINE4_TAIL);
        // ubuntu: 20-unzip60-alt-iconv-utf8.patch
        if flavour::iconv_charsets(f) {
            line4.push_str(m::UNZIP_USAGE_LINE4_ICONV);
        }
        uz.info(flag, line4.as_bytes());
        uz.info(flag, m::UNZIP_USAGE_LINE5.as_bytes());
    }
    if error { PK_PARAM } else { PK_COOL }
}

// port: unzip.c:help_extended
/// `unzip -hh`: the extended help, to standard output. Each line is printed
/// with `"%s\n"`, so its text is not a format (`%%` stays two bytes).
fn help_extended(uz: &mut Uz) {
    for line in m::HELP_EXTENDED {
        let mut l = line.as_bytes().to_vec();
        l.push(b'\n');
        uz.info(0, &l);
    }
}

// port: unzip.c:show_version_info
/// `unzip -v` alone: the banner, the build's options and the environment's,
/// to standard output; `-vqqqq` prints the version number only.
fn show_version_info(uz: &mut Uz) {
    let f = uz.flavour;
    if uz.o.qflag > 3 {
        // "unzip -vqqqq": UZ_MAJORVER*100 + UZ_MINORVER*10 + UZ_PATCHLEVEL
        uz.info(0, b"600\n");
        return;
    }
    let mut line1 = Vec::new();
    printf(
        &mut line1,
        flavour::unzip_banner(f),
        &[env!("CARGO_PKG_VERSION").as_bytes()],
    );
    line1.extend_from_slice(flavour::unzip_banner_rest(f).as_bytes());
    uz.info(0, &line1);
    uz.info(0, m::UNZIP_USAGE_LINE2V.as_bytes());
    version(uz);
    uz.info(0, m::COMPILE_OPTIONS.as_bytes());
    let mut opts: Vec<String> = Vec::new();
    // ubuntu: -DACORN_FTYPE_NFS
    if flavour::acorn_ftype_nfs(f) {
        opts.push(m::OPT_ACORN_FTYPE_NFS.into());
    }
    opts.extend(
        [
            m::OPT_COPYRIGHT_CLEAN,
            m::OPT_SET_DIR_ATTRIB,
            m::OPT_SYMLINKS,
            m::OPT_TIMESTAMP,
            m::OPT_UNIXBACKUP,
            m::OPT_USE_EF_UT_TIME,
            m::OPT_USE_UNSHRINK,
            m::OPT_USE_DEFLATE64,
        ]
        .map(String::from),
    );
    // ubuntu: -DUNICODE_SUPPORT (`UTF8_MAYBE_NATIVE`: the codeset
    // `nl_langinfo(CODESET)` names, `UTF-8` or `other`; `fileio::init_locale`).
    if flavour::unicode_support(f) {
        let coding = if uz.native_is_utf8 {
            m::SYS_CH_UTF8
        } else {
            m::SYS_CH_OTHER
        };
        let mut line = Vec::new();
        printf(&mut line, m::OPT_USE_UNICODE, &[coding.as_bytes()]);
        opts.push(String::from_utf8_lossy(&line).into_owned());
    }
    opts.extend([m::OPT_USE_LFS, m::OPT_USE_ZIP64].map(String::from));
    // ubuntu: -DUSE_BZIP2
    if flavour::use_bzip2(f) {
        opts.push(m::OPT_USE_BZIP2.into());
    }
    opts.push(m::OPT_VMS_TEXT_CONV.into());
    // ubuntu: -DWILD_STOP_AT_DIR
    if flavour::wild_stop_at_dir(f) {
        opts.push(m::OPT_WILD_STOP_AT_DIR.into());
    }
    for o in &opts {
        uz.info_fmt(0, m::COMPILE_OPT_FORMAT, &[o.as_bytes()]);
    }
    // CRYPT (never `numopts == 0`: the "[none]" line is unreachable)
    uz.info(0, m::DECRYPTION.as_bytes());

    uz.info(0, m::ENV_OPTIONS.as_bytes());
    for name in ["UNZIP", "UNZIPOPT", "ZIPINFO", "ZIPINFOOPT"] {
        let value = getenv(uz, name).filter(|v| !v.is_empty());
        // EnvOptFormat: "%16s:  %.1024s\n"
        let mut line = format!("{name:>16}:  ").into_bytes();
        match value {
            Some(v) => line.extend_from_slice(&v[..v.len().min(1024)]),
            None => line.extend_from_slice(m::NONE.as_bytes()),
        }
        line.push(b'\n');
        uz.info(0, &line);
    }
}

// port: unix/unix.c:version
/// The `Compiled with ...` line of `-v` and its blank line.
fn version(uz: &mut Uz) {
    uz.info(0, flavour::compiled_with(uz.flavour).as_bytes());
}

/// What funzip's command line says (funzip.c:main): the password (an
/// argument starting with `-`, `CRYPT`) and the input file, if given.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FunzipArgs {
    /// `p`: the first argument's bytes after its `-`.
    pub password: Option<Vec<u8>>,
    /// The input file (the next argument); standard input when `None`.
    pub input: Option<OsString>,
}

// port: funzip.c:main
/// funzip's arguments: skip the program name, take a first argument
/// starting with `-` as the password, then the input file (`funzip.rs`
/// ports the rest of `main`).
pub(crate) fn parse_funzip(args: &[OsString]) -> FunzipArgs {
    let mut rest = args.iter();
    let mut out = FunzipArgs::default();
    // get the command line password, if any
    let mut next = rest.next();
    if let Some(a) = next {
        let b = bytes(a);
        if b.first() == Some(&b'-') {
            out.password = Some(b[1..].to_vec());
            next = rest.next();
        }
    }
    out.input = next.cloned();
    out
}

#[cfg(test)]
mod tests;
