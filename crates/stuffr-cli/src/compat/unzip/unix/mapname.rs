//! `unix/unix.c`'s names and paths: `mapname()` (an entry's name to the
//! path it is extracted to) and `checkdir()` (the extraction root, the path
//! being built, the directories made on the way), with Apple's `mkdir_qtn()`.
//!
//! The path is built as the C builds it, into [`Checkdir::buildpath`] and
//! then `G.filename` (`uz.filename`): under Apple's tree it starts with the
//! root's real absolute path (`G.rootpath`, no trailing `/`), under
//! upstream's (Ubuntu) with the `-d` operand and a `/`, or nothing. Every
//! file-system operation takes the part after the root ([`target`]) and
//! goes through the beneath walk (`beneath.rs`, deviation 3).

use std::io;

use super::super::fileio::{self, c_str};
use super::super::messages as m;
use super::super::{PK_WARN, Uz, flavour};
use super::beneath::{self, Root, Stat};
use crate::compat::host;

/// unzpriv.h's `mapname()`/`checkdir()` codes.
pub(crate) const MPN_OK: i32 = 0;
pub(crate) const MPN_INF_TRUNC: i32 = 1 << 8;
pub(crate) const MPN_INF_SKIP: i32 = 2 << 8;
pub(crate) const MPN_ERR_SKIP: i32 = 3 << 8;
pub(crate) const MPN_ERR_TOOLONG: i32 = 4 << 8;
pub(crate) const MPN_CREATED_DIR: i32 = 16 << 8;
pub(crate) const MPN_VOL_LABEL: i32 = 17 << 8;
pub(crate) const MPN_MASK: i32 = 0x7f00;

/// unzpriv.h's host number `UNIX_`.
const UNIX_: u8 = 3;
/// `S_ISGID`.
#[cfg(unix)]
const S_ISGID: u32 = 0o2000;

/// `checkdir()`'s state (`SYSTEM_SPECIFIC_GLOBALS`: `rootpath`, `rootlen`,
/// `rootdir`, `buildpath`, `end`, `created_dir`, `renamed_fullpath`, and
/// `G.create_dirs`).
#[derive(Default)]
pub(crate) struct Checkdir {
    /// `G.rootpath` (Apple: the real absolute path, no trailing `/`;
    /// upstream: the operand and a `/`), `G.rootlen` its length (0: none).
    pub(crate) rootpath: Vec<u8>,
    /// apple: unix.c:1169, `G.rootdir`: the root's descriptor. For the
    /// Ubuntu flavour the `-d` root's (upstream keeps only the path).
    pub(crate) rootdir: Option<Root>,
    /// The Ubuntu flavour's paths without a root (no `-d`, or a name
    /// renamed to an absolute one): walked beneath the current directory
    /// (deviation 3).
    pub(crate) cwd: Option<Root>,
    /// `G.buildpath`, the path being built (`None`: freed).
    pub(crate) buildpath: Option<Vec<u8>>,
    /// `G.created_dir`: this entry's path made a directory.
    pub(crate) created_dir: bool,
    /// `G.renamed_fullpath`: renamed to an absolute name (no root prefix).
    pub(crate) renamed_fullpath: bool,
    /// `G.create_dirs`: directories may be made (not `-f`, or renamed).
    pub(crate) create_dirs: bool,
}

impl Checkdir {
    /// `G.rootlen`.
    pub(crate) fn rootlen(&self) -> usize {
        self.rootpath.len()
    }
}

/// Where the path `full` (a `G.filename` or `G.buildpath` this module
/// built) lives: the root it is walked from and the part after the root.
/// ruling: T10-3. Apple's tree takes `full + G.rootlen + 1` on faith; for a
/// name renamed to an absolute one (no root prefix) that points past the
/// name into stale memory (undefined behaviour; the binary failed with
/// "No such file or directory"). Here such a path is "No such file or
/// directory" for every operation. Upstream builds it relative (the
/// leading `/` is dropped) and walks it from the current directory, as the
/// Ubuntu flavour does here.
pub(crate) fn target<'a>(uz: &'a Uz, full: &'a [u8]) -> io::Result<(&'a Root, &'a [u8])> {
    let ck = &uz.ck;
    let rootlen = ck.rootlen();
    if flavour::apple_root(uz.flavour) {
        let root = ck.rootdir.as_ref().ok_or_else(enoent)?;
        if rootlen > 0
            && full.len() > rootlen
            && full.starts_with(&ck.rootpath)
            && full[rootlen] == b'/'
        {
            return Ok((root, &full[rootlen + 1..]));
        }
        Err(enoent())
    } else if rootlen > 0 && !ck.renamed_fullpath && full.starts_with(&ck.rootpath) {
        let root = ck.rootdir.as_ref().ok_or_else(enoent)?;
        Ok((root, &full[rootlen..]))
    } else {
        let root = ck.cwd.as_ref().ok_or_else(enoent)?;
        Ok((root, full))
    }
}

/// `ENOENT`.
fn enoent() -> io::Error {
    #[cfg(unix)]
    {
        io::Error::from_raw_os_error(libc::ENOENT)
    }
    #[cfg(not(unix))]
    {
        io::Error::from(io::ErrorKind::NotFound)
    }
}

/// How the extraction shows a path (`full`, a `G.filename`): apple:
/// unzpriv.h:2738 `FnFilterP` (`uO.exdir`, a `/`, then the name from
/// `full + G.rootlen + 1`), upstream's `FnFilter1(G.filename)`. Without a
/// root (`-c`, `-p`) Apple's skips the name's first byte, as its binary
/// does (probe: `unzip -c a.zip` of `dir/f.txt` shows `extracting:
/// ir/f.txt`; with `-d x`, `x/ir/f.txt`); past the name's end it reads what
/// `G.filename` holds there, as the C reads its array.
pub(crate) fn shown(uz: &mut Uz, full: &[u8]) -> Vec<u8> {
    if flavour::apple_root(uz.flavour) {
        let off = uz.ck.rootlen() + 1;
        let raw = if off <= full.len() {
            full[off..].to_vec()
        } else {
            c_str(uz.filename.get(off..).unwrap_or(&[])).to_vec()
        };
        let pfx = uz.o.exdir.clone();
        return fileio::fnfilterp(uz, pfx.as_deref(), &raw);
    }
    fileio::fnfilter1(uz, full)
}

/// The text `strerror()` gives for `e`: an escape is `EACCES`, as Apple's
/// `open_outfile()` converts `ENOTCAPABLE` (apple: fileio.c:314), and as
/// the Ubuntu flavour answers for what it cannot create (deviation 3).
pub(crate) fn strerror(_uz: &Uz, e: &io::Error) -> Vec<u8> {
    if beneath::is_escape(e) {
        return host::strerror(&beneath::eacces());
    }
    host::strerror(e)
}

/// [`strerror`] where Apple prints `ENOTCAPABLE` as it is: `checkdir()`'s
/// "cannot create" (probe: `unzip -d dst c.zip` of `link/sub/file.txt`
/// with `dst/link -> ../bar`: `Capabilities insufficient`).
fn strerror_unconverted(uz: &Uz, e: &io::Error) -> Vec<u8> {
    if flavour::apple_root(uz.flavour) {
        return host::strerror(e);
    }
    strerror(uz, e)
}

/// `stat()` or `fstatat(..., AT_RESOLVE_BENEATH | AT_SYMLINK_NOFOLLOW)` of a
/// path this module built.
pub(crate) fn lstat(uz: &Uz, full: &[u8]) -> io::Result<Stat> {
    let (root, rel) = target(uz, full)?;
    root.lstat(rel)
}

/// `stat()` beneath the root (the last component followed beneath it).
pub(crate) fn stat(uz: &Uz, full: &[u8]) -> io::Result<Stat> {
    let (root, rel) = target(uz, full)?;
    root.stat(rel)
}

// port: unix.c:mkdir_qtn
/// `mkdir_qtn(zipfd, path, mode)` within the root: the parent opened
/// beneath the root, `mkdirat()` there, and the archive's quarantine given
/// to the directory (apple: unix.c:757; both flavours on macOS, deviation
/// 7). `EEXIST` is success in Apple's wrapper; upstream calls `mkdir()`
/// itself, for which it is a failure.
fn mkdir_qtn(uz: &Uz, path: &[u8], mode: u32) -> io::Result<()> {
    let (root, rel) = target(uz, path)?;
    let (dir, name) = root.parent(rel)?;
    match dir.mkdir(&name, mode) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && flavour::apple_root(uz.flavour) => {}
        Err(e) => return Err(e),
    }
    if uz.qf.is_some()
        && let Ok(d) = root.dir(rel)
        && super::attrs::quarantine_dir(uz, &d).is_err()
    {
        // apple: unix.c:809 (the new directory is removed again)
        let _ = dir.unlink(&name, true);
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `mkdir_qtn()` of the extraction root itself (`G.rootpath` still NULL:
/// the operand, made in the current directory), with its quarantine
/// (apple: unix.c:781).
fn mkdir_root(uz: &Uz, tmproot: &[u8], mode: u32) -> io::Result<()> {
    let p = uz.host.path(tmproot);
    let made = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().mode(mode).create(&p)
        }
        #[cfg(not(unix))]
        {
            let _ = mode;
            std::fs::create_dir(&p)
        }
    };
    match made {
        Ok(()) => {}
        // apple: unix.c:787 (Apple's wrapper; upstream's own `mkdir()`
        // fails)
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && flavour::apple_root(uz.flavour) => {}
        Err(e) => return Err(e),
    }
    if uz.qf.is_some()
        && let Ok(r) = Root::open(&p)
        && let Ok(d) = r.top()
        && super::attrs::quarantine_dir(uz, &d).is_err()
    {
        let _ = std::fs::remove_dir(&p);
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// port: unix.c:checkdir (ROOT)
/// `checkdir(exdir, ROOT)`: the extraction root, made when missing (one
/// level, as the C makes it) unless freshening. Apple's tree always has one
/// (`.` without `-d`) and keeps its real path; upstream's only for `-d`.
/// Returns an `MPN_*` code.
pub(crate) fn checkdir_root(uz: &mut Uz, pathcomp: &[u8]) -> i32 {
    if uz.ck.rootlen() > 0 {
        // rootpath was already set, nothing to do
        return MPN_OK;
    }
    if pathcomp.is_empty() {
        return MPN_OK;
    }
    let mut tmproot = pathcomp.to_vec();
    if tmproot.last() == Some(&b'/') {
        tmproot.pop();
    }
    if !tmproot.is_empty() {
        let p = uz.host.path(&tmproot);
        let is_dir = std::fs::metadata(&p).is_ok_and(|md| md.is_dir());
        if !is_dir {
            // path does not exist
            if !uz.ck.create_dirs {
                // skip (or treat as stored file)
                return MPN_INF_SKIP;
            }
            // create the directory (could add loop here scanning tmproot
            // to create more than one level, but why really necessary?)
            if let Err(e) = mkdir_root(uz, &tmproot, 0o777) {
                let shown = fileio::fnfilter1(uz, &tmproot);
                let err = host::strerror(&e);
                uz.info_fmt(1, m::CHECKDIR_CANNOT_CREATE_ROOT, &[&shown, &err]);
                // path didn't exist, tried to create, and failed: file
                // exists, or 2+ subdir levels required
                return MPN_ERR_SKIP;
            }
        }
    }
    if flavour::apple_root(uz.flavour) {
        // apple: unix.c:1162
        let Ok(real) = std::fs::canonicalize(uz.host.path(&tmproot)) else {
            return MPN_ERR_SKIP;
        };
        let Ok(root) = Root::open(&real) else {
            return MPN_ERR_SKIP;
        };
        uz.ck.rootpath = real.as_os_str().as_encoded_bytes().to_vec();
        uz.ck.rootdir = Some(root);
    } else {
        tmproot.push(b'/');
        match Root::open(&uz.host.path(&tmproot)) {
            Ok(root) => uz.ck.rootdir = Some(root),
            Err(_) => return MPN_ERR_SKIP,
        }
        uz.ck.rootpath = tmproot;
    }
    MPN_OK
}

/// The Ubuntu flavour's root for paths without one (deviation 3): the
/// current directory, opened once.
pub(crate) fn open_cwd(uz: &mut Uz) {
    if uz.ck.cwd.is_none() {
        uz.ck.cwd = Root::open(&uz.host.path(b".")).ok();
    }
}

// port: unix.c:checkdir (INIT)
/// `checkdir(NULL, INIT)`: start the path at the root (unless renamed to an
/// absolute name).
fn checkdir_init(uz: &mut Uz) {
    let mut b = Vec::new();
    if uz.ck.rootlen() > 0 && !uz.ck.renamed_fullpath {
        b.extend_from_slice(&uz.ck.rootpath);
    }
    uz.ck.buildpath = Some(b);
}

// port: unix.c:checkdir (APPEND_DIR)
/// `checkdir(pathcomp, APPEND_DIR)`: append a directory and make it when it
/// does not exist (unless freshening). Under Apple's tree a symlink there
/// is left for the walk (apple: unix.c:1002). Returns an `MPN_*` code.
fn checkdir_append_dir(uz: &mut Uz, pathcomp: &[u8]) -> i32 {
    let apple = flavour::apple_root(uz.flavour);
    let filnamsiz = uz.filename.len();
    let mut b = uz.ck.buildpath.take().unwrap_or_default();
    if apple {
        b.push(b'/');
    }
    b.extend_from_slice(pathcomp);
    // next check: need to append '/', at least one-char name, '\0'
    let too_long = b.len() > filnamsiz - 3;
    let st = if apple {
        lstat(uz, &b)
    } else {
        // ruling: deviation 3. Upstream's `stat()` follows a symlink out of
        // the root and sees what is there; here such a path is taken for
        // the directory Ubuntu would usually find, so the entry goes on to
        // its create, which is refused ("cannot create ... Permission
        // denied"), and nothing outside is looked at to decide.
        match stat(uz, &b) {
            Err(e) if beneath::is_escape(&e) => Ok(Stat {
                mode: 0o040755,
                dev: 0,
                ino: 0,
                mtime: 0,
            }),
            st => st,
        }
    };
    match st {
        Err(_) => {
            // path doesn't exist
            if !uz.ck.create_dirs {
                // told not to create (freshening)
                return MPN_INF_SKIP;
            }
            if too_long {
                let shown = fileio::fnfilter1(uz, &b);
                uz.info_fmt(1, m::CHECKDIR_TOO_LONG, &[&shown]);
                // no room for filenames:  fatal
                return MPN_ERR_TOOLONG;
            }
            if let Err(e) = mkdir_qtn(uz, &b, 0o777) {
                let err = strerror_unconverted(uz, &e);
                let shown2 = fileio::fnfilter2(uz, &b);
                let name = c_str(&uz.filename).to_vec();
                let shown1 = fileio::fnfilter1(uz, &name);
                uz.info_fmt(1, m::CHECKDIR_CANNOT_CREATE, &[&shown2, &err, &shown1]);
                // path didn't exist, tried to create, failed
                return MPN_ERR_SKIP;
            }
            uz.ck.created_dir = true;
        }
        // apple: unix.c:1002 (dead, or pointing outside the root: dealt
        // with later)
        Ok(st) if apple && st.is_symlink() => {}
        Ok(st) if !st.is_dir() => {
            let shown2 = fileio::fnfilter2(uz, &b);
            let name = c_str(&uz.filename).to_vec();
            let shown1 = fileio::fnfilter1(uz, &name);
            uz.info_fmt(1, m::CHECKDIR_NOT_DIR, &[&shown2, &shown1]);
            // path existed but wasn't dir
            return MPN_ERR_SKIP;
        }
        Ok(_) => {}
    }
    if too_long {
        let shown = fileio::fnfilter1(uz, &b);
        uz.info_fmt(1, m::CHECKDIR_TOO_LONG, &[&shown]);
        // no room for filenames:  fatal
        return MPN_ERR_TOOLONG;
    }
    if !apple {
        b.push(b'/');
    }
    uz.ck.buildpath = Some(b);
    MPN_OK
}

// port: unix.c:checkdir (APPEND_NAME)
/// `checkdir(pathcomp, APPEND_NAME)`: append the name, truncated (with a
/// warning) at `FILNAMSIZ`.
fn checkdir_append_name(uz: &mut Uz, pathcomp: &[u8]) -> i32 {
    let filnamsiz = uz.filename.len();
    let mut b = uz.ck.buildpath.take().unwrap_or_default();
    if flavour::apple_root(uz.flavour) {
        b.push(b'/');
    }
    for &c in pathcomp {
        b.push(c);
        if b.len() >= filnamsiz {
            b.pop();
            let name = c_str(&uz.filename).to_vec();
            let shown1 = fileio::fnfilter1(uz, &name);
            let shown2 = fileio::fnfilter2(uz, &b);
            uz.info_fmt(0x201, m::CHECKDIR_TRUNCATING, &[&shown1, &shown2]);
            uz.ck.buildpath = Some(b);
            // filename truncated
            return MPN_INF_TRUNC;
        }
    }
    uz.ck.buildpath = Some(b);
    MPN_OK
}

// port: unix.c:checkdir (GETPATH)
/// `checkdir(G.filename, GETPATH)`: the built path into `G.filename`.
fn checkdir_getpath(uz: &mut Uz) {
    let b = uz.ck.buildpath.take().unwrap_or_default();
    set_filename(uz, &b);
}

/// `strcpy(G.filename, s)` (the path never passes `FILNAMSIZ - 1` bytes:
/// `checkdir()` holds it there).
pub(crate) fn set_filename(uz: &mut Uz, s: &[u8]) {
    let n = s.len().min(uz.filename.len() - 1);
    uz.filename[..n].copy_from_slice(&s[..n]);
    uz.filename[n] = 0;
}

/// unix.c:filtattr: the set-user-ID, set-group-ID and sticky bits dropped
/// unless `-K`.
pub(crate) fn filtattr(uz: &Uz, perms: u32) -> u32 {
    let mut perms = perms;
    // keep setuid/setgid/tacky perms?
    if !uz.o.k_flag {
        perms &= !0o7000;
    }
    0xffff & perms
}

// port: unix.c:mapname
/// `mapname(renamed)`: the entry's name (`G.filename`) mapped to the path it
/// is extracted to, directories made on the way, `G.filename` set to it.
/// `../` components are dropped with a warning (unless `-:`), control
/// bytes dropped (unless `-^`), a VMS version removed (unless `-V`), and
/// `.` and `..` as a last component become `_` and `__`. A directory entry
/// is made here and answers `MPN_CREATED_DIR` (or `MPN_INF_SKIP` when it
/// existed). `pinfo` is the entry's `G.pInfo` (its `file_attr` may change).
pub(crate) fn mapname(uz: &mut Uz, pinfo: &mut super::super::extract::Info, renamed: bool) -> i32 {
    let mut killed_ddot = false; // is set when skipping "../" pathcomp
    let mut error = MPN_OK;

    if pinfo.pinfo.vollabel {
        return MPN_VOL_LABEL; // can't set disk volume labels in Unix
    }

    // can create path as long as not just freshening, or if user told us
    uz.ck.create_dirs = !uz.o.fflag || renamed;
    uz.ck.created_dir = false; // not yet

    let filename = c_str(&uz.filename).to_vec();
    // user gave full pathname:  don't prepend rootpath
    uz.ck.renamed_fullpath = renamed && filename.first() == Some(&b'/');

    checkdir_init(uz); // initialize path buffer

    let mut pathcomp: Vec<u8> = Vec::new(); // initialize translation buffer
    let mut lastsemi: Option<usize> = None;
    let cp = if uz.o.jflag {
        // junking directories
        match filename.iter().rposition(|&b| b == b'/') {
            Some(i) => &filename[i + 1..],
            None => &filename[..],
        }
    } else {
        &filename[..]
    };

    for &workch in cp {
        match workch {
            b'/' => {
                // can assume -j flag not given
                if pathcomp == b"." {
                    // don't bother appending "./" to the path
                    pathcomp.clear();
                } else if uz.o.ddotflag == 0 && pathcomp == b".." {
                    // "../" dir traversal detected, skip over it
                    pathcomp.clear();
                    killed_ddot = true; // set "show message" flag
                }
                // when path component is not empty, append it now
                if !pathcomp.is_empty() {
                    error = checkdir_append_dir(uz, &pathcomp);
                    if error & MPN_MASK > MPN_INF_TRUNC {
                        return error;
                    }
                }
                pathcomp.clear(); // reset conversion buffer for next piece
                lastsemi = None; // leave direct. semi-colons alone
            }
            b';' => {
                // VMS version (or DEC-20 attrib?)
                lastsemi = Some(pathcomp.len());
                pathcomp.push(b';'); // keep for now; remove VMS ";##"
            }
            // ubuntu: -DACORN_FTYPE_NFS keeps a ',' for the NFS filetype
            // here (`flavour::acorn_ftype_nfs`, Task 13).
            _ => {
                // disable control character filter when requested, else
                // allow 8-bit characters (e.g. UTF-8) in filenames:
                if uz.o.cflxflag != 0
                    || fileio::is_print(uz, workch)
                    || (128..=254).contains(&workch)
                {
                    pathcomp.push(workch);
                }
            }
        }
    }

    // Show warning when stripping insecure "parent dir" path components
    if killed_ddot && uz.o.qflag == 0 {
        let shown = fileio::fnfilter1(uz, &filename);
        uz.info_fmt(0, m::SKIPPED_DDOT, &[&shown]);
        if error & !MPN_MASK == 0 {
            error = (error & MPN_MASK) | PK_WARN;
        }
    }

    // Report if directory was created (and no file to create:  filename
    // ended in '/'), check name to be sure it exists, and combine path and
    // name before exiting.
    // ruling: T10-4. An empty name makes the C read `G.filename[-1]` (before
    // the array: undefined behaviour); here an empty name does not end in
    // '/', so it fails conversion below.
    if filename.last() == Some(&b'/') {
        checkdir_getpath(uz);
        if uz.ck.created_dir {
            let full = c_str(&uz.filename).to_vec();
            if uz.o.qflag == 0 {
                let shown = shown(uz, &full);
                uz.info_fmt(0, m::CREATING, &[&shown]);
            }
            // Filter out security-relevant attributes bits.
            pinfo.file_attr = filtattr(uz, pinfo.file_attr);
            // When extracting non-UNIX directories or when extracting
            // without UID/GID restoration or SGID preservation, any SGID
            // flag inherited from the parent directory should be
            // maintained to allow files extracted into this new folder to
            // inherit the GID setting from the parent directory.
            if pinfo.pinfo.hostnum != UNIX_ || !(uz.o.x_flag != 0 || uz.o.k_flag) {
                // preserve SGID bit when inherited from parent dir (a
                // `stat()`: read only, as the C's)
                match std::fs::metadata(uz.host.path(&full)) {
                    #[cfg(unix)]
                    Ok(st) => {
                        use std::os::unix::fs::PermissionsExt;
                        pinfo.file_attr |= st.permissions().mode() & S_ISGID;
                    }
                    #[cfg(not(unix))]
                    Ok(_) => {}
                    Err(e) => perror(uz, m::PERROR_DIR_ATTRS, &e),
                }
            }
            // set approx. dir perms (make sure can still read/write in dir)
            if let Err(e) = super::attrs::chmod_dir(uz, &full, pinfo.file_attr | 0o700) {
                perror(uz, m::PERROR_CHMOD_DIR, &e);
            }
            // set dir time (note trailing '/')
            return (error & !MPN_MASK) | MPN_CREATED_DIR;
        }
        // dir existed already; don't look for data to extract
        return (error & !MPN_MASK) | MPN_INF_SKIP;
    }

    // if not saving them, remove VMS version numbers (appended ";###")
    if !uz.o.v_flag
        && let Some(semi) = lastsemi
        && pathcomp[semi + 1..].iter().all(u8::is_ascii_digit)
    {
        // only digits between ';' and end:  nuke
        pathcomp.truncate(semi);
    }

    // On UNIX (and compatible systems), "." and ".." are reserved for
    // directory navigation and cannot be used as regular file names. These
    // reserved one-dot and two-dot names are mapped to "_" and "__".
    if pathcomp == b"." {
        pathcomp = b"_".to_vec();
    } else if pathcomp == b".." {
        pathcomp = b"__".to_vec();
    }

    if pathcomp.is_empty() {
        let shown = fileio::fnfilter1(uz, &filename);
        uz.info_fmt(1, m::MAPNAME_FAILED, &[&shown]);
        return (error & !MPN_MASK) | MPN_ERR_SKIP;
    }

    checkdir_append_name(uz, &pathcomp); // returns 1 if truncated: care?
    checkdir_getpath(uz);
    error
}

/// `perror(s)`: `s: <strerror>` and a newline on standard error, straight
/// to the stream (not through `Info()`: `G.sol` is not touched).
pub(crate) fn perror(uz: &mut Uz, s: &str, e: &io::Error) {
    let mut v = s.as_bytes().to_vec();
    v.extend_from_slice(b": ");
    v.extend_from_slice(&strerror(uz, e));
    v.push(b'\n');
    let _ = uz.err.write_all(&v);
    let _ = uz.err.flush();
}
