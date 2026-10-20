//! The resolve-beneath walk (deviation 3): what Apple's `O_RESOLVE_BENEATH`
//! and `AT_RESOLVE_BENEATH` sites do, done by hand so that both flavours,
//! and every platform with `openat(2)`, get it.
//!
//! Every path the extraction creates, removes or changes is a path
//! relative to the extraction root ([`Root`]), walked one component at a
//! time from the root's descriptor with `openat(O_DIRECTORY | O_NOFOLLOW)`.
//! A symlink met on the way is followed only while the resolution stays
//! beneath the root: an absolute target, or a `..` at the root, is an
//! escape (macOS's `ENOTCAPABLE`, [`is_escape`]), and so is anything past
//! [`MAXSYMLINKS`] links (`ELOOP`). The walk keeps the directory names it
//! has resolved, not their descriptors, so a `..` re-walks that prefix from
//! the root (at most a name's length of descriptors is never held).
//!
//! The last component is never followed by an operation that changes it
//! ([`Dir::create_file`] opens with `O_NOFOLLOW`; `mkdirat`, `unlinkat`,
//! `symlinkat`, `renameat` act on the name itself), so a symlink already in
//! the destination is at most the object of an operation, never a door out
//! of the root.
//!
//! probe: Apple's `unzip -d dst` of `link/file.txt` with `dst/link -> bar`
//! (inside) extracts into `dst/bar`; with `dst/link -> ../bar` and with an
//! absolute `dst/link` pointing inside `dst`, both refuse ("cannot enter
//! dst/link", `Permission denied`, from `ENOTCAPABLE`); with `dst/link ->
//! dead`, "No such file or directory".
//!
//! Off unix (R8: built, not promised) the same interface runs over
//! `std::fs` with joined paths, `..` still refused at the root.

use std::fs::File;
use std::io;

/// `MAXSYMLINKS` (sys/param.h on both references' platforms: 32).
#[cfg(unix)]
pub(crate) const MAXSYMLINKS: u32 = 32;

/// What `fstatat()` told about a name: the fields the extraction reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Stat {
    /// `st_mode` (type and permission bits).
    pub(crate) mode: u32,
    pub(crate) dev: u64,
    pub(crate) ino: u64,
    /// `st_mtime`.
    pub(crate) mtime: i64,
}

/// `S_IFMT` and the types, as both references' platforms number them.
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
#[cfg(not(unix))]
const S_IFREG: u32 = 0o100000;

impl Stat {
    pub(crate) fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }
    pub(crate) fn is_symlink(&self) -> bool {
        self.mode & S_IFMT == S_IFLNK
    }
}

/// The error an escape gives: macOS's own `ENOTCAPABLE` there, elsewhere an
/// error whose text is macOS's ("Capabilities insufficient": the flavour
/// that prints it unconverted is Apple's).
pub(crate) fn escape() -> io::Error {
    #[cfg(target_os = "macos")]
    {
        io::Error::from_raw_os_error(libc::ENOTCAPABLE)
    }
    #[cfg(not(target_os = "macos"))]
    {
        io::Error::other(Escaped)
    }
}

/// Whether `e` is [`escape`]'s error.
pub(crate) fn is_escape(e: &io::Error) -> bool {
    #[cfg(target_os = "macos")]
    {
        e.raw_os_error() == Some(libc::ENOTCAPABLE)
    }
    #[cfg(not(target_os = "macos"))]
    {
        e.get_ref().is_some_and(|x| x.is::<Escaped>())
    }
}

/// [`escape`]'s error off macOS.
#[cfg(not(target_os = "macos"))]
#[derive(Debug)]
struct Escaped;

#[cfg(not(target_os = "macos"))]
impl std::fmt::Display for Escaped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(super::super::messages::NOT_CAPABLE)
    }
}

#[cfg(not(target_os = "macos"))]
impl std::error::Error for Escaped {}

/// `EACCES`, which Apple's `open_outfile()` makes of `ENOTCAPABLE` (and the
/// Ubuntu flavour of every escape: deviation 3).
pub(crate) fn eacces() -> io::Error {
    #[cfg(unix)]
    {
        io::Error::from_raw_os_error(libc::EACCES)
    }
    #[cfg(not(unix))]
    {
        io::Error::from(io::ErrorKind::PermissionDenied)
    }
}

/// The components of a relative path, as the walk takes them.
fn components(rel: &[u8]) -> impl DoubleEndedIterator<Item = &[u8]> {
    rel.split(|&b| b == b'/')
}

/// A component that names its own directory (empty or `.`).
fn is_here(c: &[u8]) -> bool {
    c.is_empty() || c == b"."
}

#[cfg(not(unix))]
pub(crate) use imp_std::{Dir, Root};
#[cfg(unix)]
pub(crate) use imp_unix::{Dir, Root};

/// `open_beneath(root, rel, create)`: the file `rel` names beneath `root`,
/// its last component not followed: created (`O_CREAT | O_TRUNC | O_RDWR`,
/// mode 0666 less the umask) when `create`, else opened read-only.
pub(crate) fn open_beneath(root: &Root, rel: &[u8], create: bool) -> io::Result<File> {
    let (dir, name) = root.parent(rel)?;
    if create {
        dir.create_file(&name)
    } else {
        dir.open_file(&name)
    }
}

#[cfg(unix)]
mod imp_unix {
    use super::{MAXSYMLINKS, Stat, components, escape, is_here};
    use std::collections::VecDeque;
    use std::ffi::CString;
    use std::fs::File;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::path::Path;

    /// How a directory on the walk is opened: for searching only where the
    /// platform can (macOS `O_SEARCH`, as Apple's sites; Linux `O_PATH`),
    /// else for reading.
    #[cfg(target_os = "macos")]
    const DIR_FLAGS: libc::c_int = libc::O_SEARCH;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const DIR_FLAGS: libc::c_int = libc::O_PATH | libc::O_DIRECTORY;
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "android")))]
    const DIR_FLAGS: libc::c_int = libc::O_RDONLY | libc::O_DIRECTORY;

    fn cstr(b: &[u8]) -> io::Result<CString> {
        CString::new(b).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
    }

    fn check(rc: libc::c_int) -> io::Result<()> {
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// `openat(at, name, flags | O_CLOEXEC, mode)`, retried on `EINTR`.
    fn open_at(
        at: RawFd,
        name: &[u8],
        flags: libc::c_int,
        mode: libc::c_uint,
    ) -> io::Result<OwnedFd> {
        let c = cstr(name)?;
        loop {
            // SAFETY: `c` is NUL-terminated and lives across the call; `at`
            // is an open descriptor this module owns. The result is a new
            // descriptor nothing else owns.
            let fd = unsafe { libc::openat(at, c.as_ptr(), flags | libc::O_CLOEXEC, mode) };
            if fd >= 0 {
                // SAFETY: `fd` was just returned by `openat` and is owned
                // by nothing else.
                return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }

    /// `fstatat(at, name, &st, AT_SYMLINK_NOFOLLOW)`.
    fn lstat_at(at: RawFd, name: &[u8]) -> io::Result<Stat> {
        let c = cstr(name)?;
        // SAFETY: `st` is plain data the call fills in whole on success;
        // `c` is NUL-terminated; `at` is an open descriptor.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        check(unsafe { libc::fstatat(at, c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) })?;
        Ok(stat_of(&st))
    }

    // `st_mode`, `st_dev`, `st_ino` and `st_mtime`'s types differ by
    // platform.
    #[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
    fn stat_of(st: &libc::stat) -> Stat {
        Stat {
            mode: u32::from(st.st_mode),
            dev: st.st_dev as u64,
            ino: st.st_ino as u64,
            mtime: st.st_mtime as i64,
        }
    }

    /// `readlinkat(at, name)`: the whole target (bounded by the platform's
    /// `PATH_MAX`, as the kernel bounds it).
    fn readlink_at(at: RawFd, name: &[u8]) -> io::Result<Vec<u8>> {
        let c = cstr(name)?;
        let mut buf = vec![0u8; libc::PATH_MAX as usize + 1];
        // SAFETY: `buf` is valid for `buf.len()` bytes; `c` is
        // NUL-terminated; `at` is an open descriptor.
        let n = unsafe { libc::readlinkat(at, c.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        buf.truncate(n as usize);
        Ok(buf)
    }

    /// The extraction root: a descriptor of its directory (Apple's
    /// `G.rootdir`), from which every walk starts.
    pub(crate) struct Root {
        fd: OwnedFd,
    }

    /// A directory reached beneath the root, by descriptor.
    pub(crate) struct Dir {
        fd: OwnedFd,
    }

    impl Root {
        /// `open(path, O_DIRECTORY | O_SEARCH)`: the root itself is reached
        /// as the reference reaches it (following symlinks).
        pub(crate) fn open(path: &Path) -> io::Result<Root> {
            use std::os::unix::ffi::OsStrExt;
            let fd = open_at(libc::AT_FDCWD, path.as_os_str().as_bytes(), DIR_FLAGS, 0)?;
            Ok(Root { fd })
        }

        /// The root's own directory.
        pub(crate) fn top(&self) -> io::Result<Dir> {
            Ok(Dir {
                fd: self.fd.try_clone()?,
            })
        }

        /// The directory `rel` names, every component resolved beneath the
        /// root (symlinks followed while they stay beneath it).
        pub(crate) fn dir(&self, rel: &[u8]) -> io::Result<Dir> {
            self.resolve(components(rel).map(<[u8]>::to_vec).collect())
        }

        /// The directory holding `rel`'s last component, and that
        /// component as it is (`..` too: `mkdirat(dir, "..")` is the C's
        /// `EEXIST`; every `Dir` operation that would change it refuses it).
        /// An empty last component (a trailing `/`) is `.`.
        pub(crate) fn parent(&self, rel: &[u8]) -> io::Result<(Dir, Vec<u8>)> {
            let mut comps: VecDeque<Vec<u8>> = components(rel).map(<[u8]>::to_vec).collect();
            let last = comps.pop_back().unwrap_or_default();
            let last = if last.is_empty() { b".".to_vec() } else { last };
            Ok((self.resolve(comps)?, last))
        }

        /// `fstatat(rootdir, rel, AT_RESOLVE_BENEATH | AT_SYMLINK_NOFOLLOW)`
        /// (a last `.` or `..` resolved beneath the root).
        pub(crate) fn lstat(&self, rel: &[u8]) -> io::Result<Stat> {
            let (d, name) = self.parent(rel)?;
            if is_here(&name) || name == b".." {
                return self.dir(rel)?.stat_self();
            }
            d.lstat(&name)
        }

        /// `fstatat(rootdir, rel, AT_RESOLVE_BENEATH)`: the last component
        /// followed too, beneath the root.
        pub(crate) fn stat(&self, rel: &[u8]) -> io::Result<Stat> {
            let (d, name) = self.parent(rel)?;
            if is_here(&name) || name == b".." {
                return self.dir(rel)?.stat_self();
            }
            match d.lstat(&name)? {
                st if st.is_symlink() => self.dir(rel)?.stat_self(),
                st => Ok(st),
            }
        }

        /// The walk: `comps` in order from the root; a symlink's relative
        /// target is spliced in where it stood.
        fn resolve(&self, mut q: VecDeque<Vec<u8>>) -> io::Result<Dir> {
            // The real directories resolved so far, from the root.
            let mut names: Vec<Vec<u8>> = Vec::new();
            let mut cur = self.fd.try_clone()?;
            let mut links = 0u32;
            while let Some(c) = q.pop_front() {
                if is_here(&c) {
                    continue;
                }
                if c == b".." {
                    if names.pop().is_none() {
                        return Err(escape());
                    }
                    cur = self.rewalk(&names)?;
                    continue;
                }
                match open_at(cur.as_raw_fd(), &c, DIR_FLAGS | libc::O_NOFOLLOW, 0) {
                    Ok(fd) => {
                        cur = fd;
                        names.push(c);
                    }
                    Err(e) => match lstat_at(cur.as_raw_fd(), &c) {
                        Ok(st) if st.is_symlink() => {
                            links += 1;
                            if links > MAXSYMLINKS {
                                return Err(io::Error::from_raw_os_error(libc::ELOOP));
                            }
                            let target = readlink_at(cur.as_raw_fd(), &c)?;
                            if target.first() == Some(&b'/') {
                                return Err(escape());
                            }
                            if target.is_empty() {
                                return Err(io::Error::from_raw_os_error(libc::ENOENT));
                            }
                            for t in components(&target).rev() {
                                q.push_front(t.to_vec());
                            }
                        }
                        Ok(_) if e.raw_os_error() == Some(libc::ELOOP) => {
                            // Not a symlink after all: it changed under us.
                            return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
                        }
                        _ => return Err(e),
                    },
                }
            }
            Ok(Dir { fd: cur })
        }

        /// The real directories `names` from the root again (after a `..`),
        /// none of them followed.
        fn rewalk(&self, names: &[Vec<u8>]) -> io::Result<OwnedFd> {
            let mut cur = self.fd.try_clone()?;
            for n in names {
                cur = open_at(cur.as_raw_fd(), n, DIR_FLAGS | libc::O_NOFOLLOW, 0)?;
            }
            Ok(cur)
        }
    }

    /// A name an operation that changes it refuses: `..` (which may be
    /// above the root) and `.` (the directory itself).
    fn changing(name: &[u8]) -> io::Result<()> {
        if name == b".." || is_here(name) {
            Err(escape())
        } else {
            Ok(())
        }
    }

    impl Dir {
        /// `fstatat(dir, name, AT_SYMLINK_NOFOLLOW)`.
        pub(crate) fn lstat(&self, name: &[u8]) -> io::Result<Stat> {
            lstat_at(self.fd.as_raw_fd(), name)
        }

        /// `fstat()` of the directory itself.
        pub(crate) fn stat_self(&self) -> io::Result<Stat> {
            // SAFETY: `st` is plain data filled in whole on success; the
            // descriptor is open.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            check(unsafe { libc::fstat(self.fd.as_raw_fd(), &mut st) })?;
            Ok(stat_of(&st))
        }

        /// `openat(dir, name, O_CREAT | O_TRUNC | O_RDWR | O_NOFOLLOW,
        /// 0666)`: apple: fileio.c:559.
        pub(crate) fn create_file(&self, name: &[u8]) -> io::Result<File> {
            changing(name)?;
            let fd = open_at(
                self.fd.as_raw_fd(),
                name,
                libc::O_CREAT | libc::O_TRUNC | libc::O_RDWR | libc::O_NOFOLLOW,
                0o666,
            )?;
            Ok(File::from(fd))
        }

        /// `openat(dir, name, O_RDONLY | O_NOFOLLOW)`: apple:
        /// extract.c:2595.
        pub(crate) fn open_file(&self, name: &[u8]) -> io::Result<File> {
            changing(name)?;
            let fd = open_at(
                self.fd.as_raw_fd(),
                name,
                libc::O_RDONLY | libc::O_NOFOLLOW,
                0,
            )?;
            Ok(File::from(fd))
        }

        /// `mkdirat(dir, name, mode)`.
        pub(crate) fn mkdir(&self, name: &[u8], mode: u32) -> io::Result<()> {
            let c = cstr(name)?;
            // SAFETY: `c` is NUL-terminated; the descriptor is open.
            check(unsafe { libc::mkdirat(self.fd.as_raw_fd(), c.as_ptr(), mode as libc::mode_t) })
        }

        /// `unlinkat(dir, name, dir ? AT_REMOVEDIR : 0)`.
        pub(crate) fn unlink(&self, name: &[u8], dir: bool) -> io::Result<()> {
            changing(name)?;
            let c = cstr(name)?;
            let flag = if dir { libc::AT_REMOVEDIR } else { 0 };
            // SAFETY: `c` is NUL-terminated; the descriptor is open.
            check(unsafe { libc::unlinkat(self.fd.as_raw_fd(), c.as_ptr(), flag) })
        }

        /// `renameat(dir, from, to_dir, to)`.
        pub(crate) fn rename_to(&self, from: &[u8], to_dir: &Dir, to: &[u8]) -> io::Result<()> {
            changing(from)?;
            changing(to)?;
            let (a, b) = (cstr(from)?, cstr(to)?);
            // SAFETY: both strings are NUL-terminated; both descriptors are
            // open.
            check(unsafe {
                libc::renameat(
                    self.fd.as_raw_fd(),
                    a.as_ptr(),
                    to_dir.fd.as_raw_fd(),
                    b.as_ptr(),
                )
            })
        }

        /// The same directory, by another descriptor.
        pub(crate) fn reopen(&self) -> io::Result<Dir> {
            Ok(Dir {
                fd: self.fd.try_clone()?,
            })
        }

        /// `symlinkat(target, dir, name)`.
        pub(crate) fn symlink(&self, target: &[u8], name: &[u8]) -> io::Result<()> {
            changing(name)?;
            let (t, c) = (cstr(target)?, cstr(name)?);
            // SAFETY: both strings are NUL-terminated; the descriptor is
            // open.
            check(unsafe { libc::symlinkat(t.as_ptr(), self.fd.as_raw_fd(), c.as_ptr()) })
        }

        /// `fchmodat(dir, name, mode, AT_SYMLINK_NOFOLLOW)`: `lchmod()`.
        pub(crate) fn lchmod(&self, name: &[u8], mode: u32) -> io::Result<()> {
            changing(name)?;
            let c = cstr(name)?;
            // SAFETY: `c` is NUL-terminated; the descriptor is open.
            check(unsafe {
                libc::fchmodat(
                    self.fd.as_raw_fd(),
                    c.as_ptr(),
                    mode as libc::mode_t,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            })
        }

        /// `fchownat(dir, name, uid, gid, AT_SYMLINK_NOFOLLOW)`: `lchown()`.
        pub(crate) fn lchown(&self, name: &[u8], uid: u32, gid: u32) -> io::Result<()> {
            changing(name)?;
            let c = cstr(name)?;
            // SAFETY: `c` is NUL-terminated; the descriptor is open.
            check(unsafe {
                libc::fchownat(
                    self.fd.as_raw_fd(),
                    c.as_ptr(),
                    uid as libc::uid_t,
                    gid as libc::gid_t,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            })
        }

        /// A descriptor of the directory itself that `fchmod()`,
        /// `fchown()`, `futimens()` and `fsetxattr()` accept (Linux's
        /// `O_PATH` descriptor does not: there `.` is reopened for reading).
        pub(crate) fn attr_file(&self) -> io::Result<File> {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            {
                let fd = open_at(
                    self.fd.as_raw_fd(),
                    b".",
                    libc::O_RDONLY | libc::O_DIRECTORY,
                    0,
                )?;
                Ok(File::from(fd))
            }
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            {
                Ok(File::from(self.fd.try_clone()?))
            }
        }

        /// The symlink `name` itself, opened for its attributes (macOS's
        /// `O_SYMLINK`: apple: extract.c:2633).
        #[cfg(target_os = "macos")]
        pub(crate) fn open_symlink(&self, name: &[u8]) -> io::Result<File> {
            changing(name)?;
            let fd = open_at(
                self.fd.as_raw_fd(),
                name,
                libc::O_RDONLY | libc::O_SYMLINK,
                0,
            )?;
            Ok(File::from(fd))
        }
    }
}

#[cfg(not(unix))]
mod imp_std {
    use super::{Stat, components, escape, is_here};
    use std::fs::{self, File};
    use std::io;
    use std::path::{Path, PathBuf};

    fn os(b: &[u8]) -> PathBuf {
        PathBuf::from(String::from_utf8_lossy(b).into_owned())
    }

    fn stat_of(m: &fs::Metadata) -> Stat {
        let t = m.file_type();
        let kind = if t.is_symlink() {
            super::S_IFLNK
        } else if t.is_dir() {
            super::S_IFDIR
        } else {
            super::S_IFREG
        };
        let perm = if m.permissions().readonly() {
            0o444
        } else {
            0o666
        };
        let mtime = m
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs() as i64);
        Stat {
            mode: kind | perm,
            dev: 0,
            ino: 0,
            mtime,
        }
    }

    /// The extraction root, by path.
    pub(crate) struct Root {
        dir: PathBuf,
    }

    /// A directory beneath the root, by path.
    pub(crate) struct Dir {
        dir: PathBuf,
    }

    impl Root {
        pub(crate) fn open(path: &Path) -> io::Result<Root> {
            if fs::metadata(path)?.is_dir() {
                Ok(Root {
                    dir: path.to_path_buf(),
                })
            } else {
                Err(io::Error::from(io::ErrorKind::NotADirectory))
            }
        }

        pub(crate) fn top(&self) -> io::Result<Dir> {
            Ok(Dir {
                dir: self.dir.clone(),
            })
        }

        pub(crate) fn dir(&self, rel: &[u8]) -> io::Result<Dir> {
            let mut depth = 0usize;
            let mut p = self.dir.clone();
            for c in components(rel) {
                if is_here(c) {
                    continue;
                }
                if c == b".." {
                    if depth == 0 {
                        return Err(escape());
                    }
                    depth -= 1;
                    p.pop();
                } else {
                    depth += 1;
                    p.push(os(c));
                }
            }
            Ok(Dir { dir: p })
        }

        pub(crate) fn parent(&self, rel: &[u8]) -> io::Result<(Dir, Vec<u8>)> {
            let (dir, last) = match rel.iter().rposition(|&b| b == b'/') {
                Some(i) => (self.dir(&rel[..i])?, &rel[i + 1..]),
                None => (self.top()?, rel),
            };
            let last = if last.is_empty() { &b"."[..] } else { last };
            Ok((dir, last.to_vec()))
        }

        pub(crate) fn lstat(&self, rel: &[u8]) -> io::Result<Stat> {
            let (d, name) = self.parent(rel)?;
            if is_here(&name) || name == b".." {
                return self.dir(rel)?.stat_self();
            }
            d.lstat(&name)
        }

        pub(crate) fn stat(&self, rel: &[u8]) -> io::Result<Stat> {
            let (d, name) = self.parent(rel)?;
            if is_here(&name) || name == b".." {
                return self.dir(rel)?.stat_self();
            }
            Ok(stat_of(&fs::metadata(d.dir.join(os(&name)))?))
        }
    }

    impl Dir {
        fn at(&self, name: &[u8]) -> PathBuf {
            self.dir.join(os(name))
        }

        pub(crate) fn lstat(&self, name: &[u8]) -> io::Result<Stat> {
            Ok(stat_of(&fs::symlink_metadata(self.at(name))?))
        }

        pub(crate) fn stat_self(&self) -> io::Result<Stat> {
            Ok(stat_of(&fs::metadata(&self.dir)?))
        }

        pub(crate) fn create_file(&self, name: &[u8]) -> io::Result<File> {
            File::options()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(self.at(name))
        }

        pub(crate) fn open_file(&self, name: &[u8]) -> io::Result<File> {
            File::open(self.at(name))
        }

        pub(crate) fn mkdir(&self, name: &[u8], _mode: u32) -> io::Result<()> {
            fs::create_dir(self.at(name))
        }

        pub(crate) fn unlink(&self, name: &[u8], dir: bool) -> io::Result<()> {
            if dir {
                fs::remove_dir(self.at(name))
            } else {
                fs::remove_file(self.at(name))
            }
        }

        pub(crate) fn rename_to(&self, from: &[u8], to_dir: &Dir, to: &[u8]) -> io::Result<()> {
            fs::rename(self.at(from), to_dir.at(to))
        }

        pub(crate) fn reopen(&self) -> io::Result<Dir> {
            Ok(Dir {
                dir: self.dir.clone(),
            })
        }

        pub(crate) fn symlink(&self, _target: &[u8], _name: &[u8]) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }

        pub(crate) fn lchmod(&self, _name: &[u8], _mode: u32) -> io::Result<()> {
            Ok(())
        }

        pub(crate) fn lchown(&self, _name: &[u8], _uid: u32, _gid: u32) -> io::Result<()> {
            Ok(())
        }

        pub(crate) fn attr_file(&self) -> io::Result<File> {
            File::open(&self.dir)
        }
    }
}

#[cfg(all(test, unix))]
mod tests;
