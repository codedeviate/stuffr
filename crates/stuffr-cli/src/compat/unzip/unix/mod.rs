//! `unix/unix.c`: `do_wild()` (a wildcard archive name, expanded in its
//! directory) and `stamp_file()` (`-T`) here; the extraction's names and
//! paths (`mapname.rs`: `mapname()`, `checkdir()`), attributes
//! (`attrs.rs`: `mapattr()`, `close_outfile()`, `defer_dir_attribs()`,
//! `set_direc_attribs()`, `set_symlnk_attribs()`, Apple's quarantine) and
//! the resolve-beneath walk every one of them goes through (`beneath.rs`,
//! deviation 3).

use super::matching::{iswild, matches};
use super::{Uz, flavour};

pub(crate) mod attrs;
pub(crate) mod beneath;
pub(crate) mod charset;
pub(crate) mod mapname;

/// `do_wild()`'s state (`SYSTEM_SPECIFIC_GLOBALS`: `wild_dir`, `wildname`,
/// `dirname`, `matchname`, `notfirstcall`, `have_dirname`, `dirnamelen`).
pub(crate) struct Wild {
    notfirstcall: bool,
    wild_dir: Option<Dir>,
    wildname: Vec<u8>,
    dirname: Vec<u8>,
    have_dirname: bool,
}

impl Wild {
    pub(crate) fn new() -> Wild {
        Wild {
            notfirstcall: false,
            wild_dir: None,
            wildname: Vec::new(),
            dirname: Vec::new(),
            have_dirname: false,
        }
    }

    /// `matchname`: `wildspec` truncated as `strncpy(G.matchname, wildspec,
    /// FILNAMSIZ); G.matchname[FILNAMSIZ-1] = '\0'` leaves it.
    fn raw(uz: &Uz, wildspec: &[u8]) -> Vec<u8> {
        let n = uz.filename.len() - 1;
        wildspec[..wildspec.len().min(n)].to_vec()
    }

    /// `G.dirname` followed by `d_name`.
    /// ruling: the C copies both into `matchname[FILNAMSIZ]` with
    /// `strcpy`, which writes past it for a long directory part (undefined
    /// behaviour); the whole name is kept here.
    fn joined(&self, d_name: &[u8]) -> Vec<u8> {
        if self.have_dirname {
            [&self.dirname[..], d_name].concat()
        } else {
            d_name.to_vec()
        }
    }

    // port: unix.c:do_wild
    /// The next archive name `wildspec` stands for: itself when it is not
    /// a wildcard, else each directory entry its last component matches
    /// (case-sensitively; a leading `.` only by a pattern starting with
    /// one), or, when there is none, `wildspec` itself once. `None` when
    /// there are no more.
    pub(crate) fn do_wild(&mut self, uz: &Uz, wildspec: &[u8]) -> Option<Vec<u8>> {
        // ubuntu: -DWILD_STOP_AT_DIR (`WISEP`)
        let stop = flavour::wild_stop_at_dir(uz.flavour) && uz.o.w_flag;
        if !self.notfirstcall {
            // first call:  must initialize everything
            self.notfirstcall = true;

            if !iswild(wildspec) {
                self.have_dirname = false;
                self.wild_dir = None;
                return Some(Self::raw(uz, wildspec));
            }

            // break the wildspec into a directory part and a wildcard
            // filename
            match wildspec.iter().rposition(|&b| b == b'/') {
                None => {
                    self.dirname = b".".to_vec();
                    self.have_dirname = false;
                    self.wildname = wildspec.to_vec();
                }
                Some(i) => {
                    self.dirname = wildspec[..=i].to_vec();
                    self.wildname = wildspec[i + 1..].to_vec();
                    self.have_dirname = true;
                }
            }

            self.wild_dir = Dir::open(&uz.host.path(&self.dirname));
            if let Some(dir) = self.wild_dir.as_mut() {
                while let Some(name) = dir.next() {
                    if name.first() == Some(&b'.') && self.wildname.first() != Some(&b'.') {
                        continue; // Unix:  '*' and '?' do not match leading dot
                    }
                    // skip "." and ".." directory entries
                    if matches(&self.wildname, &name, false, stop) && name != b"." && name != b".."
                    {
                        return Some(self.joined(&name));
                    }
                }
                // if we get to here directory is exhausted, so close it
                self.wild_dir = None;
            }
            // return the raw wildspec in case that works (e.g., directory
            // not searchable, but filespec was not wild and file is
            // readable)
            return Some(Self::raw(uz, wildspec));
        }

        // last time through, might have failed opendir but returned raw
        // wildspec
        let Some(dir) = self.wild_dir.as_mut() else {
            self.notfirstcall = false; // nothing left--reset for new wildspec
            return None;
        };

        // If we've gotten this far, we've read and matched at least one
        // entry successfully (in a previous call).
        while let Some(name) = dir.next() {
            if name.first() == Some(&b'.') && self.wildname.first() != Some(&b'.') {
                continue; // Unix:  '*' and '?' do not match leading dot
            }
            if matches(&self.wildname, &name, false, stop) {
                return Some(self.joined(&name));
            }
        }
        // at least one entry read; nothing left
        self.wild_dir = None;
        self.notfirstcall = false; // reset for new wildspec
        None
    }
}

/// A directory being read, entry by entry, as `opendir()`/`readdir()`
/// return them (`.` and `..` included, in the file system's order).
#[cfg(unix)]
pub(crate) struct Dir(std::ptr::NonNull<libc::DIR>);

#[cfg(unix)]
impl Dir {
    /// `opendir(path)`.
    pub(crate) fn open(path: &std::path::Path) -> Option<Dir> {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
        // SAFETY: `c` is a NUL-terminated string that lives across the
        // call.
        let d = unsafe { libc::opendir(c.as_ptr()) };
        std::ptr::NonNull::new(d).map(Dir)
    }

    /// `readdir()`'s next name, `None` at the end (or on an error, as the
    /// C's loop takes either).
    pub(crate) fn next(&mut self) -> Option<Vec<u8>> {
        // SAFETY: the stream is open (closed only by `Drop`); `readdir`
        // returns null or an entry valid until the next call on this
        // stream, whose `d_name` is NUL-terminated; the name is copied out
        // before that.
        unsafe {
            let ent = libc::readdir(self.0.as_ptr());
            if ent.is_null() {
                return None;
            }
            let name = std::ffi::CStr::from_ptr((*ent).d_name.as_ptr());
            Some(name.to_bytes().to_vec())
        }
    }
}

#[cfg(unix)]
impl Drop for Dir {
    fn drop(&mut self) {
        // SAFETY: the stream was opened by `opendir` and is closed once.
        unsafe {
            libc::closedir(self.0.as_ptr());
        }
    }
}

/// Off unix (R8: built, not promised): `std::fs::read_dir`'s names,
/// without `.` and `..`.
#[cfg(not(unix))]
pub(crate) struct Dir(std::vec::IntoIter<Vec<u8>>);

#[cfg(not(unix))]
impl Dir {
    pub(crate) fn open(path: &std::path::Path) -> Option<Dir> {
        let names: Vec<Vec<u8>> = std::fs::read_dir(path)
            .ok()?
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().as_encoded_bytes().to_vec())
            .collect();
        Some(Dir(names.into_iter()))
    }

    pub(crate) fn next(&mut self) -> Option<Vec<u8>> {
        self.0.next()
    }
}

// port: unix.c:stamp_file
/// `utime(fname, {modtime, modtime})`: the archive's access and
/// modification times set to `modtime` (`-T`).
pub(crate) fn stamp_file(uz: &Uz, fname: &[u8], modtime: i64) -> std::io::Result<()> {
    let path = uz.host.path(fname);
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes())?;
        let tp = libc::utimbuf {
            actime: modtime as libc::time_t,
            modtime: modtime as libc::time_t,
        };
        // SAFETY: `c` is NUL-terminated and `tp` is a valid `utimbuf`; both
        // live across the call.
        let rc = unsafe { libc::utime(c.as_ptr(), &tp) };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
    #[cfg(not(unix))]
    {
        let t = if modtime >= 0 {
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(modtime as u64)
        } else {
            std::time::UNIX_EPOCH
        };
        let f = std::fs::OpenOptions::new().write(true).open(&path)?;
        f.set_times(std::fs::FileTimes::new().set_accessed(t).set_modified(t))
    }
}
