//! zip's unix file attributes: `unix/unix.c`'s `filetime`, `set_extra_field`
//! and `set_new_unix_extra_field`, and `fileio.c`'s `unix2dostime`.
//!
//! [`UnixMeta`] is what one `stat` says of an input; [`extra_fields`]
//! builds the bytes Task 6 writes after each name (the `UT` and `ux`
//! blocks; the 16-bit `Ux` block only where a flavour writes it, which
//! neither does: ruling Z3). Sizes of `st_uid` and `st_gid` are 4 bytes on
//! every target this family runs on (macOS, Linux), as measured.

use std::fs::Metadata;

use super::flavour::{self, Flavour};
use super::{Zr, localtime};

/// `S_IFMT` and the file types, the values of every unix this family runs on.
pub(crate) const S_IFMT: u32 = 0o170000;
pub(crate) const S_IFDIR: u32 = 0o040000;
pub(crate) const S_IFREG: u32 = 0o100000;
pub(crate) const S_IFLNK: u32 = 0o120000;
pub(crate) const S_IFIFO: u32 = 0o010000;

/// The fields of a `stat` zip keeps for an input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UnixMeta {
    /// `st_mode`, type bits included.
    pub(crate) mode: u32,
    pub(crate) mtime: i64,
    pub(crate) atime: i64,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) size: u64,
}

impl UnixMeta {
    /// The file type bits of the mode.
    pub(crate) fn file_type(&self) -> u32 {
        self.mode & S_IFMT
    }
}

/// `st_mode`, times, owner and size of `md`. Off unix there are no such
/// fields: the mode follows the type, the owner is 0.
#[cfg(unix)]
pub(crate) fn meta_of(md: &Metadata) -> UnixMeta {
    use std::os::unix::fs::MetadataExt;
    UnixMeta {
        mode: md.mode(),
        mtime: md.mtime(),
        atime: md.atime(),
        uid: md.uid(),
        gid: md.gid(),
        size: md.len(),
    }
}

#[cfg(not(unix))]
pub(crate) fn meta_of(md: &Metadata) -> UnixMeta {
    let secs = |t: std::io::Result<std::time::SystemTime>| {
        t.ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs() as i64)
    };
    let ft = md.file_type();
    let kind = if ft.is_dir() {
        S_IFDIR | 0o755
    } else if ft.is_symlink() {
        S_IFLNK | 0o755
    } else {
        S_IFREG | 0o644
    };
    UnixMeta {
        mode: kind,
        mtime: secs(md.modified()),
        atime: secs(md.accessed()),
        uid: 0,
        gid: 0,
        size: md.len(),
    }
}

/// `fstat(0)` of standard input as `filetime("-")` sees it: a real
/// process's descriptor 0, or a sandbox's pipe (not a regular file, its
/// times now).
#[allow(clippy::useless_conversion)] // `time_t` is 32 bits on some unixes
pub(crate) fn stdin_meta(z: &Zr) -> Option<UnixMeta> {
    #[cfg(unix)]
    if matches!(z.host, super::Host::Real) {
        // SAFETY: `st` is plain data that a successful `fstat` fills in
        // whole; descriptor 0 is only inspected.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(0, &mut st) } != 0 {
            return None;
        }
        return Some(UnixMeta {
            mode: u32::from(st.st_mode),
            mtime: i64::from(st.st_mtime),
            atime: i64::from(st.st_atime),
            uid: st.st_uid,
            gid: st.st_gid,
            size: st.st_size as u64,
        });
    }
    let _ = z;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    Some(UnixMeta {
        // a pipe: S_IFIFO, 0600
        mode: S_IFIFO | 0o600,
        mtime: now,
        atime: now,
        uid: 0,
        gid: 0,
        size: 0,
    })
}

/// fileio.c:unix2dostime: the Unix time `t` as a DOS date and time,
/// rounded up to the next two-second boundary, in local time (a sandbox's
/// zone is UTC).
// port: fileio.c:unix2dostime
pub(crate) fn unix2dostime(z: &Zr, t: i64) -> u64 {
    // `(unsigned long)t + 1 & ~1`
    let even = ((t as u64).wrapping_add(1) & !1) as i64;
    let tm = localtime(&z.host, even);
    super::cli::dostime(
        tm.year,
        i64::from(tm.mon) + 1,
        i64::from(tm.mday),
        i64::from(tm.hour),
        i64::from(tm.min),
        i64::from(tm.sec),
    )
}

/// unix.c:set_extra_field and set_new_unix_extra_field: the extra field
/// blocks of an entry, local (`UT` with modification and access time, then
/// `ux` with the owner) or central (`UT` with the modification time only,
/// then the same `ux`). `Ux` (the old 16-bit owner block) follows `UT`
/// only where [`flavour::writes_ux_16bit`] says; neither build writes it.
/// The caller leaves all of this out under `-X`.
// port: unix/unix.c:set_extra_field
pub(crate) fn extra_fields(f: Flavour, meta: &UnixMeta, local: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    // UT: tag 0x5455, flags = mtime | atime (the central copy keeps the
    // flags and drops the access time)
    out.extend_from_slice(b"UT");
    out.extend_from_slice(&(if local { 9u16 } else { 5 }).to_le_bytes());
    out.push(3);
    out.extend_from_slice(&(meta.mtime as i32).to_le_bytes());
    if local {
        out.extend_from_slice(&(meta.atime as i32).to_le_bytes());
    }
    // Ux: tag 0x5855, only for a 16-bit st_uid and st_gid
    if flavour::writes_ux_16bit(f) {
        out.extend_from_slice(b"Ux");
        // the central copy has the header only
        out.extend_from_slice(&(if local { 4u16 } else { 0 }).to_le_bytes());
        if local {
            out.extend_from_slice(&(meta.uid as u16).to_le_bytes());
            out.extend_from_slice(&(meta.gid as u16).to_le_bytes());
        }
    }
    // ux: tag 0x7875, version 1, uid size, uid, gid size, gid (the same
    // 11 data bytes in both headers)
    out.extend_from_slice(b"ux");
    out.extend_from_slice(&11u16.to_le_bytes());
    out.push(1);
    out.push(4);
    out.extend_from_slice(&meta.uid.to_le_bytes());
    out.push(4);
    out.extend_from_slice(&meta.gid.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The record's standard tree as the user 501:20 owns it (Apple's
    /// run): mtime = atime = 1000000000.
    fn meta(uid: u32, gid: u32) -> UnixMeta {
        UnixMeta {
            mode: S_IFREG | 0o644,
            mtime: 1_000_000_000,
            atime: 1_000_000_000,
            uid,
            gid,
            size: 6,
        }
    }

    /// `xf.cases x_plain`: local `UT[9]=03 00ca9a3b 00ca9a3b`,
    /// `ux[11]=01 04 <uid32> 04 <gid32>`; the flavours write the same.
    #[test]
    fn the_local_blocks_are_the_recorded_bytes() {
        let want: Vec<u8> = [
            "55540900", "03", "00ca9a3b", "00ca9a3b", "75780b00", "01", "04", "f5010000", "04",
            "14000000",
        ]
        .iter()
        .flat_map(|h| unhex(h))
        .collect();
        for f in [Flavour::Apple, Flavour::Ubuntu] {
            assert_eq!(extra_fields(f, &meta(501, 20), true), want, "{f:?}");
        }
    }

    /// The central `UT[5]=03 00ca9a3b` (no access time) and the same `ux`.
    #[test]
    fn the_central_blocks_are_the_recorded_bytes() {
        let want: Vec<u8> = [
            "55540500", "03", "00ca9a3b", "75780b00", "01", "04", "92100000", "04", "92100000",
        ]
        .iter()
        .flat_map(|h| unhex(h))
        .collect();
        for f in [Flavour::Apple, Flavour::Ubuntu] {
            assert_eq!(extra_fields(f, &meta(0x1092, 0x1092), false), want, "{f:?}");
        }
    }

    /// Neither build writes the 16-bit `Ux` block (ruling Z3): no 0x5855
    /// tag anywhere in either, whatever the owner.
    #[test]
    fn no_flavour_writes_the_16_bit_block() {
        for f in [Flavour::Apple, Flavour::Ubuntu] {
            for local in [true, false] {
                let b = extra_fields(f, &meta(4242, 4242), local);
                assert!(!b.windows(2).any(|w| w == b"Ux"), "{f:?} {b:?}");
                assert_eq!(b.len(), if local { 13 + 15 } else { 9 + 15 });
            }
        }
    }

    /// The times are the low 32 bits, as the C's `(char)(t >> 24)` stores
    /// them.
    #[test]
    fn times_are_truncated_to_32_bits() {
        let mut m = meta(1, 1);
        m.mtime = 0x1_0000_0001;
        m.atime = -1;
        let b = extra_fields(Flavour::Apple, &m, true);
        assert_eq!(&b[5..9], &[1, 0, 0, 0]);
        assert_eq!(&b[9..13], &[0xff; 4]);
    }

    fn unhex(h: &str) -> Vec<u8> {
        (0..h.len() / 2)
            .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }
}
