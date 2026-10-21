//! `zipinfo.c`'s `zi_short()`: the one-line formats `-s` (the default),
//! `-m` (with the ratio) and `-l` (with the compressed size).

use super::super::fileio;
use super::super::list::{find_compr_idx, ratio};
use super::super::messages as m;
use super::super::process::CentralEntry;
use super::super::{PK_COOL, Uz};
use super::{
    ACORN_, AMIGA_, Clock, DEFLATED, ENHDEFLATED, FS_FAT_, FS_HPFS_, FS_NTFS_, IMPLODED, MVS_,
    NUM_METHODS, THEOS_, UNIX_, VM_CMS_, VMS_, zi_time, zu_w,
};

/// Unix mode bits zi_short() reads (zipinfo.c's `UNX_*`).
pub(super) const UNX_IFMT: u32 = 0o170000;
pub(super) const UNX_IFREG: u32 = 0o100000;
pub(super) const UNX_IFSOCK: u32 = 0o140000;
pub(super) const UNX_IFLNK: u32 = 0o120000;
pub(super) const UNX_IFBLK: u32 = 0o060000;
pub(super) const UNX_IFDIR: u32 = 0o040000;
pub(super) const UNX_IFCHR: u32 = 0o020000;
pub(super) const UNX_IFIFO: u32 = 0o010000;
pub(super) const UNX_ISUID: u32 = 0o4000;
pub(super) const UNX_ISGID: u32 = 0o2000;
pub(super) const UNX_ISVTX: u32 = 0o1000;
pub(super) const UNX_IRUSR: u32 = 0o400;
pub(super) const UNX_IWUSR: u32 = 0o200;
pub(super) const UNX_IXUSR: u32 = 0o100;
pub(super) const UNX_IRGRP: u32 = 0o040;
pub(super) const UNX_IWGRP: u32 = 0o020;
pub(super) const UNX_IXGRP: u32 = 0o010;
pub(super) const UNX_IROTH: u32 = 0o004;
pub(super) const UNX_IWOTH: u32 = 0o002;
pub(super) const UNX_IXOTH: u32 = 0o001;

/// Amiga protection bits (zipinfo.c's `AMI_*`).
pub(super) const AMI_IFMT: u32 = 0o6000;
pub(super) const AMI_IFDIR: u32 = 0o4000;
pub(super) const AMI_IFREG: u32 = 0o2000;
pub(super) const AMI_IHIDDEN: u32 = 0o0200;
pub(super) const AMI_ISCRIPT: u32 = 0o0100;
pub(super) const AMI_IPURE: u32 = 0o0040;
pub(super) const AMI_IARCHIVE: u32 = 0o0020;
pub(super) const AMI_IREAD: u32 = 0o0010;
pub(super) const AMI_IWRITE: u32 = 0o0004;
pub(super) const AMI_IEXECUTE: u32 = 0o0002;
pub(super) const AMI_IDELETE: u32 = 0o0001;

/// Theos bits (zipinfo.c's `THS_*`).
pub(super) const THS_IFMT: u32 = 0xF000;
pub(super) const THS_IFCHR: u32 = 0x2000;
pub(super) const THS_IFDIR: u32 = 0x4000;
pub(super) const THS_IFLIB: u32 = 0x5000;
pub(super) const THS_IFREG: u32 = 0x8000;
pub(super) const THS_IFREL: u32 = 0x9000;
pub(super) const THS_IFKEY: u32 = 0xA000;
pub(super) const THS_IFIND: u32 = 0xB000;
pub(super) const THS_IFR16: u32 = 0xD000;
pub(super) const THS_IFP16: u32 = 0xE000;
pub(super) const THS_IFP32: u32 = 0xF000;
pub(super) const THS_IMODF: u32 = 0x0800;
pub(super) const THS_INHID: u32 = 0x0400;
pub(super) const THS_IEUSR: u32 = 0x0200;
pub(super) const THS_IRUSR: u32 = 0x0100;
pub(super) const THS_IWUSR: u32 = 0x0080;
pub(super) const THS_IXUSR: u32 = 0x0040;
pub(super) const THS_IROTH: u32 = 0x0004;
pub(super) const THS_IWOTH: u32 = 0x0002;

/// A C `char` array as `sprintf()` leaves it: `sprintf_at` writes a string
/// and its NUL at an offset, and [`Attribs::text`] is the C string (up to
/// the first NUL).
/// ruling: zi_short()'s `attribs[16]` is too short for the `"%u.%u"` of a
/// version byte of 100 or more written at offset 12 (VMS, Amiga, Theos) or
/// after the 12-byte MS-DOS template (`".r.-...     "`): `sprintf` writes
/// one byte past the array (undefined behaviour; patch 08, which Apple's
/// tree carries too, fixes only the Unix branch). Here the buffer grows,
/// so the line shows the whole version (`-rw-a--     25.5 fat`), as a
/// buffer large enough would.
pub(super) struct Attribs(Vec<u8>);

impl Attribs {
    /// `n` bytes of `fill`, then a NUL.
    pub(super) fn new(n: usize, fill: u8) -> Attribs {
        let mut v = vec![fill; n];
        v.push(0);
        Attribs(v)
    }

    /// `attribs[i] = c`.
    pub(super) fn set(&mut self, i: usize, c: u8) {
        if self.0.len() <= i {
            self.0.resize(i + 1, 0);
        }
        self.0[i] = c;
    }

    /// `sprintf(&attribs[at], "%s", s)`: `s` and its NUL.
    pub(super) fn sprintf_at(&mut self, at: usize, s: &[u8]) {
        if self.0.len() < at + s.len() + 1 {
            self.0.resize(at + s.len() + 1, 0);
        }
        self.0[at..at + s.len()].copy_from_slice(s);
        self.0[at + s.len()] = 0;
    }

    /// The C string.
    pub(super) fn text(&self) -> &[u8] {
        fileio::c_str(&self.0)
    }
}

/// `"%u.%u"` of a version byte.
pub(super) fn version(hostver: u8) -> Vec<u8> {
    format!("{}.{}", hostver / 10, hostver % 10).into_bytes()
}

/// zi_short()'s and zi_long()'s Unix-like `rwx` letters (the type letter
/// at 0, then nine permission letters); `sgid_x` is the set-group-id
/// letter without group execute (`S` here, `l` in zi_long()).
pub(super) fn unix_letters(attribs: &mut Attribs, xattr: u32, sgid_x: u8) {
    attribs.set(
        0,
        match xattr & UNX_IFMT {
            UNX_IFDIR => b'd',
            UNX_IFREG => b'-',
            UNX_IFLNK => b'l',
            UNX_IFBLK => b'b',
            UNX_IFCHR => b'c',
            UNX_IFIFO => b'p',
            UNX_IFSOCK => b's',
            _ => b'?',
        },
    );
    let bit = |b: u32, c: u8| if xattr & b != 0 { c } else { b'-' };
    attribs.set(1, bit(UNX_IRUSR, b'r'));
    attribs.set(4, bit(UNX_IRGRP, b'r'));
    attribs.set(7, bit(UNX_IROTH, b'r'));
    attribs.set(2, bit(UNX_IWUSR, b'w'));
    attribs.set(5, bit(UNX_IWGRP, b'w'));
    attribs.set(8, bit(UNX_IWOTH, b'w'));
    let pick =
        |x: u32, s: u32, both: u8, xonly: u8, sonly: u8| match (xattr & x != 0, xattr & s != 0) {
            (true, true) => both,
            (true, false) => xonly,
            (false, true) => sonly,
            (false, false) => b'-',
        };
    attribs.set(3, pick(UNX_IXUSR, UNX_ISUID, b's', b'x', b'S')); // S = undefined
    attribs.set(6, pick(UNX_IXGRP, UNX_ISGID, b's', b'x', sgid_x)); // == UNX_ENFMT
    attribs.set(9, pick(UNX_IXOTH, UNX_ISVTX, b't', b'x', b'T')); // T = undefined
}

/// The VMS permission letters by group (system, owner, group, world in the
/// C's `workspace[12]`: three groups of R, W, E, D).
pub(super) fn vms_workspace(xattr: u32) -> [u8; 12] {
    let mut w = [0u8; 12];
    if xattr & UNX_IRUSR != 0 {
        w[0] = b'R';
    }
    if xattr & UNX_IWUSR != 0 {
        w[1] = b'W';
        w[3] = b'D';
    }
    if xattr & UNX_IXUSR != 0 {
        w[2] = b'E';
    }
    if xattr & UNX_IRGRP != 0 {
        w[4] = b'R';
    }
    if xattr & UNX_IWGRP != 0 {
        w[5] = b'W';
        w[7] = b'D';
    }
    if xattr & UNX_IXGRP != 0 {
        w[6] = b'E';
    }
    if xattr & UNX_IROTH != 0 {
        w[8] = b'R';
    }
    if xattr & UNX_IWOTH != 0 {
        w[9] = b'W';
        w[11] = b'D';
    }
    if xattr & UNX_IXOTH != 0 {
        w[10] = b'E';
    }
    w
}

/// The Amiga letters `attribs[0..9]`.
pub(super) fn amiga_letters(attribs: &mut Attribs, xattr: u32) {
    attribs.set(
        0,
        match xattr & AMI_IFMT {
            AMI_IFDIR => b'd',
            AMI_IFREG => b'-',
            _ => b'?',
        },
    );
    let bit = |b: u32, c: u8| if xattr & b != 0 { c } else { b'-' };
    attribs.set(1, bit(AMI_IHIDDEN, b'h'));
    attribs.set(2, bit(AMI_ISCRIPT, b's'));
    attribs.set(3, bit(AMI_IPURE, b'p'));
    attribs.set(4, bit(AMI_IARCHIVE, b'a'));
    attribs.set(5, bit(AMI_IREAD, b'r'));
    attribs.set(6, bit(AMI_IWRITE, b'w'));
    attribs.set(7, bit(AMI_IEXECUTE, b'e'));
    attribs.set(8, bit(AMI_IDELETE, b'd'));
}

/// The Theos permission letters, `attribs[at..at + 8]` (a bit set shows
/// `.`, clear its letter).
pub(super) fn theos_letters(attribs: &mut Attribs, xattr: u32, at: usize) {
    let bit = |b: u32, c: u8| if xattr & b != 0 { b'.' } else { c };
    attribs.set(at, bit(THS_INHID, b'H'));
    attribs.set(at + 1, bit(THS_IMODF, b'M'));
    attribs.set(at + 2, bit(THS_IWOTH, b'W'));
    attribs.set(at + 3, bit(THS_IROTH, b'R'));
    attribs.set(at + 4, bit(THS_IEUSR, b'E'));
    attribs.set(at + 5, bit(THS_IXUSR, b'X'));
    attribs.set(at + 6, bit(THS_IWUSR, b'W'));
    attribs.set(at + 7, bit(THS_IRUSR, b'R'));
}

// port: zipinfo.c:zi_short
/// One entry's line in `-s`, `-m` or `-l` format: its attributes and
/// version, host, size, text/binary and encryption mark, extra-field and
/// data-descriptor mark, ratio (`-m`) or compressed size (`-l`), method,
/// time and name. The comment is skipped.
pub(super) fn zi_short(uz: &mut Uz, e: &CentralEntry) -> i32 {
    let error_in_archive = PK_COOL;

    // Print out various interesting things about the compressed file.
    let methid = e.compression_method;
    let methnum = find_compr_idx(e.compression_method);
    let hostnum = e.pinfo.hostnum;
    let hostver = e.pinfo.hostver;

    let mut methbuf = m::ZI_SHORT_METHODS[methnum].as_bytes().to_vec();
    if methid == IMPLODED {
        methbuf[1] = if e.general_purpose_bit_flag & 2 != 0 {
            b'8'
        } else {
            b'4'
        };
        methbuf[3] = if e.general_purpose_bit_flag & 4 != 0 {
            b'3'
        } else {
            b'2'
        };
    } else if methid == DEFLATED || methid == ENHDEFLATED {
        let dnum = usize::from((e.general_purpose_bit_flag >> 1) & 3);
        methbuf[3] = m::DTYPE[dnum];
    } else if methnum >= NUM_METHODS {
        // unknown
        // ruling: `sprintf(&methbuf[1], "%03u")` of a method above 999
        // overflows `methbuf[5]` (undefined behaviour; Apple's build has
        // no fix). Both flavours print what Ubuntu's
        // 19-cve-2016-9844-zipinfo-buffer-overflow.patch prints: four
        // upper-case hex digits in place of `u###` (`03E8`).
        // ubuntu: 19-cve-2016-9844-zipinfo-buffer-overflow.patch
        methbuf = if e.compression_method <= 999 {
            format!("u{:03}", e.compression_method).into_bytes()
        } else {
            format!("{:04X}", e.compression_method).into_bytes()
        };
    }

    let mut attribs = Attribs::new(15, b' ');

    let ext = e.external_file_attributes;
    let mut xattr = ((ext >> 16) & 0xFFFF) as u32;
    match hostnum {
        VMS_ => {
            let workspace = vms_workspace(xattr);
            let mut p = 0usize;
            for group in workspace.chunks(4) {
                // groups of permissions
                for &c in group.iter().filter(|&&c| c != 0) {
                    // perms within a group
                    attribs.set(p, c);
                    p += 1;
                }
                attribs.set(p, b','); // group separator
                p += 1;
            }
            p -= 1;
            attribs.set(p, b' '); // overwrite last comma
            if p < 12 {
                attribs.sprintf_at(12, &version(hostver));
            }
        }
        AMIGA_ => {
            amiga_letters(&mut attribs, xattr);
            attribs.sprintf_at(12, &version(hostver));
        }
        THEOS_ => {
            attribs.set(
                0,
                match xattr & THS_IFMT {
                    THS_IFLIB => b'L',
                    THS_IFDIR => b'D',
                    THS_IFCHR => b'C',
                    THS_IFREG => b'S',
                    THS_IFREL => b'R',
                    THS_IFKEY => b'K',
                    THS_IFIND => b'I',
                    THS_IFR16 => b'P',
                    THS_IFP16 => b'2',
                    THS_IFP32 => b'3',
                    _ => b'?',
                },
            );
            theos_letters(&mut attribs, xattr, 1);
            attribs.sprintf_at(12, &version(hostver));
        }
        // FS_VFAT_ (OLD_THEOS_EXTRA is not built) falls through here.
        _ if matches!(
            hostnum,
            super::FS_VFAT_ | FS_FAT_ | FS_HPFS_ | FS_NTFS_ | VM_CMS_ | MVS_ | ACORN_
        ) && (hostnum != FS_FAT_
            || (xattr & 0o700)
                != (0o400 | (u32::from(ext & 1 == 0) << 7) | (((ext & 0x10) as u32) << 2))) =>
        {
            xattr = (ext & 0xFF) as u32;
            let mut t = m::ZI_SHORT_FAT_ATTRIBS.as_bytes().to_vec();
            t.extend_from_slice(&version(hostver));
            attribs.sprintf_at(0, &t);
            attribs.set(2, if xattr & 0x01 != 0 { b'-' } else { b'w' });
            attribs.set(5, if xattr & 0x02 != 0 { b'h' } else { b'-' });
            attribs.set(6, if xattr & 0x04 != 0 { b's' } else { b'-' });
            attribs.set(4, if xattr & 0x20 != 0 { b'a' } else { b'-' });
            if xattr & 0x10 != 0 {
                attribs.set(0, b'd');
                attribs.set(3, b'x');
            } else {
                attribs.set(0, b'-');
            }
            if xattr & 0x08 != 0 {
                // IS_VOLID
                attribs.set(0, b'V');
            } else if let Some(dot) = e.filename.iter().rposition(|&b| b == b'.') {
                let p = &e.filename[dot + 1..];
                if m::ZI_SHORT_EXE_EXTS
                    .iter()
                    .any(|x| p.len() >= 3 && p[..3].eq_ignore_ascii_case(x.as_bytes()))
                {
                    attribs.set(3, b'x');
                }
            }
        }
        _ => {
            // assume Unix-like
            // (attribs[6]: `l` in real 4.3BSD, `S` as SunOS 4.1.x)
            unix_letters(&mut attribs, xattr, b'S');
            // apple: zipinfo.c:2117 (`sprintf(&attribs[11], "%2u.%u", ...)`)
            // ubuntu: 08-allow-greater-hostver-values.patch (the same line)
            let v = format!("{:>2}.{}", hostver / 10, hostver % 10).into_bytes();
            attribs.sprintf_at(11, &v);
        }
    } // end switch (hostnum: external attributes format)

    let os = m::ZI_SHORT_OS[usize::from(hostnum)].as_bytes();
    let line = {
        let mut b = Vec::new();
        m::printf(
            &mut b,
            m::ZI_SHORT_HEAD,
            &[attribs.text(), os, &zu_w(e.ucsize, 8)],
        );
        b
    };
    uz.info(0, &line);
    let text = e.internal_file_attributes & 1 != 0;
    let mark = if e.general_purpose_bit_flag & 1 != 0 {
        if text { b'T' } else { b'B' } // encrypted
    } else if text {
        b't' // plaintext
    } else {
        b'b'
    };
    uz.info(0, &[mark]);
    // a local-only "UX" (old Unix/OS2/NT GMT times "IZUNIX") e.f.?
    let k = e.extra_field_length != 0
        || (ext & 0x8000 != 0 && matches!(hostnum, UNIX_ | FS_HPFS_ | FS_NTFS_));
    let descriptor = e.general_purpose_bit_flag & 8 != 0; // extended local header or not
    let mark = match (k, descriptor) {
        (true, true) => b'X', // extra field
        (true, false) => b'x',
        (false, true) => b'l', // no extra field
        (false, false) => b'-',
    };
    uz.info(0, &[mark]);

    if uz.o.lflag == 4 {
        let mut csiz = e.csize;
        if e.general_purpose_bit_flag & 1 != 0 {
            csiz = csiz.wrapping_sub(12); // if encrypted, don't count encryption header
        }
        // ruling: `ratio() + 5` overflows `int` for a ratio above INT_MAX -
        // 5 (undefined behaviour); here, unlike list.c's (P23), both
        // references' compilers know nothing of its sign and the sum wraps
        // (`-214748364%` for INT_MAX), and so it does here.
        // probe: zipinfo -m of 1000 bytes stored in 2^31 + 1000 + k, k in
        // 1..=5, on both references
        let pct = format!("{:>3}", ratio(e.ucsize, csiz).wrapping_add(5) / 10).into_bytes();
        uz.info_fmt(0, m::ZI_SHORT_PERCENT, &[&pct]);
    } else if uz.o.lflag == 5 {
        uz.info_fmt(0, m::ZI_SHORT_CSIZE, &[&zu_w(e.csize, 8)]);
    }

    // For printing of date & time, the C reuses `attribs` (16 bytes,
    // enough for every format here).
    let z_modtim = super::ut_mtime(uz.flavour, e);
    let time = zi_time(uz, e.last_mod_dos_datetime, z_modtim, Clock::Local);
    uz.info_fmt(0, m::ZI_SHORT_TAIL, &[&methbuf, &time]);
    fileio::fnprint(uz);

    // Skip the file comment, if any (the filename has already been
    // printed, above).  That finishes up this file entry...
    if e.file_comment_length != 0 {
        let error = fileio::do_string(
            uz,
            usize::from(e.file_comment_length),
            fileio::DoString::Skip,
            None,
        );
        if error > 1 {
            return error;
        }
    }
    error_in_archive
}
