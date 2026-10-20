//! `zipinfo.c`'s `zi_long()`: one entry's `-v` report.

use super::super::fileio::{self, DoString};
use super::super::list::find_compr_idx;
use super::super::messages as m;
use super::super::process::CentralEntry;
use super::super::{PK_COOL, PK_ERR, PK_WARN, Uz};
use super::short::{
    Attribs, THS_IFDIR, THS_IFIND, THS_IFKEY, THS_IFLIB, THS_IFMT, THS_IFP16, THS_IFP32, THS_IFR16,
    THS_IFREG, THS_IFREL, amiga_letters, theos_letters, unix_letters, vms_workspace,
};
use super::{
    ACORN_, AMIGA_, Clock, DEFLATED, ENHDEFLATED, FS_FAT_, FS_HPFS_, FS_NTFS_, FS_VFAT_, IMPLODED,
    MVS_, NUM_HOSTS, NUM_METHODS, THEOS_, UNIX_, VM_CMS_, VMS_, extra, next_endprev, ut_mtime,
    zi_time, zu, zx,
};

/// unzpriv.h's `EF_IZUNIX`, the id `lExtraFieldType` names.
const EF_IZUNIX: u16 = 0x5855;

/// `unknown (%d)`.
fn unknown(n: i64) -> Vec<u8> {
    let mut b = Vec::new();
    m::printf(&mut b, m::UNKNOWN_NO, &[n.to_string().as_bytes()]);
    b
}

// port: zipinfo.c:zi_long
/// One entry's `-v` report: the gap since the previous entry's data, the
/// name, offsets, origin and versions, method, flags, times, CRC, sizes,
/// lengths, attributes in the host's format and as MS-DOS's, the extra
/// field, the local-only `UX` field, and the comment. `p_endprev` is where
/// the previous entry's data ended (0: unknown). `error_in_archive` may
/// carry a delayed fatal error from reading the extra field, which ends
/// the report there. Returns the PK code.
pub(super) fn zi_long(
    uz: &mut Uz,
    e: &CentralEntry,
    p_endprev: &mut u64,
    error_in_archive: i32,
) -> i32 {
    let mut error_in_archive = error_in_archive;

    // Check whether there's any extra space inside the zipfile.  If
    // *pEndprev is zero, it's probably a signal that OS/2 extra fields are
    // involved (with unknown compressed size).  We won't worry about
    // prepended junk here...
    if e.relative_offset_local_header != *p_endprev && *p_endprev > 0 {
        let gap = e.relative_offset_local_header.wrapping_sub(*p_endprev) as i64;
        uz.info_fmt(0, m::EXTRA_BYTES_PRECEDING, &[gap.to_string().as_bytes()]);
    }

    // calculate endprev for next time around (problem:  extra fields may
    // differ in length between local and central-directory records)
    *p_endprev = next_endprev(e);

    // Print out various interesting things about the compressed file.
    let hostnum = e.pinfo.hostnum;
    let hostver = e.pinfo.hostver;
    let extnum = e.version_needed_to_extract[1].min(NUM_HOSTS);
    let extver = e.version_needed_to_extract[0];
    let methid = e.compression_method;
    let methnum = find_compr_idx(e.compression_method);

    uz.info(0, b"  ");
    fileio::fnprint(uz);

    let off = e.relative_offset_local_header;
    uz.info_fmt(0, m::LOCAL_HEADER_OFFSET, &[&zu(off), &zx(off)]);

    let varmsg = if hostnum >= NUM_HOSTS {
        unknown(i64::from(e.version_made_by[1]))
    } else {
        // ruling: `os[20..29]` are `NULL`, which the C passes to `%s`
        // (undefined in C; both references' libcs print `(null)`, and so
        // does this).
        // probe: zipinfo -v of an entry made by host 20
        m::OS_NAMES[usize::from(hostnum)]
            .unwrap_or(m::PRINTF_NULL)
            .as_bytes()
            .to_vec()
    };
    uz.info_fmt(0, m::HOST_OS, &[&varmsg]);
    let (a, b) = ((hostver / 10).to_string(), (hostver % 10).to_string());
    uz.info_fmt(0, m::ENCODE_SW_VER, &[a.as_bytes(), b.as_bytes()]);

    let varmsg = match m::OS_NAMES.get(usize::from(extnum)).copied().flatten() {
        Some(name) => name.as_bytes().to_vec(),
        None => unknown(i64::from(e.version_needed_to_extract[1])),
    };
    uz.info_fmt(0, m::MIN_OS_COMP_REQ, &[&varmsg]);
    let (a, b) = ((extver / 10).to_string(), (extver % 10).to_string());
    uz.info_fmt(0, m::MIN_SW_VER_REQ, &[a.as_bytes(), b.as_bytes()]);

    let varmsg = if methnum >= NUM_METHODS {
        unknown(i64::from(e.compression_method))
    } else {
        m::ZI_LONG_METHODS[methnum].as_bytes().to_vec()
    };
    uz.info_fmt(0, m::COMPRESS_METHOD, &[&varmsg]);
    let flag = e.general_purpose_bit_flag;
    if methid == IMPLODED {
        let w: &[u8] = if flag & 2 != 0 { b"8" } else { b"4" };
        uz.info_fmt(0, m::SLIDE_WINDOW_SIZE_IMPLODE, &[w]);
        let t: &[u8] = if flag & 4 != 0 { b"3" } else { b"2" };
        uz.info_fmt(0, m::SHANNON_FANO_TREES, &[t]);
    } else if methid == DEFLATED || methid == ENHDEFLATED {
        let dnum = usize::from((flag >> 1) & 3);
        uz.info_fmt(0, m::COMPRESS_SUBTYPE, &[m::DTYPELNG[dnum].as_bytes()]);
    }

    let not: &[u8] = if flag & 1 != 0 {
        b""
    } else {
        m::NOT_.as_bytes()
    };
    uz.info_fmt(0, m::FILE_SECURITY, &[not]);
    let yes = if flag & 8 != 0 { m::YES } else { m::NO };
    uz.info_fmt(0, m::EXTENDED_LOCAL_HDR, &[yes.as_bytes()]);
    // print upper 3 bits for amusement?

    let dos = e.last_mod_dos_datetime;
    let t = zi_time(uz, dos, None, Clock::Local);
    uz.info_fmt(0, m::FILE_MOD_DATE, &[&t]);
    if let Some(mtime) = ut_mtime(e) {
        // signal "show local time"
        let t = zi_time(uz, dos, Some(mtime), Clock::Local);
        uz.info_fmt(0, m::UT_FILE_MOD_DATE, &[&t, m::LOCAL_TIME.as_bytes()]);
        // signal "show UTC (GMT) time"
        let t = zi_time(uz, dos, Some(mtime), Clock::Utc);
        uz.info_fmt(0, m::UT_FILE_MOD_DATE, &[&t, m::GM_TIME.as_bytes()]);
    }

    let crc = format!("{:08x}", e.crc32).into_bytes();
    uz.info_fmt(0, m::CRC32_VALUE, &[&crc]);
    uz.info_fmt(0, m::COMPRESSED_FILE_SIZE, &[&zu(e.csize)]);
    uz.info_fmt(0, m::UNCOMPRESSED_FILE_SIZE, &[&zu(e.ucsize)]);
    uz.info_fmt(
        0,
        m::FILENAME_LENGTH,
        &[e.filename_length.to_string().as_bytes()],
    );
    uz.info_fmt(
        0,
        m::EXTRA_FIELD_LENGTH,
        &[e.extra_field_length.to_string().as_bytes()],
    );
    uz.info_fmt(
        0,
        m::FILE_COMMENT_LENGTH,
        &[e.file_comment_length.to_string().as_bytes()],
    );
    uz.info_fmt(
        0,
        m::FILE_DISK_NUM,
        &[&zu(e.disk_number_start.wrapping_add(1))],
    );
    let kind = if e.internal_file_attributes & 1 != 0 {
        m::TEXT
    } else if e.internal_file_attributes & 2 != 0 {
        m::EBCDIC
    } else {
        m::BINARY
    }; // changed to accept EBCDIC
    uz.info_fmt(0, m::APPARENT_FILE_TYPE, &[kind.as_bytes()]);

    let ext = e.external_file_attributes;
    let xattr = ((ext >> 16) & 0xFFFF) as u32;
    let octal = format!("{xattr:06o}").into_bytes();
    if hostnum == VMS_ {
        // "(" then the system's permissions, the owner's (the same), the
        // group's and the world's, each group's letters and a comma, the
        // last comma replaced by ")".
        let workspace = vms_workspace(xattr);
        let groups: Vec<Vec<u8>> = workspace
            .chunks(4)
            .map(|g| g.iter().copied().filter(|&c| c != 0).collect())
            .collect();
        let mut attribs = vec![b'('];
        for (j, g) in groups.iter().enumerate() {
            // loop over groups of permissions
            attribs.extend_from_slice(g);
            attribs.push(b','); // group separator
            if j == 0 {
                // system, owner perms are same
                attribs.extend_from_slice(g);
                attribs.push(b',');
            }
        }
        attribs.pop();
        attribs.push(b')'); // overwrite last comma
        uz.info_fmt(0, m::VMS_FILE_ATTRIBUTES, &[&octal, &attribs]);
    } else if hostnum == AMIGA_ {
        let mut attribs = Attribs::new(22, 0);
        amiga_letters(&mut attribs, xattr);
        attribs.set(9, 0); // better dlm the string
        uz.info_fmt(0, m::AMIGA_FILE_ATTRIBUTES, &[&octal, attribs.text()]);
    } else if hostnum == THEOS_ {
        let ftyp = match xattr & THS_IFMT {
            THS_IFLIB => m::THEOS_FTYP_LIB,
            THS_IFDIR => m::THEOS_FTYP_DIR,
            THS_IFREG => m::THEOS_FTYP_REG,
            THS_IFREL => m::THEOS_FTYP_REL,
            THS_IFKEY => m::THEOS_FTYP_KEY,
            THS_IFIND => m::THEOS_FTYP_IND,
            THS_IFR16 => m::THEOS_FTYP_R16,
            THS_IFP16 => m::THEOS_FTYP_P16,
            THS_IFP32 => m::THEOS_FTYP_P32,
            _ => m::THEOS_FTYP_UKN,
        };
        let mut attribs = Attribs::new(0, 0);
        attribs.sprintf_at(0, ftyp.as_bytes());
        theos_letters(&mut attribs, xattr, 12);
        attribs.set(20, 0);
        let hex = format!("{xattr:04X}").into_bytes();
        uz.info_fmt(0, m::THEOS_FILE_ATTRIBUTES, &[&hex, attribs.text()]);
    } else if !matches!(
        hostnum,
        FS_FAT_ | FS_HPFS_ | FS_NTFS_ | FS_VFAT_ | ACORN_ | VM_CMS_ | MVS_
    ) {
        // assume Unix-like
        let mut attribs = Attribs::new(22, 0);
        unix_letters(&mut attribs, xattr, b'l');
        attribs.set(10, 0);
        uz.info_fmt(0, m::UNIX_FILE_ATTRIBUTES, &[&octal, attribs.text()]);
    } else {
        let hex = format!("{:06X}", ext >> 8).into_bytes();
        uz.info_fmt(0, m::NON_MSDOS_FILE_ATTRIBUTES, &[&hex]);
    } // endif (hostnum: external attributes format)

    let xattr = (ext & 0xFF) as u32;
    let hex = format!("{xattr:02X}").into_bytes();
    if xattr == 0 {
        uz.info_fmt(0, m::MSDOS_FILE_ATTRIBUTES, &[&hex]);
    } else if xattr == 1 {
        uz.info_fmt(0, m::MSDOS_FILE_ATTRIBUTES_RO, &[&hex]);
    } else {
        let mut args: Vec<&[u8]> = vec![&hex];
        for (bit, word) in m::MSDOS_ATTR_WORDS.iter().enumerate() {
            args.push(if xattr & (1 << bit) != 0 {
                word.as_bytes()
            } else {
                b""
            });
        }
        uz.info_fmt(0, m::MSDOS_FILE_ATTRIBUTES_ALPHA, &args);
    }

    // Analyze the extra field, if any, and print the file comment, if any
    // (the filename has already been printed, above).  That finishes up
    // this file entry...
    if e.extra_field_length > 0 {
        if error_in_archive > PK_WARN {
            // fatal:  can't continue
            // delayed "fatal error" return from extra field reading
            return error_in_archive;
        }
        let Some(ef) = e.extra.as_deref() else {
            return PK_ERR; // not consistent with crec length
        };
        extra::dump(uz, ef, hostnum, off, p_endprev);
    }

    // high bit == Unix/OS2/NT GMT times (mtime, atime); next bit == UID/GID
    let xattr = ((ext & 0xC000) >> 12) as u32;
    if xattr & 8 != 0 {
        if matches!(hostnum, UNIX_ | FS_HPFS_ | FS_NTFS_) {
            let what = if xattr & 4 != 0 {
                m::EF_IZ_UID
            } else {
                m::EF_IZ_NOUID
            };
            uz.info_fmt(
                0,
                m::L_EXTRA_FIELD_TYPE,
                &[
                    m::IS.as_bytes(),
                    format!("{EF_IZUNIX:04x}").as_bytes(),
                    m::EF_IZUNIX_NAME.as_bytes(),
                    (xattr & 12).to_string().as_bytes(),
                    what.as_bytes(),
                ],
            );
            if *p_endprev > 0 {
                *p_endprev = p_endprev.wrapping_add(u64::from(xattr & 12));
            }
        } else if hostnum == FS_FAT_ && xattr & 4 == 0 {
            uz.info_fmt(
                0,
                m::L_EXTRA_FIELD_TYPE,
                &[
                    m::MAY_BE.as_bytes(),
                    format!("{EF_IZUNIX:04x}").as_bytes(),
                    m::EF_IZUNIX_NAME.as_bytes(),
                    b"8",
                    m::EF_IZ_NOUID.as_bytes(),
                ],
            );
        }
    }

    if e.file_comment_length == 0 {
        uz.info(0, m::NO_FILE_COMMENT.as_bytes());
    } else {
        uz.info(0, m::FILE_COMM_BEGIN.as_bytes());
        let pinfo = e.pinfo;
        let error = fileio::do_string(
            uz,
            usize::from(e.file_comment_length),
            DoString::Displ8,
            Some(&pinfo),
        );
        if error != PK_COOL {
            error_in_archive = error; // might be warning
            if error > PK_WARN {
                // fatal
                return error;
            }
        }
        uz.info(0, m::FILE_COMM_END.as_bytes());
    }

    error_in_archive
}
