//! `zi_long()`'s analysis of the central extra field, block by block, and
//! `zi_showMacTypeCreator()`.
//!
//! Every read stays inside the block's data (`eb_datalen`, cut to what is
//! left of the field when a block claims more), as the C's do once each
//! block's length test has passed.

use super::super::Uz;
use super::super::fileio::{self, makelong, makeword};
use super::super::messages as m;
use super::UNIX_;

/// unzpriv.h's extra-field block ids.
const EF_PKSZ64: u16 = 0x0001;
const EF_AV: u16 = 0x0007;
const EF_OS2: u16 = 0x0009;
const EF_PKW32: u16 = 0x000a;
const EF_PKVMS: u16 = 0x000c;
const EF_PKUNIX: u16 = 0x000d;
const EF_IZVMS: u16 = 0x4d49;
const EF_IZUNIX: u16 = 0x5855;
const EF_IZUNIX2: u16 = 0x7855;
const EF_IZUNIX3: u16 = 0x7875;
const EF_TIME: u16 = 0x5455;
const EF_UNIPATH: u16 = 0x7075;
const EF_UNICOMNT: u16 = 0x6375;
const EF_MAC3: u16 = 0x334d;
const EF_JLMAC: u16 = 0x07c8;
const EF_ZIPIT: u16 = 0x2605;
const EF_ZIPIT2: u16 = 0x2705;
const EF_SMARTZIP: u16 = 0x4d63;
const EF_VMCMS: u16 = 0x4704;
const EF_MVS: u16 = 0x470f;
const EF_ACL: u16 = 0x4c41;
const EF_NTSD: u16 = 0x4453;
const EF_ATHEOS: u16 = 0x7441;
const EF_BEOS: u16 = 0x6542;
const EF_QDOS: u16 = 0xfb4a;
const EF_AOSVS: u16 = 0x5356;
const EF_SPARK: u16 = 0x4341;
const EF_TANDEM: u16 = 0x4154;
const EF_THEOS: u16 = 0x6854;
const EF_MD5: u16 = 0x4b46;
const EF_ASIUNIX: u16 = 0x756e;

/// unzpriv.h's extra-field layout constants zi_long() reads.
const EB_HEADSIZE: usize = 4;
const EB_FLGS_OFFS: usize = 4;
const EB_OS2_HLEN: usize = 4;
const EB_BEOS_HLEN: usize = 5;
const EB_BE_FL_UNCMPR: u8 = 0x01;
const EB_MAC3_HLEN: usize = 14;
const EB_SMARTZIP_HLEN: usize = 64;
const EB_M3_FL_DATFRK: u16 = 0x01;
const EB_M3_FL_UNCMPR: u16 = 0x04;
const EB_M3_FL_TIME64: u16 = 0x08;
const EB_NTSD_C_LEN: usize = 4;
const EB_IZVMS_HLEN: usize = 12;
const EB_IZVMS_FLGS: usize = 4;
const EB_IZVMS_UCSIZ: usize = 6;
const EB_IZVMS_BCMASK: u16 = 0o7;

/// zipinfo.c's `NSK_*` Tandem file codes.
const NSK_UNSTRUCTURED: u32 = 0;
const NSK_OBJECTFILECODE: u32 = 100;
const NSK_EDITFILECODE: u32 = 101;

/// The block's name (`ef_fieldname`).
fn field_name(eb_id: u16) -> &'static str {
    match eb_id {
        EF_PKSZ64 => m::EF_PKSZ64_NAME,
        EF_AV => m::EF_AV_NAME,
        EF_OS2 => m::EF_OS2_NAME,
        EF_ACL => m::EF_ACL_NAME,
        EF_NTSD => m::EF_NTSD_NAME,
        EF_PKVMS => m::EF_PKVMS_NAME,
        EF_IZVMS => m::EF_IZVMS_NAME,
        EF_PKW32 => m::EF_PKWIN32_NAME,
        EF_PKUNIX => m::EF_PKUNIX_NAME,
        EF_IZUNIX => m::EF_IZUNIX_NAME,
        EF_IZUNIX2 => m::EF_IZUNIX2_NAME,
        EF_IZUNIX3 => m::EF_IZUNIX3_NAME,
        EF_TIME => m::EF_TIME_NAME,
        EF_UNIPATH => m::EF_U8PATH_NAME,
        EF_UNICOMNT => m::EF_U8COMMNT_NAME,
        EF_MAC3 => m::EF_MAC3_NAME,
        EF_JLMAC => m::EF_JLMAC_NAME,
        EF_ZIPIT => m::EF_ZIPIT_NAME,
        EF_ZIPIT2 => m::EF_ZIPIT2_NAME,
        EF_VMCMS => m::EF_VMCMS_NAME,
        EF_MVS => m::EF_MVS_NAME,
        EF_ATHEOS => m::EF_ATHEOS_NAME,
        EF_BEOS => m::EF_BEOS_NAME,
        EF_QDOS => m::EF_QDOS_NAME,
        EF_AOSVS => m::EF_AOSVS_NAME,
        EF_SPARK => m::EF_SPARK_NAME, // from RISC OS
        EF_MD5 => m::EF_MD5_NAME,
        EF_ASIUNIX => m::EF_ASIUNIX_NAME,
        EF_TANDEM => m::EF_TANDEM_NAME,
        EF_SMARTZIP => m::EF_SMARTZIP_NAME,
        EF_THEOS => m::EF_THEOS_NAME,
        _ => m::EF_UNKNOWN_NAME,
    }
}

// port: zipinfo.c:zi_long
/// The central extra field `ef` of an entry made on `hostnum` whose local
/// header is at `rel_offset`: a line per block (id, name, length), what
/// the block says when zipinfo knows its layout, else its first bytes;
/// `p_endprev` gains what the local copy of a block adds (or becomes 0,
/// unknown).
pub(super) fn dump(uz: &mut Uz, ef: &[u8], hostnum: u8, rel_offset: u64, p_endprev: &mut u64) {
    let mut p = 0usize; // ef_ptr
    let mut ef_len = ef.len(); // a `ush`: the field is at most 64 KiB

    uz.info(0, m::EXTRA_FIELDS.as_bytes());

    while ef_len >= EB_HEADSIZE {
        let eb_id = makeword(&ef[p..]);
        let mut eb_datalen = usize::from(makeword(&ef[p + 2..]));
        p += EB_HEADSIZE;
        ef_len -= EB_HEADSIZE;

        if eb_datalen > ef_len {
            let args = [
                format!("{eb_id:04x}"),
                eb_datalen.to_string(),
                ef_len.to_string(),
            ];
            uz.info_fmt(
                0x421,
                m::EXTRA_FIELD_TRUNC,
                &[args[0].as_bytes(), args[1].as_bytes(), args[2].as_bytes()],
            );
            eb_datalen = ef_len;
        }
        let data = &ef[p..p + eb_datalen];

        // The C's name switch also adjusts `*pEndprev` for these.
        match eb_id {
            EF_PKSZ64 if rel_offset & !0xFFFF_FFFFu64 != 0 => {
                // Subtract the size of the 64bit local offset from the local
                // e.f. size, local Z64 e.f. block has no offset; when only
                // local offset present, the entire local PKSZ64 block is
                // missing.
                *p_endprev = p_endprev.wrapping_sub(if eb_datalen == 8 { 12 } else { 8 });
            }
            EF_IZUNIX if hostnum == UNIX_ && *p_endprev > 0 => {
                *p_endprev = p_endprev.wrapping_add(4); // also have UID/GID in local copy
            }
            EF_IZUNIX2 if *p_endprev > 0 => {
                *p_endprev = p_endprev.wrapping_add(4); // 4 byte UID/GID in local copy
            }
            _ => {}
        }
        let args = [format!("{eb_id:04x}"), eb_datalen.to_string()];
        uz.info_fmt(
            0,
            m::EXTRA_FIELD_TYPE,
            &[
                args[0].as_bytes(),
                field_name(eb_id).as_bytes(),
                args[1].as_bytes(),
            ],
        );

        // additional, field-specific information:
        if !field_specific(uz, eb_id, data, p_endprev) {
            default_display(uz, data);
        }
        uz.info(0, b".");

        p += eb_datalen;
        ef_len -= eb_datalen;
    }
    uz.info(0, b"\n");
}

/// `%lu` of `makelong(at)`.
fn long_at(data: &[u8], at: usize) -> String {
    makelong(&data[at..]).to_string()
}

/// The block-specific lines; `false` where the C goes to
/// `ef_default_display` (a block too short for its layout, or one it
/// knows no layout for).
fn field_specific(uz: &mut Uz, eb_id: u16, data: &[u8], p_endprev: &mut u64) -> bool {
    let eb_datalen = data.len();
    match eb_id {
        EF_OS2 | EF_ACL => {
            if eb_datalen < EB_OS2_HLEN {
                return false;
            }
            let msg = if eb_id == EF_OS2 {
                m::OS2_EAS
            } else {
                m::ACL_DATA
            };
            uz.info_fmt(0, msg, &[long_at(data, 0).as_bytes()]);
            *p_endprev = 0; // no clue about csize of local
        }
        EF_NTSD => {
            if eb_datalen < EB_NTSD_C_LEN {
                return false;
            }
            uz.info_fmt(0, m::NTSD_DATA, &[long_at(data, 0).as_bytes()]);
            *p_endprev = 0; // no clue about csize of local
        }
        EF_IZVMS => {
            if eb_datalen < 8 {
                return false;
            }
            let compr = usize::from((makeword(&data[EB_IZVMS_FLGS..]) & EB_IZVMS_BCMASK).min(3));
            let mut q: Vec<u8> = Vec::new();
            let kind = match makelong(data) {
                0x4241_4656 => m::VMS_FAB,    // "VFAB"
                0x4C4C_4156 => m::VMS_XABALL, // "VALL"
                0x4348_4656 => m::VMS_XABFHC, // "VFHC"
                0x5441_4456 => m::VMS_XABDAT, // "VDAT"
                0x5444_5256 => m::VMS_XABRDT, // "VRDT"
                0x4F52_5056 => m::VMS_XABPRO, // "VPRO"
                0x5945_4B56 => m::VMS_XABKEY, // "VKEY"
                0x5653_4D56 => {
                    // "VMSV"
                    if eb_datalen >= 16 {
                        // " (" and up to four bytes (`strncpy` stops at a
                        // NUL, and `%s` there), then ")"
                        q.extend_from_slice(b" (");
                        let v = &data[EB_IZVMS_HLEN..EB_IZVMS_HLEN + 4];
                        let n = v.iter().position(|&b| b == 0);
                        q.extend_from_slice(&v[..n.unwrap_or(4)]);
                        if n.is_none() {
                            q.push(b')');
                        }
                    }
                    m::VMS_VERSION
                }
                _ => m::VMS_UNKNOWN,
            };
            let ucsiz = makeword(&data[EB_IZVMS_UCSIZ..]).to_string();
            uz.info_fmt(
                0,
                m::IZ_VMS_DATA,
                &[
                    m::IZ_VMS_COMP[compr].as_bytes(),
                    ucsiz.as_bytes(),
                    kind.as_bytes(),
                    &q,
                ],
            );
        }
        EF_TIME => {
            if eb_datalen > 0 {
                let mut types: Vec<u8> = Vec::new();
                let mut num = 0;
                let flags = data[0];
                if flags & 1 != 0 {
                    types.extend_from_slice(m::UT_MODIFICATION.as_bytes());
                    num += 1;
                }
                if flags & 2 != 0 {
                    if num != 0 {
                        types.push(b'/');
                    }
                    types.extend_from_slice(m::UT_ACCESS.as_bytes());
                    num += 1;
                    if *p_endprev > 0 {
                        *p_endprev = p_endprev.wrapping_add(4);
                    }
                }
                if flags & 4 != 0 {
                    if num != 0 {
                        types.push(b'/');
                    }
                    types.extend_from_slice(m::UT_CREATION.as_bytes());
                    num += 1;
                    if *p_endprev > 0 {
                        *p_endprev = p_endprev.wrapping_add(4);
                    }
                }
                if num > 0 {
                    let s: &[u8] = if num == 1 {
                        b""
                    } else {
                        m::PLUR_SUFX.as_bytes()
                    };
                    uz.info_fmt(0, m::UT_DATA, &[&types, s]);
                }
            }
        }
        EF_UNIPATH | EF_UNICOMNT => {
            if eb_datalen < 5 {
                return false;
            }
            let name_crc = format!("{:08x}", makelong(&data[1..]));
            let v = data[0].to_string();
            let (msg, n) = if eb_datalen <= 29 {
                (m::U8_PTH_CMN_COMPLETE, eb_datalen)
            } else {
                (m::U8_PTH_CMN_F24, 29)
            };
            uz.info_fmt(0, msg, &[v.as_bytes(), name_crc.as_bytes()]);
            for &b in &data[5..n] {
                ef_byte(uz, b);
            }
        }
        EF_MAC3 => {
            if eb_datalen < EB_MAC3_HLEN {
                return false;
            }
            let eb_uc = makelong(data);
            let mac3_flgs = makeword(&data[EB_FLGS_OFFS..]);
            let eb_is_uc = mac3_flgs & EB_M3_FL_UNCMPR != 0;
            let un: &[u8] = if eb_is_uc { m::UN.as_bytes() } else { b"" };
            uz.info_fmt(0, m::MAC3_DATA, &[eb_uc.to_string().as_bytes(), un]);
            if eb_is_uc {
                if *p_endprev > 0 {
                    *p_endprev = p_endprev.wrapping_add(u64::from(eb_uc));
                }
            } else {
                *p_endprev = 0; // no clue about csize of local
            }
            let fork = if mac3_flgs & EB_M3_FL_DATFRK != 0 {
                m::MAC_OS_DF
            } else {
                m::MAC_OS_RF
            };
            let bits: &[u8] = if mac3_flgs & EB_M3_FL_TIME64 != 0 {
                b"64"
            } else {
                b"32"
            };
            uz.info_fmt(0, m::MAC_OS_MAC3_FLAGS, &[fork.as_bytes(), bits]);
            show_mac_type_creator(uz, &data[6..14]);
        }
        EF_ZIPIT2 => {
            if !(eb_datalen >= 5 && makelong(data) == 0x5449_505A) {
                // "ZPIT"
                return false;
            }
            if eb_datalen >= 12 {
                show_mac_type_creator(uz, &data[4..12]);
            }
        }
        EF_ZIPIT => {
            if !(eb_datalen >= 5 && makelong(data) == 0x5449_505A) {
                // "ZPIT"
                return false;
            }
            let fnlen = usize::from(data[4]);
            if eb_datalen >= fnlen + (5 + 8) {
                // terminate filename (A_TO_N: nothing on ASCII)
                let name = fileio::c_str(&data[5..5 + fnlen]);
                uz.info_fmt(0, m::ZIP_IT_FNAME, &[name]);
                show_mac_type_creator(uz, &data[fnlen + 5..fnlen + 13]);
            }
        }
        EF_JLMAC => {
            if !(eb_datalen >= 40 && makelong(data) == 0x4545_4C4A) {
                // "JLEE"
                return false;
            }
            show_mac_type_creator(uz, &data[4..12]);
            let fork = if data[31] & 1 != 0 {
                m::MAC_OS_DF
            } else {
                m::MAC_OS_RF
            };
            uz.info_fmt(0, m::MAC_OS_JLEE_FLAGS, &[fork.as_bytes()]);
        }
        EF_SMARTZIP => {
            if !(eb_datalen == EB_SMARTZIP_HLEN && makelong(data) == 0x7069_5A64) {
                // "dZip"
                return false;
            }
            show_mac_type_creator(uz, &data[4..12]);
            // ruling: the C copies 31 bytes into `filenameBuf[32]` and
            // writes its NUL at `filenameBuf[ef_ptr[32]]`, which a length
            // byte above 31 puts outside the array (undefined behaviour;
            // and `filenameBuf[31]` is then never written). Here the name
            // is the 31 bytes, cut at the length byte when it is shorter,
            // and at their first NUL.
            let copied = &data[33..64];
            let len = usize::from(data[32]).min(copied.len());
            let name = fileio::c_str(&copied[..len]);
            uz.info_fmt(0, m::ZIP_IT_FNAME, &[name]);
        }
        EF_ATHEOS | EF_BEOS => {
            if eb_datalen < EB_BEOS_HLEN {
                return false;
            }
            let eb_uc = makelong(data);
            let eb_is_uc = data[EB_FLGS_OFFS] & EB_BE_FL_UNCMPR != 0;
            let msg = if eb_id == EF_ATHEOS {
                m::ATHE_OS_DATA
            } else {
                m::BE_OS_DATA
            };
            let un: &[u8] = if eb_is_uc { m::UN.as_bytes() } else { b"" };
            uz.info_fmt(0, msg, &[eb_uc.to_string().as_bytes(), un]);
            if eb_is_uc {
                if *p_endprev > 0 {
                    *p_endprev = p_endprev.wrapping_add(u64::from(eb_uc));
                }
            } else {
                *p_endprev = 0; // no clue about csize of local
            }
        }
        EF_QDOS => {
            if eb_datalen < 4 {
                return false;
            }
            uz.info_fmt(0, m::QDOS_DATA, &[&data[..4]]);
        }
        EF_AOSVS => {
            if eb_datalen < 5 {
                return false;
            }
            let (a, b) = ((data[4] / 10).to_string(), (data[4] % 10).to_string());
            uz.info_fmt(0, m::AOSVS_DATA, &[a.as_bytes(), b.as_bytes()]);
        }
        EF_TANDEM => {
            if eb_datalen != 20 {
                return false;
            }
            let mut kind = u32::from((data[18] & 0x60) >> 5);
            let code = u32::from(makeword(data));
            // Arrg..., Tandem e.f. uses BigEndian byte-order
            let code = ((code << 8) & 0xff00) | ((code >> 8) & 0x00ff);
            if kind == NSK_UNSTRUCTURED {
                if code == NSK_EDITFILECODE {
                    kind = 4;
                } else if code == NSK_OBJECTFILECODE {
                    kind = 5;
                }
            }
            uz.info_fmt(
                0,
                m::TANDEM_DATA,
                &[
                    m::TANDEM_FILEFORMAT[kind as usize].as_bytes(),
                    code.to_string().as_bytes(),
                ],
            );
        }
        EF_MD5 => {
            if eb_datalen < 19 {
                return false; // else: fall through !!
            }
            let md5: String = (0..16).map(|i| format!("{:02x}", data[15 - i])).collect();
            uz.info_fmt(0, m::MD5_DATA, &[md5.as_bytes()]);
        }
        _ => return false,
    }
    true
}

/// `ef_default_display`: up to 24 bytes whole, else the first 20.
fn default_display(uz: &mut Uz, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let n = if data.len() <= 24 {
        uz.info(0, m::COLON_INDENT.as_bytes());
        data.len()
    } else {
        uz.info(0, m::FIRST20.as_bytes());
        20
    };
    for &b in &data[..n] {
        ef_byte(uz, b);
    }
}

/// `efFormat`, `" %02x"`.
fn ef_byte(uz: &mut Uz, b: u8) {
    uz.info_fmt(0, m::EF_FORMAT, &[format!("{b:02x}").as_bytes()]);
}

// port: zipinfo.c:zi_showMacTypeCreator
/// A Macintosh type and creator, `ebfield[0..8]`: as characters when all
/// eight print, else as two hex words.
fn show_mac_type_creator(uz: &mut Uz, ebfield: &[u8]) {
    // not every Type / Creator character is printable
    if ebfield.iter().all(|&c| fileio::is_print(uz, c)) {
        uz.info_fmt(0, m::MAC_OS_DATA, &[&ebfield[..4], &ebfield[4..8]]);
    } else {
        let word = |b: &[u8]| {
            format!(
                "{:x}",
                (u32::from(b[0]) << 24)
                    + (u32::from(b[1]) << 16)
                    + (u32::from(b[2]) << 8)
                    + u32::from(b[3])
            )
        };
        let (t, c) = (word(&ebfield[..4]), word(&ebfield[4..8]));
        uz.info_fmt(0, m::MAC_OS_DATA1, &[t.as_bytes(), c.as_bytes()]);
    }
}
