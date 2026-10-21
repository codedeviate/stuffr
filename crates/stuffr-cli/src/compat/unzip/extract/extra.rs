//! `extract.c`'s extra-field checks: `TestExtraField()` (what `-t` says of
//! an entry's attribute blocks once its data tested OK), `test_compr_eb()`
//! and `memextract()` (a compressed block inflated in memory, through the
//! run's one window as the C's is), and fileio.c's `is_vms_varlen_txt()`
//! with `extract_izvms_block()` and `decompress_bits()` (`VMS_TEXT_CONV`).
//!
//! Nothing is allocated by a size the block claims: `memextract()`'s output
//! is only counted (its CRC taken), and a VMS block is bounded by its own
//! length.

use std::cell::RefCell;

use stuffr::infozip::{self, Stop};

use super::super::fileio::{self, c_str};
use super::super::flavour;
use super::super::messages as m;
use super::super::{PK_COOL, PK_OK, PK_WARN, Uz};
use super::{PK_ERR, PK_MEM3, pad22};

/// unzpriv.h's extra block ids.
const EF_OS2: u16 = 0x0009;
const EF_PKVMS: u16 = 0x000c;
const EF_MAC3: u16 = 0x334d;
const EF_ACL: u16 = 0x4c41;
const EF_NTSD: u16 = 0x4453;
const EF_ATHEOS: u16 = 0x7441;
const EF_BEOS: u16 = 0x6542;
const EF_IZVMS: u16 = 0x4d49;

/// unzpriv.h's block layout constants.
const EB_HEADSIZE: usize = 4;
const EB_UCSIZE_P: usize = 0;
const EB_CMPRHEADLEN: usize = 6;
const EB_FLGS_OFFS: usize = 4;
const EB_OS2_HLEN: usize = 4;
const EB_BEOS_HLEN: usize = 5;
const EB_BE_FL_UNCMPR: u8 = 0x01;
const EB_MAC3_HLEN: usize = 14;
const EB_M3_FL_UNCMPR: u16 = 0x04;
const EB_NTSD_L_LEN: usize = 5;
const EB_NTSD_VERSION: usize = 4;
const EB_NTSD_MAX_VER: u8 = 0;
const EB_IZVMS_HLEN: usize = 12;
const EB_IZVMS_FLGS: usize = 4;
const EB_IZVMS_UCSIZ: usize = 6;
const EB_IZVMS_BCMASK: u16 = 0o7;
const EB_IZVMS_BCSTOR: u16 = 0;
const EB_IZVMS_BC00: u16 = 1;
const EB_IZVMS_BCDEFL: u16 = 2;

/// unzpriv.h's `IZ_EF_TRUNC` and unzip.h's `PK_MEM4`.
const IZ_EF_TRUNC: i32 = 79;
const PK_MEM4: i32 = 7;

/// The method numbers memextract() knows.
const STORED: u16 = 0;
const DEFLATED: u16 = 8;
const ENHDEFLATED: u16 = 9;

/// The CRC-32 of `b` (`crc32(CRCVAL_INITIAL, b, len)`).
fn crc32(b: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(b);
    c.sum()
}

/// The entry's name, padded (`"%-22s "` under `-q`), on standard error
/// (standard output under `-t`).
fn quiet_name(uz: &mut Uz) {
    if uz.o.qflag != 0 {
        let name = c_str(&uz.filename).to_vec();
        let shown = fileio::fnfilter1(uz, &name);
        uz.info_fmt(1, m::NAME_22, &[&pad22(&shown)]);
    }
}

// port: extract.c:TestExtraField
/// `TestExtraField(ef, ef_len)`: each attribute block of the local extra
/// field that is compressed tested (OS/2, ACL, Mac, BeOS, AtheOS, NT
/// security), PKWARE's VMS block's CRC checked; " OK" unless `-q`. Returns
/// the first failure's code.
pub(crate) fn test_extra_field(uz: &mut Uz, ef: &[u8]) -> i32 {
    let mut ef = ef;
    // we know the regular compressed file data tested out OK, or else we
    // wouldn't be here ==> print filename if any extra-field errors found
    while ef.len() >= EB_HEADSIZE {
        let eb_id = fileio::makeword(ef);
        let eb_len = usize::from(fileio::makeword(&ef[2..]));
        if eb_len > ef.len() - EB_HEADSIZE {
            // Discovered some extra field inconsistency!
            quiet_name(uz);
            let (a, b) = (eb_len.to_string(), (ef.len() - EB_HEADSIZE).to_string());
            uz.info_fmt(1, m::INCONSIST_EF_LENGTH, &[a.as_bytes(), b.as_bytes()]);
            return PK_ERR;
        }
        let block = &ef[..EB_HEADSIZE + eb_len];
        match eb_id {
            EF_OS2 | EF_ACL | EF_MAC3 | EF_BEOS | EF_ATHEOS => {
                let offs = match eb_id {
                    EF_MAC3 => {
                        if eb_len >= EB_MAC3_HLEN
                            && fileio::makeword(&block[EB_HEADSIZE + EB_FLGS_OFFS..])
                                & EB_M3_FL_UNCMPR
                                != 0
                            && fileio::makelong(&block[EB_HEADSIZE..]) as usize
                                == eb_len - EB_MAC3_HLEN
                        {
                            0
                        } else {
                            EB_MAC3_HLEN
                        }
                    }
                    EF_BEOS | EF_ATHEOS => {
                        if eb_len >= EB_BEOS_HLEN
                            && block[EB_HEADSIZE + EB_FLGS_OFFS] & EB_BE_FL_UNCMPR != 0
                            && fileio::makelong(&block[EB_HEADSIZE..]) as usize
                                == eb_len - EB_BEOS_HLEN
                        {
                            0
                        } else {
                            EB_BEOS_HLEN
                        }
                    }
                    _ => EB_OS2_HLEN,
                };
                let r = test_compr_eb(uz, block, eb_len, offs);
                if r != PK_OK {
                    quiet_name(uz);
                    eas_failure(uz, r, eb_len, offs, m::TRUNC_EAS);
                    return r;
                }
            }
            EF_NTSD => {
                let mut r = if eb_len < EB_NTSD_L_LEN {
                    IZ_EF_TRUNC
                } else if block[EB_HEADSIZE + EB_NTSD_VERSION] > EB_NTSD_MAX_VER {
                    PK_WARN | 0x4000
                } else {
                    test_compr_eb(uz, block, eb_len, EB_NTSD_L_LEN)
                };
                if r != PK_OK {
                    quiet_name(uz);
                    if r == PK_WARN | 0x4000 {
                        let v = block[EB_HEADSIZE + EB_NTSD_VERSION].to_string();
                        uz.info_fmt(1, m::UNSUPP_NTSD_VERS_EAS, &[v.as_bytes()]);
                        r = PK_WARN;
                    } else {
                        eas_failure(uz, r, eb_len, EB_NTSD_L_LEN, m::TRUNC_NTSD);
                    }
                    return r;
                }
            }
            EF_PKVMS => {
                if eb_len < 4 {
                    let a = eb_len.to_string();
                    uz.info_fmt(1, m::TOO_SMALL_EB_LENGTH, &[a.as_bytes(), b"4"]);
                } else if fileio::makelong(&block[EB_HEADSIZE..])
                    != crc32(&block[EB_HEADSIZE + 4..])
                {
                    uz.info_fmt(1, m::BAD_CRC_EAS, &[]);
                }
            }
            _ => {}
        }
        ef = &ef[EB_HEADSIZE + eb_len..];
    }
    if uz.o.qflag == 0 {
        uz.info_fmt(0, m::OK, &[]);
    }
    PK_COOL
}

/// TestExtraField's report of a failed compressed block.
fn eas_failure(uz: &mut Uz, r: i32, eb_len: usize, offs: usize, trunc: &str) {
    match r {
        IZ_EF_TRUNC => {
            // `%d` of the C's unsigned difference
            let n = (eb_len as i64 - (offs + EB_CMPRHEADLEN) as i64) as i32;
            uz.info_fmt(1, trunc, &[n.to_string().as_bytes(), b"\n"]);
        }
        PK_ERR => uz.info_fmt(1, m::INVALID_COMPR_DATA_EAS, &[]),
        PK_MEM3 | PK_MEM4 => uz.info_fmt(1, m::NOT_ENOUGH_MEM_EAS, &[]),
        _ => {
            if r & 0xff != PK_ERR {
                uz.info_fmt(1, m::UNKN_ERROR_EAS, &[]);
            } else {
                let method = (r >> 8) as u16;
                if method == DEFLATED {
                    // GRR KLUDGE!
                    uz.info_fmt(1, m::BAD_CRC_EAS, &[]);
                } else {
                    let n = method.to_string();
                    uz.info_fmt(1, m::UNKN_COMPR_METHOD_EAS, &[n.as_bytes()]);
                }
            }
        }
    }
}

// port: extract.c:test_compr_eb
/// `test_compr_eb(eb, eb_size, compr_offset, NULL)`: a compressed block
/// (`eb`, header included) whose data starts `compr_offset` bytes in,
/// inflated in memory (`memextract()`); `IZ_EF_TRUNC` when it is too short
/// to hold its size or its compression header, or claims 0 bytes; `PK_ERR`
/// when a stored block's sizes disagree.
fn test_compr_eb(uz: &mut Uz, eb: &[u8], eb_size: usize, compr_offset: usize) -> i32 {
    if compr_offset < 4 {
        // field is not compressed: do nothing and signal OK
        return PK_OK;
    }
    if eb_size < EB_UCSIZE_P + 4 {
        return IZ_EF_TRUNC; // no/bad compressed data!
    }
    let eb_ucsize = u64::from(fileio::makelong(&eb[EB_HEADSIZE + EB_UCSIZE_P..]));
    if eb_ucsize == 0 || eb_size <= compr_offset + EB_CMPRHEADLEN {
        return IZ_EF_TRUNC; // no/bad compressed data!
    }
    // For STORE method, compressed and uncompressed sizes must agree.
    let eb_compr_method = fileio::makeword(&eb[EB_HEADSIZE + compr_offset..]);
    // apple: extract.c:2307 counts the 6-byte compression header as data;
    // ubuntu: 12-cve-2014-9636-test-compr-eb.patch does not.
    let stored_len = if flavour::cve_2014_9636_stored_size(uz.flavour) {
        (eb_size - compr_offset - EB_CMPRHEADLEN) as u64
    } else {
        (eb_size - compr_offset) as u64
    };
    if eb_compr_method == STORED && stored_len != eb_ucsize {
        return PK_ERR;
    }
    memextract(
        uz,
        eb_ucsize,
        &eb[EB_HEADSIZE + compr_offset..EB_HEADSIZE + eb_size],
    )
    .0
}

// port: extract.c:memextract
/// `memextract(tgt, tgtsize, src, srcsize)`: `src` (method word, CRC, data)
/// stored or inflated into at most `tgtsize` bytes (`memflush()`: more is
/// `PK_DISK`), then its CRC checked. Returns the code and the bytes (kept
/// only up to `keep`, for the VMS block's record attributes).
fn memextract_keep(uz: &mut Uz, tgtsize: u64, src: &[u8], keep: usize) -> (i32, Vec<u8>) {
    let method = fileio::makeword(src);
    let extra_field_crc = fileio::makelong(&src[2..]);
    let data = &src[6..];
    let mut error = PK_OK;
    let mut crc = flate2::Crc::new();
    let mut kept = Vec::new();
    match method {
        STORED => {
            crc.update(data);
            kept.extend_from_slice(&data[..data.len().min(keep)]);
        }
        DEFLATED | ENHDEFLATED => {
            let mut outsize = tgtsize;
            let mut slide = std::mem::take(&mut uz.slide);
            let r = {
                let cell = RefCell::new(&mut *uz);
                let mut src = data.iter();
                let mut flush = |buf: &[u8]| -> Result<(), i32> {
                    if buf.len() as u64 > outsize {
                        // more data than output buffer can hold
                        return Err(super::PK_DISK);
                    }
                    outsize -= buf.len() as u64;
                    crc.update(buf);
                    let room = keep.saturating_sub(kept.len());
                    kept.extend_from_slice(&buf[..buf.len().min(room)]);
                    Ok(())
                };
                let mut message = |msg: &'static str| {
                    let mut uz = cell.borrow_mut();
                    if uz.o.qflag == 0 {
                        uz.print_raw(1, msg.as_bytes());
                    }
                };
                infozip::inflate(
                    &mut src,
                    method == ENHDEFLATED,
                    &mut slide,
                    &mut flush,
                    &mut message,
                )
            };
            uz.slide = slide;
            uz.restore_slide();
            if let Err(stop) = r {
                let r = match stop {
                    Stop::Code(c) => c,
                    Stop::Flush(e) => e,
                    Stop::Length { .. } => 1,
                };
                if !uz.o.tflag {
                    let why = if r == 3 {
                        m::NOT_ENOUGH_MEM
                    } else {
                        m::INVALID_COMPR_DATA
                    };
                    uz.info_fmt(
                        0x401,
                        m::ERR_UNZIP_NO_FILE,
                        &[why.as_bytes(), m::INFLATE.as_bytes()],
                    );
                }
                error = if r == 3 { PK_MEM3 } else { PK_ERR };
            }
        }
        _ => {
            if uz.o.tflag {
                error = PK_ERR | (i32::from(method) << 8);
            } else {
                let n = method.to_string();
                uz.info_fmt(0x401, m::UNSUPPORTED_EXTRA_FIELD, &[n.as_bytes()]);
                error = PK_ERR; // GRR:  should be passed on up via SetEAs()
            }
        }
    }
    if error == 0 {
        let crcval = crc.sum();
        if crcval != extra_field_crc {
            if uz.o.tflag {
                error = PK_ERR | (i32::from(DEFLATED) << 8); // kludge for now
            } else {
                let zipfn = uz.zipfn.clone();
                let (a, b) = (format!("{crcval:08x}"), format!("{extra_field_crc:08x}"));
                uz.info_fmt(
                    0x401,
                    m::BAD_EXTRA_FIELD_CRC,
                    &[&zipfn, a.as_bytes(), b.as_bytes()],
                );
                error = PK_ERR;
            }
        }
    }
    (error, kept)
}

/// [`memextract_keep`] keeping nothing.
fn memextract(uz: &mut Uz, tgtsize: u64, src: &[u8]) -> (i32, Vec<u8>) {
    memextract_keep(uz, tgtsize, src, 0)
}

/// `VMSFAB_B_RFM`: the FAB's record format byte.
const VMSFAB_B_RFM: usize = 31;
/// `VMS_FABSIG`, "VFAB".
const VMS_FABSIG: u32 = 0x4241_4656;
/// `VMSREC_C_VAR`: variable-length records.
const VMSREC_C_VAR: u8 = 2;
/// `VMSATR_C_RECATTR`: the record-attributes item of a PKWARE VMS block.
const VMSATR_C_RECATTR: u16 = 4;

// port: fileio.c:is_vms_varlen_txt
/// `is_vms_varlen_txt(ef, ef_len)`: the extra field says the file was a VMS
/// file of variable-length records (PKWARE's block, CRC checked, or
/// Info-ZIP's FAB copy), which `-a` turns into lines.
/// ruling: T10-8. The C reads past a block when it is shorter than what it
/// reads from it (a PKWARE block under its 4-byte CRC, an item longer than
/// what is left, an Info-ZIP block under its 12-byte header, `0 -> 0 bit`
/// data shorter than its size): undefined behaviour. Here such a block (or
/// item) ends the scan of that block, and missing bits read as zeros.
pub(crate) fn is_vms_varlen_txt(uz: &mut Uz, ef: &[u8]) -> bool {
    let mut vms_rectype = 0u8;
    let mut ef = ef;
    while ef.len() >= EB_HEADSIZE {
        let eb_id = fileio::makeword(ef);
        let eb_len = usize::from(fileio::makeword(&ef[2..]));
        if eb_len > ef.len() - EB_HEADSIZE {
            // discovered some extra field inconsistency!
            break;
        }
        let data = &ef[EB_HEADSIZE..EB_HEADSIZE + eb_len];
        match eb_id {
            EF_PKVMS if eb_len >= 4 => {
                let items = &data[4..];
                if fileio::makelong(data) != crc32(items) {
                    uz.info_fmt(1, m::VMS_CRC_WARNING, &[]);
                } else {
                    // scan through the attribute data items
                    let mut items = items;
                    while items.len() > 4 {
                        let fldsize = usize::from(fileio::makeword(&items[2..]));
                        if fileio::makeword(items) == VMSATR_C_RECATTR && fldsize >= 1 {
                            vms_rectype = items[4] & 15;
                        }
                        // skip to next data item
                        if fldsize + 4 > items.len() {
                            break;
                        }
                        items = &items[fldsize + 4..];
                    }
                }
            }
            EF_IZVMS if eb_len >= 4 && fileio::makelong(data) == VMS_FABSIG => {
                if let Some(fab) = extract_izvms_block(uz, data, VMSFAB_B_RFM + 1)
                    && fab.len() > VMSFAB_B_RFM
                {
                    vms_rectype = fab[VMSFAB_B_RFM] & 15;
                }
            }
            _ => {}
        }
        // Skip this extra field block
        ef = &ef[EB_HEADSIZE + eb_len..];
    }
    vms_rectype == VMSREC_C_VAR
}

// port: extract.c:extract_izvms_block
/// `extract_izvms_block(ebdata, size, &retlen, NULL, 0)`: an Info-ZIP VMS
/// block's data (stored, `0 -> 0 bit`, or deflated), its first `keep`
/// bytes (all that is read of it); `None` for an unknown kind.
fn extract_izvms_block(uz: &mut Uz, ebdata: &[u8], keep: usize) -> Option<Vec<u8>> {
    let size = ebdata.len();
    if size < EB_IZVMS_HLEN {
        return None;
    }
    let cmptype = fileio::makeword(&ebdata[EB_IZVMS_FLGS..]) & EB_IZVMS_BCMASK;
    let csiz = size - EB_IZVMS_HLEN;
    let usiz = if cmptype == EB_IZVMS_BCSTOR {
        csiz
    } else {
        usize::from(fileio::makeword(&ebdata[EB_IZVMS_UCSIZ..]))
    };
    let body = &ebdata[EB_IZVMS_HLEN..];
    match cmptype {
        EB_IZVMS_BCSTOR => Some(body[..usiz.min(keep)].to_vec()),
        EB_IZVMS_BC00 => Some(decompress_bits(usiz.min(keep), body)),
        EB_IZVMS_BCDEFL => Some(memextract_keep(uz, usiz as u64, &pad6(body), keep).1),
        _ => None,
    }
}

/// memextract() reads a method word and a CRC before the data; a deflated
/// VMS block too short for them is read as zeros (T10-8).
fn pad6(b: &[u8]) -> Vec<u8> {
    let mut v = b.to_vec();
    if v.len() < 6 {
        v.resize(6, 0);
    }
    v
}

// port: extract.c:decompress_bits
/// `decompress_bits(outptr, needlen, bitptr)`: a 1 bit and a byte, or a 0
/// bit for a zero byte, `needlen` times (bits past `bits` read as zeros:
/// T10-8).
fn decompress_bits(needlen: usize, bits: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(needlen);
    let mut bitbuf: u64 = 0;
    let mut bitcnt: i32 = 0;
    let mut at = 0usize;
    let mut fill = |bitbuf: &mut u64, bitcnt: &mut i32| {
        *bitbuf |= u64::from(bits.get(at).copied().unwrap_or(0)) << *bitcnt;
        at += 1;
        *bitcnt += 8;
    };
    for _ in 0..needlen {
        if bitcnt <= 0 {
            fill(&mut bitbuf, &mut bitcnt);
        }
        if bitbuf & 1 != 0 {
            bitbuf >>= 1;
            bitcnt -= 1;
            if bitcnt < 8 {
                fill(&mut bitbuf, &mut bitcnt);
            }
            out.push(bitbuf as u8);
            bitcnt -= 8;
            bitbuf >>= 8;
        } else {
            out.push(0);
            bitcnt -= 1;
            bitbuf >>= 1;
        }
    }
    out
}
