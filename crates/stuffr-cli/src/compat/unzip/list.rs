//! `list.c`: unzip's own listings (`list_files()`: `-l`, `-v`), `-T`'s
//! newest time (`get_time_stamp()`, `fn_is_dir()`) and the compression
//! ratio both listings and zipinfo print (`ratio()`). `fnprint()` is in
//! `fileio.rs`, beside `fnfilter()`.

use super::fileio::{self, DoString};
use super::messages as m;
use super::process::{self, CentralEntry, EB_UT_FL_MTIME, IzTimes, WalkEnd};
use super::{PK_COOL, PK_FIND, PK_WARN, Uz, flavour};

/// unzpriv.h's `NUM_METHODS`.
const NUM_METHODS: usize = 17;

/// extract.c's `ComprIDs[]`: the methods `list_files()` names.
const COMPR_IDS: [u16; NUM_METHODS] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 18, 19, 97, 98];

/// unzpriv.h's `DEFLATED` and `ENHDEFLATED`.
const DEFLATED: u16 = 8;
const ENHDEFLATED: u16 = 9;

// port: extract.c:find_compr_idx
/// The index of `method` in `ComprIDs[]`, `NUM_METHODS` for another.
pub(crate) fn find_compr_idx(method: u16) -> usize {
    COMPR_IDS
        .iter()
        .position(|&id| id == method)
        .unwrap_or(NUM_METHODS)
}

// port: list.c:ratio
/// The compression ratio of `c` bytes for `uc` in tenths of a percent
/// (negative for an expansion), rounded, in the C's unsigned 64-bit
/// arithmetic: a wrapped size gives the C's figure.
/// ruling: the C converts the 64-bit quotient to `int` (implementation
/// defined: its low 32 bits, as both references' compilers do) and negates
/// it, which overflows for `INT_MIN` (undefined behaviour); the negation
/// wraps here.
pub(crate) fn ratio(uc: u64, c: u64) -> i32 {
    if uc == 0 {
        return 0;
    }
    if uc > 2_000_000 {
        // risk signed overflow if multiply numerator
        let denom = uc / 1000;
        if uc >= c {
            ((uc - c).wrapping_add(denom >> 1) / denom) as i32
        } else {
            (((c - uc).wrapping_add(denom >> 1) / denom) as i32).wrapping_neg()
        }
    } else {
        // ^^^^^^^^ rounding
        let denom = uc;
        if uc >= c {
            (1000u64.wrapping_mul(uc - c).wrapping_add(denom >> 1) / denom) as i32
        } else {
            ((1000u64.wrapping_mul(c - uc).wrapping_add(denom >> 1) / denom) as i32).wrapping_neg()
        }
    }
}

/// `ratio()` as the listings print it: the sign and the rounded percent
/// (`cfactor`).
/// ruling (P23, replacing T8-6's wrap): `(-cfactor + 5) / 10` overflows
/// `int` for a ratio of INT_MIN, and `(cfactor + 5) / 10` for one above
/// INT_MAX - 5 (undefined behaviour). Both references compute these as
/// unsigned: clang and gcc take the operand as non-negative after the sign
/// test, so the figure is `(|ratio| + 5) / 10` in unsigned arithmetic
/// (`-214748365%` for INT_MIN, ` 214748365%` for INT_MAX), and so it is
/// here.
/// probe: unzip -v of 1000 bytes stored in 2^31 + 1000 + k, k in -6..=6,
/// on both references (Apple and Ubuntu print the same figures)
fn cfactor(uc: u64, c: u64) -> (u8, i32) {
    let r = ratio(uc, c);
    let sgn = if r < 0 { b'-' } else { b' ' };
    // at most (2^31 + 5) / 10, which fits an `int`
    (sgn, ((r.unsigned_abs() + 5) / 10) as i32)
}

/// `cfactorstr`: `100%` or the sign and the percent (`CompFactor100`,
/// `CompFactorStr`).
fn cfactorstr(sgn: u8, cfactor: i32) -> Vec<u8> {
    if cfactor == 100 {
        m::COMP_FACTOR_100.as_bytes().to_vec()
    } else {
        let mut v = vec![sgn];
        v.extend_from_slice(cfactor.to_string().as_bytes());
        v.push(b'%');
        v
    }
}

/// `methbuf`: the method's name; deflate's with its option letter
/// (`N`ormal, `X`tra, `F`ast, `S`uperfast from flag bits 1-2), an unknown
/// method's number.
/// ruling: the C writes `Unk:` and `%03u` into an 8-byte `methbuf`, which a
/// method above 999 overflows (Apple's unzip dies by `__sprintf_chk`, exit
/// 133: probe `unzip -l` of an entry of method 1000). Both flavours print
/// what Ubuntu's 18-cve-2014-9913-unzip-buffer-overflow.patch prints:
/// `Unk` and four upper-case hex digits (`Unk03E8`).
fn methbuf(e: &CentralEntry) -> Vec<u8> {
    let methnum = find_compr_idx(e.compression_method);
    let mut b = m::LIST_METHODS[methnum].as_bytes().to_vec();
    if e.compression_method == DEFLATED || e.compression_method == ENHDEFLATED {
        b[5] = m::DTYPE[usize::from((e.general_purpose_bit_flag >> 1) & 3)];
    } else if methnum >= NUM_METHODS {
        b.truncate(3);
        if e.compression_method <= 999 {
            b.push(b':');
            b.extend_from_slice(format!("{:03}", e.compression_method).as_bytes());
        } else {
            b.extend_from_slice(format!("{:04X}", e.compression_method).as_bytes());
        }
    }
    b
}

/// The year, month, day, hour and minute an entry is listed with: the
/// local time of its central `EF_TIME` modification time when it has one,
/// else its MS-DOS date and time; in the order `DATE_FORMAT` gives.
fn entry_date(uz: &Uz, e: &CentralEntry) -> [u64; 5] {
    let mut z_utime = IzTimes::default();
    let t = match &e.extra {
        Some(ef)
            if process::ef_scan_for_izux(
                uz.flavour,
                ef,
                true,
                e.last_mod_dos_datetime,
                Some(&mut z_utime),
            ) & EB_UT_FL_MTIME
                != 0 =>
        {
            fileio::localtime(uz, z_utime.mtime)
        }
        _ => None,
    };
    let dt = e.last_mod_dos_datetime;
    let (mut yr, mut mo, mut dy, hh, mm) = match t {
        Some(t) => (
            t.year as u64 & 0xffff_ffff,
            u64::from(t.mon),
            u64::from(t.mday),
            u64::from(t.hour),
            u64::from(t.min),
        ),
        None => (
            u64::from((dt >> 25) & 0x7f) + 1980,
            u64::from((dt >> 21) & 0x0f),
            u64::from((dt >> 16) & 0x1f),
            u64::from((dt >> 11) & 0x1f),
            u64::from((dt >> 5) & 0x3f),
        ),
    };
    // permute date so it displays according to nat'l convention
    match flavour::date_format(uz.flavour) {
        flavour::DateFormat::Ymd => {
            let t = mo;
            mo = yr;
            yr = dy;
            dy = t;
        }
        flavour::DateFormat::Dmy => std::mem::swap(&mut mo, &mut dy),
        flavour::DateFormat::Mdy => {}
    }
    [mo, dy, yr, hh, mm]
}

// port: list.c:list_files
/// `unzip -l` (short) and `-v` (long): a heading, one line per selected
/// entry with its comment (unless `-q`), the totals, the end-record check.
/// `PK_FIND` when nothing was listed.
pub(crate) fn list_files(uz: &mut Uz) -> i32 {
    let longhdr = uz.o.vflag > 1;
    let sep = m::DATE_SEPCHAR;

    if uz.o.qflag < 2 {
        let (h0, h1) = if longhdr {
            (m::HEADERS_L, m::HEADERS_L1)
        } else {
            (m::HEADERS_S, m::HEADERS_S1)
        };
        if uz.o.l_flag != 0 {
            uz.info_fmt(0, m::CASE_CONVERSION, &[h0.as_bytes(), h1.as_bytes()]);
        } else {
            uz.info_fmt(0, m::TWO_LINES, &[h0.as_bytes(), h1.as_bytes()]);
        }
    }

    let mut members: u64 = 0;
    let (mut tot_csize, mut tot_ucsize) = (0u64, 0u64);
    let qcond = uz.o.qflag == 0; // QQ: comments with -vq or -vqq
    let error_in_archive = process::walk_central(uz, &mut |uz, e| {
        // check if specified on command line
        if !process::selected(uz, &e.filename, None, None) {
            // not listing this file: SKIP_ (whose do_string(SKIP) is
            // always PK_OK)
            fileio::do_string(uz, usize::from(e.file_comment_length), DoString::Skip, None);
            return PK_COOL;
        }
        let [mo, dy, yr, hh, mm] = entry_date(uz, e);

        let mut csiz = e.csize;
        if e.general_purpose_bit_flag & 1 != 0 {
            // if encrypted, don't count encryption header
            csiz = csiz.wrapping_sub(12);
        }
        let (sgn, cf) = cfactor(e.ucsize, csiz);
        let cfs = cfactorstr(sgn, cf);
        let lc = if e.pinfo.lcflag { b'^' } else { b' ' };
        let line = if longhdr {
            m::long_hdr_stats(
                e.ucsize,
                &methbuf(e),
                csiz,
                &cfs,
                [mo, dy, yr, hh, mm],
                sep,
                e.crc32,
                lc,
            )
        } else {
            m::short_hdr_stats(e.ucsize, [mo, dy, yr, hh, mm], sep, lc)
        };
        uz.info(0, &line);
        fileio::fnprint(uz);

        let option = if qcond {
            DoString::Displ8
        } else {
            DoString::Skip
        };
        let pinfo = e.pinfo;
        let error = fileio::do_string(uz, usize::from(e.file_comment_length), option, Some(&pinfo));
        tot_ucsize = tot_ucsize.wrapping_add(e.ucsize);
        tot_csize = tot_csize.wrapping_add(csiz);
        members += 1;
        error
    });
    if error_in_archive > PK_WARN {
        return error_in_archive;
    }
    let mut error_in_archive = error_in_archive;

    // Print footer line and totals (compressed size, uncompressed size,
    // number of members in zipfile).
    if uz.o.qflag < 2 {
        let (sgn, cf) = cfactor(tot_ucsize, tot_csize);
        let cfs = cfactorstr(sgn, cf);
        let line = if longhdr {
            m::long_file_trailer(tot_ucsize, tot_csize, &cfs, members)
        } else {
            m::short_file_trailer(tot_ucsize, members)
        };
        uz.info(0, &line);
    }

    // Double check that we're back at the end-of-central-directory record.
    let sig = uz.sig;
    let want = if uz.ecrec.have_ecr64 {
        process::END_CENTRAL64_SIG
    } else {
        process::END_CENTRAL_SIG
    };
    if sig != want && !uz.ecrec.is_zip64_archive && sig != process::END_CENTRAL_SIG {
        // just to make sure again
        uz.info(0x401, m::END_SIG_MSG.as_bytes());
        error_in_archive = PK_WARN; // didn't find sig
    }
    // Set specific return code when no files have been found.
    if members == 0 && error_in_archive <= PK_WARN {
        error_in_archive = PK_FIND;
    }
    error_in_archive
}

// port: list.c:fn_is_dir
/// Whether the entry's name is a directory's: it ends in `/`, or, from
/// MS-DOS with no `/` in it, in `\`.
fn fn_is_dir(e: &CentralEntry) -> bool {
    let name = &e.filename;
    match name.last() {
        None => false,
        Some(&endc) => {
            endc == b'/'
                || (e.pinfo.hostnum == fileio::FS_FAT_ && !name.contains(&b'/') && endc == b'\\')
        }
    }
}

// port: list.c:get_time_stamp
/// `-T`: the newest modification time among the selected entries that are
/// not directories (their central `EF_TIME` time, else the MS-DOS time in
/// local time), and how many there were. `PK_FIND` when none.
pub(crate) fn get_time_stamp(uz: &mut Uz, last_modtime: &mut i64, nmember: &mut u64) -> i32 {
    *last_modtime = 0; // assuming no zipfile data older than 1970
    *nmember = 0;
    let mut latest = 0i64;
    let mut count = 0u64;
    let error = process::walk(uz, WalkEnd::TimeStamp, &mut |uz, e| {
        if process::selected(uz, &e.filename, None, None) && !fn_is_dir(e) {
            let mut z_utime = IzTimes::default();
            let ut = match &e.extra {
                Some(ef) => {
                    process::ef_scan_for_izux(
                        uz.flavour,
                        ef,
                        true,
                        e.last_mod_dos_datetime,
                        Some(&mut z_utime),
                    ) & EB_UT_FL_MTIME
                        != 0
                }
                None => false,
            };
            let modtime = if ut {
                z_utime.mtime
            } else {
                fileio::dos_to_unix_time(uz, e.last_mod_dos_datetime)
            };
            if latest < modtime {
                latest = modtime;
            }
            count += 1;
        }
        fileio::do_string(uz, usize::from(e.file_comment_length), DoString::Skip, None)
    });
    *last_modtime = latest;
    *nmember = count;
    if error > PK_WARN {
        return error;
    }
    let mut error_in_archive = error;

    // Double check that we're back at the end-of-central-directory record.
    if uz.sig != process::END_CENTRAL_SIG {
        // just to make sure again
        uz.info(0x401, m::END_SIG_MSG.as_bytes());
        error_in_archive = PK_WARN;
    }
    if *nmember == 0 && error_in_archive <= PK_WARN {
        error_in_archive = PK_FIND;
    }
    error_in_archive
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The figures both references printed (probe: `unzip -v` of
    /// hand-built archives, `LANG=C`).
    #[test]
    fn ratio_is_the_c_arithmetic() {
        assert_eq!(ratio(0, 5), 0);
        assert_eq!(cfactor(6, 6), (b' ', 0));
        assert_eq!(cfactor(2200, 63), (b' ', 97));
        assert_eq!(cfactor(2206, 69), (b' ', 97));
        // An encrypted entry stored in fewer bytes than its header: `csiz`
        // wraps (probe: `20  Stored 18446744073709551609  85899481%`).
        let csiz = 5u64.wrapping_sub(12);
        assert_eq!(csiz, 18_446_744_073_709_551_609);
        assert_eq!(cfactor(20, csiz), (b' ', 85_899_481));
        assert_eq!(cfactorstr(b' ', 100), b"100%");
        assert_eq!(cfactorstr(b'-', 50), b"-50%");
        // An expansion over 2 MB takes the other branch.
        assert_eq!(cfactor(4_000_000, 8_000_000), (b'-', 100));
        // ruling (P23): at INT_MIN and near INT_MAX the figure is the
        // unsigned one both references print.
        let k = |k: i64| ((1u64 << 31) as i64 + 1000 + k) as u64;
        assert_eq!(ratio(1000, k(0)), i32::MIN);
        assert_eq!(cfactor(1000, k(0)), (b'-', 214_748_365));
        assert_eq!(ratio(1000, k(1)), i32::MAX);
        assert_eq!(cfactor(1000, k(1)), (b' ', 214_748_365));
        assert_eq!(cfactor(1000, k(4)), (b' ', 214_748_364));
        assert_eq!(cfactor(1000, k(-6)), (b'-', 214_748_364));
    }

    #[test]
    fn methods_are_named_and_numbered() {
        let e = |method: u16, flags: u16| CentralEntry {
            compression_method: method,
            general_purpose_bit_flag: flags,
            ..CentralEntry::default()
        };
        assert_eq!(methbuf(&e(0, 0)), b"Stored");
        assert_eq!(methbuf(&e(8, 0)), b"Defl:N");
        assert_eq!(methbuf(&e(8, 2)), b"Defl:X");
        assert_eq!(methbuf(&e(8, 4)), b"Defl:F");
        assert_eq!(methbuf(&e(9, 6)), b"Def64S");
        assert_eq!(methbuf(&e(12, 0)), b"BZip2");
        assert_eq!(methbuf(&e(99, 0)), b"Unk:099");
        assert_eq!(methbuf(&e(999, 0)), b"Unk:999");
        // ruling: past 999, Ubuntu's CVE-2014-9913 format for both flavours.
        assert_eq!(methbuf(&e(1000, 0)), b"Unk03E8");
        assert_eq!(methbuf(&e(65535, 0)), b"UnkFFFF");
    }

    #[test]
    fn directories_are_named_by_their_last_byte() {
        let e = |name: &[u8], host: u8| CentralEntry {
            filename: name.to_vec(),
            pinfo: fileio::PInfo {
                hostnum: host,
                ..fileio::PInfo::default()
            },
            ..CentralEntry::default()
        };
        assert!(fn_is_dir(&e(b"d/", 3)));
        assert!(!fn_is_dir(&e(b"d", 3)));
        assert!(!fn_is_dir(&e(b"", 0)));
        assert!(fn_is_dir(&e(b"d\\", 0)));
        assert!(!fn_is_dir(&e(b"d\\", 3)));
        assert!(!fn_is_dir(&e(b"a/d\\", 0)));
    }
}
