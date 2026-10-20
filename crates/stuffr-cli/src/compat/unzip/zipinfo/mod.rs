//! `zipinfo.c`'s listing half: the end-of-central-directory report
//! (`zi_end_central()`), the directory loop and its totals (`zipinfo()`),
//! the times (`zi_time()`); the one-line formats `-s`, `-m`, `-l`
//! (`short.rs`: `zi_short()`), the `-v` report (`long.rs`: `zi_long()`) and
//! its extra-field dump (`extra.rs`, with `zi_showMacTypeCreator()`).
//! `zi_opts()` is in `cli.rs`.
//!
//! **zipinfo's loop is not list.c's** (`process::walk_central`): it reads
//! an entry's extra field only when the entry is selected, after the
//! match; an error ends the loop with `break` (the totals and the cautions
//! still follow, under the C's conditions) instead of returning; a failed
//! extra-field read drops the field (`G.extra_field = NULL`), so `-v` then
//! answers `PK_ERR` for that entry. It reuses `process_cdir_file_hdr`,
//! `read_filename`, `read_extra_field` (`getZip64Data()` included) and
//! `selected`.
//!
//! Every count and size from the archive drives a loop or a format, never
//! an allocation beyond the field it came from (an extra field is at most
//! 64 KiB, held already by `CentralEntry`).
//!
//! The C's fixed buffers (`attribs[16]`, `methbuf[5]`, `filenameBuf[32]`)
//! overflow on some archive values; each such place is ruled (`// ruling:`)
//! and pinned by `compat_unzip_apple.rs`'s `zipinfo_rulings`.

use super::fileio::{self, DoString, c_str};
use super::list::ratio;
use super::messages as m;
use super::process::{self, CENTRAL_HDR_SIG, CentralEntry};
use super::{PK_BADERR, PK_COOL, PK_EOF, PK_FIND, PK_WARN, Uz};

mod extra;
mod long;
mod short;

#[cfg(test)]
mod tests;

/// unzpriv.h's `NUM_HOSTS`.
pub(super) const NUM_HOSTS: u8 = 31;
/// unzpriv.h's `NUM_METHODS`.
pub(super) const NUM_METHODS: usize = 17;
/// unzpriv.h's `LREC_SIZE` (after the signature).
const LREC_SIZE: u64 = 26;

/// unzpriv.h's host numbers zipinfo.c tests.
pub(super) const FS_FAT_: u8 = 0;
pub(super) const AMIGA_: u8 = 1;
pub(super) const VMS_: u8 = 2;
pub(super) const UNIX_: u8 = 3;
pub(super) const VM_CMS_: u8 = 4;
pub(super) const FS_HPFS_: u8 = 6;
pub(super) const FS_NTFS_: u8 = 11;
pub(super) const ACORN_: u8 = 13;
pub(super) const FS_VFAT_: u8 = 14;
pub(super) const MVS_: u8 = 15;
pub(super) const THEOS_: u8 = 18;

/// unzpriv.h's method numbers zipinfo.c tests.
pub(super) const IMPLODED: u16 = 6;
pub(super) const DEFLATED: u16 = 8;
pub(super) const ENHDEFLATED: u16 = 9;

/// `FmZofft(v, NULL, "u")`: `%llu`.
pub(super) fn zu(v: u64) -> Vec<u8> {
    v.to_string().into_bytes()
}

/// `FmZofft(v, "<w>", "u")`: `%<w>llu`.
pub(super) fn zu_w(v: u64, w: usize) -> Vec<u8> {
    format!("{v:>w$}").into_bytes()
}

/// `FmZofft(v, FZOFFT_HEX_DOT_WID, "X")`: `%.16llX`.
pub(super) fn zx(v: u64) -> Vec<u8> {
    format!("{v:016X}").into_bytes()
}

// port: zipinfo.c:zi_end_central
/// What zipinfo says about the end records, after `find_ecrec()` found
/// them: `-v`'s report, else under `-h` the size and entry count.
pub(crate) fn zi_end_central(uz: &mut Uz) {
    if uz.o.lflag > 9 {
        // verbose format
        uz.info(0, m::END_CENT_DIR_REC.as_bytes());
        uz.info(0, m::LINE_SEPARATORS.as_bytes());

        let ziplen = uz.zin.ziplen;
        let size = format!("{ziplen:>11}").into_bytes();
        uz.info_fmt(0, m::ZIP_FSIZE_VERBOSE, &[&size, &zx(ziplen as u64)]);
        let (real, expect) = (uz.real_ecrec_offset as u64, uz.expect_ecrec_offset as u64);
        uz.info_fmt(
            0,
            m::ACT_OFFSET_CENT_DIR,
            &[&zu_w(real, 11), &zx(real), &zu_w(expect, 11), &zx(expect)],
        );

        let ec = uz.ecrec;
        let entries = |n: u64| if n == 1 { m::ENTRY } else { m::ENTRIES };
        if ec.number_this_disk == 0 {
            uz.info_fmt(
                0,
                m::SINGLE_PART_ARCHIVE1,
                &[
                    &zu(ec.total_entries_central_dir),
                    entries(ec.total_entries_central_dir).as_bytes(),
                    &zu(ec.size_central_directory),
                    &zx(ec.size_central_directory),
                ],
            );
            uz.info_fmt(
                0,
                m::SINGLE_PART_ARCHIVE2,
                &[
                    &zu(ec.offset_start_central_directory),
                    &zx(ec.offset_start_central_directory),
                ],
            );
        } else {
            uz.info_fmt(
                0,
                m::MULTI_PART_ARCHIVE1,
                &[
                    &zu(ec.number_this_disk.wrapping_add(1)),
                    &zu(ec.num_disk_start_cdir.wrapping_add(1)),
                ],
            );
            uz.info_fmt(
                0,
                m::MULTI_PART_ARCHIVE2,
                &[
                    &zu(ec.offset_start_central_directory),
                    &zx(ec.offset_start_central_directory),
                    &zu(ec.size_central_directory),
                    &zx(ec.size_central_directory),
                ],
            );
            let this = ec.num_entries_centrl_dir_ths_disk;
            let verb = if this == 1 { m::IS } else { m::ARE };
            uz.info_fmt(
                0,
                m::MULTI_PART_ARCHIVE3,
                &[
                    &zu(this),
                    verb.as_bytes(),
                    &zu(ec.total_entries_central_dir),
                    entries(ec.total_entries_central_dir).as_bytes(),
                ],
            );
        }
    } else if uz.o.hflag {
        // print zip file size and number of contained entries:
        let size = uz.zin.ziplen.to_string().into_bytes();
        uz.info_fmt(
            0,
            m::ZIP_INF_HEADER2,
            &[&size, &zu(uz.ecrec.total_entries_central_dir)],
        );
    }
}

/// `SKIP_(length)` in zipinfo.c: step over `length` bytes when there are
/// any. `Some(error)` when the step was taken (the C assigns `error` only
/// then); `do_string(SKIP)` never fails, so it is always `PK_COOL`.
fn skip(uz: &mut Uz, length: u16) -> Option<i32> {
    (length != 0).then(|| fileio::do_string(uz, usize::from(length), DoString::Skip, None))
}

// port: zipinfo.c:zipinfo
/// zipinfo's listing of the archive whose central directory starts at the
/// current position: one line (or report) per selected entry in the
/// format `uO.lflag` names, the totals under `-t`, the cautions for
/// patterns nothing matched, the end-record check. Returns the PK code
/// (`PK_FIND` when nothing was listed).
pub(crate) fn zipinfo(uz: &mut Uz) -> i32 {
    let mut error_in_archive = PK_COOL;
    let mut members: u64 = 0;
    let (mut tot_csize, mut tot_ucsize) = (0u64, 0u64);

    // Space for check on unmatched filespecs (one flag per pattern).
    let mut fn_matched = vec![false; uz.pfnames.len()];
    let mut xn_matched = vec![false; uz.pxnames.len()];

    uz.o.l_flag = 0; // zipinfo mode: never convert name to lowercase

    // reset endprev for new zipfile; account for multi-part archives (?)
    let mut endprev: u64 = if uz.crec_relative_offset_local_header == 4 {
        4
    } else {
        0
    };

    let mut j: u64 = 1;
    loop {
        if process::read_sig(uz) == 0 {
            error_in_archive = PK_EOF;
            break;
        }
        if uz.sig != CENTRAL_HDR_SIG {
            // is it a CentDir entry?
            // no new central directory entry -> is the number of processed
            // entries compatible with the number of entries as stored in
            // the end_central record?
            let mask = if uz.ecrec.have_ecr64 {
                u64::MAX
            } else {
                0xffff
            };
            if (j.wrapping_sub(1) & mask) == uz.ecrec.total_entries_central_dir {
                // "j modulus 4T/64k" matches the reported 64/16-bit-unsigned
                // number of directory entries -> probably, the regular end
                // of the central directory has been reached
                break;
            }
            let n = j.to_string();
            uz.info_fmt(0x401, m::CENT_SIG_MSG, &[n.as_bytes()]);
            // apple: zipinfo.c:774 (`"%s"`)
            uz.info(0x401, m::REPORT_MSG.as_bytes());
            error_in_archive = PK_BADERR; // sig not found
            break;
        }
        // process_cdir_file_hdr() sets pInfo->hostnum, pInfo->lcflag, ...:
        let mut e = match process::process_cdir_file_hdr(uz) {
            Ok(e) => e,
            Err(code) => {
                error_in_archive = code; // only PK_EOF defined
                break;
            }
        };
        e.index = j;
        uz.crec_relative_offset_local_header = e.relative_offset_local_header;

        let pinfo = e.pinfo;
        // (The C's `error` is the function's; every iteration sets it here
        // before reading it.)
        let mut error = fileio::read_filename(uz, usize::from(e.filename_length), &pinfo, false);
        if error != PK_COOL {
            if error > error_in_archive {
                error_in_archive = error;
            }
            if error > PK_WARN {
                // fatal
                break;
            }
        }
        e.filename = c_str(&uz.filename).to_vec();

        // check if specified on command line
        let do_this_file = process::selected(
            uz,
            &e.filename,
            Some(&mut fn_matched),
            Some(&mut xn_matched),
        );

        // If current file was specified on command line, or if no names
        // were specified, do the listing for this file.  Otherwise, get rid
        // of the file comment and go back for the next file.
        if do_this_file {
            // Read the extra field, if any.  The extra field info is
            // required for resolving the Zip64 sizes/offsets and may be used
            // in more analysis of the entry below.
            error = process::read_extra_field(uz, &mut e);
            if error != 0 {
                e.extra = None; // free(G.extra_field)
                error_in_archive = error;
                // The premature return in case of a "fatal" error (PK_EOF)
                // is delayed until we analyze the extra field contents.
            }
            uz.crec_relative_offset_local_header = e.relative_offset_local_header;

            match uz.o.lflag {
                1 | 2 => {
                    fileio::fnprint(uz);
                    if let Some(err) = skip(uz, e.file_comment_length) {
                        error = err;
                    }
                }
                3..=5 => {
                    error = short::zi_short(uz, &e);
                    if error != PK_COOL {
                        error_in_archive = error; // might be warning
                    }
                }
                10 => {
                    let n = j.to_string();
                    uz.info_fmt(0, m::CENTRAL_DIR_ENTRY, &[n.as_bytes()]);
                    error = long::zi_long(uz, &e, &mut endprev, error_in_archive);
                    if error != PK_COOL {
                        error_in_archive = error; // might be warning
                    }
                }
                _ => {
                    if let Some(err) = skip(uz, e.file_comment_length) {
                        error = err;
                    }
                }
            }
            if error > PK_WARN {
                // fatal
                break;
            }

            tot_csize = tot_csize.wrapping_add(e.csize);
            tot_ucsize = tot_ucsize.wrapping_add(e.ucsize);
            if e.general_purpose_bit_flag & 1 != 0 {
                tot_csize = tot_csize.wrapping_sub(12); // don't count encryption header
            }
            members += 1;
        } else {
            // not listing this file (the C's `error` from these two is
            // overwritten before it is read again)
            skip(uz, e.extra_field_length);
            skip(uz, e.file_comment_length);
            if endprev != 0 {
                endprev = 0;
            }
        }
        j = j.wrapping_add(1);
    }

    // Check that we actually found requested files; if so, print totals.
    if error_in_archive <= PK_WARN && uz.o.tflag {
        let r = ratio(tot_ucsize, tot_csize);
        let sgn: &[u8] = if r < 0 { b"-" } else { b"" };
        // ruling: `cfactor = -cfactor` of INT_MIN overflows `int`
        // (undefined behaviour). Both references print its magnitude,
        // 2147483648 tenths (`-214748364.8%`: clang and gcc take the negated
        // value as non-negative), and so does this.
        // probe: zipinfo -t of an entry of 1000 bytes stored in 2^31 + 1000
        let cfactor = r.unsigned_abs();
        let plural: &[u8] = if members == 1 {
            b""
        } else {
            m::PLUR_SUFX.as_bytes()
        };
        let (n, whole, tenth) = (
            members.to_string(),
            (cfactor / 10).to_string(),
            (cfactor % 10).to_string(),
        );
        uz.info_fmt(
            0,
            m::ZIPFILE_STATS,
            &[
                n.as_bytes(),
                plural,
                &zu(tot_ucsize),
                &zu(tot_csize),
                sgn,
                whole.as_bytes(),
                tenth.as_bytes(),
            ],
        );
    }

    // Check for unmatched filespecs on command line and print warning if
    // any found.
    if error_in_archive <= PK_WARN {
        let names = uz.pfnames.clone();
        for (name, _) in names.iter().zip(&fn_matched).filter(|(_, hit)| !**hit) {
            uz.info_fmt(0x401, m::FILENAME_NOT_MATCHED, &[name]);
        }
        let names = uz.pxnames.clone();
        for (name, _) in names.iter().zip(&xn_matched).filter(|(_, hit)| !**hit) {
            uz.info_fmt(0x401, m::EXCL_FILENAME_NOT_MATCHED, &[name]);
        }
    }

    // Skip the following checks in case of a premature listing break.
    if error_in_archive <= PK_WARN {
        // Double check that we're back at the end-of-central-directory
        // record.
        let sig = uz.sig;
        let want = if uz.ecrec.have_ecr64 {
            process::END_CENTRAL64_SIG
        } else {
            process::END_CENTRAL_SIG
        };
        if sig != want && !uz.ecrec.is_zip64_archive && sig != process::END_CENTRAL_SIG {
            // just to make sure again
            // apple: zipinfo.c:963 (`"%s"`)
            uz.info(0x401, m::END_SIG_MSG.as_bytes());
            error_in_archive = PK_WARN; // didn't find sig
        }

        // Set specific return code when no files have been found.
        if members == 0 && error_in_archive <= PK_WARN {
            error_in_archive = PK_FIND;
        }

        if uz.o.lflag >= 10 {
            uz.info(0, b"\n");
        }
    }
    error_in_archive
}

/// Which clock `zi_time()` shows a Unix time on: `d_t_str[0]` set to 0
/// ("show local time") or 1 ("show UTC (GMT) time").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Clock {
    Local,
    Utc,
}

// port: zipinfo.c:zi_time
/// The entry's time as zipinfo prints it: `1991 Feb 23 17:15:00` (`-v`),
/// `19910223.171500` (`-T`) or `91-Feb-23 17:15`. `modtimez` is a Unix
/// time from the `UT` extra field, shown on `clock`; without one, the
/// MS-DOS date and time `datetimez` as stored. A month outside 1..12 shows
/// as its number (`%03d`).
pub(super) fn zi_time(uz: &Uz, datetimez: u32, modtimez: Option<i64>, clock: Clock) -> Vec<u8> {
    let t = match modtimez {
        Some(mt) => {
            // check for our secret message from above...
            let t = match clock {
                Clock::Utc => Some(fileio::gmtime(mt)),
                Clock::Local => fileio::localtime(uz, mt),
            };
            if uz.o.lflag > 9 && t.is_none() {
                // time conversion error in verbose listing format, return
                // string with '?' instead of data
                return m::LNG_YMDHMS_TIME_ERROR.as_bytes().to_vec();
            }
            t
        }
        None => None,
    };
    // `unsigned` fields: `tm_year` is the year less 1900.
    let (yr, mo, dy, hh, mm, ss) = match t {
        Some(t) => ((t.year - 1900) as u32, t.mon, t.mday, t.hour, t.min, t.sec),
        None => (
            ((datetimez >> 25) & 0x7f) + 80,
            (datetimez >> 21) & 0x0f,
            (datetimez >> 16) & 0x1f,
            (datetimez >> 11) & 0x1f,
            (datetimez >> 5) & 0x3f,
            (datetimez << 1) & 0x3e,
        ),
    };

    let monthbuf;
    let monthstr: &[u8] = if mo == 0 || mo > 12 {
        monthbuf = format!("{mo:03}").into_bytes(); // BogusFmt, %03d
        &monthbuf
    } else {
        m::MONTHS[(mo - 1) as usize].as_bytes()
    };

    if uz.o.lflag > 9 {
        // verbose listing format
        m::lng_ymdhms_time(yr.wrapping_add(1900), monthstr, dy, hh, mm, ss)
    } else if uz.o.t_flag {
        m::decimal_time(yr.wrapping_add(1900), mo, dy, hh, mm, ss)
    } else {
        // was:  if ((uO.lflag >= 3) && (uO.lflag <= 5))
        m::sht_ymdhm_time(yr % 100, monthstr, dy, hh, mm)
    }
}

/// The entry's `UT` modification time from its central extra field, if it
/// has one (`ef_scan_for_izux(..., 1, ...) & EB_UT_FL_MTIME`).
pub(super) fn ut_mtime(e: &CentralEntry) -> Option<i64> {
    let ef = e.extra.as_deref()?;
    let mut z_utime = process::IzTimes::default();
    let flags = process::ef_scan_for_izux(ef, true, e.last_mod_dos_datetime, Some(&mut z_utime));
    (flags & process::EB_UT_FL_MTIME != 0).then_some(z_utime.mtime)
}

/// zi_long()'s and zi_short()'s `endprev` step: where the next local
/// header should start (`relative_offset_local_header + 4 + LREC_SIZE +
/// filename_length + extra_field_length + csize`, unsigned 64-bit).
pub(super) fn next_endprev(e: &CentralEntry) -> u64 {
    e.relative_offset_local_header
        .wrapping_add(4 + LREC_SIZE)
        .wrapping_add(u64::from(e.filename_length))
        .wrapping_add(u64::from(e.extra_field_length))
        .wrapping_add(e.csize)
}
