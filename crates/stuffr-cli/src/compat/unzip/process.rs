//! `process.c`: the archives of a run (`process_zipfiles()`, with
//! `unix.c`'s `do_wild()` for a wildcard archive name), one archive's
//! opening (`do_seekable()`), its end-of-central-directory records
//! (`process/end.rs`: `find_ecrec()`, `rec_find()`, `find_ecrec64()`,
//! `process_zip_cmmnt()`) and its directory entries (`process_cdir_file_hdr()`, `get_cdir_ent()`,
//! `process_local_file_hdr()`, `getZip64Data()`, `ef_scan_for_izux()`).
//!
//! [`walk_central`] is list.c's loop over the central directory, shared by
//! the listings; [`selected`] is the include/exclude test every loop makes.
//! `check_ecrec_zip64()` is `#if 0` in the C and has no port. Apple's
//! build has no `UNICODE_SUPPORT`, so `getUnicodeData()` is Task 13's.
//!
//! Every count and offset from the archive drives a loop or a seek, never
//! an allocation: a name, an extra field or a comment is at most 64 KiB.

use super::fileio::{self, PInfo, readbuf, seek_zipf};
use super::matching::{iswild, matches};
use super::messages as m;
use super::{
    IZ_DIR, PK_BADERR, PK_COOL, PK_EOF, PK_ERR, PK_FIND, PK_NOZIP, PK_OK, PK_WARN, Uz, flavour,
    list, unix,
};
use crate::compat::host;

/// The central directory header's signature, `PK\1\2`.
pub(crate) const CENTRAL_HDR_SIG: [u8; 4] = *b"PK\x01\x02";
/// The local header's, `PK\3\4`.
pub(crate) const LOCAL_HDR_SIG: [u8; 4] = *b"PK\x03\x04";
/// The end-of-central-directory record's, `PK\5\6`.
pub(crate) const END_CENTRAL_SIG: [u8; 4] = *b"PK\x05\x06";
/// The Zip64 end-of-central-directory locator's, `PK\6\7`.
pub(crate) const END_CENTLOC64_SIG: [u8; 4] = *b"PK\x06\x07";
/// The Zip64 end-of-central-directory record's, `PK\6\6`.
pub(crate) const END_CENTRAL64_SIG: [u8; 4] = *b"PK\x06\x06";

/// unzpriv.h's record lengths (after the signature).
const LREC_SIZE: usize = 26;
const CREC_SIZE: usize = 42;
const ECREC_SIZE: usize = 18;
const ECLOC64_SIZE: usize = 16;
const ECREC64_SIZE: usize = 52;

/// unzpriv.h's `NUM_HOSTS`.
const NUM_HOSTS: u8 = 31;
/// unzpriv.h's host numbers `process_cdir_file_hdr()` tests.
const VMS_: u8 = 2;
const VM_CMS_: u8 = 4;
const ATARI_: u8 = 5;
const CPM_: u8 = 9;
const TOPS20_: u8 = 10;
const MVS_: u8 = 15;
const TANDEM_: u8 = 17;

/// unzpriv.h's extra field block ids and offsets.
const EB_HEADSIZE: usize = 4;
const EF_PKSZ64: u16 = 0x0001;
const EF_PKUNIX: u16 = 0x000d;
const EF_IZUNIX: u16 = 0x5855;
const EF_IZUNIX2: u16 = 0x7855;
const EF_IZUNIX3: u16 = 0x7875;
const EF_TIME: u16 = 0x5455;
const EB_UX_MINLEN: usize = 8;
const EB_UX_FULLSIZE: usize = 12;
const EB_UX_UID: usize = 8;
const EB_UX_GID: usize = 10;
const EB_UX2_MINLEN: usize = 4;
const EB_UX3_MINLEN: usize = 7;
const EB_UX_ATIME: usize = 0;
const EB_UX_MTIME: usize = 4;
const EB_UT_MINLEN: usize = 1;
const EB_UT_FLAGS: usize = 0;
const EB_UT_TIME1: usize = 1;
/// unzpriv.h's `EB_UT_FL_*`: which times an `EF_TIME` block holds.
pub(crate) const EB_UT_FL_MTIME: u32 = 1 << 0;
pub(crate) const EB_UT_FL_ATIME: u32 = 1 << 1;
pub(crate) const EB_UT_FL_CTIME: u32 = 1 << 2;

/// unzpriv.h's `MASK_ZUCN16`: the classic record's 16-bit entry count.
const MASK_ZUCN16: u64 = 0xffff;

/// `G.ecrec`: the end-of-central-directory record (`ecdir_rec`), Zip64
/// values merged in by `find_ecrec64()`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Ecrec {
    pub number_this_disk: u64,
    pub num_disk_start_cdir: u64,
    pub num_entries_centrl_dir_ths_disk: u64,
    pub total_entries_central_dir: u64,
    pub size_central_directory: u64,
    pub offset_start_central_directory: u64,
    pub zipfile_comment_length: u16,
    /// A Zip64 record was found and agrees with the classic one.
    pub have_ecr64: bool,
    /// Some field needed the Zip64 record's value.
    pub is_zip64_archive: bool,
}

/// `G.lrec`: the last local file header read (`local_file_hdr`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Lrec {
    pub version_needed_to_extract: [u8; 2],
    pub general_purpose_bit_flag: u16,
    pub compression_method: u16,
    pub last_mod_dos_datetime: u32,
    pub crc32: u32,
    pub csize: u64,
    pub ucsize: u64,
    pub filename_length: u16,
    pub extra_field_length: u16,
}

/// One central directory entry: every field of `G.crec` (`cdir_file_hdr`,
/// after `getZip64Data()` and `process_cdir_file_hdr()`'s adjustments),
/// the `G.pInfo` fields `process_cdir_file_hdr()` sets, and what follows
/// the header: the name as `G.filename` holds it, the extra field
/// (`G.extra_field`). The comment, `file_comment_length` bytes, follows in
/// the archive: the walk's callback reads or skips it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CentralEntry {
    /// `j`: the entry's number in the directory, from 1.
    pub index: u64,
    pub version_made_by: [u8; 2],
    pub version_needed_to_extract: [u8; 2],
    pub general_purpose_bit_flag: u16,
    pub compression_method: u16,
    pub last_mod_dos_datetime: u32,
    pub crc32: u32,
    pub csize: u64,
    pub ucsize: u64,
    pub filename_length: u16,
    pub extra_field_length: u16,
    pub file_comment_length: u16,
    pub disk_number_start: u64,
    pub internal_file_attributes: u16,
    pub external_file_attributes: u64,
    pub relative_offset_local_header: u64,
    /// `G.pInfo`'s host, case and label fields.
    pub pinfo: PInfo,
    /// `G.filename`: the name as read (a C string: up to its first NUL),
    /// converted, lowercased under `lcflag`.
    pub filename: Vec<u8>,
    /// `G.extra_field`: `None` when the length is 0.
    pub extra: Option<Vec<u8>>,
}

/// The times `ef_scan_for_izux()` returns (`iztimes`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct IzTimes {
    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,
}

// port: process.c:process_zipfiles
/// Every archive the operand names (a wildcard is expanded in the
/// operand's directory), each through `do_seekable()`; when a single
/// candidate failed, again with `.zip` and `.ZIP` added; then, for a
/// wildcard, the summary. Returns the run's PK code.
pub(crate) fn process_zipfiles(uz: &mut Uz, parsed: &super::cli::Parsed) -> i32 {
    uz.wildzipfn = super::cli::bytes(&parsed.archive);
    uz.pfnames = parsed
        .include
        .iter()
        .map(|a| super::cli::bytes(a))
        .collect();
    uz.pxnames = parsed
        .exclude
        .iter()
        .map(|a| super::cli::bytes(a))
        .collect();

    // Initialize the internal flag holding the mode of processing
    // "overwrite existing file" cases.  In case of conflicting options, the
    // 'safer' flag uO.overwrite_none takes precedence.
    uz.overwrite_mode = if uz.o.overwrite_none {
        super::extract::OVERWRT_NEVER
    } else if uz.o.overwrite_all != 0 {
        super::extract::OVERWRT_ALWAYS
    } else {
        super::extract::OVERWRT_QUERY
    };

    let mut error = 0;
    let mut error_in_archive = 0;
    let mut lastzipfn: Option<Vec<u8>> = None;
    let (mut num_win, mut num_lose, mut num_warn) = (0i32, 0i32, 0i32);
    let (mut num_miss_dirs, mut num_miss_files) = (0i32, 0i32);

    // Make sure timezone info is set correctly (tzset(): `fileio::localtime`
    // calls it).
    let wild = uz.wildzipfn.clone();
    let mut w = unix::Wild::new();
    while let Some(zipfn) = w.do_wild(uz, &wild) {
        uz.zipfn = zipfn.clone();
        lastzipfn = Some(zipfn);

        // print a blank line between the output of different zipfiles
        if uz.o.qflag == 0
            && error != PK_NOZIP
            && error != IZ_DIR
            && (!uz.o.t_flag || uz.o.zipinfo_mode)
            && (num_win + num_lose + num_warn + num_miss_files) > 0
        {
            uz.info(0, b"\n");
        }

        error = do_seekable(uz, false);
        // readbyte()'s `EXIT(PK_BADERR)` after a read error
        if let Some(code) = uz.abort {
            return code;
        }
        if error == PK_WARN {
            num_warn += 1;
        } else if error == IZ_DIR {
            num_miss_dirs += 1;
        } else if error == PK_NOZIP {
            num_miss_files += 1;
        } else if error != PK_OK {
            num_lose += 1;
        } else {
            num_win += 1;
        }
        if error != IZ_DIR && error > error_in_archive {
            error_in_archive = error;
        }
    } // end while-loop (wildcard zipfiles)

    if (num_win + num_warn + num_lose) == 0
        && (num_miss_dirs + num_miss_files) == 1
        && let Some(mut last) = lastzipfn
    {
        // Although we already "know" the failure result, we call
        // do_seekable() again with the same zipfile name (and the
        // lastchance flag set), just to trigger the error report...
        let p = last.len();
        last.extend_from_slice(m::ZSUFX.as_bytes());
        uz.zipfn = last;

        num_miss_dirs = 0;
        num_miss_files = 0;
        error_in_archive = PK_COOL;

        // only Unix has case-sensitive filesystems
        error = do_seekable(uz, false);
        if error == PK_NOZIP || error == IZ_DIR {
            if error == IZ_DIR {
                num_miss_dirs += 1;
            }
            uz.zipfn.truncate(p);
            uz.zipfn.extend_from_slice(m::ALT_ZSUFX.as_bytes());
            error = do_seekable(uz, true);
        }
        match error {
            PK_WARN => num_warn += 1,
            IZ_DIR => {
                num_miss_dirs += 1;
                error = PK_NOZIP;
            }
            // increment again => bug: "1 file had no zipfile directory."
            PK_NOZIP => {}
            _ => {
                if error != 0 {
                    num_lose += 1;
                } else {
                    num_win += 1;
                }
            }
        }
        if error > error_in_archive {
            error_in_archive = error;
        }
    }

    // Print summary of all zipfiles, assuming zipfile spec was a wildcard
    // (no need for a summary if just one zipfile).
    let o = &uz.o;
    if iswild(&uz.wildzipfn) && o.qflag < 3 && !(o.t_flag && !o.zipinfo_mode && o.qflag > 1) {
        if (num_miss_files + num_lose + num_warn > 0 || num_win != 1)
            && !(o.t_flag && !o.zipinfo_mode && o.qflag != 0)
            && !(o.tflag && o.qflag > 1)
        {
            uz.info(0x401, b"\n");
        }
        if num_win > 1 || (num_win == 1 && num_miss_dirs + num_miss_files + num_lose + num_warn > 0)
        {
            let n = num_win.to_string();
            let s: &[u8] = if num_win == 1 { b" was" } else { b"s were" };
            uz.info_fmt(0x401, m::FILES_PROCESS_OK, &[n.as_bytes(), s]);
        }
        if num_warn > 0 {
            let n = num_warn.to_string();
            let s: &[u8] = if num_warn == 1 { b"" } else { b"s" };
            uz.info_fmt(0x401, m::ARCHIVE_WARNING, &[n.as_bytes(), s]);
        }
        if num_lose > 0 {
            let n = num_lose.to_string();
            let s: &[u8] = if num_lose == 1 { b"" } else { b"s" };
            uz.info_fmt(0x401, m::ARCHIVE_FATAL_ERROR, &[n.as_bytes(), s]);
        }
        if num_miss_files > 0 {
            let n = num_miss_files.to_string();
            let s: &[u8] = if num_miss_files == 1 { b"" } else { b"s" };
            uz.info_fmt(0x401, m::FILE_HAD_NO_ZIPFILE_DIR, &[n.as_bytes(), s]);
        }
        if num_miss_dirs == 1 {
            uz.info(0x401, m::ZIPFILE_WAS_DIR.as_bytes());
        } else if num_miss_dirs > 0 {
            let n = num_miss_dirs.to_string();
            uz.info_fmt(0x401, m::MANY_ZIPFILES_WERE_DIR, &[n.as_bytes()]);
        }
        if num_win + num_lose + num_warn == 0 {
            uz.info(0x401, m::NO_ZIPFILE_FOUND.as_bytes());
        }
    }
    error_in_archive
}

/// `uO.zipinfo_mode ? "zipinfo" : "unzip"` (`Zipnfo`, `Unzip`).
fn who(uz: &Uz) -> &'static [u8] {
    if uz.o.zipinfo_mode {
        m::ZIPNFO.as_bytes()
    } else {
        m::UNZIP.as_bytes()
    }
}

/// `CLOSE_INFILE()`.
fn close_infile(uz: &mut Uz) {
    uz.zin.fd = None;
}

// port: fileio.c:open_input_file
/// Open `G.zipfn` for reading: 1 (after `CannotOpenZipfile`) on failure.
/// Every open goes through `Host::track` (R7).
fn open_input_file(uz: &mut Uz) -> i32 {
    let path = uz.host.path(&uz.zipfn);
    match std::fs::File::open(&path) {
        Ok(f) => {
            // apple: fileio.c:262 (`qtn_file_init_with_fd` on the archive,
            // R9; deviation 7: both flavours on macOS)
            uz.qf = super::unix::attrs::archive_quarantine(&uz.host, &f);
            uz.zin.fd = Some(uz.host.track(&path, f));
            0
        }
        Err(e) => {
            let zipfn = uz.zipfn.clone();
            uz.info_fmt(
                0x401,
                m::CANNOT_OPEN_ZIPFILE,
                &[&zipfn, &host::strerror(&e)],
            );
            1
        }
    }
}

// port: process.c:do_seekable
/// One archive, `G.zipfn`: find its end records, check them, then list,
/// test or extract it. With `lastchance`, a missing archive is reported.
fn do_seekable(uz: &mut Uz, lastchance: bool) -> i32 {
    let mut too_weird_to_continue = false;
    let mut uxstamp = 0i64;
    let mut nmember = 0u64;

    // Open the zipfile for reading in BINARY mode to prevent CR/LF
    // translation, which would corrupt the bit streams.
    let path = uz.host.path(&uz.zipfn);
    let stat = std::fs::metadata(&path);
    let is_dir = stat.as_ref().is_ok_and(|md| md.is_dir());
    let Some(meta) = stat.ok().filter(|md| !md.is_dir()) else {
        if lastchance && uz.o.qflag < 3 {
            let (wild, zipfn) = (uz.wildzipfn.clone(), uz.zipfn.clone());
            if uz.no_ecrec {
                let gap: &[u8] = if uz.o.zipinfo_mode { b"  " } else { b"" };
                uz.info_fmt(
                    1,
                    m::CANNOT_FIND_ZIPFILE_DIR_MSG,
                    &[who(uz), &wild, gap, &wild, &zipfn],
                );
            } else {
                uz.info_fmt(
                    1,
                    m::CANNOT_FIND_EITHER_ZIPFILE,
                    &[who(uz), &wild, &wild, &zipfn],
                );
            }
        }
        return if is_dir { IZ_DIR } else { PK_NOZIP };
    };
    uz.zin.ziplen = meta.len() as i64;

    // no extension on Unix exes:  might find unzip, not unzip.zip; etc.
    #[cfg(unix)]
    let maybe_exe = {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o100 != 0
    };
    #[cfg(not(unix))]
    let maybe_exe = false;

    if open_input_file(uz) != 0 {
        // this should never happen, given the stat() test above, but...
        return PK_NOZIP;
    }

    // Find and process the end-of-central-directory header.  UnZip need
    // only check last 65557 bytes of zipfile; ZipInfo searches the whole
    // zipfile.
    uz.zin.cur_zipfile_bufstart = 0;
    uz.zin.inptr = 0;

    if (!uz.o.zipinfo_mode && uz.o.qflag == 0 && !uz.o.t_flag) || (uz.o.zipinfo_mode && uz.o.hflag)
    {
        let zipfn = uz.zipfn.clone();
        uz.info_fmt(0, m::LOG_INITLINE, &[&zipfn]);
    }

    let searchlen = if uz.o.zipinfo_mode {
        uz.zin.ziplen
    } else {
        uz.zin.ziplen.min(66000)
    };
    let mut error_in_archive = end::find_ecrec(uz, searchlen);
    if uz.abort.is_some() {
        // `q` at the comment's `^S` pause in a sandbox: the C has exited
        close_infile(uz);
        return PK_COOL;
    }
    if error_in_archive > PK_WARN {
        close_infile(uz);
        if maybe_exe {
            let zipfn = uz.zipfn.clone();
            uz.info_fmt(0x401, m::MAYBE_EXE, &[&zipfn]);
        }
        if lastchance {
            return error_in_archive;
        }
        uz.no_ecrec = true; // assume we found wrong file:  e.g.,
        return PK_NOZIP; //  unzip instead of unzip.zip
    }

    if uz.o.zflag > 0 && !uz.o.zipinfo_mode {
        // unzip: zflag = comment ONLY
        close_infile(uz);
        return error_in_archive;
    }

    // Test the end-of-central-directory info for incompatibilities
    // (multi-disk archives) or inconsistencies (missing or extra bytes in
    // zipfile).
    let ecrec = uz.ecrec;
    let multi = !uz.o.zipinfo_mode && ecrec.number_this_disk != 0;

    if uz.o.zipinfo_mode && ecrec.number_this_disk != ecrec.num_disk_start_cdir {
        let zipfn = uz.zipfn.clone();
        let (a, b) = (
            ecrec.number_this_disk.to_string(),
            ecrec.num_disk_start_cdir.to_string(),
        );
        if ecrec.number_this_disk > ecrec.num_disk_start_cdir {
            uz.info_fmt(
                0x401,
                m::CENT_DIR_NOT_IN_ZIP_MSG,
                &[&zipfn, a.as_bytes(), b.as_bytes()],
            );
            error_in_archive = PK_FIND;
            too_weird_to_continue = true;
        } else {
            uz.info_fmt(
                0x401,
                m::END_CENT_DIR_BOGUS,
                &[&zipfn, a.as_bytes(), b.as_bytes()],
            );
            error_in_archive = PK_WARN;
        }
    }

    if !too_weird_to_continue {
        // (relatively) normal zipfile:  go for it
        if multi {
            let zipfn = uz.zipfn.clone();
            uz.info_fmt(0x401, m::MAYBE_PAK_BUG, &[&zipfn]);
            error_in_archive = PK_WARN;
        }
        uz.zin.extra_bytes = uz.real_ecrec_offset.wrapping_sub(uz.expect_ecrec_offset);
        if uz.zin.extra_bytes < 0 {
            let zipfn = uz.zipfn.clone();
            let n = uz.zin.extra_bytes.wrapping_neg().to_string();
            uz.info_fmt(0x401, m::MISSING_BYTES, &[&zipfn, n.as_bytes()]);
            error_in_archive = PK_ERR;
        } else if uz.zin.extra_bytes > 0 {
            if uz.ecrec.offset_start_central_directory == 0 && uz.ecrec.size_central_directory != 0
            {
                // zip 1.5 -go bug
                let zipfn = uz.zipfn.clone();
                uz.info_fmt(0x401, m::NULL_CENT_DIR_OFFSET, &[&zipfn]);
                uz.ecrec.offset_start_central_directory = uz.zin.extra_bytes as u64;
                uz.zin.extra_bytes = 0;
                error_in_archive = PK_ERR;
            } else {
                let zipfn = uz.zipfn.clone();
                let n = uz.zin.extra_bytes.to_string();
                let s: &[u8] = if uz.zin.extra_bytes == 1 { b"" } else { b"s" };
                uz.info_fmt(0x401, m::EXTRA_BYTES_AT_START, &[&zipfn, n.as_bytes(), s]);
                error_in_archive = PK_WARN;
            }
        }

        // Check for empty zipfile and exit now if so.
        if uz.expect_ecrec_offset == 0 && uz.ecrec.size_central_directory == 0 {
            if uz.o.zipinfo_mode {
                let pre: &[u8] = if uz.o.lflag > 9 { b"\n  " } else { b"" };
                uz.info_fmt(0, m::EMPTY_ZIPFILE_ZI, &[pre]);
            } else {
                let zipfn = uz.zipfn.clone();
                uz.info_fmt(0x401, m::ZIPFILE_EMPTY, &[&zipfn]);
            }
            close_infile(uz);
            return if error_in_archive > PK_WARN {
                error_in_archive
            } else {
                PK_WARN
            };
        }

        // Compensate for missing or extra bytes, and seek to where the
        // start of central directory should be.  If header not found,
        // uncompensate and try again.
        let start = uz.ecrec.offset_start_central_directory as i64;
        let mut error = seek_zipf(uz, start);
        if error == PK_BADERR {
            close_infile(uz);
            return PK_BADERR;
        }
        if error != PK_OK || read_sig(uz) == 0 || uz.sig != CENTRAL_HDR_SIG {
            let tmp = uz.zin.extra_bytes;
            uz.zin.extra_bytes = 0;
            error = seek_zipf(uz, start);
            if error != PK_OK || read_sig(uz) == 0 || uz.sig != CENTRAL_HDR_SIG {
                if error != PK_BADERR {
                    let zipfn = uz.zipfn.clone();
                    uz.info_fmt(
                        0x401,
                        m::CENT_DIR_START_NOT_FOUND,
                        &[&zipfn, m::REPORT_MSG.as_bytes()],
                    );
                }
                close_infile(uz);
                return if error != PK_OK { error } else { PK_BADERR };
            }
            let zipfn = uz.zipfn.clone();
            let n = tmp.wrapping_neg().to_string();
            uz.info_fmt(0x401, m::CENT_DIR_TOO_LONG, &[&zipfn, n.as_bytes()]);
            error_in_archive = PK_ERR;
        }

        // Seek to the start of the central directory one last time, since
        // we have just read the first entry's signature bytes; then list,
        // extract or test member files as instructed, and close the
        // zipfile.
        let error = seek_zipf(uz, start);
        if error != PK_OK {
            close_infile(uz);
            return error;
        }

        let error = if uz.o.zipinfo_mode {
            super::zipinfo::zipinfo(uz) // ZIPINFO 'EM
        } else if uz.o.t_flag {
            list::get_time_stamp(uz, &mut uxstamp, &mut nmember)
        } else if uz.o.vflag != 0 && !uz.o.tflag && !uz.o.cflag {
            list::list_files(uz) // LIST 'EM
        } else {
            super::extract::extract_or_test_files(uz) // EXTRACT OR TEST 'EM
        };
        if uz.abort.is_some() {
            return error;
        }

        if error > error_in_archive {
            // don't overwrite stronger error with (for example) a warning
            error_in_archive = error;
        }
    } // end if (!too_weird_to_continue)

    close_infile(uz);

    if uz.o.t_flag && !uz.o.zipinfo_mode && nmember > 0 {
        let zipfn = uz.zipfn.clone();
        if unix::stamp_file(uz, &zipfn, uxstamp).is_err() {
            // TIME-STAMP 'EM
            if uz.o.qflag < 3 {
                uz.info_fmt(0x201, m::ZIP_TIME_STAMP_FAILED, &[&zipfn]);
            }
            if error_in_archive < PK_WARN {
                error_in_archive = PK_WARN;
            }
        } else if uz.o.qflag == 0 {
            uz.info_fmt(0, m::ZIP_TIME_STAMP_SUCCESS, &[&zipfn]);
        }
    }
    error_in_archive
}

/// `readbuf(__G__ G.sig, 4)`: the bytes read into `G.sig`, the rest of it
/// (after a short read) left as it was.
pub(crate) fn read_sig(uz: &mut Uz) -> usize {
    let mut sig = uz.sig;
    let n = readbuf(uz, &mut sig);
    uz.sig = sig;
    n
}

// port: process.c:process_cdir_file_hdr
/// The next central directory header (`get_cdir_ent()`), with `G.pInfo`'s
/// host, lowercase and volume-label fields set from it. `Err(PK_EOF)` when
/// none could be read.
pub(crate) fn process_cdir_file_hdr(uz: &mut Uz) -> Result<CentralEntry, i32> {
    let mut e = get_cdir_ent(uz)?;

    e.pinfo.hostver = e.version_made_by[0];
    e.pinfo.hostnum = e.version_made_by[1].min(NUM_HOSTS);

    e.pinfo.lcflag = false;
    if uz.o.l_flag == 1 {
        // name conversion for monocase systems
        e.pinfo.lcflag = matches!(
            e.pinfo.hostnum,
            fileio::FS_FAT_ | CPM_ | VM_CMS_ | MVS_ | TANDEM_ | TOPS20_ | VMS_
        );
    } else if uz.o.l_flag > 1 {
        // let -LL force lower case for all names
        e.pinfo.lcflag = true;
    }

    // Handle the PKWare verification bit, bit 2 (0x0004) of internal
    // attributes.  If this is set, then a verification checksum is in the
    // first 3 bytes of the external attributes.
    if e.internal_file_attributes & 0x0004 != 0 {
        e.external_file_attributes &= 0xff;
    }

    // do Amigas (AMIGA_) also have volume labels?
    if e.external_file_attributes & 0x08 != 0
        && matches!(
            e.pinfo.hostnum,
            fileio::FS_FAT_ | fileio::FS_HPFS_ | fileio::FS_NTFS_ | ATARI_
        )
    {
        e.pinfo.vollabel = true;
        e.pinfo.lcflag = false; // preserve case of volume labels
    } else {
        e.pinfo.vollabel = false;
    }

    // this flag is needed to detect archives made by "PKZIP for Unix" when
    // deciding which kind of codepage conversion has to be applied to
    // strings (see do_string() function in fileio.c)
    e.pinfo.has_ux_att = e.external_file_attributes & 0xffff_0000 != 0;

    // ubuntu: -DUNICODE_SUPPORT notes general-purpose bit 11 here (Task 13).
    // The symlink flag (`G.pInfo->symlink = 0`) starts false in each
    // `extract::Info`.
    Ok(e)
}

// port: process.c:get_cdir_ent
/// The central directory header's 42 bytes after its signature.
/// ruling: a header cut short by the end of the file leaves the C's
/// `byterec` partly uninitialised; the bytes not read are zeros here.
fn get_cdir_ent(uz: &mut Uz) -> Result<CentralEntry, i32> {
    let mut b = [0u8; CREC_SIZE];
    if readbuf(uz, &mut b) == 0 {
        return Err(PK_EOF);
    }
    let word = |at: usize| fileio::makeword(&b[at..]);
    let long = |at: usize| fileio::makelong(&b[at..]);
    Ok(CentralEntry {
        version_made_by: [b[0], b[1]],
        version_needed_to_extract: [b[2], b[3]],
        general_purpose_bit_flag: word(4),
        compression_method: word(6),
        last_mod_dos_datetime: long(8),
        crc32: long(12),
        csize: u64::from(long(16)),
        ucsize: u64::from(long(20)),
        filename_length: word(24),
        extra_field_length: word(26),
        file_comment_length: word(28),
        disk_number_start: u64::from(word(30)),
        internal_file_attributes: word(32),
        external_file_attributes: u64::from(long(34)), // LONG, not word!
        relative_offset_local_header: u64::from(long(38)),
        ..CentralEntry::default()
    })
}

// port: process.c:process_local_file_hdr
/// The local header at the archive's position into `G.lrec`; with
/// general-purpose bit 3 its CRC and sizes are the central directory's
/// (`G.pInfo`'s, from `e`). Sets `G.csize`. `PK_EOF` when none could be
/// read.
/// ruling: a header cut short leaves the C's `byterec` partly
/// uninitialised; the bytes not read are zeros here.
pub(crate) fn process_local_file_hdr(uz: &mut Uz, e: &CentralEntry) -> i32 {
    let mut b = [0u8; LREC_SIZE];
    if readbuf(uz, &mut b) == 0 {
        return PK_EOF;
    }
    let word = |at: usize| fileio::makeword(&b[at..]);
    let long = |at: usize| fileio::makelong(&b[at..]);
    uz.lrec = Lrec {
        version_needed_to_extract: [b[0], b[1]],
        general_purpose_bit_flag: word(2),
        compression_method: word(4),
        last_mod_dos_datetime: long(6),
        crc32: long(10),
        csize: u64::from(long(14)),
        ucsize: u64::from(long(18)),
        filename_length: word(22),
        extra_field_length: word(24),
    };
    if uz.lrec.general_purpose_bit_flag & 8 != 0 {
        // can't trust local header, use central directory:
        uz.lrec.crc32 = e.crc32;
        uz.lrec.csize = e.csize;
        uz.lrec.ucsize = e.ucsize;
    }
    uz.csize = uz.lrec.csize as i64;
    PK_COOL
}

// port: process.c:getZip64Data
/// The Zip64 extra block (`EF_PKSZ64`) of the extra field `ef`: each of
/// the central (or local) sizes, the local header's offset and the disk
/// number that is all ones takes its 64-bit value, in that order. Every
/// `EF_PKSZ64` block counts (the C's `break` is `#if 0`). `PK_ERR` when a
/// value would run past the rest of the extra field (which the C checks
/// against what is left of the whole field, not of the block).
pub(crate) fn get_zip64_data(uz: &mut Uz, e: &mut CentralEntry, ef: &[u8]) -> i32 {
    const Z64FLGS: u64 = 0xffff;
    const Z64FLGL: u64 = 0xffff_ffff;
    let f = uz.flavour;
    let mut ef = ef;
    while ef.len() >= EB_HEADSIZE {
        let eb_id = fileio::makeword(ef);
        let eb_len = usize::from(fileio::makeword(&ef[2..]));
        if eb_len > ef.len() - EB_HEADSIZE {
            // Extra block length exceeds remaining extra field length.
            break;
        }
        if eb_id == EF_PKSZ64 {
            let mut offset = EB_HEADSIZE;
            let ef_len = ef.len();
            if e.ucsize == Z64FLGL || uz.lrec.ucsize == Z64FLGL {
                if offset + 8 > ef_len {
                    return PK_ERR;
                }
                let v = fileio::makeint64(f, &ef[offset..]);
                e.ucsize = v;
                uz.lrec.ucsize = v;
                offset += 8;
            }
            if e.csize == Z64FLGL || uz.lrec.csize == Z64FLGL {
                if offset + 8 > ef_len {
                    return PK_ERR;
                }
                let v = fileio::makeint64(f, &ef[offset..]);
                e.csize = v;
                uz.lrec.csize = v;
                uz.csize = v as i64;
                offset += 8;
            }
            if e.relative_offset_local_header == Z64FLGL {
                if offset + 8 > ef_len {
                    return PK_ERR;
                }
                e.relative_offset_local_header = fileio::makeint64(f, &ef[offset..]);
                offset += 8;
            }
            if e.disk_number_start == Z64FLGS {
                if offset + 4 > ef_len {
                    return PK_ERR;
                }
                e.disk_number_start = u64::from(fileio::makelong(&ef[offset..]));
            }
        }
        // Skip this extra field block.
        ef = &ef[eb_len + EB_HEADSIZE..];
    }
    PK_COOL
}

// port: fileio.c:do_string
/// `do_string(G.crec.extra_field_length, EXTRA_FIELD)`: the entry's extra
/// field into `e.extra`, its Zip64 values taken (`getZip64Data()`, whose
/// failure is warned about). `PK_EOF` when nothing could be read,
/// `PK_ERR` for a short read.
pub(crate) fn read_extra_field(uz: &mut Uz, e: &mut CentralEntry) -> i32 {
    let length = usize::from(e.extra_field_length);
    if length == 0 {
        return PK_COOL;
    }
    let mut field = vec![0u8; length];
    let bytes_read = readbuf(uz, &mut field);
    if bytes_read == 0 {
        e.extra = Some(field);
        return PK_EOF;
    }
    if bytes_read != length {
        e.extra = Some(field);
        return PK_ERR;
    }
    let mut error = PK_OK;
    // Looks like here is where extra fields are read
    if get_zip64_data(uz, e, &field) != PK_COOL {
        uz.info_fmt(
            0x401,
            m::EXTRA_FIELD_CORRUPT,
            &[m::EF_PKSZ64_HEX.as_bytes()],
        );
        error = PK_WARN;
    }
    // ubuntu: -DUNICODE_SUPPORT (Task 13): getUnicodeData() and the UTF-8
    // name come here, unless `-UU`.
    e.extra = Some(field);
    error
}

/// The rule a central directory walk ends by: list.c's (`(j - 1)` modulo
/// 2^64 or 2^16, as the end record is Zip64 or not, equal to the entry
/// count) or `get_time_stamp()`'s (always modulo 2^16).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WalkEnd {
    List,
    TimeStamp,
}

// port: list.c:list_files
/// list.c's loop over the central directory: for each entry, its header
/// (`process_cdir_file_hdr()`), name (`do_string(DS_FN)`) and extra field
/// (`do_string(EXTRA_FIELD)`), then `each`, which owns the entry's comment
/// (it must show or skip its `file_comment_length` bytes) and returns the
/// entry's PK code. The walk ends at the first header that is not a
/// central one when the count agrees with the end record, else with
/// `CentSigMsg`, `PK_BADERR`.
///
/// Returns the walk's code: a fatal one (> `PK_WARN`) as soon as it
/// happens, as list.c returns (the caller prints no totals then), else the
/// last warning (`error_in_archive = error`). `uz.sig` holds the signature
/// that ended it.
pub(crate) fn walk_central(
    uz: &mut Uz,
    each: &mut dyn FnMut(&mut Uz, &CentralEntry) -> i32,
) -> i32 {
    walk(uz, WalkEnd::List, each)
}

/// [`walk_central`] with the end rule `end`.
pub(crate) fn walk(
    uz: &mut Uz,
    end: WalkEnd,
    each: &mut dyn FnMut(&mut Uz, &CentralEntry) -> i32,
) -> i32 {
    let mut error_in_archive = PK_COOL;
    let mut j: u64 = 1;
    loop {
        if read_sig(uz) == 0 {
            return PK_EOF;
        }
        if uz.sig != CENTRAL_HDR_SIG {
            // no new central directory entry -> is the number of processed
            // entries compatible with the number of entries as stored in
            // the end_central record?
            let done = match end {
                WalkEnd::List => {
                    let mask = if uz.ecrec.have_ecr64 {
                        u64::MAX
                    } else {
                        MASK_ZUCN16
                    };
                    ((j - 1) & mask) == uz.ecrec.total_entries_central_dir
                }
                WalkEnd::TimeStamp => {
                    ((j - 1) as u32 & 0xffff) == uz.ecrec.total_entries_central_dir as u32
                }
            };
            if done {
                break;
            }
            let n = j.to_string();
            uz.info_fmt(0x401, m::CENT_SIG_MSG, &[n.as_bytes()]);
            uz.info(0x401, m::REPORT_MSG.as_bytes());
            return PK_BADERR; // sig not found
        }
        // process_cdir_file_hdr() sets pInfo->hostnum, pInfo->lcflag, ...:
        let mut e = match process_cdir_file_hdr(uz) {
            Ok(e) => e,
            Err(code) => return code, // only PK_EOF defined
        };
        e.index = j;

        let pinfo = e.pinfo;
        let error = fileio::read_filename(uz, usize::from(e.filename_length), &pinfo, false);
        if error != PK_COOL {
            error_in_archive = error;
            if error > PK_WARN {
                // fatal:  can't continue
                return error;
            }
        }
        e.filename = fileio::c_str(&uz.filename).to_vec();

        let error = read_extra_field(uz, &mut e);
        if error != 0 {
            error_in_archive = error;
            if error > PK_WARN {
                // fatal
                return error;
            }
        }

        let error = each(uz, &e);
        if error != 0 {
            error_in_archive = error; // might be just warning
            if error > PK_WARN {
                // fatal
                return error;
            }
        }
        j = j.wrapping_add(1);
    }
    error_in_archive
}

/// Whether the entry named `name` is one the command line asks for:
/// matching an include pattern (or there are none) and no exclude pattern
/// (list.c, zipinfo.c and extract.c's `do_this_file` test). `-C` folds
/// case; Ubuntu's `-W` stops wildcards at `/`. `fn_matched` and
/// `xn_matched`, when given, note which patterns matched (zipinfo's and
/// the extraction's "not matched" cautions); each must have one flag per
/// pattern (`uz.pfnames`, `uz.pxnames`).
pub(crate) fn selected(
    uz: &Uz,
    name: &[u8],
    mut fn_matched: Option<&mut [bool]>,
    mut xn_matched: Option<&mut [bool]>,
) -> bool {
    if let Some(m) = fn_matched.as_deref() {
        assert_eq!(m.len(), uz.pfnames.len(), "one fn_matched flag per pattern");
    }
    if let Some(m) = xn_matched.as_deref() {
        assert_eq!(m.len(), uz.pxnames.len(), "one xn_matched flag per pattern");
    }
    if uz.process_all_files {
        return true;
    }
    let ic = uz.o.c_flag;
    // ubuntu: -DWILD_STOP_AT_DIR (`WISEP`: '/' under -W)
    let stop = flavour::wild_stop_at_dir(uz.flavour) && uz.o.w_flag;
    let mut do_this_file = if uz.pfnames.is_empty() {
        true
    } else {
        // check if this entry matches an `include' argument
        let mut hit = false;
        for (i, p) in uz.pfnames.iter().enumerate() {
            if matches(p, name, ic, stop) {
                hit = true;
                if let Some(m) = fn_matched.as_deref_mut() {
                    m[i] = true;
                }
                break; // found match, so stop looping
            }
        }
        hit
    };
    if do_this_file {
        // check if this is an excluded file
        for (i, p) in uz.pxnames.iter().enumerate() {
            if matches(p, name, ic, stop) {
                do_this_file = false; // ^-- ignore case in match
                if let Some(m) = xn_matched.as_deref_mut() {
                    m[i] = true;
                }
                break;
            }
        }
    }
    do_this_file
}

// port: process.c:ef_scan_for_izux
/// The Unix times in an extra field: the last `EF_TIME` ("UT") block, or
/// failing one an `EF_IZUNIX2`, or the obsolete `EF_IZUNIX`/`EF_PKUNIX`
/// blocks. Returns the `EF_TIME` flags of the times found (0 for none);
/// `ef_is_c` is a central directory's field (an `EF_TIME` block there holds
/// the modification time only). A 32-bit time with its top bit set is kept
/// only when the DOS time says 2038 or later (`time_t` is 64-bit).
/// ubuntu: -DIZ_HAVE_UXUIDGID adds the owner fields (Task 13), and
/// 17-restore-unix-timestamps-accurately.patch changes which earlier flags
/// an `EF_IZUNIX2`/`EF_IZUNIX3` block clears (Task 14). A listing asks for
/// no owner, so neither shows in one but the patch's.
pub(crate) fn ef_scan_for_izux(
    ef: &[u8],
    ef_is_c: bool,
    dos_mdatetime: u32,
    z_utim: Option<&mut IzTimes>,
) -> u32 {
    ef_scan_for_izux_owner(ef, ef_is_c, dos_mdatetime, z_utim, None)
}

/// unzpriv.h's `EB_UX2_VALID`: [`ef_scan_for_izux_owner`] found the owner.
pub(crate) const EB_UX2_VALID: u32 = 1 << 8;

/// `read_ux3_value()`: a `ux` block's UID or GID of `size` bytes (2, 4 or
/// 8; an 8-byte one always fits a 64-bit `ulg`). The C leaves the value as
/// it was for any other size: 0 here (T10-12).
fn read_ux3_value(f: flavour::Flavour, b: &[u8], size: usize) -> Option<u64> {
    match size {
        2 => Some(u64::from(fileio::makeword(b))),
        4 => Some(u64::from(fileio::makelong(b))),
        8 => Some(fileio::makeint64(f, b)),
        _ => Some(0),
    }
}

/// [`ef_scan_for_izux`] with `-DIZ_HAVE_UXUIDGID`'s owner: `owner`, when
/// given (the build reads owners: `flavour::iz_have_uxuidgid`), takes the
/// UID and GID of a `Ux` block of exactly 4 bytes, a `ux` block of version 1
/// (which then also drops earlier times), or a full `UX` block, and the
/// flags gain [`EB_UX2_VALID`]. Ubuntu builds with the patched
/// (05-fix-uid-gid-handling.patch) form of the `ux` reading, which is what
/// is ported.
/// ruling: T10-12. A `ux` block whose UID/GID sizes run past the block makes
/// the C read past it; here the owner is then not taken. A size other than
/// 2, 4 or 8 leaves the C's (uninitialised) value: 0 here.
pub(crate) fn ef_scan_for_izux_owner(
    ef: &[u8],
    ef_is_c: bool,
    dos_mdatetime: u32,
    z_utim: Option<&mut IzTimes>,
    mut owner: Option<(&mut [u64; 2], flavour::Flavour)>,
) -> u32 {
    let mut flags: u32 = 0;
    let mut have_new_type_eb = 0;
    let mut ut_zip_unzip_compatible = false;

    let Some(z_utim) = z_utim else {
        return 0;
    };
    if ef.is_empty() {
        return 0;
    }
    let mut ef = ef;
    while ef.len() >= EB_HEADSIZE {
        let eb_id = fileio::makeword(ef);
        let eb_len = usize::from(fileio::makeword(&ef[2..]));
        if eb_len > ef.len() - EB_HEADSIZE {
            // discovered some extra field inconsistency!
            break;
        }
        let data = &ef[EB_HEADSIZE..EB_HEADSIZE + eb_len];
        let long_at = |at: usize| i64::from(fileio::makelong(&data[at..]));

        match eb_id {
            EF_TIME => 'ut: {
                flags &= !0x0ff; // ignore previous IZUNIX or EF_TIME fields
                have_new_type_eb = 1;
                if eb_len >= EB_UT_MINLEN {
                    let mut eb_idx = EB_UT_TIME1;
                    flags |= u32::from(data[EB_UT_FLAGS]) & 0x0ff;
                    if flags & EB_UT_FL_MTIME != 0 {
                        if eb_idx + 4 <= eb_len {
                            let i_time = long_at(eb_idx);
                            eb_idx += 4;
                            if i_time & 0x8000_0000 != 0 {
                                // `(time_t)0x80000000L < 0` is false for a
                                // 64-bit time_t
                                ut_zip_unzip_compatible =
                                    dos_mdatetime >= fileio::DOSTIME_2038_01_18;
                                if !ut_zip_unzip_compatible {
                                    // UnZip interprets mtime differently
                                    // than Zip; without modtime: ignore
                                    // complete UT field
                                    flags &= !0x0ff; // no time_t times available
                                    break 'ut; // stop scanning this field
                                }
                            } else {
                                // cannot determine, safe assumption is FALSE
                                ut_zip_unzip_compatible = false;
                            }
                            z_utim.mtime = i_time;
                        } else {
                            flags &= !EB_UT_FL_MTIME;
                        }
                    }
                    if ef_is_c {
                        break 'ut; // central version of TIME field ends here
                    }
                    if flags & EB_UT_FL_ATIME != 0 {
                        if eb_idx + 4 <= eb_len {
                            let i_time = long_at(eb_idx);
                            eb_idx += 4;
                            if i_time & 0x8000_0000 != 0 && !ut_zip_unzip_compatible {
                                flags &= !EB_UT_FL_ATIME;
                            } else {
                                z_utim.atime = i_time;
                            }
                        } else {
                            flags &= !EB_UT_FL_ATIME;
                        }
                    }
                    if flags & EB_UT_FL_CTIME != 0 {
                        if eb_idx + 4 <= eb_len {
                            let i_time = long_at(eb_idx);
                            if i_time & 0x8000_0000 != 0 && !ut_zip_unzip_compatible {
                                flags &= !EB_UT_FL_CTIME;
                            } else {
                                z_utim.ctime = i_time;
                            }
                        } else {
                            flags &= !EB_UT_FL_CTIME;
                        }
                    }
                }
            }
            EF_IZUNIX2 => {
                if have_new_type_eb == 0 {
                    flags &= !0x0ff; // ignore any previous IZUNIX field
                    have_new_type_eb = 1;
                }
                // IZUNIX3 overrides IZUNIX2 e.f. block !
                if have_new_type_eb <= 1
                    && eb_len == EB_UX2_MINLEN
                    && let Some((ug, _)) = owner.as_mut()
                {
                    ug[0] = u64::from(fileio::makeword(data));
                    ug[1] = u64::from(fileio::makeword(&data[2..]));
                    flags |= EB_UX2_VALID; // signal success
                }
            }
            EF_IZUNIX3 => {
                // new 3rd generation Unix ef
                have_new_type_eb = 2;
                if eb_len >= EB_UX3_MINLEN
                    && data[0] == 1
                    && let Some((ug, f)) = owner.as_mut()
                {
                    // only know about version 1
                    let uid_size = usize::from(data[1]);
                    flags &= !0x0ff; // ignore any previous UNIX field
                    let gid_at = uid_size + 2;
                    if let Some(&gid_size) = data.get(gid_at) {
                        let gid_size = usize::from(gid_size);
                        let uid = data.get(2..2 + uid_size);
                        let gid = data.get(gid_at + 1..gid_at + 1 + gid_size);
                        if let (Some(u), Some(g)) = (uid, gid)
                            && let (Some(u), Some(g)) = (
                                read_ux3_value(*f, &pad8(u), uid_size),
                                read_ux3_value(*f, &pad8(g), gid_size),
                            )
                        {
                            ug[0] = u;
                            ug[1] = g;
                            flags |= EB_UX2_VALID; // signal success
                        }
                    }
                }
            }
            // PKUNIX e.f. layout is identical to IZUNIX
            EF_IZUNIX | EF_PKUNIX if eb_len >= EB_UX_MINLEN && have_new_type_eb == 0 => {
                {
                    flags |= EB_UT_FL_MTIME | EB_UT_FL_ATIME;
                    let i_time = long_at(EB_UX_MTIME);
                    if i_time & 0x8000_0000 != 0 {
                        ut_zip_unzip_compatible = dos_mdatetime >= fileio::DOSTIME_2038_01_18;
                        if !ut_zip_unzip_compatible {
                            // UnZip interpretes mtime differently than Zip;
                            // without modtime: ignore complete UT field
                            flags &= !0x0ff; // no time_t times available
                        }
                    } else {
                        // cannot determine, safe assumption is FALSE
                        ut_zip_unzip_compatible = false;
                    }
                    z_utim.mtime = i_time;
                    let i_time = long_at(EB_UX_ATIME);
                    if i_time & 0x8000_0000 != 0 && !ut_zip_unzip_compatible && flags & 0x0ff != 0 {
                        // atime not in range of UnZip's time_t
                        flags &= !EB_UT_FL_ATIME;
                    } else {
                        z_utim.atime = i_time;
                    }
                    if eb_len >= EB_UX_FULLSIZE
                        && let Some((ug, _)) = owner.as_mut()
                    {
                        ug[0] = u64::from(fileio::makeword(&data[EB_UX_UID..]));
                        ug[1] = u64::from(fileio::makeword(&data[EB_UX_GID..]));
                        flags |= EB_UX2_VALID;
                    }
                }
            }
            _ => {}
        }
        // Skip this extra field block
        ef = &ef[eb_len + EB_HEADSIZE..];
    }
    flags
}

/// `b` read as at least 8 bytes (what a value of `b.len()` bytes needs).
fn pad8(b: &[u8]) -> Vec<u8> {
    let mut v = b.to_vec();
    if v.len() < 8 {
        v.resize(8, 0);
    }
    v
}

mod end;

#[cfg(test)]
mod tests;
