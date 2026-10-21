//! `extract.c`: testing and extracting an archive's entries.
//!
//! [`extract_or_test_files`] reads the central directory in blocks of
//! `DIR_BLKSIZ` entries ([`store_info`] keeps what each selected one needs:
//! `G.info[]`, here [`Info`]), then for each entry of the block seeks to its
//! local header, checks it against the central one, decides whether and
//! where it is written (`mapname()`, `check_for_newer()`, the overwrite
//! question, the open-archive guard of deviation 4), and decodes it
//! (`member.rs`: `extract_or_test_member()`, the decoders through
//! `stuffr::infozip`, the CRC); after the last block it makes the deferred
//! symlinks and sets the made directories' attributes, deepest first.
//! `crypt.rs` is crypt.c's `decrypt()`; `extra.rs` is `TestExtraField()`,
//! `test_compr_eb()` and `memextract()`; `cover.rs` is Ubuntu's bomb
//! detection (23-cve-2019-13232-zip-bomb-with-overlapped-entries.patch).
//!
//! Every count from the archive drives a loop, never an allocation beyond a
//! field's width: a block holds at most `DIR_BLKSIZ` entries, each a name
//! of at most `FILNAMSIZ` bytes.

use super::fileio::{self, PInfo, c_str, readbuf, seek_zipf};
use super::messages as m;
use super::process::{self, CentralEntry, read_sig};
use super::unix::attrs::{self, DirEntry, SlinkEntry};
use super::unix::mapname::{
    self, MPN_CREATED_DIR, MPN_INF_SKIP, MPN_INF_TRUNC, MPN_MASK, MPN_VOL_LABEL,
};
use super::{PK_BADERR, PK_COOL, PK_EOF, PK_ERR, PK_FIND, PK_OK, PK_WARN, Uz, flavour};

mod cover;
mod crypt;
mod extra;
mod member;
pub(crate) mod output;

/// unzip.h's codes this file returns.
pub(crate) const PK_MEM: i32 = 4;
pub(crate) const PK_MEM2: i32 = 5;
pub(crate) const PK_MEM3: i32 = 6;
pub(crate) const PK_DISK: i32 = 50;
pub(crate) const IZ_UNSUP: i32 = 81;
pub(crate) const IZ_BADPWD: i32 = 82;
/// unzip.h's `PK_BOMB` (ubuntu: 23-cve-2019-13232-zip-bomb-with-overlapped-
/// entries.patch): likely zip bomb.
pub(crate) const PK_BOMB: i32 = 12;

/// unzpriv.h's `DIR_BLKSIZ` (not `SMALL_MEM`): entries per block.
const DIR_BLKSIZ: usize = 16384;

/// unzpriv.h's `OVERWRT_*`: `G.overwrite_mode`.
pub(crate) const OVERWRT_QUERY: i32 = 0;
pub(crate) const OVERWRT_ALWAYS: i32 = 1;
pub(crate) const OVERWRT_NEVER: i32 = 2;

/// unzpriv.h's `check_for_newer()` answers.
const DOES_NOT_EXIST: i32 = -1;
const EXISTS_AND_OLDER: i32 = 0;
const EXISTS_AND_NEWER: i32 = 1;

/// The host numbers this file tests.
const VMS_: u8 = 2;
const FS_FAT_: u8 = 0;
/// unzpriv.h's `VMS_UNZIP_VERSION`.
const VMS_UNZIP_VERSION: u8 = 42;

/// `G.info[j]` (`min_info`): what [`store_info`] keeps of a selected
/// central directory entry for the second loop, and what that loop sets on
/// it (`G.pInfo` points at it).
#[derive(Clone, Debug, Default)]
pub(crate) struct Info {
    /// The host, case and label fields `process_cdir_file_hdr()` set.
    pub(crate) pinfo: PInfo,
    /// General-purpose bit 0.
    pub(crate) encrypted: bool,
    /// General-purpose bit 3 (of the central header: P10).
    pub(crate) ext_loc_hdr: bool,
    /// Internal attribute bit 0.
    pub(crate) textfile: bool,
    /// Convert line ends (`-a`, `-aa`).
    pub(crate) textmode: bool,
    pub(crate) crc: u32,
    pub(crate) compr_size: u64,
    pub(crate) uncompr_size: u64,
    /// The mode it is extracted with (`mapattr()`).
    pub(crate) file_attr: u32,
    /// A symlink to restore (`mapattr()`).
    pub(crate) symlink: bool,
    pub(crate) diskstart: u64,
    /// The local header's offset (a C `zoff_t`).
    pub(crate) offset: i64,
    /// `cfilname`: the central header's name, for the comparison with the
    /// local one.
    pub(crate) cfilname: Vec<u8>,
}

/// The extraction's state over one archive (the `G` fields
/// `extract_or_test_files()` and the functions it calls share).
pub(crate) struct Ex {
    /// `G.pInfo`: the entry being tested or extracted.
    pub(crate) pinfo: Info,
    /// `G.crec` as the central loop last left it (`getZip64Data()` of a
    /// local extra field reads it).
    pub(crate) crec: CentralEntry,
    /// `G.extra_field`: the last extra field read (central in the first
    /// loop, local in the second; an empty one leaves the previous).
    pub(crate) extra_field: Option<Vec<u8>>,
    /// `G.outfile`: the file being written.
    pub(crate) outfile: Option<output::OutFile>,
    /// `G.symlnk`: the entry is a symlink being restored.
    pub(crate) symlnk: bool,
    /// `G.slink_head`: the deferred symlinks, in order.
    pub(crate) slinks: Vec<SlinkEntry>,
    /// `dirlist`: the made directories whose attributes wait.
    pub(crate) dirs: Vec<DirEntry>,
    /// `G.crc32val`.
    pub(crate) crc: flate2::Crc,
    /// `G.newfile`, `G.didCRlast`: the text conversion's state.
    pub(crate) newfile: bool,
    pub(crate) did_cr_last: bool,
    /// The VMS text state (`VMS_TEXT_CONV`: `G.VMS_line_state`,
    /// `G.VMS_line_length`, `G.VMS_line_pad`).
    pub(crate) vms_line_state: i32,
    pub(crate) vms_line_length: u32,
    pub(crate) vms_line_pad: bool,
    /// `G.disk_full`: 1 skip the rest of this file, 2 stop.
    pub(crate) disk_full: i32,
    /// `G.reported_backslash`.
    pub(crate) reported_backslash: bool,
    /// The keys decrypting the entry (`G.keys`), set by `decrypt()`.
    pub(crate) keys: Option<stuffr::infozip::crypt::Keys>,
    /// `G.cover` (ubuntu: 23-cve-2019-13232-zip-bomb-with-overlapped-
    /// entries.patch): the spans tested or extracted so far.
    pub(crate) cover: cover::Cover,
}

impl Ex {
    fn new() -> Ex {
        Ex {
            pinfo: Info::default(),
            crec: CentralEntry::default(),
            extra_field: None,
            outfile: None,
            symlnk: false,
            slinks: Vec::new(),
            dirs: Vec::new(),
            crc: flate2::Crc::new(),
            newfile: true,
            did_cr_last: false,
            vms_line_state: -1,
            vms_line_length: 0,
            vms_line_pad: false,
            disk_full: 0,
            reported_backslash: false,
            keys: None,
            cover: cover::Cover::default(),
        }
    }
}

/// `%-22s`.
pub(crate) fn pad22(s: &[u8]) -> Vec<u8> {
    let mut v = s.to_vec();
    while v.len() < 22 {
        v.push(b' ');
    }
    v
}

/// `QCOND2`: `!uO.qflag`.
fn qcond2(uz: &Uz) -> bool {
    uz.o.qflag == 0
}

/// `(uO.tflag && uO.qflag) || (!uO.tflag && !QCOND2)`: quiet enough that
/// the name was not shown yet.
pub(crate) fn quiet(uz: &Uz) -> bool {
    (uz.o.tflag && uz.o.qflag != 0) || (!uz.o.tflag && !qcond2(uz))
}

// port: extract.c:extract_or_test_files
/// `extract_or_test_files()`: every selected entry of the archive tested
/// (`-t`), written to standard output (`-c`, `-p`) or extracted, then the
/// deferred symlinks and directory attributes, the not-matched cautions and
/// `-t`'s summary. Returns the archive's PK code.
pub(crate) fn extract_or_test_files(uz: &mut Uz) -> i32 {
    let mut error_in_archive = PK_COOL;

    // b) check out if specified extraction root directory exists
    if uz.extract_flag {
        uz.ck.create_dirs = !uz.o.fflag;
        let exdir = uz.o.exdir.clone();
        let error = if flavour::apple_root(uz.flavour) {
            // apple: extract.c:370 (`uO.exdir ? uO.exdir : "."`)
            mapname::checkdir_root(uz, exdir.as_deref().unwrap_or(b"."))
        } else {
            mapname::open_cwd(uz);
            match exdir.as_deref() {
                Some(d) => mapname::checkdir_root(uz, d),
                None => mapname::MPN_OK,
            }
        };
        if error > MPN_INF_SKIP {
            // out of memory, or file in way
            return PK_ERR;
        }
    }

    let mut ex = Ex::new();

    // ubuntu: 23-cve-2019-13232-zip-bomb-with-overlapped-entries.patch,
    // 24-cve-2019-13232-do-not-raise-alert-for-misplaced-central-
    // directory.patch: one more: initialize cover structure for bomb
    // detection. Start with spans that cover any extra bytes at the start,
    // the central directory, the end of central directory record (including
    // the Zip64 end of central directory locator, if present), and the Zip64
    // end of central directory record, if present.
    if flavour::detects_overlapped_entries(uz.flavour) {
        let error = cover_init(uz, &mut ex.cover);
        if error != PK_COOL {
            return error;
        }
    }

    uz.newzip = true;
    ex.reported_backslash = false;

    // malloc space for check on unmatched filespecs
    let mut fn_matched = vec![false; uz.pfnames.len()];
    let mut xn_matched = vec![false; uz.pxnames.len()];

    let mut members_processed: u64 = 0;
    let mut no_endsig_found = false;
    let mut reached_end = false;
    let mut filnum: u64 = 0;
    let mut blknum: u64 = 0;
    let mut num_skipped: u64 = 0;
    let mut num_bad_pwd: u64 = 0;
    let mut old_extra_bytes: i64 = 0;
    while !reached_end {
        let mut list: Vec<Info> = Vec::new();
        // Loop through files in central directory, storing offsets, file
        // attributes, case-conversion and text-conversion flags until block
        // size is reached.
        while list.len() < DIR_BLKSIZ {
            let j = list.len() as u64;
            if read_sig(uz) == 0 {
                error_in_archive = PK_EOF;
                reached_end = true; // ...so no more left to do
                break;
            }
            if uz.sig != process::CENTRAL_HDR_SIG {
                // no new central directory entry -> is the number of
                // processed entries compatible with the number of entries
                // as stored in the end_central record?
                let mask = if uz.ecrec.have_ecr64 {
                    u64::MAX
                } else {
                    0xffff
                };
                if members_processed & mask == uz.ecrec.total_entries_central_dir {
                    // yes, so look if we ARE back at the end_central record
                    let want = if uz.ecrec.have_ecr64 {
                        process::END_CENTRAL64_SIG
                    } else {
                        process::END_CENTRAL_SIG
                    };
                    no_endsig_found = uz.sig != want
                        && !uz.ecrec.is_zip64_archive
                        && uz.sig != process::END_CENTRAL_SIG;
                } else {
                    // no; we have found an error in the central directory
                    // -> report it and stop searching for more Zip entries
                    let n = (j + blknum * DIR_BLKSIZ as u64 + 1).to_string();
                    uz.info_fmt(0x401, m::CENT_SIG_MSG, &[n.as_bytes()]);
                    uz.info(0x401, m::REPORT_MSG.as_bytes());
                    error_in_archive = PK_BADERR;
                }
                reached_end = true; // ...so no more left to do
                break;
            }
            // process_cdir_file_hdr() sets pInfo->hostnum, pInfo->lcflag
            let mut e = match process::process_cdir_file_hdr(uz) {
                Ok(e) => e,
                Err(error) => {
                    error_in_archive = error; // only PK_EOF defined
                    reached_end = true; // ...so no more left to do
                    break;
                }
            };
            let pinfo = e.pinfo;
            let error = fileio::read_filename(uz, usize::from(e.filename_length), &pinfo, false);
            if error != PK_COOL {
                if error > error_in_archive {
                    error_in_archive = error;
                }
                if error > PK_WARN {
                    // fatal:  no more left to do
                    let name = c_str(&uz.filename).to_vec();
                    let shown = fileio::fnfilter1(uz, &name);
                    uz.info_fmt(0x401, m::FIL_NAM_MSG, &[&shown, b"central"]);
                    reached_end = true;
                    break;
                }
            }
            e.filename = c_str(&uz.filename).to_vec();
            let len = usize::from(e.extra_field_length);
            let error = read_extra(uz, &mut ex, &mut e, len, false);
            if error != 0 {
                if error > error_in_archive {
                    error_in_archive = error;
                }
                if error > PK_WARN {
                    // fatal
                    let name = c_str(&uz.filename).to_vec();
                    let shown = fileio::fnfilter1(uz, &name);
                    uz.info_fmt(0x401, m::EXT_FIELD_MSG, &[&shown, b"central"]);
                    reached_end = true;
                    break;
                }
            }
            let error = fileio::do_string(
                uz,
                usize::from(e.file_comment_length),
                fileio::DoString::Skip,
                None,
            );
            if error != PK_COOL {
                if error > error_in_archive {
                    error_in_archive = error;
                }
                if error > PK_WARN {
                    // fatal
                    let name = c_str(&uz.filename).to_vec();
                    let shown = fileio::fnfilter1(uz, &name);
                    uz.info_fmt(0x421, m::BAD_FILE_COMM_LENGTH, &[&shown]);
                    reached_end = true;
                    break;
                }
            }
            let name = c_str(&uz.filename).to_vec();
            let do_this_file =
                process::selected(uz, &name, Some(&mut fn_matched), Some(&mut xn_matched));
            if do_this_file {
                match store_info(uz, &ex, &e) {
                    Some(info) => list.push(info), // file is OK
                    None => num_skipped += 1,      // unsupp. compression or encryption
                }
            }
            ex.crec = CentralEntry {
                extra: None,
                filename: Vec::new(),
                ..e
            };
            members_processed = members_processed.wrapping_add(1);
        } // end while-loop (adding files to current block)

        // save position in central directory so can come back later
        let cd_bufstart = uz.zin.cur_zipfile_bufstart;
        let cd_inptr = uz.zin.inptr;
        let cd_incnt = uz.zin.incnt;

        // Second loop:  process files in current block, extracting or
        // testing each one.
        let error = extract_or_test_entrylist(
            uz,
            &mut ex,
            &mut list,
            &mut filnum,
            &mut num_bad_pwd,
            &mut old_extra_bytes,
            error_in_archive,
        );
        if error != PK_COOL {
            if error > error_in_archive {
                error_in_archive = error;
            }
            // ...and keep going (unless disk full or user break)
            // ubuntu: 23-cve-2019-13232-zip-bomb-with-overlapped-entries.patch
            // (or a bomb)
            if ex.disk_full > 1 || uz.abort.is_some() || error == PK_BOMB {
                // clear reached_end to signal premature stop ...
                reached_end = false;
                // ... and cancel scanning the central directory
                break;
            }
        }

        // Jump back to where we were in the central directory, then go and
        // do the next batch of files.
        uz.zin.cur_zipfile_bufstart = uz.zin.lseek(cd_bufstart);
        let _ = uz.zin.read_at(0, fileio::INBUFSIZ); // been here before...
        uz.zin.inptr = cd_inptr;
        uz.zin.incnt = cd_incnt;
        blknum += 1;
    } // end while-loop (blocks of files in central directory)

    // Process the list of deferred symlink extractions and finish up the
    // symbolic links.
    if !ex.slinks.is_empty() {
        if qcond2(uz) {
            uz.info_fmt(0, m::SYM_LNK_DEFERRED, &[]);
        }
        for s in std::mem::take(&mut ex.slinks) {
            let error = member::set_deferred_symlink(uz, &s);
            // apple: extract.c:649
            if flavour::deferred_symlink_errors_count(uz.flavour) && error > error_in_archive {
                error_in_archive = error;
            }
        }
    }

    // Go back through saved list of directories, sort and set
    // times/perms/UIDs and GIDs from the deepest level on up.
    if !ex.dirs.is_empty() {
        let mut dirs = std::mem::take(&mut ex.dirs);
        // `dirlist` is built by prepending; `qsort` with dircomp (reverse
        // strcmp) is not stable, but equal names compare the same way.
        dirs.reverse();
        // port: extract.c:dircomp
        dirs.sort_by(|a, b| b.fname.cmp(&a.fname));
        let mut ndirs_fail = 0u64;
        for d in &dirs {
            let error = attrs::set_direc_attribs(uz, d);
            if error != PK_OK {
                ndirs_fail += 1;
                uz.info_fmt(0x201, m::DIRLIST_SET_ATTR_FAILED, &[&d.fname]);
                let raise = if flavour::dir_attrib_error_is_max(uz.flavour) {
                    // apple: extract.c:701
                    error > error_in_archive
                } else {
                    error_in_archive == 0
                };
                if raise {
                    error_in_archive = error;
                }
            }
        }
        if !uz.o.tflag && qcond2(uz) && ndirs_fail > 0 {
            let n = ndirs_fail.to_string();
            uz.info_fmt(0, m::DIRLIST_FAIL_ATTR_SUM, &[n.as_bytes()]);
        }
    }

    // Check for unmatched filespecs on command line and print warning if
    // any found.  (But suppress check when central dir scan was interrupted
    // prematurely.)
    if reached_end {
        for (i, hit) in fn_matched.iter().enumerate() {
            if !hit {
                let p = uz.pfnames[i].clone();
                uz.info_fmt(1, m::FILENAME_NOT_MATCHED, &[&p]);
                if error_in_archive <= PK_WARN {
                    error_in_archive = PK_FIND; // some files not found
                }
            }
        }
        for (i, hit) in xn_matched.iter().enumerate() {
            if !hit {
                let p = uz.pxnames[i].clone();
                uz.info_fmt(0x401, m::EXCL_FILENAME_NOT_MATCHED, &[&p]);
            }
        }
    }

    // When the central directory processing has been interrupted
    // prematurely, it is safe to return immediately.
    if !reached_end {
        return error_in_archive;
    }

    // Double-check that we're back at the end-of-central-directory record,
    // and print quick summary of results, if we were just testing the
    // archive.
    if no_endsig_found {
        // just to make sure
        uz.info(0x401, m::END_SIG_MSG.as_bytes());
        uz.info(0x401, m::REPORT_MSG.as_bytes());
        if error_in_archive == 0 {
            // don't overwrite stronger error
            error_in_archive = PK_WARN;
        }
    }
    if uz.o.tflag {
        let num = filnum.wrapping_sub(num_bad_pwd);
        if uz.o.qflag < 2 {
            let zipfn = uz.zipfn.clone();
            if error_in_archive != 0 {
                let w: &[u8] = if error_in_archive == PK_WARN {
                    b"warning-"
                } else {
                    b""
                };
                uz.info_fmt(0, m::ERROR_IN_ARCHIVE, &[w, &zipfn]);
            } else if num == 0 {
                uz.info_fmt(0, m::ZERO_FILES_TESTED, &[&zipfn]);
            } else if uz.process_all_files && num_skipped + num_bad_pwd == 0 {
                uz.info_fmt(0, m::NO_ERR_IN_COMP_DATA, &[&zipfn]);
            } else {
                let n = num.to_string();
                let s: &[u8] = if num == 1 { b"" } else { b"s" };
                uz.info_fmt(0, m::NO_ERR_IN_TESTED_FILES, &[&zipfn, n.as_bytes(), s]);
            }
            if num_skipped > 0 {
                let n = num_skipped.to_string();
                let s: &[u8] = if num_skipped == 1 { b"" } else { b"s" };
                uz.info_fmt(0, m::FILES_SKIPPED, &[n.as_bytes(), s]);
            }
            if num_bad_pwd > 0 {
                let n = num_bad_pwd.to_string();
                let s: &[u8] = if num_bad_pwd == 1 { b"" } else { b"s" };
                uz.info_fmt(0, m::FILES_SKIP_BAD_PASSWD, &[n.as_bytes(), s]);
            }
        }
    }

    // give warning if files not tested or extracted (first condition can
    // still happen if zipfile is empty and no files specified on command
    // line)
    if filnum == 0 && error_in_archive <= PK_WARN {
        error_in_archive = if num_skipped > 0 {
            IZ_UNSUP // unsupport. compression/encryption
        } else {
            PK_FIND // no files found at all
        };
    } else if filnum == num_bad_pwd && error_in_archive <= PK_WARN {
        error_in_archive = IZ_BADPWD; // bad passwd => all files skipped
    } else if num_skipped > 0 && error_in_archive <= PK_WARN {
        error_in_archive = IZ_UNSUP; // was PK_WARN; Jean-loup complained
    } else if num_bad_pwd > 0 && error_in_archive == 0 {
        error_in_archive = PK_WARN;
    }
    error_in_archive
}

// port: fileio.c:do_string
/// `do_string(length, EXTRA_FIELD)` into `G.extra_field` (`ex.extra_field`):
/// a length of 0 leaves the previous field (the C's `if (!length) return`),
/// a short read keeps what was read; the Zip64 values taken from it
/// (`getZip64Data()` updates `G.crec`, `G.lrec` and `G.csize`; a central
/// field's `e`, a local one's the stale `G.crec`). `PK_EOF` when nothing
/// could be read, `PK_ERR` for a short read. `e` is `G.crec`: the entry's
/// own for a central field, the stale one for a local field.
fn read_extra(uz: &mut Uz, ex: &mut Ex, e: &mut CentralEntry, length: usize, local: bool) -> i32 {
    if length == 0 {
        if !local {
            e.extra = ex.extra_field.clone();
        }
        return PK_COOL;
    }
    let mut field = vec![0u8; length];
    let bytes_read = readbuf(uz, &mut field);
    if bytes_read == 0 {
        ex.extra_field = Some(field);
        return PK_EOF;
    }
    if bytes_read != length {
        ex.extra_field = Some(field);
        return PK_ERR;
    }
    let mut error = PK_OK;
    // Looks like here is where extra fields are read
    let r = process::get_zip64_data(uz, e, &field);
    if r != PK_COOL {
        uz.info_fmt(
            0x401,
            m::EXTRA_FIELD_CORRUPT,
            &[m::EF_PKSZ64_HEX.as_bytes()],
        );
        error = PK_WARN;
    }
    // ubuntu: -DUNICODE_SUPPORT (`G.pInfo`: the central header's bit 11,
    // also for a local field)
    if flavour::unicode_support(uz.flavour) {
        let pinfo = if local { ex.pinfo.pinfo } else { e.pinfo };
        let r = fileio::unicode_name(uz, &field, &pinfo);
        if r != PK_COOL {
            error = r;
        }
    }
    if !local {
        e.extra = Some(field.clone());
    }
    ex.extra_field = Some(field);
    error
}

/// ubuntu: 23-cve-2019-13232-zip-bomb-with-overlapped-entries.patch and
/// 24-cve-2019-13232-do-not-raise-alert-for-misplaced-central-
/// directory.patch: the cover list started as `extract_or_test_files()`
/// starts it: the central directory (a span that cannot be added is "not
/// enough memory", `PK_MEM`: an empty directory), then any preamble, the
/// Zip64 end record and the end record (overlapping ones are `PK_BOMB`).
/// The C's `zoff_t + zusz_t` sums are unsigned, then read as `bound_t`.
fn cover_init(uz: &mut Uz, cover: &mut cover::Cover) -> i32 {
    cover.clear();
    let extra = uz.zin.extra_bytes as u64;
    let cd = extra.wrapping_add(uz.ecrec.offset_start_central_directory);
    let cd_end = cd.wrapping_add(uz.ecrec.size_central_directory);
    if cover.add(cd as i64, cd_end as i64) != 0 {
        uz.info(0x401, m::NOT_ENOUGH_MEM_COVER.as_bytes());
        return PK_MEM;
    }
    let e = uz.ecrec;
    if (uz.zin.extra_bytes != 0 && cover.add(0, uz.zin.extra_bytes) != 0)
        || (e.have_ecr64 && cover.add(e.ec64_start as i64, e.ec64_end as i64) != 0)
        || cover.add(e.ec_start as i64, e.ec_end as i64) != 0
    {
        uz.info(0x401, m::OVERLAPPED_COMPONENTS.as_bytes());
        return PK_BOMB;
    }
    PK_COOL
}

/// unzpriv.h's `UNZVERS_SUPPORT`: 4.5 (4.6 with `USE_BZIP2`).
fn unzvers_support(uz: &Uz) -> u8 {
    if flavour::use_bzip2(uz.flavour) {
        46
    } else {
        45
    }
}

/// unzpriv.h's `UNKN_COMPR` for both builds (`COPYRIGHT_CLEAN`: reduce is
/// unknown; `USE_UNSHRINK`, `USE_DEFLATE64`; bzip2 only with `USE_BZIP2`).
fn unknown_method(uz: &Uz, method: u16) -> bool {
    let unkn_bz2 = !(flavour::use_bzip2(uz.flavour) && method == 12);
    (2..=5).contains(&method) || method == 7 || (method > 9 && unkn_bz2)
}

// port: extract.c:store_info
/// `store_info()`: the central entry `e`'s `G.pInfo` fields, after its
/// version, method and encryption are checked (each refusal a "skipping:"
/// line unless quiet enough, then `None`: counted as skipped).
fn store_info(uz: &mut Uz, ex: &Ex, e: &CentralEntry) -> Option<Info> {
    let mut info = Info {
        pinfo: e.pinfo,
        encrypted: e.general_purpose_bit_flag & 1 != 0,
        ext_loc_hdr: e.general_purpose_bit_flag & 8 == 8,
        textfile: e.internal_file_attributes & 1 != 0,
        crc: e.crc32,
        compr_size: e.csize,
        uncompr_size: e.ucsize,
        ..Info::default()
    };
    info.textmode = match uz.o.aflag {
        0 => false,
        1 => info.textfile, // auto-convert mode
        _ => true,
    };

    let shown_name = |uz: &mut Uz| {
        let name = c_str(&uz.filename).to_vec();
        let shown = fileio::fnfilter1(uz, &name);
        pad22(&shown)
    };
    let need = e.version_needed_to_extract;
    if need[1] == VMS_ {
        if need[0] > VMS_UNZIP_VERSION {
            if !quiet(uz) {
                let shown = shown_name(uz);
                version_msg(uz, &shown, b"VMS", need[0], VMS_UNZIP_VERSION);
            }
            return None;
        } else if !uz.o.tflag && uz.overwrite_mode != OVERWRT_ALWAYS {
            // won't be able to use extra field, but still have data: if
            // -o, extract anyway
            let name = c_str(&uz.filename).to_vec();
            let shown = fileio::fnfilter1(uz, &name);
            uz.info_fmt(0x481, m::VMS_FORMAT_QUERY, &[&shown]);
            output::fgets_answer(uz);
            if uz.answerbuf[0] != b'y' && uz.answerbuf[0] != b'Y' {
                return None;
            }
        }
    // usual file type:  don't need VMS to extract
    } else if need[0] > unzvers_support(uz) {
        if !quiet(uz) {
            let shown = shown_name(uz);
            let can = unzvers_support(uz);
            version_msg(uz, &shown, b"PK", need[0], can);
        }
        return None;
    }

    let method = e.compression_method;
    if unknown_method(uz, method) {
        if !quiet(uz) {
            let shown = shown_name(uz);
            match m::COMPR_NAMES.iter().find(|(id, _)| *id == method) {
                Some((_, name)) => {
                    uz.info_fmt(0x401, m::COMPR_MSG_NAME, &[&shown, name.as_bytes()]);
                }
                None => {
                    let n = method.to_string();
                    uz.info_fmt(0x401, m::COMPR_MSG_NUM, &[&shown, n.as_bytes()]);
                }
            }
        }
        return None;
    }

    // store a copy of the central header filename for later comparison
    info.cfilname = c_str(&uz.filename).to_vec();

    // map whatever file attributes we have into the local format
    let mut ec = e.clone();
    ec.filename = info.cfilname.clone();
    ec.extra = ex.extra_field.clone();
    attrs::mapattr(uz, &ec, &mut info);

    info.diskstart = e.disk_number_start;
    info.offset = e.relative_offset_local_header as i64;
    Some(info)
}

/// extract.c:VersionMsg.
fn version_msg(uz: &mut Uz, shown: &[u8], what: &[u8], need: u8, can: u8) {
    let (a, b) = ((need / 10).to_string(), (need % 10).to_string());
    let (c, d) = ((can / 10).to_string(), (can % 10).to_string());
    uz.info_fmt(
        0x401,
        m::VERSION_MSG,
        &[
            shown,
            what,
            a.as_bytes(),
            b.as_bytes(),
            c.as_bytes(),
            d.as_bytes(),
        ],
    );
}

/// The `SKIP_*` values of extract_or_test_entrylist's `skip_entry`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Skip {
    No,
    Existing,
    NonExist,
}

// port: extract.c:extract_or_test_entrylist
/// `extract_or_test_entrylist()`: each entry of the block in turn: its
/// local header found (re-compensating once for a preamble), read and
/// checked, the entry decrypted (`-P`), its destination decided, then
/// `extract_or_test_member()`. Returns the block's PK code (early only when
/// the disk is full).
#[allow(clippy::too_many_arguments)]
fn extract_or_test_entrylist(
    uz: &mut Uz,
    ex: &mut Ex,
    list: &mut [Info],
    pfilnum: &mut u64,
    pnum_bad_pwd: &mut u64,
    pold_extra_bytes: &mut i64,
    error_in_archive: i32,
) -> i32 {
    let mut error_in_archive = error_in_archive;
    let bombs = flavour::detects_overlapped_entries(uz.flavour);
    'entries_next: for info in list.iter_mut() {
        *pfilnum += 1;
        ex.pinfo = info.clone();

        // if the target position is not within the current input buffer
        // (either haven't yet read far enough, or (maybe) skipping
        // backward), skip to the target position and reset readbuf().
        let inbufsiz = fileio::INBUFSIZ as i64;
        let mut request = ex.pinfo.offset.wrapping_add(uz.zin.extra_bytes);
        // ubuntu: 23-cve-2019-13232-zip-bomb-with-overlapped-entries.patch
        if bombs && ex.cover.within(request) {
            uz.info(0x401, m::OVERLAPPED_COMPONENTS.as_bytes());
            return PK_BOMB;
        }
        let mut inbuf_offset = request.wrapping_rem(inbufsiz);
        let mut bufstart = request.wrapping_sub(inbuf_offset);
        let n = pfilnum.to_string();

        if request < 0 {
            let zipfn = uz.zipfn.clone();
            uz.info_fmt(0x401, m::SEEK_MSG, &[&zipfn, m::REPORT_MSG.as_bytes()]);
            error_in_archive = PK_ERR;
            if *pfilnum == 1 && uz.zin.extra_bytes != 0 {
                uz.info_fmt(0x401, m::ATTEMPT_RECOMPENSATE, &[]);
                *pold_extra_bytes = uz.zin.extra_bytes;
                uz.zin.extra_bytes = 0;
                request = ex.pinfo.offset; // could also check if != 0
                inbuf_offset = request.wrapping_rem(inbufsiz);
                bufstart = request.wrapping_sub(inbuf_offset);
                // try again
                if request < 0 {
                    let zipfn = uz.zipfn.clone();
                    uz.info_fmt(0x401, m::SEEK_MSG, &[&zipfn, m::REPORT_MSG.as_bytes()]);
                    error_in_archive = PK_BADERR;
                    continue;
                }
            } else {
                error_in_archive = PK_BADERR;
                continue; // this one hosed; try next
            }
        }

        if bufstart != uz.zin.cur_zipfile_bufstart {
            uz.zin.cur_zipfile_bufstart = uz.zin.lseek(bufstart);
            uz.zin.incnt = uz.zin.read_at(0, fileio::INBUFSIZ);
            if uz.zin.incnt <= 0 {
                let b = bufstart.to_string();
                uz.info_fmt(
                    0x401,
                    m::OFFSET_MSG,
                    &[n.as_bytes(), b"lseek", b.as_bytes()],
                );
                error_in_archive = PK_BADERR;
                continue; // can still do next file
            }
            uz.zin.inptr = inbuf_offset as usize;
            uz.zin.incnt -= inbuf_offset;
        } else {
            uz.zin.incnt += uz.zin.inptr as i64 - inbuf_offset;
            uz.zin.inptr = inbuf_offset as usize;
        }

        // should be in proper position now, so check for sig
        let r = request.to_string();
        if read_sig(uz) == 0 {
            // bad offset
            uz.info_fmt(0x401, m::OFFSET_MSG, &[n.as_bytes(), b"EOF", r.as_bytes()]);
            error_in_archive = PK_BADERR;
            continue; // but can still try next one
        }
        if uz.sig != process::LOCAL_HDR_SIG {
            uz.info_fmt(
                0x401,
                m::OFFSET_MSG,
                &[n.as_bytes(), m::LOCAL_HDR_SIG.as_bytes(), r.as_bytes()],
            );
            error_in_archive = PK_ERR;
            if (*pfilnum == 1 && uz.zin.extra_bytes != 0)
                || (uz.zin.extra_bytes == 0 && *pold_extra_bytes != 0)
            {
                uz.info_fmt(0x401, m::ATTEMPT_RECOMPENSATE, &[]);
                if uz.zin.extra_bytes != 0 {
                    *pold_extra_bytes = uz.zin.extra_bytes;
                    uz.zin.extra_bytes = 0;
                } else {
                    uz.zin.extra_bytes = *pold_extra_bytes; // third attempt
                }
                let error = seek_zipf(uz, ex.pinfo.offset);
                if error != PK_OK || read_sig(uz) == 0 {
                    // bad offset
                    if error != PK_BADERR {
                        uz.info_fmt(0x401, m::OFFSET_MSG, &[n.as_bytes(), b"EOF", r.as_bytes()]);
                    }
                    error_in_archive = PK_BADERR;
                    continue; // but can still try next one
                }
                if uz.sig != process::LOCAL_HDR_SIG {
                    uz.info_fmt(
                        0x401,
                        m::OFFSET_MSG,
                        &[n.as_bytes(), m::LOCAL_HDR_SIG.as_bytes(), r.as_bytes()],
                    );
                    error_in_archive = PK_BADERR;
                    continue;
                }
            } else {
                continue; // this one hosed; try next
            }
        }
        let central = CentralEntry {
            crc32: ex.pinfo.crc,
            csize: ex.pinfo.compr_size,
            ucsize: ex.pinfo.uncompr_size,
            ..CentralEntry::default()
        };
        let error = process::process_local_file_hdr(uz, &central);
        if error != PK_COOL {
            uz.info_fmt(0x421, m::BAD_LOCAL_HDR, &[n.as_bytes()]);
            error_in_archive = error; // only PK_EOF defined
            continue; // can still try next one
        }
        // ubuntu: -DUNICODE_SUPPORT
        if flavour::unicode_support(uz.flavour)
            && (uz.lrec.general_purpose_bit_flag & (1 << 11) == 1 << 11)
                != ex.pinfo.pinfo.gpf_is_utf8
        {
            if qcond2(uz) {
                let cname = ex.pinfo.cfilname.clone();
                let shown = fileio::fnfilter1(uz, &cname);
                let is_utf8: &[u8] = if ex.pinfo.pinfo.gpf_is_utf8 {
                    b"1"
                } else {
                    b"0"
                };
                uz.info_fmt(
                    0x421,
                    m::GP11_FLAGS_DIFFER,
                    &[n.as_bytes(), &shown, is_utf8],
                );
            }
            if error_in_archive < PK_WARN {
                error_in_archive = PK_WARN;
            }
        }
        let pinfo = ex.pinfo.pinfo;
        let error = fileio::read_filename(uz, usize::from(uz.lrec.filename_length), &pinfo, true);
        if error != PK_COOL {
            if error > error_in_archive {
                error_in_archive = error;
            }
            if error > PK_WARN {
                let name = c_str(&uz.filename).to_vec();
                let shown = fileio::fnfilter1(uz, &name);
                uz.info_fmt(0x401, m::FIL_NAM_MSG, &[&shown, b"local"]);
                continue; // go on to next one
            }
        }
        ex.extra_field = None;
        let mut crec = std::mem::take(&mut ex.crec);
        let error = read_extra(
            uz,
            ex,
            &mut crec,
            usize::from(uz.lrec.extra_field_length),
            true,
        );
        ex.crec = crec;
        if error != 0 {
            if error > error_in_archive {
                error_in_archive = error;
            }
            if error > PK_WARN {
                let name = c_str(&uz.filename).to_vec();
                let shown = fileio::fnfilter1(uz, &name);
                uz.info_fmt(0x401, m::EXT_FIELD_MSG, &[&shown, b"local"]);
                continue; // go on
            }
        }
        // Filename consistency checks must come after reading in the local
        // extra field, so that a UTF-8 entry name e.f. block has already
        // been processed.
        let cname = std::mem::take(&mut ex.pinfo.cfilname);
        if cname != c_str(&uz.filename) {
            let s2 = fileio::fnfilter2(uz, &cname);
            let lname = c_str(&uz.filename).to_vec();
            let s1 = fileio::fnfilter1(uz, &lname);
            uz.info_fmt(0x401, m::LVS_CF_NAM_MSG, &[&s2, &s1]);
            mapname::set_filename(uz, &cname);
            if error_in_archive < PK_WARN {
                error_in_archive = PK_WARN;
            }
        }
        // Size consistency checks must come after reading in the local
        // extra field, so that any Zip64 extension local e.f. block has
        // already been processed.
        if uz.lrec.compression_method == 0 {
            let mut csiz_decrypted = uz.lrec.csize;
            if ex.pinfo.encrypted {
                // ubuntu: 16-fix-integer-underflow-csiz-decrypted.patch:
                // handle the error now to prevent unsigned overflow (the
                // rest of this block of entries is dropped with it)
                if flavour::csize_below_header_refused(uz.flavour) && csiz_decrypted < 12 {
                    uz.info_fmt(
                        0x401,
                        m::ERR_UNZIP_NO_FILE,
                        &[m::INVALID_COMPR_DATA.as_bytes(), m::INFLATE.as_bytes()],
                    );
                    return PK_ERR;
                }
                csiz_decrypted = csiz_decrypted.wrapping_sub(12);
            }
            if uz.lrec.ucsize != csiz_decrypted {
                let name = c_str(&uz.filename).to_vec();
                let shown = fileio::fnfilter1(uz, &name);
                let (a, b) = (uz.lrec.ucsize.to_string(), csiz_decrypted.to_string());
                uz.info_fmt(
                    0x401,
                    m::WRN_STOR_UCSIZ_CSIZ_DIFF,
                    &[&shown, a.as_bytes(), b.as_bytes()],
                );
                uz.lrec.ucsize = csiz_decrypted;
                if error_in_archive < PK_WARN {
                    error_in_archive = PK_WARN;
                }
            }
        }

        ex.keys = None;
        if ex.pinfo.encrypted {
            let pw = uz.o.pwdarg.clone();
            let error = crypt::decrypt_entry(uz, ex, pw.as_deref());
            if error != PK_COOL {
                let name = c_str(&uz.filename).to_vec();
                let shown = fileio::fnfilter1(uz, &name);
                let shown = pad22(&shown);
                if error == PK_WARN {
                    if !quiet(uz) {
                        uz.info_fmt(0x401, m::SKIP_INCORRECT_PASSWD, &[&shown]);
                    }
                    *pnum_bad_pwd += 1;
                } else {
                    // (error > PK_WARN)
                    if error > error_in_archive {
                        error_in_archive = error;
                    }
                    uz.info_fmt(0x401, m::SKIP_CANNOT_GET_PASSWD, &[&shown]);
                }
                continue; // go on to next file
            }
        }

        // just about to extract file:  if extracting to disk, check if
        // already exists, and if so, take appropriate action according to
        // fflag/uflag/overwrite_all/etc.
        if !uz.o.tflag && !uz.o.cflag {
            let mut renamed = false; // user hasn't renamed output file yet
            let mut skip_entry;
            'startover: loop {
                let mut query = false;
                skip_entry = Skip::No;
                // for files from DOS FAT, check for use of backslash instead
                // of slash as directory separator (bug in some zipper(s); so
                // far, not a problem in HPFS, NTFS or VFAT systems)
                let name = c_str(&uz.filename).to_vec();
                if ex.pinfo.pinfo.hostnum == FS_FAT_ && !name.contains(&b'/') {
                    let mut fixed = name.clone();
                    for c in fixed.iter_mut() {
                        if *c == b'\\' {
                            if !ex.reported_backslash {
                                let zipfn = uz.zipfn.clone();
                                uz.info_fmt(0x21, m::BACKSLASH_PATH_SEP, &[&zipfn]);
                                ex.reported_backslash = true;
                                if error_in_archive == 0 {
                                    error_in_archive = PK_WARN;
                                }
                            }
                            *c = b'/';
                        }
                    }
                    mapname::set_filename(uz, &fixed);
                }

                if !renamed {
                    // remove absolute path specs
                    let name = c_str(&uz.filename).to_vec();
                    if name.first() == Some(&b'/') {
                        let shown = fileio::fnfilter1(uz, &name);
                        uz.info_fmt(0x401, m::ABSOLUTE_PATH_WARNING, &[&shown]);
                        if error_in_archive == 0 {
                            error_in_archive = PK_WARN;
                        }
                        let start = name.iter().position(|&b| b != b'/').unwrap_or(name.len());
                        mapname::set_filename(uz, &name[start..]);
                    }
                }

                // mapname can create dirs if not freshening or if renamed
                let error = mapname::mapname(uz, &mut ex.pinfo, ex.extra_field.as_deref(), renamed);
                let errcode = error & !MPN_MASK;
                if errcode != PK_OK && error_in_archive < errcode {
                    error_in_archive = errcode;
                }
                let errcode = error & MPN_MASK;
                if errcode > MPN_INF_TRUNC {
                    if errcode == MPN_CREATED_DIR {
                        ex.dirs.push(attrs::defer_dir_attribs(uz, ex));
                    } else if errcode == MPN_VOL_LABEL {
                        let name = c_str(&uz.filename).to_vec();
                        let shown = fileio::fnfilter1(uz, &name);
                        uz.info_fmt(1, m::SKIP_VOLUME_LABEL, &[&pad22(&shown), b""]);
                    } else if errcode > MPN_INF_SKIP && error_in_archive < PK_ERR {
                        error_in_archive = PK_ERR;
                    }
                    continue 'entries_next;
                }

                let full = c_str(&uz.filename).to_vec();
                match output::check_for_newer(uz, ex, &full) {
                    DOES_NOT_EXIST => {
                        // freshen (no new files): skip unless just renamed
                        if uz.o.fflag && !renamed {
                            skip_entry = Skip::NonExist;
                        }
                    }
                    EXISTS_AND_OLDER => {
                        if !uz.o.b_flag {
                            if uz.overwrite_mode == OVERWRT_NEVER {
                                // never overwrite:  skip file
                                skip_entry = Skip::Existing;
                            } else if uz.overwrite_mode != OVERWRT_ALWAYS {
                                query = true;
                            }
                        }
                    }
                    _ => {
                        // EXISTS_AND_NEWER (or equal)
                        if (!uz.o.b_flag && uz.overwrite_mode == OVERWRT_NEVER)
                            || (uz.o.uflag && !renamed)
                        {
                            // skip if update/freshen & orig name
                            skip_entry = Skip::Existing;
                        } else if uz.overwrite_mode != OVERWRT_ALWAYS && !uz.o.b_flag {
                            query = true;
                        }
                    }
                }
                if query {
                    'reprompt: loop {
                        let full = c_str(&uz.filename).to_vec();
                        let shown = mapname::shown(uz, &full);
                        uz.info_fmt(0x81, m::REPLACE_QUERY, &[&shown]);
                        if !output::fgets_answer(uz) {
                            uz.info_fmt(1, m::ASSUME_NONE, &[]);
                            uz.answerbuf[0] = b'N';
                            if error_in_archive == 0 {
                                error_in_archive = 1; // not extracted:  warning
                            }
                        }
                        match uz.answerbuf[0] {
                            b'r' | b'R' => {
                                loop {
                                    uz.info_fmt(0x81, m::NEW_NAME_QUERY, &[]);
                                    let read = output::fgets_filename(uz);
                                    // usually get \n here:  better check for it
                                    let mut fnlen = c_str(&uz.filename).len();
                                    if fnlen > 0 && uz.filename[fnlen - 1] == b'\n' {
                                        fnlen -= 1;
                                        uz.filename[fnlen] = 0;
                                    }
                                    if fnlen != 0 {
                                        break;
                                    }
                                    // ruling: T10-9. With the name empty
                                    // and the input at its end, the C asks
                                    // "new name: " forever (a hang, not
                                    // undefined; probe: `printf 'r\n\n' |
                                    // unzip a.zip`). Here the end of input
                                    // answers as at the first question:
                                    // "[N]one".
                                    if !read {
                                        uz.info_fmt(1, m::ASSUME_NONE, &[]);
                                        uz.answerbuf[0] = b'N';
                                        if error_in_archive == 0 {
                                            error_in_archive = 1;
                                        }
                                        uz.overwrite_mode = OVERWRT_NEVER;
                                        continue 'entries_next;
                                    }
                                }
                                renamed = true;
                                continue 'startover; // sorry for a goto
                            }
                            b'A' => {
                                // dangerous option:  force caps
                                uz.overwrite_mode = OVERWRT_ALWAYS;
                                // FALL THROUGH, extract
                            }
                            b'y' | b'Y' => {}
                            b'N' => {
                                uz.overwrite_mode = OVERWRT_NEVER;
                                // FALL THROUGH, skip
                                skip_entry = Skip::Existing;
                            }
                            b'n' => {
                                // skip file
                                skip_entry = Skip::Existing;
                            }
                            c => {
                                if c == b'\n' || c == b'\r' {
                                    // Improve echo of '\n' and/or '\r'
                                    uz.answerbuf = [0; 10];
                                    uz.answerbuf[..m::ENTER.len()].copy_from_slice(m::ENTER);
                                }
                                // usually get \n here:  remove it for nice
                                // display
                                let mut fnlen = c_str(&uz.answerbuf).len();
                                if fnlen > 0 && uz.answerbuf[fnlen - 1] == b'\n' {
                                    fnlen -= 1;
                                    uz.answerbuf[fnlen] = 0;
                                }
                                let a = c_str(&uz.answerbuf).to_vec();
                                uz.info_fmt(1, m::INVALID_RESPONSE, &[&a]);
                                continue 'reprompt; // yet another goto?
                            }
                        }
                        break;
                    }
                }
                break;
            }
            if skip_entry != Skip::No {
                continue;
            }
        }

        ex.disk_full = 0;
        let error = member::extract_or_test_member(uz, ex);
        if error != PK_COOL {
            if error > error_in_archive {
                error_in_archive = error; // ...and keep going
            }
            if ex.disk_full > 1 || uz.abort.is_some() {
                return error_in_archive; // (unless disk full)
            }
        }
        // ubuntu: 23-cve-2019-13232-zip-bomb-with-overlapped-entries.patch
        if bombs {
            let end = uz
                .zin
                .cur_zipfile_bufstart
                .wrapping_add(uz.zin.inptr as i64);
            let error = ex.cover.add(request, end);
            if error < 0 {
                uz.info(0x401, m::NOT_ENOUGH_MEM_COVER.as_bytes());
                return PK_MEM;
            }
            if error != 0 {
                uz.info(0x401, m::OVERLAPPED_COMPONENTS.as_bytes());
                return PK_BOMB;
            }
        }
    } // end for-loop (i:  files in current block)
    error_in_archive
}

#[cfg(test)]
mod tests;
