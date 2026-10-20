//! `process.c`'s end-of-central-directory search: `find_ecrec()` (with
//! `rec_find()`'s backward block search), the Zip64 records
//! (`find_ecrec64()`) and the archive comment (`process_zip_cmmnt()`).
//! Split from `process.rs` by function group (R5).

use super::super::fileio::{self, DoString, readbuf};
use super::super::messages as m;
use super::super::{PK_COOL, PK_EOF, PK_ERR, PK_WARN, Uz, flavour};
use super::{ECLOC64_SIZE, ECREC_SIZE, ECREC64_SIZE, Ecrec};
use super::{END_CENTLOC64_SIG, END_CENTRAL_SIG, END_CENTRAL64_SIG};

// port: process.c:rec_find
/// Search the last `searchlen` bytes of the archive backwards, a block at
/// a time, for `signature` followed by `rec_size` bytes: 0 when found
/// (`G.inptr` at it), 1 when not, 2 on a read error.
fn rec_find(uz: &mut Uz, searchlen: i64, signature: &[u8; 4], rec_size: usize) -> i32 {
    let mut found = false;
    let inbufsiz = fileio::INBUFSIZ as i64;
    let tail_len = uz.zin.ziplen % inbufsiz;

    // Zipfile is longer than INBUFSIZ:  may need to loop.  Start with short
    // block at end of zipfile (if not TOO short).
    if tail_len > rec_size as i64 {
        let at = uz.zin.ziplen - tail_len;
        uz.zin.cur_zipfile_bufstart = uz.zin.lseek(at);
        uz.zin.incnt = uz.zin.read_at(0, tail_len as usize);
        if uz.zin.incnt != tail_len {
            return 2; // it's expedient...
        }
        // 'P' must be at least (rec_size+4) bytes from end of zipfile
        let mut p = tail_len - (rec_size as i64 + 4);
        while p >= 0 {
            let i = p as usize;
            if uz.zin.inbuf[i] == 0x50 && uz.zin.inbuf[i..i + 4] == *signature {
                uz.zin.incnt -= p;
                uz.zin.inptr = i;
                found = true;
                break;
            }
            p -= 1;
        }
        // sig may span block boundary:
        let n = fileio::INBUFSIZ;
        uz.zin.inbuf.copy_within(0..3, n);
    } else {
        uz.zin.cur_zipfile_bufstart = uz.zin.ziplen - tail_len;
    }

    // Loop through blocks of zipfile data, starting at the end and going
    // toward the beginning.
    let numblks = (searchlen - tail_len + (inbufsiz - 1)) / inbufsiz;
    let mut i = 1i64;
    while !found && i <= numblks {
        uz.zin.cur_zipfile_bufstart -= inbufsiz;
        let at = uz.zin.cur_zipfile_bufstart;
        uz.zin.lseek(at);
        uz.zin.incnt = uz.zin.read_at(0, fileio::INBUFSIZ);
        if uz.zin.incnt != inbufsiz {
            return 2; // read error is fatal failure
        }
        let mut p = inbufsiz - 1;
        while p >= 0 {
            let k = p as usize;
            if uz.zin.inbuf[k] == 0x50 && uz.zin.inbuf[k..k + 4] == *signature {
                uz.zin.incnt -= p;
                uz.zin.inptr = k;
                found = true;
                break;
            }
            p -= 1;
        }
        // sig may span block boundary:
        let n = fileio::INBUFSIZ;
        uz.zin.inbuf.copy_within(0..3, n);
        i += 1;
    }
    if found { 0 } else { 1 }
}

/// `Info(slide, 0x401, ((char *)slide, "[%s]\n", G.zipfn))` before an
/// end-record failure, under `-q` and in zipinfo mode (whose "Archive:"
/// line is missing then).
fn name_the_archive(uz: &mut Uz) {
    if uz.o.qflag != 0 || uz.o.zipinfo_mode {
        let zipfn = uz.zipfn.clone();
        uz.info_fmt(0x401, m::BRACKETED_NAME, &[&zipfn]);
    }
}

/// `find_ecrec64()`'s read failure: the archive's name, then
/// `Cent64EndSigSearchErr`, `PK_ERR`.
fn cent64_search_err(uz: &mut Uz) -> i32 {
    name_the_archive(uz);
    uz.info(0x401, m::CENT64_END_SIG_SEARCH_ERR.as_bytes());
    PK_ERR
}

// port: process.c:find_ecrec64
/// The Zip64 end records: when the locator sits just before the classic
/// record and the Zip64 record it points at agrees with the classic one,
/// every all-ones field of `G.ecrec` takes the Zip64 value.
fn find_ecrec64(uz: &mut Uz) -> i32 {
    let f = uz.flavour;
    let mut byterec = [0u8; ECREC64_SIZE + 4];
    let mut byterec_l = [0u8; ECLOC64_SIZE + 4];

    // First, find the ecrec64 locator.  By definition, this must be before
    // ecrec with nothing in between.
    let ecloc64_start_offset = uz.real_ecrec_offset - (ECLOC64_SIZE as i64 + 4);
    if ecloc64_start_offset < 0 {
        // Seeking would go past beginning, so probably empty archive
        return PK_COOL;
    }
    uz.zin.cur_zipfile_bufstart = uz.zin.lseek(ecloc64_start_offset);
    uz.zin.incnt = uz.zin.read_into(&mut byterec_l);
    if uz.zin.incnt != (ECLOC64_SIZE + 4) as i64 {
        return cent64_search_err(uz);
    }
    if byterec_l[..4] != END_CENTLOC64_SIG {
        // not found
        return PK_COOL;
    }

    // Read the locator.
    let ecrec64_start_disk = u64::from(fileio::makelong(&byterec_l[4..]));
    let mut ecrec64_start_offset = fileio::makeint64(f, &byterec_l[8..]);
    let ecloc64_total_disks = u64::from(fileio::makelong(&byterec_l[16..]));

    // Check for consistency: the disk numbers in ecrec and ecloc64 must
    // match (the locator counts disks from 1).
    // ubuntu: handle_windows_zip64.patch (a zero disk count is no
    // contradiction; `flavour::handle_windows_zip64`)
    if uz.ecrec.number_this_disk != 0xffff
        && (!flavour::handle_windows_zip64(f) || ecloc64_total_disks != 0)
        && uz.ecrec.number_this_disk != ecloc64_total_disks.wrapping_sub(1)
    {
        return PK_COOL;
    }

    // If found locator, look for ecrec64 where the locator says it is.
    if ecrec64_start_offset > ecloc64_start_offset as u64 {
        // ecrec64 has to be before ecrec64 locator
        return cent64_search_err(uz);
    }
    uz.zin.cur_zipfile_bufstart = uz.zin.lseek(ecrec64_start_offset as i64);
    uz.zin.incnt = uz.zin.read_into(&mut byterec);
    if uz.zin.incnt != (ECREC64_SIZE + 4) as i64 {
        return cent64_search_err(uz);
    }

    if byterec[..4] != END_CENTRAL64_SIG {
        // Zip64 EOCD Record not found: there may be bytes prepended to the
        // archive.  Make a guess as to where the Zip64 EOCD Record might be
        ecrec64_start_offset = (ecloc64_start_offset - ECREC64_SIZE as i64 - 4) as u64;
        uz.zin.cur_zipfile_bufstart = uz.zin.lseek(ecrec64_start_offset as i64);
        uz.zin.incnt = uz.zin.read_into(&mut byterec);
        if uz.zin.incnt != (ECREC64_SIZE + 4) as i64 {
            return cent64_search_err(uz);
        }
        if byterec[..4] != END_CENTRAL64_SIG {
            // Probably something not so easy to handle so exit
            return cent64_search_err(uz);
        }
        name_the_archive(uz);
        uz.info(0x401, m::CENT64_END_SIG_SEARCH_OFF.as_bytes());
    }

    // Check consistency of found ecrec64 with ecloc64 (and ecrec):
    if u64::from(fileio::makelong(&byterec[16..])) != ecrec64_start_disk {
        // found ecrec64 does not match ecloc64 info -> no Zip64 archive
        return PK_COOL;
    }
    // Read all relevant ecrec64 fields and compare them to the
    // corresponding ecrec fields unless those are set to "all-ones".
    let e = uz.ecrec;
    let ecrec64_disk_cdstart = u64::from(fileio::makelong(&byterec[20..]));
    if e.num_disk_start_cdir != 0xffff && e.num_disk_start_cdir != ecrec64_disk_cdstart {
        return PK_COOL;
    }
    let ecrec64_this_entries = fileio::makeint64(f, &byterec[24..]);
    if e.num_entries_centrl_dir_ths_disk != 0xffff
        && e.num_entries_centrl_dir_ths_disk != ecrec64_this_entries
    {
        return PK_COOL;
    }
    let ecrec64_tot_entries = fileio::makeint64(f, &byterec[32..]);
    if e.total_entries_central_dir != 0xffff && e.total_entries_central_dir != ecrec64_tot_entries {
        return PK_COOL;
    }
    let ecrec64_cdirsize = fileio::makeint64(f, &byterec[40..]);
    if e.size_central_directory != 0xffff_ffff && e.size_central_directory != ecrec64_cdirsize {
        return PK_COOL;
    }
    let ecrec64_offs_cdstart = fileio::makeint64(f, &byterec[48..]);
    if e.offset_start_central_directory != 0xffff_ffff
        && e.offset_start_central_directory != ecrec64_offs_cdstart
    {
        return PK_COOL;
    }

    // Now, we are (almost) sure that we have a Zip64 archive.
    uz.ecrec.have_ecr64 = true;
    // ubuntu: 24-cve-2019-13232-do-not-raise-alert-for-misplaced-central-
    // directory.patch records the Zip64 record's span here (Task 14).

    // Update the "end-of-central-dir offset" for later checks.
    uz.real_ecrec_offset = ecrec64_start_offset as i64;

    // Update all ecdir_rec data that are flagged to be invalid in Zip64
    // mode.  Set the ecrec64-mandatory flag when such a case is found.
    let r = &mut uz.ecrec;
    if r.number_this_disk == 0xffff {
        r.number_this_disk = ecrec64_start_disk;
        if ecrec64_start_disk != 0xffff {
            r.is_zip64_archive = true;
        }
    }
    if r.num_disk_start_cdir == 0xffff {
        r.num_disk_start_cdir = ecrec64_disk_cdstart;
        if ecrec64_disk_cdstart != 0xffff {
            r.is_zip64_archive = true;
        }
    }
    if r.num_entries_centrl_dir_ths_disk == 0xffff {
        r.num_entries_centrl_dir_ths_disk = ecrec64_this_entries;
        if ecrec64_this_entries != 0xffff {
            r.is_zip64_archive = true;
        }
    }
    if r.total_entries_central_dir == 0xffff {
        r.total_entries_central_dir = ecrec64_tot_entries;
        if ecrec64_tot_entries != 0xffff {
            r.is_zip64_archive = true;
        }
    }
    if r.size_central_directory == 0xffff_ffff {
        r.size_central_directory = ecrec64_cdirsize;
        if ecrec64_cdirsize != 0xffff_ffff {
            r.is_zip64_archive = true;
        }
    }
    if r.offset_start_central_directory == 0xffff_ffff {
        r.offset_start_central_directory = ecrec64_offs_cdstart;
        if ecrec64_offs_cdstart != 0xffff_ffff {
            r.is_zip64_archive = true;
        }
    }
    PK_COOL
}

// port: process.c:find_ecrec
/// The end-of-central-directory record in the last `searchlen` bytes, its
/// fields into `G.ecrec`, the archive comment (`process_zip_cmmnt()`),
/// then the Zip64 records. `PK_ERR` (after `CentDirEndSigNotFound`) when
/// there is none.
pub(super) fn find_ecrec(uz: &mut Uz, searchlen: i64) -> i32 {
    let mut found = false;

    // Treat case of short zipfile separately.
    if uz.zin.ziplen <= fileio::INBUFSIZ as i64 {
        uz.zin.lseek(0);
        let ziplen = uz.zin.ziplen;
        uz.zin.incnt = uz.zin.read_at(0, ziplen.max(0) as usize);
        if uz.zin.incnt == ziplen {
            // 'P' must be at least (ECREC_SIZE+4) bytes from end of zipfile
            let mut p = ziplen - (ECREC_SIZE as i64 + 4);
            while p >= 0 {
                let i = p as usize;
                if uz.zin.inbuf[i] == 0x50 && uz.zin.inbuf[i..i + 4] == END_CENTRAL_SIG {
                    uz.zin.incnt -= p;
                    uz.zin.inptr = i;
                    found = true;
                    break;
                }
                p -= 1;
            }
        }
    } else {
        // Zipfile is longer than INBUFSIZ
        found = rec_find(uz, searchlen, &END_CENTRAL_SIG, ECREC_SIZE) == 0;
    }

    // Searched through whole region where signature should be without
    // finding it.  Print informational message and die a horrible death.
    if !found {
        name_the_archive(uz);
        uz.info(0x401, m::CENT_DIR_END_SIG_NOT_FOUND.as_bytes());
        return PK_ERR; // failed
    }

    // Found the signature, so get the end-central data before returning.
    uz.real_ecrec_offset = uz.zin.cur_zipfile_bufstart + uz.zin.inptr as i64;

    // ruling: a record cut short by the end of the file leaves the C's
    // `byterec` partly uninitialised; the bytes not read are zeros here.
    let mut byterec = [0u8; ECREC_SIZE + 4];
    if readbuf(uz, &mut byterec) == 0 {
        return PK_EOF;
    }
    let word = |at: usize| u64::from(fileio::makeword(&byterec[at..]));
    let long = |at: usize| u64::from(fileio::makelong(&byterec[at..]));
    uz.ecrec = Ecrec {
        number_this_disk: word(4),
        num_disk_start_cdir: word(6),
        num_entries_centrl_dir_ths_disk: word(8),
        total_entries_central_dir: word(10),
        size_central_directory: long(12),
        offset_start_central_directory: long(16),
        zipfile_comment_length: fileio::makeword(&byterec[20..]),
        have_ecr64: false,
        is_zip64_archive: false,
    };
    // ubuntu: 24-cve-2019-13232-do-not-raise-alert-for-misplaced-central-
    // directory.patch records the record's span here (Task 14).

    // Now, we have to read the archive comment, BEFORE the file pointer is
    // moved away backwards to seek for a Zip64 ECLOC64 structure.
    let mut error_in_archive = process_zip_cmmnt(uz);
    if error_in_archive > PK_WARN {
        return error_in_archive;
    }

    // Next: Check for existence of Zip64 end-of-cent-dir locator ECLOC64,
    // which must sit at exactly (ECLOC64_SIZE+4) bytes in front of the
    // ECREC.
    let result = find_ecrec64(uz);
    if result != PK_COOL {
        if error_in_archive < result {
            error_in_archive = result;
        }
        return error_in_archive;
    }

    uz.expect_ecrec_offset = (uz.ecrec.offset_start_central_directory as i64)
        .wrapping_add(uz.ecrec.size_central_directory as i64);

    if uz.o.zipinfo_mode {
        // In ZipInfo mode, additional info about the data found in the
        // end-of-central-directory areas is printed out.
        super::super::zipinfo::zi_end_central(uz);
    }
    error_in_archive
}

// port: process.c:process_zip_cmmnt
/// The archive comment: shown by zipinfo's verbose listing (with its
/// frame), by `zipinfo -z`, by `unzip -z`, and by an unzip run that is
/// neither quiet nor `-T`; otherwise left for `seek_zipf()` to skip.
fn process_zip_cmmnt(uz: &mut Uz) -> i32 {
    let mut error = PK_COOL;
    let len = usize::from(uz.ecrec.zipfile_comment_length);

    if uz.o.zipinfo_mode && uz.o.lflag > 9 {
        // ZipInfo, verbose format
        if len == 0 {
            uz.info(0, m::NO_ZIPFILE_COMMENT.as_bytes());
        } else {
            let n = len.to_string();
            uz.info_fmt(0, m::ZIPFILE_COMMENT_DESC, &[n.as_bytes()]);
            uz.info(0, m::ZIPFILE_COMM_BEGIN.as_bytes());
            if fileio::do_string(uz, len, DoString::Display, None) != 0 {
                error = PK_WARN;
            }
            uz.info(0, m::ZIPFILE_COMM_END.as_bytes());
            if error != 0 {
                uz.info(0, m::ZIPFILE_COMM_TRUNC2.as_bytes());
            }
        }
    } else if len != 0 && uz.o.zflag > 0 && uz.o.zipinfo_mode {
        // ZipInfo, non-verbose mode:  print zipfile comment only if
        // requested
        if fileio::do_string(uz, len, DoString::Display, None) != 0 {
            uz.info(0x401, m::ZIPFILE_COMM_TRUNC1.as_bytes());
            error = PK_WARN;
        }
    } else if len != 0
        && (uz.o.zflag > 0
            || (uz.o.zflag == 0 && !uz.o.zipinfo_mode && !uz.o.t_flag && uz.o.qflag == 0))
        && fileio::do_string(uz, len, DoString::Display, None) != 0
    {
        uz.info(0x401, m::ZIPFILE_COMM_TRUNC1.as_bytes());
        error = PK_WARN;
    }
    error
}
