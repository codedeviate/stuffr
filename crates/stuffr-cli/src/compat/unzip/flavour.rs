//! The two builds the unzip family can be, and one function per place their
//! behaviour differs (R13).
//!
//! The port follows Apple's tree (`zip-33`'s `unzip60/`); Debian 13's build
//! (`6.0-29+deb13u1`; Ubuntu 24.04's `6.0-28ubuntu4.1` until 0.26.0)
//! differs by its `DEFINES` (`debian/rules`) and its patch series
//! (`debian/patches/series`). Each difference the front end meets is a
//! function here, named for its define or patch, so the call site reads as
//! the C's `#ifdef` did.
//!
//! **R13, the order of the work:** Tasks 7–12 give each hook Apple's answer
//! for both flavours (a pass-through), Task 13 fills the `DEFINES`-driven
//! ones and Task 14 the patch-driven ones. A hook still passing through says
//! so in its doc. The banner and compile line are the exception: they are
//! text, recorded from each reference (`// probe:`), so both are exact now.
//!
//! Debian's `DEFINES` (`debian/rules`), each where it acts: `ACORN_FTYPE_NFS`
//! [`acorn_ftype_nfs`], `WILD_STOP_AT_DIR` [`wild_stop_at_dir`],
//! `UNICODE_SUPPORT`, `UNICODE_WCHAR` and `UTF8_MAYBE_NATIVE`
//! [`unicode_support`] (with `Uz::native_is_utf8` and
//! `Uz::unicode_escape_all`), `NO_LCHMOD` [`no_lchmod`],
//! `DATE_FORMAT=DF_YMD` [`date_format`], `USE_BZIP2` [`use_bzip2`],
//! `IZ_HAVE_UXUIDGID` [`iz_have_uxuidgid`], `NO_WORKING_ISPRINT`
//! [`no_working_isprint`]. Two have no hook: `LARGE_FILE_SUPPORT` is in
//! both builds (`-v` lists it in both, and the port's sizes and offsets are
//! 64-bit throughout), and `NOMEMCPY` changes only how inflate.c and
//! explode.c copy a match within the window (a byte loop instead of
//! `memcpy()` for non-overlapping runs), which writes the same bytes: no
//! observable effect (Tasks 4 and 5 probed their C drivers built both ways,
//! identical output).
//!
//! Debian 13's patch series (`debian/patches/series`), in its order, each
//! where it acts (`// debian: <patch>` at the site) or why it has none:
//! - `01-manpages-in-section-1-not-in-section-1l`: man pages only.
//! - `02-this-is-debian-unzip`: the banner, [`unzip_banner`] and
//!   [`unzip_banner_rest`] (deviation 2's form of it).
//! - `03-include-unistd-for-kfreebsd`: a build fix (an `#include`); Apple's
//!   tree has it too.
//! - `04-handle-pkware-verification-bit`, `06-initialize-the-symlink-flag`,
//!   `07-increase-size-of-cfactorstr`, `08-allow-greater-hostver-values`,
//!   `09-cve-2014-8139-crc-overflow`, `10-cve-2014-8140-test-compr-eb`,
//!   `11-cve-2014-8141-getzip64data`: already in Apple's tree in the same
//!   form, so ported for both flavours by Tasks 8-10 (`process.rs`,
//!   `list.rs`, `zipinfo/short.rs`, `extract/extra.rs`).
//! - `05-fix-uid-gid-handling`: code only `IZ_HAVE_UXUIDGID` builds, ported
//!   in its patched form (`process::ef_scan_for_izux_owner`).
//! - `12-cve-2014-9636-test-compr-eb`: [`cve_2014_9636_stored_size`].
//! - `13-remove-build-date`: [`compiled_with`].
//! - `14-cve-2015-7696`: [`cve_2015_7696_short_header`].
//! - `15-cve-2015-7697`, `25-cve-2019-13232-fix-bug-in-uzbunzip2`: in
//!   `UZbunzip2()`, which only Debian builds (`extract::member::bunzip2`,
//!   Task 13).
//! - `16-fix-integer-underflow-csiz-decrypted`: [`csize_below_header_refused`].
//! - `17-restore-unix-timestamps-accurately`: [`izunix_keeps_times`].
//! - `18-cve-2014-9913-unzip-buffer-overflow`,
//!   `19-cve-2016-9844-zipinfo-buffer-overflow`: both flavours print the
//!   patched form, Apple's being undefined behaviour (rulings T8-1, T9-2).
//! - `20-cve-2018-1000035-unzip-buffer-overflow`: the password prompt's
//!   length check (`fileio::passw_prompt`, ruling T11-5).
//! - `21-fix-warning-messages-on-big-files`: [`makeint64_reads_byte_5`].
//! - `22-cve-2019-13232-fix-bug-in-undefer-input`:
//!   [`cve_2019_13232_undefer_input`].
//! - `23-cve-2019-13232-zip-bomb-with-overlapped-entries`:
//!   [`detects_overlapped_entries`] (`extract::cover`, `PK_BOMB`) and
//!   [`skips_data_descriptor`].
//! - `24-cve-2019-13232-do-not-raise-alert-for-misplaced-central-directory`:
//!   the end records' spans (`process::Ecrec::ec_start` and its siblings),
//!   read by [`detects_overlapped_entries`]'s cover.
//! - `26-cve-2019-13232-fix-bug-in-uzinflate`: in `UZinflate()`, the
//!   `USE_ZLIB` path Debian does not build (its `DEFINES` have no
//!   `USE_ZLIB`): no effect.
//! - `27-zipgrep-avoid-test-errors`: the `zipgrep` script only, which this
//!   family does not provide.
//! - `28-cve-2022-0529-and-cve-2022-0530`: code only `UNICODE_SUPPORT`
//!   builds, ported in its patched form (`process::unicode`,
//!   `fileio::unicode_name`, Task 13).
//! - `29-handle-windows-zip64-files` (Ubuntu's `handle_windows_zip64`, the
//!   same hunk): [`handle_windows_zip64`].
//! - `30-drop-conflicting-declarations`: a build fix (two prototypes in
//!   `unix/unxcfg.h`, for gcc 15): no effect.
//! - `31-fix-zipgrep`: the `zipgrep` script only: not ported.
//! - `can-2026-2034440` (`EF_IZUNIX3` sizes): [`ux3_sizes_checked`].
//! - `can-2026-2034443` (SmartZip's name length in zipinfo): the length is
//!   cut to 31, which was already the port's answer for both flavours (the
//!   SmartZip ruling in `zipinfo::extra`): Debian's is now that, defined.
//! - `can-2026-2034442` (`memextract()`'s stored copy):
//!   [`memextract_checks_room`].
//!
//! Not in Debian 13's series, so gone with Ubuntu (0.27.0):
//! `20-unzip60-alt-iconv-utf8` (`-O`/`-I` and `iconv(3)` names: Debian's
//! `-O`/`-I` are bad options and its names go through the OEM 850 table, as
//! Apple's), `29-fix-troff-warning` (man pages), and `CVE-2021-4217`.
//! Apple's tree carries CVE-2021-4217's `do_string()` half (a short read of
//! an extra field is `PK_ERR`) and stuffr keeps both halves for Debian too:
//! without them Debian's build reads an uninitialised heap block, and
//! dereferences a NULL name for a Unicode Path block on a first entry with
//! no name (deviation 11).

/// Which reference the family behaves as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavour {
    /// Apple's `/usr/bin/unzip` (UnZip 6.00 with Apple's changes): the
    /// default on macOS and the BSDs.
    Apple,
    /// Debian 13's apt `unzip` `6.0-29+deb13u1` (Ubuntu 24.04's
    /// `6.0-28ubuntu4.1` until 0.26.0): the default elsewhere.
    Debian,
}

/// `-DUNICODE_SUPPORT` (with `-DUNICODE_WCHAR -DUTF8_MAYBE_NATIVE`), Debian
/// only: `-U` counts (`uO.U_flag`) instead of being the obsolete inverse of
/// `-L`, zipinfo accepts `-U`, the usage gains the `-U`/`-UU` line and `-v`
/// the `UNICODE_SUPPORT` line; names are read whole (`G.filename_full`),
/// general-purpose bit 11 is noted, and an extra field's UTF-8 name (bit
/// 11's, or the Unicode Path block `0x7075`) replaces the entry's
/// (`fileio::unicode_name`).
pub(crate) fn unicode_support(f: Flavour) -> bool {
    f == Flavour::Debian
}

/// `-DACORN_FTYPE_NFS`, Debian only: unzip accepts `-F`
/// (`uO.acorn_nfs_ext`), `-v` lists `ACORN_FTYPE_NFS`, and under `-F`
/// `mapname()` gives a name with a SparkFS block its `,xxx` filetype.
pub(crate) fn acorn_ftype_nfs(f: Flavour) -> bool {
    f == Flavour::Debian
}

/// `-DWILD_STOP_AT_DIR`, Debian only: unzip and zipinfo accept `-W`
/// (`uO.W_flag`), `-v` lists `WILD_STOP_AT_DIR`, and under `-W` a `*` or
/// `?` stops at a `/` (`match()`'s `sepc`).
pub(crate) fn wild_stop_at_dir(f: Flavour) -> bool {
    f == Flavour::Debian
}

/// `-DUSE_BZIP2`, Debian only: `-v` lists `USE_BZIP2` with libbzip2's
/// version, the build can do version 4.6, and method 12 is decoded
/// (`extract::member`'s `UZbunzip2()`, over `stuffr::bzip2_stream`, R1).
pub(crate) fn use_bzip2(f: Flavour) -> bool {
    f == Flavour::Debian
}

/// `UnzipUsageLine1`'s first line, unzip's banner (usage and `-v`), R2's
/// text: the reference's own line, by stuffr, marked as altered (Info-ZIP
/// licence clause 3, deviation 2). `%s` is stuffr's version.
pub(crate) fn unzip_banner(f: Flavour) -> &'static str {
    match f {
        // apple: unzip.c:574 (`by Info-ZIP, with modifications by Apple Inc.`)
        Flavour::Apple => super::messages::APPLE_UNZIP_BANNER,
        // debian: 02-this-is-debian-unzip.patch (`by Debian. Original by
        // Info-ZIP.`)
        Flavour::Debian => super::messages::DEBIAN_UNZIP_BANNER,
    }
}

/// What follows the banner in `UnzipUsageLine1`, through its blank line.
pub(crate) fn unzip_banner_rest(f: Flavour) -> &'static str {
    match f {
        // apple: unzip.c:575
        Flavour::Apple => super::messages::APPLE_REPORT_BUGS,
        // debian: 02-this-is-debian-unzip.patch (the bug-report line is
        // gone; the blank line stays)
        Flavour::Debian => "\n",
    }
}

/// zipinfo's banner (`ZipInfoUsageLine1`'s first line), R2's pattern.
pub(crate) fn zipinfo_banner(f: Flavour) -> &'static str {
    match f {
        Flavour::Apple => super::messages::APPLE_ZIPINFO_BANNER,
        Flavour::Debian => super::messages::DEBIAN_ZIPINFO_BANNER,
    }
}

/// funzip's banner (its usage's first line), R2's pattern.
pub(crate) fn funzip_banner(f: Flavour) -> &'static str {
    match f {
        Flavour::Apple => super::messages::APPLE_FUNZIP_BANNER,
        Flavour::Debian => super::messages::DEBIAN_FUNZIP_BANNER,
    }
}

/// `unix/unix.c:version()`'s line in `-v`: the reference's own, which names
/// its compiler (and, for Apple, its build date).
pub(crate) fn compiled_with(f: Flavour) -> &'static str {
    match f {
        Flavour::Apple => super::messages::APPLE_COMPILED_WITH,
        // debian: 13-remove-build-date.patch (no ` on <date>`)
        Flavour::Debian => super::messages::DEBIAN_COMPILED_WITH,
    }
}

/// unzpriv.h's `DATE_FORMAT`: the order the listings print a date in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DateFormat {
    /// `DF_MDY`, `10-26-91` (unix's default).
    Mdy,
    /// `DF_DMY`, `26-10-91`.
    #[allow(dead_code)]
    Dmy,
    /// `DF_YMD`, `91-10-26`.
    Ymd,
}

/// `-DDATE_FORMAT=DF_YMD`, Debian only: dates print year first; Apple's
/// is unix's default, `DF_MDY` (unxcfg.h).
pub(crate) fn date_format(f: Flavour) -> DateFormat {
    match f {
        Flavour::Apple => DateFormat::Mdy,
        Flavour::Debian => DateFormat::Ymd,
    }
}

/// `-DNO_WORKING_ISPRINT`, Debian only: unxcfg.h then leaves
/// `HAVE_WORKING_ISPRINT` undefined, so `fnfilter()` escapes the bytes
/// below 32 as `^X` and leaves every other byte as it is, DEL and 0x80 to
/// 0xff included, in every locale (Apple's `isprint()` makes a byte it
/// refuses `?`). Nothing else changes: `mapname()` and zipinfo's Mac
/// type/creator line call `isprint()` themselves.
/// probe: `unzip -l` and `zipinfo` of `c\x80\xa0\xad\xe9\xff\x7f.txt`
/// show the bytes raw under `C`, `C.UTF-8`, `en_US.UTF-8`, `en_US.utf8`
/// and `C.utf8` alike (glibc's `isprint()` refuses all of them in each).
pub(crate) fn no_working_isprint(f: Flavour) -> bool {
    f == Flavour::Debian
}

/// `17-restore-unix-timestamps-accurately.patch`, Debian only: an
/// `EF_IZUNIX2` (`Ux`) block no longer drops the times an earlier
/// `EF_IZUNIX`/`EF_PKUNIX` (`UX`) block gave, and an `EF_IZUNIX3` (`ux`)
/// block no longer drops a `UT` block's: each now clears only an earlier
/// block's owner (`flags &= 0x0ff`, where upstream's cleared `~0x0ff`).
pub(crate) fn izunix_keeps_times(f: Flavour) -> bool {
    f == Flavour::Debian
}

/// `21-fix-warning-messages-on-big-files.patch`, Debian only:
/// `makeint64()` reads byte 5 of a 64-bit field, which upstream's (and
/// Apple's) leaves out.
pub(crate) fn makeint64_reads_byte_5(f: Flavour) -> bool {
    f == Flavour::Debian
}

/// `29-handle-windows-zip64-files.patch`, Debian only: `find_ecrec64()` takes a
/// Zip64 locator whose disk count is 0 (as Windows writes it) as no
/// contradiction of the classic record's disk number.
pub(crate) fn handle_windows_zip64(f: Flavour) -> bool {
    f == Flavour::Debian
}

/// `can-2026-2034440.patch`, Debian only (the `ux` owner is read in no
/// other build: [`iz_have_uxuidgid`]): an `EF_IZUNIX3` (`ux`) block's owner
/// is taken only when the block holds its GID size byte and two bytes more
/// (`5 + uid_size <= eb_len`) and its sizes fill it exactly (`3 + uid_size +
/// gid_size == eb_len`). Without the patch the C reads the sizes and values
/// wherever they point (a heap read past the block).
pub(crate) fn ux3_sizes_checked(f: Flavour) -> bool {
    f == Flavour::Debian
}

/// `can-2026-2034442.patch`, Debian only: `memextract()` refuses (`PK_ERR`,
/// silently) a stored block whose data is longer than the size it was
/// given room for, and `extract_izvms_block()` gives up on a VMS block
/// whose `memextract()` failed (it used the buffer anyway). Without the
/// patch the stored copy runs past its heap buffer.
pub(crate) fn memextract_checks_room(f: Flavour) -> bool {
    f == Flavour::Debian
}

/// unzpriv.h's `FILNAMSIZ`, the platform's `PATH_MAX`: the longest name
/// (with its NUL) `G.filename` holds. Not a define or a patch but each
/// reference's platform constant, so both are exact now: macOS's 1024,
/// Linux's 4096.
pub(crate) fn filnamsiz(f: Flavour) -> usize {
    match f {
        Flavour::Apple => 1024,
        Flavour::Debian => 4096,
    }
}

/// fileio.c:dos_to_unix_time()'s `BSD4_4` branch: an MS-DOS time is local
/// time less `localtime()`'s `tm_gmtoff`. Not a define or a patch but each
/// reference's platform (macOS's is a BSD4_4 one, Linux's is not), so both
/// are exact: the Linux build adds `timezone` and takes an hour off in
/// summer time.
pub(crate) fn dos_time_bsd4_4(f: Flavour) -> bool {
    f == Flavour::Apple
}

// ---- extraction (Task 10) ----
//
// ruling: T10-1. Apple's own changes to upstream's extraction code (its
// `__APPLE__` blocks in extract.c, fileio.c and unix.c) are the Debian
// flavour's upstream code the other way round: no define and no patch
// carries them, so no later task fills them, and these hooks give each
// flavour its own tree's answer now (not R13 pass-throughs).

/// apple: extract.c:370, unix.c:1161 (`G.rootpath = realpath(...)`): the
/// extraction root is always set (`-d` or `.`), held as its real absolute
/// path without a trailing `/`, and names are shown relative to it after
/// `uO.exdir` (`FnFilterP`); a directory in the path that is a symlink is
/// left for the beneath walk, and a parent that will not open is "cannot
/// enter". Upstream (Debian) sets a root only for `-d`, as the operand plus
/// `/`, and shows the whole built path (`FnFilter1(G.filename)`).
pub(crate) fn apple_root(f: Flavour) -> bool {
    f == Flavour::Apple
}

/// apple: extract.c:1984 (`error = close_outfile(__G)`): the decoder's code
/// is replaced by what `close_outfile()` returns. Upstream keeps it.
/// ruling: T10-2. Apple's `close_outfile()` has no `return` on its
/// regular-file path (undefined behaviour); its binary answers as if it
/// returned 0: probe: `unzip bad.zip` of a corrupt deflate entry prints
/// `error:  invalid compressed data to inflate` then ` bad CRC 00000000
/// (should be ...)` and keeps the file, exit 2. Here it returns `PK_COOL`.
pub(crate) fn close_outfile_replaces_error(f: Flavour) -> bool {
    f == Flavour::Apple
}

/// apple: extract.c:649 (`error = set_deferred_symlink(...)`): a failed
/// deferred symlink counts in the exit code. Upstream's returns nothing.
pub(crate) fn deferred_symlink_errors_count(f: Flavour) -> bool {
    f == Flavour::Apple
}

/// Apple's build of 2026-10-03 (macOS 27.2) refuses a deferred symlink
/// whose target, resolved through the real tree from the link's directory,
/// leaves the extraction root: `symlink error: Permission denied` after the
/// `linking` line, the placeholder already gone, the link not made, the
/// run going on (exit 2 through `deferred_symlink_errors_count`). `-:`
/// does not lift it. Upstream (Debian) makes every link as stored.
/// probe: `/usr/bin/unzip` of `/usr/bin/zip -y` archives, the table in
/// `beneath::symlink_escapes`.
pub(crate) fn refuses_escaping_symlinks(f: Flavour) -> bool {
    f == Flavour::Apple
}

/// apple: extract.c:701 (`if (error > error_in_archive)`): a failed
/// directory attribute raises the exit code to its own; upstream's `if
/// (!error_in_archive)` only sets it when it was 0.
pub(crate) fn dir_attrib_error_is_max(f: Flavour) -> bool {
    f == Flavour::Apple
}

/// `-DIZ_HAVE_UXUIDGID`, Debian only: `ef_scan_for_izux()` reads the owner
/// from `ux`/`Ux`/`UX` blocks, so `-X` can restore it.
pub(crate) fn iz_have_uxuidgid(f: Flavour) -> bool {
    f == Flavour::Debian
}

/// `-DNO_LCHMOD`, Debian only: a deferred symlink's mode is not set
/// (Apple's build calls `lchmod()`). `NO_LCHOWN` stays undefined, so
/// `SET_SYMLINK_ATTRIBS` is still on: the times and, under `-X`, the owner
/// are still set.
pub(crate) fn no_lchmod(f: Flavour) -> bool {
    f == Flavour::Debian
}

/// `14-cve-2015-7696.patch`, Debian only: `decrypt()` gives up at the
/// first `EOF` of an encryption header cut short (`PK_ERR`, "unable to get
/// password"), returning before `undefer_input()`, so the input stays
/// deferred for the next entry (Apple reads the missing bytes as `EOF`'s
/// 0xff and goes on).
pub(crate) fn cve_2015_7696_short_header(f: Flavour) -> bool {
    f == Flavour::Debian
}

/// `16-fix-integer-underflow-csiz-decrypted.patch`, Debian only: an
/// encrypted stored entry shorter than its header is refused before its
/// sizes are compared ("invalid compressed data to inflate"), and the rest
/// of its block of entries with it (`return PK_ERR` from
/// `extract_or_test_entrylist()`); Apple's size wraps.
pub(crate) fn csize_below_header_refused(f: Flavour) -> bool {
    f == Flavour::Debian
}

/// `12-cve-2014-9636-test-compr-eb.patch`, Debian only: a stored extra
/// block's data is its size less the method, CRC and size words
/// (`EB_CMPRHEADLEN` included); Apple's own form of the check
/// (extract.c:2307) leaves the 6-byte compression header in.
pub(crate) fn cve_2014_9636_stored_size(f: Flavour) -> bool {
    f == Flavour::Debian
}

/// `23-cve-2019-13232-zip-bomb-with-overlapped-entries.patch` with
/// `24-cve-2019-13232-do-not-raise-alert-for-misplaced-central-
/// directory.patch`, Debian only: testing or extracting keeps a list of the
/// spans covered so far (the central directory, a preamble, the end
/// records, then each entry from its local header to where its reading
/// stopped, `extract::cover`); an entry starting inside one, or ending over
/// one, prints "invalid zip file with overlapped components (possible zip
/// bomb)" and ends the archive, `PK_BOMB` (12). Apple has no bomb check.
pub(crate) fn detects_overlapped_entries(f: Flavour) -> bool {
    f == Flavour::Debian
}

/// `23-cve-2019-13232-zip-bomb-with-overlapped-entries.patch`, Debian
/// only: after an entry with general-purpose bit 3 is tested or extracted,
/// its data descriptor is read past (12 bytes, 4 more when it is signed,
/// 8 more under `G.zip64`); fewer bytes left is `PK_ERR`, silently.
pub(crate) fn skips_data_descriptor(f: Flavour) -> bool {
    f == Flavour::Debian
}

/// `22-cve-2019-13232-fix-bug-in-undefer-input.patch`, Debian only:
/// `undefer_input()` clamps a negative `G.csize` (a decoder read past the
/// entry) to 0 before giving the buffer back; Apple's moves `G.inptr` past
/// the hidden bytes by that much.
pub(crate) fn cve_2019_13232_undefer_input(f: Flavour) -> bool {
    f == Flavour::Debian
}
