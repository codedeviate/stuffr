//! The two builds the unzip family can be, and one function per place their
//! behaviour differs (R13).
//!
//! The port follows Apple's tree (`zip-33`'s `unzip60/`); Ubuntu's build
//! (`6.0-28ubuntu4.1`) differs by its `DEFINES` (`debian/rules`) and its
//! patch series (`debian/patches/series`). Each difference the front end
//! meets is a function here, named for its define or patch, so the call
//! site reads as the C's `#ifdef` did.
//!
//! **R13, the order of the work:** Tasks 7–12 give each hook Apple's answer
//! for both flavours (a pass-through), Task 13 fills the `DEFINES`-driven
//! ones and Task 14 the patch-driven ones. A hook still passing through says
//! so in its doc. The banner and compile line are the exception: they are
//! text, recorded from each reference (`// probe:`), so both are exact now.

/// Which reference the family behaves as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavour {
    /// Apple's `/usr/bin/unzip` (UnZip 6.00 with Apple's changes): the
    /// default on macOS and the BSDs.
    Apple,
    /// Ubuntu 24.04's apt `unzip` `6.0-28ubuntu4.1`: the default elsewhere.
    Ubuntu,
}

/// `-DUNICODE_SUPPORT` (with `-DUNICODE_WCHAR -DUTF8_MAYBE_NATIVE`), Ubuntu
/// only: `-U` counts (`uO.U_flag`) instead of being the obsolete inverse of
/// `-L`, zipinfo accepts `-U`, the usage gains the `-U`/`-UU` line and `-v`
/// the `UNICODE_SUPPORT` line.
///
/// Pass-through until Task 13: Apple's answer (`false`) for both.
pub(crate) fn unicode_support(_f: Flavour) -> bool {
    false
}

/// `-DACORN_FTYPE_NFS`, Ubuntu only: unzip accepts `-F`
/// (`uO.acorn_nfs_ext`) and `-v` lists `ACORN_FTYPE_NFS`.
///
/// Pass-through until Task 13: Apple's answer (`false`) for both.
pub(crate) fn acorn_ftype_nfs(_f: Flavour) -> bool {
    false
}

/// `-DWILD_STOP_AT_DIR`, Ubuntu only: unzip and zipinfo accept `-W`
/// (`uO.W_flag`) and `-v` lists `WILD_STOP_AT_DIR`.
///
/// Pass-through until Task 13: Apple's answer (`false`) for both.
pub(crate) fn wild_stop_at_dir(_f: Flavour) -> bool {
    false
}

/// `-DUSE_BZIP2`, Ubuntu only: `-v` lists `USE_BZIP2` with libbzip2's
/// version (R1: method 12 under `cfg(feature = "bzip2")`).
///
/// Pass-through until Task 13: Apple's answer (`false`) for both.
pub(crate) fn use_bzip2(_f: Flavour) -> bool {
    false
}

/// `20-unzip60-alt-iconv-utf8.patch`, Ubuntu only: the usage texts gain the
/// `-O CHARSET` and `-I CHARSET` lines (and unzip's a blank line after
/// them), and unzip and zipinfo accept `-O`/`-I` (`Options::oem_cp`,
/// `Options::iso_cp`; deviation 5).
///
/// Pass-through until Task 14: Apple's answer (`false`) for both. Task 14
/// also ports the patch's `-O`/`-I` cases in `uz_opts` and `zi_opts`.
pub(crate) fn iconv_charsets(_f: Flavour) -> bool {
    false
}

/// `UnzipUsageLine1`'s first line, unzip's banner (usage and `-v`), R2's
/// text: the reference's own line, by stuffr, marked as altered (Info-ZIP
/// licence clause 3, deviation 2). `%s` is stuffr's version.
pub(crate) fn unzip_banner(f: Flavour) -> &'static str {
    match f {
        // apple: unzip.c:574 (`by Info-ZIP, with modifications by Apple Inc.`)
        Flavour::Apple => super::messages::APPLE_UNZIP_BANNER,
        // ubuntu: 02-this-is-debian-unzip.patch (`by Debian. Original by
        // Info-ZIP.`)
        Flavour::Ubuntu => super::messages::UBUNTU_UNZIP_BANNER,
    }
}

/// What follows the banner in `UnzipUsageLine1`, through its blank line.
pub(crate) fn unzip_banner_rest(f: Flavour) -> &'static str {
    match f {
        // apple: unzip.c:575
        Flavour::Apple => super::messages::APPLE_REPORT_BUGS,
        // ubuntu: 02-this-is-debian-unzip.patch (the bug-report line is
        // gone; the blank line stays)
        Flavour::Ubuntu => "\n",
    }
}

/// zipinfo's banner (`ZipInfoUsageLine1`'s first line), R2's pattern.
pub(crate) fn zipinfo_banner(f: Flavour) -> &'static str {
    match f {
        Flavour::Apple => super::messages::APPLE_ZIPINFO_BANNER,
        Flavour::Ubuntu => super::messages::UBUNTU_ZIPINFO_BANNER,
    }
}

/// funzip's banner (its usage's first line), R2's pattern.
pub(crate) fn funzip_banner(f: Flavour) -> &'static str {
    match f {
        Flavour::Apple => super::messages::APPLE_FUNZIP_BANNER,
        Flavour::Ubuntu => super::messages::UBUNTU_FUNZIP_BANNER,
    }
}

/// `unix/unix.c:version()`'s line in `-v`: the reference's own, which names
/// its compiler (and, for Apple, its build date).
pub(crate) fn compiled_with(f: Flavour) -> &'static str {
    match f {
        Flavour::Apple => super::messages::APPLE_COMPILED_WITH,
        // ubuntu: 13-remove-build-date.patch (no ` on <date>`)
        Flavour::Ubuntu => super::messages::UBUNTU_COMPILED_WITH,
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
    #[allow(dead_code)]
    Ymd,
}

/// `-DDATE_FORMAT=DF_YMD`, Ubuntu only: dates print year first.
///
/// Pass-through until Task 13: Apple's answer (`DF_MDY`) for both.
pub(crate) fn date_format(_f: Flavour) -> DateFormat {
    DateFormat::Mdy
}

/// `-DNO_WORKING_ISPRINT`, Ubuntu only: `fnfilter()` escapes control
/// bytes and leaves every other byte as it is (Apple's `isprint()` makes
/// a byte it refuses `?`).
///
/// Pass-through until Task 13: Apple's answer (`false`) for both.
pub(crate) fn no_working_isprint(_f: Flavour) -> bool {
    false
}

/// `21-fix-warning-messages-on-big-files.patch`, Ubuntu only:
/// `makeint64()` reads byte 5 of a 64-bit field, which upstream's (and
/// Apple's) leaves out.
///
/// Pass-through until Task 14: Apple's answer (`false`) for both.
pub(crate) fn makeint64_reads_byte_5(_f: Flavour) -> bool {
    false
}

/// `handle_windows_zip64.patch`, Ubuntu only: `find_ecrec64()` takes a
/// Zip64 locator whose disk count is 0 (as Windows writes it) as no
/// contradiction of the classic record's disk number.
///
/// Pass-through until Task 14: Apple's answer (`false`) for both.
pub(crate) fn handle_windows_zip64(_f: Flavour) -> bool {
    false
}

/// unzpriv.h's `FILNAMSIZ`, the platform's `PATH_MAX`: the longest name
/// (with its NUL) `G.filename` holds. Not a define or a patch but each
/// reference's platform constant, so both are exact now: macOS's 1024,
/// Linux's 4096.
pub(crate) fn filnamsiz(f: Flavour) -> usize {
    match f {
        Flavour::Apple => 1024,
        Flavour::Ubuntu => 4096,
    }
}
