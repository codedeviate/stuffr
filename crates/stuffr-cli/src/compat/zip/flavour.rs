//! The two builds the zip family can be, and one function per place their
//! behaviour differs.
//!
//! The port follows Info-ZIP Zip 3.0 (July 5th 2008). Apple's build is
//! `zip-33`'s `zip/zip30/` (its patch against upstream is `apple.diff`);
//! Ubuntu's is `3.0-13ubuntu0.2`, which differs from upstream by its build
//! (`BZIP2_SUPPORT` and `UNICODE_SUPPORT` on, `UIDGID_NOT_16BIT`) and a
//! thirteen-patch series. Each difference the code meets is a function
//! here, named for the behaviour, so a call site reads as the C's `#ifdef`
//! did.
//!
//! **Measured, and overriding the spec (rulings Z3 to Z6 of the record,
//! `zip-measurements.md`):**
//! - Apple writes no 16-bit `Ux` field although its `-v` says
//!   `UIDGID_16BIT` (`unix.c` writes it only for a 16-bit `st_uid`): both
//!   builds write the same extra fields ([`writes_ux_16bit`] is false for
//!   both).
//! - Ubuntu's typo patches (01, 02, 05, 11) touch man pages only; patch 07
//!   (`fclose(in_file)` for zipnote), 10 (no build date) and 12/13 (overflow
//!   fixes) are the ones with an effect.
//!
//! Hooks used by the front end now: [`bzip2_support`], [`unicode_support`],
//! [`help2_brace_line`], [`origin`],
//! [`version_pre`], [`version_post`]. The others are consumed by the later tasks
//! named in their docs; each states the behaviour it will select.

/// Which reference the family behaves as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavour {
    /// Apple's `/usr/bin/zip` (Zip 3.0 with Apple's changes): the default
    /// on macOS and the BSDs.
    Apple,
    /// Ubuntu 24.04's apt `zip` `3.0-13ubuntu0.2`: the default elsewhere.
    Ubuntu,
}

/// `-DBZIP2_SUPPORT`, Ubuntu only: `-Z bzip2` (`-Z b`) is accepted and
/// means method 12, the `-Z` complaint lists `bzip2`, and `-v` has the
/// `BZIP2_SUPPORT` lines. Apple's build has none: `-Z bzip2` is exit 19
/// ("Compression method bzip2 not enabled").
pub(crate) fn bzip2_support(f: Flavour) -> bool {
    f == Flavour::Ubuntu
}

/// `-DUNICODE_SUPPORT`, Ubuntu only: the option table gains `-su`, `-sU`
/// and `-UN` (`unicode`), `-v` has the `UNICODE_SUPPORT` line, names get
/// the UTF-8 flag and the Unicode path field (Task 11), and a newline in a
/// name is shown as `^J` (Task 5). Apple's table has none of the three
/// options: `-su` is `-s u` (a bad size), `--show-unicode` is not
/// supported.
pub(crate) fn unicode_support(f: Flavour) -> bool {
    f == Flavour::Ubuntu
}

/// Whether the 16-bit `Ux` extra field is written: neither build writes it
/// (ruling Z3, measured: the field appears only for a 16-bit `st_uid`). For
/// Task 6, which writes the extra fields.
pub(crate) fn writes_ux_16bit(_f: Flavour) -> bool {
    false
}

/// apple.diff (zip.c:925): Apple comments out the `In cmd, {} replaced by
/// temp archive path, else temp appended.` line of `-h2`; Ubuntu keeps it
/// (and its `-TT` replaces the first `{}`, see [`tt_replaces_braces`]).
pub(crate) fn help2_brace_line(f: Flavour) -> bool {
    f == Flavour::Ubuntu
}

/// `-TT cmd` under Ubuntu is run through `system("cmd 'temp'")` with the
/// first `{}` replaced by the quoted temp path; under Apple (apple.diff,
/// zip.c:1425) it is `posix_spawnp` of `cmd` as ONE program name with argv
/// `[cmd, temp]`, and a `{}` is refused (`ZE_PARMS`, exit 16). For Task 7
/// (`-T`).
#[allow(dead_code)]
pub(crate) fn tt_replaces_braces(f: Flavour) -> bool {
    f == Flavour::Ubuntu
}

/// Ubuntu shows a newline in an entry name as `^J` in its messages (its
/// `UNICODE_SUPPORT` display path); Apple shows it raw. For Task 5.
#[allow(dead_code)]
pub(crate) fn shows_newline_escaped(f: Flavour) -> bool {
    f == Flavour::Ubuntu
}

/// zip.c:main, `-MM` and an input that could not be opened: Ubuntu's
/// `zip I/O error:` line says `Invalid argument`, the `errno` glibc's
/// stdio leaves after the warnings before it; Apple's says why the open
/// failed (measured, the record's code table, exit 18).
pub(crate) fn stale_errno_after_warning(f: Flavour) -> bool {
    f == Flavour::Ubuntu
}

/// Ubuntu sets general-purpose bit 11 for any valid non-ASCII UTF-8 name in
/// every locale and writes no Unicode path field for it; Apple never sets
/// it. For Task 11.
#[allow(dead_code)]
pub(crate) fn sets_utf8_bit(f: Flavour) -> bool {
    f == Flavour::Ubuntu
}

/// Where the reference came from, for the banner: stuffr's banner line is
/// the reference's, by stuffr, marked as altered (Info-ZIP licence clause
/// 3), and says whose build it alters.
pub(crate) fn origin(f: Flavour) -> &'static str {
    match f {
        // apple: revision.h (`by Info-ZIP, with modifications by Apple Inc.`)
        Flavour::Apple => super::messages::APPLE_ORIGIN,
        // ubuntu: 02-typo-it-is-privileges-not-priviliges is man-page only;
        // the build is Debian's package of upstream's banner
        Flavour::Ubuntu => super::messages::UBUNTU_ORIGIN,
    }
}

/// The preamble of `-v` for `name`, flavour `f`: the recorded text before
/// the banner line.
pub(crate) fn version_pre(f: Flavour, name: &str) -> &'static str {
    use super::messages as m;
    match (name, f) {
        ("zip", Flavour::Apple) => m::ZIP_V_APPLE_PRE,
        ("zip", Flavour::Ubuntu) => m::ZIP_V_UBUNTU_PRE,
        ("zipcloak", Flavour::Apple) => m::ZIPCLOAK_V_APPLE_PRE,
        ("zipcloak", Flavour::Ubuntu) => m::ZIPCLOAK_V_UBUNTU_PRE,
        ("zipnote", Flavour::Apple) => m::ZIPNOTE_V_APPLE_PRE,
        ("zipnote", Flavour::Ubuntu) => m::ZIPNOTE_V_UBUNTU_PRE,
        (_, Flavour::Apple) => m::ZIPSPLIT_V_APPLE_PRE,
        (_, Flavour::Ubuntu) => m::ZIPSPLIT_V_UBUNTU_PRE,
    }
}

/// What follows the banner line of `-v` for `name`, flavour `f`.
pub(crate) fn version_post(f: Flavour, name: &str) -> &'static str {
    use super::messages as m;
    match (name, f) {
        ("zip", Flavour::Apple) => m::ZIP_V_APPLE_POST,
        ("zip", Flavour::Ubuntu) => m::ZIP_V_UBUNTU_POST,
        ("zipcloak", Flavour::Apple) => m::ZIPCLOAK_V_APPLE_POST,
        ("zipcloak", Flavour::Ubuntu) => m::ZIPCLOAK_V_UBUNTU_POST,
        ("zipnote", Flavour::Apple) => m::ZIPNOTE_V_APPLE_POST,
        ("zipnote", Flavour::Ubuntu) => m::ZIPNOTE_V_UBUNTU_POST,
        (_, Flavour::Apple) => m::ZIPSPLIT_V_APPLE_POST,
        (_, Flavour::Ubuntu) => m::ZIPSPLIT_V_UBUNTU_POST,
    }
}
