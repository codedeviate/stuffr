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
//! **Measured, and overriding the spec (the record, `zip-measurements.md`):**
//! Apple writes no 16-bit `Ux` field although its `-v` says `UIDGID_16BIT`
//! (`unix.c` writes it only for a 16-bit `st_uid`): both builds write the
//! same extra fields ([`writes_ux_16bit`] is false for both).
//!
//! **The build (Ubuntu's DEFINES):** `BZIP2_SUPPORT` ([`bzip2_support`]:
//! `cli.rs`'s `-Z`, `zipup.rs`'s `bzfilecompress`, `-v`'s lines,
//! [`last_known_method`]); `UNICODE_SUPPORT` ([`unicode_support`]: the
//! option table, `-v`, [`shows_newline_escaped`], and every site in
//! `unicode.rs`, `readzip.rs` (the central and local names), `zipfile.rs`
//! (putlocal/putcentral), `scan.rs` (`-su`/`-sU`, `-UN escape`, matching by
//! the Unicode name), `fix.rs` (`-FF`), `zipup.rs` (a new entry's UTF-8
//! name)); `UIDGID_NOT_16BIT` ([`writes_ux_16bit`], no effect: neither build
//! writes the field).
//!
//! **The patch series** (`debian/patches/series`, in order):
//!
//! | Patch | Effect | Hook |
//! |---|---|---|
//! | 01 typo "transferring" | `man/zip.1`, `zip.txt` only | none: no binary string changes |
//! | 02 typo "privileges" | man page only | none |
//! | 03 man pages in section 1 | man page only | none |
//! | 04 no unwanted CFLAGS | build flags (`-O3` dropped) | none: no behaviour |
//! | 05 typo "preceding" | man page only | none |
//! | 06 stack markings in i386 assembly | `crc_i386.S`, `match.S` (x86 only) | none: no behaviour |
//! | 07 `fclose(in_file)`, not `fclose(x)` | zipnote `-w` works (Apple's fails: closes the temp's stream) | none: both flavours take 07 (deviation 26, ruling Z4) |
//! | 08 `printf("%s", text)` | help/licence texts have no `%`: same output | none |
//! | 09 `LDFLAGS` | build only | none |
//! | 10 no build date | `-v`'s `Compiled with gcc 13.3.0 for Unix (Linux ELF).` has no date | [`version_post`] (the recorded text) |
//! | 11 typo "ambiguities" | man page only | none |
//! | 12 `mbstowcs(..., wsize + 1)` | without it glibc's fortify aborts on any non-ASCII name | none: the defined, patched behaviour is the only one (`unicode::local_to_wide`; deviation 28, `ub_rulings`) |
//! | 13 `-TT` buffer `+ 4` | without it one byte is written past the command | none: stuffr builds the command as a string (`-TT` in `zip.c:check_zipfile`'s port; deviation 28, `ub_rulings`) |
//!
//! Every Ubuntu row is compared with the reference by
//! `compat_zip_ubuntu::ubuntu_build_rows` (Docker) and the shared table.
//!
//! Hooks used by the front end: [`bzip2_support`], [`unicode_support`],
//! [`help2_brace_line`], [`tt_replaces_braces`], [`test_through_shell`],
//! [`shows_newline_escaped`], [`last_known_method`],
//! [`stale_errno_after_warning`], [`fnmax`], [`origin`], [`version_pre`],
//! [`version_post`].

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
/// the UTF-8 flag or the Unicode path field (`unicode.rs`), and a newline
/// in a name is shown as `^J`. Apple's table has none of the three
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
/// `[cmd, temp]`, and a `{}` is refused (`ZE_PARMS`, exit 16).
pub(crate) fn tt_replaces_braces(f: Flavour) -> bool {
    f == Flavour::Ubuntu
}

/// Ubuntu shows a newline in an entry name as `^J` in its messages (its
/// `UNICODE_SUPPORT` display path); Apple shows it raw.
pub(crate) fn shows_newline_escaped(f: Flavour) -> bool {
    f == Flavour::Ubuntu
}

/// zip.h:LAST_KNOWN_COMPMETHOD, which `-v`'s `zipoddities` compares an
/// entry's method with: BZIP2 (12) with Ubuntu's `BZIP2_SUPPORT`, DEFLATE
/// (8) for Apple.
pub(crate) fn last_known_method(f: Flavour) -> u16 {
    if bzip2_support(f) { 12 } else { 8 }
}

/// `-T` (zip.c:check_zipfile): Apple runs `unzip` and a `-TT` command with
/// `posix_spawnp` (no shell; `{}` refused), Ubuntu through `system()`
/// (`/bin/sh -c`, the temp path quoted, `{}` replaced). Same as
/// [`tt_replaces_braces`].
pub(crate) fn test_through_shell(f: Flavour) -> bool {
    tt_replaces_braces(f)
}

/// zip.c:main, `-MM` and an input that could not be opened: Ubuntu's
/// `zip I/O error:` line says `Invalid argument`, the `errno` glibc's
/// stdio leaves after the warnings before it; Apple's says why the open
/// failed (measured, the record's code table, exit 18).
pub(crate) fn stale_errno_after_warning(f: Flavour) -> bool {
    f == Flavour::Ubuntu
}

/// tailor.h:FNMAX (`PATH_MAX`): macOS's 1024, glibc's 4096. The split
/// prompts read lines of this size (`fgets(buf, FNMAX, stdin)` for `-sp`,
/// `FNMAX + 4010` when asking where a part to read is), so a longer answer
/// is read in pieces, each its own answer.
pub(crate) fn fnmax(f: Flavour) -> usize {
    match f {
        Flavour::Apple => 1024,
        Flavour::Ubuntu => 4096,
    }
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
