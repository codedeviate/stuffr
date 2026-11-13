//! The two builds the zip family can be, and one function per place their
//! behaviour differs.
//!
//! The port follows Info-ZIP Zip 3.0 (July 5th 2008). Apple's build is
//! `zip-33`'s `zip/zip30/` (its patch against upstream is `apple.diff`);
//! Debian's is Debian 13 (trixie)'s `3.0-15+deb13u1`, which differs from
//! upstream by its build (`BZIP2_SUPPORT` and `UNICODE_SUPPORT` on,
//! `UIDGID_NOT_16BIT`) and a seventeen-patch series. Until 0.27.0 the Linux
//! flavour was Ubuntu 24.04's `3.0-13ubuntu0.2` (`STUFFR_ZIP_FLAVOR=ubuntu`
//! is still accepted, as an alias of `debian`); Debian 13 renumbers its two
//! buffer-overflow patches and adds four. Each difference the code meets is
//! a function here, named for the behaviour, so a call site reads as the
//! C's `#ifdef` did; a site a patch changes is marked `// debian: <patch>`.
//!
//! **Measured, and overriding the spec (the record, `zip-measurements.md`):**
//! Apple writes no 16-bit `Ux` field although its `-v` says `UIDGID_16BIT`
//! (`unix.c` writes it only for a 16-bit `st_uid`): both builds write the
//! same extra fields ([`writes_ux_16bit`] is false for both).
//!
//! **The build (Debian's DEFINES):** `BZIP2_SUPPORT` ([`bzip2_support`]:
//! `cli.rs`'s `-Z`, `zipup.rs`'s `bzfilecompress`, `-v`'s lines,
//! [`last_known_method`]); `UNICODE_SUPPORT` ([`unicode_support`]: the
//! option table, `-v`, [`shows_newline_escaped`], and every site in
//! `unicode.rs`, `readzip.rs` (the central and local names), `zipfile.rs`
//! (putlocal/putcentral), `scan.rs` (`-su`/`-sU`, `-UN escape`, matching by
//! the Unicode name), `fix.rs` (`-FF`), `zipup.rs` (a new entry's UTF-8
//! name)); `UIDGID_NOT_16BIT` ([`writes_ux_16bit`], no effect: neither build
//! writes the field). `debian/rules` (`sh unix/configure`, `make -f
//! unix/Makefile generic`, `-Wall -I. -DUNIX` plus `dpkg-buildflags`) is
//! Ubuntu 24.04's but for its changelog, and `zip -v`'s compilation options
//! are Ubuntu's list line for line; only the compiler line moved, to `gcc
//! 14.2.0` ([`version_post`]).
//!
//! **The patch series** (`debian/patches/series` of `3.0-15+deb13u1`, in
//! order):
//!
//! | Patch | Effect | Hook |
//! |---|---|---|
//! | 01 typo "transferring" | `man/zip.1`, `zip.txt` only | none: no binary string changes |
//! | 02 typo "privileges" | `man/zip.1`, `zip.txt` only | none |
//! | 03 man pages in section 1 | man page only | none |
//! | 04 no unwanted CFLAGS | build flags (`-O3` dropped) | none: no behaviour |
//! | 05 typo "preceding" | `man/zip.1`, `zip.txt` only | none |
//! | 06 stack markings in i386 assembly | `crc_i386.S`, `match.S` (x86 only) | none: no behaviour |
//! | 07 `fclose(in_file)`, not `fclose(x)` | zipnote `-w` works (Apple's fails: closes the temp's stream) | none: both flavours take 07 (deviation 26, ruling Z4) |
//! | 08 `printf("%s", text)` | help/licence texts have no `%`: same output | none |
//! | 09 `LDFLAGS` | build only | none |
//! | 10 no build date | `-v`'s `Compiled with gcc 14.2.0 for Unix (Linux ELF).` has no date | [`version_post`] (the recorded text) |
//! | 11 typo "ambiguities" | `man/zip.1`, `zip.txt` only | none |
//! | 12 fix build with gcc 14 | `unix/configure` no longer adds `-DNO_RMDIR`, `-DNO_STRCHR`, `-DNO_STRRCHR`, `-DNO_RENAME`, `-DNO_MKTEMP`, `-DNO_MKTIME`, `-DNO_MKSTEMP`, `-DZMEM`, `-DNO_ERRNO`, `-DNO_DIR` or `-DNO_VALLOC` when its undeclared-function probe fails (gcc 14 makes an implicit declaration an error, so every probe would fail). On glibc those probes succeeded under gcc 13, so the DEFINES are Ubuntu's: none of these is set, as before | none: no behaviour (measured: `zip -v`'s options are Ubuntu's) |
//! | 13 typo "OS/2" | `man/zip.1`, `zip.txt` only | none |
//! | 14 buffer overflow, Unicode file name (Ubuntu's 12) | `mbstowcs(..., wsize + 1)`: without it glibc's fortify aborts on any non-ASCII name | none: the defined, patched behaviour is the only one (`unicode::local_to_wide`; deviation 28, `debian_patch_rulings`) |
//! | 15 buffer overflow, CVE-2018-13410 (Ubuntu's 13) | `-TT` buffer `+ 4`: without it one byte is written past the command | none: stuffr builds the command as a string (`update::tt_command`; deviation 28, `debian_patch_rulings`) |
//! | 16 fix symlink update detection | `unix.c:filetime` gives a symlink its `st_size` (under `-y`, its target's length): `-sf`/`-du` figures, a stored link's sizes (`zip -y - l` streams it; before, exit 16 "zip -0 not supported for I/O on pipes or devices"), `-FS`/`-u`/`-f` freshness (an unchanged link is current) | [`symlink_has_size`] (`scan.rs`, `zipup.rs`, `readzip::disk_time`) |
//! | fix-command-injection | `zip.c:quote_arg`: the name `-T` gives `unzip -t` or a `-TT` command is in double quotes, `"`, `$`, `` ` ``, `\` escaped and `!` as `"'!'"` (Ubuntu's put it in single quotes, so a name holding one broke the command: `test of a'b.zip FAILED`) | [`test_through_shell`] (`update::quote_arg`, `update::tt_command`) |
//!
//! Every Debian row is compared with the reference by
//! `compat_zip_debian::debian_build_rows` and `debian_patch_rows` (Docker)
//! and the shared table.
//!
//! Hooks used by the front end: [`bzip2_support`], [`unicode_support`],
//! [`help2_brace_line`], [`tt_replaces_braces`], [`test_through_shell`],
//! [`shows_newline_escaped`], [`last_known_method`],
//! [`stale_errno_after_warning`], [`symlink_has_size`], [`fnmax`],
//! [`origin`], [`version_pre`], [`version_post`].

/// Which reference the family behaves as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavour {
    /// Apple's `/usr/bin/zip` (Zip 3.0 with Apple's changes): the default
    /// on macOS and the BSDs.
    Apple,
    /// Debian 13 (trixie)'s apt `zip` `3.0-15+deb13u1`: the default
    /// elsewhere (Ubuntu 24.04's `3.0-13ubuntu0.2` until 0.27.0).
    Debian,
}

/// unix.c:filetime's size (Debian's 16-fix-symlink-update-detection): a
/// symlink (seen under `-y`, `lstat`) has its own size, its target's
/// length, as a regular file does; anything else is -1. Apple's (and
/// upstream's) gives a symlink -1. The size is `-sf`'s and `-du`'s figure,
/// a stored link's sizes (so `zip -y - l` can stream it: a size of -1 on
/// a pipe is "zip -0 not supported for I/O on pipes or devices"), and
/// what `-FS`/`-u`/`-f` compare: an unchanged link is current.
///
/// Unix only (ruling T3-1): Windows takes the Debian flavour too, but its
/// `symlink_metadata` length is the reparse point's (0), not the target's
/// length, so off unix a symlink keeps the size -1 it had before 0.27.0.
pub(crate) fn symlink_has_size(f: Flavour) -> bool {
    cfg!(unix) && f == Flavour::Debian
}

/// `-DBZIP2_SUPPORT`, Debian only: `-Z bzip2` (`-Z b`) is accepted and
/// means method 12, the `-Z` complaint lists `bzip2`, and `-v` has the
/// `BZIP2_SUPPORT` lines. Apple's build has none: `-Z bzip2` is exit 19
/// ("Compression method bzip2 not enabled").
pub(crate) fn bzip2_support(f: Flavour) -> bool {
    f == Flavour::Debian
}

/// `-DUNICODE_SUPPORT`, Debian only: the option table gains `-su`, `-sU`
/// and `-UN` (`unicode`), `-v` has the `UNICODE_SUPPORT` line, names get
/// the UTF-8 flag or the Unicode path field (`unicode.rs`), and a newline
/// in a name is shown as `^J`. Apple's table has none of the three
/// options: `-su` is `-s u` (a bad size), `--show-unicode` is not
/// supported.
pub(crate) fn unicode_support(f: Flavour) -> bool {
    f == Flavour::Debian
}

/// Whether the 16-bit `Ux` extra field is written: neither build writes it
/// (ruling Z3, measured: the field appears only for a 16-bit `st_uid`). For
/// Task 6, which writes the extra fields.
pub(crate) fn writes_ux_16bit(_f: Flavour) -> bool {
    false
}

/// apple.diff (zip.c:925): Apple comments out the `In cmd, {} replaced by
/// temp archive path, else temp appended.` line of `-h2`; Debian keeps it
/// (and its `-TT` replaces the first `{}`, see [`tt_replaces_braces`]).
pub(crate) fn help2_brace_line(f: Flavour) -> bool {
    f == Flavour::Debian
}

/// `-TT cmd` under Debian is run through `system("cmd \"temp\"")` with the
/// first `{}` replaced by the temp path, quoted by `quote_arg()`; under
/// Apple (apple.diff, zip.c:1425) it is `posix_spawnp` of `cmd` as ONE
/// program name with argv `[cmd, temp]`, and a `{}` is refused (`ZE_PARMS`,
/// exit 16).
pub(crate) fn tt_replaces_braces(f: Flavour) -> bool {
    f == Flavour::Debian
}

/// Debian shows a newline in an entry name as `^J` in its messages (its
/// `UNICODE_SUPPORT` display path); Apple shows it raw.
pub(crate) fn shows_newline_escaped(f: Flavour) -> bool {
    f == Flavour::Debian
}

/// zip.h:LAST_KNOWN_COMPMETHOD, which `-v`'s `zipoddities` compares an
/// entry's method with: BZIP2 (12) with Debian's `BZIP2_SUPPORT`, DEFLATE
/// (8) for Apple.
pub(crate) fn last_known_method(f: Flavour) -> u16 {
    if bzip2_support(f) { 12 } else { 8 }
}

/// `-T` (zip.c:check_zipfile): Apple runs `unzip` and a `-TT` command with
/// `posix_spawnp` (no shell; `{}` refused), Debian through `system()`
/// (`/bin/sh -c`, the temp path quoted by `quote_arg()`: Debian's
/// fix-command-injection, `update::quote_arg`; `{}` replaced). Same as
/// [`tt_replaces_braces`].
pub(crate) fn test_through_shell(f: Flavour) -> bool {
    tt_replaces_braces(f)
}

/// zip.c:main, `-MM` and an input that could not be opened: Debian's
/// `zip I/O error:` line says `Invalid argument`, the `errno` glibc's
/// stdio leaves after the warnings before it; Apple's says why the open
/// failed (measured, the record's code table, exit 18).
pub(crate) fn stale_errno_after_warning(f: Flavour) -> bool {
    f == Flavour::Debian
}

/// tailor.h:FNMAX (`PATH_MAX`): macOS's 1024, glibc's 4096. The split
/// prompts read lines of this size (`fgets(buf, FNMAX, stdin)` for `-sp`,
/// `FNMAX + 4010` when asking where a part to read is), so a longer answer
/// is read in pieces, each its own answer.
pub(crate) fn fnmax(f: Flavour) -> usize {
    match f {
        Flavour::Apple => 1024,
        Flavour::Debian => 4096,
    }
}

/// Where the reference came from, for the banner: stuffr's banner line is
/// the reference's, by stuffr, marked as altered (Info-ZIP licence clause
/// 3), and says whose build it alters.
pub(crate) fn origin(f: Flavour) -> &'static str {
    match f {
        // apple: revision.h (`by Info-ZIP, with modifications by Apple Inc.`)
        Flavour::Apple => super::messages::APPLE_ORIGIN,
        // debian: 02-typo-it-is-privileges-not-priviliges is man-page only;
        // the build is Debian's package of upstream's banner
        Flavour::Debian => super::messages::DEBIAN_ORIGIN,
    }
}

/// The preamble of `-v` for `name`, flavour `f`: the recorded text before
/// the banner line.
pub(crate) fn version_pre(f: Flavour, name: &str) -> &'static str {
    use super::messages as m;
    match (name, f) {
        ("zip", Flavour::Apple) => m::ZIP_V_APPLE_PRE,
        ("zip", Flavour::Debian) => m::ZIP_V_DEBIAN_PRE,
        ("zipcloak", Flavour::Apple) => m::ZIPCLOAK_V_APPLE_PRE,
        ("zipcloak", Flavour::Debian) => m::ZIPCLOAK_V_DEBIAN_PRE,
        ("zipnote", Flavour::Apple) => m::ZIPNOTE_V_APPLE_PRE,
        ("zipnote", Flavour::Debian) => m::ZIPNOTE_V_DEBIAN_PRE,
        (_, Flavour::Apple) => m::ZIPSPLIT_V_APPLE_PRE,
        (_, Flavour::Debian) => m::ZIPSPLIT_V_DEBIAN_PRE,
    }
}

/// What follows the banner line of `-v` for `name`, flavour `f`.
pub(crate) fn version_post(f: Flavour, name: &str) -> &'static str {
    use super::messages as m;
    match (name, f) {
        ("zip", Flavour::Apple) => m::ZIP_V_APPLE_POST,
        ("zip", Flavour::Debian) => m::ZIP_V_DEBIAN_POST,
        ("zipcloak", Flavour::Apple) => m::ZIPCLOAK_V_APPLE_POST,
        ("zipcloak", Flavour::Debian) => m::ZIPCLOAK_V_DEBIAN_POST,
        ("zipnote", Flavour::Apple) => m::ZIPNOTE_V_APPLE_POST,
        ("zipnote", Flavour::Debian) => m::ZIPNOTE_V_DEBIAN_POST,
        (_, Flavour::Apple) => m::ZIPSPLIT_V_APPLE_POST,
        (_, Flavour::Debian) => m::ZIPSPLIT_V_DEBIAN_POST,
    }
}
