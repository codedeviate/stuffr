//! `suffix.c`: the `--suffix` check and the output name of an input, from
//! XZ Utils 5.8.4 (0BSD, `LICENSE-xz`).
//!
//! The DJGPP 8.3-name branches are left out (stuffr does not build for
//! DOS). On Windows (`TUKLIB_DOSLIKE`) `\` and `:` also separate
//! directories and suffixes compare without regard to case, as there.

use std::io::Write;

use super::args::{FormatChoice, OpMode};
use super::message::{Messages, mask_nonprint};
use super::messages as m;

/// suffix.c: is_dir_sep.
fn is_dir_sep(c: u8) -> bool {
    if cfg!(windows) {
        matches!(c, b'/' | b'\\' | b':')
    } else {
        c == b'/'
    }
}

/// suffix.c: has_dir_sep.
pub(crate) fn has_dir_sep(s: &[u8]) -> bool {
    s.iter().any(|&c| is_dir_sep(c))
}

/// suffix.c's `suffix_strcmp`: `strcmp`, or `strcasecmp` where names
/// ignore case.
fn suffix_eq(a: &[u8], b: &[u8]) -> bool {
    if cfg!(windows) {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

/// suffix.c: test_suffix: the length of `src` without `suffix`, or 0 when
/// `src` does not end in it with at least one character before it (one
/// that is not a directory separator).
fn test_suffix(suffix: &[u8], src: &[u8]) -> usize {
    let (sl, n) = (suffix.len(), src.len());
    if n <= sl || is_dir_sep(src[n - sl - 1]) {
        return 0;
    }
    if suffix_eq(suffix, &src[n - sl..]) {
        n - sl
    } else {
        0
    }
}

/// suffix.c: uncompressed_name's table.
const UNCOMPRESSED: &[(&[u8], &[u8])] = &[
    (b".xz", b""),
    (b".txz", b".tar"),
    (b".lzma", b""),
    (b".tlz", b".tar"),
    (b".lz", b""),
];

/// suffix.c: uncompressed_name. `None` after the "unknown suffix" warning.
fn uncompressed_name(
    src: &[u8],
    format: FormatChoice,
    custom: Option<&[u8]>,
    msg: &mut Messages,
    err: &mut dyn Write,
) -> Option<Vec<u8>> {
    let mut new_suffix: &[u8] = b"";
    let mut new_len = 0;
    if format != FormatChoice::Raw {
        for &(compressed, uncompressed) in UNCOMPRESSED {
            new_len = test_suffix(compressed, src);
            if new_len != 0 {
                new_suffix = uncompressed;
                break;
            }
        }
    }
    if new_len == 0
        && let Some(c) = custom
    {
        new_len = test_suffix(c, src);
    }
    if new_len == 0 {
        msg.warning(err, m::UNKNOWN_SUFFIX, &[&mask_nonprint(src)]);
        return None;
    }
    let mut dest = src[..new_len].to_vec();
    dest.extend_from_slice(new_suffix);
    Some(dest)
}

/// suffix.c: msg_suffix.
fn msg_suffix(src: &[u8], suffix: &[u8], msg: &mut Messages, err: &mut dyn Write) {
    msg.warning(
        err,
        m::HAS_SUFFIX,
        &[&mask_nonprint(src), &mask_nonprint(suffix)],
    );
}

/// suffix.c: compressed_name. `None` after the "already has suffix"
/// warning. `format` is `.xz`, `.lzma` or raw (args.c rules out the
/// others when compressing).
fn compressed_name(
    src: &[u8],
    format: FormatChoice,
    custom: Option<&[u8]>,
    msg: &mut Messages,
    err: &mut dyn Write,
) -> Option<Vec<u8>> {
    let suffixes: &[&[u8]] = match format {
        FormatChoice::Xz => &[b".xz", b".txz"],
        FormatChoice::Lzma => &[b".lzma", b".tlz"],
        _ => &[],
    };
    for s in suffixes {
        if test_suffix(s, src) != 0 {
            msg_suffix(src, s, msg, err);
            return None;
        }
    }
    if let Some(c) = custom
        && test_suffix(c, src) != 0
    {
        msg_suffix(src, c, msg, err);
        return None;
    }
    // Raw without a custom suffix never gets here (args.c refuses it, or
    // the output is standard output).
    let suffix = custom.or_else(|| suffixes.first().copied()).unwrap_or(b"");
    let mut dest = src.to_vec();
    dest.extend_from_slice(suffix);
    Some(dest)
}

/// suffix.c: suffix_get_dest_name: the output name for `src` under `mode`
/// (compressing or not), or `None` after a warning.
pub(crate) fn dest_name(
    src: &[u8],
    mode: OpMode,
    format: FormatChoice,
    custom: Option<&[u8]>,
    msg: &mut Messages,
    err: &mut dyn Write,
) -> Option<Vec<u8>> {
    if mode == OpMode::Compress {
        compressed_name(src, format, custom, msg, err)
    } else {
        uncompressed_name(src, format, custom, msg, err)
    }
}

/// suffix.c: suffix_set's check: an empty suffix, or one holding a
/// directory separator, is fatal.
pub(crate) fn check(suffix: &[u8], msg: &Messages, err: &mut dyn Write) -> Result<(), u8> {
    if suffix.is_empty() || has_dir_sep(suffix) {
        return Err(msg.fatal(err, m::INVALID_SUFFIX, &[&mask_nonprint(suffix)]));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compat::xz::message::Status;

    fn name(
        src: &str,
        mode: OpMode,
        format: FormatChoice,
        custom: Option<&str>,
    ) -> (Option<String>, String, Status) {
        let mut msg = Messages::new(b"xz");
        let mut err = Vec::new();
        let r = dest_name(
            src.as_bytes(),
            mode,
            format,
            custom.map(str::as_bytes),
            &mut msg,
            &mut err,
        );
        (
            r.map(|v| String::from_utf8(v).unwrap()),
            String::from_utf8(err).unwrap(),
            msg.status,
        )
    }

    /// Review Focus 4's suffix-time half, with the reference's warnings
    /// (recorded from xz 5.8.4: `xz a.xz`, `unxz a`, `unxz a.txz`, ...);
    /// each is a warning (exit 2).
    #[test]
    fn suffix_rules() {
        use FormatChoice::*;
        use OpMode::*;
        let w = Status::Warning;
        let ok = Status::Success;
        assert_eq!(
            name("a.xz", Compress, Xz, None),
            (
                None,
                "xz: a.xz: File already has '.xz' suffix, skipping\n".into(),
                w
            )
        );
        assert_eq!(
            name("a.tlz", Compress, Lzma, None),
            (
                None,
                "xz: a.tlz: File already has '.tlz' suffix, skipping\n".into(),
                w
            )
        );
        assert_eq!(
            name("a.foo", Compress, Xz, Some(".foo")),
            (
                None,
                "xz: a.foo: File already has '.foo' suffix, skipping\n".into(),
                w
            )
        );
        assert_eq!(
            name("a", Decompress, Auto, None),
            (
                None,
                "xz: a: Filename has an unknown suffix, skipping\n".into(),
                w
            )
        );
        assert_eq!(
            name(".xz", Decompress, Auto, None),
            (
                None,
                "xz: .xz: Filename has an unknown suffix, skipping\n".into(),
                w
            )
        );
        assert_eq!(
            name("d/.xz", Decompress, Auto, None).0,
            None,
            "a directory separator before the suffix leaves no name"
        );
        assert_eq!(
            name("a.txz", Decompress, Auto, None),
            (Some("a.tar".into()), String::new(), ok)
        );
        assert_eq!(
            name("a.tlz", Decompress, Lzma, None).0.as_deref(),
            Some("a.tar")
        );
        assert_eq!(name("a.lz", Decompress, Auto, None).0.as_deref(), Some("a"));
        assert_eq!(
            name("a.foo", Decompress, Auto, Some(".foo")).0.as_deref(),
            Some("a")
        );
        assert_eq!(name("a", Compress, Xz, None).0.as_deref(), Some("a.xz"));
        assert_eq!(name("a", Compress, Lzma, None).0.as_deref(), Some("a.lzma"));
        assert_eq!(
            name("a", Compress, Raw, Some(".r")).0.as_deref(),
            Some("a.r")
        );
        // Raw decompression ignores the known suffixes.
        assert_eq!(name("a.xz", Decompress, Raw, None).0, None);
        assert_eq!(
            name("a.xz", Decompress, Raw, Some("z")).0.as_deref(),
            Some("a.x")
        );
        // A name with unprintable bytes is masked in the warning only.
        assert_eq!(
            name("\u{1}.xz", Compress, Xz, None).1,
            "xz: ?.xz: File already has '.xz' suffix, skipping\n"
        );
    }

    #[test]
    fn suffix_set_refuses_empty_and_separators() {
        let msg = Messages::new(b"xz");
        let mut err = Vec::new();
        assert_eq!(check(b"", &msg, &mut err), Err(1));
        assert_eq!(check(b"a/b", &msg, &mut err), Err(1));
        assert_eq!(check(b".x", &msg, &mut err), Ok(()));
        assert_eq!(
            String::from_utf8(err).unwrap(),
            "xz: : Invalid filename suffix\nxz: a/b: Invalid filename suffix\n"
        );
    }
}
