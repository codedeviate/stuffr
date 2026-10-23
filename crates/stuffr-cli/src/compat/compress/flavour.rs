//! Which reference the compress family behaves as, and how a run picks it.

use std::ffi::OsString;

/// Which reference the family behaves as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavour {
    /// Apple's `/usr/bin/compress` (`file_cmds-487.0.1`): the default on
    /// macOS and the BSDs.
    Apple,
    /// ncompress 5.0 as Ubuntu 24.04 ships it (`5.0-1`): the default
    /// elsewhere.
    Ncompress,
}

/// The flavour a build uses when `STUFFR_COMPRESS_FLAVOR` is unset or
/// empty: Apple on Apple platforms and the BSDs (the cfg of
/// `gzip::default_flavour`), ncompress everywhere else, Windows included.
pub fn default_flavour() -> Flavour {
    if cfg!(any(
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )) {
        Flavour::Apple
    } else {
        Flavour::Ncompress
    }
}

/// The flavour `STUFFR_COMPRESS_FLAVOR`'s value selects: `apple` or
/// `ncompress`, the default when unset or empty, and `Err(value)` for
/// anything else (another case, a blank).
pub(crate) fn flavour_from(value: Option<OsString>) -> Result<Flavour, OsString> {
    match value {
        None => Ok(default_flavour()),
        Some(v) if v.is_empty() => Ok(default_flavour()),
        Some(v) if v == "apple" => Ok(Flavour::Apple),
        Some(v) if v == "ncompress" => Ok(Flavour::Ncompress),
        Some(v) => Err(v),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flavour_var_selects_and_rejects() {
        let d = default_flavour();
        assert_eq!(flavour_from(None), Ok(d));
        assert_eq!(flavour_from(Some("".into())), Ok(d));
        assert_eq!(flavour_from(Some("apple".into())), Ok(Flavour::Apple));
        assert_eq!(
            flavour_from(Some("ncompress".into())),
            Ok(Flavour::Ncompress)
        );
        for bad in ["Apple", "NCOMPRESS", " apple", "bsd", "ubuntu", "gnu"] {
            assert_eq!(flavour_from(Some(bad.into())), Err(bad.into()));
        }
    }

    #[test]
    fn default_flavour_is_apple_on_macos() {
        let apple = cfg!(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly"
        ));
        assert_eq!(
            default_flavour(),
            if apple {
                Flavour::Apple
            } else {
                Flavour::Ncompress
            }
        );
        if cfg!(target_os = "macos") {
            assert_eq!(default_flavour(), Flavour::Apple);
        }
    }
}
