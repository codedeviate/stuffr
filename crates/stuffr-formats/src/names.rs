//! Names a reader cannot carry verbatim (bug hunt 2026-11-15, finding 20).

use stuffr_core::{Fidelity, FidelityReport, FormatId};

/// How much of a name a warning holds: a name may be 16 MiB, and a
/// warning lives until the walk ends (task 4 review, I1).
const CLIP: usize = 256;

/// [`Fidelity::Unlisted`]'s `what` for the names [`not_utf8`] reports, shared
/// by the tar and ar readers (here so that either compiles without the other).
pub(crate) const NAME_NOT_UTF8: &str = "have a name that is not valid UTF-8";

/// `s` cut to [`CLIP`] bytes at a character boundary, `…` marking a cut.
pub(crate) fn clip(s: &str) -> String {
    if s.len() <= CLIP {
        return s.to_owned();
    }
    let mut end = CLIP;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// `None` when `bytes` is valid UTF-8; otherwise the
/// [`Fidelity::NameNotUtf8`] that says so for `entry` (the name as
/// delivered), spelling the stored bytes with `\xNN` for each byte that is
/// not UTF-8. Both are held as a prefix of about [`CLIP`] bytes.
pub(crate) fn not_utf8(
    format: FormatId,
    entry: &str,
    field: &'static str,
    bytes: &[u8],
) -> Option<Fidelity> {
    if std::str::from_utf8(bytes).is_ok() {
        return None;
    }
    let mut raw = String::new();
    'spell: for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            if raw.len() >= CLIP {
                break 'spell;
            }
            raw.push(c);
        }
        for b in chunk.invalid() {
            if raw.len() >= CLIP {
                break 'spell;
            }
            raw.push_str(&format!("\\x{b:02x}"));
        }
    }
    if raw.len() >= CLIP {
        raw.push('…');
    }
    Some(Fidelity::NameNotUtf8 {
        format,
        entry: clip(entry),
        field,
        raw,
    })
}

/// One kind of per-entry warning, listed for the first [`Self::LISTED`]
/// entries and counted after that in one [`Fidelity::Unlisted`] (zip's
/// `DisagreementLog` is the precedent).
pub(crate) struct WarningLog {
    format: FormatId,
    what: &'static str,
    listed: u64,
    unlisted: u64,
    /// Where the report holds the count once there is one.
    at: Option<usize>,
}

impl WarningLog {
    /// Warnings listed one by one before the rest are counted.
    pub(crate) const LISTED: u64 = 64;

    pub(crate) fn new(format: FormatId, what: &'static str) -> Self {
        Self {
            format,
            what,
            listed: 0,
            unlisted: 0,
            at: None,
        }
    }

    /// Record `w`, made by `make` only while warnings are still listed.
    pub(crate) fn warn(&mut self, report: &mut FidelityReport, make: impl FnOnce() -> Fidelity) {
        if self.listed < Self::LISTED {
            self.listed += 1;
            report.warn(make());
            return;
        }
        self.unlisted += 1;
        let entries = self.unlisted;
        if let Some(at) = self.at
            && let Some(Fidelity::Unlisted { entries: n, .. }) = report.warnings.get_mut(at)
        {
            *n = entries;
            return;
        }
        self.at = Some(report.warnings.len());
        report.warn(Fidelity::Unlisted {
            format: self.format,
            what: self.what,
            entries,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_utf8_earns_nothing_and_the_rest_is_spelled_byte_by_byte() {
        let f = FormatId::new("tar");
        assert_eq!(not_utf8(f, "café", "name", "café".as_bytes()), None);
        let Some(Fidelity::NameNotUtf8 { raw, field, .. }) =
            not_utf8(f, "caf\u{fffd}", "name", b"caf\xe9")
        else {
            panic!()
        };
        assert_eq!((raw.as_str(), field), ("caf\\xe9", "name"));
        let a = not_utf8(f, "x", "name", b"caf\xe9");
        let b = not_utf8(f, "x", "name", b"caf\xe8");
        assert_ne!(a, b, "two stored names stay distinguishable");
    }
}
