//! Names a reader cannot carry verbatim (bug hunt 2026-11-15, finding 20).

use stuffr_core::{Fidelity, FormatId};

/// `None` when `bytes` is valid UTF-8; otherwise the
/// [`Fidelity::NameNotUtf8`] that says so for `entry` (the name as
/// delivered), spelling the stored bytes with `\xNN` for each byte that is
/// not UTF-8.
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
    for chunk in bytes.utf8_chunks() {
        raw.push_str(chunk.valid());
        for b in chunk.invalid() {
            raw.push_str(&format!("\\x{b:02x}"));
        }
    }
    Some(Fidelity::NameNotUtf8 {
        format,
        entry: entry.to_owned(),
        field,
        raw,
    })
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
