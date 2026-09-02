//! Parsing for `--memory-limit`.
//!
//! Strict on purpose: a malformed size is a usage error naming the accepted
//! forms, never a silent fall back to the default. A user who typed `512MB`
//! and got 25% of RAM instead would have no way to notice.

/// Parses `512`, `512K`, `512M`, `2G` (and lowercase) into bytes.
///
/// Binary multipliers (1024-based), matching what `--max-ratio`'s siblings and
/// every compression tool in this space mean by `M`.
pub fn parse_size(s: &str) -> Result<u64, String> {
    let t = s.trim();
    if t.is_empty() {
        return Err("empty size; expected a number with an optional K, M or G suffix".into());
    }
    let (digits, mult) = match t.as_bytes()[t.len() - 1] {
        b'K' | b'k' => (&t[..t.len() - 1], 1024u64),
        b'M' | b'm' => (&t[..t.len() - 1], 1024 * 1024),
        b'G' | b'g' => (&t[..t.len() - 1], 1024 * 1024 * 1024),
        _ => (t, 1),
    };
    let n: u64 = digits
        .trim()
        .parse()
        .map_err(|_| format!("invalid size `{s}`; expected e.g. 512M, 2G, or a byte count"))?;
    n.checked_mul(mult)
        .ok_or_else(|| format!("size `{s}` overflows a 64-bit byte count"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_bytes_and_every_suffix() {
        assert_eq!(parse_size("512").unwrap(), 512);
        assert_eq!(parse_size("512K").unwrap(), 512 * 1024);
        assert_eq!(parse_size("512M").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_size("2G").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("2g").unwrap(), 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn suffixes_are_binary_not_decimal() {
        // 1024-based, not 1000-based. Stated as a test because getting this
        // wrong is invisible until someone compares against `xz --memlimit`.
        assert_eq!(parse_size("1M").unwrap(), 1_048_576);
        assert_ne!(parse_size("1M").unwrap(), 1_000_000);
    }

    #[test]
    fn malformed_input_is_an_error_naming_the_accepted_forms() {
        for bad in ["", "  ", "512MB", "M", "-1", "1.5G", "abc"] {
            let err = parse_size(bad).unwrap_err();
            assert!(
                err.contains("512M") || err.contains("expected"),
                "error for {bad:?} must name the accepted forms, got: {err}"
            );
        }
    }

    #[test]
    fn overflow_is_reported_rather_than_wrapping() {
        assert!(
            parse_size("18446744073709551615G")
                .unwrap_err()
                .contains("overflow")
        );
    }
}
