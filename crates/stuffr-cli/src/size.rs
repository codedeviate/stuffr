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
        // Shows the same concrete forms every other error here shows. A user
        // who passed an empty value needs the guidance at least as much as one
        // who mistyped a suffix, and a test now requires every syntax error to
        // carry it.
        return Err("empty size; expected e.g. 512M, 2G, or a byte count".into());
    }
    let (digits, mult) = match t.as_bytes()[t.len() - 1] {
        b'K' | b'k' => (&t[..t.len() - 1], 1024u64),
        b'M' | b'm' => (&t[..t.len() - 1], 1024 * 1024),
        b'G' | b'g' => (&t[..t.len() - 1], 1024 * 1024 * 1024),
        _ => (t, 1),
    };
    let n: u64 = digits.trim().parse::<u64>().map_err(|e| match e.kind() {
        // A digit string too large for u64 is an overflow, not a syntax
        // error, and saying "invalid size" for `99999999999999999999` would
        // send the reader hunting for a typo that is not there.
        std::num::IntErrorKind::PosOverflow => {
            format!("size `{s}` overflows a 64-bit byte count")
        }
        _ => format!("invalid size `{s}`; expected e.g. 512M, 2G, or a byte count"),
    })?;
    n.checked_mul(mult)
        .ok_or_else(|| format!("size `{s}` overflows a 64-bit byte count"))
}

/// Renders a byte count the way a human reads it, for `stf info`.
///
/// The inverse of [`parse_size`], and the two live in different crates but
/// are tested together below so they cannot drift: anything this prints
/// must parse back to the same value.
///
/// Lives in `stuffr-core` now, not here — whole-branch review LOW-5: three
/// codecs in `stuffr-formats` had their own, differently-united renderings
/// of the identical "declared size vs. configured limit" message this
/// function was already written for, and `stuffr-formats` cannot depend on
/// this crate to reach it. See `stuffr_core::size`'s module doc for the
/// full reasoning. Re-exported here so every existing caller in this crate
/// (`main.rs`'s `stuffr_cli::size::format_size`, this module's own tests)
/// keeps working unchanged.
pub use stuffr::size::format_size;

#[cfg(test)]
mod tests {
    use super::*;

    // `format_size`'s own rendering behaviour is tested where it now lives,
    // `stuffr_core::size`. What belongs here is the property that only holds
    // with BOTH functions present: this crate's `parse_size` must invert
    // that crate's `format_size`.
    #[test]
    fn every_exact_rendering_parses_back_to_itself() {
        // The two functions live together so they cannot drift; this is what
        // enforces it. Only exact multiples round-trip — a "1.5 KiB" rendering
        // is for human eyes and parse_size deliberately rejects floats.
        for n in [
            512u64,
            1024,
            4096,
            256 * 1024 * 1024,
            2 * 1024 * 1024 * 1024,
        ] {
            let rendered = format_size(n);
            let compact: String = rendered
                .replace(" bytes", "")
                .replace(" KiB", "K")
                .replace(" MiB", "M")
                .replace(" GiB", "G");
            assert_eq!(
                parse_size(&compact).unwrap(),
                n,
                "{n} rendered as {rendered:?} did not parse back"
            );
        }
    }

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
        // The `||` this replaced was too weak to constrain anything: its
        // second branch, `contains("expected")`, matches nearly every message
        // the function can produce, so the assertion passed almost by default.
        // Requiring the concrete example means a future rewording that drops
        // the guidance actually fails.
        for bad in [
            "", "  ", "512MB", "M", "-1", "1.5G", "abc", "512 MB", "K512",
        ] {
            let err = parse_size(bad).unwrap_err();
            assert!(
                err.contains("512M") && err.contains("2G"),
                "error for {bad:?} must show the accepted forms concretely, got: {err}"
            );
        }
    }

    #[test]
    fn forms_that_parse_but_are_worth_pinning() {
        // Neither is documented anywhere a user would look, so pin the actual
        // behaviour rather than leaving it to be discovered and "fixed".
        //
        // A space before the suffix is accepted, because the digit half is
        // trimmed: `512 M` is 512 MiB.
        assert_eq!(parse_size("512 M").unwrap(), 512 * 1024 * 1024);
        // A leading `+` is accepted by Rust's unsigned FromStr.
        assert_eq!(parse_size("+512").unwrap(), 512);
    }

    #[test]
    fn a_digit_string_too_large_for_u64_reports_overflow_not_a_syntax_error() {
        // Distinct from the exact-u64::MAX-times-a-multiplier case below:
        // this overflows before any multiplier applies, and calling it
        // "invalid size" would send the reader hunting for a typo.
        let err = parse_size("99999999999999999999999").unwrap_err();
        assert!(
            err.contains("overflow"),
            "expected an overflow message, got: {err}"
        );
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
