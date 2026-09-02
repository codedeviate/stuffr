//! Human-readable byte-count rendering.
//!
//! Lives here, not in the CLI, so a codec's `--memory-limit` refusal message
//! and `stf info`'s resolved-limit display share one formatter rather than
//! inventing their own — see the whole-branch review's LOW-5 finding: before
//! this, the same quantity (a declared or configured memory bound) appeared
//! as raw **bytes** (`xz_pure.rs`, `lzip.rs`), **KiB** (`lzma_pure.rs`), and
//! **MiB/GiB** (`stf info`) in the same build, which is exactly backwards for
//! the one message a user reads to decide what to pass back to
//! `--memory-limit`.
//!
//! `stuffr-cli`'s `size::parse_size` is the inverse and stays in the CLI
//! crate — it is flag-syntax (`512M`, `2G`), not a general utility, and this
//! crate has no reason to know what a command-line flag looks like. This
//! function has no such reason to live above `stuffr-core`: it is pure
//! arithmetic, with no format dependency, so codecs in `stuffr-formats` can
//! use it directly for their own refusal messages.

/// Renders a byte count the way a human reads it.
///
/// Exact multiples get a bare suffix (`256 MiB`); anything else keeps one
/// decimal (`1.5 GiB`), because rounding a limit or a declared size to a tidy
/// figure would be actively unhelpful in a message someone is using to size
/// a flag.
pub fn format_size(bytes: u64) -> String {
    const UNITS: [(u64, &str); 3] = [
        (1024 * 1024 * 1024, "GiB"),
        (1024 * 1024, "MiB"),
        (1024, "KiB"),
    ];
    for (unit, name) in UNITS {
        if bytes >= unit {
            // `is_multiple_of` rather than `% == 0` because clippy requires
            // it (MSRV 1.88).
            if bytes.is_multiple_of(unit) {
                return format!("{} {name}", bytes / unit);
            }
            return format!("{:.1} {name}", bytes as f64 / unit as f64);
        }
    }
    format!("{bytes} bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_size_is_readable_and_exact_where_it_can_be() {
        assert_eq!(format_size(256 * 1024 * 1024), "256 MiB");
        assert_eq!(format_size(2 * 1024 * 1024 * 1024), "2 GiB");
        assert_eq!(format_size(512), "512 bytes");
        assert_eq!(format_size(1536), "1.5 KiB");
        // Not rounded to "2 GiB": someone reading this to check a limit needs
        // the value, not a tidy approximation of it.
        assert_eq!(
            format_size(1024 * 1024 * 1024 + 512 * 1024 * 1024),
            "1.5 GiB"
        );
    }
}
