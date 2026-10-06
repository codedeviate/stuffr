//! Rendering an archive-supplied name for a person to read.

use std::fmt;

/// Displays `name` with every character that could rewrite or hide terminal
/// output escaped: C0 controls and DEL (`\0` `\t` `\n` `\r` by name, the rest
/// `\xHH`), C1 controls (`\u{HH}`) and the bidi embeddings, overrides and
/// isolates U+202A–U+202E and U+2066–U+2069 (`\u{HHHH}`). Everything else —
/// backslashes, quotes, spaces, other non-ASCII — is written unchanged, so a
/// name with nothing to escape displays exactly as before. For display only:
/// not reversible, and never used for a name stuffr writes or matches.
pub fn fmt_name(name: &str) -> impl fmt::Display + '_ {
    struct N<'a>(&'a str);
    impl fmt::Display for N<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            for c in self.0.chars() {
                match c {
                    '\0' => f.write_str("\\0")?,
                    '\t' => f.write_str("\\t")?,
                    '\n' => f.write_str("\\n")?,
                    '\r' => f.write_str("\\r")?,
                    '\u{0}'..='\u{1f}' | '\u{7f}' => write!(f, "\\x{:02x}", c as u32)?,
                    '\u{80}'..='\u{9f}' => write!(f, "\\u{{{:x}}}", c as u32)?,
                    '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => {
                        write!(f, "\\u{{{:x}}}", c as u32)?
                    }
                    c => fmt::Write::write_char(f, c)?,
                }
            }
            Ok(())
        }
    }
    N(name)
}

#[cfg(test)]
mod tests {
    use super::fmt_name;
    fn s(x: &str) -> String {
        fmt_name(x).to_string()
    }

    #[test]
    fn a_plain_name_is_unchanged() {
        for n in [
            "a.txt",
            "dir/sub file.tar",
            "C:\\x\\y.txt",
            "\"q\" 'q'",
            "naïve/日本.txt",
        ] {
            assert_eq!(s(n), n);
        }
    }
    #[test]
    fn c0_controls_and_del_are_escaped() {
        assert_eq!(s("a\0b"), "a\\0b");
        assert_eq!(s("a\tb\nc\rd"), "a\\tb\\nc\\rd");
        assert_eq!(s("a\x1b[31mb"), "a\\x1b[31mb");
        assert_eq!(s("\x01\x7f"), "\\x01\\x7f");
    }
    #[test]
    fn c1_controls_are_escaped() {
        assert_eq!(s("a\u{85}b\u{9b}"), "a\\u{85}b\\u{9b}");
    }
    #[test]
    fn bidi_overrides_and_isolates_are_escaped() {
        assert_eq!(s("x\u{202e}gpj.exe"), "x\\u{202e}gpj.exe");
        for c in [
            '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{2066}', '\u{2067}', '\u{2068}',
            '\u{2069}',
        ] {
            assert!(!s(&format!("a{c}b")).contains(c));
        }
    }
}
