use crate::format::FormatId;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("usage error: {0}")]
    Usage(String),

    #[error("format `{0}` is not available in this build")]
    FormatNotEnabled(FormatId),

    #[error("could not detect format; leading bytes were {seen}")]
    UnknownFormat { seen: String },

    #[error("input is not seekable and `{format}` requires random access")]
    NotSeekable { format: FormatId },

    #[error("spill limit of {limit} bytes exceeded; raise --max-spill or use a seekable input")]
    SpillLimitExceeded { limit: u64 },

    #[error("resource limit exceeded: {0}")]
    ResourceLimit(String),

    #[error("archive is corrupt: {0}")]
    Corrupt(String),

    #[error("unsafe entry path `{path}` refused")]
    UnsafePath { path: String },

    #[error("fidelity degraded under strict mode: {0} warning(s)")]
    FidelityDegraded(usize),

    #[error("entry `{0}` not found")]
    EntryNotFound(String),

    #[error("unsupported: {0}")]
    Unsupported(String),
}

impl Error {
    /// Maps to the process exit code, per the spec's table. Lives here rather
    /// than in the CLI so it is unit-testable without a process spawn.
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Usage(_) => 2,
            Error::FormatNotEnabled(_) => 3,
            Error::FidelityDegraded(_) => 4,
            Error::Corrupt(_) => 5,
            Error::SpillLimitExceeded { .. } | Error::ResourceLimit(_) => 6,
            Error::UnsafePath { .. } => 7,
            _ => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::FormatId;

    #[test]
    fn exit_codes_match_the_spec_table() {
        assert_eq!(Error::Usage("bad flag".into()).exit_code(), 2);
        assert_eq!(
            Error::FormatNotEnabled(FormatId::new("zstd")).exit_code(),
            3
        );
        assert_eq!(Error::FidelityDegraded(2).exit_code(), 4);
        assert_eq!(Error::Corrupt("bad crc".into()).exit_code(), 5);
        assert_eq!(Error::SpillLimitExceeded { limit: 42 }.exit_code(), 6);
        assert_eq!(Error::ResourceLimit("oom".into()).exit_code(), 6);
        assert_eq!(
            Error::UnsafePath {
                path: "../x".into()
            }
            .exit_code(),
            7
        );
        assert_eq!(Error::Corrupt("x".into()).exit_code(), 5);
    }

    #[test]
    fn not_seekable_names_the_format_so_callers_can_act() {
        let e = Error::NotSeekable {
            format: FormatId::new("squashfs"),
        };
        assert!(e.to_string().contains("squashfs"));
        assert_eq!(e.exit_code(), 1);
    }

    #[test]
    fn unknown_format_reports_what_was_actually_seen() {
        // The error must name the bytes, otherwise debugging a misdetection
        // means adding print statements to the library.
        let e = Error::UnknownFormat {
            seen: "1f 8b 08".into(),
        };
        assert!(e.to_string().contains("1f 8b 08"));
    }
}
