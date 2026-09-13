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

    #[error("format is ambiguous; candidates: {candidates}. Pass --format to choose.")]
    AmbiguousFormat { candidates: String },

    #[error("input is not seekable and `{format}` requires random access")]
    NotSeekable { format: FormatId },

    #[error("spill limit of {limit} bytes exceeded; raise --max-spill or use a seekable input")]
    SpillLimitExceeded { limit: u64 },

    #[error("resource limit exceeded: {0}")]
    ResourceLimit(String),

    #[error("archive is corrupt: {0}")]
    Corrupt(String),

    #[error("unsafe entry path `{path}` refused: {reason}")]
    UnsafePath { path: String, reason: &'static str },

    #[error("fidelity degraded under strict mode: {0} warning(s)")]
    FidelityDegraded(usize),

    #[error("entry `{0}` not found")]
    EntryNotFound(String),

    #[error("unsupported: {0}")]
    Unsupported(String),

    #[error("`{format}` can be {available} but not {requested} by this build")]
    CapabilityUnavailable {
        format: FormatId,
        /// The direction that IS available, e.g. "read".
        available: &'static str,
        /// The direction that was asked for and is not, e.g. "written".
        requested: &'static str,
    },

    /// Nesting exceeded [`crate::probe::MAX_CHAIN_DEPTH`]. Names the bound so
    /// the message is actionable rather than merely a refusal.
    #[error("archive nesting exceeds the {depth}-layer limit")]
    ChainTooDeep { depth: usize },

    /// The chain resolved to raw bytes with no container to open — e.g.
    /// `list`/`test` pointed at a plain codec stream, or at a file whose
    /// magic and extension both name none. Names what the input actually
    /// resolved to (`chain.describe()`), so "unpack this .gz" is actionable
    /// rather than a bare refusal.
    #[error("{chain} is not an archive — it has no entries to list")]
    NotAnArchive { chain: String },
}

impl Error {
    /// "Entry number `index` does not exist; here is what does."
    ///
    /// One constructor rather than a `format!` at each raiser, because there
    /// are two routes to an out-of-range index and they must report it
    /// IDENTICALLY: a container's own [`crate::ArchiveRead::by_index`] finds
    /// it immediately (zip, which has a central directory to check against),
    /// while a caller counting a forward walk finds it only at the end of the
    /// archive (tar, ar, cpio, and anything on a pipe). A script that could
    /// tell those apart from the message would be reading an implementation
    /// detail of the source it was handed.
    ///
    /// [`Self::EntryNotFound`] rather than [`Self::Usage`] because the variant
    /// exists for exactly this — "you named an entry this archive does not
    /// have" — and carries the same exit code, 2. The payload is shaped to
    /// read inside that variant's own `entry \`{0}\` not found` wording.
    ///
    /// Indices are 0-based throughout, so the valid range is stated
    /// explicitly rather than left to be derived from the count: `0-5` is
    /// harder to get wrong than "6 entries" is.
    pub fn entry_index_out_of_range(index: usize, entries: usize) -> Self {
        Error::EntryNotFound(match entries {
            0 => format!("#{index} (this archive has no entries)"),
            n => format!(
                "#{index} (valid indices are 0-{} in this {n}-entry archive)",
                n - 1
            ),
        })
    }

    /// Maps to the process exit code, per the spec's table. Lives here rather
    /// than in the CLI so it is unit-testable without a process spawn.
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Usage(_) => 2,
            Error::NotAnArchive { .. } => 2,
            // The caller named an entry the archive does not contain — the
            // same shape as naming a format this build does not have, and
            // the same answer `NotAnArchive` above gives for "you pointed
            // this verb at the wrong thing". Explicit, not the wildcard
            // below: `stuffr unpack a.tar -C out nosuch.txt` extracting
            // nothing must be distinguishable from an i/o failure.
            Error::EntryNotFound(_) => 2,
            // The same shape again, and the fourth wrong code this
            // wildcard has produced. `stuffr list plain.txt.gz` (not an
            // archive) exited 2; `stuffr list plain.txt` (no format at all)
            // exited 1, as if stuffr had failed rather than the caller
            // having pointed a verb at the wrong file. `AmbiguousFormat`'s
            // own message literally says "Pass `--format` to choose" —
            // actionable advice with an exit code that says "internal
            // failure". Both are usage, both are 2.
            Error::UnknownFormat { .. } | Error::AmbiguousFormat { .. } => 2,
            Error::FormatNotEnabled(_) => 3,
            Error::CapabilityUnavailable { .. } => 3,
            // Exit 3 is "this build cannot do that", and every raiser of
            // `Unsupported` in this workspace is exactly that — a capability
            // or expressiveness limit, never an internal failure:
            //
            // * tar's, ar's and cpio's `by_index` refusal on a seekable
            //   source ("this container carries no entry index, by design").
            // * cpio's 4 GiB per-entry ceiling, which is its `u32` size
            //   field and not a bug.
            // * zip's unsupported compression method — an encrypted entry, a
            //   pre-deflate legacy method, or the pure tier's zstd gap, whose
            //   message names `--features c-backed`.
            // * a `Chain` variant added upstream that this build does not
            //   know how to open, decode or describe.
            // * `create_symlink` on a non-unix host.
            //
            // Explicit, not the wildcard below, and it did fall through it
            // until Phase 2's Task 11: every one of those was reported as a
            // generic failure, indistinguishable from an internal error, so a
            // user told "rebuild with `--features c-backed`" got the same
            // exit code as a panic-adjacent bug. That is the THIRD wrong code
            // this wildcard has produced in this phase, after
            // `ChainTooDeep` and `EntryNotFound`.
            Error::Unsupported(_) => 3,
            // "You asked for random access and this source cannot do it" is
            // the same answer as the two arms above — a capability limit,
            // actionable, and never an internal failure. It is the *required*
            // reply to `by_index` on a forward-only source (container
            // conformance property 6, and SEVEN raisers: `tar.rs`, `ar.rs`,
            // `cpio.rs` and `zip.rs` each raise it once for exactly this, and
            // `ladder.rs` (twice) and `probe.rs` (once) raise it from below
            // the container layer, when the ladder itself cannot supply
            // seek), so a valid archive on a pipe produced it on every single
            // read — and the wildcard below
            // reported that by-design refusal as exit 1, "stuffr failed".
            // `entries.rs:453` already treats it as interchangeable with
            // `Unsupported` when deciding whether to fall back to a forward
            // walk; the exit code now agrees with that. The FIFTH wrong code
            // this wildcard has produced, after `ChainTooDeep`,
            // `EntryNotFound`, `Unsupported` and the
            // `UnknownFormat`/`AmbiguousFormat` pair. Found by Phase 3a's
            // honesty oracle (`honesty.rs`), before the fuzzer had run once.
            Error::NotSeekable { .. } => 3,
            Error::FidelityDegraded(_) => 4,
            Error::Corrupt(_) => 5,
            // A nesting bound is a bound on WORK, the same family as the
            // spill and ratio limits — never exit 5, so a refused nesting
            // bomb stays distinguishable from a corrupt file. Explicit, not
            // the wildcard below: falling through it would make a refused
            // nesting bomb indistinguishable from an internal error.
            Error::SpillLimitExceeded { .. }
            | Error::ResourceLimit(_)
            | Error::ChainTooDeep { .. } => 6,
            Error::UnsafePath { .. } => 7,
            // A wrong exit code landing here is not always this match's own
            // fault: it can equally mean the wrong `Error` variant was
            // constructed upstream, before this function ever ran. See
            // `Error::from_decode_io` — Task 4b's fix lives there, not here.
            _ => 1,
        }
    }

    /// Classifies an io error that arose while decoding.
    ///
    /// Malformed input becomes [`Error::Corrupt`] (exit 5); everything else
    /// stays [`Error::Io`] (exit 1). `InvalidData` is the convention every
    /// codec's decoder is expected to normalise onto for malformed input; a
    /// codec whose backend disagrees adapts at its own boundary rather than
    /// this classification changing. gzip is one such codec: flate2's
    /// pure-Rust backend actually raises `InvalidInput` and `UnexpectedEof`,
    /// never `InvalidData`, so gzip's decoder wraps it in an adapter that
    /// folds both onto `InvalidData` before this function ever sees them.
    ///
    /// `OutOfMemory` becomes [`Error::ResourceLimit`] (exit 6), not
    /// `Corrupt`: a codec whose dictionary allocation would exceed
    /// `DecodeOpts::memory_limit` is refusing to allocate, not reporting a
    /// damaged file, and exit 5 would actively mislead the caller about
    /// which of those happened. A codec that raises this kind is expected to
    /// have NOT routed it through the same `InvalidData`-folding adapter it
    /// uses for malformed input, the same way `InvalidData` above is a
    /// convention the codec opts into deliberately.
    ///
    /// One rule here rather than a helper each codec calls: putting the
    /// decision in nine places means the natural code — a bare `?` on an
    /// `io::Error` — silently bypasses it, and a convention whose failure mode
    /// is invisible is not a convention. Conformance property 9 enforces the
    /// codec half, that malformed input surfaces as `InvalidData` at all.
    ///
    /// Lives in `stuffr-core` rather than in `ops` because Phase 2's containers
    /// need the identical classification on their own decode paths.
    ///
    /// **Task 4b (Phase 3a's fuzzing harness) added a fourth call site:**
    /// `probe.rs`'s `resolve_chain_deep_with` re-probes a DECODED stream
    /// whenever a codec has no container above it and the path named
    /// nothing further (stdin, or an extension that ran out) — the loop
    /// documented on `resolve_chain_deep`'s own doc comment. That re-probe
    /// used to read through a bare `?`, so a truncated zlib stream
    /// (`\x78\xda\x0a`, three bytes) or an empty file named `.lz` reported
    /// `Error::Io` — exit 1, "stuffr failed" — for input that is simply
    /// corrupt, while `stuffr cat` on the IDENTICAL bytes (via
    /// `ops::decompress`, whose decode read was already wired to this
    /// function) correctly exited 5. This is deliberately NOT filed as a
    /// sixth instance of `exit_code`'s `_ => 1` wildcard misfiling a KNOWN
    /// variant (see that match's own comment for the five it has produced):
    /// `Error::Io` reaching that wildcard is correct, by construction —
    /// it has no dedicated arm because the wildcard IS its arm. The bug
    /// here was upstream of `exit_code` entirely: the wrong variant got
    /// constructed in the first place, at a read that passed through a
    /// decoder without this classifier's protection.
    pub fn from_decode_io(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::InvalidData => Error::Corrupt(e.to_string()),
            std::io::ErrorKind::OutOfMemory => Error::ResourceLimit(e.to_string()),
            _ => Error::Io(e),
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
        assert_eq!(
            Error::Unsupported("no zstd in this build".into()).exit_code(),
            3
        );
        assert_eq!(
            Error::NotSeekable {
                format: FormatId::new("squashfs")
            }
            .exit_code(),
            3
        );
        assert_eq!(Error::FidelityDegraded(2).exit_code(), 4);
        assert_eq!(Error::Corrupt("bad crc".into()).exit_code(), 5);
        assert_eq!(Error::EntryNotFound("nosuch.txt".into()).exit_code(), 2);
        assert_eq!(Error::SpillLimitExceeded { limit: 42 }.exit_code(), 6);
        assert_eq!(Error::ResourceLimit("oom".into()).exit_code(), 6);
        assert_eq!(
            Error::UnsafePath {
                path: "../x".into(),
                reason: "path traversal above the destination",
            }
            .exit_code(),
            7
        );
    }

    /// The refusal has to say what IS valid, not merely that the asked-for
    /// index is not — and the zero-entry case must not underflow its way to
    /// "valid indices are 0-18446744073709551615".
    #[test]
    fn an_out_of_range_index_names_the_valid_range_and_survives_an_empty_archive() {
        let e = Error::entry_index_out_of_range(9, 6);
        assert_eq!(e.exit_code(), 2);
        let text = e.to_string();
        assert!(text.contains("#9"), "{text}");
        assert!(
            text.contains("0-5"),
            "the valid range must be stated, not left to be derived: {text}"
        );

        let empty = Error::entry_index_out_of_range(0, 0).to_string();
        assert!(
            empty.contains("no entries") && !empty.contains("0-1844"),
            "an empty archive must not underflow into a nonsense range: {empty}"
        );
    }

    #[test]
    fn from_decode_io_keys_resource_limit_off_out_of_memory_not_corrupt() {
        // A codec refusing to allocate a declared dictionary is not reporting
        // a damaged file — exit 6, never exit 5. See `DecodeOpts::memory_limit`.
        let io_err = std::io::Error::new(std::io::ErrorKind::OutOfMemory, "too big");
        let classified = Error::from_decode_io(io_err);
        assert!(matches!(classified, Error::ResourceLimit(_)));
        assert_eq!(classified.exit_code(), 6);
    }

    #[test]
    fn not_seekable_names_the_format_so_callers_can_act() {
        let e = Error::NotSeekable {
            format: FormatId::new("squashfs"),
        };
        assert!(e.to_string().contains("squashfs"));
        // Exit 3, not 1. A source that cannot seek is a capability limit in
        // exactly the sense `Unsupported` and `CapabilityUnavailable` are,
        // and it is the mandated answer to `by_index` on a forward-only
        // source — so exit 1 meant every valid archive read from a pipe
        // reported "stuffr failed". See `exit_code`'s own arm for why this
        // is the fifth variant the wildcard has misfiled.
        assert_eq!(e.exit_code(), 3);
        assert_ne!(
            e.exit_code(),
            1,
            "a by-design refusal must stay distinguishable from an internal failure"
        );
    }

    #[test]
    fn unsupported_is_a_capability_limit_not_a_generic_failure() {
        // The three exit-3 variants say the same thing at different
        // granularities — "this build cannot do that" — so they must not
        // disagree on the code. `Unsupported` fell through the wildcard to 1
        // until Phase 2's Task 11, which made a container's honest
        // "rebuild with `--features c-backed`" indistinguishable from an
        // internal error. See `exit_code`'s own comment for the full list of
        // raisers and why every one of them belongs here.
        let unsupported = Error::Unsupported(
            "zip entry uses compression method 93 (zstd); rebuild with `--features c-backed`"
                .into(),
        );
        assert_eq!(unsupported.exit_code(), 3);
        assert_eq!(
            Error::FormatNotEnabled(FormatId::new("zstd")).exit_code(),
            3
        );
        assert_eq!(
            Error::CapabilityUnavailable {
                format: FormatId::new("lzma"),
                available: "read as a zip entry",
                requested: "written as one",
            }
            .exit_code(),
            3
        );
        assert_ne!(
            unsupported.exit_code(),
            1,
            "exit 1 is an internal failure; a capability limit is actionable and must be \
             distinguishable from one"
        );
    }

    #[test]
    fn chain_too_deep_is_a_resource_limit_not_a_generic_failure() {
        // A refused nesting bomb must be distinguishable from an internal
        // error — falling through the wildcard to 1 would erase that.
        assert_eq!(Error::ChainTooDeep { depth: 4 }.exit_code(), 6);
    }

    #[test]
    fn not_an_archive_names_the_chain_and_is_a_usage_error() {
        let e = Error::NotAnArchive {
            chain: "gzip".into(),
        };
        assert!(
            e.to_string().contains("gzip"),
            "must name what the input resolved to: {e}"
        );
        assert_eq!(e.exit_code(), 2);
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

    /// "You pointed the verb at the wrong file" is one answer, not three.
    ///
    /// `NotAnArchive` already exited 2. `UnknownFormat` and
    /// `AmbiguousFormat` fell through the wildcard to 1 — an internal
    /// failure — so `stuffr list plain.txt.gz` exited 2 and `stuffr list
    /// plain.txt` exited 1 for the same class of mistake. Explicit arms,
    /// not the wildcard: that wildcard has now produced a wrong code five
    /// times, `NotSeekable` being the fifth (see its own arm in
    /// `exit_code`).
    #[test]
    fn pointing_a_verb_at_the_wrong_file_is_always_exit_two() {
        assert_eq!(
            Error::UnknownFormat {
                seen: "de ad be ef".into()
            }
            .exit_code(),
            2,
            "an undetectable format is the caller's mistake, not an internal failure"
        );
        let ambiguous = Error::AmbiguousFormat {
            candidates: "lzma, lzip".into(),
        };
        assert_eq!(
            ambiguous.exit_code(),
            2,
            "a message that says `Pass --format to choose` is actionable, so exit 2"
        );
        assert!(
            ambiguous.to_string().contains("--format"),
            "and it must keep saying so: {ambiguous}"
        );
        // The neighbour they must agree with.
        assert_eq!(
            Error::NotAnArchive {
                chain: "gzip".into()
            }
            .exit_code(),
            2
        );
        // And the codes they must NOT collide with: a build-capability
        // limit is still 3, a damaged file still 5.
        assert_eq!(Error::Unsupported("no".into()).exit_code(), 3);
        assert_eq!(Error::Corrupt("bad".into()).exit_code(), 5);
    }
}
