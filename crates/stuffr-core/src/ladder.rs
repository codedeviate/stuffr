//! The adaptive stream ladder.
//!
//! A container never opens a file. It declares what it needs via
//! [`ContainerCaps`] and this module supplies the highest reachable rung,
//! together with the fidelity cost of getting there.

use crate::error::{Error, Result};
use crate::fidelity::{Fidelity, FidelityReport, Rung};
use crate::format::{ContainerCaps, FormatId};
use crate::source::{Source, SpillPolicy, SpillSource};

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum StreamPolicy {
    /// Require an authoritative read. Errors rather than approximating.
    Exact,
    /// The full ladder. Each rung can be individually disabled.
    Adaptive {
        allow_forward_only: bool,
        spill: SpillPolicy,
        allow_degraded: bool,
    },
    /// Never seek and never spool. Constant memory, single pass.
    ForwardOnly,
}

impl Default for StreamPolicy {
    fn default() -> Self {
        StreamPolicy::Adaptive {
            allow_forward_only: true,
            spill: SpillPolicy::default(),
            allow_degraded: true,
        }
    }
}

/// A source prepared for a specific container, with the cost of preparing it.
///
/// `#[non_exhaustive]`: this struct is constructed only inside `stuffr-core`
/// (see the constructors in this module) and destructured everywhere else —
/// every `Container::open` impl will do `let Resolved { source, rung, report
/// } = resolved;`. A struct in that shape — destructured downstream, never
/// constructed — takes the attribute for free: there is no
/// `..Default::default()` literal to break, only a future field to add
/// without breaking every format crate's destructure at once. See the
/// `#[non_exhaustive]` section of CONTRIBUTING.md.
#[non_exhaustive]
pub struct Resolved {
    pub source: Box<dyn Source>,
    pub rung: Rung,
    pub report: FidelityReport,
}

// Manual impl: `Source` carries no `Debug` bound, so `Box<dyn Source>` cannot
// derive it. Needed for `Result<Resolved, _>::unwrap_err()` in the tests below.
impl std::fmt::Debug for Resolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolved")
            .field("source", &"<dyn Source>")
            .field("rung", &self.rung)
            .field("report", &self.report)
            .finish()
    }
}

/// Referenced by `resolve` for the `ForwardOnly` policy. A `static` rather than
/// an inline `&SpillPolicy::Off`: `SpillPolicy` owns a `PathBuf`, so it has a
/// `Drop` impl, rvalue static promotion does not apply, and the temporary would
/// not outlive the borrow.
static NO_SPILL: SpillPolicy = SpillPolicy::Off;

/// Seeds the report with the losses implied by reading `caps` at `rung`.
///
/// Only capability-derived warnings belong here. Per-entry findings are added
/// by the container as it parses, by calling [`FidelityReport::warn`] directly
/// on the report it inherited from [`Resolved`] — not by building a second
/// report and folding it in with `merge`.
fn seed_report(rung: Rung, format: FormatId, caps: ContainerCaps) -> FidelityReport {
    let mut report = FidelityReport::new(rung);
    if rung.is_authoritative() {
        return report;
    }
    if caps.trailing_index {
        report.warn(Fidelity::TrailingIndexUnread { format });
        report.warn(Fidelity::EntryCountUnknown);
    }
    report
}

/// Places `src` on the highest ladder rung reachable under `policy`.
///
/// Order: Exact → ForwardOnly → Spilled → Degraded. ForwardOnly is preferred
/// over Spilled so that piping a zip into a grep does not touch the disk. A
/// user who wants full fidelity instead opts out via `allow_forward_only: false`.
pub fn resolve(
    src: Box<dyn Source>,
    format: FormatId,
    caps: ContainerCaps,
    policy: &StreamPolicy,
) -> Result<Resolved> {
    // Rung 1: already seekable.
    if src.caps().seekable {
        return Ok(Resolved {
            source: src,
            rung: Rung::Exact,
            report: FidelityReport::exact(),
        });
    }

    let (allow_forward_only, spill, allow_degraded) = match policy {
        StreamPolicy::Exact => return Err(Error::NotSeekable { format }),
        StreamPolicy::ForwardOnly => (true, &NO_SPILL, false),
        StreamPolicy::Adaptive {
            allow_forward_only,
            spill,
            allow_degraded,
        } => (*allow_forward_only, spill, *allow_degraded),
    };

    // Rung 2: full-fidelity forward parse.
    if caps.forward_parse && allow_forward_only && !caps.needs_seek {
        return Ok(Resolved {
            source: src,
            rung: Rung::ForwardOnly,
            report: seed_report(Rung::ForwardOnly, format, caps),
        });
    }

    // Rung 3: spool so the container gets real random access.
    if spill.is_enabled() {
        let spilled = SpillSource::materialize(src, spill)?;
        return Ok(Resolved {
            source: Box::new(spilled),
            rung: Rung::Spilled,
            report: FidelityReport::new(Rung::Spilled),
        });
    }

    // Rung 4: best-effort salvage.
    if allow_degraded && caps.degraded_parse {
        return Ok(Resolved {
            source: src,
            rung: Rung::Degraded,
            report: seed_report(Rung::Degraded, format, caps),
        });
    }

    Err(Error::NotSeekable { format })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{FileSource, ReaderSource};
    use crate::{Fidelity, FormatId, Rung};

    const ZIP: FormatId = FormatId::new("zip");
    const SQUASHFS: FormatId = FormatId::new("squashfs");

    fn pipe(bytes: &[u8]) -> Box<dyn Source> {
        Box::new(ReaderSource::new(std::io::Cursor::new(bytes.to_vec())))
    }

    fn file(bytes: &[u8]) -> Box<dyn Source> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut f, bytes).unwrap();
        let (_, path) = f.keep().unwrap();
        Box::new(FileSource::open(&path).unwrap())
    }

    /// zip: forward-parseable, trailing index, per-entry codecs.
    fn zip_caps() -> ContainerCaps {
        ContainerCaps {
            read: true,
            forward_parse: true,
            trailing_index: true,
            per_entry_codec: true,
            ..Default::default()
        }
    }

    /// squashfs: a filesystem image. Cannot be parsed forward at all.
    fn squashfs_caps() -> ContainerCaps {
        ContainerCaps {
            read: true,
            needs_seek: true,
            ..Default::default()
        }
    }

    #[test]
    fn seekable_input_reaches_exact_and_reports_no_loss() {
        let r = resolve(file(b"payload"), ZIP, zip_caps(), &StreamPolicy::default()).unwrap();
        assert_eq!(r.rung, Rung::Exact);
        assert!(r.report.is_lossless());
    }

    #[test]
    fn pipe_prefers_forward_only_over_spilling_to_disk() {
        // The motivating case: grep a zip on a pipe without touching the disk.
        let r = resolve(pipe(b"payload"), ZIP, zip_caps(), &StreamPolicy::default()).unwrap();
        assert_eq!(r.rung, Rung::ForwardOnly);
        assert!(!r.report.is_lossless());
    }

    #[test]
    fn forward_only_on_a_trailing_index_format_records_the_index_loss() {
        let r = resolve(pipe(b"payload"), ZIP, zip_caps(), &StreamPolicy::default()).unwrap();
        assert!(
            r.report
                .warnings
                .contains(&Fidelity::TrailingIndexUnread { format: ZIP })
        );
        assert!(r.report.warnings.contains(&Fidelity::EntryCountUnknown));
    }

    #[test]
    fn a_forward_parseable_format_without_a_trailing_index_loses_nothing_specific() {
        // tar on a pipe: rung is ForwardOnly, but there is no index to lose.
        let tar = ContainerCaps {
            read: true,
            forward_parse: true,
            ..Default::default()
        };
        let r = resolve(
            pipe(b"payload"),
            FormatId::new("tar"),
            tar,
            &StreamPolicy::default(),
        )
        .unwrap();
        assert_eq!(r.rung, Rung::ForwardOnly);
        assert!(r.report.warnings.is_empty());
    }

    #[test]
    fn needs_seek_format_on_a_pipe_spills_and_stays_authoritative() {
        let r = resolve(
            pipe(b"payload"),
            SQUASHFS,
            squashfs_caps(),
            &StreamPolicy::default(),
        )
        .unwrap();
        assert_eq!(r.rung, Rung::Spilled);
        assert!(r.rung.is_authoritative());
        assert!(r.report.is_lossless());
        assert!(
            r.source.caps().seekable,
            "spilling must produce a seekable source"
        );
    }

    #[test]
    fn spilling_preserves_the_bytes() {
        let mut r = resolve(
            pipe(b"0123456789"),
            SQUASHFS,
            squashfs_caps(),
            &StreamPolicy::default(),
        )
        .unwrap();
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut r.source, &mut out).unwrap();
        assert_eq!(out, b"0123456789");
    }

    #[test]
    fn exact_policy_refuses_a_pipe_and_names_the_format() {
        let err = resolve(pipe(b"x"), SQUASHFS, squashfs_caps(), &StreamPolicy::Exact).unwrap_err();
        assert!(matches!(err, crate::Error::NotSeekable { format } if format == SQUASHFS));
    }

    #[test]
    fn forward_only_policy_never_spills() {
        let err = resolve(
            pipe(b"x"),
            SQUASHFS,
            squashfs_caps(),
            &StreamPolicy::ForwardOnly,
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::NotSeekable { .. }));
    }

    #[test]
    fn forward_only_policy_still_works_where_the_format_allows_it() {
        let r = resolve(pipe(b"x"), ZIP, zip_caps(), &StreamPolicy::ForwardOnly).unwrap();
        assert_eq!(r.rung, Rung::ForwardOnly);
    }

    #[test]
    fn spill_off_falls_through_to_degraded_when_the_format_can_salvage() {
        let sevenz = ContainerCaps {
            read: true,
            degraded_parse: true,
            trailing_index: true,
            solid: true,
            needs_seek: true,
            ..Default::default()
        };
        let policy = StreamPolicy::Adaptive {
            allow_forward_only: true,
            spill: SpillPolicy::Off,
            allow_degraded: true,
        };
        let r = resolve(pipe(b"x"), FormatId::new("7z"), sevenz, &policy).unwrap();
        assert_eq!(r.rung, Rung::Degraded);
        assert!(!r.rung.is_authoritative());
    }

    #[test]
    fn spill_off_and_no_salvage_path_is_an_error_not_a_lie() {
        let policy = StreamPolicy::Adaptive {
            allow_forward_only: true,
            spill: SpillPolicy::Off,
            allow_degraded: true,
        };
        let err = resolve(pipe(b"x"), SQUASHFS, squashfs_caps(), &policy).unwrap_err();
        assert!(matches!(err, crate::Error::NotSeekable { .. }));
    }

    #[test]
    fn disallowing_forward_only_forces_a_spill_even_where_forward_would_work() {
        // Opting out of approximation must actually raise fidelity.
        let policy = StreamPolicy::Adaptive {
            allow_forward_only: false,
            spill: SpillPolicy::default(),
            allow_degraded: true,
        };
        let r = resolve(pipe(b"payload"), ZIP, zip_caps(), &policy).unwrap();
        assert_eq!(r.rung, Rung::Spilled);
        assert!(r.report.is_lossless());
    }

    /// Rung 3 drains its source into a spool, and until the decode-side
    /// marker existed it did so through a bare `?` — so a codec reporting
    /// malformed bytes to `SpillSource::materialize` became `Error::Io`, exit
    /// 1, "stuffr failed".
    ///
    /// This is the site the release-blocking reproducer hit: a 21-byte zstd
    /// frame whose decoded bytes open with ARJ's `60 EA` magic. ARJ declares
    /// `needs_seek`, a decoder's output is never seekable, so the ladder
    /// always takes this rung for that pair — `stuffr list` and `stuffr test`
    /// exited 1 where `stuffr cat` on the identical bytes exited 5. Measured
    /// from the backtrace, not inferred: `SpillSource::materialize` <-
    /// `ladder::resolve` <- `entries::open_archive`.
    ///
    /// `Error::Corrupt`, exit 5 and not 6, per `Error::exit_code`'s own rule:
    /// stuffr read the bytes and they contradict each other; no allocation was
    /// ever in question.
    #[test]
    fn spilling_classifies_a_decode_side_failure_as_corruption() {
        use crate::testing::decode_side_failing_source;

        let err = resolve(
            decode_side_failing_source(b"some good bytes", std::io::ErrorKind::InvalidData),
            SQUASHFS,
            squashfs_caps(),
            &StreamPolicy::default(),
        )
        .expect_err("a source that fails part-way cannot spool");

        assert!(
            matches!(err, crate::Error::Corrupt(_)),
            "a decoder's malformed-input report must not claim stuffr failed: {err:?}"
        );
        assert_eq!(err.exit_code(), 5);
        assert!(
            err.to_string()
                .contains(crate::testing::FAILING_SOURCE_MESSAGE),
            "the decoder's own wording must survive classification: {err}"
        );
    }

    /// The hazard side, and the reason the fix is a marker rather than a
    /// `map_err` at this call site: the IDENTICAL error kind, raised by a
    /// source no decoder produced, must stay `Error::Io`. A spool drains
    /// whatever the ladder was handed — a bare `.arj` arriving on a pipe is
    /// the raw file — so classifying unconditionally here would report a disk
    /// or pipe failure as a corrupt archive.
    #[test]
    fn spilling_leaves_a_raw_side_failure_as_an_io_error() {
        use crate::testing::raw_failing_source;

        let err = resolve(
            raw_failing_source(b"some good bytes", std::io::ErrorKind::InvalidData),
            SQUASHFS,
            squashfs_caps(),
            &StreamPolicy::default(),
        )
        .expect_err("a source that fails part-way cannot spool");

        assert!(
            matches!(err, crate::Error::Io(_)),
            "only the marking separates this from the test above: {err:?}"
        );
        assert_eq!(err.exit_code(), 1);
    }

    /// A `--max-ratio` refusal below a container took the same route and the
    /// same wrong turn. `RatioGuardedSource` raises `OutOfMemory` precisely so
    /// the classification maps it to `ResourceLimit` (exit 6); unmarked, it
    /// met this spool's bare `?` instead. Measured before the fix: `stuffr
    /// list` on a 60-byte zstd frame expanding to 1 MiB of ARJ-magic-prefixed
    /// zeros answered exit 1, against exit 6 from `stuffr cat`.
    #[test]
    fn spilling_classifies_a_decode_side_ratio_refusal_as_a_resource_limit() {
        use crate::testing::decode_side_failing_source;

        let err = resolve(
            decode_side_failing_source(b"some good bytes", std::io::ErrorKind::OutOfMemory),
            SQUASHFS,
            squashfs_caps(),
            &StreamPolicy::default(),
        )
        .expect_err("a source that fails part-way cannot spool");

        assert!(
            matches!(err, crate::Error::ResourceLimit(_)),
            "a refused expansion is a limit, never corruption and never exit 1: {err:?}"
        );
        assert_eq!(err.exit_code(), 6);
    }

    #[test]
    fn default_policy_enables_every_rung() {
        match StreamPolicy::default() {
            StreamPolicy::Adaptive {
                allow_forward_only,
                allow_degraded,
                spill,
            } => {
                assert!(allow_forward_only && allow_degraded && spill.is_enabled());
            }
            other => panic!("unexpected default: {other:?}"),
        }
    }
}
