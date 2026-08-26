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
/// by the container as it parses, via [`FidelityReport::merge`].
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
