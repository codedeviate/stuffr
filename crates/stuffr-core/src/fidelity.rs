use std::fmt;

use crate::format::FormatId;

/// Which rung of the adaptive stream ladder a read landed on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum Rung {
    /// Input was seekable. Authoritative index, full metadata.
    Exact,
    /// Not seekable, parsed forward. Real data, approximate metadata.
    ForwardOnly,
    /// Spooled to memory/temp then read exactly. Costs disk, not accuracy.
    Spilled,
    /// Best-effort salvage. Partial results by construction.
    Degraded,
}

impl Rung {
    /// Whether the read used the format's authoritative structures.
    ///
    /// Note `Spilled` is authoritative: spilling trades disk for accuracy, and
    /// treating it as lossy would make `--strict-fidelity` reject exact reads.
    pub fn is_authoritative(&self) -> bool {
        matches!(self, Rung::Exact | Rung::Spilled)
    }

    /// Ordering by *quality loss*, worst = highest. Used by `merge`.
    fn severity(&self) -> u8 {
        match self {
            Rung::Exact => 0,
            Rung::Spilled => 1,
            Rung::ForwardOnly => 2,
            Rung::Degraded => 3,
        }
    }
}

impl fmt::Display for Rung {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Rung::Exact => "exact",
            Rung::ForwardOnly => "forward-only",
            Rung::Spilled => "spilled",
            Rung::Degraded => "degraded",
        };
        f.write_str(s)
    }
}

/// Which metadata fields are **missing**. `true` means absent, not present.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct MetaFields {
    pub mtime: bool,
    pub mode: bool,
    pub uid_gid: bool,
    pub comment: bool,
    pub extra: bool,
    pub crc: bool,
}

impl MetaFields {
    pub fn missing(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.mtime {
            v.push("mtime")
        }
        if self.mode {
            v.push("mode")
        }
        if self.uid_gid {
            v.push("uid_gid")
        }
        if self.comment {
            v.push("comment")
        }
        if self.extra {
            v.push("extra")
        }
        if self.crc {
            v.push("crc")
        }
        v
    }
}

/// One specific, structured thing that was lost or approximated.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "kebab-case"))]
#[non_exhaustive]
pub enum Fidelity {
    #[error(
        "`{format}` central/trailing index was never read; entry metadata came from inline headers"
    )]
    TrailingIndexUnread { format: FormatId },

    #[error("size of entry `{entry}` was only known after its data (data descriptor)")]
    SizeFromDataDescriptor { entry: String },

    #[error("total entry count is unknown without the trailing index")]
    EntryCountUnknown,

    #[error("entry `{entry}` is missing metadata: {}", fields.missing().join(", "))]
    MetadataIncomplete { entry: String, fields: MetaFields },

    #[error("decoded a solid block, wasting {wasted_bytes} bytes, to reach the requested entry")]
    SolidBlockFullyDecoded { wasted_bytes: u64 },

    #[error("skipped encrypted entry `{entry}`")]
    EncryptedEntrySkipped { entry: String },

    #[error("stream truncated at offset {at}")]
    TruncatedStream { at: u64 },
}

/// What a read cost in fidelity. Returned alongside data, never logged and
/// discarded — the caller must be able to discover what was approximated.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct FidelityReport {
    pub rung: Rung,
    pub warnings: Vec<Fidelity>,
}

impl FidelityReport {
    pub fn exact() -> Self {
        Self::new(Rung::Exact)
    }

    pub fn new(rung: Rung) -> Self {
        Self {
            rung,
            warnings: Vec::new(),
        }
    }

    pub fn warn(&mut self, w: Fidelity) {
        self.warnings.push(w);
    }

    /// Whether anything was approximated. **This is the `--strict-fidelity`
    /// gate** (exit code 4).
    ///
    /// Gating on warnings rather than on the rung is deliberate: a tar read
    /// from a pipe lands on `ForwardOnly`, but tar has no trailing index, so
    /// nothing was lost. Failing it would hand a script an error it cannot act
    /// on. The rung stays diagnostic — reported by `stf info`.
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    /// True only if the rung was authoritative *and* nothing was approximated.
    ///
    /// Deliberately **not** the `--strict-fidelity` gate — see
    /// [`Self::has_warnings`]. This is the stronger "the format's own index was
    /// read and nothing was lost" claim, useful for archival verification.
    pub fn is_lossless(&self) -> bool {
        self.rung.is_authoritative() && self.warnings.is_empty()
    }

    /// Fold another report in: worst rung wins, warnings are unioned.
    ///
    /// For combining reports from independently-resolved layers — e.g. a
    /// codec's own report merged with the inner container's, once a chain has
    /// more than one — rather than for a single container's own findings,
    /// which it now records by calling [`Self::warn`] directly on the report
    /// it inherited from the ladder (see [`crate::ladder::seed_report`]). A
    /// warning already present is not repeated, so folding the same loss in
    /// from two sources still tells the caller about it once.
    pub fn merge(&mut self, other: &FidelityReport) {
        if other.rung.severity() > self.rung.severity() {
            self.rung = other.rung;
        }
        for w in &other.warnings {
            if !self.warnings.contains(w) {
                self.warnings.push(w.clone());
            }
        }
    }
}

impl Default for FidelityReport {
    fn default() -> Self {
        Self::exact()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::FormatId;

    #[test]
    fn spilled_is_authoritative_even_though_it_is_a_lower_rung() {
        // Spilling costs disk, not accuracy. Treating it as lossy would make
        // `--strict-fidelity` reject perfectly exact reads.
        assert!(Rung::Exact.is_authoritative());
        assert!(Rung::Spilled.is_authoritative());
        assert!(!Rung::ForwardOnly.is_authoritative());
        assert!(!Rung::Degraded.is_authoritative());
    }

    #[test]
    fn exact_report_is_lossless() {
        let r = FidelityReport::exact();
        assert_eq!(r.rung, Rung::Exact);
        assert!(r.is_lossless());
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn a_warning_makes_an_otherwise_exact_report_lossy() {
        let mut r = FidelityReport::exact();
        r.warn(Fidelity::EntryCountUnknown);
        assert!(!r.is_lossless());
        assert_eq!(r.warnings.len(), 1);
    }

    #[test]
    fn forward_only_is_lossy_even_with_no_warnings() {
        assert!(!FidelityReport::new(Rung::ForwardOnly).is_lossless());
    }

    #[test]
    fn merge_keeps_the_worst_rung_and_concatenates_warnings() {
        let mut a = FidelityReport::exact();
        a.warn(Fidelity::EntryCountUnknown);

        let mut b = FidelityReport::new(Rung::Degraded);
        b.warn(Fidelity::TruncatedStream { at: 99 });

        a.merge(&b);
        assert_eq!(a.rung, Rung::Degraded);
        assert_eq!(a.warnings.len(), 2);
    }

    #[test]
    fn merge_does_not_upgrade_a_worse_rung() {
        let mut a = FidelityReport::new(Rung::Degraded);
        a.merge(&FidelityReport::exact());
        assert_eq!(a.rung, Rung::Degraded);
    }

    #[test]
    fn merge_does_not_repeat_a_warning_already_present() {
        // The ladder and the container can each independently observe the same
        // loss; the caller should be told once.
        let mut a = FidelityReport::exact();
        a.warn(Fidelity::EntryCountUnknown);

        let mut b = FidelityReport::new(Rung::ForwardOnly);
        b.warn(Fidelity::EntryCountUnknown);

        a.merge(&b);
        assert_eq!(a.warnings.len(), 1);
        assert_eq!(a.rung, Rung::ForwardOnly);
    }

    #[test]
    fn warnings_carry_actionable_detail_not_just_a_kind() {
        // The whole premise is that the caller can find out WHAT was lost.
        let f = Fidelity::SizeFromDataDescriptor {
            entry: "logs/a.txt".into(),
        };
        assert!(format!("{f}").contains("logs/a.txt"));

        let f = Fidelity::TrailingIndexUnread {
            format: FormatId::new("zip"),
        };
        assert!(format!("{f}").contains("zip"));

        let f = Fidelity::SolidBlockFullyDecoded {
            wasted_bytes: 41_943_040,
        };
        assert!(format!("{f}").contains("41943040"));

        let f = Fidelity::MetadataIncomplete {
            entry: "b.bin".into(),
            fields: MetaFields {
                mode: true,
                ..Default::default()
            },
        };
        let s = format!("{f}");
        assert!(s.contains("b.bin") && s.contains("mode"));
    }

    #[test]
    fn meta_fields_lists_only_the_missing_ones() {
        let m = MetaFields {
            mtime: true,
            crc: true,
            ..Default::default()
        };
        assert_eq!(m.missing(), vec!["mtime", "crc"]);
        assert!(MetaFields::default().missing().is_empty());
    }

    #[test]
    fn a_forward_only_read_that_lost_nothing_passes_strict_mode() {
        // tar on a pipe: rung is ForwardOnly, but tar has no trailing index, so
        // nothing was approximated. Strict mode must not fail this.
        let r = FidelityReport::new(Rung::ForwardOnly);
        assert!(!r.has_warnings(), "nothing was approximated");
        assert!(!r.is_lossless(), "but the rung was not authoritative");
    }

    #[test]
    fn strict_mode_fires_on_any_warning_regardless_of_rung() {
        let mut r = FidelityReport::exact();
        r.warn(Fidelity::EntryCountUnknown);
        assert!(r.has_warnings());
    }

    #[test]
    fn a_clean_exact_read_passes_both_predicates() {
        let r = FidelityReport::exact();
        assert!(!r.has_warnings());
        assert!(r.is_lossless());
    }
}
