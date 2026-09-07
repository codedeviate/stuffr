use stuffr_core::{Error, RATIO_FLOOR, Result};

/// Bounds decoded output for one archive, per entry and in total.
///
/// Two limits because they catch different attacks. The per-entry ratio stops
/// one entry that expands absurdly; the running total stops many entries that
/// are each individually innocent and collectively a bomb. A per-entry check
/// alone passes the second case completely.
pub struct ArchiveBudget {
    /// `None` for a pipe, which does not know its own size.
    compressed_total: Option<u64>,
    max_ratio: u64,
    decoded_so_far: u64,
}

impl ArchiveBudget {
    pub fn new(compressed_total: Option<u64>, max_ratio: u64) -> Self {
        Self {
            compressed_total,
            max_ratio,
            decoded_so_far: 0,
        }
    }

    /// The absolute output ceiling. `RATIO_FLOOR` is why a 3-byte file
    /// expanding to 30 bytes is not a "bomb": without a floor, every tiny
    /// input trips the ratio. When the compressed size is unknown the floor
    /// alone applies, so the budget is still bounded rather than unlimited.
    fn ceiling(&self) -> u64 {
        let from_ratio = self
            .compressed_total
            .and_then(|c| c.checked_mul(self.max_ratio))
            .unwrap_or(u64::MAX);
        from_ratio.max(RATIO_FLOOR)
    }

    /// Charges `decoded` bytes for `entry`. The error names the entry, which
    /// is the difference between an actionable refusal and a mystery.
    pub fn charge(&mut self, entry: &str, decoded: u64) -> Result<()> {
        let ceiling = self.ceiling();

        // Per-entry first, so a single vast entry is attributed to itself
        // rather than to whichever entry happens to cross the running total.
        if decoded > ceiling {
            return Err(Error::ResourceLimit(format!(
                "entry {entry:?} expands to {decoded} bytes, past the {ceiling}-byte limit \
                 (raise it with --max-ratio)"
            )));
        }

        self.decoded_so_far = self.decoded_so_far.saturating_add(decoded);
        if self.decoded_so_far > ceiling {
            return Err(Error::ResourceLimit(format!(
                "archive expands to {} bytes by entry {entry:?}, past the {ceiling}-byte \
                 limit (raise it with --max-ratio)",
                self.decoded_so_far
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stuffr_core::DEFAULT_MAX_RATIO;

    #[test]
    fn one_absurdly_expanding_entry_is_refused_and_names_itself() {
        let mut b = ArchiveBudget::new(Some(1024), DEFAULT_MAX_RATIO);
        let err = b
            .charge("bomb.bin", 1024 * DEFAULT_MAX_RATIO + 1)
            .expect_err("must refuse");
        match err {
            Error::ResourceLimit(msg) => assert!(
                msg.contains("bomb.bin"),
                "the error must name the entry that tripped it, got: {msg}"
            ),
            other => panic!("expected ResourceLimit, got {other:?}"),
        }
    }

    #[test]
    fn many_innocent_entries_cannot_sum_past_the_archive_total() {
        // Each entry alone is far under the per-entry ratio; together they are a
        // bomb. A per-entry check ALONE would pass every one of these.
        let mut b = ArchiveBudget::new(Some(1024), DEFAULT_MAX_RATIO);
        let per = 1024 * DEFAULT_MAX_RATIO / 4;
        assert!(b.charge("a", per).is_ok());
        assert!(b.charge("b", per).is_ok());
        assert!(b.charge("c", per).is_ok());
        assert!(b.charge("d", per).is_ok());
        let err = b
            .charge("e", per)
            .expect_err("the accumulated total must be refused");
        assert!(matches!(err, Error::ResourceLimit(_)));
    }

    #[test]
    fn small_archives_are_not_penalised_by_the_ratio_floor() {
        // RATIO_FLOOR exists so a 3-byte input expanding to 30 bytes is not a
        // "bomb". Without it, every tiny file trips the ratio.
        let mut b = ArchiveBudget::new(Some(3), DEFAULT_MAX_RATIO);
        assert!(b.charge("tiny.txt", 30).is_ok());
    }

    #[test]
    fn an_unknown_compressed_size_falls_back_to_the_absolute_floor() {
        // A pipe does not know its own size. The budget must still bound output
        // rather than becoming unlimited.
        let mut b = ArchiveBudget::new(None, DEFAULT_MAX_RATIO);
        assert!(b.charge("a", RATIO_FLOOR).is_ok());
    }
}
