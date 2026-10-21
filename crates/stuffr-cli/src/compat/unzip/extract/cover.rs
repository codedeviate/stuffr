//! ubuntu: 23-cve-2019-13232-zip-bomb-with-overlapped-entries.patch's
//! bomb detection (`flavour::detects_overlapped_entries`): a sorted list of
//! the archive spans already covered (`cover_t`), and its three functions.
//!
//! The list grows by one span per entry processed at most (the central
//! directory, any preamble and the end records start it), so its size is
//! bounded by the entries actually read, never by a count the archive
//! claims; like the C's `realloc()` doubling from 16, a failed growth is
//! `-2` ("not enough memory for bomb detection").

/// extract.c's `bound_t` (`zoff_t`): an offset in the archive.
pub(crate) type Bound = i64;

/// extract.c's `span_t`: `beg..end`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Span {
    beg: Bound,
    end: Bound,
}

/// extract.c's `cover_t`: allocated, distinct, and sorted spans.
#[derive(Debug, Default)]
pub(crate) struct Cover {
    span: Vec<Span>,
}

impl Cover {
    /// `((cover_t *)G.cover)->num = 0`: emptied for the next archive, the
    /// allocation kept.
    pub(crate) fn clear(&mut self) {
        self.span.clear();
    }

    // port: extract.c:cover_find
    /// The index of the first span whose `beg` is greater than `val`, or
    /// the number of spans when there is none.
    fn find(&self, val: Bound) -> usize {
        let (mut lo, mut hi) = (0usize, self.span.len());
        while lo < hi {
            let mid = (lo + hi) >> 1;
            if val < self.span[mid].beg {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        hi
    }

    // port: extract.c:cover_within
    /// `val` lies within one of the spans.
    pub(crate) fn within(&self, val: Bound) -> bool {
        let pos = self.find(val);
        pos > 0 && val < self.span[pos - 1].end
    }

    // port: extract.c:cover_add
    /// Add `beg..end` unless it overlaps a span already there, keeping the
    /// list sorted and merging adjacent spans. 0 when added, 1 when it
    /// overlaps (not added), -1 when `beg >= end`, -2 when the list cannot
    /// grow.
    pub(crate) fn add(&mut self, beg: Bound, end: Bound) -> i32 {
        if beg >= end {
            // The new span is invalid.
            return -1;
        }
        // Find where the new span should go, and make sure that it does not
        // overlap with any existing spans.
        let pos = self.find(beg);
        let num = self.span.len();
        if (pos > 0 && beg < self.span[pos - 1].end) || (pos < num && end > self.span[pos].beg) {
            return 1;
        }
        // Check for adjacencies.
        let prec = pos > 0 && beg == self.span[pos - 1].end;
        let foll = pos < num && end == self.span[pos].beg;
        if prec && foll {
            // The new span connects the preceding and following spans.
            // Merge the following span into the preceding span, and delete
            // the following span.
            self.span[pos - 1].end = self.span[pos].end;
            self.span.remove(pos);
        } else if prec {
            // Adjacent only to the preceding span: extend its end.
            self.span[pos - 1].end = end;
        } else if foll {
            // Adjacent only to the following span: extend its beginning.
            self.span[pos].beg = beg;
        } else {
            // Gaps on both sides: assure that there is room and insert.
            if self.span.len() == self.span.capacity() {
                let max = if self.span.capacity() == 0 {
                    16
                } else {
                    self.span.capacity() << 1
                };
                if self.span.try_reserve_exact(max - self.span.len()).is_err() {
                    return -2;
                }
            }
            self.span.insert(pos, Span { beg, end });
        }
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_merge_and_refuse_overlaps() {
        let mut c = Cover::default();
        assert_eq!(c.add(5, 5), -1);
        assert_eq!(c.add(10, 20), 0);
        assert_eq!(c.add(30, 40), 0);
        assert_eq!(c.add(19, 25), 1);
        assert_eq!(c.add(25, 31), 1);
        assert!(c.within(10) && c.within(19) && !c.within(20) && !c.within(9));
        assert_eq!(c.add(20, 30), 0); // joins both
        assert_eq!(c.span, vec![Span { beg: 10, end: 40 }]);
        assert_eq!(c.add(0, 10), 0); // extends the beginning
        assert_eq!(c.add(40, 41), 0); // extends the end
        assert_eq!(c.span, vec![Span { beg: 0, end: 41 }]);
        assert!(!c.within(41) && !c.within(-1));
        c.clear();
        assert!(!c.within(5));
    }

    #[test]
    fn the_list_grows_by_doubling_from_16() {
        let mut c = Cover::default();
        for i in 0..17 {
            assert_eq!(c.add(i * 10, i * 10 + 1), 0);
        }
        assert_eq!(c.span.len(), 17);
        assert!(c.span.capacity() >= 32);
    }
}
