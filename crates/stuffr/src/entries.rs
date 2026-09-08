use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use stuffr_core::{
    ArchiveRead, Chain, Counting, EntryMeta, Error, FormatId, OpenOpts, RATIO_FLOOR, RatioGuard,
    Registry, Result, SeekRead, Source, SourceCaps, StreamPolicy, ladder, resolve_chain_deep,
};

use crate::ops::{Input, Outcome};

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

    /// The absolute output ceiling.
    ///
    /// For a known size: `RATIO_FLOOR` is why a 3-byte file expanding to 30
    /// bytes is not a "bomb" — without a floor, every tiny input trips the
    /// ratio. The ratio is floored, and a genuine multiplication overflow
    /// falls back to `u64::MAX`, the permissive direction; a wrapping product
    /// would instead yield a tiny ceiling that rejects legitimate archives.
    ///
    /// For an unknown size (a pipe): the floor is the whole budget. This must
    /// NOT fall through to the overflow fallback — that is what made the pipe
    /// path unbounded. A pipe is where untrusted input of unknown size
    /// arrives, and the budget must still bound output rather than becoming
    /// unlimited.
    #[allow(clippy::manual_saturating_arithmetic)]
    fn ceiling(&self) -> u64 {
        match self.compressed_total {
            // Known size: the ratio applies, floored so a tiny file is not a
            // "bomb". A genuine multiplication overflow falls back to u64::MAX,
            // the permissive direction — a wrapping product would instead yield a
            // tiny ceiling that rejects legitimate archives.
            Some(c) => c
                .checked_mul(self.max_ratio)
                .unwrap_or(u64::MAX)
                .max(RATIO_FLOOR),
            // Unknown size (a pipe): the floor is the whole budget. This must NOT
            // share the overflow fallback above — that is what made the pipe path
            // unbounded.
            None => RATIO_FLOOR,
        }
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

/// Bounds the codec layer beneath a container the same way `ops::decompress`
/// bounds a plain codec stream — `Counting` (wrapped around the raw input in
/// [`open_archive`]) tallies compressed bytes going in, and this wraps the
/// DECODED stream the container reads from, calling [`RatioGuard::record`]
/// on every read. A small `bomb.tar.gz` is refused before the container
/// (which has no ratio concept of its own — it just sees a byte stream) ever
/// absorbs its output.
///
/// `caps()` and `as_seek()` are forwarded to `inner` unchanged, exactly like
/// `Counting` — so an uncompressed, seekable `.tar` keeps `Rung::Exact`
/// rather than being downgraded merely for passing through this wrapper.
/// The cost: a caller that reaches `inner` through `as_seek()` bypasses this
/// guard's `record()` check entirely. Accepted today because `tar` — the
/// only registered container — never seeks its source; see `tar.rs`'s own
/// module doc on why it always uses `entries()`, never `entries_with_seek()`.
/// A future seekable container must not rely on this wrapper alone to bound
/// it.
struct RatioGuardedSource {
    inner: Box<dyn Source>,
    guard: RatioGuard,
}

impl RatioGuardedSource {
    fn new(inner: Box<dyn Source>, consumed: Arc<AtomicU64>, max_ratio: u64) -> Self {
        Self {
            inner,
            guard: RatioGuard::new(consumed, max_ratio),
        }
    }
}

impl std::io::Read for RatioGuardedSource {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        // `OutOfMemory` is the kind `Error::from_decode_io` maps to
        // `Error::ResourceLimit` (exit 6), never `Corrupt` (exit 5) — the
        // same convention `lzma_pure.rs` uses to surface a memory-limit
        // refusal through a plain `io::Read`, reused here for a ratio
        // refusal. `RatioGuard::record`'s own message (naming the ratio,
        // the limit and `--max-ratio`) survives the round trip verbatim.
        if let Err(Error::ResourceLimit(msg)) = self.guard.record(n) {
            return Err(std::io::Error::new(std::io::ErrorKind::OutOfMemory, msg));
        }
        Ok(n)
    }
}

impl Source for RatioGuardedSource {
    fn caps(&self) -> SourceCaps {
        self.inner.caps()
    }

    fn as_seek(&mut self) -> Option<&mut dyn SeekRead> {
        self.inner.as_seek()
    }
}

/// Opens `src`, resolving any codec layers above the container and bounding
/// them with `--max-ratio` — see [`RatioGuardedSource`].
///
/// Shared by [`list`] and [`test`] so the two cannot drift on how they
/// resolve a chain — the defect shape where a container flag is accepted but
/// not honoured on one of two near-identical code paths.
fn open_archive(
    registry: &Registry,
    src: Input,
    max_ratio: u64,
) -> Result<(Box<dyn ArchiveRead>, FormatId)> {
    let path = src.path().map(Path::to_path_buf);
    // `Counting` wraps the RAW input, tallying compressed bytes as
    // `resolve_chain_deep`'s own internal decode reads them — the same
    // `Counting`/`RatioGuard` pair `ops::decompress` uses, just relocated:
    // there the copy loop calls `record` explicitly, here `record` is called
    // for whoever reads the returned source later, since a container pulls
    // its own bytes rather than being driven by an explicit loop here.
    let (counting, consumed) = Counting::new(src.open()?);
    let (chain, source) = resolve_chain_deep(registry, path.as_deref(), Box::new(counting))?;
    // Kept for the error path: once the loop below has peeled layers, the
    // original chain is the only thing that can say what the input actually
    // was.
    let described = chain.describe();

    // Do NOT decode here. `resolve_chain_deep` already guarantees `source` is
    // positioned past every codec layer named in `chain` — on both the path
    // and the pathless (piped) route — so calling a codec's decoder again
    // would decode the same bytes twice, and would do so only on the pipe
    // path, making it a bug that appears exclusively when piping. Walk the
    // chain only to find which container to hand the source to.
    //
    // Wrapping unconditionally (even with zero codec layers, a bare `.tar`)
    // is harmless: `consumed` and the guard's `produced` then advance in
    // lockstep — see the module's own test for this.
    let source: Box<dyn Source> = Box::new(RatioGuardedSource::new(source, consumed, max_ratio));
    let mut chain = &chain;
    loop {
        match chain {
            Chain::Codec { inner, .. } => chain = inner,
            Chain::Container { container } => {
                let k = registry.require_container(*container)?;
                // `ladder::resolve` takes FOUR arguments: the source, the
                // format, the container's own caps, and the policy.
                // `StreamPolicy::default()` is `Adaptive { allow_forward_only:
                // true, .. }`, which is what keeps a piped archive off the
                // disk.
                let resolved =
                    ladder::resolve(source, *container, k.caps(), &StreamPolicy::default())?;
                return Ok((k.open(resolved, &OpenOpts::default())?, *container));
            }
            // Names what the input resolved to, so "unpack this .gz" is
            // actionable rather than a bare refusal.
            Chain::Raw => return Err(Error::NotAnArchive { chain: described }),
            // `Chain` is `#[non_exhaustive]` and this crate is not its
            // defining crate, so a fourth variant added upstream must fail
            // loudly here rather than fail to compile silently-wrong.
            _ => {
                return Err(Error::Unsupported(
                    "unrecognised chain shape; this build does not know how to open it".into(),
                ));
            }
        }
    }
}

/// Lists every entry in an archive, extracting nothing.
pub fn list(src: Input, max_ratio: u64) -> Result<Vec<EntryMeta>> {
    let (mut ar, _format) = open_archive(crate::registry(), src, max_ratio)?;
    let mut out = Vec::new();
    while let Some(entry) = ar.next_entry()? {
        out.push(entry.meta().clone());
    }
    Ok(out)
}

/// Reads every entry to the end, verifying integrity, writing nothing.
///
/// The data must actually be pulled: a `test` that only walked headers would
/// pass on an archive whose payloads are corrupt, which is precisely the
/// failure it exists to find.
pub fn test(src: Input, max_ratio: u64) -> Result<Outcome> {
    let (mut ar, format) = open_archive(crate::registry(), src, max_ratio)?;
    let mut bytes = 0u64;
    while let Some(mut entry) = ar.next_entry()? {
        // `Error::from_decode_io`, not a bare `?`: a container's own
        // truncation/corruption detection on an entry's payload (e.g. tar's
        // `EntryPayload::read`, which compares delivered bytes against the
        // size its header declares) raises a raw `io::ErrorKind::InvalidData`.
        // A bare `?` would wrap that as `Error::Io` (exit 1) instead of
        // `Error::Corrupt` (exit 5) — the same classification `ops::decompress`
        // already applies to its own decode loop.
        let n =
            std::io::copy(entry.reader(), &mut std::io::sink()).map_err(Error::from_decode_io)?;
        bytes += n;
    }
    // `Outcome` is a plain four-field public struct with no constructors, so
    // build it with a struct literal. Do NOT grow the public type for an
    // entry count — that belongs in the fidelity report, not here.
    Ok(Outcome {
        bytes_in: 0,
        bytes_out: bytes,
        format,
        fidelity: ar.fidelity().clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use stuffr_core::{DEFAULT_MAX_RATIO, ReaderSource};

    #[test]
    fn ratio_guarded_source_forwards_bytes_unchanged() {
        let (counting, consumed) = Counting::new(Box::new(ReaderSource::new(
            std::io::Cursor::new(b"0123456789".to_vec()),
        )));
        let mut guarded = RatioGuardedSource::new(Box::new(counting), consumed, DEFAULT_MAX_RATIO);
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut guarded, &mut out).unwrap();
        assert_eq!(out, b"0123456789");
    }

    #[test]
    fn ratio_guarded_source_forwards_capabilities_from_its_inner_source() {
        // An uncompressed, seekable `.tar` must not be downgraded to
        // forward-only merely for passing through this wrapper.
        let (counting, consumed) = Counting::new(Box::new(ReaderSource::new(
            std::io::Cursor::new(b"x".to_vec()),
        )));
        let guarded = RatioGuardedSource::new(Box::new(counting), consumed, DEFAULT_MAX_RATIO);
        // `ReaderSource` models a pipe (not seekable); `Counting` and this
        // wrapper both forward that unchanged rather than hardcoding either
        // answer — this is the same property `Counting` itself is tested for.
        assert!(!guarded.caps().seekable);
    }

    #[test]
    fn ratio_guarded_source_refuses_pathological_expansion_as_a_resource_limit_not_corrupt() {
        // Exercises the exact composition `open_archive` builds: `consumed`
        // stays tiny while reads keep flowing, well past `RATIO_FLOOR`.
        let consumed = Arc::new(AtomicU64::new(1));
        let big = vec![b'x'; RATIO_FLOOR as usize + 1];
        let mut guarded = RatioGuardedSource {
            inner: Box::new(ReaderSource::new(std::io::Cursor::new(big))),
            guard: RatioGuard::new(consumed, 10),
        };
        let mut buf = vec![0u8; RATIO_FLOOR as usize + 1];
        let err = std::io::Read::read(&mut guarded, &mut buf).unwrap_err();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::OutOfMemory,
            "must be the kind Error::from_decode_io maps to ResourceLimit, not InvalidData"
        );
        let classified = Error::from_decode_io(err);
        assert!(matches!(classified, Error::ResourceLimit(_)));
        assert_eq!(classified.exit_code(), 6, "a bomb must exit 6, not 1 or 5");
    }

    #[test]
    fn ratio_guarded_source_leaves_a_one_to_one_stream_unbounded() {
        // Models the bare, uncompressed `.tar` case: every byte the guard
        // sees was ALSO just tallied into `consumed` (no codec layer sits
        // between them), so the ratio never exceeds ~1:1 regardless of how
        // low `max_ratio` is set.
        let (counting, consumed) = Counting::new(Box::new(ReaderSource::new(
            std::io::Cursor::new(vec![b'x'; 4 * 1024 * 1024]),
        )));
        let mut guarded = RatioGuardedSource::new(Box::new(counting), consumed, 1);
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut guarded, &mut out).unwrap();
        assert_eq!(out.len(), 4 * 1024 * 1024);
    }

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
    fn an_unknown_compressed_size_is_still_bounded_by_the_absolute_floor() {
        // A pipe does not know its own size. The budget must still bound output
        // rather than becoming unlimited — this is the case where untrusted input
        // arrives, so an unbounded ceiling here would defeat the control entirely.
        let mut b = ArchiveBudget::new(None, DEFAULT_MAX_RATIO);
        assert!(b.charge("a", RATIO_FLOOR).is_ok());

        let mut b = ArchiveBudget::new(None, DEFAULT_MAX_RATIO);
        let err = b
            .charge("huge.bin", RATIO_FLOOR + 1)
            .expect_err("an unknown compressed size must still be bounded by the floor");
        assert!(matches!(err, Error::ResourceLimit(_)));
    }

    #[test]
    fn overflow_on_known_size_falls_back_to_permissive_u64_max() {
        // A very large known compressed size times the ratio overflows u64.
        // The fallback must be permissive (u64::MAX), not a wrapping product
        // that yields a tiny ceiling and rejects legitimate archives.
        let mut b = ArchiveBudget::new(Some(u64::MAX / 2), DEFAULT_MAX_RATIO);
        let large_charge = u64::MAX / 3;
        assert!(b.charge("large.bin", large_charge).is_ok());
    }
}
