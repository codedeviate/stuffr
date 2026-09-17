use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use stuffr_core::{
    ArchiveRead, Chain, Counting, CountingWriter, CreateOpts, DEFAULT_MAX_RATIO, DecodeOpts,
    EncodeOpts, Entry, EntryKind, EntryMeta, Error, Fidelity, FidelityReport, FormatId, MetaFields,
    OpenOpts, PROBE_LEN, PlainSink, RATIO_FLOOR, RatioGuard, Registry, Result, Rung, SeekRead,
    Sink, Source, SourceCaps, StreamPolicy, check_symlink_target, ladder, resolve_chain,
    resolve_chain_deep_with, safe_join,
};

use crate::ops::{CompressOpts, Input, Outcome, Output, discard, publish};

/// Bounds decoded output for one archive, per entry and in total.
///
/// Two limits because they catch different attacks. The per-entry ratio stops
/// one entry that expands absurdly; the running total stops many entries that
/// are each individually innocent and collectively a bomb. A per-entry check
/// alone passes the second case completely.
pub struct ArchiveBudget {
    /// `None` for a pipe, which does not know its own size.
    compressed_total: Option<u64>,
    /// Running tally of compressed bytes pulled from the input, when one is
    /// available. This is what lets `--max-ratio` mean something on a pipe:
    /// the total is unknown, but the amount consumed SO FAR is not.
    consumed: Option<Arc<AtomicU64>>,
    max_ratio: u64,
    decoded_so_far: u64,
}

impl ArchiveBudget {
    pub fn new(compressed_total: Option<u64>, max_ratio: u64) -> Self {
        Self {
            compressed_total,
            consumed: None,
            max_ratio,
            decoded_so_far: 0,
        }
    }

    /// Attaches the input's running compressed-byte tally, from
    /// [`open_archive`].
    ///
    /// Only affects the unknown-size (pipe) path; with a known
    /// `compressed_total` the ratio already has a denominator.
    #[must_use]
    pub fn tracking(mut self, consumed: Arc<AtomicU64>) -> Self {
        self.consumed = Some(consumed);
        self
    }

    /// The absolute output ceiling.
    ///
    /// For a known size: `RATIO_FLOOR` is why a 3-byte file expanding to 30
    /// bytes is not a "bomb" — without a floor, every tiny input trips the
    /// ratio. The ratio is floored, and a genuine multiplication overflow
    /// falls back to `u64::MAX`, the permissive direction; a wrapping product
    /// would instead yield a tiny ceiling that rejects legitimate archives.
    ///
    /// For an unknown size (a pipe): the ratio is applied against the bytes
    /// pulled from the input SO FAR, which [`open_archive`]'s `Counting`
    /// wrapper tallies. This must NOT fall through to the overflow fallback —
    /// that is what made the pipe path unbounded. But a flat `RATIO_FLOOR`
    /// was the opposite error: it refused any piped archive over 1 MiB and
    /// `--max-ratio`, which the refusal names, could not raise it, so the
    /// documented `cat photos.zip | stuffr test -` broke on any real archive.
    /// A running denominator still bounds a bomb — an 8 KB zip holding an
    /// 8 MB entry is refused at `--max-ratio 10`, measured — without bounding
    /// the archive's SIZE, which is what the floor was doing. It gives the
    /// pipe exactly the seekable path's behaviour: at the default ratio both
    /// admit that same zip, and both refuse it at 10.
    ///
    /// With no tally attached the floor still applies, because a budget with
    /// neither a total nor a running count has no denominator at all.
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
            // Unknown size (a pipe): apply the ratio to what has actually been
            // read so far. Shares the known-size arm's overflow fallback and
            // floor, and for the same reasons; what it must NOT do is ignore
            // `max_ratio`, which is the flag its own refusal tells the user to
            // raise.
            None => match &self.consumed {
                Some(c) => c
                    .load(Ordering::Relaxed)
                    .checked_mul(self.max_ratio)
                    .unwrap_or(u64::MAX)
                    .max(RATIO_FLOOR),
                None => RATIO_FLOOR,
            },
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
/// guard's `record()` check entirely, and that is no longer hypothetical.
/// Of the four registered containers, tar, ar and cpio never seek their
/// source (see `tar.rs`'s module doc on why it always uses `entries()`,
/// never `entries_with_seek()`), but `zip.rs`'s `SeekAdapter` DOES call
/// `as_seek()` — so a seekable zip reads through the inner source directly
/// and this wrapper's ratio check never fires for it.
///
/// That is bounded elsewhere rather than left open: a seekable zip is a
/// real file whose codec layer, if any, is bounded by
/// [`DecodeOpts::memory_limit`] (threaded through
/// `resolve_chain_deep_with`, see [`open_archive`]), and every entry's
/// decoded payload is charged against [`ArchiveBudget`] by the verb that
/// reads it. A future seekable container must not rely on this wrapper
/// alone to bound it.
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
///
/// Returns the running compressed-byte tally alongside the archive:
/// [`ArchiveBudget`] needs it to give `--max-ratio` a denominator on a pipe,
/// where the total size is unknowable up front.
fn open_archive(
    registry: &Registry,
    src: Input,
    max_ratio: u64,
    memory_limit: Option<u64>,
) -> Result<(Box<dyn ArchiveRead>, FormatId, Arc<AtomicU64>)> {
    let path = src.path().map(Path::to_path_buf);
    // `Counting` wraps the RAW input, tallying compressed bytes as
    // `resolve_chain_deep`'s own internal decode reads them — the same
    // `Counting`/`RatioGuard` pair `ops::decompress` uses, just relocated:
    // there the copy loop calls `record` explicitly, here `record` is called
    // for whoever reads the returned source later, since a container pulls
    // its own bytes rather than being driven by an explicit loop here.
    let (counting, consumed) = Counting::new(src.open()?);
    // `resolve_chain_deep_with`, NOT `resolve_chain_deep`: the plain spelling
    // defaults `DecodeOpts`, which leaves `memory_limit: None`, which is
    // unbounded. That is the whole reason a 131-byte `.tar.lz` declaring a
    // 512 MiB dictionary drove 538 MB peak RSS through `list`/`test`/`cat`
    // while single-stream `unpack` of the same bytes refused at exit 6 in
    // 2.6 MB: `--max-ratio` counts decoded OUTPUT bytes and the allocation
    // precedes any output, so only this bound can see it.
    let opts = DecodeOpts {
        memory_limit,
        ..Default::default()
    };
    let (chain, source) =
        resolve_chain_deep_with(registry, path.as_deref(), Box::new(counting), &opts)?;
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
    let source: Box<dyn Source> = Box::new(RatioGuardedSource::new(
        source,
        Arc::clone(&consumed),
        max_ratio,
    ));
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
                return Ok((
                    k.open(resolved, &OpenOpts::default())?,
                    *container,
                    consumed,
                ));
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

/// Which entries a read verb acts on.
///
/// The three ways of saying "which entries" are variants of ONE type rather
/// than two parameters a caller could pass together, because "a name pattern
/// AND a position" has no meaning anybody would agree on — union, or
/// intersection? Making the ambiguity unrepresentable below the CLI means the
/// only place that has to rule on it is the one place a user can type both,
/// and the ruling there is a usage error (exit 2) rather than a guess.
///
/// # Index numbering
///
/// [`Selection::Indices`] is **0-based**, and an index is a position in
/// ARCHIVE ORDER — the order [`ArchiveRead::next_entry`] yields, which is the
/// order [`list`] returns and therefore the order `stuffr list`'s own index
/// column prints. That is what makes `list` and `--index` incapable of
/// disagreeing: both read the same sequence and count it the same way.
///
/// 0-based because it is the same integer [`ArchiveRead::by_index`] already
/// takes. The flag, the column, the trait method and the out-of-range message
/// zip already raises (`index 9; this archive has 2 entries`) then all speak
/// one numbering, with no `-1` anywhere — and a translation layer is exactly
/// where an off-by-one hides.
///
/// # Order and duplicates
///
/// Entries are visited in archive order whatever order the indices arrive in,
/// and a repeated index selects its entry once. That is the same contract
/// [`Selection::Names`] already has, and it is what lets the random-access
/// route and the counted route produce byte-identical output: the counted
/// route can only ever deliver archive order, so defining the contract any
/// other way would make the two routes disagree by construction.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Selection {
    /// Every entry in the archive.
    #[default]
    All,
    /// Entries whose name matches one of these patterns — an exact entry
    /// name, or a directory selecting everything beneath it.
    Names(Vec<String>),
    /// Entries at these archive positions, 0-based. See the type's own doc
    /// for the numbering and the ordering rules.
    Indices(Vec<usize>),
}

impl Selection {
    /// The patterns to name in an [`Error::EntryNotFound`] when a selection
    /// matched nothing. `None` for [`Selection::All`], which cannot miss, and
    /// for [`Selection::Indices`], which reports its own out-of-range index
    /// with the archive's length attached.
    fn missed(&self) -> Option<String> {
        match self {
            Selection::Names(p) if !p.is_empty() => Some(p.join(", ")),
            _ => None,
        }
    }
}

/// Runs `visit` over exactly the entries `selection` picks, in archive order,
/// returning how many were visited.
///
/// The single place [`cat`] and [`extract`] agree on what a selection MEANS.
/// They were two hand-copied `if !patterns.is_empty() && !matches_any(..)`
/// guards before `--index` existed, which is one copy per verb of a rule that
/// has to be identical in both — the drift shape [`open_archive`] was factored
/// out to prevent on the chain-resolution side.
fn visit_selected(
    ar: &mut dyn ArchiveRead,
    selection: &Selection,
    mut visit: impl FnMut(&mut Entry<'_>) -> Result<()>,
) -> Result<u64> {
    if let Selection::Indices(wanted) = selection {
        return visit_by_index(ar, wanted, visit);
    }
    let mut visited = 0u64;
    while let Some(mut entry) = ar.next_entry()? {
        if let Selection::Names(patterns) = selection
            && !patterns.is_empty()
            && !matches_any(&entry.meta().name, patterns)
        {
            continue;
        }
        visited += 1;
        visit(&mut entry)?;
    }
    Ok(visited)
}

/// [`visit_selected`] for [`Selection::Indices`]: two routes to the same
/// answer.
///
/// 1. **Random access.** [`ArchiveRead::by_index`] reaches an entry without
///    touching any other, and is what makes `--index` cheap on a large zip.
/// 2. **Counting the forward walk.** Works for every container and every
///    source shape, a pipe included, because it needs nothing but
///    `next_entry`.
///
/// Route 1 is taken only when the read is authoritative AND the container
/// actually has an index; `by_index`'s own refusal is the signal for the
/// second half, and container-conformance property 6 is what makes it
/// trustworthy — a container that faked random access over a forward-only
/// source would fail that property before it ever reached here. zip is the
/// only container in this build that takes route 1 at all: tar, ar and cpio
/// are sequential formats with no index and refuse `by_index` on every source
/// shape, seekable included.
///
/// **A refusal has two spellings, and both mean "count instead".** They are
/// not interchangeable and neither is redundant:
///
/// * [`Error::NotSeekable`] — *the source* cannot seek. A piped zip.
/// * [`Error::Unsupported`] — *the format* has no index to seek to, however
///   seekable the source is. `tar.rs`, `ar.rs` and `cpio.rs` each raise this
///   on a seekable source deliberately, so that a caller is told "reaching
///   entry N here means walking 0..N" rather than being handed a re-scan
///   billed as random access.
///
/// Catching only the first was a real defect in this function's first draft:
/// every `--index` against a tar, ar or cpio ON A FILE failed at exit 3 with
/// "tar carries no entry index", because the honest refusal was propagated as
/// though it were fatal instead of being read as the routing signal it is.
/// The CLI tests caught it immediately; the unit tests below now pin both
/// spellings so it cannot come back.
///
/// Treating `Unsupported` as routing rather than as fatal cannot SWALLOW a
/// genuine capability limit — zip raises it for an encrypted entry, and for a
/// zstd entry on a pure build — because the counted route then reaches that
/// same entry through `next_entry` and raises the identical error there. The
/// cost of the ambiguity is a walk, never a wrong answer.
///
/// The rung gate is `is_authoritative()`, NOT `== Rung::Exact`: zip's `open`
/// takes its indexed branch for `Exact` (a file) and `Spilled` (a pipe the
/// ladder spooled to disk) alike, and both really do have the central
/// directory in hand. Gating on `Exact` alone would send a spooled read down
/// the slow route while the fast one was sitting right there.
///
/// Both routes must give the same answer, which is why `wanted` is sorted and
/// deduplicated first — see [`Selection`]'s own doc — and why out-of-range is
/// reported with the identical message either way.
fn visit_by_index(
    ar: &mut dyn ArchiveRead,
    wanted: &[usize],
    mut visit: impl FnMut(&mut Entry<'_>) -> Result<()>,
) -> Result<u64> {
    let mut wanted: Vec<usize> = wanted.to_vec();
    wanted.sort_unstable();
    wanted.dedup();
    if wanted.is_empty() {
        return Ok(0);
    }

    // The probe and the first delivery are the same call: asking twice would
    // decode the first entry twice, and on a zip whose first selected entry is
    // a symlink the target is read as part of building the entry, so "just to
    // see whether it works" is not free.
    //
    // It reduces to a `bool` rather than staying a `match` around the whole
    // fast path because a `match` on `Result<Entry<'_>, _>` holds the borrow
    // of `ar` for the entire match — the scrutinee temporary outlives every
    // arm — so the second `by_index` inside it cannot borrow `ar` again.
    let random_access = ar.fidelity().rung.is_authoritative()
        && match ar.by_index(wanted[0]) {
            Ok(mut entry) => {
                visit(&mut entry)?;
                true
            }
            // "No random access here" — count instead. Both spellings; see
            // this function's doc for why there are two.
            Err(Error::NotSeekable { .. } | Error::Unsupported(_)) => false,
            Err(e) => return Err(e),
        };
    if random_access {
        for &index in &wanted[1..] {
            let mut entry = ar.by_index(index)?;
            visit(&mut entry)?;
        }
        return Ok(wanted.len() as u64);
    }

    let mut position = 0usize;
    let mut cursor = 0usize;
    let mut visited = 0u64;
    while let Some(mut entry) = ar.next_entry()? {
        if wanted[cursor] == position {
            visit(&mut entry)?;
            visited += 1;
            cursor += 1;
            // Everything asked for has been delivered; reading the rest of
            // the archive would buy nothing. Safe for the out-of-range check
            // below precisely because it only fires when `cursor` did NOT
            // reach the end, which is the case this break cannot be in.
            if cursor == wanted.len() {
                return Ok(visited);
            }
        }
        position += 1;
    }
    // The SAME constructor a container's own `by_index` uses for the same
    // mistake — see `Error::entry_index_out_of_range`. Sharing it is what
    // makes "both routes give the same answer" true of the failure as well as
    // of the success.
    Err(Error::entry_index_out_of_range(wanted[cursor], position))
}

/// Lists every entry in an archive, extracting nothing.
///
/// `memory_limit` bounds the codec layer beneath the container — see
/// [`open_archive`]. `None` is unbounded, the library default; the CLI
/// always resolves a value. "Reads nothing and extracts nothing" is only
/// true of the ENTRIES: reaching the container's first header still decodes
/// whatever codec sits above it, so this verb is as exposed to a crafted
/// dictionary declaration as `unpack` is.
///
/// # Why it returns an [`Outcome`] as well as the entries
///
/// It used to return the `Vec` alone, and therefore **dropped the container's
/// fidelity report on the floor**. Measured on a zip whose central directory
/// holds 8 records under 6 distinct names: `stuffr test` warned that 2 records
/// are shadowed and unreachable, while `stuffr list` on the identical bytes
/// printed 6 rows and nothing at all on stderr. `list` is the verb a user
/// reaches for FIRST, so it was the one verb staying silent about the one
/// thing its own output was incomplete about.
///
/// The `Outcome`'s `bytes_out` is 0 — listing reads no payload, which is the
/// whole point of the verb — so it carries the report and the format, and
/// nothing else. Returning the same type `test`, `cat` and `extract` already
/// return is what lets the CLI hand it to the SAME `report_fidelity` call
/// rather than growing a second printer that could drift.
///
/// The entries' positions in the returned `Vec` are the indices
/// [`Selection::Indices`] selects by: one forward walk produces both, so they
/// cannot disagree.
pub fn list(
    src: Input,
    max_ratio: u64,
    memory_limit: Option<u64>,
) -> Result<(Vec<EntryMeta>, Outcome)> {
    let (mut ar, format, _consumed) =
        open_archive(crate::registry(), src, max_ratio, memory_limit)?;
    let mut out = Vec::new();
    while let Some(entry) = ar.next_entry()? {
        out.push(entry.meta().clone());
    }
    let outcome = Outcome {
        bytes_in: 0,
        bytes_out: 0,
        format,
        fidelity: ar.fidelity().clone(),
        notes: Vec::new(),
    };
    Ok((out, outcome))
}

/// Reads every entry to the end, verifying integrity, writing nothing.
///
/// The data must actually be pulled: a `test` that only walked headers would
/// pass on an archive whose payloads are corrupt, which is precisely the
/// failure it exists to find.
pub fn test(src: Input, max_ratio: u64, memory_limit: Option<u64>) -> Result<Outcome> {
    // Before `src` is consumed by `open_archive`, which takes it by value —
    // the same ordering `extract` and `cat` already use.
    let compressed_total = src
        .path()
        .and_then(|p| std::fs::metadata(p).ok())
        .map(|m| m.len());
    let (mut ar, format, consumed) = open_archive(crate::registry(), src, max_ratio, memory_limit)?;
    // `test` built no budget at all until the Phase 2 final review: a
    // 204 KB zip holding one 200 MB entry verified clean at exit 0 under
    // `--max-ratio 10`, while `cat` and `unpack` of the identical file
    // refused it at exit 6. `test` is precisely the verb reached for to
    // inspect an UNTRUSTED archive, so it must be the strictest of the
    // three, not the only unbounded one.
    // `every_entry_aware_verb_applies_the_same_expansion_bound` in
    // `crates/stuffr-cli/tests/cli.rs` pins the parity, and
    // `a_piped_archive_larger_than_the_ratio_floor_is_not_refused` pins that
    // the bound this gained does not refuse ordinary piped archives.
    let mut budget = ArchiveBudget::new(compressed_total, max_ratio).tracking(consumed);
    let mut bytes = 0u64;
    while let Some(mut entry) = ar.next_entry()? {
        let name = entry.meta().name.clone();
        // Charged from bytes ACTUALLY read, never from the size the header
        // declares — the same rule `extract` documents, and for the same
        // reason: a header that under-declares its length would otherwise
        // walk straight through the check.
        //
        // `copy_charging` applies `Error::from_decode_io` to the copy, which
        // is what keeps a container's own truncation/corruption detection on
        // an entry payload (e.g. tar's `EntryPayload::read`, comparing
        // delivered bytes against the declared size) reporting as
        // `Error::Corrupt` (exit 5) rather than `Error::Io` (exit 1).
        let n = copy_charging(entry.reader(), &mut std::io::sink(), &name, &mut budget)?;
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
        notes: Vec::new(),
    })
}

/// What [`extract`] may do beyond the defaults.
#[derive(Clone, Debug)]
pub struct ExtractOpts {
    /// Expansion ratio past which an entry — or the archive's running total —
    /// is refused. See [`ArchiveBudget`].
    pub max_ratio: u64,
    /// The archive's own compressed size, when it is known from somewhere
    /// other than the input itself. Left `None`, [`extract`] reads it from
    /// the input path's length, and a pipe (which cannot know it) leaves the
    /// budget bounded by `RATIO_FLOOR` alone.
    pub compressed_total: Option<u64>,
    /// Replace a file or symlink already sitting at an entry's target path.
    /// Without it an existing target is refused, the same contract
    /// `pack`/`unpack` already apply to a single output file.
    pub force: bool,
    /// Bounds the codec layer beneath the container — see [`open_archive`].
    /// `None` is unbounded, the library default; the CLI always resolves a
    /// value.
    pub memory_limit: Option<u64>,
}

impl Default for ExtractOpts {
    fn default() -> Self {
        Self {
            max_ratio: DEFAULT_MAX_RATIO,
            compressed_total: None,
            force: false,
            memory_limit: None,
        }
    }
}

/// Extracts the entries [`Selection`] picks — by name, by 0-based archive
/// position, or all of them — into `dest`.
///
/// # Not atomic, unlike the single-stream path
///
/// `ops::decompress` publishes through temp-file-plus-rename, so a refused
/// decode leaves no partial file at all — a property its own tests assert
/// by name. This function has no equivalent: each entry is written straight
/// to its final path, so a refusal partway through (a bomb tripping
/// [`ArchiveBudget`], an unsafe path, a corrupt payload) leaves whatever
/// entries already completed on disk, plus one partially-written file.
///
/// Documented rather than fixed, deliberately. Making extraction atomic
/// means staging the whole tree somewhere and moving it into place, which
/// needs a temp directory on the destination's own filesystem, a rename
/// strategy for an existing `dest`, and an answer for a destination larger
/// than the free space — a design decision, not a patch. Until then the
/// honest advice, which `--examples` also gives, is: extract untrusted
/// archives into a fresh directory you can delete, and check the exit code
/// before trusting the contents.
///
/// **The ONLY containment call site in the tree.** No container performs the
/// check — that is what container-harness property 12 protects, by requiring
/// a container to report a hostile name *verbatim* so this loop still has
/// something to refuse. Everything a hostile archive can do to a filesystem
/// it does here or nowhere.
///
/// Three orderings inside the loop are load-bearing:
///
/// 1. [`safe_join`] runs **before any filesystem call for that entry**.
///    Checking afterwards would already have created a file at the
///    attacker's path even if the write were then refused.
/// 2. [`check_symlink_target`] is handed the path `safe_join` produced, not
///    the raw entry name — it derives the link's depth below `dest` from
///    that path, so a raw name would make it measure the wrong depth.
/// 3. The budget is charged from bytes **actually read**, not from the size
///    the header declares. A header that under-declares its length would
///    otherwise walk straight through the check it exists to satisfy.
pub fn extract(src: Input, dest: &Path, selection: &Selection, o: &ExtractOpts) -> Result<Outcome> {
    // Before `src` is consumed by `open_archive`, which takes it by value.
    let compressed_total = o.compressed_total.or_else(|| {
        src.path()
            .and_then(|p| std::fs::metadata(p).ok())
            .map(|m| m.len())
    });
    let (mut ar, format, consumed) =
        open_archive(crate::registry(), src, o.max_ratio, o.memory_limit)?;
    let mut budget = ArchiveBudget::new(compressed_total, o.max_ratio).tracking(consumed);

    // The destination itself, once, up front: an archive of plain files
    // names no directory entry to create it, and a destination that cannot
    // be created should fail before any entry is read. This is not an
    // entry's path — it is the one the caller typed.
    std::fs::create_dir_all(dest)?;

    let mut written = 0u64;
    let mut matched = 0u64;
    // Accumulated rather than pushed straight onto the archive's own report:
    // `ar.fidelity()` borrows `ar`, which `next_entry` needs mutably. Folded
    // in once the loop is done — see the end of this function, and
    // `Outcome::fidelity`, which is what `--strict-fidelity` reads.
    let mut warnings: Vec<Fidelity> = Vec::new();
    // Directory metadata is applied AFTER every entry has been written.
    // Applying it inline would be wrong twice over: creating a child updates
    // its parent's mtime, and a directory whose archived mode is read-only
    // (0o555, say) could not be written into afterwards.
    let mut deferred_dirs: Vec<(PathBuf, EntryMeta)> = Vec::new();

    matched += visit_selected(ar.as_mut(), selection, |entry| {
        let meta = entry.meta().clone();

        // Containment BEFORE anything is created. Checking after opening the
        // destination would already have created a file at an attacker's
        // path even if the write were then refused.
        let target = safe_join(dest, &meta.name)?;
        // A post-condition on `safe_join`, not a second opinion: it returns
        // either `dest` or `dest.join(..)`, so this cannot fire today.
        // Asserting it anyway is what keeps `check_symlink_target`'s
        // `parent.strip_prefix(dest).unwrap_or("")` fallback from silently
        // MASKING a bug here — handed a `link_path` outside `dest`, that
        // fallback measures the link as sitting directly under `dest`
        // (stricter, so never an escape, but wrong) rather than complaining.
        if !target.starts_with(dest) {
            return Err(Error::UnsafePath {
                path: meta.name.clone(),
                reason: "resolved outside the destination",
            });
        }
        // `safe_join` resolves `.` and `./` to `dest` ITSELF — deliberately,
        // because that is the first entry `tar cf x.tar .` emits — and it
        // cannot decide this case on its own, because it never sees the
        // entry's KIND. So the refusal belongs here, the one place that has
        // both the resolved path and the kind.
        //
        // Left open, a FILE entry named `.` made `unpack` run
        // `File::create(dest)` on the caller's own directory: `i/o error: Is
        // a directory (os error 21)`, **exit 1** — "stuffr failed" for a
        // three-byte hostile name, which is the one code `check_error_is_
        // classified` exists to keep hostile input out of. A `Symlink` named
        // `.` is worse still: `replace_conflicting` plus `create_symlink`
        // would replace the destination directory with a link.
        //
        // Exit 7 (`UnsafePath`), argued against `error.rs`'s own rule rather
        // than picked for symmetry with the refusal above it:
        //
        // * NOT exit 5 (`Corrupt`) — nothing about the archive disagrees
        //   with itself. A `-lh0-` entry named `.` is a well-formed header
        //   delivering exactly the payload it declares; `error.rs` reserves
        //   5 for "stuffr read the bytes and they contradict each other".
        // * NOT exit 6 — no limit decided anything and nothing was sized
        //   from a declared field, which is `error.rs`'s definition of 6.
        // * NOT exit 3 — this build reads the entry perfectly well; the
        //   refusal is about what MATERIALISING it would do, not about a
        //   capability this build lacks.
        // * NOT exit 1, which is the whole point.
        //
        // That leaves the family of "the archive asked this extraction to
        // write somewhere it must not", which is exactly `UnsafePath`, and
        // it already carries a sibling shape: `safe_join` refuses `a/..`
        // with "path traversal nets back to the destination" — the other
        // name that resolves to `dest`, refused there because that one has
        // no legitimate reading at all.
        //
        // The hole was NOT introduced by the LHA name change; it is
        // pre-existing and a raw `tar` with a `REGTYPE` `.` entry reaches it
        // identically. Closing it here closes it for every container at
        // once, which is why it is not in `lha.rs`.
        if target == dest && !matches!(meta.kind, EntryKind::Dir) {
            return Err(Error::UnsafePath {
                path: meta.name.clone(),
                reason: "only a directory entry may name the destination itself",
            });
        }
        // Still before any filesystem call for this entry — and the one
        // check that has to look at the filesystem, because the two above
        // are lexical and a lexical check cannot see a symlink standing in
        // the middle of the entry's own path.
        refuse_symlinked_ancestors(dest, &target, &meta.name)?;

        match &meta.kind {
            EntryKind::Dir => {
                // `.` and `./` resolve to `dest` itself — the first entry
                // `tar cf x.tar .` emits. The destination already exists, so
                // this is a no-op rather than an error, and nothing at that
                // path may be replaced: `dest` may legitimately BE a symlink
                // to a directory the caller named.
                if target != dest {
                    replace_conflicting(&target, o.force)?;
                    std::fs::create_dir_all(&target)?;
                    deferred_dirs.push((target.clone(), meta.clone()));
                } else {
                    // The destination is the caller's own directory, named by
                    // them — not something this extraction created. Re-moding
                    // it is not extraction, and reporting it as a loss would
                    // fail `--strict-fidelity` for every `tar cf x.tar .`
                    // archive there is, which is the same reason `tar.rs`
                    // raises no warning for a forward-only read.
                    std::fs::create_dir_all(&target)?;
                }
            }
            EntryKind::Symlink {
                target: link_target,
            } => {
                // The subtler escape: the link's own PATH is contained while
                // its TARGET is not, and a later entry written "through" the
                // link lands wherever it points. Refusing here aborts the
                // whole extraction, so that later entry is never reached.
                check_symlink_target(dest, &target, link_target)?;
                replace_conflicting(&target, o.force)?;
                create_parent(&target)?;
                create_symlink(link_target, &target)?;
                // A symlink's own mode and mtime cannot be set through `std`:
                // `set_permissions` and `File::set_times` both follow the
                // link, and there is no `lchmod`/`lutimes` here (nor a `libc`
                // dependency to reach one with). Whatever the entry declared
                // is therefore lost, and saying so is the whole job of the
                // fidelity report.
                let missing = MetaFields {
                    mtime: meta.mtime.is_some(),
                    mode: meta.mode.is_some(),
                    ..Default::default()
                };
                warn_metadata(&mut warnings, &meta.name, missing);
            }
            EntryKind::File => {
                replace_conflicting(&target, o.force)?;
                create_parent(&target)?;
                let mut out = std::fs::File::create(&target)?;
                // Charged as data streams, not from the declared size.
                written += copy_charging(entry.reader(), &mut out, &meta.name, &mut budget)?;
                out.flush()?;
                // Through the open handle rather than the path: an fd cannot
                // be redirected by a symlink appearing underneath it.
                let missing = apply_metadata(&out, &meta);
                warn_metadata(&mut warnings, &meta.name, missing);
            }
            // `EntryKind::Other` — a device node, fifo, socket or hardlink,
            // the honest answer `tar` gives for a shape `EntryKind` has no
            // variant for yet. SKIPPED, and said out loud. Writing one out as
            // a regular file carrying its "contents" would materialise
            // something the archive never held: a 0-byte plain file where a
            // character device was, or a broken copy of a hardlink's target.
            // `_` rather than naming the variant because `EntryKind` is
            // `#[non_exhaustive]`; anything added upstream is unknown to this
            // loop and skipping it is the same honest answer.
            _ => {
                warnings.push(Fidelity::EntrySkipped {
                    entry: meta.name.clone(),
                    reason: "device nodes, fifos, sockets and hardlinks are not created".into(),
                });
            }
        }
        Ok(())
    })?;

    // Now that nothing more will be created inside them. Sorted deepest
    // path first: a parent chmod'd to something without the execute bit
    // (0o400, say) would otherwise be applied BEFORE its children's own
    // metadata, and `File::open` needs execute permission on every ancestor
    // to traverse into a child at all — the child would then be silently
    // left at the umask default, reported as a missing mtime and mode it
    // never lost. Sorting by component count (rather than simply reversing
    // `deferred_dirs`) is what makes this ORDER-INDEPENDENT: reversal alone
    // only works because every real archive writer lists a parent before
    // its children, and an archive that happened to list one out of order
    // would silently reinstate the exact bug this fixes. Descending by
    // depth is correct regardless of archive order, at the same one-line
    // cost. Safe for mtime too, either way: chmod or utimes on a child does
    // not touch its parent's mtime, so applying children first cannot cause
    // the parent to observe a stale timestamp.
    deferred_dirs.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
    for (path, meta) in &deferred_dirs {
        let missing = match std::fs::File::open(path) {
            Ok(handle) => apply_metadata(&handle, meta),
            // The directory is there — it was just created — so a failure to
            // reopen it is a metadata loss, not a reason to fail the
            // extraction after the data is already on disk.
            Err(_) => MetaFields {
                mtime: meta.mtime.is_some(),
                mode: meta.mode.is_some(),
                ..Default::default()
            },
        };
        warn_metadata(&mut warnings, &meta.name, missing);
    }

    // A selection that selects nothing must not report success: a typo'd name
    // would otherwise look exactly like an archive that had nothing to give.
    // An index selection never reaches here having matched nothing — an index
    // past the end is already an error naming the archive's real length.
    if matched == 0
        && let Some(missed) = selection.missed()
    {
        return Err(Error::EntryNotFound(missed));
    }

    // The container's own report, plus everything writing to disk cost. This
    // is what `--strict-fidelity` gates on, so a warning recorded anywhere
    // else would be worse than none at all — it would look handled.
    let mut fidelity = ar.fidelity().clone();
    for w in warnings {
        fidelity.warn(w);
    }

    Ok(Outcome {
        bytes_in: 0,
        bytes_out: written,
        format,
        fidelity,
        notes: Vec::new(),
    })
}

/// The permission bits extraction restores.
///
/// setuid, setgid and the sticky bit (`0o7000`) are deliberately NOT among
/// them: an archive is untrusted input, and honouring a setuid bit out of one
/// is a privilege-escalation primitive handed over for free — the same
/// default `tar` and `bsdtar` apply for a non-root extraction. Dropping them
/// is a real difference from what the archive declared, so it is REPORTED as
/// a mode loss rather than quietly applied or quietly ignored.
const RESTORED_MODE_BITS: u32 = 0o777;

/// Restores what a written entry's own metadata can carry, returning the
/// fields that could not be restored.
///
/// Takes the open handle rather than the path: an fd cannot be redirected by
/// a symlink appearing underneath it between the write and this call.
fn apply_metadata(handle: &std::fs::File, meta: &EntryMeta) -> MetaFields {
    let mut missing = MetaFields::default();

    if let Some(mode) = meta.mode {
        // `EntryMeta::mode` carries the header's mode field as the container
        // read it, and writers disagree about what belongs in there: Apache
        // Commons Compress's `TarArchiveEntry.DEFAULT_FILE_MODE` is
        // `0o100644` — an `st_mode`-shaped value with `S_IFREG` still in it —
        // which puts it in Java, Gradle and Maven tarballs. Masking to the
        // permission and special bits BEFORE deciding what was dropped is
        // what stops `0o100644` reading as "setuid was refused" and failing
        // `--strict-fidelity` on every entry of an entirely ordinary archive,
        // while the file itself lands at 0o644 exactly as it should. Masked
        // here rather than in one container so every container inherits it;
        // the pack side masks identically, for the same reason (`mode_of`).
        let mode = mode & 0o7777;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if mode & !RESTORED_MODE_BITS != 0 {
                missing.mode = true;
            }
            if handle
                .set_permissions(std::fs::Permissions::from_mode(mode & RESTORED_MODE_BITS))
                .is_err()
            {
                missing.mode = true;
            }
        }
        #[cfg(not(unix))]
        {
            let _ = handle;
            missing.mode = true;
        }
    }

    if let Some(mtime) = meta.mtime
        && handle
            .set_times(std::fs::FileTimes::new().set_modified(mtime))
            .is_err()
    {
        missing.mtime = true;
    }

    missing
}

/// Records a metadata loss, if there was one.
///
/// `MetaFields` reads "true means absent", so an all-false value means
/// everything the entry declared was restored and there is nothing to say.
fn warn_metadata(warnings: &mut Vec<Fidelity>, entry: &str, missing: MetaFields) {
    if missing == MetaFields::default() {
        return;
    }
    warnings.push(Fidelity::MetadataIncomplete {
        entry: entry.to_string(),
        fields: missing,
    });
}

/// Writes the payload of every entry [`Selection`] picks — by name, by 0-based
/// archive position, or all of them — to `dst`, in archive order.
///
/// No containment here, deliberately: `cat` opens no path at all. An entry's
/// name is only ever compared against the selection, and its bytes go to `dst`
/// — a hostile name has nowhere to point. The bomb budget still applies,
/// since the motivating case (`curl … | stuffr cat - a.txt`) streams
/// untrusted input of unknown size.
pub fn cat(
    src: Input,
    selection: &Selection,
    max_ratio: u64,
    memory_limit: Option<u64>,
    dst: &mut dyn Write,
) -> Result<Outcome> {
    let compressed_total = src
        .path()
        .and_then(|p| std::fs::metadata(p).ok())
        .map(|m| m.len());
    let (mut ar, format, consumed) = open_archive(crate::registry(), src, max_ratio, memory_limit)?;
    let mut budget = ArchiveBudget::new(compressed_total, max_ratio).tracking(consumed);
    let mut written = 0u64;
    let mut matched = 0u64;

    matched += visit_selected(ar.as_mut(), selection, |entry| {
        let name = entry.meta().name.clone();
        // A directory or symlink entry frames no payload, so this copies
        // zero bytes for one rather than needing a case of its own.
        written += copy_charging(entry.reader(), dst, &name, &mut budget)?;
        Ok(())
    })?;

    if matched == 0
        && let Some(missed) = selection.missed()
    {
        return Err(Error::EntryNotFound(missed));
    }
    dst.flush()?;

    Ok(Outcome {
        bytes_in: 0,
        bytes_out: written,
        format,
        fidelity: ar.fidelity().clone(),
        notes: Vec::new(),
    })
}

/// What [`salvage`] may do beyond the engine's own recovery-biased default —
/// [`stuffr_core::salvage::SalvagePolicy::default()`] is `partial: Keep`,
/// `max_entry: MAX_SALVAGE_ENTRY` (4 GiB), `strict: false`.
///
/// `dest` lives here rather than as a sibling parameter (unlike [`extract`]'s
/// `dest: &Path`) because [`salvage`]'s own interface is fixed by this
/// task's brief as a two-argument function; bundling it costs nothing since
/// nobody constructs a `SalvageOpts` without deciding where recovery should
/// land, if anywhere.
///
/// Fix round 1, REQUIRED 1/2: `dest` widened to `Option<PathBuf>` and
/// `select` added. Before this round the CLI approximated both by calling
/// `salvage` unconditionally (writing every recoverable entry) and then
/// filtering the RETURNED report — which never touched what actually landed
/// on disk, so `--index N -C DIR` measurably left every other entry in `DIR`
/// too. Both now gate the write itself, inside [`place_salvaged_entry`],
/// before anything is ever opened for writing.
pub struct SalvageOpts {
    /// Where recovered entries land, as a directory tree — one file (or
    /// `.partial` file) per entry, named by the entry's own relative name,
    /// created if it does not exist.
    ///
    /// `None` is report-only: every record's status, shadow relationship and
    /// — for a `Partial` entry — its [`PartialCause`] are still computed
    /// exactly as they would be otherwise, but nothing touches the
    /// filesystem at all, not even to create a directory. This is what lets
    /// `stuffr salvage --list ARCHIVE` answer "what does this archive hold"
    /// with no `-C` at all — listing is not recovering.
    pub dest: Option<PathBuf>,
    pub policy: stuffr_core::salvage::SalvagePolicy,
    /// Restricts which scan positions may be written at all.
    ///
    /// `None` recovers every eligible entry, as before. `Some(set)` reports
    /// every scan position NOT in `set` as
    /// [`SalvageDisposition::NotSelected`] — checked in
    /// [`place_salvaged_entry`] right after shadow detection (which stays
    /// first, unchanged: a shadow is never written regardless of selection,
    /// and that is a more permanent fact about the entry than what the
    /// caller happened to ask for) and before any path is ever joined
    /// against `dest`, so an unselected entry can never touch a pre-existing
    /// file of the same name sitting in `dest` already.
    pub select: Option<HashSet<usize>>,
    /// Forces which format [`salvage`] scans `path` as, instead of detecting
    /// one from its magic bytes and extension ([`resolve_salvage_format`]).
    ///
    /// `None` is the common case: detect. `Some` is Task 2's `--format`,
    /// widened from Stage 1's accept-or-reject-`zip` scaffolding to select
    /// among whichever scanners this build actually has wired — naming one
    /// this build has registered but has no salvage scanner for yet (a
    /// `tar`, or a legacy container before its own task lands) is
    /// [`Error::Unsupported`] (exit 3), exactly as an undetected archive of
    /// the same format would be; naming it explicitly never bypasses that.
    pub format: Option<FormatId>,
}

/// Why a `Partial` entry is `Partial` — see Ruling R-J. Both land the entry
/// as `name.partial` (or, under a policy that skips partials, not at all)
/// and both set the caller up for exit 4, but the two causes are different
/// diagnoses and a report that could not tell them apart would be less
/// useful than the status alone.
///
/// Computed without a second checksum pass: [`stuffr_formats::zip_salvage`]
/// already proved the entry `Partial` (a decode that ran out, or one that
/// completed and disagreed with the CRC-32). This ops layer's own re-decode
/// (needed regardless, to produce bytes worth writing) only has to observe
/// whether it too reached the entry's declared length — reaching it means
/// the earlier disagreement can only have been the checksum, since a
/// deterministic decoder given the same bytes a second time does not
/// truncate where it did not before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartialCause {
    /// The payload ran out before its declared length, or the decoder
    /// failed mid-stream.
    Truncated,
    /// Every declared byte decoded, but the result disagreed with the
    /// checksum the original writer computed.
    ChecksumMismatch,
}

/// What became of one scanned record once the ops layer acted on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SalvageDisposition {
    /// Written under its own name — `Intact` or `Complete`.
    Written(PathBuf),
    /// Written under a DISAMBIGUATED name, because an earlier record in this
    /// same run already wrote the name this one asks for.
    ///
    /// # Why this exists
    ///
    /// The final whole-branch review measured what happened without it, on
    /// an 8-record archive holding two pairs of same-named records with
    /// DIFFERENT payloads: `salvage -C out` printed `8 scanned: 8 written`
    /// at exit 0 and left **six files**, with `out/dup.txt` holding the
    /// later record's bytes and the earlier record's gone — while `salvage
    /// --index 2 -o f` returned that earlier record correctly, proving it
    /// was recoverable the whole time. A scripted `salvage broken.zip -C out
    /// && rm broken.zip` therefore lost data and reported success, in the
    /// one verb whose entire purpose is not losing things.
    ///
    /// # The principle applied
    ///
    /// The same one [`Self::WrittenPartial`] already stands on: **recover by
    /// default, and let the filesystem carry the distinction.** A truncated
    /// file under its real name is indistinguishable from a whole one to
    /// every tool downstream, so it gets `.partial`; a second record under a
    /// name already taken is indistinguishable from the first, so it gets a
    /// suffix naming its own SCAN POSITION — which maps straight back to the
    /// `--list` row a user just read, and is unique by construction.
    ///
    /// Not a fidelity warning and not a skip: both records exist, both
    /// verify, and both are worth having. The run still reports it and still
    /// exits non-zero (bucket 4, see [`salvage_exit_code`]), because a
    /// caller who scripted this needs to know a name had to be changed.
    WrittenDisambiguated {
        /// Where the bytes actually landed — the suffixed name, plus
        /// `.partial` on top of it when [`Self::partial`] is `Some`.
        path: PathBuf,
        /// The EARLIER scan position that wrote this entry's own name first.
        taken_by: usize,
        /// `Some` when this record is ALSO `Partial`, carrying the same
        /// cause [`Self::WrittenPartial`] would. The two facts are
        /// independent — a record can need disambiguating and be truncated —
        /// so they compose here rather than forcing a choice between two
        /// dispositions that are both true.
        partial: Option<PartialCause>,
    },
    /// Written under `name.partial`, never under the entry's real name —
    /// the load-bearing rule that makes recovering `Partial` entries by
    /// default safe rather than reckless (see this module's `salvage` doc
    /// and Ruling R-J).
    WrittenPartial { path: PathBuf, cause: PartialCause },
    /// A directory entry: created, never suffixed `.partial` — a directory
    /// carries no payload to disagree with a checksum.
    Directory(PathBuf),
    /// Not written: `Partial`, and the policy in effect (`--partial=skip`,
    /// or `--strict`, which forces every `Partial` entry to skip regardless
    /// of `partial`) declined it. `--partial=ask` is folded into this
    /// variant too: there is no interactive channel at this layer (a
    /// library function, not a terminal), so `Ask` is read conservatively
    /// as `Skip` rather than silently upgraded to `Keep` — the safe
    /// direction to err in when a decision cannot actually be asked for.
    ///
    /// Fix round 1, REQUIRED 3: carries the same [`PartialCause`]
    /// [`SalvageDisposition::WrittenPartial`] does, rather than a bare unit —
    /// a `--partial=skip` run used to report "Partial" with no "why" on
    /// exactly the entries the flag caused to be dropped, in a verb whose
    /// whole selling point is per-entry honesty. Determined the same way a
    /// KEPT partial's cause is (decode once, observe whether the declared
    /// length was reached), except the decoded bytes go to [`std::io::sink`]
    /// rather than a file — nothing is persisted for an entry this policy
    /// declined, but the cause costs nothing extra to learn.
    SkippedPartial(PartialCause),
    /// Not written: [`stuffr_core::salvage::SalvageStatus::Unverified`] —
    /// nothing about this entry's content was verified, for either of that
    /// status's two causes (Ruling R-M): this build recognises the entry's
    /// compression method but cannot decode it, or no length was available
    /// to bound a read against (an unreconciled zip data descriptor). The
    /// cause is not repeated here — it already lives on
    /// `SalvagedRecord::status`, this variant is only the DECISION ("listed,
    /// not written"), which is identical for both causes. Extracting the raw
    /// undecoded bytes of an undecodable-method entry is a different
    /// feature, not Stage 1's.
    SkippedUnverified,
    /// Not written: this build's codec registry does not have a decoder for
    /// the method this entry needs, even though
    /// [`stuffr_formats::zip_salvage`] already proved its content (e.g. a
    /// build with `zip` enabled but `deflate` compiled out). A build
    /// configuration gap, not an archive defect — distinct from
    /// `SkippedUnverified`, which is the archive using a method no build of
    /// this project decodes at all.
    SkippedNotBuiltIn,
    /// Not written: `SalvagedEntry::shadows` — this record's
    /// `(name, declared_len, verifier)` triple duplicates an EARLIER one
    /// (named by its scan position), which already recovered the identical
    /// content.
    SkippedShadow(usize),
    /// Not written: a kind this build has no entry shape for. Not reachable
    /// from the zip scanner today (it only ever reports `Dir` or `File`),
    /// kept for the same reason [`extract`]'s own match keeps a skip arm:
    /// `EntryKind` is `#[non_exhaustive]`.
    SkippedUnsupportedKind,
    /// Fix round 1, REQUIRED 1: not written because [`SalvageOpts::select`]
    /// is `Some` and this scan position is not in it — the caller asked for
    /// a different, narrower set of entries. Distinct from every `Skipped*`
    /// variant above: those are all facts about the ENTRY (its content, its
    /// method, its relationship to an earlier one); this one is purely about
    /// what the caller asked for, and reported on every position `select`
    /// excludes so `--list` can still show the full scan.
    NotSelected,
    /// Fix round 1, REQUIRED 2: not written because [`SalvageOpts::dest`] is
    /// `None` — report-only mode (`stuffr salvage --list` with neither `-C`
    /// nor `-o`). This entry was otherwise eligible (not a shadow, not
    /// `Unverified`, not excluded by `select`, and — if `Partial` — the
    /// policy in effect would have kept it), but there is no destination for
    /// its bytes to land in. A `Partial` entry that reaches this point
    /// instead of here — see [`place_salvaged_file`] — still resolves to
    /// `SkippedPartial` with its cause, since "no destination" and "policy
    /// declined it" both mean nothing is decoded to a real file, and the
    /// cause is worth reporting either way.
    NotWritten,
}

/// One scanned record, plus what the ops layer did with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SalvagedRecord {
    /// This record's position in SCAN order — see
    /// [`stuffr_core::salvage::SalvagedEntry::scan_position`].
    pub scan_position: usize,
    pub name: String,
    pub status: stuffr_core::salvage::SalvageStatus,
    /// An EARLIER scan position this record was measured to be a
    /// byte-identical copy of — see
    /// [`stuffr_core::salvage::SalvagedEntry::shadows`].
    pub shadows: Option<usize>,
    /// An EARLIER scan position using the same name, where the two were NOT
    /// proven identical — see
    /// [`stuffr_core::salvage::SalvagedEntry::collides_with`]. Mutually
    /// exclusive with [`Self::shadows`], and the fact that actually decides
    /// what happens on disk: two records under one name with two different
    /// payloads cannot both land on one path.
    pub collides_with: Option<usize>,
    pub disposition: SalvageDisposition,
}

/// The report [`salvage`] returns: what the scan found and what became of
/// each record on disk.
#[derive(Debug)]
pub struct SalvageOutcome {
    pub entries: Vec<SalvagedRecord>,
}

/// Ruling R-N (fix round 1): the exit-code bucket a COMPLETED salvage run's
/// outcome maps to. Written here once so Task 6's CLI consumes this rule
/// rather than re-deriving one — nine [`SalvageDisposition`] variants
/// collapse onto five exit-code buckets, and until this fix round no
/// aggregation policy was recorded anywhere.
///
/// **Exit 6 (over the ceiling) and exit 7 (path escape) are NOT covered
/// here.** Both are errors that abort the run — `salvage` returns `Err`
/// before a `SalvageOutcome` ever exists — so there is nothing to
/// aggregate for them; this function is only meaningful for a `salvage()`
/// call that returned `Ok`.
///
/// Among a completed run's entries, the HIGHEST applicable bucket wins:
///
/// ```text
/// 5  nothing recoverable at all (no entries were even scanned)
/// 3  any entry Unverified
/// 4  any entry Partial (written or skipped), any entry skipped for any
///    other reason, or any entry written under a disambiguated name
/// 0  every entry Intact or Complete
/// ```
///
/// **A disambiguated write is in bucket 4 even though nothing was lost**,
/// and that is deliberate: the archive held two records under one name and
/// only one of them can have it, so a caller scripting `salvage -C out &&
/// rm broken.zip` needs the run to say something happened. Exit 0 is
/// reserved for a recovery that reproduced the archive's own names exactly.
///
/// **3 outranks 4 deliberately.** `Unverified` is actionable and names its
/// own remedy — a rebuild, or `--features c-backed` — where 4 only says
/// "degraded". A user who can fix their build should be told that before
/// being told something was lossy.
///
/// **Fix round 1: `NotSelected` and `NotWritten` count toward neither
/// bucket**, deliberately, alongside `Written`/`Directory`. Both are facts
/// about what the CALLER asked for (a narrower `--index` selection, or no
/// destination at all in report-only mode) rather than anything wrong with
/// the archive or the recovery — so selecting fewer entries, or only ever
/// listing, must never by itself turn a clean run into exit 4.
pub fn salvage_exit_code(outcome: &SalvageOutcome) -> i32 {
    if outcome.entries.is_empty() {
        return 5;
    }

    let mut any_unverified = false;
    let mut any_degraded = false;
    for record in &outcome.entries {
        match &record.disposition {
            SalvageDisposition::Written(_)
            | SalvageDisposition::Directory(_)
            | SalvageDisposition::NotSelected
            | SalvageDisposition::NotWritten => {}
            SalvageDisposition::SkippedUnverified => any_unverified = true,
            SalvageDisposition::WrittenDisambiguated { .. }
            | SalvageDisposition::WrittenPartial { .. }
            | SalvageDisposition::SkippedPartial(_)
            | SalvageDisposition::SkippedNotBuiltIn
            | SalvageDisposition::SkippedShadow(_)
            | SalvageDisposition::SkippedUnsupportedKind => any_degraded = true,
        }
    }

    if any_unverified {
        3
    } else if any_degraded {
        4
    } else {
        0
    }
}

/// Identifies which container format [`salvage`] should scan `path` as —
/// `opts.format`'s hint if one was given (Task 2 widens `--format` from
/// Stage 1's accept-or-reject-`zip` scaffolding into this selector), else
/// detected from `path`'s magic bytes and extension.
///
/// Reuses [`resolve_chain`] — the SAME magic+extension resolution every
/// other read verb (`list`, `cat`, `test`, `unpack`) builds on — rather than
/// a salvage-private sniffer, so a format this build recognises at all is
/// recognised identically here. Deliberately the SHALLOW resolver, never
/// [`resolve_chain_deep_with`]: salvage has no use for decoding through a
/// codec layer to find a container beneath it, and, more importantly, never
/// asks a container to OPEN itself to be identified — `resolve_chain` reads
/// a bounded prefix and matches it against registered magic/extension
/// tables only, so a truncated central directory or a zeroed header cannot
/// prevent format detection the way actually opening the container could.
/// [`Chain::container`] is what makes a compressed container (`.tar.gz`,
/// were salvage ever extended to one) and a bare one answer alike; a chain
/// that resolves no container at all (a bare codec stream, or raw bytes) is
/// [`Error::NotAnArchive`] — salvage has nothing with entries to scan.
fn resolve_salvage_format(path: &Path, hint: Option<FormatId>) -> Result<FormatId> {
    if let Some(id) = hint {
        return Ok(id);
    }
    let mut file = std::fs::File::open(path)?;
    let mut prefix = vec![0u8; PROBE_LEN];
    let mut filled = 0;
    loop {
        match file.read(&mut prefix[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    prefix.truncate(filled);
    let chain = resolve_chain(crate::registry(), Some(path), &prefix)?;
    chain.container().ok_or_else(|| Error::NotAnArchive {
        chain: chain.describe(),
    })
}

/// Dispatches a resolved container format to its salvage scanner, matching
/// [`stuffr_formats::zip_salvage::salvage_zip`]'s own signature exactly —
/// `fn(&mut dyn SeekRead, &SalvagePolicy) -> Result<SalvageOutcome>` (the
/// [`stuffr_core::salvage::SalvageOutcome`] the shared engine produces, not
/// this module's own [`SalvageOutcome`] report) — so each later task's own
/// scanner (zoo, lha, arj) drops in as one more arm here, gated on its own
/// feature, alongside the task that adds it. `zip` (Task 2) and `arc`
/// (Task 3, [`stuffr_formats::legacy::arc_salvage::salvage_arc`]) are wired;
/// every other format — including one this build has fully registered as an
/// ordinary container, like `tar` — answers [`Error::Unsupported`] (exit 3)
/// **naming the format**, never a silent empty
/// [`stuffr_core::salvage::SalvageOutcome`]. An empty outcome would reach
/// the CLI as "the scan found nothing recoverable" (exit 5), a claim about
/// the ARCHIVE; the truth here is a claim about this BUILD — it never
/// tried. `tar`, `ar` and `cpio` answer this way for a structural reason
/// (Stage 3, if it ever comes: a false-positive scan over their headers is
/// undetectable by construction); `zoo`, `lha` and `arj` answer this way
/// only until their own task lands a scanner.
fn salvage_scan(
    format: FormatId,
    src: &mut dyn SeekRead,
    policy: &stuffr_core::salvage::SalvagePolicy,
) -> Result<stuffr_core::salvage::SalvageOutcome> {
    match format.as_str() {
        #[cfg(feature = "zip")]
        "zip" => stuffr_formats::zip_salvage::salvage_zip(src, policy),
        #[cfg(not(feature = "zip"))]
        "zip" => Err(Error::FormatNotEnabled(FormatId::new("zip"))),
        #[cfg(feature = "arc")]
        "arc" => stuffr_formats::legacy::arc_salvage::salvage_arc(src, policy),
        #[cfg(not(feature = "arc"))]
        "arc" => Err(Error::FormatNotEnabled(FormatId::new("arc"))),
        other => Err(Error::Unsupported(format!(
            "salvage has no scanner for `{other}` archives in this build"
        ))),
    }
}

/// Recovers what this build's per-format scanner ([`salvage_scan`]) finds in
/// a damaged archive at `path`, writing what can safely be written into
/// `opts.dest`.
///
/// # The governing principle
///
/// Salvage is the one recovery-biased verb in this tool; `list`, `cat`,
/// `unpack` and `test` stay exactly as uncompromising as they already are.
/// So a `Partial` entry is written **by default** (`--partial=keep`), but
/// never under its real name — always `name.partial` — because a truncated
/// file under its real name is indistinguishable from a whole one to every
/// tool downstream. An `Unverified` entry (Ruling R-K, widened by Ruling
/// R-M) is never written at all, for either of its two causes: this build
/// never decoded an undecodable method, and never even had a length to
/// bound a read against for an unreconciled data descriptor — either way
/// there is no recovered content to write, only raw bytes a different
/// feature would extract.
///
/// # Containment is reused, never reimplemented
///
/// Every entry this function decides to place on disk goes through
/// [`safe_join`] and [`refuse_symlinked_ancestors`] — the SAME calls
/// [`extract`] makes, in the same order, including the `target == dest`
/// refusal for a non-directory entry. A hostile name escaping `opts.dest`
/// aborts the whole run with [`Error::UnsafePath`] (exit 7), exactly as it
/// aborts `unpack`; salvage's permissiveness is about WHAT gets written for
/// damaged content, never about WHERE.
///
/// An entry this function has already decided not to write for some other
/// reason (a shadow, `Unverified`, a skipped partial) never reaches
/// containment at all: refusing to write something buys no protection by
/// also refusing to look at its name, and aborting the recovery of an
/// entire archive over one entry's hostile name that was never going to be
/// written would be exactly backwards for a recovery-biased verb.
///
/// # Payload decoding is each format's own job (rewritten, Task 3c)
///
/// Stage 2 now has TWO wired scanners — [`stuffr_formats::zip_salvage`] and
/// [`stuffr_formats::legacy::arc_salvage`]; see [`salvage_scan`] for the
/// scan-side dispatch and [`write_salvaged_payload`] for the write-side
/// one, every format outside both refuses through. This function itself
/// never decodes anything: it hands each entry to
/// [`write_salvaged_payload`], which hands it on to the resolved format's
/// own `write_payload` — [`stuffr_formats::zip_salvage::write_payload`] or
/// [`stuffr_formats::legacy::arc_salvage::write_payload`] today, one more
/// per format as zoo/lha/arj each land.
///
/// This section used to say the opposite of all three of those facts —
/// "exactly one wired scanner", decoding "goes through
/// [`crate::registry`]'s own decoder for `deflate`", and "the dispatch
/// below never reaches past Stored/Deflate" — because it was written when
/// zip really was the only scanner and its write path really did live
/// inline, below, dispatching through the registry. Task 3c moved the
/// write path out to each scanner's own module and, along with it, changed
/// how zip's own Deflate entries decode: **`zip_salvage.rs::write_payload`
/// now calls `flate2::read::DeflateDecoder` directly, the same backend its
/// own `verify_candidate` already used to check the entry's CRC-32, rather
/// than going through `crate::registry().require_decoder("deflate")`.**
/// That is a real, user-visible behaviour change, not only an internal
/// one: `stuffr`'s `zip` feature does NOT imply `deflate`
/// (`crates/stuffr/Cargo.toml`), so on a `--no-default-features --features
/// zip` build, a Deflate zip entry that used to report
/// [`SalvageDisposition::SkippedNotBuiltIn`] (`FormatNotEnabled`, because
/// the registry had no `deflate` decoder registered) now decodes and
/// writes normally. This is judged an improvement, not a regression:
/// `verify_candidate` already used `flate2` directly and already reported
/// such an entry `Intact`, so the two halves of salvage — deciding a
/// status and then acting on it — used to disagree about whether this
/// build could really decode the entry, and now agree.
pub fn salvage(path: &Path, opts: &SalvageOpts) -> Result<SalvageOutcome> {
    let format = resolve_salvage_format(path, opts.format)?;
    let scan = {
        let mut file = std::fs::File::open(path)?;
        salvage_scan(format, &mut file, &opts.policy)?
    };

    if let Some(dest) = &opts.dest {
        std::fs::create_dir_all(dest)?;
    }

    // Every destination path an earlier entry IN THIS RUN has already
    // written, mapped to the scan position that claimed it. Salvage is the
    // one verb whose input can legitimately name the same file twice (that
    // is the whole feature), so "already there" has to mean "written by this
    // run", not "exists on disk" — a stale file from a previous attempt must
    // still be replaced, which is what `replace_conflicting(.., true)` in
    // `place_salvaged_file` is for and why it is NOT what closes this.
    let mut claimed: std::collections::HashMap<PathBuf, usize> = std::collections::HashMap::new();

    let mut entries = Vec::with_capacity(scan.entries.len());
    for entry in &scan.entries {
        let disposition = place_salvaged_entry(path, opts, entry, &mut claimed, format)?;
        entries.push(SalvagedRecord {
            scan_position: entry.scan_position,
            name: entry.meta.name.clone(),
            status: entry.status,
            shadows: entry.shadows,
            collides_with: entry.collides_with,
            disposition,
        });
    }
    Ok(SalvageOutcome { entries })
}

/// Decides — and, for everything but a shadow/skip, carries out — what
/// happens to one scanned record.
///
/// Shadow detection is checked FIRST, before anything else, including
/// `select` and containment: a shadowed record contributes nothing that was
/// not already recovered under its earliest occurrence, so there is nothing
/// to gain by even looking at its name — and this is a permanent fact about
/// the entry's own content, unlike selection, which is only about what the
/// caller asked for.
///
/// `select` is checked SECOND, before containment: an unselected scan
/// position is skipped before [`salvage_contained_target`] ever runs, so it
/// can never touch a pre-existing file of the same name sitting in
/// `opts.dest` already (fix round 1, REQUIRED 1).
fn place_salvaged_entry(
    archive_path: &Path,
    opts: &SalvageOpts,
    entry: &stuffr_core::salvage::SalvagedEntry,
    claimed: &mut std::collections::HashMap<PathBuf, usize>,
    format: FormatId,
) -> Result<SalvageDisposition> {
    if let Some(earlier) = entry.shadows {
        return Ok(SalvageDisposition::SkippedShadow(earlier));
    }
    if let Some(select) = &opts.select
        && !select.contains(&entry.scan_position)
    {
        return Ok(SalvageDisposition::NotSelected);
    }

    match entry.meta.kind {
        // A directory entry is NOT tracked in `claimed` and is never
        // disambiguated: `create_dir_all` over a directory that already
        // exists is idempotent, so a repeated directory entry costs nothing
        // and destroys nothing — unlike a repeated FILE entry, where the
        // second write replaces the first record's bytes.
        EntryKind::Dir => match &opts.dest {
            Some(dest) => {
                let target = salvage_contained_target(dest, entry)?;
                std::fs::create_dir_all(&target)?;
                Ok(SalvageDisposition::Directory(target))
            }
            // Report-only: nothing to create, and nothing worth a path —
            // there is no `dest` for one to be relative to.
            None => Ok(SalvageDisposition::NotWritten),
        },
        EntryKind::File => place_salvaged_file(
            archive_path,
            &opts.dest,
            &opts.policy,
            entry,
            claimed,
            format,
        ),
        _ => Ok(SalvageDisposition::SkippedUnsupportedKind),
    }
}

/// [`place_salvaged_entry`]'s `EntryKind::File` arm: decides whether this
/// entry is written at all, and under which name, before touching
/// containment or the filesystem.
///
/// `dest: &Option<PathBuf>` rather than `&Path`, because whether a
/// destination exists at all is a THIRD reason (alongside policy and
/// `Unverified`) this function may end up not writing real bytes anywhere —
/// see the `dest.is_none()` arm below.
fn place_salvaged_file(
    archive_path: &Path,
    dest: &Option<PathBuf>,
    policy: &stuffr_core::salvage::SalvagePolicy,
    entry: &stuffr_core::salvage::SalvagedEntry,
    claimed: &mut std::collections::HashMap<PathBuf, usize>,
    format: FormatId,
) -> Result<SalvageDisposition> {
    use stuffr_core::salvage::{PartialPolicy, SalvageStatus};

    // R-K, widened by Ruling R-M: never written, regardless of any policy,
    // for EITHER cause `Unverified` now carries — an undecodable method, or
    // (since the fix-round-1 engine change) an unreconciled data descriptor
    // with no length to bound a read against. This build never decoded the
    // content either way, so there is nothing recovered to write.
    if matches!(entry.status, SalvageStatus::Unverified(_)) {
        return Ok(SalvageDisposition::SkippedUnverified);
    }

    let Some(compressed_len) = entry.meta.compressed_size else {
        // Defensive only, and should be unreachable: with Ruling R-M,
        // `zip_salvage.rs::verify_candidate` reports `Unverified` for every
        // candidate with no declared length, which the check above already
        // caught. Reaching here means that engine invariant no longer
        // holds — refused rather than guessing at a length to bound a read
        // against, the same "never write from an unbounded declaration"
        // discipline this whole module follows.
        return Err(Error::Corrupt(format!(
            "entry `{}` carries no declared length but was not reported \
             Unverified; the salvage engine's own invariant (Ruling R-M) \
             does not hold for it",
            entry.meta.name
        )));
    };

    let is_partial = entry.status == SalvageStatus::Partial;
    // `strict` overrides `partial` wholesale (Ruling: "demand proof: partial
    // skipped"), never the other way — `partial: Keep` under `strict: true`
    // still skips. Moot when `is_partial` is false.
    let policy_would_keep = !is_partial || {
        let effective = if policy.strict {
            PartialPolicy::Skip
        } else {
            policy.partial
        };
        matches!(effective, PartialPolicy::Keep)
    };

    if is_partial && !(policy_would_keep && dest.is_some()) {
        // No real bytes will land anywhere for this entry — either the
        // policy declined it, or there is no destination at all
        // (report-only `--list`). Fix round 1, REQUIRED 3: the cause is
        // still knowable without persisting anything, by decoding once into
        // `io::sink()` rather than a file — the exact same observation
        // `write_payload`'s caller below makes for a KEPT partial, just
        // discarded rather than kept.
        return Ok(
            match write_salvaged_payload(
                format,
                archive_path,
                entry,
                compressed_len,
                &mut std::io::sink(),
            ) {
                Ok(completed) => {
                    let cause = if completed {
                        PartialCause::ChecksumMismatch
                    } else {
                        PartialCause::Truncated
                    };
                    SalvageDisposition::SkippedPartial(cause)
                }
                Err(Error::FormatNotEnabled(_) | Error::Unsupported(_)) => {
                    SalvageDisposition::SkippedNotBuiltIn
                }
                Err(e) => return Err(e),
            },
        );
    }

    let Some(dest) = dest else {
        // Not `Partial` (Intact/Complete), and there is no destination:
        // nothing to decode a cause for, nothing to write.
        return Ok(SalvageDisposition::NotWritten);
    };

    // Contained target, computed only now that this entry really will be
    // written in some form — see `salvage`'s own doc for why an entry
    // declined above never reaches this call.
    let target = salvage_contained_target(dest, entry)?;

    // An EARLIER entry in this same run already wrote this path: the
    // archive holds two records under one name, and only one of them can
    // have it. Recover both and let the filesystem carry the distinction —
    // see `SalvageDisposition::WrittenDisambiguated` for the measurement
    // that made this necessary and for why the suffix names the scan
    // position.
    let taken_by = claimed.get(&target).copied();
    let base_target = match taken_by {
        Some(_) => disambiguated_path(&target, entry.scan_position),
        None => target.clone(),
    };
    let write_target = if is_partial {
        partial_path(&base_target)
    } else {
        base_target
    };
    // Both the name the entry ASKED for and the name it actually got are
    // claimed. The first is what makes a later record under the same name
    // disambiguate; the second matters because an archive is free to
    // contain a real entry literally named `x.salvaged-6`, and two records
    // landing on one path is the defect being closed, not a shape to leave
    // one door open on. `or_insert` keeps the EARLIEST claimant, which is
    // the position `taken_by` must name.
    claimed.entry(target).or_insert(entry.scan_position);
    claimed
        .entry(write_target.clone())
        .or_insert(entry.scan_position);

    // No `--force` concept exists for salvage (not in this feature's flag
    // list) and none is needed: recovery is meant to be re-run, and a stale
    // `.partial` (or a stale real-named file) from a previous attempt must
    // not block this one. `true` unconditionally, unlike `extract`'s own
    // `o.force`. `replace_conflicting` is reused rather than a bare
    // `File::create` specifically because it also removes a pre-existing
    // SYMLINK sitting at the target — `File::create` would instead follow
    // it, landing the recovered bytes wherever it points.
    //
    // It is deliberately NOT what stops one salvage run overwriting its own
    // earlier output: "replace what was already on disk" and "two records
    // in this archive want one name" are different facts, and conflating
    // them is exactly how eight recovered records became six files at exit
    // 0. `claimed` above is what separates them.
    replace_conflicting(&write_target, true)?;
    create_parent(&write_target)?;
    let mut out = std::fs::File::create(&write_target)?;
    let completed =
        match write_salvaged_payload(format, archive_path, entry, compressed_len, &mut out) {
            Ok(completed) => completed,
            Err(Error::FormatNotEnabled(_) | Error::Unsupported(_)) => {
                drop(out);
                let _ = std::fs::remove_file(&write_target);
                return Ok(SalvageDisposition::SkippedNotBuiltIn);
            }
            Err(e) => return Err(e),
        };
    out.flush()?;

    let partial_cause = is_partial.then_some(if completed {
        PartialCause::ChecksumMismatch
    } else {
        PartialCause::Truncated
    });

    if let Some(taken_by) = taken_by {
        // Disambiguation and partiality are independent facts and both can
        // be true at once, so the one disposition carries both rather than
        // forcing a choice between two variants that are each correct.
        Ok(SalvageDisposition::WrittenDisambiguated {
            path: write_target,
            taken_by,
            partial: partial_cause,
        })
    } else if let Some(cause) = partial_cause {
        Ok(SalvageDisposition::WrittenPartial {
            path: write_target,
            cause,
        })
    } else if completed {
        Ok(SalvageDisposition::Written(write_target))
    } else {
        // The scan already proved this entry `Intact`/`Complete` — a
        // deterministic re-decode of the same bytes should reach the same
        // length every time. Reaching here means the archive changed on
        // disk between the scan and this write, or a real device fault
        // interrupted it; either way, writing a short file under the
        // entry's REAL name would recreate the exact hazard `.partial`
        // naming exists to prevent, through a different door. Refused
        // instead, and the half-written file is not left behind.
        let _ = std::fs::remove_file(&write_target);
        Err(Error::Corrupt(format!(
            "entry `{}` decoded short on write after the scan reported it {:?}; the \
             archive may have changed on disk between scanning and salvage",
            entry.meta.name, entry.status
        )))
    }
}

/// [`safe_join`] plus the same two refinements [`extract`] applies before
/// any filesystem call for an entry — reused verbatim, not reimplemented,
/// per this task's own governing rule.
fn salvage_contained_target(
    dest: &Path,
    entry: &stuffr_core::salvage::SalvagedEntry,
) -> Result<PathBuf> {
    let target = safe_join(dest, &entry.meta.name)?;
    // A post-condition on `safe_join`, asserted rather than assumed — see
    // `extract`'s identical check for why.
    if !target.starts_with(dest) {
        return Err(Error::UnsafePath {
            path: entry.meta.name.clone(),
            reason: "resolved outside the destination",
        });
    }
    if target == dest && !matches!(entry.meta.kind, EntryKind::Dir) {
        return Err(Error::UnsafePath {
            path: entry.meta.name.clone(),
            reason: "only a directory entry may name the destination itself",
        });
    }
    refuse_symlinked_ancestors(dest, &target, &entry.meta.name)?;
    Ok(target)
}

/// `name` becomes `name.partial` — appended to the WHOLE final component,
/// not replacing an existing extension, so `report.txt` becomes
/// `report.txt.partial` rather than `report.partial`.
fn partial_path(target: &Path) -> PathBuf {
    let mut name = target
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    name.push(".partial");
    target.with_file_name(name)
}

/// `name` becomes `name.salvaged-N`, where `N` is the record's own SCAN
/// POSITION — appended to the whole final component, exactly as
/// [`partial_path`] appends `.partial`, and for the identical reason.
///
/// The scan position is what makes the name both unique (no two records
/// share one) and traceable: it is the number in the first column of the
/// `stuffr salvage --list` row a user just read, so a file on disk maps
/// back to the record it came from with no second lookup. A bare counter
/// (`.1`, `.2`) would be unique too and would name nothing.
///
/// Composes with `.partial` rather than competing with it: a disambiguated
/// partial lands as `name.salvaged-6.partial`, with `.partial` LAST so the
/// suffix every downstream tool is being warned by stays the final one.
fn disambiguated_path(target: &Path, scan_position: usize) -> PathBuf {
    let mut name = target
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    name.push(format!(".salvaged-{scan_position}"));
    target.with_file_name(name)
}

/// Dispatches to the format's own salvage payload writer — matching
/// [`salvage_scan`]'s own dispatch exactly, so each later task's own
/// scanner (zoo, lha, arj) drops in as one more arm here too, alongside the
/// arm it already adds there.
///
/// Task 3c replaced what used to be one zip-shaped `write_payload` here: it
/// unconditionally read a 30-byte zip local header from `entry.offset` to
/// locate a payload, and dispatched decoding through a `store`/`deflate`
/// match that had no arm for anything else. Both were fine for zip, the
/// only wired scanner at the time, and both broke the moment ARC (Task 3)
/// added a second one — an ARC candidate near end-of-file made that 30-byte
/// read run past EOF and raise `Error::Io` (exit 1, the wildcard this
/// project treats as a defect), and an ARC entry's `EntryMeta::codec` was
/// never populated in the first place, so even a successful read would have
/// fallen through to `SkippedNotBuiltIn` rather than really being written.
/// Locating a payload and decoding it are now each format's own job —
/// [`stuffr_formats::zip_salvage::write_payload`] and
/// [`stuffr_formats::legacy::arc_salvage::write_payload`] — using
/// [`stuffr_core::salvage::SalvagedEntry::payload_start`], which every
/// scanner now computes once, at discovery, instead of a generic caller
/// re-deriving (and mis-deriving) it later.
///
/// # Fix round 1, MEDIUM-2: this table and [`salvage_scan`]'s are two
/// independent `match`es, coupled only by convention
///
/// Nothing — neither the type system nor, before this fix round, a test —
/// stops a later task from adding a scanner arm to [`salvage_scan`] and
/// forgetting the matching arm here. The result is not a compile error or
/// even a loud runtime one: an unmatched format falls to the `other =>` arm
/// below, [`place_salvaged_file`] maps that `Error::Unsupported` to
/// [`SalvageDisposition::SkippedNotBuiltIn`], and the run reports `N
/// scanned: 0 written … N skipped` at exit 4 — a scan that silently never
/// writes anything, which is the EXACT companion gap ARC itself shipped
/// with in Task 3 (a real scanner, an unpopulated `EntryMeta::codec`,
/// every entry quietly `SkippedNotBuiltIn`) recurring through the seam
/// built to close it. `salvage_seam_tests`'s
/// `every_salvage_slot_reaches_a_real_payload_writer` pins the positive
/// set — every name in [`stuffr_core::testing::SALVAGE_SLOTS`] (the same
/// list the fuzz corpus generator and `entries::salvage`'s own dispatch
/// table are checked against elsewhere) must reach a real per-format arm
/// here, never this function's own fallback — so the NEXT scanner task
/// that forgets this half fails a test rather than shipping silently. A
/// `SalvageScan::write_payload` trait method would make this a compile
/// error instead and was considered; deferred rather than taken mid-phase,
/// since it would have to land ahead of the three scanners (zoo, lha, arj)
/// still to come, before its right shape is known from more than one
/// example.
fn write_salvaged_payload(
    format: FormatId,
    archive_path: &Path,
    entry: &stuffr_core::salvage::SalvagedEntry,
    compressed_len: u64,
    out: &mut dyn Write,
) -> Result<bool> {
    match format.as_str() {
        #[cfg(feature = "zip")]
        "zip" => {
            stuffr_formats::zip_salvage::write_payload(archive_path, entry, compressed_len, out)
        }
        #[cfg(not(feature = "zip"))]
        "zip" => Err(Error::FormatNotEnabled(FormatId::new("zip"))),
        #[cfg(feature = "arc")]
        "arc" => stuffr_formats::legacy::arc_salvage::write_payload(
            archive_path,
            entry,
            compressed_len,
            out,
        ),
        #[cfg(not(feature = "arc"))]
        "arc" => Err(Error::FormatNotEnabled(FormatId::new("arc"))),
        // Unreachable in practice: `salvage_scan` already refuses any other
        // format before a single candidate is ever produced, so `salvage()`
        // never reaches a per-entry write for one.
        other => Err(Error::Unsupported(format!(
            "salvage has no payload writer for `{other}` archives in this build"
        ))),
    }
}

/// Collects `paths` into a new `container` archive at `dst`, optionally
/// inside `codec`.
///
/// A named file becomes one entry; a named DIRECTORY becomes its whole tree,
/// walked by [`crate::walk`] and named beneath the directory's own final
/// component. Both go through the same walk, so a file packed on its own and
/// the same file packed as part of its parent carry identical metadata —
/// ownership included, which is what an earlier hand-built `EntryMeta` here
/// silently dropped while still reporting `Rung::Exact`.
///
/// `codec` is what makes `bundle.tar.gz` writable in one step: the codec's own
/// `Sink` becomes the container's destination, so the container writes its
/// entries and trailer THROUGH the encoder, and one `finish` at each layer
/// closes both in the right order. `None` writes a bare container.
///
/// Every input is validated before the destination is touched, the same
/// contract `Codec::check_encode_opts` gives the single-stream path: a
/// rejected command costs nothing, with no temp file created and no existing
/// file disturbed. The codec's own option checks run there too, for the same
/// reason.
///
/// # What the returned report carries
///
/// The `Outcome`'s `fidelity` is no longer a hardcoded `Rung::Exact` with an
/// empty warning list. The rung stays `Exact` — it describes a READ ladder,
/// and there is no ladder on the write side — but the warnings are real:
/// anything the walk met and could not store (see [`crate::walk::ItemSource`]),
/// anything this container has no shape for (`ar` has neither directories nor
/// symlinks), any file that could not be OPENED when its turn came, any entry
/// whose ownership was never learned, and a summary of hardlinks that will
/// extract as independent copies. `--strict-fidelity` turns any of them into
/// exit 4, exactly as it does on the read side.
///
/// # Excluding the output from its own walk
///
/// `stuffr pack . -o backup.tar` walks `.`, which — the first time `--force`
/// re-runs the same command — already contains `backup.tar` from the
/// previous run. Left unhandled, every run nests the last one inside the
/// new one and the file grows without bound; GNU tar's answer to the same
/// shape is `file is the archive; not dumped`, and this is that same
/// refusal applied per-file rather than at the top. See [`canonical_output_path`]
/// and [`is_output_file`] for how the comparison is made honest against
/// relative walk paths and a destination that does not exist yet.
///
/// # A plan that would write nothing worth having is refused
///
/// Two shapes, both returning [`Error::Usage`] before `dst.create`, so an
/// archive already sitting at the destination is never even opened:
///
/// 1. **The plan holds no storable item at all** — every path named was the
///    output itself, or every path named was skipped.
///    `pack backup.tar -o backup.tar --force` is the shape.
/// 2. **The plan holds nothing with contents, and the output was excluded
///    from it.** `pack /backups -o /backups/nightly.tar --force` over a
///    directory whose only member is last night's archive: the plan is not
///    empty — `/backups`'s own directory entry is in it — so the first guard
///    does not fire, and a healthy archive is replaced by a shell holding one
///    directory entry, at exit 0, with `--strict-fidelity` reporting it
///    clean.
///
/// Both used to pass. A fidelity warning could not have fixed either: by the
/// time one could be raised the good archive has already been replaced, and
/// the replacement IS the harm. A self-exclusion is also (correctly) a note
/// rather than a warning, so it never reached the strict gate at all.
///
/// An empty DIRECTORY is neither case: its own entry is in the plan, nothing
/// was excluded from that plan, and the pack succeeds. That is the whole
/// weight the second guard's conjunction carries — the two plans are
/// otherwise identical.
pub fn create_archive(
    paths: &[PathBuf],
    dst: Output,
    container: FormatId,
    codec: Option<FormatId>,
    o: &CompressOpts,
) -> Result<Outcome> {
    // `require_container_writer`, not `require_container`: a read-only
    // container (ARC, ZOO — LHA and ARJ were on this list until Phase 3c
    // Tasks 6 and 7 gave them encoders) must be refused here, by the
    // registry, in the same
    // sentence `require_encoder` refuses a decode-only codec — not by
    // reaching `create()` and relying on each adapter to hand-roll a refusal
    // of its own. See that method's doc comment.
    let kind = crate::registry().require_container_writer(container)?;

    // Resolved, checked and consented to BEFORE the destination is opened —
    // the same order `ops::compress_with` uses, so a rejected level or an
    // unconsented weak encoder costs nothing on either path.
    let encoder = match codec {
        Some(id) => {
            let c = crate::registry().require_encoder(id)?;
            if c.caps().weak_encoder && !o.allow_weak_encoder {
                return Err(Error::Usage(format!(
                    "`{id}` in this build has only a weak encoder: it produces valid \
                     output with a markedly worse ratio, and buffers the whole input in \
                     memory. Pass --allow-weak-encoder to use it anyway, or rebuild with \
                     --features c-backed for the real encoder."
                )));
            }
            let encode = EncodeOpts {
                level: o.level,
                // `ops::resolved_budget(o)`, matching the single-stream path.
                //
                // Phase 2c used to hardcode `None` here: the CLI refused
                // `--threads`, `--turbo` and `--allow-weak-encoder` whenever
                // the output named a container, so building a governor from
                // `STUFFR_THREADS` alone (which no flag check can see) would
                // have let the environment succeed at exactly what the flag
                // was refused for — and, because xz and lzip split their
                // input per worker, `STUFFR_THREADS=4 stuffr pack big -o
                // x.tar.xz` would have emitted different bytes from the same
                // command without it.
                //
                // Now that `refuse_unhonoured_pack_flags` only refuses these
                // where the resolved chain has NO codec layer, a composed
                // write with a codec is exactly the case `resolved_budget`
                // exists for, and the reproducibility promise (same input +
                // same flags + same environment) holds the same way it does
                // on the single-stream path: `STUFFR_THREADS` is consulted
                // here precisely because `--threads` is now honoured here.
                governor: crate::ops::resolved_budget(o),
                ..Default::default()
            };
            c.check_encode_opts(&encode)?;
            Some((c, encode))
        }
        None => None,
    };

    // Resolved once, before the walk, so every file it finds can be checked
    // against it: a re-run of `stuffr pack . -o backup.tar --force` must not
    // walk `backup.tar` back into the new `backup.tar`, the way GNU tar
    // refuses with `file is the archive; not dumped`. Read-only (a `stat` of
    // the parent, nothing more), so it costs nothing against the "every
    // input validated before the destination is touched" contract above.
    let dst_canonical = canonical_output_path(&dst);

    let mut plan: Vec<crate::walk::WalkItem> = Vec::with_capacity(paths.len());
    let mut names = HashSet::new();
    // Told, never counted. See `Outcome::notes`.
    let mut notes: Vec<String> = Vec::new();
    // Whether the walk met the archive being written and left it out. The
    // guard below needs this as a fact rather than as an inference.
    let mut excluded_output = false;
    for path in paths {
        let name = entry_name_for(path)?;
        // `metadata`, which follows a symlink, not `symlink_metadata`: a path
        // named on the command line is followed, so `stuffr pack
        // link-to-notes.txt` stores the file it points at. Storing the link
        // itself would let `pack` produce an archive `unpack` then refuses at
        // exit 7 — stuffr must not write what it will not read. `walk` stats
        // its root the same way, for the same reason; this stat exists only
        // so a NAMED socket or fifo is still a usage error rather than an
        // archive with nothing in it. Inside a walk such a thing is an
        // incidental find and is skipped with a warning; named on the command
        // line it is what the user asked for, and there is no entry shape for
        // it.
        let md = std::fs::metadata(path)?;
        if !md.is_dir() && !md.is_file() {
            return Err(Error::Usage(format!(
                "`{}` is neither a file nor a directory; there is no entry shape \
                 for it yet",
                path.display()
            )));
        }
        for item in crate::walk::walk(path, &name)? {
            // The walk found the archive `pack` is about to write. Storing
            // it would nest a growing copy of the previous run inside the
            // new one every time `--force` re-runs the same command — safe
            // (the whole plan, this item included, is built before the
            // destination is even opened), but a monotonically growing
            // archive is still a bug, and the flagship example in
            // `examples.txt` is exactly this shape (`stuffr pack . -o
            // backup.tar`).
            //
            // A NOTE, not a fidelity warning, and not part of the plan.
            // Phase 2c recast it as a `Skipped` item so it would be named the
            // way everything else the walk cannot store is named — and that
            // put it on the `--strict-fidelity` gate, where
            // `pack proj -o proj/backup.tar --force --strict-fidelity` exited
            // 0 on the first run and **4 on every run after**, forever, on an
            // archive that had lost nothing the user wanted. A fidelity
            // warning means "you lost something you asked for"; this is
            // stuffr correctly declining to put a file inside itself, which
            // is not a loss at all. The user is still told, on stderr, every
            // run — see `Outcome::notes`.
            if let crate::walk::ItemSource::File(p) = &item.source
                && is_output_file(p, dst_canonical.as_deref())
            {
                // Tracked separately from `notes` rather than inferred from
                // it: `notes` is a channel for anything worth telling the
                // user, and the guard below turns this particular exclusion
                // into a REFUSAL. Reading a refusal out of "is the note list
                // non-empty" would make the next note anybody adds here
                // silently change when a pack is refused.
                excluded_output = true;
                notes.push(format!(
                    "`{}` is the archive being written and is not stored inside itself",
                    item.meta.name
                ));
                continue;
            }
            // A skipped item claims no name, deliberately. It is never
            // written, and `meta.name` for one may carry U+FFFD where the
            // real name was undecodable — two different names can render
            // identically, so letting them into this set would refuse a pack
            // over a collision that does not exist in the archive.
            if matches!(item.source, crate::walk::ItemSource::Skipped { .. }) {
                plan.push(item);
                continue;
            }
            if !names.insert(item.meta.name.clone()) {
                return Err(Error::Usage(format!(
                    "two inputs would both be stored as entry `{}`; an archive with \
                     duplicate names cannot be extracted without --force",
                    item.meta.name
                )));
            }
            plan.push(item);
        }
    }

    // Nothing at all would be written, so refuse — and refuse HERE, one line
    // before `dst.create`, which is the entire benefit. The plan is complete,
    // no temp file has been opened, no rename can happen, and an archive
    // already sitting at `dst` survives byte for byte.
    //
    // The shape that made this urgent: `stuffr pack /backups -o
    // /backups/nightly.tar --force --strict-fidelity` in a nightly job, over
    // a directory whose only member is last night's archive. Excluding the
    // output from its own walk is correct, and recasting that exclusion as a
    // note rather than a fidelity warning is correct, but together they let a
    // healthy 2 KiB archive be replaced by an empty 1 KiB one at exit 0 —
    // with `--strict-fidelity`, the strongest gate this tool has, reporting
    // it clean. A warning could not fix that: by the time one could be
    // raised, the empty archive has already replaced the good one, and that
    // replacement IS the harm.
    //
    // An empty DIRECTORY is deliberately NOT this case. `pack empty-dir -o
    // x.tar` still carries the directory's own entry in the plan and still
    // succeeds. The plan is barren only when every walked item is either the
    // output itself or something the walk could not store — which is also why
    // the test asserts the empty-directory case explicitly: making this guard
    // fire on legitimate input would be the eleventh instance of this
    // project's signature defect.
    //
    // **The directory entry is not enough, when the output was excluded.**
    // Counting any storable item left the motivating shape unprotected, and
    // it is the one that matters: `pack /backups -o /backups/nightly.tar
    // --force --strict-fidelity` over a directory whose only member is last
    // night's archive produces a plan holding exactly one item — `/backups`
    // itself — so the plan is not empty, the guard did not fire, and a
    // healthy archive was replaced by a 1536-byte shell containing one
    // directory entry, at exit 0, with `--strict-fidelity` calling it clean.
    // Measured on `70ca649`, not reasoned about.
    //
    // What separates that from `pack empty-dir -o x.tar`, which must keep
    // succeeding, is not the plan's contents — both plans hold one directory
    // entry and nothing else — but whether anything was TAKEN OUT of it. An
    // empty directory excluded nothing; the nightly job excluded the very
    // archive it is about to overwrite. So the predicate is a conjunction:
    // nothing with contents survived AND the output was one of the things
    // that did not.
    //
    // "With contents" rather than "a regular file": a symlink is real
    // content, its target is stored, and an archive of symlinks is a
    // legitimate thing to want. Only a directory entry is pure structure —
    // an archive holding nothing else is a shell whatever it declares.
    let nothing_with_contents = !plan.iter().any(|i| {
        matches!(
            i.source,
            crate::walk::ItemSource::File(_) | crate::walk::ItemSource::Symlink
        )
    });
    let nothing_storable = !plan
        .iter()
        .any(|i| !matches!(i.source, crate::walk::ItemSource::Skipped { .. }));
    if nothing_storable || (nothing_with_contents && excluded_output) {
        // Two ways to arrive, wanting different advice, so the message names
        // which one happened rather than reporting a bare "nothing to pack".
        //
        // Only the FIRST is reachable today, and the other two are honest
        // defence rather than tested behaviour — said plainly here because an
        // untestable branch that looks tested is worse than no branch. Two
        // gates above make them unreachable: a path named on the command line
        // is refused unless `metadata` says file or directory, and `walk`
        // always emits its root as the first item, which `item_for` types as
        // `File` or `Dir` from that same stat. So every named path contributes
        // at least one storable item unless it IS the output. An all-`Skipped`
        // plan would need a walk that can skip its own root; if one is ever
        // written, the message below is already right. The first attempt at a
        // test for it passed with the guard removed entirely — it was
        // measuring the named-fifo refusal that
        // `a_named_socket_is_still_a_usage_error_rather_than_an_empty_archive`
        // already owns — and was deleted rather than kept as decoration.
        let cause = if excluded_output && !nothing_storable {
            // The tightened case: directory entries survived, but the only
            // thing with contents was the archive itself. Says what would have
            // been written, because "nothing to pack" alone would read as
            // wrong to someone looking at a directory that visibly exists.
            "the only file found is the archive being written, which is not \
             stored inside itself; what is left would be an archive of empty \
             directories, replacing one that is not"
                .to_string()
        } else if excluded_output {
            // Deliberately does NOT repeat the destination here: the sentence
            // that follows already names it, and a long absolute path printed
            // twice in one line is harder to read, not more informative.
            "every path named is the archive being written, which is not stored \
             inside itself"
                .to_string()
        } else if plan.is_empty() {
            "no input paths were given".to_string()
        } else {
            let listed = plan
                .iter()
                .filter_map(|i| match &i.source {
                    crate::walk::ItemSource::Skipped { reason } => {
                        Some(format!("`{}`: {reason}", i.meta.name))
                    }
                    _ => None,
                })
                .take(3)
                .collect::<Vec<_>>()
                .join("; ");
            format!("every path named was skipped ({listed})")
        };
        return Err(Error::Usage(format!(
            "nothing to pack: {cause}. No archive was written, so `{}` is \
             unchanged",
            output_name(&dst)
        )));
    }

    let opened = dst.create(o.force, o.sync)?;
    let finish = opened.finish;
    // `CountingWriter` is innermost, closest to the file, so `bytes_out`
    // counts the bytes that actually land on disk — compressed, when there is
    // a codec.
    let (counted, bytes_out) = CountingWriter::new(opened.writer);

    // The sink chain, innermost first. With a codec the codec's own `Sink` IS
    // the container's destination — never wrapped in `PlainSink`, which would
    // compile (a `Box<dyn Sink>` is `Write + Send`) and then flush instead of
    // finishing, dropping the codec's trailer: the very bug this composes to
    // fix. `PlainSink` is for the bare-container case only.
    let sink: Box<dyn Sink> = match encoder {
        Some((c, encode)) => c.encoder(Box::new(counted), &encode)?,
        None => PlainSink::new(Box::new(counted)),
    };

    let archive = kind.create(
        sink,
        &CreateOpts {
            level: o.level,
            ..Default::default()
        },
    )?;

    // Read once, outside the closure: what this container can and cannot
    // represent decides whether a directory or symlink is written or warned
    // about, and asking per entry would ask the same question thousands of
    // times over a real tree.
    let caps = kind.caps();

    // An immediately-invoked `FnOnce`, not the `let run = || …` shape the
    // codec path uses: `ArchiveWrite::finish` consumes the writer, which a
    // reusable closure cannot do.
    let result = (move || -> Result<(u64, Vec<Fidelity>)> {
        let mut archive = archive;
        let mut bytes_in = 0u64;
        let mut warnings = Vec::new();
        for item in &plan {
            match &item.source {
                // A file the walk named and this process cannot OPEN is a
                // warning, never a failure — the same ruling `walk.rs`'s
                // `descend` already applies to a directory that cannot be
                // listed, and R9's answer for the analogous case.
                //
                // It used to be a bare `?`, which meant `stuffr pack ~ -o
                // backup.tar` aborted over one unreadable file in a home
                // directory and produced nothing at all. Losing one named
                // file is strictly better than losing the whole backup, and
                // this is not silent: the entry is named in the fidelity
                // report and `--strict-fidelity` refuses on it, exactly as it
                // does for every other thing the walk met and could not
                // store. The asymmetry — unreadable DIRECTORY skipped,
                // unreadable FILE fatal — was introduced by Phase 2c's walk
                // and was never ruled on.
                //
                // Only `open` is forgiven. An error part-way THROUGH the
                // payload still propagates: by then the container has a
                // half-written entry whose header declares a length the
                // stream will not deliver, and there is no honest way to
                // finish that archive.
                crate::walk::ItemSource::File(p) => match std::fs::File::open(p) {
                    Ok(file) => {
                        // Never the bare `File`. The entry header carrying
                        // this file's length was written from the walk's
                        // `stat`, and a live filesystem may have changed the
                        // file in between — so the payload is framed to the
                        // length already promised rather than to whatever the
                        // file now holds. See `ExactLength`, and
                        // `Fidelity::EntrySizeChanged` for why this is a
                        // warning and not a refusal.
                        match item.meta.size {
                            Some(declared) => {
                                let mut sized = ExactLength::new(file, declared);
                                archive.add(&item.meta, &mut sized)?;
                                bytes_in += sized.real;
                                if let Some(w) = sized.warning(&item.meta.name) {
                                    warnings.push(w);
                                }
                            }
                            // No length was recorded, so nothing was promised
                            // and there is nothing to hold the payload to:
                            // the container measures it itself, and
                            // `bytes_in` gains nothing because nothing here
                            // knows what it read. The walk always records a
                            // length for a regular file, so this is reachable
                            // only through a caller that built a plan by hand
                            // — and it is what the code did for every entry
                            // before this.
                            None => {
                                let mut file = file;
                                archive.add(&item.meta, &mut file)?;
                            }
                        }
                    }
                    Err(e) => warnings.push(Fidelity::EntrySkipped {
                        entry: item.meta.name.clone(),
                        reason: format!("could not be opened ({e}); it is not stored"),
                    }),
                },
                // No payload: a directory has none, and a symlink's target
                // lives in the container's own header (or, for cpio and zip,
                // is written by the container from `EntryKind::Symlink`). The
                // reader handed over is not consumed either way — the
                // convention `tar.rs`, `cpio.rs` and `zip.rs` all document.
                //
                // A container with no shape for the kind is NOT asked to
                // write one. `ar` would land a directory as a zero-byte
                // regular file under the directory's name, after which every
                // entry beneath it is unextractable — its parent is a file.
                // Warning and moving on keeps the archive's contents correct
                // and says what was dropped, which is the whole point of a
                // fidelity report; refusing would be the tenth instance of
                // this project's signature defect.
                crate::walk::ItemSource::Dir => {
                    if caps.stores_dirs {
                        archive.add(&item.meta, &mut std::io::empty())?;
                    } else {
                        warnings.push(Fidelity::EntrySkipped {
                            entry: item.meta.name.clone(),
                            reason: format!(
                                "`{container}` has no directory entries, so the directory \
                                 itself is not stored; everything inside it still is, and \
                                 extraction recreates the parents it needs"
                            ),
                        });
                    }
                }
                crate::walk::ItemSource::Symlink => {
                    if caps.stores_symlinks {
                        archive.add(&item.meta, &mut std::io::empty())?;
                    } else {
                        warnings.push(Fidelity::EntrySkipped {
                            entry: item.meta.name.clone(),
                            reason: format!(
                                "`{container}` has no symlink entries; storing it as a \
                                 regular file would materialise the link's target text as \
                                 that file's contents"
                            ),
                        });
                    }
                }
                // NEVER written. `meta.name` here deliberately carries lossy
                // U+FFFD text where the real name could not be decoded, and
                // writing it would reintroduce exactly the silent-substitution
                // defect the walk exists to avoid.
                crate::walk::ItemSource::Skipped { reason } => {
                    warnings.push(Fidelity::EntrySkipped {
                        entry: item.meta.name.clone(),
                        reason: reason.clone(),
                    });
                }
            }
            if let Some(w) = ownership_warning(&item.source, &item.meta) {
                warnings.push(w);
            }
        }

        // One summary line, not one per entry: see `hardlink_count`'s doc for
        // what it does and does not count.
        let linked = crate::walk::hardlink_count(&plan);
        if linked > 0 {
            warnings.push(Fidelity::EntrySkipped {
                entry: format!("{linked} entries"),
                reason: "hardlinked to each other; stored as independent copies, so \
                         extraction will not share their inodes"
                    .into(),
            });
        }

        // Container trailer first, then the layer beneath it. `finish` hands
        // the sink back precisely so this second call is possible; dropping
        // it is what truncated every composed archive before Phase 2c, and is
        // why `Sink` is `#[must_use]`.
        let sink = archive.finish()?;
        sink.finish()?;
        Ok((bytes_in, warnings))
    })();

    match result {
        Ok((bytes_in, warnings)) => {
            // Only now: every byte, trailer included, is written and flushed.
            publish(finish)?;
            Ok(Outcome {
                bytes_in,
                bytes_out: bytes_out.load(Ordering::Relaxed),
                format: container,
                fidelity: FidelityReport {
                    // `Rung` describes the adaptive READ ladder, which has no
                    // write-side counterpart: every input here is a real,
                    // seekable file (`entry_name_for` refuses a pipe, which
                    // has no name to store). The warnings are where a write's
                    // losses are recorded, and `is_lossless` already accounts
                    // for both halves.
                    rung: Rung::Exact,
                    warnings,
                },
                notes,
            })
        }
        Err(e) => {
            discard(finish);
            Err(e)
        }
    }
}

/// Delivers **exactly** the number of bytes an entry's header already
/// declared, whatever the file underneath now holds.
///
/// A container writes the entry header — the declared length included — before
/// it reads a byte of the payload, and the length it writes comes from the
/// walk's `stat`, which happened earlier still: on a large tree, the whole
/// write is that window. A file a live system truncates or appends to inside
/// it therefore arrives at the container with the wrong number of bytes, and
/// the container has no way to go back and rewrite a header it has already
/// streamed out. Before this existed, `tar.rs` refused
/// (`entry ... declared a size of N bytes but supplied M`), which aborted the
/// entire pack and left **no archive at all** — losing a whole backup over one
/// file that something happened to touch.
///
/// So the promise is kept instead of broken:
///
/// * the file **shrank** — the shortfall is padded with zeros, so the entry is
///   the length its header claims and every entry after it stays correctly
///   framed;
/// * the file **grew** — the excess is not read, and the payload stops at the
///   declared length.
///
/// Either way a [`Fidelity::EntrySizeChanged`] warning names the entry and both
/// numbers, so `--strict-fidelity` still refuses and a quiet run still says
/// what happened. This is GNU tar's `file changed as we read it` bargain: the
/// archive is structurally valid and complete, and one entry's tail is known
/// to be approximate.
///
/// Deliberately NOT a substitute for `tar.rs`'s own check, which stays as a
/// last line of defence for any other caller that builds a plan by hand.
struct ExactLength<R> {
    inner: R,
    /// Bytes still owed to the container to satisfy the declared length.
    remaining: u64,
    /// Bytes that genuinely came out of the file.
    real: u64,
    /// Bytes invented (zeros) to make up a shortfall.
    padded: u64,
    /// Whether the file still had data left once the declared length was met.
    grew: bool,
}

impl<R: Read> ExactLength<R> {
    fn new(inner: R, declared: u64) -> Self {
        Self {
            inner,
            remaining: declared,
            real: 0,
            padded: 0,
            grew: false,
        }
    }

    /// The warning this entry earned, if it earned one. `None` is the
    /// overwhelmingly common case: a file nothing touched pads nothing and
    /// grows not at all.
    fn warning(&self, entry: &str) -> Option<Fidelity> {
        let declared = self.real + self.padded;
        if self.padded > 0 {
            return Some(Fidelity::EntrySizeChanged {
                entry: entry.to_string(),
                declared,
                fixup: format!(
                    "the file supplied only {}; the missing {} byte(s) were padded with \
                     zeros so the archive stays correctly framed",
                    self.real, self.padded
                ),
            });
        }
        if self.grew {
            return Some(Fidelity::EntrySizeChanged {
                entry: entry.to_string(),
                declared,
                fixup: "the file grew past that length while it was being read, and the \
                        excess is not stored"
                    .into(),
            });
        }
        None
    }
}

impl<R: Read> Read for ExactLength<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            // The declared length is satisfied. One byte is read past it, and
            // discarded, purely so a file that GREW can be reported rather
            // than silently clipped — `Read` gives no other way to ask
            // "is there more?". Once, not per call: `grew` latches.
            if !self.grew {
                let mut probe = [0u8; 1];
                if self.inner.read(&mut probe)? > 0 {
                    self.grew = true;
                }
            }
            return Ok(0);
        }
        let cap = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        let n = self.inner.read(&mut buf[..cap])?;
        if n == 0 {
            // EOF short of what was promised. Hand back zeros rather than
            // ending the payload early: ending it early is precisely the
            // mis-framing the container cannot survive.
            buf[..cap].fill(0);
            self.remaining -= cap as u64;
            self.padded += cap as u64;
            return Ok(cap);
        }
        self.remaining -= n as u64;
        self.real += n as u64;
        Ok(n)
    }
}

/// How to name the destination in a message, before it exists.
///
/// Deliberately the path AS THE USER WROTE IT, not the canonical form
/// [`canonical_output_path`] builds: a message saying `nightly.tar` is
/// unchanged is read against the command that was typed, and an absolute
/// resolved path with every symlink expanded is harder to match against it,
/// not easier.
fn output_name(dst: &Output) -> String {
    match dst {
        Output::Path(p) => p.display().to_string(),
        Output::Stdout => "-".to_string(),
    }
}

/// The archive's own destination, canonicalized, so [`is_output_file`] can
/// tell when a walked file IS the archive `create_archive` is about to write.
///
/// `dst` need not exist yet — this runs before `Output::create` touches the
/// filesystem at all, which is the point of validating every input before the
/// destination is touched — so only the PARENT is canonicalized (resolving
/// `..`, `.` and any symlinks in it) and the file name is joined back on
/// afterwards. That gives the same answer `Path::canonicalize` would once the
/// file exists, without requiring that it already does. Mirrors the
/// parent-vs-"." handling `Output::create` itself uses for the same reason.
///
/// `Output::Stdout`, and a parent that cannot itself be resolved yet (a typo,
/// or a destination under a directory that does not exist), both return
/// `None`: there is nothing to compare walked files against, and
/// `Output::create` reports the real problem moments later with a clearer
/// message than a silent skip-everything here would.
fn canonical_output_path(dst: &Output) -> Option<PathBuf> {
    let Output::Path(p) = dst else {
        return None;
    };
    let parent = match p.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let file_name = p.file_name()?;
    Some(parent.canonicalize().ok()?.join(file_name))
}

/// Whether the walked file at `candidate` IS the archive being written.
///
/// Compares canonical paths, not strings: `stuffr pack . -o backup.tar`
/// walks with paths relative to `.`, while `backup.tar` names the very same
/// file through a different-looking path the moment a symlinked parent or a
/// `..` component is involved — and the reverse (a relative destination,
/// absolute walk paths) is just as easy to construct. `candidate` was
/// stat'ed by the walk moments before this runs, so `canonicalize` should
/// succeed; if it somehow does not (a race with something removing the
/// file), this reports "not the output" rather than propagating that as an
/// error here — the file is about to be opened for real a few lines later,
/// where a genuine problem surfaces on its own with a clearer message.
///
/// That fallback is a check-then-use window, and it is accepted on the
/// precedent [`refuse_symlinked_ancestors`] set and documented at length —
/// the tree's other filesystem check whose answer can go stale between the
/// look and the write. What it risks here is much smaller than there: the
/// worst case is the archive packing itself as an entry, not a write escaping
/// its destination.
fn is_output_file(candidate: &Path, dst_canonical: Option<&Path>) -> bool {
    let Some(dst) = dst_canonical else {
        return false;
    };
    candidate.canonicalize().is_ok_and(|c| c == dst)
}

/// Says so when an entry is about to be written with no ownership.
///
/// `MetaFields::uid_gid` is the field for exactly this and, until now, was set
/// nowhere in the workspace — the ladder could describe an ownership loss and
/// nothing ever did. It matters because `None` here does not reach the archive
/// as "unknown": `tar.rs`, `ar.rs` and `cpio.rs` all write
/// `meta.uid.unwrap_or(0)`, so an entry with no ids asserts `root:root`, and
/// an archive that asserts the wrong owner while reporting exact fidelity is
/// lying twice.
///
/// On unix the walk always learns both, so this fires for nothing; it is the
/// non-unix build (and any future entry source with no ids) that needs it.
/// Skipped items are excluded — an entry that was not written cannot have lost
/// its ownership.
fn ownership_warning(source: &crate::walk::ItemSource, meta: &EntryMeta) -> Option<Fidelity> {
    if matches!(source, crate::walk::ItemSource::Skipped { .. })
        || (meta.uid.is_some() && meta.gid.is_some())
    {
        return None;
    }
    Some(Fidelity::MetadataIncomplete {
        entry: meta.name.clone(),
        fields: MetaFields {
            uid_gid: true,
            ..Default::default()
        },
    })
}

/// The entry name a command-line path is stored under: its final component.
///
/// Not the path as typed. `stuffr pack /etc/hosts -o x.tar` must not write an
/// entry named `/etc/hosts`, because [`extract`] would refuse that archive at
/// exit 7 — stuffr does not write what it will not read.
///
/// # `.` and `..` resolve rather than refuse
///
/// [`Path::file_name`] returns `None` for `.`, for `..`, and for any path
/// whose LAST component is `..` (`proj/..`, `../..`) — those are not names,
/// and it will not invent one. A trailing `.` is a different case and needs
/// no fallback: [`Path::components`] normalises away a non-leading `CurDir`,
/// so `proj/.` and `./proj/.` both yield `Some("proj")` and take the fast
/// path above. (Measured, because the two read alike: `proj/.` gives
/// `Some("proj")`, `proj/..` gives `None`.) Refusing on the `None` cases made
/// `stuffr pack . -o x.tar` exit 2, and
/// that is the single most common archiving idiom there is: `tar cf x.tar .`
/// is what every tutorial teaches, so it is the likeliest first thing anyone
/// types at the directory walk this phase added. It is also the write-side
/// twin of a bug Phase 2 already spent a fix round on — a bare `.` entry,
/// which `tar cf x.tar .` emits, was refused on extraction at exit 7.
///
/// So a path whose final component is not a name is CANONICALISED, and the
/// name comes from the result: packing `.` from `/home/me/proj` writes
/// `proj/…`, and `..` from `/home/me/proj/src` writes `proj/…`. That is the
/// same final-component rule applied consistently, not a special case — this
/// project chose that rule over storing a directory's contents unprefixed,
/// and `.` is not an exception to it.
///
/// Canonicalisation happens ONLY on that fallback. A path that already has a
/// final component keeps it verbatim, which is what preserves the rule that a
/// symlink NAMED on the command line is stored under the link's own name
/// while its target's contents are packed — resolving unconditionally would
/// silently rename such an entry to its target.
///
/// A trailing slash needs nothing: `Path::file_name` already reads `proj/` as
/// `proj`. The test pins that, because a hand-rolled "split on `/` and take
/// the last" would yield an empty name instead.
///
/// `/` itself still has no name to store, and still refuses — with the
/// resolved path in the message, since the typed one may not show why.
fn entry_name_for(path: &Path) -> Result<String> {
    if let Some(name) = path.file_name() {
        // Two different failures, and they used to share one message. A path
        // whose final component is not valid UTF-8 HAS a final component — it
        // simply cannot be spelled as text, which is what an entry name is —
        // and reporting it as "no final path component" sent the reader
        // looking for a naming bug that was not there. `walk.rs` already
        // names UTF-8 as the cause for the same input found inside a tree;
        // this is the same diagnosis for one named on the command line. The
        // verdict still differs, and deliberately: the walk skips with a
        // warning because an incidental find should not fail a backup, while
        // a path the user typed is a request, and silently packing a U+FFFD
        // substitute for it is the lossy rename neither side will do.
        return match name.to_str() {
            Some(n) => Ok(n.to_string()),
            None => Err(undecodable_entry_name(path, name)),
        };
    }
    // `.`, `..`, `proj/..`, `../..` — see the doc comment. `canonicalize`
    // needs the path to exist, which it must: `create_archive` stats it
    // immediately after this, so a missing path fails either way, and here
    // it fails as the `Io` error it is rather than as a naming complaint.
    let resolved = std::fs::canonicalize(path)?;
    let Some(name) = resolved.file_name() else {
        // The genuine article — `/` and nothing else.
        return Err(Error::Usage(format!(
            "`{}` resolves to `{}`, which has no final path component to name \
             an entry after",
            path.display(),
            resolved.display()
        )));
    };
    match name.to_str() {
        Some(n) => Ok(n.to_string()),
        None => Err(undecodable_entry_name(&resolved, name)),
    }
}

/// The refusal for a path whose final component cannot be spelled as text.
///
/// Shared by both arms of [`entry_name_for`] so the typed path and the
/// resolved one give the same diagnosis; `{name:?}` renders the raw `OsStr`
/// with its undecodable bytes escaped, which is the only faithful rendering
/// there is.
fn undecodable_entry_name(path: &Path, name: &std::ffi::OsStr) -> Error {
    Error::Usage(format!(
        "`{}` has a final path component whose name is not valid UTF-8 ({name:?}); an \
         entry name is text, and storing it under a lossy substitute would rename it",
        path.display()
    ))
}

/// The unix permission bits, where the platform has them.
///
/// Masked to `0o7777`: `Metadata::mode` carries the file-type bits too
/// (`S_IFREG`, `0o100000`), and a tar header's mode field holds permissions
/// alone — the type lives in its typeflag. Storing the raw value would write
/// a mode no other tar tool would recognise, and would make extraction report
/// a mode loss (see `RESTORED_MODE_BITS`) for every file stuffr packed
/// itself.
pub(crate) fn mode_of(md: &std::fs::Metadata) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(md.mode() & 0o7777)
    }
    #[cfg(not(unix))]
    {
        let _ = md;
        None
    }
}

/// Whether `name` is selected by any of `patterns`.
///
/// An exact name, or a directory prefix: `docs` selects `docs/a.txt` as well
/// as `docs/` itself. Deliberately not globbing — a shell already expands
/// `*`, and a pattern language nobody asked for is a pattern language to get
/// subtly wrong. A leading `./` and a trailing `/` are noise on either side:
/// tar names its directory entries `sub/`, and `tar cf x.tar .` prefixes
/// every name with `./`.
fn matches_any(name: &str, patterns: &[String]) -> bool {
    let name = normalize_for_match(name);
    patterns.iter().any(|pattern| {
        let pattern = normalize_for_match(pattern);
        !pattern.is_empty()
            && (name == pattern
                || name
                    .strip_prefix(pattern)
                    .is_some_and(|rest| rest.starts_with('/')))
    })
}

/// Strips the `./` prefix and trailing `/` that carry no meaning in a name.
fn normalize_for_match(s: &str) -> &str {
    let mut s = s;
    while let Some(rest) = s.strip_prefix("./") {
        s = rest;
    }
    s.trim_end_matches('/')
}

/// Refuses an entry whose path is written *through* an existing symlink.
///
/// [`safe_join`] and [`check_symlink_target`] are both lexical, which is what
/// makes them filesystem-free, exhaustively testable and immune to a symlink
/// appearing between the check and the write — an immunity this function,
/// which does touch the filesystem, does NOT inherit; see the TOCTOU section
/// below. The price of being lexical is that neither can see a symlink
/// standing in the middle of an entry's own path, and the two together do
/// not close this:
///
/// ```text
/// a/b/           an ordinary directory
/// a/b/up -> ..   contained: resolves to <dest>/a
/// a/b/up/link -> ../..
///                contained component-wise from <dest> (it nets to `a`), but
///                the OS resolves it through `up`, whose real parent is
///                <dest>/a — so the link lands on <dest>/.., outside
/// a/b/up/link/pwned.txt
///                an ordinary contained name, written straight through it
/// ```
///
/// Refusing any entry with a symlinked path component closes the whole
/// class, in the same shape as libarchive's `SECURE_SYMLINKS`: refused
/// rather than quietly unlinked, per the README's contract. It also covers
/// the case neither lexical check can reach at all — a hostile symlink
/// planted inside `dest` by somebody else *before* extraction started.
///
/// # The TOCTOU window this leaves open
///
/// This is the only containment check in the tree that consults the
/// filesystem, and it is check-then-use: it `symlink_metadata`s the
/// ancestors and then the caller writes through `File::create`
/// (`O_WRONLY|O_CREAT|O_TRUNC` — no `O_NOFOLLOW`, no `create_new`),
/// `create_dir_all` and `symlink`, every one of which follows a symlink it
/// meets. A component that becomes a symlink *between* this check and that
/// write is followed.
///
/// Against a hostile **archive**, the window is closed: the extraction loop
/// is single-threaded and sequential, so nothing runs between the check and
/// the write, and every symlink the archive itself creates has already been
/// through [`check_symlink_target`].
///
/// Against a hostile archive **plus a concurrent local process with write
/// access into `dest`**, it is open, and this function does not claim
/// otherwise. Closing it means never resolving a path by name at all —
/// walking `dest` with `openat(O_NOFOLLOW)` per component and writing
/// through the resulting descriptors — which needs a `rustix` or `libc`
/// dependency this crate does not have and a design cycle of its own.
/// Deferred deliberately, and stated rather than glossed: the lexical
/// checks above really are immune to a symlink appearing between check and
/// write, this one is not, and a reader must not carry the first claim over
/// onto the second.
///
/// The entry's OWN final component is exempt: a symlink entry is supposed to
/// become a symlink, and something already sitting at that exact path is
/// [`replace_conflicting`]'s business, not this function's.
fn refuse_symlinked_ancestors(dest: &Path, target: &Path, name: &str) -> Result<()> {
    let Ok(relative) = target.strip_prefix(dest) else {
        // Unreachable: the caller has just asserted `target.starts_with(dest)`.
        return Err(Error::UnsafePath {
            path: name.to_string(),
            reason: "resolved outside the destination",
        });
    };
    let mut ancestors: Vec<_> = relative.components().collect();
    ancestors.pop();

    let mut walked = dest.to_path_buf();
    for component in ancestors {
        walked.push(component);
        if let Ok(md) = std::fs::symlink_metadata(&walked)
            && md.file_type().is_symlink()
        {
            return Err(Error::UnsafePath {
                path: name.to_string(),
                reason: "a directory in this entry's path is a symlink",
            });
        }
    }
    Ok(())
}

/// Refuses — or, with `force`, removes — something already sitting at an
/// entry's target path. Runs only AFTER containment, on a path [`safe_join`]
/// produced.
///
/// Two jobs. The obvious one is applying `pack`/`unpack`'s existing "an
/// existing output is refused unless --force" contract per entry. The second
/// matters more: REMOVING what is in the way, rather than writing through
/// it, is what stops a pre-existing symlink at the target path from
/// redirecting the entry's bytes. `File::create` follows a symlink, so
/// somebody who could plant `dest/x -> /etc/passwd` before extraction would
/// otherwise have the payload land there.
fn replace_conflicting(target: &Path, force: bool) -> Result<()> {
    // `symlink_metadata`, not `metadata`: a dangling symlink still counts as
    // something being there, and a symlink must report as a symlink rather
    // than as whatever it points at. The same reasoning `Output::create`
    // gives for the single-output path.
    let Ok(md) = std::fs::symlink_metadata(target) else {
        return Ok(());
    };
    if md.is_dir() {
        // A real directory is written INTO — that is the ordinary shape of an
        // archive carrying a directory and its contents — and is never
        // removed, with or without --force: that would delete files the
        // archive never mentioned.
        return Ok(());
    }
    if !force {
        return Err(Error::Usage(format!(
            "{} already exists; pass --force to overwrite",
            target.display()
        )));
    }
    std::fs::remove_file(target)?;
    Ok(())
}

/// Creates an entry's parent directories.
fn create_parent(target: &Path) -> Result<()> {
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

/// Creates a symlink at `at` pointing to `link_target`.
///
/// Unix-only: `stuffr` builds for macOS and Linux (see `containment.rs`), and
/// a Windows symlink has to declare at creation time whether its target is a
/// file or a directory — which an archive entry does not always say.
fn create_symlink(link_target: &str, at: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(link_target, at)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (link_target, at);
        Err(Error::Unsupported(
            "this build cannot create symlinks; extract on a unix host".into(),
        ))
    }
}

/// Copies while charging the budget incrementally, so a bomb is refused
/// mid-stream rather than after the disk has already filled.
///
/// The two error paths are deliberately not the same. A failed READ is the
/// archive's fault and goes through [`Error::from_decode_io`], so a
/// truncated entry payload reports as `Corrupt` (exit 5) and a refusal from
/// the ratio guard beneath the container as `ResourceLimit` (exit 6). A
/// failed WRITE is the destination's fault and stays `Error::Io`, which is
/// what lets `stuffr cat … | head` map a `BrokenPipe` to a clean exit.
fn copy_charging(
    src: &mut dyn Read,
    dst: &mut dyn Write,
    entry: &str,
    budget: &mut ArchiveBudget,
) -> Result<u64> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = src.read(&mut buf).map_err(Error::from_decode_io)?;
        if n == 0 {
            return Ok(total);
        }
        budget.charge(entry, n as u64)?;
        dst.write_all(&buf[..n])?;
        total += n as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stuffr_core::{DEFAULT_MAX_RATIO, ReaderSource};

    /// A container of `a`/`b`/`c`/`d` that records which of the two routes
    /// [`visit_by_index`] actually took.
    ///
    /// Hand-rolled rather than borrowed from `stuffr_core::testing`, because
    /// that module is behind the `testing` feature and the gate's default
    /// test leg does not enable it — a mock that only exists under
    /// `--all-features` would leave these assertions unrun on one of the two
    /// legs, which is exactly the "never executed once" shape the workspace
    /// already found in its `x-pure` tests.
    /// How a container answers `by_index`. The two refusals are NOT
    /// interchangeable and both are real: `NotSeekable` is "this source
    /// cannot seek" (a piped zip), `Unsupported` is "this format has no index
    /// to seek to" (tar, ar and cpio on a real file, each raising it
    /// deliberately rather than billing a re-scan as random access).
    ///
    /// Both are in this enum because catching only the first shipped a
    /// version in which every `--index` against a tar ON A FILE failed at
    /// exit 3.
    #[derive(Clone, Copy, Debug)]
    enum Index {
        Has,
        RefusesNotSeekable,
        RefusesUnsupported,
    }

    struct Routes {
        names: Vec<&'static str>,
        next: usize,
        report: FidelityReport,
        index: Index,
        by_index_calls: usize,
        next_entry_calls: usize,
    }

    impl Routes {
        fn new(rung: Rung, index: Index) -> Self {
            Self {
                names: vec!["a", "b", "c", "d"],
                next: 0,
                report: FidelityReport::new(rung),
                index,
                by_index_calls: 0,
                next_entry_calls: 0,
            }
        }

        fn entry(name: &str) -> Entry<'static> {
            // The payload is the name repeated, so a test comparing BYTES
            // rather than names cannot be satisfied by the wrong entry.
            let payload = name.repeat(3).into_bytes();
            Entry::new(
                EntryMeta::file(name),
                Box::new(std::io::Cursor::new(payload)),
            )
        }
    }

    impl ArchiveRead for Routes {
        fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
            self.next_entry_calls += 1;
            if self.next >= self.names.len() {
                return Ok(None);
            }
            let name = self.names[self.next];
            self.next += 1;
            Ok(Some(Self::entry(name)))
        }

        fn by_index(&mut self, index: usize) -> Result<Entry<'_>> {
            self.by_index_calls += 1;
            match self.index {
                Index::RefusesNotSeekable => {
                    return Err(Error::NotSeekable {
                        format: FormatId::new("mock"),
                    });
                }
                Index::RefusesUnsupported => {
                    return Err(Error::Unsupported(format!(
                        "mock carries no entry index, so entry {index} can only be reached \
                         by reading forward from the start"
                    )));
                }
                Index::Has => {}
            }
            match self.names.get(index) {
                Some(name) => Ok(Self::entry(name)),
                None => Err(Error::entry_index_out_of_range(index, self.names.len())),
            }
        }

        fn fidelity(&self) -> &FidelityReport {
            &self.report
        }
    }

    /// Collects what a selection delivers, as `(name, payload)` pairs.
    fn deliver(ar: &mut Routes, selection: &Selection) -> Result<Vec<(String, Vec<u8>)>> {
        let mut got = Vec::new();
        visit_selected(ar, selection, |entry| {
            let name = entry.meta().name.clone();
            let mut payload = Vec::new();
            entry.reader().read_to_end(&mut payload)?;
            got.push((name, payload));
            Ok(())
        })?;
        Ok(got)
    }

    /// Every way a container can answer `by_index`. Each of the three must
    /// end up delivering the same entries.
    const EVERY_INDEX_BEHAVIOUR: [Index; 3] = [
        Index::Has,
        Index::RefusesNotSeekable,
        Index::RefusesUnsupported,
    ];

    /// The property the whole two-route design rests on: a container WITH an
    /// index and one WITHOUT must deliver the same entries, in the same
    /// order, with the same bytes, for the same `--index` request — and
    /// "without" covers BOTH refusal spellings.
    ///
    /// Asserted against an absolute expectation as well as against each
    /// other — two routes that were off by one in the same direction would
    /// agree with each other perfectly and still both be wrong.
    #[test]
    fn the_random_access_and_counted_routes_deliver_identical_entries() {
        let want = vec![
            ("b".to_string(), b"bbb".to_vec()),
            ("d".to_string(), b"ddd".to_vec()),
        ];
        let selection = Selection::Indices(vec![1, 3]);

        let mut indexed = Routes::new(Rung::Exact, Index::Has);
        let fast = deliver(&mut indexed, &selection).unwrap();
        assert!(
            indexed.by_index_calls == 2 && indexed.next_entry_calls == 0,
            "a container with an index must be reached through it, not walked: \
             by_index={}, next_entry={}",
            indexed.by_index_calls,
            indexed.next_entry_calls
        );
        assert_eq!(
            fast, want,
            "the random-access route delivered the wrong entries"
        );

        for refusal in [Index::RefusesNotSeekable, Index::RefusesUnsupported] {
            let mut sequential = Routes::new(Rung::Exact, refusal);
            let counted = deliver(&mut sequential, &selection)
                .unwrap_or_else(|e| panic!("{refusal:?} must route to the walk, not fail: {e}"));
            assert!(
                sequential.next_entry_calls > 0,
                "{refusal:?}: a container that refuses by_index must be counted instead"
            );
            assert_eq!(counted, want, "{refusal:?}: the counted route was wrong");
            assert_eq!(fast, counted, "{refusal:?}: the two routes disagreed");
        }
    }

    /// Indices are 0-based, and `Selection::Indices(vec![0])` is the FIRST
    /// entry. Pinned on its own because an off-by-one here would be invisible
    /// to the agreement test above (both routes share the numbering).
    #[test]
    fn index_zero_is_the_first_entry_on_every_route() {
        for behaviour in EVERY_INDEX_BEHAVIOUR {
            let mut ar = Routes::new(Rung::Exact, behaviour);
            let got = deliver(&mut ar, &Selection::Indices(vec![0])).unwrap();
            assert_eq!(
                got,
                vec![("a".to_string(), b"aaa".to_vec())],
                "{behaviour:?}"
            );
        }
    }

    /// Archive order, and once each, whatever order the flags arrived in —
    /// the contract that lets the two routes agree at all.
    #[test]
    fn indices_are_delivered_in_archive_order_and_deduplicated() {
        for behaviour in EVERY_INDEX_BEHAVIOUR {
            let mut ar = Routes::new(Rung::Exact, behaviour);
            let got = deliver(&mut ar, &Selection::Indices(vec![2, 0, 2])).unwrap();
            let names: Vec<&str> = got.iter().map(|(n, _)| n.as_str()).collect();
            assert_eq!(names, ["a", "c"], "{behaviour:?}");
        }
    }

    /// A forward-only read has no index to jump with even if the container
    /// type normally has one — a piped zip is exactly that — so the rung gate
    /// must keep `by_index` unasked.
    #[test]
    fn a_non_authoritative_read_is_never_asked_for_random_access() {
        let mut ar = Routes::new(Rung::ForwardOnly, Index::Has);
        let got = deliver(&mut ar, &Selection::Indices(vec![1])).unwrap();
        assert_eq!(got, vec![("b".to_string(), b"bbb".to_vec())]);
        assert_eq!(
            ar.by_index_calls, 0,
            "the rung said the read is not authoritative; by_index must not be tried"
        );
    }

    /// Out of range is exit 2 and names the archive's real length — the same
    /// message whichever route found it, so a script cannot tell them apart.
    #[test]
    fn an_out_of_range_index_is_the_same_usage_error_on_every_route() {
        let mut messages = Vec::new();
        for behaviour in EVERY_INDEX_BEHAVIOUR {
            let mut ar = Routes::new(Rung::Exact, behaviour);
            let err = deliver(&mut ar, &Selection::Indices(vec![9]))
                .expect_err("index 9 of a 4-entry archive must be refused");
            assert_eq!(err.exit_code(), 2, "{behaviour:?}: {err}");
            let text = err.to_string();
            assert!(
                text.contains("#9") && text.contains("0-3"),
                "the message must name the index asked for and the VALID range: {text}"
            );
            messages.push(text);
        }
        assert!(
            messages.windows(2).all(|w| w[0] == w[1]),
            "the routes reported the same mistake differently: {messages:?}"
        );
    }

    /// The counted route must stop as soon as the last requested index has
    /// been delivered — `cat --index 0` of a thousand-entry archive should
    /// not read nine hundred and ninety-nine more headers.
    #[test]
    fn the_counted_route_stops_once_the_last_requested_index_is_delivered() {
        let mut ar = Routes::new(Rung::Exact, Index::RefusesNotSeekable);
        deliver(&mut ar, &Selection::Indices(vec![0])).unwrap();
        assert_eq!(
            ar.next_entry_calls, 1,
            "reading past the last requested entry buys nothing"
        );
    }

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
    fn a_running_tally_gives_max_ratio_a_denominator_on_a_pipe() {
        // The floor ALONE was the Phase 2 re-review's second finding: it
        // refused any piped archive over 1 MiB, and `--max-ratio` — the flag
        // the refusal names — could not raise it, so `cat photos.zip | stuffr
        // test -` broke on any real archive. With a running tally the ratio
        // has a denominator even though the total is unknown.
        let consumed = Arc::new(AtomicU64::new(0));
        let mut b = ArchiveBudget::new(None, DEFAULT_MAX_RATIO).tracking(Arc::clone(&consumed));

        // 3 MiB pulled from the pipe: far past the floor, and legitimate.
        consumed.store(3 * 1024 * 1024, Ordering::Relaxed);
        b.charge("big.bin", 3 * 1024 * 1024)
            .expect("a 1:1 archive must not be refused merely for exceeding the floor");

        // The bound is still real: at the same tally, the ratio still bites.
        let mut b = ArchiveBudget::new(None, DEFAULT_MAX_RATIO).tracking(Arc::clone(&consumed));
        let err = b
            .charge("bomb.bin", 3 * 1024 * 1024 * DEFAULT_MAX_RATIO + 1)
            .expect_err("the ratio must still bound a pipe");
        assert!(matches!(err, Error::ResourceLimit(_)));
    }

    #[test]
    fn the_pipe_ceiling_tracks_the_tally_rather_than_being_fixed_at_open() {
        // The ceiling is read at charge time, not captured when the budget is
        // built — otherwise every piped archive would be judged against a
        // tally of zero, which is the floor again by another route.
        let consumed = Arc::new(AtomicU64::new(0));
        let mut b = ArchiveBudget::new(None, DEFAULT_MAX_RATIO).tracking(Arc::clone(&consumed));
        assert!(
            b.charge("a", RATIO_FLOOR + 1).is_err(),
            "with nothing yet read the floor is the whole budget"
        );

        let mut b = ArchiveBudget::new(None, DEFAULT_MAX_RATIO).tracking(Arc::clone(&consumed));
        consumed.store(1024, Ordering::Relaxed);
        assert!(
            b.charge("a", RATIO_FLOOR + 1).is_ok(),
            "once 1 KiB has been read the ratio allows far more than the floor"
        );
    }

    #[test]
    fn a_pipe_with_no_tally_attached_still_falls_back_to_the_floor() {
        // `tracking` is what a caller attaches; a budget built without one has
        // no denominator at all, and must not become unlimited.
        let mut b = ArchiveBudget::new(None, DEFAULT_MAX_RATIO);
        assert!(b.charge("huge.bin", RATIO_FLOOR + 1).is_err());
    }

    #[test]
    fn a_pattern_matches_an_exact_name_or_a_directory_beneath_it() {
        let patterns = vec!["b.txt".to_string(), "docs".to_string()];
        assert!(matches_any("b.txt", &patterns));
        assert!(matches_any("docs", &patterns));
        // A directory pattern takes everything under it, at any depth.
        assert!(matches_any("docs/a.txt", &patterns));
        assert!(matches_any("docs/deep/a.txt", &patterns));
        // Not a prefix match on the raw string: `docsy` is a different name.
        assert!(!matches_any("docsy/a.txt", &patterns));
        assert!(!matches_any("a.txt", &patterns));
        assert!(!matches_any("b.txt.bak", &patterns));
    }

    #[test]
    fn a_pattern_ignores_the_leading_dot_slash_and_trailing_slash_tar_emits() {
        // `tar cf x.tar .` names every entry `./a.txt`, and names directory
        // entries with a trailing slash. Neither is something a user should
        // have to type.
        assert!(matches_any("./b.txt", &["b.txt".to_string()]));
        assert!(matches_any("b.txt", &["./b.txt".to_string()]));
        assert!(matches_any("docs/", &["docs".to_string()]));
        assert!(matches_any("./docs/a.txt", &["docs/".to_string()]));
    }

    #[test]
    fn an_empty_pattern_selects_nothing_rather_than_everything() {
        // An empty string normalises to nothing, and "" is a prefix of every
        // name: treated as a prefix it would quietly select the whole
        // archive. Callers spell "everything" as an EMPTY LIST of patterns,
        // which `extract` and `cat` check before they get here.
        assert!(!matches_any("a.txt", &[String::new()]));
        assert!(!matches_any("a.txt", &["./".to_string()]));
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
    /// `ownership_warning` in isolation, because on unix nothing can reach
    /// its `Some` branch: `walk::ids_of` returns `(Some, Some)`
    /// unconditionally there, and there is no non-unix CI leg. Closing
    /// carried finding 2 by adding a setter for `MetaFields::uid_gid` that
    /// no supported platform ever executes and no test ever observes would
    /// only have moved the finding, not answered it.
    ///
    /// It is a pure function over borrowed arguments, so four assertions pin
    /// it permanently. The failure they exist to catch: someone later adds a
    /// path that learns a uid but not a gid, changes the `&&` to `||` to
    /// "simplify" it, and nothing notices that an entry with half its
    /// ownership now reports none lost.
    fn meta_with(uid: Option<u32>, gid: Option<u32>) -> EntryMeta {
        EntryMeta {
            name: "proj/notes.txt".into(),
            uid,
            gid,
            ..Default::default()
        }
    }

    #[test]
    fn an_entry_with_no_ownership_reports_the_uid_gid_loss() {
        let w = ownership_warning(&crate::walk::ItemSource::Dir, &meta_with(None, None))
            .expect("an entry written with no ids asserts root:root, which is a loss");
        match w {
            Fidelity::MetadataIncomplete { entry, fields } => {
                assert_eq!(entry, "proj/notes.txt", "the warning must name the entry");
                assert!(
                    fields.uid_gid,
                    "`MetaFields::uid_gid` is the field for this, and must be the one set"
                );
                assert_eq!(
                    fields.missing(),
                    vec!["uid_gid"],
                    "and the ONLY one: nothing else was lost here"
                );
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn an_entry_that_knows_both_ids_reports_nothing() {
        assert!(
            ownership_warning(
                &crate::walk::ItemSource::Dir,
                &meta_with(Some(501), Some(20))
            )
            .is_none(),
            "the unix case: a warning here would fire on every entry of every pack"
        );
    }

    #[test]
    fn half_an_ownership_is_still_a_loss() {
        // The `&&`-versus-`||` question, pinned. A uid with no gid still
        // reaches the container as `gid.unwrap_or(0)` — group root — so it
        // is a loss, and an implementation that only warns when BOTH are
        // absent would miss it.
        assert!(
            ownership_warning(&crate::walk::ItemSource::Dir, &meta_with(Some(501), None)).is_some(),
            "a known uid does not make an unknown gid harmless"
        );
        assert!(
            ownership_warning(&crate::walk::ItemSource::Dir, &meta_with(None, Some(20))).is_some(),
            "nor the other way round"
        );
    }

    #[test]
    fn a_skipped_entry_reports_no_ownership_loss_because_it_was_never_written() {
        assert!(
            ownership_warning(
                &crate::walk::ItemSource::Skipped {
                    reason: "not a regular file".into()
                },
                &meta_with(None, None),
            )
            .is_none(),
            "an entry that was not written cannot have lost its ownership; it \
             already carries its own EntrySkipped warning, and a second one \
             about a field it never had is noise"
        );
    }

    /// The three decisions [`is_output_file`] makes, the third of which is a
    /// TOCTOU fallback no end-to-end test can schedule.
    ///
    /// The race itself — a file the walk stat'ed moments ago disappearing
    /// before this `canonicalize` runs — needs an injection point the function
    /// does not have, and a test that tried to win it by timing would be a
    /// test that passes when it loses. The DECISION it encodes is a pure
    /// function of a path that cannot be canonicalized, and that is testable
    /// directly: report "not the output" rather than propagate, because the
    /// file is opened for real a few lines later, where a genuine problem
    /// surfaces with a clearer message than a naming complaint here.
    ///
    /// The middle case is not decoration: without it, a function returning
    /// `false` unconditionally would satisfy the other two.
    #[test]
    fn a_candidate_that_cannot_be_canonicalized_is_not_the_output() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("backup.tar");
        std::fs::write(&archive, b"pretend archive").unwrap();
        let canonical = archive.canonicalize().unwrap();

        assert!(
            is_output_file(&archive, Some(&canonical)),
            "the archive itself IS the output; without this the test below passes \
             against a function that always says false"
        );

        let vanished = dir.path().join("deleted-between-stat-and-here.txt");
        assert!(
            !vanished.exists(),
            "the premise: this path really cannot be canonicalized"
        );
        assert!(
            !is_output_file(&vanished, Some(&canonical)),
            "a candidate that cannot be resolved is not the output — it is not an \
             error here either"
        );

        assert!(
            !is_output_file(&archive, None),
            "with no destination to compare against (stdout, or a parent that does \
             not resolve) nothing can be the output"
        );
    }

    /// A reader that yields `bytes` and then EOF, in chunks of at most
    /// `chunk` — so the padding path is exercised across several `read`
    /// calls rather than only on a single convenient one.
    struct Chunked {
        bytes: Vec<u8>,
        at: usize,
        chunk: usize,
    }

    impl std::io::Read for Chunked {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.chunk.min(buf.len()).min(self.bytes.len() - self.at);
            buf[..n].copy_from_slice(&self.bytes[self.at..self.at + n]);
            self.at += n;
            Ok(n)
        }
    }

    fn drain(mut r: impl Read) -> Vec<u8> {
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        out
    }

    /// Finding 1. A file the walk stat'd at 16 bytes, truncated to 4 before
    /// its payload was read: the container has already written a header
    /// saying 16, so 16 is what must come out.
    #[test]
    fn a_file_that_shrank_is_padded_to_the_length_its_header_declares() {
        let src = Chunked {
            bytes: b"abcd".to_vec(),
            at: 0,
            chunk: 3,
        };
        let mut sized = ExactLength::new(src, 16);
        let got = drain(&mut sized);

        assert_eq!(
            got.len(),
            16,
            "the payload MUST be the declared length; anything else mis-frames \
             every entry after it"
        );
        assert_eq!(&got[..4], b"abcd", "the real bytes come first, unaltered");
        assert!(
            got[4..].iter().all(|b| *b == 0),
            "the shortfall is zeros, not stale buffer contents: {got:?}"
        );

        let w = sized
            .warning("proj/zzz.bin")
            .expect("a shrink must be reported");
        let text = w.to_string();
        assert!(
            text.contains("proj/zzz.bin") && text.contains("16") && text.contains("4"),
            "the warning must name the entry and BOTH lengths: {text}"
        );
        assert!(
            text.contains("padded with zeros"),
            "and say what was done about it: {text}"
        );
    }

    /// The other direction: a file appended to between the stat and the read.
    /// The excess cannot go into an entry whose length is already committed,
    /// so the payload stops — and says so.
    #[test]
    fn a_file_that_grew_stops_at_the_length_its_header_declares() {
        let src = Chunked {
            bytes: b"abcdefghij".to_vec(),
            at: 0,
            chunk: 4,
        };
        let mut sized = ExactLength::new(src, 6);
        let got = drain(&mut sized);

        assert_eq!(got, b"abcdef", "the payload stops at the declared length");

        let w = sized
            .warning("proj/growing.log")
            .expect("growth must be reported");
        let text = w.to_string();
        assert!(
            text.contains("proj/growing.log") && text.contains('6'),
            "the warning must name the entry and the declared length: {text}"
        );
        assert!(
            text.contains("grew") && text.contains("not stored"),
            "and say the excess was dropped: {text}"
        );
    }

    /// The overwhelmingly common case. A warning here would put every
    /// ordinary pack on the --strict-fidelity gate.
    #[test]
    fn a_file_that_did_not_change_earns_no_warning() {
        let src = Chunked {
            bytes: b"abcdef".to_vec(),
            at: 0,
            chunk: 4,
        };
        let mut sized = ExactLength::new(src, 6);
        assert_eq!(drain(&mut sized), b"abcdef");
        assert!(
            sized.warning("proj/quiet.txt").is_none(),
            "a file nothing touched must be silent"
        );
    }

    /// `grew` latches: the one-byte probe past the declared length must not
    /// consume a byte per call, and repeated reads at EOF must stay `Ok(0)`.
    #[test]
    fn the_growth_probe_runs_once_and_reads_stay_empty() {
        let src = Chunked {
            bytes: b"abcdefgh".to_vec(),
            at: 0,
            chunk: 8,
        };
        let mut sized = ExactLength::new(src, 2);
        assert_eq!(drain(&mut sized), b"ab");
        let mut buf = [0u8; 4];
        for _ in 0..3 {
            assert_eq!(
                sized.read(&mut buf).unwrap(),
                0,
                "past the declared length there is nothing left to hand over"
            );
        }
        assert!(sized.warning("x").is_some());
    }
}

/// Task 5's own required tests, plus the containment falsification the
/// brief names by hand. Gated on `feature = "zip"`: Stage 1 has exactly one
/// salvage scanner, so a build without it has nothing for `salvage` to run
/// against.
#[cfg(all(test, feature = "zip"))]
mod salvage_tests {
    use super::*;
    use stuffr_core::salvage::{SalvagePolicy, SalvageStatus};

    /// CRC-32/ISO-HDLC — the same algorithm `zip_salvage.rs`'s own
    /// `crc32_ieee` computes, reimplemented here rather than reused because
    /// that function is private to a different crate. A fixture builder is
    /// the one place in this test module that legitimately needs it; the
    /// production code above never recomputes a checksum at all (see
    /// `PartialCause`'s own doc for why).
    fn crc32(data: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFF_FFFF;
        for &b in data {
            crc ^= u32::from(b);
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
        !crc
    }

    /// One zip local file header plus its payload — no central directory,
    /// no end-of-central-directory record. The raw scanner
    /// (`ZipSalvage::next_candidate`) needs neither: this is exactly the
    /// "index destroyed or absent" shape salvage exists for, and building
    /// only what the scan actually reads keeps a fixture's shape legible
    /// rather than incidentally exercising the reconciliation path this task
    /// does not touch.
    ///
    /// `payload` is exactly what is written to disk (raw bytes for Stored,
    /// compressed bytes for Deflate); `uncompressed_size` and `declared_crc`
    /// are independent fields, so a caller can build a header whose
    /// `uncompressed_size` disagrees with what `payload` actually decodes to
    /// — the shape a truncated/corrupted Deflate fixture needs.
    fn local_header_entry_with_method(
        name: &str,
        method: u16,
        payload: &[u8],
        uncompressed_size: u32,
        declared_crc: u32,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed to extract
        out.extend_from_slice(&0u16.to_le_bytes()); // flags: no data descriptor
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // mod time
        out.extend_from_slice(&0u16.to_le_bytes()); // mod date
        out.extend_from_slice(&declared_crc.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // compressed size
        out.extend_from_slice(&uncompressed_size.to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// [`local_header_entry_with_method`] specialised to Stored (method 0),
    /// where the payload IS the uncompressed bytes — every test this task
    /// originally shipped uses this shape.
    fn local_header_entry(name: &str, data: &[u8], declared_crc: u32) -> Vec<u8> {
        local_header_entry_with_method(name, 0, data, data.len() as u32, declared_crc)
    }

    /// Compresses `data` through this crate's own `deflate` codec (the
    /// registry, not a direct `flate2` dependency — `stuffr` does not depend
    /// on `flate2` at all, unlike `stuffr-formats`) so a fixture can carry a
    /// REAL Deflate-method entry rather than a hand-rolled approximation.
    #[cfg(feature = "deflate")]
    fn deflate_compress(data: &[u8]) -> Vec<u8> {
        let buf = stuffr_core::testing::SharedBuf::new();
        let codec = crate::registry()
            .require_encoder(FormatId::new("deflate"))
            .expect("this test is gated on `feature = \"deflate\"`");
        let mut sink = codec
            .encoder(Box::new(buf.clone()), &EncodeOpts::default())
            .unwrap();
        sink.write_all(data).unwrap();
        sink.finish().unwrap();
        buf.contents()
    }

    fn write_archive(bytes: &[u8]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("damaged.zip");
        std::fs::write(&archive, bytes).unwrap();
        (dir, archive)
    }

    /// The brief's first required test. A Stored entry whose header
    /// declares the CRC of the ORIGINAL payload, with one payload byte
    /// flipped afterwards — so the scan finds a well-formed candidate
    /// (nothing about the header disagrees with itself) but
    /// `zip_salvage.rs`'s own CRC check disagrees with the corrupted
    /// content, reporting `Partial`.
    #[test]
    fn a_partial_recovery_lands_under_a_partial_name() {
        let original = b"hello, this is the real content".to_vec();
        let crc = crc32(&original);
        let mut corrupted = original.clone();
        corrupted[5] ^= 0xFF;
        let bytes = local_header_entry("report.txt", &corrupted, crc);
        let (_archive_dir, archive) = write_archive(&bytes);

        let out_dir = tempfile::tempdir().unwrap();
        let opts = SalvageOpts {
            dest: Some(out_dir.path().to_path_buf()),
            policy: SalvagePolicy::default(),
            select: None,
            format: None,
        };
        let outcome = salvage(&archive, &opts)
            .expect("a corrupted-but-well-formed entry must not abort the run");

        assert_eq!(outcome.entries.len(), 1);
        let record = &outcome.entries[0];
        assert_eq!(record.status, SalvageStatus::Partial);

        let SalvageDisposition::WrittenPartial { path, cause } = &record.disposition else {
            panic!("expected WrittenPartial, got {:?}", record.disposition);
        };
        assert_eq!(*cause, PartialCause::ChecksumMismatch);
        assert!(
            path.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .ends_with(".partial"),
            "must land under `name.partial`, not `{}`",
            path.display()
        );
        assert!(path.exists(), "the .partial file must actually be on disk");
        assert_eq!(std::fs::read(path).unwrap(), corrupted);

        let real_name_path = out_dir.path().join("report.txt");
        assert!(
            !real_name_path.exists(),
            "a partial recovery must NEVER land under the entry's real name — that is \
             what makes recovering it by default safe rather than reckless"
        );
    }

    /// Fix round 1, REQUIRED 2: `PartialCause::Truncated` had no test — only
    /// `ChecksumMismatch` (above) was pinned. A REAL Deflate stream (built
    /// through this crate's own `deflate` codec, not a hand-rolled
    /// approximation), cut in half AFTER compression, so the redecode runs
    /// out partway through rather than completing and merely disagreeing
    /// with its CRC. The header's declared `uncompressed_size` and CRC are
    /// both the ORIGINAL, uncut payload's — a real writer's values, which is
    /// what makes this "ran out", not "the header lied about its own size".
    #[test]
    #[cfg(feature = "deflate")]
    fn a_truncated_decode_is_marked_truncated_not_checksum_mismatch() {
        let plaintext = b"this payload needs to be long enough that cutting the compressed \
             stream in half leaves flate2 well short of the declared uncompressed length, \
             rather than coincidentally still landing on a valid end-of-stream marker"
            .to_vec();
        let crc = crc32(&plaintext);
        let compressed = deflate_compress(&plaintext);
        assert!(
            compressed.len() > 8,
            "the payload must actually compress to something with a middle to cut"
        );
        let cut = compressed.len() / 2;
        let truncated_compressed = &compressed[..cut];

        let bytes = local_header_entry_with_method(
            "big.bin",
            8, // Deflate
            truncated_compressed,
            plaintext.len() as u32,
            crc,
        );
        let (_archive_dir, archive) = write_archive(&bytes);

        let out_dir = tempfile::tempdir().unwrap();
        let opts = SalvageOpts {
            dest: Some(out_dir.path().to_path_buf()),
            policy: SalvagePolicy::default(),
            select: None,
            format: None,
        };
        let outcome = salvage(&archive, &opts)
            .expect("a truncated-but-well-formed entry must not abort the run");

        assert_eq!(outcome.entries.len(), 1);
        assert_eq!(outcome.entries[0].status, SalvageStatus::Partial);
        let SalvageDisposition::WrittenPartial { cause, .. } = &outcome.entries[0].disposition
        else {
            panic!(
                "expected WrittenPartial, got {:?}",
                outcome.entries[0].disposition
            );
        };
        assert_eq!(
            *cause,
            PartialCause::Truncated,
            "a decode that never reached the declared length must be Truncated, not \
             ChecksumMismatch — the branch this test exists to pin"
        );
    }

    /// The brief's second required test. A well-formed (CRC-correct) Stored
    /// entry whose NAME tries to escape `dest` via `..` traversal.
    #[test]
    fn a_recovered_name_that_escapes_the_destination_is_refused() {
        let data = b"pwned".to_vec();
        let crc = crc32(&data);
        let bytes = local_header_entry("../escaped.txt", &data, crc);
        let (_archive_dir, archive) = write_archive(&bytes);

        let out_dir = tempfile::tempdir().unwrap();
        let opts = SalvageOpts {
            dest: Some(out_dir.path().join("dest")),
            policy: SalvagePolicy::default(),
            select: None,
            format: None,
        };
        let err = salvage(&archive, &opts).expect_err("an escaping name must refuse the whole run");
        assert_eq!(err.exit_code(), 7);

        // Nothing escaped: neither the (never-created) destination nor its
        // parent gained the file the hostile name asked for.
        assert!(!out_dir.path().join("escaped.txt").exists());
        assert!(!out_dir.path().join("dest").join("escaped.txt").exists());
    }

    /// The brief's third required test. The same corrupted-CRC fixture as
    /// the first test, but under `--strict`: a `Partial` entry must be
    /// skipped even though the default policy (`partial: Keep`) would have
    /// written it.
    #[test]
    fn strict_mode_skips_what_it_cannot_prove() {
        let original = b"hello, this is the real content".to_vec();
        let crc = crc32(&original);
        let mut corrupted = original.clone();
        corrupted[5] ^= 0xFF;
        let bytes = local_header_entry("report.txt", &corrupted, crc);
        let (_archive_dir, archive) = write_archive(&bytes);

        let out_dir = tempfile::tempdir().unwrap();
        let opts = SalvageOpts {
            dest: Some(out_dir.path().to_path_buf()),
            policy: SalvagePolicy {
                strict: true,
                ..SalvagePolicy::default()
            },
            select: None,
            format: None,
        };
        let outcome = salvage(&archive, &opts).unwrap();

        assert_eq!(outcome.entries.len(), 1);
        assert_eq!(outcome.entries[0].status, SalvageStatus::Partial);
        assert_eq!(
            outcome.entries[0].disposition,
            // The corrupted payload decodes to its full declared length (a
            // Stored copy cannot run short here), so the cause is a
            // checksum disagreement, not a truncation.
            SalvageDisposition::SkippedPartial(PartialCause::ChecksumMismatch)
        );
        assert!(
            std::fs::read_dir(out_dir.path()).unwrap().next().is_none(),
            "strict mode must write nothing at all for an unprovable entry"
        );
    }

    /// A clean, uncorrupted entry is written under its own name, at the top
    /// tier the engine reports (`Complete`, since Stored has no checksum
    /// concept beyond CRC agreement — see `zip_salvage.rs`'s own doc for why
    /// a Stored/agreeing entry reports `Intact`, not `Complete`; pinned here
    /// so a regression in the write path cannot hide behind only ever
    /// testing the damaged cases above).
    #[test]
    fn an_intact_entry_is_written_under_its_own_name() {
        let data = b"nothing wrong with this one".to_vec();
        let crc = crc32(&data);
        let bytes = local_header_entry("fine.txt", &data, crc);
        let (_archive_dir, archive) = write_archive(&bytes);

        let out_dir = tempfile::tempdir().unwrap();
        let opts = SalvageOpts {
            dest: Some(out_dir.path().to_path_buf()),
            policy: SalvagePolicy::default(),
            select: None,
            format: None,
        };
        let outcome = salvage(&archive, &opts).unwrap();

        assert_eq!(outcome.entries.len(), 1);
        assert_eq!(outcome.entries[0].status, SalvageStatus::Intact);
        let SalvageDisposition::Written(path) = &outcome.entries[0].disposition else {
            panic!("expected Written, got {:?}", outcome.entries[0].disposition);
        };
        assert_eq!(path, &out_dir.path().join("fine.txt"));
        assert_eq!(std::fs::read(path).unwrap(), data);
    }

    /// Fix round 1, REQUIRED 1. Before this round, `SalvageOpts` had no
    /// `select` at all: the CLI approximated `--index` by writing every
    /// eligible entry and then filtering the REPORT, so `salvage archive.zip
    /// -C out --index 0` left `excluded.txt` sitting in `out/` right next to
    /// `kept.txt` — measured directly against a shipped build, `out/` held
    /// BOTH files after selecting only scan position 0. `select` must gate
    /// the WRITE itself: only the selected scan position may ever reach
    /// disk, and every other one reports `NotSelected` rather than being
    /// silently written anyway.
    #[test]
    fn select_gates_what_is_written_not_just_what_is_reported() {
        let kept = b"this one was selected".to_vec();
        let excluded = b"this one was not selected and must never reach disk".to_vec();
        let mut bytes = local_header_entry("kept.txt", &kept, crc32(&kept));
        bytes.extend(local_header_entry(
            "excluded.txt",
            &excluded,
            crc32(&excluded),
        ));
        let (_archive_dir, archive) = write_archive(&bytes);

        let out_dir = tempfile::tempdir().unwrap();
        let opts = SalvageOpts {
            dest: Some(out_dir.path().to_path_buf()),
            policy: SalvagePolicy::default(),
            select: Some(HashSet::from([0])),
            format: None,
        };
        let outcome = salvage(&archive, &opts).unwrap();

        assert_eq!(outcome.entries.len(), 2);
        assert_eq!(outcome.entries[0].scan_position, 0);
        assert!(matches!(
            outcome.entries[0].disposition,
            SalvageDisposition::Written(_)
        ));
        assert_eq!(outcome.entries[1].scan_position, 1);
        assert_eq!(
            outcome.entries[1].disposition,
            SalvageDisposition::NotSelected,
            "scan position 1 was not in `select` and must be reported as such"
        );

        // The measurement that exposed the bug: the directory listing, not
        // merely a count.
        let names: Vec<String> = std::fs::read_dir(out_dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec!["kept.txt".to_string()],
            "`out/` must hold ONLY the selected entry; found {names:?}"
        );
    }

    /// The two suffixes compose in one order only: the disambiguating one
    /// goes on first and `.partial` goes on LAST, so the marker every
    /// downstream tool is being warned by stays the final extension. Also
    /// pins that neither replaces an existing extension — `report.txt`
    /// becomes `report.txt.salvaged-6`, never `report.salvaged-6`.
    #[cfg(feature = "zip")]
    #[test]
    fn a_disambiguated_partial_keeps_dot_partial_last() {
        let target = PathBuf::from("/out/report.txt");
        let renamed = disambiguated_path(&target, 6);
        assert_eq!(renamed, PathBuf::from("/out/report.txt.salvaged-6"));
        assert_eq!(
            partial_path(&renamed),
            PathBuf::from("/out/report.txt.salvaged-6.partial")
        );
        // A record that needed neither is untouched by either.
        assert_eq!(
            partial_path(&target),
            PathBuf::from("/out/report.txt.partial")
        );
    }

    /// Fix round 1, REQUIRED 3 (Ruling R-N): the aggregation rule, pinned
    /// against constructed `SalvageOutcome`s rather than full end-to-end
    /// archives — the rule is pure arithmetic over dispositions, and a
    /// fixture-based test would only be testing the fixture as much as the
    /// rule.
    #[test]
    fn exit_code_precedence_follows_ruling_r_n() {
        let record = |disposition: SalvageDisposition| SalvagedRecord {
            scan_position: 0,
            name: "x".into(),
            status: SalvageStatus::Intact,
            shadows: None,
            collides_with: None,
            disposition,
        };

        assert_eq!(
            salvage_exit_code(&SalvageOutcome { entries: vec![] }),
            5,
            "nothing recoverable at all"
        );

        assert_eq!(
            salvage_exit_code(&SalvageOutcome {
                entries: vec![
                    record(SalvageDisposition::Written(PathBuf::from("a"))),
                    record(SalvageDisposition::Directory(PathBuf::from("b"))),
                ],
            }),
            0,
            "every entry Intact/Complete and written must be clean"
        );

        assert_eq!(
            salvage_exit_code(&SalvageOutcome {
                entries: vec![record(SalvageDisposition::WrittenPartial {
                    path: PathBuf::from("a.partial"),
                    cause: PartialCause::ChecksumMismatch,
                })],
            }),
            4,
            "a Partial entry alone is bucket 4"
        );

        assert_eq!(
            salvage_exit_code(&SalvageOutcome {
                entries: vec![record(SalvageDisposition::SkippedUnverified)],
            }),
            3,
            "an Unverified entry alone is bucket 3"
        );

        assert_eq!(
            salvage_exit_code(&SalvageOutcome {
                entries: vec![
                    record(SalvageDisposition::Written(PathBuf::from("a"))),
                    record(SalvageDisposition::WrittenDisambiguated {
                        path: PathBuf::from("a.salvaged-1"),
                        taken_by: 0,
                        partial: None,
                    }),
                ],
            }),
            4,
            "nothing was lost, but a name the archive declared could not be honoured — a \
             script that ran `salvage -C out && rm broken.zip` has to be told"
        );

        assert_eq!(
            salvage_exit_code(&SalvageOutcome {
                entries: vec![
                    record(SalvageDisposition::WrittenPartial {
                        path: PathBuf::from("a.partial"),
                        cause: PartialCause::Truncated,
                    }),
                    record(SalvageDisposition::SkippedUnverified),
                ],
            }),
            3,
            "3 must outrank 4 when a run has BOTH a Partial and an Unverified entry — \
             the actionable diagnosis (rebuild, or --features c-backed) wins over the \
             merely-degraded one"
        );

        // Fix round 1: neither `NotSelected` nor `NotWritten` counts as a
        // degradation — both are facts about what the CALLER asked for
        // (`--index`, or no destination at all), never about the archive or
        // the recovery.
        assert_eq!(
            salvage_exit_code(&SalvageOutcome {
                entries: vec![
                    record(SalvageDisposition::Written(PathBuf::from("a"))),
                    record(SalvageDisposition::NotSelected),
                    record(SalvageDisposition::NotSelected),
                ],
            }),
            0,
            "an entry excluded by --index must not turn a clean selective run into exit 4"
        );
        assert_eq!(
            salvage_exit_code(&SalvageOutcome {
                entries: vec![record(SalvageDisposition::NotWritten); 3],
            }),
            0,
            "a report-only run (--list with no destination) must exit 0 when nothing is \
             actually wrong with any entry"
        );

        // A `SkippedPartial` still degrades the run, cause attached or not —
        // the new payload must not accidentally exempt it from bucket 4.
        assert_eq!(
            salvage_exit_code(&SalvageOutcome {
                entries: vec![record(SalvageDisposition::SkippedPartial(
                    PartialCause::Truncated
                ))],
            }),
            4,
            "a policy-skipped Partial entry is still bucket 4, cause attached or not"
        );
    }
}

/// Task 2's own required test: dispatch on a resolved format this build has
/// no scanner for yet. Deliberately NOT inside [`salvage_tests`] above, which
/// is gated on `feature = "zip"` — the whole point of this dispatch is that
/// it must answer correctly even in a build with no salvage scanner wired
/// at all, so its own test must not depend on one either. Gated on
/// `feature = "tar"` purely to build a fixture the registry's magic table
/// recognises: `tar` is part of the `pure` feature bundle, which both the
/// default feature set and the pure-tier build (`--no-default-features
/// --features pure`) include, so this runs on all three tiers `make check`
/// exercises.
#[cfg(all(test, feature = "tar"))]
mod salvage_dispatch_tests {
    use super::*;
    use stuffr_core::salvage::SalvagePolicy;

    /// A minimal `ustar` header — enough for [`resolve_chain`]'s magic match
    /// (`b"ustar"` at offset 257) to identify the file as `tar`, nothing
    /// else filled in. [`salvage`]'s own format resolution never opens the
    /// container to identify it (see [`resolve_salvage_format`]'s doc), so
    /// this is sufficient: the dispatch this test pins never reaches far
    /// enough to care whether the rest of the header is well-formed.
    fn tar_like_bytes() -> Vec<u8> {
        let mut header = vec![0u8; 512];
        header[257..262].copy_from_slice(b"ustar");
        header
    }

    /// A tar is a container this stage cannot salvage (Task 2 wires zip,
    /// Task 3 wires `arc`; `zoo`/`lha`/`arj` each get their own scanner in a
    /// later task, and tar itself never will — see `CLAUDE.md`'s State
    /// section on the Stage 3 deferral). The refusal is [`Error::Unsupported`] (exit 3)
    /// naming the format — never a silent empty [`SalvageOutcome`], which
    /// would read to a caller as "the scan found nothing recoverable" (exit
    /// 5): a claim about the ARCHIVE, where the truth here is a claim about
    /// this BUILD — it never tried.
    #[test]
    fn salvage_refuses_a_format_it_cannot_scan() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("archive.tar");
        std::fs::write(&archive, tar_like_bytes()).unwrap();

        let opts = SalvageOpts {
            dest: None,
            policy: SalvagePolicy::default(),
            select: None,
            format: None,
        };
        let err = salvage(&archive, &opts)
            .expect_err("a format with no salvage scanner must refuse, not report empty");
        assert_eq!(
            err.exit_code(),
            3,
            "must be exit 3 (a build-capability limit), never a silent exit 5 empty outcome"
        );
        assert!(
            matches!(err, Error::Unsupported(_)),
            "expected Error::Unsupported, got {err:?}"
        );
        assert!(
            err.to_string().contains("tar"),
            "the message must name the format it refused: {err}"
        );
    }
}

/// Task 3c's own regression test: an ARC entry positioned such that the
/// OLD, zip-shaped payload lookup (`entries.rs`'s since-removed
/// `zip_payload_start`, which unconditionally read 30 bytes from
/// `entry.offset` as if it were a zip local header) runs past end-of-file.
///
/// This is the crash the Stage 2 salvage fuzz target needed 20,000
/// iterations to surface (past the 2,000-run smoke budget `make fuzz`
/// checks) once it could select ARC — reproduced here directly, with no
/// fuzzing at all, because a defect only a long fuzz run can see is one the
/// suite should be able to see on its own. Gated on `feature = "arc"`
/// alone (not `zip`, unlike `salvage_tests` above): the whole point is
/// that ARC's own write path must not borrow zip's.
#[cfg(all(test, feature = "arc"))]
mod arc_salvage_tests {
    use super::*;
    use stuffr_core::salvage::{SalvagePolicy, SalvageStatus};

    const ARC_MARKER: u8 = 0x1A;
    const ARC_NAME_LEN: usize = 13;

    /// CRC-16/ARC — the same algorithm `arc_salvage.rs`'s own `crc16_arc`
    /// computes, reimplemented here rather than reused because that
    /// function is private to a different crate. The one place in this
    /// module that legitimately needs it: building a header whose CRC-16
    /// deliberately disagrees with its payload, to force
    /// `SalvageStatus::Partial` without needing a truncated fixture.
    fn crc16_arc(data: &[u8]) -> u16 {
        let mut crc: u16 = 0;
        for &b in data {
            crc ^= u16::from(b);
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xA001 & mask);
            }
        }
        crc
    }

    /// One ARC entry: the marker byte plus the fixed 28-byte record,
    /// followed by `payload`. `stored_crc` is supplied by the caller rather
    /// than computed from `payload`, so a fixture can deliberately
    /// disagree with its own content.
    fn arc_entry(method: u8, name: &str, payload: &[u8], stored_crc: u16) -> Vec<u8> {
        arc_entry_declaring(method, name, payload.len() as u32, payload, stored_crc)
    }

    /// Like [`arc_entry`], but the header's declared `compressed_size` may
    /// be LARGER than the number of bytes `actual_payload` actually
    /// supplies — the shape of a truncated entry, where the header's own
    /// declaration has nothing real behind it. `original_size` is set to
    /// the identical `declared_size` figure; use
    /// [`arc_entry_declaring_sizes`] when a test needs the two to differ
    /// (fix round 2's NEW-1 regression test does, on purpose).
    fn arc_entry_declaring(
        method: u8,
        name: &str,
        declared_size: u32,
        actual_payload: &[u8],
        stored_crc: u16,
    ) -> Vec<u8> {
        arc_entry_declaring_sizes(
            method,
            name,
            declared_size,
            declared_size,
            actual_payload,
            stored_crc,
        )
    }

    /// [`arc_entry_declaring`], with `compressed_size` and `original_size`
    /// independently controlled — needed for fix round 2's NEW-1
    /// regression test, which requires a declared `original_size` SMALLER
    /// than the declared `compressed_size` (a shape no other test in this
    /// module needed before it).
    fn arc_entry_declaring_sizes(
        method: u8,
        name: &str,
        declared_compressed: u32,
        declared_original: u32,
        actual_payload: &[u8],
        stored_crc: u16,
    ) -> Vec<u8> {
        let mut out = vec![ARC_MARKER, method];
        let mut field = [0u8; ARC_NAME_LEN];
        field[..name.len()].copy_from_slice(name.as_bytes());
        out.extend_from_slice(&field);
        out.extend_from_slice(&declared_compressed.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // date/time
        out.extend_from_slice(&stored_crc.to_le_bytes());
        out.extend_from_slice(&declared_original.to_le_bytes());
        out.extend_from_slice(actual_payload);
        out
    }

    /// A one-entry, 29-byte ARC archive (marker + 28-byte record + a
    /// zero-byte payload) whose CRC-16 deliberately disagrees, so the entry
    /// is `Partial` — which is what makes `--list` (no destination at all)
    /// still call the payload writer: `place_salvaged_file` decodes into
    /// `io::sink()` for ANY partial entry, regardless of `dest`, purely to
    /// learn whether the cause is a checksum mismatch or a truncation. That
    /// is exactly the call the original bug report's `salvage --format arc
    /// --list <file>` reached.
    ///
    /// The archive is only 29 bytes long, so `entry.offset + 30` (the old
    /// `zip_payload_start`'s unconditional read size) already runs past
    /// end of file at the FIRST and only entry — no need for a second entry
    /// or any padding to force it near EOF.
    #[test]
    fn a_partial_arc_entry_near_eof_does_not_crash_the_salvage_write_path() {
        let wrong_crc = crc16_arc(b"not the payload");
        let bytes = arc_entry(1, "x", b"", wrong_crc);
        assert_eq!(
            bytes.len(),
            29,
            "the fixture must be shorter than the 30 bytes the old zip-shaped lookup read \
             unconditionally from entry.offset"
        );

        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("tiny.arc");
        std::fs::write(&archive, &bytes).unwrap();

        let opts = SalvageOpts {
            dest: None,
            policy: SalvagePolicy::default(),
            select: None,
            format: Some(FormatId::new("arc")),
        };
        let outcome = salvage(&archive, &opts).expect(
            "a damaged-but-well-formed ARC entry must never abort the whole salvage run with \
             an unclassified i/o error (the pre-fix behaviour: Error::Io, exit 1)",
        );

        assert_eq!(outcome.entries.len(), 1);
        assert_eq!(outcome.entries[0].status, SalvageStatus::Partial);
        assert_eq!(
            outcome.entries[0].disposition,
            SalvageDisposition::SkippedPartial(PartialCause::ChecksumMismatch)
        );
    }

    /// Fix round 1, HIGH-1. A healthy `a.txt` followed by a truncated
    /// header declaring a 512 MiB payload that never follows (the file
    /// ends right after the header) — the reviewer's own 60-byte
    /// reproducer, reproduced here rather than paraphrased. Before the
    /// fix, `write_payload` checked this DECLARED figure against ARC's
    /// 256 MiB ceiling before bounding it against what the file actually
    /// held, so the whole run aborted with `Error::ResourceLimit` (exit 6)
    /// — destroying `a.txt`, which decodes perfectly well on its own, along
    /// with it. `salvage()` must now succeed, and `a.txt` must actually be
    /// recovered, not merely reported as such.
    #[test]
    fn a_truncated_entry_declaring_an_oversized_length_does_not_abort_the_whole_run() {
        let a_payload = b"hi";
        let a_crc = crc16_arc(a_payload);
        let entry_a = arc_entry(1, "a.txt", a_payload, a_crc);

        // Header only (29 bytes) — the declared 512 MiB payload never
        // follows. The stored CRC is irrelevant: a truncated candidate is
        // decided `Partial` before any checksum comparison ever runs.
        const OVERSIZED: u32 = 512 * 1024 * 1024;
        let entry_b = arc_entry_declaring(1, "b.dat", OVERSIZED, b"", 0);

        let mut bytes = entry_a.clone();
        bytes.extend_from_slice(&entry_b);
        assert_eq!(
            bytes.len(),
            60,
            "matches the reviewer's own 60-byte reproducer byte for byte"
        );

        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("huge-tail.arc");
        std::fs::write(&archive, &bytes).unwrap();

        let out_dir = tempfile::tempdir().unwrap();
        let opts = SalvageOpts {
            dest: Some(out_dir.path().to_path_buf()),
            policy: SalvagePolicy::default(),
            select: None,
            format: Some(FormatId::new("arc")),
        };
        let outcome = salvage(&archive, &opts).expect(
            "a truncated entry declaring an oversized length must never abort the WHOLE \
             run — doing so destroys every entry already recovered, which is exactly the \
             archive salvage exists to rescue (fix round 1, HIGH-1)",
        );

        assert_eq!(outcome.entries.len(), 2);
        assert_eq!(outcome.entries[0].name, "a.txt");
        assert_eq!(outcome.entries[0].status, SalvageStatus::Intact);
        assert_eq!(
            outcome.entries[0].disposition,
            SalvageDisposition::Written(out_dir.path().join("a.txt")),
            "a.txt must be WRITTEN, not lost as collateral damage from b.dat's lie"
        );
        assert_eq!(
            std::fs::read(out_dir.path().join("a.txt")).unwrap(),
            a_payload,
            "a.txt must actually be recovered on disk, not merely reported recovered"
        );

        assert_eq!(outcome.entries[1].name, "b.dat");
        assert_eq!(outcome.entries[1].status, SalvageStatus::Partial);
    }

    /// Fix round 1, MEDIUM-1. A Stored entry whose header declares a
    /// 36-byte payload but whose file only carries the first 20 of those
    /// bytes — a genuinely truncated mid-payload cut, not merely a missing
    /// tail. Before the fix, `write_payload` allocated a buffer sized by
    /// the DECLARED 36 bytes and `read_exact`'d it, which failed outright
    /// on the short read and wrote nothing at all: `salvage` reported
    /// `Partial (truncated)` and produced an EMPTY `.partial` file, even
    /// though 20 genuine bytes of the original content were sitting right
    /// there on disk. That is exactly the contract zip's own truncated-tail
    /// handling already honours and `CLAUDE.md`'s salvage section states in
    /// so many words: recover the genuine surviving prefix, invent nothing.
    #[test]
    fn a_truncated_entry_recovers_its_genuine_surviving_prefix() {
        let full: &[u8] = b"HELLO-WORLD-THIS-IS-THE-PAYLOAD!!!!!";
        assert_eq!(full.len(), 36);
        let prefix = &full[..20];

        // The header's own claimed CRC-16 — over the FULL, never-delivered
        // payload. Irrelevant here: truncation is decided from the byte
        // count alone, before any checksum comparison runs.
        let claimed_crc = crc16_arc(full);
        let bytes = arc_entry_declaring(1, "cut.txt", 36, prefix, claimed_crc);
        assert_eq!(bytes.len(), 29 + 20);

        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("cut.arc");
        std::fs::write(&archive, &bytes).unwrap();

        let out_dir = tempfile::tempdir().unwrap();
        let opts = SalvageOpts {
            dest: Some(out_dir.path().to_path_buf()),
            policy: SalvagePolicy::default(),
            select: None,
            format: Some(FormatId::new("arc")),
        };
        let outcome = salvage(&archive, &opts).unwrap();

        assert_eq!(outcome.entries.len(), 1);
        assert_eq!(outcome.entries[0].status, SalvageStatus::Partial);
        let SalvageDisposition::WrittenPartial { path, cause } = &outcome.entries[0].disposition
        else {
            panic!(
                "expected WrittenPartial, got {:?}",
                outcome.entries[0].disposition
            );
        };
        assert_eq!(*cause, PartialCause::Truncated);

        let recovered = std::fs::read(path).unwrap();
        assert_eq!(
            recovered, prefix,
            "the genuine surviving 20-byte prefix must be written, not an empty file \
             (fix round 1, MEDIUM-1)"
        );
        assert!(!recovered.is_empty());
    }

    /// LOW (fix round 1, taken): no existing test asserted the BYTES a
    /// clean ARC entry recovers to disk are correct — only that a
    /// disposition of `Written` was reported. A `write_payload` that
    /// decoded to the wrong bytes would have passed every test in this
    /// module until now.
    #[test]
    fn an_intact_entry_recovers_its_exact_bytes_to_disk() {
        let payload = b"hello from a real arc entry";
        let crc = crc16_arc(payload);
        let bytes = arc_entry(1, "hi.txt", payload, crc);

        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("hi.arc");
        std::fs::write(&archive, &bytes).unwrap();

        let out_dir = tempfile::tempdir().unwrap();
        let opts = SalvageOpts {
            dest: Some(out_dir.path().to_path_buf()),
            policy: SalvagePolicy::default(),
            select: None,
            format: Some(FormatId::new("arc")),
        };
        let outcome = salvage(&archive, &opts).unwrap();

        assert_eq!(outcome.entries.len(), 1);
        assert_eq!(outcome.entries[0].status, SalvageStatus::Intact);
        let SalvageDisposition::Written(path) = &outcome.entries[0].disposition else {
            panic!("expected Written, got {:?}", outcome.entries[0].disposition);
        };
        assert_eq!(std::fs::read(path).unwrap(), payload);
    }

    /// Fix round 2, NEW-1. A Stored entry whose header declares
    /// `compressed_size = 36` and `original_size = 10`, with only 20 bytes
    /// physically present — genuinely truncated at the compressed level,
    /// the same shape the HIGH-1/MEDIUM-1 fixtures use, except this one's
    /// declared `original_size` is small enough that the bounded read's
    /// own partial decode still satisfies it. Before this fix,
    /// `write_payload` reported this as `PartialCause::ChecksumMismatch`
    /// — no checksum comparison ever ran — because `stream_bounded_copy`
    /// stopped at the declared 10 bytes and reported "completed". The
    /// tier is already correct (`verify_candidate` reports `Partial` from
    /// the byte count alone, before any of this runs); the cause must not
    /// contradict the reason the entry is `Partial` in the first place.
    #[test]
    fn a_truncated_entry_with_a_small_declared_original_size_still_reports_truncated() {
        let present: &[u8] = b"01234567890123456789"; // 20 bytes, a genuine prefix
        assert_eq!(present.len(), 20);
        let bytes = arc_entry_declaring_sizes(1, "mis.txt", 36, 10, present, 0);
        assert_eq!(bytes.len(), 29 + 20);

        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("mis.arc");
        std::fs::write(&archive, &bytes).unwrap();

        let out_dir = tempfile::tempdir().unwrap();
        let opts = SalvageOpts {
            dest: Some(out_dir.path().to_path_buf()),
            policy: SalvagePolicy::default(),
            select: None,
            format: Some(FormatId::new("arc")),
        };
        let outcome = salvage(&archive, &opts).unwrap();

        assert_eq!(outcome.entries.len(), 1);
        assert_eq!(outcome.entries[0].status, SalvageStatus::Partial);
        let SalvageDisposition::WrittenPartial { cause, .. } = &outcome.entries[0].disposition
        else {
            panic!(
                "expected WrittenPartial, got {:?}",
                outcome.entries[0].disposition
            );
        };
        assert_eq!(
            *cause,
            PartialCause::Truncated,
            "a compressed payload with fewer bytes present than declared must always \
             report Truncated, regardless of how small the declared original_size is \
             (fix round 2, NEW-1)"
        );
    }
}

/// Fix round 1, MEDIUM-2: `salvage_scan`'s dispatch table and
/// `write_salvaged_payload`'s are two independent `match`es, coupled only
/// by convention — nothing stops a later scanner task from adding the
/// first arm and forgetting the second, which reproduces the exact
/// companion gap ARC itself shipped with in Task 3 (a real scanner, an
/// unpopulated codec, every entry quietly `SkippedNotBuiltIn`). This pins
/// the positive set the review asked for: every name
/// `stuffr_core::testing::SALVAGE_SLOTS` lists must reach a REAL
/// per-format arm of `write_salvaged_payload`, never its own fallback.
#[cfg(test)]
mod salvage_seam_tests {
    use super::*;
    use stuffr_core::salvage::{SalvageStatus, SalvagedEntry};
    use stuffr_core::testing::SALVAGE_SLOTS;

    #[test]
    fn every_salvage_slot_reaches_a_real_payload_writer() {
        for &name in SALVAGE_SLOTS {
            let format = FormatId::new(name);
            // `meta.codec` is `None` on purpose: every real per-format
            // `write_payload` refuses a `None` codec itself, with its own,
            // differently-worded error, WITHOUT ever opening
            // `archive_path` first — so a path that does not exist is safe
            // to use, and the two failure messages are trivially
            // distinguishable from each other.
            let entry = SalvagedEntry {
                scan_position: 0,
                offset: 0,
                payload_start: 0,
                meta: EntryMeta::file("probe"),
                status: SalvageStatus::Complete,
                shadows: None,
                collides_with: None,
            };
            let err = write_salvaged_payload(
                format,
                Path::new("/nonexistent-salvage-seam-probe"),
                &entry,
                0,
                &mut std::io::sink(),
            )
            .expect_err("a codec-less probe entry must always be refused");
            let message = err.to_string();
            assert!(
                !message.contains("has no payload writer for"),
                "SALVAGE_SLOTS names `{name}`, which `salvage_scan` dispatches to a real \
                 scanner, but `write_salvaged_payload` fell through to its own fallback \
                 for it instead of a real per-format arm: {message}"
            );
        }
    }
}
