use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use stuffr_core::{
    ArchiveRead, Chain, Counting, CountingWriter, CreateOpts, DEFAULT_MAX_RATIO, DecodeOpts,
    EntryKind, EntryMeta, Error, Fidelity, FidelityReport, FormatId, MetaFields, OpenOpts,
    RATIO_FLOOR, RatioGuard, Registry, Result, Rung, SeekRead, Source, SourceCaps, StreamPolicy,
    check_symlink_target, ladder, resolve_chain_deep_with, safe_join,
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
fn open_archive(
    registry: &Registry,
    src: Input,
    max_ratio: u64,
    memory_limit: Option<u64>,
) -> Result<(Box<dyn ArchiveRead>, FormatId)> {
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
///
/// `memory_limit` bounds the codec layer beneath the container — see
/// [`open_archive`]. `None` is unbounded, the library default; the CLI
/// always resolves a value. "Reads nothing and extracts nothing" is only
/// true of the ENTRIES: reaching the container's first header still decodes
/// whatever codec sits above it, so this verb is as exposed to a crafted
/// dictionary declaration as `unpack` is.
pub fn list(src: Input, max_ratio: u64, memory_limit: Option<u64>) -> Result<Vec<EntryMeta>> {
    let (mut ar, _format) = open_archive(crate::registry(), src, max_ratio, memory_limit)?;
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
pub fn test(src: Input, max_ratio: u64, memory_limit: Option<u64>) -> Result<Outcome> {
    // Before `src` is consumed by `open_archive`, which takes it by value —
    // the same ordering `extract` and `cat` already use.
    let compressed_total = src
        .path()
        .and_then(|p| std::fs::metadata(p).ok())
        .map(|m| m.len());
    let (mut ar, format) = open_archive(crate::registry(), src, max_ratio, memory_limit)?;
    // `test` built no budget at all until the Phase 2 final review: a
    // 204 KB zip holding one 200 MB entry verified clean at exit 0 under
    // `--max-ratio 10`, while `cat` and `unpack` of the identical file
    // refused it at exit 6. `test` is precisely the verb reached for to
    // inspect an UNTRUSTED archive, so it must be the strictest of the
    // three, not the only unbounded one. `entries_test_matches_cat_and_unpack`
    // in `crates/stuffr-cli/tests/cli.rs` pins the parity.
    let mut budget = ArchiveBudget::new(compressed_total, max_ratio);
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

/// Extracts entries matching `patterns` (all of them when empty) into `dest`.
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
pub fn extract(src: Input, dest: &Path, patterns: &[String], o: &ExtractOpts) -> Result<Outcome> {
    // Before `src` is consumed by `open_archive`, which takes it by value.
    let compressed_total = o.compressed_total.or_else(|| {
        src.path()
            .and_then(|p| std::fs::metadata(p).ok())
            .map(|m| m.len())
    });
    let (mut ar, format) = open_archive(crate::registry(), src, o.max_ratio, o.memory_limit)?;
    let mut budget = ArchiveBudget::new(compressed_total, o.max_ratio);

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

    while let Some(mut entry) = ar.next_entry()? {
        let meta = entry.meta().clone();
        if !patterns.is_empty() && !matches_any(&meta.name, patterns) {
            continue;
        }
        matched += 1;

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
                    reason: "device nodes, fifos, sockets and hardlinks are not created",
                });
            }
        }
    }

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

    // Patterns that select nothing must not report success: a typo'd name
    // would otherwise look exactly like an archive that had nothing to give.
    if !patterns.is_empty() && matched == 0 {
        return Err(Error::EntryNotFound(patterns.join(", ")));
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

/// Writes the payload of every entry matching `patterns` (all of them when
/// empty) to `dst`, in archive order.
///
/// No containment here, deliberately: `cat` opens no path at all. An entry's
/// name is only ever compared against `patterns`, and its bytes go to `dst`
/// — a hostile name has nowhere to point. The bomb budget still applies,
/// since the motivating case (`curl … | stuffr cat - a.txt`) streams
/// untrusted input of unknown size.
pub fn cat(
    src: Input,
    patterns: &[String],
    max_ratio: u64,
    memory_limit: Option<u64>,
    dst: &mut dyn Write,
) -> Result<Outcome> {
    let compressed_total = src
        .path()
        .and_then(|p| std::fs::metadata(p).ok())
        .map(|m| m.len());
    let (mut ar, format) = open_archive(crate::registry(), src, max_ratio, memory_limit)?;
    let mut budget = ArchiveBudget::new(compressed_total, max_ratio);
    let mut written = 0u64;
    let mut matched = 0u64;

    while let Some(mut entry) = ar.next_entry()? {
        let meta = entry.meta().clone();
        if !patterns.is_empty() && !matches_any(&meta.name, patterns) {
            continue;
        }
        matched += 1;
        // A directory or symlink entry frames no payload, so this copies
        // zero bytes for one rather than needing a case of its own.
        written += copy_charging(entry.reader(), dst, &meta.name, &mut budget)?;
    }

    if !patterns.is_empty() && matched == 0 {
        return Err(Error::EntryNotFound(patterns.join(", ")));
    }
    dst.flush()?;

    Ok(Outcome {
        bytes_in: 0,
        bytes_out: written,
        format,
        fidelity: ar.fidelity().clone(),
    })
}

/// Collects `paths` into a new `container` archive at `dst` — one entry each.
///
/// Every input is validated before the destination is touched, the same
/// contract `Codec::check_encode_opts` gives the single-stream path: a
/// rejected command costs nothing, with no temp file created and no existing
/// file disturbed.
pub fn create_archive(
    paths: &[PathBuf],
    dst: Output,
    container: FormatId,
    o: &CompressOpts,
) -> Result<Outcome> {
    let kind = crate::registry().require_container(container)?;

    let mut planned: Vec<(String, std::fs::Metadata)> = Vec::with_capacity(paths.len());
    let mut names = HashSet::new();
    for path in paths {
        let name = entry_name_for(path)?;
        if !names.insert(name.clone()) {
            return Err(Error::Usage(format!(
                "two inputs would both be stored as entry `{name}`; an archive with \
                 duplicate names cannot be extracted without --force"
            )));
        }
        // `metadata`, which follows a symlink, not `symlink_metadata`: a path
        // named on the command line is followed, so `stuffr pack
        // link-to-notes.txt` stores the file it points at. Storing the link
        // itself would let `pack` produce an archive `unpack` then refuses at
        // exit 7 — stuffr must not write what it will not read.
        let md = std::fs::metadata(path)?;
        if md.is_dir() {
            return Err(Error::Usage(format!(
                "`{}` is a directory; this build packs named files only, so list \
                 them individually",
                path.display()
            )));
        }
        if !md.is_file() {
            return Err(Error::Usage(format!(
                "`{}` is neither a file nor a directory; there is no entry shape \
                 for it yet",
                path.display()
            )));
        }
        planned.push((name, md));
    }

    let opened = dst.create(o.force, o.sync)?;
    let finish = opened.finish;
    let (counted, bytes_out) = CountingWriter::new(opened.writer);
    let archive = kind.create(
        Box::new(counted),
        &CreateOpts {
            level: o.level,
            ..Default::default()
        },
    )?;

    // An immediately-invoked `FnOnce`, not the `let run = || …` shape the
    // codec path uses: `ArchiveWrite::finish` consumes the writer, which a
    // reusable closure cannot do.
    let result = (move || -> Result<u64> {
        let mut archive = archive;
        let mut bytes_in = 0u64;
        for ((name, md), path) in planned.iter().zip(paths) {
            let mut file = std::fs::File::open(path)?;
            archive.add(
                &EntryMeta {
                    name: name.clone(),
                    size: Some(md.len()),
                    mtime: md.modified().ok(),
                    mode: mode_of(md),
                    kind: EntryKind::File,
                    ..Default::default()
                },
                &mut file,
            )?;
            bytes_in += md.len();
        }
        // Writes the container's trailer and flushes; the destination was
        // handed over by value, so nothing else can flush it.
        archive.finish()?;
        Ok(bytes_in)
    })();

    match result {
        Ok(bytes_in) => {
            // Only now: every byte, trailer included, is written and flushed.
            publish(finish)?;
            Ok(Outcome {
                bytes_in,
                bytes_out: bytes_out.load(Ordering::Relaxed),
                format: container,
                // Every input is a real, seekable file — `entry_name_for`
                // refuses a pipe, which has no name to store.
                fidelity: FidelityReport::new(Rung::Exact),
            })
        }
        Err(e) => {
            discard(finish);
            Err(e)
        }
    }
}

/// The entry name a command-line path is stored under: its final component.
///
/// Not the path as typed. `stuffr pack /etc/hosts -o x.tar` must not write an
/// entry named `/etc/hosts`, because [`extract`] would refuse that archive at
/// exit 7 — stuffr does not write what it will not read.
fn entry_name_for(path: &Path) -> Result<String> {
    let name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
        Error::Usage(format!(
            "`{}` has no final path component to name an entry after",
            path.display()
        ))
    })?;
    Ok(name.to_string())
}

/// The unix permission bits, where the platform has them.
///
/// Masked to `0o7777`: `Metadata::mode` carries the file-type bits too
/// (`S_IFREG`, `0o100000`), and a tar header's mode field holds permissions
/// alone — the type lives in its typeflag. Storing the raw value would write
/// a mode no other tar tool would recognise, and would make extraction report
/// a mode loss (see `RESTORED_MODE_BITS`) for every file stuffr packed
/// itself.
fn mode_of(md: &std::fs::Metadata) -> Option<u32> {
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
}
