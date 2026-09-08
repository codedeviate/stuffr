//! tar, via the `tar` crate — the first container in this tree, and the
//! shape the three that follow (ar, cpio, zip) are expected to copy.
//!
//! Four things below are not obvious, and each is a decision this module
//! makes rather than one the `tar` crate makes for it. The three later
//! containers will meet the first only if their crates have the same shape;
//! they will meet the other three regardless.
//!
//! # `TarRead` is self-referential, and that is the crate's doing
//!
//! `tar::Archive::entries()` returns `Entries<'a, R>`, which BORROWS the
//! archive (`EntriesFields<'a>` plus `PhantomData<&'a Archive<R>>`), and the
//! crate offers no owning iterator. A struct that holds both is therefore
//! self-referential. Calling `entries()` once per `next_entry` is not a way
//! out: `_entries` guards with `if self.inner.pos.get() != 0 { return
//! Err(other("cannot call entries unless archive is at position 0")) }`, so
//! the second call fails outright once a single byte has been read.
//!
//! **`self_cell` was tried first (the plan's ruling) and does not fit.** Its
//! only mutable access to the dependent is
//! `with_dependent_mut(&'outer mut self, impl for<'q> FnOnce(&'q Owner,
//! &'outer mut Dependent<'q>) -> Ret) -> Ret`: `Ret` is fixed before `'q` is
//! quantified, so a value borrowed from the dependent — which is exactly
//! what `Iterator::next` on `Entries<'q, _>` produces — cannot leave the
//! closure. `ArchiveRead::next_entry` has to return such a value.
//! (`self_cell::MutBorrow` solves a different half of the problem, that
//! `entries()` takes `&mut self` while the builder is handed `&Owner`, and
//! would have been enough on its own if the dependent could escape.) So the
//! plan's stated fallback is what is here: the archive is allocated with
//! `Box::into_raw`, and reclaimed in `Drop`. This module's only `unsafe` is
//! that pair. Not taking the dependency also drops its licence question:
//! `self_cell` is `Apache-2.0 OR GPL-2.0-only`, and the only crate added
//! here is `tar`, which is `MIT OR Apache-2.0` like most of this tree.
//!
//! Raw rather than a `Box` kept in the struct on purpose: `Box` is a
//! `noalias` pointer, so deriving a borrow from one and then MOVING the box
//! — which building this struct does — is the aliasing hazard
//! `Box::into_raw` sidesteps entirely.
//!
//! # `entries()`, never `entries_with_seek()`, even on a seekable file
//!
//! The two differ only in how they reach the next header: `entries()` READS
//! its way past an entry's payload, `entries_with_seek()` SEEKS. Seeking
//! past the end of a truncated file SUCCEEDS, after which the header that
//! is not there reads back as a clean end of archive — a cut archive
//! reported as complete. Reading fails with "unexpected EOF during skip"
//! instead. So the seekable path is the one that loses information, and this
//! container does not take it. The cost is that `stuffr list big.tar` reads
//! rather than seeks; the benefit is that it cannot silently accept damage.
//!
//! # tar's own reader does not detect two kinds of truncation
//!
//! Measured, not assumed:
//!
//! 1. A cut INSIDE an entry's payload. `EntryIo::Data` is a `Take` over the
//!    source, so end-of-stream is `Ok(0)` — a short read reported as a
//!    complete entry. [`EntryPayload`] compares delivered bytes against the
//!    size the entry's own header declares and raises `InvalidData` itself.
//! 2. A missing or partial END-OF-ARCHIVE MARKER. `try_read_all` returns
//!    `Ok(false)` when the first read of a header comes back empty, which
//!    `next_entry` turns into `Ok(None)` — "the archive ended here",
//!    indistinguishable from a real ending. Worse, tar stops at the FIRST
//!    zero block and never looks at what follows, so it cannot see a stream
//!    that was cut inside the marker either.
//!
//!    [`TrailerWatch`] therefore counts what the source delivers, and
//!    [`TarRead::verify_end_of_archive`] asks one question AT TAR'S OWN STOP
//!    POSITION — the position being the load-bearing part, since the same
//!    question asked at end of stream is both too strict and too lax at
//!    once, as an earlier version of this module was:
//!
//!    **Does a whole further 512-byte block exist?**
//!
//!    That separates tar's two indistinguishable endings. tar returns
//!    `Ok(None)` either having read one whole all-zero block — a marker, so
//!    a second block follows — or having asked for a header and got nothing,
//!    in which case `try_read_all` consumed NOTHING and the source is
//!    exhausted, so no block follows. It is also what an entry whose
//!    payload merely ends in zeros cannot forge: without this, an archive
//!    with an all-zero payload tail and its marker removed reads back as
//!    complete.
//!
//!    "The last block tar consumed was zeros" looks like a second rule and
//!    is not one: on the route where it fails, the source is exhausted and
//!    the question above already rejects. Mutation-checked — deleting it
//!    left the suite green — so it survives only as the DIAGNOSIS that
//!    phrases the error, which the tests assert.
//!
//!    Whatever follows the second block is ignored, as every tar tool
//!    ignores it.
//!
//!    Both rules are MEASURED against three reference tools — macOS `bsdtar`
//!    3.5.3, GNU `tar` (`gtar`) and Python's `tarfile` — on hand-cut
//!    fixtures, on the accept side as much as the reject side, because a
//!    refusal that fires on input every tool accepts is worse than no
//!    refusal:
//!
//!    | fixture | the three tools | stuffr |
//!    |---|---|---|
//!    | complete | accept | accept |
//!    | + 1 byte / 20 bytes / a 512-byte non-zero block of junk | accept | accept |
//!    | + zero padding to a 10240-byte record | accept | accept |
//!    | one zero block then a non-zero block | accept (GNU warns "A lone zero block") | accept |
//!    | no marker at all | reject ("Damaged tar archive", `ReadError`) | reject |
//!    | a lone zero block, then nothing | reject ("Truncated input file (needed 512 bytes, only 0 available)", `ReadError`) | reject |
//!    | an all-zero payload tail with the marker removed | reject | reject |
//!    | a partial second marker block | `bsdtar` and `tarfile` disagree with each other | reject |
//!
//!    Two deliberate departures, both recorded because they are the places
//!    this module is not simply copying a reference:
//!
//!    * The question is whether a whole block EXISTS, not whether it is
//!      zero. Demanding zeros rejects the "one zero block then a non-zero
//!      block" row above, which all three tools accept — and rejecting it
//!      buys nothing, since every entry in such an archive is intact and
//!      readable.
//!    * The last row is the one case where the tools do not agree with each
//!      other: `bsdtar` calls a partial trailing block "Truncated tar
//!      archive" in one shape and accepts it in another, and `tarfile`
//!      accepts both. There is no structural difference between a partial
//!      block of 511 zeros and one of 200, so no rule can accept one and
//!      reject the other; conformance property 9 requires the archive cut
//!      one byte short of its end to be caught, so both are rejected. No
//!      writer produces a partial final block, so this is damage rather than
//!      benign input.
//!
//!    Concatenated tars (`cat a.tar b.tar`, read as just `a.tar`'s entries
//!    by every tool) pass: `a.tar`'s own marker satisfies both rules and
//!    `b.tar` is part of the ignored tail.
//!
//! # `add` measures a payload whose size the caller did not declare
//!
//! `tar::Builder::append` writes the header first and pads from the number
//! of bytes it actually copied, so a `size` field that disagrees with the
//! data produces a structurally valid tar whose contents are mis-framed —
//! corruption this project generated itself. `EntryMeta::size` is
//! `Option<u64>` because a caller streaming from a pipe does not know it, so
//! `add` buffers that entry and writes the real length. A size that IS
//! declared is streamed and then verified; a mismatch is refused rather than
//! written.

use std::io::{self, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use stuffr_core::{
    ArchiveRead, ArchiveWrite, Container, ContainerCaps, CreateOpts, Entry, EntryKind, EntryMeta,
    Error, FidelityReport, FormatId, FormatMeta, MagicRule, OpenOpts, Resolved, Result, Source,
};

use crate::normalize::{NormalizeDecodeErrors, TAR_MALFORMED_AS_OTHER};

pub const TAR: FormatId = FormatId::new("tar");

/// `ustar` at offset 257 — inside `PROBE_LEN` (4096), so detection needs no
/// special handling. Old pre-POSIX tars have no magic at all and are reached
/// by extension; that is why harness property 2 requires only that ONE rule
/// match what `create` produces. Five bytes rather than six because POSIX
/// ustar writes `ustar\0` and GNU writes `ustar `, and both are tar.
static TAR_MAGIC: &[MagicRule] = &[MagicRule {
    offset: 257,
    bytes: b"ustar",
    format: TAR,
}];

/// Registration metadata for tar.
///
/// `["tar"]` and deliberately NOT `"tgz"` and friends: `probe.rs`'s
/// `inner_from_path` reaches tar-inside-a-codec by stripping the leading `t`
/// from the OUTER extension and looking the remainder up as a codec, so
/// registering `tgz` here would make a `.tgz` file resolve to a bare tar
/// instead of tar over gzip.
pub fn meta() -> FormatMeta {
    FormatMeta::container(TAR, &["tar"], TAR_MAGIC)
}

/// One tar block. Every header is one, and every payload is padded to a
/// multiple of one.
const BLOCK: usize = 512;

/// The `name` and `linkname` fields of a tar header. Anything longer needs a
/// GNU extension entry ahead of it.
const NAME_FIELD: usize = 100;

/// The mode `add` writes for a FILE entry when the caller does not say —
/// `rw-r--r--`, what every tar tool defaults a regular file to. Also the mode
/// of the synthetic GNU long-name extension header `set_header_field` emits,
/// which is never a real file and has no `EntryKind` of its own to branch on.
const DEFAULT_MODE: u32 = 0o644;

/// The mode `add` writes for a DIRECTORY entry when the caller does not say.
///
/// `DEFAULT_MODE` alone used to cover directories too, and `0o644` has no
/// owner-execute bit: a directory extracted with it is not traversable —
/// `cd`, or any tool opening a file beneath it, fails outright — in every
/// tool that respects the archived mode, not just this one. `0o755`,
/// `rwxr-xr-x`, is what every tar tool defaults an unset directory mode to
/// instead, matching `DEFAULT_MODE`'s own "what every tar tool defaults to"
/// rationale one level up.
const DEFAULT_DIR_MODE: u32 = 0o755;

/// The reader handed to `tar::Archive`. Wraps the ladder's source only to
/// watch for the end-of-archive marker; see the module doc's point 4.
type TarArchive = tar::Archive<TrailerWatch>;

pub struct Tar;

impl Container for Tar {
    fn id(&self) -> FormatId {
        TAR
    }

    /// Note what is NOT here: tar offers no random access at all, on any
    /// source.
    ///
    /// `ContainerCaps` has no field for that — `needs_seek: false` says tar
    /// does not *require* seeking, not that it can *use* it — so it is worth
    /// stating where a reader meets the type. `by_index` refuses on every
    /// source shape (see its own doc), and this module never calls
    /// `tar::Archive::entries_with_seek`, which is the only thing seekability
    /// would buy: it reaches the next header by SEEKING rather than reading,
    /// and a seek past the end of a truncated file succeeds, after which the
    /// header that is not there reads back as a clean end of archive. Trading
    /// random access this format never had for truncation this format
    /// otherwise hides is the right way round for an archive tool, but it is
    /// a trade, and the next reader should learn it here rather than by
    /// noticing that `entries_with_seek` is unused.
    fn caps(&self) -> ContainerCaps {
        ContainerCaps {
            read: true,
            write: true,
            // tar is natively streaming: entries carry their own headers and
            // sizes inline, so a forward read yields the same data and the
            // same metadata a seekable one does. That is what `forward_parse`
            // claims, and why the ladder's `ForwardOnly` rung costs tar no
            // fidelity warnings at all.
            forward_parse: true,
            ..Default::default()
        }
    }

    /// The ladder's fidelity report is carried through UNCHANGED, which is
    /// the whole of tar's rung story.
    ///
    /// A piped tar lands on `Rung::ForwardOnly` and stays there — the rung
    /// describes the access path, and a pipe genuinely is not seekable, which
    /// is what `Rung::Exact`'s own doc ("Input was seekable") and
    /// `is_authoritative()` both promise. What a forward read did NOT cost is
    /// recorded the other way: `caps().trailing_index` is false, so
    /// `ladder::seed_report` adds no warnings, so `has_warnings()` is false
    /// and `--strict-fidelity` (which gates on warnings, deliberately, for
    /// exactly this case — see `FidelityReport::has_warnings`) passes a piped
    /// tar. Promoting the rung to `Exact` here would instead tell a user via
    /// `stuffr info` that random access was available, which `by_index`
    /// establishes it never is.
    fn open(&self, resolved: Resolved, _o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
        let Resolved { source, report, .. } = resolved;
        let seekable = source.caps().seekable;

        let trailer = TrailerState::new();
        let shared: SharedSource = Arc::new(std::sync::Mutex::new(source));
        let watched = TrailerWatch {
            inner: Arc::clone(&shared),
            state: Arc::clone(&trailer),
        };

        // Leaked deliberately and reclaimed in `TarRead::drop` — see the
        // module doc for why `self_cell` cannot express this and why the
        // pointer is raw rather than a `Box` field.
        let archive: *mut TarArchive = Box::into_raw(Box::new(tar::Archive::new(watched)));

        // SAFETY: `archive` was just allocated by `Box::into_raw`, so it is
        // non-null, aligned and initialised, and nothing else has a pointer
        // to it. The borrow taken here is extended to `'static` and stored
        // in the `TarRead` below, which is sound because: the allocation is
        // never moved (only the pointer is), no second borrow of it is ever
        // handed out, and `TarRead::drop` drops the borrower (`entries`)
        // before freeing the allocation.
        let entries = unsafe { &mut *archive }
            .entries()
            .map_err(classify_tar_error);
        let entries = match entries {
            Ok(entries) => entries,
            Err(e) => {
                // SAFETY: as above, and `entries` never came into existence,
                // so nothing borrows the allocation.
                drop(unsafe { Box::from_raw(archive) });
                return Err(e);
            }
        };

        Ok(Box::new(TarRead {
            entries: Some(entries),
            archive,
            report,
            seekable,
            source: shared,
            trailer,
            ended: false,
        }))
    }

    fn create(&self, dst: Box<dyn Write + Send>, _o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
        Ok(Box::new(TarWrite {
            builder: Some(tar::Builder::new(dst)),
        }))
    }
}

/// Folds an error raised by `tar`'s own reader into this project's error
/// vocabulary. See [`TAR_MALFORMED_AS_OTHER`] for why `Other` — and only
/// `Other` — means the bytes were rejected rather than the disk failing.
fn classify_tar_error(e: io::Error) -> Error {
    if TAR_MALFORMED_AS_OTHER.contains(&e.kind()) {
        return Error::Corrupt(e.to_string());
    }
    Error::from_decode_io(e)
}

/// What [`TrailerWatch`] records about the bytes delivered so far.
struct TrailerState {
    delivered: AtomicU64,
    /// Consecutive zero bytes at the END of what has been delivered.
    trailing_zeros: AtomicU64,
}

impl TrailerState {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            delivered: AtomicU64::new(0),
            trailing_zeros: AtomicU64::new(0),
        })
    }

    fn delivered(&self) -> u64 {
        self.delivered.load(Ordering::Relaxed)
    }

    /// Consecutive zero bytes at the end of everything delivered so far.
    ///
    /// This says nothing on its own, and an earlier version of this module
    /// wrongly argued that it did. A run of 1024 or more can come entirely
    /// from an entry whose PAYLOAD ends in zeros, so "the stream ends in two
    /// zero blocks" is not evidence that an end-of-archive marker is
    /// present. [`TarRead::verify_end_of_archive`] uses this only as half of
    /// its rule (a), where the question is narrower and answerable: at tar's
    /// own stop position, is the last block it read a zero one?
    fn trailing_zeros(&self) -> u64 {
        self.trailing_zeros.load(Ordering::Relaxed)
    }

    fn record(&self, chunk: &[u8]) {
        self.delivered
            .fetch_add(chunk.len() as u64, Ordering::Relaxed);
        let zeros_at_end = chunk.iter().rev().take_while(|b| **b == 0).count() as u64;
        if zeros_at_end == chunk.len() as u64 {
            self.trailing_zeros
                .fetch_add(zeros_at_end, Ordering::Relaxed);
        } else {
            self.trailing_zeros.store(zeros_at_end, Ordering::Relaxed);
        }
    }
}

/// The ladder's source, plus a shared record of what it has delivered.
///
/// Only `Read` is implemented, deliberately: `tar::Archive` needs nothing
/// more, and not offering `Seek` is what makes it impossible for this module
/// to reach `entries_with_seek` by accident (see the module doc).
///
/// The source sits behind an `Arc<Mutex<..>>` because `tar::Archive` takes it
/// by value while [`TarRead::verify_end_of_archive`] must read the tail tar
/// stopped short of. The lock is never contended — tar has no read in flight
/// at the moment iteration ends — and costs one uncontended acquisition per
/// read of a 512-byte or 32 KiB chunk.
struct TrailerWatch {
    inner: SharedSource,
    state: Arc<TrailerState>,
}

type SharedSource = Arc<std::sync::Mutex<Box<dyn Source>>>;

impl Read for TrailerWatch {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self
            .inner
            .lock()
            .expect("tar source mutex poisoned")
            .read(buf)?;
        self.state.record(&buf[..n]);
        Ok(n)
    }
}

struct TarRead {
    /// Borrows the allocation `archive` points at, with its lifetime
    /// extended. `Option` so [`Drop`] can drop it BEFORE freeing what it
    /// borrows, rather than relying on `tar::Entries` having no `Drop` impl
    /// of its own — true today, and not this module's promise to keep.
    entries: Option<tar::Entries<'static, TrailerWatch>>,
    /// Owned by this struct, reclaimed in [`Drop`]. See the module doc.
    archive: *mut TarArchive,
    report: FidelityReport,
    seekable: bool,
    /// The same source `TrailerWatch` reads through, so the end-of-archive
    /// check can read the tail tar stopped short of.
    source: SharedSource,
    trailer: Arc<TrailerState>,
    /// Set once iteration has finished, so the end-of-archive check runs
    /// exactly once and a caller polling past the end gets `Ok(None)` rather
    /// than the same error repeatedly.
    ended: bool,
}

impl Drop for TarRead {
    fn drop(&mut self) {
        // Drop the borrower first. Order matters and the field order alone
        // would give it, but this says so.
        self.entries = None;
        // SAFETY: `archive` came from `Box::into_raw` in `Tar::open`, is
        // never copied out of this struct and is freed nowhere else, and the
        // only borrow of it was just dropped.
        drop(unsafe { Box::from_raw(self.archive) });
    }
}

impl TarRead {
    /// Checks the marker tar itself never looks at, at tar's OWN stop
    /// position. See the module doc's truncation section, item 2, for the
    /// reference measurements behind it.
    ///
    /// The position is what makes this work, and getting it wrong the first
    /// time produced a false positive and a false negative from one cause.
    /// `self.trailer` is read BEFORE anything else is, so it describes
    /// exactly what tar consumed and nothing more.
    ///
    /// There is exactly ONE condition here, and it is worth saying why,
    /// because the obvious second one is unfalsifiable. tar reaches
    /// `Ok(None)` by only two routes (`archive.rs`'s `next_entry` loop):
    /// having read one whole all-zero block, or having asked for a header
    /// and got nothing, in which case `try_read_all` returns `false`
    /// consuming NOTHING and the source is by definition exhausted. So
    /// "a whole further block exists" already separates them — on the second
    /// route there is nothing left to read — and a rule that also demanded
    /// "the last block tar consumed was zeros" could never be the condition
    /// that rejected anything. Mutation-checked: deleting that condition
    /// left the whole suite green, which is this project's own definition of
    /// a check that cannot fail. It survives below as the DIAGNOSIS, used
    /// only to phrase the error, and the tests assert the phrasing.
    fn verify_end_of_archive(&self) -> Result<()> {
        let consumed = self.trailer.delivered();
        // Best-effort, and knowingly fooled by an entry whose payload ends
        // in zeros — which is exactly why it decides only wording. `consumed`
        // is always a whole number of blocks at this point (tar reads headers
        // a block at a time and skips payloads by their padded length), so
        // the alignment term is an invariant, not a test.
        let stopped_on_a_zero_block =
            consumed.is_multiple_of(BLOCK as u64) && self.trailer.trailing_zeros() >= BLOCK as u64;

        // A whole SECOND block must exist. This is the detection: it proves
        // tar stopped because it read a marker, not because the stream ran
        // out, and it is what an all-zero payload tail cannot forge.
        //
        // Existence, not content — see the module doc: demanding zeros here
        // would reject two shapes `bsdtar`, GNU `tar` and Python `tarfile`
        // all accept, and reject them for archives whose every entry is
        // intact.
        let mut second = [0u8; BLOCK];
        let present = self.read_block(&mut second)?;
        if present < BLOCK {
            return Err(Error::Corrupt(if stopped_on_a_zero_block {
                format!(
                    "tar stream ends {present} bytes into the second block of its \
                     end-of-archive marker, after {consumed} bytes; a tar terminates with \
                     two whole {BLOCK}-byte blocks, so the archive is truncated"
                )
            } else {
                format!(
                    "tar stream ran out after {consumed} bytes with no end-of-archive \
                     marker; a tar terminates with two zero blocks, so the archive is \
                     truncated"
                )
            }));
        }

        // Whatever follows is ignored, exactly as every tar tool ignores it:
        // padding to a blocking factor, a concatenated archive, or junk.
        // Nothing beyond this point can change the answer, which is why
        // there is no drain here.
        Ok(())
    }

    /// Fills `buf` from the source, returning how many bytes were actually
    /// available. Short only at end of stream.
    fn read_block(&self, buf: &mut [u8]) -> Result<usize> {
        let mut source = self.source.lock().expect("tar source mutex poisoned");
        let mut filled = 0;
        while filled < buf.len() {
            match source
                .read(&mut buf[filled..])
                .map_err(classify_tar_error)?
            {
                0 => break,
                n => filled += n,
            }
        }
        Ok(filled)
    }
}

impl ArchiveRead for TarRead {
    fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
        if self.ended {
            return Ok(None);
        }
        let iter = self
            .entries
            .as_mut()
            .expect("TarRead::entries is only taken in Drop");
        let Some(next) = iter.next() else {
            self.ended = true;
            // tar cannot tell "the archive ended" from "the stream ran out",
            // so this does — see the module doc's point 4.2.
            self.verify_end_of_archive()?;
            return Ok(None);
        };
        let raw = next.map_err(classify_tar_error)?;
        let meta = entry_meta(&raw);
        let payload = EntryPayload {
            remaining: raw.size(),
            entry: raw,
            name: meta.name.clone(),
        };
        Ok(Some(Entry::new(
            meta,
            Box::new(NormalizeDecodeErrors::new(payload, TAR_MALFORMED_AS_OTHER)),
        )))
    }

    /// tar has no entry index, on any source.
    ///
    /// Two errors rather than one, because they say different true things.
    /// Over a forward-only source the answer harness property 6 pins is
    /// `NotSeekable` — the ladder could not supply random access. Over a
    /// seekable one that would be a lie in both halves ("input is not
    /// seekable and `tar` requires random access"): the input IS seekable and
    /// tar does not require seeking for anything. What is true there is that
    /// the FORMAT has nowhere to index from — reaching entry N means walking
    /// entries 0..N, which is not random access however it is dressed up — so
    /// that case is `Unsupported`. Nothing in `ops` calls this; the shape
    /// exists so a later caller gets an honest refusal rather than a re-scan
    /// billed as an index.
    fn by_index(&mut self, index: usize) -> Result<Entry<'_>> {
        if self.seekable {
            return Err(Error::Unsupported(format!(
                "tar carries no entry index, so entry {index} can only be reached by reading \
                 forward from the start"
            )));
        }
        Err(Error::NotSeekable { format: TAR })
    }

    fn fidelity(&self) -> &FidelityReport {
        &self.report
    }
}

/// One entry's payload, with the short-read guard tar itself does not have.
///
/// Not `Send`, and it cannot be made so: it holds a `tar::Entry`, which holds
/// `&Archive<dyn Read>` over a `RefCell`, and `&T: Send` requires `T: Sync`.
/// This is the type that made `stuffr_core::Entry` drop the `Send` bound on
/// its reader rather than have every container built on the `tar` crate
/// assert `unsafe impl Send` for a property that is false — see `Entry`'s own
/// doc in `archive.rs`.
struct EntryPayload<'a> {
    entry: tar::Entry<'a, TrailerWatch>,
    /// Payload bytes the entry's own header promised and has not delivered.
    remaining: u64,
    /// Kept for the error message: a corrupt archive should say WHICH entry.
    name: String,
}

impl Read for EntryPayload<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // `Read`'s contract: an empty buffer reads nothing and is not an
        // error. Without this the short-read guard below cannot tell "the
        // stream ended" from "you gave me nowhere to put bytes" and reports
        // an intact archive as truncated. `io::copy` and `read_to_end` never
        // pass an empty slice, so nothing in this tree trips it — a caller
        // draining into a full fixed buffer would.
        if buf.is_empty() {
            return Ok(0);
        }
        let n = self.entry.read(buf)?;
        if n == 0 && self.remaining > 0 {
            // tar's own reader is a `Take` over the source, so a stream that
            // ran out mid-payload reports `Ok(0)` — a short read that looks
            // like a complete entry. The header said otherwise.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "entry `{}` is {} bytes short of the size its header declares; \
                     the archive is truncated",
                    self.name, self.remaining
                ),
            ));
        }
        self.remaining = self.remaining.saturating_sub(n as u64);
        Ok(n)
    }
}

/// Whether this entry type holds ordinary file contents.
///
/// Wider than `EntryType::is_file()`, which is `== Regular` alone and would
/// report the other two as `EntryKind::Other` — which `ops` would then skip
/// on extraction, silently dropping real files:
///
/// * `Continuous` (typeflag `7`) is a regular file on the systems that ever
///   wrote it, and every tar tool treats it as one.
/// * `GNUSparse` (typeflag `S`) is a sparse regular file. tar has already
///   expanded its block map by the time this is called, so the entry reads
///   back as its full logical contents, holes included.
///
/// The legacy NUL typeflag needs no case of its own: `EntryType::new` maps
/// both `\0` and `0` to `Regular`.
fn is_regular_file(entry_type: tar::EntryType) -> bool {
    entry_type.is_file() || entry_type.is_gnu_sparse() || entry_type == tar::EntryType::Continuous
}

/// Everything this container reports about one entry, read from the header
/// tar has already parsed (including GNU long names and PAX overrides).
///
/// Names come from `path_bytes`, not `path()`: the latter fails on a
/// non-UTF-8 name on Windows, and `EntryMeta::name` is a `String` either way,
/// so a lossy conversion is the most this layer can carry. Names are NOT
/// sanitised — see harness property 12; refusal is the ops layer's job and it
/// can only refuse what it can still see.
fn entry_meta(entry: &tar::Entry<'_, TrailerWatch>) -> EntryMeta {
    let header = entry.header();
    let entry_type = header.entry_type();
    let kind = if entry_type.is_dir() {
        EntryKind::Dir
    } else if entry_type.is_symlink() {
        EntryKind::Symlink {
            target: entry
                .link_name_bytes()
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default(),
        }
    } else if is_regular_file(entry_type) {
        EntryKind::File
    } else {
        // Hardlinks, devices, FIFOs. `EntryKind` gains variants for these in
        // a later phase; until then `Other` is the honest answer and is not
        // silently turned into a regular file.
        EntryKind::Other
    };

    EntryMeta {
        name: String::from_utf8_lossy(&entry.path_bytes()).into_owned(),
        size: Some(entry.size()),
        mtime: header
            .mtime()
            .ok()
            .map(|secs| UNIX_EPOCH + Duration::from_secs(secs)),
        mode: header.mode().ok(),
        uid: header.uid().ok().and_then(|v| u32::try_from(v).ok()),
        gid: header.gid().ok().and_then(|v| u32::try_from(v).ok()),
        kind,
        ..Default::default()
    }
}

struct TarWrite {
    /// `None` once `finish` has consumed it. `Option` rather than a
    /// consuming call chain because `ArchiveWrite::add` takes `&mut self`.
    builder: Option<tar::Builder<Box<dyn Write + Send>>>,
}

impl TarWrite {
    fn builder(&mut self) -> Result<&mut tar::Builder<Box<dyn Write + Send>>> {
        self.builder
            .as_mut()
            .ok_or_else(|| Error::Usage("tar writer used after finish()".into()))
    }
}

impl ArchiveWrite for TarWrite {
    fn add(&mut self, meta: &EntryMeta, data: &mut dyn Read) -> Result<()> {
        let builder = self.builder()?;

        // GNU headers so long names and large sizes work without the caller
        // having to care; ustar's 100-byte name limit would otherwise refuse
        // ordinary deep paths.
        let mut header = tar::Header::new_gnu();
        let default_mode = match meta.kind {
            EntryKind::Dir => DEFAULT_DIR_MODE,
            _ => DEFAULT_MODE,
        };
        header.set_mode(meta.mode.unwrap_or(default_mode));
        header.set_uid(meta.uid.unwrap_or(0).into());
        header.set_gid(meta.gid.unwrap_or(0).into());
        header.set_mtime(meta.mtime.map(unix_seconds).unwrap_or(0));
        header.set_entry_type(match meta.kind {
            EntryKind::Dir => tar::EntryType::Directory,
            EntryKind::Symlink { .. } => tar::EntryType::Symlink,
            // `EntryKind::Other` — a hardlink, device or FIFO read out of
            // some other archive — is written as a regular file, because
            // that is all `EntryKind` can currently express about it. The
            // fidelity to recover here is in `EntryKind`'s own missing
            // variants (see `archive.rs`), not in this match.
            _ => tar::EntryType::Regular,
        });

        // The name is written into the header field directly rather than
        // through `Builder::append_data`, which routes through
        // `Header::set_path` and REFUSES exactly the names harness property
        // 12 requires stored: "paths in archives must not have `..`" and
        // "paths in archives must be relative". A container that refused
        // them, or quietly rewrote them, would destroy the evidence the
        // ops-layer refusal depends on. The GNU long-name extension that
        // `append_data` would have emitted for us is emitted here instead.
        //
        // Name before link target, matching the order `tar::Builder`'s own
        // `append_fs` emits the two extension entries in when both are
        // needed (`prepare_header_path`, then `prepare_header_link`).
        set_header_field(builder, &mut header, Field::Name, meta.name.as_bytes())?;
        if let EntryKind::Symlink { target } = &meta.kind {
            set_header_field(builder, &mut header, Field::LinkName, target.as_bytes())?;
        }

        // A directory or symlink entry has no payload to frame: its target,
        // where it has one, lives in the header. Any reader handed for such
        // an entry is not consumed, and the size is written as zero whatever
        // the caller declared.
        if matches!(meta.kind, EntryKind::Dir | EntryKind::Symlink { .. }) {
            header.set_size(0);
            header.set_cksum();
            return builder.append(&header, io::empty()).map_err(Error::from);
        }

        match meta.size {
            // Streamed, then verified. `tar::Builder::append` pads from the
            // bytes it actually copied while the reader frames from the
            // header, so a wrong size yields a structurally valid tar with
            // mis-framed contents. Refusing mid-write leaves a broken
            // archive behind, which is why `ops` writes to a temp file and
            // promotes it only on success.
            Some(size) => {
                header.set_size(size);
                header.set_cksum();
                let mut counted = CountingReader {
                    inner: data,
                    read: 0,
                };
                builder.append(&header, &mut counted)?;
                if counted.read != size {
                    return Err(Error::Usage(format!(
                        "entry `{}` declared a size of {size} bytes but supplied {}; \
                         the resulting archive would be mis-framed",
                        meta.name, counted.read
                    )));
                }
                Ok(())
            }
            // The caller does not know the length — reading from a pipe, for
            // instance — so measure it. Buffering is the cost of a size
            // field that precedes its data: nothing else can be written
            // until the length is known.
            None => {
                let mut buffered = Vec::new();
                data.read_to_end(&mut buffered)?;
                header.set_size(buffered.len() as u64);
                header.set_cksum();
                builder.append(&header, &buffered[..]).map_err(Error::from)
            }
        }
    }

    /// Writes the two zero blocks that terminate a tar, then flushes.
    ///
    /// Never via `Drop`: `tar::Builder`'s own `Drop` finishes the archive and
    /// discards any error, which is the hazard harness property 4 exists to
    /// catch. Dropping a `TarWrite` that was never finished still produces a
    /// terminated archive — that is tar's behaviour, not this module's — but
    /// nothing reports whether it worked, so `finish` is the only path a
    /// caller may rely on.
    fn finish(mut self: Box<Self>) -> Result<()> {
        let builder = self
            .builder
            .take()
            .ok_or_else(|| Error::Usage("tar writer finished twice".into()))?;
        // `into_inner` writes the trailer, then hands the destination back.
        // The caller gave it to us by value at `Container::create` and has no
        // other handle left to flush it, so that is done here.
        let mut dst = builder.into_inner()?;
        dst.flush()?;
        Ok(())
    }
}

/// Which fixed-width header field [`set_header_field`] is filling, and which
/// GNU extension type carries an over-long value for it.
#[derive(Clone, Copy)]
enum Field {
    Name,
    LinkName,
}

impl Field {
    /// The GNU extension typeflag that carries an over-long value: `L` for a
    /// name, `K` for a link target.
    fn long_typeflag(self) -> u8 {
        match self {
            Field::Name => b'L',
            Field::LinkName => b'K',
        }
    }
}

/// Writes `value` into one of `header`'s fixed 100-byte fields, emitting the
/// GNU extension entry first when it does not fit.
///
/// Mirrors `tar::Builder`'s own private `prepare_header`/`prepare_header_path`
/// pair, which is unreachable from outside the crate, and is what lets this
/// container store a name tar's public API refuses (see `add`).
fn set_header_field(
    builder: &mut tar::Builder<Box<dyn Write + Send>>,
    header: &mut tar::Header,
    field: Field,
    value: &[u8],
) -> Result<()> {
    if value.len() > NAME_FIELD {
        let mut long = tar::Header::new_gnu();
        fill(header_field(&mut long, Field::Name), b"././@LongLink");
        long.set_mode(DEFAULT_MODE);
        long.set_uid(0);
        long.set_gid(0);
        long.set_mtime(0);
        // + 1 for the trailing NUL, to be compliant with GNU tar.
        long.set_size(value.len() as u64 + 1);
        long.set_entry_type(tar::EntryType::new(field.long_typeflag()));
        long.set_cksum();
        let mut data = value.chain(io::repeat(0).take(1));
        builder.append(&long, &mut data)?;
    }
    // The truncated copy still goes in the real header: GNU tar puts one
    // there too, and a reader that does not understand the extension then
    // sees something rather than an empty name.
    fill(header_field(header, field), value);
    Ok(())
}

/// The header field `field` names. The `expect` is unreachable: every header
/// in this module comes from `Header::new_gnu`, which sets the GNU magic
/// `as_gnu_mut` checks for.
fn header_field(header: &mut tar::Header, field: Field) -> &mut [u8] {
    let gnu = header
        .as_gnu_mut()
        .expect("every header written here comes from Header::new_gnu");
    match field {
        Field::Name => &mut gnu.name,
        Field::LinkName => &mut gnu.linkname,
    }
}

/// Copies as much of `value` as fits into `slot`, NUL-padding the rest.
fn fill(slot: &mut [u8], value: &[u8]) {
    let n = value.len().min(slot.len());
    slot[..n].copy_from_slice(&value[..n]);
    slot[n..].fill(0);
}

/// Seconds since the epoch, which is what a tar header stores. A timestamp
/// before 1970 clamps to zero rather than failing the write: tar's field is
/// unsigned, and refusing to archive a file because of its mtime would be a
/// worse answer than recording the epoch.
fn unix_seconds(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Counts what it passes through, so `add` can check a declared size against
/// the data actually supplied.
struct CountingReader<'a> {
    inner: &'a mut dyn Read,
    read: u64,
}

impl Read for CountingReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read += n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stuffr_core::testing::{SharedBuf, assert_container_conforms, open_forward_only};
    use stuffr_core::{
        ArchiveRead, CreateOpts, EntryKind, EntryMeta, OpenOpts, ReaderSource, Rung, Source,
        StreamPolicy,
    };

    /// Writes `entries` through `Tar` itself and returns the archive bytes —
    /// the same path `stuffr pack` takes, not a hand-rolled tar.
    fn build_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let buf = SharedBuf::new();
        let mut w = Tar
            .create(Box::new(buf.clone()), &CreateOpts::default())
            .expect("create");
        for (name, data) in entries {
            w.add(&EntryMeta::file(*name), &mut std::io::Cursor::new(*data))
                .expect("add");
        }
        w.finish().expect("finish");
        buf.contents()
    }

    /// Reads every entry back through the ladder over a NON-seekable source,
    /// which is what `ReaderSource` models.
    fn read_back(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut ar = open(bytes);
        let mut out = Vec::new();
        while let Some(mut entry) = ar.next_entry().expect("next_entry") {
            let name = entry.meta().name.clone();
            let mut data = Vec::new();
            entry.reader().read_to_end(&mut data).expect("entry read");
            out.push((name, data));
        }
        out
    }

    fn open(bytes: &[u8]) -> Box<dyn ArchiveRead> {
        let src: Box<dyn Source> =
            Box::new(ReaderSource::new(std::io::Cursor::new(bytes.to_vec())));
        let resolved =
            stuffr_core::resolve(src, TAR, Tar.caps(), &StreamPolicy::default()).expect("resolve");
        Tar.open(resolved, &OpenOpts::default()).expect("open")
    }

    fn which(bin: &str) -> Option<std::path::PathBuf> {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path).find_map(|dir| {
            let candidate = dir.join(bin);
            candidate.is_file().then_some(candidate)
        })
    }

    #[test]
    fn tar_conforms() {
        assert_container_conforms(&Tar, &meta());
    }

    /// The rung and the losses are two different questions, and a piped tar
    /// answers them differently: it lands on `ForwardOnly` — a pipe is not
    /// seekable, and that is all the rung claims — while losing NOTHING,
    /// because tar has no trailing index for a forward read to skip. Both
    /// halves are asserted here: the rung alone would miss the point, and so
    /// would the warnings alone.
    ///
    /// The second half is the one with teeth. `--strict-fidelity` gates on
    /// `has_warnings()`, not on the rung (see `FidelityReport::has_warnings`,
    /// which uses this exact case as its worked example), so a warning raised
    /// here would fail `stuffr test --strict-fidelity` for every tarball
    /// arriving on a pipe — an error a script could do nothing about.
    #[test]
    fn tar_reports_forward_only_on_a_pipe_but_warns_about_nothing() {
        let bytes = build_tar(&[("a.txt", b"alpha")]);
        let ar = open_forward_only(&Tar, &bytes);
        assert_eq!(
            ar.fidelity().rung,
            Rung::ForwardOnly,
            "a pipe is not seekable, and the rung describes the access path"
        );
        assert!(
            !ar.fidelity().has_warnings(),
            "a forward tar read skips no authoritative structure, so it must raise no \
             fidelity warning — --strict-fidelity gates on exactly this"
        );

        // The seekable shape, for contrast: same absence of warnings, higher
        // rung. Without this the assertion above could be passing because
        // nothing ever reports Exact.
        let seekable = open_seekable(&bytes);
        assert_eq!(seekable.fidelity().rung, Rung::Exact);
        assert!(!seekable.fidelity().has_warnings());
    }

    #[test]
    fn capabilities_and_metadata_match_the_format() {
        let c = Tar.caps();
        assert!(c.read && c.write && c.forward_parse);
        assert!(
            !c.trailing_index && !c.per_entry_codec && !c.solid && !c.needs_seek,
            "tar has no index, no per-entry codec and no solid blocks"
        );
        let m = meta();
        assert_eq!(m.id, TAR);
        assert_eq!(m.extensions, &["tar"]);
    }

    /// `ustar` at offset 257 — the registered rule, checked against real
    /// output rather than against the constant.
    #[test]
    fn output_carries_the_ustar_magic_at_offset_257() {
        let bytes = build_tar(&[("a.txt", b"alpha")]);
        assert_eq!(&bytes[257..262], b"ustar");
    }

    /// A cut inside an entry's payload, which is the case harness property 9
    /// could not reach before Task 7 extended it. Asserted here as well
    /// because tar's own backend does NOT raise anything for it: a `Take`
    /// over the source returns `Ok(0)` at end of stream, so the short read
    /// looks like a complete entry.
    #[test]
    fn a_cut_inside_an_entry_payload_is_reported_as_corrupt() {
        let payload = stuffr_core::testing::incompressible(64 * 1024);
        let bytes = build_tar(&[("big.bin", &payload)]);
        // 512-byte header, then the payload: any offset in 512..512+65536 is
        // inside the entry's data.
        for cut in [513usize, 1024, 32768, 512 + 65536 - 1] {
            let mut ar = open(&bytes[..cut]);
            let mut err = None;
            loop {
                match ar.next_entry() {
                    Ok(Some(mut entry)) => {
                        let mut sink = Vec::new();
                        if let Err(e) = entry.reader().read_to_end(&mut sink) {
                            // `Error::from_decode_io` is the classification
                            // every caller applies to an io error raised
                            // while decoding — `InvalidData` is what has to
                            // arrive for it to reach exit 5.
                            err = Some(stuffr_core::Error::from_decode_io(e));
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        err = Some(e);
                        break;
                    }
                }
            }
            let Some(err) = err else {
                panic!("a cut at {cut} inside the entry payload was accepted silently")
            };
            assert_eq!(
                err.exit_code(),
                5,
                "a payload cut must be Corrupt (exit 5), got {err:?}"
            );
        }
    }

    /// Cross-implementation arbiter, the precedent being system `xz`
    /// validating what `lzma-rust2` writes. Skips cleanly when absent; CI
    /// installs it so this does not silently no-op (Phase 1e, Finding 8).
    #[test]
    fn system_tar_accepts_what_we_write() {
        let Some(tar_bin) = which("tar") else { return };
        // The long name is here rather than in a test of its own because
        // this module writes the GNU LongName ('L') extension entry by hand
        // (`Builder::append_data`, which would do it for us, refuses the
        // names property 12 requires) — so a reference tool reading it back
        // is the only independent evidence that framing is right.
        let long_name: String = std::iter::repeat_n("long-name-segment/", 20).collect();
        let bytes = build_tar(&[
            ("a.txt", b"alpha"),
            ("dir/b.bin", b"\x00\xff\x00"),
            (&long_name, b"deep"),
        ]);

        let path =
            std::env::temp_dir().join(format!("stuffr-tar-crossimpl-{}.tar", std::process::id()));
        std::fs::write(&path, &bytes).unwrap();

        let listed = std::process::Command::new(&tar_bin)
            .arg("-tf")
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            listed.status.success(),
            "system tar rejected our archive: {}",
            String::from_utf8_lossy(&listed.stderr)
        );
        let listing = String::from_utf8_lossy(&listed.stdout);
        assert!(listing.contains("a.txt"), "listing was {listing:?}");
        assert!(listing.contains("dir/b.bin"), "listing was {listing:?}");
        assert!(
            listing.contains(long_name.as_str()),
            "system tar did not read back our hand-written GNU long name; listing was \
             {listing:?}"
        );

        // Listing proves the framing; extracting to stdout proves the DATA.
        let cat = std::process::Command::new(&tar_bin)
            .arg("-xOf")
            .arg(&path)
            .arg("a.txt")
            .output()
            .unwrap();
        assert!(cat.status.success(), "system tar could not extract a.txt");
        assert_eq!(cat.stdout, b"alpha");

        let _ = std::fs::remove_file(&path);
    }

    /// The end-of-archive marker, which `tar`'s own reader never inspects:
    /// it stops at the FIRST zero block and treats a stream that simply ran
    /// out as a clean ending. Both rules here were calibrated against
    /// reference tools rather than invented — see the module doc's point 4.2
    /// — and this is the case harness property 9's framing cuts reach only
    /// by accident.
    #[test]
    fn a_missing_or_partial_end_of_archive_marker_is_refused() {
        let full = build_tar(&[("a.txt", b"alpha"), ("b.txt", b"beta")]);
        // header, payload, header, payload, then 1024 zero bytes.
        assert_eq!(
            full.len(),
            3072,
            "the fixture's layout is what pins the cuts"
        );

        // The third column is the DIAGNOSIS the error must carry. It is the
        // only thing that exercises `stopped_on_a_zero_block`, which is not
        // a detection condition (see `verify_end_of_archive`): asserting
        // exit 5 alone would leave it unfalsifiable, as a mutation check
        // showed it was.
        let cases = [
            (
                2048usize,
                "no marker at all",
                "with no end-of-archive marker",
            ),
            (
                2560,
                "a lone zero block",
                "ends 0 bytes into the second block",
            ),
            (
                3071,
                "a marker one byte short of complete",
                "ends 511 bytes into the second block",
            ),
        ];
        for (cut, what, diagnosis) in cases {
            let mut ar = open(&full[..cut]);
            // Both entries read back intact — the damage is entirely in the
            // trailer, so nothing before it may be affected.
            for expected in ["a.txt", "b.txt"] {
                let mut entry = ar
                    .next_entry()
                    .unwrap_or_else(|e| panic!("{what}: {e}"))
                    .unwrap_or_else(|| panic!("{what}: expected {expected}"));
                assert_eq!(entry.meta().name, expected, "{what}");
                let mut data = Vec::new();
                entry.reader().read_to_end(&mut data).unwrap();
            }
            let err = ar
                .next_entry()
                .expect_err(&format!("{what} was accepted as a complete archive"));
            assert_eq!(err.exit_code(), 5, "{what}: {err}");
            assert!(
                err.to_string().contains(diagnosis),
                "{what}: the error must say which ending it was — expected it to mention \
                 {diagnosis:?}, got {err}"
            );
        }

        // The whole marker present is accepted, so the rules above cannot be
        // passing by refusing everything.
        let mut ar = open(&full);
        while ar
            .next_entry()
            .expect("a complete archive must read")
            .is_some()
        {}
    }

    /// The false negative the review reproduced: an entry whose PAYLOAD ends
    /// in zeros, with the marker entirely removed, used to read back as
    /// clean and complete. The old rule looked at the end of the whole
    /// stream, where a 1024-byte zero run is a 1024-byte zero run whoever
    /// wrote it; the rule now looks at tar's stop position, where the
    /// question is whether tar READ a marker block, and a payload tail
    /// cannot answer yes.
    ///
    /// Both zero-tail lengths matter. At 1024 the old `trailing_zeros >=
    /// 1024` test was satisfied outright, which is the reproduction; at 512
    /// it was not, so that row confirms the new rule does not merely move
    /// the threshold.
    #[test]
    fn an_all_zero_payload_tail_does_not_pass_for_a_missing_marker() {
        for zeros in [512usize, 1024, 2048] {
            let mut payload = b"real data then a hole: ".to_vec();
            payload.resize(payload.len() + zeros, 0);
            let full = build_tar(&[("sparse-ish.bin", &payload)]);

            // Everything except the 1024-byte marker.
            let headless = &full[..full.len() - 1024];
            assert!(
                headless.len().is_multiple_of(512),
                "zeros={zeros}: the fixture must be block-aligned for this to be the \
                 case under test rather than a misalignment"
            );

            let mut ar = open(headless);
            let mut entry = ar
                .next_entry()
                .expect("the entry itself is intact")
                .unwrap();
            let mut got = Vec::new();
            entry
                .reader()
                .read_to_end(&mut got)
                .expect("the payload is complete; only the marker is gone");
            assert_eq!(got, payload, "zeros={zeros}");
            drop(entry);

            let err = ar.next_entry().expect_err(&format!(
                "zeros={zeros}: an archive with no end-of-archive marker was accepted \
                 because its payload happened to end in zeros"
            ));
            assert_eq!(err.exit_code(), 5, "zeros={zeros}: {err}");
        }
    }

    /// The accept side of the end-of-archive rules, pinned so a future
    /// tightening cannot quietly start rejecting input every reference tool
    /// reads. Measured against `bsdtar` 3.5.3, GNU `tar` and Python
    /// `tarfile`: all three accept every fixture below, and an earlier
    /// version of this module rejected the first four with
    /// "…not a whole number of 512-byte blocks; the archive is truncated" —
    /// a claim of truncation about a stream LONGER than the archive.
    #[test]
    fn trailing_bytes_after_a_complete_marker_are_ignored() {
        let complete = build_tar(&[("a.txt", b"alpha"), ("b.txt", b"beta")]);

        let cases: [(&str, Vec<u8>); 6] = [
            ("nothing", vec![]),
            ("one byte", b"\n".to_vec()),
            ("20 bytes of junk", vec![b'X'; 20]),
            ("a whole block of junk", vec![b'X'; 512]),
            ("a partial block of junk", vec![b'X'; 200]),
            (
                "zero padding to a 10240-byte record",
                vec![0u8; 10240 - complete.len()],
            ),
        ];

        for (what, tail) in cases {
            let mut bytes = complete.clone();
            bytes.extend_from_slice(&tail);
            let got = read_back(&bytes);
            assert_eq!(
                got.len(),
                2,
                "{what}: trailing bytes after a complete marker must be ignored, not \
                 reported as damage"
            );
            assert_eq!(got[0].0, "a.txt", "{what}");
            assert_eq!(got[1].0, "b.txt", "{what}");
        }

        // One zero block followed by a NON-zero block. All three reference
        // tools accept this (GNU `tar` warns "A lone zero block"), and every
        // entry in it is intact — which is why rule (b) asks whether a
        // second block exists rather than whether it is zero.
        let mut lone_then_junk = complete[..complete.len() - 1024].to_vec();
        lone_then_junk.extend_from_slice(&[0u8; 512]);
        lone_then_junk.extend_from_slice(&[b'X'; 512]);
        let got = read_back(&lone_then_junk);
        assert_eq!(
            got.len(),
            2,
            "a non-zero second block must not be treated as damage: every reference tool \
             reads this archive whole"
        );
    }

    /// `Read`'s contract: an empty buffer reads nothing and is not an error.
    /// The short-read guard cannot distinguish "the stream ended" from "you
    /// gave me nowhere to put bytes" on its own, so an intact archive used
    /// to report itself truncated to a caller draining into a full buffer.
    /// `io::copy` and `read_to_end` never pass an empty slice, which is why
    /// nothing else in this tree noticed.
    #[test]
    fn reading_an_entry_into_an_empty_buffer_is_not_an_error() {
        let bytes = build_tar(&[("a.txt", b"alpha")]);
        let mut ar = open(&bytes);
        let mut entry = ar.next_entry().unwrap().unwrap();

        assert_eq!(
            entry
                .reader()
                .read(&mut [])
                .expect("an empty buffer must not error"),
            0
        );

        // …and the entry is undisturbed by it.
        let mut got = Vec::new();
        entry.reader().read_to_end(&mut got).unwrap();
        assert_eq!(&got[..], b"alpha");
    }

    /// Concatenated tars — `cat a.tar b.tar`, which every reference tool
    /// reads as just `a.tar`'s entries — must not be caught by the trailer
    /// rules above. They look at the end of the WHOLE stream, which is
    /// `b.tar`'s own marker.
    #[test]
    fn a_concatenated_archive_still_reads_as_its_first_member() {
        let mut both = build_tar(&[("a.txt", b"alpha")]);
        both.extend_from_slice(&build_tar(&[("b.txt", b"beta")]));
        let got = read_back(&both);
        assert_eq!(
            got.len(),
            1,
            "tar stops at the first marker, as tar tools do"
        );
        assert_eq!(got[0].0, "a.txt");
    }

    /// The arbiter in the other direction, which matters more than it looks:
    /// `system_tar_accepts_what_we_write` only proves our writer and our
    /// reader agree with the system tool about archives WE framed. A system
    /// tar writes ustar-or-GNU headers of its own choosing, pads to its own
    /// blocking factor and (on macOS) interleaves AppleDouble `._x` entries
    /// — and the end-of-archive rules this module added are strict enough
    /// that getting them wrong would reject ordinary real archives. So the
    /// entries are checked as a SUBSET rather than an exact list: what
    /// matters is that the read completes and the data is right.
    #[test]
    fn we_accept_what_system_tar_writes() {
        let Some(tar_bin) = which("tar") else { return };

        let dir = std::env::temp_dir().join(format!("stuffr-tar-reverse-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("a.txt"), b"alpha").unwrap();
        std::fs::write(dir.join("sub/b.bin"), vec![0xABu8; 5000]).unwrap();

        let archive = dir.join("made-by-system-tar.tar");
        let status = std::process::Command::new(&tar_bin)
            .arg("-cf")
            .arg(&archive)
            .arg("-C")
            .arg(&dir)
            .arg("a.txt")
            .arg("sub")
            .status()
            .unwrap();
        assert!(status.success(), "system tar could not write the fixture");

        let got = read_back(&std::fs::read(&archive).unwrap());
        let find = |name: &str| {
            got.iter().find(|(n, _)| n == name).unwrap_or_else(|| {
                panic!(
                    "{name} missing from {:?}",
                    got.iter().map(|(n, _)| n).collect::<Vec<_>>()
                )
            })
        };
        assert_eq!(&find("a.txt").1[..], b"alpha");
        assert_eq!(find("sub/b.bin").1, vec![0xABu8; 5000]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The false-positive guard on the end-of-archive rules, which are
    /// stricter than the `tar` crate's own: every reference writer available
    /// must be accepted, and the EMPTY archive from each is the shape most
    /// likely to look like a missing marker, since it is nothing BUT a
    /// marker.
    ///
    /// Three writers, each skipped cleanly when absent, because they pad
    /// differently and the difference is the point — measured on this
    /// machine: `bsdtar` writes an empty archive as exactly 1024 bytes (the
    /// bare marker, the tightest case these rules can face), while GNU `tar`
    /// and Python `tarfile` both pad to a 10240-byte record. A rule that was
    /// even slightly wrong about alignment or about how many zero blocks it
    /// demands would reject one of these.
    ///
    /// This is the check Task 5's finding calls for: a refusal that fires on
    /// ubiquitous benign input is worse than no refusal, because it trains
    /// users to bypass the one control that matters.
    #[test]
    fn every_reference_writer_is_accepted_including_its_empty_archive() {
        let dir = std::env::temp_dir().join(format!("stuffr-tar-writers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"alpha").unwrap();

        let mut writers_tried = 0;

        // `tar` is whichever the platform ships (bsdtar on macOS, GNU on the
        // CI runner); `gtar` is GNU where a BSD one is the default. Both are
        // listed so a machine with either or both covers as much as it can.
        for bin in ["tar", "gtar"] {
            let Some(tar_bin) = which(bin) else { continue };
            writers_tried += 1;

            let empty = dir.join(format!("{bin}-empty.tar"));
            let status = std::process::Command::new(&tar_bin)
                .arg("-cf")
                .arg(&empty)
                .args(["-T", "/dev/null"])
                .status()
                .unwrap();
            assert!(status.success(), "{bin} could not write an empty archive");
            assert!(
                read_back(&std::fs::read(&empty).unwrap()).is_empty(),
                "{bin}'s empty archive must read back as zero entries, not an error"
            );

            let one = dir.join(format!("{bin}-one.tar"));
            let status = std::process::Command::new(&tar_bin)
                .arg("-cf")
                .arg(&one)
                .arg("-C")
                .arg(&dir)
                .arg("a.txt")
                .status()
                .unwrap();
            assert!(
                status.success(),
                "{bin} could not write a one-entry archive"
            );
            let got = read_back(&std::fs::read(&one).unwrap());
            assert!(
                got.iter().any(|(n, d)| n == "a.txt" && d == b"alpha"),
                "{bin}'s one-entry archive lost a.txt: {:?}",
                got.iter().map(|(n, _)| n).collect::<Vec<_>>()
            );
        }

        // Python's `tarfile`, the third independent implementation — and the
        // one this project already uses as a reference arbiter in `gzip.rs`.
        if let Some(python) = which("python3") {
            writers_tried += 1;
            let script = format!(
                "import tarfile\n\
                 tarfile.open({empty:?}, 'w').close()\n\
                 t = tarfile.open({one:?}, 'w')\n\
                 t.add({src:?}, arcname='a.txt')\n\
                 t.close()\n",
                empty = dir.join("python-empty.tar").to_str().unwrap(),
                one = dir.join("python-one.tar").to_str().unwrap(),
                src = dir.join("a.txt").to_str().unwrap(),
            );
            let out = std::process::Command::new(&python)
                .arg("-c")
                .arg(&script)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "python tarfile could not write the fixtures: {}",
                String::from_utf8_lossy(&out.stderr)
            );

            let empty = std::fs::read(dir.join("python-empty.tar")).unwrap();
            assert!(
                read_back(&empty).is_empty(),
                "python tarfile's empty archive ({} bytes) must read back as zero entries",
                empty.len()
            );
            let got = read_back(&std::fs::read(dir.join("python-one.tar")).unwrap());
            assert!(
                got.iter().any(|(n, d)| n == "a.txt" && d == b"alpha"),
                "python tarfile's one-entry archive lost a.txt: {:?}",
                got.iter().map(|(n, _)| n).collect::<Vec<_>>()
            );
        }

        assert!(
            writers_tried > 0,
            "no reference tar writer found at all — this test proved nothing, which is \
             worth knowing rather than passing silently"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The dormant `.tar.gz` / `.tgz` resolution in `probe.rs` was gated on
    /// `reg.container(id).is_some()` and returned `Chain::Raw` because no
    /// container existed. Registering tar is the whole change — nothing in
    /// `probe.rs` was touched.
    #[test]
    #[cfg(feature = "gzip")]
    fn tar_gz_and_tgz_now_resolve_to_tar_over_gzip() {
        use stuffr_core::{Chain, Registry};

        let mut reg = Registry::new();
        crate::register_all(&mut reg);

        let gzip_magic = [0x1fu8, 0x8b, 0x08, 0x00];
        for name in ["bundle.tar.gz", "bundle.tgz"] {
            let chain =
                stuffr_core::resolve_chain(&reg, Some(std::path::Path::new(name)), &gzip_magic)
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
            match &chain {
                Chain::Codec { codec, inner } => {
                    assert_eq!(*codec, crate::gzip::GZIP, "{name}");
                    assert!(
                        matches!(**inner, Chain::Container { container } if container == TAR),
                        "{name} resolved to {chain:?}, expected tar inside gzip"
                    );
                }
                other => panic!("{name} resolved to {other:?}, expected a codec over a container"),
            }
            assert_eq!(chain.describe(), "tar over gzip", "{name}");
        }
    }

    /// Names tar's own `Builder` refuses outright — `set_path` rejects `..`
    /// ("paths in archives must not have `..`") and absolute paths ("paths in
    /// archives must be relative"). Harness property 12 requires them stored
    /// and reported VERBATIM, because the ops layer can only refuse what it
    /// can still see, so this writer sets the header's name field itself.
    #[test]
    fn hostile_names_are_stored_verbatim_rather_than_refused_or_rewritten() {
        for name in ["../../etc/passwd", "/abs/path", "a/../../b", "./"] {
            let bytes = build_tar(&[(name, b"x")]);
            let got = read_back(&bytes);
            assert_eq!(got.len(), 1, "{name}");
            assert_eq!(got[0].0, name, "{name} came back as {:?}", got[0].0);
        }
    }

    /// A name past the 100-byte `name` field needs a GNU LongName ('L')
    /// extension entry ahead of the real header. Written by hand here for
    /// the same reason the hostile names above are: `Builder::append_data`,
    /// which would do it for us, refuses the names property 12 requires.
    #[test]
    fn a_name_longer_than_the_header_field_round_trips_through_a_gnu_extension() {
        for len in [99usize, 100, 101, 255, 600] {
            let name: String = std::iter::repeat_n('n', len).collect();
            let bytes = build_tar(&[(&name, b"payload")]);
            let got = read_back(&bytes);
            assert_eq!(got.len(), 1, "len={len}");
            assert_eq!(got[0].0.len(), len, "len={len}: name came back truncated");
            assert_eq!(got[0].0, name, "len={len}");
            assert_eq!(&got[0].1[..], b"payload", "len={len}");
        }
    }

    #[test]
    fn directory_and_symlink_entries_round_trip_their_kind_and_target() {
        let buf = SharedBuf::new();
        let mut w = Tar
            .create(Box::new(buf.clone()), &CreateOpts::default())
            .unwrap();

        let mut dir = EntryMeta::file("d/");
        dir.kind = EntryKind::Dir;
        dir.mode = Some(0o750);
        w.add(&dir, &mut std::io::Cursor::new(&[][..])).unwrap();

        let mut link = EntryMeta::file("d/link");
        link.kind = EntryKind::Symlink {
            target: "../target.txt".into(),
        };
        w.add(&link, &mut std::io::Cursor::new(&[][..])).unwrap();

        w.finish().unwrap();

        let mut ar = open(&buf.contents());
        let first = ar.next_entry().unwrap().unwrap();
        assert_eq!(first.meta().name, "d/");
        assert_eq!(first.meta().kind, EntryKind::Dir);
        assert_eq!(first.meta().mode, Some(0o750));
        drop(first);

        let second = ar.next_entry().unwrap().unwrap();
        assert_eq!(second.meta().name, "d/link");
        assert_eq!(
            second.meta().kind,
            EntryKind::Symlink {
                target: "../target.txt".into()
            },
            "a symlink entry that lost its target would extract as an empty file"
        );
    }

    /// `DEFAULT_MODE` (`0o644`) used to be applied to directory entries too:
    /// no owner-execute bit, so a directory whose caller omitted a mode
    /// extracted as one nothing could traverse into. A file entry with no
    /// mode still gets `0o644` — only the directory default changed.
    #[test]
    fn a_directory_entry_with_no_mode_defaults_to_an_executable_one() {
        let buf = SharedBuf::new();
        let mut w = Tar
            .create(Box::new(buf.clone()), &CreateOpts::default())
            .unwrap();

        let mut dir = EntryMeta::file("d/");
        dir.kind = EntryKind::Dir;
        assert_eq!(dir.mode, None, "the point of this test");
        w.add(&dir, &mut std::io::Cursor::new(&[][..])).unwrap();

        let file = EntryMeta::file("f.txt");
        assert_eq!(file.mode, None, "the point of this test");
        w.add(&file, &mut std::io::Cursor::new(b"x".as_slice()))
            .unwrap();

        w.finish().unwrap();

        let mut ar = open(&buf.contents());
        let d = ar.next_entry().unwrap().unwrap();
        assert_eq!(
            d.meta().mode,
            Some(DEFAULT_DIR_MODE),
            "an unset directory mode must default to something traversable"
        );
        drop(d);

        let f = ar.next_entry().unwrap().unwrap();
        assert_eq!(
            f.meta().mode,
            Some(DEFAULT_MODE),
            "a file's own default must be unaffected by the directory fix"
        );
    }

    /// The `Continuous` typeflag (`7`) is a regular file, and `EntryType`'s
    /// own `is_file()` — which is `== Regular` alone — says otherwise. Read
    /// as `EntryKind::Other` it would be skipped on extraction rather than
    /// written, so this pins the widening in `is_regular_file`. Written
    /// through the raw `tar::Builder` because this module's own `add` never
    /// produces that typeflag.
    ///
    /// Its sibling case, `GNUSparse`, is not tested here for want of a
    /// fixture: writing one needs GNU tar's `--sparse`, which is absent from
    /// the CI runner and from macOS, and a hand-built sparse block map would
    /// be testing this test rather than the code.
    #[test]
    fn a_continuous_typeflag_entry_reads_back_as_a_file_not_as_other() {
        let buf = SharedBuf::new();
        let mut builder =
            tar::Builder::new(Box::new(buf.clone()) as Box<dyn std::io::Write + Send>);
        let mut header = tar::Header::new_gnu();
        header.set_path("continuous.dat").unwrap();
        header.set_size(4);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Continuous);
        header.set_cksum();
        builder.append(&header, &b"cont"[..]).unwrap();
        builder.into_inner().unwrap().flush().unwrap();

        let mut ar = open(&buf.contents());
        let mut entry = ar.next_entry().unwrap().unwrap();
        assert_eq!(entry.meta().kind, EntryKind::File);
        let mut data = Vec::new();
        entry.reader().read_to_end(&mut data).unwrap();
        assert_eq!(&data[..], b"cont");
    }

    /// A caller streaming from a pipe does not know the length up front.
    /// `add` must measure it rather than write `size: 0`, which would frame
    /// the entry as empty and silently drop its data.
    #[test]
    fn add_measures_the_payload_when_the_caller_does_not_declare_a_size() {
        let buf = SharedBuf::new();
        let mut w = Tar
            .create(Box::new(buf.clone()), &CreateOpts::default())
            .unwrap();
        let meta = EntryMeta::file("unknown-length.bin");
        assert_eq!(meta.size, None, "the point of this test");
        w.add(
            &meta,
            &mut std::io::Cursor::new(&b"twenty-two bytes long!"[..]),
        )
        .unwrap();
        w.finish().unwrap();

        let got = read_back(&buf.contents());
        assert_eq!(got.len(), 1);
        assert_eq!(&got[0].1[..], b"twenty-two bytes long!");
        assert_eq!(got[0].0, "unknown-length.bin");
    }

    /// A declared size that does not match the data would produce a
    /// structurally valid tar with mis-framed contents — corruption we
    /// generated ourselves — because `tar::Builder::append` pads from the
    /// actual byte count while the reader believes the header.
    #[test]
    fn add_refuses_a_declared_size_that_disagrees_with_the_data() {
        for (declared, data) in [(99u64, &b"short"[..]), (2u64, &b"longer"[..])] {
            let buf = SharedBuf::new();
            let mut w = Tar
                .create(Box::new(buf.clone()), &CreateOpts::default())
                .unwrap();
            let mut meta = EntryMeta::file("liar.bin");
            meta.size = Some(declared);
            let err = w
                .add(&meta, &mut std::io::Cursor::new(data))
                .expect_err("a size that disagrees with the data must be refused");
            assert!(
                err.to_string().contains("liar.bin"),
                "the error must name the entry: {err}"
            );
        }
    }

    /// tar carries no entry index at all, so `by_index` is never random
    /// access. Property 6 pins the forward-only answer; this pins both, so
    /// the seekable case cannot quietly start faking an index.
    #[test]
    fn by_index_is_refused_on_every_source_shape() {
        let bytes = build_tar(&[("a.txt", b"alpha"), ("b.txt", b"beta")]);

        let mut fwd = open_forward_only(&Tar, &bytes);
        assert!(
            matches!(fwd.by_index(0), Err(stuffr_core::Error::NotSeekable { .. })),
            "a forward-only source must answer NotSeekable"
        );

        let mut seekable = open_seekable(&bytes);
        assert!(
            matches!(
                seekable.by_index(0),
                Err(stuffr_core::Error::Unsupported(_))
            ),
            "a seekable source is not the problem — tar has no index to index into"
        );
    }

    /// Opens `bytes` from a real file, which is the only source shape that
    /// reaches the Exact rung by seeking rather than by tar's own promotion.
    fn open_seekable(bytes: &[u8]) -> Box<dyn ArchiveRead> {
        let path = std::env::temp_dir().join(format!(
            "stuffr-tar-seekable-{}-{:p}.tar",
            std::process::id(),
            bytes
        ));
        std::fs::write(&path, bytes).unwrap();
        let src: Box<dyn Source> = Box::new(stuffr_core::FileSource::open(&path).unwrap());
        let _ = std::fs::remove_file(&path);
        let resolved =
            stuffr_core::resolve(src, TAR, Tar.caps(), &StreamPolicy::default()).expect("resolve");
        Tar.open(resolved, &OpenOpts::default()).expect("open")
    }
}
