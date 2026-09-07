//! tar, via the `tar` crate — the first container in this tree, and the
//! shape the three that follow (ar, cpio, zip) are expected to copy.
//!
//! Five things below are not obvious, and each is a decision this module
//! makes rather than one the `tar` crate makes for it. The three later
//! containers will meet the first two only if their crates have the same
//! shape; they will meet the last three regardless.
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
//! `Box::into_raw`, and reclaimed in `Drop`.
//!
//! Raw rather than a `Box` kept in the struct on purpose: `Box` is a
//! `noalias` pointer, so deriving a borrow from one and then MOVING the box
//! — which building this struct does — is the aliasing hazard
//! `Box::into_raw` sidesteps entirely.
//!
//! # `tar::Entry` is not `Send`, and `Entry::new` requires that it be
//!
//! `EntriesFields<'a>` holds `&'a Archive<dyn Read + 'a>`, whose
//! `ArchiveInner` holds a `RefCell<R>`. `&T: Send` needs `T: Sync`, and
//! `RefCell` is never `Sync`, so `tar::Entry` is `!Send` for ANY reader — it
//! cannot be fixed by choosing a different `R`. `stuffr_core::Entry::new`
//! takes `Box<dyn Read + Send + 'a>`, so the payload reader carries an
//! `unsafe impl Send` with its argument spelled out on the type. The two
//! alternatives were both worse: buffering each entry's payload defeats the
//! streaming this container exists for (a 10 GB member in RAM), and reading
//! the payload straight off a shared source handle instead of through tar
//! silently corrupts GNU sparse entries, whose archive bytes are not the
//! contiguous run the entry's size describes.
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
//!    [`TrailerWatch`] therefore counts what the source actually delivered,
//!    and [`TarRead::verify_end_of_archive`] reads whatever follows the
//!    marker and applies two rules, both CALIBRATED against reference tools
//!    (macOS `bsdtar` 3.5.3 and Python's `tarfile`) on hand-cut fixtures
//!    rather than chosen:
//!
//!    * The stream is a whole number of 512-byte blocks. A tar is
//!      block-structured throughout, and a partial final block is what
//!      `bsdtar` calls "Truncated tar archive" (exit 1).
//!    * The last two blocks are entirely zero — the marker POSIX defines.
//!      With the rule above this is exactly "the final 1024 bytes are
//!      zeros". No marker at all is `bsdtar`'s "Damaged tar archive"; a lone
//!      zero block is its "Truncated input file (needed 512 bytes, only 0
//!      available)", and `tarfile` raises `ReadError` for both. This project
//!      does not want to be the one tool that accepts them.
//!
//!    Concatenated tars (`cat a.tar b.tar`, which every tool reads as just
//!    `a.tar`'s entries) still pass: the rules look at the end of the whole
//!    stream, which is `b.tar`'s own marker.
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
//!
//! # Licence note
//!
//! No `self_cell` dependency remains (see above), so the only crate this
//! module adds is `tar`, which is MIT OR Apache-2.0. Had `self_cell` been
//! used it would have been the first **GPL-2.0-only**-optional crate in the
//! tree (`Apache-2.0 OR GPL-2.0-only`), taken under its Apache-2.0 option —
//! lawful, and precedented by `lzma-rust2`, but worth recording. It is not
//! in the graph.

use std::io::{self, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use stuffr_core::{
    ArchiveRead, ArchiveWrite, Container, ContainerCaps, CreateOpts, Entry, EntryKind, EntryMeta,
    Error, FidelityReport, FormatId, FormatMeta, MagicRule, OpenOpts, Resolved, Result, Rung,
    Source,
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

/// The mode `add` writes when the caller does not say — `rw-r--r--`, what
/// every tar tool defaults a regular file to.
const DEFAULT_MODE: u32 = 0o644;

/// The reader handed to `tar::Archive`. Wraps the ladder's source only to
/// watch for the end-of-archive marker; see the module doc's point 4.
type TarArchive = tar::Archive<TrailerWatch>;

pub struct Tar;

impl Container for Tar {
    fn id(&self) -> FormatId {
        TAR
    }

    fn caps(&self) -> ContainerCaps {
        ContainerCaps {
            read: true,
            write: true,
            // tar is natively streaming: entries carry their own headers and
            // sizes inline, so a forward read is not degraded at all. This is
            // the whole reason tar reaches Exact on a pipe where zip cannot.
            forward_parse: true,
            ..Default::default()
        }
    }

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
            report: exact_however_the_bytes_arrived(report),
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

/// Reports `Rung::Exact` whether the bytes arrived from a file or a pipe.
///
/// The ladder hands tar `Rung::ForwardOnly` for a non-seekable source,
/// because that is the rung it placed the SOURCE on. For tar that would
/// describe a fidelity loss that has not occurred: every field this container
/// reports comes from a header stored inline, ahead of the data it describes,
/// so a forward read consults exactly the same authoritative structures a
/// seekable one does. Nothing is approximated and nothing is skipped — which
/// is why `caps().trailing_index` is false and harness property 7, the rung
/// honesty check, does not apply to tar.
///
/// The observable difference this makes is `FidelityReport::is_lossless`,
/// which ANDs `rung.is_authoritative()` with "no warnings": left at
/// `ForwardOnly` it would answer `false` for a piped tar that lost nothing.
/// Note that `fidelity.rs`'s doc comment on `has_warnings` still says "a tar
/// read from a pipe lands on `ForwardOnly`" as its worked example; that
/// sentence and this function disagree, and the sentence is the one that
/// should move.
fn exact_however_the_bytes_arrived(mut report: FidelityReport) -> FidelityReport {
    if report.rung == Rung::ForwardOnly {
        report.rung = Rung::Exact;
    }
    report
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
    /// Read together with a block-aligned total this is exact rather than a
    /// heuristic: `>= 1024` with `delivered % 512 == 0` means the final two
    /// blocks are entirely zero, which is precisely the marker. A payload
    /// whose own tail happens to be zeros can push the count over only by
    /// genuinely making those blocks zero — in which case the archive really
    /// does end in two zero blocks, whatever wrote it.
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
    /// Checks the marker tar itself never looks at. See the module doc's
    /// point 4.2 for the two rules and how each was calibrated against
    /// `bsdtar` and Python's `tarfile`.
    fn verify_end_of_archive(&self) -> Result<()> {
        self.read_tail()?;
        let delivered = self.trailer.delivered();
        if !delivered.is_multiple_of(BLOCK as u64) {
            return Err(Error::Corrupt(format!(
                "tar stream is {delivered} bytes, not a whole number of {BLOCK}-byte \
                 blocks; the archive is truncated"
            )));
        }
        if self.trailer.trailing_zeros() < 2 * BLOCK as u64 {
            return Err(Error::Corrupt(format!(
                "tar stream of {delivered} bytes does not end in the two zero blocks that \
                 mark the end of an archive; it is truncated"
            )));
        }
        Ok(())
    }

    /// Reads whatever follows the first zero block, which is where tar stops.
    ///
    /// Not the extra pass it looks like: this container reads rather than
    /// seeks its way past every entry (see the module doc), so the whole
    /// stream is read either way — this only covers the trailing padding.
    fn read_tail(&self) -> Result<()> {
        let mut source = self.source.lock().expect("tar source mutex poisoned");
        let mut buf = [0u8; 8 * 1024];
        loop {
            let n = source.read(&mut buf).map_err(classify_tar_error)?;
            if n == 0 {
                return Ok(());
            }
            self.trailer.record(&buf[..n]);
        }
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
/// # Safety of the `Send` assertion below
///
/// `tar::Entry` is `!Send` for one reason: it holds `&Archive<dyn Read>`, and
/// `&T: Send` requires `T: Sync`, which `ArchiveInner`'s `RefCell` never is.
/// That makes it unsound to have TWO threads touching one archive, which
/// cannot happen here:
///
/// * `ArchiveRead::next_entry(&mut self)` returns `Entry<'_>` borrowing
///   `self`, so for as long as this payload exists the `TarRead` it came from
///   is exclusively borrowed — no other code, on any thread, can call a
///   method on it, drop it, or ask it for a second entry.
/// * `TarRead::entries` is inside that same exclusive borrow, so the
///   iterator cannot be advanced while this payload is alive either.
/// * The archive's own reader is `Box<dyn Source>`, and `Source: Read + Send`
///   — the bytes underneath are themselves safe to touch from another thread.
/// * tar borrows the `RefCell` only for the duration of a single `read`, so
///   there is no outstanding borrow for a move to invalidate.
///
/// The assertion exists at all only because `stuffr_core::Entry::new`
/// requires `Box<dyn Read + Send + 'a>`. Relaxing that bound in
/// `stuffr-core` — an entry is read on the thread that asked for it, and
/// nothing in the tree sends one anywhere — would delete this `unsafe`
/// outright, and is the change to make if a second container ever needs the
/// same assertion.
struct EntryPayload<'a> {
    entry: tar::Entry<'a, TrailerWatch>,
    /// Payload bytes the entry's own header promised and has not delivered.
    remaining: u64,
    /// Kept for the error message: a corrupt archive should say WHICH entry.
    name: String,
}

// SAFETY: argued in full on the type's doc comment above.
unsafe impl Send for EntryPayload<'_> {}

impl Read for EntryPayload<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
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
        header.set_mode(meta.mode.unwrap_or(DEFAULT_MODE));
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

    /// tar is natively streaming: it must reach Exact even on a pipe. This is
    /// the property that distinguishes it from zip and the reason it is the
    /// first container implemented.
    #[test]
    fn tar_reports_exact_even_on_a_non_seekable_source() {
        let bytes = build_tar(&[("a.txt", b"alpha")]);
        let ar = open_forward_only(&Tar, &bytes);
        assert_eq!(ar.fidelity().rung, Rung::Exact);
        assert!(
            !ar.fidelity().has_warnings(),
            "a forward tar read loses nothing, so it must raise no fidelity warning"
        );
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

        let cases = [
            (2048usize, "no marker at all"),
            (2560, "a lone zero block"),
            (3071, "a marker one byte short of complete"),
        ];
        for (cut, what) in cases {
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
