//! cpio, `newc` only, via the `cpio` crate.
//!
//! The crate ships exactly one on-disk format despite its module name
//! suggesting a family: no `odc` ("old ASCII"), no CRC variant (`newc`'s own
//! sibling that adds a per-entry checksum). This container therefore
//! declares `newc` alone rather than implying the others work — see the
//! crate's own `newc::Builder::write` (used here) against the sibling
//! `write_crc` it does not call.
//!
//! # Not self-referential, unlike tar
//!
//! `cpio::newc::Reader<R>` OWNS the reader it was constructed from and hands
//! it back only through `finish(self) -> io::Result<R>`, consuming itself —
//! there is no borrowed `Entry<'a, R>` type the way `ar::Entry` or
//! `tar::Entry` are. [`CpioState`] models the two shapes that ownership
//! implies (holding the raw reader between entries, holding a live `Reader`
//! while one entry's payload is being read) as a plain enum, and
//! [`CpioEntryPayload`] borrows `&mut CpioState` rather than owning a `Reader`
//! outright. Borrowing (not owning) is what makes this safe without
//! `unsafe`: the trait's own `next_entry(&mut self) -> Result<Option<Entry<'_>>>`
//! already ties the returned `Entry`'s lifetime to `&mut self`, so the
//! borrow checker refuses a second call to `next_entry` until the previous
//! `Entry` — and the borrow of `self.state` inside it — has been dropped.
//! That is the exact guarantee [`CpioRead::next_entry`] depends on to finish
//! the PREVIOUS entry (draining whatever the caller did not read, then
//! recovering the reader) before the next header is parsed.
//!
//! # No end-of-archive marker check, unlike tar
//!
//! tar's own reader cannot tell "the archive ended" from "the stream ran
//! out" (see `tar.rs`'s module doc, point 4.2), because both routes reach an
//! indistinguishable `Ok(None)`. cpio has no such ambiguity: the only way to
//! reach a clean end is to actually PARSE a `TRAILER!!!` entry
//! (`Entry::is_trailer`), and `cpio::newc::Reader::new` has no route to
//! return anything but an error for a stream that runs out before one — its
//! header fields are read via plain `read_exact` calls with no special
//! end-of-stream handling at all, so a truncated stream surfaces as an
//! ordinary `UnexpectedEof`. This container therefore needs no marker-
//! position check of its own.
//!
//! # `add` cannot stream an unknown-length input, and neither can `cpio`
//!
//! Same constraint as `ar.rs`, for the same reason: `newc::Builder::write`
//! needs the entry's `file_size` up front, before any payload byte is
//! written, so an entry is always buffered into memory first and framed
//! with its measured length — never the caller's declared one.
//!
//! # The `u32` size field
//!
//! `newc::Builder::write`'s `file_size` parameter is `u32` — a hard 4 GiB
//! per-entry ceiling this format cannot express past. [`check_u32_size`]
//! refuses an oversized entry with a typed error naming the limit, checked
//! against the caller's DECLARED size before anything is read (so the
//! refusal costs nothing) and again against what was actually measured, in
//! case none was declared. A silent `as u32` truncating cast would instead
//! emit a structurally valid archive framed with the wrong length —
//! corruption this project generated itself, invisible until something else
//! tried to read it back.
//!
//! # Symlinks: the one entry kind this module reads its own payload for
//!
//! Unlike tar's `linkname` header field, `newc` has nowhere to put a
//! symlink's target except the entry's PAYLOAD — the mode field's `S_IFLNK`
//! bits (`0o120000`) are the only signal that an entry even IS one.
//! [`CpioRead::next_entry`] detects this from the header alone (before
//! deciding what kind of reader to hand back) and, only for this one kind,
//! reads the payload EAGERLY, right there, rather than deferring it to the
//! caller the way every other entry's data is. This is deliberately narrow:
//! a symlink target is bounded by the platform's `PATH_MAX` in every
//! realistic archive, so the read is small and constant-cost, and it does
//! not touch the streaming property conformance property 8 checks — that
//! property's own fixture is an ordinary FILE entry, never a symlink, so
//! this path is never on its critical path.
//!
//! A hostile archive claiming an implausibly large symlink "target" is
//! refused outright by [`MAX_SYMLINK_TARGET_LEN`], checked BEFORE a single
//! byte is read — deliberately not left to `--max-ratio`: `entries::
//! open_archive` does wrap the source in a `RatioGuardedSource`, but that
//! bounds decoded bytes against COMPRESSED ones, which is ~1:1 for a plain,
//! uncompressed `.cpio` and so does not meaningfully bind an oversized
//! target either way; containers also receive no `--memory-limit` at all
//! (`OpenOpts` carries no such field). The explicit cap is what makes "this
//! read is small and constant-cost" true unconditionally, not just for a
//! well-formed archive.
//!
//! Real-world cpio payloads — initramfs images, RPM archives — are dense
//! with symlinks, which is why this is a real requirement and not a
//! nice-to-have: an extraction that skipped every one of them would be
//! broken, not merely lossy.
//!
//! The mode field's type bits matter on the WRITE side too, for the same
//! structural reason: `newc` has no OTHER way to record "this is a
//! directory" or "this is a symlink", so [`ArchiveWrite::add`] normalises
//! them in regardless of what the caller's own `EntryMeta::mode` carries —
//! masking out whatever type bits (if any) were already there and OR-ing in
//! the correct ones for `meta.kind`. A caller supplying a permission-only
//! mode for a directory or a symlink (tar's own test fixtures do exactly
//! this: `dir.mode = Some(0o750)`, no `S_IFDIR` bit at all — `tar` does not
//! need one, since its typeflag byte already says what the entry is) would
//! otherwise write a `newc` entry indistinguishable from a plain file to
//! ANY cpio reader, this one included — not an internal inconsistency, a
//! genuine interop defect, since the type bits are the only place `newc`
//! carries this information at all.
//!
//! `EntryKind::File` gets the same treatment, but only where there is
//! nothing to overwrite. Until 0.3.1 it was left alone entirely, on the
//! reasoning that THIS reader does not need `S_IFREG` to recognise a plain
//! file (see `entry_kind`'s own doc — the absence of every OTHER type's bits
//! is what decides `File`). That reasoning was sound about this reader and
//! wrong about the format: GNU cpio 2.15 refuses a type-bit-less entry with
//! `unknown file type`, skips it, and exits 0 anyway, so every regular file
//! in a stuffr-written cpio vanished on extraction — silently, with a
//! success status. And `entries.rs`'s `mode_of` masks a walked file's mode
//! to `0o7777` on purpose (tar's header field wants permissions alone), so
//! EVERY file packed from disk arrived here type-bit-less. bsdcpio
//! (libarchive), which is what macOS ships, infers a regular file and
//! extracts the archive whole — which is why the defect shipped.
//!
//! So the file arm ORs `S_IFREG` into a permission-only mode and leaves a
//! mode that already carries type bits exactly as given. The verbatim half
//! is load-bearing: the container-conformance harness's property 11 requires
//! a reported mode to survive a round trip unaltered, and this container
//! reports the raw `newc` mode field. Property 11's own fixture writes a
//! permission-only `0o640`, which now reads back as `0o100640`, so the
//! harness was taught the one transformation a container may legitimately
//! make to a mode — folding in the type bits the format demands — and still
//! fails any container that touches a permission bit or overwrites type bits
//! a caller supplied.

use std::io::{self, Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use stuffr_core::{
    ArchiveRead, ArchiveWrite, Container, ContainerCaps, CreateOpts, Entry, EntryKind, EntryMeta,
    Error, FidelityReport, FormatId, FormatMeta, MagicRule, OpenOpts, Resolved, Result, Sink,
    Source,
};

use crate::normalize::CPIO_MALFORMED_AS_INVALID_DATA_EOF;

pub const CPIO: FormatId = FormatId::new("cpio");

/// The "new ASCII" magic, `070701`, at offset 0. This container never writes
/// the sibling `070702` ("new CRC") form — see the module doc — so only the
/// one rule is registered.
static CPIO_MAGIC: &[MagicRule] = &[MagicRule {
    offset: 0,
    bytes: b"070701",
    format: CPIO,
}];

/// The mode `add` writes for a FILE entry when the caller does not say —
/// `rw-r--r--` with the regular-file type bits set, `st_mode`-shaped the
/// same way `ar.rs`'s `DEFAULT_MODE` is (see that constant's doc for why
/// `apply_metadata`'s own `0o7777` mask already expects this).
const DEFAULT_FILE_MODE: u32 = 0o100644;

/// The mode `add` writes for a DIRECTORY entry when the caller does not say.
///
/// `DEFAULT_FILE_MODE` alone has no owner-execute bit, so an unset directory
/// mode would extract into one nothing could traverse into — the exact
/// defect `tar.rs`'s carried fix closes for tar (see `DEFAULT_DIR_MODE`
/// there). Applied here from the start rather than inherited as a bug: cpio
/// is the other format in this tree whose entries can legitimately be
/// directories.
const DEFAULT_DIR_MODE: u32 = 0o040755;

/// The mode `add` writes for a SYMLINK entry when the caller does not say —
/// `rwxrwxrwx` with the symlink type bits set: a symlink's own permission
/// bits are conventionally ignored by every tool that follows one, so unlike
/// files and directories there is no meaningful "restrictive" default to
/// pick.
const DEFAULT_SYMLINK_MODE: u32 = 0o120_777;

/// The `S_IFMT` mask (`st_mode`'s top four bits): what's left after masking
/// a mode with this is the permission/setuid/setgid/sticky bits alone.
const MODE_TYPE_MASK: u32 = 0o170_000;

/// `S_IFDIR`: the type bits `newc`'s mode field must carry for a directory.
const S_IFDIR: u32 = 0o040_000;

/// `S_IFLNK`: the type bits `newc`'s mode field must carry for a symlink.
const S_IFLNK: u32 = 0o120_000;

/// `S_IFREG`: the type bits `newc`'s mode field must carry for a plain file.
///
/// This reader does not NEED them — [`entry_kind`] answers `File` for the
/// absence of every other type's bits — but GNU cpio does, and the tolerance
/// is not shared: GNU cpio 2.15 refuses an entry whose mode carries no type
/// bits with `unknown file type`, skips it, and still exits 0, so a stuffr
/// archive extracted by it silently loses every regular file. bsdcpio
/// (libarchive) infers a regular file and extracts the same archive whole,
/// which is why this survived a whole phase of macOS-only verification. See
/// [`ArchiveWrite::add`]'s mode normalisation.
const S_IFREG: u32 = 0o100_000;

pub fn meta() -> FormatMeta {
    FormatMeta::container(CPIO, &["cpio"], CPIO_MAGIC)
}

pub struct CpioNewc;

impl Container for CpioNewc {
    fn id(&self) -> FormatId {
        CPIO
    }

    /// No trailing index, no per-entry codec, no solid blocks: entries carry
    /// their own headers and sizes inline, the same shape as tar and ar.
    ///
    /// Not reflected in any field here, because `ContainerCaps` has none for
    /// it, but worth stating at the same place a caller checking this
    /// format's capabilities would look: `newc`'s per-entry size field is
    /// `u32` — a hard 4 GiB ceiling this format cannot express past. An
    /// entry larger than that is refused by `add` with a typed error naming
    /// the limit (see [`check_u32_size`]), never silently truncated to the
    /// wrong length.
    fn caps(&self) -> ContainerCaps {
        ContainerCaps {
            read: true,
            write: true,
            forward_parse: true,
            // Through the mode's `S_IFMT` type bits, which `add` normalises
            // for both kinds rather than trusting a caller's mode — see its
            // comment. A symlink's target is its payload.
            stores_dirs: true,
            stores_symlinks: true,
            ..Default::default()
        }
    }

    /// Reads no byte of `resolved`, deliberately. The magic check that
    /// [`refuse_a_recognised_variant_this_crate_cannot_read`] performs
    /// happens on the first [`CpioRead::next_entry`] instead, because
    /// container-harness property 10 requires a source error to surface as
    /// itself from a READ rather than from `open` — a container that opens
    /// eagerly turns a bad disk into an open failure and fails that
    /// property.
    fn open(&self, resolved: Resolved, _o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
        let Resolved { source, report, .. } = resolved;
        let seekable = source.caps().seekable;
        Ok(Box::new(CpioRead {
            // The one and only place a `CpioSource` is built — see its doc
            // for why installing the read-ahead buffer here, rather than
            // wrapping per entry, is the whole fix.
            state: CpioState::Idle(CpioSource::new(source)),
            report,
            seekable,
            magic_checked: false,
        }))
    }

    fn create(&self, dst: Box<dyn Sink>, _o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
        Ok(Box::new(CpioWrite { dst: Some(dst) }))
    }
}

/// The cpio variants this build RECOGNISES but cannot read, by magic.
///
/// The `cpio` crate implements `newc` (`070701`) alone. Point stuffr at a
/// perfectly valid `odc` archive — `find . -type f | cpio -o -H odc`, the
/// portable format POSIX standardised — and the crate rejected the magic
/// with "Invalid magic number", which `classify_cpio_error` folded onto
/// [`Error::Corrupt`]: exit 5, telling the user their intact file was
/// damaged.
///
/// That contradicts the doctrine Task 11 established and `examples.txt`
/// states: exit 3, not 5, for a capability this build does not have. So
/// both siblings are named here and refused as [`Error::Unsupported`] (exit
/// 3) with a message naming the variant, before the crate's own parser gets
/// a chance to call them broken.
///
/// Only variants that are genuinely cpio are listed. Anything else — bytes
/// that are not cpio at all — falls through to the crate and is reported as
/// corrupt, which is the right answer for it.
const RECOGNISED_UNREADABLE_VARIANTS: &[(&[u8], &str)] = &[
    (b"070707", "odc (POSIX \"old character\"/portable ASCII)"),
    (b"070702", "newc-crc (the CRC variant of new ASCII)"),
];

/// Refuses a cpio variant this build recognises but cannot read.
///
/// See [`RECOGNISED_UNREADABLE_VARIANTS`]. A prefix shorter than six bytes
/// matches nothing and falls through: a stream that short is not a cpio
/// header of any variant, and the crate's own truncation handling is the
/// right place to say so.
fn refuse_a_recognised_variant_this_crate_cannot_read(prefix: &[u8]) -> Result<()> {
    for (magic, name) in RECOGNISED_UNREADABLE_VARIANTS {
        if prefix.starts_with(magic) {
            return Err(Error::Unsupported(format!(
                "this is a valid cpio archive in the {name} variant, magic `{}` — \
                 not a damaged one. This build reads `newc` (magic `070701`) only. \
                 Convert it with `cpio -i < old.cpio | cpio -o -H newc > new.cpio`.",
                String::from_utf8_lossy(magic)
            )));
        }
    }
    Ok(())
}

/// Folds an error raised by the `cpio` crate's own reader into this
/// project's error vocabulary. See [`CPIO_MALFORMED_AS_INVALID_DATA_EOF`]
/// for what was measured.
fn classify_cpio_error(e: io::Error) -> Error {
    if CPIO_MALFORMED_AS_INVALID_DATA_EOF.contains(&e.kind()) {
        return Error::Corrupt(e.to_string());
    }
    Error::from_decode_io(e)
}

/// The reader `cpio::newc::Reader` is handed, installed exactly ONCE per
/// archive (in `CpioNewc::open`) and threaded through every entry by
/// [`CpioState`]: it wraps the real source and carries the single, reused
/// read-ahead buffer [`CpioRead::next_entry`]'s per-header peek fills.
///
/// # Why a wrapper installed once, and not a peek per entry
///
/// [`refuse_an_oversized_namesize`] has to see `c_namesize` before EVERY
/// header, because the allocation it guards is one `cpio::newc::Reader::new`
/// call per entry, not one per archive. The obvious way to write that —
/// wrap the source in a fresh `PeekSource` before each header, the way
/// `stuffr_core::probe` wraps one before a whole stream — is what 0.3.1
/// shipped, and it is quadratic: `PeekSource::fill` takes a
/// `Box<dyn Source>` and RETURNS a new one, so entry *N*'s bytes are read
/// through *N* nested dynamic-dispatch frames, each retaining its own
/// ~112-byte prefix. Measured on a forward-only (pipe-shaped) archive of
/// zero-length entries, release build:
///
/// | entries | nested peek (0.3.1) | this wrapper |
/// |---|---|---|
/// | 5,000 | 116 ms | 5.2 ms |
/// | 10,000 | 368 ms | 5.8 ms |
/// | 20,000 | 1.56 s | 6.9 ms |
/// | 40,000 | 6.10 s | 12.0 ms |
/// | 100,000 | **stack overflow, `SIGABRT`** | 27.0 ms |
///
/// Doubling the entry count quadrupled the time, and at 100,000 entries the
/// nesting exhausted a 2 MiB test-thread stack outright — so the fix for an
/// unbounded per-header ALLOCATION had bought an unbounded per-entry frame.
/// `ar.rs`'s `ArGuardedReader` is the
/// sibling precedent and has never had this problem for exactly this reason:
/// it is installed once, below the crate, and inspects headers as they flow
/// through it. cpio can take the same shape but does not need the full state
/// machine, because this module — unlike `ar`'s — already drives the
/// entry loop itself and therefore already knows where every header starts.
///
/// # The nesting is unrepresentable, not merely avoided
///
/// `CpioSource` deliberately does NOT implement [`Source`]. `PeekSource::fill`
/// — and every other wrapper in `stuffr_core::source` — takes a
/// `Box<dyn Source>`, so re-wrapping this type does not TYPECHECK. That is
/// the regression guard: a timing assertion tight enough to separate linear
/// from quadratic growth would flake on a loaded CI runner, whereas "it does
/// not compile" cannot silently stop being true. The measurement above is
/// reproducible on demand via the `#[ignore]`d
/// `a_forward_read_scales_linearly_with_entry_count`.
///
/// # One path, not two
///
/// The 0.3.1 helper had a separate seekable branch that read the prefix and
/// then seeked back. That is gone: buffering 102 bytes costs the same on a
/// file as on a pipe, and a single path is one fewer place for the two to
/// disagree. Nothing below this wrapper seeks — `by_index` refuses on every
/// cpio source (see [`CpioRead::by_index`]) — so no position needs restoring.
struct CpioSource {
    inner: Box<dyn Source>,
    /// Bytes read ahead of `cpio::newc::Reader` and not yet replayed to it.
    /// Never longer than [`CPIO_NAMESIZE_FIELD_END`]: it is topped up to
    /// that width before each header and fully drained by the header read
    /// that follows.
    peeked: Vec<u8>,
    /// How much of `peeked` has already been replayed.
    pos: usize,
}

impl CpioSource {
    fn new(inner: Box<dyn Source>) -> Self {
        CpioSource {
            inner,
            peeked: Vec::new(),
            pos: 0,
        }
    }

    /// Reads ahead far enough to cover `c_namesize` — see
    /// [`CPIO_NAMESIZE_FIELD_END`] — without consuming anything: whatever is
    /// buffered here is replayed by this type's own `Read` impl before a single
    /// byte is taken from `inner` again.
    ///
    /// A short read is not an error. A stream that ends before offset 102 is
    /// truncated, and `cpio::newc::Reader::new`'s own `read_exact` is the
    /// right place to say so — [`peek_namesize`] returns `None` for a prefix
    /// too short to hold the field, so the guard simply stands aside.
    fn fill_header_prefix(&mut self) -> Result<()> {
        // Anything already replayed is spent; anything not replayed (there
        // is none on the honest path, since a header read always drains the
        // whole prefix) is kept and topped up rather than re-read.
        self.peeked.drain(..self.pos);
        self.pos = 0;
        while self.peeked.len() < CPIO_NAMESIZE_FIELD_END {
            let at = self.peeked.len();
            self.peeked.resize(CPIO_NAMESIZE_FIELD_END, 0);
            let n = self.inner.read(&mut self.peeked[at..])?;
            self.peeked.truncate(at + n);
            if n == 0 {
                break;
            }
        }
        Ok(())
    }

    /// What [`CpioSource::fill_header_prefix`] buffered, and what the two
    /// header guards inspect. Borrowed, not cloned — the borrow ends before
    /// this source is moved into `cpio::newc::Reader::new`.
    fn header_prefix(&self) -> &[u8] {
        &self.peeked[self.pos..]
    }
}

impl Read for CpioSource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos < self.peeked.len() {
            let n = (self.peeked.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.peeked[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        self.inner.read(buf)
    }
}

/// What this reader currently holds. See the module doc's "Not
/// self-referential" section for why this shape, rather than a borrowed
/// entry type, is what `cpio::newc::Reader`'s owning API requires.
enum CpioState {
    /// Between entries: the raw reader, ready to parse the next header.
    Idle(CpioSource),
    /// One entry's header has been parsed and its payload may still have
    /// unread bytes.
    Reading(cpio::newc::Reader<CpioSource>),
    /// The trailer entry was reached, or the archive failed outright. Either
    /// way, nothing more will be read.
    Ended,
}

struct CpioRead {
    state: CpioState,
    report: FidelityReport,
    seekable: bool,
    /// Whether the one-time variant check has run. The state machine
    /// returns to [`CpioState::Idle`] between entries (and after a symlink,
    /// whose payload is consumed eagerly), so "am I in `Idle`" cannot stand
    /// in for "is this the first entry".
    magic_checked: bool,
}

impl ArchiveRead for CpioRead {
    fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
        // Recover the raw reader, finishing off whatever entry the PREVIOUS
        // call returned — `Reader::finish` drains any bytes the caller did
        // not read itself, exactly as if the caller had read them.
        let mut src = match std::mem::replace(&mut self.state, CpioState::Ended) {
            CpioState::Idle(src) => src,
            CpioState::Reading(reader) => reader.finish().map_err(classify_cpio_error)?,
            CpioState::Ended => return Ok(None),
        };

        // Read ahead before EVERY header, not just the first: `refuse_an_
        // oversized_namesize` (Task 5c) must see `c_namesize` before
        // `cpio::newc::Reader::new` gets a chance to allocate on its say-so,
        // and that allocation is one `Reader::new` call per entry, not one
        // per archive. The read-ahead is non-consuming — `src` replays what
        // it buffered — and it reuses ONE buffer for the archive's whole
        // lifetime rather than stacking a wrapper per entry; see
        // `CpioSource`'s doc for the measurements that shape cost. A read
        // failure here propagates as `Error::Io` — property 10's
        // source-error passthrough — rather than being mistaken for a
        // variant refusal.
        src.fill_header_prefix()?;
        if !self.magic_checked {
            refuse_a_recognised_variant_this_crate_cannot_read(src.header_prefix())?;
            self.magic_checked = true;
        }
        refuse_an_oversized_namesize(src.header_prefix())?;

        let mut reader = cpio::newc::Reader::new(src).map_err(classify_cpio_error)?;
        if reader.entry().is_trailer() {
            // The trailer's own file_size is always 0, so there is nothing
            // left to drain; `finish` only hands back a reader nothing more
            // will be done with.
            let _ = reader.finish();
            self.state = CpioState::Ended;
            return Ok(None);
        }

        let mut meta = entry_meta(reader.entry());
        let name = meta.name.clone();

        // A symlink's target lives in the PAYLOAD, not a header field — see
        // the module doc's "Symlinks" section. Read it now, while `reader`
        // is still in hand, rather than deferring to the caller the way
        // every other entry's data is.
        if is_symlink_mode(reader.entry().mode()) {
            let target = read_symlink_target(&mut reader, &name)?;
            let src = reader.finish().map_err(classify_cpio_error)?;
            self.state = CpioState::Idle(src);
            meta.kind = EntryKind::Symlink { target };
            // The payload was already consumed above; nothing is left for a
            // caller to read. `entries::extract` never calls `.reader()` for
            // a Symlink entry (it uses `meta.kind`'s own target), the same
            // convention tar's own Dir/Symlink entries already rely on.
            return Ok(Some(Entry::new(meta, Box::new(io::empty()))));
        }

        let remaining = u64::from(reader.entry().file_size());
        self.state = CpioState::Reading(reader);

        let payload = CpioEntryPayload {
            state: &mut self.state,
            remaining,
            name,
        };
        Ok(Some(Entry::new(meta, Box::new(payload))))
    }

    /// cpio carries no entry index, on any source — the same shape as tar's
    /// and ar's own `by_index` (see `tar.rs`'s doc for why the two errors
    /// say different true things).
    fn by_index(&mut self, index: usize) -> Result<Entry<'_>> {
        if self.seekable {
            return Err(Error::Unsupported(format!(
                "cpio carries no entry index, so entry {index} can only be reached by reading \
                 forward from the start"
            )));
        }
        Err(Error::NotSeekable { format: CPIO })
    }

    fn fidelity(&self) -> &FidelityReport {
        &self.report
    }
}

/// One entry's payload. Borrows the [`CpioState`] it was read out of rather
/// than owning a `Reader` outright — see the module doc.
///
/// Carries the same short-read guard `tar.rs`'s `EntryPayload` and `ar.rs`'s
/// `ArEntryPayload` do: `cpio::newc::Reader`'s own `Read` impl limits every
/// read to `file_size - bytes_read` and proxies the result unchanged, with no
/// truncation check of its own — a stream that runs out mid-entry reports a
/// clean `Ok(0)` with bytes still promised. `Reader::finish`'s internal
/// `io::copy` of the unread remainder has the identical blind spot (`io::copy`
/// stops cleanly on `Ok(0)` without comparing against how much was expected),
/// which is why this struct tracks the declared length itself instead of
/// trusting either path to notice.
struct CpioEntryPayload<'a> {
    state: &'a mut CpioState,
    remaining: u64,
    name: String,
}

impl Read for CpioEntryPayload<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // `Read`'s contract: an empty buffer reads nothing and is not an
        // error — see `tar.rs`'s `EntryPayload::read` for why this guard has
        // to come before the short-read check below.
        if buf.is_empty() {
            return Ok(0);
        }
        let CpioState::Reading(reader) = self.state else {
            unreachable!(
                "a CpioEntryPayload only exists while CpioRead::next_entry has just set \
                 CpioState::Reading, and nothing else replaces that state while this \
                 payload — which borrows it — is alive"
            );
        };
        let n = reader.read(buf)?;
        if n == 0 && self.remaining > 0 {
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

/// Which `EntryKind` a raw `st_mode`-shaped mode field describes, ASIDE from
/// symlinks — `CpioRead::next_entry` checks [`is_symlink_mode`] itself,
/// before this function is ever consulted, and overrides whatever it would
/// have said (`Other`, below) with the real `EntryKind::Symlink { target }`
/// once the payload has been read. This function's own `S_IFLNK` arm is
/// therefore never the answer a caller actually sees; it stays in the match
/// as the honest "not yet overridden" value rather than being silently
/// folded into `File`.
///
/// Devices, FIFOs and sockets have no `EntryKind` variant to report at all
/// yet (see `archive.rs`'s own note that Phase 2 adds them), and read back
/// as [`EntryKind::Other`] — the same honest "skipped, not silently turned
/// into a file" answer `tar.rs`'s `is_regular_file` gives its own
/// unsupported types.
///
/// Mode `0` (never set — a minimal or hand-built writer) falls through to
/// `File` rather than `Other`: property 11's own fixture writes an explicit
/// mode with no type bits at all, and a real caller doing the same expects a
/// plain file back, not a skipped entry.
fn entry_kind(mode: u32) -> EntryKind {
    match mode & MODE_TYPE_MASK {
        S_IFDIR => EntryKind::Dir,
        0o010000 | 0o020000 | 0o060000 | 0o140000 | S_IFLNK => EntryKind::Other,
        _ => EntryKind::File,
    }
}

/// Whether a raw `st_mode`-shaped field names a symlink (`S_IFLNK`).
fn is_symlink_mode(mode: u32) -> bool {
    mode & MODE_TYPE_MASK == S_IFLNK
}

/// A generous ceiling well beyond any real platform's `PATH_MAX` (4096 on
/// Linux, 1024 on macOS/BSD) — no legitimate symlink target comes anywhere
/// near it. [`read_symlink_target`] refuses a declared target past this
/// BEFORE reading a single byte, which is what makes the module doc's
/// bounded-cost claim for the eager read hold unconditionally rather than
/// resting only on `--max-ratio`: `RatioGuardedSource` bounds decoded bytes
/// against COMPRESSED ones, which is ~1:1 for a plain, uncompressed
/// `.cpio`, so it does not meaningfully bind here — and containers receive
/// no `--memory-limit` at all (`OpenOpts` carries no such field). Without
/// this cap, a hostile entry claiming an implausible `file_size` under an
/// `S_IFLNK` mode could otherwise force an allocation of that size before
/// any caller had asked to read anything.
const MAX_SYMLINK_TARGET_LEN: u64 = 65_536;

/// Offset, from the start of a `newc` header, of the byte immediately past
/// `c_namesize` — the field this container must inspect before delegating
/// to the `cpio` crate. Six-byte magic, then eleven 8-byte hex fields
/// (`c_ino` through `c_rdevminor`), then the 8-byte `c_namesize` field
/// itself: `6 + 8 * 12 == 102`. See the crate's own `newc::Reader::new`
/// (quoted verbatim in this file's module doc / the task brief that added
/// this check) for the exact field order this mirrors.
const CPIO_NAMESIZE_FIELD_END: usize = 6 + 8 * 12;

/// Ceiling on a `newc` header's declared `c_namesize`, checked from the raw
/// header bytes BEFORE `cpio::newc::Reader::new` gets a chance to allocate
/// `name_len` zeroed bytes on the header's say-so alone.
///
/// This is the same shape of bug [`MAX_SYMLINK_TARGET_LEN`] already closes
/// for a symlink's target, and the same fix: `cpio-0.4.1/src/newc.rs`'s
/// `Reader::new` does
///
/// ```text
/// let mut name_bytes = vec![0u8; name_len];
/// inner.read_exact(&mut name_bytes)?;
/// ```
///
/// with `name_len` taken straight from the header, before a single byte of
/// the name is read. The real fuzz reproducer (Task 5c) hit `libFuzzer:
/// out-of-memory (malloc(2863311530))` inside exactly this call, at run
/// ~868 on one corpus seed and ~30,986 on another — well inside the
/// scheduled deep-fuzz workflow's budget, though outside the smoke job's
/// 2000-run one. The crate cannot be patched from here, so the check has
/// to run in this module, before the crate's parser is invoked at all.
///
/// **Why a fixed ceiling, not `DecodeOpts::memory_limit`:** `DecodeOpts`
/// binds a CODEC's dictionary/window allocation (see its own doc — the
/// identical shape closed in Phase 1f for `xz-pure`, `lzip`, `lzma-pure`),
/// but containers are opened through `OpenOpts`, which carries no memory
/// field at all — [`MAX_SYMLINK_TARGET_LEN`]'s doc already establishes this
/// for the very same reason. There is nothing to bind against here; a fixed
/// structural ceiling is the only option this container has, exactly as it
/// was for the symlink case.
///
/// **Why `Error::ResourceLimit` (exit 6), not `Error::Corrupt` (exit 5):**
/// because the refusal happens BEFORE the crate's allocator is asked — the
/// rule for all five of this workspace's header-field guards, written once
/// in `stuffr_core::Error::exit_code`'s doc comment and pointed at from
/// here rather than re-derived. [`MAX_SYMLINK_TARGET_LEN`]'s refusal, the
/// structurally identical case one field over in the same header, is the
/// same shape and the same code.
///
/// It is emphatically NOT a judgement that a 2.6 GiB name is a size some
/// larger machine could honour. The Task 5c reproducer is a 274-byte file,
/// and nothing anywhere can deliver that name; `ar.rs`'s two guards answer
/// 5 and 6 on one 68-byte file for the same reason. What separates the codes
/// is which guard stopped first, not how plausible the field is.
///
/// **Why 65,536 bytes:** `MAX_SYMLINK_TARGET_LEN`'s own figure and
/// reasoning transfer unchanged — a generous ceiling well beyond any real
/// platform's `PATH_MAX` (4096 on Linux, 1024 on macOS/BSD), and a `newc`
/// entry name is exactly as path-shaped as a symlink target. Proven against
/// a legitimate long, deeply-nested name well under this ceiling by
/// `a_legitimate_long_name_still_round_trips`.
const MAX_CPIO_NAME_LEN: u64 = 65_536;

/// Parses just the `c_namesize` field out of a raw header prefix, trusting
/// nothing past it. `None` means the prefix is too short to contain the
/// field (a stream ending before offset 102 is truncated, and
/// `cpio::newc::Reader::new`'s own EOF handling is the right place to say
/// so — this function does not duplicate it) or the bytes are not valid
/// 8-hex-digit ASCII (likewise the crate's own error is the right one to
/// surface).
fn peek_namesize(prefix: &[u8]) -> Option<u32> {
    let field = prefix.get(CPIO_NAMESIZE_FIELD_END - 8..CPIO_NAMESIZE_FIELD_END)?;
    let s = std::str::from_utf8(field).ok()?;
    u32::from_str_radix(s, 16).ok()
}

/// Refuses a header whose declared `c_namesize` exceeds
/// [`MAX_CPIO_NAME_LEN`] — see that constant's doc for the reasoning behind
/// both the bound and the error kind.
fn refuse_an_oversized_namesize(prefix: &[u8]) -> Result<()> {
    let Some(name_len) = peek_namesize(prefix) else {
        return Ok(());
    };
    if u64::from(name_len) > MAX_CPIO_NAME_LEN {
        return Err(Error::ResourceLimit(format!(
            "entry header declares a name of {name_len} bytes, past the \
             {MAX_CPIO_NAME_LEN}-byte ceiling this container reads eagerly; no legitimate cpio \
             entry name is this long"
        )));
    }
    Ok(())
}

/// Reads a symlink entry's target out of its payload — see the module doc's
/// "Symlinks" section for why this container reads it eagerly rather than
/// deferring to the caller. Refuses a declared length past
/// [`MAX_SYMLINK_TARGET_LEN`] before reading anything, and otherwise detects
/// truncation itself: `cpio::newc::Reader`'s own `Read` impl has no
/// truncation check of its own (see [`CpioEntryPayload`]'s doc), so a
/// stream that runs out mid-target would otherwise report a
/// shorter-than-declared target as if it were the whole thing.
fn read_symlink_target(reader: &mut cpio::newc::Reader<CpioSource>, name: &str) -> Result<String> {
    let declared = u64::from(reader.entry().file_size());
    if declared > MAX_SYMLINK_TARGET_LEN {
        return Err(Error::ResourceLimit(format!(
            "entry `{name}` declares a symlink target of {declared} bytes, past the \
             {MAX_SYMLINK_TARGET_LEN}-byte ceiling this container reads eagerly; no \
             legitimate symlink target is this long"
        )));
    }
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).map_err(classify_cpio_error)?;
    if (buf.len() as u64) < declared {
        return Err(Error::Corrupt(format!(
            "entry `{name}` (a symlink) is {} bytes short of the target length its header \
             declares; the archive is truncated",
            declared - buf.len() as u64
        )));
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn entry_meta(e: &cpio::newc::Entry) -> EntryMeta {
    EntryMeta {
        name: e.name().to_string(),
        size: Some(u64::from(e.file_size())),
        mtime: Some(UNIX_EPOCH + Duration::from_secs(u64::from(e.mtime()))),
        mode: Some(e.mode()),
        uid: Some(e.uid()),
        gid: Some(e.gid()),
        kind: entry_kind(e.mode()),
        ..Default::default()
    }
}

/// Refuses a size the `newc` `file_size` field cannot hold — see the module
/// doc's "The `u32` size field" section.
fn check_u32_size(name: &str, size: u64) -> Result<u32> {
    u32::try_from(size).map_err(|_| {
        Error::Unsupported(format!(
            "cpio newc cannot store `{name}`: {size} bytes exceeds the format's 4 GiB (u32) \
             per-entry size field"
        ))
    })
}

struct CpioWrite {
    /// `None` once `finish` has consumed it.
    dst: Option<Box<dyn Sink>>,
}

impl ArchiveWrite for CpioWrite {
    fn add(&mut self, meta: &EntryMeta, data: &mut dyn Read) -> Result<()> {
        // A symlink's target IS its payload here — see the module doc's
        // "Symlinks" section — so `data` is not consumed for one, the same
        // "the caller's data reader is irrelevant for this kind" contract
        // `tar.rs`'s own `add` applies to `EntryKind::Dir`/`Symlink` (there
        // the target lives in the header instead, but the convention that
        // `data` is ignored for these kinds is the same).
        let buf = if let EntryKind::Symlink { target } = &meta.kind {
            target.clone().into_bytes()
        } else {
            // Checked against the DECLARED size first, before a single byte
            // is read or allocated, so a caller who already knows an entry
            // is oversized is refused for free.
            //
            // That ordering is LOAD-BEARING OUTSIDE THIS FILE, so do not
            // fold this check into the one below on the grounds that the two
            // look redundant: `cli.rs`'s
            // `a_failed_write_never_replaces_an_existing_archive` (Phase 2c
            // property 3) drives the only mid-write failure in the suite
            // through it, using a 4 GiB SPARSE file. Refusing off `meta.size`
            // costs no disk and no time; refusing only after `read_to_end`
            // would materialise 4 GiB and make that test unrunnable, and the
            // property it pins — a failed pack leaves the existing archive
            // intact — would silently stop being tested. Move the check and
            // that test needs a new mechanism first.
            if let Some(size) = meta.size {
                check_u32_size(&meta.name, size)?;
            }
            let mut buf = Vec::new();
            data.read_to_end(&mut buf)?;
            buf
        };
        let size = check_u32_size(&meta.name, buf.len() as u64)?;

        // `newc` has no field OTHER than the mode's own type bits to record
        // what an entry IS, so a Dir or a Symlink mode is normalised
        // regardless of what the caller supplied: mask out whatever type
        // bits (if any) were already there, OR in the correct ones. See the
        // module doc for why leaving this to the caller would be a real
        // interop defect, not merely an internal inconsistency.
        //
        // `EntryKind::File` is normalised too, but CONSERVATIVELY, and the
        // difference is deliberate: a mode that already carries type bits is
        // passed through verbatim, and only a permission-only mode (no
        // `S_IFMT` bits at all — which is exactly what `entries.rs`'s
        // `mode_of` produces, since tar's header wants permissions alone)
        // has `S_IFREG` OR-ed in. Overwriting the type bits here the way the
        // two arms above do would relabel a caller's explicit `0o100644` and
        // break the round-trip this format's own reader relies on; leaving
        // them absent is what shipped in 0.2.0, and GNU cpio drops every
        // such entry with `unknown file type` at exit 0 (see `S_IFREG`).
        //
        // The `_` arm — `EntryKind::Other`, plus any variant `EntryKind`
        // grows later, since it is `#[non_exhaustive]` — deliberately gets
        // NEITHER treatment. `Other` is the one kind that does not say what
        // it is: a char device, a block device, a fifo, a socket and a
        // hardlink all arrive as it, so there are no correct type bits to
        // synthesise and forcing `S_IFREG` would relabel a device node as a
        // plain file — the same silent misrepresentation `entries.rs`
        // refuses to make when it SKIPS an `Other` entry on extraction
        // rather than materialising a 0-byte file where a device was.
        // Whatever the caller supplied is the only information available, so
        // it is written through untouched. stuffr's own pack never reaches
        // this arm: `walk.rs` marks every such item `ItemSource::Skipped`
        // before a plan is built, so only a hand-built plan can.
        let mode = match &meta.kind {
            EntryKind::Dir => (meta.mode.unwrap_or(DEFAULT_DIR_MODE) & !MODE_TYPE_MASK) | S_IFDIR,
            EntryKind::Symlink { .. } => {
                (meta.mode.unwrap_or(DEFAULT_SYMLINK_MODE) & !MODE_TYPE_MASK) | S_IFLNK
            }
            EntryKind::File => {
                let mode = meta.mode.unwrap_or(DEFAULT_FILE_MODE);
                if mode & MODE_TYPE_MASK == 0 {
                    mode | S_IFREG
                } else {
                    mode
                }
            }
            _ => meta.mode.unwrap_or(DEFAULT_FILE_MODE),
        };
        // Every entry goes out with `ino = 0`, `dev = 0` and `nlink = 1` —
        // the `cpio` crate's `Builder` defaults, left alone deliberately.
        // GNU cpio keys hardlink detection on `(dev, ino)`, so entries
        // sharing `(0, 0)` looks alarming, and is inert: its `copyin`
        // consults that pair only for an entry declaring `nlink > 1`, and
        // nothing here ever declares one. Measured, not reasoned about — a
        // 42-entry archive, every entry `(0, 0)`, extracts under GNU cpio
        // 2.15 as 42 independent files with the right contents and a link
        // count of 1 each. bsdcpio agrees.
        //
        // The condition is what matters if this ever changes: no container
        // in this tree writes a hardlink entry (see `walk.rs`'s
        // `hardlink_count`, which raises a fidelity warning saying so), so
        // `nlink` stays 1 and `ino` stays inert. Write a real hardlink entry
        // and `ino` must become unique per inode FIRST, or GNU cpio will
        // coalesce every entry in the archive into one file.
        let builder = cpio::newc::Builder::new(&meta.name)
            .mode(mode)
            .mtime(meta.mtime.map(unix_seconds).unwrap_or(0))
            .uid(meta.uid.unwrap_or(0))
            .gid(meta.gid.unwrap_or(0));

        let dst = self
            .dst
            .take()
            .ok_or_else(|| Error::Usage("cpio writer used after finish()".into()))?;
        let mut w = builder.write(dst, size);
        w.write_all(&buf)?;
        self.dst = Some(w.finish()?);
        Ok(())
    }

    /// Writes the `TRAILER!!!` entry that terminates a `newc` archive, then
    /// returns the destination. Never via `Drop` — see `tar.rs`'s own
    /// `finish` doc for why that is the one path a caller may rely on.
    ///
    /// The destination is returned, not finished: the caller owns completion,
    /// because a codec layer beneath us has its own trailer still to write.
    fn finish(mut self: Box<Self>) -> Result<Box<dyn Sink>> {
        let dst = self
            .dst
            .take()
            .ok_or_else(|| Error::Usage("cpio writer finished twice".into()))?;
        Ok(cpio::newc::trailer(dst)?)
    }
}

/// Seconds since the epoch, which is what `cpio::newc`'s `mtime` field
/// stores. A timestamp before 1970 clamps to zero rather than failing the
/// write, the same choice `tar.rs`'s own `unix_seconds` makes.
fn unix_seconds(t: SystemTime) -> u32 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .try_into()
        .unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stuffr_core::testing::{SharedBuf, assert_container_conforms, open_forward_only};
    use stuffr_core::{ArchiveRead, CreateOpts, OpenOpts, PlainSink, ReaderSource, Source};

    fn build_cpio(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let buf = SharedBuf::new();
        let mut w = CpioNewc
            .create(
                PlainSink::new(Box::new(buf.clone())),
                &CreateOpts::default(),
            )
            .expect("create");
        for (name, data) in entries {
            w.add(&EntryMeta::file(*name), &mut std::io::Cursor::new(*data))
                .expect("add");
        }
        w.finish().expect("finish").finish().expect("finish sink");
        buf.contents()
    }

    fn open(bytes: &[u8]) -> Box<dyn ArchiveRead> {
        let src: Box<dyn Source> =
            Box::new(ReaderSource::new(std::io::Cursor::new(bytes.to_vec())));
        let resolved = stuffr_core::resolve(
            src,
            CPIO,
            CpioNewc.caps(),
            &stuffr_core::StreamPolicy::default(),
        )
        .expect("resolve");
        CpioNewc.open(resolved, &OpenOpts::default()).expect("open")
    }

    fn which(bin: &str) -> Option<std::path::PathBuf> {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path).find_map(|dir| {
            let candidate = dir.join(bin);
            candidate.is_file().then_some(candidate)
        })
    }

    /// Locates `bin` on `PATH`, panicking rather than silently skipping if
    /// it is absent. CI always installs `cpio` (see the CI workflow's
    /// `gate` and `msrv` jobs) and `find` ships everywhere, so an absence
    /// here means only a contributor's own machine lacks it — and a silent
    /// `return` in that case would report every cross-implementation test
    /// in this file as PASSING having verified nothing at all, exactly the
    /// shape Finding 8 (Phase 1e) warns against. Failing loudly beats
    /// passing quietly.
    fn require_bin(bin: &str) -> std::path::PathBuf {
        which(bin).unwrap_or_else(|| {
            panic!(
                "no reference `{bin}` tool found on PATH — this test proved nothing, which is \
                 worth knowing rather than passing silently"
            )
        })
    }

    #[test]
    fn cpio_conforms() {
        assert_container_conforms(&CpioNewc, &meta());
    }

    #[test]
    fn capabilities_and_metadata_match_the_format() {
        let c = CpioNewc.caps();
        assert!(c.read && c.write && c.forward_parse);
        assert!(
            !c.trailing_index && !c.per_entry_codec && !c.solid && !c.needs_seek,
            "cpio newc has no index, no per-entry codec and no solid blocks"
        );
        let m = meta();
        assert_eq!(m.id, CPIO);
        assert_eq!(m.extensions, &["cpio"]);
    }

    /// The Phase 2 final review's I6.
    ///
    /// `find . -type f | cpio -o -H odc` produces a perfectly valid archive
    /// with magic `070707`. The `cpio` crate rejects that magic, and the
    /// rejection landed on `Error::Corrupt` — exit 5, telling a user their
    /// intact file was damaged. Exit 3 is the doctrine for "a capability
    /// this build does not have", and both recognised siblings now take it.
    #[test]
    fn a_recognised_cpio_variant_this_build_cannot_read_is_unsupported_not_corrupt() {
        // A real `newc` archive with only its magic rewritten, so the
        // refusal is provably decided on the magic rather than on anything
        // else being malformed.
        for (magic, expect_in_message) in [(b"070707", "odc"), (b"070702", "newc-crc")] {
            let mut bytes = build_cpio(&[("a.txt", b"alpha")]);
            bytes[..6].copy_from_slice(magic);

            // Surfaced from the first `next_entry`, not from `open`:
            // `open` reads no byte, so that container-harness property 10
            // (a source error passes through as itself, from a READ) still
            // holds. See `CpioNewc::open`'s own doc.
            let mut ar = open(&bytes);
            let err = ar
                .next_entry()
                .expect_err("a variant this build cannot read must be refused");

            assert!(
                matches!(err, Error::Unsupported(_)),
                "a valid archive in an unreadable variant is a capability limit \
                 (exit 3), not a damaged file (exit 5); got {err:?}"
            );
            assert_eq!(err.exit_code(), 3, "the doctrine is exit 3");
            let msg = err.to_string();
            assert!(
                msg.contains(expect_in_message),
                "the message must name the variant, got: {msg}"
            );
            assert!(
                !msg.contains("corrupt") && !msg.contains("Invalid magic"),
                "the message must not suggest damage, got: {msg}"
            );
        }
    }

    /// The regression guard for the test above: bytes that are NOT cpio at
    /// all, and a `newc` archive that is genuinely damaged, must both stay
    /// `Corrupt` (exit 5). Widening the variant check into "anything the
    /// parser dislikes is unsupported" would be a worse defect than I6.
    #[test]
    fn genuinely_broken_input_is_still_corrupt_not_unsupported() {
        // Right magic, truncated body.
        let mut bytes = build_cpio(&[("a.txt", b"alpha")]);
        bytes.truncate(20);
        let mut ar = open(&bytes);
        let err = ar
            .next_entry()
            .expect_err("a truncated newc archive must fail");
        assert_eq!(
            err.exit_code(),
            5,
            "a truncated archive is damaged, not a capability limit: {err:?}"
        );

        // Not cpio at all, but routed here by extension.
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(
            b"this is definitely not a cpio archive".to_vec(),
        )));
        let resolved = stuffr_core::resolve(
            src,
            CPIO,
            CpioNewc.caps(),
            &stuffr_core::StreamPolicy::default(),
        )
        .expect("resolve");
        let mut ar = CpioNewc
            .open(resolved, &OpenOpts::default())
            .expect("open must not pre-judge unknown bytes");
        let err = ar.next_entry().expect_err("must fail");
        assert_eq!(
            err.exit_code(),
            5,
            "bytes that are not cpio at all are corrupt for this container: {err:?}"
        );
    }

    /// A short stream must not be mistaken for a variant refusal — the
    /// prefix check has to tolerate fewer than six bytes and fall through
    /// to the crate's own truncation handling.
    #[test]
    fn a_stream_shorter_than_the_magic_falls_through_to_the_truncation_path() {
        for bytes in [b"".to_vec(), b"07".to_vec(), b"07070".to_vec()] {
            let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
            let resolved = stuffr_core::resolve(
                src,
                CPIO,
                CpioNewc.caps(),
                &stuffr_core::StreamPolicy::default(),
            )
            .expect("resolve");
            let mut ar = CpioNewc
                .open(resolved, &OpenOpts::default())
                .expect("a short stream is not a variant refusal");
            let err = ar.next_entry().expect_err("must fail as truncated");
            assert_eq!(err.exit_code(), 5, "got {err:?}");
        }
    }

    #[test]
    fn output_carries_the_newc_magic_at_offset_zero() {
        let bytes = build_cpio(&[("a.txt", b"alpha")]);
        assert_eq!(&bytes[..6], b"070701");
    }

    /// A zero-entry archive is exactly the trailer entry — nothing this
    /// container writes needs a caller to add an entry first.
    #[test]
    fn an_empty_archive_reads_back_as_zero_entries() {
        let bytes = build_cpio(&[]);
        let mut ar = open(&bytes);
        assert!(
            ar.next_entry().expect("must not be an error").is_none(),
            "a trailer-only archive must read back as zero entries"
        );
    }

    /// The refusal the brief's own test names: an entry larger than the
    /// `newc` format's `u32` `file_size` field must be a typed error naming
    /// the limit, not a silent truncating cast. Declares the size up front
    /// rather than actually supplying 4 GiB of data — `check_u32_size` is
    /// checked against `EntryMeta::size` before a byte is read, which is
    /// exactly what makes this fast rather than needing real gigabytes.
    #[test]
    fn cpio_refuses_an_entry_larger_than_its_u32_size_field() {
        let err = add_entry_of_declared_size(u64::from(u32::MAX) + 1).expect_err("refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("4 GiB") || msg.contains("u32"),
            "the error must name the limit: {msg}"
        );
        assert_eq!(
            err.exit_code(),
            3,
            "a format's own expressiveness limit is exit 3 — \"this build cannot do that\" — \
             never corruption (5), never a resource limit (6), and never a generic failure \
             (1). It asserted 1 until Phase 2's Task 11, which was asserting the accident \
             that `Error::Unsupported` fell through `exit_code`'s wildcard"
        );
    }

    fn add_entry_of_declared_size(size: u64) -> Result<()> {
        let mut w = CpioNewc
            .create(
                PlainSink::new(Box::new(SharedBuf::new())),
                &CreateOpts::default(),
            )
            .unwrap();
        let mut meta = EntryMeta::file("huge.bin");
        meta.size = Some(size);
        w.add(&meta, &mut std::io::empty())
    }

    /// Writes one entry and hands back the raw `mode` field of its header,
    /// straight out of the bytes — not what this container's own reader
    /// makes of them. The interop defect this pins is invisible to any
    /// reader tolerant enough to infer the kind (ours, and bsdcpio's), so
    /// the bytes are the only place it can be seen portably.
    fn written_mode(meta: &EntryMeta) -> u32 {
        let buf = SharedBuf::new();
        let mut w = CpioNewc
            .create(
                PlainSink::new(Box::new(buf.clone())),
                &CreateOpts::default(),
            )
            .unwrap();
        w.add(meta, &mut std::io::Cursor::new(b"m".as_slice()))
            .unwrap();
        w.finish().unwrap().finish().unwrap();

        // `newc`'s header is fixed-width ASCII hex: a six-byte magic, then
        // thirteen eight-byte fields of which `mode` is the second.
        let bytes = buf.contents();
        assert_eq!(&bytes[..6], b"070701", "not a newc header");
        let field = std::str::from_utf8(&bytes[6 + 8..6 + 16]).expect("ascii hex");
        u32::from_str_radix(field, 16).expect("hex mode")
    }

    /// The 0.2.0 interop defect, pinned at the byte level so it fails on
    /// every platform.
    ///
    /// `entries.rs`'s `mode_of` masks a walked file's mode to `0o7777`, so
    /// EVERY file packed from disk reaches this container with no `S_IFMT`
    /// bits at all — and `newc` has no other field naming the kind. GNU cpio
    /// 2.15 answers `unknown file type` to such an entry, SKIPS it, and
    /// still exits 0, so `stuffr pack -o x.cpio` followed by GNU `cpio -i`
    /// lost every regular file and reported success. bsdcpio — what macOS
    /// ships, and what `system_cpio_accepts_what_we_write` below therefore
    /// exercises — infers a regular file and extracts the same archive
    /// whole, which is why this shipped and why a reference-tool test alone
    /// could not be trusted to catch it.
    #[test]
    fn a_permission_only_file_mode_gains_the_regular_file_type_bits() {
        let mut meta = EntryMeta::file("m.txt");
        meta.mode = Some(0o640);
        assert_eq!(
            written_mode(&meta),
            0o100_640,
            "a file written with a permission-only mode must carry S_IFREG on the wire"
        );
    }

    /// The other half, and the reason the file arm ORs rather than masking
    /// and replacing the way the Dir and Symlink arms do: a mode that
    /// already names its kind is written through untouched.
    #[test]
    fn an_explicit_st_mode_shaped_file_mode_is_written_verbatim() {
        let mut meta = EntryMeta::file("m.txt");
        meta.mode = Some(0o100_644);
        assert_eq!(written_mode(&meta), 0o100_644);

        // Including one whose type bits are NOT a regular file's. `Other` is
        // the kind that cannot say what it is — see `add`'s own comment —
        // and the `_` arm must not relabel it.
        let mut dev = EntryMeta::file("c");
        dev.kind = EntryKind::Other;
        dev.mode = Some(0o020_644);
        assert_eq!(written_mode(&dev), 0o020_644);
    }

    /// A mode with no `S_IFMT` type bits at all (a caller-supplied mode with
    /// none set, as opposed to this container's own defaulted one) must
    /// still read back as a plain file — see `entry_kind`'s own doc for why
    /// `Other` would be the wrong answer here. It reads back as `0o100640`
    /// rather than the `0o640` written, because `add` folds `S_IFREG` in;
    /// the permission bits are what must survive, and do.
    #[test]
    fn an_explicit_mode_with_no_type_bits_still_reads_back_as_a_file() {
        let buf = SharedBuf::new();
        let mut w = CpioNewc
            .create(
                PlainSink::new(Box::new(buf.clone())),
                &CreateOpts::default(),
            )
            .unwrap();
        let mut meta = EntryMeta::file("m.txt");
        meta.mode = Some(0o640);
        w.add(&meta, &mut std::io::Cursor::new(b"m".as_slice()))
            .unwrap();
        w.finish().unwrap().finish().unwrap();

        let mut ar = open(&buf.contents());
        let entry = ar.next_entry().unwrap().unwrap();
        assert_eq!(entry.meta().mode, Some(0o100_640));
        assert_eq!(entry.meta().kind, EntryKind::File);
    }

    #[test]
    fn a_directory_entry_with_no_mode_defaults_to_an_executable_one() {
        let buf = SharedBuf::new();
        let mut w = CpioNewc
            .create(
                PlainSink::new(Box::new(buf.clone())),
                &CreateOpts::default(),
            )
            .unwrap();
        let mut dir = EntryMeta::file("d");
        dir.kind = EntryKind::Dir;
        w.add(&dir, &mut std::io::Cursor::new(&[][..])).unwrap();
        w.finish().unwrap().finish().unwrap();

        let mut ar = open(&buf.contents());
        let entry = ar.next_entry().unwrap().unwrap();
        assert_eq!(entry.meta().mode, Some(DEFAULT_DIR_MODE));
        assert_eq!(entry.meta().kind, EntryKind::Dir);
    }

    /// A symlink's target lives in the payload, not a header field — see the
    /// module doc's "Symlinks" section. This is the round trip the
    /// coordinator's fix request is centred on.
    #[test]
    fn a_symlink_entry_round_trips_its_kind_and_target() {
        let buf = SharedBuf::new();
        let mut w = CpioNewc
            .create(
                PlainSink::new(Box::new(buf.clone())),
                &CreateOpts::default(),
            )
            .unwrap();
        let mut link = EntryMeta::file("mylink");
        link.kind = EntryKind::Symlink {
            target: "../escaped/target.txt".into(),
        };
        // Empty data: a symlink's target comes from `meta.kind`, never from
        // the caller's data reader — mirrors `tar.rs`'s own test fixtures.
        w.add(&link, &mut std::io::Cursor::new(&[][..])).unwrap();
        w.finish().unwrap().finish().unwrap();

        let mut ar = open(&buf.contents());
        let entry = ar.next_entry().unwrap().unwrap();
        assert_eq!(entry.meta().name, "mylink");
        assert_eq!(
            entry.meta().kind,
            EntryKind::Symlink {
                target: "../escaped/target.txt".into()
            },
            "a symlink entry that lost its target would extract as an empty file"
        );
    }

    /// A symlink target past [`MAX_SYMLINK_TARGET_LEN`] is refused before a
    /// single byte is read, not silently allocated. Written through this
    /// container's own writer (which places no cap of its own on the WRITE
    /// side — only the read-side eager buffer needs bounding) so the fixture
    /// is a realistic, well-formed archive, not a hand-crafted one.
    #[test]
    fn a_symlink_target_past_the_length_ceiling_is_refused() {
        let buf = SharedBuf::new();
        let mut w = CpioNewc
            .create(
                PlainSink::new(Box::new(buf.clone())),
                &CreateOpts::default(),
            )
            .unwrap();
        let mut link = EntryMeta::file("mylink");
        link.kind = EntryKind::Symlink {
            target: "x".repeat((MAX_SYMLINK_TARGET_LEN + 1) as usize),
        };
        w.add(&link, &mut std::io::Cursor::new(&[][..])).unwrap();
        w.finish().unwrap().finish().unwrap();

        let mut ar = open(&buf.contents());
        let err = ar
            .next_entry()
            .expect_err("an implausibly long symlink target must be refused");
        assert!(
            matches!(err, stuffr_core::Error::ResourceLimit(_)),
            "got {err:?}"
        );
        assert_eq!(err.exit_code(), 6, "a resource limit is exit 6, never 5");
    }

    /// `newc` has no field OTHER than the mode's own type bits to record
    /// "this is a directory" or "this is a symlink" (see the module doc) —
    /// so a caller supplying a PERMISSION-ONLY mode (no `S_IFDIR`/`S_IFLNK`
    /// bit at all, exactly what `entries_extract.rs`'s own tar fixtures use:
    /// `dir.mode = Some(0o750)`, `symlink.mode = Some(0o777)`) must still
    /// round-trip as the right kind, not silently misread as a plain file.
    #[test]
    fn a_directory_or_symlink_with_a_permission_only_mode_still_normalizes_the_type_bits() {
        let buf = SharedBuf::new();
        let mut w = CpioNewc
            .create(
                PlainSink::new(Box::new(buf.clone())),
                &CreateOpts::default(),
            )
            .unwrap();

        let mut dir = EntryMeta::file("d");
        dir.kind = EntryKind::Dir;
        dir.mode = Some(0o750); // no S_IFDIR bit
        w.add(&dir, &mut std::io::Cursor::new(&[][..])).unwrap();

        let mut link = EntryMeta::file("d/link");
        link.kind = EntryKind::Symlink {
            target: "target.txt".into(),
        };
        link.mode = Some(0o777); // no S_IFLNK bit
        w.add(&link, &mut std::io::Cursor::new(&[][..])).unwrap();

        w.finish().unwrap().finish().unwrap();

        let mut ar = open(&buf.contents());
        let d = ar.next_entry().unwrap().unwrap();
        assert_eq!(d.meta().kind, EntryKind::Dir, "must not misread as a file");
        assert_eq!(
            d.meta().mode,
            Some(S_IFDIR | 0o750),
            "the caller's permission bits must survive alongside the normalised type bits"
        );
        drop(d);

        let l = ar.next_entry().unwrap().unwrap();
        assert_eq!(
            l.meta().kind,
            EntryKind::Symlink {
                target: "target.txt".into()
            },
            "must not misread as a file"
        );
        assert_eq!(l.meta().mode, Some(S_IFLNK | 0o777));
    }

    #[test]
    fn add_measures_the_payload_when_the_caller_does_not_declare_a_size() {
        let buf = SharedBuf::new();
        let mut w = CpioNewc
            .create(
                PlainSink::new(Box::new(buf.clone())),
                &CreateOpts::default(),
            )
            .unwrap();
        let meta = EntryMeta::file("unknown-length.bin");
        assert_eq!(meta.size, None, "the point of this test");
        w.add(
            &meta,
            &mut std::io::Cursor::new(&b"twenty-two bytes long!"[..]),
        )
        .unwrap();
        w.finish().unwrap().finish().unwrap();

        let mut ar = open(&buf.contents());
        let mut entry = ar.next_entry().unwrap().unwrap();
        let mut got = Vec::new();
        entry.reader().read_to_end(&mut got).unwrap();
        assert_eq!(&got[..], b"twenty-two bytes long!");
    }

    /// A caller who skips straight to the next entry without reading the
    /// current one's payload at all must still see every entry in order —
    /// proving `next_entry`'s own "finish the previous entry" step (see the
    /// module doc) works when nothing was read, not only when everything was.
    #[test]
    fn skipping_an_entrys_payload_entirely_does_not_disturb_the_next_one() {
        let bytes = build_cpio(&[("a.txt", b"alpha"), ("b.txt", b"beta")]);
        let mut ar = open(&bytes);

        let first = ar.next_entry().unwrap().unwrap();
        assert_eq!(first.meta().name, "a.txt");
        drop(first); // never read

        let mut second = ar.next_entry().unwrap().unwrap();
        assert_eq!(second.meta().name, "b.txt");
        let mut got = Vec::new();
        second.reader().read_to_end(&mut got).unwrap();
        assert_eq!(&got[..], b"beta");
    }

    /// `by_index` is never random access here, on either source shape — the
    /// same double-check `tar.rs` and `ar.rs` pin for the identical reason.
    #[test]
    fn by_index_is_refused_on_every_source_shape() {
        let bytes = build_cpio(&[("a.txt", b"alpha"), ("b.txt", b"beta")]);

        let mut fwd = open_forward_only(&CpioNewc, &bytes);
        assert!(
            matches!(fwd.by_index(0), Err(stuffr_core::Error::NotSeekable { .. })),
            "a forward-only source must answer NotSeekable"
        );

        let path = std::env::temp_dir().join(format!(
            "stuffr-cpio-seekable-{}-{:p}.cpio",
            std::process::id(),
            &bytes
        ));
        std::fs::write(&path, &bytes).unwrap();
        let src: Box<dyn Source> = Box::new(stuffr_core::FileSource::open(&path).unwrap());
        let _ = std::fs::remove_file(&path);
        let resolved = stuffr_core::resolve(
            src,
            CPIO,
            CpioNewc.caps(),
            &stuffr_core::StreamPolicy::default(),
        )
        .unwrap();
        let mut seekable = CpioNewc.open(resolved, &OpenOpts::default()).unwrap();
        let err = seekable
            .by_index(0)
            .expect_err("cpio has no index to index into");
        assert!(
            matches!(err, stuffr_core::Error::Unsupported(_)),
            "a seekable source is not the problem — cpio has no index to index into: {err:?}"
        );
        // Exit 3, "this build cannot do that", not the generic 1 it reported
        // until Phase 2's Task 11 gave `Error::Unsupported` an explicit arm.
        // A caller asking for random access a format never had should be able
        // to tell that answer from an internal failure.
        assert_eq!(err.exit_code(), 3, "{err}");
    }

    /// A cut inside an entry's payload. `cpio::newc::Reader`'s own `Read`
    /// impl does not detect this itself (see the module doc);
    /// `CpioEntryPayload` does.
    #[test]
    fn a_cut_inside_an_entry_payload_is_reported_as_corrupt() {
        let payload = stuffr_core::testing::incompressible(64 * 1024);
        let bytes = build_cpio(&[("big.bin", &payload)]);
        // The header is 110 bytes plus the padded name ("big.bin\0" = 8,
        // padded to 12 with the 110-byte header for a 4-byte-aligned total
        // of 124), then the payload.
        for cut in [125usize, 1024, 32768, 124 + 65536 - 1] {
            let mut ar = open(&bytes[..cut]);
            let mut err = None;
            loop {
                match ar.next_entry() {
                    Ok(Some(mut entry)) => {
                        let mut sink = Vec::new();
                        if let Err(e) = entry.reader().read_to_end(&mut sink) {
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

    /// Cross-implementation arbiter: what stuffr writes must read back
    /// through a real `cpio`. CI installs it explicitly (unlike `tar`/`ar`,
    /// `ubuntu-latest` does not ship it — see the CI workflow); a
    /// contributor's machine lacking it fails this test loudly rather than
    /// passing having verified nothing (Phase 1e, Finding 8, repeating) —
    /// see `require_bin`.
    #[test]
    fn system_cpio_accepts_what_we_write() {
        let cpio_bin = require_bin("cpio");

        // Built by hand rather than through `build_cpio`, which only ever
        // writes plain files: this also covers the symlink round trip in
        // the forward direction, per the coordinator's fix request.
        let buf = SharedBuf::new();
        let mut w = CpioNewc
            .create(
                PlainSink::new(Box::new(buf.clone())),
                &CreateOpts::default(),
            )
            .unwrap();
        w.add(
            &EntryMeta::file("a.txt"),
            &mut std::io::Cursor::new(b"alpha".as_slice()),
        )
        .unwrap();
        w.add(
            &EntryMeta::file("dir/b.bin"),
            &mut std::io::Cursor::new(b"\x00\xff\x00".as_slice()),
        )
        .unwrap();
        let mut link = EntryMeta::file("mylink");
        link.kind = EntryKind::Symlink {
            target: "a.txt".into(),
        };
        w.add(&link, &mut std::io::Cursor::new(&[][..])).unwrap();
        w.finish().unwrap().finish().unwrap();
        let bytes = buf.contents();

        // Verbose listing (`-itv`), not plain `-it`: only the verbose form
        // shows a symlink's leading `l` type and its `-> target` — plain
        // `-it` prints names only and would pass even if the mode bits were
        // wrong and the entry were misread as a regular file.
        let mut child = std::process::Command::new(&cpio_bin)
            .args(["-itv"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&bytes)
            .expect("write archive to system cpio's stdin");
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "system cpio rejected our archive: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let listing = String::from_utf8_lossy(&out.stdout);
        assert!(listing.contains("a.txt"), "listing was {listing:?}");
        assert!(listing.contains("dir/b.bin"), "listing was {listing:?}");
        let link_line = listing
            .lines()
            .find(|l| l.contains("mylink"))
            .unwrap_or_else(|| panic!("mylink missing from listing: {listing:?}"));
        assert!(
            link_line.starts_with('l'),
            "system cpio did not read our entry back as a symlink: {link_line:?}"
        );
        assert!(
            link_line.contains("mylink -> a.txt"),
            "system cpio's listing must show the target: {link_line:?}"
        );
    }

    /// The reverse direction: a symlink `cpio` itself wrote (from a REAL
    /// symlink on disk, via `find | cpio -o -H newc`) must read back through
    /// this container as `EntryKind::Symlink` with the exact target — not
    /// `Other`, and not a file holding the target string as file contents.
    #[test]
    fn we_accept_a_symlink_system_cpio_writes() {
        let cpio_bin = require_bin("cpio");
        let find_bin = require_bin("find");

        let dir = std::env::temp_dir().join(format!(
            "stuffr-cpio-reverse-symlink-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("target.txt"), b"hello").unwrap();
        std::os::unix::fs::symlink("target.txt", dir.join("mylink")).unwrap();

        let find = std::process::Command::new(&find_bin)
            .arg(".")
            .current_dir(&dir)
            .output()
            .unwrap();
        assert!(find.status.success(), "find failed");

        let mut child = std::process::Command::new(&cpio_bin)
            .args(["-o", "-H", "newc"])
            .current_dir(&dir)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&find.stdout).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "system cpio could not write the fixture: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let mut ar = open(&out.stdout);
        let mut found = None;
        while let Some(entry) = ar.next_entry().unwrap() {
            if entry.meta().name.ends_with("mylink") {
                found = Some(entry.meta().kind.clone());
            }
        }
        assert_eq!(
            found,
            Some(EntryKind::Symlink {
                target: "target.txt".into()
            }),
            "a symlink system cpio wrote must read back as EntryKind::Symlink with the right \
             target, not Other or a file"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The empty-archive case specifically, mirroring `ar.rs`'s equivalent:
    /// measured directly against this machine's `cpio` (`bsdcpio`), which
    /// pads an archive it writes itself out to a full 512-byte block —
    /// this container's own trailer-only output is nowhere near that (124
    /// bytes), and must still be accepted.
    #[test]
    fn system_cpio_accepts_an_empty_archive_we_write() {
        let cpio_bin = require_bin("cpio");

        let bytes = build_cpio(&[]);
        let mut child = std::process::Command::new(&cpio_bin)
            .args(["-it"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&bytes).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "system cpio rejected our empty archive: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            out.stdout.is_empty(),
            "an empty archive must list zero members: {:?}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    /// The reverse of the test above: this container must read `cpio`'s OWN
    /// empty archive too, not just accept the one it wrote itself. Measured
    /// directly on this machine (`bsdcpio` 3.5.3): `printf '' | cpio -o -H
    /// newc` produces exactly 512 bytes — a bare `TRAILER!!!` header padded
    /// out to a full block — against this container's own 124-byte
    /// equivalent (110-byte header + 11-byte padded name + 3 bytes of
    /// 4-byte alignment padding, no block padding at all). That gap is
    /// exactly the shape that hid `bsdtar`'s zero-margin empty `.tar`
    /// (1024 bytes, no slack) from Task 7 until a read-direction test was
    /// added for tar too — see `tar.rs`'s
    /// `every_reference_writer_is_accepted_including_its_empty_archive`.
    #[test]
    fn we_accept_an_empty_archive_system_cpio_writes() {
        let cpio_bin = require_bin("cpio");

        let mut child = std::process::Command::new(&cpio_bin)
            .args(["-o", "-H", "newc"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        // No input at all: an archive with zero entries.
        drop(child.stdin.take());
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "system cpio could not write an empty archive: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let mut ar = open(&out.stdout);
        assert!(
            ar.next_entry()
                .expect("bsdcpio's own empty archive must read back as zero entries, not an error")
                .is_none(),
            "an empty archive must have zero entries"
        );
    }

    /// I6 against a REAL `odc` archive, written by the system tool rather
    /// than by patching a magic constant this test also asserts.
    ///
    /// The unit test above proves the classification; this proves the magic
    /// `070707` is genuinely what `cpio -o -H odc` emits, so the two cannot
    /// agree with each other while both being wrong about the format.
    #[test]
    fn a_real_odc_archive_from_system_cpio_is_unsupported_not_corrupt() {
        let cpio_bin = require_bin("cpio");

        let mut child = std::process::Command::new(&cpio_bin)
            .args(["-o", "-H", "odc"])
            .current_dir(std::env::temp_dir())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        // An empty archive is enough: the magic is in the trailer header
        // too, and this needs no file on disk to exist.
        drop(child.stdin.take());
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "system cpio could not write an odc archive: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            &out.stdout[..6],
            b"070707",
            "the reference tool's own odc magic must be what this build refuses on"
        );

        let mut ar = open(&out.stdout);
        let err = ar
            .next_entry()
            .expect_err("a valid odc archive must be refused, not read");
        assert_eq!(
            err.exit_code(),
            3,
            "an intact archive in an unreadable variant is exit 3, never 5: {err:?}"
        );
    }

    /// `require_bin` is what makes a missing reference tool a loud failure
    /// rather than a silent skip — proven directly, on a name guaranteed
    /// absent from `PATH`, rather than trusted by inspection alone.
    #[test]
    #[should_panic(expected = "no reference `this-binary-does-not-exist-xyz` tool found on PATH")]
    fn require_bin_panics_rather_than_skips_silently() {
        require_bin("this-binary-does-not-exist-xyz");
    }

    // --- Task 5c: the `c_namesize` OOM the fuzzer found -------------------
    //
    // `cpio-0.4.1/src/newc.rs`'s `Reader::new` allocates `vec![0u8; name_len]`
    // — `name_len` taken straight from the header's `c_namesize` field —
    // BEFORE reading a single byte of the name. A header declaring
    // `0x80000000` buys a ~2 GiB zeroed allocation from a handful of bytes on
    // disk; the real fuzz target hit `libFuzzer: out-of-memory
    // (malloc(2863311530))` inside this exact call.

    /// One field of a `newc` header: 8 lowercase-hex ASCII digits, exactly
    /// what `cpio::newc::read_hex_u32` (vendored crate source, quoted in the
    /// task brief) parses back out.
    fn hex8(n: u32) -> [u8; 8] {
        let s = format!("{n:08x}");
        s.as_bytes().try_into().unwrap()
    }

    /// A hand-built, byte-level `newc` header — magic plus all thirteen
    /// fixed 8-byte fields, `c_namesize` set to an absurd value and NOTHING
    /// after it: no name bytes, not even the rest of a real archive. Total
    /// length is exactly `HEADER_LEN` (110: 6-byte magic + 13 8-byte
    /// fields) — see the crate's own `newc.rs` `HEADER_LEN` constant, quoted
    /// in this module's doc.
    ///
    /// `0xAAAA_AAAA` (2_863_311_530) is not a round number chosen for looks —
    /// it is the exact figure the real fuzz reproducer's libFuzzer abort
    /// named (`malloc(2863311530)`), so this header reproduces the same
    /// declared size the fuzzer actually found, not a stand-in for it.
    const ABSURD_NAMESIZE: u32 = 0xAAAA_AAAA;

    fn header_declaring_namesize(namesize: u32) -> Vec<u8> {
        let mut h = Vec::with_capacity(110);
        h.extend_from_slice(b"070701"); // c_magic (newc)
        h.extend_from_slice(&hex8(0)); // c_ino
        h.extend_from_slice(&hex8(0o100_644)); // c_mode: regular file
        h.extend_from_slice(&hex8(0)); // c_uid
        h.extend_from_slice(&hex8(0)); // c_gid
        h.extend_from_slice(&hex8(1)); // c_nlink
        h.extend_from_slice(&hex8(0)); // c_mtime
        h.extend_from_slice(&hex8(0)); // c_filesize
        h.extend_from_slice(&hex8(0)); // c_devmajor
        h.extend_from_slice(&hex8(0)); // c_devminor
        h.extend_from_slice(&hex8(0)); // c_rdevmajor
        h.extend_from_slice(&hex8(0)); // c_rdevminor
        h.extend_from_slice(&hex8(namesize)); // c_namesize
        h.extend_from_slice(&hex8(0)); // c_checksum
        assert_eq!(h.len(), 110, "must be exactly HEADER_LEN, no name bytes");
        h
    }

    /// A `Source` that panics if ever asked to fill a buffer larger than
    /// `max_single_read`.
    ///
    /// This is what turns "no allocation happened" from an assertion into
    /// something a test can actually falsify. `cpio::newc::Reader::new`'s
    /// name-reading code is the ONLY caller anywhere in this path that would
    /// ever request a buffer sized by an attacker-controlled `c_namesize` —
    /// and it allocates that buffer (`vec![0u8; name_len]`) BEFORE handing it
    /// to `read_exact`, so a request here for anything past a sane header-
    /// sized window proves that allocation already happened. A pre-flight
    /// refusal that runs before `Reader::new` is ever reached can never trip
    /// this guard; a refusal bolted on AFTER the crate's own parsing (i.e.
    /// the bug, un-fixed) trips it on the very first oversized read.
    struct PanicsOnBigRead {
        inner: std::io::Cursor<Vec<u8>>,
        max_single_read: usize,
    }

    impl Read for PanicsOnBigRead {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            assert!(
                buf.len() <= self.max_single_read,
                "a single read of {} bytes was requested — past the {}-byte guard. This is \
                 proof the oversized `c_namesize` allocation (`vec![0u8; name_len]` inside the \
                 `cpio` crate's `Reader::new`) was reached before any refusal ran, i.e. the \
                 pre-flight check did not fire before the crate's own parser did",
                buf.len(),
                self.max_single_read
            );
            std::io::Read::read(&mut self.inner, buf)
        }
    }

    impl Source for PanicsOnBigRead {
        fn caps(&self) -> stuffr_core::SourceCaps {
            stuffr_core::SourceCaps {
                seekable: false,
                len: None,
            }
        }
        fn as_seek(&mut self) -> Option<&mut dyn stuffr_core::SeekRead> {
            None
        }
    }

    fn open_guarded(bytes: Vec<u8>, max_single_read: usize) -> Box<dyn ArchiveRead> {
        let src: Box<dyn Source> = Box::new(PanicsOnBigRead {
            inner: std::io::Cursor::new(bytes),
            max_single_read,
        });
        let resolved = stuffr_core::resolve(
            src,
            CPIO,
            CpioNewc.caps(),
            &stuffr_core::StreamPolicy::default(),
        )
        .expect("resolve");
        CpioNewc
            .open(resolved, &OpenOpts::default())
            .expect("open reads no byte")
    }

    /// The failing-first test for Task 5c: an absurd `c_namesize` must be
    /// refused as a typed error, at exit 6 (`Error::ResourceLimit`) — never
    /// exit 5 (`Error::Corrupt`), and never by way of the 2.6 GiB allocation
    /// the un-fixed crate makes on the way to failing. `max_single_read` is
    /// set to `PROBE_LEN` (4096, the peek window this fix itself uses) —
    /// generous for any legitimate header read, and roughly six orders of
    /// magnitude below the declared name length, so nothing on the honest
    /// path can trip it.
    #[test]
    fn refuses_an_absurd_namesize_before_the_allocation_it_would_size() {
        let bytes = header_declaring_namesize(ABSURD_NAMESIZE);
        let mut ar = open_guarded(bytes, stuffr_core::PROBE_LEN);

        let err = ar
            .next_entry()
            .expect_err("an absurd c_namesize must be refused");

        assert!(
            matches!(err, Error::ResourceLimit(_)),
            "an implausible declared name length is this build refusing to allocate, not a \
             verdict that the file is damaged — see MAX_CPIO_NAME_LEN's doc; got {err:?}"
        );
        assert_eq!(err.exit_code(), 6, "ResourceLimit is exit 6: {err:?}");
        let msg = err.to_string();
        assert!(
            msg.contains(&ABSURD_NAMESIZE.to_string()),
            "the message must name the declared size, got: {msg}"
        );
    }

    /// The regression guard for the test above: a header naming a namesize
    /// UNDER the ceiling must still fail (there is no name data behind it,
    /// so it is a truncated archive), but as ordinary corruption — exit 5 —
    /// never `ResourceLimit`. Pins that the new check is bounded by
    /// `MAX_CPIO_NAME_LEN`, not "any namesize with no data behind it."
    #[test]
    fn a_modest_namesize_with_no_data_behind_it_is_corrupt_not_resource_limited() {
        let bytes = header_declaring_namesize(64);
        let mut ar = open_guarded(bytes, 4096);
        let err = ar
            .next_entry()
            .expect_err("a truncated entry must still fail");
        assert_eq!(
            err.exit_code(),
            5,
            "a small, merely-truncated namesize is corruption, not a resource ceiling: {err:?}"
        );
    }

    /// A legitimate long name — well past any ordinary path, comfortably
    /// under the ceiling — must still round-trip. Guards against the
    /// obvious way to get this wrong: picking a ceiling so tight it refuses
    /// real archives, which this project has shipped before (see
    /// `CLAUDE.md`'s running count of checks that fired on legitimate
    /// input).
    #[test]
    fn a_legitimate_long_name_still_round_trips() {
        let deep_name: String = std::iter::repeat_n("segment/", 500).collect::<String>() + "leaf";
        assert!(
            deep_name.len() < 65_536,
            "fixture must stay under the ceiling to prove a real long name is unaffected"
        );
        let bytes = build_cpio(&[(deep_name.as_str(), b"payload")]);
        let mut ar = open(&bytes);
        let entry = ar
            .next_entry()
            .expect("a legitimate long name must not be refused")
            .expect("must yield the one entry written");
        assert_eq!(entry.meta().name, deep_name);
    }
    /// A timing harness, not a gate — see the note in this module's
    /// `CpioSource` doc. Reads a forward-only (pipe-shaped) archive at two
    /// entry counts an order of magnitude apart and prints the wall time
    /// for each, so the growth can be read off directly.
    ///
    /// `#[ignore]`d deliberately: the numbers below are seconds on an idle
    /// machine, and any ratio assertion tight enough to separate linear
    /// from quadratic is loose enough to flake on a loaded CI runner. The
    /// regression guard for the shape this measures is a TYPE-level one
    /// instead (see `CpioSource`'s doc); this test exists so the
    /// measurement can be reproduced on demand:
    ///
    /// ```text
    /// cargo test -p stuffr-formats --features cpio --release --lib \
    ///     -- --ignored --nocapture scales
    /// ```
    #[test]
    #[ignore = "timing harness, run explicitly with --ignored --nocapture"]
    fn a_forward_read_scales_linearly_with_entry_count() {
        for n in [10_000usize, 100_000usize] {
            let names: Vec<String> = (0..n).map(|i| format!("entry{i:07}")).collect();
            let entries: Vec<(&str, &[u8])> =
                names.iter().map(|s| (s.as_str(), &b""[..])).collect();
            let bytes = build_cpio(&entries);
            let started = std::time::Instant::now();
            let mut ar = open_forward_only(&CpioNewc, &bytes);
            let mut seen = 0usize;
            while let Some(entry) = ar.next_entry().expect("forward read") {
                let _ = entry.meta();
                seen += 1;
            }
            let elapsed = started.elapsed();
            assert_eq!(seen, n, "every entry must come back");
            println!("forward read: {n} entries in {elapsed:?}");
        }
    }
}
