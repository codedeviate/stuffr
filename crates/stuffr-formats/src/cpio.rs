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
//! carries this information at all. `EntryKind::File` is deliberately left
//! unnormalised: property 11 requires an explicit file mode to round-trip
//! VERBATIM, and doing so already produces a correct entry, since this
//! format does not require the `S_IFREG` bit to identify a plain file (see
//! `entry_kind`'s own doc — the absence of every OTHER type's bits is what
//! decides `File`).

use std::io::{self, Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use stuffr_core::{
    ArchiveRead, ArchiveWrite, Container, ContainerCaps, CreateOpts, Entry, EntryKind, EntryMeta,
    Error, FidelityReport, FormatId, FormatMeta, MagicRule, OpenOpts, Resolved, Result, Source,
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
            ..Default::default()
        }
    }

    fn open(&self, resolved: Resolved, _o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
        let Resolved { source, report, .. } = resolved;
        let seekable = source.caps().seekable;
        Ok(Box::new(CpioRead {
            state: CpioState::Idle(source),
            report,
            seekable,
        }))
    }

    fn create(&self, dst: Box<dyn Write + Send>, _o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
        Ok(Box::new(CpioWrite { dst: Some(dst) }))
    }
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

type CpioSource = Box<dyn Source>;

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
}

impl ArchiveRead for CpioRead {
    fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
        // Recover the raw reader, finishing off whatever entry the PREVIOUS
        // call returned — `Reader::finish` drains any bytes the caller did
        // not read itself, exactly as if the caller had read them.
        let src = match std::mem::replace(&mut self.state, CpioState::Ended) {
            CpioState::Idle(src) => src,
            CpioState::Reading(reader) => reader.finish().map_err(classify_cpio_error)?,
            CpioState::Ended => return Ok(None),
        };

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
    dst: Option<Box<dyn Write + Send>>,
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
            if let Some(size) = meta.size {
                check_u32_size(&meta.name, size)?;
            }
            let mut buf = Vec::new();
            data.read_to_end(&mut buf)?;
            buf
        };
        let size = check_u32_size(&meta.name, buf.len() as u64)?;

        // `newc` has no field OTHER than the mode's own type bits to record
        // "this is a directory" or "this is a symlink" — so, unlike
        // `EntryKind::File` (left alone below; property 11 requires an
        // explicit file mode to round-trip verbatim), a Dir or Symlink mode
        // is normalised regardless of what the caller supplied, masking out
        // whatever type bits (if any) were already there and OR-ing in the
        // correct ones. See the module doc for why leaving this to the
        // caller would be a real interop defect, not merely an internal
        // inconsistency.
        let mode = match &meta.kind {
            EntryKind::Dir => (meta.mode.unwrap_or(DEFAULT_DIR_MODE) & !MODE_TYPE_MASK) | S_IFDIR,
            EntryKind::Symlink { .. } => {
                (meta.mode.unwrap_or(DEFAULT_SYMLINK_MODE) & !MODE_TYPE_MASK) | S_IFLNK
            }
            _ => meta.mode.unwrap_or(DEFAULT_FILE_MODE),
        };
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
    /// flushes. Never via `Drop` — see `tar.rs`'s own `finish` doc for why
    /// that is the one path a caller may rely on.
    fn finish(mut self: Box<Self>) -> Result<()> {
        let dst = self
            .dst
            .take()
            .ok_or_else(|| Error::Usage("cpio writer finished twice".into()))?;
        let mut dst = cpio::newc::trailer(dst)?;
        dst.flush()?;
        Ok(())
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
    use stuffr_core::{ArchiveRead, CreateOpts, OpenOpts, ReaderSource, Source};

    fn build_cpio(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let buf = SharedBuf::new();
        let mut w = CpioNewc
            .create(Box::new(buf.clone()), &CreateOpts::default())
            .expect("create");
        for (name, data) in entries {
            w.add(&EntryMeta::file(*name), &mut std::io::Cursor::new(*data))
                .expect("add");
        }
        w.finish().expect("finish");
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
            1,
            "an unsupported-format limitation is a generic failure, not corruption or a \
             resource limit"
        );
    }

    fn add_entry_of_declared_size(size: u64) -> Result<()> {
        let mut w = CpioNewc
            .create(Box::new(SharedBuf::new()), &CreateOpts::default())
            .unwrap();
        let mut meta = EntryMeta::file("huge.bin");
        meta.size = Some(size);
        w.add(&meta, &mut std::io::empty())
    }

    /// A mode with no `S_IFMT` type bits at all (a caller-supplied mode with
    /// none set, as opposed to this container's own defaulted one) must
    /// still read back as a plain file — see `entry_kind`'s own doc for why
    /// `Other` would be the wrong answer here.
    #[test]
    fn an_explicit_mode_with_no_type_bits_still_reads_back_as_a_file() {
        let buf = SharedBuf::new();
        let mut w = CpioNewc
            .create(Box::new(buf.clone()), &CreateOpts::default())
            .unwrap();
        let mut meta = EntryMeta::file("m.txt");
        meta.mode = Some(0o640);
        w.add(&meta, &mut std::io::Cursor::new(b"m".as_slice()))
            .unwrap();
        w.finish().unwrap();

        let mut ar = open(&buf.contents());
        let entry = ar.next_entry().unwrap().unwrap();
        assert_eq!(entry.meta().mode, Some(0o640));
        assert_eq!(entry.meta().kind, EntryKind::File);
    }

    #[test]
    fn a_directory_entry_with_no_mode_defaults_to_an_executable_one() {
        let buf = SharedBuf::new();
        let mut w = CpioNewc
            .create(Box::new(buf.clone()), &CreateOpts::default())
            .unwrap();
        let mut dir = EntryMeta::file("d");
        dir.kind = EntryKind::Dir;
        w.add(&dir, &mut std::io::Cursor::new(&[][..])).unwrap();
        w.finish().unwrap();

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
            .create(Box::new(buf.clone()), &CreateOpts::default())
            .unwrap();
        let mut link = EntryMeta::file("mylink");
        link.kind = EntryKind::Symlink {
            target: "../escaped/target.txt".into(),
        };
        // Empty data: a symlink's target comes from `meta.kind`, never from
        // the caller's data reader — mirrors `tar.rs`'s own test fixtures.
        w.add(&link, &mut std::io::Cursor::new(&[][..])).unwrap();
        w.finish().unwrap();

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
            .create(Box::new(buf.clone()), &CreateOpts::default())
            .unwrap();
        let mut link = EntryMeta::file("mylink");
        link.kind = EntryKind::Symlink {
            target: "x".repeat((MAX_SYMLINK_TARGET_LEN + 1) as usize),
        };
        w.add(&link, &mut std::io::Cursor::new(&[][..])).unwrap();
        w.finish().unwrap();

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
            .create(Box::new(buf.clone()), &CreateOpts::default())
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

        w.finish().unwrap();

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
        assert!(
            matches!(
                seekable.by_index(0),
                Err(stuffr_core::Error::Unsupported(_))
            ),
            "a seekable source is not the problem — cpio has no index to index into"
        );
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
            .create(Box::new(buf.clone()), &CreateOpts::default())
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
        w.finish().unwrap();
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

    /// `require_bin` is what makes a missing reference tool a loud failure
    /// rather than a silent skip — proven directly, on a name guaranteed
    /// absent from `PATH`, rather than trusted by inspection alone.
    #[test]
    #[should_panic(expected = "no reference `this-binary-does-not-exist-xyz` tool found on PATH")]
    fn require_bin_panics_rather_than_skips_silently() {
        require_bin("this-binary-does-not-exist-xyz");
    }
}
