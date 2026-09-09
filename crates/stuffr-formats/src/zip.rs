//! zip and zip64, via the `zip` crate — the first container in this tree
//! whose authoritative metadata lives at the END of the stream.
//!
//! tar, ar and cpio all carry every entry's metadata inline, so a forward read
//! loses nothing and their `ContainerCaps::trailing_index` is `false`. zip's
//! is `true`, and that single flag is where the project's streaming claim
//! finally costs something. Five decisions below follow from it, and none of
//! them is the `zip` crate's default behaviour.
//!
//! # Two readers, one per rung, because zip really does have two formats
//!
//! * **Seekable source → [`Rung::Exact`].** `zip::ZipArchive` reads the
//!   central directory at the end of the file, which is the only place a zip
//!   stores unix modes, file comments and an entry COUNT. `by_index` works.
//! * **Non-seekable source → [`Rung::ForwardOnly`].** `zip::read::
//!   read_zipfile_from_stream` walks LOCAL headers instead. The data is
//!   identical; the metadata is a strict subset — `external_attributes` is
//!   documented as zero on this path, so `unix_mode()` returns `None`, which
//!   in turn means a **symlink is indistinguishable from a regular file
//!   holding its target as contents** (`S_IFLNK` lives nowhere else in a
//!   zip). That is a real loss and it is reported as one:
//!   [`Fidelity::TrailingIndexUnread`] plus [`Fidelity::EntryCountUnknown`],
//!   the vocabulary Phase 0 defined for exactly this, seeded by
//!   `ladder::seed_report` and re-asserted here so the report is complete
//!   however it was constructed.
//!
//! The rung describes the ACCESS PATH and the warnings describe the LOSS —
//! `--strict-fidelity` gates on the warnings (see
//! `FidelityReport::has_warnings`). A piped zip therefore fails strict mode,
//! where a piped tar does not, and that difference is the honest one.
//! `by_index` on the forward reader is `Err(NotSeekable)`, never a re-scan
//! billed as random access.
//!
//! # The forward reader has to check the trailing structure ITSELF
//!
//! Measured, not assumed. `read_zipfile_from_stream` stops the moment it sees
//! a central-directory signature and returns `Ok(None)` — "no more files" —
//! without reading a byte of what follows. So an archive truncated anywhere
//! in its central directory or its end-of-central-directory record reads back
//! as COMPLETE, which conformance property 9 (a cut one byte from the end)
//! catches immediately. This is the same class of hole `tar.rs`'s
//! `verify_end_of_archive` exists for, and [`verify_trailing_index`] closes
//! it the same way: after `Ok(None)`, walk the central directory's own framing
//! forward — fixed block, name, extra, comment, repeat — through the optional
//! zip64 records and require a whole end-of-central-directory record to be
//! present.
//!
//! Forward parsing rather than the backward EOCD SEARCH a seekable reader
//! does, for two reasons: a pipe cannot seek, and a forward walk is
//! unambiguous where the search is not (a `PK\x05\x06` inside a file comment
//! is exactly the case that makes the backward search heuristic). Constant
//! memory — nothing is buffered, the fields are skipped by their declared
//! lengths.
//!
//! Whatever follows the EOCD record is ignored, as every zip tool ignores it.
//! This walks the index's FRAMING and deliberately reads none of its
//! CONTENTS, so `TrailingIndexUnread` stays true: entry metadata still came
//! from the inline local headers.
//!
//! # Writing: `new_stream` cannot be used, and the reason is structural
//!
//! `ZipWriter::new_stream` is the obvious choice for a `Box<dyn Write>`
//! destination, and it produces archives THIS CRATE CANNOT READ FORWARD.
//! `new_stream` sets `seek_possible: false`, which makes every entry use a
//! DATA DESCRIPTOR: the local header's crc32 and both size fields are written
//! as zero and the real values follow the payload. `ZipFileData::
//! from_local_block` refuses that outright —
//! `UnsupportedArchive("The file length is not available in the local
//! header")` — because a streaming reader cannot know where a payload of
//! undeclared length ends. Conformance property 3's round trip goes through
//! the forward reader (its source is a `ReaderSource`, which reports
//! `seekable: false`), so `new_stream` fails the very first property.
//!
//! A zip local header must therefore carry the crc32 and the compressed size,
//! and neither is known until the payload has been compressed. Something has
//! to hold bytes back. [`Spool`] holds back exactly ONE entry: it presents a
//! `Write + Seek` face to `ZipWriter` over an in-memory window, and
//! [`ZipWrite::add`] commits everything below the new entry's header offset to
//! the real destination as soon as `start_file` has fixed up the PREVIOUS
//! entry's header. Peak memory is one entry's compressed size, not the
//! archive's — which is the true floor for zip-without-seek, and is asserted
//! by `the_writer_does_not_buffer_the_whole_archive`.
//!
//! A useful side effect: every write `ZipWriter` issues lands in memory and
//! cannot fail, so the destination's first failure is observed by `commit`,
//! which this module calls — `zip`'s own `Drop` never gets to run a failing
//! `finalize` and print to stderr.
//!
//! # `finish()` explicitly, never `Drop`
//!
//! `impl<W: Write + Seek> Drop for ZipWriter<W>` finalizes the archive and
//! writes any failure to **stderr**, losing it. Conformance property 4 exists
//! for precisely this hazard (`tar::Builder` has the same shape), so
//! [`ZipWrite::finish`] takes the writer out of its `Option` and calls
//! `ZipWriter::finish` itself.
//!
//! # The one capability difference between the build tiers
//!
//! zip's `zstd` feature is the only entry codec that pulls a C-compiling
//! crate (`zstd-sys`), so it is reached only through `stuffr-formats/
//! zip-zstd`, which the facade's `c-backed` bundle turns on. On the default
//! tier a zstd-compressed zip ENTRY is refused as an
//! [`Error::Unsupported`] naming `--features c-backed` — never as
//! corruption, which would tell a user their perfectly good zip was damaged.
//! Note the asymmetry that makes this worth spelling out: the pure tier reads
//! a standalone `.zst` file fine, through `ruzstd`; it is only the in-zip
//! method that is missing. Encrypted entries and the legacy pre-deflate
//! methods are refused the same way, for the same reason.

use std::cell::RefCell;
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use stuffr_core::{
    ArchiveRead, ArchiveWrite, Container, ContainerCaps, CreateOpts, Entry, EntryKind, EntryMeta,
    Error, Fidelity, FidelityReport, FormatId, FormatMeta, MagicRule, OpenOpts, Resolved, Result,
    Rung, SeekRead, Source,
};
use zip::CompressionMethod;
use zip::result::ZipError;
use zip::write::SimpleFileOptions;

use crate::normalize::{NormalizeDecodeErrors, ZIP_MALFORMED_AS_INVALID_INPUT_EOF};

pub const ZIP: FormatId = FormatId::new("zip");

/// Two rules, and property 2 requires only that ONE of them match.
///
/// `PK\x03\x04` is a local file header, so it is the first four bytes of every
/// zip that has at least one entry. An EMPTY zip has no local header at all:
/// it is a bare end-of-central-directory record, `PK\x05\x06`, 22 bytes
/// total. Registering only the first would leave `stuffr` unable to detect an
/// empty zip by magic — a real file that `unzip` and `zip -sf` both accept,
/// and one this container writes itself.
static ZIP_MAGIC: &[MagicRule] = &[
    MagicRule {
        offset: 0,
        bytes: b"PK\x03\x04",
        format: ZIP,
    },
    MagicRule {
        offset: 0,
        bytes: b"PK\x05\x06",
        format: ZIP,
    },
];

/// Registration metadata for zip.
///
/// No `priority` yet, deliberately. `FormatMeta::priority` exists for the ZIP
/// FAMILY — jar, apk, docx, epub and odt all begin `PK\x03\x04`, and ranking
/// the base format above its derivatives is what lets a bare stream resolve to
/// `zip` while `foo.apk` reaches apk by extension. None of those derivatives is
/// registered in this build, so there is nothing to outrank; the moment one is,
/// it gets a lower priority than this and this gets a higher one than 0.
pub fn meta() -> FormatMeta {
    FormatMeta::container(ZIP, &["zip"], ZIP_MAGIC)
}

/// Central-directory file header. Signature plus a 42-byte fixed block.
const SIG_CENTRAL_HEADER: [u8; 4] = *b"PK\x01\x02";
/// End of central directory. Signature plus an 18-byte fixed block.
const SIG_END_OF_CENTRAL_DIR: [u8; 4] = *b"PK\x05\x06";
/// Zip64 end of central directory. Signature plus an 8-byte self-describing
/// length.
const SIG_ZIP64_END: [u8; 4] = *b"PK\x06\x06";
/// Zip64 end-of-central-directory locator. Signature plus 16 fixed bytes.
const SIG_ZIP64_LOCATOR: [u8; 4] = *b"PK\x06\x07";

/// Bytes of a central-directory file header after its signature.
const CENTRAL_HEADER_FIXED: usize = 42;
/// Bytes of an end-of-central-directory record after its signature.
const END_OF_CENTRAL_DIR_FIXED: usize = 18;
/// Bytes of a zip64 EOCD locator after its signature.
const ZIP64_LOCATOR_FIXED: usize = 16;

/// A symlink's target lives in its PAYLOAD (the mode's `S_IFLNK` bits are the
/// only signal that an entry is one), so the seekable reader reads it eagerly.
/// The cap is checked against the DECLARED size before a byte is read, exactly
/// as `cpio.rs`'s equivalent is: containers receive no `--memory-limit` at all
/// (`OpenOpts` carries no such field), and `--max-ratio` bounds decoded bytes
/// against compressed ones, which does not meaningfully bind a stored target.
/// Without this, a hostile entry claiming an implausible size under an
/// `S_IFLNK` mode could force that allocation before any caller asked to read
/// anything.
const MAX_SYMLINK_TARGET_LEN: u64 = 65_536;

/// The mode zip stores for a file entry when the caller declares none. zip's
/// own `DEFAULT_FILE_PERMISSIONS`, and what every zip tool writes.
const DEFAULT_FILE_MODE: u32 = 0o644;

/// `EntryMeta::codec` for a stored (uncompressed) entry. Deliberately a value
/// rather than `None`: `None` on a `per_entry_codec` container reads as "not
/// known", and "this entry is not compressed" is a different, knowable fact.
const STORE: FormatId = FormatId::new("store");

pub struct Zip;

impl Container for Zip {
    fn id(&self) -> FormatId {
        ZIP
    }

    fn caps(&self) -> ContainerCaps {
        ContainerCaps {
            read: true,
            write: true,
            // Local headers carry each entry's name, size and compressed size,
            // so a forward read yields real DATA. It does not yield real
            // metadata, which is what `trailing_index` below says.
            forward_parse: true,
            // The central directory is at the END of the stream. This flag is
            // what conformance property 7 keys on — zip is the first container
            // in this tree for which that property does anything at all — and
            // what makes `ladder::seed_report` warn on a forward read.
            trailing_index: true,
            // Every entry names its own compression method, and they may
            // differ within one archive. `EntryMeta::codec` reports it.
            per_entry_codec: true,
            ..Default::default()
        }
    }

    fn open(&self, resolved: Resolved, _o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
        let Resolved { source, report, .. } = resolved;

        if source.caps().seekable {
            // Authoritative: the central directory carries real metadata and
            // enables `by_index`. Reached for `Rung::Exact` (a file) and for
            // `Rung::Spilled` (a pipe the ladder spooled), both of which are
            // authoritative and neither of which loses anything, so the
            // report is carried through unchanged.
            let archive = zip::ZipArchive::new(SeekAdapter(source)).map_err(classify_zip_error)?;
            return Ok(Box::new(ZipIndexed {
                archive,
                report,
                next: 0,
            }));
        }

        // Forward: local headers only. `FidelityReport` has no `downgrade`, so
        // the ForwardOnly report is built and the ladder's own merged into it —
        // `merge` keeps the WORSE rung, so a `Degraded` report survives while
        // an optimistic one cannot. Unconditional rather than guarded on the
        // inherited rung: `resolve` only ever hands a non-seekable source a
        // non-authoritative rung today, and this makes property 7 hold by
        // construction rather than by that coincidence.
        let mut report = {
            let mut r = FidelityReport::new(Rung::ForwardOnly);
            r.merge(&report);
            r
        };
        // `ladder::seed_report` already adds both for a `trailing_index`
        // container, and `merge` above will have carried them over. Added here
        // only if absent, so the caller is told once — never twice, and never
        // not at all if a future `Resolved` arrives without them.
        for w in [
            Fidelity::TrailingIndexUnread { format: ZIP },
            Fidelity::EntryCountUnknown,
        ] {
            if !report.warnings.contains(&w) {
                report.warn(w);
            }
        }
        Ok(Box::new(ZipStreamed {
            source: Pushback {
                inner: source,
                held: Vec::new(),
            },
            report,
            ended: false,
        }))
    }

    fn create(&self, dst: Box<dyn Write + Send>, o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
        // Validated before a single byte is written, the way `Codec::
        // check_encode_opts` is called before `ops` touches the filesystem: a
        // caller naming an entry codec this build cannot produce, or a level
        // that codec does not have, should be refused now — not halfway
        // through an archive, with a partly-written destination behind it.
        let method = method_for(o.entry_codec)?;
        check_level(method, o.level)?;
        let spool = Rc::new(RefCell::new(Spool::new(dst)));
        Ok(Box::new(ZipWrite {
            inner: Some(zip::ZipWriter::new(SpoolHandle(Rc::clone(&spool)))),
            spool,
            method,
            level: o.level,
        }))
    }
}

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

/// Folds a `ZipError` into this project's vocabulary.
///
/// The two interesting cases are the ones that must NOT become
/// [`Error::Corrupt`]:
///
/// * `UnsupportedArchive` and `CompressionMethodNotSupported` describe a
///   perfectly good zip this build cannot fully read — an encrypted entry, a
///   pre-deflate legacy method, a zstd entry on the pure tier, or a
///   data-descriptor entry met on a pipe. Reporting exit 5 there would tell
///   the user their file is damaged when it is not.
/// * A genuine source failure (`ZipError::Io` carrying `PermissionDenied`,
///   say) passes through as itself — conformance property 10.
///
/// `UnexpectedEof` is the exception within `Io`: `zip`'s header parsing uses
/// `read_exact`, so a stream that runs out mid-structure surfaces as an I/O
/// error even though it is really a cut archive. That single kind is folded
/// onto [`Error::Corrupt`] (exit 5), which is what conformance property 9
/// requires and what `Error::from_decode_io` would otherwise leave at exit 1.
fn classify_zip_error(e: ZipError) -> Error {
    match e {
        ZipError::Io(io_err) => {
            if io_err.kind() == ErrorKind::UnexpectedEof {
                return Error::Corrupt(format!("zip stream ended mid-structure: {io_err}"));
            }
            Error::from_decode_io(io_err)
        }
        ZipError::InvalidArchive(msg) => Error::Corrupt(msg.into_owned()),
        ZipError::UnsupportedArchive(msg) => Error::Unsupported(format!(
            "this build cannot read that zip: {msg}{}",
            unsupported_hint(msg)
        )),
        ZipError::CompressionMethodNotSupported(id) => Error::Unsupported(format!(
            "zip entry uses compression method {id} ({}), which this build cannot decompress{}",
            method_name(id),
            method_hint(id)
        )),
        ZipError::FileNotFound => Error::EntryNotFound("requested zip entry".into()),
        ZipError::InvalidPassword => {
            Error::Usage("the supplied password does not decrypt this zip entry".into())
        }
        // `ZipError` is `#[non_exhaustive]`. A variant added upstream is more
        // likely to be another "cannot read this" than damage, so it lands on
        // `Unsupported` (exit 1) rather than silently claiming corruption
        // (exit 5).
        other => Error::Unsupported(other.to_string()),
    }
}

/// Extra guidance for the `UnsupportedArchive` messages this module can
/// actually meet, so the refusal says what to do next rather than only what
/// went wrong. Matched on the message because `zip` carries no code for these.
fn unsupported_hint(msg: &str) -> &'static str {
    if msg.contains("Encrypted") {
        return "; stuffr is built without zip's `aes-crypto` feature, so it cannot decrypt \
                entries at all";
    }
    if msg.contains("file length is not available") {
        return "; this entry uses a data descriptor, so its length is only known AFTER its \
                data — read the archive from a real file rather than a pipe, which lets the \
                central directory supply it";
    }
    ""
}

/// A zip compression method's name, for an error a human has to act on.
fn method_name(id: u16) -> &'static str {
    match id {
        0 => "store",
        1 => "shrink",
        2..=5 => "reduce",
        6 => "implode",
        8 => "deflate",
        9 => "deflate64",
        12 => "bzip2",
        14 => "lzma",
        93 => "zstd",
        95 => "xz",
        98 => "ppmd",
        99 => "AES-encrypted",
        _ => "unrecognised",
    }
}

/// What a caller can do about an unsupported method. Only zstd has an answer.
fn method_hint(id: u16) -> &'static str {
    if id == 93 {
        // The documented capability gap. zip's `zstd` feature is the one that
        // pulls `zstd-sys`, so it lives behind `c-backed`.
        return "; rebuild with `--features c-backed` to read zstd-compressed zip entries \
                (a standalone .zst file already works on this build)";
    }
    ""
}

// ---------------------------------------------------------------------------
// Reading: the seekable (Exact) rung
// ---------------------------------------------------------------------------

/// Presents a ladder [`Source`] as the `Read + Seek` that `zip::ZipArchive`
/// requires.
///
/// Only constructed once `source.caps().seekable` is known true, so `as_seek`
/// returning `None` is unreachable; it is reported as an I/O error rather than
/// a panic because `Seek` has no other channel.
struct SeekAdapter(Box<dyn Source>);

impl Read for SeekAdapter {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Seek for SeekAdapter {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let seek: &mut dyn SeekRead = self
            .0
            .as_seek()
            .ok_or_else(|| io::Error::other("zip: source reported seekable but cannot seek"))?;
        seek.seek(pos)
    }
}

struct ZipIndexed {
    archive: zip::ZipArchive<SeekAdapter>,
    report: FidelityReport,
    /// Cursor for `next_entry`. `by_index` does not disturb it — the two are
    /// independent views of the same index, which is the point of having one.
    next: usize,
}

impl ZipIndexed {
    fn entry_at(&mut self, index: usize) -> Result<Entry<'_>> {
        let mut file = self.archive.by_index(index).map_err(classify_zip_error)?;
        let mut meta = entry_meta(&file, file.unix_mode());

        // A symlink's target is its payload — read it now, while the entry is
        // in hand, the same narrow exception `cpio.rs` makes for the same
        // reason. Bounded by `MAX_SYMLINK_TARGET_LEN` before anything is read.
        if file.is_symlink() {
            let target = read_symlink_target(&mut file, &meta.name)?;
            meta.kind = EntryKind::Symlink { target };
            // The payload is consumed; nothing is left for a caller to read.
            // `entries::extract` never calls `.reader()` for a `Symlink`
            // entry — it uses `meta.kind`'s own target — the convention tar's
            // and cpio's symlink entries already rely on.
            return Ok(Entry::new(meta, Box::new(io::empty())));
        }

        Ok(Entry::new(
            meta,
            Box::new(NormalizeDecodeErrors::new(
                file,
                ZIP_MALFORMED_AS_INVALID_INPUT_EOF,
            )),
        ))
    }
}

impl ArchiveRead for ZipIndexed {
    fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
        if self.next >= self.archive.len() {
            return Ok(None);
        }
        let index = self.next;
        self.next += 1;
        self.entry_at(index).map(Some)
    }

    /// Real random access: the central directory was read, so entry `index`
    /// is reachable without touching any other entry.
    fn by_index(&mut self, index: usize) -> Result<Entry<'_>> {
        let len = self.archive.len();
        if index >= len {
            return Err(Error::EntryNotFound(format!(
                "index {index}; this archive has {len} entries"
            )));
        }
        self.entry_at(index)
    }

    fn fidelity(&self) -> &FidelityReport {
        &self.report
    }
}

// ---------------------------------------------------------------------------
// Reading: the forward-only rung
// ---------------------------------------------------------------------------

/// The ladder's source with room to put a four-byte signature back.
///
/// [`ZipStreamed::next_entry`] reads each record's signature ITSELF and
/// dispatches on it, then replays it for `read_zipfile_from_stream` when it
/// turns out to be a local file header. Two reasons, and the first is a
/// correctness bug rather than a preference:
///
/// 1. **An EMPTY zip is not a local header and is not a central-directory
///    header either.** It is a bare end-of-central-directory record,
///    `PK\x05\x06`. `read_zipfile_from_stream` returns `Ok(None)` only for
///    `PK\x01\x02`; handed `PK\x05\x06` it returns
///    `InvalidArchive("Invalid local file header")` — so delegating the
///    end-of-entries decision to it reports a perfectly good empty zip as
///    CORRUPT. Conformance property 3 checks the zero-entry round trip first,
///    for exactly this class of mistake.
/// 2. Dispatching here also lets [`verify_trailing_index`] be told which
///    signature it starts from, instead of having to assume the one the crate
///    happened to consume.
struct Pushback {
    inner: Box<dyn Source>,
    /// Bytes read ahead and not yet handed on. At most one four-byte
    /// signature at a time.
    held: Vec<u8>,
}

impl Pushback {
    fn push_back(&mut self, bytes: &[u8]) {
        self.held.extend_from_slice(bytes);
    }
}

impl Read for Pushback {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.held.is_empty() && !buf.is_empty() {
            let n = self.held.len().min(buf.len());
            buf[..n].copy_from_slice(&self.held[..n]);
            self.held.drain(..n);
            return Ok(n);
        }
        // `Read`'s contract: an empty buffer reads nothing and is not an
        // error, whether or not anything is held back.
        if buf.is_empty() {
            return Ok(0);
        }
        self.inner.read(buf)
    }
}

/// Local file header. What every entry starts with.
const SIG_LOCAL_HEADER: [u8; 4] = *b"PK\x03\x04";

struct ZipStreamed {
    source: Pushback,
    report: FidelityReport,
    /// Set once the entries have run out (or a read has failed), so the
    /// trailing-structure check runs exactly once and a caller polling past
    /// the end gets `Ok(None)` rather than the same error repeatedly. The
    /// same shape `tar.rs`'s `ended` has.
    ended: bool,
}

impl ArchiveRead for ZipStreamed {
    fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
        if self.ended {
            return Ok(None);
        }

        // Dispatch on the record signature here rather than letting the crate
        // do it — see [`Pushback`] for the empty-archive bug that costs.
        let signature = read_fixed::<4>(&mut self.source, "entry or central directory signature")?;
        if signature != SIG_LOCAL_HEADER {
            self.ended = true;
            // Everything from here on is the trailing index, which
            // `read_zipfile_from_stream` would never have looked at. See the
            // module doc for why that leaves a truncated archive undetected.
            verify_trailing_index(&mut self.source, signature)?;
            return Ok(None);
        }
        self.source.push_back(&signature);

        let file = match zip::read::read_zipfile_from_stream(&mut self.source) {
            Ok(Some(file)) => file,
            // Unreachable: the signature just replayed IS a local file
            // header, and that is the one input for which the crate does not
            // return `None`. Reported rather than silently ended, because
            // ending here would skip the trailing-index check and accept a
            // truncated archive.
            Ok(None) => {
                self.ended = true;
                return Err(Error::Corrupt(
                    "zip: a local file header signature was not accepted as one".into(),
                ));
            }
            Err(e) => {
                self.ended = true;
                return Err(classify_zip_error(e));
            }
        };

        // `unix_mode()` is documented as `None` on this path: the external
        // attributes that carry it live only in the central directory. Passed
        // explicitly rather than read off the entry so the seekable path is
        // the only one that CAN supply a mode, and this one visibly cannot.
        let meta = entry_meta(&file, None);
        Ok(Some(Entry::new(
            meta,
            Box::new(NormalizeDecodeErrors::new(
                file,
                ZIP_MALFORMED_AS_INVALID_INPUT_EOF,
            )),
        )))
    }

    /// Forward-only: there is no index to index INTO. Returning an entry here
    /// would be random access faked over a source that does not have it, which
    /// conformance property 6 exists to catch.
    fn by_index(&mut self, _index: usize) -> Result<Entry<'_>> {
        Err(Error::NotSeekable { format: ZIP })
    }

    fn fidelity(&self) -> &FidelityReport {
        &self.report
    }
}

/// Walks the central directory's FRAMING forward, from just after the
/// signature `read_zipfile_from_stream` already consumed, and requires a whole
/// end-of-central-directory record to be present.
///
/// This is the forward reader's truncation check for everything after the last
/// entry — see the module doc for why the crate itself cannot provide it.
/// Constant memory: every variable-length field is skipped by the length the
/// structure declares, never buffered.
///
/// The contents of the index are deliberately not read. A cut here is damage
/// and is reported as [`Error::Corrupt`]; a byte that follows a complete EOCD
/// record is ignored, exactly as every zip tool ignores it.
fn verify_trailing_index(source: &mut Pushback, first: [u8; 4]) -> Result<()> {
    let mut signature = first;
    loop {
        match signature {
            SIG_CENTRAL_HEADER => {
                let fixed = read_fixed::<CENTRAL_HEADER_FIXED>(source, "central directory header")?;
                // Offsets are relative to the start of this 42-byte block,
                // i.e. four less than the offsets in APPNOTE 4.3.12: name
                // length at 28, extra at 30, comment at 32.
                let name = u16::from_le_bytes([fixed[24], fixed[25]]);
                let extra = u16::from_le_bytes([fixed[26], fixed[27]]);
                let comment = u16::from_le_bytes([fixed[28], fixed[29]]);
                skip(
                    source,
                    u64::from(name) + u64::from(extra) + u64::from(comment),
                    "central directory header fields",
                )?;
            }
            SIG_ZIP64_END => {
                // Self-describing: an 8-byte size counting everything after
                // itself. Skipping by it rather than by a fixed width is what
                // makes this tolerant of the zip64 extensible data sector.
                let size = read_fixed::<8>(source, "zip64 end of central directory")?;
                skip(
                    source,
                    u64::from_le_bytes(size),
                    "zip64 end of central directory",
                )?;
            }
            SIG_ZIP64_LOCATOR => {
                read_fixed::<ZIP64_LOCATOR_FIXED>(
                    source,
                    "zip64 end of central directory locator",
                )?;
            }
            SIG_END_OF_CENTRAL_DIR => {
                let fixed =
                    read_fixed::<END_OF_CENTRAL_DIR_FIXED>(source, "end of central directory")?;
                let comment = u16::from_le_bytes([fixed[16], fixed[17]]);
                skip(
                    source,
                    u64::from(comment),
                    "end-of-central-directory comment",
                )?;
                return Ok(());
            }
            other => {
                return Err(Error::Corrupt(format!(
                    "unexpected signature {other:02x?} in this zip's central directory; the \
                     archive's trailing index is damaged"
                )));
            }
        }
        signature = read_fixed::<4>(source, "central directory signature")?;
    }
}

/// Reads exactly `N` bytes, reporting a short read as the truncation it is.
///
/// `what` names the structure that was cut, so the error tells a user WHERE
/// the archive ends rather than only that it does. A genuine source failure
/// keeps its own kind and exit code — the `UnexpectedEof` fold lives in
/// [`classify_zip_error`], which is exactly the distinction property 10 turns
/// on.
fn read_fixed<const N: usize>(source: &mut Pushback, what: &str) -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    let mut filled = 0;
    while filled < N {
        match source.read(&mut buf[filled..]).map_err(Error::from)? {
            0 => {
                return Err(Error::Corrupt(format!(
                    "zip stream ends {filled} bytes into a {N}-byte {what}; the archive is \
                     truncated"
                )));
            }
            n => filled += n,
        }
    }
    Ok(buf)
}

/// Discards `count` bytes, reporting a short stream as truncation. A fixed
/// scratch buffer, so an absurd declared length costs time rather than memory.
fn skip(source: &mut Pushback, mut count: u64, what: &str) -> Result<()> {
    let mut scratch = [0u8; 4096];
    while count > 0 {
        let want = count.min(scratch.len() as u64) as usize;
        match source.read(&mut scratch[..want]).map_err(Error::from)? {
            0 => {
                return Err(Error::Corrupt(format!(
                    "zip stream ends {count} bytes short of the end of its {what}; the archive \
                     is truncated"
                )));
            }
            n => count -= n as u64,
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry metadata
// ---------------------------------------------------------------------------

/// Everything this container reports about one entry.
///
/// `mode` is passed in rather than read off `file`: only the seekable reader
/// has one (it comes from the central directory's external attributes), and
/// making that a parameter is what stops the forward path from acquiring it by
/// accident. It is `st_mode`-shaped — type bits included, e.g. `0o100644` —
/// the same shape `cpio.rs` reports, which `entries::apply_metadata` masks to
/// `0o7777`.
///
/// Names are NOT sanitised: harness property 12 requires them verbatim, and
/// the ops-layer refusal can only refuse what it can still see.
fn entry_meta<R: Read>(file: &zip::read::ZipFile<'_, R>, mode: Option<u32>) -> EntryMeta {
    // Name-based, and therefore the one kind that survives a forward read
    // intact: a zip directory entry is a zero-length entry whose name ends in
    // `/`. `S_IFLNK` has no such fallback, which is why a piped read cannot
    // see symlinks at all (see the module doc).
    let kind = if file.is_dir() {
        EntryKind::Dir
    } else {
        // Symlinks are upgraded by `ZipIndexed::entry_at`, which has the mode
        // to detect them and can read the target. `File` is the honest answer
        // wherever that has not happened.
        EntryKind::File
    };

    EntryMeta {
        name: file.name().to_owned(),
        size: Some(file.size()),
        compressed_size: Some(file.compressed_size()),
        mtime: file.last_modified().and_then(system_time_from_dos),
        mode,
        // zip has no uid/gid field at all outside the Info-ZIP extra fields
        // this build does not parse. `None` says so.
        uid: None,
        gid: None,
        kind,
        codec: Some(codec_for(file.compression())),
        // No `..Default::default()`: every `EntryMeta` field is set above, and
        // clippy's `needless_update` denies the trailing rest pattern once
        // that is true. A field added to `EntryMeta` later will therefore
        // fail to compile here, which is the right way round — this container
        // should have to decide what a zip says about a new field rather than
        // silently defaulting it.
    }
}

/// Reads a symlink entry's target out of its payload. Refuses a declared
/// length past [`MAX_SYMLINK_TARGET_LEN`] before reading anything, and treats
/// a short payload as the truncation it is rather than reporting a partial
/// target as the whole thing.
fn read_symlink_target<R: Read>(
    file: &mut zip::read::ZipFile<'_, R>,
    name: &str,
) -> Result<String> {
    let declared = file.size();
    if declared > MAX_SYMLINK_TARGET_LEN {
        return Err(Error::Corrupt(format!(
            "entry `{name}` is a symlink whose target is declared as {declared} bytes, past the \
             {MAX_SYMLINK_TARGET_LEN}-byte limit; refusing to allocate that for a path"
        )));
    }
    let mut target = Vec::with_capacity(declared as usize);
    file.read_to_end(&mut target)
        .map_err(|e| Error::from_decode_io(normalize_payload_error(e)))?;
    if target.len() as u64 != declared {
        return Err(Error::Corrupt(format!(
            "entry `{name}` is a symlink declaring a {declared}-byte target but supplied {}; \
             the archive is truncated",
            target.len()
        )));
    }
    Ok(String::from_utf8_lossy(&target).into_owned())
}

/// Folds the kinds zip's payload readers use for malformed data onto
/// `InvalidData`, so [`Error::from_decode_io`] classifies them as corruption.
/// The same rule [`NormalizeDecodeErrors`] applies to a caller-driven payload
/// read, applied to the one payload this module reads for itself.
fn normalize_payload_error(e: io::Error) -> io::Error {
    if ZIP_MALFORMED_AS_INVALID_INPUT_EOF.contains(&e.kind()) {
        return io::Error::new(ErrorKind::InvalidData, e.to_string());
    }
    e
}

/// Which `FormatId` an entry's compression method names.
///
/// Reported even for methods this build cannot DECODE (`deflate64`, `ppmd`,
/// and `zstd` on the pure tier): `stuffr list` should be able to say what an
/// entry is compressed with before anything tries to read it, and that is the
/// whole point of `per_entry_codec`. Ids match this project's own registered
/// format names where one exists, so a caller can look them up.
///
/// Compared against `CompressionMethod`'s associated CONSTANTS rather than a
/// numeric conversion, deliberately: `CompressionMethod` is
/// `#[non_exhaustive]`, its `serialize_to_u16` is `pub(crate)`, `from_u16` is
/// deprecated, and — the part that matters — the enum's variants are
/// themselves feature-gated, so `CompressionMethod::ZSTD` is `Zstd` on one
/// tier and `Unsupported(93)` on the other. The constants are defined for
/// every method on every tier and compare equal to whatever the parser
/// produced, which makes this one match work identically in both builds.
fn codec_for(method: CompressionMethod) -> FormatId {
    for (m, id) in [
        (CompressionMethod::STORE, STORE),
        (CompressionMethod::DEFLATE, FormatId::new("deflate")),
        (CompressionMethod::DEFLATE64, FormatId::new("deflate64")),
        (CompressionMethod::BZIP2, FormatId::new("bzip2")),
        (CompressionMethod::LZMA, FormatId::new("lzma")),
        (CompressionMethod::ZSTD, FormatId::new("zstd")),
        (CompressionMethod::XZ, FormatId::new("xz")),
        (CompressionMethod::PPMD, FormatId::new("ppmd")),
        (CompressionMethod::AES, FormatId::new("aes")),
    ] {
        if method == m {
            return id;
        }
    }
    FormatId::new("unknown")
}

/// A zip `DateTime` (an MS-DOS civil date) as a `SystemTime`.
///
/// `None` for a date the format cannot represent — `try_from_msdos` rejects a
/// day-of-month past the month's length, which a hand-built or damaged header
/// can carry. An unreadable timestamp is metadata this container does not
/// have, not a reason to refuse the entry.
fn system_time_from_dos(dt: zip::DateTime) -> Option<SystemTime> {
    // `PrimitiveDateTime` rather than `OffsetDateTime`: zip gates the
    // `OffsetDateTime` conversions behind its own `deprecated-time` feature,
    // which this build does not enable. A zip stores a civil date with no
    // zone, so `assume_utc` is the honest reading — the same convention every
    // zip tool applies.
    let secs = time::PrimitiveDateTime::try_from(dt)
        .ok()?
        .assume_utc()
        .unix_timestamp();
    // MS-DOS dates start at 1980, so a negative timestamp is not reachable
    // from a valid `DateTime`; `try_from` is what guarantees that, and this
    // conversion refuses rather than wrapping if it ever stops being true.
    u64::try_from(secs)
        .ok()
        .map(|s| UNIX_EPOCH + Duration::from_secs(s))
}

/// A `SystemTime` as the MS-DOS civil date a zip header stores.
///
/// Clamps rather than fails, the same choice `tar.rs`'s `unix_seconds` makes:
/// MS-DOS dates cover only 1980-2107, and refusing to archive a file because
/// of its mtime would be a worse answer than recording the nearest date the
/// format has. `DateTime::DEFAULT` is 1980-01-01 00:00:00.
fn dos_from_system_time(t: SystemTime) -> zip::DateTime {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    time::OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|odt| {
            zip::DateTime::try_from(time::PrimitiveDateTime::new(odt.date(), odt.time())).ok()
        })
        .unwrap_or(zip::DateTime::DEFAULT)
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// Which zip compression method an `EntryMeta`/`CreateOpts` codec id names.
///
/// `None` means "the container's own default", which is deflate — what every
/// zip tool writes and what every zip reader understands. A named codec this
/// build cannot produce is refused with [`Error::Unsupported`] rather than
/// silently downgraded to deflate, because the output would afterwards be
/// indistinguishable from what was asked for.
fn method_for(codec: Option<FormatId>) -> Result<CompressionMethod> {
    let Some(id) = codec else {
        return Ok(CompressionMethod::DEFLATE);
    };
    match id.as_str() {
        "store" | "stored" => Ok(CompressionMethod::Stored),
        "deflate" => Ok(CompressionMethod::DEFLATE),
        "bzip2" => Ok(CompressionMethod::BZIP2),
        "xz" => Ok(CompressionMethod::XZ),
        // Measured, not assumed: `zip 8.6.0`'s `prepare_next_writer` answers
        // `CompressionMethod::Lzma` with `UnsupportedArchive("LZMA isn't
        // supported for compression")` even with its `lzma` feature ON — the
        // feature buys the DECODER only. This is exactly what
        // `CapabilityUnavailable` exists to say (exit 3, "can be read but not
        // written by this build"), and saying it here rather than letting the
        // crate's own message surface halfway through `add` keeps the refusal
        // free: nothing has been written yet.
        "lzma" => Err(Error::CapabilityUnavailable {
            format: FormatId::new("lzma"),
            available: "read as a zip entry",
            requested: "written as one",
        }),
        "zstd" => {
            #[cfg(feature = "zip-zstd")]
            {
                Ok(CompressionMethod::ZSTD)
            }
            #[cfg(not(feature = "zip-zstd"))]
            {
                Err(Error::Unsupported(
                    "this build cannot write a zstd-compressed zip entry: zip's zstd support is \
                     the one entry codec that needs a C toolchain. Rebuild with `--features \
                     c-backed`, or pick `deflate`, `bzip2`, `xz`, `lzma` or `store`"
                        .into(),
                ))
            }
        }
        other => Err(Error::Unsupported(format!(
            "`{other}` is not a zip entry codec; zip stores entries with deflate, bzip2, xz, \
             lzma, zstd or store"
        ))),
    }
}

/// Rejects a `--level` the chosen entry codec does not have, BEFORE the
/// destination has been touched.
///
/// zip validates the level inside `start_file`, which is halfway through
/// `add`: the error would arrive after the archive had begun, and it arrives
/// as `UnsupportedArchive("Unsupported compression level")` — an
/// [`Error::Unsupported`] (exit 1) where every codec in this tree answers an
/// out-of-range level with [`Error::Usage`] (exit 2). `stuffr pack a b -o
/// x.zip --level 99` should be the same class of mistake as `--level 0` on
/// bzip2, and cost the same nothing.
///
/// Validated by DRY RUN rather than by a table of ranges copied out of zip:
/// the ranges are computed from the backend crates' own
/// `Compression::fast()`/`best()` at runtime (see
/// `write.rs::deflate_compression_level_range`), so a copy here would be a
/// second source of truth free to drift from the one that actually decides.
/// The rehearsal writes a header into a throwaway `Vec`, which costs a few
/// dozen bytes and no I/O.
fn check_level(method: CompressionMethod, level: Option<i32>) -> Result<()> {
    let Some(level) = level else {
        return Ok(());
    };
    let mut rehearsal = zip::ZipWriter::new(io::Cursor::new(Vec::new()));
    let options = SimpleFileOptions::DEFAULT
        .compression_method(method)
        .compression_level(Some(i64::from(level)));
    match rehearsal.start_file("level-check", options) {
        Ok(()) => Ok(()),
        // Only a level complaint becomes a usage error. Anything else is a
        // real failure of this build's writer and is reported as itself,
        // rather than being blamed on the caller's flag.
        Err(ZipError::UnsupportedArchive(msg)) if msg.contains("compression level") => {
            Err(Error::Usage(format!(
                "level {level} is out of range for a zip entry compressed with `{}`",
                codec_for(method)
            )))
        }
        Err(e) => Err(classify_zip_error(e)),
    }
}

/// The in-memory window that gives `ZipWriter` the `Seek` it needs over a
/// destination that has none. See the module doc for why nothing else works.
///
/// Invariant: `base <= pos`, and `buf` holds the bytes from absolute offset
/// `base` to `base + buf.len()`. Everything below `base` has already been
/// handed to `dst` and can no longer be rewritten — a seek there is refused
/// rather than silently ignored.
struct Spool {
    dst: Box<dyn Write + Send>,
    buf: Vec<u8>,
    base: u64,
    pos: u64,
}

impl Spool {
    fn new(dst: Box<dyn Write + Send>) -> Self {
        Self {
            dst,
            buf: Vec::new(),
            base: 0,
            pos: 0,
        }
    }

    /// The absolute offset the next write lands at — `ZipWriter`'s
    /// `stream_position`, read from outside.
    fn position(&self) -> u64 {
        self.pos
    }

    /// Hands everything below absolute offset `upto` to the real destination.
    ///
    /// Called with the offset of the entry `ZipWriter` has just STARTED: that
    /// call finalized the previous entry's local header, so nothing below the
    /// new entry's own header can be rewritten again.
    fn commit_upto(&mut self, upto: u64) -> io::Result<()> {
        // Clamped to `pos` as well as to the buffer, which keeps the `base <=
        // pos` invariant true by construction rather than by every caller
        // remembering it. `SpoolHandle::write` computes `pos - base` as a
        // `u64`, so a `base` past `pos` would wrap in release and panic in
        // debug — a latent trap for a future caller committing at a point the
        // cursor has not reached, which nothing here does today.
        let upto = upto.min(self.pos);
        if upto <= self.base {
            return Ok(());
        }
        let n = ((upto - self.base) as usize).min(self.buf.len());
        if n == 0 {
            return Ok(());
        }
        self.dst.write_all(&self.buf[..n])?;
        self.buf.drain(..n);
        self.base += n as u64;
        Ok(())
    }

    /// The terminal commit: everything still held goes out.
    ///
    /// The cursor moves to the end with it, so [`Self::commit_upto`]'s clamp
    /// cannot silently hold bytes back. `ZipWriter::finalize` does leave the
    /// cursor at the end (it seeks `End(0)` before returning), but the window
    /// should not depend on that to avoid truncating its own output.
    fn commit_all(&mut self) -> io::Result<()> {
        let end = self.base + self.buf.len() as u64;
        self.pos = self.pos.max(end);
        self.commit_upto(end)
    }

    fn flush_destination(&mut self) -> io::Result<()> {
        self.dst.flush()
    }
}

/// A shared handle on the [`Spool`], so `ZipWriter` can own a writer while
/// [`ZipWrite`] still reaches the commit machinery.
///
/// `Rc`, not `Arc`: neither `ArchiveWrite` nor `zip::ZipWriter` carries a
/// `Send` bound, and nothing in this tree sends an archive writer between
/// threads. `ZipWriter::get_ref` exists but returns `Option<&W>` and there is
/// no `get_mut` at all, so a shared handle is the only way to commit from
/// outside.
#[derive(Clone)]
struct SpoolHandle(Rc<RefCell<Spool>>);

impl Write for SpoolHandle {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut spool = self.0.borrow_mut();
        let off = usize::try_from(spool.pos - spool.base).map_err(|_| {
            io::Error::other("zip: spool window exceeds this platform's addressing")
        })?;
        // A seek past the end followed by a write would leave a hole. zip
        // never does that, and zero-filling is what a real file would do.
        if off > spool.buf.len() {
            spool.buf.resize(off, 0);
        }
        let end = off + data.len();
        if end > spool.buf.len() {
            spool.buf.resize(end, 0);
        }
        spool.buf[off..end].copy_from_slice(data);
        spool.pos += data.len() as u64;
        Ok(data.len())
    }

    /// Flushes the real destination without committing the window: the bytes
    /// still held back are ones `ZipWriter` may yet rewrite, so handing them
    /// over here would defeat the whole arrangement.
    fn flush(&mut self) -> io::Result<()> {
        self.0.borrow_mut().flush_destination()
    }
}

impl Seek for SpoolHandle {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let mut spool = self.0.borrow_mut();
        let end = spool.base + spool.buf.len() as u64;
        let target = match pos {
            SeekFrom::Start(x) => x,
            SeekFrom::End(d) => offset(end, d)?,
            SeekFrom::Current(d) => offset(spool.pos, d)?,
        };
        if target < spool.base {
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                format!(
                    "zip: cannot rewrite offset {target}; bytes below {} have already been \
                     written to the destination",
                    spool.base
                ),
            ));
        }
        spool.pos = target;
        Ok(target)
    }
}

/// `base + delta`, refusing a result before the start of the stream the way
/// a real `Seek` does.
fn offset(base: u64, delta: i64) -> io::Result<u64> {
    base.checked_add_signed(delta).ok_or_else(|| {
        io::Error::new(
            ErrorKind::InvalidInput,
            "zip: seek would move before the start of the archive",
        )
    })
}

struct ZipWrite {
    /// `None` once `finish` has consumed it. `Option` rather than a consuming
    /// call chain because `ArchiveWrite::add` takes `&mut self`.
    inner: Option<zip::ZipWriter<SpoolHandle>>,
    /// The same window `inner` writes through, so `add` and `finish` can
    /// commit it.
    spool: Rc<RefCell<Spool>>,
    method: CompressionMethod,
    level: Option<i32>,
}

impl ZipWrite {
    fn writer(&mut self) -> Result<&mut zip::ZipWriter<SpoolHandle>> {
        self.inner
            .as_mut()
            .ok_or_else(|| Error::Usage("zip writer used after finish()".into()))
    }

    /// The options every entry is written with.
    ///
    /// Built from `SimpleFileOptions::DEFAULT`, whose `last_modified_time` is
    /// a fixed 1980-01-01, NOT from `SimpleFileOptions::default()`, whose
    /// `DateTime::default_for_write()` returns the CURRENT time under zip's
    /// `time` feature. That difference is the project's reproducibility
    /// promise: same input, same flags, same bytes. Every entry's real mtime
    /// is set explicitly below when the caller supplies one.
    fn options(&self, meta: &EntryMeta) -> SimpleFileOptions {
        let mut o = SimpleFileOptions::DEFAULT
            .compression_method(self.method)
            // Masked to `0o777` by zip itself, so an `st_mode`-shaped value
            // from another container round-trips without the type bits
            // fighting the ones zip sets from `EntryKind` below.
            .unix_permissions(meta.mode.unwrap_or(DEFAULT_FILE_MODE))
            // zip64 per entry, decided from the DECLARED size. Without it,
            // `ZipWriter::write` aborts the entry past 4 GiB with "Large file
            // option has not been set"; with it unconditionally, every small
            // entry would carry a zip64 extra field and 32-bit sentinels that
            // older readers handle worse.
            .large_file(meta.size.is_some_and(|s| s > ZIP64_SIZE_THRESHOLD));
        if let Some(mtime) = meta.mtime {
            o = o.last_modified_time(dos_from_system_time(mtime));
        }
        if let Some(level) = self.level {
            o = o.compression_level(Some(i64::from(level)));
        }
        o
    }
}

/// The 32-bit size ceiling a zip local header can express. Past it an entry
/// needs zip64 fields, which is what `FileOptions::large_file` adds.
const ZIP64_SIZE_THRESHOLD: u64 = u32::MAX as u64 - 1;

impl ArchiveWrite for ZipWrite {
    fn add(&mut self, meta: &EntryMeta, data: &mut dyn Read) -> Result<()> {
        let options = self.options(meta);
        // The offset this entry's local header will start at. Read BEFORE the
        // entry is started, because starting it is what finalizes the previous
        // one's header — after which everything below this offset is settled.
        let header_start = self.spool.borrow().position();
        let writer = self.writer()?;

        match &meta.kind {
            EntryKind::Dir => {
                // `add_directory` appends the trailing `/` a zip directory
                // entry is identified by, and ORs `0o40000` into the mode. It
                // writes no payload, so any reader handed here is not
                // consumed — the same convention `tar.rs` follows.
                writer
                    .add_directory(meta.name.clone(), options)
                    .map_err(classify_zip_error)?;
            }
            EntryKind::Symlink { target } => {
                // The target is stored as the entry's payload and `S_IFLNK` is
                // ORed into the mode; zip forces `Stored` for it, since
                // compressing a path wastes space. `add_symlink` finalizes the
                // entry itself.
                writer
                    .add_symlink(meta.name.clone(), target.clone(), options)
                    .map_err(classify_zip_error)?;
            }
            _ => {
                // `EntryKind::Other` — a device node or fifo read out of some
                // other archive — is written as a regular file, because that
                // is all `EntryKind` can currently express about it. The
                // fidelity to recover is in `EntryKind`'s missing variants
                // (see `archive.rs`), not here.
                writer
                    .start_file(meta.name.clone(), options)
                    .map_err(classify_zip_error)?;
                let mut counted = CountingReader {
                    inner: data,
                    read: 0,
                };
                io::copy(&mut counted, writer)?;
                // Declared sizes are verified rather than trusted, the same
                // check `tar.rs::add` makes for the same reason: a size that
                // disagrees with the data would be written into the local
                // header and the central directory, producing a structurally
                // valid archive whose contents are mis-framed. Unlike tar,
                // this cannot leave a broken archive behind — the entry is
                // still in the spool window, and `ops` writes to a temp file
                // and promotes it only on success either way.
                if let Some(size) = meta.size
                    && counted.read != size
                {
                    return Err(Error::Usage(format!(
                        "entry `{}` declared a size of {size} bytes but supplied {}; the \
                         resulting archive would be mis-framed",
                        meta.name, counted.read
                    )));
                }
            }
        }

        // Everything before this entry's own header is final now.
        self.spool
            .borrow_mut()
            .commit_upto(header_start)
            .map_err(Error::from)
    }

    /// Writes the central directory and the end-of-central-directory record,
    /// commits the window and flushes.
    ///
    /// Never via `Drop`: `impl<W: Write + Seek> Drop for ZipWriter<W>`
    /// finalizes the archive and writes any failure to STDERR, so relying on
    /// it loses the error entirely — the hazard conformance property 4 asserts
    /// against. `ZipWriter::finish` here consumes the writer, after which its
    /// `Drop` sees a closed archive and does nothing.
    fn finish(mut self: Box<Self>) -> Result<()> {
        let writer = self
            .inner
            .take()
            .ok_or_else(|| Error::Usage("zip writer finished twice".into()))?;
        writer.finish().map_err(classify_zip_error)?;
        // Only now does the destination see anything it has not seen already.
        // The caller handed it over by value at `Container::create` and has no
        // other handle left to flush it, so that is done here.
        let mut spool = self.spool.borrow_mut();
        spool.commit_all()?;
        spool.flush_destination()?;
        Ok(())
    }
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
    use stuffr_core::{ArchiveRead, OpenOpts, ReaderSource, StreamPolicy};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn build_with(opts: &CreateOpts, entries: &[(EntryMeta, &[u8])]) -> Vec<u8> {
        let buf = SharedBuf::new();
        let mut w = Zip.create(Box::new(buf.clone()), opts).expect("create");
        for (meta, data) in entries {
            w.add(meta, &mut io::Cursor::new(*data)).expect("add");
        }
        w.finish().expect("finish");
        buf.contents()
    }

    fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let owned: Vec<(EntryMeta, &[u8])> = entries
            .iter()
            .map(|(n, d)| (EntryMeta::file(*n), *d))
            .collect();
        build_with(&CreateOpts::default(), &owned)
    }

    /// Opens `bytes` over a genuinely seekable source — a real file, via
    /// `FileSource` — which is the only way to reach `Rung::Exact` and the
    /// central-directory reader.
    ///
    /// Fallible, because on this rung `open` itself is where a damaged
    /// archive is found: `ZipArchive::new` reads the whole central directory
    /// up front. A helper that `expect`ed here would turn every seekable
    /// truncation test into a panic instead of an assertion about the error.
    fn try_open_seekable(bytes: &[u8]) -> Result<Box<dyn ArchiveRead>> {
        let path = std::env::temp_dir().join(format!(
            "stuffr-zip-seekable-{}-{:p}.zip",
            std::process::id(),
            bytes
        ));
        std::fs::write(&path, bytes).unwrap();
        let src: Box<dyn Source> = Box::new(stuffr_core::FileSource::open(&path).unwrap());
        let _ = std::fs::remove_file(&path);
        let resolved = stuffr_core::resolve(src, ZIP, Zip.caps(), &StreamPolicy::default())?;
        Zip.open(resolved, &OpenOpts::default())
    }

    fn open_seekable(bytes: &[u8]) -> Box<dyn ArchiveRead> {
        try_open_seekable(bytes).expect("open")
    }

    /// Reads every entry through the ladder over a NON-seekable source, the
    /// same "as if from a pipe" setup the harness itself uses.
    ///
    /// Payload reads go through `Error::from_decode_io`, NOT a bare `?`.
    /// That is not test convenience: it is what `entries::test` and
    /// `entries::copy_charging` — every real caller of `Entry::reader` in
    /// this workspace — do, precisely so a container's raw
    /// `io::ErrorKind::InvalidData` becomes `Error::Corrupt` (exit 5) rather
    /// than `Error::Io` (exit 1). A helper using a bare `?` would report
    /// exit 1 for a corrupt zip and the exit-code assertions below would be
    /// measuring the helper rather than the container.
    fn read_all_forward(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(io::Cursor::new(bytes.to_vec())));
        let resolved = stuffr_core::resolve(src, ZIP, Zip.caps(), &StreamPolicy::default())?;
        let mut ar = Zip.open(resolved, &OpenOpts::default())?;
        let mut out = Vec::new();
        while let Some(mut e) = ar.next_entry()? {
            let name = e.meta().name.clone();
            let mut data = Vec::new();
            e.reader()
                .read_to_end(&mut data)
                .map_err(Error::from_decode_io)?;
            out.push((name, data));
        }
        Ok(out)
    }

    fn read_all_seekable(bytes: &[u8]) -> Result<Vec<(EntryMeta, Vec<u8>)>> {
        let mut ar = try_open_seekable(bytes)?;
        let mut out = Vec::new();
        while let Some(mut e) = ar.next_entry()? {
            let meta = e.meta().clone();
            let mut data = Vec::new();
            e.reader()
                .read_to_end(&mut data)
                .map_err(Error::from_decode_io)?;
            out.push((meta, data));
        }
        Ok(out)
    }

    fn which(bin: &str) -> Option<std::path::PathBuf> {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path).find_map(|dir| {
            let candidate = dir.join(bin);
            candidate.is_file().then_some(candidate)
        })
    }

    /// Locates `bin` on `PATH`, panicking rather than silently skipping if it
    /// is absent — the strictest of this tree's three cross-implementation
    /// patterns, copied from `ar.rs`/`cpio.rs`. `zip`, `unzip` and `python3`
    /// all ship on every platform CI runs on, so an absence here means only a
    /// contributor's own machine lacks it, and a silent `return` would report
    /// every cross-implementation test in this file as PASSING having
    /// verified nothing at all.
    fn require_bin(bin: &str) -> std::path::PathBuf {
        which(bin).unwrap_or_else(|| {
            panic!(
                "no reference `{bin}` tool found on PATH — this test proved nothing, which is \
                 worth knowing rather than passing silently"
            )
        })
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("stuffr-zip-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // -----------------------------------------------------------------------
    // Conformance and declared capabilities
    // -----------------------------------------------------------------------

    #[test]
    fn zip_conforms() {
        assert_container_conforms(&Zip, &meta());
    }

    #[test]
    fn capabilities_and_metadata_match_the_format() {
        let c = Zip.caps();
        assert!(c.read && c.write && c.forward_parse);
        assert!(
            c.trailing_index && c.per_entry_codec,
            "zip's index is at the end of the stream and every entry names its own codec"
        );
        assert!(
            !c.solid && !c.needs_seek && !c.degraded_parse,
            "zip entries are independently compressed and enumerable forward"
        );
        let m = meta();
        assert_eq!(m.id, ZIP);
        assert_eq!(m.extensions, &["zip"]);
    }

    /// Property 7 is the reason this container exists in the harness's eyes,
    /// and it SKIPPED for tar, ar and cpio (all `trailing_index: false`). This
    /// asserts it now actually runs, by proving the flag it keys on is set and
    /// that a forward read really does report a non-`Exact` rung.
    #[test]
    fn property_seven_is_no_longer_skipped_for_this_container() {
        assert!(
            Zip.caps().trailing_index,
            "property 7 is gated on this flag; without it the check does nothing"
        );
        let bytes = build_zip(&[("a.txt", b"alpha"), ("b.txt", b"beta")]);
        assert_ne!(
            open_forward_only(&Zip, &bytes).fidelity().rung,
            Rung::Exact,
            "the authoritative index is at the END of the stream and was never read"
        );
    }

    // -----------------------------------------------------------------------
    // The two rungs
    // -----------------------------------------------------------------------

    #[test]
    fn a_seekable_zip_read_uses_the_central_directory_and_reports_exact() {
        let bytes = build_zip(&[("a.txt", b"alpha")]);
        let ar = open_seekable(&bytes);
        assert_eq!(ar.fidelity().rung, Rung::Exact);
        assert!(
            ar.fidelity().is_lossless(),
            "the central directory was read; nothing was approximated"
        );
    }

    #[test]
    fn a_piped_zip_read_uses_local_headers_and_reports_forward_only() {
        let bytes = build_zip(&[("a.txt", b"alpha")]);
        let ar = open_forward_only(&Zip, &bytes);
        assert_eq!(ar.fidelity().rung, Rung::ForwardOnly);
    }

    /// The rung/warning split, stated as a test because getting it wrong for
    /// tar cost a fix round. The rung describes the ACCESS PATH; the warnings
    /// describe the LOSS, and `--strict-fidelity` gates on the warnings. A
    /// piped tar has none; a piped zip must have exactly these.
    #[test]
    fn a_piped_zip_warns_about_the_index_it_did_not_read() {
        let bytes = build_zip(&[("a.txt", b"alpha")]);
        let ar = open_forward_only(&Zip, &bytes);
        let report = ar.fidelity();
        assert!(
            report.has_warnings(),
            "--strict-fidelity must fail a piped zip: its metadata really is approximate"
        );
        assert!(
            report
                .warnings
                .contains(&Fidelity::TrailingIndexUnread { format: ZIP })
        );
        assert!(report.warnings.contains(&Fidelity::EntryCountUnknown));
        assert_eq!(
            report.warnings.len(),
            2,
            "each loss is reported once, not twice: {:?}",
            report.warnings
        );
    }

    /// Property 6 pins this for the forward source; this pins the other half,
    /// which the harness never exercises: on a SEEKABLE source zip really does
    /// have random access, so `by_index` must work rather than refuse.
    #[test]
    fn by_index_works_on_a_seekable_source_and_refuses_on_a_pipe() {
        let bytes = build_zip(&[("a.txt", b"alpha"), ("b.txt", b"beta")]);

        let mut seekable = open_seekable(&bytes);
        let mut second = seekable
            .by_index(1)
            .expect("the central directory was read");
        assert_eq!(second.meta().name, "b.txt");
        let mut data = Vec::new();
        second.reader().read_to_end(&mut data).unwrap();
        assert_eq!(data, b"beta");
        // Out of range is a caller error (exit 2), not corruption.
        drop(second);
        let err = seekable.by_index(9).unwrap_err();
        assert!(matches!(err, Error::EntryNotFound(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 2);

        let err = open_forward_only(&Zip, &bytes).by_index(0).unwrap_err();
        assert!(
            matches!(err, Error::NotSeekable { format } if format == ZIP),
            "a forward read must refuse rather than fake random access: {err:?}"
        );
    }

    /// `by_index` must not disturb forward iteration, which is the only reason
    /// to have both.
    #[test]
    fn by_index_and_next_entry_are_independent_views_of_the_same_index() {
        let bytes = build_zip(&[("a.txt", b"alpha"), ("b.txt", b"beta")]);
        let mut ar = open_seekable(&bytes);
        assert_eq!(ar.next_entry().unwrap().unwrap().meta().name, "a.txt");
        assert_eq!(ar.by_index(0).unwrap().meta().name, "a.txt");
        assert_eq!(ar.next_entry().unwrap().unwrap().meta().name, "b.txt");
        assert!(ar.next_entry().unwrap().is_none());
    }

    // -----------------------------------------------------------------------
    // The empty archive, in both directions
    // -----------------------------------------------------------------------

    /// An empty zip is a bare end-of-central-directory record and nothing
    /// else — 22 bytes, no local file header at all. Both reference writers on
    /// this machine produce exactly those 22 bytes (see
    /// `every_reference_writers_empty_archive_is_byte_identical_to_ours`), and
    /// the shape is why this container reads record signatures itself instead
    /// of letting `read_zipfile_from_stream` decide when the entries have run
    /// out: handed `PK\x05\x06` that function reports a valid empty zip as
    /// corrupt.
    #[test]
    fn an_empty_archive_is_a_bare_end_of_central_directory_record() {
        let bytes = build_zip(&[]);
        assert_eq!(bytes.len(), 22, "an empty zip is exactly its EOCD record");
        assert_eq!(&bytes[..4], b"PK\x05\x06");
        assert!(read_all_forward(&bytes).expect("forward").is_empty());
        assert!(read_all_seekable(&bytes).expect("seekable").is_empty());
    }

    /// The magic rule for that shape, which the more obvious `PK\x03\x04` rule
    /// cannot match.
    #[test]
    fn both_magic_rules_are_needed_and_each_matches_the_archive_it_is_for() {
        let one = build_zip(&[("a.txt", b"alpha")]);
        let none = build_zip(&[]);
        assert_eq!(&one[..4], ZIP_MAGIC[0].bytes);
        assert_eq!(&none[..4], ZIP_MAGIC[1].bytes);
        assert_ne!(
            &one[..4],
            ZIP_MAGIC[1].bytes,
            "the two rules must not be redundant"
        );
    }

    // -----------------------------------------------------------------------
    // Truncation: the hole zip's own forward reader leaves
    // -----------------------------------------------------------------------

    /// The specific defect [`verify_trailing_index`] exists for, pinned
    /// directly rather than left to conformance property 9's generic cuts.
    /// `read_zipfile_from_stream` returns `Ok(None)` the instant it sees a
    /// central-directory signature, so without this check every one of these
    /// cuts reads back as a COMPLETE archive.
    #[test]
    fn a_cut_in_the_trailing_index_is_corruption_not_a_clean_end() {
        let bytes = build_zip(&[("a.txt", b"alpha"), ("b.txt", b"beta")]);
        let cd_start = bytes
            .windows(4)
            .position(|w| w == b"PK\x01\x02")
            .expect("the archive has a central directory");

        // Every cut from the first central-directory byte to one short of the
        // end. All of them are damage; none of them is a valid archive.
        for cut in cd_start..bytes.len() {
            let Err(err) = read_all_forward(&bytes[..cut]) else {
                panic!(
                    "a zip cut at {cut} of {} read back as a COMPLETE archive; the forward \
                     reader stopped at the central-directory signature without checking it",
                    bytes.len()
                )
            };
            assert_eq!(
                err.exit_code(),
                5,
                "a zip cut at {cut} of {} must exit 5 (corrupt), got {err:?}",
                bytes.len()
            );
        }
    }

    /// A complete archive with junk appended is NOT damage. Every zip tool
    /// ignores what follows the end-of-central-directory record, and a
    /// refusal here would fire on self-extracting archives and on anything
    /// concatenated after a zip.
    #[test]
    fn trailing_bytes_after_the_end_of_central_directory_are_ignored() {
        let mut bytes = build_zip(&[("a.txt", b"alpha")]);
        bytes.extend_from_slice(b"junk appended by some other tool");
        let got = read_all_forward(&bytes).expect("trailing bytes must not be refused");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, b"alpha");
    }

    /// Truncation INSIDE an entry's payload. Detected by zip's own
    /// `Crc32Reader`, which raises `InvalidData` at end of stream when the
    /// bytes delivered do not hash to the crc32 the local header declares —
    /// this asserts that measurement rather than assuming it, and that the
    /// kind survives as exit 5 rather than being reported as an I/O failure.
    #[test]
    fn a_cut_inside_an_entry_payload_is_corruption() {
        let payload = vec![b'p'; 40_000];
        let bytes = build_with(
            &CreateOpts {
                entry_codec: Some(STORE),
                ..Default::default()
            },
            &[(EntryMeta::file("big.bin"), &payload)],
        );
        let cut = bytes.len() / 2;
        let err = read_all_forward(&bytes[..cut]).expect_err("a cut payload must be refused");
        assert_eq!(err.exit_code(), 5, "got {err:?}");
        // And on the seekable rung too, which reads the same payload through
        // the same checksum reader.
        let err = read_all_seekable(&bytes[..cut]).expect_err("a cut payload must be refused");
        assert_eq!(err.exit_code(), 5, "got {err:?}");
    }

    /// A byte flipped inside an entry's payload. zip carries a crc32 per
    /// entry, so this is real detection rather than a structural accident.
    #[test]
    fn a_corrupted_entry_payload_is_detected_by_its_crc32() {
        let mut bytes = build_with(
            &CreateOpts {
                entry_codec: Some(STORE),
                ..Default::default()
            },
            &[(EntryMeta::file("a.txt"), b"alphabetical")],
        );
        let at = bytes
            .windows(12)
            .position(|w| w == b"alphabetical")
            .expect("a stored payload is present verbatim");
        bytes[at] ^= 0xff;
        let err = read_all_forward(&bytes).expect_err("a bad crc32 must be refused");
        assert_eq!(err.exit_code(), 5, "got {err:?}");
    }

    // -----------------------------------------------------------------------
    // Metadata
    // -----------------------------------------------------------------------

    /// The seekable rung reports an `st_mode`-shaped mode, the same shape
    /// `cpio.rs` reports and the shape `entries::apply_metadata` masks to
    /// `0o7777`. The forward rung reports NONE, because a zip keeps its unix
    /// modes only in the central directory — that is the loss
    /// `TrailingIndexUnread` names.
    #[test]
    fn a_mode_survives_the_seekable_rung_and_is_absent_from_the_forward_one() {
        let mut meta_in = EntryMeta::file("m.txt");
        meta_in.mode = Some(0o640);
        let bytes = build_with(&CreateOpts::default(), &[(meta_in, b"m")]);

        let got = read_all_seekable(&bytes).unwrap();
        assert_eq!(
            got[0].0.mode,
            Some(0o100640),
            "the central directory carries the mode, with S_IFREG in the type bits"
        );
        assert_eq!(got[0].0.mode.unwrap() & 0o7777, 0o640);

        let src: Box<dyn Source> = Box::new(ReaderSource::new(io::Cursor::new(bytes)));
        let resolved =
            stuffr_core::resolve(src, ZIP, Zip.caps(), &StreamPolicy::default()).unwrap();
        let mut ar = Zip.open(resolved, &OpenOpts::default()).unwrap();
        let entry = ar.next_entry().unwrap().unwrap();
        assert_eq!(
            entry.meta().mode,
            None,
            "a forward read has no external attributes to read a mode from, and must not \
             invent one"
        );
    }

    #[test]
    fn an_mtime_round_trips_to_the_two_second_resolution_zip_has() {
        // 2021-03-04 05:06:08 UTC. An even second, because an MS-DOS
        // timestamp stores seconds/2 and cannot represent an odd one.
        let when = UNIX_EPOCH + Duration::from_secs(1_614_827_168);
        let mut meta_in = EntryMeta::file("t.txt");
        meta_in.mtime = Some(when);
        let bytes = build_with(&CreateOpts::default(), &[(meta_in, b"t")]);
        let got = read_all_seekable(&bytes).unwrap();
        assert_eq!(got[0].0.mtime, Some(when));
        // The forward rung has this one: the local header carries the date.
        let src: Box<dyn Source> = Box::new(ReaderSource::new(io::Cursor::new(bytes)));
        let resolved =
            stuffr_core::resolve(src, ZIP, Zip.caps(), &StreamPolicy::default()).unwrap();
        let mut ar = Zip.open(resolved, &OpenOpts::default()).unwrap();
        assert_eq!(ar.next_entry().unwrap().unwrap().meta().mtime, Some(when));
    }

    /// An mtime outside the MS-DOS 1980-2107 window clamps rather than
    /// failing the write — the same choice `tar.rs`'s `unix_seconds` makes.
    /// Refusing to archive a file because of its timestamp would be worse.
    #[test]
    fn an_mtime_the_format_cannot_express_clamps_instead_of_failing() {
        let mut meta_in = EntryMeta::file("old.txt");
        // 1970-01-01, nine years before MS-DOS dates begin.
        meta_in.mtime = Some(UNIX_EPOCH);
        let bytes = build_with(&CreateOpts::default(), &[(meta_in, b"o")]);
        let got = read_all_seekable(&bytes).unwrap();
        let clamped = got[0].0.mtime.expect("a date was still written");
        assert_eq!(
            clamped,
            UNIX_EPOCH + Duration::from_secs(315_532_800),
            "1980-01-01 00:00:00 UTC, the earliest date a zip can hold"
        );
    }

    #[test]
    fn a_directory_entry_round_trips_as_a_directory() {
        let mut meta_in = EntryMeta::file("docs");
        meta_in.kind = EntryKind::Dir;
        let bytes = build_with(&CreateOpts::default(), &[(meta_in, &[][..])]);
        let got = read_all_seekable(&bytes).unwrap();
        assert_eq!(
            got[0].0.name, "docs/",
            "a zip directory entry IS its trailing slash; that is the format, not a rewrite"
        );
        assert_eq!(got[0].0.kind, EntryKind::Dir);
        assert_eq!(got[0].0.mode.unwrap() & 0o170000, 0o40000);
        // Name-based, so this is the one kind a forward read still gets right.
        let fwd = read_all_forward(&bytes).unwrap();
        assert_eq!(fwd[0].0, "docs/");
    }

    /// Symlinks: a zip stores the target as the entry's PAYLOAD and `S_IFLNK`
    /// in the central directory's external attributes. So the seekable rung
    /// reads them and the forward rung structurally cannot — which is the
    /// sharpest example of what `TrailingIndexUnread` is warning about.
    #[test]
    fn a_symlink_round_trips_on_the_seekable_rung_only() {
        let mut link = EntryMeta::file("mylink");
        link.kind = EntryKind::Symlink {
            target: "a.txt".into(),
        };
        let bytes = build_with(
            &CreateOpts::default(),
            &[(EntryMeta::file("a.txt"), &b"alpha"[..]), (link, &[][..])],
        );

        let got = read_all_seekable(&bytes).unwrap();
        assert_eq!(
            got[1].0.kind,
            EntryKind::Symlink {
                target: "a.txt".into()
            }
        );
        assert_eq!(got[1].0.mode.unwrap() & 0o170000, 0o120000);

        let fwd = read_all_forward(&bytes).unwrap();
        assert_eq!(fwd[1].0, "mylink");
        assert_eq!(
            fwd[1].1, b"a.txt",
            "read forward, a symlink is a file holding its target — a real loss, and the one \
             `TrailingIndexUnread` reports"
        );
    }

    // -----------------------------------------------------------------------
    // Per-entry codecs
    // -----------------------------------------------------------------------

    /// `per_entry_codec: true` means an entry names its own compression
    /// method, so `EntryMeta::codec` must report it — on BOTH rungs, since the
    /// method lives in the local header as well as the central directory.
    #[test]
    fn every_entry_codec_this_build_can_write_round_trips_and_reports_itself() {
        for (id, expected) in [
            (STORE, STORE),
            (FormatId::new("deflate"), FormatId::new("deflate")),
            (FormatId::new("bzip2"), FormatId::new("bzip2")),
            (FormatId::new("xz"), FormatId::new("xz")),
        ] {
            let payload = b"per-entry codec payload ".repeat(64);
            let bytes = build_with(
                &CreateOpts {
                    entry_codec: Some(id),
                    ..Default::default()
                },
                &[(EntryMeta::file("p.bin"), &payload)],
            );
            let got = read_all_seekable(&bytes)
                .unwrap_or_else(|e| panic!("reading back a {id} entry: {e}"));
            assert_eq!(got[0].1, payload, "{id} payload did not round trip");
            assert_eq!(got[0].0.codec, Some(expected), "{id} codec not reported");

            let fwd = read_all_forward(&bytes).unwrap();
            assert_eq!(fwd[0].1, payload, "{id} did not round trip forward");
        }
    }

    /// The one entry codec that is READ-only, and it is the crate's doing
    /// rather than a tier difference: `zip 8.6.0`'s `lzma` feature ships a
    /// decoder and no encoder. `CapabilityUnavailable` is the typed error for
    /// exactly that shape and carries exit 3, so a script can tell "this
    /// build cannot write it" from "your file is broken".
    /// Column-zero continuation lines, deliberately: a Rust `\<newline>`
    /// escape swallows the following indentation, but the indentation of the
    /// SOURCE would otherwise end up inside the string and Python rejects a
    /// stray indent.
    const LZMA_ZIP_SCRIPT: &str = "\
import sys, zipfile\n\
z = zipfile.ZipFile(sys.argv[1], 'w')\n\
z.writestr('l.txt', 'lzma payload ' * 64, zipfile.ZIP_LZMA)\n\
z.close()\n";

    #[test]
    fn an_lzma_entry_can_be_read_but_not_written_and_the_refusal_says_so() {
        let err = method_for(Some(FormatId::new("lzma"))).expect_err("zip's lzma is decode-only");
        assert!(
            matches!(err, Error::CapabilityUnavailable { .. }),
            "got {err:?}"
        );
        assert_eq!(
            err.exit_code(),
            3,
            "not a generic failure and not corruption"
        );

        // The read half, against an LZMA entry Python's `zipfile` wrote —
        // there is no way to produce one through this container, which is the
        // whole point.
        let python = require_bin("python3");
        let dir = scratch("read-python-lzma");
        let out = std::process::Command::new(&python)
            .arg("-c")
            .arg(LZMA_ZIP_SCRIPT)
            .arg(dir.join("l.zip"))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "python3 could not write an LZMA zip: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let bytes = std::fs::read(dir.join("l.zip")).unwrap();
        let got = read_all_seekable(&bytes).expect("an LZMA zip entry must READ");
        assert_eq!(got[0].1, "lzma payload ".repeat(64).as_bytes());
        assert_eq!(got[0].0.codec, Some(FormatId::new("lzma")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_default_entry_codec_is_deflate() {
        let bytes = build_zip(&[("a.txt", b"alpha")]);
        let got = read_all_seekable(&bytes).unwrap();
        assert_eq!(got[0].0.codec, Some(FormatId::new("deflate")));
    }

    #[test]
    fn an_entry_codec_zip_cannot_express_is_refused_before_anything_is_written() {
        let buf = SharedBuf::new();
        let err = Zip
            .create(
                Box::new(buf.clone()),
                &CreateOpts {
                    entry_codec: Some(FormatId::new("brotli")),
                    ..Default::default()
                },
            )
            .err()
            .expect("zip has no brotli method");
        assert!(matches!(err, Error::Unsupported(_)), "got {err:?}");
        assert!(
            buf.contents().is_empty(),
            "the refusal must cost nothing: nothing may have been written"
        );
    }

    // -----------------------------------------------------------------------
    // The documented capability gap
    // -----------------------------------------------------------------------

    /// A zip entry compressed with zstd (method 93), built by patching a
    /// stored entry's method field in both the local header and the central
    /// directory. Nothing decompresses it — the refusal happens when the
    /// decoder is CONSTRUCTED, before a payload byte is read — so the stored
    /// bytes underneath never matter.
    #[cfg(not(feature = "zip-zstd"))]
    fn zstd_entry_fixture() -> Vec<u8> {
        let mut bytes = build_with(
            &CreateOpts {
                entry_codec: Some(STORE),
                ..Default::default()
            },
            &[(EntryMeta::file("z.bin"), b"not really zstd")],
        );
        // Local file header: signature(4) version(2) flags(2) method(2).
        bytes[8..10].copy_from_slice(&93u16.to_le_bytes());
        // Central directory header: signature(4) made-by(2) needed(2)
        // flags(2) method(2).
        let cd = bytes
            .windows(4)
            .position(|w| w == b"PK\x01\x02")
            .expect("central directory");
        bytes[cd + 10..cd + 12].copy_from_slice(&93u16.to_le_bytes());
        bytes
    }

    /// The gap `--features c-backed` closes. It must report as an unsupported
    /// CAPABILITY naming the flag — never as corruption, which would tell a
    /// user their perfectly good zip was damaged.
    #[test]
    #[cfg(not(feature = "zip-zstd"))]
    fn the_pure_tier_reports_a_zstd_entry_as_unsupported_rather_than_corrupt() {
        let fixture = zstd_entry_fixture();
        for (rung, err) in [
            ("forward", read_all_forward(&fixture).unwrap_err()),
            ("seekable", read_all_seekable(&fixture).unwrap_err()),
        ] {
            assert!(
                matches!(err, Error::Unsupported(_)),
                "{rung}: a zstd entry is a capability gap, not damage: {err:?}"
            );
            assert_ne!(
                err.exit_code(),
                5,
                "{rung}: exit 5 would claim the archive is corrupt"
            );
            let text = err.to_string();
            assert!(
                text.contains("c-backed"),
                "{rung}: the refusal must say what to do about it: {text}"
            );
            assert!(
                text.contains("zstd"),
                "{rung}: the refusal must name the method: {text}"
            );
        }
    }

    /// The write half of the same gap.
    #[test]
    #[cfg(not(feature = "zip-zstd"))]
    fn the_pure_tier_refuses_to_write_a_zstd_entry_naming_the_feature() {
        let buf = SharedBuf::new();
        let err = Zip
            .create(
                Box::new(buf),
                &CreateOpts {
                    entry_codec: Some(FormatId::new("zstd")),
                    ..Default::default()
                },
            )
            .err()
            .expect("the pure tier has no zstd zip method");
        assert!(matches!(err, Error::Unsupported(_)), "got {err:?}");
        assert!(err.to_string().contains("c-backed"), "{err}");
    }

    /// And on the C-backed tier the same entry codec works, which is what
    /// makes the row in `stuffr formats` honest.
    #[test]
    #[cfg(feature = "zip-zstd")]
    fn the_c_backed_tier_round_trips_a_zstd_entry() {
        let payload = b"zstd entry payload ".repeat(64);
        let bytes = build_with(
            &CreateOpts {
                entry_codec: Some(FormatId::new("zstd")),
                ..Default::default()
            },
            &[(EntryMeta::file("z.bin"), &payload)],
        );
        let got = read_all_seekable(&bytes).unwrap();
        assert_eq!(got[0].1, payload);
        assert_eq!(got[0].0.codec, Some(FormatId::new("zstd")));
    }

    // -----------------------------------------------------------------------
    // Writing
    // -----------------------------------------------------------------------

    /// The claim the [`Spool`] design rests on: a zip local header must carry
    /// the crc32 and compressed size of a payload that has not been
    /// compressed yet, so ONE entry is held back — never the archive.
    /// Measured, not asserted from the shape of the code.
    #[test]
    fn the_writer_does_not_buffer_the_whole_archive() {
        let buf = SharedBuf::new();
        let mut w = Zip
            .create(Box::new(buf.clone()), &CreateOpts::default())
            .unwrap();
        let first = vec![b'1'; 64 * 1024];
        w.add(
            &EntryMeta::file("one.bin"),
            &mut io::Cursor::new(&first[..]),
        )
        .unwrap();
        assert!(
            buf.contents().is_empty(),
            "the first entry's header is still rewritable, so nothing may have been committed"
        );
        w.add(
            &EntryMeta::file("two.bin"),
            &mut io::Cursor::new(&vec![b'2'; 64 * 1024][..]),
        )
        .unwrap();
        let mid = buf.contents().len();
        assert!(
            mid > 0,
            "starting the second entry settles the first, which must then be handed over"
        );
        w.finish().unwrap();
        let total = buf.contents().len();
        assert!(
            mid < total,
            "the central directory can only be written at the end ({mid} of {total})"
        );
    }

    /// Same input, same flags, same bytes — the project's reproducibility
    /// promise, and the reason this module builds its options from
    /// `SimpleFileOptions::DEFAULT` (a fixed 1980 date) rather than
    /// `::default()`, whose `default_for_write()` returns the CURRENT time
    /// under zip's `time` feature.
    #[test]
    fn the_same_input_produces_the_same_bytes() {
        let a = build_zip(&[("a.txt", b"alpha"), ("b/c.bin", b"\x00\xff\x00")]);
        let b = build_zip(&[("a.txt", b"alpha"), ("b/c.bin", b"\x00\xff\x00")]);
        assert_eq!(a, b, "an unset mtime must not become `now`");
    }

    /// A level the entry codec does not have is a USAGE error (exit 2) and
    /// costs nothing, rather than zip's own `Unsupported` (exit 1) raised
    /// from inside `add` with the destination already open.
    #[test]
    fn a_level_the_entry_codec_does_not_have_is_refused_before_anything_is_written() {
        let buf = SharedBuf::new();
        let err = Zip
            .create(
                Box::new(buf.clone()),
                &CreateOpts {
                    level: Some(99),
                    ..Default::default()
                },
            )
            .err()
            .expect("99 is not a deflate level");
        assert!(matches!(err, Error::Usage(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 2);
        assert!(
            err.to_string().contains("deflate"),
            "the refusal must name the codec whose range was missed: {err}"
        );
        assert!(
            buf.contents().is_empty(),
            "nothing may have been written before the refusal"
        );

        // And a level the codec DOES have is accepted, so the guard is not
        // simply refusing every level.
        for level in [1, 6, 9] {
            let bytes = build_with(
                &CreateOpts {
                    level: Some(level),
                    ..Default::default()
                },
                &[(EntryMeta::file("a.txt"), b"alphabet soup, repeatedly")],
            );
            assert_eq!(
                read_all_seekable(&bytes).unwrap()[0].1,
                b"alphabet soup, repeatedly",
                "level {level} must round trip"
            );
        }
    }

    #[test]
    fn a_declared_size_that_disagrees_with_the_data_is_refused() {
        let buf = SharedBuf::new();
        let mut w = Zip.create(Box::new(buf), &CreateOpts::default()).unwrap();
        let mut meta_in = EntryMeta::file("wrong.bin");
        meta_in.size = Some(99);
        let err = w
            .add(&meta_in, &mut io::Cursor::new(b"only five".as_slice()))
            .expect_err("a mis-declared size would mis-frame the archive");
        assert!(matches!(err, Error::Usage(_)), "got {err:?}");
    }

    /// The window refuses a rewrite of bytes it has already handed over,
    /// rather than silently accepting the seek and writing to the wrong
    /// place. Nothing in this module does that; the guard is what makes the
    /// `Spool` invariant enforced rather than assumed.
    #[test]
    fn the_spool_refuses_a_seek_below_what_it_has_already_committed() {
        let spool = Rc::new(RefCell::new(Spool::new(Box::new(SharedBuf::new()))));
        let mut handle = SpoolHandle(Rc::clone(&spool));
        handle.write_all(b"0123456789").unwrap();
        spool.borrow_mut().commit_upto(6).unwrap();
        assert_eq!(handle.seek(SeekFrom::Start(6)).unwrap(), 6);
        let err = handle.seek(SeekFrom::Start(5)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported, "{err}");
        // And a rewrite inside the window still works, which is the whole
        // point of holding it back.
        handle.seek(SeekFrom::Start(7)).unwrap();
        handle.write_all(b"X").unwrap();
        spool.borrow_mut().commit_all().unwrap();
    }

    // -----------------------------------------------------------------------
    // Cross-implementation, both directions
    // -----------------------------------------------------------------------

    /// `unzip -t` verifies every entry's crc32, so this checks the DATA and
    /// not merely that the framing parses.
    #[test]
    fn system_unzip_accepts_what_we_write() {
        let unzip = require_bin("unzip");
        let dir = scratch("unzip-accepts");
        let path = dir.join("ours.zip");

        let mut link = EntryMeta::file("mylink");
        link.kind = EntryKind::Symlink {
            target: "a.txt".into(),
        };
        let mut docs = EntryMeta::file("docs");
        docs.kind = EntryKind::Dir;
        let bytes = build_with(
            &CreateOpts::default(),
            &[
                (EntryMeta::file("a.txt"), &b"alpha"[..]),
                (EntryMeta::file("docs/b.bin"), &b"\x00\xff\x00"[..]),
                (docs, &[][..]),
                (link, &[][..]),
            ],
        );
        std::fs::write(&path, &bytes).unwrap();

        let out = std::process::Command::new(&unzip)
            .arg("-t")
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "system unzip rejected our archive: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let listing = String::from_utf8_lossy(&out.stdout);
        for name in ["a.txt", "docs/b.bin", "docs/", "mylink"] {
            assert!(listing.contains(name), "{name} missing from {listing:?}");
        }

        // And it extracts to the right shapes, which `-t` alone does not say.
        let out = std::process::Command::new(&unzip)
            .arg("-q")
            .arg(&path)
            .current_dir(&dir)
            .output()
            .unwrap();
        assert!(out.status.success(), "unzip extraction failed");
        assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"alpha");
        assert!(dir.join("docs").is_dir());
        assert_eq!(
            std::fs::read_link(dir.join("mylink")).unwrap(),
            std::path::Path::new("a.txt"),
            "system unzip must restore our symlink as a symlink"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The empty archive, checked explicitly in the write direction rather
    /// than assumed — `tar.rs`'s review found `bsdtar` writes an empty
    /// archive with zero margin, and Task 10 found bsdcpio's differs from its
    /// own.
    ///
    /// The assertion is byte identity with both reference writers rather than
    /// `unzip`'s exit code, because Info-ZIP `unzip 6.00` answers a VALID
    /// empty zip with `warning: zipfile is empty` and exit 1 — measured on
    /// this machine against Python's `zipfile` and against `zip`'s own
    /// (`zip z.zip f && zip -d z.zip f`), both of which produce the identical
    /// 22 bytes. An exit-code assertion would therefore have to encode
    /// unzip's warning rather than anything about our output.
    #[test]
    fn every_reference_writers_empty_archive_is_byte_identical_to_ours() {
        let python = require_bin("python3");
        let zip_bin = require_bin("zip");
        let dir = scratch("empty-both-ways");

        let ours = build_zip(&[]);

        let out = std::process::Command::new(&python)
            .arg("-c")
            .arg("import zipfile,sys;zipfile.ZipFile(sys.argv[1],'w').close()")
            .arg(dir.join("py.zip"))
            .output()
            .unwrap();
        assert!(out.status.success(), "python3 -m zipfile failed");
        let py = std::fs::read(dir.join("py.zip")).unwrap();

        std::fs::write(dir.join("f.txt"), b"x").unwrap();
        for args in [
            vec!["-q", "iz.zip", "f.txt"],
            vec!["-q", "-d", "iz.zip", "f.txt"],
        ] {
            let out = std::process::Command::new(&zip_bin)
                .args(&args)
                .current_dir(&dir)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "zip {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let iz = std::fs::read(dir.join("iz.zip")).unwrap();

        assert_eq!(
            ours, py,
            "Python's zipfile writes a different empty archive"
        );
        assert_eq!(ours, iz, "Info-ZIP writes a different empty archive");

        // And we read both of them back as zero entries, on both rungs.
        for (who, bytes) in [("python", &py), ("info-zip", &iz)] {
            assert!(
                read_all_forward(bytes)
                    .unwrap_or_else(|e| panic!("{who} empty zip, forward: {e}"))
                    .is_empty()
            );
            assert!(
                read_all_seekable(bytes)
                    .unwrap_or_else(|e| panic!("{who} empty zip, seekable: {e}"))
                    .is_empty()
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The read direction, against a real archive Info-ZIP `zip` wrote from
    /// real files — including a directory entry and a genuine symlink, the two
    /// shapes a container gets wrong most easily.
    #[test]
    fn we_read_what_system_zip_writes() {
        let zip_bin = require_bin("zip");
        let dir = scratch("read-system-zip");
        std::fs::create_dir_all(dir.join("d")).unwrap();
        std::fs::write(dir.join("d/a.txt"), b"alpha").unwrap();
        std::os::unix::fs::symlink("d/a.txt", dir.join("lnk")).unwrap();

        let out = std::process::Command::new(&zip_bin)
            .args(["-q", "-y", "-r", "theirs.zip", "d", "lnk"])
            .current_dir(&dir)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "system zip failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let bytes = std::fs::read(dir.join("theirs.zip")).unwrap();

        let got = read_all_seekable(&bytes).expect("we must read Info-ZIP's own output");
        let names: Vec<&str> = got.iter().map(|(m, _)| m.name.as_str()).collect();
        assert_eq!(names, vec!["d/", "d/a.txt", "lnk"], "got {names:?}");
        assert_eq!(got[0].0.kind, EntryKind::Dir);
        assert_eq!(got[1].1, b"alpha");
        assert_eq!(
            got[2].0.kind,
            EntryKind::Symlink {
                target: "d/a.txt".into()
            },
            "a symlink Info-ZIP wrote must read back as one, not as a file holding its target"
        );

        // Forward too: the data is identical, the metadata is the documented
        // subset.
        let fwd = read_all_forward(&bytes).expect("Info-ZIP's output must stream");
        assert_eq!(fwd.len(), 3);
        assert_eq!(fwd[1].1, b"alpha");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A `.jar`/`.docx`-shaped zip: Python's `zipfile` writing a stored entry
    /// first (the `mimetype` convention), deflated entries after, and nested
    /// directory paths with no directory entries at all. Every one of those
    /// is ubiquitous benign input, and a container that refused any of it
    /// would be useless.
    #[test]
    fn we_read_a_jar_shaped_zip_python_writes() {
        let python = require_bin("python3");
        let dir = scratch("read-python-zip");
        let script = "\
import sys, zipfile\n\
z = zipfile.ZipFile(sys.argv[1], 'w')\n\
z.writestr(zipfile.ZipInfo('mimetype'), 'application/epub+zip', zipfile.ZIP_STORED)\n\
z.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\\n', zipfile.ZIP_DEFLATED)\n\
z.writestr('com/example/Main.class', b'\\xca\\xfe\\xba\\xbe' * 64, zipfile.ZIP_DEFLATED)\n\
z.close()\n";
        let out = std::process::Command::new(&python)
            .arg("-c")
            .arg(script)
            .arg(dir.join("app.jar"))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "python3 failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let bytes = std::fs::read(dir.join("app.jar")).unwrap();

        for (rung, got) in [
            (
                "seekable",
                read_all_seekable(&bytes)
                    .expect("a jar-shaped zip must read")
                    .into_iter()
                    .map(|(m, d)| (m.name, d))
                    .collect::<Vec<_>>(),
            ),
            (
                "forward",
                read_all_forward(&bytes).expect("a jar-shaped zip must stream"),
            ),
        ] {
            let names: Vec<&str> = got.iter().map(|(n, _)| n.as_str()).collect();
            assert_eq!(
                names,
                vec!["mimetype", "META-INF/MANIFEST.MF", "com/example/Main.class"],
                "{rung}"
            );
            assert_eq!(got[0].1, b"application/epub+zip", "{rung}");
            assert_eq!(got[2].1, b"\xca\xfe\xba\xbe".repeat(64), "{rung}");
        }
        // The stored-first convention is reported as such, which is what
        // `per_entry_codec` is for.
        let metas = read_all_seekable(&bytes).unwrap();
        assert_eq!(metas[0].0.codec, Some(STORE));
        assert_eq!(metas[1].0.codec, Some(FormatId::new("deflate")));
        let _ = std::fs::remove_dir_all(&dir);
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
