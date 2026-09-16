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
//! # The SEEKABLE reader has to check the declared COUNT itself
//!
//! Reaching the central directory is not the same as reaching every record in
//! it. `zip::ZipArchive` stores what it parsed in an `IndexMap` keyed by the
//! raw file name, so two central-directory records naming the same path — at
//! two different local-header offsets, which is a real and well-formed shape —
//! collapse into one, and `len()` reports the number of distinct NAMES rather
//! than the number of records. Measured on a zip `unzip -t` reads whole:
//! `len()` returns 6 for an 8-record archive, and nothing in the crate's API
//! says so. The crate keeps the LAST record's data at the FIRST record's index.
//!
//! Left alone, that is the one failure mode this tool exists to rule out:
//! `list` printing six rows and `test` announcing "exact fidelity" over an
//! archive two of whose entries no caller can reach. So [`read_declared_index`]
//! parses the end-of-central-directory record directly — the crate exposes no
//! accessor for the count, `mod spec` being private and
//! `CentralDirectoryInfo::number_of_files` `pub(crate)` — and
//! [`note_unreachable_records`] raises [`Fidelity::EntryCountMismatch`] naming
//! both figures whenever the enumeration falls short. `--strict-fidelity` then
//! refuses it at exit 4.
//!
//! **Declared, not recovered.** Reading the shadowed records would mean
//! re-implementing the central-directory parse this module deliberately
//! delegates. Naming the shortfall is what a caller needs in order to know the
//! result is partial; reaching it is a different and much larger job.
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
//! [`Error::Unsupported`] naming `--features c-backed` — **exit 3**, "this
//! build cannot do that", the same code `FormatNotEnabled` carries — never as
//! corruption (exit 5), which would tell a user their perfectly good zip was
//! damaged, and never as the generic exit 1 that would make an actionable
//! refusal indistinguishable from an internal failure.
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
    Error, Fidelity, FidelityReport, FormatId, FormatMeta, MagicRule, OpenOpts, PlainSink,
    Resolved, Result, Rung, SeekRead, Sink, Source,
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

/// Ceiling on the gap [`SpoolHandle::write`] will zero-fill after a seek past
/// the end of its window. See that method for why the branch is unreachable
/// and bounded anyway. 1 MiB is far above any real zip framing.
const MAX_SPOOL_HOLE: usize = 1024 * 1024;

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
            // Measured, not assumed: zip 8.6.0's `ZipWriter::add_directory`
            // appends the trailing `/` and ORs `S_IFDIR` into the mode, and
            // `add_symlink` (write.rs:1822) ORs `ffi::S_IFLNK` into the
            // external attributes, forces `Stored` and writes the target as
            // the entry's payload. So zip stores both kinds natively and
            // neither costs a fidelity warning.
            stores_dirs: true,
            stores_symlinks: true,
            ..Default::default()
        }
    }

    fn open(&self, resolved: Resolved, _o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
        let Resolved { source, report, .. } = resolved;

        if source.caps().seekable {
            // Authoritative: the central directory carries real metadata and
            // enables `by_index`. Reached for `Rung::Exact` (a file) and for
            // `Rung::Spilled` (a pipe the ladder spooled), both of which are
            // authoritative and neither of which loses anything — so the
            // ACCESS PATH costs nothing, and the report's rung is carried
            // through unchanged.
            //
            // The archive's own contents can still cost something, and this
            // is the one rung that can prove it. `ZipArchive` collapses
            // records that share a name, so an exact read of an 8-record
            // archive can hand back 6 entries and, before this, said nothing
            // at all — `list` printed six rows and `test` reported "exact
            // fidelity". Read the declared count from the EOCD BEFORE the
            // source is moved into the archive (nothing gets it back out
            // afterwards) and hold the enumeration to it.
            let mut adapter = SeekAdapter(source);
            let declared = read_declared_index(&mut adapter);
            // Read while the source is still reachable, for the same reason
            // `read_declared_index` is: nothing gets the bytes back out from
            // under a `ZipArchive`.
            let opens_with_an_entry = begins_with_a_local_header(&mut adapter);
            let archive = zip::ZipArchive::new(adapter).map_err(classify_zip_error)?;
            refuse_an_index_that_reaches_nothing(&archive, opens_with_an_entry)?;
            let mut report = report;
            note_unreachable_records(&mut report, &archive, declared);
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

    fn create(&self, dst: Box<dyn Sink>, o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
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
        // `Unsupported` (exit 3, "this build cannot do that") rather than
        // silently claiming corruption (exit 5).
        other => Error::Unsupported(other.to_string()),
    }
}

/// Extra guidance for the `UnsupportedArchive` messages this module can
/// actually meet, so the refusal says what to do next rather than only what
/// went wrong.
///
/// Matched on the message because `zip` carries no error code for these — but
/// the encrypted arm compares against `ZipError::PASSWORD_REQUIRED`, the
/// constant the crate EXPORTS for exactly this purpose (`result.rs:47`),
/// rather than a substring of it. The first version of this function tested
/// `msg.contains("Encrypted")` and was therefore **dead**: the message is
/// "Password required to decrypt file" and contains no such word, so the hint
/// written specifically for encrypted entries could never fire. Caught in
/// review; `both_unsupported_hints_are_reachable` now covers both arms, since
/// nothing else did.
///
/// The data-descriptor arm has no exported constant to compare against, so it
/// stays a substring, narrowed to the distinctive part of the sentence. A
/// wording change upstream costs the hint and nothing else — the refusal, its
/// class and its exit code are unaffected — and that test fails loudly if it
/// happens.
fn unsupported_hint(msg: &str) -> &'static str {
    if msg == ZipError::PASSWORD_REQUIRED {
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

/// What the archive's own end-of-central-directory record DECLARES.
///
/// Read independently of the `zip` crate, because the crate exposes no
/// accessor for it: `CentralDirectoryInfo::number_of_files` is `pub(crate)`,
/// `mod spec` — where the EOCD structs with their `pub` fields live — is a
/// private module, and `ZipArchiveMetadata` carries only the collapsed map.
/// `ZipArchive::len()` is therefore the only count the crate will hand back,
/// and it is not the declared one.
///
/// That distinction is the whole point of this struct. `ZipArchive` stores
/// its records in an `IndexMap` keyed by the raw file name
/// (`read/zip_archive.rs`'s `SharedBuilder::build`), so two central-directory
/// records naming the same path at different local-header offsets collapse
/// into one — the LAST record's data, at the FIRST record's index. `len()`
/// then reports the number of distinct NAMES, and every reader above it
/// enumerates fewer entries than the archive holds with no indication that
/// anything was dropped. Measured on a real 8-record archive that `unzip -t`
/// reads whole: `len()` returns 6.
struct DeclaredIndex {
    /// Total records across the archive: the EOCD's field at offset 10.
    ///
    /// Deliberately the archive TOTAL rather than the on-this-disk count at
    /// offset 8 that `zip` itself reads. A single-disk archive — the only
    /// kind this crate will open at all, since it refuses a central directory
    /// on another disk — must declare the same number in both, so holding the
    /// reader to the total is a check rather than a restatement.
    entries: u64,
    /// Offset of the central directory, relative to the start of the archive.
    ///
    /// Carried only to confirm that the record found here is the same one the
    /// `zip` crate itself parsed. See [`note_unreachable_records`].
    cd_offset: u64,
}

/// Ceiling on the backwards EOCD search: the record is 22 bytes and the only
/// thing that may follow it is its own comment, whose length is a `u16`.
const MAX_EOCD_SEARCH: u64 = 22 + u16::MAX as u64;
/// Bytes of a whole end-of-central-directory record, signature included.
const END_OF_CENTRAL_DIR_TOTAL: usize = 4 + END_OF_CENTRAL_DIR_FIXED;
/// Bytes of a whole zip64 EOCD locator, signature included.
const ZIP64_LOCATOR_TOTAL: usize = 4 + ZIP64_LOCATOR_FIXED;

fn le16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Reads the declared record count, or `None` when it cannot be read with
/// certainty.
///
/// `None` rather than a guess, everywhere, and that asymmetry is deliberate:
/// the only thing this feeds is a fidelity WARNING, and a warning raised on a
/// number this function was not sure of would be exactly the kind of
/// over-claim the warning exists to prevent. Staying silent leaves the
/// behaviour identical to what it was before; guessing does not.
fn read_declared_index<R: Read + Seek>(r: &mut R) -> Option<DeclaredIndex> {
    let end = r.seek(SeekFrom::End(0)).ok()?;
    let window = end.min(MAX_EOCD_SEARCH);
    if window < END_OF_CENTRAL_DIR_TOTAL as u64 {
        return None;
    }
    r.seek(SeekFrom::Start(end - window)).ok()?;
    let mut tail = vec![0u8; usize::try_from(window).ok()?];
    r.read_exact(&mut tail).ok()?;

    // Backwards, and only a signature whose declared comment length runs
    // EXACTLY to the end of the file is accepted. A bare backwards search for
    // `PK\x05\x06` is a heuristic — those four bytes occur inside file
    // comments and inside stored payloads, which is the whole reason the
    // forward reader parses framing instead — while agreement between the
    // declared comment length and the bytes actually remaining is a check.
    let at = (0..=tail.len() - END_OF_CENTRAL_DIR_TOTAL)
        .rev()
        .find(|&i| {
            tail[i..i + 4] == SIG_END_OF_CENTRAL_DIR
                && i + END_OF_CENTRAL_DIR_TOTAL + le16(&tail[i + 20..]) as usize == tail.len()
        })?;

    let entries = le16(&tail[at + 10..]);
    let cd_offset = le32(&tail[at + 16..]);
    if entries != u16::MAX && cd_offset != u32::MAX {
        return Some(DeclaredIndex {
            entries: u64::from(entries),
            cd_offset: u64::from(cd_offset),
        });
    }
    // Either field saturated: the real values live in the zip64 record, and
    // the locator that points at it sits immediately before this one.
    read_zip64_declared_index(r, &tail, at)
}

/// The zip64 escape hatch, reached when the 16-bit count or the 32-bit offset
/// in the plain EOCD has saturated.
///
/// Known limitation, stated rather than papered over: the locator stores the
/// zip64 record's offset RELATIVE to the start of the archive, and this reads
/// it as an absolute file offset. A zip64 archive with data prepended to it —
/// a self-extracting stub — therefore lands on the wrong bytes, the signature
/// check below fails, and this returns `None`. That costs a warning on an
/// archive that is both zip64 AND prepended AND holds shadowed records; it
/// never produces a wrong one, which is the direction that matters. Resolving
/// the archive offset properly would mean reading it from a `ZipArchive` that
/// does not exist yet at this point in [`Container::open`].
fn read_zip64_declared_index<R: Read + Seek>(
    r: &mut R,
    tail: &[u8],
    eocd_at: usize,
) -> Option<DeclaredIndex> {
    let locator_at = eocd_at.checked_sub(ZIP64_LOCATOR_TOTAL)?;
    if tail[locator_at..locator_at + 4] != SIG_ZIP64_LOCATOR {
        return None;
    }
    let record_at = le64(&tail[locator_at + 8..]);

    r.seek(SeekFrom::Start(record_at)).ok()?;
    // Through the total-entries field at offset 32 and the central-directory
    // offset at 48; the extensible data sector that may follow is not read.
    let mut fixed = [0u8; 56];
    r.read_exact(&mut fixed).ok()?;
    if fixed[..4] != SIG_ZIP64_END {
        return None;
    }
    Some(DeclaredIndex {
        entries: le64(&fixed[32..]),
        cd_offset: le64(&fixed[48..]),
    })
}

/// Records the shortfall between what the index declares and what the reader
/// could enumerate, when there is one.
///
/// Two guards stand between a disagreement and a warning, because a false
/// fidelity warning on a healthy archive would be worse than the silence it
/// replaces:
///
/// 1. The declared record must have been read with certainty at all
///    ([`read_declared_index`] returns `None` otherwise).
/// 2. It must be the SAME record `zip` itself used. `ZipArchive::
///    get_metadata` retries against progressively earlier EOCD records when
///    one fails to parse, so the last plausible record in the file is not
///    necessarily the one the archive was built from. `central_directory_
///    start()` and `offset()` are both public and together say exactly where
///    the crate's chosen record pointed; requiring that to agree with this
///    one's own `cd_offset` makes the comparison apples to apples.
///
/// Only a shortfall is reported. The opposite direction is unreachable —
/// `read_central_header` pushes exactly `number_of_files` records and
/// propagates any parse failure, so the collapsed map can never hold more
/// names than the archive declared records — and a branch that cannot fire is
/// not worth a message nobody will ever read.
fn note_unreachable_records(
    report: &mut FidelityReport,
    archive: &zip::ZipArchive<SeekAdapter>,
    declared: Option<DeclaredIndex>,
) {
    let Some(declared) = declared else { return };
    if declared.cd_offset.checked_add(archive.offset()) != Some(archive.central_directory_start()) {
        return;
    }
    let enumerated = archive.len() as u64;
    let Some(shadowed) = declared.entries.checked_sub(enumerated).filter(|n| *n > 0) else {
        return;
    };
    report.warn(Fidelity::EntryCountMismatch {
        format: ZIP,
        declared: declared.entries,
        enumerated,
        reason: format!(
            "{shadowed} record(s) repeat a name already in the index and are shadowed by \
             it; only the last record under each name can be read"
        ),
    });
}

/// One central-directory file header, physically enumerated.
///
/// Unlike `zip::ZipArchive`'s own view (an `IndexMap` keyed by name — see
/// [`DeclaredIndex`]'s doc for why that collapses two records sharing a name
/// down to the last one), a `CdRecord` is one PER RECORD: an archive with
/// eight central-directory records under six names yields eight of these,
/// two of which repeat a `name` already seen at a different
/// `local_header_offset`. That is precisely what [`walk_central_directory`]
/// exists to recover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdRecord {
    /// Byte offset of this record's own signature within the archive.
    pub offset: u64,
    /// The local file header this record's entry claims to start at,
    /// relative to the start of the archive. Two records can agree on every
    /// other field and still be genuinely separate entries by differing only
    /// here — that is the shape a shadowed pair takes.
    pub local_header_offset: u64,
    /// Decoded lossily (`String::from_utf8_lossy`): a name this project
    /// cannot honestly represent is still a name a caller may want to see,
    /// and a walk whose whole purpose is recovery should not itself refuse a
    /// record over an encoding quirk.
    pub name: String,
    pub method: u16,
    pub crc32: u32,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
}

/// Ceiling on a central-directory record's declared `name_len`, checked
/// before allocating a buffer sized from it — the same ceiling and the same
/// reasoning as `cpio.rs`'s `c_namesize` guard and `ar.rs`'s BSD extended
/// identifier: a length read from a scanned header is untrustworthy twice
/// over, attacker-controlled and possibly corrupt, and 65,536 bytes is far
/// past any real path.
const MAX_CD_NAME_LEN: u64 = 65_536;

/// Walks the central directory record by record, from the offset the
/// archive's own end-of-central-directory record declares, recovering every
/// record the archive physically holds.
///
/// `None` only when the walk cannot even begin: [`read_declared_index`]
/// could not read the EOCD with certainty (it already refuses to guess
/// there), or the initial seek to `cd_offset` itself fails. Once under way,
/// this is a RECOVERY rather than a verifier — carrying `read_declared_
/// index`'s discipline forward with one deliberate difference. That function
/// feeds only a fidelity WARNING, so it returns `None` rather than a number
/// it is not sure of; this feeds a recovery, so it returns the records it IS
/// sure of and stops at the first one it is not. Either way, it never
/// invents a record: the length of the returned `Vec` is always exactly what
/// was actually walked, never the EOCD's declared count.
pub fn walk_central_directory<R: Read + Seek>(r: &mut R) -> Option<Vec<CdRecord>> {
    let declared = read_declared_index(r)?;
    r.seek(SeekFrom::Start(declared.cd_offset)).ok()?;

    let mut records = Vec::new();
    loop {
        let offset = r.stream_position().ok()?;
        match read_one_cd_record(r, offset) {
            Ok(Some(record)) => records.push(record),
            // Not a central-directory signature at all — ordinarily the
            // EOCD itself. The walk has reached the end of the index, which
            // is the expected, healthy way for it to stop.
            Ok(None) => break,
            // Malformed, or refused before an allocation it could not
            // justify. Either way: stop rather than invent what comes next.
            // `note_unreachable_records`'s warning is what tells a caller
            // when this recovery came up short of the EOCD's declared
            // count.
            Err(_) => break,
        }
    }
    Some(records)
}

/// Reads one central-directory record at the reader's current position.
///
/// `Ok(None)` when the four bytes here are not [`SIG_CENTRAL_HEADER`] — not
/// damage, just the walk reaching the end of the central directory (an EOCD,
/// almost always). [`Error::ResourceLimit`] (exit 6) when `name_len` exceeds
/// [`MAX_CD_NAME_LEN`], refused before the allocation it would otherwise
/// justify. [`Error::Corrupt`] (exit 5) for anything else that keeps a
/// record matched by signature from being read whole: a truncated fixed
/// block, or a name/extra/comment field that runs past the end of the
/// source. One arm per case, deliberately — see `error.rs`'s exit-5-versus-6
/// rule.
fn read_one_cd_record<R: Read + Seek>(r: &mut R, offset: u64) -> Result<Option<CdRecord>> {
    let mut signature = [0u8; 4];
    if r.read_exact(&mut signature).is_err() {
        return Ok(None);
    }
    if signature != SIG_CENTRAL_HEADER {
        return Ok(None);
    }

    let mut fixed = [0u8; CENTRAL_HEADER_FIXED];
    r.read_exact(&mut fixed).map_err(|e| {
        Error::Corrupt(format!(
            "zip: central directory record at {offset} truncated: {e}"
        ))
    })?;

    let method = le16(&fixed[6..]);
    let crc32 = le32(&fixed[12..]);
    let compressed_size = le32(&fixed[16..]);
    let uncompressed_size = le32(&fixed[20..]);
    let name_len = le16(&fixed[24..]);
    let extra_len = le16(&fixed[26..]);
    let comment_len = le16(&fixed[28..]);
    let local_header_offset = le32(&fixed[38..]);

    if u64::from(name_len) > MAX_CD_NAME_LEN {
        return Err(Error::ResourceLimit(format!(
            "central directory record at {offset} declares a name of {name_len} bytes, \
             past the {MAX_CD_NAME_LEN}-byte ceiling this build allocates for one"
        )));
    }

    let mut name_bytes = vec![0u8; name_len as usize];
    r.read_exact(&mut name_bytes).map_err(|e| {
        Error::Corrupt(format!(
            "zip: central directory record at {offset}'s name truncated: {e}"
        ))
    })?;
    let name = String::from_utf8_lossy(&name_bytes).into_owned();

    skip_forward(r, u64::from(extra_len) + u64::from(comment_len)).map_err(|e| {
        Error::Corrupt(format!(
            "zip: central directory record at {offset}'s extra/comment field truncated: {e}"
        ))
    })?;

    Ok(Some(CdRecord {
        offset,
        local_header_offset: u64::from(local_header_offset),
        name,
        method,
        crc32,
        compressed_size: u64::from(compressed_size),
        uncompressed_size: u64::from(uncompressed_size),
    }))
}

/// Reads and discards exactly `n` bytes, reporting a short read rather than
/// silently accepting whatever was there. A raw seek past a field like this
/// would not fail on a truncated source — the following read would just find
/// itself somewhere it should not be — so this reads the bytes instead of
/// jumping over them.
fn skip_forward<R: Read>(r: &mut R, n: u64) -> io::Result<()> {
    let copied = io::copy(&mut r.take(n), &mut io::sink())?;
    if copied != n {
        return Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            format!("expected to skip {n} bytes, only {copied} were available"),
        ));
    }
    Ok(())
}

/// Reproduces the shape of a real-world archive: eight central-directory
/// records under six names, where the two extras are byte-identical copies (a
/// real local file header and payload, physically duplicated) at different
/// local-header offsets. The bytes are BUILT here rather than committed, so
/// nothing proprietary enters the tree and the expectation cannot strand from
/// the fixture — the `sample.arj` lesson (see `CONTRIBUTING.md`'s legacy-
/// formats section).
///
/// `pub(crate)`, not private: Task 4's `zip_salvage.rs` reuses this exact
/// fixture (ruling R-D) rather than growing a second one that could drift
/// from it. `#[cfg(test)]` at the top level of this module rather than
/// nested inside `mod tests`, deliberately — a private `mod tests` is not
/// visible to a sibling module in this crate, and R-D requires it to be.
#[cfg(test)]
pub(crate) fn build_shadowing_zip() -> Vec<u8> {
    let names = [
        "one.txt",
        "two.txt",
        "shadowed-a.bin",
        "shadowed-b.bin",
        "five.txt",
        "six.txt",
    ];
    let payloads: [&[u8]; 6] = [
        b"payload for entry one",
        b"payload for entry two",
        b"payload for the first record that will be shadowed",
        b"payload for the second record that will be shadowed",
        b"payload for entry five",
        b"payload for entry six",
    ];

    // 1. A clean base archive, six distinct entries, Stored so that a local
    // header's declared compressed size is unambiguous (no deflate framing
    // to reason about) and — because the sink is a `Cursor` (`Seek`) —
    // written with no data descriptor, per zip-rs's own `using_data_
    // descriptor = !seek_possible`. That is what makes "30 bytes fixed +
    // name + extra + compressed_size" the whole local block, checked
    // directly below rather than assumed.
    let mut cursor = io::Cursor::new(Vec::new());
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    {
        let mut w = zip::ZipWriter::new(&mut cursor);
        for (name, data) in names.iter().zip(payloads.iter()) {
            w.start_file(*name, opts).expect("start_file");
            w.write_all(data).expect("write payload");
        }
        w.finish().expect("finish base archive");
    }
    let base = cursor.into_inner();

    let base_names = zip::ZipArchive::new(io::Cursor::new(base.clone()))
        .expect("base archive opens")
        .len();
    assert_eq!(
        base_names, 6,
        "base fixture must start clean: 6 distinct, unshadowed names"
    );

    let declared =
        read_declared_index(&mut io::Cursor::new(&base)).expect("base archive's EOCD reads");
    let cd_start = usize::try_from(declared.cd_offset).expect("cd_offset fits usize");
    let eocd_start = base.len() - END_OF_CENTRAL_DIR_TOTAL;
    assert_eq!(
        base[eocd_start..eocd_start + 4],
        SIG_END_OF_CENTRAL_DIR,
        "base fixture must end in a bare EOCD with no trailing comment"
    );

    // 2. Locate every record's own span in the central directory, and its
    // local header's span, using nothing but the fixed-field layout this
    // module already documents (`CENTRAL_HEADER_FIXED`'s doc, and the
    // local-header layout `begins_with_a_local_header`/`read_symlink_
    // target` rely on) — not `walk_central_directory` itself, which does
    // not exist yet at the point in the TDD cycle this builder is written.
    fn cd_record_span(bytes: &[u8], at: usize) -> (usize, usize) {
        assert_eq!(
            bytes[at..at + 4],
            SIG_CENTRAL_HEADER,
            "expected a central-directory record at this offset"
        );
        let name_len = le16(&bytes[at + 28..]) as usize;
        let extra_len = le16(&bytes[at + 30..]) as usize;
        let comment_len = le16(&bytes[at + 32..]) as usize;
        let lho = le32(&bytes[at + 42..]) as usize;
        (lho, 46 + name_len + extra_len + comment_len)
    }
    fn local_block_span(bytes: &[u8], lho: usize) -> usize {
        assert_eq!(
            bytes[lho..lho + 4],
            SIG_LOCAL_HEADER,
            "expected a local file header at the declared offset"
        );
        let name_len = le16(&bytes[lho + 26..]) as usize;
        let extra_len = le16(&bytes[lho + 28..]) as usize;
        let compressed_size = le32(&bytes[lho + 18..]) as usize;
        30 + name_len + extra_len + compressed_size
    }

    let mut records = Vec::new();
    let mut at = cd_start;
    while at < eocd_start {
        let (lho, len) = cd_record_span(&base, at);
        records.push((at, lho, len));
        at += len;
    }
    assert_eq!(
        records.len(),
        6,
        "base fixture's central directory must hold exactly 6 records"
    );

    let (rec2_at, rec2_lho, rec2_len) = records[2];
    let (rec3_at, rec3_lho, rec3_len) = records[3];
    let rec2_local_len = local_block_span(&base, rec2_lho);
    let rec3_local_len = local_block_span(&base, rec3_lho);

    // 3. Assemble the shadowed archive: the original local file data, then a
    // byte-identical copy of each shadowed entry's local header and payload
    // at a NEW offset, then the central directory — the 6 original records
    // followed by 2 duplicates whose only changed bytes are the patched
    // local-header-offset field — then a patched EOCD declaring 8.
    let mut out = Vec::new();
    out.extend_from_slice(&base[..cd_start]);

    let dup2_lho = out.len() as u32;
    out.extend_from_slice(&base[rec2_lho..rec2_lho + rec2_local_len]);
    let dup3_lho = out.len() as u32;
    out.extend_from_slice(&base[rec3_lho..rec3_lho + rec3_local_len]);

    let new_cd_start = out.len() as u32;
    out.extend_from_slice(&base[cd_start..eocd_start]);
    let dup2_cd_at = out.len();
    out.extend_from_slice(&base[rec2_at..rec2_at + rec2_len]);
    out[dup2_cd_at + 42..dup2_cd_at + 46].copy_from_slice(&dup2_lho.to_le_bytes());
    let dup3_cd_at = out.len();
    out.extend_from_slice(&base[rec3_at..rec3_at + rec3_len]);
    out[dup3_cd_at + 42..dup3_cd_at + 46].copy_from_slice(&dup3_lho.to_le_bytes());

    let new_eocd_start = out.len();
    let new_cd_size = (new_eocd_start - new_cd_start as usize) as u32;
    out.extend_from_slice(&base[eocd_start..]);
    out[new_eocd_start + 8..new_eocd_start + 10].copy_from_slice(&8u16.to_le_bytes());
    out[new_eocd_start + 10..new_eocd_start + 12].copy_from_slice(&8u16.to_le_bytes());
    out[new_eocd_start + 12..new_eocd_start + 16].copy_from_slice(&new_cd_size.to_le_bytes());
    out[new_eocd_start + 16..new_eocd_start + 20].copy_from_slice(&new_cd_start.to_le_bytes());

    // 4. Assert the result really has 8 records under 6 names, using sources
    // INDEPENDENT of `walk_central_directory`: the `zip` crate's own
    // collapsed count for the names, and `read_declared_index` (this
    // module's pre-existing EOCD reader) for the count now declared. A
    // broken builder fails loudly here rather than silently handing Steps
    // 1/6 a healthy 6-record zip that would pass while proving nothing —
    // this project's own signature defect.
    let shadowed_names = zip::ZipArchive::new(io::Cursor::new(out.clone()))
        .expect("shadowed archive still opens")
        .len();
    assert_eq!(
        shadowed_names, 6,
        "shadowed fixture must still collapse to 6 distinct names"
    );
    let redeclared =
        read_declared_index(&mut io::Cursor::new(&out)).expect("shadowed archive's EOCD reads");
    assert_eq!(
        redeclared.entries, 8,
        "shadowed fixture must declare 8 records"
    );
    assert_eq!(
        redeclared.cd_offset,
        u64::from(new_cd_start),
        "shadowed fixture's cd_offset must point at the rewritten central directory"
    );

    out
}

/// Does the file open with a local file header?
///
/// Four bytes at offset 0, and deliberately only there. Byte 0 of a zip is a
/// local file header (the archive holds at least one entry), an
/// end-of-central-directory record (it holds none), a zip64 record, or a
/// self-extracting stub — it is never `PK\x03\x04` on an archive with no
/// entries. Scanning the whole file for the signature instead is what the
/// FORWARD reader does, and outside that reader's framing walk it is a
/// heuristic: those four bytes occur inside stored payloads and inside file
/// comments, which is the whole reason [`read_declared_index`] refuses a bare
/// backwards search for the EOCD's own signature. Offset 0 is a check.
///
/// The cost of the narrowness is a miss, never a wrong answer. A
/// stub-prefixed (self-extracting) archive whose index is unusable is not
/// caught, because its first local header sits at `ZipArchive::offset()`
/// rather than at 0. **That is a deferral, not an impossibility, and the
/// earlier wording here claimed the latter.** `ZipArchive::into_inner` is
/// public in zip 8.6.0 alongside `offset()`, so the bytes ARE reachable from
/// inside the `is_empty()` branch; closing the gap means re-reading four
/// bytes at `offset()` there. It is left open because the exposure is narrow
/// — magic detection needs `PK` at offset 0, so only extension-based
/// resolution reaches a stub-prefixed file at all, and the fuzz targets
/// cannot construct the class either. A miss leaves the behaviour exactly as
/// it was; a false positive would refuse a valid archive.
fn begins_with_a_local_header<R: Read + Seek>(r: &mut R) -> bool {
    let mut head = [0u8; 4];
    r.seek(SeekFrom::Start(0)).is_ok()
        && r.read_exact(&mut head).is_ok()
        && head == SIG_LOCAL_HEADER
}

/// Refuses an archive whose index reaches NOTHING while the file itself opens
/// with an entry.
///
/// Measured, on the 568-byte reproducer Phase 3a's `container` fuzz target
/// parked (`crash-fidelity-claim-zip.bin`; its first byte is the target's
/// format selector, not archive content). Its only `PK\x05\x06` record
/// declares `total_entries = 0` and `cd_offset = 0`, and `ZipArchive` accepts
/// it. Before this guard `stuffr list` printed no rows, `stuffr test
/// --strict-fidelity` answered `0 bytes verified (exact fidelity)`, and
/// `stuffr unpack -C out --strict-fidelity` created an empty directory — all
/// three at exit 0, with the strict gate on — for a file whose four entries
/// the SAME binary recovers in full, correctly named, when the identical
/// bytes arrive on a pipe. Info-ZIP's `unzip -l` refuses it at exit 3.
///
/// [`note_unreachable_records`] cannot see the 568-byte reproducer, and is not
/// being loosened to make it: its guard 1 requires the EOCD's declared comment
/// length to run exactly to the end of the file, that record's does not, so
/// `declared` is `None` and there is no count to compare against.
///
/// **It is not blind to the whole class, though, and an earlier wording here
/// overstated that.** Of 211 inputs this guard refuses, one had a
/// well-formed-enough EOCD that `note_unreachable_records` did fire on it —
/// exit 0 with an `EntryCountMismatch` warning, exit 4 under the strict gate.
/// This guard runs first, so such an archive is now refused at exit 5 rather
/// than warned about. That escalation is right on the merits — nothing was
/// reachable either way — but it does mean a zero-enumeration archive can no
/// longer report a count mismatch. That guard is what keeps
/// the count warning off healthy archives and it is right; this is a second,
/// independent observation standing beside it.
///
/// **Refused, not warned** — the opposite ruling to the count shortfall two
/// functions up, and the same one the size-lying entry got. There the index
/// is self-consistent and the reader reaches most of it, so handing back what
/// is reachable is a service and naming the shortfall is enough. Here nothing
/// is reachable, so a warning would leave `unpack -C out` creating an empty
/// directory at exit 0, with `--strict-fidelity` the only thing between a
/// user and a restore that silently produced no files. `Error::Corrupt` (exit
/// 5) rather than `ResourceLimit` (exit 6) for the reason `error.rs`'s
/// `exit_code` states once for all five bounding guards: the bytes were read
/// and found to contradict themselves, and no budget makes that archive
/// readable.
///
/// **Still not recovered.** Reaching the four entries would mean
/// re-implementing the central-directory parse this module deliberately
/// delegates — the "declared, not recovered" ruling in the module doc. The
/// message names the route that already works instead.
///
/// A legitimately empty zip is unaffected and must stay that way: it is 22
/// bytes beginning `PK\x05\x06`, so `opens_with_an_entry` is false and this
/// returns `Ok`. `an_empty_zip_is_still_exact_and_empty` pins it.
fn refuse_an_index_that_reaches_nothing(
    archive: &zip::ZipArchive<SeekAdapter>,
    opens_with_an_entry: bool,
) -> Result<()> {
    if !archive.is_empty() || !opens_with_an_entry {
        return Ok(());
    }
    Err(Error::Corrupt(
        "zip index reaches no entries at all, yet the file opens with a local file header \
         (`PK\\x03\\x04`): the end-of-central-directory record does not describe this archive. \
         A forward read of the same bytes (`cat FILE | stuffr list -`) parses the local \
         headers instead"
            .into(),
    ))
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

        let payload = EntryPayload::new(file, meta.size, &meta.name);
        Ok(Entry::new(
            meta,
            Box::new(NormalizeDecodeErrors::new(
                payload,
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
            // Through the shared constructor, NOT a `format!` of its own: a
            // caller counting a forward walk raises the very same refusal for
            // the very same mistake, and the two must be indistinguishable.
            // See `Error::entry_index_out_of_range`.
            return Err(Error::entry_index_out_of_range(index, len));
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
        let payload = EntryPayload::new(file, meta.size, &meta.name);
        Ok(Some(Entry::new(
            meta,
            Box::new(NormalizeDecodeErrors::new(
                payload,
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

/// One entry's payload, held to the length its own header declares — the
/// short-read guard `tar.rs`, `ar.rs` and `cpio.rs` have each carried since
/// Phase 2 and zip did not.
///
/// It looks redundant next to zip's per-entry crc32 and it is not, because
/// the crc is computed over the bytes DELIVERED and compared against a value
/// the SAME header supplies. A local header declaring 42 uncompressed bytes,
/// 0 compressed bytes and crc32 `0` — the crc of nothing — therefore
/// satisfies its own checksum perfectly, and `zip::ZipFile`'s reader is a
/// `Take` over the COMPRESSED length, so nothing else in the read path ever
/// looked at the uncompressed one. Found by the `container` fuzz target;
/// before this, `stuffr list` printed `42  hello.txt` while `stuffr test
/// --strict-fidelity` answered `0 bytes verified (exact fidelity)` at exit 0
/// and `unpack` wrote the empty file.
///
/// Both directions are refused. A payload that runs out early is truncation;
/// one that keeps going past the declared length is a header disagreeing with
/// its own contents — Info-ZIP's `unzip -t` reports that second shape too
/// (`ucsize 1 <> csize 5 for STORED entry`) and exits non-zero for it.
///
/// `Error::Corrupt` (exit 5), not a fidelity warning, and the wording is
/// `tar.rs`'s verbatim so the four containers answer a cut payload with one
/// sentence. The bytes are MISSING, not approximated: a warning would leave
/// `unpack` writing a truncated file and calling the run successful, with
/// `--strict-fidelity` the only thing between a user and a silently wrong
/// file on disk. That is the opposite ruling to `Fidelity::
/// EntryCountMismatch`, deliberately — there the archive's index is
/// self-consistent and the READER cannot reach every record, so returning
/// what is reachable is a service; here the archive contradicts itself and
/// there is nothing honest to return.
///
/// Exit 5 rather than `ResourceLimit`'s 6 for the reason
/// `stuffr_core::Error::exit_code`'s doc states once for all five of this
/// workspace's header-field guards: the bytes were READ and found to
/// disagree with each other, where exit 6 means a ceiling refused before an
/// allocator was asked.
///
/// A SYMLINK entry never reaches this: `ZipIndexed::entry_at` consumes its
/// payload itself (the target IS the payload) and hands the caller
/// `io::empty()` before this wrapper is ever built. `read_symlink_target`
/// does its own short-read check, so nothing is lost by that.
struct EntryPayload<R> {
    inner: R,
    /// Payload bytes the entry's header promised and has not delivered.
    /// `None` when the header declared no size at all — impossible for zip
    /// today (`entry_meta` always sets one) and left representable rather
    /// than `expect`ed, so a future metadata change cannot turn this into a
    /// panic.
    remaining: Option<u64>,
    /// Kept for the error message: a corrupt archive should say WHICH entry.
    name: String,
}

impl<R> EntryPayload<R> {
    fn new(inner: R, declared: Option<u64>, name: &str) -> Self {
        Self {
            inner,
            remaining: declared,
            name: name.to_owned(),
        }
    }
}

impl<R: Read> Read for EntryPayload<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // `Read`'s contract: an empty buffer reads nothing and is not an
        // error. Without this the short-read check below cannot tell "the
        // stream ended" from "you gave me nowhere to put bytes" and reports
        // an intact archive as truncated — the same guard, for the same
        // reason, that `tar.rs`'s `EntryPayload::read` opens with.
        if buf.is_empty() {
            return Ok(0);
        }
        let n = self.inner.read(buf)?;
        let Some(remaining) = self.remaining.as_mut() else {
            return Ok(n);
        };
        if n == 0 {
            if *remaining > 0 {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "entry `{}` is {} bytes short of the size its header declares; \
                         the archive is truncated",
                        self.name, remaining
                    ),
                ));
            }
            return Ok(0);
        }
        if n as u64 > *remaining {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "entry `{}` delivers more bytes than the size its header declares; \
                     the archive's index and its contents disagree",
                    self.name
                ),
            ));
        }
        *remaining -= n as u64;
        Ok(n)
    }
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
                    // NOT `lzma` in that list: the arm two up rejects it,
                    // because zip's `lzma` feature is decode-only.
                    // Recommending a codec this same function refuses would
                    // send the caller straight into a second error.
                    "this build cannot write a zstd-compressed zip entry: zip's zstd support is \
                     the one entry codec that needs a C toolchain. Rebuild with `--features \
                     c-backed`, or pick `deflate`, `bzip2`, `xz` or `store`"
                        .into(),
                ))
            }
        }
        other => Err(Error::Unsupported(format!(
            "`{other}` is not a zip entry codec; this build writes zip entries with deflate, \
             bzip2, xz or store (zstd needs `--features c-backed`; lzma is read-only)"
        ))),
    }
}

/// Rejects a `--level` the chosen entry codec does not have, BEFORE the
/// destination has been touched.
///
/// zip validates the level inside `start_file`, which is halfway through
/// `add`: the error would arrive after the archive had begun, and it arrives
/// as `UnsupportedArchive("Unsupported compression level")` — an
/// [`Error::Unsupported`] (exit 3, "this build cannot do that") where every
/// codec in this tree answers an out-of-range level with [`Error::Usage`]
/// (exit 2, "you asked for the wrong thing"). A level outside a codec's range
/// is the caller's mistake, not a missing capability, so `stuffr pack a b -o
/// x.zip --level 99` should be the same class of mistake as `--level 0` on
/// bzip2 — and cost the same nothing.
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
    dst: Box<dyn Sink>,
    buf: Vec<u8>,
    base: u64,
    pos: u64,
}

impl Spool {
    fn new(dst: Box<dyn Sink>) -> Self {
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

    /// Hands the real destination back, leaving a placeholder behind.
    ///
    /// Deliberately NOT `Rc::try_unwrap(self.spool)`: [`SpoolHandle`] shares
    /// that `Rc`, so an unwrap depends on drop order and would fail at
    /// runtime the moment a handle outlives the writer by one step. A swap
    /// has no such dependency.
    fn take_destination(&mut self) -> Box<dyn Sink> {
        std::mem::replace(&mut self.dst, PlainSink::new(Box::new(std::io::sink())))
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
        // A seek past the end followed by a write would leave a hole, and
        // zero-filling it is what a real file would do. `ZipWriter` never
        // does this — it only ever seeks BACK, to a header it already wrote —
        // so the branch is unreachable in practice.
        //
        // Bounded anyway, because it is the one place in this module where an
        // OFFSET turns into an allocation, and every other allocation here is
        // explicitly capped (`MAX_SYMLINK_TARGET_LEN`, `skip`'s 4 KiB
        // scratch). Without the cap, a seek to a large offset followed by one
        // byte would try to allocate that offset. The bound is generous
        // relative to real framing — a local header plus a name and extra
        // fields is at most a few hundred KiB — so it cannot fire on
        // legitimate output.
        if off > spool.buf.len() {
            let hole = off - spool.buf.len();
            if hole > MAX_SPOOL_HOLE {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "zip: refusing to zero-fill a {hole}-byte hole in the spool window; \
                         the cap is {MAX_SPOOL_HOLE}"
                    ),
                ));
            }
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
    /// commits the window, then returns the destination.
    ///
    /// Never via `Drop`: `impl<W: Write + Seek> Drop for ZipWriter<W>`
    /// finalizes the archive and writes any failure to STDERR, so relying on
    /// it loses the error entirely — the hazard conformance property 4 asserts
    /// against. `ZipWriter::finish` here consumes the writer, after which its
    /// `Drop` sees a closed archive and does nothing.
    ///
    /// The destination is returned, not finished: the caller owns completion,
    /// because a codec layer beneath us has its own trailer still to write.
    /// `commit_all` has already pushed every byte down with `write_all`, and
    /// there is deliberately no flush of the destination here — tar, ar and
    /// cpio dropped theirs when `Sink` became the write-side currency, and a
    /// flush on a codec sink is not free: `GzEncoder::flush` emits a
    /// `Z_SYNC_FLUSH` empty stored block and liblzma's emits `LZMA_SYNC_FLUSH`,
    /// closing a block early and costing real ratio on `pack -o x.zip.xz`.
    /// `Sink::finish`, which the caller now owns, flushes.
    fn finish(mut self: Box<Self>) -> Result<Box<dyn Sink>> {
        let writer = self
            .inner
            .take()
            .ok_or_else(|| Error::Usage("zip writer finished twice".into()))?;
        writer.finish().map_err(classify_zip_error)?;
        // Only now does the destination see anything it has not seen already.
        let mut spool = self.spool.borrow_mut();
        spool.commit_all()?;
        Ok(spool.take_destination())
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
        let mut w = Zip
            .create(PlainSink::new(Box::new(buf.clone())), opts)
            .expect("create");
        for (meta, data) in entries {
            w.add(meta, &mut io::Cursor::new(*data)).expect("add");
        }
        w.finish().expect("finish").finish().expect("finish sink");
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
        // **Skips nothing.** zip is the only container in this tree that runs
        // all thirteen: it declares `trailing_index` (property 7), both
        // `stores_dirs` and `stores_symlinks` (13), and parses forward (5,
        // 6, 8). The empty list is the strongest statement a caller can
        // make here, and it is asserted rather than assumed.
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

    // -----------------------------------------------------------------------
    // A record the index declares but the reader cannot reach
    // -----------------------------------------------------------------------

    /// Appends a verbatim copy of the archive's FIRST central-directory record
    /// and bumps the declared count, producing a zip whose index holds one
    /// more record than it has distinct names.
    ///
    /// Forged at the byte level rather than written with `Zip.create`, because
    /// `ZipWriter` will not produce this shape — which is the point: the file
    /// that motivated this arrived from somewhere else. `unzip -t` reads its
    /// real-world equivalent without complaint, and so must this; the archive
    /// is well-formed, it merely names one path twice.
    ///
    /// The copy points at the same local header as the original, which the
    /// original names at a different offset. That difference does not matter
    /// to what is being tested: `ZipArchive` keys its map on the NAME, so any
    /// two records sharing one collapse the same way.
    fn with_shadowed_record(bytes: &[u8]) -> Vec<u8> {
        // `build_zip` writes no archive comment, so the EOCD is the last 22.
        let eocd = bytes.len() - END_OF_CENTRAL_DIR_TOTAL;
        assert_eq!(bytes[eocd..eocd + 4], SIG_END_OF_CENTRAL_DIR, "no EOCD");
        let entries = le16(&bytes[eocd + 10..]);
        let cd_size = le32(&bytes[eocd + 12..]) as usize;
        let cd_at = le32(&bytes[eocd + 16..]) as usize;

        let cd = &bytes[cd_at..cd_at + cd_size];
        assert_eq!(cd[..4], SIG_CENTRAL_HEADER, "no central directory");
        // 46 fixed bytes, then the three variable-length fields at 28/30/32.
        let first =
            46 + le16(&cd[28..]) as usize + le16(&cd[30..]) as usize + le16(&cd[32..]) as usize;

        let mut out = bytes[..cd_at + cd_size].to_vec();
        out.extend_from_slice(&cd[..first]);
        let mut tail = bytes[eocd..].to_vec();
        tail[8..10].copy_from_slice(&(entries + 1).to_le_bytes());
        tail[10..12].copy_from_slice(&(entries + 1).to_le_bytes());
        tail[12..16].copy_from_slice(&((cd_size + first) as u32).to_le_bytes());
        out.extend_from_slice(&tail);
        out
    }

    fn count_mismatch(report: &FidelityReport) -> Option<(u64, u64)> {
        report.warnings.iter().find_map(|w| match w {
            Fidelity::EntryCountMismatch {
                declared,
                enumerated,
                ..
            } => Some((*declared, *enumerated)),
            _ => None,
        })
    }

    /// The defect this exists for. `ZipArchive` collapses records that share a
    /// name, so an archive declaring three holds back one — and before this,
    /// an exact read reported the two survivors and claimed it had lost
    /// nothing, which is the one thing this tool must never do.
    #[test]
    fn an_index_that_declares_more_records_than_are_reachable_is_reported() {
        let bytes = with_shadowed_record(&build_zip(&[("a.txt", b"alpha"), ("b.txt", b"beta")]));
        let ar = open_seekable(&bytes);
        let report = ar.fidelity();

        assert_eq!(
            count_mismatch(report),
            Some((3, 2)),
            "both numbers must be named: {:?}",
            report.warnings
        );
        assert!(
            report.has_warnings(),
            "--strict-fidelity must fail an archive that was only partly enumerated"
        );
        assert!(
            !report.is_lossless(),
            "a read that could not reach every record is not lossless, whatever rung it landed on"
        );
        // The rung is untouched: the ACCESS PATH really was exact. What is
        // lost is in the archive's own index, not in how it was reached.
        assert_eq!(report.rung, Rung::Exact);
    }

    /// The other half, and the one that would catch a guard that fires on
    /// everything: an ordinary archive must gain no warning at all.
    #[test]
    fn an_ordinary_zip_gains_no_count_warning() {
        let bytes = build_zip(&[("a.txt", b"alpha"), ("b.txt", b"beta"), ("c.txt", b"c")]);
        let ar = open_seekable(&bytes);
        assert_eq!(count_mismatch(ar.fidelity()), None);
        assert!(
            ar.fidelity().is_lossless(),
            "an exact read of a well-formed zip loses nothing: {:?}",
            ar.fidelity().warnings
        );
    }

    /// An empty zip is a bare EOCD declaring zero records, and zero reachable
    /// records is not a shortfall. The boundary the subtraction sits on.
    #[test]
    fn an_empty_zip_declares_nothing_and_loses_nothing() {
        let bytes = build_zip(&[]);
        let ar = open_seekable(&bytes);
        assert_eq!(count_mismatch(ar.fidelity()), None);
        assert!(ar.fidelity().is_lossless());
    }

    // -----------------------------------------------------------------------
    // An index that reaches NOTHING over a file that opens with an entry
    // -----------------------------------------------------------------------

    /// Rewrites the EOCD's two counts and its central-directory offset to
    /// zero, leaving every local header and every central-directory record
    /// physically intact.
    ///
    /// The same shape the parked 568-byte fuzz reproducer has
    /// (`crash-fidelity-claim-zip.bin`): a single mutated EOCD that describes
    /// an empty archive sitting on top of a file that is not one. Forged
    /// rather than written, for the reason `with_shadowed_record` gives —
    /// `ZipWriter` will not produce it, and the file that motivates it comes
    /// from somewhere else.
    fn with_an_index_reaching_nothing(bytes: &[u8]) -> Vec<u8> {
        let mut out = bytes.to_vec();
        let eocd = out.len() - END_OF_CENTRAL_DIR_TOTAL;
        assert_eq!(out[eocd..eocd + 4], SIG_END_OF_CENTRAL_DIR, "no EOCD");
        out[eocd + 8..eocd + 12].copy_from_slice(&[0u8; 4]); // both counts
        out[eocd + 16..eocd + 20].copy_from_slice(&[0u8; 4]); // cd_offset
        out
    }

    /// The defect this exists for, and the worst shape this module has
    /// shipped: a seekable read that recovers NOTHING and calls it exact.
    ///
    /// Before the guard, the reproducer's four entries were reported as zero
    /// rows by `list`, zero bytes verified by `test --strict-fidelity` and an
    /// empty destination directory by `unpack -C --strict-fidelity`, all
    /// three at exit 0 — while a forward read of the identical bytes
    /// recovered all four, correctly named. `note_unreachable_records` cannot
    /// see it: its guard 1 rejects the mutated EOCD, so there is no declared
    /// count to compare and `check_entry_count` has nothing to say.
    #[test]
    fn an_index_reaching_nothing_over_a_file_that_opens_with_an_entry_is_refused() {
        let clean = build_zip(&[("a.txt", b"alpha"), ("b.txt", b"beta")]);
        let bytes = with_an_index_reaching_nothing(&clean);
        // The premise: the forward reader still finds the entries, so the
        // bytes really do carry something an "empty archive" verdict loses.
        assert_eq!(
            read_all_forward(&bytes).expect("forward read").len(),
            2,
            "the forged archive must still be forward-readable, or this test \
             is refusing a file with nothing in it"
        );

        let Err(err) = try_open_seekable(&bytes) else {
            panic!("an empty-and-exact verdict over these bytes is a lie");
        };
        assert!(
            matches!(err, Error::Corrupt(_)),
            "self-contradiction, not a resource limit: {err:?}"
        );
        assert_eq!(err.exit_code(), 5);
        let msg = err.to_string();
        assert!(
            msg.contains("PK\\x03\\x04"),
            "the message must name the evidence: {msg}"
        );
    }

    /// The other arm of the conjunction, and the twelfth-wrongly-firing-check
    /// guard: a legitimately empty zip is a real thing and must stay exit 0
    /// with exact fidelity.
    ///
    /// It is 22 bytes beginning `PK\x05\x06`, so it is `is_empty()` — the
    /// half the reproducer shares — and is accepted purely because it does
    /// NOT open with a local file header. Zero entries on its own is never
    /// enough to refuse.
    #[test]
    fn an_empty_zip_is_still_exact_and_empty() {
        let bytes = build_zip(&[]);
        assert_eq!(bytes[..4], SIG_END_OF_CENTRAL_DIR, "not a bare EOCD");
        let mut ar = try_open_seekable(&bytes).expect("an empty zip is not corrupt");
        assert!(ar.next_entry().expect("walk").is_none());
        assert_eq!(ar.fidelity().rung, Rung::Exact);
        assert!(
            ar.fidelity().is_lossless(),
            "an empty archive lost nothing: {:?}",
            ar.fidelity().warnings
        );
    }

    /// The remaining arm: an ordinary archive opens with a local file header
    /// on every single read, so the header half of the conjunction is true
    /// for essentially every zip in the world. Only reaching nothing makes it
    /// a finding.
    #[test]
    fn an_ordinary_zip_opens_with_a_local_header_and_is_still_accepted() {
        let bytes = build_zip(&[("a.txt", b"alpha")]);
        assert_eq!(bytes[..4], SIG_LOCAL_HEADER, "not a local header");
        let ar = open_seekable(&bytes);
        assert!(ar.fidelity().is_lossless());
    }

    /// Builds a zip whose archive comment is `decoy` followed by `padding`
    /// bytes of filler, leaving the real EOCD intact ahead of it.
    fn with_archive_comment(clean: &[u8], decoy: &[u8], padding: usize) -> Vec<u8> {
        let mut bytes = clean.to_vec();
        let eocd = bytes.len() - END_OF_CENTRAL_DIR_TOTAL;
        let comment_len = decoy.len() + padding;
        bytes[eocd + 20..eocd + 22].copy_from_slice(&(comment_len as u16).to_le_bytes());
        bytes.extend_from_slice(decoy);
        bytes.extend(std::iter::repeat_n(b'.', padding));
        bytes
    }

    /// A plausible-looking end-of-central-directory record claiming `entries`.
    fn decoy_record(entries: u16) -> Vec<u8> {
        let mut d = SIG_END_OF_CENTRAL_DIR.to_vec();
        d.extend_from_slice(&[0u8; END_OF_CENTRAL_DIR_FIXED]);
        d[8..10].copy_from_slice(&entries.to_le_bytes());
        d[10..12].copy_from_slice(&entries.to_le_bytes());
        d
    }

    /// `PK\x05\x06` INSIDE an archive comment must not be mistaken for the
    /// record itself — the exact ambiguity that makes a bare backwards search
    /// a heuristic, and why [`read_declared_index`] requires the declared
    /// comment length to run to the end of the file. Bytes follow this decoy,
    /// and it claims a zero-length comment, so the two disagree and it is
    /// rejected.
    ///
    /// Asserted against `read_declared_index` directly, not through a
    /// warning: `note_unreachable_records` independently refuses a record
    /// whose `cd_offset` is not the one `zip` itself used, so a naive search
    /// that swallowed this decoy would still raise no warning — and a test
    /// that only checked the warning would pass against the very bug it
    /// names. Measured: written that way first, it did.
    #[test]
    fn a_decoy_signature_inside_the_archive_comment_does_not_become_the_record() {
        let clean = build_zip(&[("a.txt", b"alpha"), ("b.txt", b"beta")]);
        let bytes = with_archive_comment(&clean, &decoy_record(99), 8);

        assert_eq!(
            read_declared_index(&mut io::Cursor::new(bytes.clone())).map(|d| d.entries),
            Some(2),
            "the record found must be the real one, not the decoy claiming 99"
        );
        assert_eq!(count_mismatch(open_seekable(&bytes).fidelity()), None);
    }

    /// The second guard, and the one that carries the case the first cannot.
    ///
    /// A decoy placed at the very END of the file, declaring a zero-length
    /// comment, is structurally indistinguishable from a real record: it
    /// satisfies the length agreement above, and `read_declared_index` really
    /// does return its count — asserted here so the limitation is recorded
    /// rather than assumed away. What stops a false warning is that
    /// `note_unreachable_records` requires the record's own `cd_offset` to be
    /// the one `ZipArchive` parsed, which this decoy's zero is not.
    ///
    /// Not a contrived shape. `ZipArchive::get_metadata` retries against
    /// progressively earlier records when one fails to parse, so "the last
    /// plausible record in the file" and "the record the archive was built
    /// from" are genuinely two different things.
    #[test]
    fn a_record_zip_did_not_use_cannot_raise_a_warning() {
        let clean = build_zip(&[("a.txt", b"alpha"), ("b.txt", b"beta")]);
        let bytes = with_archive_comment(&clean, &decoy_record(99), 0);

        assert_eq!(
            read_declared_index(&mut io::Cursor::new(bytes.clone())).map(|d| d.entries),
            Some(99),
            "the search cannot tell this one apart; that is what the second guard is for"
        );
        assert_eq!(
            count_mismatch(open_seekable(&bytes).fidelity()),
            None,
            "99 vs 2 would be a false fidelity warning on a healthy archive"
        );
    }

    /// The brief's Step 1 test, verbatim: the walk reaches every physical
    /// record, not every distinct name.
    #[test]
    fn the_record_walk_reaches_records_the_index_shadows() {
        let bytes = build_shadowing_zip();
        let recs = walk_central_directory(&mut io::Cursor::new(&bytes)).expect("walk");
        assert_eq!(
            recs.len(),
            8,
            "the walk must reach every record, not every NAME"
        );
        let names: Vec<_> = recs.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names.iter().collect::<std::collections::HashSet<_>>().len(),
            6
        );
        // The two shadowed records carry the same CRC as their originals.
        assert_eq!(recs[6].crc32, recs[2].crc32);
        assert_eq!(recs[7].crc32, recs[3].crc32);
        // ...at DIFFERENT offsets, which is what makes them separate records.
        assert_ne!(recs[6].local_header_offset, recs[2].local_header_offset);
        assert_ne!(recs[7].local_header_offset, recs[3].local_header_offset);
    }

    /// Every field the walk reports for a shadowed record, not only its CRC
    /// and offset — pinning `method`/`compressed_size`/`uncompressed_size`
    /// too, so a future refactor that copied only part of a record would
    /// still be caught.
    #[test]
    fn a_shadowed_records_full_fields_match_its_original() {
        let bytes = build_shadowing_zip();
        let recs = walk_central_directory(&mut io::Cursor::new(&bytes)).expect("walk");
        assert_eq!(recs[6].name, recs[2].name);
        assert_eq!(recs[6].method, recs[2].method);
        assert_eq!(recs[6].compressed_size, recs[2].compressed_size);
        assert_eq!(recs[6].uncompressed_size, recs[2].uncompressed_size);
        assert_eq!(recs[7].name, recs[3].name);
        assert_eq!(recs[7].method, recs[3].method);
        assert_eq!(recs[7].compressed_size, recs[3].compressed_size);
        assert_eq!(recs[7].uncompressed_size, recs[3].uncompressed_size);
    }

    /// An ordinary, unshadowed zip walks to exactly its own entry count —
    /// the walk must not manufacture shadowing where none exists.
    #[test]
    fn an_unshadowed_zip_walks_to_its_own_entry_count() {
        let bytes = build_zip(&[("a.txt", b"alpha"), ("b.txt", b"beta"), ("c.txt", b"gamma")]);
        let recs = walk_central_directory(&mut io::Cursor::new(&bytes)).expect("walk");
        assert_eq!(recs.len(), 3);
        let names: Vec<_> = recs.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["a.txt", "b.txt", "c.txt"]);
    }

    /// A central-directory record whose fixed block is cut short MID-WALK —
    /// not the walk's opening seek, the second record — leaves the first,
    /// whole record intact and stops there rather than inventing a second.
    /// A fresh, self-consistent EOCD is appended after the cut so
    /// `read_declared_index` still finds one and the walk truly gets to
    /// BEGIN; without that, this would just re-test "no EOCD at all", which
    /// [`read_declared_index`]'s own tests already cover.
    #[test]
    fn a_mid_walk_truncation_keeps_what_came_before_it_and_stops() {
        let bytes = build_zip(&[("a.txt", b"alpha"), ("b.txt", b"beta")]);
        let declared = read_declared_index(&mut io::Cursor::new(&bytes)).expect("EOCD reads");
        let cd_start = usize::try_from(declared.cd_offset).unwrap();
        let record0_len = {
            let name_len = le16(&bytes[cd_start + 28..]) as usize;
            let extra_len = le16(&bytes[cd_start + 30..]) as usize;
            let comment_len = le16(&bytes[cd_start + 32..]) as usize;
            46 + name_len + extra_len + comment_len
        };
        let record1_start = cd_start + record0_len;

        // Keep record 0 whole, plus 10 bytes of record 1 (its signature and
        // part of its fixed block) — genuinely mid-structure.
        let mut truncated = bytes[..record1_start + 10].to_vec();
        let mut eocd = SIG_END_OF_CENTRAL_DIR.to_vec();
        eocd.extend_from_slice(&[0u8; END_OF_CENTRAL_DIR_FIXED]);
        eocd[8..10].copy_from_slice(&2u16.to_le_bytes());
        eocd[10..12].copy_from_slice(&2u16.to_le_bytes());
        eocd[16..20].copy_from_slice(&(cd_start as u32).to_le_bytes());
        truncated.extend_from_slice(&eocd);

        let recs = walk_central_directory(&mut io::Cursor::new(&truncated))
            .expect("a well-formed EOCD is present; the walk must be able to begin");
        assert_eq!(
            recs.len(),
            1,
            "must recover exactly the one whole record before the truncation, never invent a second"
        );
        assert_eq!(recs[0].name, "a.txt");
    }

    /// [`read_declared_index`] itself already refuses a file too short to
    /// hold an EOCD at all — this pins that [`walk_central_directory`]
    /// inherits the refusal rather than guessing a `cd_offset` of its own:
    /// `None`, never a record count invented from nothing.
    #[test]
    fn no_eocd_at_all_leaves_the_walk_unable_to_begin() {
        let bytes = build_zip(&[("a.txt", b"alpha"), ("b.txt", b"beta")]);
        let declared = read_declared_index(&mut io::Cursor::new(&bytes)).expect("EOCD reads");
        let cd_start = usize::try_from(declared.cd_offset).unwrap();
        // Cut away everything from the central directory onward, EOCD
        // included: nothing is left to declare a `cd_offset` from.
        let truncated = &bytes[..cd_start];

        assert_eq!(
            walk_central_directory(&mut io::Cursor::new(truncated)),
            None,
            "no EOCD at all must leave the walk unable to start, not guessing"
        );
    }

    /// [`MAX_CD_NAME_LEN`]'s ceiling is checked before allocating a name
    /// buffer, exactly like `cpio.rs`'s `c_namesize` and `ar.rs`'s BSD
    /// identifier guards it is deliberately the same numeral as. **Unlike
    /// those two**, this one can never actually fire over a genuine central-
    /// directory record: `name_len` is a 16-bit field (APPNOTE 4.3.12),
    /// capping every real declared value at `u16::MAX` (65,535) — one byte
    /// under the 65,536-byte ceiling — so there is no way to encode a
    /// wire-valid record this guard would refuse. Recorded here rather than
    /// silently dropped: the check is kept anyway, for the same reason
    /// `error.rs`'s exit-5-vs-6 rule is written down once rather than
    /// re-derived per call site — a future change to how `name_len` is read
    /// (a wider field, a value assembled some other way) would have this
    /// ceiling already in place. This test pins the boundary that DOES
    /// exist: the maximum representable value is accepted, not refused.
    #[test]
    fn the_maximum_representable_name_len_stays_under_the_ceiling() {
        let mut record = SIG_CENTRAL_HEADER.to_vec();
        record.extend_from_slice(&[0u8; CENTRAL_HEADER_FIXED]);
        record[4 + 24..4 + 26].copy_from_slice(&u16::MAX.to_le_bytes());
        // The name field itself must still be present, or this would fail on
        // truncation instead of pinning the ceiling comparison.
        record.extend(std::iter::repeat_n(b'x', u16::MAX as usize));

        let result = read_one_cd_record(&mut io::Cursor::new(&record), 0).expect("not refused");
        let name = result.expect("a valid signature and whole record").name;
        assert_eq!(name.len(), u16::MAX as usize);
    }

    /// A record whose fixed block is truncated is `Error::Corrupt` (exit 5),
    /// the opposite verdict from the ceiling above on purpose: nothing here
    /// was refused for being too expensive, the bytes that were there just
    /// ran out mid-structure.
    #[test]
    fn a_truncated_fixed_block_is_corrupt_not_a_resource_limit() {
        let mut record = SIG_CENTRAL_HEADER.to_vec();
        record.extend_from_slice(&[0u8; CENTRAL_HEADER_FIXED - 5]);

        let err = read_one_cd_record(&mut io::Cursor::new(&record), 0).unwrap_err();
        assert!(
            matches!(err, Error::Corrupt(_)),
            "expected Corrupt, got {err:?}"
        );
        assert_eq!(err.exit_code(), 5, "Corrupt is exit 5: {err:?}");
    }

    /// A non-central-header signature — the ordinary way the walk ends, an
    /// EOCD record — is `Ok(None)`: the healthy end of the index, not an
    /// error.
    #[test]
    fn a_non_central_header_signature_is_a_clean_stop_not_an_error() {
        let record = SIG_END_OF_CENTRAL_DIR.to_vec();
        let result = read_one_cd_record(&mut io::Cursor::new(&record), 0).expect("not an error");
        assert_eq!(result, None);
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

    /// The crc32 a zip entry's header carries, computed here rather than
    /// pulled in as a dependency: `hand_built_zip` below needs a CORRECT
    /// checksum for an archive whose only defect is its size field, and
    /// `stuffr-formats` has no crc32 crate of its own (the `zip` crate keeps
    /// the one it uses private). Eight lines of the textbook bitwise form —
    /// pinned against a known vector by the test below it.
    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &b in data {
            crc ^= u32::from(b);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    /// The helper above is only useful if it is right, and a wrong one would
    /// make every test built on it fail for the wrong reason — a bad crc32
    /// is refused as corruption too, which is exactly the verdict those tests
    /// assert. Pinned against the standard `check` vector and the empty
    /// string.
    #[test]
    fn the_test_crc32_agrees_with_the_standard_vector() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    /// Builds a one-entry zip from RAW field values — a local file header, a
    /// matching central-directory record and an end-of-central-directory
    /// record — so a test can state a header that disagrees with its own
    /// payload.
    ///
    /// `build_with` cannot serve here and no amount of coaxing will make it:
    /// `zip::ZipWriter` computes the crc32 and both size fields from the data
    /// it is handed, so every archive it produces is self-consistent by
    /// construction. That is the very property under test, which is why this
    /// lays the bytes down by hand. Fields are little-endian throughout, per
    /// APPNOTE 4.3.7 (local header) and 4.3.12 (central header).
    ///
    /// The central record repeats whatever the local one said, so the two
    /// reading rungs — forward (local headers) and seekable (the central
    /// directory) — see the identical claim and neither can pass by reading
    /// the other's numbers.
    fn hand_built_zip(
        name: &str,
        crc: u32,
        compressed: u32,
        uncompressed: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let n = name.as_bytes();
        let n_len = u16::try_from(n.len()).expect("a test name is short");

        let mut local = Vec::new();
        local.extend_from_slice(&SIG_LOCAL_HEADER);
        local.extend_from_slice(&20u16.to_le_bytes()); // version needed
        local.extend_from_slice(&0u16.to_le_bytes()); // flags: NO data descriptor
        local.extend_from_slice(&0u16.to_le_bytes()); // method: STORE
        local.extend_from_slice(&0u16.to_le_bytes()); // mod time
        local.extend_from_slice(&0u16.to_le_bytes()); // mod date
        local.extend_from_slice(&crc.to_le_bytes());
        local.extend_from_slice(&compressed.to_le_bytes());
        local.extend_from_slice(&uncompressed.to_le_bytes());
        local.extend_from_slice(&n_len.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes()); // extra length
        local.extend_from_slice(n);
        local.extend_from_slice(payload);

        let mut central = Vec::new();
        central.extend_from_slice(&SIG_CENTRAL_HEADER);
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0u16.to_le_bytes()); // flags
        central.extend_from_slice(&0u16.to_le_bytes()); // method: STORE
        central.extend_from_slice(&0u16.to_le_bytes()); // mod time
        central.extend_from_slice(&0u16.to_le_bytes()); // mod date
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&compressed.to_le_bytes());
        central.extend_from_slice(&uncompressed.to_le_bytes());
        central.extend_from_slice(&n_len.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra length
        central.extend_from_slice(&0u16.to_le_bytes()); // comment length
        central.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        central.extend_from_slice(&0u32.to_le_bytes()); // external attributes
        central.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        central.extend_from_slice(n);

        let mut eocd = Vec::new();
        eocd.extend_from_slice(&SIG_END_OF_CENTRAL_DIR);
        eocd.extend_from_slice(&0u16.to_le_bytes()); // this disk
        eocd.extend_from_slice(&0u16.to_le_bytes()); // disk with the cd
        eocd.extend_from_slice(&1u16.to_le_bytes()); // records on this disk
        eocd.extend_from_slice(&1u16.to_le_bytes()); // records total
        eocd.extend_from_slice(&(central.len() as u32).to_le_bytes());
        eocd.extend_from_slice(&(local.len() as u32).to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes()); // comment length

        let mut out = local;
        out.extend_from_slice(&central);
        out.extend_from_slice(&eocd);
        out
    }

    /// An entry whose header declares an uncompressed size its payload never
    /// delivers. **The fuzzer's finding, minimised**: `container` aborted on
    /// a 677-byte artefact (`.superpowers/sdd/2026-09-12-phase3a-fuzzing-
    /// harness/crash-entry-size-container.bin`) with `entry "…sample/
    /// hello.txt…" declared 42 bytes but produced 0`; every byte of it that
    /// did not contribute is gone from this, leaving the shape itself.
    ///
    /// zip's own crc32 cannot catch it and this is not a gap in the check but
    /// its definition: the crc is computed over the bytes DELIVERED and
    /// compared against a value the SAME header supplies, so a header
    /// declaring 42 uncompressed bytes, 0 compressed bytes and crc32 `0` —
    /// the crc of nothing — satisfies its own checksum exactly. `ZipFile`'s
    /// reader is a `Take` over the COMPRESSED length; before this guard
    /// nothing in the read path ever compared the uncompressed length against
    /// anything at all.
    ///
    /// Measured before it was fixed: `stuffr list` printed `42  hello.txt`,
    /// `stuffr test --strict-fidelity` answered `0 bytes verified (exact
    /// fidelity)` at exit 0, and `stuffr unpack --strict-fidelity` wrote a
    /// 0-byte `hello.txt` and reported exact fidelity — the tool contradicting
    /// itself across two lines and calling both of them clean.
    #[test]
    fn a_declared_size_the_payload_never_delivers_is_corruption() {
        let bytes = hand_built_zip("hello.txt", 0, 0, 42, b"");

        let err = read_all_forward(&bytes).expect_err("a short payload must be refused");
        assert_eq!(err.exit_code(), 5, "forward rung: got {err:?}");
        let err = read_all_seekable(&bytes).expect_err("a short payload must be refused");
        assert_eq!(err.exit_code(), 5, "seekable rung: got {err:?}");
    }

    /// The same lie the other way up: a payload LONGER than the uncompressed
    /// size its header declares. Info-ZIP's `unzip -t` calls this out
    /// (`ucsize 1 <> csize 5 for STORED entry`, exit 1); before this guard
    /// stuffr listed the entry as 1 byte, verified 5, and reported exact
    /// fidelity at exit 0.
    ///
    /// Worth a test of its own rather than folding into the one above: the
    /// short case is caught by a reader that ends early, the long case by one
    /// that does not end at all, and a guard written for only the first is
    /// the easy mistake here.
    #[test]
    fn a_payload_longer_than_its_declared_size_is_corruption() {
        let payload = b"alpha";
        let crc = crc32(payload);
        let bytes = hand_built_zip("a.txt", crc, payload.len() as u32, 1, payload);

        let err = read_all_forward(&bytes).expect_err("an over-long payload must be refused");
        assert_eq!(err.exit_code(), 5, "forward rung: got {err:?}");
        let err = read_all_seekable(&bytes).expect_err("an over-long payload must be refused");
        assert_eq!(err.exit_code(), 5, "seekable rung: got {err:?}");
    }

    /// The false-firing guard for the two tests above, in the shape most
    /// likely to trip one: an entry that declares nothing and delivers
    /// nothing, built by the same hand-laid bytes so the ONLY difference from
    /// the refused archive is the number in the size field.
    ///
    /// A round-trip test would not do — it proves the writer and the reader
    /// agree, which they would even if both were wrong about this — so this
    /// states the bytes itself and asserts the read is clean.
    #[test]
    fn an_entry_that_delivers_what_it_declares_is_not_refused() {
        for (payload, declared) in [(&b""[..], 0u32), (&b"alpha"[..], 5)] {
            let crc = crc32(payload);
            let bytes = hand_built_zip("a.txt", crc, payload.len() as u32, declared, payload);

            let got = read_all_forward(&bytes).expect("an honest header must not be refused");
            assert_eq!(got.len(), 1);
            assert_eq!(got[0].1, payload, "forward rung returned the wrong payload");
            let got = read_all_seekable(&bytes).expect("an honest header must not be refused");
            assert_eq!(got.len(), 1);
            assert_eq!(
                got[0].1, payload,
                "seekable rung returned the wrong payload"
            );
        }
    }

    /// A SYMLINK entry has the same surface shape as the bug — a non-zero
    /// declared size and a reader that hands back nothing — and must not be
    /// refused. `ZipIndexed::entry_at` consumes a symlink's payload itself,
    /// because the target IS the payload, and gives the caller `io::empty()`
    /// afterwards; `meta.size` keeps the declared target length. Truncation
    /// there is already `read_symlink_target`'s job and it raises
    /// `Error::Corrupt` of its own, so nothing is lost by leaving this shape
    /// alone — and a length guard applied to it would refuse every symlink in
    /// every zip this project writes.
    ///
    /// This is also the archive that made `check_entry_size` itself too
    /// strict: `stuffr pack tree -o t.zip` over a directory holding one
    /// symlink, fed to the `container` fuzz target, aborted with `entry
    /// "tree/link.txt" declared 8 bytes but produced 0` — a legitimate
    /// archive stuffr had just written.
    #[test]
    fn a_symlinks_eagerly_consumed_payload_is_not_a_short_read() {
        let mut link = EntryMeta::file("link.txt");
        link.kind = EntryKind::Symlink {
            target: "real.txt".into(),
        };
        let bytes = build_with(
            &CreateOpts::default(),
            &[(EntryMeta::file("real.txt"), b"hello"), (link, b"")],
        );

        let got = read_all_seekable(&bytes).expect("a symlink must not be refused");
        assert_eq!(got.len(), 2);
        let (meta, data) = &got[1];
        assert_eq!(
            meta.kind,
            EntryKind::Symlink {
                target: "real.txt".into()
            }
        );
        assert_eq!(
            meta.size,
            Some(8),
            "the declared size stays the target length"
        );
        assert!(
            data.is_empty(),
            "the target was consumed by the reader, not left for the caller"
        );
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

    /// Both `unsupported_hint` arms fire on the message `zip` ACTUALLY
    /// raises, checked against the crate's own exported constant and its own
    /// refusal path rather than against a message this module invented.
    ///
    /// The encrypted arm was **dead** on arrival: it tested
    /// `msg.contains("Encrypted")`, and zip 8.6.0 raises
    /// `ZipError::PASSWORD_REQUIRED` — "Password required to decrypt file" —
    /// which contains no such word. Nothing covered it, which is why it went
    /// unnoticed until review. This is the test that was missing.
    #[test]
    fn both_unsupported_hints_are_reachable() {
        // Straight from the crate, so a wording change upstream moves this
        // test's input too and the assertion still means what it says.
        let encrypted = unsupported_hint(ZipError::PASSWORD_REQUIRED);
        assert!(
            encrypted.contains("aes-crypto"),
            "the encrypted hint must fire on the message zip really raises, not on a word \
             that never appears in it: {encrypted:?}"
        );

        // The data-descriptor message has no exported constant, so it is
        // provoked through the real refusal path instead of quoted: a zip
        // written with data descriptors, which `read_zipfile_from_stream`
        // declines, is exactly what a pipe from another tool can carry.
        let buf = SharedBuf::new();
        let mut w = zip::ZipWriter::new_stream(buf.clone());
        w.start_file("d.txt", SimpleFileOptions::DEFAULT)
            .expect("start_file");
        w.write_all(b"data descriptor payload").expect("write");
        w.finish().expect("finish");
        let err = read_all_forward(&buf.contents())
            .expect_err("zip cannot read a data-descriptor entry forward");
        let text = err.to_string();
        assert!(
            text.contains("data descriptor"),
            "the data-descriptor hint must fire on the message zip really raises: {text}"
        );
        assert!(
            matches!(err, Error::Unsupported(_)) && err.exit_code() == 3,
            "a data-descriptor zip is a capability gap, not damage: {err:?}"
        );

        // And an unrelated message gets no hint, so the arms are selective
        // rather than always-on.
        assert_eq!(unsupported_hint("something else entirely"), "");
    }

    /// The zstd refusal must not recommend a codec this same function
    /// rejects. It listed `lzma`, which the arm above it refuses because
    /// zip's `lzma` feature is decode-only — so a caller following the advice
    /// walked straight into a second error.
    #[test]
    fn no_refusal_recommends_a_codec_this_build_cannot_write() {
        // `Vec::new` + `push` rather than a `vec![]` literal: the zstd
        // refusal below is `cfg`'d out on the C-backed tier, and with a
        // literal the binding's `mut` then becomes unnecessary there —
        // `-D warnings` under `--all-features` rejects that.
        let mut refusals = Vec::new();
        refusals.push(
            method_for(Some(FormatId::new("brotli")))
                .expect_err("zip has no brotli method")
                .to_string(),
        );
        #[cfg(not(feature = "zip-zstd"))]
        refusals.push(
            method_for(Some(FormatId::new("zstd")))
                .expect_err("the pure tier cannot write zstd")
                .to_string(),
        );

        for text in &refusals {
            for codec in ["deflate", "bzip2", "xz", "store"] {
                if text.contains(codec) {
                    assert!(
                        method_for(Some(FormatId::new(codec))).is_ok(),
                        "`{codec}` is recommended by {text:?} but method_for refuses it"
                    );
                }
            }
            // The specific regression: `lzma` may appear only where the text
            // says it is read-only, never as something to "pick".
            if let Some(at) = text.find("or pick") {
                assert!(
                    !text[at..].contains("lzma"),
                    "a suggestion list must not offer lzma, which is decode-only: {text:?}"
                );
            }
        }
    }

    /// The one place in the `Spool` where an offset becomes an allocation.
    /// `ZipWriter` never seeks past the end, so this is unreachable through
    /// the container — bounded anyway, for consistency with every other
    /// allocation in this module.
    #[test]
    fn the_spool_refuses_to_zero_fill_an_unbounded_hole() {
        let spool = Rc::new(RefCell::new(Spool::new(PlainSink::new(Box::new(
            SharedBuf::new(),
        )))));
        let mut handle = SpoolHandle(Rc::clone(&spool));
        handle.write_all(b"start").unwrap();

        // Just inside the cap still works: the hole is legitimate framing as
        // far as the window can tell.
        handle.seek(SeekFrom::Start(MAX_SPOOL_HOLE as u64)).unwrap();
        handle.write_all(b"x").unwrap();

        // Past it is refused rather than allocated.
        handle
            .seek(SeekFrom::Start(4 * 1024 * 1024 * 1024))
            .unwrap();
        let err = handle
            .write_all(b"x")
            .expect_err("a 4 GiB hole must be refused, not allocated");
        assert_eq!(err.kind(), ErrorKind::InvalidInput, "{err}");
        assert!(err.to_string().contains("zero-fill"), "{err}");
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
                PlainSink::new(Box::new(buf.clone())),
                &CreateOpts {
                    entry_codec: Some(FormatId::new("brotli")),
                    ..Default::default()
                },
            )
            .err()
            .expect("zip has no brotli method");
        assert!(matches!(err, Error::Unsupported(_)), "got {err:?}");
        assert_eq!(
            err.exit_code(),
            3,
            "zip cannot express brotli — a capability limit, exit 3: {err}"
        );
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
            // Exit 3, "this build cannot do that" — the same code
            // `FormatNotEnabled` carries. It was 1 until the fix round for
            // this task: a refusal that tells the user exactly what to
            // rebuild with should not share an exit code with an internal
            // failure they can do nothing about.
            assert_eq!(
                err.exit_code(),
                3,
                "{rung}: a capability gap is exit 3, not a generic failure: {err}"
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
                PlainSink::new(Box::new(buf)),
                &CreateOpts {
                    entry_codec: Some(FormatId::new("zstd")),
                    ..Default::default()
                },
            )
            .err()
            .expect("the pure tier has no zstd zip method");
        assert!(matches!(err, Error::Unsupported(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 3, "a capability gap is exit 3: {err}");
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
            .create(
                PlainSink::new(Box::new(buf.clone())),
                &CreateOpts::default(),
            )
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
        w.finish().unwrap().finish().unwrap();
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
    /// costs nothing, rather than zip's own `Unsupported` (exit 3) raised
    /// from inside `add` with the destination already open. Exit 3 would not
    /// be WRONG about the archive, but it is wrong about whose mistake it
    /// was: an out-of-range level is the caller's, and every codec in this
    /// tree answers it with exit 2.
    #[test]
    fn a_level_the_entry_codec_does_not_have_is_refused_before_anything_is_written() {
        let buf = SharedBuf::new();
        let err = Zip
            .create(
                PlainSink::new(Box::new(buf.clone())),
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
        let mut w = Zip
            .create(PlainSink::new(Box::new(buf)), &CreateOpts::default())
            .unwrap();
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
        let spool = Rc::new(RefCell::new(Spool::new(PlainSink::new(Box::new(
            SharedBuf::new(),
        )))));
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
