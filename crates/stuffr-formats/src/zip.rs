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
//!   zip). From a pipe, then, a symlink entry becomes a regular file holding
//!   its target text, streamed and never buffered, so the 64 KiB
//!   symlink-target cap (exit 6) applies to seekable reads only; the
//!   `zip_on_a_pipe` suite pins that asymmetry. Until the walk reaches the
//!   central directory, that is reported as
//!   [`Fidelity::TrailingIndexUnread`] plus [`Fidelity::EntryCountUnknown`],
//!   the vocabulary Phase 0 defined for exactly this, seeded by
//!   `ladder::seed_report` and re-asserted here so the report is complete
//!   however it was constructed.
//!
//! The rung describes the ACCESS PATH and the warnings describe the LOSS —
//! `--strict-fidelity` gates on the warnings (see
//! `FidelityReport::has_warnings`). Since ruling B2 the forward reader reads
//! the central directory at the end of the pipe and compares it with the
//! local headers it walked (see "The forward reader reads and compares the
//! index" below). When the index is read whole and agrees, both warnings are
//! withdrawn and a well-formed piped zip passes strict mode (it failed in
//! 0.22.0); when it is cut off, absent, past the bound, contradicted by its
//! end record, or holds a symlink the forward read delivered as a file, both
//! stay.
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
//! archive two of whose entries no caller can reach. So `read_declared_index`
//! parses the end-of-central-directory record directly — the crate exposes no
//! accessor for the count, `mod spec` being private and
//! `CentralDirectoryInfo::number_of_files` `pub(crate)` — and
//! `note_unreachable_records` raises [`Fidelity::EntryCountMismatch`] naming
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
//! `verify_end_of_archive` exists for, and `verify_trailing_index` closes
//! it the same way: after `Ok(None)`, walk the central directory's own framing
//! forward — fixed block, name, extra, comment, repeat — through the optional
//! zip64 records and require a whole end-of-central-directory record to be
//! present.
//!
//! Forward parsing rather than the backward EOCD SEARCH a seekable reader
//! does, for two reasons: a pipe cannot seek, and a forward walk is
//! unambiguous where the search is not (a `PK\x05\x06` inside a file comment
//! is exactly the case that makes the backward search heuristic). Nothing is
//! sized by a declared length: comments and unneeded extra fields are skipped
//! through a fixed buffer, and a name or extra field read is a 16-bit length.
//!
//! Whatever follows the EOCD record is ignored, as every zip tool ignores it.
//!
//! # The forward reader reads and compares the index (ruling B2)
//!
//! A pipe can show one archive under names or contents its central directory
//! does not (the "cloaking" of GHSA-m665-v7pm-7grj). So the walk records each
//! local header's raw claim on ruling B3's fields (`peek_local_claim`, which
//! parses the header and replays it for zip), reads each central record's
//! raw name and fields as `verify_trailing_index` passes it, and compares the
//! two at the end record (`compare_walk`): the same fields as the seekable
//! path (`disagreeing_fields`), plus records present on one side only
//! (`"entry count"`) and order (`"order"`): one
//! [`Fidelity::HeadersDisagree`] per entry, naming every field, for the
//! first 64 entries, then one [`Fidelity::HeadersDisagreeUnlisted`]
//! counting the rest (`DisagreementLog`). The bytes delivered stay the local
//! headers'; only the warnings are new.
//!
//! B3's "the descriptor, if read, is compared instead" is not implemented
//! because it is vacuous today: zip 9 refuses a bit-3 entry on a pipe, and
//! the seekable path never reads a data descriptor.
//!
//! What is held is bounded: `MAX_INDEX_CHECK_BYTES` of claims (names plus a
//! fixed charge per record). Past it the comparison is given up, its memory
//! freed, and the two index warnings stay, as for any index that was not
//! read.
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
//! to hold bytes back. `Spool` holds back exactly ONE entry: it presents a
//! `Write + Seek` face to `ZipWriter` over an in-memory window, and
//! `ZipWrite::add` commits everything below the new entry's header offset to
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
//! `ZipWrite::finish` takes the writer out of its `Option` and calls
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
//! method that is missing. Encrypted entries and the reduce methods (2-5)
//! are refused the same way, for the same reason.
//!
//! **Shrink (1) and implode (6)** are read, on a seekable source, through
//! `crate::infozip` (`zip` has no decoder for them): the entry is read raw,
//! decoded whole in memory (declared sizes capped at
//! `MAX_LEGACY_ENTRY_BYTES`, exit 6), and its CRC-32 checked; a decode
//! failure or a CRC mismatch is `Error::Corrupt` (exit 5). On a forward-only
//! pipe they stay refused, and salvage does not decode them. A directory
//! entry is never decoded: it lists with its declared size, and a size it
//! does not deliver is exit 5 on read, as for every other method. **A shrink or
//! implode entry whose mode says symlink is read as a regular file holding
//! its target as contents**, as every entry is from a pipe: the legacy path
//! never upgrades the kind, and no fidelity note names it (`FidelityReport`
//! has no downgrade vocabulary for one entry). `unpack` therefore writes a
//! file, never a link; `a_legacy_symlink_entry_reads_as_a_regular_file`
//! pins it.
//!
//! # zip 9: extraction audit and header consistency
//!
//! RUSTSEC-2026-0367/0368/0369 live in zip's own `extract*`, which nothing in
//! this workspace calls (audited at the zip 9 bump). The crate supplies entry
//! metadata, payload readers and `ZipWriter` only. `stuffr unpack` and
//! `salvage` write through `stuffr::entries` (`safe_join`, symlinked-ancestor
//! refusal, `place_entry`), restoring at most `0o777` through the open
//! handle; `convert`/`pack` write one archive file; the `unzip` and `zip`
//! compatibility links are Info-ZIP ports that never touch this crate
//! (`unzip` writes beneath `compat/unzip/unix/beneath.rs`).
//!
//! zip 9's `enforce_header_consistency` is deliberately left OFF: it fails
//! the read outright where a local header disagrees with its central record,
//! and that disagreement (the GHSA-m665-v7pm-7grj "cloaking" split between
//! this module's two readers) is to be reported, not refused.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
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

use crate::normalize::{
    NormalizeDecodeErrors, ZIP_MALFORMED_AS_INVALID_INPUT_OTHER_UNSUPPORTED_EOF,
};

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
///
/// A derivative registered on these magics later (jar, apk, …) registers
/// this module's `confirm` too: same bytes, same check. Without one it
/// would count as confirmed and could win wherever zip's own check fails.
pub fn meta() -> FormatMeta {
    FormatMeta::container(ZIP, &["zip"], ZIP_MAGIC).with_confirm(confirm)
}

/// The record behind `PK`. A local file header (`PK\x03\x04`): the version
/// needed is at most 6.3 (APPNOTE's latest; the field's upper byte is a host
/// system, "mapped as" version made by, APPNOTE 4.4.3), the method is one
/// APPNOTE 4.4.5 defines, and the name is at least one byte and fits the
/// probe window. Sizes are not checked: a streamed entry records zeros and
/// a zip64 one `0xFFFFFFFF`. An end-of-central-directory record
/// (`PK\x05\x06`) at offset 0 is an empty zip, so it must be whole and
/// list no entries and no directory bytes.
fn confirm(prefix: &[u8], whole: bool) -> bool {
    let u16_at = |i: usize| {
        prefix
            .get(i..i + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    if prefix.starts_with(&SIG_END_OF_CENTRAL_DIR) {
        let fixed = 4 + END_OF_CENTRAL_DIR_FIXED;
        return prefix.len() >= fixed
            && u16_at(8) == Some(0)
            && u16_at(10) == Some(0)
            && prefix[12..16] == [0; 4];
    }
    if whole && u16_at(26).is_none_or(|n| prefix.len() < 30 + usize::from(n)) {
        // A whole stream must hold the local header and the name it gives.
        return false;
    }
    prefix.get(4).is_none_or(|&version| version <= 63)
        && u16_at(8).is_none_or(defined_method)
        && u16_at(26).is_none_or(|n| n >= 1 && 30 + usize::from(n) <= stuffr_core::PROBE_LEN)
}

/// APPNOTE 4.4.5's methods: 0-10 (stored through the reserved 7 and
/// Deflate64), 12 bzip2, 14 LZMA, 16 IBM z/OS CMPSC, 18 IBM TERSE, 19 LZ77,
/// 20 the deprecated zstd number, 93-99 (zstd, MP3, xz, JPEG, WavPack,
/// PPMd, AE-x). 11, 13, 15 and 17 are reserved.
fn defined_method(method: u16) -> bool {
    matches!(method, 0..=10 | 12 | 14 | 16 | 18..=20 | 93..=99)
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

/// The mode zip stores for a DIRECTORY entry when the caller declares none:
/// `0o755`, traversable, as `tar.rs` and `cpio.rs` default theirs.
/// `DEFAULT_FILE_MODE` has no owner-execute bit, and a directory extracted
/// with it cannot be entered.
const DEFAULT_DIR_MODE: u32 = 0o755;

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
            // `crate::zip_salvage` scans it; `stuffr::entries::salvage_scanner`
            // dispatches to it, and a test there pins this flag to that arm.
            // `zip` 8.6.0's writer refuses `Duplicate filename`.
            unique_names: true,
            // The name is a length-prefixed field: a NUL round-trips — measured.
            nul_in_names: true,
            // The target is the entry's body, stored by length: a NUL
            // round-trips (measured).
            nul_in_link_targets: true,
            // No owner field outside the Info-ZIP extra fields, which the
            // writer does not emit (and the reader reports `uid: None`).
            stores_ownership: false,
            // No link concept in the format.
            stores_hardlinks: false,
            salvage: true,
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
            let mut adapter = SeekAdapter::new(source);
            let handle = adapter.clone();
            let declared = read_declared_index(&mut adapter);
            // Read while the source is still reachable, for the same reason
            // `read_declared_index` is: nothing gets the bytes back out from
            // under a `ZipArchive`.
            let opens_with_an_entry = begins_with_a_local_header(&mut adapter);
            // For the local-header comparison's work budget; an unknown
            // length leaves it at its floor.
            let archive_len = adapter.seek(SeekFrom::End(0)).unwrap_or(0);
            let archive = zip::ZipArchive::new(adapter)
                .map_err(|e| name_a_self_contradicting_index(classify_zip_error(e), &declared))?;
            refuse_an_index_that_reaches_nothing(&archive, opens_with_an_entry)?;
            let mut report = report;
            note_unreachable_records(&mut report, &archive, declared);
            return Ok(Box::new(ZipIndexed {
                archive,
                handle,
                report,
                next: 0,
                compared: HashSet::new(),
                claims: LocalClaims::new(archive_len),
                disagreements: DisagreementLog::default(),
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
            index: IndexCheck::default(),
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
///   reduce entry (methods 2-5), a zstd entry on the pure tier, or a
///   data-descriptor entry met on a pipe. Reporting exit 5 there would tell
///   the user their file is damaged when it is not.
/// * A genuine source failure (`ZipError::Io` carrying `PermissionDenied`,
///   say) passes through as itself — conformance property 10.
///
/// `UnexpectedEof` is the exception within `Io`: `zip`'s header parsing uses
/// `read_exact`, so a stream that runs out mid-structure surfaces as an I/O
/// error even though it is really a cut archive. That kind is folded onto
/// [`Error::Corrupt`] (exit 5), which is what conformance property 9
/// requires and what `Error::from_decode_io` would otherwise leave at exit 1.
/// `Other`, `InvalidInput` and `Unsupported` are folded the same way since
/// zip 9, for the header sites the payload constant's doc lists — but only
/// when the error carries no OS error code: an `EINVAL` from the source is
/// a real I/O failure and stays [`Error::Io`].
fn classify_zip_error(e: ZipError) -> Error {
    match e {
        ZipError::Io(io_err) => {
            if io_err.kind() == ErrorKind::UnexpectedEof {
                return Error::Corrupt(format!("zip stream ended mid-structure: {io_err}"));
            }
            // zip 9.1.3's header parsing raises `Other` and `InvalidInput`
            // for malformed fields too — an extended-timestamp extra field
            // whose length disagrees with its flags, a local header whose
            // data range overflows `u64` — and both reached exit 1 through
            // `from_decode_io` (the first in 8.6 as well). The list and why
            // folding them is safe: `normalize::
            // ZIP_MALFORMED_AS_INVALID_INPUT_OTHER_UNSUPPORTED_EOF`.
            // Only an error zip made itself: one carrying an OS error code
            // is the source failing, and stays `Error::Io`.
            if io_err.raw_os_error().is_none()
                && ZIP_MALFORMED_AS_INVALID_INPUT_OTHER_UNSUPPORTED_EOF.contains(&io_err.kind())
            {
                return Error::Corrupt(io_err.to_string());
            }
            Error::from_decode_io(io_err)
        }
        ZipError::InvalidArchive(msg) => Error::Corrupt(msg.into_owned()),
        ZipError::UnsupportedArchive(msg) => Error::Unsupported(format!(
            "this build cannot read that zip: {msg}{}",
            unsupported_hint(msg)
        )),
        ZipError::CompressionMethodNotSupported(id @ (1 | 6)) => Error::Unsupported(format!(
            "zip entry uses compression method {id} ({}), which stuffr reads only from a \
             seekable source: read the archive from a file rather than a pipe, or use \
             `stuffr convert`, which spools it",
            method_name(id)
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
///
/// The source is shared (`Clone` is another handle on the SAME source), so
/// [`ZipIndexed`] can keep one after the archive owns the other: `zip` exposes
/// no accessor for an entry's general-purpose flags, and explode needs bits 1-2
/// of them. A second handle's position moves the first's, which is harmless
/// only because of the borrow: `ZipIndexed` uses its handle (through an
/// entry's payload) under `&mut self`, so no `ZipFile` is alive then, and the
/// archive repositions itself on every `by_index*` before reading.
#[derive(Clone)]
struct SeekAdapter(Rc<RefCell<Box<dyn Source>>>);

impl SeekAdapter {
    fn new(source: Box<dyn Source>) -> Self {
        Self(Rc::new(RefCell::new(source)))
    }

    fn lock(&self) -> std::cell::RefMut<'_, Box<dyn Source>> {
        self.0.borrow_mut()
    }
}

impl Read for SeekAdapter {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.lock().read(buf)
    }
}

impl Seek for SeekAdapter {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let mut guard = self.lock();
        let seek: &mut dyn SeekRead = guard
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
    /// Records on this disk: the EOCD's field at offset 8 (zip64: 24).
    ///
    /// Carried because it is the figure `zip` actually LOOPS over for a plain
    /// EOCD (`CentralDirectoryInfo::try_from` reads
    /// `number_of_files_on_this_disk`; only a zip64 record has it read the
    /// total). When it disagrees with [`Self::entries`] the index contradicts
    /// itself, and the enumeration can then land on EITHER side of the
    /// declared total — see [`note_unreachable_records`]. zip 9 refuses
    /// such an EOCD outright, so the disagreement now reaches
    /// [`name_a_self_contradicting_index`] instead.
    entries_on_disk: u64,
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

    let entries_on_disk = le16(&tail[at + 8..]);
    let entries = le16(&tail[at + 10..]);
    let cd_offset = le32(&tail[at + 16..]);
    if entries != u16::MAX && cd_offset != u32::MAX {
        return Some(DeclaredIndex {
            entries: u64::from(entries),
            entries_on_disk: u64::from(entries_on_disk),
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
        entries_on_disk: le64(&fixed[24..]),
        cd_offset: le64(&fixed[48..]),
    })
}

/// Rewords zip 9's refusal of an end-of-central-directory record whose two
/// record counts disagree, so the message says what the archive contradicts.
///
/// zip 9 raises `InvalidArchive("Multi-disk ZIP files are not supported")`
/// in `find_central_directory` (`format/find_central_directory.rs:236-240`
/// for a plain EOCD, `:343-344` for zip64) both for a genuine multi-disk
/// EOCD and for one whose on-this-disk and total counts disagree. zip 8.6
/// opened the second (it looped over the on-this-disk count) and
/// [`note_unreachable_records`] warned: exit 0, 4 under `--strict-fidelity`.
/// zip 9's refusal is kept — exit 5 is `error.rs`'s rule for bytes that
/// contradict themselves — and only reworded to name both counts, since such
/// an archive is no multi-disk set. That is a behaviour change zip 9 forces:
/// undoing it would mean rewriting the EOCD under the crate.
///
/// Every other "Multi-disk" refusal keeps the crate's wording and exit 5.
/// zip 8.6 answered exit 3 (`UnsupportedArchive`) for an EOCD naming a
/// non-zero disk with agreeing counts, but exit 5 for the last segment of a
/// real split set (`stuffr-cli/tests/data/zip/split.zip`, "Invalid local
/// file header"), and fuzzer junk reaches the same check; mapping it to
/// exit 3 would call hostile bytes "a split archive", so it is not mapped.
fn name_a_self_contradicting_index(err: Error, declared: &Option<DeclaredIndex>) -> Error {
    match (&err, declared) {
        (Error::Corrupt(msg), Some(d))
            if msg.contains("Multi-disk") && d.entries != d.entries_on_disk =>
        {
            Error::Corrupt(format!(
                "zip: the end-of-central-directory record contradicts itself, declaring {} \
                 record(s) in the archive but {} on its only disk; `stuffr salvage` reads the \
                 records themselves",
                d.entries, d.entries_on_disk
            ))
        }
        _ => err,
    }
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
/// Both directions are reported. This used to report only a shortfall, on
/// the premise that `read_central_header` pushes exactly the declared number
/// of records so the collapsed map can never hold MORE names than were
/// declared. That premise was false: for a plain EOCD the crate loops over
/// the on-this-disk count (offset 8), not the total (offset 10) this compares
/// against, so an EOCD declaring 4 on this disk and 1 in total enumerated
/// four entries in silence — `test --strict-fidelity` said "exact fidelity"
/// at exit 0 (the v0.7.0 deep-fuzz `container` finding). Info-ZIP's
/// `zipinfo` reports the total ("number of entries: 1") for that file.
///
/// The reason names the cause it can actually see: when the EOCD's two
/// counts disagree — which a single-disk archive, the only kind `zip` opens,
/// must never do — that self-contradiction is the cause, whichever side of
/// the total the enumeration landed on, ON it included (names collapsing
/// can bring an on-disk walk down to exactly the total, so equality proves
/// nothing there); otherwise a shortfall is names
/// collapsing in the crate's map. An excess with agreeing counts is not
/// believed reachable (only a zip64 record whose total disagrees with an
/// unsaturated plain EOCD could produce one) and is still reported rather
/// than trusted.
///
/// **Since zip 9 the self-contradiction arm is not reached through
/// `ZipArchive::new`**: the crate refuses an EOCD whose two counts disagree
/// before this runs (see [`name_a_self_contradicting_index`]). The arm is
/// kept, not deleted, so a later zip that relaxes that check is warned about
/// rather than trusted.
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
    // The self-contradiction is checked BEFORE the equality return (the
    // Salvage Stage 3 final review's zip M1): `zip` walks the on-disk count
    // and collapses repeated names, so an EOCD saying 8 on disk and 6 in
    // total over eight records under six names enumerates exactly 6 — equal
    // to the total, and still two records short of what the archive holds.
    let contradicts_itself = declared.entries_on_disk != declared.entries;
    if enumerated == declared.entries && !contradicts_itself {
        return;
    }
    let reason = if contradicts_itself {
        format!(
            "the end-of-central-directory record contradicts itself, declaring {} record(s) \
             in the archive but {} on its only disk",
            declared.entries, declared.entries_on_disk
        )
    } else if let Some(shadowed) = declared.entries.checked_sub(enumerated) {
        format!(
            "{shadowed} record(s) repeat a name already in the index and are shadowed by \
             it; only the last record under each name can be read"
        )
    } else {
        "the reader enumerated more records than the end-of-central-directory record \
         declares"
            .to_string()
    };
    report.warn(Fidelity::EntryCountMismatch {
        format: ZIP,
        declared: declared.entries,
        enumerated,
        reason,
    });
}

/// One central-directory file header, physically enumerated.
///
/// Unlike `zip::ZipArchive`'s own view (an `IndexMap` keyed by name — see
/// `DeclaredIndex`'s doc for why that collapses two records sharing a name
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
    /// The unix mode the record carries in the high half of its external
    /// attributes, when its "version made by" names a unix host (3, or 19
    /// for OS X) and that half is not zero — what `zip`'s `unix_mode()`
    /// answers for the same record. `None` otherwise (a DOS-made archive).
    /// Salvage gives a recovered file this mode, masked by the umask.
    pub unix_mode: Option<u32>,
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
/// `None` only when the walk cannot even begin: `read_declared_index`
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
    let external_attributes = le32(&fixed[34..]);
    let local_header_offset = le32(&fixed[38..]);
    // `fixed` starts after the signature: byte 1 is "version made by"'s
    // host system (APPNOTE 4.4.2).
    let unix_mode = (matches!(fixed[1], 3 | 19) && external_attributes >> 16 != 0)
        .then_some(external_attributes >> 16);

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
        unix_mode,
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
///
/// **This fixture pins the IDENTICAL-duplicate case only, and that is now
/// stated rather than left to be discovered.** The two extras are
/// byte-for-byte copies, which is the shape the motivating real-world
/// archive actually had — but it is only one of the two shapes a repeated
/// name comes in, and under it a whole class of defect is invisible:
/// marking a duplicate costs nothing to get right, and overwriting one on
/// disk costs nothing at all, because the bytes agree. The final
/// whole-branch review found three separate findings hiding behind exactly
/// that. [`build_distinct_duplicate_zip`] is the other half — same eight
/// records under the same six names, with the duplicates carrying DIFFERENT
/// content — and both are kept, because both are real.
#[cfg(test)]
pub(crate) fn build_shadowing_zip() -> Vec<u8> {
    build_duplicating_zip(DuplicateContent::Identical)
}

/// The realistic counterpart to [`build_shadowing_zip`]: the same eight
/// central-directory records under the same six names, except each
/// duplicate's payload is a DIFFERENT string of the same length, with its
/// CRC-32 recomputed in both the local header and the central-directory
/// record so every record still verifies as `Intact`.
///
/// Same length on purpose: every size field in both headers stays valid, so
/// the ONLY thing separating this fixture from [`build_shadowing_zip`] is
/// the payload bytes and the checksum over them. That is what makes it a
/// controlled comparison rather than a second, differently-shaped archive —
/// anything that behaves differently between the two does so because the
/// duplicate's CONTENT differs, and for no other reason.
///
/// This is the shape `stuffr list`'s own `EntryCountMismatch` fidelity
/// warning fires on (a repeated NAME, whatever the bytes under it), and the
/// shape where recovering a record and then overwriting it with a later
/// record's bytes actually loses data.
#[cfg(test)]
pub(crate) fn build_distinct_duplicate_zip() -> Vec<u8> {
    build_duplicating_zip(DuplicateContent::Distinct)
}

/// Which of the two duplicate shapes [`build_duplicating_zip`] assembles.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DuplicateContent {
    /// A byte-for-byte copy of the record it duplicates.
    Identical,
    /// The same name and the same length, different bytes, checksum
    /// recomputed so the record is still `Intact`.
    Distinct,
}

/// CRC-32/ISO-HDLC, the checksum a zip local/central header's `crc32` field
/// carries over an entry's UNCOMPRESSED bytes.
///
/// `#[cfg(test)]` and used only by [`build_duplicating_zip`], which has to
/// recompute one after rewriting a duplicated record's payload. Not taken
/// from `crc32fast` for the reason `zip_salvage.rs`'s own copy records: a
/// dependency for one twelve-line routine buys no capability. Pinned
/// against the algorithm's published check value by
/// `the_fixture_builders_crc_matches_the_published_check_value` below, so a
/// transcription error cannot hide behind this project's own expectations.
#[cfg(test)]
fn fixture_crc32(data: &[u8]) -> u32 {
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

#[cfg(test)]
fn build_duplicating_zip(duplicate_content: DuplicateContent) -> Vec<u8> {
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
    // copy of each shadowed entry's local header and payload at a NEW
    // offset, then the central directory — the 6 original records followed
    // by 2 duplicates whose only changed bytes are the patched
    // local-header-offset field (plus, under `DuplicateContent::Distinct`,
    // the payload and the two copies of its CRC-32) — then a patched EOCD
    // declaring 8.
    let mut out = Vec::new();
    out.extend_from_slice(&base[..cd_start]);

    let dup2_lho = out.len() as u32;
    out.extend_from_slice(&base[rec2_lho..rec2_lho + rec2_local_len]);
    let dup3_lho = out.len() as u32;
    out.extend_from_slice(&base[rec3_lho..rec3_lho + rec3_local_len]);

    // Under `Distinct`, overwrite each duplicate's payload IN PLACE with a
    // same-length, different string and recompute its checksum. Same length
    // is what keeps every size field in both headers valid, so the payload
    // bytes and the CRC are the only difference between the two fixtures.
    // `DIFFERENT_*` are byte-length-matched to the originals by the
    // assertion right below, not by eye.
    let dup_crcs: Option<(u32, u32)> = match duplicate_content {
        DuplicateContent::Identical => None,
        DuplicateContent::Distinct => {
            const DIFFERENT_A: &[u8] = b"DIFFERENT bytes under the first duplicated name!!!";
            const DIFFERENT_B: &[u8] = b"DIFFERENT bytes under the second duplicated name!!!";
            let mut crcs = Vec::new();
            for (lho, replacement) in [
                (dup2_lho as usize, DIFFERENT_A),
                (dup3_lho as usize, DIFFERENT_B),
            ] {
                let name_len = le16(&out[lho + 26..]) as usize;
                let extra_len = le16(&out[lho + 28..]) as usize;
                let payload_at = lho + 30 + name_len + extra_len;
                let payload_len = le32(&out[lho + 18..]) as usize;
                assert_eq!(
                    payload_len,
                    replacement.len(),
                    "a distinct duplicate's replacement payload must be the SAME length as \
                     the record it replaces, or every size field in both headers stops \
                     agreeing with the bytes"
                );
                out[payload_at..payload_at + payload_len].copy_from_slice(replacement);
                let crc = fixture_crc32(replacement);
                out[lho + 14..lho + 18].copy_from_slice(&crc.to_le_bytes());
                crcs.push(crc);
            }
            Some((crcs[0], crcs[1]))
        }
    };

    let new_cd_start = out.len() as u32;
    out.extend_from_slice(&base[cd_start..eocd_start]);
    let dup2_cd_at = out.len();
    out.extend_from_slice(&base[rec2_at..rec2_at + rec2_len]);
    out[dup2_cd_at + 42..dup2_cd_at + 46].copy_from_slice(&dup2_lho.to_le_bytes());
    let dup3_cd_at = out.len();
    out.extend_from_slice(&base[rec3_at..rec3_at + rec3_len]);
    out[dup3_cd_at + 42..dup3_cd_at + 46].copy_from_slice(&dup3_lho.to_le_bytes());

    // The central-directory record carries its OWN copy of the checksum
    // (offset 16 in a central header, against 14 in a local one), so a
    // distinct duplicate has to patch both or the two indexes disagree
    // about the same record — which would make the fixture itself the
    // damage, rather than the duplicate name it exists to model.
    if let Some((crc_a, crc_b)) = dup_crcs {
        out[dup2_cd_at + 16..dup2_cd_at + 20].copy_from_slice(&crc_a.to_le_bytes());
        out[dup3_cd_at + 16..dup3_cd_at + 20].copy_from_slice(&crc_b.to_le_bytes());
    }

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
    /// A second handle on the archive's source, for the local-header flags.
    handle: SeekAdapter,
    report: FidelityReport,
    /// Cursor for `next_entry`. `by_index` does not disturb it — the two are
    /// independent views of the same index, which is the point of having one.
    next: usize,
    /// Entries whose local header has been compared with their central
    /// record, so an entry opened twice warns once.
    compared: HashSet<usize>,
    /// The local-header reads behind those comparisons, memoised and bounded
    /// ([`LocalClaims`]).
    claims: LocalClaims,
    /// The disagreements reported so far, capped ([`DisagreementLog`]).
    disagreements: DisagreementLog,
}

/// Entries an archive names in [`Fidelity::HeadersDisagree`] before the rest
/// are only counted ([`Fidelity::HeadersDisagreeUnlisted`]); `SightingLog`'s
/// figure in salvage.
const MAX_LISTED_DISAGREEMENTS: u64 = 64;

/// One archive's header disagreements (finding PARSE-5): one warning per
/// entry listing every field, the first [`MAX_LISTED_DISAGREEMENTS`] entries
/// by name, the rest counted in one warning kept up to date in place. Each
/// listed warning copies its entry's name, so without the cap an index of
/// 100,000 cloaked records made a report as large as itself.
#[derive(Default)]
struct DisagreementLog {
    listed: u64,
    unlisted: u64,
    /// Where `report` holds the [`Fidelity::HeadersDisagreeUnlisted`]
    /// warning once there is one.
    unlisted_at: Option<usize>,
}

impl DisagreementLog {
    fn warn(&mut self, report: &mut FidelityReport, entry: String, fields: Vec<&'static str>) {
        if fields.is_empty() {
            return;
        }
        if self.listed < MAX_LISTED_DISAGREEMENTS {
            self.listed += 1;
            report.warn(Fidelity::HeadersDisagree {
                format: ZIP,
                entry,
                fields,
            });
            return;
        }
        self.unlisted += 1;
        let entries = self.unlisted;
        if let Some(at) = self.unlisted_at
            && let Some(Fidelity::HeadersDisagreeUnlisted { entries: n, .. }) =
                report.warnings.get_mut(at)
        {
            *n = entries;
            return;
        }
        self.unlisted_at = Some(report.warnings.len());
        report.warn(Fidelity::HeadersDisagreeUnlisted {
            format: ZIP,
            entries,
        });
    }
}

/// Bytes of parsed local headers [`LocalClaims`] remembers at once.
const LOCAL_CLAIM_MEMO_BYTES: usize = 1024 * 1024;

/// Local-header bytes [`LocalClaims`] reads beyond twice the archive's length
/// before it stops comparing ([`Fidelity::LocalHeadersUnchecked`]).
const LOCAL_CLAIM_BUDGET_FLOOR: u64 = 64 * 1024 * 1024;

/// Accounting for each [`HeaderClaim`] held in the memo, on top of its two
/// names.
const LOCAL_CLAIM_OVERHEAD: usize = 96;

/// The seekable rung's local-header reads (finding PARSE-4).
///
/// Every central record's local header is read and parsed to compare it
/// (ruling B3): up to 30 + 65,535 + 65,535 bytes. An index of many records
/// pointing at ONE fat local header made each record pay that again — 100,000
/// records at one header took 7.3 s to `list`. Two bounds, each covering what
/// the other cannot:
///
/// - **A memo keyed by `header_start`**, so a header is read once however
///   many records point at it. Bounded in bytes ([`LOCAL_CLAIM_MEMO_BYTES`]);
///   an insert that does not fit clears it first, so the memo is always
///   about the most recent headers, the ones a fan-out keeps returning to.
///   A well-formed archive points each record at its own header, so its
///   memo never hits; that costs one map insert per entry.
/// - **A read budget**: twice the archive's length plus
///   [`LOCAL_CLAIM_BUDGET_FLOOR`]. The memo alone is defeated by cycling over
///   more fat headers than it holds — and those headers can overlap, a new
///   `PK\x03\x04` every few bytes inside one another's names, so a small file
///   holds thousands of them. A well-formed archive reads each local header
///   once, never more than its own length; past the budget, the remaining
///   entries are not compared and [`Fidelity::LocalHeadersUnchecked`] counts
///   them.
///
/// Reading the extra field lazily was considered and not done: it is needed
/// in the ordinary case (equal names — the Unicode Path field decides the
/// name each record delivers, ruling T5-d), so it would not bound the cost.
struct LocalClaims {
    memo: HashMap<u64, Option<HeaderClaim>>,
    held: usize,
    /// Local-header bytes still allowed to be read.
    budget: u64,
    /// Entries left uncompared since the budget ran out.
    unchecked: u64,
    /// Where `report` holds the [`Fidelity::LocalHeadersUnchecked`] warning
    /// once there is one, to count it up in place.
    unchecked_at: Option<usize>,
}

impl LocalClaims {
    fn new(archive_len: u64) -> Self {
        Self {
            memo: HashMap::new(),
            held: 0,
            budget: archive_len
                .saturating_mul(2)
                .saturating_add(LOCAL_CLAIM_BUDGET_FLOOR),
            unchecked: 0,
            unchecked_at: None,
        }
    }

    /// The claim of the local header at `header_start`, from the memo or
    /// read through `handle`. `Err(())` once the budget is spent: the entry
    /// is counted as unchecked in `report`. `Ok(None)` when the header
    /// cannot be read (left to the entry's own open, as before).
    fn get<R: Read + Seek>(
        &mut self,
        handle: &mut R,
        header_start: u64,
        report: &mut FidelityReport,
    ) -> std::result::Result<Option<&HeaderClaim>, ()> {
        if !self.memo.contains_key(&header_start) {
            if self.budget == 0 {
                self.count_unchecked(report);
                return Err(());
            }
            let (claim, read) = read_local_claim(handle, header_start);
            self.budget = self.budget.saturating_sub(read);
            let cost = claim.as_ref().map_or(0, |c| {
                c.name.len() + c.shown.as_ref().map_or(0, String::len)
            }) + LOCAL_CLAIM_OVERHEAD;
            if self.held + cost > LOCAL_CLAIM_MEMO_BYTES {
                self.memo.clear();
                self.held = 0;
            }
            self.held += cost;
            self.memo.insert(header_start, claim);
        }
        Ok(self.memo.get(&header_start).and_then(Option::as_ref))
    }

    fn count_unchecked(&mut self, report: &mut FidelityReport) {
        self.unchecked += 1;
        let entries = self.unchecked;
        if let Some(at) = self.unchecked_at
            && let Some(Fidelity::LocalHeadersUnchecked { entries: n, .. }) =
                report.warnings.get_mut(at)
        {
            *n = entries;
            return;
        }
        self.unchecked_at = Some(report.warnings.len());
        report.warn(Fidelity::LocalHeadersUnchecked {
            format: ZIP,
            entries,
        });
    }
}

#[cfg(test)]
thread_local! {
    /// Local-header bytes [`read_local_claim`] read on this thread: the
    /// PARSE-4 tests count work, not time.
    static LOCAL_CLAIM_BYTES_READ: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

impl ZipIndexed {
    fn entry_at(&mut self, index: usize) -> Result<Entry<'_>> {
        self.compare_local_header(index);
        // Shrink and implode: `zip` has no decoder for either on this build,
        // so the entry is read raw and decoded by `infozip`.
        if let Some(method) = self.legacy_method_at(index)? {
            return self.legacy_entry_at(index, method);
        }
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
                ZIP_MALFORMED_AS_INVALID_INPUT_OTHER_UNSUPPORTED_EOF,
            )),
        ))
    }
}

// ---------------------------------------------------------------------------
// Cloaking: a local header that disagrees with its central record
// ---------------------------------------------------------------------------

/// What one record — central or local — says about an entry, on the fields
/// ruling B3 compares. `None` for CRC-32 and sizes means "not stated here"
/// (bit 3 is set, or a zip64 field could not be resolved), never compared.
#[derive(Debug, PartialEq, Eq)]
struct HeaderClaim {
    name: Vec<u8>,
    /// The name a reader of this record alone delivers: the raw name with
    /// this record's own Info-ZIP Unicode Path field applied as zip 9 applies
    /// it ([`shown_name`]), ruling T5-d. `None` when it could not be read;
    /// then only the raw names are compared.
    shown: Option<String>,
    flags: u16,
    method: u16,
    crc: Option<u32>,
    csize: Option<u64>,
    usize_: Option<u64>,
}

/// General-purpose flag bit 0: the entry is encrypted.
const FLAG_ENCRYPTED: u16 = 0x0001;
/// General-purpose flag bit 3: CRC-32 and sizes follow the data.
const FLAG_DATA_DESCRIPTOR: u16 = 0x0008;
/// General-purpose flag bit 11: the name is UTF-8.
const FLAG_UTF8: u16 = 0x0800;
/// Compression method 99: WinZip AES. zip resolves the real method from the
/// AES extra field, whose metadata ruling B3 leaves uncompared.
const METHOD_AES: u16 = 99;

/// Reads the local header at `header_start` as far as rulings B3 and T5-d
/// need: the 30-byte fixed block, the name and the extra field (zip64 sizes,
/// and the Unicode Path field for [`HeaderClaim::shown`]). zip 9 reads the
/// same fixed block when it opens the entry (`find_content`) and does not
/// expose it, so this is an extra read (ruling T4-a): at most 30 + 65,535 +
/// 65,535 bytes at an offset about to be read anyway. The only other one is
/// [`read_central_name_and_flags`], for an entry with a Unicode Path field.
/// `None` on any failure: a header this cannot read is left to zip's own
/// path, which classifies it. Also returns how many bytes were read, for
/// [`LocalClaims`]' budget.
fn read_local_claim<R: Read + Seek>(r: &mut R, header_start: u64) -> (Option<HeaderClaim>, u64) {
    if r.seek(SeekFrom::Start(header_start)).is_err() {
        return (None, 0);
    }
    let mut counted = ClaimCounter { inner: r, read: 0 };
    let claim = parse_local_claim(&mut counted);
    let read = counted.read;
    #[cfg(test)]
    LOCAL_CLAIM_BYTES_READ.with(|n| n.set(n.get() + read));
    (claim, read)
}

/// Counts the bytes [`read_local_claim`] reads.
struct ClaimCounter<'a, R> {
    inner: &'a mut R,
    read: u64,
}

impl<R: Read> Read for ClaimCounter<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read += n as u64;
        Ok(n)
    }
}

/// [`read_local_claim`]'s parse, from wherever `r` stands: the signature, the
/// fixed block, the name and the extra field. The forward reader calls it on
/// the stream itself, through [`Recording`], and replays what it read. `None`
/// if the fixed block or the name cannot be read; an unreadable extra field
/// leaves `shown` and any zip64 size `None`.
fn parse_local_claim<R: Read>(r: &mut R) -> Option<HeaderClaim> {
    let mut fixed = [0u8; 30];
    r.read_exact(&mut fixed).ok()?;
    if fixed[..4] != SIG_LOCAL_HEADER {
        return None;
    }
    let flags = le16(&fixed[6..8]);
    let method = le16(&fixed[8..10]);
    let crc = le32(&fixed[14..18]);
    let csize32 = le32(&fixed[18..22]);
    let usize32 = le32(&fixed[22..26]);
    let name_len = usize::from(le16(&fixed[26..28]));
    let extra_len = usize::from(le16(&fixed[28..30]));
    let mut name = vec![0u8; name_len];
    r.read_exact(&mut name).ok()?;
    let mut extra = vec![0u8; extra_len];
    let extra = r.read_exact(&mut extra).ok().map(|()| extra);
    let shown = extra.as_deref().map(|x| shown_name(&name, flags, x));

    if flags & FLAG_DATA_DESCRIPTOR != 0 {
        return Some(HeaderClaim {
            name,
            shown,
            flags,
            method,
            crc: None,
            csize: None,
            usize_: None,
        });
    }
    let (mut csize, mut usize_) = (Some(u64::from(csize32)), Some(u64::from(usize32)));
    if csize32 == u32::MAX || usize32 == u32::MAX {
        let zip64 = extra.as_deref().and_then(zip64_block);
        let (u, c) = local_zip64_sizes(zip64, usize32, csize32);
        usize_ = u;
        csize = c;
    }
    Some(HeaderClaim {
        name,
        shown,
        flags,
        method,
        crc: Some(crc),
        csize,
        usize_,
    })
}

/// The name a reader delivers for one record: `raw` with the record's own
/// Info-ZIP Unicode Path field (0x7075) applied exactly as zip 9 applies it
/// (`ZipFileData::apply_extra_fields`, `extra_fields/extra_field.rs`): every
/// such field in order, each replacing the name when its CRC-32 matches the
/// RAW name and its content is UTF-8, so the last valid one wins. Otherwise
/// the raw name decoded by the language-encoding flag ([`entry_name`]).
/// Fields are walked as id, length, data; a field running past the end stops
/// the walk (zip 9 refuses such a header outright, so nothing it delivers is
/// at stake).
fn shown_name(raw: &[u8], flags: u16, extra: &[u8]) -> String {
    const UNICODE_PATH: u16 = 0x7075;
    let mut crc = None;
    let mut shown = None;
    let mut at = 0usize;
    while at + 4 <= extra.len() {
        let id = le16(&extra[at..at + 2]);
        let len = usize::from(le16(&extra[at + 2..at + 4]));
        let Some(data) = extra.get(at + 4..at + 4 + len) else {
            break;
        };
        if id == UNICODE_PATH && data.len() >= 5 {
            let raw_crc =
                *crc.get_or_insert_with(|| !crate::salvage_verify::crc32_ieee_update(!0, raw));
            if le32(&data[1..5]) == raw_crc
                && let Ok(name) = std::str::from_utf8(&data[5..])
            {
                shown = Some(name.to_owned());
            }
        }
        at += 4 + len;
    }
    shown.unwrap_or_else(|| entry_name(raw, flags))
}

/// The data of the first zip64 extended-information block (id 0x0001) in an
/// extra field, if it is whole.
fn zip64_block(extra: &[u8]) -> Option<&[u8]> {
    let mut at = 0usize;
    while at + 4 <= extra.len() {
        let id = le16(&extra[at..at + 2]);
        let len = usize::from(le16(&extra[at + 2..at + 4]));
        let data = extra.get(at + 4..at + 4 + len)?;
        if id == 0x0001 {
            return Some(data);
        }
        at += 4 + len;
    }
    None
}

/// A local header's sizes where a 32-bit field is `0xFFFFFFFF`. APPNOTE
/// 4.5.3 says the local zip64 block carries both sizes (uncompressed first);
/// a shorter block carries only the saturated ones, in that order. A size
/// this cannot resolve is `None`, never compared.
fn local_zip64_sizes(
    block: Option<&[u8]>,
    usize32: u32,
    csize32: u32,
) -> (Option<u64>, Option<u64>) {
    let plain = |v: u32| (v != u32::MAX).then_some(u64::from(v));
    let Some(block) = block else {
        return (plain(usize32), plain(csize32));
    };
    if block.len() >= 16 {
        return (Some(le64(&block[0..8])), Some(le64(&block[8..16])));
    }
    let mut fields = block
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| u64::from_le_bytes(*c));
    let usize_ = if usize32 == u32::MAX {
        fields.next()
    } else {
        Some(u64::from(usize32))
    };
    let csize = if csize32 == u32::MAX {
        fields.next()
    } else {
        Some(u64::from(csize32))
    };
    (usize_, csize)
}

/// The fields of ruling B3 on which `local` disagrees with `central`, in a
/// fixed order. Both claims hold their record's own raw bytes: the name and
/// flags are compared exactly.
///
/// CRC-32 and the sizes are compared only when neither record sets bit 3. A
/// bit 3 set on one side only is itself a disagreement ("data-descriptor
/// flag", ruling T4-b): otherwise one flipped bit would switch those checks
/// off unseen.
fn disagreeing_fields(central: &HeaderClaim, local: &HeaderClaim) -> Vec<&'static str> {
    let mut out = Vec::new();
    // Ruling T5-d: the raw names, and the names each record alone would be
    // delivered under. One "name" either way.
    let shown_differ = matches!((&central.shown, &local.shown), (Some(c), Some(l)) if c != l);
    if local.name != central.name || shown_differ {
        out.push("name");
    }
    if central.method != local.method && central.method != METHOD_AES && local.method != METHOD_AES
    {
        out.push("compression method");
    }
    let described = (central.flags | local.flags) & FLAG_DATA_DESCRIPTOR == 0;
    if described {
        let differs =
            |a: Option<u64>, b: Option<u64>| matches!((a, b), (Some(a), Some(b)) if a != b);
        if differs(central.crc.map(u64::from), local.crc.map(u64::from)) {
            out.push("CRC-32");
        }
        if differs(central.csize, local.csize) {
            out.push("compressed size");
        }
        if differs(central.usize_, local.usize_) {
            out.push("uncompressed size");
        }
    }
    let flags_differ = central.flags ^ local.flags;
    if flags_differ & FLAG_ENCRYPTED != 0 {
        out.push("encryption flag");
    }
    if flags_differ & FLAG_DATA_DESCRIPTOR != 0 {
        out.push("data-descriptor flag");
    }
    if flags_differ & FLAG_UTF8 != 0 {
        out.push("UTF-8 flag");
    }
    out
}

/// The flags and raw name of the central-directory record at `at`, read
/// from the record itself: 46 fixed bytes and the name. Needed only for an
/// entry carrying an Info-ZIP Unicode Path field (0x7075), because zip 9
/// replaces the name it keeps with that field's content (when the field's
/// CRC-32 matches the original name) and sets bit 11 on its copy, so its
/// view no longer holds the record's own name or flags. `None` on any
/// failure.
fn read_central_name_and_flags<R: Read + Seek>(r: &mut R, at: u64) -> Option<(u16, Vec<u8>)> {
    let mut fixed = [0u8; 4 + CENTRAL_HEADER_FIXED];
    r.seek(SeekFrom::Start(at)).ok()?;
    r.read_exact(&mut fixed).ok()?;
    if fixed[..4] != SIG_CENTRAL_HEADER {
        return None;
    }
    let flags = le16(&fixed[8..10]);
    let mut name = vec![0u8; usize::from(le16(&fixed[28..30]))];
    r.read_exact(&mut name).ok()?;
    Some((flags, name))
}

impl ZipIndexed {
    /// Compares entry `index`'s local header with its central record and
    /// warns once per entry, naming every field of ruling B3 they
    /// disagree on (`Fidelity::HeadersDisagree`). The bytes handed back stay
    /// the central directory's; this only reports. Anything that cannot be
    /// read here is left silently to the entry's own open, which classifies
    /// it.
    fn compare_local_header(&mut self, index: usize) {
        if !self.compared.insert(index) {
            return;
        }
        let (mut central, header_start, central_start, renamed) = {
            // `by_index_raw` decodes nothing and reads only the local fixed
            // block zip reads to open the entry anyway (cached after).
            let Ok(raw) = self.archive.by_index_raw(index) else {
                return;
            };
            #[allow(deprecated)] // the raw method id; zip offers no other spelling
            let method = raw.compression().to_u16();
            let central = HeaderClaim {
                name: raw.name_raw().to_vec(),
                // zip's view, its own Unicode Path applied: what this path
                // delivers (ruling T5-d).
                shown: Some(entry_name(raw.name_raw(), raw.flags().as_u16())),
                flags: raw.flags().as_u16(),
                method,
                crc: Some(raw.crc32()),
                csize: Some(raw.compressed_size()),
                usize_: Some(raw.size()),
            };
            let renamed = raw
                .extra_data_fields()
                .any(|f| matches!(f, zip::ExtraField::UnicodePath(_)));
            (
                central,
                raw.header_start(),
                raw.central_header_start(),
                renamed,
            )
        };
        // The warning names the entry as stuffr names it (zip's view, a valid
        // Unicode Path applied); the comparison uses the record's own bytes.
        let entry = entry_name(&central.name, central.flags);
        if renamed {
            let Some((flags, name)) = read_central_name_and_flags(&mut self.handle, central_start)
            else {
                return;
            };
            central.flags = flags;
            central.name = name;
        }
        let Ok(Some(local)) = self
            .claims
            .get(&mut self.handle, header_start, &mut self.report)
        else {
            return;
        };
        let fields = disagreeing_fields(&central, local);
        self.disagreements.warn(&mut self.report, entry, fields);
    }
}

/// Which of the two legacy methods this build decodes through `infozip`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LegacyMethod {
    Shrink,
    Implode,
}

impl LegacyMethod {
    fn name(self) -> &'static str {
        match self {
            LegacyMethod::Shrink => "shrink",
            LegacyMethod::Implode => "implode",
        }
    }
}

/// Ceiling on a shrink or implode entry, compressed and uncompressed alike.
/// Those decoders are callback-driven and cannot be pulled through `Read`, so
/// an entry is decoded whole into memory; this bounds that. Checked against
/// the DECLARED sizes before anything is allocated, so past it is
/// `Error::ResourceLimit` (exit 6), as with `MAX_SYMLINK_TARGET_LEN`.
///
/// Both buffers are then reserved exactly (`try_reserve_exact`) at their
/// declared sizes and never grow, so an entry holds at most its compressed
/// plus its uncompressed size, each under this ceiling; a refused
/// reservation is exit 6 too. A shrink stream of about 110 KB reaches
/// 256 MiB, so this is the whole bound on what one entry can cost.
const MAX_LEGACY_ENTRY_BYTES: u64 = 256 * 1024 * 1024;

impl ZipIndexed {
    /// `Some` when entry `index` is stored with method 1 or 6 and is not
    /// encrypted (an encrypted one keeps `zip`'s own refusal).
    fn legacy_method_at(&mut self, index: usize) -> Result<Option<LegacyMethod>> {
        let raw = match self.archive.by_index_raw(index) {
            Ok(raw) => raw,
            // Leave header trouble to the normal path's classification.
            Err(_) => return Ok(None),
        };
        if raw.encrypted() {
            return Ok(None);
        }
        Ok(if raw.compression() == CompressionMethod::SHRINK {
            Some(LegacyMethod::Shrink)
        } else if raw.compression() == CompressionMethod::IMPLODE {
            Some(LegacyMethod::Implode)
        } else {
            None
        })
    }

    /// The entry itself is cheap: sizes are checked against the ceiling and
    /// nothing is read. The raw read, the decode and the CRC-32 check run on
    /// the payload's first `read`, so a verb that only enumerates never pays
    /// for them (as with every other method).
    fn legacy_entry_at(&mut self, index: usize, method: LegacyMethod) -> Result<Entry<'_>> {
        let (meta, params) = {
            let raw = self
                .archive
                .by_index_raw(index)
                .map_err(classify_zip_error)?;
            let meta = entry_meta(&raw, raw.unix_mode());
            let Some(data_start) = raw.data_start() else {
                return Err(Error::Corrupt(format!(
                    "entry `{}`: zip did not locate its data",
                    meta.name
                )));
            };
            let params = LegacyParams {
                name: meta.name.clone(),
                method,
                header_start: raw.header_start(),
                data_start,
                crc: raw.crc32(),
                csize: raw.compressed_size(),
                usize_: raw.size(),
            };
            (meta, params)
        };
        // A directory has no payload to decode, but keeps its declared size
        // and the normal path's length check: a directory declaring bytes it
        // never delivers is refused on read (exit 5), as `entry_at`'s
        // `EntryPayload` refuses it for every other method. The stored
        // payload is read raw (never decoded), so a directory carrying bytes
        // it declares none of is refused too, as the stored path refuses it.
        if meta.kind == EntryKind::Dir {
            let raw = RawPayload {
                handle: self.handle.clone(),
                start: params.data_start,
                left: params.csize,
                seeked: false,
                name: params.name.clone(),
            };
            let payload = EntryPayload::new(raw, meta.size, &meta.name);
            return Ok(Entry::new(meta, Box::new(payload)));
        }
        for (what, n) in [
            ("compressed", params.csize),
            ("uncompressed", params.usize_),
        ] {
            if n > MAX_LEGACY_ENTRY_BYTES {
                return Err(Error::ResourceLimit(format!(
                    "entry `{}` declares {n} {what} bytes, past the \
                     {MAX_LEGACY_ENTRY_BYTES}-byte ceiling for a {} entry, which is \
                     decoded in memory",
                    params.name,
                    method.name()
                )));
            }
        }
        Ok(Entry::new(
            meta,
            Box::new(LegacyPayload {
                pending: Some((params, self.handle.clone())),
                data: io::Cursor::new(Vec::new()),
            }),
        ))
    }
}

/// The raw (undecoded) payload of a legacy-method entry: `csize` bytes from
/// `start`. It seeks on the first read, so listing stays cheap, and a payload
/// that ends before `csize` bytes is `InvalidData` (exit 5), never a short
/// success.
struct RawPayload {
    handle: SeekAdapter,
    start: u64,
    left: u64,
    seeked: bool,
    name: String,
}

impl Read for RawPayload {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.seeked {
            self.handle.seek(SeekFrom::Start(self.start))?;
            self.seeked = true;
        }
        if self.left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = usize::try_from(self.left).map_or(buf.len(), |l| l.min(buf.len()));
        let n = self.handle.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "entry `{}`: {} bytes short of the compressed size its header \
                     declares; the archive is truncated",
                    self.name, self.left
                ),
            ));
        }
        self.left -= n as u64;
        Ok(n)
    }
}

/// Everything a deferred shrink/implode decode needs.
struct LegacyParams {
    name: String,
    method: LegacyMethod,
    header_start: u64,
    data_start: u64,
    crc: u32,
    csize: u64,
    usize_: u64,
}

/// A shrink or implode entry's payload, decoded on the first `read`. Errors
/// are `io::Error`s of kind `InvalidData` for corruption (so
/// `Error::from_decode_io` gives exit 5) and the source's own otherwise.
struct LegacyPayload {
    pending: Option<(LegacyParams, SeekAdapter)>,
    data: io::Cursor<Vec<u8>>,
}

impl Read for LegacyPayload {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some((p, mut handle)) = self.pending.take() {
            self.data = io::Cursor::new(decode_legacy_entry(&p, &mut handle)?);
        }
        self.data.read(buf)
    }
}

fn decode_legacy_entry(p: &LegacyParams, handle: &mut SeekAdapter) -> io::Result<Vec<u8>> {
    let bad =
        |why: String| io::Error::new(ErrorKind::InvalidData, format!("entry `{}`: {why}", p.name));
    // Exact reservations at the declared sizes (each under
    // `MAX_LEGACY_ENTRY_BYTES`, checked when the entry was made): neither
    // buffer grows, so a doubling never reserves past the ceiling.
    let reserve = |n: u64, what: &str| -> io::Result<Vec<u8>> {
        let mut v = Vec::new();
        v.try_reserve_exact(n as usize).map_err(|_| {
            io::Error::new(
                ErrorKind::OutOfMemory,
                format!(
                    "entry `{}`: cannot allocate {n} bytes for its {what} {} data, \
                     which is decoded in memory",
                    p.name,
                    p.method.name()
                ),
            )
        })?;
        Ok(v)
    };
    let mut packed = reserve(p.csize, "compressed")?;
    handle.seek(SeekFrom::Start(p.data_start))?;
    handle.by_ref().take(p.csize).read_to_end(&mut packed)?;
    if packed.len() as u64 != p.csize {
        return Err(bad(format!(
            "{} bytes short of the compressed size its header declares; the archive is truncated",
            p.csize - packed.len() as u64
        )));
    }
    let flags = if p.method == LegacyMethod::Implode {
        local_header_flags(handle, p.header_start)?
    } else {
        0
    };
    let out = reserve(p.usize_, "uncompressed")?;
    let data = decode_legacy(p.method, flags, &packed, p.usize_, out).map_err(bad)?;
    drop(packed);
    let mut crc = flate2::Crc::new();
    crc.update(&data);
    if crc.sum() != p.crc {
        return Err(bad(format!(
            "CRC-32 mismatch after {} decompression (header {:08x}, data {:08x})",
            p.method.name(),
            p.crc,
            crc.sum()
        )));
    }
    Ok(data)
}

/// The general-purpose bit flag of the local header at `header_start`.
fn local_header_flags<R: Read + Seek>(r: &mut R, header_start: u64) -> io::Result<u16> {
    let mut fixed = [0u8; 30];
    r.seek(SeekFrom::Start(header_start))?;
    r.read_exact(&mut fixed)?;
    if fixed[..4] != SIG_LOCAL_HEADER {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "zip local file header signature missing",
        ));
    }
    Ok(le16(&fixed[6..8]))
}

/// Runs `infozip`'s decoder over `packed`, producing exactly `declared`
/// bytes into `out` (empty, reserved for `declared` bytes by the caller, so
/// it never reallocates). `Err` is a sentence for `Error::Corrupt`.
fn decode_legacy(
    method: LegacyMethod,
    flags: u16,
    packed: &[u8],
    declared: u64,
    mut out: Vec<u8>,
) -> std::result::Result<Vec<u8>, String> {
    use crate::infozip::{Stop, WSIZE, explode, unshrink};
    let mut window = vec![0u8; WSIZE];
    let mut src = packed.iter();
    let mut flush = |chunk: &[u8]| -> std::result::Result<(), ()> {
        if (out.len() + chunk.len()) as u64 > declared {
            return Err(());
        }
        out.extend_from_slice(chunk);
        Ok(())
    };
    let result = match method {
        LegacyMethod::Shrink => unshrink(&mut src, &mut window, &mut flush),
        LegacyMethod::Implode => explode(&mut src, flags, declared, &mut window, &mut flush),
    };
    match result {
        Ok(()) => {}
        Err(Stop::Code(c)) => {
            return Err(format!(
                "{} data is corrupt (Info-ZIP code {c})",
                method.name()
            ));
        }
        Err(Stop::Length { .. }) => {
            return Err(format!(
                "{} data does not end at the compressed size its header declares",
                method.name()
            ));
        }
        Err(Stop::Flush(())) => {
            return Err(format!(
                "{} data decodes to more bytes than the size its header declares",
                method.name()
            ));
        }
    }
    if out.len() as u64 != declared {
        return Err(format!(
            "{} data decodes to {} bytes but the header declares {declared}",
            method.name(),
            out.len()
        ));
    }
    Ok(out)
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
    /// Bytes read ahead and not yet handed on: a four-byte signature, or a
    /// whole local header [`peek_local_claim`] read to record it (at most
    /// 30 + 65,535 + 65,535 bytes, handed on before the next entry).
    held: Vec<u8>,
}

impl Pushback {
    /// Puts `bytes` back in front of anything already held, so they are
    /// read again first.
    fn push_back(&mut self, bytes: &[u8]) {
        self.held.splice(0..0, bytes.iter().copied());
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
    /// What the walk keeps to compare with the central directory when it
    /// reaches it.
    index: IndexCheck,
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
            verify_trailing_index(&mut self.source, signature, &mut self.index)?;
            self.conclude_index_check();
            return Ok(None);
        }
        self.source.push_back(&signature);
        // Read and replayed, so zip reads the same bytes after.
        let claim = peek_local_claim(&mut self.source);

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
        self.index.record_local(claim, &meta.name);
        let payload = EntryPayload::new(file, meta.size, &meta.name);
        Ok(Some(Entry::new(
            meta,
            Box::new(NormalizeDecodeErrors::new(
                payload,
                ZIP_MALFORMED_AS_INVALID_INPUT_OTHER_UNSUPPORTED_EOF,
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
fn verify_trailing_index(
    source: &mut Pushback,
    first: [u8; 4],
    check: &mut IndexCheck,
) -> Result<()> {
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
                let variable = u64::from(name) + u64::from(extra) + u64::from(comment);
                check.note_central_framing(&fixed, variable);
                let what = "central directory header fields";
                if check.can_hold(usize::from(name)) {
                    // The record's own name and extra field (zip64 sizes, and
                    // the Unicode Path field for the name it would be
                    // delivered under, ruling T5-d): each at most 65,535
                    // bytes, the extra field dropped once read. The comment
                    // is skipped as before.
                    let name = read_vec(source, usize::from(name), what)?;
                    let extra = read_vec(source, usize::from(extra), what)?;
                    skip(source, u64::from(comment), what)?;
                    check.record_central(central_claim(&fixed, name, &extra));
                } else {
                    skip(source, variable, what)?;
                }
            }
            SIG_ZIP64_END => {
                // Self-describing: an 8-byte size counting everything after
                // itself. Skipping by it rather than by a fixed width is what
                // makes this tolerant of the zip64 extensible data sector.
                let size =
                    u64::from_le_bytes(read_fixed::<8>(source, "zip64 end of central directory")?);
                // The fixed part (44 bytes) carries the declared record count
                // and directory size; read when whole, the rest skipped.
                let mut rest = size;
                if size >= ZIP64_END_FIXED as u64 {
                    let fixed =
                        read_fixed::<ZIP64_END_FIXED>(source, "zip64 end of central directory")?;
                    // After the size field: versions (4), disk numbers
                    // (8), records on this disk, total records, directory
                    // size (APPNOTE 4.3.14).
                    check.zip64_declared = Some((
                        le64(&fixed[12..20]),
                        le64(&fixed[20..28]),
                        le64(&fixed[28..36]),
                    ));
                    rest -= ZIP64_END_FIXED as u64;
                }
                skip(source, rest, "zip64 end of central directory")?;
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
                // After the signature: disk numbers (4), records on this
                // disk, total records, directory size (APPNOTE 4.3.16).
                check.eocd_declared =
                    Some((le16(&fixed[4..6]), le16(&fixed[6..8]), le32(&fixed[8..12])));
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

/// Reads exactly `len` bytes into a new buffer, reporting a short stream as
/// truncation in [`skip`]'s words. Callers pass a 16-bit field's length, so
/// the allocation is at most 65,535 bytes.
fn read_vec(source: &mut Pushback, len: usize, what: &str) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let mut filled = 0;
    while filled < len {
        match source.read(&mut buf[filled..]).map_err(Error::from)? {
            0 => {
                return Err(Error::Corrupt(format!(
                    "zip stream ends {} bytes short of the end of its {what}; the archive \
                     is truncated",
                    len - filled
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
// The forward reader's index check: local headers against the central
// directory (spec goal 2, rulings B2 and B3)
// ---------------------------------------------------------------------------

/// The fixed part of the zip64 end-of-central-directory record after its
/// 8-byte size: versions, disks, both counts, the directory size and offset.
const ZIP64_END_FIXED: usize = 44;

/// The most bytes [`IndexCheck`] holds for the comparison: every walked local
/// header's raw name and its delivered name (held twice: the claim's `shown`
/// and the warning's entry) and every central record's raw and shown names,
/// each charged with its fixed part ([`CLAIM_OVERHEAD`]). Past it the comparison
/// is given up, memory is freed, and the archive keeps the forward reader's
/// two warnings exactly as before (ruling B2, "over the bound"). 32 MiB holds
/// about 200,000 entries with 40-byte names.
const MAX_INDEX_CHECK_BYTES: usize = 32 * 1024 * 1024;

/// What one recorded claim costs besides its name bytes.
const CLAIM_OVERHEAD: usize = std::mem::size_of::<HeaderClaim>() + std::mem::size_of::<String>();

/// Unix file-type bits for a symlink, in a central record's external
/// attributes (high 16 bits) when the record was made on unix (host 3).
const S_IFMT: u32 = 0o170_000;
const S_IFLNK: u32 = 0o120_000;
const HOST_UNIX: u8 = 3;

/// What the forward walk keeps to compare with the central directory when
/// the walk reaches it.
///
/// When the directory was read whole, matched its end record, and was
/// compared, the forward reader's [`Fidelity::TrailingIndexUnread`] and
/// [`Fidelity::EntryCountUnknown`] are no longer true and are withdrawn
/// ([`ZipStreamed::conclude_index_check`]). Anything short of that — a cut
/// directory (an error before this is consulted), no directory, the bound
/// passed, an end record that contradicts the directory — leaves both.
#[derive(Default)]
struct IndexCheck {
    /// Each walked local header, in order, with the name it was delivered
    /// under.
    locals: Vec<(HeaderClaim, String)>,
    /// Each central record, in order.
    centrals: Vec<HeaderClaim>,
    /// Bytes charged against [`MAX_INDEX_CHECK_BYTES`].
    held: usize,
    /// Set once something could not be recorded (the bound, or a local header
    /// this could not parse): the comparison is then not made.
    incomplete: bool,
    /// Central records walked, and the bytes they span (signatures
    /// included), counted whether or not they were recorded.
    central_records: u64,
    central_bytes: u64,
    /// A central record marks a unix symlink, which a forward read delivers
    /// as a regular file holding the target.
    symlink: bool,
    /// The end record's records-on-this-disk count, total record count and
    /// directory size.
    eocd_declared: Option<(u16, u16, u32)>,
    /// The zip64 end record's, when present and whole.
    zip64_declared: Option<(u64, u64, u64)>,
}

impl IndexCheck {
    /// Whether `name_len` more bytes of claim fit under the bound. The first
    /// refusal gives the comparison up and frees what it held.
    fn can_hold(&mut self, name_len: usize) -> bool {
        if self.incomplete {
            return false;
        }
        if self.held.saturating_add(name_len + CLAIM_OVERHEAD) > MAX_INDEX_CHECK_BYTES {
            self.give_up();
            return false;
        }
        true
    }

    fn give_up(&mut self) {
        self.incomplete = true;
        self.locals = Vec::new();
        self.centrals = Vec::new();
        self.held = 0;
    }

    fn record_local(&mut self, claim: Option<HeaderClaim>, delivered: &str) {
        let Some(claim) = claim else {
            // zip accepted a header this could not parse; nothing to compare
            // it with.
            self.give_up();
            return;
        };
        // What zip delivered for this header is the shown name (ruling
        // T5-d), rather than a re-derivation of it.
        let claim = HeaderClaim {
            shown: Some(delivered.to_owned()),
            ..claim
        };
        let cost = claim.name.len() + 2 * delivered.len();
        if self.can_hold(cost) {
            self.held += cost + CLAIM_OVERHEAD;
            self.locals.push((claim, delivered.to_owned()));
        }
    }

    fn record_central(&mut self, claim: HeaderClaim) {
        let cost = claim.name.len() + claim.shown.as_ref().map_or(0, String::len);
        if self.can_hold(cost) {
            self.held += cost + CLAIM_OVERHEAD;
            self.centrals.push(claim);
        }
    }

    /// Counts one central record from its fixed block, recorded or not.
    fn note_central_framing(&mut self, fixed: &[u8; CENTRAL_HEADER_FIXED], variable: u64) {
        self.central_records += 1;
        self.central_bytes += 4 + CENTRAL_HEADER_FIXED as u64 + variable;
        let host = fixed[1];
        let mode = le32(&fixed[34..38]) >> 16;
        if host == HOST_UNIX && mode & S_IFMT == S_IFLNK {
            self.symlink = true;
        }
    }

    /// Whether the end record declares the directory that was walked: the
    /// same number of records and the same size, and its records-on-this-disk
    /// count equal to its total (a seekable read refuses an end record whose
    /// two counts disagree, exit 5; here it leaves the two warnings). A 16-
    /// or 32-bit field at its maximum defers to the zip64 end record
    /// (APPNOTE 4.4.1.4), whose own two counts must agree too; with none,
    /// nothing is confirmed.
    fn declared_matches_walk(&self) -> bool {
        let Some((on_disk16, count16, size32)) = self.eocd_declared else {
            return false;
        };
        if on_disk16 != count16 {
            return false;
        }
        let count = if count16 == u16::MAX {
            match self.zip64_declared {
                Some((on_disk, count, _)) if on_disk == count => count,
                _ => return false,
            }
        } else {
            u64::from(count16)
        };
        let size = if size32 == u32::MAX {
            match self.zip64_declared {
                Some((_, _, size)) => size,
                None => return false,
            }
        } else {
            u64::from(size32)
        };
        count == self.central_records && size == self.central_bytes
    }
}

/// A central record's claim on ruling B3's fields, from its own bytes: the
/// 42-byte fixed block after the signature, the raw name, and the extra
/// field. The central zip64 block holds only the saturated fields,
/// uncompressed size first (APPNOTE 4.5.3); one that cannot be resolved is
/// `None`, never compared. `shown` applies the record's own Unicode Path
/// field ([`shown_name`]).
fn central_claim(fixed: &[u8; CENTRAL_HEADER_FIXED], name: Vec<u8>, extra: &[u8]) -> HeaderClaim {
    let usize32 = le32(&fixed[20..24]);
    let csize32 = le32(&fixed[16..20]);
    let flags = le16(&fixed[4..6]);
    let shown = Some(shown_name(&name, flags, extra));
    let mut fields = zip64_block(extra)
        .unwrap_or(&[])
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| u64::from_le_bytes(*c));
    let usize_ = if usize32 == u32::MAX {
        fields.next()
    } else {
        Some(u64::from(usize32))
    };
    let csize = if csize32 == u32::MAX {
        fields.next()
    } else {
        Some(u64::from(csize32))
    };
    HeaderClaim {
        name,
        shown,
        flags,
        method: le16(&fixed[6..8]),
        crc: Some(le32(&fixed[12..16])),
        csize,
        usize_,
    }
}

/// A reader that keeps a copy of everything it hands on.
struct Recording<'a> {
    inner: &'a mut Pushback,
    seen: Vec<u8>,
}

impl Read for Recording<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.seen.extend_from_slice(&buf[..n]);
        Ok(n)
    }
}

/// Parses the local header at the front of `source` with
/// [`parse_local_claim`] and puts every byte it read back, so zip's own
/// `read_zipfile_from_stream` reads the same bytes after. The raw header is
/// what ruling B3 compares; zip's view has already applied an Info-ZIP
/// Unicode Path field to the name. `None` if the header cannot be parsed:
/// zip then reports it, and the comparison is not made.
fn peek_local_claim(source: &mut Pushback) -> Option<HeaderClaim> {
    let mut recording = Recording {
        inner: source,
        seen: Vec::new(),
    };
    let claim = parse_local_claim(&mut recording);
    let seen = recording.seen;
    source.push_back(&seen);
    claim
}

/// Compares the walked local headers with the central records (ruling B3's
/// fields, plus entries present on one side only and order) and returns the
/// warnings, in central order.
///
/// Records pair by name: at the same position first, else the first unpaired
/// local header of that name. A pairing that runs backwards against the walk
/// is one `"order"` warning for the archive, naming the first entry found out
/// of place. Records left unpaired on both sides pair up in order, which is
/// how a cloaked name is reported (`"name"`, plus any other field that
/// differs); what remains on either side is `"entry count"`, one warning per
/// record. A local header's entry is named as it was delivered; a central-only
/// record by its own raw name and flag.
fn compare_walk(
    locals: &[(HeaderClaim, String)],
    centrals: &[HeaderClaim],
) -> Vec<(String, Vec<&'static str>)> {
    let mut out: Vec<(String, Vec<&'static str>)> = Vec::new();
    let mut warn = |entry: &str, fields: Vec<&'static str>| {
        if !fields.is_empty() {
            out.push((entry.to_owned(), fields));
        }
    };
    // Each name's local headers in walk order. A paired index is dropped from
    // the front when next met, so the lookups are linear in all, however many
    // records share a name.
    let mut by_name: HashMap<&[u8], VecDeque<usize>> = HashMap::new();
    for (j, (claim, _)) in locals.iter().enumerate() {
        by_name
            .entry(claim.name.as_slice())
            .or_default()
            .push_back(j);
    }
    let mut paired = vec![false; locals.len()];
    let mut unpaired_centrals = Vec::new();
    let mut last = None;
    let mut order_reported = false;
    for (k, central) in centrals.iter().enumerate() {
        let positional = locals
            .get(k)
            .is_some_and(|(l, _)| !paired[k] && l.name == central.name);
        let j = if positional {
            Some(k)
        } else {
            by_name.get_mut(central.name.as_slice()).and_then(|js| {
                while js.front().is_some_and(|&j| paired[j]) {
                    js.pop_front();
                }
                js.front().copied()
            })
        };
        let Some(j) = j else {
            unpaired_centrals.push(k);
            continue;
        };
        paired[j] = true;
        let (local, delivered) = &locals[j];
        let mut fields = Vec::new();
        if last.is_some_and(|last| j < last) && !order_reported {
            fields.push("order");
            order_reported = true;
        }
        last = Some(j);
        fields.extend(disagreeing_fields(central, local));
        warn(delivered, fields);
    }
    let unpaired_locals: Vec<usize> = (0..locals.len()).filter(|&j| !paired[j]).collect();
    for (&k, &j) in unpaired_centrals.iter().zip(&unpaired_locals) {
        let (local, delivered) = &locals[j];
        warn(delivered, disagreeing_fields(&centrals[k], local));
    }
    for &j in unpaired_locals.iter().skip(unpaired_centrals.len()) {
        warn(&locals[j].1, vec!["entry count"]);
    }
    for &k in unpaired_centrals.iter().skip(unpaired_locals.len()) {
        let central = &centrals[k];
        warn(
            &entry_name(&central.name, central.flags),
            vec!["entry count"],
        );
    }
    out
}

impl ZipStreamed {
    /// Called once the walk has read the whole central directory and its end
    /// record. Reports every disagreement the comparison finds, then withdraws
    /// the two index warnings when they are no longer true: the comparison
    /// was made, and the end record declares the directory that was walked.
    ///
    /// Kept, as in 0.22.0, when the directory holds a unix symlink: the
    /// forward read delivered it as a regular file, which only the index
    /// could have said otherwise.
    fn conclude_index_check(&mut self) {
        let check = std::mem::take(&mut self.index);
        if check.incomplete {
            return;
        }
        let mut log = DisagreementLog::default();
        for (entry, fields) in compare_walk(&check.locals, &check.centrals) {
            log.warn(&mut self.report, entry, fields);
        }
        if check.symlink || !check.declared_matches_walk() {
            return;
        }
        self.report.warnings.retain(|w| {
            !matches!(
                w,
                Fidelity::TrailingIndexUnread { format: ZIP } | Fidelity::EntryCountUnknown
            )
        });
    }
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
///
/// Nor are they taken from `ZipFile::name()`: see [`entry_name`].
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
        name: entry_name(file.name_raw(), file.flags().as_u16()),
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
        return Err(Error::ResourceLimit(format!(
            "entry `{name}` declares a symlink target of {declared} bytes, past the \
             {MAX_SYMLINK_TARGET_LEN}-byte ceiling this container reads eagerly; no \
             legitimate symlink target is this long"
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
    if ZIP_MALFORMED_AS_INVALID_INPUT_OTHER_UNSUPPORTED_EOF.contains(&e.kind()) {
        return io::Error::new(ErrorKind::InvalidData, e.to_string());
    }
    e
}

/// An entry's name, decoded by the language-encoding flag (bit 11) as zip
/// 8.6 decoded it: flag set → UTF-8, lossily; flag clear → IBM code page 437.
///
/// zip 9's `ZipFile::name()` decides by CONTENT instead — any name that
/// happens to be valid UTF-8 is UTF-8, every other one CP437, flag
/// ignored — and returns a `Result`. Taking it would have changed the name
/// `list` prints for an unflagged non-ASCII name that is also valid UTF-8,
/// and for a flagged one that is not, in a release meant to change no
/// behaviour. `name_raw()` already carries an Info-ZIP Unicode Path (0x7075)
/// when the crate accepted one, with the flag set, so that case decodes as
/// UTF-8 here exactly as it did in 8.6. Infallible: CP437 maps all 256 bytes.
fn entry_name(raw: &[u8], flags: u16) -> String {
    const LANGUAGE_ENCODING: u16 = 0x0800;
    if flags & LANGUAGE_ENCODING != 0 {
        return String::from_utf8_lossy(raw).into_owned();
    }
    raw.iter().map(|&b| cp437(b)).collect()
}

/// One IBM code page 437 byte as a `char` — the table zip 8.6's `cp437.rs`
/// used, which is the standard one (0x00-0x7F identical to ASCII).
fn cp437(b: u8) -> char {
    const HIGH: [char; 128] = [
        'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å', //
        'É', 'æ', 'Æ', 'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ', //
        'á', 'í', 'ó', 'ú', 'ñ', 'Ñ', 'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»', //
        '░', '▒', '▓', '│', '┤', '╡', '╢', '╖', '╕', '╣', '║', '╗', '╝', '╜', '╛', '┐', //
        '└', '┴', '┬', '├', '─', '┼', '╞', '╟', '╚', '╔', '╩', '╦', '╠', '═', '╬', '╧', //
        '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌', '█', '▄', '▌', '▐', '▀', //
        'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ', '∞', 'φ', 'ε', '∩', //
        '≡', '±', '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²', '■', '\u{a0}',
    ];
    if b < 0x80 {
        char::from(b)
    } else {
        HIGH[usize::from(b - 0x80)]
    }
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
        (CompressionMethod::SHRINK, FormatId::new("shrink")),
        (CompressionMethod::IMPLODE, FormatId::new("implode")),
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
        let default_mode = match meta.kind {
            EntryKind::Dir => DEFAULT_DIR_MODE,
            _ => DEFAULT_FILE_MODE,
        };
        let mut o = SimpleFileOptions::DEFAULT
            .compression_method(self.method)
            // Masked to `0o777` by zip itself, so an `st_mode`-shaped value
            // from another container round-trips without the type bits
            // fighting the ones zip sets from `EntryKind` below.
            .unix_permissions(meta.mode.unwrap_or(default_mode))
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
        if matches!(meta.kind, EntryKind::Hardlink { .. }) {
            return Err(Error::hardlink_not_storable("zip", &meta.name));
        }
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

    /// One central record whose "version made by" host is `host` and whose
    /// external attributes hold the unix word for a 0644 regular file.
    fn cd_record_from_host(host: u8) -> CdRecord {
        let mut bytes = SIG_CENTRAL_HEADER.to_vec();
        let mut fixed = [0u8; CENTRAL_HEADER_FIXED];
        fixed[0] = 30;
        fixed[1] = host;
        fixed[24..26].copy_from_slice(&1u16.to_le_bytes());
        fixed[34..38].copy_from_slice(&(0o100644u32 << 16).to_le_bytes());
        bytes.extend_from_slice(&fixed);
        bytes.push(b'f');
        read_one_cd_record(&mut std::io::Cursor::new(bytes), 0)
            .unwrap()
            .unwrap()
    }

    /// A unix mode is taken only from a record a unix host (3) or OS X (19)
    /// made; the same attribute word from MS-DOS (0) or NTFS (10) is not a
    /// mode.
    #[test]
    fn a_central_record_carries_a_unix_mode_only_from_a_unix_host() {
        assert_eq!(cd_record_from_host(3).unix_mode, Some(0o100644));
        assert_eq!(cd_record_from_host(19).unix_mode, Some(0o100644));
        assert_eq!(cd_record_from_host(0).unix_mode, None);
        assert_eq!(cd_record_from_host(10).unix_mode, None);
    }
    use stuffr_core::testing::{SharedBuf, assert_container_conforms, open_forward_only};
    use stuffr_core::{ArchiveRead, OpenOpts, ReaderSource, StreamPolicy};

    /// The header-parsing fold reaches only errors `zip` made itself. An OS
    /// `EINVAL` is `InvalidInput` too, but it is the source failing: it must
    /// stay `Error::Io`, never be reported as a corrupt archive. A crate-made
    /// `InvalidInput` beside it is still folded.
    #[cfg(unix)]
    #[test]
    fn an_os_error_of_a_folded_kind_stays_io() {
        // EINVAL is 22 on every unix this builds for (no `libc` dependency).
        let os = io::Error::from_raw_os_error(22);
        assert_eq!(os.kind(), ErrorKind::InvalidInput);
        let classified = classify_zip_error(ZipError::Io(os));
        assert!(
            matches!(classified, Error::Io(_)),
            "an OS error is not a malformed archive: {classified:?}"
        );

        let made = io::Error::new(ErrorKind::InvalidInput, "range overflows u64");
        assert!(matches!(
            classify_zip_error(ZipError::Io(made)),
            Error::Corrupt(_)
        ));
    }

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

    /// An Info-ZIP fixture, or `None` when the directory is absent (it is
    /// excluded from the published crate; ruling P8). A named file that is
    /// missing from a present directory panics.
    fn infozip_fixture(name: &str) -> Option<Vec<u8>> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/infozip");
        if !dir.is_dir() {
            eprintln!("note: {} absent; skipping", dir.display());
            return None;
        }
        Some(std::fs::read(dir.join(name)).unwrap_or_else(|e| panic!("fixture {name}: {e}")))
    }

    fn read_indexed(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
        let mut ar = try_open_seekable(bytes)?;
        let mut out = Vec::new();
        while let Some(mut e) = ar.next_entry()? {
            let mut data = Vec::new();
            e.reader()
                .read_to_end(&mut data)
                .map_err(Error::from_decode_io)?;
            out.push((e.meta().name.clone(), data));
        }
        Ok(out)
    }

    #[test]
    fn shrink_and_implode_entries_decode() {
        let Some(shrink) = infozip_fixture("shrink-commons.zip") else {
            return;
        };
        let entries = read_indexed(&shrink).expect("shrink");
        assert_eq!(entries.len(), 2);
        assert_eq!(
            codec_for(CompressionMethod::SHRINK),
            FormatId::new("shrink")
        );
        assert_eq!(
            codec_for(CompressionMethod::IMPLODE),
            FormatId::new("implode")
        );
        assert_eq!(entries[0].1.len(), 76);
        assert_eq!(entries[1].1.len(), 81);
        let full = infozip_fixture("shrink-full-table.zip").unwrap();
        assert_eq!(read_indexed(&full).unwrap()[0].1.len(), 26001);
        let mut hand = Vec::new();
        for n in [
            "implode-hand-4k-2trees.zip",
            "implode-hand-4k-3trees.zip",
            "implode-hand-8k-2trees.zip",
            "implode-hand-8k-3trees.zip",
            "implode-4k-2trees.zip",
            "implode-8k-3trees.zip",
        ] {
            let e =
                read_indexed(&infozip_fixture(n).unwrap()).unwrap_or_else(|e| panic!("{n}: {e}"));
            hand.push(e);
        }
        assert!(
            hand[..4]
                .iter()
                .all(|e| e[0].1.len() == 9400 && e[0].1 == hand[0][0].1)
        );
    }

    /// A header CRC that the decoded bytes do not hash to is corruption, exit 5.
    #[test]
    fn shrink_crc_mismatch_is_corrupt() {
        let Some(mut bytes) = infozip_fixture("shrink-commons.zip") else {
            return;
        };
        let cd = bytes
            .windows(4)
            .position(|w| w == b"PK\x01\x02")
            .expect("central directory");
        bytes[cd + 16] ^= 0xFF;
        let err = read_indexed(&bytes).expect_err("a bad crc must be refused");
        assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
        assert_eq!(err.exit_code(), 5);
    }

    /// I1: a shrink or implode entry declaring more than
    /// `MAX_LEGACY_ENTRY_BYTES` is refused when the entry is made, before
    /// anything is allocated or decoded: exit 6.
    #[test]
    fn a_legacy_entry_past_the_ceiling_is_exit_6() {
        let Some(mut bytes) = infozip_fixture("shrink-full-table.zip") else {
            return;
        };
        let over = (MAX_LEGACY_ENTRY_BYTES + 1) as u32;
        let cd = bytes
            .windows(4)
            .position(|w| w == b"PK\x01\x02")
            .expect("central directory");
        for at in [22, cd + 24] {
            bytes[at..at + 4].copy_from_slice(&over.to_le_bytes());
        }
        let mut ar = open_seekable(&bytes);
        let Err(err) = ar.next_entry() else {
            panic!("an entry past the ceiling was made");
        };
        assert!(matches!(err, Error::ResourceLimit(_)), "{err:?}");
        assert_eq!(err.exit_code(), 6);
        assert!(err.to_string().contains("ceiling"), "{err}");
    }

    /// I1: the decoded buffer is the caller's exact reservation and never
    /// grows: its capacity is the declared size, not a doubling past it.
    #[test]
    fn legacy_output_never_grows_past_its_declared_size() {
        let Some(bytes) = infozip_fixture("shrink-full-table.zip") else {
            return;
        };
        assert_eq!(bytes[..4], SIG_LOCAL_HEADER);
        let csize = u32::from_le_bytes(bytes[18..22].try_into().unwrap()) as usize;
        let usize_ = u64::from(u32::from_le_bytes(bytes[22..26].try_into().unwrap()));
        let at = 30 + usize::from(le16(&bytes[26..28])) + usize::from(le16(&bytes[28..30]));
        let mut out = Vec::new();
        out.try_reserve_exact(usize_ as usize).unwrap();
        let data = decode_legacy(LegacyMethod::Shrink, 0, &bytes[at..at + csize], usize_, out)
            .expect("decodes");
        assert_eq!(data.len() as u64, usize_);
        assert_eq!(data.capacity() as u64, usize_);
    }

    /// M6: a shrink entry whose central header says symlink (`S_IFLNK`,
    /// made on Unix) is read as a regular file holding its decoded bytes,
    /// with no warning: the module doc states this downgrade.
    #[test]
    fn a_legacy_symlink_entry_reads_as_a_regular_file() {
        let Some(mut bytes) = infozip_fixture("shrink-commons.zip") else {
            return;
        };
        let cd = bytes
            .windows(4)
            .position(|w| w == b"PK\x01\x02")
            .expect("central directory");
        bytes[cd + 5] = 3; // made on Unix
        bytes[cd + 38..cd + 42].copy_from_slice(&(0o120_777u32 << 16).to_le_bytes());
        let mut ar = open_seekable(&bytes);
        let mut e = ar.next_entry().unwrap().expect("an entry");
        assert_eq!(e.meta().kind, EntryKind::File);
        assert_eq!(e.meta().mode.map(|m| m & 0o170_000), Some(0o120_000));
        let mut data = Vec::new();
        e.reader().read_to_end(&mut data).unwrap();
        assert_eq!(data.len(), 76);
        drop(e);
        assert!(!ar.fidelity().has_warnings(), "{:?}", ar.fidelity());
    }

    /// A flipped payload byte in an imploded entry never exits 1.
    #[test]
    fn damaged_implode_payload_is_never_exit_1() {
        let Some(orig) = infozip_fixture("implode-hand-8k-3trees.zip") else {
            return;
        };
        for at in [40usize, 80, 200, 500, 1000, 2000] {
            let mut bytes = orig.clone();
            if at >= bytes.len() {
                continue;
            }
            bytes[at] ^= 0x55;
            if let Err(e) = read_indexed(&bytes) {
                assert!(matches!(e.exit_code(), 5), "at {at}: {e:?}");
            }
        }
    }

    /// The writer's backstop (`plan_entry_write` keeps links away from it): a
    /// hard link is refused, never stored as a regular file.
    #[test]
    fn a_hard_link_is_refused_never_written_as_a_regular_file() {
        let buf = SharedBuf::new();
        let mut w = Zip
            .create(
                PlainSink::new(Box::new(buf.clone())),
                &CreateOpts::default(),
            )
            .expect("create");
        let mut meta = EntryMeta::file("a");
        meta.kind = EntryKind::Hardlink { target: "b".into() };
        let err = w
            .add(&meta, &mut std::io::Cursor::new(b"x"))
            .expect_err("a hard link must be refused");
        assert!(matches!(err, Error::Unsupported(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 3);
        assert!(err.to_string().contains("hard link"), "{err}");
        assert!(buf.contents().is_empty(), "nothing was written");
        assert!(!Zip.caps().stores_hardlinks);
    }

    /// `read_fixed` and `skip` — the forward reader's two primitives — spell
    /// the conversion out as `map_err(Error::from)`, and until the decode-side
    /// marker existed that conversion could not tell a decoder's malformed
    /// bytes from a disk failure. Measured from the backtrace of a real
    /// failure (`zip::read_fixed` <- `ZipStreamed::next_entry` <-
    /// `entries::list`): a truncated codec stream under a zip archive
    /// reported `i/o error`, exit 1, where `stuffr cat` on the identical
    /// bytes exited 5.
    ///
    /// This site's own doc comment says "a genuine source failure keeps its
    /// own kind and exit code" — still true, and the test below is that half.
    /// What it could not say before was WHICH source, and that is what the
    /// marker records.
    #[test]
    fn a_decode_side_failure_in_the_forward_reader_is_corruption_not_an_io_failure() {
        use stuffr_core::testing::decode_side_failing_source;

        // HALF a local file header signature, then the stream dies, so the
        // failure lands inside `read_fixed` itself. A COMPLETE signature
        // would be satisfied from the prefix and the failure would move on to
        // `read_zipfile_from_stream`, which `classify_zip_error` already
        // folds — i.e. the test would pass without the fix and prove nothing.
        let resolved = stuffr_core::resolve(
            decode_side_failing_source(b"PK", std::io::ErrorKind::InvalidData),
            ZIP,
            Zip.caps(),
            &StreamPolicy::default(),
        )
        .expect("zip forward-parses, so resolving reads nothing");
        let mut ar = Zip
            .open(resolved, &OpenOpts::default())
            .expect("zip's forward open reads nothing itself");

        let err = ar
            .next_entry()
            .expect_err("the signature read must fail on this source");
        assert!(
            matches!(err, Error::Corrupt(_)),
            "a decoder's malformed-input report must not claim stuffr failed: {err:?}"
        );
        assert_eq!(err.exit_code(), 5);
    }

    /// The hazard side: the identical failure from a source no decoder
    /// produced stays `Error::Io`, exit 1. Only the marking separates them.
    #[test]
    fn a_raw_side_failure_in_the_forward_reader_is_still_an_io_failure() {
        use stuffr_core::testing::raw_failing_source;

        let resolved = stuffr_core::resolve(
            raw_failing_source(b"PK", std::io::ErrorKind::InvalidData),
            ZIP,
            Zip.caps(),
            &StreamPolicy::default(),
        )
        .expect("resolve");
        let mut ar = Zip.open(resolved, &OpenOpts::default()).expect("open");

        let err = ar.next_entry().expect_err("the signature read must fail");
        assert!(
            matches!(err, Error::Io(_)),
            "a raw source failing is stuffr's environment failing: {err:?}"
        );
        assert_eq!(err.exit_code(), 1);
    }

    /// A one-entry archive whose central-directory record carries a zip64
    /// extended-information extra field (tag `0x0001`) declaring
    /// `header_start` as the entry's relative local-header offset.
    ///
    /// Hand-spliced onto a genuine `ZipWriter` archive rather than minimised
    /// out of the fuzzer's own 6,779-byte artefact, because the mechanism is
    /// three fields wide and naming them is worth more than a blob:
    /// `Zip64ExtendedInformation::parse`
    /// (`extra_fields/zip64_extended_information.rs`) overwrites
    /// `ZipFileData::header_start` with this block's offset `u64`, and the
    /// local-header lookup then hands that value straight to
    /// `Seek::seek(SeekFrom::Start(..))`. The block carries the offset ALONE,
    /// as APPNOTE 4.5.3 says it must when only the offset field holds the
    /// sentinel: zip 8.6 read the offset as the block's THIRD `u64` whatever
    /// the sentinels said (the fuzzer's artefact had all three), zip 9 reads
    /// only the values a sentinel asked for, so the three-value block this
    /// fixture carried under 8.6 handed 9 the uncompressed size, 2, as the
    /// offset. On unix `std` casts that `u64` to
    /// `off_t`, an `i64`, so anything above `i64::MAX` reaches `lseek(2)`
    /// NEGATIVE and the kernel answers `EINVAL` — a real
    /// `Os { code: 22, kind: InvalidInput }`, which
    /// `Error::from_decode_io` does not fold and which therefore reported
    /// exit 1.
    ///
    /// Everything else about the archive is valid, which is the point: the
    /// ONE thing separating it from an archive that reads cleanly is a
    /// single declared offset.
    fn build_zip_declaring_a_zip64_header_offset(header_start: u64) -> Vec<u8> {
        const EXTRA_LEN: usize = 12;
        let mut cursor = io::Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut cursor);
            w.start_file(
                "a.txt",
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
            )
            .expect("start_file");
            w.write_all(b"hi").expect("write payload");
            w.finish().expect("finish");
        }
        let base = cursor.into_inner();

        let declared =
            read_declared_index(&mut io::Cursor::new(&base)).expect("base archive's EOCD reads");
        let cd_start = usize::try_from(declared.cd_offset).expect("cd_offset fits usize");
        assert_eq!(base[cd_start..cd_start + 4], SIG_CENTRAL_HEADER);
        let name_len = le16(&base[cd_start + 28..]) as usize;
        let extra_len = le16(&base[cd_start + 30..]) as usize;
        assert_eq!(
            extra_len, 0,
            "the splice below assumes ZipWriter emitted no central extra field"
        );

        // Tag, block size, then the one `u64` the sentinel below asks for.
        let mut extra = Vec::with_capacity(EXTRA_LEN);
        extra.extend_from_slice(&1u16.to_le_bytes());
        extra.extend_from_slice(&8u16.to_le_bytes());
        extra.extend_from_slice(&header_start.to_le_bytes());
        assert_eq!(extra.len(), EXTRA_LEN);

        let mut out = base.clone();
        // The extra field follows the record's name.
        let insert_at = cd_start + 46 + name_len;
        out.splice(insert_at..insert_at, extra.iter().copied());
        out[cd_start + 30..cd_start + 32].copy_from_slice(&(EXTRA_LEN as u16).to_le_bytes());
        // The 32-bit offset field carries the zip64 sentinel, the spelling a
        // real archive uses when the extra field supplies the real one.
        out[cd_start + 42..cd_start + 46].copy_from_slice(&u32::MAX.to_le_bytes());

        // The EOCD's declared central-directory SIZE grew with the record;
        // its OFFSET did not move, and neither did the comment length, so
        // both of `read_declared_index`'s guards still hold.
        let eocd = out.len() - END_OF_CENTRAL_DIR_TOTAL;
        assert_eq!(out[eocd..eocd + 4], SIG_END_OF_CENTRAL_DIR);
        let cd_size = le32(&out[eocd + 12..]) + EXTRA_LEN as u32;
        out[eocd + 12..eocd + 16].copy_from_slice(&cd_size.to_le_bytes());
        out
    }

    /// An archive-declared local-header offset that no file could ever hold
    /// must be the FILE's fault, not stuffr's.
    ///
    /// The `container` fuzz target's honesty oracle found this as
    /// `next_entry error classification: "a decoder raised Io(Os { code: 22,
    /// kind: InvalidInput, message: \"Invalid argument\" })"`, and the CLI
    /// reproduced it directly: `stuffr list`, `test` and `unpack` all exited
    /// **1** — "stuffr failed" — on a 6,779-byte file.
    ///
    /// `Error::Corrupt` (exit 5) rather than `ResourceLimit` (exit 6) by
    /// `error.rs`'s `exit_code` rule, which is stated there once for every
    /// bounding guard in the tree: exit 6 is "stuffr declined to ask the
    /// allocator", exit 5 is "stuffr read the bytes and they contradict each
    /// other". Nothing is allocated from this offset and no budget makes a
    /// position past `i64::MAX` reachable — the record simply does not
    /// describe a place in this file.
    ///
    /// The refusal is NOT raised in this module: it comes from
    /// `stuffr_core::source::GuardedSeek`, one layer down, so every container
    /// that seeks to an archive-declared offset is covered by the same guard.
    /// See that module's doc for why it is there and not here.
    #[test]
    fn a_zip64_header_offset_past_the_addressable_range_is_corrupt_not_an_i_o_failure() {
        // The reproducer's own declared value, transcribed from its central
        // directory: file offset 1048 holds `bf590c4f0d2147bb`.
        let bytes = build_zip_declaring_a_zip64_header_offset(0xBB47_210D_4F0C_59BF);
        let mut ar = open_seekable(&bytes);
        let err = ar
            .next_entry()
            .expect_err("an unreachable local-header offset must be refused");
        assert!(
            matches!(err, Error::Corrupt(_)),
            "must be classified as the archive's own inconsistency, not Error::Io: {err:?}"
        );
        assert_eq!(err.exit_code(), 5, "{err}");
        let text = err.to_string();
        assert!(
            text.contains("13494791149483481535"),
            "the refusal must name the position the archive declared: {text}"
        );
    }

    /// The controlled half of the test above: the identical splice with an
    /// offset that IS addressable is not refused by the seek guard, so the
    /// test above is measuring the offset and not the splice.
    #[test]
    fn the_same_splice_with_an_addressable_offset_is_not_refused_by_the_seek_guard() {
        let bytes = build_zip_declaring_a_zip64_header_offset(0);
        let mut ar = open_seekable(&bytes);
        let mut entry = ar
            .next_entry()
            .expect("an addressable offset must reach the local header")
            .expect("one entry");
        assert_eq!(entry.meta().name, "a.txt");
        let mut got = Vec::new();
        entry.reader().read_to_end(&mut got).expect("payload reads");
        assert_eq!(got, b"hi");
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
    /// piped tar has none; a piped zip has exactly these until its walk has
    /// read the central directory, and none once that index agrees (ruling
    /// B2; in 0.22.0 they stayed to the end).
    #[test]
    fn a_piped_zip_warns_about_the_index_it_did_not_read() {
        let bytes = build_zip(&[("a.txt", b"alpha")]);
        let mut ar = open_forward_only(&Zip, &bytes);
        let report = ar.fidelity();
        assert!(
            report.has_warnings(),
            "before the walk reaches the index, a piped zip's metadata really is approximate"
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

        while ar.next_entry().unwrap().is_some() {}
        assert_eq!(ar.fidelity().rung, Rung::ForwardOnly);
        assert!(
            ar.fidelity().warnings.is_empty(),
            "the index was read and agrees: {:?}",
            ar.fidelity().warnings
        );
    }

    fn claim(name: &[u8]) -> HeaderClaim {
        HeaderClaim {
            name: name.to_vec(),
            shown: None,
            flags: 0,
            method: 0,
            crc: Some(0),
            csize: Some(0),
            usize_: Some(0),
        }
    }

    /// The pipe's comparison holds at most `MAX_INDEX_CHECK_BYTES` of claims.
    /// The first record past it gives the comparison up and frees what it
    /// held, and nothing is recorded after.
    #[test]
    fn the_pipes_index_check_gives_up_at_its_bound_and_frees_what_it_held() {
        let mut check = IndexCheck::default();
        let name = vec![b'n'; 60_000];
        let delivered = "d".repeat(60_000);
        let mut recorded = 0usize;
        while !check.incomplete {
            check.record_local(Some(claim(&name)), &delivered);
            recorded += 1;
            assert!(check.held <= MAX_INDEX_CHECK_BYTES);
        }
        assert_eq!(
            recorded - 1,
            MAX_INDEX_CHECK_BYTES / (180_000 + CLAIM_OVERHEAD),
            "every record that fits is kept"
        );
        assert!(check.locals.capacity() == 0 && check.held == 0);
        assert!(!check.can_hold(0), "nothing more is recorded");
    }

    /// Many records under one name pair in linear time: a paired index is
    /// dropped when next met, never scanned again. Quadratic, this would be
    /// 10^10 steps.
    #[test]
    fn many_records_sharing_a_name_compare_in_linear_time() {
        let n = 100_000;
        // Locals `other, same, same, ...`; centrals `same, same, ..., other`.
        // No `same` record is at its local's position, so every one is found
        // by the lookup, each the next after the last one paired.
        let mut locals = vec![(claim(b"other"), "other".to_owned())];
        locals.extend((1..n).map(|_| (claim(b"same"), "same".to_owned())));
        let mut centrals: Vec<HeaderClaim> = (1..n).map(|_| claim(b"same")).collect();
        centrals.push(claim(b"other"));
        let started = std::time::Instant::now();
        let warnings = compare_walk(&locals, &centrals);
        assert!(started.elapsed() < std::time::Duration::from_secs(20));
        assert_eq!(
            warnings,
            vec![("other".to_owned(), vec!["order"])],
            "only `other` moved"
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
    // zip 9 port: names decode as zip 8.6 decoded them; malformed header
    // fields are corruption, never exit 1
    // -----------------------------------------------------------------------

    /// A one-entry stored zip with the given raw name bytes, general-purpose
    /// flags and extra field, the same bytes in the local header and the
    /// central record, so both rungs read the identical claim.
    fn raw_zip(name: &[u8], flags: u16, extra: &[u8], payload: &[u8]) -> Vec<u8> {
        raw_zip_with_extras(name, flags, extra, extra, payload)
    }

    /// [`raw_zip`] with a different extra field in each header.
    fn raw_zip_with_extras(
        name: &[u8],
        flags: u16,
        local_extra: &[u8],
        central_extra: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        let crc = crc32(payload);
        let size = u32::try_from(payload.len()).expect("short payload");
        let n_len = u16::try_from(name.len()).expect("short name");
        let fixed = |out: &mut Vec<u8>, extra: &[u8]| {
            let x_len = u16::try_from(extra.len()).expect("short extra");
            out.extend_from_slice(&20u16.to_le_bytes()); // version needed
            out.extend_from_slice(&flags.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // method: STORE
            out.extend_from_slice(&0u16.to_le_bytes()); // mod time
            out.extend_from_slice(&0x21u16.to_le_bytes()); // mod date 1980-01-01
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&n_len.to_le_bytes());
            out.extend_from_slice(&x_len.to_le_bytes());
        };
        let mut out = Vec::new();
        out.extend_from_slice(&SIG_LOCAL_HEADER);
        fixed(&mut out, local_extra);
        out.extend_from_slice(name);
        out.extend_from_slice(local_extra);
        out.extend_from_slice(payload);
        let cd_start = u32::try_from(out.len()).expect("small archive");
        out.extend_from_slice(&SIG_CENTRAL_HEADER);
        out.extend_from_slice(&20u16.to_le_bytes()); // version made by
        fixed(&mut out, central_extra);
        out.extend_from_slice(&0u16.to_le_bytes()); // comment length
        out.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        out.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        out.extend_from_slice(&0u32.to_le_bytes()); // external attributes
        out.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        out.extend_from_slice(name);
        out.extend_from_slice(central_extra);
        let cd_size = u32::try_from(out.len()).expect("small archive") - cd_start;
        out.extend_from_slice(&SIG_END_OF_CENTRAL_DIR);
        out.extend_from_slice(&0u16.to_le_bytes()); // this disk
        out.extend_from_slice(&0u16.to_le_bytes()); // disk with the CD
        out.extend_from_slice(&1u16.to_le_bytes()); // records on this disk
        out.extend_from_slice(&1u16.to_le_bytes()); // records in total
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_start.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // comment length
        out
    }

    fn names_on_both_rungs(bytes: &[u8]) -> (String, String) {
        let seekable = read_all_seekable(bytes).expect("seekable read");
        let forward = read_all_forward(bytes).expect("forward read");
        (seekable[0].0.name.clone(), forward[0].0.clone())
    }

    /// zip 9's `ZipFile::name()` decides by content (valid UTF-8 → UTF-8,
    /// else CP437) and ignores the language-encoding flag; zip 8.6 decided by
    /// the flag. `entry_name` keeps 8.6's rule. Pinned on the two shapes
    /// where the rules disagree, on both rungs.
    #[test]
    fn names_decode_by_the_language_encoding_flag_as_zip_8_6_did() {
        // "é.txt" in UTF-8 with the flag CLEAR: CP437 (0xC3 '├', 0xA9 '⌐'),
        // where zip 9's `name()` would answer "é.txt".
        let unflagged = raw_zip("é.txt".as_bytes(), 0, &[], b"x");
        let (s, f) = names_on_both_rungs(&unflagged);
        assert_eq!((s.as_str(), f.as_str()), ("├⌐.txt", "├⌐.txt"));

        // 0xFF is not UTF-8; with the flag SET it decodes lossily, where zip
        // 9's `name()` would answer CP437's U+00A0.
        let flagged = raw_zip(b"\xff.txt", 0x0800, &[], b"x");
        let (s, f) = names_on_both_rungs(&flagged);
        assert_eq!((s.as_str(), f.as_str()), ("\u{fffd}.txt", "\u{fffd}.txt"));

        // And the ordinary cases are untouched.
        let ascii = raw_zip(b"a.txt", 0, &[], b"x");
        assert_eq!(
            names_on_both_rungs(&ascii),
            ("a.txt".into(), "a.txt".into())
        );
        let utf8 = raw_zip("é.txt".as_bytes(), 0x0800, &[], b"x");
        assert_eq!(names_on_both_rungs(&utf8), ("é.txt".into(), "é.txt".into()));
    }

    // -----------------------------------------------------------------------
    // Cloaking: a local header disagreeing with its central record
    // (GHSA-m665-v7pm-7grj). The seekable rung reads the central directory's
    // bytes and warns; it never switches to the local header's reading.
    // -----------------------------------------------------------------------

    /// Offsets inside `raw_zip`'s one local header, which starts at 0
    /// (APPNOTE 4.3.7).
    const LH_FLAGS: usize = 6;
    const LH_METHOD: usize = 8;
    const LH_TIME: usize = 10;
    const LH_CRC: usize = 14;
    const LH_CSIZE: usize = 18;
    const LH_USIZE: usize = 22;
    const LH_NAME: usize = 30;

    /// Every entry's payload over the seekable rung, and every
    /// `HeadersDisagree` the read raised as `(entry, field)`.
    fn read_with_disagreements(bytes: &[u8]) -> (Vec<Vec<u8>>, Vec<(String, &'static str)>) {
        let mut ar = open_seekable(bytes);
        let mut payloads = Vec::new();
        while let Some(mut e) = ar.next_entry().expect("entry") {
            let mut data = Vec::new();
            e.reader().read_to_end(&mut data).expect("payload");
            payloads.push(data);
        }
        (payloads, disagreements(ar.fidelity()))
    }

    fn disagreements(report: &FidelityReport) -> Vec<(String, &'static str)> {
        report
            .warnings
            .iter()
            .filter_map(|w| match w {
                Fidelity::HeadersDisagree {
                    format,
                    entry,
                    fields,
                } => {
                    assert_eq!(*format, ZIP);
                    assert!(!fields.is_empty(), "a warning names its fields");
                    Some(fields.iter().map(|f| (entry.clone(), *f)))
                }
                _ => None,
            })
            .flatten()
            .collect()
    }

    fn put16(bytes: &mut [u8], at: usize, v: u16) {
        bytes[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn put32(bytes: &mut [u8], at: usize, v: u32) {
        bytes[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// A zip of `headers` fat local headers (65,535-byte name, 65,532-byte
    /// extra of empty fields, no payload) and `records` central records,
    /// record `i` pointing at header `i % headers` under its own short name
    /// (zip collapses records sharing a name). The PARSE-4 fan-out shape.
    fn fan_out_zip(headers: usize, records: usize) -> (Vec<u8>, u64) {
        const NAME: usize = 65_535;
        const EXTRA: usize = 65_532;
        let mut out = Vec::new();
        let mut starts = Vec::new();
        for h in 0..headers {
            starts.push(u32::try_from(out.len()).expect("small"));
            out.extend_from_slice(&SIG_LOCAL_HEADER);
            out.extend_from_slice(&20u16.to_le_bytes()); // version needed
            out.extend_from_slice(&0u16.to_le_bytes()); // flags
            out.extend_from_slice(&0u16.to_le_bytes()); // STORE
            out.extend_from_slice(&0u16.to_le_bytes()); // time
            out.extend_from_slice(&0x21u16.to_le_bytes()); // date
            out.extend_from_slice(&0u32.to_le_bytes()); // crc of nothing
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&u16::try_from(NAME).expect("fits").to_le_bytes());
            out.extend_from_slice(&u16::try_from(EXTRA).expect("fits").to_le_bytes());
            let tag = u8::try_from(h % 26).expect("small") + b'a';
            out.extend(std::iter::repeat_n(tag, NAME));
            out.extend(std::iter::repeat_n(0u8, EXTRA));
        }
        let cd_start = u32::try_from(out.len()).expect("small");
        for i in 0..records {
            let name = format!("e{i}");
            out.extend_from_slice(&SIG_CENTRAL_HEADER);
            out.extend_from_slice(&20u16.to_le_bytes()); // made by
            out.extend_from_slice(&20u16.to_le_bytes()); // needed
            out.extend_from_slice(&0u16.to_le_bytes()); // flags
            out.extend_from_slice(&0u16.to_le_bytes()); // STORE
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0x21u16.to_le_bytes());
            out.extend_from_slice(&[0u8; 12]); // crc, csize, usize
            out.extend_from_slice(&u16::try_from(name.len()).expect("short").to_le_bytes());
            out.extend_from_slice(&[0u8; 12]); // extra, comment, disk, attrs
            out.extend_from_slice(&starts[i % headers].to_le_bytes());
            out.extend_from_slice(name.as_bytes());
        }
        let cd_len = u32::try_from(out.len()).expect("small") - cd_start;
        let n = u16::try_from(records).expect("fits");
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&cd_len.to_le_bytes());
        out.extend_from_slice(&cd_start.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        let header_len = u64::try_from(30 + NAME + EXTRA).expect("fits");
        (out, header_len)
    }

    /// Lists every entry (the comparison runs for each, as `list` does) and
    /// returns the report and the local-header bytes this thread read.
    fn list_counting_claim_reads(bytes: &[u8]) -> (FidelityReport, usize, u64) {
        LOCAL_CLAIM_BYTES_READ.with(|n| n.set(0));
        let mut ar = open_seekable(bytes);
        let mut entries = 0;
        while ar.next_entry().expect("entry").is_some() {
            entries += 1;
        }
        let read = LOCAL_CLAIM_BYTES_READ.with(std::cell::Cell::get);
        (ar.fidelity().clone(), entries, read)
    }

    /// PARSE-4: many central records at ONE fat local header read it once,
    /// not once per record (2,000 x 131 KB = 262 MB unmemoised).
    #[test]
    fn records_fanning_out_to_one_local_header_read_it_once() {
        let (bytes, header_len) = fan_out_zip(1, 2_000);
        let (report, entries, read) = list_counting_claim_reads(&bytes);
        assert_eq!(entries, 2_000);
        assert!(
            read <= header_len,
            "read {read} local-header bytes for a {header_len}-byte header"
        );
        assert!(
            !report
                .warnings
                .iter()
                .any(|w| matches!(w, Fidelity::LocalHeadersUnchecked { .. })),
            "every record was compared"
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|w| matches!(w, Fidelity::HeadersDisagree { .. })),
            "the names still disagree"
        );
    }

    /// PARSE-4: cycling over more fat headers than the memo holds misses
    /// every time; the read budget stops it at about twice the archive's
    /// length plus the floor, and says how many entries went unchecked.
    #[test]
    fn cycling_past_the_claim_memo_stops_at_the_read_budget() {
        let headers = 12;
        let records = 800;
        let (bytes, header_len) = fan_out_zip(headers, records);
        let per_claim = 2 * 65_535 + LOCAL_CLAIM_OVERHEAD;
        assert!(headers * per_claim > LOCAL_CLAIM_MEMO_BYTES, "memo too big");
        let budget = 2 * bytes.len() as u64 + LOCAL_CLAIM_BUDGET_FLOOR;
        assert!(records as u64 * header_len > budget, "fixture too small");
        let (report, entries, read) = list_counting_claim_reads(&bytes);
        assert_eq!(entries, records);
        assert!(
            read <= budget + header_len,
            "read {read} bytes against a budget of {budget}"
        );
        assert!(read >= budget, "the budget was spent: {read} of {budget}");
        let unchecked: Vec<u64> = report
            .warnings
            .iter()
            .filter_map(|w| match w {
                Fidelity::LocalHeadersUnchecked { format, entries } => {
                    assert_eq!(*format, ZIP);
                    Some(*entries)
                }
                _ => None,
            })
            .collect();
        assert_eq!(unchecked.len(), 1, "one warning, counted up in place");
        // Every read before the budget ran out compared one entry (a memo
        // hit compares one for free), so at most this many were not.
        let misses = read.div_ceil(header_len);
        assert!(
            unchecked[0] > 0 && unchecked[0] <= records as u64 - misses,
            "{} unchecked after {misses} reads",
            unchecked[0]
        );
    }

    /// PARSE-5: one warning per entry, naming every field it disagrees on.
    #[test]
    fn an_entry_disagreeing_on_several_fields_is_one_warning() {
        let mut bytes = raw_zip(b"a.txt", 0, &[], b"payload");
        bytes[LH_NAME] = b'b';
        bytes[LH_CRC] ^= 1;
        let ar = {
            let mut ar = open_seekable(&bytes);
            while ar.next_entry().expect("entry").is_some() {}
            ar
        };
        let found: Vec<&Fidelity> = ar
            .fidelity()
            .warnings
            .iter()
            .filter(|w| matches!(w, Fidelity::HeadersDisagree { .. }))
            .collect();
        assert_eq!(
            found,
            vec![&Fidelity::HeadersDisagree {
                format: ZIP,
                entry: "a.txt".to_owned(),
                fields: vec!["name", "CRC-32"],
            }]
        );
    }

    /// PARSE-5: past 64 entries, disagreements are counted in one warning,
    /// on the seekable rung and on a pipe alike.
    #[test]
    fn disagreements_past_the_listed_cap_are_counted_in_one_warning() {
        let records = 100;
        let (bytes, _) = fan_out_zip(1, records);
        let count = |report: &FidelityReport| {
            let listed = report
                .warnings
                .iter()
                .filter(|w| matches!(w, Fidelity::HeadersDisagree { .. }))
                .count() as u64;
            let unlisted: Vec<u64> = report
                .warnings
                .iter()
                .filter_map(|w| match w {
                    Fidelity::HeadersDisagreeUnlisted { entries, .. } => Some(*entries),
                    _ => None,
                })
                .collect();
            (listed, unlisted)
        };
        let (report, _, _) = list_counting_claim_reads(&bytes);
        assert_eq!(
            count(&report),
            (
                MAX_LISTED_DISAGREEMENTS,
                vec![records as u64 - MAX_LISTED_DISAGREEMENTS]
            )
        );
        let mut log = DisagreementLog::default();
        let mut report = FidelityReport::exact();
        for i in 0..records {
            log.warn(&mut report, format!("e{i}"), vec!["entry count"]);
            log.warn(&mut report, format!("quiet{i}"), Vec::new());
        }
        assert_eq!(
            count(&report),
            (
                MAX_LISTED_DISAGREEMENTS,
                vec![records as u64 - MAX_LISTED_DISAGREEMENTS]
            ),
            "the pipe's log, and an entry with no field is no warning"
        );
    }

    #[test]
    fn a_local_name_differing_from_its_central_record_is_reported() {
        let mut bytes = raw_zip(b"a.txt", 0, &[], b"payload");
        bytes[LH_NAME] = b'b';
        let (payloads, found) = read_with_disagreements(&bytes);
        assert_eq!(found, vec![("a.txt".to_string(), "name")]);
        assert_eq!(payloads, vec![b"payload".to_vec()]);
    }

    /// One row per compared field: the local header alone is patched, the
    /// central record keeps the truth, and exactly that field is named.
    #[test]
    fn each_compared_field_differing_in_the_local_header_alone_is_reported() {
        type Patch = fn(&mut Vec<u8>);
        let rows: [(&str, Patch); 7] = [
            ("compression method", |b| put16(b, LH_METHOD, 8)),
            ("CRC-32", |b| b[LH_CRC] ^= 1),
            ("compressed size", |b| put32(b, LH_CSIZE, 8)),
            ("uncompressed size", |b| put32(b, LH_USIZE, 8)),
            ("encryption flag", |b| put16(b, LH_FLAGS, 0x0001)),
            ("UTF-8 flag", |b| put16(b, LH_FLAGS, 0x0800)),
            ("data-descriptor flag", |b| put16(b, LH_FLAGS, 0x0008)),
        ];
        for (field, patch) in rows {
            let mut bytes = raw_zip(b"a.txt", 0, &[], b"payload");
            patch(&mut bytes);
            let (payloads, found) = read_with_disagreements(&bytes);
            assert_eq!(
                found,
                vec![("a.txt".to_string(), field)],
                "patching the local {field} alone"
            );
            assert_eq!(
                payloads,
                vec![b"payload".to_vec()],
                "patching the local {field}: the central directory's bytes come back"
            );
        }
    }

    /// `list` opens every entry, and opening one reads its local header
    /// (zip 9's `find_content`), so listing alone compares.
    #[test]
    fn listing_alone_compares_because_opening_an_entry_reads_its_local_header() {
        let mut bytes = raw_zip(b"a.txt", 0, &[], b"payload");
        bytes[LH_NAME] = b'b';
        let mut ar = open_seekable(&bytes);
        while ar.next_entry().expect("entry").is_some() {}
        assert_eq!(
            disagreements(ar.fidelity()),
            vec![("a.txt".to_string(), "name")]
        );
    }

    #[test]
    fn a_disagreement_is_reported_once_however_often_the_entry_is_opened() {
        let mut bytes = raw_zip(b"a.txt", 0, &[], b"payload");
        bytes[LH_NAME] = b'b';
        let mut ar = open_seekable(&bytes);
        while ar.next_entry().expect("entry").is_some() {}
        for _ in 0..3 {
            ar.by_index(0).expect("by_index");
        }
        assert_eq!(
            disagreements(ar.fidelity()),
            vec![("a.txt".to_string(), "name")]
        );
    }

    /// Bit 3: a streaming writer leaves the local CRC and sizes zero and puts
    /// them in a data descriptor after the payload. Not a disagreement.
    #[test]
    fn a_data_descriptor_entry_is_not_reported() {
        let payload = b"payload";
        let mut bytes = raw_zip(b"a.txt", 0x0008, &[], payload);
        for at in [LH_CRC, LH_CSIZE, LH_USIZE] {
            put32(&mut bytes, at, 0);
        }
        let mut descriptor = Vec::new();
        descriptor.extend_from_slice(b"PK\x07\x08");
        descriptor.extend_from_slice(&crc32(payload).to_le_bytes());
        descriptor.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        descriptor.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        let end_of_payload = LH_NAME + 5 + payload.len();
        bytes.splice(end_of_payload..end_of_payload, descriptor.iter().copied());
        let eocd = bytes.len() - 22;
        let cd_offset = le32(&bytes[eocd + 16..eocd + 20]) + descriptor.len() as u32;
        put32(&mut bytes, eocd + 16, cd_offset);

        let (payloads, found) = read_with_disagreements(&bytes);
        assert_eq!(found, vec![]);
        assert_eq!(payloads, vec![payload.to_vec()]);
    }

    /// Ruling B3's "not compared": writers drift on times and extra fields.
    #[test]
    fn differing_mtime_and_extra_fields_are_not_reported() {
        let extra = [0xFE, 0xCA, 4, 0, 1, 2, 3, 4]; // a private 0xCAFE block
        let mut bytes = raw_zip(b"a.txt", 0, &extra, b"payload");
        put16(&mut bytes, LH_TIME, 0x6000);
        let extra_data = LH_NAME + 5 + 4;
        bytes[extra_data..extra_data + 4].copy_from_slice(&[9, 9, 9, 9]);

        let (payloads, found) = read_with_disagreements(&bytes);
        assert_eq!(found, vec![]);
        assert_eq!(payloads, vec![b"payload".to_vec()]);
    }

    /// A decoy local entry sits first in the file, where a forward reader
    /// meets it; the central directory points past it at the real one, whose
    /// own local header is also cloaked (another name). The bytes returned
    /// are what the central record's offset points at, and the cloak warns.
    #[test]
    fn the_bytes_returned_are_the_central_directorys() {
        let decoy_archive = raw_zip(b"a.txt", 0, &[], b"EVIL!");
        let decoy = &decoy_archive[..LH_NAME + 5 + 5];
        let mut real = raw_zip(b"a.txt", 0, &[], b"good!");
        real[LH_NAME] = b'b';
        let shift = decoy.len() as u32;
        let eocd = real.len() - 22;
        let cd_start = le32(&real[eocd + 16..eocd + 20]) as usize;
        put32(&mut real, cd_start + 42, shift); // the central record's local offset
        put32(&mut real, eocd + 16, cd_start as u32 + shift);
        let mut bytes = decoy.to_vec();
        bytes.extend_from_slice(&real);

        let (payloads, found) = read_with_disagreements(&bytes);
        assert_eq!(payloads, vec![b"good!".to_vec()]);
        assert_eq!(found, vec![("a.txt".to_string(), "name")]);
    }

    /// One `raw_zip` whose two records carry an Info-ZIP Unicode Path field
    /// (0x7075) vouching for `raw_name` (its CRC-32) and naming `unicode`.
    fn unicode_path_zip(raw_name: &[u8], unicode: &str) -> Vec<u8> {
        let unicode = unicode.as_bytes();
        let mut extra = Vec::new();
        extra.extend_from_slice(&0x7075u16.to_le_bytes());
        extra.extend_from_slice(&((1 + 4 + unicode.len()) as u16).to_le_bytes());
        extra.push(1); // version
        extra.extend_from_slice(&crc32(raw_name).to_le_bytes());
        extra.extend_from_slice(unicode);
        raw_zip(raw_name, 0, &extra, b"payload")
    }

    /// An Info-ZIP Unicode Path field (0x7075) naming `unicode`, vouched for
    /// by `crc`.
    fn unicode_path_field(crc: u32, unicode: &str) -> Vec<u8> {
        let mut extra = Vec::new();
        extra.extend_from_slice(&0x7075u16.to_le_bytes());
        extra.extend_from_slice(&((1 + 4 + unicode.len()) as u16).to_le_bytes());
        extra.push(1); // version
        extra.extend_from_slice(&crc.to_le_bytes());
        extra.extend_from_slice(unicode.as_bytes());
        extra
    }

    /// The disagreements a forward (piped) walk of `bytes` reports, with
    /// whether the two index warnings were withdrawn.
    fn piped_disagreements(bytes: &[u8]) -> (Vec<(String, &'static str)>, bool) {
        let mut ar = open_forward_only(&Zip, bytes);
        while let Some(mut e) = ar.next_entry().expect("entry") {
            io::copy(&mut e.reader(), &mut io::sink()).expect("payload");
        }
        let report = ar.fidelity();
        let withdrawn = !report.warnings.contains(&Fidelity::EntryCountUnknown);
        (disagreements(report), withdrawn)
    }

    /// Ruling T5-d: raw names alike, but one record carries a Unicode Path
    /// field the other does not, so a reader of that record alone delivers
    /// another name (zip 9 applies a local field on the pipe,
    /// `read/stream.rs:774`, and a central one on the seekable path). Both
    /// shapes are reported as "name" on both paths, once.
    #[test]
    fn a_unicode_path_field_in_one_header_only_is_a_name_disagreement() {
        let field = unicode_path_field(crc32(b"a.txt"), "evil.sh");
        let local_only = raw_zip_with_extras(b"a.txt", 0, &field, &[], b"payload");
        let central_only = raw_zip_with_extras(b"a.txt", 0, &[], &field, b"payload");

        // Seekable: delivered under the central record's name.
        let (_, found) = read_with_disagreements(&local_only);
        assert_eq!(found, vec![("a.txt".to_string(), "name")]);
        let (_, found) = read_with_disagreements(&central_only);
        assert_eq!(found, vec![("evil.sh".to_string(), "name")]);

        // Piped: delivered under the local header's name. The index was read
        // and compared, so the two index warnings go; the cloak warning is
        // what is left.
        let (found, withdrawn) = piped_disagreements(&local_only);
        assert_eq!(found, vec![("evil.sh".to_string(), "name")]);
        assert!(withdrawn);
        let (found, _) = piped_disagreements(&central_only);
        assert_eq!(found, vec![("a.txt".to_string(), "name")]);
    }

    /// Info-ZIP writes the same Unicode Path field in both headers: agreement
    /// on both paths. A field whose CRC-32 does not vouch for the raw name is
    /// ignored by zip 9, so in one header only it changes nothing delivered
    /// and is not reported either.
    #[test]
    fn a_matching_or_ignored_unicode_path_field_is_not_a_disagreement() {
        let good = unicode_path_field(crc32(b"a.txt"), "évil.sh");
        let forged = unicode_path_field(crc32(b"a.txt") ^ 1, "evil.sh");
        for (what, bytes) in [
            (
                "matching in both",
                raw_zip_with_extras(b"a.txt", 0, &good, &good, b"payload"),
            ),
            (
                "forged, local only",
                raw_zip_with_extras(b"a.txt", 0, &forged, &[], b"payload"),
            ),
            (
                "forged, central only",
                raw_zip_with_extras(b"a.txt", 0, &[], &forged, b"payload"),
            ),
        ] {
            let (_, found) = read_with_disagreements(&bytes);
            assert_eq!(found, vec![], "seekable, {what}");
            let (found, withdrawn) = piped_disagreements(&bytes);
            assert_eq!(found, vec![], "piped, {what}");
            assert!(withdrawn, "piped, {what}");
        }
    }

    /// The anti-goal "no change on well-formed archives", for zip64 on the
    /// pipe: a central record whose 32-bit sizes are `0xFFFFFFFF` with the
    /// real ones in its zip64 block, and an end record whose count is
    /// `0xFFFF`, deferring to a zip64 end record and locator. The walk
    /// resolves both, reports nothing and withdraws both index warnings.
    #[test]
    fn a_piped_zip64_archive_raises_nothing_and_withdraws_both_warnings() {
        let name = b"big.bin";
        let payload = b"zip64 payload";
        let crc = crc32(payload);
        let size = payload.len() as u64;
        let fixed = |out: &mut Vec<u8>, sizes32: u32, x_len: u16| {
            out.extend_from_slice(&45u16.to_le_bytes()); // version needed
            out.extend_from_slice(&0u16.to_le_bytes()); // flags
            out.extend_from_slice(&0u16.to_le_bytes()); // STORE
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0x21u16.to_le_bytes());
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&sizes32.to_le_bytes());
            out.extend_from_slice(&sizes32.to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&x_len.to_le_bytes());
        };
        let mut out = Vec::new();
        out.extend_from_slice(&SIG_LOCAL_HEADER);
        fixed(&mut out, size as u32, 0);
        out.extend_from_slice(name);
        out.extend_from_slice(payload);

        let cd_start = out.len() as u64;
        out.extend_from_slice(&SIG_CENTRAL_HEADER);
        out.extend_from_slice(&45u16.to_le_bytes()); // version made by
        fixed(&mut out, u32::MAX, 20);
        out.extend_from_slice(&[0u8; 6]); // comment, disk, internal attrs
        out.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        out.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        out.extend_from_slice(name);
        out.extend_from_slice(&0x0001u16.to_le_bytes());
        out.extend_from_slice(&16u16.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes()); // uncompressed
        out.extend_from_slice(&size.to_le_bytes()); // compressed
        let cd_size = out.len() as u64 - cd_start;

        let zip64_end = out.len() as u64;
        out.extend_from_slice(&SIG_ZIP64_END);
        out.extend_from_slice(&44u64.to_le_bytes());
        out.extend_from_slice(&45u16.to_le_bytes());
        out.extend_from_slice(&45u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&1u64.to_le_bytes());
        out.extend_from_slice(&1u64.to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_start.to_le_bytes());
        out.extend_from_slice(&SIG_ZIP64_LOCATOR);
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&zip64_end.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&SIG_END_OF_CENTRAL_DIR);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&u16::MAX.to_le_bytes());
        out.extend_from_slice(&u16::MAX.to_le_bytes());
        out.extend_from_slice(&u32::MAX.to_le_bytes());
        out.extend_from_slice(&u32::MAX.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());

        let mut ar = open_forward_only(&Zip, &out);
        let mut data = Vec::new();
        let mut e = ar.next_entry().expect("entry").expect("one entry");
        e.reader().read_to_end(&mut data).expect("payload");
        drop(e);
        assert_eq!(data, payload);
        assert!(ar.next_entry().expect("the index walk").is_none());
        assert!(
            ar.fidelity().warnings.is_empty(),
            "{:?}",
            ar.fidelity().warnings
        );
        // And the seekable reader accepts the same bytes, so the fixture is
        // a real zip64 archive, not one only this walk believes in.
        let (payloads, found) = read_with_disagreements(&out);
        assert_eq!(payloads, vec![payload.to_vec()]);
        assert_eq!(found, vec![]);
    }

    /// zip 9 replaces a central name with a valid Info-ZIP Unicode Path
    /// (0x7075) and sets bit 11 on its copy. The local header still carries
    /// the record's original bytes and flags, which is agreement, not a cloak.
    #[test]
    fn a_unicode_path_extra_field_is_not_a_disagreement() {
        let bytes = unicode_path_zip(b"caf\x82.txt", "café.txt"); // CP437 "café.txt"
        let (payloads, found) = read_with_disagreements(&bytes);
        assert_eq!(found, vec![]);
        assert_eq!(payloads, vec![b"payload".to_vec()]);
        // And a cloaked local name under the same extra field still warns,
        // named as stuffr names the entry.
        let mut cloaked = bytes.clone();
        cloaked[LH_NAME] = b'C';
        let (_, found) = read_with_disagreements(&cloaked);
        assert_eq!(found, vec![("café.txt".to_string(), "name")]);
    }

    /// The review's attack: a local name that differs from the central
    /// record's raw name but has the same CRC-32, the one value a Unicode
    /// Path field vouches with. CRC-32 is linear, so such a name is cheap to
    /// make. The raw names are compared, so it is reported.
    #[test]
    fn a_local_name_sharing_the_central_names_crc_is_still_reported() {
        let central = b"0008ddf9.txt";
        let local = b"02008894.txt";
        assert_eq!(crc32(central), crc32(local), "the pair must collide");
        let mut bytes = unicode_path_zip(central, "unicode-é.txt");
        bytes[LH_NAME..LH_NAME + local.len()].copy_from_slice(local);
        let (payloads, found) = read_with_disagreements(&bytes);
        assert_eq!(found, vec![("unicode-é.txt".to_string(), "name")]);
        assert_eq!(payloads, vec![b"payload".to_vec()]);
    }

    /// Bit 11 is compared with the central record's own bit, even where zip
    /// set it on its copy for a Unicode Path field.
    #[test]
    fn the_utf8_flag_is_compared_with_the_central_records_own_bit() {
        let mut bytes = unicode_path_zip(b"caf\x82.txt", "café.txt");
        put16(&mut bytes, LH_FLAGS, 0x0800);
        let (_, found) = read_with_disagreements(&bytes);
        assert_eq!(found, vec![("café.txt".to_string(), "UTF-8 flag")]);
    }

    /// Ruling T4-b: bit 3 on one side only switches the CRC and size checks
    /// off, so it is itself reported, whichever record sets it.
    #[test]
    fn a_data_descriptor_flag_on_one_side_only_is_reported() {
        let mut local_only = raw_zip(b"a.txt", 0, &[], b"payload");
        put16(&mut local_only, LH_FLAGS, 0x0008);
        let (payloads, found) = read_with_disagreements(&local_only);
        assert_eq!(found, vec![("a.txt".to_string(), "data-descriptor flag")]);
        assert_eq!(payloads, vec![b"payload".to_vec()]);

        let mut central_only = raw_zip(b"a.txt", 0, &[], b"payload");
        let eocd = central_only.len() - 22;
        let cd_start = le32(&central_only[eocd + 16..eocd + 20]) as usize;
        put16(&mut central_only, cd_start + 8, 0x0008);
        // And the local CRC lies, which bit 3 on one side alone must not hide
        // behind: the flag is what is reported.
        central_only[LH_CRC] ^= 1;
        let (_, found) = read_with_disagreements(&central_only);
        assert_eq!(found, vec![("a.txt".to_string(), "data-descriptor flag")]);
    }

    /// A hostile local header is left to zip's own open: no comparison, no
    /// `HeadersDisagree`, and the error it always raised (never exit 1).
    #[test]
    fn a_hostile_local_header_raises_no_disagreement_and_keeps_its_error() {
        fn walk(bytes: &[u8]) -> (Option<i32>, Vec<(String, &'static str)>) {
            let mut ar = match try_open_seekable(bytes) {
                Ok(ar) => ar,
                Err(e) => return (Some(e.exit_code()), vec![]),
            };
            let mut code = None;
            loop {
                match ar.next_entry() {
                    Ok(Some(mut e)) => {
                        let mut d = Vec::new();
                        if let Err(err) = e.reader().read_to_end(&mut d) {
                            code = Some(Error::from_decode_io(err).exit_code());
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        code = Some(e.exit_code());
                        break;
                    }
                }
            }
            (code, disagreements(ar.fidelity()))
        }

        // The local name length runs past the end of the file.
        let mut long_name = raw_zip(b"a.txt", 0, &[], b"payload");
        put16(&mut long_name, 26, u16::MAX);
        let (code, found) = walk(&long_name);
        assert_eq!(found, vec![]);
        assert_eq!(code, Some(5), "a name past EOF");

        // The central record's local-header offset points past the end.
        let mut far = raw_zip(b"a.txt", 0, &[], b"payload");
        let eocd = far.len() - 22;
        let cd_start = le32(&far[eocd + 16..eocd + 20]) as usize;
        put32(&mut far, cd_start + 42, 0x7FFF_0000);
        let (code, found) = walk(&far);
        assert_eq!(found, vec![]);
        assert_eq!(code, Some(5), "a local header past EOF");
    }

    /// Zip64: the local header's 32-bit sizes are 0xFFFFFFFF and the real
    /// ones are in its zip64 extra field. Read there, they agree.
    #[test]
    fn local_zip64_sizes_are_read_from_the_extra_field() {
        let payload = b"payload";
        let mut extra = Vec::new();
        extra.extend_from_slice(&0x0001u16.to_le_bytes());
        extra.extend_from_slice(&16u16.to_le_bytes());
        extra.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        extra.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        // `raw_zip` puts the same extra on both records; the central one is
        // then a zip64 extra with no 0xFFFFFFFF field to fill, which zip
        // ignores, so the central sizes stay the 32-bit ones.
        let mut bytes = raw_zip(b"a.txt", 0, &extra, payload);
        put32(&mut bytes, LH_CSIZE, u32::MAX);
        put32(&mut bytes, LH_USIZE, u32::MAX);
        let (payloads, found) = read_with_disagreements(&bytes);
        assert_eq!(found, vec![]);
        assert_eq!(payloads, vec![payload.to_vec()]);

        // The same with the extra field's uncompressed size cloaked.
        let x = LH_NAME + 5 + 4;
        bytes[x] ^= 1;
        let (_, found) = read_with_disagreements(&bytes);
        assert_eq!(found, vec![("a.txt".to_string(), "uncompressed size")]);
    }

    /// Every byte of the CP437 table, against the standard mapping's
    /// landmarks: identity below 0x80, then the first and last of each row
    /// of the high half.
    #[test]
    fn the_cp437_table_matches_the_standard_mapping() {
        for b in 0u8..0x80 {
            assert_eq!(cp437(b), char::from(b));
        }
        for (b, c) in [
            (0x80, 'Ç'),
            (0x8f, 'Å'),
            (0x90, 'É'),
            (0x9f, 'ƒ'),
            (0xa0, 'á'),
            (0xaf, '»'),
            (0xb0, '░'),
            (0xbf, '┐'),
            (0xc0, '└'),
            (0xcf, '╧'),
            (0xd0, '╨'),
            (0xdf, '▀'),
            (0xe0, 'α'),
            (0xef, '∩'),
            (0xf0, '≡'),
            (0xff, '\u{a0}'),
        ] {
            assert_eq!(cp437(b), c, "{b:#04x}");
        }
    }

    /// An extended-timestamp extra field (0x5455) whose length disagrees with
    /// its flags: zip raises `ZipError::Io(Other)` for it while parsing the
    /// header. On zip 8.6 the seekable rung reached exit 1 with it; on zip 9
    /// the forward rung does (the crate now parses it there). Both rungs must
    /// answer exit 5 or read the archive — never exit 1.
    #[test]
    fn a_malformed_extended_timestamp_is_never_exit_1() {
        // len 9 with only the "modified" flag: 1 + 4 * 1 = 5, and 9 != 5.
        let mut extra = Vec::new();
        extra.extend_from_slice(&0x5455u16.to_le_bytes());
        extra.extend_from_slice(&9u16.to_le_bytes());
        extra.push(0x01);
        extra.extend_from_slice(&[0u8; 8]);
        let bytes = raw_zip(b"a.txt", 0, &extra, b"hello");

        for (rung, result) in [
            ("seekable", read_all_seekable(&bytes).map(|_| ())),
            ("forward", read_all_forward(&bytes).map(|_| ())),
        ] {
            if let Err(err) = result {
                assert!(matches!(err, Error::Corrupt(_)), "{rung}: {err:?}");
                assert_eq!(err.exit_code(), 5, "{rung}: {err}");
            }
        }
        let err = read_all_forward(&bytes).expect_err("zip 9 refuses it on the forward rung");
        assert!(err.to_string().contains("extended timestamp"), "{err}");
    }

    /// lzma-rust2 0.23 (zip 9's) raises `ErrorKind::Unsupported` for an xz
    /// stream header with a reserved flag bit set, where 0.16.5 (zip 8.6's)
    /// said `InvalidData`; unfolded, a zip whose xz entry carries one
    /// answered `i/o error: invalid XZ stream flags`, exit 1, on both rungs.
    #[test]
    fn an_xz_entry_with_reserved_stream_flags_is_corrupt_not_exit_1() {
        // A 12-byte xz stream header: magic, flags 01 00 (a reserved bit in
        // the first byte), and the CRC32 of those two flag bytes, so the
        // header checksum passes and the flags are what is refused.
        let mut xz = vec![0xFD, b'7', b'z', b'X', b'Z', 0x00, 0x01, 0x00];
        xz.extend_from_slice(&crc32(&[0x01, 0x00]).to_le_bytes());
        xz.extend_from_slice(&[0u8; 32]);
        let mut bytes = raw_zip(b"a.txt", 0, &[], &xz);
        // Method 95 (xz) in the local header and the central record.
        bytes[8..10].copy_from_slice(&95u16.to_le_bytes());
        let cd = bytes
            .windows(4)
            .position(|w| w == SIG_CENTRAL_HEADER)
            .expect("central record");
        bytes[cd + 10..cd + 12].copy_from_slice(&95u16.to_le_bytes());

        for (rung, result) in [
            ("seekable", read_all_seekable(&bytes).map(|_| ())),
            ("forward", read_all_forward(&bytes).map(|_| ())),
        ] {
            let err = result.expect_err("reserved xz stream flags must be refused");
            assert!(matches!(err, Error::Corrupt(_)), "{rung}: {err:?}");
            assert_eq!(err.exit_code(), 5, "{rung}: {err}");
        }
    }

    // -----------------------------------------------------------------------
    // An EOCD whose two counts disagree with each other
    // -----------------------------------------------------------------------

    /// Rewrites one of the EOCD's two record counts — `field` is its offset
    /// within the record, 8 (on this disk) or 10 (archive total) — leaving
    /// every central-directory record physically intact.
    fn with_eocd_count(bytes: &[u8], field: usize, count: u16) -> Vec<u8> {
        let eocd = bytes.len() - END_OF_CENTRAL_DIR_TOTAL;
        assert_eq!(bytes[eocd..eocd + 4], SIG_END_OF_CENTRAL_DIR, "no EOCD");
        let mut out = bytes.to_vec();
        out[eocd + field..eocd + field + 2].copy_from_slice(&count.to_le_bytes());
        out
    }

    /// Opens `bytes` seekably and requires the refusal zip 9 gives an EOCD
    /// whose two record counts disagree, worded by
    /// `name_a_self_contradicting_index` to name both counts.
    fn assert_self_contradicting_index_refused(bytes: &[u8], total: u64, on_disk: u64) {
        let err = match try_open_seekable(bytes) {
            Err(e) => e,
            Ok(_) => panic!("an EOCD whose counts disagree must be refused"),
        };
        assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
        assert_eq!(err.exit_code(), 5, "{err}");
        let text = err.to_string();
        assert!(
            text.contains(&format!("{total} record(s) in the archive"))
                && text.contains(&format!("{on_disk} on its only disk")),
            "the refusal must name the self-contradiction, not a multi-disk set: {text}"
        );
    }

    /// The v0.7.0 deep-fuzz finding (`container` target, 505-byte input):
    /// an EOCD declaring 4 records on this disk but 1 in the whole archive.
    /// Under zip 8.6 the crate enumerated the on-disk count and
    /// `note_unreachable_records` warned (exit 0, 4 under strict). zip 9
    /// refuses the record (`find_central_directory.rs:236-240`), so the
    /// verdict is now exit 5 — bytes that contradict themselves — with a
    /// message naming both counts rather than the crate's "Multi-disk".
    #[test]
    fn an_eocd_declaring_fewer_records_in_total_than_on_its_only_disk_is_refused() {
        let clean = build_zip(&[("a.txt", b"alpha"), ("b.txt", b"beta"), ("c.txt", b"c")]);
        let bytes = with_eocd_count(&clean, 10, 1);
        assert_self_contradicting_index_refused(&bytes, 1, 3);
    }

    /// The converse: 3 in total, 1 on this disk. Refused the same way.
    #[test]
    fn an_eocd_declaring_more_records_in_total_than_on_its_only_disk_is_refused() {
        let clean = build_zip(&[("a.txt", b"alpha"), ("b.txt", b"beta"), ("c.txt", b"c")]);
        let bytes = with_eocd_count(&clean, 8, 1);
        assert_self_contradicting_index_refused(&bytes, 3, 1);
    }

    /// Salvage Stage 3 final review, zip M1: the two counts disagree AND
    /// the enumeration would land on the total (eight records under six
    /// names, EOCD saying 8 on this disk and 6 in total). Under zip 8.6 that
    /// needed the contradiction checked before the equality return; under
    /// zip 9 the record is refused before anything is enumerated, so the
    /// coincidence cannot hide it either way.
    #[test]
    fn an_eocd_contradicting_itself_is_refused_even_when_the_enumeration_would_match_its_total() {
        let shadowing = build_shadowing_zip();
        let eocd = shadowing.len() - END_OF_CENTRAL_DIR_TOTAL;
        assert_eq!(le16(&shadowing[eocd + 8..]), 8, "fixture: 8 on this disk");
        let bytes = with_eocd_count(&shadowing, 10, 6);
        assert_self_contradicting_index_refused(&bytes, 6, 8);
    }

    /// A multi-disk EOCD with agreeing counts keeps zip 9's verdict, exit 5
    /// with the crate's wording (zip 8.6 said exit 3 for this synthetic
    /// shape; see `name_a_self_contradicting_index` for why it is not mapped).
    #[test]
    fn a_multi_disk_eocd_with_agreeing_counts_keeps_the_crates_verdict() {
        let clean = build_zip(&[("a.txt", b"alpha")]);
        let eocd = clean.len() - END_OF_CENTRAL_DIR_TOTAL;
        let mut bytes = clean.clone();
        bytes[eocd + 4..eocd + 6].copy_from_slice(&1u16.to_le_bytes());
        let err = match try_open_seekable(&bytes) {
            Err(e) => e,
            Ok(_) => panic!("a multi-disk EOCD must be refused"),
        };
        assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
        assert_eq!(err.exit_code(), 5, "{err}");
        assert!(err.to_string().contains("Multi-disk"), "{err}");
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

    /// `fixture_crc32` is pinned against CRC-32/ISO-HDLC's own published
    /// check value (`0xCBF43926` over the nine bytes `123456789`), not
    /// against anything this project computed. A transcription error in the
    /// polynomial would otherwise be invisible: the builder writes a CRC and
    /// this project's own reader checks it, so the two would agree on a
    /// wrong value forever.
    #[test]
    fn the_fixture_builders_crc_matches_the_published_check_value() {
        assert_eq!(fixture_crc32(b"123456789"), 0xCBF4_3926);
    }

    /// The realistic duplicate shape: eight records under six names, where
    /// the two extras carry DIFFERENT bytes from the records whose name they
    /// repeat. Everything structural matches [`build_shadowing_zip`] — same
    /// counts, same names, same sizes — so the checksum is the one field
    /// that separates the two fixtures, which is exactly what makes them a
    /// controlled pair.
    #[test]
    fn the_distinct_duplicate_fixture_repeats_names_but_not_content() {
        let bytes = build_distinct_duplicate_zip();
        let recs = walk_central_directory(&mut io::Cursor::new(&bytes)).expect("walk");
        assert_eq!(
            recs.len(),
            8,
            "eight records, same as the identical fixture"
        );
        assert_eq!(
            recs.iter()
                .map(|r| r.name.as_str())
                .collect::<std::collections::HashSet<_>>()
                .len(),
            6,
            "under six names, same as the identical fixture"
        );
        assert_eq!(recs[6].name, recs[2].name, "the NAME is repeated");
        assert_eq!(recs[7].name, recs[3].name);
        assert_eq!(
            recs[6].compressed_size, recs[2].compressed_size,
            "same declared length — the payload swap is length-preserving"
        );
        assert_eq!(recs[7].compressed_size, recs[3].compressed_size);
        assert_ne!(
            recs[6].crc32, recs[2].crc32,
            "and DIFFERENT content: the whole point of this fixture"
        );
        assert_ne!(recs[7].crc32, recs[3].crc32);
    }

    /// The two fixtures must actually differ, and differ only where they are
    /// meant to. Without this, a builder bug that ignored
    /// `DuplicateContent::Distinct` would leave every test that stands on
    /// the new fixture silently re-testing the old one — the precise failure
    /// mode (a fixture that does not model what its name says) that hid
    /// three findings behind `build_shadowing_zip` in the first place.
    #[test]
    fn the_two_duplicate_fixtures_are_the_same_shape_and_different_bytes() {
        let identical = build_shadowing_zip();
        let distinct = build_distinct_duplicate_zip();
        assert_eq!(
            identical.len(),
            distinct.len(),
            "length-preserving by construction"
        );
        assert_ne!(identical, distinct, "but not the same bytes");

        let id_recs = walk_central_directory(&mut io::Cursor::new(&identical)).expect("walk");
        let di_recs = walk_central_directory(&mut io::Cursor::new(&distinct)).expect("walk");
        for (id, di) in id_recs.iter().zip(di_recs.iter()) {
            assert_eq!(id.name, di.name);
            assert_eq!(id.local_header_offset, di.local_header_offset);
            assert_eq!(id.compressed_size, di.compressed_size);
            assert_eq!(id.uncompressed_size, di.uncompressed_size);
            assert_eq!(id.method, di.method);
        }
        // The six originals are untouched; only records 6 and 7 changed.
        for i in 0..6 {
            assert_eq!(
                id_recs[i].crc32, di_recs[i].crc32,
                "record {i} must be identical between the two fixtures"
            );
        }
        assert_ne!(id_recs[6].crc32, di_recs[6].crc32);
        assert_ne!(id_recs[7].crc32, di_recs[7].crc32);
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

    /// A directory handed over with no mode used to get `DEFAULT_FILE_MODE`
    /// (`0o644`): no owner-execute bit, so it extracted as a directory
    /// nothing could traverse into — `tar.rs`'s and `cpio.rs`'s
    /// `DEFAULT_DIR_MODE` defect, still open here. `pack` never reached it
    /// (a walked directory always has a mode); `stuffr convert` from an lha
    /// archive, whose entries carry none, did. A file's default is unchanged.
    #[test]
    fn a_directory_entry_with_no_mode_defaults_to_an_executable_one() {
        let mut dir = EntryMeta::file("d/");
        dir.kind = EntryKind::Dir;
        assert_eq!(dir.mode, None, "the point of this test");
        let file = EntryMeta::file("d/f.txt");
        assert_eq!(file.mode, None, "the point of this test");
        let bytes = build_with(&CreateOpts::default(), &[(dir, b""), (file, b"x")]);

        let got = read_all_seekable(&bytes).unwrap();
        assert_eq!(
            got[0].0.mode.map(|m| m & 0o7777),
            Some(DEFAULT_DIR_MODE),
            "an unset directory mode must default to something traversable"
        );
        assert_eq!(
            got[1].0.mode.map(|m| m & 0o7777),
            Some(DEFAULT_FILE_MODE),
            "a file's own default must be unaffected by the directory fix"
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

    /// A symlink whose target is declared (and delivered) past
    /// `MAX_SYMLINK_TARGET_LEN` is a resource limit, exit 6, exactly as cpio's
    /// identical check answers: the field was measured against a structural
    /// ceiling and refused before it was read. It was `Corrupt`/5 until 0.10.4.
    ///
    /// The target is genuinely written at 65,537 bytes, so the reader's own
    /// earlier checks (payload past EOF, size/offset sanity) have nothing to
    /// object to and the guard under test is the one that answers.
    #[test]
    fn a_symlink_target_past_the_length_ceiling_is_refused_as_a_resource_limit() {
        let mut link = EntryMeta::file("biglink");
        link.kind = EntryKind::Symlink {
            target: "t".repeat(MAX_SYMLINK_TARGET_LEN as usize + 1),
        };
        let bytes = build_with(&CreateOpts::default(), &[(link, &[][..])]);

        let err = read_all_seekable(&bytes).expect_err("an oversized symlink target must refuse");
        assert_eq!(
            err.exit_code(),
            6,
            "a target past the ceiling is refused before it is read, so exit 6: {err}"
        );
        assert!(
            matches!(err, Error::ResourceLimit(_)),
            "must be ResourceLimit: {err:?}"
        );
        let text = err.to_string();
        assert!(
            text.contains("biglink") && text.contains("65537") && text.contains("65536"),
            "the refusal names the entry, the declared length and the ceiling: {text}"
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

    /// An LZMA (method 14) entry body whose first match points further back
    /// than anything decoded so far: `lzma_rust2`'s `LzDecoder::repeat`
    /// raises `io::Error::other("dist overflow")` for it. The 9-byte zip
    /// LZMA header (version `00 00`, properties size `05 00`, props `00`,
    /// dictionary `0x673`) followed by the range-coder bytes the fuzzer
    /// found.
    const DIST_OVERFLOW_LZMA_BODY: &[u8] = &[
        0x00, 0x00, 0x05, 0x00, 0x00, 0x73, 0x06, 0x00, 0x00, 0x00, 0x04, 0x00, 0x04, 0x00, 0xf5,
        0x00, 0x00, 0x00, 0xed, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    /// **The 0.10.0 tag's deep-fuzz finding**, verbatim (the fuzz slot
    /// byte dropped): a stored directory entry, then a local header naming
    /// method 14 over [`DIST_OVERFLOW_LZMA_BODY`], and no central
    /// directory. The `container` target aborted on it with `a decoder
    /// raised Io(Custom { kind: Other, error: "dist overflow" }), which maps
    /// to exit code 1` — hostile input reaching exit 1, which the exit-code
    /// contract forbids. `ZIP_MALFORMED_AS_INVALID_INPUT_OTHER_UNSUPPORTED_EOF`'s doc
    /// carries the trace.
    ///
    /// The seekable rung needs a central directory, so it is asserted over
    /// the same body re-laid by [`hand_built_zip`] with both method fields
    /// patched to 14 — the decoder sees the identical bytes either way.
    #[test]
    fn a_malformed_lzma_entry_is_corruption_never_exit_1() {
        let mut fuzzed = b"PK\x03\x04\x14\x00\x00\x00\x00\x00\xef\x25\x47\x5d\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00sample/\
PK\x03\x04\x14\x00\x00\x00\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\xed\x41\x41\x00\x00\x00\x00\x00\x00\x00"
            .to_vec();
        fuzzed.extend_from_slice(DIST_OVERFLOW_LZMA_BODY);
        let err = read_all_forward(&fuzzed).expect_err("a dist overflow must be refused");
        assert_eq!(err.exit_code(), 5, "forward rung: got {err:?}");
        assert!(err.to_string().contains("dist overflow"), "{err}");

        let body = DIST_OVERFLOW_LZMA_BODY;
        let mut bytes = hand_built_zip("l.txt", 0, body.len() as u32, 65, body);
        bytes[8..10].copy_from_slice(&14u16.to_le_bytes());
        let central = 30 + "l.txt".len() + body.len();
        assert_eq!(bytes[central..central + 4], SIG_CENTRAL_HEADER);
        bytes[central + 10..central + 12].copy_from_slice(&14u16.to_le_bytes());
        let err = read_all_seekable(&bytes).expect_err("a dist overflow must be refused");
        assert_eq!(err.exit_code(), 5, "seekable rung: got {err:?}");
        assert!(err.to_string().contains("dist overflow"), "{err}");
    }

    /// The sibling sweep behind the fix above: every byte of a real LZMA
    /// entry's compressed payload (Python's `zipfile`, a COMPRESSIBLE text,
    /// so corruption lands inside the LZ77 match machinery where `Other`
    /// originates — see `XZ_PURE_MALFORMED_AS_INVALID_DATA_INPUT_OTHER_EOF`'s
    /// doc for what an incompressible payload hides) is flipped in turn, and
    /// no position may reach exit 1. A flip the crc32 and the decoder both
    /// miss would read clean, so `Ok` is allowed; an error must be exit 5.
    #[test]
    fn no_corrupted_byte_of_an_lzma_entry_reaches_exit_1() {
        let python = require_bin("python3");
        let dir = scratch("lzma-corruption-sweep");
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
        let _ = std::fs::remove_dir_all(&dir);

        let name_len = u16::from_le_bytes([bytes[26], bytes[27]]) as usize;
        let extra_len = u16::from_le_bytes([bytes[28], bytes[29]]) as usize;
        let compressed = u32::from_le_bytes([bytes[18], bytes[19], bytes[20], bytes[21]]) as usize;
        let start = 30 + name_len + extra_len;
        let mut errors = 0;
        for at in start..start + compressed {
            let mut corrupt = bytes.clone();
            corrupt[at] ^= 0xff;
            for (rung, got) in [
                ("forward", read_all_forward(&corrupt).map(|_| ())),
                ("seekable", read_all_seekable(&corrupt).map(|_| ())),
            ] {
                if let Err(err) = got {
                    errors += 1;
                    assert_eq!(
                        err.exit_code(),
                        5,
                        "{rung} rung, byte {at} of the payload flipped: {err:?}"
                    );
                }
            }
        }
        assert!(
            errors > 0,
            "the sweep detected nothing, so it asserted nothing"
        );
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
    #[cfg(unix)]
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

    /// `hand_built_zip`'s one entry carrying `payload` (compressed size =
    /// its length), re-stored with `method` in both its local and its
    /// central header.
    fn hand_built_with_method(name: &str, declared: u32, method: u16, payload: &[u8]) -> Vec<u8> {
        let csize = u32::try_from(payload.len()).expect("a test payload is short");
        let mut bytes = hand_built_zip(name, 0, csize, declared, payload);
        let cd = 30 + name.len() + payload.len();
        bytes[8..10].copy_from_slice(&method.to_le_bytes());
        bytes[cd + 10..cd + 12].copy_from_slice(&method.to_le_bytes());
        bytes
    }

    /// What the first entry of `bytes` lists as, and what reading its
    /// payload gives: the bytes, or the error's exit code.
    fn list_and_read_first(bytes: &[u8]) -> (EntryMeta, std::result::Result<usize, i32>) {
        let mut ar = open_seekable(bytes);
        let mut e = ar.next_entry().unwrap().expect("an entry");
        let meta = e.meta().clone();
        let mut data = Vec::new();
        let read = e
            .reader()
            .read_to_end(&mut data)
            .map_err(|err| Error::from_decode_io(err).exit_code());
        (meta, read)
    }

    /// 0.16.0 deep fuzz (`container`, `entry "sample/" declared 33554432
    /// bytes but produced 0`): a shrink or implode DIRECTORY entry declaring
    /// a size. The normal path lists it as a `Dir` of its declared size and
    /// refuses the missing payload on read (exit 5); the legacy path must
    /// agree on all three, for any declared size, rather than hand back an
    /// empty reader under a size it never delivers.
    #[test]
    fn a_legacy_directory_entry_lists_and_reads_as_the_normal_path_does() {
        let rows: [(u32, &[u8]); 6] = [
            (0x0200_0000, b""),
            (1, b""),
            (0, b""),
            (0, b"x"),
            (0, b"0123456789"),
            (5, b"abc"),
        ];
        for (declared, payload) in rows {
            let (stored, stored_read) =
                list_and_read_first(&hand_built_with_method("sample/", declared, 0, payload));
            let what = format!("declared {declared}, payload {} bytes", payload.len());
            assert_eq!(stored.kind, EntryKind::Dir, "{what}");
            assert_eq!(stored.size, Some(u64::from(declared)), "{what}");
            let expected = if declared == 0 && payload.is_empty() {
                Ok(0)
            } else {
                Err(5)
            };
            assert_eq!(stored_read, expected, "stored: {what}");
            for method in [1u16, 6] {
                let (legacy, legacy_read) = list_and_read_first(&hand_built_with_method(
                    "sample/", declared, method, payload,
                ));
                let what = format!("method {method}, {what}");
                assert_eq!(legacy.kind, stored.kind, "{what}");
                assert_eq!(legacy.size, stored.size, "{what}");
                assert_eq!(legacy_read, stored_read, "{what}");
            }
        }
    }

    /// A directory whose compressed size claims bytes the archive does not
    /// hold (the payload runs past EOF) is corrupt (exit 5) on both paths,
    /// never a panic or a short success.
    #[test]
    fn a_legacy_directory_payload_past_the_end_is_corrupt() {
        // The outcome of listing and reading the one entry: a read giving
        // exit 5, or a listing refusal with its exit code. An entry that
        // lists and reads cleanly, or no entry at all, is -1 (a failure).
        let outcome = |method: u16| -> std::result::Result<(), i32> {
            let mut bytes = hand_built_with_method("sample/", 0, method, b"0123456789");
            // Central directory csize (offset 20 in the record) claims more.
            let cd = 30 + "sample/".len() + 10;
            assert_eq!(&bytes[cd..cd + 4], &SIG_CENTRAL_HEADER);
            bytes[cd + 20..cd + 24].copy_from_slice(&0x0100_0000u32.to_le_bytes());
            let mut ar = open_seekable(&bytes);
            match ar.next_entry() {
                Ok(Some(mut e)) => e
                    .reader()
                    .read_to_end(&mut Vec::new())
                    .map(|_| ())
                    .map_err(|err| Error::from_decode_io(err).exit_code()),
                Ok(None) => Err(-1),
                Err(err) => Err(err.exit_code()),
            }
        };
        let stored = outcome(0);
        assert_eq!(stored, Err(5), "stored");
        for method in [1u16, 6] {
            assert_eq!(
                outcome(method),
                stored,
                "method {method} differs from stored"
            );
        }
    }

    /// The forward-only (pipe) rung keeps refusing a legacy method, for a
    /// directory carrying a payload as for a file: the change above touches
    /// the seekable path only.
    #[test]
    fn a_legacy_method_stays_refused_on_the_forward_rung() {
        for method in [1u16, 6] {
            for name in ["sample/", "f.txt"] {
                let bytes = hand_built_with_method(name, 0, method, b"x");
                let err = read_all_forward(&bytes).expect_err("forward must refuse");
                assert_eq!(err.exit_code(), 3, "method {method}, {name}");
            }
        }
    }

    /// A shrink or implode FILE entry that decodes to fewer bytes than it
    /// declares is refused on read (exit 5), never a short success:
    /// `decode_legacy` compares the decoded length with the declared one
    /// exactly, before the CRC-32.
    #[test]
    fn a_short_legacy_file_entry_is_corrupt() {
        for method in [1u16, 6] {
            let (meta, read) =
                list_and_read_first(&hand_built_with_method("f.txt", 10, method, b""));
            assert_eq!(meta.kind, EntryKind::File);
            assert_eq!(meta.size, Some(10));
            assert_eq!(read, Err(5), "method {method}");
        }
    }
}

#[cfg(test)]
mod confirm_tests {
    use super::*;
    use crate::confirm_test::{
        assert_every_cut_confirms, assert_never_panics, assert_own_archives_confirm, matches_magic,
        write_archive,
    };
    use stuffr_core::ConfirmFn;

    fn confirm_fn() -> ConfirmFn {
        meta().confirm.expect("zip registers a confirm function")
    }

    /// The registered function judging a window (`whole` false): what
    /// every test below that cuts a stream short means.
    fn confirm() -> impl Fn(&[u8]) -> bool {
        |p| confirm_fn()(p, false)
    }

    /// A whole stream that stops inside the header the check reads is
    /// refused; the same bytes as a window onto a longer stream are not.
    #[test]
    fn confirm_refuses_a_whole_stream_cut_inside_its_header() {
        use crate::confirm_test::assert_whole_cuts_refused as refused;
        let s = one_entry();
        let name = usize::from(u16::from_le_bytes([s[26], s[27]]));
        refused("zip", confirm_fn(), &s[..30 + name], 0);
        assert!(!confirm_fn()(b"PK\x03\x04\x14", true));
        assert!(confirm_fn()(b"PK\x03\x04\x14", false));
    }

    fn one_entry() -> Vec<u8> {
        write_archive(
            &Zip,
            &CreateOpts::default(),
            &[(EntryMeta::file("a.txt"), b"alpha".to_vec())],
        )
        .unwrap()
    }

    /// Every entry codec this build writes, so each method number the
    /// writer can put in a local header is seen; and the empty archive,
    /// which is a bare end-of-central-directory record. That record must be
    /// whole (22 bytes, always inside the window of a file long enough to
    /// be one), so the cuts start at 22; a local header's shorter cuts are
    /// checked on their own.
    #[test]
    fn confirm_accepts_own_output() {
        assert_every_cut_confirms("one entry", confirm_fn(), &one_entry(), 4);
        let mut checked = 0;
        for codec in ["store", "deflate", "bzip2", "xz", "zstd"] {
            let opts = CreateOpts {
                entry_codec: Some(FormatId::new(codec)),
                ..Default::default()
            };
            if Zip
                .create(PlainSink::new(Box::new(io::sink())), &opts)
                .is_err()
            {
                continue;
            }
            checked += assert_own_archives_confirm(codec, &Zip, &opts, &meta(), 22);
        }
        assert!(checked >= 14, "only {checked} zip archives were checked");
        let empty = write_archive(&Zip, &CreateOpts::default(), &[]).unwrap();
        assert!(empty.starts_with(b"PK\x05\x06"));
        assert!(confirm()(&empty));
    }

    #[test]
    fn confirm_rejects_magic_plus_noise() {
        let good = one_entry();
        assert!(confirm()(&good));
        let mut version = good.clone();
        version[4] = 64;
        assert!(!confirm()(&version), "version needed 6.4");
        for method in [11u16, 13, 21, 92, 100, 0xffff] {
            let mut bad = good.clone();
            bad[8..10].copy_from_slice(&method.to_le_bytes());
            assert!(!confirm()(&bad), "method {method}");
        }
        let mut nameless = good.clone();
        nameless[26..28].fill(0);
        assert!(!confirm()(&nameless), "an empty name");
        let mut huge_name = good;
        huge_name[26..28].copy_from_slice(&5000u16.to_le_bytes());
        assert!(!confirm()(&huge_name), "a name longer than the window");
    }

    /// The version-needed field's upper byte is a host system in APPNOTE
    /// 4.4.3 ("mapped as above", i.e. as version made by): only the lower
    /// byte is a version. Every method APPNOTE 4.4.5 defines is accepted.
    #[test]
    fn confirm_accepts_every_defined_method_and_a_host_byte() {
        let mut good = one_entry();
        good[5] = 3;
        assert!(confirm()(&good), "version needed with a Unix host byte");
        for method in (0u16..=10).chain([12, 14, 16, 18, 19, 20]).chain(93..=99) {
            good[8..10].copy_from_slice(&method.to_le_bytes());
            assert!(confirm()(&good), "method {method}");
        }
    }

    #[test]
    fn the_empty_archive_record_must_be_whole_and_empty() {
        let empty = write_archive(&Zip, &CreateOpts::default(), &[]).unwrap();
        assert!(confirm()(&empty));
        assert!(!confirm()(&empty[..21]), "a cut record");
        let mut counted = empty.clone();
        counted[10] = 1;
        assert!(!confirm()(&counted), "an entry count of one");
        let mut on_disk = empty;
        on_disk[8] = 1;
        assert!(!confirm()(&on_disk), "an entry count on this disk of one");
        // `PK\x05\x06` then text: no empty archive.
        let text = b"PK\x05\x06 is the end-of-central-directory signature".to_vec();
        assert!(matches_magic(&meta(), &text));
        assert!(!confirm()(&text));
    }

    #[test]
    fn confirm_never_panics_on_short_input() {
        assert_never_panics(confirm_fn(), &one_entry());
        let empty = write_archive(&Zip, &CreateOpts::default(), &[]).unwrap();
        assert_never_panics(confirm_fn(), &empty);
    }
}
