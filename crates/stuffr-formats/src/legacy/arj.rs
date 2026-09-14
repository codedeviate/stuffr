//! ARJ, read-only, via `unarj-rs`.
//!
//! # ARJ is the constrained case, and its caps differ from LHA's
//!
//! `unarj_rs::arj_archive::ArjArchieve<T>` requires `T: Read + Seek` — unlike
//! `delharc::LhaDecodeReader`, which streams off a plain `Read` with no seek
//! bound anywhere in its API (see `legacy::lha`'s own module doc). And where
//! `LhaDecodeReader` decodes incrementally through its own `Read` impl,
//! `ArjArchieve::read(&header)` hands back the WHOLE entry as one
//! `Vec<u8>` — there is no per-entry streaming reader to speak of. Both
//! differences are structural, not implementation slack this module could
//! work around:
//!
//! ```text
//! ContainerCaps {
//!     needs_seek: true,
//!     ..ContainerCaps::read_only()   // read: true, write: false,
//! }                                  // forward_parse: false
//! ```
//!
//! `forward_parse: false` together with `needs_seek: true` means
//! `stuffr_core::ladder::resolve` never hands this container a genuinely
//! forward-only source (see that function's rung order: rung 2, the
//! forward-parse rung, is gated on `caps.forward_parse`, which this
//! container does not claim). A file opens at `Rung::Exact` directly; a pipe
//! is spooled to a temp file first and opens at `Rung::Spilled` — a LOWER
//! rung than `Exact` but still `is_authoritative()` (see
//! `stuffr_core::fidelity::Rung`), so a piped `stuffr list backup.arj` still
//! works and the fidelity report says how it got there.
//!
//! # The bound before the allocation
//!
//! `ArjArchieve::read` (crate 0.2.1, `arj_archive.rs`) is:
//!
//! ```text
//! pub fn read(&mut self, header: &LocalFileHeader) -> io::Result<Vec<u8>> {
//!     let mut compressed_buffer = vec![0; header.compressed_size as usize];
//!     self.reader.read_exact(&mut compressed_buffer)?;
//!     let uncompressed = match header.compression_method {
//!         CompressionMethod::Stored => compressed_buffer,
//!         CompressionMethod::CompressedMost | ... => {
//!             let mut decoder = ...;
//!             let mut decompressed_buffer = vec![0; header.original_size as usize];
//!             ...
//!         }
//!         ...
//!     };
//!     ...
//! }
//! ```
//!
//! Note the FIRST line: `compressed_buffer` is sized from `header.
//! compressed_size` and allocated **unconditionally**, for every
//! compression method, before the method is even inspected — the task
//! brief that added this module names `original_size` as the field to
//! guard, and that field matters too (a second `vec![0; header.
//! original_size]` for every method except `Stored`), but tracing the
//! crate's own source (there is no independent tool to check this fixture
//! or this reasoning against — see `fixtures/legacy/MANIFEST.md`) shows
//! `compressed_size` is allocated FIRST and unconditionally, so
//! [`refuse_if_over_ceiling`] is called on both fields, in that order,
//! before [`ArjRead::next_entry`] ever calls `read`. This is the same shape
//! `cpio.rs`'s `MAX_CPIO_NAME_LEN`/`refuse_an_oversized_namesize` and
//! `MAX_SYMLINK_TARGET_LEN`/`read_symlink_target` close: a header field
//! reaching an allocator before anything has validated it.
//!
//! **Why a fixed ceiling, not `DecodeOpts::memory_limit`:** the same reason
//! `cpio.rs` gives for its own two guards — `DecodeOpts::memory_limit`
//! binds a CODEC's dictionary/window allocation, but a container opens
//! through [`OpenOpts`], which carries no memory field at all. There is
//! nothing to bind against here; [`MAX_ARJ_ENTRY_LEN`] is a fixed structural
//! ceiling for the identical reason `MAX_CPIO_NAME_LEN` is.
//!
//! # Error mapping has no wildcard
//!
//! `unarj-rs` surfaces a bare `io::Error`, never a typed enum. Two things
//! matter about how it uses that type, and [`classify_arj_io`] handles both:
//!
//! - Every DELIBERATE failure the crate raises (a header checksum mismatch,
//!   a CRC-32 mismatch on the decoded payload, an unrecognised compression
//!   method) is `io::ErrorKind::InvalidData`, which [`Error::from_decode_io`]
//!   already folds onto [`Error::Corrupt`] (exit 5).
//! - Every structural read in the crate goes through `Read::read_exact`
//!   (`read_header`, `read_extended_headers`, `ArjArchieve::read`'s
//!   `compressed_buffer` fill), whose OWN contract is to raise
//!   `io::ErrorKind::UnexpectedEof` when the stream runs out before the
//!   requested length — exactly what "a header declares N bytes and the
//!   stream has fewer" looks like. Left unclassified this stays
//!   `Error::Io` (exit 1: "stuffr failed") via `from_decode_io`'s catch-all,
//!   which is wrong for a truncated archive — the identical shape
//!   `legacy::lha`'s `classify_lha_error` already documents and folds. A
//!   genuine SOURCE failure (a disk read error) keeps its own native
//!   `io::ErrorKind` all the way through: `read_exact` only substitutes
//!   `UnexpectedEof` for a clean end-of-input, never for an inner error
//!   that already carries its own kind.
//!
//! `create()` is [`Error::CapabilityUnavailable`] (exit 3), the same refusal
//! `Registry::require_container_writer` raises before ops ever reaches it (see
//! `lha.rs`'s twin): there never was an ARJ
//! encoder here, only a reader for archives the real, decades-old
//! `arj`/`unarj` tools wrote.
//!
//! An entry whose `compression_method` is `NoData`, `NoDataNoCrc` or
//! `Unknown` has no decoder in `unarj-rs` at all — `ArjArchieve::read`'s own
//! match falls to an arm that raises `io::ErrorKind::InvalidData` for these,
//! which would otherwise fold onto `Error::Corrupt` via the rule above. That
//! is the wrong answer: the archive is not damaged, this crate simply has no
//! decoder for that method. [`ArjRead::next_entry`] checks
//! `compression_method` itself, before calling `read`, and raises
//! [`Error::Unsupported`] (exit 3) directly for these three — the same
//! capability-vs-damage distinction `legacy::lha`'s `is_decoder_supported()`
//! check makes for an unsupported LHA method.
//!
//! # Entry kinds
//!
//! Only `FileType::Directory` gets special handling (no payload is decoded;
//! see [`ArjRead::next_entry`]). `Binary` and `Text7Bit` are
//! [`EntryKind::File`]. `VolumeLabel`, `ChapterLabel`, `CommentHeader` and
//! any `Unknown` value are [`EntryKind::Other`] — the kind that exists for
//! exactly this: an entry this container can read the bytes of but cannot
//! honestly call a plain file.
//!
//! # `by_index` has one honest answer, not two
//!
//! Unlike `legacy::lha` (which answers `Error::NotSeekable` on a genuinely
//! forward-only source and `Error::Unsupported` on a seekable one with no
//! index — two different callers, two different honest answers), ARJ's
//! `needs_seek: true` plus `forward_parse: false` means `resolve` never
//! hands this container a forward-only source at all (see the module doc
//! above). Every source [`Arj::open`] ever sees is seekable, so
//! [`ArjRead::by_index`] has exactly one answer on every call:
//! `Error::Unsupported`, naming that ARJ carries no entry index of its own
//! — `ArjArchieve` exposes only forward iteration via `get_next_entry`. This
//! routes `entries.rs`'s `by_index` fallback to a counted forward walk,
//! the same as `tar`/`ar`/`cpio` deliberately raising `Unsupported` on a
//! seekable source with no index of their own.
use std::io::{self, Read, Seek, SeekFrom};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use unarj_rs::arj_archive::ArjArchieve;
use unarj_rs::date_time::DosDateTime;
use unarj_rs::local_file_header::{CompressionMethod, FileType};

use stuffr_core::{
    ArchiveRead, ArchiveWrite, Container, ContainerCaps, CreateOpts, Entry, EntryKind, EntryMeta,
    Error, FidelityReport, FormatId, FormatMeta, MagicRule, OpenOpts, Resolved, Result, SeekRead,
    Sink, Source,
};

pub const ARJ: FormatId = FormatId::new("arj");

/// ARJ's header id, at offset 0 of both the main header and every local
/// file header — see `fixtures/legacy/MANIFEST.md` for the full envelope
/// this frames.
const ARJ_MAGIC: &[MagicRule] = &[MagicRule {
    offset: 0,
    bytes: &[0x60, 0xEA],
    format: ARJ,
}];

pub fn meta() -> FormatMeta {
    FormatMeta::container(ARJ, &["arj"], ARJ_MAGIC)
}

pub struct Arj;

impl Container for Arj {
    fn id(&self) -> FormatId {
        ARJ
    }

    fn caps(&self) -> ContainerCaps {
        // See `lha.rs`'s twin for why the constructor rather than a literal.
        // `needs_seek: true` is the one thing ARJ must override: `unarj-rs`
        // cannot read an archive at all without `Seek`.
        ContainerCaps {
            needs_seek: true,
            ..ContainerCaps::read_only()
        }
    }

    fn open(&self, resolved: Resolved, _o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
        let Resolved { source, report, .. } = resolved;
        let adapter = ArjSeekAdapter(source);
        let archive = ArjArchieve::new(adapter).map_err(classify_arj_io)?;
        Ok(Box::new(ArjRead {
            archive,
            report,
            done: false,
        }))
    }

    /// Unreachable through ops: `Registry::require_container_writer` reads
    /// `caps().write` and refuses first, exactly as `require_encoder` does
    /// for a decode-only codec. This is the trait-level backstop, and it
    /// answers the SAME error the registry raises — see `lha.rs`'s twin.
    fn create(&self, _dst: Box<dyn Sink>, _o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
        Err(Error::CapabilityUnavailable {
            format: ARJ,
            available: "read",
            requested: "written",
        })
    }
}

/// Presents a ladder [`Source`] as the `Read + Seek` `ArjArchieve` requires.
///
/// Only constructed once the ladder has already guaranteed a seekable
/// source — `Arj::caps` declares `needs_seek: true` and `forward_parse:
/// false`, so `stuffr_core::ladder::resolve` either hands this container an
/// already-seekable rung (`Exact`) or spools a pipe to a temp file first
/// (`Spilled`, still seekable), never a genuinely forward-only source (see
/// that function's own rung order). `as_seek` returning `None` is therefore
/// unreachable in practice; it is reported as an I/O error rather than a
/// panic because `Seek` has no other channel — the same choice `zip.rs`'s
/// own `SeekAdapter` makes for the identical situation.
struct ArjSeekAdapter(Box<dyn Source>);

impl Read for ArjSeekAdapter {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Seek for ArjSeekAdapter {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let seek: &mut dyn SeekRead = self
            .0
            .as_seek()
            .ok_or_else(|| io::Error::other("arj: source reported seekable but cannot seek"))?;
        seek.seek(pos)
    }
}

/// See this module's doc for why `compressed_size` matters here as much as
/// `original_size`: `ArjArchieve::read` allocates a `compressed_size`
/// buffer unconditionally, for every compression method, before it even
/// inspects which method the entry uses.
///
/// 256 MiB — generous headroom for any legitimate ARJ archive (a DOS/16-bit
/// era format, predating the multi-gigabyte single files common today) while
/// staying well short of what a hostile or merely corrupt header could
/// otherwise force this build to allocate for one entry. Fixed rather than
/// derived from `DecodeOpts::memory_limit`; see this module's doc for why a
/// container has no such knob to read.
const MAX_ARJ_ENTRY_LEN: u64 = 256 * 1024 * 1024;

/// Refuses a header field that would drive an allocation past
/// [`MAX_ARJ_ENTRY_LEN`], before that allocation is ever attempted.
fn refuse_if_over_ceiling(name: &str, declared: u32, field: &str) -> Result<()> {
    if u64::from(declared) > MAX_ARJ_ENTRY_LEN {
        return Err(Error::ResourceLimit(format!(
            "entry `{name}` declares {declared} bytes of {field}, past the \
             {MAX_ARJ_ENTRY_LEN}-byte ceiling this container decodes whole and cannot stream; \
             no legitimate ARJ entry is this large"
        )));
    }
    Ok(())
}

/// Classifies an `io::Error` one of this module's own calls into `unarj-rs`
/// raises — see this module's doc for why `UnexpectedEof` needs folding
/// onto [`Error::Corrupt`] here, the same shape `legacy::lha`'s
/// `classify_lha_error` already documents for the identical reason.
fn classify_arj_io(e: io::Error) -> Error {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        return Error::Corrupt(e.to_string());
    }
    Error::from_decode_io(e)
}

/// Converts an ARJ/DOS-packed modification timestamp into a `SystemTime`,
/// or `None` when the packed value has no valid calendar date — the shape
/// a minimal or hand-built entry uses to declare no timestamp at all
/// (`sample.arj`'s own two entries do exactly this; see
/// `fixtures/legacy/MANIFEST.md`).
fn dos_mtime(dt: DosDateTime) -> Option<SystemTime> {
    let (year, month, day) = (
        i64::from(dt.year()),
        u32::from(dt.month()),
        u32::from(dt.day()),
    );
    if month == 0 || month > 12 || day == 0 || day > 31 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let secs = days
        .checked_mul(86_400)?
        .checked_add(i64::from(dt.hour()) * 3600)?
        .checked_add(i64::from(dt.minute()) * 60)?
        .checked_add(i64::from(dt.second()))?;
    u64::try_from(secs)
        .ok()
        .map(|s| UNIX_EPOCH + Duration::from_secs(s))
}

/// Days since the Unix epoch (1970-01-01) for a proleptic-Gregorian
/// `(year, month, day)` — Howard Hinnant's `days_from_civil` algorithm
/// (public domain; <http://howardhinnant.github.io/date_algorithms.html>),
/// used because converting a DOS-packed timestamp needs exactly this and
/// nothing in this workspace already provides it — `stuffr-core` takes no
/// date/calendar dependency, and this is the one site in `stuffr-formats`
/// that needs one, small enough to write out rather than add a crate for.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (i64::from(m) + 9) % 12; // [0, 11]
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

struct ArjRead {
    archive: ArjArchieve<ArjSeekAdapter>,
    report: FidelityReport,
    /// Set once `get_next_entry` answers `Ok(None)` (clean end of archive)
    /// or any error was raised — either way, nothing more will be read.
    done: bool,
}

impl ArchiveRead for ArjRead {
    fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
        if self.done {
            return Ok(None);
        }

        let header = match self.archive.get_next_entry() {
            Ok(Some(h)) => h,
            Ok(None) => {
                self.done = true;
                return Ok(None);
            }
            Err(e) => {
                self.done = true;
                return Err(classify_arj_io(e));
            }
        };

        let name = header.name.clone();
        let mtime = dos_mtime(header.date_time_modified);

        if header.file_type == FileType::Directory {
            // A directory carries no payload this container cares about.
            // `skip` advances the underlying reader past whatever bytes the
            // header still declares (ordinarily zero for a directory)
            // rather than decoding them — the crate has no other way to
            // reach the NEXT header, since `get_next_entry` does not skip
            // unread payload itself (see this module's doc / the fixture's
            // own envelope layout in MANIFEST.md).
            if let Err(e) = self.archive.skip(&header) {
                self.done = true;
                return Err(classify_arj_io(e));
            }
            let meta = EntryMeta {
                name,
                size: Some(0),
                compressed_size: Some(0),
                mtime,
                kind: EntryKind::Dir,
                ..Default::default()
            };
            return Ok(Some(Entry::new(meta, Box::new(io::empty()))));
        }

        // A capability gap, not damage: `ArjArchieve::read` has no decoder
        // for any of these three and raises `io::ErrorKind::InvalidData`,
        // which `classify_arj_io` would otherwise fold onto `Error::Corrupt`
        // — see this module's doc. Checked before the size guard below: an
        // entry this build cannot decode at all should say so, regardless
        // of how large it claims to be.
        if matches!(
            header.compression_method,
            CompressionMethod::NoData
                | CompressionMethod::NoDataNoCrc
                | CompressionMethod::Unknown(_)
        ) {
            self.done = true;
            return Err(Error::Unsupported(format!(
                "entry `{name}` uses ARJ compression method {:?}, which this build cannot decode",
                header.compression_method
            )));
        }

        // THE GUARD — see this module's doc and MAX_ARJ_ENTRY_LEN's own.
        // Must run before `self.archive.read` below: that call allocates a
        // buffer sized by these two fields, unconditionally, before it has
        // validated anything else about the entry.
        if let Err(e) = refuse_if_over_ceiling(&name, header.compressed_size, "compressed data")
            .and_then(|()| refuse_if_over_ceiling(&name, header.original_size, "decompressed data"))
        {
            self.done = true;
            return Err(e);
        }

        let data = match self.archive.read(&header) {
            Ok(d) => d,
            Err(e) => {
                self.done = true;
                return Err(classify_arj_io(e));
            }
        };

        // See this module's doc's "Entry kinds" section: only `Binary` and
        // `Text7Bit` are plain files. `VolumeLabel`, `ChapterLabel`,
        // `CommentHeader` and any `Unknown` value are `EntryKind::Other` —
        // this container can hand back their bytes but cannot honestly call
        // them a plain file.
        let kind = match header.file_type {
            FileType::Binary | FileType::Text7Bit => EntryKind::File,
            _ => EntryKind::Other,
        };

        let meta = EntryMeta {
            name,
            size: Some(u64::from(header.original_size)),
            compressed_size: Some(u64::from(header.compressed_size)),
            mtime,
            kind,
            ..Default::default()
        };
        Ok(Some(Entry::new(meta, Box::new(io::Cursor::new(data)))))
    }

    fn by_index(&mut self, _index: usize) -> Result<Entry<'_>> {
        // See this module's doc's "`by_index` has one honest answer, not
        // two" section: every source this container is ever opened over is
        // seekable (`needs_seek: true`, `forward_parse: false`), so this is
        // never reached with a genuinely forward-only source, and the one
        // honest answer is that ARJ carries no index at all.
        Err(Error::Unsupported(
            "ARJ carries no entry index; entries can only be reached by reading forward".into(),
        ))
    }

    fn fidelity(&self) -> &FidelityReport {
        &self.report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stuffr_core::testing::{ContainerFixture, ExpectedEntry, assert_container_conforms_with};
    use stuffr_core::{CreateOpts, OpenOpts, PlainSink, ReaderSource, StreamPolicy};

    const SAMPLE_ARJ: &[u8] = include_bytes!("../../fixtures/legacy/sample.arj");

    const ARJ_EXPECTED: &[ExpectedEntry] = &[
        ExpectedEntry {
            name: "sample/hello.txt",
            content: b"alpha\n",
        },
        ExpectedEntry {
            name: "sample/sub/b.bin",
            content: b"beta\n",
        },
    ];

    fn arj_fixture() -> ContainerFixture {
        ContainerFixture {
            bytes: SAMPLE_ARJ,
            expected: ARJ_EXPECTED,
            provenance: "hand-built ARJ archive (two Stored/method-0 entries), constructed by \
                         tracing unarj-rs 0.2.1's own parser source field-by-field \
                         (local_file_header.rs, main_header.rs, arj_archive.rs) — NOT verified \
                         against any independent ARJ reader, since none is installed on this \
                         machine and none is obtainable (arj/unarj are not in Homebrew). This \
                         is the WEAKEST provenance in the phase: a mistake shared between this \
                         fixture's construction and unarj-rs's own parser would agree with \
                         itself and pass undetected. See fixtures/legacy/MANIFEST.md's \
                         `sample.arj` entry and this module's `build_arj` for the exact byte \
                         layout, and the same equality test that pins the checked-in fixture \
                         to it.",
        }
    }

    /// CRC-32 (IEEE 802.3 / ISO-HDLC — poly 0xEDB88320 reflected, init and
    /// xorout 0xFFFFFFFF), the same variant zlib, gzip, PNG and `crc32fast`
    /// (the crate `unarj-rs` itself uses internally, for both its header
    /// envelope checksum and each entry's `original_crc32`) all use.
    /// `unarj-rs` does not expose `crc32fast` or any checksum helper of its
    /// own, so this fixture builder needs an independent implementation —
    /// verified against the standard CRC-32 check value below, not against
    /// `crc32fast` directly (no such cross-check is possible without adding
    /// a new dependency for a single test-only computation).
    fn crc32_ieee(data: &[u8]) -> u32 {
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

    #[test]
    fn crc32_ieee_matches_the_standard_check_value() {
        // The universally-cited CRC-32/ISO-HDLC check value for the ASCII
        // string "123456789" — the same value every implementation of this
        // algorithm (zlib, crc32fast, etc.) is verified against.
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
    }

    /// Wraps `content` (either a main header's or a local file header's
    /// parsed fields) in ARJ's header envelope: magic, a little-endian u16
    /// content length, the content itself, a little-endian u32 CRC-32 over
    /// the content, and a trailing zero `u16` — the "no extended headers"
    /// terminator `unarj_rs::arj_archive::read_extended_headers` expects
    /// immediately after every header (main or local), traced from that
    /// function's own source. See `MANIFEST.md` for the full envelope.
    fn wrap_header(content: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 2 + content.len() + 4 + 2);
        out.extend_from_slice(&[0x60, 0xEA]);
        out.extend_from_slice(&(content.len() as u16).to_le_bytes());
        out.extend_from_slice(content);
        out.extend_from_slice(&crc32_ieee(content).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // no extended headers
        out
    }

    /// The archive main header's content, traced field-by-field from
    /// `unarj_rs::main_header::MainHeader::load_from`. `header_size` (the
    /// FIRST byte of the content, distinct from the outer envelope's own
    /// u16 length) is 30 — at or below `FIRST_HDR_SIZE` (34), so the
    /// crate's own conditional 4-byte extension block (arj_protection_
    /// factor, flags2, two reserved bytes) is not read, and this builder
    /// does not write it. An empty name and an empty comment follow as
    /// lone NUL bytes.
    fn build_main_header() -> Vec<u8> {
        let mut content = Vec::with_capacity(32);
        content.push(30); // header_size (inner byte; no extension)
        content.push(0); // archiver_version_number
        content.push(0); // min_version_to_extract
        content.push(2); // host_os = Unix
        content.push(0); // flags
        content.push(0); // security_version
        content.push(2); // file_type (the ARJ spec requires 2 for the main header)
        content.push(0); // reserved (skipped by the parser)
        content.extend_from_slice(&0u32.to_le_bytes()); // creation_date_time
        content.extend_from_slice(&0u32.to_le_bytes()); // compr_size
        content.extend_from_slice(&0u32.to_le_bytes()); // archive_size
        content.extend_from_slice(&0u32.to_le_bytes()); // security_envelope
        content.extend_from_slice(&0u16.to_le_bytes()); // file_spec_position
        content.extend_from_slice(&0u16.to_le_bytes()); // security_envelope_length
        content.push(0); // encryption_version
        content.push(0); // last_chapter
        assert_eq!(
            content.len(),
            30,
            "must match the inner header_size byte written above"
        );
        content.push(0); // name terminator (empty name)
        content.push(0); // comment terminator (empty comment)
        wrap_header(&content)
    }

    /// One local file entry's envelope PLUS its raw payload bytes, traced
    /// field-by-field from `unarj_rs::local_file_header::LocalFileHeader::
    /// load_from`. `compression_method` 0 (`Stored`) throughout, so the
    /// payload is the plaintext verbatim — no compression algorithm needs
    /// reimplementing to build this fixture, the same choice `legacy::lha`'s
    /// `sample.lzh` makes with `-lh0-`. `header_size` is 30 for the same
    /// reason as the main header above (`STD_HDR_SIZE`, no extension).
    fn build_local_file_entry(name: &str, content: &[u8]) -> Vec<u8> {
        let mut header = Vec::with_capacity(30 + name.len() + 2);
        header.push(30); // header_size (inner byte; no extension)
        header.push(0); // archiver_version_number
        header.push(0); // min_version_to_extract
        header.push(2); // host_os = Unix
        header.push(0); // arj_flags
        header.push(0); // compression_method = Stored
        header.push(0); // file_type = Binary
        header.push(0); // reserved (skipped by the parser)
        header.extend_from_slice(&0u32.to_le_bytes()); // date_time_modified
        header.extend_from_slice(&(content.len() as u32).to_le_bytes()); // compressed_size
        header.extend_from_slice(&(content.len() as u32).to_le_bytes()); // original_size
        header.extend_from_slice(&crc32_ieee(content).to_le_bytes()); // original_crc32
        header.extend_from_slice(&0u16.to_le_bytes()); // file_spec_position
        header.extend_from_slice(&0u16.to_le_bytes()); // file_access_mode
        header.push(0); // first_chapter
        header.push(0); // last_chapter
        assert_eq!(
            header.len(),
            30,
            "must match the inner header_size byte written above"
        );
        header.extend_from_slice(name.as_bytes());
        header.push(0); // name terminator
        header.push(0); // comment terminator (empty comment)

        let mut out = wrap_header(&header);
        out.extend_from_slice(content); // Stored: payload bytes verbatim
        out
    }

    /// Builds a complete ARJ archive: the main header, each `(name,
    /// content)` entry in order, and the end-of-archive marker — magic
    /// bytes followed by a zero-length u16, which
    /// `unarj_rs::arj_archive::read_header` recognises as "no more headers"
    /// WITHOUT reading a CRC after it (its own `if header_size == 0 {
    /// return Ok(Vec::new()) }` returns before that read). See
    /// `MANIFEST.md` for the full envelope this mirrors.
    fn build_arj(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = build_main_header();
        for (name, content) in entries {
            out.extend_from_slice(&build_local_file_entry(name, content));
        }
        out.extend_from_slice(&[0x60, 0xEA]);
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    /// `sample.arj` is checked in rather than built at test time (the same
    /// choice every other fixture in this tree makes — see
    /// `fixtures/legacy/MANIFEST.md`), but unlike `sample.lzh`'s throwaway,
    /// unchecked-in Python script, `build_arj` above is real, checked-in
    /// Rust — this test is what makes the fixture RE-DERIVABLE: run it, and
    /// the checked-in bytes are reproduced from first principles, in the
    /// same repository, rather than merely documented as having been
    /// reproduced once.
    #[test]
    fn the_checked_in_fixture_matches_its_own_construction_recipe() {
        let built = build_arj(&[
            ("sample/hello.txt", b"alpha\n"),
            ("sample/sub/b.bin", b"beta\n"),
        ]);
        assert_eq!(
            built, SAMPLE_ARJ,
            "sample.arj must be exactly what build_arj produces — see MANIFEST.md"
        );
    }

    #[test]
    fn arj_conforms() {
        let fx = arj_fixture();
        assert_container_conforms_with(&Arj, &meta(), &fx);
    }

    #[test]
    fn capabilities_and_metadata_match_the_format() {
        let c = Arj.caps();
        assert!(c.read && !c.write);
        assert!(
            !c.forward_parse && c.needs_seek,
            "ArjArchieve needs Seek and has no forward-only decode path; see this module's doc"
        );
        let m = meta();
        assert_eq!(m.id, ARJ);
        assert_eq!(m.extensions, &["arj"]);
    }

    #[test]
    fn create_is_refused_as_a_capability_limit_not_a_panic() {
        match Arj.create(
            PlainSink::new(Box::new(stuffr_core::testing::SharedBuf::new())),
            &CreateOpts::default(),
        ) {
            Err(err) => {
                // The SAME variant `Registry::require_container_writer`
                // raises — see `lha.rs`'s twin.
                assert!(
                    matches!(err, Error::CapabilityUnavailable { .. }),
                    "got {err:?}"
                );
                assert_eq!(err.exit_code(), 3);
            }
            Ok(_) => panic!("ARJ must refuse to write"),
        }
    }

    fn open_seekable(bytes: &[u8]) -> Box<dyn ArchiveRead> {
        let path = std::env::temp_dir().join(format!(
            "stuffr-arj-seekable-{}-{:p}.arj",
            std::process::id(),
            bytes
        ));
        std::fs::write(&path, bytes).unwrap();
        let src: Box<dyn Source> = Box::new(stuffr_core::FileSource::open(&path).unwrap());
        let _ = std::fs::remove_file(&path);
        let resolved = stuffr_core::resolve(src, ARJ, Arj.caps(), &StreamPolicy::default())
            .expect("resolve over a seekable source");
        Arj.open(resolved, &OpenOpts::default()).expect("open")
    }

    /// `by_index` has exactly one answer on this container, on every source
    /// shape it can ever actually be opened over — see this module's doc.
    #[test]
    fn by_index_is_always_unsupported() {
        let mut ar = open_seekable(SAMPLE_ARJ);
        let err = ar
            .by_index(0)
            .expect_err("ARJ has no index to index into, on any source shape it opens over");
        assert!(
            matches!(err, Error::Unsupported(_)),
            "expected Error::Unsupported, got {err:?}"
        );
        assert_eq!(err.exit_code(), 3);
    }

    /// A pipe still opens: the ladder spools it to a temp file first
    /// (`Rung::Spilled`), which `is_authoritative()` accepts, so every
    /// entry — names and content both — reads back correctly, and the
    /// fidelity report says how it got there rather than claiming `Exact`.
    #[test]
    fn a_piped_source_is_spooled_and_reads_back_correctly() {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(io::Cursor::new(SAMPLE_ARJ)));
        let resolved = stuffr_core::resolve(src, ARJ, Arj.caps(), &StreamPolicy::default())
            .expect("a pipe must still resolve — ARJ's caps make the ladder spool it");
        assert_eq!(
            resolved.rung,
            stuffr_core::Rung::Spilled,
            "needs_seek + !forward_parse must spool a pipe, not forward-parse it"
        );
        let mut ar = Arj
            .open(resolved, &OpenOpts::default())
            .expect("open a spooled source");
        assert!(
            ar.fidelity().rung.is_authoritative(),
            "Spilled must be reported as authoritative"
        );
        let mut got = Vec::new();
        while let Some(mut entry) = ar.next_entry().expect("next_entry over a spooled source") {
            let name = entry.meta().name.clone();
            let mut data = Vec::new();
            entry
                .reader()
                .read_to_end(&mut data)
                .expect("read spooled entry");
            got.push((name, data));
        }
        let want: Vec<(String, Vec<u8>)> = ARJ_EXPECTED
            .iter()
            .map(|e| (e.name.to_string(), e.content.to_vec()))
            .collect();
        assert_eq!(got, want, "a spooled read must recover every entry");
    }

    /// Step 6 (the highest-risk line in this task): an entry declaring an
    /// absurd size must be refused WITHOUT the allocation `ArjArchieve::
    /// read` would otherwise perform. A test that only checks the error
    /// code passes even if the bytes are allocated and then rejected —
    /// which is the entire bug (see `cpio.rs`'s
    /// `refuses_an_absurd_namesize_before_the_allocation_it_would_size` for
    /// the same technique). This is proven STRUCTURALLY, not by
    /// instrumenting the allocator: [`refuse_if_over_ceiling`] runs from raw
    /// header fields, before [`ArjRead::next_entry`] ever calls `self.
    /// archive.read`, so a header this absurd can only be refused this way —
    /// there is no path in this module where `read` is reached first and
    /// merely rejected afterward. The declared size (1 GiB) is chosen to be
    /// unambiguously past `MAX_ARJ_ENTRY_LEN` (256 MiB) while staying safe
    /// to actually allocate if this guard were ever removed (unlike, say,
    /// `u32::MAX`, which risks exhausting memory on a small CI runner during
    /// the falsification exercise this task requires).
    #[test]
    fn an_entry_over_the_memory_limit_is_refused_before_it_is_allocated() {
        const ABSURD_SIZE: u32 = 1024 * 1024 * 1024; // 1 GiB, well past the 256 MiB ceiling
        let mut header = Vec::with_capacity(34);
        header.push(30);
        header.push(0);
        header.push(0);
        header.push(2);
        header.push(0);
        header.push(0); // compression_method = Stored
        header.push(0); // file_type = Binary
        header.push(0);
        header.extend_from_slice(&0u32.to_le_bytes());
        header.extend_from_slice(&ABSURD_SIZE.to_le_bytes()); // compressed_size
        header.extend_from_slice(&ABSURD_SIZE.to_le_bytes()); // original_size
        header.extend_from_slice(&0u32.to_le_bytes()); // original_crc32 (irrelevant: refused first)
        header.extend_from_slice(&0u16.to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes());
        header.push(0);
        header.push(0);
        header.push(b'x'); // name: "x"
        header.push(0);
        header.push(0);

        let mut bytes = build_main_header();
        bytes.extend_from_slice(&wrap_header(&header));
        // Deliberately no payload bytes follow — if the guard did not run
        // first, the crate would try to allocate a 1 GiB buffer before
        // ever noticing there is nothing behind it to read.
        bytes.extend_from_slice(&[0x60, 0xEA]);
        bytes.extend_from_slice(&0u16.to_le_bytes());

        let mut ar = open_seekable(&bytes);
        let err = ar
            .next_entry()
            .expect_err("an entry declaring 1 GiB must be refused");
        assert!(
            matches!(err, Error::ResourceLimit(_)),
            "an implausible declared size is this build refusing to allocate, not a verdict \
             that the archive is damaged; got {err:?}"
        );
        assert_eq!(err.exit_code(), 6, "ResourceLimit is exit 6: {err}");
        let msg = err.to_string();
        assert!(
            msg.contains(&ABSURD_SIZE.to_string()),
            "the message must name the declared size, got: {msg}"
        );
    }

    /// Pins the discovery this task's review (S1) found unpinned: the test
    /// above sets BOTH `original_size` and `compressed_size` to the same
    /// absurd value, so it cannot tell the two `refuse_if_over_ceiling`
    /// calls apart — deleting the `compressed_size` one left the whole
    /// suite green. Here `original_size` is small and legal on its own;
    /// only an absurd `compressed_size` can trip a refusal, so only the
    /// `compressed_size` half of the guard can save this test. Falsified:
    /// removing that call reproduces the review's finding exactly —
    /// `Corrupt("failed to fill whole buffer")`, `read_exact`'s own
    /// message, reachable only after the 1 GiB allocation already
    /// succeeded.
    #[test]
    fn an_absurd_compressed_size_alone_is_refused_before_it_is_allocated() {
        const ABSURD_SIZE: u32 = 1024 * 1024 * 1024; // 1 GiB, well past the ceiling
        const LEGAL_ORIGINAL_SIZE: u32 = 5; // small and legal, standing alone

        let mut header = Vec::with_capacity(34);
        header.push(30);
        header.push(0);
        header.push(0);
        header.push(2);
        header.push(0);
        header.push(0); // compression_method = Stored
        header.push(0); // file_type = Binary
        header.push(0);
        header.extend_from_slice(&0u32.to_le_bytes());
        header.extend_from_slice(&ABSURD_SIZE.to_le_bytes()); // compressed_size
        header.extend_from_slice(&LEGAL_ORIGINAL_SIZE.to_le_bytes()); // original_size
        header.extend_from_slice(&0u32.to_le_bytes()); // original_crc32 (irrelevant: refused first)
        header.extend_from_slice(&0u16.to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes());
        header.push(0);
        header.push(0);
        header.push(b'x'); // name: "x"
        header.push(0);
        header.push(0);

        let mut bytes = build_main_header();
        bytes.extend_from_slice(&wrap_header(&header));
        // Deliberately no payload bytes follow — if the compressed_size
        // guard did not run, the crate would try to allocate a 1 GiB
        // buffer before ever noticing there is nothing behind it to read.
        bytes.extend_from_slice(&[0x60, 0xEA]);
        bytes.extend_from_slice(&0u16.to_le_bytes());

        let mut ar = open_seekable(&bytes);
        let err = ar
            .next_entry()
            .expect_err("an entry declaring a 1 GiB compressed_size must be refused");
        assert!(
            matches!(err, Error::ResourceLimit(_)),
            "a legal original_size must not save an absurd compressed_size from refusal; \
             got {err:?}"
        );
        assert_eq!(err.exit_code(), 6, "ResourceLimit is exit 6: {err}");
        let msg = err.to_string();
        assert!(
            msg.contains(&ABSURD_SIZE.to_string()),
            "the message must name the declared compressed_size, got: {msg}"
        );
    }

    /// The regression guard for the test above: a legitimate entry well
    /// under the ceiling must still round-trip, so the guard is bounded by
    /// `MAX_ARJ_ENTRY_LEN` and not merely "any entry from a header this
    /// test built by hand."
    #[test]
    fn a_legitimate_entry_under_the_ceiling_still_round_trips() {
        let bytes = build_arj(&[("plain.txt", b"just an ordinary, small entry\n")]);
        let mut ar = open_seekable(&bytes);
        let entry = ar
            .next_entry()
            .expect("a legitimate entry must not be refused")
            .expect("must yield the one entry written");
        assert_eq!(entry.meta().name, "plain.txt");
    }

    /// A capability gap, not damage: `NoData`/`NoDataNoCrc`/`Unknown` have
    /// no decoder in `unarj-rs` at all. Falsifies S3 from the task-6 review:
    /// before the check in `next_entry` existed, this method's
    /// `io::ErrorKind::InvalidData` (raised by `ArjArchieve::read`'s own
    /// match) folded straight onto `Error::Corrupt` (exit 5) via
    /// `classify_arj_io`, telling a user the archive was damaged when this
    /// build simply cannot read that one method.
    #[test]
    fn an_unsupported_compression_method_is_reported_as_unsupported_not_corrupt() {
        let mut header = Vec::with_capacity(34);
        header.push(30);
        header.push(0);
        header.push(0);
        header.push(2);
        header.push(0);
        header.push(9); // compression_method = NoData: no decoder in unarj-rs
        header.push(0); // file_type = Binary
        header.push(0);
        header.extend_from_slice(&0u32.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes()); // compressed_size
        header.extend_from_slice(&0u32.to_le_bytes()); // original_size
        header.extend_from_slice(&0u32.to_le_bytes()); // original_crc32
        header.extend_from_slice(&0u16.to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes());
        header.push(0);
        header.push(0);
        header.push(b'x'); // name: "x"
        header.push(0);
        header.push(0);

        let mut bytes = build_main_header();
        bytes.extend_from_slice(&wrap_header(&header));
        bytes.extend_from_slice(&[0x60, 0xEA]);
        bytes.extend_from_slice(&0u16.to_le_bytes());

        let mut ar = open_seekable(&bytes);
        let err = ar.next_entry().expect_err(
            "an unsupported compression method must be refused, not produce a fake entry",
        );
        assert!(
            matches!(err, Error::Unsupported(_)),
            "expected Error::Unsupported, got {err:?}"
        );
        assert_eq!(err.exit_code(), 3);
    }

    /// `VolumeLabel`/`ChapterLabel`/`CommentHeader`/`Unknown` file types are
    /// `EntryKind::Other`, not `EntryKind::File` — falsifies S4 from the
    /// task-6 review.
    #[test]
    fn a_volume_label_entry_is_reported_as_other_not_file() {
        let content = b"VOL1";
        let mut header = Vec::with_capacity(34);
        header.push(30);
        header.push(0);
        header.push(0);
        header.push(2);
        header.push(0);
        header.push(0); // compression_method = Stored
        header.push(4); // file_type = VolumeLabel
        header.push(0);
        header.extend_from_slice(&0u32.to_le_bytes());
        header.extend_from_slice(&(content.len() as u32).to_le_bytes());
        header.extend_from_slice(&(content.len() as u32).to_le_bytes());
        header.extend_from_slice(&crc32_ieee(content).to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes());
        header.push(0);
        header.push(0);
        header.push(b'v'); // name: "v"
        header.push(0);
        header.push(0);

        let mut bytes = build_main_header();
        bytes.extend_from_slice(&wrap_header(&header));
        bytes.extend_from_slice(content);
        bytes.extend_from_slice(&[0x60, 0xEA]);
        bytes.extend_from_slice(&0u16.to_le_bytes());

        let mut ar = open_seekable(&bytes);
        let entry = ar
            .next_entry()
            .expect("a volume label entry must not be refused")
            .expect("must yield the one entry written");
        assert_eq!(entry.meta().kind, EntryKind::Other);
    }

    #[test]
    fn dos_mtime_recovers_a_known_calendar_date() {
        // 2024-01-15 10:30:00, packed DOS-style: ((2024-1980)<<25) |
        // (1<<21) | (15<<16) | (10<<11) | (30<<5) | (0/2).
        let packed: u32 = ((2024 - 1980) << 25) | (1 << 21) | (15 << 16) | (10 << 11) | (30 << 5);
        let got = dos_mtime(DosDateTime::new(packed)).expect("a valid date must convert");
        let secs = got.duration_since(UNIX_EPOCH).unwrap().as_secs();
        // 2024-01-15T10:30:00Z, independently computed.
        assert_eq!(secs, 1_705_314_600);
    }

    #[test]
    fn dos_mtime_is_none_for_an_all_zero_packed_value() {
        // month == 0, which sample.arj's own entries use (see MANIFEST.md).
        assert_eq!(dos_mtime(DosDateTime::new(0)), None);
    }

    #[test]
    fn days_from_civil_matches_the_epoch_anchor() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
    }
}
