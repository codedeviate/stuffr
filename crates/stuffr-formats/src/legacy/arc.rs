//! ARC/PAK, read-only, decoded from scratch.
//!
//! # No crate wraps this one — the decoders below are this project's own
//!
//! `lha` wraps `delharc` and `arj` wraps `unarj-rs`; ARC has no equivalent
//! this project may depend on. `unarc-rs` 0.6.3 is the one reference
//! implementation in reach and it is **disqualified as a dependency** for
//! three measured reasons (an unconditional MSRV of rustc 1.95 via
//! `delharc = "0.8"`, vendored C++ via `unrar`, and a second `zip`/`tar`
//! stack duplicating what `stuffr-formats` already carries — see
//! `fixtures/legacy/MANIFEST.md`). So its `tests/` corpus is borrowed as
//! BYTES and its `src/arc/` was read as a description of the FORMAT, the
//! same way Phase 3b traced `sample.arj`'s layout from `unarj-rs`'s parser
//! without running it. Nothing here imports or calls `unarc_rs`.
//!
//! That makes the CRC witness (container-conformance **fixture property
//! 10**) carry more weight for this container than for any other in the
//! tree: every decoder below is checked against the CRC-16 the ORIGINAL
//! archiving tool wrote into each header, decades ago — a witness owned
//! neither by this project nor by the crate whose corpus was borrowed.
//!
//! # Header layout, and the one place this reader is stricter than
//! `unarc-rs`
//!
//! An entry is a `0x1A` marker byte followed by a fixed 28-byte record:
//! `method(1) + name(13, NUL-padded) + compressed_size(u32 LE) +
//! date(u16 LE) + time(u16 LE) + crc16(u16 LE) + original_size(u32 LE)`,
//! then `compressed_size` bytes of payload. `0x1A 0x00` is the
//! end-of-archive marker: two bytes, with no record behind it.
//!
//! `unarc-rs`'s `read_header` **scans** for the next `0x1A`, skipping up to
//! 65535 bytes of anything else. This reader does not: a byte that is not
//! `0x1A` where a header must begin is [`Error::Corrupt`]. Resynchronising
//! past damage is how a reader silently turns entry data into headers, and
//! this project's standing rule is to refuse rather than salvage (see
//! `zip.rs`'s "index that reaches nothing" ruling for the same call).
//!
//! # Trailing bytes after the end-of-archive marker are IGNORED
//!
//! Measured, not assumed, and it binds this reader directly: the four
//! `.pak` fixtures each carry ten unexplained bytes (`fe 02 01 00 00 00 00
//! 00 fe 00`, byte-identical in all four) AFTER their `0x1A 0x00` marker,
//! while the six `.arc` fixtures carry none — see `MANIFEST.md`. So this
//! reader stops consuming input at the marker and never asserts that the
//! marker coincides with end of file. Several containers in this project
//! do assert full consumption; copying that here would fail on four
//! legitimate fixtures for a reason invisible without the manifest.
//! `trailing_bytes_after_the_end_of_archive_marker_are_ignored` pins it.
//!
//! # `date` is the LOW half of the packed u32, not the high half
//!
//! ARC's header stores `date` then `time`, so the little-endian `u32` at
//! that offset reads `date | (time << 16)`. `unarc-rs`'s `DosDateTime`
//! takes the opposite halves (`(dt.0 >> 25) & 0x7F` for the year), and on
//! `cpm.arc` that yields month `0` — not a date at all — for both entries,
//! where the reading used here yields 1985-11-20, a plausible stamp for a
//! CP/M archive. The evidence is that asymmetry plus the classic ARC
//! header's own field order; `mtime` is informational metadata no
//! conformance property checks, so the cost of being wrong is a wrong
//! timestamp, never wrong data.
//!
//! # Methods: four decoded, the rest refused as a capability limit
//!
//! | byte | method | here |
//! |---|---|---|
//! | 1, 2 | Unpacked (Stored) | decoded |
//! | 3 | Packed (RLE90) | decoded |
//! | 4 | Squeezed (RLE90 + Huffman) | decoded |
//! | 5, 6, 7 | Crunched, pre-8 variants | [`Error::Unsupported`] |
//! | 8 | Crunched (RLE90 + 9-12 bit LZW) | decoded |
//! | 9 | Squashed (13-bit LZW, no RLE) | decoded |
//! | 10 | Crushed | [`Error::Unsupported`] |
//! | 11 | Distilled | [`Error::Unsupported`] |
//!
//! **Method 1 is treated exactly as method 2**, and that is a ruling, not a
//! verified fact — see [`Method::from_byte`].
//!
//! **Methods 5, 6 and 7 are refused even though `unarc-rs` routes them
//! through its method-8 decoder.** The borrowed corpus contains no entry
//! using any of them (measured twice — see `MANIFEST.md`), and method 8 is
//! the only member of the family whose payload begins with the `12` maxbits
//! byte this decoder consumes; feeding a genuine method-5 stream to it would
//! produce garbage that the CRC would then report as `Corrupt` (exit 5) —
//! a claim that the ARCHIVE is damaged, when the truth is that this build
//! has never seen one. Exit 3 says the true thing. Enable them when a
//! fixture exists to prove them against, not before.
//!
//! **Squashed (9) came free with Crunched (8)** and is therefore decoded
//! rather than refused: it is the identical LZW engine at 13 bits with no
//! leading maxbits byte and no RLE pass. Crushed (10) and Distilled (11)
//! are entirely separate algorithms and stay refused.
//!
//! **One LZW branch has no borrowed fixture behind it: the CLEAR code.**
//! Every archive in the corpus compresses the same 11,357-byte LICENSE and
//! none of them fills the dictionary (measured: the largest reaches roughly
//! 3,800 of 4,096 entries), so no borrowed byte ever resets the table. The
//! branch is a faithful mirror of `unarc-rs`'s, which is in turn the
//! classic `compress`-lineage shape — including the detail that the slot
//! opened by the reset (256, the CLEAR code's own) is refilled from the
//! PRE-clear `oldcode`, not skipped. `a_clear_code_resets_the_dictionary_
//! and_reuses_its_own_slot` pins that behaviour against a hand-packed
//! code stream, which proves the branch runs and that CLEAR is not read as
//! an ordinary code; it does NOT prove agreement with a 1980s encoder,
//! because no archive here was written by one that reached this path.
//!
//! # An entry decodes whole, like ARJ and unlike LHA
//!
//! Three of the five decoded methods have no incremental form here, and the
//! CRC-16 is over the whole decoded output, so every entry is decoded into
//! memory and handed back as a `Cursor`. Two consequences, both the same as
//! `arj.rs`'s and stated for the same reason:
//!
//! - `--max-ratio` is a coarser bound here than on a streaming container,
//!   because there is no partial read to charge against it incrementally.
//!   The real backstop is [`MAX_ARC_ENTRY_LEN`], a fixed structural ceiling
//!   — checked against the header's declared `compressed_size` BEFORE the
//!   buffer that field would size is allocated, and against the decoded
//!   output as it grows.
//! - That ceiling is deliberately NOT `--memory-limit`: that flag binds a
//!   CODEC's own allocation through `DecodeOpts`, and a container opens
//!   through `OpenOpts`, which carries no memory field at all.
//!
//! # Error mapping has no wildcard
//!
//! - A method this build cannot decode → [`Error::Unsupported`] (exit 3).
//! - A declared `compressed_size` past [`MAX_ARC_ENTRY_LEN`], or a decode
//!   whose output grows past it → [`Error::ResourceLimit`] (exit 6),
//!   refused before the allocation it would size. Exit 6 rather than 5 for
//!   the reason `Error::exit_code`'s own doc gives: nothing was read and
//!   found self-contradictory, this build simply declined to allocate.
//! - Malformed framing — a missing marker, a truncated header, a payload
//!   shorter than its header declares, a node index outside the Huffman
//!   tree, an LZW prefix chain that cycles — → [`Error::Corrupt`] (exit 5).
//! - A decoded entry whose CRC-16 disagrees with the one its header stores
//!   → [`Error::Corrupt`] (exit 5), naming both values.
//! - A genuine source failure passes through as ITSELF ([`Error::Io`]),
//!   never relabelled as corruption: [`classify_arc_io`] folds
//!   `UnexpectedEof` alone, exactly as `lha.rs` and `arj.rs` do and for the
//!   same reason. Container-conformance fixture property 9 is the standing
//!   proof.
//! - `create()` → [`Error::CapabilityUnavailable`] (exit 3), the one shared
//!   sentence `Registry::require_container_writer` raises first.

use std::io::{self, Read};
use std::time::SystemTime;

use stuffr_core::{
    ArchiveRead, ArchiveWrite, Container, ContainerCaps, CorruptionDetection, CreateOpts, Entry,
    EntryKind, EntryMeta, Error, FidelityReport, FormatId, FormatMeta, MagicRule, OpenOpts,
    Resolved, Result, Sink, Source,
};

use super::crc::crc16_arc;
use super::dos;

pub const ARC: FormatId = FormatId::new("arc");

/// The marker byte every entry header opens with. `0x1A` is DOS's own
/// end-of-file character, which is exactly why ARC chose it: a `TYPE`d
/// archive stopped at the first entry instead of spraying the terminal.
const MARKER: u8 = 0x1A;

/// The fixed record following the marker: `method(1) + name(13) +
/// compressed_size(4) + date(2) + time(2) + crc16(2) + original_size(4)`.
const HEADER_LEN: usize = 28;

/// The NUL-padded name field's width inside that record.
const NAME_LEN: usize = 13;

/// One rule per method byte the format defines, rather than a single rule
/// on the bare `0x1A` marker.
///
/// `0x1A` alone is one byte, and a one-byte magic on a value as common as
/// Ctrl-Z would claim every file that happens to start with it. Pairing the
/// marker with the method byte makes the signature two bytes and confines
/// the second to the eleven values ARC ever assigned, which is as specific
/// as this format's framing allows — ARC carries no format identifier
/// beyond the first entry's own header.
///
/// Every value 1..=11 is listed, INCLUDING the four this build refuses to
/// decode: detection and capability are different questions, and an
/// unrecognised `license_crushed.pak` would be reported as an unknown
/// format (exit 2) rather than as ARC's Crushed method, which this build
/// cannot decode (exit 3). The second is the true answer.
///
/// `0x1A 0x00` — an empty archive, which is a valid two-byte ARC file — is
/// deliberately NOT listed: its second byte carries no evidence at all, so
/// the rule would be a one-byte magic wearing two bytes' clothes.
const ARC_MAGIC: &[MagicRule] = &[
    MagicRule {
        offset: 0,
        bytes: &[MARKER, 1],
        format: ARC,
    },
    MagicRule {
        offset: 0,
        bytes: &[MARKER, 2],
        format: ARC,
    },
    MagicRule {
        offset: 0,
        bytes: &[MARKER, 3],
        format: ARC,
    },
    MagicRule {
        offset: 0,
        bytes: &[MARKER, 4],
        format: ARC,
    },
    MagicRule {
        offset: 0,
        bytes: &[MARKER, 5],
        format: ARC,
    },
    MagicRule {
        offset: 0,
        bytes: &[MARKER, 6],
        format: ARC,
    },
    MagicRule {
        offset: 0,
        bytes: &[MARKER, 7],
        format: ARC,
    },
    MagicRule {
        offset: 0,
        bytes: &[MARKER, 8],
        format: ARC,
    },
    MagicRule {
        offset: 0,
        bytes: &[MARKER, 9],
        format: ARC,
    },
    MagicRule {
        offset: 0,
        bytes: &[MARKER, 10],
        format: ARC,
    },
    MagicRule {
        offset: 0,
        bytes: &[MARKER, 11],
        format: ARC,
    },
];

pub fn meta() -> FormatMeta {
    FormatMeta::container(ARC, &["arc", "pak"], ARC_MAGIC)
}

pub struct Arc;

impl Container for Arc {
    fn id(&self) -> FormatId {
        ARC
    }

    fn caps(&self) -> ContainerCaps {
        // Measured against the fixtures rather than copied from a sibling:
        // every entry's size is in its own header and the headers are
        // consecutive, so a forward walk needs no `Seek` anywhere —
        // `reads_every_entry_through_a_genuinely_non_seekable_source`
        // proves it over a source whose `Seek` is erased at the type level,
        // not merely reported false.
        ContainerCaps {
            forward_parse: true,
            // Every ARC entry carries a CRC-16/ARC the format mandates, and
            // this reader checks it before handing back a single byte — a
            // format-wide guarantee, not a per-writer option, so `Always`.
            detects_corruption: CorruptionDetection::Always,
            ..ContainerCaps::read_only()
        }
    }

    fn open(&self, resolved: Resolved, _o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
        let Resolved { source, report, .. } = resolved;
        let seekable = source.caps().seekable;
        // Reads nothing here, deliberately: the first byte is read by
        // `next_entry`, so a failing source surfaces its error at the same
        // place a mid-archive failure would, and `open` cannot mis-report
        // one as the other.
        Ok(Box::new(ArcRead {
            source,
            report,
            seekable,
            done: false,
        }))
    }

    /// Unreachable through ops: `Registry::require_container_writer` reads
    /// `caps().write` and refuses first. This is the trait-level backstop,
    /// answering the SAME error rather than a second wording of one
    /// contract — see `lha.rs`'s twin.
    fn create(&self, _dst: Box<dyn Sink>, _o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
        Err(Error::CapabilityUnavailable {
            format: ARC,
            available: "read",
            requested: "written",
        })
    }
}

/// The ceiling on any single header-declared length this container acts on,
/// and on the size a decode may grow its output to.
///
/// 256 MiB, the same figure `arj.rs`'s `MAX_ARJ_ENTRY_LEN` uses and for
/// the same argument: generous headroom for any legitimate archive in a
/// DOS-era, floppy-sized format, while far short of what a hostile or
/// merely corrupt `u32` header field could otherwise force this build to
/// allocate for one entry. Fixed rather than derived from
/// `DecodeOpts::memory_limit`, because a container is opened through
/// `OpenOpts`, which has no memory field to read.
const MAX_ARC_ENTRY_LEN: u64 = 256 * 1024 * 1024;

/// Refuses a length past [`MAX_ARC_ENTRY_LEN`] before anything is allocated
/// for it.
///
/// Used at two sites, which are the only two places a length can grow
/// unboundedly here: the header's declared `compressed_size`, checked
/// before the buffer it sizes exists, and a decoder's output, checked as it
/// grows. `original_size` is deliberately NOT a third site — nothing is
/// sized by it, and the output check below measures bytes actually
/// produced, which is strictly stronger than trusting the declaration.
fn refuse_if_over_ceiling(name: &str, declared: u64, field: &str) -> Result<()> {
    if declared > MAX_ARC_ENTRY_LEN {
        return Err(Error::ResourceLimit(format!(
            "entry `{name}` declares {declared} bytes of {field}, past the \
             {MAX_ARC_ENTRY_LEN}-byte ceiling this container decodes whole and cannot stream; \
             no legitimate ARC entry is this large"
        )));
    }
    Ok(())
}

/// Classifies an `io::Error` raised while reading an archive's own bytes.
///
/// `UnexpectedEof` — and only that kind — folds onto [`Error::Corrupt`].
/// It is this reader's own `read_exact` reporting that the archive stopped
/// mid-header or mid-payload, which is damage; left as `Error::Io` it would
/// reach `Error::exit_code`'s `_ => 1` wildcard and announce that *stuffr*
/// failed. Every other kind passes through untouched, so a failing disk
/// still arrives as `PermissionDenied` — the same narrowness `lha.rs`'s
/// `classify_lha_error` and `arj.rs`'s `classify_arj_io` argue for, proven
/// by container-conformance fixture property 9.
fn classify_arc_io(e: io::Error) -> Error {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        return Error::Corrupt(format!("ARC archive ended mid-record: {e}"));
    }
    Error::from_decode_io(e)
}

/// The compression methods this build decodes. Everything else is refused
/// by [`Method::from_byte`] as a capability limit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Method {
    /// Method 1 or 2 — the payload IS the content.
    Stored,
    /// Method 3 — RLE90 alone.
    Rle90,
    /// Method 4 — Huffman ("squeeze") with an RLE90 pass under it.
    Squeezed,
    /// Method 8 — 9-to-12-bit LZW with an RLE90 pass under it.
    Crunched,
    /// Method 9 — 13-bit LZW, no RLE pass.
    Squashed,
}

impl Method {
    /// Maps a header's method byte, or refuses it by name.
    ///
    /// **Method 1 is treated exactly as method 2, and that is a ruling on an
    /// open question rather than a verified fact.** `MANIFEST.md` records
    /// the state of the evidence in full: this corpus contains no method-1
    /// entry (measured twice), the one reference parser in reach
    /// (`unarc-rs`'s `local_file_header.rs`) reads methods 1 and 2 through
    /// one code path at a fixed 28-byte record, and a belief that some
    /// pre-5.21 ARC tool wrote a shorter 24-byte header for method 1 is
    /// recorded there as an OPEN QUESTION with no fixture, tool output or
    /// spec text in this repository to confirm or refute it. Following the
    /// one implementation that can be checked beats writing a special case
    /// for a shape nobody here has seen a byte of; the cost if it resolves
    /// the other way is one extra branch, added once a real method-1
    /// archive exists to test it against.
    fn from_byte(b: u8, name: &str) -> Result<Self> {
        match b {
            1 | 2 => Ok(Method::Stored),
            3 => Ok(Method::Rle90),
            4 => Ok(Method::Squeezed),
            5..=7 => Err(Error::Unsupported(format!(
                "entry `{name}` uses ARC method {b} (Crunched, a pre-method-8 variant), which \
                 this build does not decode: no archive using it exists in this project's \
                 corpus, so a decoder for it could not be proven against anything"
            ))),
            8 => Ok(Method::Crunched),
            9 => Ok(Method::Squashed),
            10 => Err(Error::Unsupported(format!(
                "entry `{name}` uses ARC method 10 (Crushed), which this build does not decode"
            ))),
            11 => Err(Error::Unsupported(format!(
                "entry `{name}` uses ARC method 11 (Distilled), which this build does not decode"
            ))),
            other => Err(Error::Unsupported(format!(
                "entry `{name}` uses ARC method {other}, which is not one this format ever \
                 assigned and this build cannot decode"
            ))),
        }
    }
}

/// One entry header, parsed out of the 28 bytes following a marker.
struct ArcHeader {
    method_byte: u8,
    name: String,
    compressed_size: u32,
    packed_datetime: u32,
    crc16: u16,
    original_size: u32,
}

impl ArcHeader {
    fn parse(record: &[u8; HEADER_LEN]) -> Self {
        let name_field = &record[1..1 + NAME_LEN];
        let end = name_field
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_field.len());
        // Stored VERBATIM, never sanitised, for the reason
        // container-conformance property 12 states: refusing a hostile name
        // is the ops layer's job, and a container that helpfully rewrote one
        // would destroy the evidence that refusal depends on.
        let name = String::from_utf8_lossy(&name_field[..end]).into_owned();
        let u32_at =
            |i: usize| u32::from_le_bytes([record[i], record[i + 1], record[i + 2], record[i + 3]]);
        ArcHeader {
            method_byte: record[0],
            name,
            compressed_size: u32_at(14),
            packed_datetime: u32_at(18),
            crc16: u16::from_le_bytes([record[22], record[23]]),
            original_size: u32_at(24),
        }
    }
}

/// Converts ARC's packed `date`/`time` pair into a `SystemTime`.
///
/// The `u32` is `date | (time << 16)` — see this module's doc for why the
/// halves are this way round and not `unarc-rs`'s. `None` whenever the
/// packed value carries no valid calendar date, which is how an entry with
/// no timestamp at all reports itself.
fn arc_mtime(packed: u32) -> Option<SystemTime> {
    let date = (packed & 0xFFFF) as u16;
    let time = (packed >> 16) as u16;
    dos::mtime(
        1980 + i64::from(date >> 9),
        u32::from((date >> 5) & 0x0F),
        u32::from(date & 0x1F),
        u32::from(time >> 11),
        u32::from((time >> 5) & 0x3F),
        u32::from(time & 0x1F) * 2,
    )
}

struct ArcRead {
    source: Box<dyn Source>,
    report: FidelityReport,
    seekable: bool,
    /// Set once the end-of-archive marker was seen or any error raised —
    /// either way nothing more will be read.
    done: bool,
}

impl ArcRead {
    /// Reads the next header, or `Ok(None)` at the end-of-archive marker.
    fn next_header(&mut self) -> Result<Option<ArcHeader>> {
        let mut byte = [0u8; 1];
        let n = self.source.read(&mut byte).map_err(classify_arc_io)?;
        if n == 0 {
            return Err(Error::Corrupt(
                "ARC archive ended without an end-of-archive marker (`0x1A 0x00`)".into(),
            ));
        }
        if byte[0] != MARKER {
            return Err(Error::Corrupt(format!(
                "expected an ARC entry marker (0x1A) but found {:#04x}; this reader does not \
                 scan forward for the next plausible header, because resynchronising past \
                 damage reads entry data as headers",
                byte[0]
            )));
        }

        let mut record = [0u8; HEADER_LEN];
        self.source
            .read_exact(&mut record[..1])
            .map_err(classify_arc_io)?;
        if record[0] == 0 {
            // The end-of-archive marker, `0x1A 0x00`. Two bytes, no record
            // behind it, and NOTHING after it is consumed or inspected —
            // see this module's doc on the four `.pak` fixtures' trailing
            // ten bytes.
            return Ok(None);
        }
        self.source
            .read_exact(&mut record[1..])
            .map_err(classify_arc_io)?;
        Ok(Some(ArcHeader::parse(&record)))
    }

    /// Reads one entry's compressed payload.
    ///
    /// The ceiling is checked FIRST, before the buffer the header's own
    /// field would size exists. That ordering is the whole point, and it is
    /// what `refuses_an_absurd_compressed_size_before_the_allocation_it_
    /// would_size` proves with a source that panics on an oversized read:
    /// a check bolted on after the read passes an error-code assertion
    /// while the memory was allocated anyway, which is the entire bug this
    /// class of defect has taken five tasks of this project to learn.
    fn read_payload(&mut self, name: &str, compressed_size: u32) -> Result<Vec<u8>> {
        refuse_if_over_ceiling(name, u64::from(compressed_size), "compressed data")?;
        let mut payload = vec![0u8; compressed_size as usize];
        self.source
            .read_exact(&mut payload)
            .map_err(classify_arc_io)?;
        Ok(payload)
    }
}

impl ArchiveRead for ArcRead {
    fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
        if self.done {
            return Ok(None);
        }

        let header = match self.next_header() {
            Ok(Some(h)) => h,
            Ok(None) => {
                self.done = true;
                return Ok(None);
            }
            Err(e) => {
                self.done = true;
                return Err(e);
            }
        };

        let result = (|| {
            let method = Method::from_byte(header.method_byte, &header.name)?;
            let payload = self.read_payload(&header.name, header.compressed_size)?;
            let decoded = decode(method, &payload, &header.name)?;
            check_declared_size(&header, decoded.len())?;
            let got = crc16_arc(&decoded);
            if got != header.crc16 {
                return Err(Error::Corrupt(format!(
                    "entry `{}` decoded to bytes whose CRC-16/ARC is {got:#06x}, but its own \
                     header records {:#06x}",
                    header.name, header.crc16
                )));
            }
            Ok(decoded)
        })();

        let decoded = match result {
            Ok(d) => d,
            Err(e) => {
                self.done = true;
                return Err(e);
            }
        };

        let meta = EntryMeta {
            name: header.name,
            size: Some(u64::from(header.original_size)),
            compressed_size: Some(u64::from(header.compressed_size)),
            mtime: arc_mtime(header.packed_datetime),
            // ARC's 28-byte record has no kind, mode, owner or group field
            // at all — the whole record is accounted for above — so every
            // entry is a plain file and every other field is `None`.
            kind: EntryKind::File,
            ..Default::default()
        };
        Ok(Some(Entry::new(meta, Box::new(io::Cursor::new(decoded)))))
    }

    fn by_index(&mut self, index: usize) -> Result<Entry<'_>> {
        // The two spellings `entries.rs` treats as "count instead", chosen
        // by which one is true here: a seekable source CAN seek, so the
        // honest refusal is that the FORMAT carries no index; a forward-only
        // one cannot seek in the first place. Same shape as `lha.rs`'s.
        if self.seekable {
            return Err(Error::Unsupported(format!(
                "ARC carries no entry index, so entry {index} can only be reached by reading \
                 forward from the start"
            )));
        }
        Err(Error::NotSeekable { format: ARC })
    }

    fn fidelity(&self) -> &FidelityReport {
        &self.report
    }
}

/// Refuses an entry whose decoded length disagrees with the `original_size`
/// its own header declares — in EITHER direction.
///
/// This is the declared-versus-delivered guard `tar.rs`, `ar.rs`, `cpio.rs`
/// and `zip.rs` each already carry, and `Error::exit_code`'s own doc records
/// the ruling: the archive contradicts itself, so there is nothing honest to
/// hand back and it is [`Error::Corrupt`] (exit 5), never a fidelity
/// warning. A warning would leave `unpack` writing the wrong-length file at
/// exit 0, with `--strict-fidelity` the only thing between a user and it.
///
/// **The per-entry CRC-16 is not a substitute, and a 41-byte archive proves
/// it**: a Stored entry declaring `compressed_size = 10`, `original_size =
/// 4096`, carrying the correct CRC-16 of the ten bytes it really holds,
/// satisfies its own checksum exactly — so `list` printed 4096, `test
/// --strict-fidelity` answered "10 bytes verified (exact fidelity)", and
/// `unpack` wrote a 10-byte file, all at exit 0. The same shape zip's
/// size-lying entry had, in the only container added since that ruling was
/// written. `an_entry_that_declares_a_size_its_payload_does_not_deliver_is_
/// corrupt` pins both directions with a CRC that is CORRECT for the payload
/// actually carried, so the guard cannot pass on the checksum's back.
///
/// Checked BEFORE the CRC, deliberately: a payload that decoded to the
/// wrong length can name two concrete figures, where a checksum can only
/// report that something differs. Both are exit 5, so the ordering changes
/// the message rather than the verdict.
fn check_declared_size(header: &ArcHeader, produced: usize) -> Result<()> {
    let declared = u64::from(header.original_size);
    let produced = produced as u64;
    let name = &header.name;
    if produced < declared {
        return Err(Error::Corrupt(format!(
            "entry `{name}` decoded to {produced} bytes, {} short of the {declared} its \
             header declares; the archive is truncated",
            declared - produced
        )));
    }
    if produced > declared {
        return Err(Error::Corrupt(format!(
            "entry `{name}` decoded to {produced} bytes, past the {declared} its header \
             declares; the header and the entry's contents disagree"
        )));
    }
    Ok(())
}

/// Runs one entry's payload through the decoder its method names.
fn decode(method: Method, payload: &[u8], name: &str) -> Result<Vec<u8>> {
    match method {
        Method::Stored => Ok(payload.to_vec()),
        Method::Rle90 => unpack_rle90(payload, name),
        Method::Squeezed => {
            let huffman = unsqueeze(payload, name)?;
            unpack_rle90(&huffman, name)
        }
        Method::Crunched => {
            let codes = lzw_decode(payload, LzwVariant::Crunched, name)?;
            unpack_rle90(&codes, name)
        }
        Method::Squashed => lzw_decode(payload, LzwVariant::Squashed, name),
    }
}

/// ARC's run marker: `<byte> 0x90 <count>` repeats `<byte>` `count` times in
/// total, and `0x90 0x00` is a literal `0x90`.
const DLE: u8 = 0x90;

/// The output-side half of the ceiling — see [`refuse_if_over_ceiling`].
fn guard_output(name: &str, len: usize) -> Result<()> {
    refuse_if_over_ceiling(name, len as u64, "decompressed data")
}

/// Undoes ARC's RLE90 run encoding.
///
/// A `0x90` with no count byte behind it (the payload ends mid-run) is
/// IGNORED rather than refused, matching `unarc-rs`. Refusing would be a
/// check firing on the strength of one missing byte, and the CRC-16 over
/// the whole entry already catches any real damage — with a message naming
/// both checksums, which "trailing DLE" would not.
fn unpack_rle90(input: &[u8], name: &str) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let mut last = 0u8;
    let mut awaiting_count = false;
    for &c in input {
        if awaiting_count {
            awaiting_count = false;
            if c == 0 {
                guard_output(name, out.len() + 1)?;
                out.push(DLE);
                last = DLE;
            } else {
                // `count` counts the run's total length, and one copy has
                // already been emitted, so this adds `count - 1` more.
                let extra = usize::from(c) - 1;
                guard_output(name, out.len() + extra)?;
                out.resize(out.len() + extra, last);
            }
        } else if c == DLE {
            awaiting_count = true;
        } else {
            guard_output(name, out.len() + 1)?;
            out.push(c);
            last = c;
        }
    }
    Ok(out)
}

/// Reads bits least-significant-first within each byte, in byte order.
///
/// That is the order both ARC bitstreams use (`bitstream_io`'s
/// `LittleEndian` in `unarc-rs`'s terms). `read_bits` answers `None` the
/// moment the stream cannot supply the full width asked for, which is how
/// both decoders below detect a clean end of stream.
struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u32,
    bits: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader {
            data,
            pos: 0,
            buf: 0,
            bits: 0,
        }
    }

    fn read_bits(&mut self, n: u32) -> Option<u16> {
        debug_assert!(n <= 16);
        while self.bits < n {
            let byte = *self.data.get(self.pos)?;
            self.pos += 1;
            self.buf |= u32::from(byte) << self.bits;
            self.bits += 8;
        }
        let value = (self.buf & ((1u32 << n) - 1)) as u16;
        self.buf >>= n;
        self.bits -= n;
        Some(value)
    }
}

/// The squeeze tree's symbol count: 256 byte values plus one end marker.
const SQUEEZE_VALUES: usize = 257;
/// The end-of-stream symbol inside that tree.
const SQUEEZE_EOF: i16 = 256;

/// Decodes ARC's "squeeze" Huffman layer.
///
/// Layout: `numnodes(u16 LE)` then `numnodes` pairs of `i16 LE` (the two
/// children of each node), then the bitstream. A node's child is either a
/// non-negative index of another node or a negative encoding `-(value + 1)`
/// of a leaf symbol; symbol 256 ends the stream. The bytes this produces
/// are still RLE90-packed — the caller runs [`unpack_rle90`] over them.
fn unsqueeze(input: &[u8], name: &str) -> Result<Vec<u8>> {
    if input.len() < 2 {
        return Err(Error::Corrupt(format!(
            "entry `{name}` is squeezed but carries no Huffman node count"
        )));
    }
    let numnodes = usize::from(u16::from_le_bytes([input[0], input[1]]));
    if numnodes >= SQUEEZE_VALUES {
        return Err(Error::Corrupt(format!(
            "entry `{name}` declares {numnodes} Huffman nodes, more than the \
             {SQUEEZE_VALUES} values the squeeze tree can hold"
        )));
    }
    if numnodes == 0 {
        return Ok(Vec::new());
    }
    let table_end = 2 + numnodes * 4;
    if input.len() < table_end {
        return Err(Error::Corrupt(format!(
            "entry `{name}` declares {numnodes} Huffman nodes but carries only {} bytes of \
             node table",
            input.len().saturating_sub(2)
        )));
    }
    let nodes: Vec<[i16; 2]> = (0..numnodes)
        .map(|i| {
            let at = |o: usize| i16::from_le_bytes([input[2 + i * 4 + o], input[3 + i * 4 + o]]);
            [at(0), at(2)]
        })
        .collect();

    let mut reader = BitReader::new(&input[table_end..]);
    let mut node: i16 = 0;
    let mut out: Vec<u8> = Vec::new();
    loop {
        let index = usize::try_from(node)
            .ok()
            .filter(|&i| i < nodes.len())
            .ok_or_else(|| {
                Error::Corrupt(format!(
                    "entry `{name}`'s squeeze tree walks to node {node}, outside its own \
                     {numnodes}-node table"
                ))
            })?;
        let Some(bit) = reader.read_bits(1) else {
            break;
        };
        node = nodes[index][usize::from(bit)];
        if node < 0 {
            let symbol = -(node + 1);
            if symbol == SQUEEZE_EOF {
                break;
            }
            if !(0..SQUEEZE_EOF).contains(&symbol) {
                return Err(Error::Corrupt(format!(
                    "entry `{name}`'s squeeze tree yields leaf value {symbol}, which is neither \
                     a byte nor the end-of-stream symbol"
                )));
            }
            guard_output(name, out.len() + 1)?;
            out.push(symbol as u8);
            node = 0;
        }
    }
    Ok(out)
}

/// Which of ARC's two LZW dialects a payload is in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LzwVariant {
    /// Method 8: a leading maxbits byte (always 12), codes 9..=12 bits,
    /// output still RLE90-packed.
    Crunched,
    /// Method 9: no leading byte, codes 9..=13 bits, output final.
    Squashed,
}

/// Code 256 resets the dictionary.
const LZW_CLEAR: u16 = 256;
/// The first code a dictionary entry may take.
const LZW_FIRST: u16 = 257;
/// Every stream starts at nine-bit codes.
const LZW_INIT_BITS: u32 = 9;

/// The variable-width code reader both LZW dialects share.
///
/// The width steps up exactly when the next free dictionary slot passes the
/// current width's largest code, and resets to nine after a CLEAR. The two
/// inner checks are written in `unarc-rs`'s order (and, under it, Thom
/// Henderson's original `arccode.c`'s), but — MEASURED, by swapping them
/// and watching every test stay green — they cannot both be true at once:
/// a CLEAR sets `free_ent` to 256 in the same breath as `clear_pending`,
/// and `maxcode` is never below 511, so `free_ent > maxcode` is always
/// false while a clear is pending. The order is therefore inert, and this
/// note exists so a future reader does not mistake "matches the reference"
/// for "proven necessary".
struct LzwCodes<'a> {
    bits: BitReader<'a>,
    width: u32,
    max_width: u32,
    maxcode: u16,
    /// One past the largest code the dictionary can ever hold.
    ceiling: u16,
    clear_pending: bool,
    free_ent: u16,
}

impl LzwCodes<'_> {
    fn next(&mut self) -> Option<u16> {
        if self.clear_pending || self.free_ent > self.maxcode {
            if self.free_ent > self.maxcode {
                self.width += 1;
                // At the dialect's own maximum width the largest code is the
                // dictionary ceiling, not `(1 << width) - 1`.
                //
                // `unarc-rs` compares against a hardcoded 12 here for BOTH
                // dialects, which pins Squashed's width at 12 and makes its
                // 13-bit codes unreachable. Its own test corpus never
                // reaches code 4096, so nothing there notices; this reads
                // the dialect's own width instead. On every squashed
                // fixture in this project the two are byte-identical (the
                // dictionary never passes 4095), so this is a correctness
                // fix with no observable difference on anything either
                // implementation can be checked against today.
                self.maxcode = if self.width == self.max_width {
                    self.ceiling
                } else {
                    (1u16 << self.width) - 1
                };
            }
            if self.clear_pending {
                self.clear_pending = false;
                self.width = LZW_INIT_BITS;
                self.maxcode = (1u16 << LZW_INIT_BITS) - 1;
            }
        }
        self.bits.read_bits(self.width)
    }
}

/// Decodes ARC's LZW layer, in whichever of its two dialects `variant`
/// names.
fn lzw_decode(input: &[u8], variant: LzwVariant, name: &str) -> Result<Vec<u8>> {
    let (max_width, body) = match variant {
        LzwVariant::Crunched => {
            let Some((&declared, rest)) = input.split_first() else {
                return Err(Error::Corrupt(format!(
                    "entry `{name}` is crunched but carries no leading code-width byte"
                )));
            };
            if declared != 12 {
                // Corrupt rather than Unsupported: the method byte already
                // said "Crunched", which IS the twelve-bit dialect, so a
                // payload declaring anything else contradicts its own
                // header rather than naming a variant this build lacks.
                return Err(Error::Corrupt(format!(
                    "entry `{name}` is crunched but its payload declares {declared}-bit codes; \
                     ARC's Crunched method is twelve-bit"
                )));
            }
            (12u32, rest)
        }
        LzwVariant::Squashed => (13u32, input),
    };
    let ceiling: u16 = 1u16 << max_width;
    let table = usize::from(ceiling);
    let mut prefix = vec![0u16; table];
    let mut suffix = vec![0u8; table];
    for (code, slot) in suffix.iter_mut().enumerate().take(256) {
        *slot = code as u8;
    }

    let mut codes = LzwCodes {
        bits: BitReader::new(body),
        width: LZW_INIT_BITS,
        max_width,
        maxcode: (1u16 << LZW_INIT_BITS) - 1,
        ceiling,
        clear_pending: false,
        free_ent: LZW_FIRST,
    };

    let mut out: Vec<u8> = Vec::new();
    let Some(mut oldcode) = codes.next() else {
        return Ok(out);
    };
    let mut finchar = oldcode as u8;
    out.push(finchar);

    let mut stack: Vec<u8> = Vec::new();
    while let Some(mut code) = codes.next() {
        if code == LZW_CLEAR {
            prefix.fill(0);
            codes.clear_pending = true;
            codes.free_ent = LZW_FIRST - 1;
            match codes.next() {
                Some(c) => code = c,
                None => break,
            }
        }
        let incode = code;
        stack.clear();
        if code >= codes.free_ent {
            // The KwKwK case: the code names the entry being built right
            // now, whose expansion is the previous one plus its own first
            // character.
            stack.push(finchar);
            code = oldcode;
        }
        // A valid chain visits each dictionary entry at most once; anything
        // longer is a cycle forged by damaged bytes. Every code is below
        // `ceiling` by construction (a width-`w` read cannot exceed
        // `(1 << w) - 1`, and `w <= max_width`), so the indexing below
        // cannot go out of bounds — the bound here is against looping, not
        // against a bad index.
        let mut steps = 0usize;
        while code >= 256 {
            steps += 1;
            if steps > table {
                return Err(Error::Corrupt(format!(
                    "entry `{name}`'s LZW dictionary chain cycles; the archive is damaged"
                )));
            }
            stack.push(suffix[usize::from(code)]);
            code = prefix[usize::from(code)];
        }
        finchar = suffix[usize::from(code)];
        stack.push(finchar);
        guard_output(name, out.len() + stack.len())?;
        out.extend(stack.iter().rev());

        let slot = codes.free_ent;
        if slot < ceiling {
            prefix[usize::from(slot)] = oldcode;
            suffix[usize::from(slot)] = finchar;
            codes.free_ent = slot + 1;
        }
        oldcode = incode;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;
    use stuffr_core::testing::{ContainerFixture, ExpectedEntry, assert_container_conforms_with};
    use stuffr_core::{CreateOpts, OpenOpts, PlainSink, ReaderSource, StreamPolicy};

    const CPM_ARC: &[u8] = include_bytes!("../../fixtures/legacy/arc/cpm.arc");
    const STORE_ARC: &[u8] = include_bytes!("../../fixtures/legacy/arc/store.arc");
    const WRONGCRC16_ARC: &[u8] = include_bytes!("../../fixtures/legacy/arc/wrongcrc16.arc");
    const CRUNCH_ARC: &[u8] = include_bytes!("../../fixtures/legacy/arc/crunch.arc");
    const CRUNCH2_ARC: &[u8] = include_bytes!("../../fixtures/legacy/arc/crunch2.arc");
    const SQUASHED_ARC: &[u8] = include_bytes!("../../fixtures/legacy/arc/squashed.arc");
    const LICENSE_PAK: &[u8] = include_bytes!("../../fixtures/legacy/arc/license.pak");
    const LICENSE_CRUNCHED_PAK: &[u8] =
        include_bytes!("../../fixtures/legacy/arc/license_crunched.pak");
    const LICENSE_SQUASHED_PAK: &[u8] =
        include_bytes!("../../fixtures/legacy/arc/license_squashed.pak");
    const LICENSE_CRUSHED_PAK: &[u8] =
        include_bytes!("../../fixtures/legacy/arc/license_crushed.pak");

    /// The two expected-output files borrowed alongside `cpm.arc` — the
    /// plaintext its two entries decode to, taken byte-for-byte from
    /// `unarc-rs` 0.6.3's own `tests/arc/` tree. See `MANIFEST.md`: they are
    /// bound to the archive by
    /// `the_borrowed_expected_outputs_match_the_crc_their_archive_stores`
    /// below, which checks them against the CRC-16 `cpm.arc`'s own headers
    /// carry with no decoder anywhere in the loop.
    const DDTZ_COM: &[u8] = include_bytes!("../../fixtures/legacy/arc/DDTZ.COM");
    const READ_COM: &[u8] = include_bytes!("../../fixtures/legacy/arc/READ.COM");

    const PROVENANCE: &str = "archive bytes from unarc-rs 0.6.3's MIT/Apache test corpus, \
                              borrowed as bytes only; every stored_crc below is parsed from \
                              the archive's OWN header at test time by this module's \
                              `raw_entries`, never from a literal and never from decoding \
                              anything. See fixtures/legacy/MANIFEST.md";

    /// One entry as it appears in an archive's raw bytes.
    struct RawEntry {
        name: String,
        method: u8,
        crc16: u16,
        payload: &'static [u8],
    }

    /// Walks an archive's headers with a parser written out longhand here,
    /// independent of everything above it in this file.
    ///
    /// Two rules `MANIFEST.md`'s banner states, and this is the code that
    /// keeps them: `stored_crc` is TRANSCRIBED from the archive's own bytes,
    /// never hardcoded from the manifest's tables (a hand-copied hex literal
    /// silently strands when a fixture changes) and never computed by
    /// decoding a payload and hashing the result (which would turn the CRC
    /// conformance property into a self-consistency check, duplicating
    /// property 5). Deliberately NOT `ArcHeader::parse`: a manifest derived
    /// from the parser under test would agree with it by construction.
    fn raw_entries(bytes: &'static [u8]) -> Vec<RawEntry> {
        let mut out = Vec::new();
        let mut at = 0usize;
        loop {
            assert_eq!(bytes[at], 0x1A, "entry marker at offset {at}");
            let method = bytes[at + 1];
            if method == 0 {
                return out;
            }
            let name_field = &bytes[at + 2..at + 15];
            let end = name_field
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(name_field.len());
            let name = String::from_utf8_lossy(&name_field[..end]).into_owned();
            let le32 = |i: usize| {
                u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]) as usize
            };
            let compressed = le32(at + 15);
            let crc16 = u16::from_le_bytes([bytes[at + 23], bytes[at + 24]]);
            let start = at + 29;
            out.push(RawEntry {
                name,
                method,
                crc16,
                payload: &bytes[start..start + compressed],
            });
            at = start + compressed;
        }
    }

    /// The LICENSE plaintext six of the borrowed archives compress, taken
    /// from the ONE that stores it uncompressed.
    ///
    /// `store.arc`'s entry is method 2, so its payload IS its content — a
    /// byte range, with no decoder involved. That makes it usable as the
    /// expected output for `crunch.arc` and its siblings without ever asking
    /// this module's own LZW to vouch for itself, and it is independently
    /// anchored: `the_borrowed_expected_outputs_match_the_crc_their_archive_
    /// stores` checks these bytes against the CRC-16 `store.arc`'s header
    /// records.
    fn license() -> &'static [u8] {
        raw_entries(STORE_ARC)[0].payload
    }

    /// Builds a fixture manifest: names and stored CRCs from the archive's
    /// own header bytes, contents supplied by the caller.
    fn manifest(archive: &'static [u8], contents: &[&'static [u8]]) -> &'static [ExpectedEntry] {
        let raw = raw_entries(archive);
        assert_eq!(
            raw.len(),
            contents.len(),
            "the archive holds {} entries but {} expected contents were given",
            raw.len(),
            contents.len()
        );
        let entries: Vec<ExpectedEntry> = raw
            .iter()
            .zip(contents)
            .map(|(r, c)| ExpectedEntry {
                name: Box::leak(r.name.clone().into_boxed_str()),
                content: c,
                stored_crc: Some(r.crc16),
            })
            .collect();
        Box::leak(entries.into_boxed_slice())
    }

    fn fixture(bytes: &'static [u8], contents: &[&'static [u8]]) -> ContainerFixture {
        ContainerFixture {
            bytes,
            expected: manifest(bytes, contents),
            provenance: PROVENANCE,
        }
    }

    fn open_forward(bytes: &[u8]) -> Box<dyn ArchiveRead> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(io::Cursor::new(bytes.to_vec())));
        let resolved = stuffr_core::resolve(src, ARC, Arc.caps(), &StreamPolicy::default())
            .expect("resolve over a forward source");
        Arc.open(resolved, &OpenOpts::default())
            .expect("open reads no byte")
    }

    fn read_all(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
        let mut ar = open_forward(bytes);
        let mut out = Vec::new();
        while let Some(mut entry) = ar.next_entry()? {
            let name = entry.meta().name.clone();
            let mut data = Vec::new();
            entry.reader().read_to_end(&mut data)?;
            out.push((name, data));
        }
        Ok(out)
    }

    /// Assembles a one-entry archive with arbitrary header fields, for the
    /// shapes no borrowed fixture carries (a hostile size, a refused method,
    /// a missing terminator).
    fn build_arc_entry(method: u8, name: &str, payload: &[u8], declared_size: u32) -> Vec<u8> {
        build_arc_entry_declaring(method, name, payload, declared_size, payload.len() as u32)
    }

    /// The same, with `original_size` under the caller's control too, so a
    /// header can be made to lie about what its payload delivers while its
    /// CRC-16 stays CORRECT for the bytes actually carried.
    fn build_arc_entry_declaring(
        method: u8,
        name: &str,
        payload: &[u8],
        declared_size: u32,
        declared_original: u32,
    ) -> Vec<u8> {
        let mut out = vec![MARKER, method];
        let mut field = [0u8; NAME_LEN];
        field[..name.len()].copy_from_slice(name.as_bytes());
        out.extend_from_slice(&field);
        out.extend_from_slice(&declared_size.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // date/time
        out.extend_from_slice(&crc16_arc(payload).to_le_bytes());
        out.extend_from_slice(&declared_original.to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn build_arc(method: u8, name: &str, payload: &[u8]) -> Vec<u8> {
        let mut out = build_arc_entry(method, name, payload, payload.len() as u32);
        out.extend_from_slice(&[MARKER, 0]);
        out
    }

    // ---- the fixtures' own ground truth, established with no decoder ----

    /// The borrowed expected-output files are bound to the archives they
    /// describe by the archives' OWN stored CRC-16 — not by this module's
    /// decoder, and not by `unarc-rs`'s.
    ///
    /// This is what makes fixture property 5 (content) evidence rather than
    /// a tautology for `cpm.arc`, whose two entries are compressed and so
    /// have no byte range to slice an expectation out of. If a future editor
    /// replaces either `.COM` file, this test goes red before any
    /// conformance test does.
    #[test]
    fn the_borrowed_expected_outputs_match_the_crc_their_archive_stores() {
        let cpm = raw_entries(CPM_ARC);
        assert_eq!(cpm.len(), 2, "cpm.arc holds two entries");
        assert_eq!(cpm[0].name, "DDTZ.COM");
        assert_eq!(cpm[1].name, "READ.COM");
        assert_eq!(
            crc16_arc(DDTZ_COM),
            cpm[0].crc16,
            "DDTZ.COM is not the plaintext cpm.arc's first entry describes"
        );
        assert_eq!(
            crc16_arc(READ_COM),
            cpm[1].crc16,
            "READ.COM is not the plaintext cpm.arc's second entry describes"
        );

        let store = raw_entries(STORE_ARC);
        assert_eq!(store.len(), 1);
        assert_eq!(store[0].method, 2, "store.arc's entry must be Stored (2)");
        assert_eq!(
            crc16_arc(license()),
            store[0].crc16,
            "store.arc's raw payload is not what its own header describes, so it cannot \
             serve as the expected output for its compressed siblings"
        );
    }

    /// The method bytes this task's scope was decided against, read off the
    /// archives rather than trusted from a filename — `license_crushed.pak`
    /// is Crushed (10), NOT a spelling of Crunched (8), and `license.pak` is
    /// Distilled (11), not "the plain one".
    #[test]
    fn each_fixtures_method_byte_is_the_one_the_manifest_records() {
        for (bytes, label, want) in [
            (STORE_ARC, "store.arc", 2u8),
            (WRONGCRC16_ARC, "wrongcrc16.arc", 2),
            (CRUNCH_ARC, "crunch.arc", 8),
            (CRUNCH2_ARC, "crunch2.arc", 8),
            (SQUASHED_ARC, "squashed.arc", 9),
            (LICENSE_CRUNCHED_PAK, "license_crunched.pak", 8),
            (LICENSE_SQUASHED_PAK, "license_squashed.pak", 9),
            (LICENSE_CRUSHED_PAK, "license_crushed.pak", 10),
            (LICENSE_PAK, "license.pak", 11),
        ] {
            assert_eq!(raw_entries(bytes)[0].method, want, "{label}");
        }
        let cpm = raw_entries(CPM_ARC);
        assert_eq!(cpm[0].method, 4, "cpm.arc entry 1 is Squeezed");
        assert_eq!(cpm[1].method, 3, "cpm.arc entry 2 is RLE90");
    }

    // ---- conformance ----

    /// The primary fixture: two entries, two different methods (Squeezed and
    /// RLE90) and a genuine multi-entry forward walk. Every `license.*` file
    /// in the corpus holds a single entry, so none of them can prove the
    /// walk advances correctly from one header to the next.
    #[test]
    fn arc_conforms() {
        assert_container_conforms_with(&Arc, &meta(), &fixture(CPM_ARC, &[DDTZ_COM, READ_COM]));
    }

    #[test]
    fn a_stored_archive_conforms() {
        assert_container_conforms_with(&Arc, &meta(), &fixture(STORE_ARC, &[license()]));
    }

    #[test]
    fn a_crunched_archive_conforms() {
        assert_container_conforms_with(&Arc, &meta(), &fixture(CRUNCH_ARC, &[license()]));
    }

    #[test]
    fn a_squashed_archive_conforms() {
        assert_container_conforms_with(&Arc, &meta(), &fixture(SQUASHED_ARC, &[license()]));
    }

    /// Every remaining archive whose entry decodes to the same LICENSE
    /// plaintext, read end to end. Four separate encoders' output — two
    /// Crunched, two Squashed, one of each from the PAK-era tools — against
    /// one expectation that came out of a fifth archive's stored payload.
    #[test]
    fn every_license_bearing_archive_decodes_to_the_same_bytes() {
        for (bytes, label) in [
            (CRUNCH_ARC, "crunch.arc"),
            (CRUNCH2_ARC, "crunch2.arc"),
            (SQUASHED_ARC, "squashed.arc"),
            (LICENSE_CRUNCHED_PAK, "license_crunched.pak"),
            (LICENSE_SQUASHED_PAK, "license_squashed.pak"),
        ] {
            let got = read_all(bytes).unwrap_or_else(|e| panic!("{label}: {e}"));
            assert_eq!(got.len(), 1, "{label} holds one entry");
            assert_eq!(got[0].0, "LICENSE", "{label}");
            assert_eq!(
                got[0].1,
                license(),
                "{label} decoded to different bytes than store.arc carries verbatim"
            );
        }
    }

    // ---- refusals ----

    /// The CRC witness firing for real. `wrongcrc16.arc` stores `0xB065` —
    /// the CRC of the correct LICENSE content — over a payload that computes
    /// `0xE763`, so a reader that skipped the check would hand back wrong
    /// bytes at exit 0. Its entry is Stored, so no decompression step is
    /// involved: the mismatch is in the archive's own bytes.
    #[test]
    fn a_stored_entry_whose_payload_betrays_its_crc_is_corrupt() {
        let err = read_all(WRONGCRC16_ARC).expect_err("a CRC mismatch must be refused");
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 5, "{err}");
        let msg = err.to_string();
        assert!(
            msg.contains("0xe763") && msg.contains("0xb065"),
            "the message must name both the computed and the recorded CRC, got: {msg}"
        );
    }

    /// The declared-versus-delivered guard, with the CRC-16 CORRECT for the
    /// payload actually carried — so the guard cannot be passing on the
    /// checksum's back.
    ///
    /// Unguarded, this exact 41-byte archive made the tool contradict itself
    /// and call both halves exact: `list` printed 4096, `test
    /// --strict-fidelity` answered "10 bytes verified (exact fidelity)", and
    /// `unpack --strict-fidelity` wrote a 10-byte file — all at exit 0.
    /// Both directions are refused, as in `zip.rs`.
    #[test]
    fn an_entry_that_declares_a_size_its_payload_does_not_deliver_is_corrupt() {
        for (declared_original, direction) in [(4096u32, "short"), (3u32, "long")] {
            let mut bytes =
                build_arc_entry_declaring(2, "LIE.TXT", b"ten bytes!", 10, declared_original);
            bytes.extend_from_slice(&[MARKER, 0]);
            assert_eq!(bytes.len(), 41, "the reviewer's reproducer is 41 bytes");
            // The CRC in that header is the real one for the ten bytes
            // behind it, so nothing below can be the checksum firing.
            assert_eq!(
                u16::from_le_bytes([bytes[23], bytes[24]]),
                crc16_arc(b"ten bytes!")
            );

            let err = match read_all(&bytes) {
                Ok(v) => panic!("a header lying {direction} by design was accepted: {v:?}"),
                Err(e) => e,
            };
            assert!(matches!(err, Error::Corrupt(_)), "{direction}: {err:?}");
            assert_eq!(
                err.exit_code(),
                5,
                "{direction}: a self-contradicting archive is corrupt, not a capability \
                 limit or a resource ceiling — {err}"
            );
            let msg = err.to_string();
            assert!(
                msg.contains("LIE.TXT")
                    && msg.contains("10")
                    && msg.contains(&declared_original.to_string()),
                "{direction}: the message must name the entry and both figures, got: {msg}"
            );
        }
    }

    /// The regression guard for the test above: every borrowed archive
    /// decodes to exactly the `original_size` its header declares, so the
    /// new comparison cannot be one that fires on legitimate input — this
    /// project's second-commonest defect.
    #[test]
    fn every_fixture_decodes_to_exactly_the_size_its_header_declares() {
        for (bytes, label) in [
            (CPM_ARC, "cpm.arc"),
            (STORE_ARC, "store.arc"),
            (CRUNCH_ARC, "crunch.arc"),
            (CRUNCH2_ARC, "crunch2.arc"),
            (SQUASHED_ARC, "squashed.arc"),
            (LICENSE_CRUNCHED_PAK, "license_crunched.pak"),
            (LICENSE_SQUASHED_PAK, "license_squashed.pak"),
        ] {
            let mut ar = open_forward(bytes);
            let mut seen = 0usize;
            while let Some(mut entry) = ar.next_entry().unwrap_or_else(|e| panic!("{label}: {e}")) {
                let declared = entry.meta().size.expect("ARC always declares a size");
                let mut data = Vec::new();
                entry.reader().read_to_end(&mut data).unwrap();
                assert_eq!(data.len() as u64, declared, "{label}");
                seen += 1;
            }
            assert!(seen > 0, "{label} yielded no entry");
        }
    }

    /// Crushed (10) and Distilled (11) are capability limits, not damage:
    /// the archive is fine, this build has no decoder for those methods.
    #[test]
    fn crushed_and_distilled_are_refused_as_capability_limits() {
        for (bytes, label, method) in [
            (LICENSE_CRUSHED_PAK, "license_crushed.pak", "Crushed"),
            (LICENSE_PAK, "license.pak", "Distilled"),
        ] {
            let err = read_all(bytes).unwrap_err();
            assert!(
                matches!(err, Error::Unsupported(_)),
                "{label} must be a capability limit, not corruption: {err:?}"
            );
            assert_eq!(err.exit_code(), 3, "{label}: {err}");
            assert!(
                err.to_string().contains(method),
                "{label}'s refusal must name the method, got: {err}"
            );
        }
    }

    /// The pre-8 Crunched variants are refused rather than fed to the
    /// method-8 decoder, which is where `unarc-rs` sends them — see this
    /// module's doc. Exit 3 ("this build cannot"), never exit 5 ("your
    /// archive is damaged").
    #[test]
    fn the_pre_method_eight_crunched_variants_are_refused() {
        for method in [5u8, 6, 7] {
            let bytes = build_arc(method, "X.TXT", b"whatever");
            let err = read_all(&bytes).unwrap_err();
            assert!(
                matches!(err, Error::Unsupported(_)),
                "method {method}: {err:?}"
            );
            assert_eq!(err.exit_code(), 3, "method {method}: {err}");
            assert!(
                err.to_string().contains(&format!("method {method}")),
                "the refusal must name the method, got: {err}"
            );
        }
    }

    /// Method 1 reads exactly like method 2 — the ruling `Method::from_byte`
    /// documents. Pinned so the choice is visible as a choice rather than an
    /// accident of a `match` arm.
    #[test]
    fn method_one_is_read_as_a_stored_entry_just_like_method_two() {
        let bytes = build_arc(1, "OLD.TXT", b"stored the old way\n");
        let got = read_all(&bytes).expect("method 1 must read as Stored");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, b"stored the old way\n");
    }

    // ---- framing ----

    /// The four `.pak` fixtures carry ten bytes after their end-of-archive
    /// marker (see `MANIFEST.md`). A reader that asserted the marker
    /// coincides with end of file — as several containers in this project do
    /// — would fail all four for a reason invisible without the manifest.
    #[test]
    fn trailing_bytes_after_the_end_of_archive_marker_are_ignored() {
        const TRAILER: &[u8] = &[0xfe, 0x02, 0x01, 0, 0, 0, 0, 0, 0xfe, 0x00];
        assert_eq!(
            &LICENSE_CRUNCHED_PAK[LICENSE_CRUNCHED_PAK.len() - TRAILER.len()..],
            TRAILER,
            "the fixture must still carry the trailing bytes this test exists for"
        );
        let got = read_all(LICENSE_CRUNCHED_PAK).expect("trailing bytes must not be an error");
        assert_eq!(got.len(), 1, "and must not look like another entry either");
    }

    /// Damage is refused, never resynchronised past. `unarc-rs` scans up to
    /// 65535 bytes for the next `0x1A`; doing that turns entry data into
    /// headers the moment a payload happens to contain one.
    #[test]
    fn a_byte_that_is_not_the_marker_is_corrupt_rather_than_scanned_past() {
        let mut bytes = vec![0xFFu8];
        bytes.extend_from_slice(STORE_ARC);
        let err = read_all(&bytes).expect_err("a misplaced first byte must be refused");
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 5, "{err}");
    }

    #[test]
    fn an_archive_that_stops_before_its_end_marker_is_corrupt() {
        let cut = &STORE_ARC[..STORE_ARC.len() - 2];
        let err = read_all(cut).expect_err("a missing end-of-archive marker must be refused");
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 5, "{err}");
    }

    // ---- the ceiling ----

    /// A `Source` that panics if ever asked to fill a buffer larger than
    /// `max_single_read` — the same instrument `cpio.rs`'s
    /// `refuses_an_absurd_namesize_before_the_allocation_it_would_size`
    /// uses, and for the same reason.
    ///
    /// `ArcRead::read_payload` allocates `vec![0u8; compressed_size]` and
    /// hands it straight to `read_exact`, whose first call requests the
    /// whole buffer. So a read past any sane header window is proof the
    /// allocation already happened, i.e. that the ceiling check ran after
    /// the fact rather than before. A test asserting only the error code
    /// passes even then, which is the entire defect.
    struct PanicsOnBigRead {
        inner: io::Cursor<Vec<u8>>,
        max_single_read: usize,
    }

    impl Read for PanicsOnBigRead {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            assert!(
                buf.len() <= self.max_single_read,
                "a single read of {} bytes was requested — past the {}-byte guard. That is \
                 proof `vec![0u8; compressed_size]` was already allocated from the header's \
                 own field before any refusal ran",
                buf.len(),
                self.max_single_read
            );
            io::Read::read(&mut self.inner, buf)
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
            inner: io::Cursor::new(bytes),
            max_single_read,
        });
        let resolved =
            stuffr_core::resolve(src, ARC, Arc.caps(), &StreamPolicy::default()).expect("resolve");
        Arc.open(resolved, &OpenOpts::default())
            .expect("open reads no byte")
    }

    /// The same declared size the Phase 3a `container` fuzz target's cpio
    /// reproducer named — 2,863,311,530 bytes — reused here so the figure is
    /// a real one rather than a stand-in.
    const ABSURD_SIZE: u32 = 0xAAAA_AAAA;

    #[test]
    fn refuses_an_absurd_compressed_size_before_the_allocation_it_would_size() {
        let bytes = build_arc_entry(2, "BIG.BIN", b"", ABSURD_SIZE);
        let mut ar = open_guarded(bytes, stuffr_core::PROBE_LEN);
        let err = ar
            .next_entry()
            .expect_err("an absurd compressed_size must be refused");
        assert!(
            matches!(err, Error::ResourceLimit(_)),
            "an implausible declared length is this build refusing to allocate, not a verdict \
             that the file is damaged — see MAX_ARC_ENTRY_LEN's doc; got {err:?}"
        );
        assert_eq!(err.exit_code(), 6, "ResourceLimit is exit 6: {err:?}");
        assert!(
            err.to_string().contains(&ABSURD_SIZE.to_string()),
            "the message must name the declared size, got: {err}"
        );
    }

    /// The regression guard for the test above: a size UNDER the ceiling
    /// with no data behind it must still fail — as ordinary corruption, exit
    /// 5, never `ResourceLimit`. Pins that the check is bounded by
    /// `MAX_ARC_ENTRY_LEN` and is not "any size with no data behind it".
    #[test]
    fn a_modest_compressed_size_with_no_data_behind_it_is_corrupt_not_resource_limited() {
        let bytes = build_arc_entry(2, "SHORT.BIN", b"", 64);
        let mut ar = open_guarded(bytes, 4096);
        let err = ar.next_entry().expect_err("a truncated entry must fail");
        assert_eq!(
            err.exit_code(),
            5,
            "a small, merely-truncated payload is corruption, not a resource ceiling: {err:?}"
        );
    }

    /// A legitimately large entry — far past any borrowed fixture,
    /// comfortably under the ceiling — must still read. Guards the obvious
    /// way to get a ceiling wrong: setting it so tight it refuses real
    /// archives, which this project has shipped before.
    #[test]
    fn an_entry_far_larger_than_any_fixture_is_still_read() {
        let payload = vec![0x5Au8; 2 * 1024 * 1024];
        assert!(
            (payload.len() as u64) < MAX_ARC_ENTRY_LEN,
            "the fixture must stay under the ceiling to prove a real entry is unaffected"
        );
        let bytes = build_arc(2, "BIG.BIN", &payload);
        let got = read_all(&bytes).expect("a 2 MiB entry is not absurd");
        assert_eq!(got[0].1.len(), payload.len());
    }

    /// The output half of the ceiling, exercised as a predicate rather than
    /// end to end: reaching it through a real decode means actually
    /// producing 256 MiB, which is not a cost worth paying on every gate
    /// run. The call sites are covered by
    /// `an_entry_far_larger_than_any_fixture_is_still_read` (which proves
    /// the guard does not fire early) and by every decode test above.
    #[test]
    fn the_output_ceiling_refuses_past_its_bound_and_not_at_it() {
        let at = guard_output("X", MAX_ARC_ENTRY_LEN as usize);
        assert!(at.is_ok(), "exactly at the ceiling must be allowed");
        let over = guard_output("X", MAX_ARC_ENTRY_LEN as usize + 1).unwrap_err();
        assert!(matches!(over, Error::ResourceLimit(_)), "{over:?}");
        assert_eq!(over.exit_code(), 6);
    }

    // ---- decoder units ----

    /// ARC's own documented run shapes, both directions of the DLE escape.
    #[test]
    fn rle90_expands_the_formats_documented_run_shapes() {
        assert_eq!(
            unpack_rle90(&[0x01, 0x90, 0x00, 0x03], "t").unwrap(),
            vec![0x01, 0x90, 0x03],
            "0x90 0x00 is a literal 0x90"
        );
        assert_eq!(
            unpack_rle90(&[0x01, 0x90, 0x05, 0x02], "t").unwrap(),
            vec![0x01, 0x01, 0x01, 0x01, 0x01, 0x02],
            "a count of 5 means five copies in total, not five more"
        );
        assert_eq!(
            unpack_rle90(&[0x41, 0x90, 0x01], "t").unwrap(),
            vec![0x41],
            "a count of 1 adds nothing"
        );
        assert_eq!(
            unpack_rle90(&[0x41, 0x90], "t").unwrap(),
            vec![0x41],
            "a DLE with no count byte behind it is ignored, not refused"
        );
    }

    #[test]
    fn a_squeeze_tree_larger_than_the_symbol_space_is_corrupt() {
        let mut payload = 300u16.to_le_bytes().to_vec();
        payload.extend_from_slice(&[0u8; 8]);
        let err = unsqueeze(&payload, "t").unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
        assert_eq!(err.exit_code(), 5);
    }

    #[test]
    fn a_squeeze_node_table_shorter_than_it_declares_is_corrupt() {
        let mut payload = 4u16.to_le_bytes().to_vec();
        payload.extend_from_slice(&[0u8; 6]); // 4 nodes need 16 bytes
        let err = unsqueeze(&payload, "t").unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
    }

    /// A crunched payload's first byte is its code width, and ARC's Crunched
    /// method is twelve-bit by definition — so any other value is the
    /// payload contradicting its own header, not a variant to refuse as
    /// unsupported.
    #[test]
    fn a_crunched_payload_declaring_another_code_width_is_corrupt() {
        let err = lzw_decode(&[13, 0, 0, 0], LzwVariant::Crunched, "t").unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
        assert_eq!(err.exit_code(), 5);
        assert!(err.to_string().contains("13-bit"), "{err}");
    }

    /// Packs nine-bit codes the way both ARC LZW dialects do — least
    /// significant bit first within each byte, in byte order.
    fn pack_nine_bit_codes(codes: &[u16]) -> Vec<u8> {
        let (mut out, mut buf, mut bits) = (Vec::new(), 0u32, 0u32);
        for &c in codes {
            buf |= u32::from(c) << bits;
            bits += 9;
            while bits >= 8 {
                out.push((buf & 0xFF) as u8);
                buf >>= 8;
                bits -= 8;
            }
        }
        if bits > 0 {
            out.push((buf & 0xFF) as u8);
        }
        out
    }

    /// The one LZW branch no borrowed archive reaches — see this module's
    /// doc. Hand-packed rather than borrowed, and what it proves is
    /// bounded: that CLEAR is handled AS a reset rather than decoded as an
    /// ordinary dictionary code, and that the slot it frees (256) is
    /// refilled from the pre-clear `oldcode`.
    ///
    /// The stream is `A`, CLEAR, 256, `B`, 257, and every step of its tail
    /// depends on the reset having happened:
    ///
    /// - The code read immediately after a CLEAR is the ONE place a 256 is
    ///   not intercepted as another CLEAR, so it is also the only way a
    ///   dictionary chain can ever run through slot 256.
    /// - With `free_ent` reset to 256, that 256 is the KwKwK case (a code
    ///   naming the entry being built right now) and expands to `AA`; slot
    ///   256 is then refilled from the PRE-clear `oldcode`.
    /// - Slot 257 links back through 256, so the final code expands to
    ///   `AAB` — reachable only if slot 256 really was rewritten.
    ///
    /// Decoding to `AAABAAB` therefore falsifies three separate mistakes:
    /// reading CLEAR as an ordinary dictionary code, leaving `free_ent` at
    /// 257 across the reset (slot 256 then still holds the zeroed table),
    /// and skipping the post-clear insert altogether.
    #[test]
    fn a_clear_code_resets_the_dictionary_and_reuses_its_own_slot() {
        let codes = pack_nine_bit_codes(&[65, LZW_CLEAR, 256, 66, 257]);
        let mut crunched = vec![12u8];
        crunched.extend_from_slice(&codes);
        assert_eq!(
            lzw_decode(&crunched, LzwVariant::Crunched, "t").unwrap(),
            b"AAABAAB"
        );
        // The same codes in the Squashed dialect, which differs only in its
        // maximum width and its missing leading byte.
        assert_eq!(
            lzw_decode(&codes, LzwVariant::Squashed, "t").unwrap(),
            b"AAABAAB"
        );
    }

    #[test]
    fn an_empty_crunched_payload_is_corrupt_rather_than_a_panic() {
        let err = lzw_decode(&[], LzwVariant::Crunched, "t").unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
    }

    // ---- metadata ----

    /// `cpm.arc`'s entries stamp 1985-11-20, which is a date; `unarc-rs`'s
    /// halves of the same `u32` give month 0, which is not. See this
    /// module's doc.
    #[test]
    fn a_packed_timestamp_reads_date_from_the_low_half() {
        let mut ar = open_forward(CPM_ARC);
        let first = ar.next_entry().unwrap().expect("one entry");
        let mtime = first.meta().mtime.expect("cpm.arc entry 1 carries a date");
        let secs = mtime.duration_since(UNIX_EPOCH).unwrap().as_secs();
        // 1985-11-20T00:00:38Z, computed independently of this module.
        assert_eq!(secs, 501_292_800 + 38);
    }

    #[test]
    fn an_all_zero_timestamp_reports_no_mtime() {
        assert_eq!(arc_mtime(0), None);
    }

    /// ARC's record has no kind, mode, owner or group field, so every entry
    /// is a plain file with nothing else claimed.
    #[test]
    fn every_entry_is_a_plain_file_with_no_invented_metadata() {
        let mut ar = open_forward(STORE_ARC);
        let entry = ar.next_entry().unwrap().expect("one entry");
        let m = entry.meta();
        assert_eq!(m.kind, EntryKind::File);
        assert_eq!(m.mode, None);
        assert_eq!(m.uid, None);
        assert_eq!(m.gid, None);
        assert_eq!(m.size, Some(11_357));
        assert_eq!(m.compressed_size, Some(11_357));
    }

    // ---- capabilities ----

    /// `forward_parse: true` claimed and then proven, over a source whose
    /// `Seek` is erased at the type level rather than merely reported false.
    #[test]
    fn reads_every_entry_through_a_genuinely_non_seekable_source() {
        let mut ar = stuffr_core::testing::open_forward_only(&Arc, CPM_ARC);
        let mut got = Vec::new();
        while let Some(mut entry) = ar.next_entry().expect("forward-only next_entry") {
            let name = entry.meta().name.clone();
            let mut data = Vec::new();
            entry
                .reader()
                .read_to_end(&mut data)
                .expect("forward-only entry read");
            got.push((name, data));
        }
        assert_eq!(
            got,
            vec![
                ("DDTZ.COM".to_string(), DDTZ_COM.to_vec()),
                ("READ.COM".to_string(), READ_COM.to_vec()),
            ]
        );
    }

    #[test]
    fn by_index_is_refused_on_every_source_shape() {
        let mut fwd = stuffr_core::testing::open_forward_only(&Arc, STORE_ARC);
        assert!(
            matches!(fwd.by_index(0), Err(Error::NotSeekable { .. })),
            "a forward-only source must answer NotSeekable"
        );

        let path = std::env::temp_dir().join(format!(
            "stuffr-arc-seekable-{}-{:p}.arc",
            std::process::id(),
            STORE_ARC
        ));
        std::fs::write(&path, STORE_ARC).unwrap();
        let src: Box<dyn Source> = Box::new(stuffr_core::FileSource::open(&path).unwrap());
        let _ = std::fs::remove_file(&path);
        let resolved = stuffr_core::resolve(src, ARC, Arc.caps(), &StreamPolicy::default())
            .expect("resolve over a seekable source");
        let mut seekable = Arc.open(resolved, &OpenOpts::default()).unwrap();
        let err = seekable
            .by_index(0)
            .expect_err("ARC has no index to index into");
        assert!(
            matches!(err, Error::Unsupported(_)),
            "a seekable source with no index must answer Unsupported, not NotSeekable — \
             got {err:?}"
        );
        assert_eq!(err.exit_code(), 3, "{err}");
    }

    #[test]
    fn create_is_refused_as_a_capability_limit_not_a_panic() {
        match Arc.create(
            PlainSink::new(Box::new(stuffr_core::testing::SharedBuf::new())),
            &CreateOpts::default(),
        ) {
            Err(err) => {
                assert!(
                    matches!(err, Error::CapabilityUnavailable { .. }),
                    "got {err:?}"
                );
                assert_eq!(err.exit_code(), 3);
            }
            Ok(_) => panic!("ARC must refuse to write"),
        }
    }

    #[test]
    fn capabilities_and_metadata_match_the_format() {
        let c = Arc.caps();
        assert!(c.read && !c.write);
        assert!(c.forward_parse, "every size is in its own header");
        assert!(!c.needs_seek);
        assert_eq!(c.detects_corruption, CorruptionDetection::Always);
        let m = meta();
        assert_eq!(m.id, ARC);
        assert_eq!(m.extensions, &["arc", "pak"]);
    }

    /// Exactly one of the eleven registered rules may match a given archive
    /// — they differ only in the method byte, so two matching would mean the
    /// table had a duplicate. Run over every fixture, including the four
    /// whose method this build refuses to decode: detection and capability
    /// are different questions, and an unrecognised `license_crushed.pak`
    /// would be an unknown format (exit 2) instead of a named, unsupported
    /// method (exit 3).
    #[test]
    fn exactly_one_magic_rule_matches_each_fixture() {
        for (bytes, label) in [
            (CPM_ARC, "cpm.arc"),
            (STORE_ARC, "store.arc"),
            (CRUNCH_ARC, "crunch.arc"),
            (CRUNCH2_ARC, "crunch2.arc"),
            (SQUASHED_ARC, "squashed.arc"),
            (WRONGCRC16_ARC, "wrongcrc16.arc"),
            (LICENSE_PAK, "license.pak"),
            (LICENSE_CRUNCHED_PAK, "license_crunched.pak"),
            (LICENSE_SQUASHED_PAK, "license_squashed.pak"),
            (LICENSE_CRUSHED_PAK, "license_crushed.pak"),
        ] {
            let hits = ARC_MAGIC
                .iter()
                .filter(|r| {
                    bytes.len() >= r.offset + r.bytes.len()
                        && &bytes[r.offset..r.offset + r.bytes.len()] == r.bytes
                })
                .count();
            assert_eq!(hits, 1, "{label} matched {hits} magic rules, expected 1");
        }
    }
}
