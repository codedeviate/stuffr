//! ARJ: read via `unarj-rs`, written by this module's own store-only encoder.
//!
//! # No external witness exists for this format, and that shapes everything
//!
//! Read this before trusting any green test below. The other two writers
//! Phase 3c shipped each have an independent judge: `legacy::compress_z`'s
//! output is read back by the real `compress`(1)/`uncompress`(1), and
//! `legacy::lha`'s by `lhasa`, a decoder sharing no code with the `delharc`
//! this project reads through. **ARJ has neither.** `arj`/`unarj` are not
//! obtainable on this machine — not in Homebrew, not anywhere this project
//! could reach — so the round trip below is *this* encoder against *this*
//! decoder, and that decoder was built in Phase 3b against a fixture
//! (`fixtures/legacy/sample.arj`) hand-derived from `unarj-rs`'s own parser.
//!
//! A shared misreading of the ARJ specification therefore round-trips
//! perfectly, and that is not hypothetical: Phase 3b's own review found
//! exactly two, by decoding the fixture in Python against the published
//! header tables — the main header's `file_type` was `0` where the spec
//! requires `2`, and the local headers wanted `arj_flags = 0x10`
//! (`PATHSYM_FLAG`) that nothing set. **`unarj-rs` validates neither
//! field**, so no test in this repository could have caught either, and the
//! same blindness applies to everything this encoder writes into a field
//! the reader does not consult.
//!
//! Two things answer that, and only together:
//!
//! - The encoder reuses this module's own field layout, so encoder and
//!   decoder cannot DRIFT. That is the opposite of independent evidence —
//!   shared definitions guarantee agreement — which is why it is only half.
//! - [`spec_constraints_the_reader_never_checks`] asserts, on the bytes the
//!   encoder actually emits, the constraints the SPECIFICATION states and
//!   `unarj-rs` ignores. Each is cited to its line of "ARJ TECHNICAL
//!   INFORMATION" (April 1993, ARJ Software Inc.; the copy read is
//!   <https://www.opennet.ru/docs/formats/arj.txt>), not to `arj.rs`. A
//!   field the reader ignores is a field only a written-output assertion
//!   can protect.
//!
//! The same discipline applies to the fields the spec does NOT constrain,
//! and there are four: `archiver version number`, `minimum archiver version
//! to extract`, `security version` and [`FILESPEC_POSITION`]. Each is
//! written as 0, each is ARGUED — in `fixtures/legacy/MANIFEST.md`'s
//! `sample.arj` block, and for the last one in its own constant's doc — and
//! each is pinned by a test, so a zero nobody chose cannot appear among
//! zeros that were chosen. The last of the four was enumerated only in Task
//! 7's fix round, which is the point of writing the list down.
//!
//! [`the_encoder_reproduces_the_hand_built_fixture_byte_for_byte`] is the
//! third leg and the nearest thing here to a second opinion: `build_arj` (the
//! fixture recipe, hand-transcribed in Phase 3b) and [`ArjWrite`] (written
//! for this task) are two independent transcriptions of the same header
//! tables, and they agree byte for byte on the same two entries. That is
//! weaker than `lhasa` reading an `.lzh` — both transcriptions are this
//! project's — and it is said here as a limit, not a credential.
//!
//! # Store-only: ARJ's compressed methods are READ, never produced
//!
//! The reader accepts methods 0-4 (`Stored`, `CompressedMost`,
//! `Compressed`, `CompressedFaster`, `CompressedFastest`); the writer emits
//! **method 0, `Stored`, and nothing else** — every entry goes out
//! uncompressed. The spec permits it outright ("method (0 = stored, ...)"),
//! so the archives are real ARJ rather than a dialect, but
//! `ContainerCaps::write == true` means "stuffr can produce an ARJ archive",
//! never "stuffr can reproduce THIS ARJ archive's method" and never "stuffr
//! will make it smaller". Unpacking a compressed `.arj` and packing it again
//! yields a valid, LARGER `.arj` whose entries are stored: no data loss, no
//! compression either. The same asymmetry `legacy::lha` carries (seven
//! methods read, `-lh5-` written), and stated in the same three places —
//! [`Arj::caps`]'s own doc, this module doc, and `examples.txt`'s legacy
//! section — rather than left for a caller to discover from a file size.
//!
//! Why store-only rather than method 4: `unarj-rs` DECODES methods 1-3 by
//! handing them to `delharc`'s `-lh6-` decoder and method 4 to its own
//! `decode_fastest`, and has no encoder for any of them. Writing one would
//! mean implementing an ARJ-flavoured LZH encoder with no reference
//! implementation to check it against — the exact evidence gap this module
//! already has too much of.
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
//!     stores_dirs: true,
//!     ..ContainerCaps::read_write()  // read: true, write: true,
//! }                                  // forward_parse: false
//! ```
//!
//! `needs_seek` describes the READ side alone — the writer only ever
//! appends and needs no seek at all — but `ContainerCaps` has one flag for
//! both directions and the reading half is the binding one. Its consequence
//! for the conformance harness is written up in
//! `stuffr_core::container_conformance`'s `reachable_forward_only`: the
//! ladder can never hand this container a forward-only source, so
//! properties 5-8 SKIP for it (visibly, on stderr) while every other
//! property still runs over the spooled source a real caller gets.
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
//! compression method, before the method is even inspected. The obvious
//! field to guard is `original_size` — and that field does matter (a second
//! `vec![0; header.original_size]` for every method except `Stored`) — but
//! tracing the
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
//! On the WRITE side, every refusal is [`Error::Unsupported`] (exit 3) and
//! each names a limit of the FORMAT rather than of the input: a name
//! carrying an interior NUL (ARJ stores names NUL-terminated, so one would
//! silently truncate the entry's name), a header that would exceed the
//! spec's own 2600-byte maximum, a payload past the format's `u32` size
//! fields, and a `Symlink` or `Other` entry kind — ARJ's `file type` table
//! has no value for a link, so writing one as a regular file would put the
//! target text in the file's contents. Never a silent truncation, never a
//! quietly different kind. See [`ArjWrite::add`].
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
use std::cell::RefCell;
use std::io::{self, Read, Seek, SeekFrom};
use std::rc::Rc;
use std::time::SystemTime;

use unarj_rs::arj_archive::ArjArchieve;
use unarj_rs::date_time::DosDateTime;
use unarj_rs::local_file_header::{CompressionMethod, FileType, LocalFileHeader};
use unarj_rs::main_header::HostOS;

use super::dos;

use stuffr_core::{
    ArchiveRead, ArchiveWrite, Container, ContainerCaps, CorruptionDetection, CreateOpts, Entry,
    EntryKind, EntryMeta, Error, FidelityReport, FormatId, FormatMeta, MagicRule, OpenOpts,
    Resolved, Result, SeekRead, Sink, Source,
};

pub const ARJ: FormatId = FormatId::new("arj");

/// The two bytes every ARJ header opens with — spec, both header tables:
/// "header id (main and local file header) = 0x60 0xEA".
///
/// One table, three readers: the magic rule below, the end-of-archive
/// marker the writer emits ([`ARJ_END_OF_ARCHIVE`]), and the guard's own
/// scan ([`seek_past_the_next_header_id`]).
const ARJ_HEADER_ID: [u8; 2] = [0x60, 0xEA];

/// ARJ's header id, at offset 0 of both the main header and every local
/// file header — see `fixtures/legacy/MANIFEST.md` for the full envelope
/// this frames.
const ARJ_MAGIC: &[MagicRule] = &[MagicRule {
    offset: 0,
    bytes: &ARJ_HEADER_ID,
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

    /// # `write: true` means STORED, and it has no external witness
    ///
    /// Two warnings sit behind this flag, and both are wider than
    /// `ContainerCaps` can express, so read them before believing it:
    ///
    /// 1. **The writer emits compression method 0 (`Stored`) and nothing
    ///    else**, while the reader accepts methods 0-4. `ContainerCaps` has
    ///    no per-method field and this task did not invent one, so a caller
    ///    reading `write: true` learns "stuffr can produce an ARJ archive",
    ///    never "stuffr can reproduce THIS archive's method" and never
    ///    "stuffr will make it smaller" — re-packing a compressed `.arj`
    ///    through `stuffr unpack`/`stuffr pack` produces a valid, LARGER
    ///    `.arj` whose entries are stored. Deliberate (see the module doc's
    ///    "Store-only" section for why method 4 was not attempted), not an
    ///    oversight, and stated for a user in `examples.txt`'s legacy
    ///    section too.
    /// 2. **Nothing outside this crate has ever read what this writer
    ///    produces.** No `arj`/`unarj` binary is obtainable here, so the
    ///    round trip is this encoder against this decoder — see the module
    ///    doc's first section for what is done about that and what is not.
    ///
    /// `stores_dirs: true` is a separate, narrower claim and it is genuine:
    /// a directory goes out with the spec's own `file type` value `3`
    /// (`3 = directory`), carries no payload, and [`ArjRead::next_entry`]
    /// reads it back as [`EntryKind::Dir`].
    ///
    /// `stores_symlinks` stays false, and here the format is the reason
    /// rather than this build: the spec's local-file-header `file type`
    /// table lists `0 = binary, 1 = 7-bit text, 3 = directory, 4 = volume
    /// label` and has no value for a link at all. Claiming it would produce
    /// exactly the lie the field exists to prevent — a regular file whose
    /// CONTENTS are the target text.
    fn caps(&self) -> ContainerCaps {
        // See `lha.rs`'s twin for why the constructor rather than a literal.
        // `needs_seek: true` is the one thing ARJ must override: `unarj-rs`
        // cannot read an archive at all without `Seek`. It describes the
        // READ side — the writer only appends — but the field covers both
        // directions and the reading half binds.
        ContainerCaps {
            needs_seek: true,
            // Every ARJ entry carries a CRC-32, checked by `unarj-rs` once
            // the payload is decoded — mandated by the format, so `Always`,
            // the same declaration `lha` makes for its CRC-16.
            detects_corruption: CorruptionDetection::Always,
            stores_dirs: true,
            ..ContainerCaps::read_write()
        }
    }

    fn open(&self, resolved: Resolved, _o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
        let Resolved { source, report, .. } = resolved;
        let src: SharedSource = Rc::new(RefCell::new(ArjGuardedReader::new(source)));
        // The MAIN header is parsed by `ArjArchieve::new` itself, by a
        // parser of its own with its own fixed-prefix rule, and panics on
        // the same two shapes a local header does — see
        // `refuse_a_header_unarj_would_panic_on`.
        refuse_a_header_unarj_would_panic_on(&mut src.borrow_mut(), HeaderShape::Main)?;
        let archive = ArjArchieve::new(ArjSeekAdapter(Rc::clone(&src))).map_err(classify_arj_io)?;
        Ok(Box::new(ArjRead {
            archive,
            src,
            report,
            done: false,
        }))
    }

    /// Writes ARJ headers with `Stored` payloads. See [`ArjWrite`].
    ///
    /// `CreateOpts::level` is deliberately ignored rather than validated,
    /// the same ruling `lha.rs`'s `create` records for the same reason: this
    /// build writes ONE compression method, and there is no second knob a
    /// number could select. Refusing a level would be worse — `stuffr pack
    /// --level 6 -o x.arj` is a reasonable thing to type, and the only
    /// honest answers are "ignored" or "invent a mapping onto methods 1-4",
    /// which this build cannot write.
    ///
    /// The main header is NOT written here, and that is load-bearing rather
    /// than lazy: `Container::create` is the one call the conformance
    /// harness's own `build()` unwraps with a generic panic, so a write
    /// failure surfacing from here would kill property 4 in setup instead
    /// of being the error that property exists to catch. It is written by
    /// whichever of [`ArjWrite::add`] or [`ArjWrite::finish`] runs first.
    fn create(&self, dst: Box<dyn Sink>, _o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
        Ok(Box::new(ArjWrite {
            dst: Some(dst),
            wrote_main_header: false,
        }))
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
struct ArjSeekAdapter(SharedSource);

impl Read for ArjSeekAdapter {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.borrow_mut().read(buf)
    }
}

impl Seek for ArjSeekAdapter {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.0.borrow_mut().seek(pos)
    }
}

/// The ladder's source, shared between the [`ArjSeekAdapter`] that
/// `ArjArchieve` owns and the [`ArjRead`] that owns the archive.
///
/// **This is what lets a guard run at all.** `ArjArchieve<T>` takes its
/// reader by value into a PRIVATE field and exposes no accessor, so without
/// this handle `ArjRead` could not look at one byte of the archive it is
/// reading — and every guard below is a look at bytes `unarj-rs` is about
/// to parse. `Rc`/`RefCell` rather than `Arc`/`Mutex` because the two
/// holders live and die together inside one `Box<dyn ArchiveRead>`, which
/// carries no `Send` bound, and because no call below holds a borrow across
/// a call into the crate.
type SharedSource = Rc<RefCell<ArjGuardedReader>>;

/// Sits between the ladder's source and `unarj-rs` for the archive's whole
/// lifetime, so every header that crate is about to parse — and the first
/// byte of every method-4 payload it is about to decode — is inspected
/// first. The shape `ar.rs`'s [`ArGuardedReader`] established, on a
/// container that can seek.
///
/// [`ArGuardedReader`]: crate::ar
///
/// # Why a guard rather than a fix upstream
///
/// `unarj-rs` 0.2.1 panics on four distinct CLI-reachable inputs, and a
/// panic is the one failure shape `stuffr_core::testing::
/// check_error_is_classified` can NEVER see: it is not an `Error`, so the
/// fuzz target aborts before the oracle runs. That is how all four survived
/// a format fuzzed at 200,000 executions, and it is the same lesson
/// `ar.rs`'s own 68-byte panic taught.
///
/// # The private facts of `unarj-rs` 0.2.1 this guard mirrors
///
/// The crate is pinned `=0.2.1` (see `Cargo.toml`'s own note, which pins it
/// for a second reason: it declares no `rust-version`). **A `0.2.x` patch
/// release that changes any of the six facts below desyncs this guard
/// silently**, and the two failure directions are not equally bad:
///
/// 1. `arj_archive::read_header` finds a header by SCANNING for `0x60
///    0xEA`, one byte at a time, resuming after the PAIR when the second
///    byte is not `0xEA` — so `60 60 EA` holds no header id as far as that
///    crate is concerned. [`seek_past_the_next_header_id`] reproduces that
///    acceptance exactly; a scanner that merely looked for a two-byte
///    window would find a header where the crate finds none, validate the
///    wrong bytes, and could REFUSE A VALID ARCHIVE.
/// 2. That scan runs from the reader's CURRENT position, and the position
///    when `get_next_entry` is called is where the previous entry's payload
///    ended — which is why the guard runs at exactly the two call sites
///    below and not once over the whole file.
/// 3. `read_header` answers an EMPTY content for a declared size of zero
///    (end of archive), refuses a declared size over 2600 itself
///    ([`MAX_ARJ_HEADER_SIZE`]), and verifies the content's CRC-32 BEFORE
///    handing it to a parser. The guard reproduces all three so that it
///    refuses only inputs the crate would otherwise reach a parser with —
///    every other shape keeps the crate's own error, unchanged.
/// 4. `MainHeader::load_from` consumes 30 fixed bytes, plus 4 more when the
///    content's first byte (`first_hdr_size`) is >= 34.
/// 5. `LocalFileHeader::load_from` consumes 30 fixed bytes, plus 4 more
///    when `first_hdr_size` is > 30, plus 12 more when it is >= 46 — a
///    DIFFERENT rule from the main header's, and not the spec's "the name
///    starts at `first_hdr_size`" either (see `arj_salvage.rs`'s module
///    doc, which does not call `load_from` at all for exactly this reason).
///    Both parsers then read two NUL-terminated strings with a `while
///    $x[0] != 0` loop that is bounded by nothing.
/// 6. `decode_fastest` compares `back_ptr > res.len() - 1` with `res` empty
///    on the first iteration — see
///    [`refuse_a_method_4_payload_unarj_would_panic_on`].
///
/// The safe direction, if the pin ever moves and a fact goes stale, is a
/// guard that refuses LESS than it should: a panic returns, loudly, and the
/// tests named in each guard's doc go red. The unsafe direction is fact 1,
/// which is why it is the fact
/// [`tests::a_false_header_id_unarj_walks_past_never_refuses_the_archive_behind_it`]
/// was written for.
///
/// **None of those tests is what actually pins the mirror, though**, and the
/// distinction is the one this task's review corrected: they stand on
/// hand-built inputs, so a drift they do not happen to exercise fails
/// nothing. [`tests::the_guard_refuses_exactly_what_unarj_panics_on`] is the
/// real instrument — it asserts the equivalence "this guard refuses X ⟺ the
/// UNGUARDED crate panics on X" over a generated corpus, which needs no
/// access to the offset `read_header` chose and therefore survives a patch
/// bump. That is the remedy `CLAUDE.md` prescribes for the identical
/// `ar = "=0.9.0"` hazard and has never had there.
struct ArjGuardedReader {
    inner: Box<dyn Source>,
    /// The scan window [`seek_past_the_next_header_id`] reads through,
    /// allocated ONCE per archive rather than once per header.
    ///
    /// The first shipped version of this guard allocated and zeroed
    /// [`HEADER_SCAN_CHUNK`] inside the scan, which runs once per
    /// `next_entry` — measured in release on archives of 8-byte Stored
    /// entries, `stuffr list` went 0.07s -> 0.20s at 20,000 entries and
    /// 0.85s -> 2.78s at 160,000. Linear, not the quadratic shape
    /// `cpio.rs`'s per-entry `PeekSource` had, but a 3-4x constant for
    /// nothing. Reused here, the shape `CpioSource` and `ArGuardedReader`
    /// each already have for the same reason.
    scan_buf: Vec<u8>,
}

impl ArjGuardedReader {
    fn new(inner: Box<dyn Source>) -> Self {
        ArjGuardedReader {
            inner,
            scan_buf: vec![0u8; HEADER_SCAN_CHUNK],
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }

    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let seek: &mut dyn SeekRead = self
            .inner
            .as_seek()
            .ok_or_else(|| io::Error::other("arj: source reported seekable but cannot seek"))?;
        seek.seek(pos)
    }

    /// Where `unarj-rs` will read from next. Only ever called between calls
    /// into that crate, never during one.
    fn position(&mut self) -> io::Result<u64> {
        self.seek(SeekFrom::Current(0))
    }

    /// Fills `buf` exactly, or answers `false` — including for a genuine
    /// I/O failure. Every caller below is a GUARD, and a guard that cannot
    /// read the bytes it wanted to inspect has nothing to say: the crate
    /// meets the same source a moment later and raises its own error for
    /// it, which is the answer a user should get.
    fn read_exactly(&mut self, buf: &mut [u8]) -> bool {
        let mut filled = 0;
        while filled < buf.len() {
            match self.read(&mut buf[filled..]) {
                Ok(0) => return false,
                Ok(n) => filled += n,
                Err(_) => return false,
            }
        }
        true
    }
}

/// Bytes read per [`seek_past_the_next_header_id`] chunk, so the scan's
/// memory use does not depend on how far away the next header id is. The
/// crate's own scan reads ONE byte per `read` call; this one reads the same
/// bytes and reaches the same verdict, in fewer calls.
const HEADER_SCAN_CHUNK: usize = 64 * 1024;

/// The first read [`scan_window`] issues, before the growth to
/// [`HEADER_SCAN_CHUNK`]. A header id normally sits at the scan's own first
/// byte, so this is the size that decides what a well-formed archive pays
/// per entry — see [`scan_window`]'s doc.
const FIRST_SCAN_READ: usize = 512;

/// Which of `unarj-rs`'s two header parsers is about to run, which is the
/// only thing the guard needs to tell them apart for: they consume
/// DIFFERENT numbers of fixed bytes before the two NUL-terminated strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeaderShape {
    /// `MainHeader::load_from`, which `ArjArchieve::new` runs on the first
    /// header of the archive and on no other.
    Main,
    /// `LocalFileHeader::load_from`, which `get_next_entry` runs on every
    /// header after it.
    Local,
}

impl HeaderShape {
    /// How many bytes this parser consumes before it reaches the name — the
    /// figure a content shorter than which makes it index past its own
    /// slice. Facts 4 and 5 of [`ArjGuardedReader`]'s doc, transcribed from
    /// `main_header.rs:66-94` and `local_file_header.rs:93-126`.
    fn fixed_prefix(self, first_hdr_size: u8) -> usize {
        match self {
            // `if header_size >= FIRST_HDR_SIZE (34) { 4 more }`.
            HeaderShape::Main if first_hdr_size >= 34 => 34,
            HeaderShape::Main => 30,
            // `if header_size > STD_HDR_SIZE (30) { 4 more; if header_size
            // >= R9_HDR_SIZE (46) { 12 more } }`.
            HeaderShape::Local if first_hdr_size >= 46 => 46,
            HeaderShape::Local if first_hdr_size > 30 => 34,
            HeaderShape::Local => 30,
        }
    }
}

/// Refuses, as [`Error::Corrupt`] (exit 5), a header `unarj-rs` would index
/// past the end of while parsing — and leaves every other shape to the
/// crate's own error, byte for byte.
///
/// Two of the four panics this task closed are here: a CRC-VALID basic
/// header shorter than the 30-byte structure both parsers walk
/// unconditionally (`local_file_header.rs:95`, `main_header.rs:68`), and
/// one whose content holds no NUL for the parser's `while $x[0] != 0` loop
/// to stop at (`local_file_header.rs:128`). Exit 5 rather than 6 by
/// `Error::exit_code`'s own rule, written once there: nothing was
/// allocated on the header's say-so and no larger machine could make the
/// archive readable — the header contradicts the fixed structure it
/// declares itself to have.
///
/// The cursor is always restored, so the crate reads exactly the bytes it
/// would have read had this function not run.
fn refuse_a_header_unarj_would_panic_on(
    src: &mut ArjGuardedReader,
    shape: HeaderShape,
) -> Result<()> {
    let resume = src.position().map_err(Error::Io)?;
    let verdict = match content_unarj_will_parse(src) {
        Some(content) => refuse_unparseable_content(&content, shape),
        None => Ok(()),
    };
    src.seek(SeekFrom::Start(resume)).map_err(Error::Io)?;
    verdict
}

/// The basic-header content `unarj_rs::arj_archive::read_header` is about
/// to hand one of its two parsers, or `None` for every shape that function
/// answers for itself — no header id before the end of the source, the
/// zero-size end-of-archive marker, a declared size past
/// [`MAX_ARJ_HEADER_SIZE`], a content the source is too short for, and a
/// content whose recorded CRC-32 does not reproduce.
///
/// Fact 3 of [`ArjGuardedReader`]'s doc. Every `None` above is a case the
/// crate either accepts or refuses in its own words, and the guard staying
/// silent for all of them is what keeps its refusals a strict subset of
/// "would have panicked".
fn content_unarj_will_parse(src: &mut ArjGuardedReader) -> Option<Vec<u8>> {
    seek_past_the_next_header_id(src)?;

    let mut size_buf = [0u8; 2];
    if !src.read_exactly(&mut size_buf) {
        return None;
    }
    let declared = usize::from(u16::from_le_bytes(size_buf));
    if declared == 0 || declared > MAX_ARJ_HEADER_SIZE {
        return None;
    }

    // Bounded by the 2600-byte ceiling checked one line above, which is the
    // crate's own and the spec's — never by a figure the file supplies.
    let mut content = vec![0u8; declared];
    if !src.read_exactly(&mut content) {
        return None;
    }
    let mut recorded = [0u8; 4];
    if !src.read_exactly(&mut recorded) {
        return None;
    }
    if crc32_ieee(&content) != u32::from_le_bytes(recorded) {
        return None;
    }
    Some(content)
}

/// Leaves the source positioned just past the next `0x60 0xEA` pair
/// `unarj_rs::arj_archive::read_header` would find, or `None` when that
/// function would run out of input first.
///
/// **Fact 1 of [`ArjGuardedReader`]'s doc, and the one worth reading the
/// crate's loop for:**
///
/// ```text
/// loop {
///     reader.read_exact(&mut u8_buf)?;
///     if u8_buf[0] != ARJ_MAGIC_1 { continue; }
///     reader.read_exact(&mut u8_buf)?;
///     if u8_buf[0] == ARJ_MAGIC_2 { break; }
/// }
/// ```
///
/// A `0x60` whose successor is not `0xEA` consumes BOTH bytes, so the scan
/// resumes past the pair rather than re-examining the second byte — and
/// `60 60 EA` therefore holds no header id at all for this crate. The index
/// rule below reproduces exactly that, chunked;
/// [`tests::the_guard_refuses_exactly_what_unarj_panics_on`] is what would
/// notice if it ever stopped agreeing, and
/// [`tests::a_false_header_id_unarj_walks_past_never_refuses_the_archive_behind_it`]
/// is the hand-built case that names the shape.
///
/// The window is [`ArjGuardedReader::scan_buf`], borrowed out and put back
/// rather than allocated here — see that field's own doc for what allocating
/// it per header measured.
fn seek_past_the_next_header_id(src: &mut ArjGuardedReader) -> Option<u64> {
    // `scan_buf` cannot stay borrowed from `src` while `src.read` runs, so
    // it is taken and restored. Every `?` below is inside `scan_window`, so
    // the buffer always comes back.
    let mut window = std::mem::take(&mut src.scan_buf);
    if window.len() != HEADER_SCAN_CHUNK {
        window.resize(HEADER_SCAN_CHUNK, 0);
    }
    let found = scan_window(src, &mut window);
    src.scan_buf = window;
    found
}

/// [`seek_past_the_next_header_id`]'s loop, with the window supplied.
///
/// The read GROWS from [`FIRST_SCAN_READ`] to the window's full size rather
/// than asking for 64 KiB every time, and that is the second half of LOW-1:
/// on a healthy archive the id is at the scan's very first byte, so a 64 KiB
/// read per header moves three orders of magnitude more bytes than the
/// answer needs — and the guard then seeks back over all of it. The growth
/// keeps a long walk through a damaged region cheap without charging a
/// well-formed archive for it.
fn scan_window(src: &mut ArjGuardedReader, window: &mut [u8]) -> Option<u64> {
    let mut base = src.position().ok()?;
    let mut expect_second_byte = false;
    let mut want = FIRST_SCAN_READ.min(window.len());
    loop {
        let n = match src.read(&mut window[..want]) {
            Ok(0) | Err(_) => return None,
            Ok(n) => n,
        };
        want = (want * 2).min(window.len());
        for (i, &b) in window[..n].iter().enumerate() {
            if expect_second_byte {
                expect_second_byte = false;
                if b == ARJ_HEADER_ID[1] {
                    let past = base.checked_add(i as u64)?.checked_add(1)?;
                    src.seek(SeekFrom::Start(past)).ok()?;
                    return Some(past);
                }
            } else if b == ARJ_HEADER_ID[0] {
                expect_second_byte = true;
            }
        }
        base = base.checked_add(n as u64)?;
    }
}

/// Refuses a basic-header content that the parser named by `shape` would
/// index past the end of.
///
/// The three refusals are the three ways `load_from` runs off its own
/// slice, and each names the figure the header itself declared, because a
/// user reading exit 5 deserves the contradiction rather than the verdict
/// alone.
fn refuse_unparseable_content(content: &[u8], shape: HeaderShape) -> Result<()> {
    let Some(&first_hdr_size) = content.first() else {
        // Unreachable through `content_unarj_will_parse`: `read_header`
        // answers an EMPTY content only for a declared size of zero, which
        // it reports as end-of-archive and never parses. Refused rather
        // than assumed away, since the alternative is the panic this whole
        // function exists to stop.
        return Err(Error::Corrupt(
            "ARJ header declares no content at all; there is nothing to parse".into(),
        ));
    };

    let fixed = shape.fixed_prefix(first_hdr_size);
    if content.len() < fixed {
        return Err(Error::Corrupt(format!(
            "ARJ header declares {} bytes of content but its `first_hdr_size` of \
             {first_hdr_size} puts the entry name at byte {fixed}; the header is shorter \
             than the fixed structure it claims to have",
            content.len()
        )));
    }

    let strings = &content[fixed..];
    let Some(name_nul) = strings.iter().position(|&b| b == 0) else {
        return Err(Error::Corrupt(format!(
            "ARJ header's {} bytes of name and comment hold no NUL terminator; the name \
             runs past the end of the header that declared it",
            strings.len()
        )));
    };
    if !strings[name_nul + 1..].contains(&0) {
        return Err(Error::Corrupt(format!(
            "ARJ header's comment runs past the end of the header: {} byte(s) follow the \
             name's terminator and none of them is a NUL",
            strings.len() - name_nul - 1
        )));
    }
    Ok(())
}

/// Whether a method-4 (`CompressedFastest`) stream opens with a
/// back-reference, from its first byte alone.
///
/// # This is a real panic in a dependency, on one bit of input
///
/// `unarj_rs::decode_fastest` (0.2.1, `decode_fastest.rs:38`) evaluates
/// `back_ptr > res.len() - 1` for every token that is not a literal, and
/// `res` is EMPTY on the first iteration — so a stream whose first token is
/// a match underflows a `usize` and aborts the process (`attempt to
/// subtract with overflow` in a debug build; a wrapped comparison and then
/// an out-of-range index at `decode_fastest.rs:46` in a release one).
///
/// The predicate is exactly one BIT. `decode_val(r, 0, 7)` reads one bit
/// and breaks immediately on a zero, answering `len == 0` — a literal; any
/// other first bit means a match. The stream is MSB-first
/// (`BitReader::endian(data, BigEndian)`), so "the first token is a match"
/// is precisely `first & 0x80 != 0`.
///
/// **Refusing on this bit never costs a decodable entry**, which is what
/// makes a one-bit guard defensible in front of a whole decoder: with `res`
/// empty, every stream reaching the match branch either underflows there or
/// runs out of bits before it, and the second answers
/// `io::ErrorKind::UnexpectedEof` — `Error::Corrupt`, exit 5, the same
/// verdict this guard gives. Swept over all 256 first-byte values by
/// [`tests::the_method_4_guard_is_exact_over_every_first_payload_byte`].
pub(super) const fn opens_with_a_backreference(first: u8) -> bool {
    first & 0x80 != 0
}

/// Refuses, as [`Error::Corrupt`] (exit 5), the method-4 payload
/// `unarj_rs::decode_fastest` would underflow a `usize` on — the third of
/// the four panics, and the only one that is not a header.
///
/// This is the "cheap local guard" rather than another pass of the header
/// wrapper above, because everything it needs is already in hand: the
/// header `get_next_entry` just returned, and a source positioned at the
/// first payload byte (`get_next_entry` leaves it there — fact 2 of
/// [`ArjGuardedReader`]'s doc — which is the same position
/// `ArjArchieve::read` itself reads the payload from).
///
/// Exit 5, not 6, by `Error::exit_code`'s rule: the bytes were read and
/// found to contradict themselves — a back-reference into an output that
/// does not exist yet — and nothing was allocated on their say-so.
///
/// A `compressed_size` or `original_size` of zero is left alone: the crate
/// never reaches the subtraction for either (`while res.len() <
/// original_size` does not run for the second, and an empty `data` fails
/// its first bit read for the first).
fn refuse_a_method_4_payload_unarj_would_panic_on(
    src: &mut ArjGuardedReader,
    name: &str,
    header: &LocalFileHeader,
) -> Result<()> {
    if header.compression_method != CompressionMethod::CompressedFastest
        || header.original_size == 0
        || header.compressed_size == 0
    {
        return Ok(());
    }

    let resume = src.position().map_err(Error::Io)?;
    let mut first = [0u8; 1];
    let read_it = src.read_exactly(&mut first);
    src.seek(SeekFrom::Start(resume)).map_err(Error::Io)?;

    if read_it && opens_with_a_backreference(first[0]) {
        return Err(Error::Corrupt(format!(
            "entry `{name}` is stored with ARJ method 4 and its stream opens with a \
             back-reference, which would copy from an output that does not exist yet"
        )));
    }
    Ok(())
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
pub(super) const MAX_ARJ_ENTRY_LEN: u64 = 256 * 1024 * 1024;

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
///
/// The calendar arithmetic itself lives in [`super::dos`], shared with
/// `legacy::arc`; only the unpacking of ARJ's own fields is here, because
/// the two formats pack the halves of their `u32` in opposite orders and
/// that is the detail each container has to get right for itself.
pub(super) fn dos_mtime(dt: DosDateTime) -> Option<SystemTime> {
    dos::mtime(
        i64::from(dt.year()),
        u32::from(dt.month()),
        u32::from(dt.day()),
        u32::from(dt.hour()),
        u32::from(dt.minute()),
        u32::from(dt.second()),
    )
}

/// The entry's unix permission bits, or `None` when this header does not
/// carry any.
///
/// The spec's local-file-header table gives offset 24 as a bare `2 file
/// access mode` with no interpretation of its own, one row below `1 host
/// OS`. That ordering is the rule: the field is HOST-DEFINED, so only a
/// header declaring `host OS = 2 (UNIX)` puts a unix mode there. An MS-DOS
/// archive puts DOS attribute bits in the same two bytes, and reporting
/// those as [`EntryMeta::mode`] would be a lie in exactly the shape
/// `cpio.rs`'s type-bit note warns about — a number a caller would then
/// `chmod` with.
///
/// Zero is reported as absent rather than as mode `0`, and that is a second
/// deliberate narrowing: `0o000` is not a mode any real archiver records
/// for a stored file, while a hand-built or minimal header (this project's
/// own `sample.arj` included, whose two entries carry zero here) leaves the
/// field unset. Reporting `Some(0)` would make `stuffr list -l` print
/// `----------` for every such entry, which reads as a fact and is an
/// absence.
fn unix_mode(header: &LocalFileHeader) -> Option<u32> {
    if header.host_os != HostOS::Unix || header.file_access_mode == 0 {
        return None;
    }
    Some(u32::from(header.file_access_mode))
}

struct ArjRead {
    archive: ArjArchieve<ArjSeekAdapter>,
    /// The same source the archive reads through — see [`SharedSource`] for
    /// why a second handle to it is what makes every guard below possible.
    src: SharedSource,
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

        // THE HEADER GUARD — `get_next_entry` parses the header it reads
        // with `LocalFileHeader::load_from`, which indexes past the end of
        // its own slice on two shapes rather than answering an error. Runs
        // here, against the source's CURRENT position, because that is
        // where the crate's own scan is about to start.
        if let Err(e) =
            refuse_a_header_unarj_would_panic_on(&mut self.src.borrow_mut(), HeaderShape::Local)
        {
            self.done = true;
            return Err(e);
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
        let mode = unix_mode(&header);

        if header.file_type == FileType::Directory {
            // A directory carries no payload this container cares about.
            // `skip` advances the underlying reader past whatever bytes the
            // header still declares (ordinarily zero for a directory)
            // rather than decoding them, because `get_next_entry` does not
            // skip unread payload itself (see this module's doc / the
            // fixture's own envelope layout in MANIFEST.md).
            //
            // What that buys is narrower than "otherwise the next header is
            // unreachable", and the difference is worth stating because it
            // is what makes this call testable: `unarj_rs`'s `read_header`
            // SCANS byte by byte for the `60 EA` magic (crate 0.2.1,
            // `arj_archive.rs:129-140`), so an unskipped payload is usually
            // walked over and the next real header still found. The payload
            // that is NOT harmless is one CONTAINING those two bytes — the
            // scan stops inside it and parses entry data as a header.
            // `a_directory_entry_is_reported_as_dir_and_the_next_entry_is_
            // still_found` uses exactly such a payload, so removing this
            // call turns that test red rather than leaving it green.
            if let Err(e) = self.archive.skip(&header) {
                self.done = true;
                return Err(classify_arj_io(e));
            }
            let meta = EntryMeta {
                name,
                size: Some(0),
                compressed_size: Some(0),
                mtime,
                mode,
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

        // THE PAYLOAD GUARD — `ArjArchieve::read` hands a method-4 payload
        // straight to `decode_fastest`, which underflows a `usize` when the
        // stream's first token is a back-reference. The source sits at the
        // first payload byte right now, which is the only moment this is
        // visible from outside the crate.
        if let Err(e) = refuse_a_method_4_payload_unarj_would_panic_on(
            &mut self.src.borrow_mut(),
            &name,
            &header,
        ) {
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
            mode,
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

// ---------------------------------------------------------------------------
// The write side.
//
// Every constant below is cited to "ARJ TECHNICAL INFORMATION" (April 1993,
// ARJ Software Inc.), the copy read being
// <https://www.opennet.ru/docs/formats/arj.txt>, and NOT to `unarj-rs` —
// that crate validates almost none of them, so a value derived from its
// parser would only be this project agreeing with itself. See this module's
// doc's first section, and `spec_constraints_the_reader_never_checks`, which
// asserts the ones the reader ignores against the bytes actually emitted.
// ---------------------------------------------------------------------------

/// `first_hdr_size` — the spec's "size up to and including 'extra data'".
///
/// Both header tables run `first_hdr_size` (1) + archiver version (1) +
/// minimum version (1) + host OS (1) + arj flags (1) + [security version |
/// method] (1) + file type (1) + reserved (1) + four `u32` fields (16) +
/// three `u16` fields (6) = 30 bytes, with no `extra data` behind them:
/// the local header's "extra data" is "4 bytes ... when EXTFILE_FLAG is set,
/// 0 bytes otherwise", and this writer never sets that flag.
///
/// 30 is also at or below `unarj-rs`'s own `STD_HDR_SIZE` (30) and
/// `FIRST_HDR_SIZE` (34) thresholds, so that crate reads neither header's
/// conditional extension block — which is why this writer emits none.
pub(super) const ARJ_FIRST_HDR_SIZE: u8 = 30;

/// Spec, both header tables: "maximum header size is 2600" — of the *basic
/// header size*, i.e. `first_hdr_size + strlen(filename) + 1 +
/// strlen(comment) + 1`, the count the `u16` after the magic carries.
///
/// This is a WRITER constraint, not only a reader one, and it is the reason
/// [`ArjWrite::add`] refuses an over-long name instead of truncating it:
/// `unarj_rs::arj_archive::read_header` enforces the same ceiling on the way
/// in ("Header size is too big", `io::ErrorKind::InvalidData`), so an
/// archive written past it would be one stuffr itself reports as corrupt.
pub(super) const MAX_ARJ_HEADER_SIZE: usize = 2600;

/// The longest name this writer will store, from the identity above with an
/// empty comment: 2600 - 30 (`first_hdr_size`) - 1 (name NUL) - 1 (comment
/// NUL).
///
/// Refused rather than truncated, for the reason `lha.rs`'s
/// `MAX_LEVEL1_NAME` gives: two names differing only past the cut would
/// collapse onto one and extraction would overwrite one with the other.
const MAX_ARJ_NAME_LEN: usize = MAX_ARJ_HEADER_SIZE - ARJ_FIRST_HDR_SIZE as usize - 2;

/// Spec, both header tables: "host OS (0 = MSDOS, 1 = PRIMOS, 2 = UNIX, ...)".
///
/// Chosen for what it means to a READER of `file access mode`: that field is
/// host-defined, and only `2` makes it a unix mode. See [`unix_mode`], the
/// read-side twin of this choice.
pub(super) const HOST_OS_UNIX: u8 = 2;

/// Spec, MAIN header table only: "file type (must equal 2)".
///
/// The strongest "must" in either table, and `unarj-rs` parses the byte into
/// `MainHeader::file_type` and never looks at it — which is how Phase 3b
/// shipped a fixture with `0` here that every test in this repository
/// accepted. Pinned by `spec_constraints_the_reader_never_checks`.
pub(super) const MAIN_HEADER_FILE_TYPE: u8 = 2;

/// Spec, LOCAL file header table: "arj flags ... (0x10 = PATHSYM_FLAG)
/// indicates filename translated ("\" changed to "/")".
///
/// Set on exactly the entries whose stored name uses `/` as a separator,
/// which for this writer is every name that contains one:
/// [`EntryMeta::name`] is already `/`-separated by the time a container sees
/// it. A cleared flag beside such a name entitles a spec-conformant reader
/// to take `/` as a literal character in a flat filename.
/// `unarj_rs::local_file_header::LocalFileHeader::is_path_sym` exists but
/// nothing in that crate — or in this module's reader — calls it, so only a
/// written-output assertion can protect this.
const PATHSYM_FLAG: u8 = 0x10;

/// Spec, LOCAL file header table: "method (0 = stored, 1 = compressed most
/// ... 4 compressed fastest)". This build writes `0` and only `0` — see the
/// module doc's "Store-only" section.
const METHOD_STORED: u8 = 0;

/// Spec, LOCAL file header table: "file type (0 = binary, 1 = 7-bit text)
/// (3 = directory, 4 = volume label)".
const FILE_TYPE_BINARY: u8 = 0;
pub(super) const FILE_TYPE_DIRECTORY: u8 = 3;

/// `filespec position in filename` — 2 bytes in BOTH header tables, written
/// as 0 by this encoder on every header, and that is a RULING, not an
/// oversight.
///
/// # What the specification actually says
///
/// Nothing beyond the field's name. The line is `2   filespec position in
/// filename` in the main-header table and again, identically, in the
/// local-file-header table, with no prose anywhere in the document, no
/// worked example of a stored filename, no statement of whether the value
/// is 0- or 1-based, and no rule for a name carrying no path at all. That
/// was checked, not assumed: the published text was re-read for every
/// occurrence of "filespec", and the independent transcription at
/// `fileformat.info/format/arj/corion.htm` (offset `001Ah`, `1 word`) gives
/// the same bare line. `unarj-rs` parses it into
/// `LocalFileHeader::file_spec_position` and reads it nowhere.
///
/// The name is strongly suggestive — the offset within `filename` at which
/// the file spec proper begins, i.e. the length of the leading path, so 4
/// for `dir/inner.txt` — and that reading is what a search engine will
/// summarise back at you. It is not what any obtainable document states,
/// and this module does not manufacture citations: see the module doc's
/// first section for why that standard is stricter here than anywhere else
/// in this workspace.
///
/// # Why 0 rather than the evident value
///
/// Because the two are not symmetric in what they cost when wrong, and
/// there is no witness to tell us which we are.
///
/// 0 says "the file spec starts at the start of the filename" — there is no
/// leading path to skip. An extractor honouring it uses the WHOLE stored
/// name, which is exactly what stuffr means: `pack` stores full relative
/// paths and `unpack` recreates the tree from them. So the worst a
/// path-stripping tool does with 0 is decline to strip, which a user can
/// see and undo.
///
/// A computed value that is off by one, or 1-based where the reader is
/// 0-based, makes that same tool cut the wrong number of characters off
/// every name in the archive — a silently mangled tree, in the one format
/// in this workspace with nothing outside the project able to notice. The
/// asymmetry is the argument.
///
/// **Revisit the moment a real `arj`/`unarj` binary is available**: one
/// `xxd` of a genuine multi-directory archive settles both the semantics
/// and the base, and computing it then costs four lines here and a matching
/// edit to `build_arj`. Recorded in `fixtures/legacy/MANIFEST.md` alongside
/// the three other fields left at 0, and pinned by
/// `spec_constraints_the_reader_never_checks` so it cannot drift into a
/// value nobody argued for.
const FILESPEC_POSITION: u16 = 0;

/// CRC-32/ISO-HDLC (reflected polynomial 0xEDB88320, init and xorout
/// 0xFFFFFFFF) — the check an ARJ header records for the entry's original
/// bytes, and the one its own basic-header CRC field carries over the header
/// content.
///
/// Written here rather than taken from `legacy::crc` (which holds CRC-16/ARC
/// alone, the check ARC, ZOO and LHA carry) or from `crc32fast`: `unarj-rs`
/// depends on `crc32fast` internally but re-exports nothing, and pulling in
/// a direct dependency for one 12-line routine would add a crate to every
/// build for no capability. Pinned to the algorithm's published check value
/// by `crc32_ieee_matches_the_standard_check_value`, so a transcription
/// error in the polynomial cannot hide behind this project's own
/// expectations.
///
/// The test module carries a SECOND, separate copy (`fixture_crc32`), and
/// that duplication is deliberate rather than an oversight: `build_arj` is
/// the checked-in fixture's own hand-transcribed recipe, and a recipe that
/// borrowed the code under test would stop being independent of it. The
/// same argument `stuffr_core::container_conformance`'s `crc16_arc_witness`
/// makes for its own copy. Both are pinned to the identical published check
/// value, so a transcription error in one cannot silently agree with a
/// transcription error in the other.
pub(super) fn crc32_ieee(data: &[u8]) -> u32 {
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

/// Packs a `SystemTime` into the DOS `YYYYYYYM MMMDDDDD hhhhhmmm mmmsssss`
/// word an ARJ header's `date time modified` field holds — the exact inverse
/// of the unpacking [`dos_mtime`] performs through
/// `unarj_rs::date_time::DosDateTime`.
///
/// `None`, which the caller stores as a literal zero, outside MS-DOS's own
/// 1980..=2107 range and before the epoch. Zero is the "no timestamp" shape
/// `dos_mtime` already answers `None` to (month 0 is not a month), so the
/// absence round-trips as an absence rather than as some arbitrary date.
///
/// The seconds field is halved because DOS records seconds in units of two,
/// so an odd second rounds DOWN — never up, so a restored mtime is never
/// later than the original, the same ruling `lha.rs`'s `dos_timestamp`
/// records.
///
/// A near-copy of that function, deliberately: `legacy::dos` shares the
/// CALENDAR arithmetic and its module doc explains at length why each
/// container keeps its own bit layout — ARC packs the two halves of its
/// `u32` in the opposite order, and a shared "pack a DOS timestamp" helper
/// would bury the one detail each caller has to get right. That ARJ's layout
/// and LHA's coincide is a fact about MS-DOS, not a shared abstraction.
fn dos_timestamp(t: SystemTime) -> Option<u32> {
    let (year, month, day, hour, minute, second) = dos::civil_fields(t)?;
    let year = u32::try_from(year - 1980).ok()?;
    if year > 0x7F {
        return None;
    }
    Some((year << 25) | (month << 21) | (day << 16) | (hour << 11) | (minute << 5) | (second / 2))
}

/// Wraps one header's CONTENT in ARJ's envelope, which both header tables
/// share: the `0x60 0xEA` id, a little-endian `u16` basic header size, the
/// content, a little-endian `u32` basic header CRC over it, and a
/// little-endian `u16` zero — the "1st extended header size (0 if none)"
/// that `unarj_rs::arj_archive::read_extended_headers` reads immediately
/// after EVERY header, main or local.
///
/// The spec's own note is why no CRC follows that zero: "1st extended
/// header's CRC (not present when 0 extended header size)".
fn wrap_header(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 2 + content.len() + 4 + 2);
    out.extend_from_slice(&[0x60, 0xEA]);
    out.extend_from_slice(&(content.len() as u16).to_le_bytes());
    out.extend_from_slice(content);
    out.extend_from_slice(&crc32_ieee(content).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// The archive main header, wrapped and ready to write.
///
/// Every field the spec's main-header table lists is emitted, in order, at
/// its stated width. Four of them are deliberately zero and each is a
/// ruling rather than an omission — see
/// `fixtures/legacy/MANIFEST.md`'s `sample.arj` section, which argues the
/// identical choices for the fixture this reproduces byte for byte:
///
/// - `archiver version number` / `minimum archiver version to extract`: the
///   table states no range, no reserved value and no rule that 0 is illegal,
///   so there is nothing here to conform TO. Real ARJ would write its own
///   release number; this was not written by ARJ.
/// - `security version`: the table's note is "(2 = current)", not a "must
///   equal" like `file type`'s. This archive is not secured (SECURED_FLAG is
///   clear), and with no tool anywhere to check a written value against,
///   0 is left as it is rather than invented. Recorded as an open question
///   in this task's report rather than quietly closed.
/// - The two date-time fields, `archive size` and the security-envelope
///   fields: an archive stuffr writes is not secured, not a volume, and
///   carries no name of its own, so there is nothing true to put in them.
///
/// `arj flags` is 0, and specifically PATHSYM_FLAG is NOT set: in the MAIN
/// header that bit "indicates archive name translated", and this writer
/// emits an empty archive name. (The per-entry flag is a different byte in a
/// different header — see [`PATHSYM_FLAG`].)
fn build_main_header() -> Vec<u8> {
    let mut content = Vec::with_capacity(ARJ_FIRST_HDR_SIZE as usize + 2);
    content.push(ARJ_FIRST_HDR_SIZE);
    content.push(0); // archiver version number
    content.push(0); // minimum archiver version to extract
    content.push(HOST_OS_UNIX);
    content.push(0); // arj flags: not secured, not a volume, no name to translate
    content.push(0); // security version
    content.push(MAIN_HEADER_FILE_TYPE);
    content.push(0); // reserved
    content.extend_from_slice(&0u32.to_le_bytes()); // date time created
    content.extend_from_slice(&0u32.to_le_bytes()); // date time last modified
    content.extend_from_slice(&0u32.to_le_bytes()); // archive size
    content.extend_from_slice(&0u32.to_le_bytes()); // security envelope position
    content.extend_from_slice(&FILESPEC_POSITION.to_le_bytes()); // see the constant's own doc
    content.extend_from_slice(&0u16.to_le_bytes()); // security envelope length
    content.extend_from_slice(&0u16.to_le_bytes()); // currently not used
    debug_assert_eq!(
        content.len(),
        ARJ_FIRST_HDR_SIZE as usize,
        "ARJ_FIRST_HDR_SIZE no longer describes the main header's fixed prefix"
    );
    content.push(0); // archive name (empty, null-terminated)
    content.push(0); // archive comment (empty, null-terminated)
    wrap_header(&content)
}

/// The spec's end-of-archive marker: the header id followed by a basic
/// header size of 0 ("= 0 if end of archive").
///
/// Exactly four bytes, never six: `read_header` returns on a zero length
/// BEFORE reading the CRC that a non-empty header would carry.
///
/// Unlike LHA's terminator this one is NOT optional, and the difference
/// matters — `read_header` scans for the id with `read_exact`, so an archive
/// that simply stopped would raise `UnexpectedEof` rather than ending
/// cleanly. Writing it is what makes a cut tail detectable *and* what makes
/// a well-formed archive readable at all, so there is no version of the
/// "writing an optional trailer hides truncation" argument `lha.rs`'s
/// `finish` makes to have here.
const ARJ_END_OF_ARCHIVE: [u8; 4] = [ARJ_HEADER_ID[0], ARJ_HEADER_ID[1], 0x00, 0x00];

/// An entry payload this build refuses, because ARJ's size fields are `u32`.
fn check_u32_size(name: &str, size: u64) -> Result<u32> {
    u32::try_from(size).map_err(|_| {
        Error::Unsupported(format!(
            "ARJ cannot store `{name}`: {size} bytes exceeds the format's 4 GiB (u32) \
             per-entry size field"
        ))
    })
}

/// The ARJ writer: one main header, one local file header per entry with a
/// `Stored` payload, and the end-of-archive marker.
///
/// # Why an entry is buffered whole, and what that costs
///
/// An ARJ local file header declares the entry's compressed size, its
/// original size AND its CRC-32 *before* the payload, and this project's
/// writers must work over a non-seekable destination (a pipe), so there is
/// nowhere to go back and patch those three fields in. The payload is
/// therefore read fully before its header can be written. A property of the
/// FORMAT, not a shortcut — `zip` solves the same problem with data
/// descriptors, which ARJ has no equivalent of.
///
/// The cost is one copy of the entry, not `legacy::lha`'s ~8.4x: nothing
/// compresses, so the buffer IS the payload and no token vector is built
/// beside it. Nothing accumulates across entries either — each is written
/// through and its buffer dropped — so a 10,000-entry archive of small
/// files costs what its largest single entry costs.
///
/// Unbounded, deliberately, for the reason `lha.rs`'s twin gives: the threat
/// model is local files the user named, a fixed ceiling would refuse files
/// this machine can hold, and `CreateOpts` carries no memory budget for a
/// container to consult. [`MAX_ARJ_ENTRY_LEN`] bounds the READ side, where
/// the size comes from a hostile header rather than from `stat`.
struct ArjWrite {
    /// `None` once `finish` has consumed it.
    dst: Option<Box<dyn Sink>>,
    /// Whether the archive main header has been written yet. It is emitted
    /// by whichever of `add`/`finish` runs first, never by `create` — see
    /// [`Arj::create`] for why that matters to conformance property 4.
    wrote_main_header: bool,
}

impl ArjWrite {
    /// Emits the main header if it has not gone out yet, and hands back the
    /// destination.
    fn dst_ready(&mut self) -> Result<&mut Box<dyn Sink>> {
        let wrote = self.wrote_main_header;
        let dst = self
            .dst
            .as_mut()
            .ok_or_else(|| Error::Usage("ARJ writer used after finish()".into()))?;
        if !wrote {
            dst.write_all(&build_main_header())?;
        }
        self.wrote_main_header = true;
        Ok(dst)
    }
}

impl ArchiveWrite for ArjWrite {
    fn add(&mut self, meta: &EntryMeta, data: &mut dyn Read) -> Result<()> {
        // ARJ stores a name as a null-terminated string (both header tables:
        // "filename (null-terminated string)"), so an interior NUL would
        // silently END the name there and leave the rest to be parsed as the
        // comment. Refused rather than truncated or escaped: `EntryMeta::name`
        // is a `String`, which may legally hold one, and a name that came
        // back shorter than it went in is the shape `ar.rs`'s inline-slash
        // defect had.
        if meta.name.as_bytes().contains(&0) {
            return Err(Error::Unsupported(format!(
                "ARJ cannot store `{}`: its name contains a NUL byte, and ARJ stores names \
                 null-terminated",
                meta.name.escape_debug()
            )));
        }
        let name = meta.name.as_bytes();
        if name.len() > MAX_ARJ_NAME_LEN {
            return Err(Error::Unsupported(format!(
                "ARJ cannot store `{}`: its name is {} bytes, and the format's maximum basic \
                 header size of {MAX_ARJ_HEADER_SIZE} leaves room for at most \
                 {MAX_ARJ_NAME_LEN}",
                meta.name,
                name.len()
            )));
        }

        let (file_type, payload) = match &meta.kind {
            // No payload and no CRC to compute: file type 3 says
            // "directory" and everything else about the entry is the
            // header. `data` is deliberately not read, the same contract
            // `tar.rs`, `cpio.rs` and `lha.rs` apply to this kind. The name
            // is stored verbatim, with no trailing separator added — ARJ
            // records the kind in a field of its own, so it needs none (and
            // `lha.rs`'s `-lhd-` note about lhasa does not apply here).
            EntryKind::Dir => (FILE_TYPE_DIRECTORY, Vec::new()),
            EntryKind::File => {
                // Refused off the DECLARED size first, before a byte is read
                // or allocated, exactly as `cpio.rs` and `lha.rs` do: a
                // caller who already knows an entry is oversized costs
                // nothing to refuse.
                if let Some(size) = meta.size {
                    check_u32_size(&meta.name, size)?;
                }
                let mut raw = Vec::new();
                data.read_to_end(&mut raw)?;
                (FILE_TYPE_BINARY, raw)
            }
            // `Symlink` and `Other` both land here. The spec's `file type`
            // table has no value for a link at all, so there is nothing
            // honest to write: stored as a regular file, the target text
            // becomes the file's contents. `caps().stores_symlinks` is
            // false, so `entries.rs` warns and skips before reaching here;
            // only a hand-built plan can, and it gets a named refusal.
            other => {
                return Err(Error::Unsupported(format!(
                    "ARJ cannot store `{}`: this build writes regular files and directories, \
                     not {other:?}",
                    meta.name
                )));
            }
        };

        let size = check_u32_size(&meta.name, payload.len() as u64)?;
        // PATHSYM_FLAG, and nothing else: not garbled (no password), not a
        // volume, no EXTFILE starting-position field, not a backup.
        let arj_flags = if meta.name.contains('/') {
            PATHSYM_FLAG
        } else {
            0
        };
        let timestamp = meta.mtime.and_then(dos_timestamp).unwrap_or(0);
        // Host-defined by the `host OS` byte above it, which this writer
        // always sets to UNIX — see [`unix_mode`], which will only read it
        // back under that same condition. Masked rather than refused: a mode
        // reaches a container through `entries.rs`'s `mode_of`, which has
        // already masked it to 0o7777.
        let access_mode = meta.mode.map_or(0u16, |m| (m & 0xFFFF) as u16);

        let mut content = Vec::with_capacity(ARJ_FIRST_HDR_SIZE as usize + name.len() + 2);
        content.push(ARJ_FIRST_HDR_SIZE);
        content.push(0); // archiver version number
        content.push(0); // minimum archiver version to extract
        content.push(HOST_OS_UNIX);
        content.push(arj_flags);
        content.push(METHOD_STORED);
        content.push(file_type);
        content.push(0); // reserved
        content.extend_from_slice(&timestamp.to_le_bytes());
        content.extend_from_slice(&size.to_le_bytes()); // compressed size
        content.extend_from_slice(&size.to_le_bytes()); // original size (Stored: equal)
        content.extend_from_slice(&crc32_ieee(&payload).to_le_bytes());
        content.extend_from_slice(&FILESPEC_POSITION.to_le_bytes()); // see the constant's doc
        content.extend_from_slice(&access_mode.to_le_bytes());
        content.extend_from_slice(&0u16.to_le_bytes()); // host data (currently not used)
        debug_assert_eq!(
            content.len(),
            ARJ_FIRST_HDR_SIZE as usize,
            "ARJ_FIRST_HDR_SIZE no longer describes a local file header's fixed prefix"
        );
        content.extend_from_slice(name);
        content.push(0); // name terminator
        content.push(0); // comment (empty, null-terminated)

        let header = wrap_header(&content);
        let dst = self.dst_ready()?;
        dst.write_all(&header)?;
        dst.write_all(&payload)?;
        Ok(())
    }

    /// Writes the end-of-archive marker and returns the destination.
    ///
    /// The main header goes out here too when nothing was added, which is
    /// the only spelling an EMPTY ARJ archive has: `ArjArchieve::new`
    /// raises "Archive ends without any headers" on a zero-length stream,
    /// so a file with no main header is not a readable empty archive at all.
    ///
    /// Never via `Drop` — see `tar.rs`'s own `finish` doc for why that is
    /// the one path a caller may rely on. The destination is returned, not
    /// finished: the caller owns completion, because a codec layer beneath
    /// us may have its own trailer still to write.
    fn finish(mut self: Box<Self>) -> Result<Box<dyn Sink>> {
        {
            let dst = self.dst_ready().map_err(|e| match e {
                Error::Usage(_) => Error::Usage("ARJ writer finished twice".into()),
                other => other,
            })?;
            dst.write_all(&ARJ_END_OF_ARCHIVE)?;
        }
        self.dst
            .take()
            .ok_or_else(|| Error::Usage("ARJ writer finished twice".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;
    use stuffr_core::testing::{
        ContainerFixture, ExpectedEntry, assert_container_conforms_skipping,
        assert_container_conforms_with_skipping,
    };
    use stuffr_core::{CreateOpts, OpenOpts, PlainSink, ReaderSource, StreamPolicy};

    const SAMPLE_ARJ: &[u8] = include_bytes!("../../fixtures/legacy/sample.arj");

    const ARJ_EXPECTED: &[ExpectedEntry] = &[
        ExpectedEntry::new("sample/hello.txt", b"alpha\n"),
        ExpectedEntry::new("sample/sub/b.bin", b"beta\n"),
    ];

    fn arj_fixture() -> ContainerFixture {
        ContainerFixture::new(
            SAMPLE_ARJ,
            ARJ_EXPECTED,
            "hand-built ARJ archive (two Stored/method-0 entries), constructed by \
                         tracing unarj-rs 0.2.1's own parser source field-by-field \
                         (local_file_header.rs, main_header.rs, arj_archive.rs) — NOT verified \
                         against any independent ARJ reader, since none is installed on this \
                         machine and none is obtainable (arj/unarj are not in Homebrew). This \
                         is the WEAKEST provenance in the phase: a mistake shared between this \
                         fixture's construction and unarj-rs's own parser would agree with \
                         itself and pass undetected. ARJ GAINED AN ENCODER IN PHASE 3C TASK 7 \
                         AND THAT DID NOT CHANGE THIS: the writer is a second transcription of \
                         the same published header tables by the same project, so \
                         `stuffr pack --format arj` round-tripping proves only that stuffr \
                         agrees with stuffr. This fixture must therefore NEVER be regenerated \
                         with that encoder — an input produced by the code under test is no \
                         input at all. See fixtures/legacy/MANIFEST.md's `sample.arj` entry \
                         and this module's `build_arj` for the exact byte layout, the equality \
                         test that pins the checked-in fixture to it, and \
                         `spec_constraints_the_reader_never_checks` for the fields the \
                         SPECIFICATION constrains and unarj-rs does not.",
        )
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

    /// The PRODUCTION CRC-32 — the one the encoder writes into every basic
    /// header CRC and every entry's `original file's CRC` — against the
    /// algorithm's published check value. Separate from the fixture
    /// recipe's own copy below, on purpose; see `crc32_ieee`'s doc.
    #[test]
    fn crc32_ieee_matches_the_standard_check_value() {
        // CRC-32/ISO-HDLC's standard check: the ASCII string "123456789" ->
        // 0xCBF43926, from the CRC RevEng catalogue. An external constant,
        // so an error in the polynomial or the init value cannot hide
        // behind our own expectations.
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn the_fixture_recipes_crc32_matches_the_standard_check_value() {
        // The universally-cited CRC-32/ISO-HDLC check value for the ASCII
        // string "123456789" — the same value every implementation of this
        // algorithm (zlib, crc32fast, etc.) is verified against.
        assert_eq!(fixture_crc32(b"123456789"), 0xCBF4_3926);
    }

    /// Wraps `content` (either a main header's or a local file header's
    /// parsed fields) in ARJ's header envelope: magic, a little-endian u16
    /// content length, the content itself, a little-endian u32 CRC-32 over
    /// the content, and a trailing zero `u16` — the "no extended headers"
    /// terminator `unarj_rs::arj_archive::read_extended_headers` expects
    /// immediately after every header (main or local), traced from that
    /// function's own source. See `MANIFEST.md` for the full envelope.
    fn fixture_wrap_header(content: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 2 + content.len() + 4 + 2);
        out.extend_from_slice(&[0x60, 0xEA]);
        out.extend_from_slice(&(content.len() as u16).to_le_bytes());
        out.extend_from_slice(content);
        out.extend_from_slice(&fixture_crc32(content).to_le_bytes());
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
    fn fixture_main_header() -> Vec<u8> {
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
        fixture_wrap_header(&content)
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
        // PATHSYM_FLAG. The spec's local-file-header table reads
        // "(0x10 = PATHSYM_FLAG) indicates filename translated
        // (\\ changed to /)", and both of this fixture's names use `/` as
        // their separator — so a cleared flag makes the header contradict
        // the bytes right after it, and entitles a spec-conformant reader
        // to treat `/` as a literal character in a flat filename. Nothing
        // in this repository could have caught that: `unarj-rs` never reads
        // the byte and applies no translation either way (see
        // `fixtures/legacy/MANIFEST.md`), which is precisely the
        // parser-agrees-with-itself shape the `file_type = 2` deviation
        // already had.
        header.push(0x10); // arj_flags = PATHSYM_FLAG
        header.push(0); // compression_method = Stored
        header.push(0); // file_type = Binary
        header.push(0); // reserved (skipped by the parser)
        header.extend_from_slice(&0u32.to_le_bytes()); // date_time_modified
        header.extend_from_slice(&(content.len() as u32).to_le_bytes()); // compressed_size
        header.extend_from_slice(&(content.len() as u32).to_le_bytes()); // original_size
        header.extend_from_slice(&fixture_crc32(content).to_le_bytes()); // original_crc32
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

        let mut out = fixture_wrap_header(&header);
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
        let mut out = fixture_main_header();
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

    /// Rewrites the checked-in `sample.arj` from [`build_arj`]. Ignored by
    /// default — it WRITES into the source tree — and exists so that a
    /// deliberate change to the recipe above has a mechanical way to land in
    /// the fixture, rather than leaving
    /// `the_checked_in_fixture_matches_its_own_construction_recipe` red with
    /// no way to fix it but a hex editor:
    ///
    /// ```text
    /// cargo test -p stuffr-formats --features arj --lib \
    ///     regenerate_the_checked_in_fixture -- --ignored
    /// ```
    ///
    /// Re-read `MANIFEST.md`'s `sample.arj` section afterwards: its byte
    /// layout and total-size arithmetic are prose, and nothing recomputes
    /// them.
    #[test]
    #[ignore = "writes into the source tree; run with --ignored after changing build_arj"]
    fn regenerate_the_checked_in_fixture() {
        let built = build_arj(&[
            ("sample/hello.txt", b"alpha\n"),
            ("sample/sub/b.bin", b"beta\n"),
        ]);
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("legacy")
            .join("sample.arj");
        std::fs::write(&path, &built).unwrap();
    }

    /// Builds an archive through the REAL writer, the way every write-side
    /// test below and the conformance harness itself reaches it.
    ///
    /// Deliberately NOT what `build_arj` above does, and the separation is
    /// the whole point: `build_arj` is the checked-in fixture's own
    /// hand-transcribed recipe and must stay independent of the encoder, or
    /// `the_checked_in_fixture_matches_its_own_construction_recipe` becomes
    /// a test of nothing.
    fn write_arj(entries: &[(EntryMeta, &[u8])]) -> Vec<u8> {
        let buf = stuffr_core::testing::SharedBuf::new();
        let mut w = Arj
            .create(
                PlainSink::new(Box::new(buf.clone())),
                &CreateOpts::default(),
            )
            .expect("create");
        for (meta, data) in entries {
            w.add(meta, &mut io::Cursor::new(*data)).expect("add");
        }
        w.finish().expect("finish").finish().expect("sink finish");
        buf.contents()
    }

    /// The error `write_arj`'s happy path would have unwrapped.
    fn write_one_expecting_error(meta: &EntryMeta, data: &[u8]) -> Error {
        let buf = stuffr_core::testing::SharedBuf::new();
        let mut w = Arj
            .create(
                PlainSink::new(Box::new(buf.clone())),
                &CreateOpts::default(),
            )
            .expect("create");
        w.add(meta, &mut io::Cursor::new(data))
            .expect_err("this entry must be refused")
    }

    /// The FULL thirteen-property harness, not the fixture-driven one — ARJ
    /// graduated when `ContainerCaps::write` became true in Phase 3c Task 7.
    ///
    /// Read a failure's prefix carefully: this raises `property N` (1-13)
    /// while [`arj_conforms`] below still raises `fixture property N`
    /// (1-10), and six numbers mean different things in the two schemes.
    ///
    /// Properties 5-8 SKIP here, visibly, on stderr, and that is correct
    /// rather than a gap: they all need the ladder to hand this container a
    /// forward-only source, which `needs_seek: true` makes impossible — see
    /// `stuffr_core::container_conformance`'s `reachable_forward_only`.
    /// `by_index_is_always_unsupported` and
    /// `a_piped_source_is_spooled_and_reads_back_correctly` below are what
    /// own those claims for this container's real source shapes.
    #[test]
    fn arj_conforms_with_a_writer() {
        // Skips 7 and 8, and the list is ASSERTED rather than reported to
        // stderr — see `PropertyLedger` in `container_conformance.rs` for
        // the demonstration that made that necessary (truncation detection
        // silently disabled for every `needs_seek` container, whole suite
        // green). 7: ARJ has no trailing index. 8: incrementality is
        // unmeasurable once the ladder spools, because the spool reads the
        // whole archive before this container sees a byte.
        //
        // **5 and 6 are NOT skipped.** They take their spilled second form:
        // a piped ARJ must still yield every entry at `Rung::Spilled`, and
        // `by_index` over that spooled source must answer the right entry or
        // a classified refusal. `by_index_is_always_unsupported` below pins
        // WHICH refusal ARJ gives; the harness pins that it is an honest one.
        assert_container_conforms_skipping(&Arj, &meta(), &[7, 8]);
    }

    /// **The constraints the ARJ SPECIFICATION states and no reader in this
    /// tree checks**, asserted against the bytes the encoder actually emits.
    ///
    /// This test is the counterweight to the encoder reusing this module's
    /// field layout. Shared definitions stop the encoder and the decoder
    /// DRIFTING, which is worth having — but they also guarantee agreement,
    /// and agreement is exactly how a shared misreading survives. Phase 3b's
    /// review found two such misreadings in `sample.arj` by decoding it
    /// against the published tables in Python, and neither could have been
    /// caught from inside this repository, because `unarj-rs` parses both
    /// fields into structs nothing consults.
    ///
    /// Every expectation below is cited to "ARJ TECHNICAL INFORMATION"
    /// (April 1993, ARJ Software Inc.;
    /// <https://www.opennet.ru/docs/formats/arj.txt>), and the bytes are
    /// walked with this test's OWN offset arithmetic rather than through
    /// `unarj-rs` — reading them back with the parser that ignores them
    /// would prove nothing at all.
    #[test]
    fn spec_constraints_the_reader_never_checks() {
        // One name WITH a separator and one without, so the PATHSYM claim
        // is tested in both directions. A test whose every name contained
        // `/` would pass with the flag hard-coded on.
        let bytes = write_arj(&[
            (EntryMeta::file("dir/inner.txt"), &b"alpha"[..]),
            (EntryMeta::file("flat.txt"), &b"beta"[..]),
        ]);

        // --- the archive main header ------------------------------------
        // Envelope: "2 header id ... = 0x60 0xEA", "2 basic header size".
        assert_eq!(&bytes[0..2], &[0x60, 0xEA], "header id");
        let main_len = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
        let main = &bytes[4..4 + main_len];

        // "basic header size (from 'first_hdr_size' thru 'comment' below)
        //  = first_hdr_size + strlen(filename) + 1 + strlen(comment) + 1".
        // Written with the writer's actual strings rather than folded
        // constants, so the identity stays readable against the spec.
        // `unarj-rs` reads the length but never checks it against this
        // identity — it simply trusts the u16.
        let archive_name = ""; // this writer emits no archive name...
        let comment = ""; // ...and no comment, on any header
        assert_eq!(
            main_len,
            usize::from(main[0]) + archive_name.len() + 1 + comment.len() + 1,
            "main basic header size must satisfy the spec's own identity"
        );
        assert!(
            main_len <= MAX_ARJ_HEADER_SIZE,
            "spec: maximum header size is {MAX_ARJ_HEADER_SIZE}"
        );

        // "1 file type (must equal 2)" — offset 6 of the content, the
        // STRONGEST must in either table, and the one Phase 3b shipped
        // wrong. `unarj-rs` parses it into `MainHeader::file_type` and
        // never reads it.
        assert_eq!(
            main[6], 2,
            "spec: the main header's file type must equal 2 — this is the field Phase 3b \
             shipped as 0 with every test in this repository green"
        );
        // "1 host OS (... 2 = UNIX)": the field that makes `file access
        // mode` a unix mode rather than DOS attribute bits.
        assert_eq!(main[3], 2, "spec: host OS 2 = UNIX");
        // "1 arj flags ... (0x10 = PATHSYM_FLAG) indicates ARCHIVE NAME
        // translated". The archive name is empty, so the bit must be
        // CLEAR — the main header's flag is about a different string than
        // the per-entry one, and setting it here would be the same class
        // of lie in the opposite direction.
        assert_eq!(
            main[4] & 0x10,
            0,
            "spec: the main header's PATHSYM_FLAG describes the ARCHIVE NAME, which is empty"
        );
        assert_eq!(main[4], 0, "not secured, not a volume, not a backup");
        // "2 filespec position in filename" — main header, offset 24.
        // Written 0 deliberately; see `FILESPEC_POSITION`'s own doc for the
        // argument, which is that no obtainable document states this
        // field's semantics and the two candidate values fail differently.
        // Asserted here rather than only argued in prose, because nothing
        // reads the field and only a written-output assertion can protect
        // it — the same reason this whole test exists.
        assert_eq!(
            u16::from_le_bytes([main[24], main[25]]),
            0,
            "the main header's filespec position is 0 by ruling, not by accident"
        );

        // --- each local file header -------------------------------------
        // Walked with this test's own arithmetic, so a parser that ignores
        // these fields cannot launder them.
        let mut at = 4 + main_len + 4 /* basic header CRC */ + 2 /* ext hdr size = 0 */;
        for (name, payload) in [("dir/inner.txt", &b"alpha"[..]), ("flat.txt", &b"beta"[..])] {
            assert_eq!(
                &bytes[at..at + 2],
                &[0x60, 0xEA],
                "local header id for {name}"
            );
            let len = u16::from_le_bytes([bytes[at + 2], bytes[at + 3]]) as usize;
            let h = &bytes[at + 4..at + 4 + len];

            // The same identity, now with a real filename in it.
            assert_eq!(
                len,
                usize::from(h[0]) + name.len() + 1 + comment.len() + 1,
                "local basic header size must satisfy the spec's own identity for {name}"
            );
            assert!(len <= MAX_ARJ_HEADER_SIZE, "spec: maximum header size");

            // "1 arj flags ... (0x10 = PATHSYM_FLAG) indicates filename
            // translated ("\\" changed to "/")". `unarj-rs` exposes
            // `LocalFileHeader::is_path_sym()` and calls it nowhere; this
            // module's reader does not call it either. Only this
            // assertion protects it.
            let want_pathsym = name.contains('/');
            assert_eq!(
                h[4] & PATHSYM_FLAG != 0,
                want_pathsym,
                "spec: PATHSYM_FLAG must be set exactly when the stored name uses `/` \
                 as a separator — {name}"
            );
            // The other five flag bits are claims this writer must not
            // make: GARBLED (passworded), VOLUME (split), EXTFILE (a
            // starting-position field this header does not carry) and
            // BACKUP.
            assert_eq!(
                h[4] & !PATHSYM_FLAG,
                0,
                "spec: no other arj flag is true of what this writer emits — {name}"
            );
            // "1 method (0 = stored, ...)" and "1 file type (0 = binary,
            // 1 = 7-bit text) (3 = directory, 4 = volume label)".
            assert_eq!(h[5], 0, "spec: method 0 = stored — {name}");
            assert_eq!(h[6], 0, "spec: file type 0 = binary — {name}");
            assert_eq!(h[3], 2, "spec: host OS 2 = UNIX — {name}");
            // "2 filespec position in filename", local header offset 24.
            // 0 for BOTH names, including the one carrying a path, where
            // the evident value would be 4. See `FILESPEC_POSITION`'s doc:
            // no obtainable document states the semantics or even the base,
            // and 0's failure mode (a path-stripping tool declines to
            // strip) is visible and undoable where a wrong offset's (every
            // name cut at the wrong place) is silent.
            assert_eq!(
                u16::from_le_bytes([h[24], h[25]]),
                0,
                "the filespec position is 0 by ruling, not by accident — {name}"
            );

            // "4 compressed size" / "4 original size": equal under
            // `Stored`, and both the real payload length. A header
            // declaring one thing and delivering another is what
            // `an_entry_whose_header_lies_about_its_size_is_corrupt`
            // below refuses on the way back IN.
            let csize = u32::from_le_bytes(h[12..16].try_into().unwrap());
            let osize = u32::from_le_bytes(h[16..20].try_into().unwrap());
            assert_eq!(csize as usize, payload.len(), "compressed size — {name}");
            assert_eq!(
                osize, csize,
                "spec: stored, so the two sizes agree — {name}"
            );

            // "? filename (null-terminated string)": stored verbatim, and
            // followed by exactly one NUL and then the empty comment's.
            assert_eq!(
                &h[30..30 + name.len()],
                name.as_bytes(),
                "filename — {name}"
            );
            assert_eq!(h[30 + name.len()], 0, "name terminator — {name}");
            assert_eq!(h[len - 1], 0, "comment terminator — {name}");

            at += 4 + len + 4 + 2 + payload.len();
        }

        // "2 basic header size ... = 0 if end of archive", and no CRC
        // after it.
        assert_eq!(
            &bytes[at..],
            &ARJ_END_OF_ARCHIVE,
            "spec: the archive ends with the header id and a zero basic header size"
        );
    }

    /// Two independent transcriptions of the same published header tables
    /// agreeing byte for byte — the nearest thing to a second opinion this
    /// format has, and said as a limit rather than a credential.
    ///
    /// `build_arj` was hand-written in Phase 3b from the spec and from
    /// `unarj-rs`'s parser; [`ArjWrite`] was written for Task 7 from the
    /// spec's own field tables. Both are this project's, so this is NOT the
    /// external witness `lhasa` gives LHA — but a transcription error in
    /// either one now has to be an error BOTH made identically, which is a
    /// materially higher bar than a round trip through a single
    /// implementation clears.
    ///
    /// It is also what keeps the encoder honest about every zero field:
    /// `archiver version number`, `security version` and the rest are
    /// argued once, in `fixtures/legacy/MANIFEST.md`, and this test is what
    /// stops the encoder quietly choosing differently from the fixture that
    /// argument covers.
    #[test]
    fn the_encoder_reproduces_the_hand_built_fixture_byte_for_byte() {
        let written = write_arj(&[
            (EntryMeta::file("sample/hello.txt"), &b"alpha\n"[..]),
            (EntryMeta::file("sample/sub/b.bin"), &b"beta\n"[..]),
        ]);
        assert_eq!(
            written, SAMPLE_ARJ,
            "the encoder and the fixture recipe are two transcriptions of one specification; \
             a disagreement means one of them is wrong, and MANIFEST.md's `sample.arj` \
             section is where the ruling for every field lives"
        );
    }

    /// A symlink has no `file type` value in ARJ's own table, so it is
    /// refused rather than written as a regular file whose CONTENTS are the
    /// target text. `EntryKind::Other` takes the same arm.
    #[test]
    fn a_symlink_is_refused_rather_than_written_as_something_else() {
        let mut meta = EntryMeta::file("link");
        meta.kind = EntryKind::Symlink {
            target: "a.txt".into(),
        };
        let err = write_one_expecting_error(&meta, b"");
        assert!(
            matches!(err, Error::Unsupported(_)),
            "a kind this format cannot record is a capability limit, not damage; got {err:?}"
        );
        assert_eq!(err.exit_code(), 3);
        assert!(
            err.to_string().contains("link"),
            "the refusal must name the entry: {err}"
        );
    }

    /// The spec's own ceiling, enforced on the way OUT: "maximum header
    /// size is 2600". Refused, never truncated — two names differing only
    /// past the cut would collapse onto one and extraction would overwrite
    /// one with the other.
    ///
    /// The boundary is walked rather than merely exceeded: the longest name
    /// that fits must still round-trip, so the guard is bounded by the
    /// format's limit and not by "any long name".
    ///
    /// **The boundary length is a literal derived from the SPEC, not from
    /// [`MAX_ARJ_NAME_LEN`].** An earlier version wrote
    /// `"n".repeat(MAX_ARJ_NAME_LEN)` and was structurally unable to fail:
    /// tightening the constant by a byte shortened the test's own name in
    /// lockstep, so the whole suite stayed green with the ceiling wrong —
    /// measured, not feared. 2568 is `2600 - 30 - 1 - 1` read straight off
    /// the spec's own identity ("basic header size = first_hdr_size +
    /// strlen(filename) + 1 + strlen(comment) + 1", "maximum header size is
    /// 2600"), with an empty comment.
    #[test]
    fn a_name_too_long_for_an_arj_header_is_refused_and_the_longest_legal_one_is_not() {
        const SPEC_LONGEST_NAME: usize = 2600 - 30 - 1 - 1;
        assert_eq!(
            MAX_ARJ_NAME_LEN, SPEC_LONGEST_NAME,
            "the ceiling must be the spec's own arithmetic, not a number this test copies \
             back out of the constant it is checking"
        );
        let longest = "n".repeat(SPEC_LONGEST_NAME);
        let bytes = write_arj(&[(EntryMeta::file(longest.clone()), &b"x"[..])]);
        let back = read_entries(&bytes);
        assert_eq!(
            back.len(),
            1,
            "the longest legal name must still be written"
        );
        assert_eq!(back[0].0, longest);

        // The entry's own basic header size reaches the spec's maximum
        // EXACTLY, and no further. Its `u16` sits just past the main
        // header: magic (2) + length (2) + content + basic header CRC (4)
        // + the zero extended-header size (2), then the local header's own
        // magic (2) and length (2).
        let main_len = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
        let local_at = 4 + main_len + 4 + 2;
        assert_eq!(
            u16::from_le_bytes([bytes[local_at + 2], bytes[local_at + 3]]) as usize,
            MAX_ARJ_HEADER_SIZE,
            "the longest legal name must produce a header of exactly the spec's maximum"
        );

        let err = write_one_expecting_error(&EntryMeta::file(format!("{longest}o")), b"x");
        assert!(
            matches!(err, Error::Unsupported(_)),
            "one byte past the format's own ceiling is a format limit, not damage; got {err:?}"
        );
        assert_eq!(err.exit_code(), 3);
        let msg = err.to_string();
        assert!(
            msg.contains(&MAX_ARJ_NAME_LEN.to_string()) && msg.contains("2600"),
            "the refusal must name the limit it is enforcing: {msg}"
        );
    }

    /// ARJ stores a name as a null-terminated string, so an interior NUL
    /// would end it there and leave the rest to be parsed as the entry's
    /// comment — a name that came back SHORTER than it went in, which is
    /// the shape `ar.rs`'s inline-slash defect had. `EntryMeta::name` is a
    /// `String` and may legally hold one, so this is reachable from a
    /// hand-built plan.
    #[test]
    fn a_name_containing_a_nul_is_refused_rather_than_truncated() {
        let err = write_one_expecting_error(&EntryMeta::file("a\0b.txt"), b"x");
        assert!(matches!(err, Error::Unsupported(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 3);
        assert!(
            err.to_string().contains("NUL"),
            "the refusal must say what about the name it cannot store: {err}"
        );
    }

    /// An mtime survives to MS-DOS's own two-second resolution, and rounds
    /// DOWN — so a restored mtime is never LATER than the original, and a
    /// `make`-style "is this newer" comparison errs toward rebuilding.
    #[test]
    fn an_mtime_round_trips_to_ms_dos_two_second_resolution() {
        // 2024-01-15T10:30:01Z — an ODD second, so the rounding is visible.
        let t = UNIX_EPOCH + std::time::Duration::from_secs(1_705_314_601);
        let mut meta = EntryMeta::file("m.txt");
        meta.mtime = Some(t);
        let bytes = write_arj(&[(meta, &b"m"[..])]);
        let got = read_meta(&bytes);
        assert_eq!(
            got[0].mtime,
            Some(UNIX_EPOCH + std::time::Duration::from_secs(1_705_314_600)),
            "an odd second must round down, never up"
        );
    }

    /// A timestamp MS-DOS cannot express is reported ABSENT rather than
    /// wrong: the packed field's year is seven bits biased by 1980, so
    /// 1979 and 2108 have nowhere to go. Writing a wrapped value would be a
    /// date, and a date is believed.
    #[test]
    fn a_timestamp_outside_the_ms_dos_range_is_absent_rather_than_wrong() {
        // 1970-01-01, nine years before MS-DOS's epoch.
        let mut meta = EntryMeta::file("old.txt");
        meta.mtime = Some(UNIX_EPOCH);
        let bytes = write_arj(&[(meta, &b"o"[..])]);
        assert_eq!(read_meta(&bytes)[0].mtime, None);
        assert_eq!(dos_timestamp(UNIX_EPOCH), None, "1970 is before 1980");
        assert!(
            dos_timestamp(UNIX_EPOCH + std::time::Duration::from_secs(4_355_812_800)).is_none(),
            "2108 is past the seven-bit year field"
        );
    }

    /// `file access mode` is HOST-DEFINED, so it round-trips only under
    /// `host OS = UNIX`, and a zero reads back as absent rather than as
    /// mode `0o000`.
    ///
    /// The non-Unix half is what makes this test able to fail in the
    /// direction that matters: an MS-DOS archive puts DOS attribute bits in
    /// the same two bytes, and reporting those as `EntryMeta::mode` would
    /// hand a caller a number to `chmod` with. The header is hand-built for
    /// that half, because this writer only ever emits host OS 2.
    #[test]
    fn a_unix_mode_round_trips_and_a_dos_header_reports_none() {
        let mut meta = EntryMeta::file("m.txt");
        meta.mode = Some(0o640);
        let bytes = write_arj(&[(meta, &b"m"[..])]);
        assert_eq!(read_meta(&bytes)[0].mode, Some(0o640));

        // No mode at all stays absent rather than becoming 0o000.
        let bare = write_arj(&[(EntryMeta::file("m.txt"), &b"m"[..])]);
        assert_eq!(read_meta(&bare)[0].mode, None);

        // The same 0o640, under host OS 0 (MS-DOS): DOS attribute bits,
        // not a unix mode, and not reported as one.
        // header_size, archiver_version, min_version, host_os = 0 MSDOS,
        // arj_flags, compression_method = Stored, file_type = Binary,
        // reserved.
        let mut header = vec![30u8, 0, 0, 0, 0, 0, 0, 0];
        header.extend_from_slice(&0u32.to_le_bytes());
        header.extend_from_slice(&1u32.to_le_bytes()); // compressed_size
        header.extend_from_slice(&1u32.to_le_bytes()); // original_size
        header.extend_from_slice(&fixture_crc32(b"m").to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes());
        header.extend_from_slice(&0o640u16.to_le_bytes()); // file_access_mode
        header.push(0);
        header.push(0);
        header.extend_from_slice(b"m.txt");
        header.push(0);
        header.push(0);
        let mut dos = fixture_main_header();
        dos.extend_from_slice(&fixture_wrap_header(&header));
        dos.extend_from_slice(b"m");
        dos.extend_from_slice(&[0x60, 0xEA, 0x00, 0x00]);
        assert_eq!(
            read_meta(&dos)[0].mode,
            None,
            "an MS-DOS header's file access mode is attribute bits, not a unix mode"
        );
    }

    /// **Declared-vs-delivered, both directions** — the defect `arc.rs`
    /// shipped and Phase 3c's Task 3 fix round closed there: an entry
    /// reporting a size from its header that its payload does not deliver,
    /// with every checksum still passing, so `list`, `test
    /// --strict-fidelity` and `unpack --strict-fidelity` all reported exact
    /// at exit 0.
    ///
    /// ARJ closes it inside `unarj-rs` rather than in this module, which is
    /// why it is pinned here rather than assumed: `ArjArchieve::read` reads
    /// exactly `compressed_size` bytes and then compares the produced
    /// length against `original_size` ("Decompressed size does not match the
    /// original size", `io::ErrorKind::InvalidData`). Both directions are
    /// refused as `Error::Corrupt` (exit 5) — the archive contradicts
    /// itself, and there is nothing honest to hand back.
    ///
    /// `fuzz/fuzz_targets/container.rs` calls `check_entry_size(...)` for
    /// every slot, ARJ included, so the scheduled deep run would abort on
    /// the absence of this guarantee. A unit test is what makes it visible
    /// without waiting for one.
    #[test]
    fn an_entry_whose_header_lies_about_its_size_is_corrupt() {
        // The payload really present, and correctly checksummed for what
        // it is — so nothing but the size comparison can catch this.
        const PAYLOAD: &[u8] = b"0123456789";

        for (declared, label) in [(4096u32, "over-declared"), (3u32, "under-declared")] {
            // header_size, archiver_version, min_version, host_os = 2
            // Unix, arj_flags, compression_method = Stored, file_type =
            // Binary, reserved.
            let mut header = vec![30u8, 0, 0, 2, 0, 0, 0, 0];
            header.extend_from_slice(&0u32.to_le_bytes());
            header.extend_from_slice(&(PAYLOAD.len() as u32).to_le_bytes()); // compressed_size
            header.extend_from_slice(&declared.to_le_bytes()); // original_size: the lie
            header.extend_from_slice(&fixture_crc32(PAYLOAD).to_le_bytes());
            header.extend_from_slice(&0u16.to_le_bytes());
            header.extend_from_slice(&0u16.to_le_bytes());
            header.push(0);
            header.push(0);
            header.extend_from_slice(b"lying.txt");
            header.push(0);
            header.push(0);

            let mut bytes = fixture_main_header();
            bytes.extend_from_slice(&fixture_wrap_header(&header));
            bytes.extend_from_slice(PAYLOAD);
            bytes.extend_from_slice(&[0x60, 0xEA, 0x00, 0x00]);

            let mut ar = open_seekable(&bytes);
            let err = match ar.next_entry() {
                Err(e) => e,
                Ok(Some(mut entry)) => {
                    let declared_size = entry.meta().size;
                    let mut data = Vec::new();
                    let read = entry.reader().read_to_end(&mut data);
                    panic!(
                        "{label}: an entry declaring {declared_size:?} bytes produced \
                         {read:?} -> {} bytes with no error at all — this is the shape \
                         `list` and `test --strict-fidelity` report as exact at exit 0",
                        data.len()
                    )
                }
                Ok(None) => panic!("{label}: the entry vanished instead of being refused"),
            };
            assert!(
                matches!(err, Error::Corrupt(_)),
                "{label}: a header contradicting its own payload is damage, not a \
                 capability limit; got {err:?}"
            );
            assert_eq!(err.exit_code(), 5, "{label}: Corrupt is exit 5: {err}");
        }
    }

    /// Reads an archive's entries back through the real reader, as
    /// `(name, bytes)`.
    fn read_entries(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut ar = open_seekable(bytes);
        let mut out = Vec::new();
        while let Some(mut entry) = ar.next_entry().expect("next_entry") {
            let name = entry.meta().name.clone();
            let mut data = Vec::new();
            entry.reader().read_to_end(&mut data).expect("entry read");
            out.push((name, data));
        }
        out
    }

    /// [`read_entries`]'s twin for the metadata half — the fields
    /// `(name, bytes)` drops.
    fn read_meta(bytes: &[u8]) -> Vec<EntryMeta> {
        let mut ar = open_seekable(bytes);
        let mut out = Vec::new();
        while let Some(mut entry) = ar.next_entry().expect("next_entry") {
            let meta = entry.meta().clone();
            let mut data = Vec::new();
            entry.reader().read_to_end(&mut data).expect("entry read");
            out.push(meta);
        }
        out
    }

    #[test]
    fn arj_conforms() {
        let fx = arj_fixture();
        // `[2, 10]`, in the FIXTURE numbering (1-10) — NOT the `[7, 8]` of
        // `arj_conforms_with_a_writer`'s thirteen-property scheme, which is
        // a different set of numbers about a different thing. 2 is the
        // read-only refusal, and `arj` gained a writer in Phase 3c Task 7;
        // 10 is the CRC witness, and this fixture's manifest records no
        // archive-stored CRC (it is hand-built from the specification — see
        // `MANIFEST.md` — so there is no outside witness to record).
        assert_container_conforms_with_skipping(&Arj, &meta(), &fx, &[2, 10]);
    }

    #[test]
    fn capabilities_and_metadata_match_the_format() {
        let c = Arj.caps();
        assert!(
            c.read && c.write,
            "ARJ gained an encoder in Phase 3c Task 7 — see Arj::caps's own doc for the two \
             warnings that flag carries"
        );
        assert!(
            !c.forward_parse && c.needs_seek,
            "ArjArchieve needs Seek and has no forward-only decode path; see this module's doc"
        );
        assert!(
            c.stores_dirs && !c.stores_symlinks,
            "file type 3 is a directory in ARJ's own table; that table has no value for a link"
        );
        let m = meta();
        assert_eq!(m.id, ARJ);
        assert_eq!(m.extensions, &["arj"]);
    }

    /// A seekable `Source` over `bytes`, through a temp file that is
    /// unlinked the moment it is open.
    ///
    /// The name carries a process-wide counter rather than the address of
    /// `bytes`, which is what it used to carry: two `Vec`s in two threads
    /// can share an address once the first is dropped, and the sweep in
    /// [`the_method_4_guard_is_exact_over_every_first_payload_byte`] builds
    /// 256 of them.
    fn seekable_source(bytes: &[u8]) -> Box<dyn Source> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "stuffr-arj-seekable-{}-{}.arj",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::write(&path, bytes).unwrap();
        let src: Box<dyn Source> = Box::new(stuffr_core::FileSource::open(&path).unwrap());
        let _ = std::fs::remove_file(&path);
        src
    }

    /// `Arj::open` over a seekable source, errors and all — the main header
    /// is parsed inside `open`, so a test for a main-header refusal has to
    /// be able to see what `open` itself returns.
    fn try_open_seekable(bytes: &[u8]) -> Result<Box<dyn ArchiveRead>> {
        let resolved = stuffr_core::resolve(
            seekable_source(bytes),
            ARJ,
            Arj.caps(),
            &StreamPolicy::default(),
        )
        .expect("resolve over a seekable source");
        Arj.open(resolved, &OpenOpts::default())
    }

    fn open_seekable(bytes: &[u8]) -> Box<dyn ArchiveRead> {
        try_open_seekable(bytes).expect("open")
    }

    // -------------------------------------------------------------------
    // Task 6b: the four panics `unarj-rs` 0.2.1 raises on hostile input.
    //
    // Every reproducer below reached `stuffr list`, `test`, `unpack` and
    // `cat` at EXIT 101 before the guards in `ArjGuardedReader`'s doc
    // existed — a panic, which is the one failure shape
    // `check_error_is_classified` can never see, and the reason all four
    // survived a format fuzzed at 200,000 executions.
    //
    // Each test asserts the CLASSIFIED error, not merely that nothing
    // panicked: a guard that turned a crash into a wrong answer would pass
    // the weaker assertion. Each is falsifiable by deleting its named
    // guard; the task report records the panic each deletion brings back.
    // -------------------------------------------------------------------

    /// The error a hostile archive raises, from whichever of `open` or
    /// `next_entry` raises it — the MAIN header is parsed inside
    /// `ArjArchieve::new` (i.e. inside `Arj::open`) and every later header
    /// inside `get_next_entry`, so a caller cannot know which in advance.
    ///
    /// **Every error this returns is put through the fuzz harness's own
    /// oracle first**, which is the point of the whole task rather than a
    /// flourish: `check_error_is_classified` is what the `container` fuzz
    /// target asserts on hostile input, and it can NEVER see a panic — the
    /// process aborts before it runs. Running it here says the same thing
    /// the target would now be able to say, at gate speed, and it fails in
    /// the one direction a hand-written `matches!` would not: an error that
    /// became `Error::Io` (exit 1, "stuffr failed") rather than a refusal.
    fn read_expecting_error(bytes: &[u8]) -> Error {
        let err = raise_from(bytes);
        stuffr_core::testing::check_error_is_classified(&err)
            .expect("hostile ARJ input must be refused with a classified error");
        err
    }

    fn raise_from(bytes: &[u8]) -> Error {
        let mut ar = match try_open_seekable(bytes) {
            Ok(ar) => ar,
            Err(e) => return e,
        };
        loop {
            match ar.next_entry() {
                Ok(Some(mut entry)) => {
                    let mut sink = Vec::new();
                    if let Err(e) = entry.reader().read_to_end(&mut sink) {
                        return Error::Io(e);
                    }
                }
                Ok(None) => panic!("this archive must be refused, not read cleanly to its end"),
                Err(e) => return e,
            }
        }
    }

    /// A local file header with the `method`, sizes and payload the test
    /// chooses — `build_local_file_entry` fixes all three at `Stored`, and
    /// method 4 is the only one with a panicking decoder behind it.
    fn build_method_4_entry(name: &str, original_size: u32, payload: &[u8]) -> Vec<u8> {
        let mut header = vec![
            30u8, // header_size (inner byte; no extension)
            0,    // archiver_version_number
            0,    // min_version_to_extract
            2,    // host_os = Unix
            0,    // arj_flags
            4,    // compression_method = CompressedFastest
            0,    // file_type = Binary
            0,    // reserved
        ];
        header.extend_from_slice(&0u32.to_le_bytes()); // date_time_modified
        header.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // compressed_size
        header.extend_from_slice(&original_size.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes()); // original_crc32
        header.extend_from_slice(&0u16.to_le_bytes()); // file_spec_position
        header.extend_from_slice(&0u16.to_le_bytes()); // file_access_mode
        header.push(0); // first_chapter
        header.push(0); // last_chapter
        assert_eq!(header.len(), 30, "must match the inner header_size byte");
        header.extend_from_slice(name.as_bytes());
        header.push(0); // name terminator
        header.push(0); // comment terminator
        let mut out = fixture_wrap_header(&header);
        out.extend_from_slice(payload);
        out
    }

    /// An archive holding exactly one hand-built header, whose CONTENT is
    /// the test's to malform — the envelope around it is always correct, so
    /// the header reaches `LocalFileHeader::load_from` with every check
    /// `read_header` makes already passed.
    fn archive_with_one_local_content(content: &[u8]) -> Vec<u8> {
        let mut bytes = fixture_main_header();
        bytes.extend_from_slice(&fixture_wrap_header(content));
        bytes.extend_from_slice(&ARJ_END_OF_ARCHIVE);
        bytes
    }

    /// **Panic 1 of 4 — `main_header.rs:68`, and the one that was not in
    /// the task's own table.** A CRC-valid MAIN header of one byte:
    /// `MainHeader::load_from` walks 30 fixed bytes unconditionally and
    /// takes the second of them from a slice of length zero. Eleven bytes
    /// of file, exit 101, from `stuffr list` on the `0.5.0` binary.
    #[test]
    fn a_main_header_shorter_than_its_own_parser_is_corrupt_rather_than_a_panic() {
        let bytes = fixture_wrap_header(&[30]);
        assert_eq!(
            bytes.len(),
            11,
            "the whole reproducer: id, a declared content size of 1, that byte, its CRC-32 \
             and an empty extended-header chain"
        );
        let err = read_expecting_error(&bytes);
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
        assert_eq!(
            err.exit_code(),
            5,
            "see `Error::exit_code`'s own 5-vs-6 rule"
        );
        assert!(
            err.to_string().contains("shorter than the fixed structure"),
            "the refusal must name the contradiction, not just the verdict: {err}"
        );
    }

    /// **Panic 2 of 4 — `local_file_header.rs:95`.** The same one-byte
    /// content behind a valid main header, which reaches the OTHER of the
    /// crate's two parsers.
    #[test]
    fn a_local_file_header_shorter_than_its_own_parser_is_corrupt_rather_than_a_panic() {
        let err = read_expecting_error(&archive_with_one_local_content(&[30]));
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 5);
        assert!(
            err.to_string().contains("shorter than the fixed structure"),
            "{err}"
        );
    }

    /// **Panic 3 of 4 — `local_file_header.rs:128.`** A content of exactly
    /// 30 bytes: every fixed field parses, and then `convert_string!`'s
    /// `while $x[0] != 0` loop indexes an empty slice looking for the name's
    /// terminator.
    #[test]
    fn a_header_whose_name_has_no_terminator_is_corrupt_rather_than_a_panic() {
        let mut content = vec![b'A'; 30];
        content[0] = 30; // first_hdr_size
        let err = read_expecting_error(&archive_with_one_local_content(&content));
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 5);
        assert!(err.to_string().contains("no NUL terminator"), "{err}");
    }

    /// The same loop one string later (`local_file_header.rs:129`): the
    /// name terminates, and the COMMENT runs off the end of the header.
    /// Distinct from the test above because the guard has a distinct arm
    /// for it, and a single-arm guard would pass the other one.
    #[test]
    fn a_header_whose_comment_has_no_terminator_is_corrupt_rather_than_a_panic() {
        let mut content = vec![0u8; 30];
        content[0] = 30;
        content.extend_from_slice(b"a.txt");
        content.push(0); // the name's terminator, and the last byte there is
        let err = read_expecting_error(&archive_with_one_local_content(&content));
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 5);
        assert!(
            err.to_string().contains("comment runs past the end"),
            "{err}"
        );
    }

    /// **Panic 4 of 4 — `decode_fastest.rs:38`** (`attempt to subtract with
    /// overflow` in a debug build; an out-of-range index at `:46` in a
    /// release one). A method-4 stream whose first token is a match, with
    /// no output yet to copy from.
    #[test]
    fn a_method_4_stream_opening_with_a_backreference_is_corrupt_rather_than_a_panic() {
        let mut bytes = fixture_main_header();
        bytes.extend_from_slice(&build_method_4_entry(
            "a.txt",
            64,
            &[0x80, 0, 0, 0, 0, 0, 0, 0],
        ));
        bytes.extend_from_slice(&ARJ_END_OF_ARCHIVE);
        let err = read_expecting_error(&bytes);
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 5);
        assert!(err.to_string().contains("back-reference"), "{err}");
    }

    /// The method-4 predicate is ONE BIT, and this pins it over all 256
    /// first-payload-byte values rather than over the two the test above
    /// would reach.
    ///
    /// Two separate claims, and the second is what stops the guard from
    /// being tightened into a refusal of decodable entries: every byte
    /// exits 5 (nothing panics, nothing reports exit 1), and the guard's
    /// own message appears for exactly the high-bit half —
    /// `0x80`-`0xFF` refused here, `0x00`-`0x7F` reaching `decode_fastest`
    /// and failing inside it, which is the crate's own `UnexpectedEof` and
    /// also exit 5. The two halves were measured 128/128 at the CLI before
    /// this guard existed, as exit 5 and exit 101; that split is now a
    /// message split at one exit code.
    #[test]
    fn the_method_4_guard_is_exact_over_every_first_payload_byte() {
        for first in 0u8..=u8::MAX {
            let mut bytes = fixture_main_header();
            bytes.extend_from_slice(&build_method_4_entry(
                "a.txt",
                64,
                &[first, 0, 0, 0, 0, 0, 0, 0],
            ));
            bytes.extend_from_slice(&ARJ_END_OF_ARCHIVE);
            let err = read_expecting_error(&bytes);
            assert_eq!(err.exit_code(), 5, "first payload byte {first:#04X}: {err}");
            assert_eq!(
                err.to_string().contains("back-reference"),
                opens_with_a_backreference(first),
                "first payload byte {first:#04X} must be refused by the guard if and only if \
                 its top bit is set: {err}"
            );
        }
    }

    /// **The guard's own scan must accept exactly what `read_header`'s
    /// accepts, and this is the test that would notice if it stopped** —
    /// fact 1 of [`ArjGuardedReader`]'s doc, and the only one of the six
    /// whose drift refuses a VALID archive rather than letting a panic
    /// back.
    ///
    /// The decoy is a lone `0x60` in front of a complete, CRC-valid header
    /// envelope whose content is one byte. `read_header` consumes that
    /// `0x60` AND the `0x60` after it, resumes at the `0xEA`, and walks
    /// straight past the whole decoy to the real header behind it — so this
    /// archive reads cleanly, and did before Task 6b too. A guard scanning
    /// for a two-byte window instead would match the decoy's own id, find a
    /// one-byte content with a CRC that reproduces, and refuse this archive
    /// at exit 5.
    #[test]
    fn a_false_header_id_unarj_walks_past_never_refuses_the_archive_behind_it() {
        let mut bytes = fixture_main_header();
        bytes.push(0x60);
        bytes.extend_from_slice(&fixture_wrap_header(&[30]));
        bytes.extend_from_slice(&build_local_file_entry("kept.txt", b"alpha"));
        bytes.extend_from_slice(&ARJ_END_OF_ARCHIVE);

        let got = read_meta(&bytes);
        assert_eq!(got.len(), 1, "the real entry behind the decoy must survive");
        assert_eq!(got[0].name, "kept.txt");
    }

    /// The same fact, asserted directly on the scanner rather than through
    /// an archive: `60 60 EA 60 EA` holds TWO two-byte windows and exactly
    /// ONE header id, because the crate's loop consumes the pair it
    /// rejects.
    #[test]
    fn the_header_id_scan_consumes_the_pair_it_rejects() {
        let mut src = ArjGuardedReader::new(in_memory_source(b"\x60\x60\xEA\x60\xEA"));
        assert_eq!(
            seek_past_the_next_header_id(&mut src),
            Some(5),
            "the id at 3..5 is the one `read_header` finds; a window scan would answer 3 \
             (the pair at 1..3)"
        );
    }

    /// `MainHeader::load_from` and `LocalFileHeader::load_from` walk
    /// DIFFERENT numbers of fixed bytes for the same `first_hdr_size`
    /// (facts 4 and 5), and a guard applying one rule to the other header
    /// would refuse archives the crate reads. Pinned as a table rather than
    /// discovered from a failure.
    #[test]
    fn each_header_shape_keeps_its_own_fixed_prefix_rule() {
        for (first_hdr_size, main, local) in [
            (0u8, 30usize, 30usize),
            (30, 30, 30),
            (31, 30, 34),
            (33, 30, 34),
            (34, 34, 34),
            (45, 34, 34),
            (46, 34, 46),
            (255, 34, 46),
        ] {
            assert_eq!(
                HeaderShape::Main.fixed_prefix(first_hdr_size),
                main,
                "main header, first_hdr_size {first_hdr_size}"
            );
            assert_eq!(
                HeaderShape::Local.fixed_prefix(first_hdr_size),
                local,
                "local file header, first_hdr_size {first_hdr_size}"
            );
        }
    }

    /// The guard refuses only what would have panicked: every OTHER shape
    /// keeps the crate's own error, in the crate's own words. Without this
    /// the guard could quietly become the thing that answers for a
    /// truncated or checksum-broken archive, and the crate's messages would
    /// stop being reachable at all.
    #[test]
    fn a_header_the_crate_refuses_itself_keeps_the_crates_own_error() {
        // A basic header whose recorded CRC-32 does not reproduce. Its
        // content is one byte, i.e. exactly the shape the guard refuses —
        // so if the guard ran ahead of the crate's checksum check, this
        // would carry the guard's message instead.
        let mut bytes = fixture_main_header();
        let mut envelope = fixture_wrap_header(&[30]);
        let crc_at = envelope.len() - 6;
        envelope[crc_at] ^= 0xFF;
        bytes.extend_from_slice(&envelope);
        bytes.extend_from_slice(&ARJ_END_OF_ARCHIVE);

        let err = read_expecting_error(&bytes);
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 5);
        assert!(
            err.to_string().contains("Header checksum is invalid"),
            "the crate's own verdict must survive the guard: {err}"
        );
    }

    // -------------------------------------------------------------------
    // The drift test: the instrument fact 1 needs, and the one the first
    // round of this task declared impossible.
    //
    // That claim rested on a true premise and a false conclusion.
    // `ArjArchieve` really does not expose the offset its scan chose — but
    // THE OFFSET IS NOT THE OBSERVABLE. The property the mirror has to hold
    // is
    //
    //     this guard refuses X  <=>  the UNGUARDED crate panics on X
    //
    // and "does the unguarded crate panic" is directly observable through
    // `catch_unwind`, with no private field and no new dependency. Every
    // piece is already in this module: `ArjSeekAdapter` and
    // `ArjGuardedReader` are its own types, and `ArjArchieve::new`,
    // `get_next_entry`, `skip` and `read` are all public.
    //
    // This is the remedy `CLAUDE.md` prescribes for the identical
    // `ar = "=0.9.0"` mirror ("replace the mirror with a drift test") and has
    // never had there. It is worth more than the two hand-built fact-1 tests
    // combined, because a drift those two do not happen to exercise fails
    // nothing at all.
    // -------------------------------------------------------------------

    /// A seekable [`Source`] over bytes already in memory.
    ///
    /// The drift test builds thousands of archives and walks each one twice;
    /// [`seekable_source`]'s temp file would make that two filesystem writes
    /// per archive and turn a sub-second test into a slow one.
    struct InMemorySource(io::Cursor<Vec<u8>>);

    impl Read for InMemorySource {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Source for InMemorySource {
        fn caps(&self) -> stuffr_core::SourceCaps {
            stuffr_core::SourceCaps {
                seekable: true,
                len: Some(self.0.get_ref().len() as u64),
            }
        }

        fn as_seek(&mut self) -> Option<&mut dyn SeekRead> {
            Some(&mut self.0)
        }
    }

    fn in_memory_source(bytes: &[u8]) -> Box<dyn Source> {
        Box::new(InMemorySource(io::Cursor::new(bytes.to_vec())))
    }

    /// What a walk over one archive ended in.
    ///
    /// The four outcomes are kept apart because the property below is not
    /// the naive "refuses ⟺ panics" — see
    /// [`the_guard_refuses_exactly_what_unarj_panics_on`]'s own doc for the
    /// case that disproved that version on the generator's first run.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Walk {
        /// One of this module's two guards refused the archive.
        GuardRefused,
        /// `unarj-rs` panicked — the shape this whole task exists to stop,
        /// and the one `check_error_is_classified` can never see.
        Panicked,
        /// The crate raised its own error, carrying the exit code stuffr
        /// would report for it (`classify_arj_io`'s answer). Distinct from
        /// [`Walk::Completed`] because a guard that refuses where the crate
        /// would merely have errored costs a user nothing, while a guard
        /// that refuses where the crate would have SUCCEEDED is the false
        /// refusal `CLAUDE.md` calls the worst kind.
        CrateError(i32),
        /// The ordinary reader's own refusal — an undecodable method, or a
        /// size past [`MAX_ARJ_ENTRY_LEN`]. Identical with the guards in or
        /// out, since neither guard is involved.
        ReaderStopped,
        /// Walked to the archive's clean end.
        Completed,
    }

    /// Walks `bytes` exactly as [`ArjRead::next_entry`] does, with this
    /// module's guards either in or out, and reports which of the three ways
    /// it ended.
    ///
    /// **The two configurations must differ in NOTHING but the guards**, or
    /// the equivalence below stops being about them: the method refusal and
    /// both entry ceilings are mirrored here so that an unguarded walk
    /// cannot allocate 4 GiB from a header field the ordinary reader would
    /// have refused.
    fn walk_archive(bytes: &[u8], guards: bool) -> Walk {
        let mut outcome = Walk::Completed;
        let ran = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let src: SharedSource =
                Rc::new(RefCell::new(ArjGuardedReader::new(in_memory_source(bytes))));
            if guards
                && refuse_a_header_unarj_would_panic_on(&mut src.borrow_mut(), HeaderShape::Main)
                    .is_err()
            {
                outcome = Walk::GuardRefused;
                return;
            }
            let mut archive = match ArjArchieve::new(ArjSeekAdapter(Rc::clone(&src))) {
                Ok(a) => a,
                Err(e) => {
                    outcome = Walk::CrateError(classify_arj_io(e).exit_code());
                    return;
                }
            };
            loop {
                if guards
                    && refuse_a_header_unarj_would_panic_on(
                        &mut src.borrow_mut(),
                        HeaderShape::Local,
                    )
                    .is_err()
                {
                    outcome = Walk::GuardRefused;
                    return;
                }
                let header = match archive.get_next_entry() {
                    Ok(Some(h)) => h,
                    Ok(None) => return,
                    Err(e) => {
                        outcome = Walk::CrateError(classify_arj_io(e).exit_code());
                        return;
                    }
                };
                if header.file_type == FileType::Directory {
                    if let Err(e) = archive.skip(&header) {
                        outcome = Walk::CrateError(classify_arj_io(e).exit_code());
                        return;
                    }
                    continue;
                }
                if matches!(
                    header.compression_method,
                    CompressionMethod::NoData
                        | CompressionMethod::NoDataNoCrc
                        | CompressionMethod::Unknown(_)
                ) || u64::from(header.compressed_size) > MAX_ARJ_ENTRY_LEN
                    || u64::from(header.original_size) > MAX_ARJ_ENTRY_LEN
                {
                    outcome = Walk::ReaderStopped;
                    return;
                }
                if guards
                    && refuse_a_method_4_payload_unarj_would_panic_on(
                        &mut src.borrow_mut(),
                        &header.name,
                        &header,
                    )
                    .is_err()
                {
                    outcome = Walk::GuardRefused;
                    return;
                }
                if let Err(e) = archive.read(&header) {
                    outcome = Walk::CrateError(classify_arj_io(e).exit_code());
                    return;
                }
            }
        }));
        match ran {
            Err(_) => Walk::Panicked,
            Ok(()) => outcome,
        }
    }

    /// xorshift64*, seeded by the caller — a deterministic generator with no
    /// dependency, so a failure here reproduces exactly.
    struct Rng(u64);

    impl Rng {
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next_u64() % n
        }

        fn byte(&mut self) -> u8 {
            (self.next_u64() >> 33) as u8
        }
    }

    /// One header CONTENT, biased hard toward the boundaries that decide
    /// whether `load_from` runs off its own slice.
    ///
    /// Half the time it is well-formed (a 30-byte fixed prefix, a name, two
    /// NULs); the rest of the time its length and its `first_hdr_size` are
    /// drawn from a set that straddles 30, 34 and 46, which is what makes a
    /// generated corpus reach the panics at all rather than bouncing off the
    /// CRC-32 gate.
    fn generated_content(rng: &mut Rng, main: bool) -> Vec<u8> {
        if rng.below(2) == 0 {
            // Well-formed: exactly the shape the fixture builders emit.
            let mut c = vec![
                30u8,
                0,
                0,
                2,
                0,
                if main {
                    0
                } else {
                    METHOD_BYTES[rng.below(METHOD_BYTES.len() as u64) as usize]
                },
                if main { 2 } else { (rng.below(6)) as u8 },
                0,
            ];
            c.extend_from_slice(&0u32.to_le_bytes()); // date_time_modified
            let payload = rng.below(9) as u32; // compressed_size
            c.extend_from_slice(&payload.to_le_bytes());
            c.extend_from_slice(&(rng.below(9) as u32).to_le_bytes()); // original_size
            c.extend_from_slice(&0u32.to_le_bytes()); // crc
            c.extend_from_slice(&0u16.to_le_bytes());
            c.extend_from_slice(&0u16.to_le_bytes());
            c.push(0);
            c.push(0);
            assert_eq!(c.len(), 30);
            c.extend_from_slice(b"g.txt");
            c.push(0);
            c.push(0);
            return c;
        }
        const LENGTHS: &[usize] = &[1, 8, 29, 30, 31, 33, 34, 35, 45, 46, 47, 60];
        const FIRST: &[u8] = &[0, 1, 29, 30, 31, 33, 34, 45, 46, 47, 255];
        let len = LENGTHS[rng.below(LENGTHS.len() as u64) as usize];
        let mut c = vec![0u8; len];
        for b in c.iter_mut() {
            // Mostly non-zero, so a NUL terminator is present only sometimes
            // — the whole point of the `convert_string!` sites.
            *b = match rng.below(4) {
                0 => 0,
                _ => rng.byte() | 1,
            };
        }
        c[0] = FIRST[rng.below(FIRST.len() as u64) as usize];
        c
    }

    /// The method bytes a generated well-formed header picks from: the five
    /// `unarj-rs` decodes, the two it names but cannot, and one it does not
    /// know at all.
    const METHOD_BYTES: &[u8] = &[0, 1, 2, 3, 4, 8, 9, 7];

    /// One generated archive: a main header, zero to two local headers with
    /// payloads, and — this is the part fact 1 needs — decoy bytes between
    /// them that a two-byte-window scan would read as header ids and
    /// `read_header` walks straight past.
    fn generated_archive(rng: &mut Rng) -> Vec<u8> {
        let mut out = fixture_wrap_header(&generated_content(rng, true));
        for _ in 0..rng.below(3) {
            match rng.below(8) {
                // A lone `0x60`, which makes the NEXT header's own `0x60` the
                // second byte of a pair the crate rejects and consumes.
                0 => out.push(0x60),
                1 => out.extend_from_slice(&[0x60, 0x60]),
                // A complete, CRC-valid decoy header one byte behind a
                // `0x60`: the crate never sees it, and a window scan does.
                2 => {
                    out.push(0x60);
                    out.extend_from_slice(&fixture_wrap_header(&generated_content(rng, false)));
                }
                _ => {}
            }
            let content = generated_content(rng, false);
            out.extend_from_slice(&fixture_wrap_header(&content));
            for _ in 0..rng.below(10) {
                out.push(rng.byte());
            }
        }
        if rng.below(4) != 0 {
            out.extend_from_slice(&ARJ_END_OF_ARCHIVE);
        }
        out
    }

    /// **The drift test**, and the instrument fact 1 has had none of until
    /// now. It walks each generated archive twice — once with this module's
    /// guards, once without — and compares the two outcomes.
    ///
    /// # Why this survives a patch bump and the two hand-built fact tests do not
    ///
    /// It never names an offset, a threshold or a line number. It runs the
    /// REAL dependency and compares it against itself, so the day a `0.2.x`
    /// release changes `read_header`'s scan, some generated archive breaks
    /// one of the three properties below and this test says which — where
    /// [`a_false_header_id_unarj_walks_past_never_refuses_the_archive_behind_it`]
    /// only notices a drift its one hand-built decoy happens to exercise.
    ///
    /// # The property is NOT "refuses ⟺ panics", and the generator proved it
    ///
    /// That was the shape this test was first written in, and it failed on
    /// its first run — correctly. The archive it produced ends in a method-4
    /// entry whose single payload byte is `0xD1`: top bit set, so
    /// [`opens_with_a_backreference`] refuses it, while `decode_fastest`
    /// reaches the match branch and then runs out of BITS before the
    /// subtraction, answering `UnexpectedEof` rather than panicking. The
    /// one-bit guard is deliberately a shade eager — its own doc says so —
    /// and an equivalence that called that a defect would have been a
    /// wrong test, not a found bug.
    ///
    /// So the three properties asserted are the ones that actually matter,
    /// and together they are stronger than the equivalence:
    ///
    /// 1. **No missed panic.** The unguarded crate panicking implies the
    ///    guard refused. This is the direction a guard grown too lax breaks.
    /// 2. **No false refusal, and no changed verdict.** The guard refusing
    ///    implies the unguarded crate would have panicked or raised its own
    ///    error *with the same exit code the guard reports* (5). It can
    ///    never imply [`Walk::Completed`] — refusing an archive the crate
    ///    reads successfully is fact 1's own failure mode and the one
    ///    `CLAUDE.md` calls "the worst kind". Asserting the exit code too is
    ///    what makes the guard's eagerness provably free: a user cannot tell
    ///    the two apart.
    /// 3. **The two walks agree exactly whenever no guard fires**, so a
    ///    guard cannot change an outcome by some route other than refusing.
    ///
    /// And [`Walk::Panicked`] never appears in the guarded configuration at
    /// all — the task's whole claim, over generated input rather than over
    /// four reproducers.
    ///
    /// # Non-vacuity
    ///
    /// A generator producing only boring archives would satisfy all three
    /// trivially, which is the failure this project keeps rediscovering
    /// (`broken_codecs`, the unseeded `salvage` target). The floors below
    /// are asserted, not printed: the corpus must actually panic the
    /// unguarded crate on a real share of its archives AND walk a real share
    /// of them to a clean end.
    #[test]
    fn the_guard_refuses_exactly_what_unarj_panics_on() {
        // The gate reads this test's stderr; a few thousand deliberate
        // panics would bury everything else in it. Other threads keep the
        // default behaviour, so a genuine panic in a test running beside
        // this one still prints.
        let ours = std::thread::current().id();
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if std::thread::current().id() != ours {
                eprintln!("{info}");
            }
        }));

        let mut rng = Rng(0x5EED_A5EE_D5EE_DA5E);
        let mut panicked = 0usize;
        let mut refused = 0usize;
        let mut completed = 0usize;
        let mut refused_where_the_crate_only_errored = 0usize;
        let mut broken: Vec<(Vec<u8>, Walk, Walk, &'static str)> = Vec::new();

        const ARCHIVES: usize = 4000;
        for _ in 0..ARCHIVES {
            let bytes = generated_archive(&mut rng);
            let guarded = walk_archive(&bytes, true);
            let bare = walk_archive(&bytes, false);

            let broke = if guarded == Walk::Panicked {
                Some("the GUARDED walk panicked — a guard has stopped covering a panic site")
            } else if bare == Walk::Panicked && guarded != Walk::GuardRefused {
                Some("property 1: the unguarded crate panicked and no guard refused")
            } else if guarded == Walk::GuardRefused
                && !matches!(bare, Walk::Panicked | Walk::CrateError(5))
            {
                Some(
                    "property 2: a guard refused where the unguarded crate neither panicked \
                     nor raised an exit-5 error of its own — a FALSE REFUSAL, or a changed \
                     verdict",
                )
            } else if guarded != Walk::GuardRefused && guarded != bare {
                Some("property 3: no guard fired, yet the two walks disagree")
            } else {
                None
            };
            if let Some(why) = broke {
                broken.push((bytes, guarded, bare, why));
                break;
            }

            match guarded {
                Walk::GuardRefused => {
                    refused += 1;
                    if bare != Walk::Panicked {
                        refused_where_the_crate_only_errored += 1;
                    }
                }
                Walk::Completed => completed += 1,
                _ => {}
            }
            if bare == Walk::Panicked {
                panicked += 1;
            }
        }

        std::panic::set_hook(previous);

        if let Some((bytes, guarded, bare, why)) = broken.pop() {
            panic!(
                "{why}\nguarded walk: {guarded:?}\nunguarded walk: {bare:?}\nthe mirror in \
                 `ArjGuardedReader`'s doc has drifted from `unarj-rs 0.2.1` — archive:\n\
                 {bytes:02X?}"
            );
        }

        // Non-vacuity. The floors sit a long way below what this seed
        // actually produces, so they pin that the corpus is doing work
        // without pinning the generator's exact behaviour — a test that
        // asserted the exact counts would have to be edited for every
        // harmless change to the generator, and would stop being read.
        assert!(
            panicked >= ARCHIVES / 20,
            "only {panicked} of {ARCHIVES} archives panicked the unguarded crate — the \
             generator has stopped reaching the panic sites, so property 1 is vacuous"
        );
        assert!(
            completed >= ARCHIVES / 20,
            "only {completed} of {ARCHIVES} archives walked to a clean end — the generator \
             has stopped producing READABLE archives, so property 2 (no false refusal) is \
             vacuous"
        );
        assert!(
            refused >= panicked,
            "every panic must have been refused, so refusals ({refused}) cannot be fewer \
             than panics ({panicked})"
        );
        // Not an assertion about a number, but the reason this test cannot
        // be an equivalence: the method-4 guard is one bit and refuses a
        // little more than `decode_fastest` panics on, at the same exit
        // code. Printed so a reader can see the margin rather than infer it.
        println!(
            "drift: {ARCHIVES} archives, {panicked} panicked unguarded, {refused} refused by \
             a guard ({refused_where_the_crate_only_errored} of them where the crate would \
             have raised its own exit-5 error), {completed} walked to a clean end"
        );
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

    /// An entry declaring an
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

        let mut bytes = fixture_main_header();
        bytes.extend_from_slice(&fixture_wrap_header(&header));
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

        let mut bytes = fixture_main_header();
        bytes.extend_from_slice(&fixture_wrap_header(&header));
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

        let mut bytes = fixture_main_header();
        bytes.extend_from_slice(&fixture_wrap_header(&header));
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
        header.extend_from_slice(&fixture_crc32(content).to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes());
        header.push(0);
        header.push(0);
        header.push(b'v'); // name: "v"
        header.push(0);
        header.push(0);

        let mut bytes = fixture_main_header();
        bytes.extend_from_slice(&fixture_wrap_header(&header));
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

    /// `FileType::Directory` is the one entry-kind path in either legacy
    /// container with no test at all — `lha.rs` has
    /// `a_directory_entry_is_produced_not_refused` and this had nothing.
    /// It is also the only branch that calls `self.archive.skip(&header)`.
    ///
    /// The directory's declared payload is `60 EA 00 00` deliberately: that
    /// is the end-of-archive marker, and `unarj_rs::read_header` finds its
    /// next header by SCANNING for the `60 EA` magic rather than expecting
    /// it at the current position. So an unskipped payload of ordinary
    /// bytes would be walked over harmlessly and this test would pass with
    /// the `skip` call deleted — measured, not assumed. With these four
    /// bytes the scan stops INSIDE the payload, reads the entry data as a
    /// header, and `after.txt` disappears. That is what makes the call
    /// load-bearing and this test able to fail.
    ///
    /// The declared sizes are deliberately NON-ZERO in the header here and
    /// the entry is still reported as `size: Some(0)`. That is the ruling,
    /// not an accident, and it differs from LHA's (which reports a
    /// directory's declared sizes verbatim): an ARJ directory entry has no
    /// content, the bytes a header claims for one are not retrievable
    /// through this container in any case, and reporting a size `cat` could
    /// never produce would be a number with nothing behind it. `skip` still
    /// honours the DECLARED length, which is why the following entry is
    /// found — the two are separate questions.
    ///
    /// The `skip` error path stays unreached, and cannot be reached from a
    /// fixture: `ArjArchieve::skip` is a bare `seek(SeekFrom::Current(n))`
    /// (crate 0.2.1, `arj_archive.rs:33`), and seeking past the end of a
    /// file or a cursor succeeds on every platform this builds for. Only a
    /// source whose SEEK fails could trip it.
    #[test]
    fn a_directory_entry_is_reported_as_dir_and_the_next_entry_is_still_found() {
        const DIR_PAYLOAD: &[u8] = &[0x60, 0xEA, 0x00, 0x00];

        let mut header = Vec::with_capacity(30);
        header.push(30); // header_size (inner byte; no extension)
        header.push(0); // archiver_version_number
        header.push(0); // min_version_to_extract
        header.push(2); // host_os = Unix
        header.push(0); // arj_flags
        header.push(0); // compression_method = Stored
        header.push(3); // file_type = Directory
        header.push(0); // reserved
        header.extend_from_slice(&0u32.to_le_bytes()); // date_time_modified
        header.extend_from_slice(&(DIR_PAYLOAD.len() as u32).to_le_bytes()); // compressed_size
        header.extend_from_slice(&(DIR_PAYLOAD.len() as u32).to_le_bytes()); // original_size
        header.extend_from_slice(&fixture_crc32(DIR_PAYLOAD).to_le_bytes()); // original_crc32
        header.extend_from_slice(&0u16.to_le_bytes()); // file_spec_position
        header.extend_from_slice(&0u16.to_le_bytes()); // file_access_mode
        header.push(0); // first_chapter
        header.push(0); // last_chapter
        assert_eq!(header.len(), 30);
        header.extend_from_slice(b"d"); // name
        header.push(0); // name terminator
        header.push(0); // comment terminator

        let mut bytes = fixture_main_header();
        bytes.extend_from_slice(&fixture_wrap_header(&header));
        bytes.extend_from_slice(DIR_PAYLOAD);
        bytes.extend_from_slice(&build_local_file_entry("after.txt", b"beta"));
        bytes.extend_from_slice(&[0x60, 0xEA]);
        bytes.extend_from_slice(&0u16.to_le_bytes());

        let mut ar = open_seekable(&bytes);

        let mut dir = ar
            .next_entry()
            .expect("a directory entry must not be refused")
            .expect("must yield the directory entry");
        assert_eq!(dir.meta().kind, EntryKind::Dir);
        assert_eq!(dir.meta().name, "d");
        assert_eq!(dir.meta().size, Some(0), "see this test's doc comment");
        assert_eq!(dir.meta().compressed_size, Some(0));
        let mut payload = Vec::new();
        dir.reader()
            .read_to_end(&mut payload)
            .expect("a directory entry's reader is empty, never an error");
        assert!(payload.is_empty());
        drop(dir);

        // The whole point of the `skip` call: without it the reader is
        // still sitting on the directory's declared payload, whose first
        // two bytes are the header magic `read_header` scans for, and this
        // archive ends there instead.
        let mut next = ar
            .next_entry()
            .expect("the entry after a directory must still parse")
            .expect("must yield the second entry");
        assert_eq!(next.meta().name, "after.txt");
        let mut data = Vec::new();
        next.reader().read_to_end(&mut data).unwrap();
        assert_eq!(data, b"beta");
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
}
