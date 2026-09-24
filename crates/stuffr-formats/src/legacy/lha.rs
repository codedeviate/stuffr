//! LHA/LZH: read via `delharc`, write via `oxiarc-lzhuf`.
//!
//! # The reader accepts seven methods; the writer emits ONE
//!
//! Read-only for the whole of Phase 3b and given a `-lh5-` encoder in Phase
//! 3c Task 6, which is where the asymmetry comes from and it is worth
//! meeting before anything else here: the READER accepts `-lh0-` through
//! `-lh7-` (plus the LArc `-lz*-` family, per the `delharc` features this
//! build compiles — `std`, `lh1`, `lz`, no `lhx`), while the WRITER emits
//! `-lh5-` and nothing else. `-lhd-` is written too, but that is a KIND
//! marker for a directory entry rather than a compression method.
//!
//! So `ContainerCaps::write == true` means "stuffr can produce an LHA
//! archive", never "stuffr can reproduce THIS LHA archive". Unpacking an
//! `-lh7-` archive and packing it again yields a valid `.lzh` whose entries
//! are `-lh5-`: a smaller dictionary, a larger file, no data loss. Phase 3c's
//! design names this a known weakness rather than an oversight, and
//! [`Lha::caps`] and `examples.txt`'s legacy section both state it where a
//! caller and a user respectively will meet it.
//!
//! `-lh5-` and not `-lh6-`/`-lh7-` because it is what every LHA reader in
//! existence supports; the whole point of this format being here is the
//! decades-old tools, and the two larger-window methods postdate a good deal
//! of them.
//!
//! # The end-of-archive marker is written for an EMPTY archive alone
//!
//! LHA's terminator is one `0x00` byte standing in for the next header's
//! length field, and `delharc` treats it and end-of-file as the same answer
//! (`parser.rs:190`, `Some(0) | None => return Ok(None)`). Two consequences,
//! both measured rather than reasoned about:
//!
//! - An EMPTY archive has no other spelling. `LhaDecodeReader::new` raises
//!   `"a header is missing"` the moment its first header read comes back
//!   empty, so a zero-byte file is not a readable empty LHA archive at all.
//!   [`LhaWrite::finish`] writes the marker when nothing was added, and
//!   [`Lha::open`] peeks one byte to turn it back into "no entries" instead
//!   of `Error::Corrupt`.
//! - For a NON-empty archive the marker is redundant, and writing it would
//!   make the last byte of every archive stuffr produces removable with no
//!   reader able to tell. Measured on the conformance harness's own
//!   two-entry fixture: with the marker the archive is 90 bytes and a read
//!   of its first 89 returns BOTH entries at no error.
//!
//! The honest limit, stated rather than implied closed: LHA carries no entry
//! count, no index and no mandatory trailer, so a cut landing EXACTLY on an
//! entry boundary is indistinguishable from a shorter valid archive, and no
//! writer choice changes that. Measured on the same fixture: entry 1 ends at
//! byte 45, and a read of the first 45 bytes returns one entry, cleanly.
//! Container-conformance property 9 passes here because none of its four cut
//! offsets lands on a boundary — not because this format detects every
//! truncation. **The margin is ONE BYTE**, and "offset-dependent" is too
//! comfortable a word for it: the cuts are `1, len/3, len/2, len-1`, and on
//! a two-entry archive `len/2` IS the entry boundary exactly when the two
//! `-lh5-` payloads are the same length — today they are 13 and 12. A
//! one-byte change in either payload turns that property red with no defect
//! present, and the fix would be a bigger fixture, never a loosened
//! property. What a writer CAN control is whether it manufactures such a
//! boundary at the end of every archive it writes, and this one does not.
//!
//! # `delharc` streams; this is why LHA's caps differ from ARJ's
//!
//! `delharc::LhaDecodeReader<R>` is `impl<R: std::io::Read>` — no `Seek`
//! bound anywhere in its public API — and it implements `std::io::Read`
//! directly for the CURRENT entry's decoded bytes. So LHA parses forward off
//! a pipe natively: `--max-ratio` works normally here, and no
//! bound-before-allocation guard is needed the way `legacy::arj` needs one
//! (that crate materialises whole entries; this one does not). Do not copy
//! ARJ's guard in here "for symmetry" — it would be dead code protecting
//! against a decode shape this crate does not have.
//!
//! # No borrowed entry type — unlike tar, ar and cpio
//!
//! `LhaDecodeReader` does not hand back a borrowed `Entry<'a, R>` the way
//! `tar::Entries`/`ar::Archive`/`cpio::newc::Reader` do. It owns a "current
//! entry" cursor directly: `header()` describes it, `Read` decodes it, and
//! `next_file()` advances past whatever of it was not consumed. That means
//! this module needs none of `cpio.rs`'s or `tar.rs`'s self-referential
//! `Box::into_raw` machinery — [`LhaRead`] just owns the `LhaDecodeReader`
//! outright and hands back an `Entry` whose reader borrows `&mut self`.
//!
//! # The fixture's expectation comes from `lhasa`, not `delharc`
//!
//! That is the entire reason this format sits in Phase 3b rather than 3c —
//! see `fixtures/legacy/MANIFEST.md`'s `sample.lzh` entry for exactly how the
//! fixture was produced and independently verified (`lha v`/`lha t`/`lha x`,
//! lhasa 0.6.0). No tool on the build machine can CREATE an `.lzh` archive
//! (`lhasa` decompresses only; `delharc` itself has no writer), so the
//! fixture is hand-built from the LHA level-1 header layout and then checked
//! against lhasa, an implementation independent of the crate this module
//! wraps. Both agree, byte for byte — there is no lhasa/delharc disagreement
//! to report for this fixture.
//!
//! Task 6 did not retire that fixture and must not: the thirteen-property
//! harness round-trips through THIS PROJECT'S OWN encoder, so every property
//! in it is stuffr agreeing with stuffr. `sample.lzh` is the one check here
//! that evidence from outside this crate underwrites, and
//! `lhasa_reads_what_we_write` is its write-side twin — the only test proving
//! that what `oxiarc-lzhuf` emits is genuinely LHA rather than something it
//! and `delharc` merely agree about.
//!
//! # Error mapping has no wildcard
//!
//! - `is_decoder_supported() == false` → [`Error::Unsupported`] (exit 3). A
//!   capability answer, not damage: the archive is fine, this build's `delharc`
//!   feature set (`std`, `lh1`, `lz` — no `lhx`) cannot decode that entry's
//!   method. Directories (`-lhd-`) are the one case where an unsupported
//!   decoder is NOT an error — see [`LhaRead::next_entry`].
//! - A failed `crc_check()` → `io::ErrorKind::InvalidData`, surfaced from the
//!   entry's own `Read` impl once its payload is fully consumed (see
//!   [`LhaEntryReader`]). Downstream, `entries.rs`'s `copy_charging` applies
//!   [`Error::from_decode_io`] to this, which is what turns it into
//!   [`Error::Corrupt`] (exit 5) for a real caller.
//! - A payload that stops short of its declared length → the same
//!   `InvalidData`, folded from delharc's `UnexpectedEof` by
//!   [`fold_truncated_payload`], for the same reason and at the same
//!   boundary. Left alone it was exit 1 — the Phase 3a honesty oracle's
//!   finding; see that function's doc.
//! - Malformed header structure, encountered while [`LhaRead::next_entry`]
//!   advances via `next_file()` (or while [`Lha::open`] parses the first
//!   header), is classified directly by [`classify_lha_error`] into
//!   [`Error::Corrupt`] — a `crate::Error` constructed straight from
//!   `next_entry`'s own `Result`, never routed through the generic
//!   `io::Error -> Error::Io` `?`-conversion that would otherwise demote it
//!   to exit 1 (see that function's doc for why this distinction matters).
//! - Genuine io errors (a failing source) pass through as themselves via the
//!   same function.
//! - On the WRITE side: a name too long for a level-1 header's single length
//!   byte, a `Symlink` or `Other` entry kind, and a payload past the format's
//!   `u32` size fields are each [`Error::Unsupported`] (exit 3) — a limit of
//!   the FORMAT this build writes, named, never a silent truncation or a
//!   quietly different entry kind. The one exception is the encoder itself
//!   failing, which is [`Error::Io`] (exit 1) deliberately: see
//!   [`LhaWrite::add`].
//!
//! # Two crates, and why the name parsing is this module's own
//!
//! `delharc` cannot write and `oxiarc-lzhuf` does not parse headers, so this
//! module owns the header layout in both directions ([`write_level1_header`])
//! and delegates only the `-lh5-` bitstream. It also parses entry NAMES
//! itself: `delharc`'s own accessor strips `..`, `.` and empty components,
//! which would destroy the evidence the ops-layer containment refusal depends
//! on. See [`raw_pathname`].

use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use delharc::LhaDecodeReader;
use delharc::decode::LhaDecodeError;
use delharc::header::LhaHeader;
use delharc::header::ext::{EXT_HEADER_FILENAME, EXT_HEADER_PATH};
use oxiarc_lzhuf::{LzhMethod, encode_lzh};
use stuffr_core::{
    ArchiveRead, ArchiveWrite, Container, ContainerCaps, CorruptionDetection, CreateOpts, Entry,
    EntryKind, EntryMeta, Error, FidelityReport, FormatId, FormatMeta, MagicRule, OpenOpts,
    Resolved, Result, Sink, Source,
};

use super::crc::crc16_arc;
use super::dos;

pub const LHA: FormatId = FormatId::new("lha");

/// LHA/LZH archives carry several method-family spellings at the same
/// offset (`compression` is 5 bytes: `-`, two method letters, a digit or
/// letter, `-`). Two rules, deliberately, not one: no registered format
/// exercised the container-conformance harness's "at least one of several"
/// magic semantics before this one, and this is where it first gets a real
/// second rule to prove it against. `sample.lzh`'s own fixture uses
/// `-lh0-`, which matches the first rule and not the second — exactly the
/// "one hits, one doesn't" shape the property needs.
const LHA_MAGIC: &[MagicRule] = &[
    MagicRule {
        offset: 2,
        bytes: b"-lh",
        format: LHA,
    },
    MagicRule {
        offset: 2,
        bytes: b"-lz",
        format: LHA,
    },
];

pub fn meta() -> FormatMeta {
    FormatMeta::container(LHA, &["lzh", "lha"], LHA_MAGIC)
}

pub struct Lha;

impl Container for Lha {
    fn id(&self) -> FormatId {
        LHA
    }

    /// # `write: true` does NOT mean every method round-trips
    ///
    /// This is the one place in `ContainerCaps` where the flag is coarser
    /// than the format, so read this before believing it: the READER accepts
    /// `-lh0-` through `-lh7-` (plus the LArc `-lz*-` family, subject to the
    /// `delharc` features this build compiles — see the module doc), while
    /// the WRITER emits `-lh5-` and nothing else. `ContainerCaps` has no
    /// per-method field and this task did not invent one, so a caller reading
    /// `write: true` learns "stuffr can produce an LHA archive", never
    /// "stuffr can reproduce THIS LHA archive's method". Re-packing an
    /// `-lh7-` archive through `stuffr unpack`/`stuffr pack` therefore
    /// produces a valid `.lzh` whose entries are `-lh5-` — smaller dictionary,
    /// larger output, no data loss. The asymmetry is deliberate (Phase 3c's
    /// design names it as a known weakness), not an oversight, and
    /// `examples.txt`'s legacy section states it for a user.
    ///
    /// `stores_dirs: true` is a separate, narrower claim and it is genuine:
    /// a directory goes out as an `-lhd-` entry, which is the format's own
    /// marker for "this is a directory, there is no payload", and
    /// [`LhaRead::next_entry`] reads it back as [`EntryKind::Dir`].
    /// `-lhd-` is a KIND marker rather than a compression method, so it does
    /// not widen the "one method" claim above.
    ///
    /// `stores_symlinks` stays false: LHA's own convention for a symlink is
    /// a `-lhd-` entry whose name is `link|target`, which no part of this
    /// module reads back as a link, so claiming it would produce exactly the
    /// lie the field exists to prevent.
    fn caps(&self) -> ContainerCaps {
        // Was `ContainerCaps::read_only()` for the whole of Phase 3b. The
        // sibling constructor is the same shape with `write: true`, and
        // `needs_seek: false` still holds in both directions — `delharc`
        // genuinely does not need seek to read, and the writer only ever
        // appends.
        ContainerCaps {
            forward_parse: true,
            // Every plain LHA entry carries a CRC-16 the format MANDATES,
            // and `delharc`'s `crc_check()` is what raises on a mismatch —
            // a format-wide guarantee, not a per-writer option, so
            // `Always`. Read by the read-only conformance harness's
            // corruption property.
            detects_corruption: CorruptionDetection::Always,
            stores_dirs: true,
            ..ContainerCaps::read_write()
        }
    }

    /// # The one byte peeked before `delharc` sees the stream
    ///
    /// `LhaDecodeReader::new` raises `HeaderParse("a header is missing")` the
    /// moment its first header read comes back empty (`decode.rs:150`), and a
    /// header read comes back empty for TWO different inputs: end-of-file,
    /// and a header-length byte of `0`. The second of those is LHA's own
    /// end-of-archive marker, so at offset 0 it means an archive with no
    /// entries — a perfectly valid thing for [`LhaWrite::finish`] to have
    /// produced, and the only spelling an empty LHA archive HAS (there is no
    /// header to hold a count and no trailer to state one). Handed straight
    /// to `delharc` it came back as `Error::Corrupt`: an empty archive
    /// reported as a damaged file.
    ///
    /// One byte is peeked to separate the two, and only the explicit `0` is
    /// accepted. A zero-length stream stays an error, deliberately: nothing
    /// in it says "LHA", so "this file is not an archive" is the honest
    /// answer, and conflating the two would make `stuffr list` print nothing
    /// at exit 0 for any empty file that happened to be named `.lzh`.
    ///
    /// [`stuffr_core::PeekSource`] rather than a hand-rolled one-byte buffer,
    /// and the SEEKABLE flag is captured before it: a peek wrapper reports
    /// `seekable: false` by construction, and `by_index`'s two spellings
    /// (`NotSeekable` for a pipe, `Unsupported` for a real file with no
    /// index) depend on knowing which one this source really was.
    fn open(&self, resolved: Resolved, _o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
        let Resolved { source, report, .. } = resolved;
        let seekable = source.caps().seekable;
        let peeked = stuffr_core::PeekSource::fill(source, 1)?;
        if peeked.prefix() == [0] {
            return Ok(Box::new(LhaRead {
                reader: None,
                report,
                seekable,
                advance_before_yield: false,
                done: true,
            }));
        }
        let source: Box<dyn Source> = Box::new(peeked);
        let reader = LhaDecodeReader::new(source).map_err(classify_lha_error)?;
        Ok(Box::new(LhaRead {
            reader: Some(reader),
            report,
            seekable,
            advance_before_yield: false,
            done: false,
        }))
    }

    /// Writes LHA level-1 headers with `-lh5-` payloads. See [`LhaWrite`].
    ///
    /// `CreateOpts::level` is deliberately ignored rather than validated:
    /// LHA's method letter IS its level, this build writes one method, and
    /// there is no second knob (no dictionary choice, no effort setting) that
    /// a number could select. Refusing a level would be worse — `stuffr pack
    /// --level 6 -o x.lzh` is a reasonable thing to type, and the only honest
    /// answers are "ignored" or "invent a mapping onto `-lh4-`/`-lh6-`/
    /// `-lh7-`", which this build cannot write.
    fn create(&self, dst: Box<dyn Sink>, _o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
        Ok(Box::new(LhaWrite {
            dst: Some(dst),
            wrote_any: false,
        }))
    }
}

/// Classifies an error `delharc` raised while parsing a header, into this
/// project's error vocabulary — directly, as a `crate::Error`, from
/// [`LhaRead::next_entry`] (a `Result`-returning method), never via a bare
/// `io::Error` propagated through `?`.
///
/// That distinction is load-bearing, not stylistic. An `io::Error` reaching
/// a caller via `entry.reader().read_to_end(&mut data)?` is auto-converted
/// through `Error`'s `#[from] std::io::Error`, landing on `Error::Io` — and
/// `Error::Io` has no explicit arm in `Error::exit_code()`, so it ALWAYS
/// falls to that match's `_ => 1` wildcard regardless of the wrapped
/// `io::ErrorKind`. A corrupted header discovered here and reported that way
/// would say "stuffr failed", not "the archive is damaged". Building
/// `Error::Corrupt` directly and returning it from `next_entry()` sidesteps
/// that conversion entirely — `next_entry()`'s own signature is already
/// `Result<Option<Entry<'_>>>`, so nothing forces the io::Error round trip
/// here the way an `impl Read` payload reader is stuck with it.
///
/// `delharc`'s own `LhaError<io::Error> -> io::Error` conversion (used via
/// `LhaDecodeError`'s `Into<io::Error>`) folds `HeaderParse`, `Decompress`
/// and `Checksum` onto `io::ErrorKind::InvalidData` and passes `Io` through
/// unchanged. That alone is not the whole story, MEASURED directly against
/// this module's own `a_corrupted_second_header_is_reported_as_corrupt_
/// not_as_an_io_failure` test: flipping a header's declared length byte
/// does not always land on a checksum mismatch (`HeaderParse`, already
/// `InvalidData`) — it can instead make the parser try to read an
/// `extended_area` far past what the stream actually has left, which
/// surfaces as delharc's own synthesised "not enough bytes" signal
/// (`stub_io::Read::unexpected_eof`, wrapped as `LhaError::Io` since it
/// travels the ordinary `Read` error path, not a dedicated parse-error
/// variant) — `io::ErrorKind::UnexpectedEof`, passed through UNCHANGED by
/// delharc's own conversion. Left as `Error::Io`, that would fall to
/// `Error::exit_code`'s `_ => 1` wildcard: "stuffr failed", for a corrupted
/// archive.
///
/// `UnexpectedEof` is safe to fold onto `Corrupt` here, and specific to
/// this function rather than a widening of `stuffr_core::Error::
/// from_decode_io` itself, for the same reason `cpio.rs`'s
/// `CPIO_MALFORMED_AS_INVALID_DATA_EOF` and the other per-format constants
/// in `normalize.rs` are each their own constant: a genuine SOURCE failure
/// (a disk error) keeps ITS OWN native `io::ErrorKind` (e.g.
/// `PermissionDenied`) all the way through — delharc's blanket
/// `stub_io::Read` impl propagates such an error verbatim from the
/// underlying reader (`Err(e) => return Err(e)` in its `read_all`), it is
/// never rewritten to `UnexpectedEof`. Only delharc's own synthesised
/// "fewer bytes than requested, no underlying error" signal uses that kind,
/// so folding it here cannot mistake a bad disk for a bad archive.
/// The byte LHA uses to separate path components inside a stored name.
///
/// Never ambiguous against a name component: `EntryMeta::name` is a `String`,
/// so it is UTF-8, and `0xFF` is not a byte any UTF-8 encoding can produce.
/// That is why [`LhaWrite::add`] can store a `/`-bearing name verbatim rather
/// than needing `ar.rs`'s extended-identifier dance.
const LHA_PATH_SEPARATOR: u8 = 0xFF;

/// The entry's stored name, reported EXACTLY as the archive carries it.
///
/// # Why this is not `LhaHeader::parse_pathname_to_str`
///
/// `delharc`'s own accessor SANITISES, and says so in its doc: "Malicious
/// path components, like `..`, `.` or `//` are stripped from the path names."
/// Measured against `delharc 0.6.2`'s `parse_pathname_to_str` (its
/// `parser.rs:453` splits on `0xFF`, `/` and `\`, then drops every `.`, `..`
/// and empty component):
///
/// | stored in the archive | `parse_pathname_to_str` | this function |
/// |---|---|---|
/// | `../../etc/passwd` | `etc/passwd` | `../../etc/passwd` |
/// | `/abs/path` | `abs/path` | `/abs/path` |
/// | `a/../../b` | `a/b` | `a/../../b` |
///
/// That is the wrong direction for this project, and container-conformance
/// property 12 is the standing statement of why: containment is enforced
/// ONCE, at the ops layer (`entries.rs`'s `safe_join` and
/// `refuse_symlinked_ancestors`), and it can only refuse what it can still
/// see. A container that helpfully rewrites `../../etc/passwd` into
/// `etc/passwd` turns a refusal into a silent rename — the archive's claim
/// disappears, `stuffr list` shows a name the archive does not contain, and
/// the one code path built to say "no" never runs. The instinct is inverted
/// on purpose: the container must not help.
///
/// This was invisible for the whole of Phase 3b because the read-only
/// conformance harness has no property 12 — a fixture-driven container is
/// never asked to round-trip a hostile name, since there is no encoder to
/// produce one. Graduating to the write-capable harness is what surfaced it.
///
/// # What it does, enumerated — THREE differences, not one
///
/// An earlier version of this doc said "only the FILTERING is dropped" and
/// that the `%XX` escaping was "the same escaping `delharc` applies". Both
/// were false, and the review that measured them is why this list is
/// exhaustive rather than a summary. Against `delharc 0.6.2`
/// (`parser.rs:449-515`):
///
/// | stored | `delharc` | here | why |
/// |---|---|---|---|
/// | `../../etc/passwd` | `etc/passwd` | `../../etc/passwd` | the filtering, dropped — see above |
/// | byte `0xC3` | `%c3` | `%C3` | `{:02X}`, cosmetic |
/// | a literal `%1f` | `%1f` | `%251f` | `%` is escaped too, so the mapping is injective |
/// | `dos\sub\file.txt` | `dos/sub/file.txt` | `dos/sub/file.txt` | unchanged: `\` IS split |
///
/// Structure is preserved exactly. `0xFF` (the format's own separator), `/`
/// and `\` all become `/`, which is what `delharc` does and what LHA
/// archives in the wild need: `\` is the native separator of the DOS-era
/// tools this format exists to read, so leaving it literal would flatten a
/// whole directory tree into one filename. It also cuts the security way:
/// splitting is what makes `a\..\..\etc\passwd` visible to
/// `entries.rs`'s `safe_join` as traversal instead of hiding the intent
/// inside a single component — the same argument that justifies dropping
/// the filtering above.
///
/// The two escaping changes are deliberate improvements with a cost, and
/// the cost is stated rather than glossed. `%` → `%25` removes a genuine
/// ambiguity (a stored literal `%1f` was previously indistinguishable from
/// an escaped `0x1F`), and it is what makes the mapping injective, so two
/// different stored names can never collapse onto one reported name. The
/// hex case is cosmetic. **Both change name matching, which is exact**: an
/// entry a user previously reached as `stuffr cat old.lzh 'na%c3me.txt'` is
/// now `na%C3me.txt`, and the old spelling is `Error::EntryNotFound` (exit
/// 2). `README.md`'s status block and `examples.txt`'s LHA entry say so
/// where a user will meet it.
///
/// Escaping at all — rather than `String::from_utf8_lossy` — keeps a
/// Shift-JIS or CP437 name from a real DOS-era archive renderable instead of
/// a run of U+FFFD, and guarantees the output is printable ASCII, so an
/// embedded NUL or a stray `/`-lookalike byte cannot reach a `Path::join`
/// having been invented on the way.
///
/// Header precedence mirrors `delharc`'s: an extra header of type
/// [`EXT_HEADER_FILENAME`] wins over the base header's `filename` field, and
/// an [`EXT_HEADER_PATH`] extra header is prepended as the directory.
fn raw_pathname(header: &LhaHeader) -> String {
    let mut dir: &[u8] = &[];
    let mut ext_name: &[u8] = &[];
    for extra in header.iter_extra() {
        match extra {
            [EXT_HEADER_FILENAME, data @ ..] => ext_name = data,
            [EXT_HEADER_PATH, data @ ..] => dir = data,
            _ => {}
        }
    }
    let base: &[u8] = if ext_name.is_empty() {
        &header.filename
    } else {
        ext_name
    };

    lha_name_from_parts(dir, base)
}

/// The second half of [`raw_pathname`]: joins a path extra header's bytes to
/// the entry's own name bytes and applies the escaping this module reports
/// names with.
///
/// Split out of [`raw_pathname`] in Salvage Stage 2 Task 5 so
/// [`super::lha_salvage`] reports a recovered entry under **exactly** the
/// name `stuffr list` shows for the same record. That matters more here than
/// it looks: this mapping is deliberately NOT `delharc`'s (three documented
/// differences — see [`raw_pathname`]'s own table), and name matching in this
/// project is EXACT, so a scanner carrying its own second copy of the
/// escaping would report `na%c3me.txt` where `list` reports `na%C3me.txt` and
/// `salvage --pattern` would silently match neither. One function, two
/// callers, no second copy.
pub(super) fn lha_name_from_parts(dir: &[u8], base: &[u8]) -> String {
    let mut raw: Vec<u8> = Vec::with_capacity(dir.len() + base.len() + 1);
    raw.extend_from_slice(dir);
    // A path extra header conventionally ends with the separator already;
    // adding a second one would report `dir//file`, which is a name the
    // archive does not carry.
    if !raw.is_empty() && raw.last() != Some(&LHA_PATH_SEPARATOR) && !base.is_empty() {
        raw.push(LHA_PATH_SEPARATOR);
    }
    raw.extend_from_slice(base);

    let mut out = String::with_capacity(raw.len());
    for &b in &raw {
        match b {
            // `\\` alongside `0xFF`, matching `delharc`: it is the native
            // separator of the DOS-era tools that wrote these archives, so
            // a name carrying one is a PATH, not a filename with an odd
            // character in it. See this function's table.
            LHA_PATH_SEPARATOR | b'\\' => out.push('/'),
            b'%' => out.push_str("%25"),
            0x20..=0x7E => out.push(b as char),
            other => {
                // Infallible: writing to a String cannot fail.
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}

fn classify_lha_error(e: LhaDecodeError<Box<dyn Source>>) -> Error {
    let io_err: io::Error = e.into();
    if io_err.kind() == io::ErrorKind::UnexpectedEof {
        return Error::Corrupt(io_err.to_string());
    }
    Error::from_decode_io(io_err)
}

struct LhaRead {
    /// `None` for an archive that declared itself empty with a leading `0`
    /// end-of-archive marker — see [`Lha::open`]. `delharc` has no
    /// "no entries" state to construct, so the absence IS that state, and
    /// `done` is set alongside it so nothing ever has to unwrap this.
    reader: Option<LhaDecodeReader<Box<dyn Source>>>,
    report: FidelityReport,
    seekable: bool,
    /// Whether `next_file()` must be called before the header currently
    /// loaded in `reader` may be handed back as the next entry.
    ///
    /// `false` right after `open`: `LhaDecodeReader::new` already parsed the
    /// FIRST entry's header (that is how the crate's own API works — there
    /// is always a "current" entry, never a "before the first" state), so
    /// the first call to `next_entry` must not advance past it. Every call
    /// after that must.
    advance_before_yield: bool,
    /// Set once `next_file()` answers `Ok(false)` (clean end of archive) or
    /// any error was raised — either way, nothing more will be read.
    done: bool,
}

impl ArchiveRead for LhaRead {
    fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
        if self.done {
            return Ok(None);
        }

        let Some(reader) = self.reader.as_mut() else {
            // Unreachable: `done` is set wherever `reader` is `None`, and the
            // check above already returned. Kept as a branch rather than an
            // `expect` so an empty archive can never panic.
            return Ok(None);
        };

        if self.advance_before_yield {
            match reader.next_file() {
                Ok(true) => {}
                Ok(false) => {
                    self.done = true;
                    return Ok(None);
                }
                Err(e) => {
                    self.done = true;
                    return Err(classify_lha_error(e));
                }
            }
        }
        self.advance_before_yield = true;

        let header = reader.header();
        let name = raw_pathname(header);
        let is_directory = header.is_directory();
        let size = header.original_size;
        let compressed_size = header.compressed_size;
        let mtime = header
            .parse_last_modified()
            .to_utc()
            .and_then(|dt| u64::try_from(dt.timestamp()).ok())
            .map(|secs| UNIX_EPOCH + Duration::from_secs(secs));

        if !is_directory && !reader.is_decoder_supported() {
            let method = String::from_utf8_lossy(&header.compression).into_owned();
            self.done = true;
            return Err(Error::Unsupported(format!(
                "entry `{name}` uses LHA compression method `{method}`, which this build \
                 cannot decode (delharc compiled with `std`, `lh1`, `lz` — no `lhx`)"
            )));
        }

        let meta = EntryMeta {
            name,
            size: Some(size),
            compressed_size: Some(compressed_size),
            mtime,
            mode: None,
            uid: None,
            gid: None,
            kind: if is_directory {
                EntryKind::Dir
            } else {
                EntryKind::File
            },
            codec: None,
        };

        let reader: Box<dyn Read + '_> = if is_directory {
            Box::new(io::empty())
        } else {
            Box::new(LhaEntryReader {
                inner: reader,
                crc_checked: false,
            })
        };

        Ok(Some(Entry::new(meta, reader)))
    }

    fn by_index(&mut self, index: usize) -> Result<Entry<'_>> {
        if self.seekable {
            return Err(Error::Unsupported(format!(
                "LHA carries no entry index, so entry {index} can only be reached by reading \
                 forward from the start"
            )));
        }
        Err(Error::NotSeekable { format: LHA })
    }

    fn fidelity(&self) -> &FidelityReport {
        &self.report
    }
}

/// Wraps `&mut LhaDecodeReader` for one entry's payload, adding the one thing
/// the crate leaves to its caller: verifying the trailing CRC-16 once the
/// payload is fully consumed.
///
/// `delharc`'s own `std::io::Read` impl for `LhaDecodeReader` never checks
/// the checksum itself — `crc_check()`/`crc_is_ok()` are separate methods a
/// caller is expected to call once reading is done (see the crate's own
/// `no_run` example in its module doc). Folding that check into `read()`
/// itself, rather than leaving it to a caller who might forget, is what lets
/// a corrupted `-lh0-` entry (whose PassthroughDecoder has no other way to
/// notice a flipped byte — it is a byte-for-byte copy, not a real codec)
/// still surface as an error instead of silently wrong bytes.
struct LhaEntryReader<'a> {
    inner: &'a mut LhaDecodeReader<Box<dyn Source>>,
    /// Whether the CRC has already been checked. Guards against checking it
    /// more than once (harmless) and against a zero-length `read()` call
    /// that has not actually reached the entry's real end (`is_empty()` is
    /// the true gate below, not merely `n == 0`).
    crc_checked: bool,
}

/// The payload-path twin of [`classify_lha_error`], and the reason it has to
/// exist separately: `next_entry` returns `Result<_, crate::Error>` and can
/// therefore build an `Error::Corrupt` directly, but an entry's payload is
/// handed to the caller as an `impl Read`, whose only error channel is
/// `io::Error`. A truncated payload reaches that channel as delharc's
/// synthesised short-read signal, `io::ErrorKind::UnexpectedEof`, and
/// `Error::from_decode_io` — which every caller of an entry reader runs it
/// through — folds only `InvalidData` and `OutOfMemory`, leaving everything
/// else as `Error::Io`, i.e. exit 1: *stuffr* failed. So an archive whose
/// last entry is simply cut short reported an internal failure rather than a
/// damaged file.
///
/// Found by the Phase 3a honesty oracle (`check_error_is_classified`) once
/// the legacy formats joined the default feature set and the pure-tier fuzz
/// job reached them for the first time; the minimised input is a `-lh0-`
/// archive declaring a 6-byte `sample/hello.txt` and carrying 4 bytes of it.
///
/// Folding happens HERE, at this module's own boundary, and folds
/// `UnexpectedEof` ALONE — never in `from_decode_io`, where it would apply to
/// every format and every layer. The narrowness is what keeps a genuine
/// source failure honest: delharc's blanket `stub_io::Read` impl propagates
/// an underlying reader's error verbatim (`Err(e) => return Err(e)` in its
/// `read_all`), so a failing disk still arrives as `PermissionDenied` and
/// passes straight through this function unchanged. Container-conformance
/// property 9 is the standing proof of that, and
/// `a_source_error_during_a_payload_read_is_not_relabelled_as_corruption`
/// below pins it for this specific call site.
fn fold_truncated_payload(e: io::Error) -> io::Error {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        return io::Error::new(
            io::ErrorKind::InvalidData,
            format!("LHA entry payload ended before its declared length: {e}"),
        );
    }
    e
}

impl Read for LhaEntryReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf).map_err(fold_truncated_payload)?;
        if !self.crc_checked && self.inner.is_empty() {
            self.crc_checked = true;
            if !self.inner.crc_is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "LHA entry failed its CRC-16 check",
                ));
            }
        }
        Ok(n)
    }
}

// ---------------------------------------------------------------------------
// The write side, added in Phase 3c Task 6
// ---------------------------------------------------------------------------

/// The ONE compression method this build writes, via `oxiarc-lzhuf`.
///
/// `-lh5-` and not `-lh6-`/`-lh7-` (bigger dictionaries, better ratios)
/// because it is the method every LHA reader in existence supports: LHarc
/// 2.x and every tool since. `-lh6-`/`-lh7-` postdate a good deal of the
/// software that reads `.lzh` at all, and this format's entire reason to be
/// here is reading and writing archives for tools that are decades old.
const METHOD_LH5: [u8; 5] = *b"-lh5-";

/// The marker a DIRECTORY entry carries in the same 5-byte field. Not a
/// compression method — `delharc`'s `CompressionMethod::is_directory` is
/// what reads it, and such an entry has no payload at all.
const METHOD_LHD: [u8; 5] = *b"-lhd-";

/// Every byte of a level-1 header except the filename: the 5-byte method,
/// three `u32` fields (skip size, original size, timestamp), the MS-DOS
/// attribute byte, the level byte, the filename-LENGTH byte, the `u16`
/// CRC-16, the OS-TYPE byte and the `u16` "first extra header length".
///
/// Counted from the header's third byte, because that is what the
/// header-length field itself measures — the length byte and the checksum
/// byte in front of it are excluded, which is also why
/// [`write_level1_header`] computes the wrapping checksum over exactly this
/// run. `delharc`'s parser makes the same split at `parser.rs:190`.
pub(super) const LEVEL1_HEADER_OVERHEAD: usize = 25;

/// The longest name a level-1 header can carry, because the header length is
/// a single byte and [`LEVEL1_HEADER_OVERHEAD`] of it is already spoken for.
///
/// Level 2 lifts this (a `u16` header size, the name in an extra header) and
/// this build does not write level 2 — so an over-long name is refused with
/// [`Error::Unsupported`] (exit 3) naming the limit, never silently
/// truncated. Truncating would be the worse failure by far: two entries
/// whose names differ only past byte 230 would collapse onto one name and
/// extraction would overwrite one with the other.
const MAX_LEVEL1_NAME: usize = u8::MAX as usize - LEVEL1_HEADER_OVERHEAD;

/// MS-DOS `ARCHIVE` — the attribute byte every writer in the wild sets for
/// an ordinary entry, and what `sample.lzh` itself carries.
const MSDOS_ATTR_ARCHIVE: u8 = 0x20;

/// OS-TYPE `'U'`: Unix. Chosen for what it means to a READER — `delharc`'s
/// `parse_last_modified` consults a Unix timestamp in the level-1 extended
/// area only for `U`/`OSK`, finds none here (this writer emits no extended
/// area), and falls back to the MS-DOS timestamp in the base header, which
/// is the field [`dos_timestamp`] fills.
const OS_TYPE_UNIX: u8 = b'U';

/// An entry payload this build refuses to compress, because LHA's size
/// fields are `u32`.
fn check_u32_size(name: &str, size: u64) -> Result<u32> {
    u32::try_from(size).map_err(|_| {
        Error::Unsupported(format!(
            "LHA cannot store `{name}`: {size} bytes exceeds the format's 4 GiB (u32) per-entry \
             size field"
        ))
    })
}

/// Packs a `SystemTime` into the MS-DOS `YYYYYYYM MMMDDDDD hhhhhmmm mmmsssss`
/// word a level-0/1 header's `last_modified` field holds.
///
/// `None` — which the caller stores as a literal zero, the "no timestamp"
/// shape a minimal archive uses and the one `delharc`'s
/// `parse_msdos_datetime` already answers `None` to — outside MS-DOS's own
/// 1980..=2107 range, and before the epoch. That is a real fidelity limit of
/// the FORMAT rather than of this writer, and it is the reason the seconds
/// field is halved: MS-DOS records seconds in units of two, so an odd second
/// is rounded DOWN, never up. Down, so a restored mtime is never later than
/// the original — `make`-style "is this newer than that" comparisons then
/// err toward rebuilding rather than toward skipping a rebuild.
fn dos_timestamp(t: SystemTime) -> Option<u32> {
    let (year, month, day, hour, minute, second) = dos::civil_fields(t)?;
    let year = u32::try_from(year - 1980).ok()?;
    if year > 0x7F {
        return None;
    }
    Some((year << 25) | (month << 21) | (day << 16) | (hour << 11) | (minute << 5) | (second / 2))
}

/// The inverse of [`dos_timestamp`]: unpacks a level-0/1 header's
/// `last_modified` field into a [`SystemTime`].
///
/// The READER does not use this — `LhaRead::next_entry` takes the timestamp
/// from `delharc`'s own `parse_last_modified`, which also consults the
/// level-2 Unix-time extra header this function knows nothing about.
/// [`super::lha_salvage`] parses a level-0/1 base header directly and so
/// needs the base field decoded on its own; it lives HERE, beside the writer
/// that packs the same field, so the two can be pinned as inverses
/// (`a_packed_dos_timestamp_round_trips_through_its_own_inverse`) rather
/// than each being read against prose.
///
/// Note the halves: the DATE is the HIGH 16 bits and the TIME the low ones,
/// which is the opposite order from `zoo.rs`'s `zoo_mtime` — that format
/// packs the same two words the other way round, and reading one layout into
/// the other is a silent 100-year error, never a parse failure.
pub(super) fn lha_mtime(packed: u32) -> Option<SystemTime> {
    let date = (packed >> 16) as u16;
    let time = (packed & 0xFFFF) as u16;
    dos::mtime(
        1980 + i64::from(date >> 9),
        u32::from((date >> 5) & 0x0F),
        u32::from(date & 0x1F),
        u32::from(time >> 11),
        u32::from((time >> 5) & 0x3F),
        u32::from(time & 0x1F) * 2,
    )
}

/// Appends one LHA **level-1** header to `out`.
///
/// Level 1 rather than 0 or 2 for two reasons, both about who can read the
/// result: level 0 has no OS-TYPE byte at all (so no reader can tell how to
/// interpret the name), and level 2 stores its name in extra headers, which
/// the oldest tools do not parse. Level 1 is what `sample.lzh` — the fixture
/// `lhasa` independently verified in Phase 3b — already is.
///
/// `skip_size` is level 1's own quirk and is NOT simply the compressed size:
/// the field holds the number of bytes between the end of this header and the
/// start of the next one, i.e. the compressed payload PLUS every extra
/// header. This writer emits no extra headers (`first_header_len` is zero),
/// so the two are equal here — stated rather than assumed, because adding one
/// extra header later without adjusting this field would desynchronise every
/// reader from the second entry onward.
pub(super) fn write_level1_header(
    out: &mut Vec<u8>,
    method: &[u8; 5],
    name: &[u8],
    skip_size: u32,
    original_size: u32,
    crc: u16,
    timestamp: u32,
) {
    // Everything the header-length byte counts and the checksum covers.
    let mut counted = Vec::with_capacity(LEVEL1_HEADER_OVERHEAD + name.len());
    counted.extend_from_slice(method);
    counted.extend_from_slice(&skip_size.to_le_bytes());
    counted.extend_from_slice(&original_size.to_le_bytes());
    counted.extend_from_slice(&timestamp.to_le_bytes());
    counted.push(MSDOS_ATTR_ARCHIVE);
    counted.push(1); // header level
    counted.push(name.len() as u8); // bounded by MAX_LEVEL1_NAME at the call site
    counted.extend_from_slice(name);
    counted.extend_from_slice(&crc.to_le_bytes());
    counted.push(OS_TYPE_UNIX);
    counted.extend_from_slice(&0u16.to_le_bytes()); // first_header_len: no extra headers
    debug_assert_eq!(
        counted.len(),
        LEVEL1_HEADER_OVERHEAD + name.len(),
        "LEVEL1_HEADER_OVERHEAD no longer describes this header"
    );

    out.push(counted.len() as u8);
    out.push(counted.iter().fold(0u8, |acc, &b| acc.wrapping_add(b)));
    out.extend_from_slice(&counted);
}

/// The LHA writer: level-1 headers, `-lh5-` payloads, `-lhd-` directories.
///
/// # Why an entry is buffered whole, and what that costs
///
/// An LHA header declares the entry's compressed size, its uncompressed size
/// AND its CRC-16 *before* the payload, and this project's writers must work
/// over a non-seekable destination (a pipe), so there is nowhere to go back
/// and patch those three fields in. The payload therefore has to be fully
/// read and fully compressed before its header can be written. That is a
/// property of the FORMAT, not a shortcut: `zip` solves the same problem with
/// data descriptors, which LHA has no equivalent of.
///
/// The cost is real, it is **~8.4x the entry's size on incompressible data**,
/// and an earlier version of this doc understated it by roughly four times
/// by calling it "the uncompressed size plus the compressed size". Measured
/// with `/usr/bin/time -l` on a release build, `stuffr pack <file> --format
/// lha`:
///
/// | input | peak RSS | ratio |
/// |---|---|---|
/// | 50 MiB random | 444 MB | **8.5x** |
/// | 100 MiB random | 817 MB | **8.2x** |
/// | 100.7 MiB compressible text | 146 MB | 1.45x |
///
/// The mechanism is `oxiarc-lzhuf`'s own shape, not the buffering above:
/// `LzssEncoder::encode(&[u8]) -> Vec<LzssToken>` materialises one 6-byte
/// token per literal for the whole entry (`lzss.rs:548`, reserving
/// `len / 2 + 1` up front), and `optimal.rs` builds a second full Vec beside
/// it. Compressible input escapes it because matches collapse many bytes
/// into one token — which is why the text row is 1.45x and the random rows
/// are eight.
///
/// **Exhaustion is a process ABORT, not an error.** `grep -rn try_reserve`
/// over `oxiarc-lzhuf 0.4.2`'s source returns **zero** hits, so a failed
/// allocation goes to `handle_alloc_error` → `SIGABRT`: no
/// `Error::ResourceLimit` (exit 6), no exit 1, no stuffr message of any
/// kind, and a `pack` over a whole tree takes the entire archive down with
/// it. Budget roughly 4.2 GB for a 500 MB entry and 8.4 GB for a 1 GB one.
///
/// Nothing accumulates ACROSS entries — each is written through and its
/// buffers dropped — so a 10,000-entry archive of small files costs what its
/// largest single entry costs, not the sum.
///
/// Unbounded anyway, deliberately: the threat model here is local files the
/// user named, a fixed ceiling would refuse files this machine can hold, and
/// `ContainerCaps`/`CreateOpts` carry no memory budget for a container to
/// consult (`DecodeOpts::memory_limit` binds a CODEC, and is a decode-side
/// field besides — see `arj.rs`'s own note on the same gap). The figures and
/// the abort are here so the cost is predictable rather than a surprise.
struct LhaWrite {
    /// `None` once `finish` has consumed it.
    dst: Option<Box<dyn Sink>>,
    /// Whether any entry has been written. Read by [`LhaWrite::finish`],
    /// which emits the end-of-archive marker for an EMPTY archive alone —
    /// see that method for the whole ruling.
    wrote_any: bool,
}

impl ArchiveWrite for LhaWrite {
    fn add(&mut self, meta: &EntryMeta, data: &mut dyn Read) -> Result<()> {
        // A DIRECTORY's stored name must end with a path separator, and this
        // is not cosmetic — it is the same class of interop defect as
        // `cpio.rs`'s missing `S_IFREG`, invisible to every test that reads
        // back through `delharc`. MEASURED against lhasa 0.6.0: an `-lhd-`
        // entry whose name does not end in a separator makes lhasa END THE
        // ARCHIVE THERE, silently, at exit 0 — `lha v` on a one-directory
        // archive printed `Total 0 files`, and on a directory followed by a
        // file printed `Total 0 files` too, losing the file as well. With a
        // trailing `/` both entries list and both extract. `delharc` is
        // indifferent either way (it takes the kind from the method field),
        // which is exactly why nothing in this module would have caught it.
        //
        // `/` and not `0xFF`: lhasa translates `0xFF` only in the extended
        // PATH header, never in a level-1 base filename, and a name stored
        // `adir\xff` was dropped the same way a bare `adir` was. This
        // writer stores whole paths in the base filename with literal `/`
        // separators — that is what `sample.lzh` does and what `lhasa`
        // reads — so `/` is the separator that is already in use here.
        //
        // The trailing separator comes back on the read side, so a directory
        // lists as `tree/`. That is the same convention `zip` follows, and
        // container-conformance property 13 deliberately does not assert a
        // directory entry's name for exactly this reason.
        let stored_name = match &meta.kind {
            EntryKind::Dir if !meta.name.ends_with('/') => format!("{}/", meta.name),
            _ => meta.name.clone(),
        };
        let name = stored_name.as_bytes();
        if name.len() > MAX_LEVEL1_NAME {
            return Err(Error::Unsupported(format!(
                "LHA cannot store `{}`: its stored name is {} bytes (a directory gains a \
                 trailing separator) and a level-1 header's filename field holds at most \
                 {MAX_LEVEL1_NAME}",
                meta.name,
                name.len()
            )));
        }

        let (method, payload, original_size, crc) = match &meta.kind {
            // No payload, no compression, no CRC to compute — `-lhd-` says
            // "directory" and everything else about the entry is the header.
            // `data` is deliberately not read, the same contract `tar.rs` and
            // `cpio.rs` apply to this kind.
            EntryKind::Dir => (METHOD_LHD, Vec::new(), 0u32, 0u16),
            EntryKind::File => {
                // Refused off the DECLARED size first, before a byte is read
                // or allocated, exactly as `cpio.rs`'s `add` does and for the
                // same reason: a caller who already knows an entry is
                // oversized costs nothing to refuse.
                if let Some(size) = meta.size {
                    check_u32_size(&meta.name, size)?;
                }
                let mut raw = Vec::new();
                data.read_to_end(&mut raw)?;
                let original_size = check_u32_size(&meta.name, raw.len() as u64)?;
                let crc = crc16_arc(&raw);
                let packed = encode_lzh(&raw, LzhMethod::Lh5).map_err(|e| {
                    // Deliberately `Error::Io` — exit 1, which means "stuffr
                    // failed", and that is the honest verdict here. Every
                    // other error in this module classifies something about
                    // the INPUT (a damaged archive, a method this build
                    // cannot decode); this one can only fire if the encoder
                    // cannot encode ordinary bytes, which is stuffr's own
                    // fault and nobody else's. Unreachable in practice:
                    // `encode_lzh` writes into a `Vec` (no I/O to fail) and
                    // `Lh5` is a method it implements, so its two error
                    // paths are both closed at this call site.
                    Error::Io(io::Error::other(format!(
                        "the LHA -lh5- encoder failed on `{}`: {e}",
                        meta.name
                    )))
                })?;
                (METHOD_LH5, packed, original_size, crc)
            }
            // `Symlink` and `Other` both land here. Refused rather than
            // written as a regular file: LHA's own symlink convention is an
            // `-lhd-` entry whose name is `link|target`, which this module's
            // READER does not decode back into `EntryKind::Symlink`, so
            // writing one would produce an archive stuffr itself reads as a
            // directory with a strange name. `caps().stores_symlinks` is
            // false, so `entries.rs` warns and skips before reaching here;
            // only a hand-built plan can, and it gets a named refusal rather
            // than a silent misrepresentation.
            other => {
                return Err(Error::Unsupported(format!(
                    "LHA cannot store `{}`: this build writes regular files and directories, \
                     not {other:?}",
                    meta.name
                )));
            }
        };

        // Level 1's "skip size" is the compressed payload plus every extra
        // header; this writer emits none, so they are equal. See
        // `write_level1_header`.
        let skip_size = check_u32_size(&meta.name, payload.len() as u64)?;
        let timestamp = meta.mtime.and_then(dos_timestamp).unwrap_or(0);

        let mut header = Vec::with_capacity(2 + LEVEL1_HEADER_OVERHEAD + name.len());
        write_level1_header(
            &mut header,
            &method,
            name,
            skip_size,
            original_size,
            crc,
            timestamp,
        );

        let dst = self
            .dst
            .as_mut()
            .ok_or_else(|| Error::Usage("LHA writer used after finish()".into()))?;
        dst.write_all(&header)?;
        dst.write_all(&payload)?;
        self.wrote_any = true;
        Ok(())
    }

    /// Returns the destination WITHOUT writing an end-of-archive marker, and
    /// that is a deliberate ruling rather than an omission.
    ///
    /// LHA's terminator is a single `0x00` byte standing in for the next
    /// header's length field, and it is OPTIONAL: `delharc` ends the archive
    /// on `Some(0) | None` at `parser.rs:190` — a zero byte and end-of-file
    /// are the same answer — and `lhasa` agrees. Writing one would therefore
    /// make the last byte of every archive stuffr produces removable with no
    /// reader on earth able to tell, which is the shape of silent truncation
    /// this project refuses everywhere else. MEASURED, not reasoned about:
    /// with the marker written, **two** of container-conformance property
    /// 9's four cuts are accepted silently on the two-entry fixture — the
    /// `len - 1` cut (89 of 90 bytes, which removes exactly that byte and
    /// returns BOTH entries) and the midpoint (45, which lands on entry 1's
    /// own boundary and returns one). The harness iterates in order and
    /// panics at 45, so its message names that one; only the first is this
    /// ruling's own doing — see the module doc's "The end-of-archive marker"
    /// section for the separation, and
    /// `an_archive_stops_at_its_last_entry_so_a_cut_tail_is_detectable`.
    ///
    /// Never via `Drop` — see `tar.rs`'s own `finish` doc for why that is the
    /// one path a caller may rely on. The destination is returned, not
    /// finished: the caller owns completion, because a codec layer beneath us
    /// may have its own trailer still to write.
    fn finish(mut self: Box<Self>) -> Result<Box<dyn Sink>> {
        let mut dst = self
            .dst
            .take()
            .ok_or_else(|| Error::Usage("LHA writer finished twice".into()))?;
        if !self.wrote_any {
            dst.write_all(&[0])?;
        }
        Ok(dst)
    }
}

/// Test-only helpers this module shares with [`super::lha_salvage`], which
/// is a SIBLING under `legacy` rather than a descendant of this module and
/// therefore cannot reach into `mod tests`.
///
/// Lifted out of `mod tests` in Salvage Stage 2 Task 5 rather than copied.
/// Each one exists because the scanner's tests need something only this
/// module can do: produce a real `-lh5-` archive (this crate's encoder lives
/// here), walk one with the ORDINARY reader (so "the ordinary reader cannot
/// get past this damage" is measured rather than asserted), and report a
/// name through [`raw_pathname`] (so the scanner's own name mapping is
/// compared against the reader's, not against a second copy of it).
#[cfg(test)]
pub(super) mod test_archives {
    use super::*;
    use stuffr_core::{OpenOpts, PlainSink, ReaderSource, StreamPolicy};

    /// Builds an archive through the real writer, the way every write-side
    /// test and the conformance harness itself reaches it. Every entry goes
    /// out as `-lh5-`, the one method this build writes.
    pub(in crate::legacy) fn build_lha(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let buf = stuffr_core::testing::SharedBuf::new();
        let mut w = Lha
            .create(
                PlainSink::new(Box::new(buf.clone())),
                &CreateOpts::default(),
            )
            .expect("create");
        for (name, data) in entries {
            w.add(&EntryMeta::file(*name), &mut io::Cursor::new(*data))
                .expect("add");
        }
        w.finish().expect("finish").finish().expect("sink finish");
        buf.contents()
    }

    /// Walks `bytes` with the ORDINARY reader and reports the entry names it
    /// reached, or the error that stopped it.
    pub(in crate::legacy) fn read_entry_names(
        bytes: &[u8],
    ) -> std::result::Result<Vec<String>, String> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(io::Cursor::new(bytes.to_vec())));
        let resolved = stuffr_core::resolve(src, LHA, Lha.caps(), &StreamPolicy::default())
            .map_err(|e| format!("resolve: {e}"))?;
        let mut ar = Lha
            .open(resolved, &OpenOpts::default())
            .map_err(|e| format!("open: {e}"))?;
        let mut out = Vec::new();
        loop {
            match ar.next_entry() {
                Ok(Some(entry)) => out.push(entry.meta().name.clone()),
                Ok(None) => return Ok(out),
                Err(e) => return Err(format!("next_entry: {e}")),
            }
        }
    }

    /// [`raw_pathname`], reachable from the scanner's tests — so the two
    /// name mappings are compared rather than each being read against prose.
    pub(in crate::legacy) fn pathname(header: &LhaHeader) -> String {
        raw_pathname(header)
    }
}

#[cfg(test)]
mod tests {
    use super::super::crc::crc16_arc;
    use super::*;
    use stuffr_core::testing::{
        ContainerFixture, ExpectedEntry, assert_container_conforms_skipping,
        assert_container_conforms_with_skipping,
    };
    use stuffr_core::{CreateOpts, OpenOpts, PlainSink, ReaderSource, StreamPolicy};

    const SAMPLE_LZH: &[u8] = include_bytes!("../../fixtures/legacy/sample.lzh");

    /// `Lha::open` peeks ONE byte before handing the source to `delharc`, to
    /// tell an archive that declared itself empty with a leading `0` from a
    /// real one — and `PeekSource::fill` reads it through a bare `?`.
    /// Measured from the backtrace of a real failure (`PeekSource::fill` <-
    /// `Lha::open` <- `entries::open_archive`), a truncated codec stream
    /// under an LHA archive therefore reported `i/o error`, exit 1, for input
    /// that is simply corrupt — while `stuffr cat` on the same bytes said
    /// exit 5.
    ///
    /// Note this is the ONE site of the four that is not in a container's own
    /// code at all: the read belongs to `stuffr-core`'s `PeekSource`, which is
    /// shared by the probe and by three containers. A per-site `map_err` here
    /// would have been a `map_err` in `PeekSource::fill` — which
    /// `resolve_chain_deep_with`'s own doc comment forbids, because that same
    /// function reads the RAW source two calls earlier. The marker resolves
    /// the two readings without either call site choosing.
    #[test]
    fn a_decode_side_failure_in_lha_open_is_corruption_not_an_io_failure() {
        use stuffr_core::testing::decode_side_failing_source;

        let resolved = stuffr_core::resolve(
            decode_side_failing_source(&[], io::ErrorKind::InvalidData),
            LHA,
            Lha.caps(),
            &StreamPolicy::default(),
        )
        .expect("a forward-parseable container resolves without reading");

        let err = match Lha.open(resolved, &OpenOpts::default()) {
            Err(e) => e,
            Ok(_) => panic!("the one-byte peek must fail on this source"),
        };
        assert!(
            matches!(err, Error::Corrupt(_)),
            "a decoder's malformed-input report must not claim stuffr failed: {err:?}"
        );
        assert_eq!(err.exit_code(), 5);
    }

    /// The hazard side: the identical failure from a source no decoder
    /// produced stays `Error::Io`, exit 1. Only the marking separates the two.
    #[test]
    fn a_raw_side_failure_in_lha_open_is_still_an_io_failure() {
        use stuffr_core::testing::raw_failing_source;

        let resolved = stuffr_core::resolve(
            raw_failing_source(&[], io::ErrorKind::InvalidData),
            LHA,
            Lha.caps(),
            &StreamPolicy::default(),
        )
        .expect("resolve");

        let err = match Lha.open(resolved, &OpenOpts::default()) {
            Err(e) => e,
            Ok(_) => panic!("the one-byte peek must fail"),
        };
        assert!(
            matches!(err, Error::Io(_)),
            "a raw source failing is stuffr's environment failing: {err:?}"
        );
        assert_eq!(err.exit_code(), 1);
    }

    const LHA_EXPECTED: &[ExpectedEntry] = &[
        ExpectedEntry::new("sample/hello.txt", b"alpha\n"),
        ExpectedEntry::new("sample/sub/b.bin", b"beta\n"),
    ];

    fn lha_fixture() -> ContainerFixture {
        ContainerFixture::new(
            SAMPLE_LZH,
            LHA_EXPECTED,
            "hand-built LHA level-1 archive (two `-lh0-`/store entries), \
             independently verified with lhasa 0.6.0 (`lha v`/`lha t`/`lha x`) — an \
             implementation independent of delharc; see \
             fixtures/legacy/MANIFEST.md's `sample.lzh` entry",
        )
    }

    /// Hand-builds a one-entry LHA level-1 archive with an arbitrary
    /// 5-byte method identifier — the same layout `sample.lzh` uses (see
    /// MANIFEST.md), generalised so tests can exercise method families that
    /// fixture deliberately does not (an unsupported method, a directory).
    /// Built on the PRODUCTION [`write_level1_header`] rather than a second
    /// hand-rolled copy of the layout, so a change to the header this module
    /// writes cannot leave these tests asserting against the shape it used to
    /// write. Only the payload is left to the caller — that is the whole
    /// point of this helper: it stores `content` verbatim under an arbitrary
    /// 5-byte method identifier, which is how tests reach method families the
    /// `-lh5-` encoder cannot produce (an unsupported method, a directory,
    /// a deliberately truncated payload).
    ///
    /// Note the trailing `0` end-of-archive marker, which [`LhaWrite::finish`]
    /// deliberately does NOT write: keeping it here is what makes
    /// `a_reader_still_accepts_the_optional_end_of_archive_marker` a real
    /// test of the reader rather than a test of our own writer's choice.
    fn build_single_entry_lha(name: &str, method: &[u8; 5], content: &[u8]) -> Vec<u8> {
        build_named_entry_lha(name.as_bytes(), method, content)
    }

    /// [`build_single_entry_lha`] over RAW name bytes, so a test can store a
    /// name no `String` can hold — a `0xFF` separator, a non-UTF-8 byte —
    /// which is exactly what `raw_pathname`'s table needs.
    fn build_named_entry_lha(name: &[u8], method: &[u8; 5], content: &[u8]) -> Vec<u8> {
        let size = content.len() as u32;
        let mut out = Vec::new();
        write_level1_header(&mut out, method, name, size, size, crc16_arc(content), 0);
        out.extend_from_slice(content);
        out.push(0); // end-of-archive marker
        out
    }

    /// Builds an archive through the real writer, the way every write-side
    /// test and the conformance harness itself reaches it. Lives in
    /// [`super::test_archives`] rather than here because
    /// `super::super::lha_salvage`'s own tests need it too, and a second copy
    /// would be a second writer's worth of assumptions.
    use super::test_archives::build_lha;

    /// The FULL thirteen-property harness, not the fixture-driven one — LHA
    /// graduated when `ContainerCaps::write` became true in Phase 3c Task 6.
    /// Read a failure's prefix carefully: this raises `property N` (1-13)
    /// while [`lha_conforms_against_the_external_fixture`] below still raises
    /// `fixture property N` (1-10), and five numbers mean different things in
    /// the two schemes.
    #[test]
    fn lha_conforms_with_a_writer() {
        // Skips property 7 alone: LHA has no trailing index. 13 RUNS —
        // `stores_dirs` is true (`-lhd-` entries), even though
        // `stores_symlinks` is not.
        assert_container_conforms_skipping(&Lha, &meta(), &[7]);
    }

    /// Kept alongside the write-capable harness rather than replaced by it,
    /// and the reason is the whole argument for this fixture's existence: the
    /// thirteen-property harness round-trips through THIS PROJECT'S OWN
    /// encoder, so every one of its properties is stuffr agreeing with
    /// stuffr. `sample.lzh` was verified by `lhasa` — an implementation
    /// sharing no code with `delharc` — so it is the one check here that
    /// evidence from outside this crate underwrites. Dropping it on the
    /// grounds that the bigger harness subsumes it would trade a witness for
    /// a mirror.
    #[test]
    fn lha_conforms_against_the_external_fixture() {
        let fx = lha_fixture();
        // `[2, 10]`, in the FIXTURE numbering (1-10), which is not the
        // thirteen-property scheme `lha_conforms_with_a_writer` above uses:
        // 2 is the read-only refusal, and `lha` gained a writer in Phase 3c
        // Task 6, so there is no refusal left to prove; 10 is the CRC
        // witness, and `sample.lzh`'s manifest records no archive-stored
        // CRC to witness against. Both are checked facts now rather than
        // silent skips — fixture property 3 in particular used to skip with
        // no output at all.
        assert_container_conforms_with_skipping(&Lha, &meta(), &fx, &[2, 10]);
    }

    /// `forward_parse: true` is a claim the conformance harness
    /// checks only indirectly (via the read-only properties above, which
    /// never open a genuinely non-seekable source). This proves it directly:
    /// read the fixture through the exact "erase `Seek` at the type level"
    /// shape `container_conformance.rs`'s `open_forward_only` uses, and
    /// confirm every entry — names AND content — comes back correctly.
    #[test]
    fn reads_every_entry_through_a_genuinely_non_seekable_source() {
        let mut ar = stuffr_core::testing::open_forward_only(&Lha, SAMPLE_LZH);
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
        let want: Vec<(String, Vec<u8>)> = LHA_EXPECTED
            .iter()
            .map(|e| (e.name.to_string(), e.content.to_vec()))
            .collect();
        assert_eq!(got, want, "forward-only read must recover every entry");
    }

    #[test]
    fn by_index_is_refused_on_every_source_shape() {
        let mut fwd = stuffr_core::testing::open_forward_only(&Lha, SAMPLE_LZH);
        assert!(
            matches!(fwd.by_index(0), Err(stuffr_core::Error::NotSeekable { .. })),
            "a forward-only source must answer NotSeekable"
        );

        let path = std::env::temp_dir().join(format!(
            "stuffr-lha-seekable-{}-{:p}.lzh",
            std::process::id(),
            SAMPLE_LZH
        ));
        std::fs::write(&path, SAMPLE_LZH).unwrap();
        let src: Box<dyn Source> = Box::new(stuffr_core::FileSource::open(&path).unwrap());
        let _ = std::fs::remove_file(&path);
        let resolved = stuffr_core::resolve(src, LHA, Lha.caps(), &StreamPolicy::default())
            .expect("resolve over a seekable source");
        let mut seekable = Lha.open(resolved, &OpenOpts::default()).unwrap();
        let err = seekable
            .by_index(0)
            .expect_err("LHA has no index to index into");
        assert!(
            matches!(err, Error::Unsupported(_)),
            "a seekable source with no index must answer Unsupported, not NotSeekable — \
             got {err:?}"
        );
        assert_eq!(err.exit_code(), 3, "{err}");
    }

    #[test]
    fn capabilities_and_metadata_match_the_format() {
        let c = Lha.caps();
        assert!(c.read && c.write, "LHA reads and writes as of Task 6");
        assert!(
            c.forward_parse,
            "delharc streams, and the write side did not change that; see this module's doc"
        );
        assert!(!c.needs_seek);
        assert!(c.stores_dirs, "a directory goes out as an -lhd- entry");
        assert!(
            !c.stores_symlinks,
            "LHA's `link|target` convention is not read back as a link here, so claiming it \
             would be the exact lie the field exists to prevent"
        );
        let m = meta();
        assert_eq!(m.id, LHA);
        assert_eq!(m.extensions, &["lzh", "lha"]);
    }

    /// `lha_meta()` registers two magic
    /// rules (`-lh`, `-lz`), and the fixture's own bytes match only the
    /// first. `assert_container_conforms_with`'s fixture property 3 already runs
    /// this via `lha_conforms` above (it would fail loudly if the harness's
    /// "any one rule" semantics required EVERY rule to match instead) — this
    /// test pins the premise directly, so a future change to either the
    /// magic table or the fixture cannot silently stop exercising it.
    #[test]
    fn exactly_one_of_the_two_registered_magic_rules_matches_the_fixture() {
        let hits = LHA_MAGIC
            .iter()
            .filter(|r| {
                SAMPLE_LZH.len() >= r.offset + r.bytes.len()
                    && &SAMPLE_LZH[r.offset..r.offset + r.bytes.len()] == r.bytes
            })
            .count();
        assert_eq!(
            hits, 1,
            "expected exactly one registered magic rule to match sample.lzh — if this \
             is now 0, the fixture no longer matches this format at all; if it is 2, the \
             two rules no longer probe genuinely different method families and this test \
             stops proving the harness's 'at least one, not necessarily all' semantics"
        );
    }

    /// Falsifies [`classify_lha_error`]'s placement: a corrupted header
    /// discovered by `next_file()` must come back as `Error::Corrupt`
    /// (exit 5), never `Error::Io` (exit 1) — the whole reason that
    /// function is called directly from `next_entry()` rather than letting
    /// the error travel through a bare `io::Error` `?`-conversion.
    #[test]
    fn a_corrupted_second_header_is_reported_as_corrupt_not_as_an_io_failure() {
        // Offset 49 is the first byte of entry 2's header (its declared
        // header-length byte) — see the module's fixture layout in
        // MANIFEST.md. Flipping it desyncs the header parse deterministically
        // rather than merely truncating the stream.
        let mut corrupted = SAMPLE_LZH.to_vec();
        let mid = corrupted.len() / 2;
        corrupted[mid] ^= 0xFF;

        let src: Box<dyn Source> = Box::new(ReaderSource::new(io::Cursor::new(corrupted)));
        let resolved = stuffr_core::resolve(src, LHA, Lha.caps(), &StreamPolicy::default())
            .expect("resolve over a seekable source");
        let mut ar = Lha.open(resolved, &OpenOpts::default()).expect("open");

        // Entry 1 is untouched and reads back fine.
        let first = ar
            .next_entry()
            .expect("entry 1 unaffected")
            .expect("entry 1 present");
        drop(first);

        let err = ar
            .next_entry()
            .expect_err("a corrupted second header must not read back silently");
        assert!(
            matches!(err, Error::Corrupt(_)),
            "expected Error::Corrupt, got {err:?}"
        );
        assert_eq!(
            err.exit_code(),
            5,
            "a corrupted header must exit 5 (corrupt archive), not 1 (stuffr failed)"
        );
    }

    /// Falsifies [`LhaEntryReader`]'s CRC-16 check directly. `-lh0-` is a
    /// byte-for-byte passthrough with no structural redundancy at all — a
    /// flipped payload byte decodes cleanly through `delharc`'s own
    /// `PassthroughDecoder`, no error, just different bytes — so the ONLY
    /// thing that can catch this corruption is the trailing CRC-16 check
    /// [`LhaEntryReader::read`] adds. This is deliberately a DIFFERENT byte
    /// than [`a_corrupted_second_header_is_reported_as_corrupt_not_as_an_io_failure`]
    /// flips: that one lands in entry 2's HEADER (caught by
    /// `classify_lha_error`, before any `Entry` is even produced); this one
    /// lands inside entry 1's PAYLOAD (offsets 43..49, "alpha\n"), which no
    /// header-parsing check ever sees — proven by neutering the CRC check to
    /// a bare passthrough (`self.inner.read(buf)`) and re-running: every
    /// other test in this module, including `lha_conforms`, still passed,
    /// and only this one went red. See the task report for the exact
    /// command and panic message.
    ///
    /// Classified the same way `ar.rs`'s own
    /// `a_cut_inside_an_entry_payload_is_reported_as_corrupt` classifies a
    /// payload-level error: `entry.reader().read_to_end` can only return a
    /// bare `io::Error` (that is all `std::io::Read` can express), so this
    /// applies `Error::from_decode_io` itself, exactly as `entries.rs`'s own
    /// `copy_charging` does for a real caller — the container_conformance
    /// harness's raw `?`-based `Error::Io` wrapping is a property of THAT
    /// harness's own helper, not of how a real caller sees this error.
    #[test]
    fn a_corrupted_payload_byte_fails_its_crc_check() {
        let mut corrupted = SAMPLE_LZH.to_vec();
        // Offset 45 is the 'p' of entry 1's "alpha\n" payload (offsets
        // 43..49) — see the module's fixture layout in MANIFEST.md.
        corrupted[45] ^= 0xFF;

        let src: Box<dyn Source> = Box::new(ReaderSource::new(io::Cursor::new(corrupted)));
        let resolved = stuffr_core::resolve(src, LHA, Lha.caps(), &StreamPolicy::default())
            .expect("resolve over a seekable source");
        let mut ar = Lha.open(resolved, &OpenOpts::default()).expect("open");
        let mut entry = ar
            .next_entry()
            .expect("entry 1 header parses fine")
            .expect("entry 1 present");

        let mut data = Vec::new();
        let io_err = entry
            .reader()
            .read_to_end(&mut data)
            .expect_err("a payload byte flipped under -lh0- must fail its trailing CRC-16 check");
        let err = Error::from_decode_io(io_err);
        assert_eq!(
            err.exit_code(),
            5,
            "a failed CRC-16 check must be Corrupt (exit 5), got {err:?}"
        );
    }

    /// `sample.lzh` only ever exercises `-lh0-`, so the `is_decoder_supported
    /// () == false` branch in `next_entry` has no coverage from the fixture
    /// harness at all. `-pm1-` (PMarc) is recognised by `CompressionMethod`
    /// but has no decoder in this build (delharc compiled with `std`, `lh1`,
    /// `lz` — no PMarc support at all), so it is unsupported for a reason
    /// unrelated to feature gating: this build can never read it. A
    /// capability gap, not damage — must be `Error::Unsupported` (exit 3),
    /// never `Error::Corrupt`.
    #[test]
    fn an_entry_with_an_unsupported_compression_method_is_reported_as_unsupported() {
        let bytes = build_single_entry_lha("weird.bin", b"-pm1-", b"whatever");
        let src: Box<dyn Source> = Box::new(ReaderSource::new(io::Cursor::new(bytes)));
        let resolved = stuffr_core::resolve(src, LHA, Lha.caps(), &StreamPolicy::default())
            .expect("resolve over a seekable source");
        let mut ar = Lha.open(resolved, &OpenOpts::default()).expect("open");
        let err = ar
            .next_entry()
            .expect_err("an unsupported method must be refused, not produce a fake entry");
        assert!(
            matches!(err, Error::Unsupported(_)),
            "expected Error::Unsupported, got {err:?}"
        );
        assert_eq!(err.exit_code(), 3);
    }

    /// The Phase 3a honesty oracle's finding, pinned. `check_error_is_
    /// classified` refuses any error that maps to exit 1 for hostile input,
    /// and a `-lh0-` archive whose payload simply stops short produced
    /// exactly that: delharc's `UnexpectedEof` travelled the `impl Read`
    /// channel, `Error::from_decode_io` left it as `Error::Io`, and stuffr
    /// announced that *stuffr* had failed on a file that was merely cut off.
    /// See [`fold_truncated_payload`] for why the fold lives at this
    /// module's boundary rather than in `from_decode_io`.
    #[test]
    fn a_truncated_entry_payload_is_reported_as_corrupt_not_as_an_io_failure() {
        let whole = build_single_entry_lha("sample/hello.txt", b"-lh0-", b"alpha\n");
        // Two payload bytes short, plus the end-of-archive marker: the shape
        // the fuzzer minimised to, a header that declares more than the file
        // carries.
        let cut = whole[..whole.len() - 3].to_vec();
        assert!(
            cut.len() > 2 + usize::from(whole[0]),
            "the cut must land inside the payload, not inside the header"
        );

        let src: Box<dyn Source> = Box::new(ReaderSource::new(io::Cursor::new(cut)));
        let resolved = stuffr_core::resolve(src, LHA, Lha.caps(), &StreamPolicy::default())
            .expect("resolve over a seekable source");
        let mut ar = Lha.open(resolved, &OpenOpts::default()).expect("open");
        let mut entry = ar
            .next_entry()
            .expect("the header is intact, so the entry itself must be produced")
            .expect("one entry");

        let mut data = Vec::new();
        let io_err = entry
            .reader()
            .read_to_end(&mut data)
            .expect_err("a payload shorter than its declared length must fail");
        let err = Error::from_decode_io(io_err);
        assert_eq!(
            err.exit_code(),
            5,
            "a truncated entry is a damaged archive (exit 5), never an internal failure \
             (exit 1) — got {err:?}"
        );
        assert!(
            matches!(err, Error::Corrupt(_)),
            "expected Error::Corrupt, got {err:?}"
        );
    }

    /// The other half of [`fold_truncated_payload`]'s claim, and the half
    /// that would make the fold a liability if it were wrong: a genuine
    /// source failure DURING a payload read keeps its own kind and is never
    /// relabelled as corruption. Container-conformance property 9 proves
    /// this for a source that fails on its very first read — before any
    /// header is parsed — which never reaches the entry reader at all; this
    /// pins the same claim at the one call site that folds.
    #[test]
    fn a_source_error_during_a_payload_read_is_not_relabelled_as_corruption() {
        struct FailsAfter {
            bytes: std::io::Cursor<Vec<u8>>,
            budget: usize,
        }
        impl Read for FailsAfter {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.budget == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "the disk said no",
                    ));
                }
                let take = buf.len().min(self.budget);
                let n = self.bytes.read(&mut buf[..take])?;
                self.budget -= n;
                Ok(n)
            }
        }
        impl Source for FailsAfter {
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

        let whole = build_single_entry_lha("sample/hello.txt", b"-lh0-", b"alpha\n");
        // Everything up to and including the header, nothing of the payload.
        let budget = 2 + usize::from(whole[0]);
        let src: Box<dyn Source> = Box::new(FailsAfter {
            bytes: io::Cursor::new(whole),
            budget,
        });
        let resolved = stuffr_core::resolve(src, LHA, Lha.caps(), &StreamPolicy::default())
            .expect("resolve over a forward-only source");
        let mut ar = Lha.open(resolved, &OpenOpts::default()).expect("open");
        let mut entry = ar
            .next_entry()
            .expect("the header is served in full, so the entry is produced")
            .expect("one entry");

        let mut data = Vec::new();
        let io_err = entry
            .reader()
            .read_to_end(&mut data)
            .expect_err("a source that refuses to serve the payload must fail the read");
        assert_eq!(
            io_err.kind(),
            io::ErrorKind::PermissionDenied,
            "a failing disk must not be reported as a damaged archive — got {io_err:?}"
        );
        let err = Error::from_decode_io(io_err);
        assert!(
            !matches!(err, Error::Corrupt(_)),
            "expected the source error to pass through, got {err:?}"
        );
    }

    /// `-lhd-` is delharc's own "this entry is a directory (or symlink)"
    /// marker (`CompressionMethod::Lhd`), and — like `-pm1-` above — has no
    /// decoder of its own, so `is_decoder_supported()` is ALSO false for it.
    /// The two must not be confused: a directory is not a capability gap,
    /// it simply has no payload to decode, and `next_entry` must produce a
    /// `EntryKind::Dir` entry rather than raising `Error::Unsupported`.
    #[test]
    fn a_directory_entry_is_produced_not_refused() {
        let bytes = build_single_entry_lha("adir", b"-lhd-", b"");
        let src: Box<dyn Source> = Box::new(ReaderSource::new(io::Cursor::new(bytes)));
        let resolved = stuffr_core::resolve(src, LHA, Lha.caps(), &StreamPolicy::default())
            .expect("resolve over a seekable source");
        let mut ar = Lha.open(resolved, &OpenOpts::default()).expect("open");
        let mut entry = ar
            .next_entry()
            .expect("a directory entry must not be refused")
            .expect("a directory entry must be produced");
        assert_eq!(entry.meta().kind, EntryKind::Dir);
        let mut data = Vec::new();
        entry
            .reader()
            .read_to_end(&mut data)
            .expect("a directory's reader must be empty, not erroring");
        assert!(data.is_empty());
    }

    // -----------------------------------------------------------------
    // The write side (Phase 3c, Task 6)
    // -----------------------------------------------------------------

    /// The written method is pinned at the BYTE level, not inferred from a
    /// successful round trip: `delharc` reads `-lh0-` through `-lh7-`, so
    /// every one of them would round-trip through this module's own reader
    /// and nothing in the harness would notice if the encoder silently
    /// started writing a different one. The header level is pinned for the
    /// same reason — level 0 and level 2 also round-trip here, and both are
    /// worse for the old tools this format exists to interoperate with (see
    /// [`write_level1_header`]).
    #[test]
    fn every_entry_is_written_as_a_level_1_lh5_header() {
        let bytes = build_lha(&[("a.txt", b"alpha"), ("b/c.bin", b"\x00\xff\x00")]);
        for start in entry_offsets(&bytes) {
            assert_eq!(
                &bytes[start + 2..start + 7],
                &METHOD_LH5,
                "the entry at offset {start} is not -lh5-"
            );
            // Within the counted run: method(5) + skip(4) + original(4) +
            // timestamp(4) + attrs(1), so the level byte is index 18, and
            // the counted run starts two bytes into the header.
            assert_eq!(
                bytes[start + 2 + 18],
                1,
                "the entry at offset {start} is not a level-1 header"
            );
        }
    }

    /// Walks the archive's headers and returns each entry's starting
    /// offset, asserting on the way that the walk lands EXACTLY on the end
    /// of the file.
    ///
    /// That last assertion is the structural half of
    /// [`an_archive_stops_at_its_last_entry_so_a_cut_tail_is_detectable`]:
    /// "the archive does not end with a trailing zero byte" cannot be
    /// checked by looking at the last byte, because a `-lh5-` payload's
    /// last byte is zero often enough to make such a test pass or fail by
    /// luck (the two-entry fixture's really does). Walking the entry chain
    /// answers the actual question — whether anything follows the final
    /// entry.
    fn entry_offsets(bytes: &[u8]) -> Vec<usize> {
        let mut offsets = Vec::new();
        let mut pos = 0usize;
        while pos < bytes.len() {
            let header_len = usize::from(bytes[pos]);
            assert_ne!(header_len, 0, "unexpected end-of-archive marker at {pos}");
            let skip = u32::from_le_bytes([
                bytes[pos + 7],
                bytes[pos + 8],
                bytes[pos + 9],
                bytes[pos + 10],
            ]) as usize;
            offsets.push(pos);
            pos += 2 + header_len + skip;
        }
        assert_eq!(
            pos,
            bytes.len(),
            "the entry chain must account for every byte — anything left over is a trailer"
        );
        offsets
    }

    /// A directory is the ONE entry that does not get `-lh5-`, and
    /// `caps().stores_dirs` is the claim this pins at the byte level.
    /// Container-conformance property 13 already proves the ROUND TRIP
    /// (`EntryKind::Dir` in, `EntryKind::Dir` out); this proves it is
    /// `-lhd-` specifically that carries it, which is what an old reader
    /// needs to see.
    #[test]
    fn a_directory_goes_out_as_an_lhd_entry_with_no_payload() {
        let buf = stuffr_core::testing::SharedBuf::new();
        let mut w = Lha
            .create(
                PlainSink::new(Box::new(buf.clone())),
                &CreateOpts::default(),
            )
            .expect("create");
        let mut meta_in = EntryMeta::file("some/dir");
        meta_in.kind = EntryKind::Dir;
        w.add(&meta_in, &mut io::empty()).expect("add a directory");
        w.finish().expect("finish").finish().expect("sink finish");
        let bytes = buf.contents();

        assert_eq!(&bytes[2..7], &METHOD_LHD);
        // The stored name gained a trailing separator, and this is the
        // PORTABLE proof of it: `lhasa_reads_what_we_write` below catches
        // the same thing through the reference tool, but only on a machine
        // that has one. See `LhaWrite::add` for what lhasa does without it.
        let name_len = usize::from(bytes[2 + 19]);
        let name = &bytes[2 + 20..2 + 20 + name_len];
        assert_eq!(
            name, b"some/dir/",
            "a directory's stored name must end with a path separator"
        );
        assert_eq!(
            u32::from_le_bytes([bytes[7], bytes[8], bytes[9], bytes[10]]),
            0,
            "a directory's skip size must be zero — anything else desynchronises \
             every reader from the next entry onward"
        );
        assert_eq!(
            bytes.len(),
            2 + usize::from(bytes[0]),
            "a directory entry is its header and nothing else"
        );
    }

    /// `finish` writes the end-of-archive marker for an EMPTY archive and
    /// for no other, and both halves of that matter.
    ///
    /// The empty half: `delharc` cannot construct a reader at all when its
    /// first header read comes back empty (`LhaDecodeReader::new` raises
    /// `"a header is missing"`), so a zero-byte file is not a readable
    /// empty LHA archive — the single `0` byte is the only spelling there
    /// is, and [`Lha::open`]'s one-byte peek is what turns it back into
    /// "no entries" rather than "corrupt".
    ///
    /// The non-empty half is the ruling [`LhaWrite::finish`] documents, and
    /// it is MEASURED rather than argued. With the marker appended to the
    /// two-entry archive the harness builds, the archive is 90 bytes and
    /// `read_all` on its first 89 — i.e. exactly the same archive with the
    /// marker removed — returns BOTH entries with no error at all: the tail
    /// byte's loss is undetectable by construction, because `parser.rs:190`
    /// treats a `0` byte and end-of-file as the same answer. Not writing it
    /// is what keeps container-conformance property 9's `len - 1` cut
    /// landing inside a payload, where the entry's own declared length
    /// catches it.
    #[test]
    fn an_archive_stops_at_its_last_entry_so_a_cut_tail_is_detectable() {
        assert_eq!(
            build_lha(&[]),
            vec![0],
            "an empty archive is the end-of-archive marker alone"
        );

        let bytes = build_lha(&[("a.txt", b"alpha"), ("b.txt", b"beta")]);
        // Structural, not "the last byte is not zero": see `entry_offsets`
        // for why that weaker spelling would pass or fail by luck.
        assert_eq!(entry_offsets(&bytes).len(), 2);

        // The archive as written: every entry read back, no error.
        assert_eq!(read_entries(&bytes).expect("intact").len(), 2);

        // One byte short: detected, because the cut now lands inside entry
        // 2's payload rather than removing an optional trailer.
        let err = read_entries(&bytes[..bytes.len() - 1])
            .expect_err("a cut tail must be detected, not read as a shorter archive");
        assert!(err.contains("ended before its declared length"), "{err}");

        // And with the marker written, the identical cut is invisible —
        // the measurement the ruling rests on.
        let mut with_marker = bytes.clone();
        with_marker.push(0);
        let got = read_entries(&with_marker[..with_marker.len() - 1])
            .expect("removing the marker leaves a perfectly valid archive");
        assert_eq!(
            got.len(),
            2,
            "with the marker written, `len - 1` is a clean archive and nothing can say otherwise"
        );
    }

    /// LHA's optional terminator must still be ACCEPTED on the read side —
    /// essentially every archive in the wild has one, `sample.lzh`
    /// included. [`build_single_entry_lha`] writes one deliberately, so this
    /// is a real test of the reader rather than a test of our own writer.
    #[test]
    fn a_reader_still_accepts_the_optional_end_of_archive_marker() {
        let bytes = build_single_entry_lha("sample/hello.txt", b"-lh0-", b"alpha\n");
        assert_eq!(bytes.last(), Some(&0), "the fixture builder writes one");
        assert_eq!(
            read_entries(&bytes).expect("a terminated archive reads fine"),
            vec![("sample/hello.txt".to_string(), b"alpha\n".to_vec())]
        );
    }

    /// Every difference between [`raw_pathname`] and `delharc`'s own
    /// accessor, pinned as a table against the live crate so the doc cannot
    /// drift from the behaviour.
    ///
    /// The `\` row is the one with teeth. `\` is the native separator of the
    /// DOS-era tools that wrote these archives, and an earlier version of
    /// this module did NOT split on it — a `dos\sub\file.txt` entry came
    /// back as one literal filename, flattening the directory structure of
    /// exactly the archives this format exists to read, and hiding
    /// `a\..\..\etc\passwd`'s traversal from `safe_join` inside a single
    /// component. Both halves are asserted: what this module reports, and
    /// what `delharc` reports for the same bytes, so a crate release that
    /// changed either shows up here as a premise that no longer holds
    /// rather than as a silently unnecessary function.
    #[test]
    fn a_stored_name_maps_to_a_reported_name_exactly_as_documented() {
        // (stored bytes, what this module reports, what delharc reports)
        let cases: &[(&[u8], &str, &str)] = &[
            (b"../../etc/passwd", "../../etc/passwd", "etc/passwd"),
            (b"/abs/path", "/abs/path", "abs/path"),
            (b"a/../../b", "a/../../b", "a/b"),
            (
                b"dos\\sub\\file.txt",
                "dos/sub/file.txt",
                "dos/sub/file.txt",
            ),
            (
                b"a\\..\\..\\etc\\passwd",
                "a/../../etc/passwd",
                "a/etc/passwd",
            ),
            (b"ff\xffsep.txt", "ff/sep.txt", "ff/sep.txt"),
            (b"na\xc3me.txt", "na%C3me.txt", "na%c3me.txt"),
            (b"lit%1f.txt", "lit%251f.txt", "lit%1f.txt"),
        ];
        for (stored, want, delharc_says) in cases {
            assert_eq!(
                &reported_name(stored),
                want,
                "stored {:?} must be reported as {want:?}",
                String::from_utf8_lossy(stored)
            );
            // The `dos\sub` row is the one where the two columns AGREE —
            // deliberately, because that is the behaviour this module had to
            // restore after a review measured it flattened.
            let bytes = build_named_entry_lha(stored, b"-lh0-", b"x");
            let reader = LhaDecodeReader::new(io::Cursor::new(bytes)).expect("parse the header");
            assert_eq!(
                &reader.header().parse_pathname_to_str(),
                delharc_says,
                "delharc 0.6.2's own accessor no longer reports {:?} as {delharc_says:?}",
                String::from_utf8_lossy(stored)
            );
        }

        // The escaping is injective: two different stored names can never
        // report as one.
        assert_ne!(
            reported_name(b"lit%1f.txt"),
            reported_name(b"lit\x1f.txt"),
            "a literal `%1f` and an escaped 0x1F must not collapse onto one name"
        );
    }

    /// Reads one entry's reported name back out of a single-entry archive,
    /// through the real `Lha::open` path rather than by calling
    /// [`raw_pathname`] directly — the name a CALLER sees is the claim.
    fn reported_name(stored: &[u8]) -> String {
        let bytes = build_named_entry_lha(stored, b"-lh0-", b"x");
        let src: Box<dyn Source> = Box::new(ReaderSource::new(io::Cursor::new(bytes)));
        let resolved =
            stuffr_core::resolve(src, LHA, Lha.caps(), &StreamPolicy::default()).expect("resolve");
        let mut ar = Lha.open(resolved, &OpenOpts::default()).expect("open");
        let entry = ar.next_entry().expect("next").expect("one entry");
        entry.meta().name.clone()
    }

    /// A name longer than a level-1 header's single length byte can
    /// describe is REFUSED, never truncated. Truncating would let two
    /// entries whose names differ only past byte 230 collapse onto one
    /// name, and extraction would then overwrite one file with the other.
    #[test]
    fn a_name_too_long_for_a_level_1_header_is_refused() {
        let buf = stuffr_core::testing::SharedBuf::new();
        let mut w = Lha
            .create(
                PlainSink::new(Box::new(buf.clone())),
                &CreateOpts::default(),
            )
            .expect("create");

        // One byte under the limit still works, so the refusal is pinned to
        // the boundary rather than to "long names fail".
        let ok = "x".repeat(MAX_LEVEL1_NAME);
        w.add(
            &EntryMeta::file(&ok),
            &mut io::Cursor::new(b"hi".as_slice()),
        )
        .expect("a name of exactly the maximum length must be accepted");

        let too_long = "x".repeat(MAX_LEVEL1_NAME + 1);
        let err = w
            .add(
                &EntryMeta::file(&too_long),
                &mut io::Cursor::new(b"hi".as_slice()),
            )
            .expect_err("one byte over must be refused");
        assert!(matches!(err, Error::Unsupported(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 3, "{err}");
    }

    /// `stores_symlinks` is false, so `entries.rs` warns and skips before
    /// reaching `add`. A hand-built plan can still get here, and it must
    /// meet a named refusal rather than an archive whose link has silently
    /// become a directory with a strange name.
    #[test]
    fn a_symlink_is_refused_rather_than_written_as_something_else() {
        let buf = stuffr_core::testing::SharedBuf::new();
        let mut w = Lha
            .create(
                PlainSink::new(Box::new(buf.clone())),
                &CreateOpts::default(),
            )
            .expect("create");
        let mut meta_in = EntryMeta::file("link");
        meta_in.kind = EntryKind::Symlink {
            target: "a.txt".into(),
        };
        let err = w
            .add(&meta_in, &mut io::empty())
            .expect_err("LHA must refuse a symlink rather than misrepresent it");
        assert!(matches!(err, Error::Unsupported(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 3, "{err}");
    }

    /// mtime survives the round trip to MS-DOS's own resolution. The
    /// conformance harness's property 11 checks only the fields a container
    /// REPORTS, and this one is reported, so a silent loss here (writing a
    /// literal zero and reading `None` back) would pass every property in
    /// the harness.
    ///
    /// The expected value is rounded DOWN to an even second deliberately —
    /// see [`dos_timestamp`] — and the assertion says so rather than
    /// choosing an even second and hiding the rounding.
    #[test]
    fn an_mtime_round_trips_to_ms_dos_two_second_resolution() {
        // 2001-02-03 04:05:07 UTC, an ODD second.
        let when = UNIX_EPOCH + Duration::from_secs(981_173_107);
        let buf = stuffr_core::testing::SharedBuf::new();
        let mut w = Lha
            .create(
                PlainSink::new(Box::new(buf.clone())),
                &CreateOpts::default(),
            )
            .expect("create");
        let mut meta_in = EntryMeta::file("dated.txt");
        meta_in.mtime = Some(when);
        w.add(&meta_in, &mut io::Cursor::new(b"hi".as_slice()))
            .expect("add");
        w.finish().expect("finish").finish().expect("sink finish");

        let bytes = buf.contents();
        let src: Box<dyn Source> = Box::new(ReaderSource::new(io::Cursor::new(bytes)));
        let resolved =
            stuffr_core::resolve(src, LHA, Lha.caps(), &StreamPolicy::default()).expect("resolve");
        let mut ar = Lha.open(resolved, &OpenOpts::default()).expect("open");
        let entry = ar.next_entry().expect("next").expect("one entry");
        assert_eq!(
            entry.meta().mtime,
            Some(UNIX_EPOCH + Duration::from_secs(981_173_106)),
            "MS-DOS stores seconds in units of two, so an odd second rounds DOWN"
        );
    }

    /// Outside MS-DOS's own 1980..=2107 year range there is nothing to
    /// store, so the field goes out as the format's own "no timestamp"
    /// zero and the reader reports `None`. A wrapped or clamped year would
    /// be worse than an absent one: it reads back as a confident lie.
    #[test]
    fn a_timestamp_outside_the_ms_dos_range_is_absent_rather_than_wrong() {
        // 1970-01-01, a decade before MS-DOS's epoch.
        assert_eq!(dos_timestamp(UNIX_EPOCH), None);
        // 2108-01-01 00:00:00 UTC, one year past the last year the 7-bit
        // field can express.
        assert_eq!(
            dos_timestamp(UNIX_EPOCH + Duration::from_secs(4_355_596_800)),
            None
        );
        // And one that IS in range, so the guard is pinned to the boundary
        // rather than to "timestamps do not work".
        assert!(dos_timestamp(UNIX_EPOCH + Duration::from_secs(981_173_107)).is_some());
    }

    /// [`lha_mtime`] is the inverse of [`dos_timestamp`], pinned as such
    /// rather than each being read against prose — the reader never calls
    /// the first (it takes `delharc`'s `parse_last_modified` instead), so
    /// without this the salvage scanner's only check on the field's own
    /// bit layout would be its own author.
    ///
    /// Swept across the whole expressible range rather than at one point:
    /// the DATE is the HIGH half and the TIME the low one, and the twin
    /// layout in `zoo.rs` packs them the other way round — reading one into
    /// the other is a silent decades-wide error, never a parse failure, so
    /// a single sample could agree by luck on an hour field alone.
    #[test]
    fn a_packed_dos_timestamp_round_trips_through_its_own_inverse() {
        // 1980-01-01 00:00:00 (the first instant the format can express),
        // then one sample per year to 2107, each at a different month, day
        // and time so no field is held constant across the sweep.
        let mut checked = 0;
        for year in 0..=127u32 {
            let month = (year % 12) + 1;
            let day = (year % 28) + 1;
            let hour = year % 24;
            let minute = (year * 7) % 60;
            let second = (year * 2) % 60;
            let packed = (year << 25)
                | (month << 21)
                | (day << 16)
                | (hour << 11)
                | (minute << 5)
                | (second / 2);
            let when = lha_mtime(packed).unwrap_or_else(|| {
                panic!("{}-{month:02}-{day:02} must decode", 1980 + year);
            });
            assert_eq!(
                dos_timestamp(when),
                Some(packed),
                "packing {when:?} back must reproduce the exact word it came from"
            );
            checked += 1;
        }
        assert_eq!(checked, 128, "the whole 7-bit year field was swept");
        // The "no timestamp" word every minimal archive carries: month 0 and
        // day 0 are not a date, so there is nothing to report.
        assert_eq!(lha_mtime(0), None);
    }

    /// An entry payload that expands under `-lh5-` is still written as
    /// `-lh5-`, and still round-trips. Worth pinning because it is the one
    /// case a "store when compression does not help" fallback would
    /// silently change the written method for — this build writes ONE
    /// method and `caps()`'s doc says so.
    #[test]
    fn an_incompressible_payload_still_round_trips_under_lh5() {
        let payload = stuffr_core::conformance::incompressible(64 * 1024);
        let bytes = build_lha(&[("random.bin", &payload)]);
        assert_eq!(&bytes[2..7], &METHOD_LH5);
        assert_eq!(
            read_entries(&bytes).expect("round trip"),
            vec![("random.bin".to_string(), payload)]
        );
    }

    /// Reads every entry back, returning names and payloads, or the first
    /// error's message. The write-side tests' own `read_all` — deliberately
    /// separate from the conformance harness's private one, and returning a
    /// `String` rather than a typed error because every caller here only
    /// wants to say which failure it saw.
    fn read_entries(bytes: &[u8]) -> std::result::Result<Vec<(String, Vec<u8>)>, String> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(io::Cursor::new(bytes.to_vec())));
        let resolved = stuffr_core::resolve(src, LHA, Lha.caps(), &StreamPolicy::default())
            .map_err(|e| format!("resolve: {e}"))?;
        let mut ar = Lha
            .open(resolved, &OpenOpts::default())
            .map_err(|e| format!("open: {e}"))?;
        let mut out = Vec::new();
        loop {
            match ar.next_entry() {
                Ok(Some(mut entry)) => {
                    let name = entry.meta().name.clone();
                    let mut data = Vec::new();
                    entry
                        .reader()
                        .read_to_end(&mut data)
                        .map_err(|e| format!("read {name}: {e}"))?;
                    out.push((name, data));
                }
                Ok(None) => return Ok(out),
                Err(e) => return Err(format!("next_entry: {e}")),
            }
        }
    }

    /// The reference tool, resolved the way `ar.rs`, `cpio.rs`, `zip.rs`
    /// and `lzip.rs` all resolve theirs: a hard failure when it is absent,
    /// never a silent skip. CI installs it — `.github/workflows/ci.yml`'s
    /// three `apt-get install` lines carry `lhasa`.
    ///
    /// # TWO names for one program, and both have to be tried
    ///
    /// Homebrew's `lhasa` formula installs the binary as **`lha`**
    /// (`/opt/homebrew/bin/lha -> ../Cellar/lhasa/0.6.0/bin/lha`, plus
    /// `man1/lha.1`), while Debian's and Ubuntu's `lhasa` package installs
    /// exactly one binary and calls it **`lhasa`**
    /// (`packages.ubuntu.com/noble/amd64/lhasa/filelist` and the Debian
    /// bookworm equivalent both list `/usr/bin/lhasa` and `man1/lhasa.1`,
    /// and no `lha`). Same program, same verbs, different spelling — so a
    /// `require_bin("lha")` passes on a developer's Mac and turns every CI
    /// job red, which is the exact failure mode Phase 3b's `require_bin`
    /// produced on a released tag by not following the tool to the
    /// workflow.
    ///
    /// Both are tried, `lha` first because that is this project's own
    /// development platform. Nothing else on either platform is called
    /// either name (`jlha-utils` would provide a different `lha`, and is
    /// not installed by this project's CI), so the fallback cannot select
    /// a different implementation the way a bare `uncompress` can — see
    /// `compress_z.rs`'s `require_gnu_uncompress` for the case where it
    /// could and a fixed path was needed instead.
    fn require_lhasa() -> std::path::PathBuf {
        let path = std::env::var_os("PATH").expect("PATH must be set");
        let dirs: Vec<_> = std::env::split_paths(&path).collect();
        for bin in ["lha", "lhasa"] {
            if let Some(hit) = dirs.iter().find_map(|dir| {
                let candidate = dir.join(bin);
                candidate.is_file().then_some(candidate)
            }) {
                return hit;
            }
        }
        panic!(
            "no reference lhasa tool found on PATH under either of its two names, `lha` \
             (Homebrew) or `lhasa` (Debian/Ubuntu) — this test proved nothing, which is worth \
             knowing rather than passing silently. `brew install lhasa` / `apt-get install \
             lhasa`"
        )
    }

    /// lhasa's own banner, which carries its VERSION, folded into every
    /// assertion message below.
    ///
    /// Not decoration. The `-lhd-` trailing-separator guard was measured
    /// against lhasa **0.6.0**; Ubuntu noble ships **0.4.0**. If that older
    /// build happens to TOLERATE an unterminated `-lhd-` name, the guard
    /// goes green on CI with the defect reinstated and only a machine with
    /// 0.6.0 ever notices — a failure that would otherwise be read as
    /// "works on CI, broken locally". Printing the version at the moment an
    /// assertion fires is what makes that diagnosable in one look instead of
    /// a bisect.
    ///
    /// Run with no arguments, which is how lhasa prints its usage banner
    /// (`Lhasa v0.6.0 command line LHA tool ...`); the exit status is
    /// ignored because a usage banner is a failure by convention.
    fn lhasa_banner(bin: &std::path::Path) -> String {
        let out = std::process::Command::new(bin)
            .output()
            .expect("run lhasa with no arguments for its banner");
        let text = if out.stdout.is_empty() {
            String::from_utf8_lossy(&out.stderr).into_owned()
        } else {
            String::from_utf8_lossy(&out.stdout).into_owned()
        };
        text.lines().next().unwrap_or("<no banner>").to_string()
    }

    /// LHA's external witness, and the ONLY evidence in this module that
    /// what the `-lh5-` encoder writes is genuinely LHA rather than
    /// something `delharc` and `oxiarc-lzhuf` merely agree about.
    ///
    /// That distinction is the whole point: every other write-side test
    /// here reads back through `delharc`, so a shared misunderstanding of
    /// the `-lh5-` bitstream between the encoder crate and the decoder
    /// crate would pass all of them. `lhasa` is a third implementation (C,
    /// by Simon Howard, sharing no code with either) and it DECOMPRESSES
    /// ONLY — which is exactly what is needed here and why no test in
    /// Phase 3b could exist in the other direction.
    ///
    /// Both of lhasa's verbs are used, because they check different things:
    /// `lha t` verifies each entry's CRC-16 (so the header's CRC field, the
    /// one `delharc` also checks, is confirmed by an independent
    /// computation), and `lha x` writes the files out so their BYTES can be
    /// compared — a CRC agreeing proves the check value matches, not that
    /// the plaintext is right.
    #[test]
    fn lhasa_reads_what_we_write() {
        let lha_bin = require_lhasa();
        let banner = lhasa_banner(&lha_bin);

        // Deliberately three shapes: text that compresses, an
        // incompressible payload big enough to cross several `-lh5-`
        // blocks, and an empty file — the three places a block-structured
        // Huffman encoder goes wrong.
        let prose = b"the quick brown fox jumps over the lazy dog\n".repeat(400);
        let noise = stuffr_core::conformance::incompressible(70_000);
        let entries: Vec<(&str, &[u8])> = vec![
            ("prose.txt", &prose),
            ("noise.bin", &noise),
            ("empty.txt", b""),
        ];

        // A DIRECTORY entry leads, and that is the part of this test with
        // real teeth: an `-lhd-` entry whose stored name does not end with a
        // path separator makes lhasa end the archive there, silently, at
        // exit 0 — the three files behind it vanish and nothing complains.
        // See `LhaWrite::add`'s own note for the measurements. `delharc`
        // reads either spelling, so this is the only thing in the suite that
        // can catch a regression in it, which is why the entry count is
        // asserted below rather than only the files' bytes.
        let buf = stuffr_core::testing::SharedBuf::new();
        let mut w = Lha
            .create(
                PlainSink::new(Box::new(buf.clone())),
                &CreateOpts::default(),
            )
            .expect("create");
        let mut dir_meta = EntryMeta::file("adir");
        dir_meta.kind = EntryKind::Dir;
        w.add(&dir_meta, &mut io::empty()).expect("add a directory");
        for (name, data) in &entries {
            w.add(&EntryMeta::file(*name), &mut io::Cursor::new(*data))
                .expect("add");
        }
        w.finish().expect("finish").finish().expect("sink finish");
        let bytes = buf.contents();

        let dir = std::env::temp_dir().join(format!(
            "stuffr-lha-interop-{}-{:p}",
            std::process::id(),
            &bytes
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let archive = dir.join("written.lzh");
        std::fs::write(&archive, &bytes).expect("write archive");

        let test = std::process::Command::new(&lha_bin)
            .arg("t")
            .arg(&archive)
            .output()
            .expect("run lha t");
        assert!(
            test.status.success(),
            "{banner} refused an archive this build wrote: status {:?}\nstdout: {}\nstderr: {}",
            test.status.code(),
            String::from_utf8_lossy(&test.stdout),
            String::from_utf8_lossy(&test.stderr)
        );

        // The count, not just the files: lhasa's own view of how many
        // entries the archive holds is what a dropped `-lhd-` entry shows
        // up in, and `lha v`'s trailing summary is where it says so.
        let listing = std::process::Command::new(&lha_bin)
            .arg("v")
            .arg(&archive)
            .output()
            .expect("run lha v");
        let text = String::from_utf8_lossy(&listing.stdout);
        // Counted from the listing's own rows rather than matched against
        // its summary line: lhasa pads that line into columns, and a
        // literal carrying a run of spaces is what
        // `no_message_literal_in_the_workspace_carries_a_run_of_collapsed_indentation`
        // refuses. Every listed entry's row names its method.
        let rows = text.lines().filter(|l| l.contains("-lh")).count();
        assert_eq!(
            rows, 4,
            "{banner} must see all four entries — listing no rows at all is the silent \
             end-of-archive an unterminated -lhd- name causes: {text}"
        );

        let out = dir.join("out");
        std::fs::create_dir_all(&out).expect("out dir");
        let extract = std::process::Command::new(&lha_bin)
            .arg(format!("xfw={}", out.display()))
            .arg(&archive)
            .output()
            .expect("run lha x");
        assert!(
            extract.status.success(),
            "{banner} failed to extract: {}",
            String::from_utf8_lossy(&extract.stderr)
        );
        for (name, want) in &entries {
            let got = std::fs::read(out.join(name))
                .unwrap_or_else(|e| panic!("{banner} did not extract {name}: {e}"));
            assert_eq!(
                &got[..],
                *want,
                "{banner} extracted {name} with {} bytes, expected {}",
                got.len(),
                want.len()
            );
        }
        assert!(
            out.join("adir").is_dir(),
            "{banner} must extract the -lhd- entry as a directory"
        );
    }
}
