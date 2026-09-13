//! Unix `ar`, via the `ar` crate — the simplest container in this tree by
//! format, though not, it turns out, by implementation.
//!
//! # Self-referential after all, for a reason specific to this crate
//!
//! The batching task that wrote this module alongside `cpio.rs` expected
//! neither to need `unsafe`, on the reasoning that `ar::Archive<R>` hands out
//! each `Entry<'a, R>` as a borrow of its own `&mut R` rather than tar's
//! self-borrowing `Entries<'a, R>` iterator (see `tar.rs`'s module doc). That
//! held for `cpio.rs`, whose `Reader<R>` owns `R` outright and hands it back
//! through an explicit `finish()` this project calls on its own schedule.
//! It does not hold for `ar`: measured directly against `ar 0.9.0` (build a
//! 4 MiB entry, take the `Entry` `next_entry()` returns without reading a
//! byte from it, drop it, count bytes pulled from the source before and
//! after), dropping an `Entry` with unread payload EAGERLY drains all of it
//! via `io::copy` into a sink the instant the drop runs — before, only 68
//! bytes (the two headers) had been consumed; after, all 4,194,372. There is
//! no lazy, deferred-to-the-next-call alternative exposed anywhere in the
//! crate's public API — no `finish()`, no way to reach the archive's own
//! reader except through the `Entry` the crate hands out.
//!
//! Conformance harness property 8 is what caught this, not a hypothetical: a
//! single 4 MiB entry, read via exactly one `next_entry()` call whose
//! returned value is then dropped as an unbound temporary — which is exactly
//! what `entries::list`'s own iteration does too
//! (`while let Some(entry) = ar.next_entry()? { out.push(entry.meta().clone()); }`,
//! dropping `entry` at the end of every loop body without ever touching its
//! reader) — consumed the whole archive before the property's byte counter
//! was ever read. [`ArRead::current`] is what closes that gap: it stores the
//! in-progress `Entry` in `self` and hands the caller a payload that BORROWS
//! it, so the caller dropping THEIR wrapper only ends that borrow — the
//! actual drain happens where `ArRead::next_entry` chooses to run it, at the
//! start of the NEXT call, exactly mirroring `cpio.rs`'s own deferred-finish
//! design despite the two crates reaching it by different roads. Storing a
//! borrow of `*archive` alongside `archive` itself in one struct is what
//! makes `ArRead` self-referential, which is what makes `Box::into_raw` /
//! `Box::from_raw` — the same tool `tar.rs` reaches for, and for the same
//! underlying reason (see that module's doc) — necessary here too. The two
//! modules' `unsafe` blocks solve different problems that happen to need the
//! identical shape of fix.
//!
//! # `ar` has no trailer at all
//!
//! A tar or a cpio archive ends with an explicit marker a reader can look
//! for (two zero blocks; a `TRAILER!!!` entry). `ar` has neither: the format
//! is just `!<arch>\n` followed by however many header-plus-payload records
//! fit, and a reader knows it has reached the end only because the
//! underlying stream has. `Archive::next_entry` reflects this directly: it
//! returns `Ok(None)` the moment a header read comes back completely empty,
//! and an error for anything short of that — there is no second,
//! indistinguishable "clean ending" shape for this module to disambiguate
//! the way `tar.rs` has to. One consequence is worth stating because it is
//! easy to get backwards: a genuinely EMPTY (zero-byte) stream is not a
//! valid empty `ar` archive, it is a truncated one — `read_global_header_if_
//! necessary`'s `read_exact` on the 8-byte magic raises `UnexpectedEof`
//! before `next_entry` ever gets the chance to say "no entries". A valid
//! empty archive is the 8-byte magic and nothing else, which is exactly what
//! [`ArWrite::finish`] writes when [`ArchiveWrite::add`] was never called —
//! `ar::Builder` only writes that magic lazily, on the first `append`, so a
//! zero-entry archive built purely through it would be zero bytes, not
//! eight. Measured against the system `ar` on this machine (`ar t` accepts a
//! hand-written 8-byte `!<arch>\n` file as zero members, and refuses to
//! create an empty archive of its own at all — `ar: no archive members
//! specified` — so there is no reference tool that WRITES this file to
//! compare against, only one to confirm this module's own output reads back
//! clean).
//!
//! # `add` cannot stream an unknown-length input
//!
//! `ar`'s header carries the payload's size and precedes the payload itself,
//! so the size has to be known before a single payload byte is written — the
//! same constraint `cpio.rs` has, and the one place this module (like that
//! one) cannot stream: an entry is always buffered into memory first, then
//! written with its measured length, whatever `EntryMeta::size` claimed.
//! Unlike tar's `add` (which streams a DECLARED size and only checks it
//! against what was actually copied after the fact), there is no "declared
//! size disagrees with the data" failure mode here to guard against: the
//! header this module writes is always built from the bytes it actually
//! buffered, never from the caller's claim.
//!
//! # Hostile names need no defence here
//!
//! `ar::Header::new`/`Header::write` perform no validation of the identifier
//! at all — no rejection of `..`, no rejection of a leading `/` — unlike
//! `tar::Header::set_path`, which refuses both (see `tar.rs`'s `add` for how
//! that module works around it). Property 12's hostile names are stored and
//! read back verbatim by construction, with nothing for this module to do.
//!
//! # Task 5d: two of three header-declared-length OOMs, and why the third needs no fix here
//!
//! `ar` 0.9.0 allocates three buffers straight from header-declared lengths,
//! before validating them and before a byte of what they will hold is read —
//! the same shape of bug Task 5c closed for `cpio.rs`'s `c_namesize`:
//!
//! - `lib.rs:261`, `*name_table = vec![0; size as usize];` — the GNU
//!   long-name table, sized from the SAME 10-digit decimal `file size`
//!   field (`buffer[48..58]`) every entry header carries.
//! - `lib.rs:307`, `let mut id_buffer = vec![0; padded_length as usize];` —
//!   the BSD extended (`#1/N`) identifier, sized from a 13-digit decimal
//!   field (`buffer[3..16]`) unique to that header shape.
//! - `lib.rs:746`, `let mut str_table_data = vec![0u8; str_table_len as
//!   usize];` — the GNU symbol table's own string table, sized from a
//!   length read out of the symbol table's PAYLOAD (not a header field),
//!   inside `Archive::parse_symbol_table_if_necessary`.
//!
//! The third is real in the crate but **dead code from this module**: it is
//! reachable only through `Archive::symbols()` (and `count_entries`/
//! `jump_to_entry`, which call `scan_if_necessary` but never parse the
//! symbol table itself). [`ArRead::by_index`] above never calls into any of
//! them — it answers `Unsupported`/`NotSeekable` unconditionally, without
//! touching the archive's seek-based API at all, and nothing else in this
//! workspace calls `.symbols(`, `count_entries` or `jump_to_entry` either.
//! So it is left unfixed, deliberately: bounding it would mean peeking into
//! a payload this container never asks the crate to parse, for a code path
//! nothing here can reach. **If `by_index` or a `symbols` surface is ever
//! added for `ar`, this is the site that must be bounded FIRST, before that
//! lands.**
//!
//! The other two are both real, and both on this container's ORDINARY read
//! path, not just a hostile one: the GNU name table is what `ar`'s own
//! default variant on Linux writes (see the cross-compiled `.rlib` files
//! this fix was measured against, below), and the BSD extended form is what
//! THIS container's own writer produces for any `/`-bearing or >16-byte
//! identifier (see `write_safe_identifier` above).
//!
//! ## Why the fix cannot be a single peek before each entry, unlike `cpio.rs`
//!
//! `cpio.rs`'s `peek_header_prefix` peeks once per entry because cpio's
//! format is 1:1: every header the crate reads corresponds to exactly one
//! entry this container hands back (or the trailer). `ar::Archive::next_entry`
//! is not 1:1: a GNU name table or symbol table header is consumed and
//! `continue`d past internally, inside the SAME call, with no yield point
//! for this module to peek from in between — and, `ArRead::archive` being a
//! raw pointer leaked at `open` time (see this module's own doc above),
//! there is no way to reach back into a live `ar::Archive`'s private reader
//! to peek mid-archive even once that call returns.
//!
//! So the guard lives BELOW the crate instead of above it: [`ArGuardedReader`]
//! wraps the real source and is what `ar::Archive` reads from for the whole
//! archive's lifetime, mirroring just enough of `ar::Header::read`'s own
//! state machine — global header, optional one-byte pad, 60-byte header,
//! payload — to recognise a header BOUNDARY and hold the full 60 bytes back
//! (never releasing a partial header to the crate) until [`scan_ar_header`]
//! has checked the one or two length fields it carries. A refusal happens
//! before any of those 60 bytes ever reach the crate, which is what makes it
//! run before the crate's own `vec![0; ...]` rather than merely before this
//! container returns an `Entry` for it.
//!
//! ## Sizing the two ceilings
//!
//! Measured across every `.a`/`.rlib` this machine has (478 archives:
//! everything under `/usr/lib`, `/usr/local/lib` and `~/.rustup`, including
//! the 40-58 MB cross-compiled `libcore`/`libstd` `.rlib`s for
//! `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`, which are GNU-
//! variant regardless of build host):
//!
//! - The largest real GNU name table was **27,616 bytes**
//!   (`libcompiler_builtins-*.rlib`, hundreds of small translation units).
//! - The largest real BSD extended identifier was **100 bytes** — a path,
//!   the same shape `MAX_CPIO_NAME_LEN`/`MAX_SYMLINK_TARGET_LEN` bound.
//!
//! [`MAX_BSD_IDENTIFIER_LEN`] follows Task 5c's own figure and reasoning
//! unchanged: a single identifier is exactly as path-shaped as a symlink
//! target or a cpio entry name, and 65,536 bytes is generous over the
//! largest real one measured (100) by 655x. [`MAX_GNU_NAME_TABLE_LEN`] does
//! NOT reuse that figure — a name table is a TABLE, not a path, and a real
//! one can legitimately hold thousands of names. 16 MiB is ~608x the largest
//! real one measured (a library with 100,000 members averaging 40-byte names
//! would need roughly 4 MiB), while remaining ~570x smaller than the ~9.3
//! GiB a 10-digit declared length can otherwise buy.

use std::io::{self, Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use stuffr_core::{
    ArchiveRead, ArchiveWrite, Container, ContainerCaps, CreateOpts, Entry, EntryKind, EntryMeta,
    Error, FidelityReport, FormatId, FormatMeta, MagicRule, OpenOpts, Resolved, Result, Sink,
    Source,
};

use crate::normalize::{AR_MALFORMED_AS_INVALID_DATA_EOF, NormalizeDecodeErrors};

pub const AR: FormatId = FormatId::new("ar");

/// `ar`'s only magic: the literal 8-byte global header, at offset 0. Every
/// variant (common, BSD, GNU) starts with it.
static AR_MAGIC: &[MagicRule] = &[MagicRule {
    offset: 0,
    bytes: GLOBAL_HEADER,
    format: AR,
}];

/// The archive's global header — `ar`'s only magic, and the whole of what a
/// zero-entry archive contains. See the module doc for why writing this
/// unconditionally (rather than leaving it to `ar::Builder`'s own lazy
/// write on first `append`) matters for an empty archive specifically.
const GLOBAL_HEADER: &[u8; 8] = b"!<arch>\n";

/// The mode `add` writes when the caller does not say — `rw-r--r--` with the
/// regular-file bit set, matching what a real `ar` (`ar rcS`, measured on
/// this machine) writes for a plain file, and what `apply_metadata`'s own
/// `0o7777` mask already expects to see and strip (see that function's doc
/// in `crates/stuffr/src/entries.rs`).
const DEFAULT_MODE: u32 = 0o100644;

pub fn meta() -> FormatMeta {
    FormatMeta::container(AR, &["a", "ar"], AR_MAGIC)
}

pub struct Ar;

impl Container for Ar {
    fn id(&self) -> FormatId {
        AR
    }

    /// No trailing index, no per-entry codec, no solid blocks — see the
    /// module doc: this format has no structure at all beyond one header per
    /// entry, so a forward read loses nothing a seekable one would have
    /// offered.
    ///
    /// `stores_dirs` and `stores_symlinks` stay false, and that is the whole
    /// of what `ar` cannot do that the other three containers can: it has no
    /// kind field at all, so every entry is a regular file. A caller packing
    /// a walked directory tree is expected to consult these and warn rather
    /// than hand `add` a directory, which would land as a zero-byte *file*
    /// under the directory's name and make every entry beneath it
    /// unextractable.
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
        // Wrapped in `ArGuardedReader` before the crate ever sees it — see
        // the module doc's Task 5d section for why the guard has to be
        // installed here, below the crate, rather than as a peek this
        // module performs itself before delegating.
        let guarded = ArGuardedReader::new(source);
        // Leaked deliberately and reclaimed in `ArRead::drop` — see that
        // struct's own doc for why, and `tar.rs`'s module doc for the fuller
        // argument this mirrors.
        let archive: *mut ArArchive = Box::into_raw(Box::new(ar::Archive::new(guarded)));
        Ok(Box::new(ArRead {
            archive,
            current: None,
            report,
            seekable,
        }))
    }

    fn create(&self, dst: Box<dyn Sink>, _o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
        Ok(Box::new(ArWrite {
            inner: Some(ar::Builder::new(dst)),
            wrote_any: false,
        }))
    }
}

/// Folds an error raised by the `ar` crate's own reader into this project's
/// error vocabulary. See [`AR_MALFORMED_AS_INVALID_DATA_EOF`] for what was
/// measured.
fn classify_ar_error(e: io::Error) -> Error {
    if AR_MALFORMED_AS_INVALID_DATA_EOF.contains(&e.kind()) {
        return Error::Corrupt(e.to_string());
    }
    Error::from_decode_io(e)
}

// --- Task 5d: guarding two header-declared-length allocations -------------
//
// See the module doc's "Two of three header-declared-length OOMs" section
// for the full picture. What follows is [`ArGuardedReader`] (the wrapper
// `ar::Archive` reads from for the whole archive's lifetime) and
// [`scan_ar_header`] (the stripped-down mirror of `ar::Header::read`'s own
// state machine it uses to find and validate every header).

/// Fixed width of one `ar` entry header — six ASCII fields plus the 16-byte
/// identifier, `` ` `` and `\n`. Mirrors the vendored crate's own private
/// `ENTRY_HEADER_LEN` (`ar-0.9.0/src/lib.rs:103`).
const AR_ENTRY_HEADER_LEN: usize = 60;

/// Ceiling on a BSD extended (`#1/N`) identifier's declared length —
/// `ar-0.9.0/src/lib.rs:307`'s `let mut id_buffer = vec![0; padded_length as
/// usize];`, run before a single byte of the name is read.
///
/// Reuses Task 5c's own figure (`MAX_CPIO_NAME_LEN`/`MAX_SYMLINK_TARGET_LEN`)
/// unchanged: a single identifier is exactly as path-shaped as a symlink
/// target or a cpio entry name, so the same reasoning transfers — a
/// generous ceiling well beyond any real platform's `PATH_MAX` (4096 on
/// Linux, 1024 on macOS/BSD). Measured directly rather than assumed: the
/// largest BSD extended identifier across 478 real `.a`/`.rlib` files on
/// this machine (see the module doc) was 100 bytes — this ceiling is 655x
/// that.
const MAX_BSD_IDENTIFIER_LEN: u64 = 65_536;

/// Ceiling on a GNU archive's long-name TABLE — `ar-0.9.0/src/lib.rs:261`'s
/// `*name_table = vec![0; size as usize];`, run before a single byte of the
/// table is read.
///
/// Deliberately NOT [`MAX_BSD_IDENTIFIER_LEN`]'s figure: a name table is a
/// TABLE, not a path, and a real one can legitimately hold thousands of
/// names (every entry whose identifier exceeds 15 bytes contributes one
/// `name/\n` record). Measured directly: the largest across the same 478
/// real archives — including 40-58 MB cross-compiled `libcore`/`libstd`
/// `.rlib`s — was 27,616 bytes (`libcompiler_builtins-*.rlib`, hundreds of
/// small translation units). 16 MiB is ~608x that (a library with 100,000
/// members averaging 40-byte names would need roughly 4 MiB), while staying
/// ~570x smaller than the ~9.3 GiB a 10-digit declared length can otherwise
/// buy.
const MAX_GNU_NAME_TABLE_LEN: u64 = 16 * 1024 * 1024;

/// What [`scan_ar_header`] learned about one 60-byte header, needed only to
/// track [`ArGuardedReader`]'s own position through the stream — never to
/// resolve a name or build an `ar::Header`, which the crate still does
/// itself once these bytes reach it.
struct ArHeaderScan {
    /// Total bytes following this header before the next header (or EOF):
    /// the raw, UNADJUSTED `file size` field (`buffer[48..58]`) — this is
    /// also the length a BSD extended identifier's own bytes are carved out
    /// of, so it already covers that case with no separate tracking.
    payload_len: u64,
    /// Whether a single `\n` pad byte follows the payload — decided by the
    /// ADJUSTED size (`payload_len` minus a BSD identifier's length, if
    /// any), matching `ar::Header::size()`/`Archive::next_entry`'s own
    /// `size % 2 != 0` check.
    pad_after: bool,
}

/// Parses one `ar` header's decimal ASCII field the same way the vendored
/// crate's own `parse_number` does (UTF-8, then `trim_end`, then base 10) —
/// `None` rather than an error on anything that does not parse, because a
/// field this function cannot read is a field the crate's OWN reparse of
/// these same bytes cannot read either, and `Header::read` raises the
/// accurate `Corrupt` error for that once it reaches them. This function
/// only ever needs to decide "is this dangerously large", never "is this
/// archive well-formed".
fn parse_ar_field(bytes: &[u8]) -> Option<u64> {
    std::str::from_utf8(bytes).ok()?.trim_end().parse().ok()
}

/// Refuses a declared length past `limit`, before the crate ever allocates
/// from it — [`io::ErrorKind::OutOfMemory`] is what `Error::from_decode_io`
/// already classifies as [`Error::ResourceLimit`] (exit 6), so no new error
/// plumbing is needed to get the same typed refusal Task 5c's cpio guard
/// raises directly.
fn refuse_if_over(value: u64, limit: u64, what: &str, noun: &str) -> io::Result<()> {
    if value > limit {
        return Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            format!(
                "{what} declares a {noun} of {value} bytes, past the {limit}-byte ceiling this \
                 container reads eagerly; no legitimate archive's {noun} is this large"
            ),
        ));
    }
    Ok(())
}

/// Inspects one complete 60-byte `ar` entry header, mirroring just enough of
/// `ar::Header::read`'s own branching (global variant detection, the GNU
/// name-table and BSD extended-identifier special cases) to validate the
/// two length fields those branches allocate from — see the module doc.
///
/// `variant` is threaded through exactly as the crate threads its own
/// `Variant` through `Header::read`: once a header sets it to `Gnu` or `Bsd`,
/// later headers cannot flip it back, which is what makes the branch order
/// below (GNU checks before the BSD check, matching the crate's own
/// sequence) produce identical outcomes to an `else if` chain even though
/// the crate itself writes the BSD check as a separate, unconditional `if`
/// — the two are equivalent because reaching either GNU branch already
/// disqualifies the BSD one via the `variant != Gnu` guard, the same way an
/// `else if` would.
fn scan_ar_header(
    hdr: &[u8; AR_ENTRY_HEADER_LEN],
    variant: &mut ar::Variant,
) -> io::Result<ArHeaderScan> {
    let mut identifier = hdr[0..16].to_vec();
    while identifier.last() == Some(&b' ') {
        identifier.pop();
    }
    let size = parse_ar_field(&hdr[48..58]).unwrap_or(0);
    let mut adjusted_size = size;

    if *variant != ar::Variant::BSD && identifier.starts_with(b"/") {
        *variant = ar::Variant::GNU;
        if identifier == b"//" {
            refuse_if_over(
                size,
                MAX_GNU_NAME_TABLE_LEN,
                "a GNU archive",
                "long-name table",
            )?;
        }
        // The GNU symbol table (identifier exactly `/`) and an ordinary GNU
        // short-name reference (`/N`) both carry `size` bytes of payload and
        // no further length field this container can reach — see the
        // module doc's "dead code from this module" paragraph for why the
        // symbol table's OWN string-table length is out of scope.
    } else if *variant != ar::Variant::BSD && identifier.ends_with(b"/") {
        *variant = ar::Variant::GNU;
    } else if *variant != ar::Variant::GNU && identifier.starts_with(b"#1/") {
        *variant = ar::Variant::BSD;
        if let Some(padded_length) = parse_ar_field(&hdr[3..16]) {
            refuse_if_over(
                padded_length,
                MAX_BSD_IDENTIFIER_LEN,
                "a BSD extended (`#1/N`)",
                "identifier length",
            )?;
            // Matches `Header::read`: a `size` smaller than `padded_length`
            // is the crate's own `InvalidData` refusal once it reparses
            // these bytes, not a resource question — nothing to guard here,
            // `adjusted_size` just stays at the raw `size`.
            if size >= padded_length {
                adjusted_size = size - padded_length;
            }
        }
    }

    Ok(ArHeaderScan {
        payload_len: size,
        pad_after: !adjusted_size.is_multiple_of(2),
    })
}

/// Where [`ArGuardedReader::read`] currently is in the archive, mirroring
/// `ar::Archive`'s own private position tracking closely enough to find
/// every header boundary — see the module doc for why this has to live
/// below the crate rather than as a peek-then-delegate helper.
enum ArGuardPhase {
    /// Still inside the 8-byte magic `!<arch>\n`; passed through untouched.
    GlobalHeader { remaining: u8 },
    /// A single `\n` pad byte must be read (and passed through) before the
    /// next header — `ar` pads every odd-sized record.
    Pad,
    /// At a header boundary: accumulating up to `AR_ENTRY_HEADER_LEN` bytes
    /// into `buf` before releasing ANY of them, so [`scan_ar_header`] always
    /// sees the header whole. A short read here (fewer than the full width,
    /// at true end of stream) means there is nothing complete enough to
    /// validate; what was read is released as-is and the crate's own
    /// `read_exact` retry surfaces the resulting `UnexpectedEof`, same as if
    /// this wrapper were not here.
    Header { buf: Vec<u8> },
    /// A header (validated, or the truncated remainder above) is being
    /// drained out of `buf` before falling back to [`ArGuardPhase::Payload`].
    Serving {
        buf: Vec<u8>,
        pos: usize,
        remaining: u64,
        pad_after: bool,
    },
    /// Passing through `remaining` payload bytes verbatim — covers a BSD
    /// identifier's own bytes plus the entry's real data, or a skipped GNU
    /// name/symbol table's payload, all alike: nothing downstream of a
    /// validated header allocates from a declared length again until the
    /// NEXT header.
    Payload { remaining: u64, pad_after: bool },
}

/// Wraps the real archive source and is what `ar::Archive` reads from for
/// the archive's WHOLE lifetime, inspecting every entry header before the
/// crate ever sees it — see the module doc's "Why the fix cannot be a
/// single peek before each entry" section for why this shape, rather than
/// `cpio.rs`'s peek-then-delegate helper, is what closes this container's
/// two reachable OOM sites.
struct ArGuardedReader {
    inner: Box<dyn Source>,
    phase: ArGuardPhase,
    variant: ar::Variant,
}

impl ArGuardedReader {
    fn new(inner: Box<dyn Source>) -> Self {
        ArGuardedReader {
            inner,
            phase: ArGuardPhase::GlobalHeader {
                remaining: GLOBAL_HEADER.len() as u8,
            },
            variant: ar::Variant::Common,
        }
    }
}

impl Read for ArGuardedReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            match &mut self.phase {
                ArGuardPhase::GlobalHeader { remaining } => {
                    if *remaining == 0 {
                        self.phase = ArGuardPhase::Header {
                            buf: Vec::with_capacity(AR_ENTRY_HEADER_LEN),
                        };
                        continue;
                    }
                    let want = (*remaining as usize).min(out.len());
                    let n = self.inner.read(&mut out[..want])?;
                    if n == 0 {
                        return Ok(0);
                    }
                    *remaining -= n as u8;
                    return Ok(n);
                }
                ArGuardPhase::Pad => {
                    let mut one = [0u8; 1];
                    let n = self.inner.read(&mut one)?;
                    if n == 0 {
                        return Ok(0);
                    }
                    out[0] = one[0];
                    self.phase = ArGuardPhase::Header {
                        buf: Vec::with_capacity(AR_ENTRY_HEADER_LEN),
                    };
                    return Ok(1);
                }
                ArGuardPhase::Header { buf } => {
                    while buf.len() < AR_ENTRY_HEADER_LEN {
                        let want = AR_ENTRY_HEADER_LEN - buf.len();
                        let mut tmp = vec![0u8; want];
                        let n = self.inner.read(&mut tmp)?;
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    if buf.is_empty() {
                        return Ok(0);
                    }
                    let (payload_len, pad_after) = if buf.len() == AR_ENTRY_HEADER_LEN {
                        let hdr: [u8; AR_ENTRY_HEADER_LEN] = buf
                            .as_slice()
                            .try_into()
                            .expect("just checked buf.len() == AR_ENTRY_HEADER_LEN");
                        let scan = scan_ar_header(&hdr, &mut self.variant)?;
                        (scan.payload_len, scan.pad_after)
                    } else {
                        // Truncated mid-header — see this phase's own doc.
                        (0, false)
                    };
                    let full = std::mem::take(buf);
                    self.phase = ArGuardPhase::Serving {
                        buf: full,
                        pos: 0,
                        remaining: payload_len,
                        pad_after,
                    };
                }
                ArGuardPhase::Serving {
                    buf,
                    pos,
                    remaining,
                    pad_after,
                } => {
                    if *pos < buf.len() {
                        let n = (buf.len() - *pos).min(out.len());
                        out[..n].copy_from_slice(&buf[*pos..*pos + n]);
                        *pos += n;
                        return Ok(n);
                    }
                    self.phase = ArGuardPhase::Payload {
                        remaining: *remaining,
                        pad_after: *pad_after,
                    };
                }
                ArGuardPhase::Payload {
                    remaining,
                    pad_after,
                } => {
                    if *remaining == 0 {
                        self.phase = if *pad_after {
                            ArGuardPhase::Pad
                        } else {
                            ArGuardPhase::Header {
                                buf: Vec::with_capacity(AR_ENTRY_HEADER_LEN),
                            }
                        };
                        continue;
                    }
                    let want = out
                        .len()
                        .min(usize::try_from(*remaining).unwrap_or(usize::MAX));
                    let n = self.inner.read(&mut out[..want])?;
                    if n == 0 {
                        return Ok(0);
                    }
                    *remaining -= n as u64;
                    return Ok(n);
                }
            }
        }
    }
}

type ArSource = ArGuardedReader;
type ArArchive = ar::Archive<ArSource>;

/// Owns the archive on the heap and, while one is in progress, the entry
/// currently being read.
///
/// This is self-referential — `current` borrows `*archive` — for a
/// DIFFERENT reason than `tar.rs`'s identically-shaped `TarRead`: tar's own
/// `Entries` iterator is itself the thing that must outlive one call to be
/// borrowed from again in the next. Here, the reason is `ar::Entry`'s own
/// `Drop` impl, measured directly against `ar 0.9.0` (compress a 4 MiB
/// entry, take the returned `Entry` without reading it, drop it, count
/// bytes pulled from the source before and after): dropping an `Entry` with
/// unread payload EAGERLY drains all of it via `io::copy` into a sink, the
/// instant the drop runs — there is no lazy, deferred-to-the-next-call
/// alternative exposed by the crate's public API (unlike `cpio::newc::Reader`,
/// which exposes an explicit `finish()` this project can call on its own
/// schedule — see `cpio.rs`). Handing the caller a payload that BORROWS the
/// entry stored in `current` (rather than owning it outright) is what lets
/// this module choose WHEN that drain runs: at the START of the NEXT
/// `next_entry` call, exactly mirroring `cpio.rs`'s own deferred-finish
/// design, instead of the crate choosing "immediately, whether the caller
/// asked to skip or not". Conformance harness property 8 is what caught the
/// difference: its fixture is a single 4 MiB entry, read via ONE
/// `next_entry()` call whose returned value is then dropped as an unbound
/// temporary — precisely what `entries::list`'s own iteration does too
/// (`while let Some(entry) = ar.next_entry()? { out.push(entry.meta().clone()); }`,
/// dropping `entry` at the end of every loop body) — and without this
/// field, that single call-and-drop already consumed the whole 4 MiB before
/// the property's byte counter was ever read.
///
/// `archive` is a raw pointer rather than a `Box` field for the same
/// aliasing reason `tar.rs`'s `TarRead` uses one: deriving a borrow from a
/// `Box` and then MOVING the box — which constructing this struct and
/// returning it as `Box<dyn ArchiveRead>` does — is the hazard `Box`'s own
/// `noalias` guarantee makes real, and `Box::into_raw` sidesteps entirely by
/// never storing the `Box` itself once a borrow into its contents exists.
/// See that module's doc for the fuller argument, which applies unchanged.
struct ArRead {
    archive: *mut ArArchive,
    /// The entry currently in progress. `None` between entries and once the
    /// archive is exhausted.
    current: Option<ar::Entry<'static, ArSource>>,
    report: FidelityReport,
    seekable: bool,
}

impl Drop for ArRead {
    fn drop(&mut self) {
        // Drop the borrower first — the same ordering requirement, for the
        // same reason, as `tar.rs`'s own `TarRead::drop`.
        self.current = None;
        // SAFETY: `archive` came from `Box::into_raw` in `Ar::open`, is never
        // copied out of this struct and is freed nowhere else, and the only
        // borrow of it (`current`) was just dropped above.
        drop(unsafe { Box::from_raw(self.archive) });
    }
}

impl ArchiveRead for ArRead {
    fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
        // Finish the PREVIOUS entry, draining whatever the caller did not
        // read — see this struct's own doc for why doing it HERE, on our own
        // schedule, rather than via `ar::Entry`'s own Drop when the caller's
        // returned wrapper goes out of scope, is the whole point of storing
        // it in `self` at all.
        self.current = None;

        // SAFETY: `archive` is non-null, aligned and initialised — `Ar::open`
        // allocated it via `Box::into_raw` and nothing else frees it before
        // this struct's own `Drop` does — and this is the ONLY live borrow
        // of it: `current`, the only other path to one, was just cleared.
        // The borrow's lifetime is inferred as `'static` below, to match
        // `current`'s declared type; that is sound because the allocation
        // is never moved (only the raw pointer `archive` is ever copied),
        // this remains the sole borrow of it for as long as `current` holds
        // it, and `Drop for ArRead` drops `current` — ending this borrow —
        // before reclaiming the allocation.
        let next = unsafe { &mut *self.archive }.next_entry();
        let raw = match next {
            None => return Ok(None),
            Some(Err(e)) => return Err(classify_ar_error(e)),
            Some(Ok(raw)) => raw,
        };

        let meta = entry_meta(raw.header());
        let remaining = raw.header().size();
        let name = meta.name.clone();
        self.current = Some(raw);

        let payload = ArEntryPayload {
            entry: self.current.as_mut().expect("just set on the line above"),
            remaining,
            name,
        };
        Ok(Some(Entry::new(
            meta,
            Box::new(NormalizeDecodeErrors::new(
                payload,
                AR_MALFORMED_AS_INVALID_DATA_EOF,
            )),
        )))
    }

    /// `ar` carries no entry index, on any source — the same shape as tar's
    /// own `by_index` (see that module's doc for why the two errors say
    /// different true things: `NotSeekable` over a forward-only source,
    /// `Unsupported` over a seekable one where the FORMAT, not the source, is
    /// what has no index to walk to).
    fn by_index(&mut self, index: usize) -> Result<Entry<'_>> {
        if self.seekable {
            return Err(Error::Unsupported(format!(
                "ar carries no entry index, so entry {index} can only be reached by reading \
                 forward from the start"
            )));
        }
        Err(Error::NotSeekable { format: AR })
    }

    fn fidelity(&self) -> &FidelityReport {
        &self.report
    }
}

/// One entry's payload. Borrows the [`ar::Entry`] stored in [`ArRead::current`]
/// rather than owning it outright — see that field's own doc for why.
///
/// Carries the same short-read guard `tar.rs`'s `EntryPayload` and `cpio.rs`'s
/// `CpioEntryPayload` do: `ar::Entry::read` is a bare length-limited proxy
/// over the archive's reader with no truncation check of its own, so a
/// stream that runs out mid-entry reports a clean `Ok(0)` with bytes still
/// promised.
struct ArEntryPayload<'a> {
    entry: &'a mut ar::Entry<'static, ArSource>,
    /// Payload bytes the entry's own header promised and has not delivered.
    remaining: u64,
    /// Kept for the error message: a corrupt archive should say WHICH entry.
    name: String,
}

impl Read for ArEntryPayload<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // `Read`'s contract: an empty buffer reads nothing and is not an
        // error — see `tar.rs`'s `EntryPayload::read` for why this guard has
        // to come before the short-read check below.
        if buf.is_empty() {
            return Ok(0);
        }
        let n = self.entry.read(buf)?;
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

/// `ar` has no notion of a directory or a symlink — every entry is an opaque
/// named blob — so every entry reads back as [`EntryKind::File`].
fn entry_meta(header: &ar::Header) -> EntryMeta {
    EntryMeta {
        name: String::from_utf8_lossy(header.identifier()).into_owned(),
        size: Some(header.size()),
        mtime: Some(UNIX_EPOCH + Duration::from_secs(header.mtime())),
        mode: Some(header.mode()),
        uid: Some(header.uid()),
        gid: Some(header.gid()),
        kind: EntryKind::File,
        ..Default::default()
    }
}

struct ArWrite {
    /// `None` once `finish` has consumed it.
    inner: Option<ar::Builder<Box<dyn Sink>>>,
    /// Whether `add` was ever called. `ar::Builder` writes the global header
    /// lazily, on the first `append` — with zero entries that never
    /// happens, and the archive would be zero bytes rather than the 8-byte
    /// magic a valid empty archive is. See the module doc.
    wrote_any: bool,
}

impl ArWrite {
    fn builder(&mut self) -> Result<&mut ar::Builder<Box<dyn Sink>>> {
        self.inner
            .as_mut()
            .ok_or_else(|| Error::Usage("ar writer used after finish()".into()))
    }
}

impl ArchiveWrite for ArWrite {
    fn add(&mut self, meta: &EntryMeta, data: &mut dyn Read) -> Result<()> {
        // `ar` needs the size up front and cannot stream an unknown length,
        // so an entry of unknown size is buffered. Stated rather than
        // hidden: this is the one container here that cannot stream its
        // input on the write side (`cpio.rs` shares the constraint).
        let mut buf = Vec::new();
        data.read_to_end(&mut buf)?;

        let identifier = write_safe_identifier(meta.name.clone().into_bytes());
        let mut header = ar::Header::new(identifier, buf.len() as u64);
        header.set_mode(meta.mode.unwrap_or(DEFAULT_MODE));
        header.set_mtime(meta.mtime.map(unix_seconds).unwrap_or(0));
        header.set_uid(meta.uid.unwrap_or(0));
        header.set_gid(meta.gid.unwrap_or(0));

        self.builder()?.append(&header, &mut &buf[..])?;
        self.wrote_any = true;
        Ok(())
    }

    /// No trailer to write — see the module doc. The one thing that needs
    /// doing here that `ar::Builder` will not do on its own is writing the
    /// global header for a ZERO-entry archive, since `Builder::append` is
    /// the only place that header is written and `append` was never called.
    ///
    /// The destination is returned, not finished: the caller owns completion,
    /// because a codec layer beneath us has its own trailer still to write.
    fn finish(mut self: Box<Self>) -> Result<Box<dyn Sink>> {
        let builder = self
            .inner
            .take()
            .ok_or_else(|| Error::Usage("ar writer finished twice".into()))?;
        let mut dst = builder.into_inner()?;
        if !self.wrote_any {
            dst.write_all(GLOBAL_HEADER)?;
        }
        Ok(dst)
    }
}

/// Forces the BSD extended (`#1/N`) identifier form for a short name that
/// would otherwise collide with the GNU variant's reserved syntax — which
/// means ANY name containing a `/`, anywhere in it.
///
/// `Header::read` infers which of the three variants (common, BSD, GNU) it
/// is looking at header by header, and a name in the plain 16-byte field
/// that starts OR ends with `/` is exactly what marks a GNU long-name
/// reference or a GNU-style directory entry — `identifier.starts_with(b"/")`
/// tries to parse the REST of the field as a numeric name-table offset, and
/// a literal path like `/abs/path` is not one, raising "Invalid GNU filename
/// index field" instead of reading the name back at all. This bites hardest
/// on exactly the entries harness property 12 exists to protect: a hostile
/// absolute path is real input this container must store and report
/// verbatim, not an edge case to leave broken. `identifier.ends_with(b"/")`
/// has the mirror problem (GNU's own convention for a bare directory name),
/// silently dropping the trailing slash instead of erroring.
///
/// # An INTERIOR `/` is just as ambiguous, and only another tool can see it
///
/// That was the original predicate, and it was too narrow, because `ar`'s
/// own reader is not the only reader. In the GNU variant a short name is
/// stored `name/`, with `/` as the TERMINATOR, so a GNU reader stops at the
/// first `/` in the 16-byte field whether or not the name also begins or
/// ends with one. The `ar` crate happens not to (its GNU branch is entered
/// only on a leading or trailing `/`, so it reads `proj/a.txt` back whole),
/// which is exactly why a phase of macOS-only review missed this: the system
/// `ar` on macOS agrees with us, and CI's GNU `ar` does not. Measured
/// directly, on a two-entry archive this module wrote with `proj/a.txt` and
/// `proj/sub/b.bin` inline in the 16-byte field:
///
/// ```text
/// BSD ar (macOS)          GNU ar 2.47
/// proj/a.txt              proj
/// proj/sub/b.bin          proj      <- and now the two members COLLIDE
/// ```
///
/// So `pack` on any nested tree produced an archive GNU `ar` listed as N
/// copies of the top-level directory name. Since `pack` names every entry
/// beneath the walked directory's own final component, essentially every
/// multi-file `ar` this project writes was affected.
///
/// The fix is the same lever, with the predicate widened to `contains`.
/// Both alternatives were measured before choosing it. A GNU long-name
/// table (`//` plus `/offset` references) is read back whole by GNU `ar` —
/// and by BSD `ar` as the literal member names `//`, `/0` and `/12`, which
/// is worse than the bug. The BSD extended form round-trips VERBATIM
/// through both tools, so it is the only encoding that is portable in the
/// sense that matters here.
///
/// `Header::write`'s own choice between the short and BSD-extended forms is
/// unconditional on the name's CONTENT — only its length (`> 16`) or the
/// presence of a space — so there is no lever to request the extended form
/// through the crate's public API for a name that is short and space-free
/// but still ambiguous. Padding it past 16 bytes with NUL is what forces the
/// choice from OUTSIDE: a BSD-extended header's on-disk identifier FIELD
/// itself always begins `#1/`, which starts with neither `/` nor a name
/// ending in `/`, so `Header::read` never takes the GNU branch for it at
/// all — variant detection is settled before the real name is even reached.
/// The padding is NUL bytes because `Header::read`'s extended-identifier
/// parsing already strips ALL trailing NUL bytes from what it reads back
/// (both the crate's own 4-byte alignment padding and these), which is what
/// makes the round trip exact rather than merely close.
///
/// A name LONGER than 16 bytes needs nothing from this function: the crate
/// already writes it in the extended form on length alone, and a GNU reader
/// never sees a `/`-bearing 16-byte field for it.
fn write_safe_identifier(mut identifier: Vec<u8>) -> Vec<u8> {
    if identifier.contains(&b'/') && identifier.len() <= 16 {
        identifier.resize(17, 0);
    }
    identifier
}

/// Seconds since the epoch, which is what `ar::Header::mtime` stores. A
/// timestamp before 1970 clamps to zero rather than failing the write, the
/// same choice `tar.rs`'s own `unix_seconds` makes and for the same reason.
fn unix_seconds(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stuffr_core::testing::{SharedBuf, assert_container_conforms, open_forward_only};
    use stuffr_core::{
        ArchiveRead, CreateOpts, EntryMeta, OpenOpts, PlainSink, ReaderSource, Source,
    };

    fn build_ar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let buf = SharedBuf::new();
        let mut w = Ar
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
        let resolved =
            stuffr_core::resolve(src, AR, Ar.caps(), &stuffr_core::StreamPolicy::default())
                .expect("resolve");
        Ar.open(resolved, &OpenOpts::default()).expect("open")
    }

    fn which(bin: &str) -> Option<std::path::PathBuf> {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path).find_map(|dir| {
            let candidate = dir.join(bin);
            candidate.is_file().then_some(candidate)
        })
    }

    /// Locates `bin` on `PATH`, panicking rather than silently skipping if
    /// it is absent. CI always installs it (`ar` ships via `binutils` on
    /// `ubuntu-latest` unconditionally), so an absence here means only a
    /// contributor's own machine lacks it — and a silent `return` in that
    /// case would report every cross-implementation test in this file as
    /// PASSING having verified nothing at all, exactly the shape Finding 8
    /// (Phase 1e) warns against. Failing loudly beats passing quietly.
    fn require_bin(bin: &str) -> std::path::PathBuf {
        which(bin).unwrap_or_else(|| {
            panic!(
                "no reference `{bin}` tool found on PATH — this test proved nothing, which is \
                 worth knowing rather than passing silently"
            )
        })
    }

    #[test]
    fn ar_conforms() {
        assert_container_conforms(&Ar, &meta());
    }

    #[test]
    fn capabilities_and_metadata_match_the_format() {
        let c = Ar.caps();
        assert!(c.read && c.write && c.forward_parse);
        assert!(
            !c.trailing_index && !c.per_entry_codec && !c.solid && !c.needs_seek,
            "ar has no index, no per-entry codec and no solid blocks"
        );
        let m = meta();
        assert_eq!(m.id, AR);
        assert_eq!(m.extensions, &["a", "ar"]);
    }

    #[test]
    fn output_carries_the_global_header_at_offset_zero() {
        let bytes = build_ar(&[("a.txt", b"alpha")]);
        assert_eq!(&bytes[..8], GLOBAL_HEADER);
    }

    /// The case the module doc calls out: a truly empty stream is a
    /// TRUNCATED archive, not a valid empty one — only the bare 8-byte
    /// magic is.
    #[test]
    fn an_empty_archive_is_exactly_the_global_header_and_nothing_else() {
        let bytes = build_ar(&[]);
        assert_eq!(
            bytes, GLOBAL_HEADER,
            "a zero-entry ar archive is 8 bytes, not 0"
        );

        let mut ar = open(&bytes);
        assert!(
            ar.next_entry().expect("must not be an error").is_none(),
            "the bare global header must read back as zero entries"
        );
    }

    /// A name past the 16-byte short-form field switches `ar::Header::write`
    /// to the BSD extended `#1/N` form automatically — unlike tar, nothing
    /// in this module has to ask for that.
    #[test]
    fn a_long_or_spaced_name_round_trips_through_the_bsd_extended_form() {
        for name in [
            "short.txt",
            "this-name-is-longer-than-sixteen-bytes.txt",
            "a name with spaces.txt",
        ] {
            let bytes = build_ar(&[(name, b"payload")]);
            let mut ar = open(&bytes);
            let entry = ar.next_entry().unwrap().unwrap();
            assert_eq!(entry.meta().name, name, "name={name}");
            assert_eq!(entry.meta().size, Some(7), "name={name}");
        }
    }

    /// A name starting OR ending with `/`, short enough that `ar::Header::write`
    /// would otherwise choose the plain 16-byte form, collides with `ar`'s own
    /// GNU-variant reserved syntax on READ — see `write_safe_identifier`'s doc.
    /// Property 12 (harness) already covers `/abs/path` via `ar_conforms`;
    /// this pins the failure mode directly (a raw "Invalid GNU filename
    /// index" error, not a silently altered name) and adds the mirror case
    /// property 12's own fixture does not: a trailing slash.
    #[test]
    fn a_name_starting_or_ending_with_a_slash_round_trips_exactly() {
        for name in ["/abs/path", "/x", "some-dir/", "/"] {
            let bytes = build_ar(&[(name, b"payload")]);
            let mut ar = open(&bytes);
            let entry = ar
                .next_entry()
                .unwrap_or_else(|e| panic!("name={name:?}: {e}"))
                .unwrap_or_else(|| panic!("name={name:?}: expected one entry"));
            assert_eq!(entry.meta().name, name, "name={name:?}");
        }
    }

    /// The PORTABLE proof that an interior `/` is forced out of the inline
    /// 16-byte field, asserted on the bytes because no reader on this
    /// machine can see the defect.
    ///
    /// In the GNU variant a short name is stored with `/` as its
    /// TERMINATOR, so GNU `ar` truncates an inline `proj/a.txt` to `proj`
    /// and an inline `proj/sub/b.bin` to `proj` as well — two members with
    /// one name. The `ar` crate's own reader enters its GNU branch only on
    /// a LEADING or trailing `/`, and macOS's system `ar` agrees with it,
    /// so both this module's round trip and `cli.rs`'s reference-tool
    /// comparison came back clean on macOS while CI's GNU `ar` went red.
    /// Exactly the shape of `cpio.rs`'s missing `S_IFREG`, and answered the
    /// same way: assert the header bytes, where the format knowledge is.
    #[test]
    fn a_name_containing_a_slash_is_never_stored_inline() {
        let bytes = build_ar(&[("proj/a.txt", b"alpha"), ("proj/sub/b.bin", b"beta")]);

        // The first entry's 16-byte identifier field sits immediately after
        // the global header. `#1/` is the BSD extended form's marker, and a
        // field beginning with it carries no `/`-terminated name for a GNU
        // reader to truncate.
        let field = &bytes[GLOBAL_HEADER.len()..GLOBAL_HEADER.len() + 16];
        assert!(
            field.starts_with(b"#1/"),
            "a `/`-bearing name must be forced into the BSD extended form, not \
             written inline; identifier field was {:?}",
            String::from_utf8_lossy(field)
        );

        // And no inline, space-padded field anywhere in the archive carries
        // either path — the shape GNU `ar` truncates. Built rather than
        // written as a literal: a literal would carry a run of spaces, which
        // `cli.rs`'s workspace-wide message lint refuses.
        for name in ["proj/a.txt", "proj/sub/b.bin"] {
            let mut inline = name.as_bytes().to_vec();
            inline.resize(16, b' ');
            assert!(
                !bytes.windows(16).any(|w| w == inline),
                "`{name}` is stored inline in a 16-byte field, which GNU ar reads as `proj`"
            );
        }

        // Still exact through our own reader, which is what the extended
        // form has to buy without costing.
        let mut ar = open(&bytes);
        let mut names = Vec::new();
        while let Some(entry) = ar.next_entry().unwrap() {
            names.push(entry.meta().name.clone());
        }
        assert_eq!(names, vec!["proj/a.txt", "proj/sub/b.bin"]);
    }

    /// A name longer than 16 bytes already gets the extended form from
    /// `Header::write` on length alone, so `write_safe_identifier` must not
    /// pad it — and a name with no `/` at all must stay inline, or every
    /// ordinary archive this module writes grows a needless extended header.
    #[test]
    fn write_safe_identifier_pads_only_what_needs_it() {
        assert_eq!(write_safe_identifier(b"a.txt".to_vec()), b"a.txt".to_vec());
        assert_eq!(
            write_safe_identifier(b"proj/a.txt".to_vec()),
            b"proj/a.txt\0\0\0\0\0\0\0".to_vec(),
        );
        let long = b"a-very-long-directory-name/inside.txt".to_vec();
        assert_eq!(write_safe_identifier(long.clone()), long);
        // Exactly 16 bytes with a `/` is the boundary the crate would still
        // write inline, so it is padded.
        let sixteen = b"proj/aaaaaaa.txt".to_vec();
        assert_eq!(sixteen.len(), 16, "the point of this case");
        assert_eq!(write_safe_identifier(sixteen).len(), 17);
    }

    #[test]
    fn add_measures_the_payload_when_the_caller_does_not_declare_a_size() {
        let buf = SharedBuf::new();
        let mut w = Ar
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

    #[test]
    fn an_unset_mode_defaults_to_a_readable_regular_file() {
        let bytes = build_ar(&[("a.txt", b"alpha")]);
        let mut ar = open(&bytes);
        let entry = ar.next_entry().unwrap().unwrap();
        assert_eq!(entry.meta().mode, Some(DEFAULT_MODE));
    }

    /// `by_index` is never random access here, on either source shape — the
    /// same double-check `tar.rs` pins for the identical reason.
    #[test]
    fn by_index_is_refused_on_every_source_shape() {
        let bytes = build_ar(&[("a.txt", b"alpha"), ("b.txt", b"beta")]);

        let mut fwd = open_forward_only(&Ar, &bytes);
        assert!(
            matches!(fwd.by_index(0), Err(stuffr_core::Error::NotSeekable { .. })),
            "a forward-only source must answer NotSeekable"
        );

        let path = std::env::temp_dir().join(format!(
            "stuffr-ar-seekable-{}-{:p}.a",
            std::process::id(),
            &bytes
        ));
        std::fs::write(&path, &bytes).unwrap();
        let src: Box<dyn Source> = Box::new(stuffr_core::FileSource::open(&path).unwrap());
        let _ = std::fs::remove_file(&path);
        let resolved =
            stuffr_core::resolve(src, AR, Ar.caps(), &stuffr_core::StreamPolicy::default())
                .unwrap();
        let mut seekable = Ar.open(resolved, &OpenOpts::default()).unwrap();
        let err = seekable
            .by_index(0)
            .expect_err("ar has no index to index into");
        assert!(
            matches!(err, stuffr_core::Error::Unsupported(_)),
            "a seekable source is not the problem — ar has no index to index into: {err:?}"
        );
        // Exit 3, "this build cannot do that", not the generic 1 it reported
        // until Phase 2's Task 11 gave `Error::Unsupported` an explicit arm.
        // A caller asking for random access a format never had should be able
        // to tell that answer from an internal failure.
        assert_eq!(err.exit_code(), 3, "{err}");
    }

    /// A cut inside an entry's payload. `ar::Entry::read` does not detect
    /// this itself (see the module doc); `ArEntryPayload` does.
    #[test]
    fn a_cut_inside_an_entry_payload_is_reported_as_corrupt() {
        let payload = stuffr_core::testing::incompressible(64 * 1024);
        let bytes = build_ar(&[("big.bin", &payload)]);
        // 8-byte global header + 60-byte entry header, then the payload.
        for cut in [69usize, 1024, 32768, 68 + 65536 - 1] {
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
    /// through a real `ar`. CI has it unconditionally (`binutils` ships it
    /// on `ubuntu-latest`); a contributor's machine lacking it fails this
    /// test loudly rather than passing having verified nothing (Phase 1e,
    /// Finding 8) — see `require_bin`.
    #[test]
    fn system_ar_accepts_what_we_write() {
        let ar_bin = require_bin("ar");

        let long_name: String = std::iter::repeat_n("segment-", 4).collect::<String>() + ".txt";
        let spaced_name = "a name with spaces.txt";
        // Short enough that `Header::write` would store it inline, and
        // `/`-bearing, which is what GNU `ar` truncates at the first `/`.
        // Whether THIS assertion can fail depends on which `ar` is on PATH
        // (macOS's cannot see the defect); the portable proof is
        // `a_name_containing_a_slash_is_never_stored_inline`.
        let path_name = "proj/sub/b.bin";
        let bytes = build_ar(&[
            ("a.txt", b"alpha"),
            (spaced_name, b"\x00\xff\x00"),
            (path_name, b"deep"),
            (&long_name, b"deep"),
        ]);
        let path =
            std::env::temp_dir().join(format!("stuffr-ar-crossimpl-{}.a", std::process::id()));
        std::fs::write(&path, &bytes).unwrap();

        let listed = std::process::Command::new(&ar_bin)
            .arg("t")
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            listed.status.success(),
            "system ar rejected our archive: {}",
            String::from_utf8_lossy(&listed.stderr)
        );
        let listing = String::from_utf8_lossy(&listed.stdout);
        assert!(listing.contains("a.txt"), "listing was {listing:?}");
        assert!(
            listing.contains(spaced_name),
            "system ar did not read back our space-containing BSD extended-name entry; \
             listing was {listing:?}"
        );
        assert!(
            listing.contains(&long_name),
            "system ar did not read back our BSD extended-name entry; listing was {listing:?}"
        );
        assert!(
            listing.contains(path_name),
            "system ar truncated our `/`-bearing name — the GNU variant reads `/` as a \
             short name's terminator; listing was {listing:?}"
        );

        let printed = std::process::Command::new(&ar_bin)
            .arg("p")
            .arg(&path)
            .arg("a.txt")
            .output()
            .unwrap();
        assert!(printed.status.success(), "system ar could not print a.txt");
        assert_eq!(printed.stdout, b"alpha");

        let _ = std::fs::remove_file(&path);
    }

    /// The arbiter in the other direction, mirroring `tar.rs`'s own
    /// `we_accept_what_system_tar_writes`: `system_ar_accepts_what_we_write`
    /// only proves our writer and our reader agree about archives WE
    /// framed. A system `ar` writes its own header bytes, which is the
    /// only independent evidence that this container's READ side, not just
    /// its round trip, is correct.
    #[test]
    fn we_accept_what_system_ar_writes() {
        let ar_bin = require_bin("ar");

        let dir = std::env::temp_dir().join(format!("stuffr-ar-reverse-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"alpha").unwrap();
        std::fs::write(dir.join("b.bin"), vec![0xABu8; 5000]).unwrap();

        let archive = dir.join("made-by-system-ar.a");
        // `-S`: do not build a ranlib-style symbol table. Measured directly
        // on this machine: `ar rc` ALONE (no `-S`) silently produced a
        // 96-byte archive containing ONLY an empty `__.SYMDEF SORTED`
        // symbol table — both real files were dropped entirely, since
        // macOS's `ar` invokes ranlib-like indexing on plain (non-object)
        // files by default. `-S` is what makes this a plain archive of the
        // two files, the shape every other `ar` (GNU included) writes by
        // default.
        let status = std::process::Command::new(&ar_bin)
            .arg("rcS")
            .arg(&archive)
            .arg("a.txt")
            .arg("b.bin")
            .current_dir(&dir)
            .status()
            .unwrap();
        assert!(status.success(), "system ar could not write the fixture");

        let bytes = std::fs::read(&archive).unwrap();
        let mut ar = open(&bytes);
        let mut got = Vec::new();
        while let Some(mut entry) = ar.next_entry().unwrap() {
            let name = entry.meta().name.clone();
            let mut data = Vec::new();
            entry.reader().read_to_end(&mut data).unwrap();
            got.push((name, data));
        }
        let find = |name: &str| {
            got.iter().find(|(n, _)| n == name).unwrap_or_else(|| {
                panic!(
                    "{name} missing from {:?}",
                    got.iter().map(|(n, _)| n).collect::<Vec<_>>()
                )
            })
        };
        assert_eq!(&find("a.txt").1[..], b"alpha");
        assert_eq!(find("b.bin").1, vec![0xABu8; 5000]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The empty-archive case specifically: the system tool cannot WRITE one
    /// (`ar: no archive members specified` on this machine), but it must
    /// still READ one back as zero members — see the module doc.
    #[test]
    fn system_ar_accepts_an_empty_archive_we_write() {
        let ar_bin = require_bin("ar");

        let bytes = build_ar(&[]);
        let path = std::env::temp_dir().join(format!(
            "stuffr-ar-crossimpl-empty-{}.a",
            std::process::id()
        ));
        std::fs::write(&path, &bytes).unwrap();

        let listed = std::process::Command::new(&ar_bin)
            .arg("t")
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            listed.status.success(),
            "system ar rejected our empty archive: {}",
            String::from_utf8_lossy(&listed.stderr)
        );
        assert!(
            listed.stdout.is_empty(),
            "an empty archive must list zero members: {:?}",
            String::from_utf8_lossy(&listed.stdout)
        );

        let _ = std::fs::remove_file(&path);
    }

    /// `require_bin` is what makes a missing reference tool a loud failure
    /// rather than a silent skip — proven directly, on a name guaranteed
    /// absent from `PATH`, rather than trusted by inspection alone.
    #[test]
    #[should_panic(expected = "no reference `this-binary-does-not-exist-xyz` tool found on PATH")]
    fn require_bin_panics_rather_than_skips_silently() {
        require_bin("this-binary-does-not-exist-xyz");
    }

    // --- Task 5d: the two header-declared-length OOMs the fuzzer would find ---
    //
    // `ar-0.9.0/src/lib.rs:261` and `:307` allocate `vec![0; N]` straight from
    // a header field, before a single byte of the name/table is read. See
    // the module doc's own section for the full picture; what follows
    // hand-builds the two dangerous header shapes byte-for-byte, the same
    // technique `cpio.rs`'s Task 5c tests use.

    /// One `ar` header field: `n` written as decimal ASCII, left-justified
    /// and space-padded to exactly `width` bytes — the same layout
    /// `ar::Header::write`'s own `{:<N}` format specifiers produce.
    fn dec_field(n: u64, width: usize) -> Vec<u8> {
        let s = format!("{n:<width$}");
        assert_eq!(
            s.len(),
            width,
            "{n} does not fit left-justified in {width} bytes"
        );
        s.into_bytes()
    }

    /// A plain (non-extended) 16-byte identifier field: `s`, space-padded.
    fn padded_identifier(s: &str) -> [u8; 16] {
        let mut id = [b' '; 16];
        let bytes = s.as_bytes();
        assert!(bytes.len() <= 16, "fixture identifier too long: {s:?}");
        id[..bytes.len()].copy_from_slice(bytes);
        id
    }

    /// A BSD extended (`#1/N`) identifier field: `#1/` plus `padded_length`
    /// as a 13-byte decimal field — `ar-0.9.0/src/lib.rs:296`'s own
    /// `parse_number("BSD filename length", &buffer[3..16], 10)`.
    fn bsd_ext_identifier_field(padded_length: u64) -> [u8; 16] {
        let mut id = [0u8; 16];
        id[0..3].copy_from_slice(b"#1/");
        id[3..16].copy_from_slice(&dec_field(padded_length, 13));
        id
    }

    /// One hand-built 60-byte `ar` entry header — every field but the
    /// identifier and the declared size is a harmless placeholder, since
    /// every test below is refused (or fails) before those fields are ever
    /// consulted.
    fn ar_header_raw(identifier: &[u8; 16], size: u64) -> Vec<u8> {
        let mut h = Vec::with_capacity(60);
        h.extend_from_slice(identifier);
        h.extend_from_slice(&dec_field(0, 12)); // mtime
        h.extend_from_slice(&dec_field(0, 6)); // uid
        h.extend_from_slice(&dec_field(0, 6)); // gid
        h.extend_from_slice(format!("{:<8}", "100644").as_bytes()); // mode
        h.extend_from_slice(&dec_field(size, 10)); // file size
        h.extend_from_slice(b"`\n");
        assert_eq!(h.len(), 60, "must be exactly ENTRY_HEADER_LEN");
        h
    }

    /// A `Source` that panics if ever asked to fill a buffer larger than
    /// `max_single_read` — see `cpio.rs`'s identically-named struct for the
    /// full reasoning. `ArGuardedReader`'s own `Header` phase never requests
    /// more than `AR_ENTRY_HEADER_LEN` (60) bytes from the source in one
    /// call, so a request here for anything past a sane header-sized window
    /// proves the crate's own `vec![0; N]` allocation was reached — i.e.
    /// that the pre-flight check did not run before the crate's parser did.
    struct PanicsOnBigRead {
        inner: std::io::Cursor<Vec<u8>>,
        max_single_read: usize,
    }

    impl Read for PanicsOnBigRead {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            assert!(
                buf.len() <= self.max_single_read,
                "a single read of {} bytes was requested — past the {}-byte guard. This is proof \
                 the oversized header-declared allocation was reached before any refusal ran, \
                 i.e. the pre-flight check did not fire before the crate's own parser did",
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
        let resolved =
            stuffr_core::resolve(src, AR, Ar.caps(), &stuffr_core::StreamPolicy::default())
                .expect("resolve");
        Ar.open(resolved, &OpenOpts::default())
            .expect("open reads no byte")
    }

    /// The failing-first test for Task 5d's first site: an absurd GNU
    /// long-name-table size must be refused as a typed error, at exit 6
    /// (`Error::ResourceLimit`) — never exit 5 (`Error::Corrupt`), and never
    /// by way of the multi-gigabyte allocation the un-fixed crate makes on
    /// the way to failing. `max_single_read` is `PROBE_LEN` (4096) — generous
    /// for any legitimate header read, and roughly six orders of magnitude
    /// below the declared table length, so nothing on the honest path can
    /// trip it.
    #[test]
    fn refuses_an_absurd_gnu_name_table_size_before_the_allocation_it_would_size() {
        let absurd_size: u64 = 8_000_000_000; // ~7.45 GiB, well past the ceiling
        let mut bytes = GLOBAL_HEADER.to_vec();
        bytes.extend_from_slice(&ar_header_raw(&padded_identifier("//"), absurd_size));
        // No table payload follows — the refusal must happen before any of
        // it is expected, so there is nothing to supply.

        let mut ar = open_guarded(bytes, stuffr_core::PROBE_LEN);
        let err = ar
            .next_entry()
            .expect_err("an absurd GNU name-table size must be refused");

        assert!(
            matches!(err, Error::ResourceLimit(_)),
            "an implausible declared table length is this build refusing to allocate, not a \
             verdict that the file is damaged — see MAX_GNU_NAME_TABLE_LEN's doc; got {err:?}"
        );
        assert_eq!(err.exit_code(), 6, "ResourceLimit is exit 6: {err:?}");
        let msg = err.to_string();
        assert!(
            msg.contains(&absurd_size.to_string()),
            "the message must name the declared size, got: {msg}"
        );
    }

    /// The failing-first test for Task 5d's second site: an absurd BSD
    /// extended identifier length, same shape as the name-table test above.
    #[test]
    fn refuses_an_absurd_bsd_identifier_length_before_the_allocation_it_would_size() {
        let absurd_len: u64 = 8_000_000_000;
        let mut bytes = GLOBAL_HEADER.to_vec();
        bytes.extend_from_slice(&ar_header_raw(
            &bsd_ext_identifier_field(absurd_len),
            absurd_len,
        ));
        // No identifier/payload bytes follow — same reasoning as above.

        let mut ar = open_guarded(bytes, stuffr_core::PROBE_LEN);
        let err = ar
            .next_entry()
            .expect_err("an absurd BSD extended identifier length must be refused");

        assert!(
            matches!(err, Error::ResourceLimit(_)),
            "an implausible declared identifier length is this build refusing to allocate, not \
             a verdict that the file is damaged — see MAX_BSD_IDENTIFIER_LEN's doc; got {err:?}"
        );
        assert_eq!(err.exit_code(), 6, "ResourceLimit is exit 6: {err:?}");
        let msg = err.to_string();
        assert!(
            msg.contains(&absurd_len.to_string()),
            "the message must name the declared length, got: {msg}"
        );
    }

    /// The regression guard for the name-table test: a header naming a size
    /// UNDER the ceiling must still fail (there is no table data behind it),
    /// but as ordinary corruption — exit 5 — never `ResourceLimit`. Pins
    /// that the new check is bounded by `MAX_GNU_NAME_TABLE_LEN`, not "any
    /// name-table size with no data behind it."
    #[test]
    fn a_modest_gnu_name_table_size_with_no_data_behind_it_is_corrupt_not_resource_limited() {
        let mut bytes = GLOBAL_HEADER.to_vec();
        bytes.extend_from_slice(&ar_header_raw(&padded_identifier("//"), 64));
        // No table payload follows: truncated, not oversized.

        let mut ar = open(&bytes);
        let err = ar
            .next_entry()
            .expect_err("a truncated name table must still fail");
        assert_eq!(
            err.exit_code(),
            5,
            "a small, merely-truncated size is corruption, not a resource ceiling: {err:?}"
        );
    }

    /// The regression guard for the BSD identifier test, mirroring the one
    /// above.
    #[test]
    fn a_modest_bsd_identifier_length_with_no_data_behind_it_is_corrupt_not_resource_limited() {
        let mut bytes = GLOBAL_HEADER.to_vec();
        bytes.extend_from_slice(&ar_header_raw(&bsd_ext_identifier_field(64), 64));
        // No identifier bytes follow: truncated, not oversized.

        let mut ar = open(&bytes);
        let err = ar
            .next_entry()
            .expect_err("a truncated BSD extended identifier must still fail");
        assert_eq!(
            err.exit_code(),
            5,
            "a small, merely-truncated length is corruption, not a resource ceiling: {err:?}"
        );
    }

    /// A legitimate, REAL-shaped large GNU name table must still round
    /// trip. Guards against the obvious way to get this wrong: picking a
    /// ceiling so tight it refuses real archives, which this project has
    /// shipped before (see `CLAUDE.md`'s running count of checks that fired
    /// on legitimate input). Sized past the largest table actually measured
    /// on this machine (27,616 bytes — see the module doc) and far under
    /// `MAX_GNU_NAME_TABLE_LEN`. This container's own writer never produces
    /// the GNU variant (see `write_safe_identifier`'s doc), so the fixture
    /// is hand-built rather than round-tripped through `build_ar`.
    #[test]
    fn a_legitimate_large_gnu_name_table_still_round_trips() {
        let mut table = Vec::new();
        for i in 0..1000u32 {
            table.extend_from_slice(
                format!("a-fairly-long-object-file-name-{i:04}.o/\n").as_bytes(),
            );
        }
        if !table.len().is_multiple_of(2) {
            table.push(b'\n'); // even-align, the same convention a real GNU writer uses
        }
        assert!(
            table.len() > 27_616,
            "fixture must exceed the largest real name table measured"
        );
        assert!(
            (table.len() as u64) < MAX_GNU_NAME_TABLE_LEN,
            "fixture must stay comfortably under the ceiling"
        );

        let mut bytes = GLOBAL_HEADER.to_vec();
        bytes.extend_from_slice(&ar_header_raw(&padded_identifier("//"), table.len() as u64));
        bytes.extend_from_slice(&table);
        // One ordinary entry afterward: a short GNU-style name, stored
        // inline and terminated with `/` rather than referencing the table.
        bytes.extend_from_slice(&ar_header_raw(&padded_identifier("a.txt/"), 5));
        bytes.extend_from_slice(b"hello");
        bytes.push(b'\n'); // size 5 is odd: one pad byte follows

        let mut ar = open(&bytes);
        let mut entry = ar
            .next_entry()
            .expect("a legitimate large name table must not be refused")
            .expect("must yield the one real entry");
        assert_eq!(entry.meta().name, "a.txt");
        let mut got = Vec::new();
        entry.reader().read_to_end(&mut got).unwrap();
        assert_eq!(got, b"hello");
        drop(entry);
        assert!(
            ar.next_entry().unwrap().is_none(),
            "must be exactly one real entry"
        );
    }
}
