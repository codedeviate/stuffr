//! `ar` salvage: walks the archive's members IN ORDER from the start, exactly
//! as the ordinary reader does, and stops at the first one it cannot read —
//! and says so, because this scanner cannot do what every other one here
//! does.
//!
//! The eighth scanner on the shared [`stuffr_core::salvage`] machinery, and
//! the last of Salvage Stage 3's three checksumless containers. **This
//! module's deliverable is as much a limitation as a scanner.**
//!
//! # Why this scanner does not search, and what that costs
//!
//! Every other scanner in this tree finds its records by testing offsets for
//! a header that clears a plausibility gate, so a destroyed record costs only
//! itself. `ar` cannot be scanned that way. A member header is sixty bytes of
//! ASCII — a 16-byte name, five decimal or octal fields, and a two-byte
//! `` `\n `` terminator — and the terminator is the ONLY fixed marker it
//! carries. Two bytes is one chance in 65,536 per offset: a scan anchored on
//! it would stop about sixteen times in every mebibyte of ordinary data, and
//! the fields behind it (digits and spaces) are exactly what text, source
//! code and other archives' headers are full of. Such a scan would report
//! noise as entries — which the salvage spec calls worse than no scanner at
//! all — and `ar` carries no checksum anywhere with which to tell the two
//! apart afterwards.
//!
//! So [`ArSalvage`] walks. What that recovers and what it cannot:
//!
//! - **A truncated tail — the common damage — is recovered fully.** Every
//!   member before the cut is reported `Unattested`; a member whose payload
//!   the cut runs through is `Partial` and its genuine surviving prefix is
//!   written as `NAME.partial`, never padded; a cut inside a member's
//!   HEADER, its BSD `#1/N` name or a GNU `//` table ends the walk with a
//!   [`WalkStopKind::CutShort`] stop — the reader ran out of bytes inside
//!   that record, so nothing can follow it.
//! - **A hole in the middle cannot be survived.** The walk stops at the
//!   first header that does not read, and every member after it is
//!   **unreachable by construction — not absent**. The run says exactly
//!   that, with the offset, through a [`WalkStopKind::Unreadable`]
//!   [`WalkStop`] the CLI prints on stderr for `--list`, `-C` and `-o`
//!   alike. A user who gets three of ten entries is told the other seven
//!   were never looked for, rather than left to conclude they are gone.
//!
//! A walk stop is NOT a [`stuffr_core::salvage::Sighting`]: a sighting is a
//! real header the scan saw and could not gate, and this is the opposite — a
//! place where nothing could be read as a header at all. See
//! [`WalkStop`]'s own doc.
//!
//! # One reader, not a second parser
//!
//! The walk is the ORDINARY reader: `ar::Archive` over `ar.rs`'s own
//! [`ArGuardedReader`], so what this scanner accepts as a member header is,
//! by construction, exactly what `stuffr list` accepts — GNU long-name tables
//! (`//` and `/N`), BSD `#1/N` extended names, both symbol-table shapes
//! skipped, the `\n` pad byte after an odd-sized member checked. And the two
//! ceilings the guard owns (the GNU name table at 16 MiB, a BSD identifier at
//! 65,536 bytes) are enforced by the guard itself, before the crate
//! allocates, with no second copy of either figure here. The one thing the
//! crate does not expose is WHERE each member lies, so the guard reports its
//! record boundaries through a [`GuardObserver`]; it already finds them to
//! do its own job, so that adds no mirrored fact of its own about
//! `ar = "=0.9.0"` (the list is in `Cargo.toml`'s ar pin note).
//!
//! **A refusal is a stop, never an `Err`.** Whatever makes `stuffr list` fail
//! on a member — a field that does not parse, a pad byte that is not `\n`, a
//! ceiling the guard refuses, a `/N` past the name table, the file ending
//! inside a record — ends the walk with that reason as the stop's cause, and
//! everything read before it is reported. Only a failure of the SOURCE itself
//! (an I/O error no archive's bytes can produce) is an `Err`.
//!
//! **Two refusals are claims about this BUILD, exit 3, never a stop over a
//! possibly healthy archive** (fix round 1):
//!
//! - A GNU **thin** archive (`!<thin>\n`) keeps each member's content in a
//!   separate file, so the bytes after a header are the next header. Walked
//!   as an ordinary archive, they would be written as a member's content.
//! - A **symbol table** (`/`, `/SYM64/`, `__.SYMDEF`, `__.SYMDEF SORTED`;
//!   `ar.rs`'s `symbol_table_name` owns the list) whose header `ar 0.9.0`
//!   cannot parse ends the walk with a [`WalkStopKind::UnsupportedShape`]
//!   stop naming it; with nothing recovered before it, the run is exit 3
//!   rather than "nothing recoverable". The case that motivated it — GNU
//!   `ar rcs` on Mach-O writing `__.SYMDEF` with a blank mode — no longer
//!   reaches it: since 0.8.1 `ar.rs`'s guard normalises that mode, so the
//!   walk reads the table like `stuffr list` does (an inline one is a
//!   member whose mode is unknown). What still stops here is a symbol table
//!   damaged in a way the guard does not normalise, and GNU's `/SYM64/`,
//!   which the crate cannot read at all.
//!
//! Any other global header that is not `!<arch>\n` is the ordinary reader's
//! refusal: a stop at offset 0 and nothing recovered. An earlier version
//! served `!<arch>\n` whatever the file held; that fabricated member content
//! from thin archives, and was removed.
//!
//! # `ar` is `Unattested`, never `Complete`
//!
//! **`ar` records no checksum of any kind** — nothing over a member's
//! content, and nothing over its header (tar at least sums each header
//! block). A header that parses is not thereby shown to be a real member,
//! so every whole member is [`SalvageStatus::Unattested`]: written under its
//! real name, tagged on its row, exit 4 — the tier
//! `stuffr_core::testing::check_salvage_claim` permits for
//! `Attestation::Nothing`, and the only one. A damaged SIZE field that still
//! parses is the sharpest case of that: the walk believes it, as `list`
//! does, and either lands inside the next member's bytes (and stops there,
//! saying so) or runs the member past the end of the file (and reports it
//! `Partial`, the same shape a genuinely cut file takes — no evidence in the
//! format tells the two apart).
//!
//! # The whole-entry ceiling: none of this scanner's own
//!
//! [`ArSalvage::max_whole_entry`] is `u64::MAX`: members are stored, and
//! [`write_payload`] streams them through `stream_bounded_copy`, so no
//! payload length sizes a buffer. The only header fields that do — the two
//! the guard bounds — are refused before the crate reads them.

use std::cell::Cell;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::rc::Rc;

use stuffr_core::salvage::{
    Candidate, SalvageOutcome, SalvagePolicy, SalvageScan, SalvageStatus, SalvagedEntry,
    UnverifiedCause, WalkStop, WalkStopKind, salvage_all, stream_bounded_copy,
};
use stuffr_core::{Error, FormatId, Result, SeekRead};

use crate::ar::{
    AR, AR_ENTRY_HEADER_LEN, ArGuardedReader, GuardObserver, NameField, entry_meta, name_field,
    symbol_table_name, trim_extended_name,
};

/// The codec an `ar` member carries in [`stuffr_core::EntryMeta::codec`].
/// **Setting it at all is load-bearing**: `entries.rs` hands it to
/// [`write_payload`], which refuses anything else, and an unset codec would
/// make every entry a silent `SkippedNotBuiltIn` — the exact defect ARC
/// shipped in Salvage Stage 2.
pub const STORED: FormatId = FormatId::new("ar-stored");

/// What the walk needs from [`ArGuardedReader`] — see [`GuardObserver`]
/// for exactly when each is reported.
#[derive(Debug, Clone, Copy, Default)]
struct Marks {
    /// Where the header the crate most recently started to read begins.
    header_at: u64,
    /// Where the last record read whole ends.
    record_end: u64,
    /// Whether the guard rewrote the blank mode of the header the crate
    /// read last, so the member's mode is unknown — `ar.rs`'s
    /// `NORMALISED_MODE`.
    mode_unknown: bool,
}

/// A [`GuardObserver`] the walk can still read while `ar::Archive` owns the
/// guard: the crate exposes no way back to its reader, so the marks live
/// behind a shared cell.
#[derive(Debug, Clone, Default)]
struct SharedMarks(Rc<Cell<Marks>>);

impl SharedMarks {
    fn get(&self) -> Marks {
        self.0.get()
    }
}

impl GuardObserver for SharedMarks {
    fn header_starts(&mut self, at: u64) {
        let mut marks = self.0.get();
        marks.header_at = at;
        self.0.set(marks);
    }

    fn record_ends(&mut self, at: u64) {
        let mut marks = self.0.get();
        marks.record_end = at;
        self.0.set(marks);
    }

    fn header_scanned(&mut self, mode_unknown: bool) {
        let mut marks = self.0.get();
        marks.mode_unknown = mode_unknown;
        self.0.set(marks);
    }
}

/// The source as the walk reads it: the file from offset 0, counting what it
/// hands out (the guard reads exactly what the crate consumes, so after
/// `next_entry` returns a member this is that member's payload offset).
///
/// It served the global header as `!<arch>\n` whatever the file held until
/// fix round 1 (I2): those eight bytes carry one fact, `!<thin>\n`, and
/// overwriting it read a healthy GNU thin archive's next header as a
/// member's content. The file's own bytes are what the crate sees now.
struct WalkSource<'a> {
    src: &'a mut dyn SeekRead,
    pos: Rc<Cell<u64>>,
}

impl Read for WalkSource<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.src.read(buf)?;
        self.pos.set(self.pos.get() + n as u64);
        Ok(n)
    }
}

/// A GNU thin archive's global header. Its members' contents live in other
/// files, named by each header, so the bytes after a header are the NEXT
/// header — never a payload.
const THIN_GLOBAL_HEADER: &[u8; 8] = b"!<thin>\n";

/// Which symbol table, if any, the member header at `offset` names. Read
/// straight from the file, after the walk has stopped there: the crate
/// refused the header, so there is no parsed identifier to consult. The
/// names themselves are `ar.rs`'s ([`symbol_table_name`]), the list the
/// guard normalises from.
fn symbol_table_at(src: &mut dyn SeekRead, offset: u64, file_len: u64) -> Option<&'static str> {
    let header = read_at(src, offset, AR_ENTRY_HEADER_LEN as u64, file_len)?;
    match name_field(&header) {
        NameField::Inline(identifier) => symbol_table_name(&identifier),
        NameField::NotASymbolTable => None,
        NameField::Extended(len) => {
            let bytes = read_at(src, offset + AR_ENTRY_HEADER_LEN as u64, len, file_len)?;
            symbol_table_name(trim_extended_name(&bytes))
        }
    }
}

/// `len` bytes at `at`, or `None` if the source does not hold them all (or
/// cannot be read). Every caller has bounded `len` first.
fn read_at(src: &mut dyn SeekRead, at: u64, len: u64, file_len: u64) -> Option<Vec<u8>> {
    if at.checked_add(len)? > file_len {
        return None;
    }
    src.seek(SeekFrom::Start(at)).ok()?;
    let mut bytes = vec![0u8; usize::try_from(len).ok()?];
    src.read_exact(&mut bytes).ok()?;
    Some(bytes)
}

/// Everything one walk found: the members, in order, and where it stopped
/// short of the end, if it did.
struct Walk {
    candidates: Vec<Candidate>,
    stop: Option<WalkStop>,
}

/// Walks every member of the archive in `src`, in order — see the module
/// doc. `Err` for a failure of the source itself, and for a GNU thin archive
/// (exit 3), which is not a shape this walk can read at all.
fn walk(src: &mut dyn SeekRead) -> Result<Walk> {
    let file_len = src.seek(SeekFrom::End(0))?;
    if read_at(src, 0, THIN_GLOBAL_HEADER.len() as u64, file_len).as_deref()
        == Some(THIN_GLOBAL_HEADER.as_slice())
    {
        return Err(Error::Unsupported(
            "this is a GNU thin archive (`!<thin>`): each member's content lives in a \
             separate file its header names, not in the archive, and this build's ar \
             salvage does not read thin archives"
                .to_string(),
        ));
    }
    src.seek(SeekFrom::Start(0))?;
    let pos = Rc::new(Cell::new(0u64));
    let marks = SharedMarks::default();
    let mut candidates = Vec::new();
    // The failure, if the walk stopped early, and the marks at that moment.
    // Decided after `archive` is gone, since classifying it re-reads the
    // source the archive borrows.
    let failure: Option<(io::Error, Marks)> = {
        let guard = ArGuardedReader::observed(
            WalkSource {
                src: &mut *src,
                pos: Rc::clone(&pos),
            },
            marks.clone(),
        );
        let mut archive = ar::Archive::new(guard);
        loop {
            match archive.next_entry() {
                None => break None,
                // Dropped at the end of this arm, which is when the crate
                // drains whatever of the payload is present — the walk reads
                // nothing of it itself.
                Some(Ok(entry)) => {
                    let Marks {
                        header_at,
                        mode_unknown,
                        ..
                    } = marks.get();
                    let payload_start = pos.get();
                    candidates.push(candidate(
                        entry.header(),
                        mode_unknown,
                        header_at,
                        payload_start,
                        file_len,
                    ));
                }
                Some(Err(e)) => break Some((e, marks.get())),
            }
        }
    };
    let stop = match failure {
        None => None,
        Some((e, at)) => {
            let offset = at.header_at.max(at.record_end);
            let remaining = file_len.saturating_sub(offset);
            let cause = e.to_string();
            let kind = match e.kind() {
                // The file ended inside the record at `offset` — a cut
                // header, a cut `#1/N` name, a cut `//` table — so every byte
                // from there on belongs to that one incomplete record
                // (fix round 1, I1: this was decided by bytes remaining, and
                // a cut name after a whole 60-byte header read as a hole).
                io::ErrorKind::UnexpectedEof => WalkStopKind::CutShort,
                // A field that does not parse, a bad pad byte or a `/N` past
                // the name table (`InvalidData`), or a ceiling the guard
                // refused before the crate could allocate (`OutOfMemory`).
                io::ErrorKind::InvalidData | io::ErrorKind::OutOfMemory => {
                    if remaining < AR_ENTRY_HEADER_LEN as u64 {
                        WalkStopKind::CutShort
                    } else if e.kind() == io::ErrorKind::InvalidData
                        && let Some(table) = symbol_table_at(src, offset, file_len)
                    {
                        return Ok(Walk {
                            candidates,
                            stop: Some(WalkStop::new(
                                AR,
                                offset,
                                remaining,
                                WalkStopKind::UnsupportedShape,
                                format!(
                                    "the archive's symbol table (`{table}`) has a header this \
                                     build's ar reader cannot parse ({cause})"
                                ),
                            )),
                        });
                    } else {
                        WalkStopKind::Unreadable
                    }
                }
                // No archive's bytes produce any other kind: this is the
                // source failing, which is a fault of the run.
                _ => return Err(Error::from(e)),
            };
            Some(WalkStop::new(AR, offset, remaining, kind, cause))
        }
    };
    Ok(Walk { candidates, stop })
}

/// The candidate for one member the crate read, with the fields `ar.rs`'s own
/// `entry_meta` reports.
fn candidate(
    header: &ar::Header,
    mode_unknown: bool,
    offset: u64,
    payload_start: u64,
    file_len: u64,
) -> Candidate {
    let size = header.size();
    // `Some(n)` always means `n < declared_len`, per the field's contract.
    let available_len = match payload_start.checked_add(size) {
        Some(end) if end <= file_len => None,
        _ => Some(file_len.saturating_sub(payload_start)),
    };
    let mut meta = entry_meta(header, mode_unknown);
    meta.compressed_size = Some(size);
    meta.codec = Some(STORED);
    // No verifier: `ar` has none, which is also why no two members are ever
    // proven shadows of each other (only name collisions are reported).
    Candidate::new(offset, payload_start, meta)
        .with_declared_len(Some(size))
        .with_available_len(available_len)
}

/// Walks an `ar` archive member by member — see the module doc. The walk
/// runs once, on the first call to [`SalvageScan::next_candidate`], and the
/// members it found are handed out in order after that; the engine's `from`
/// is not consulted, because a sequential walk has nowhere else to resume.
#[derive(Debug, Default)]
pub struct ArSalvage {
    walked: bool,
    queue: VecDeque<Candidate>,
    stop: Option<WalkStop>,
}

impl ArSalvage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Where the walk stopped short of the end of the source, once it has
    /// run — see [`WalkStop`].
    pub fn walk_stop(&self) -> Option<&WalkStop> {
        self.stop.as_ref()
    }
}

impl SalvageScan for ArSalvage {
    fn next_candidate(&mut self, src: &mut dyn SeekRead, _from: u64) -> Result<Option<Candidate>> {
        if !self.walked {
            let Walk { candidates, stop } = walk(src)?;
            self.queue = candidates.into();
            self.stop = stop;
            self.walked = true;
        }
        Ok(self.queue.pop_front())
    }

    /// `u64::MAX`: this scanner imposes no ceiling of its own — see the
    /// module doc's last section.
    fn max_whole_entry(&self) -> u64 {
        u64::MAX
    }

    /// `Unattested` for a member whose every declared byte is present —
    /// never `Complete`, which would assert a header self-check `ar` does
    /// not have — and `Partial` for one the end of the file cuts through.
    /// Never `Err`.
    fn verify(&self, _src: &mut dyn SeekRead, candidate: &Candidate) -> Result<SalvageStatus> {
        Ok(verify_candidate(candidate))
    }

    fn write_payload(
        &self,
        archive_path: &Path,
        entry: &SalvagedEntry,
        compressed_len: u64,
        out: &mut dyn Write,
    ) -> Result<bool> {
        write_payload(archive_path, entry, compressed_len, out)
    }
}

/// Decides [`SalvageStatus`] for one candidate. See [`ArSalvage::verify`].
fn verify_candidate(candidate: &Candidate) -> SalvageStatus {
    if candidate.available_len.is_some() {
        SalvageStatus::Partial
    } else if candidate.meta.codec != Some(STORED) {
        // Unreachable from this scanner's own candidates (`candidate` always
        // sets `STORED`); kept so a candidate built elsewhere cannot be
        // called `Unattested` for bytes this writer would refuse.
        SalvageStatus::Unverified(UnverifiedCause::UndecodableMethod)
    } else {
        SalvageStatus::Unattested
    }
}

/// Writes one member's stored payload to `out`, answering whether every
/// declared byte was written. The read is bounded by what the SOURCE holds,
/// so a truncated member's genuine surviving prefix is written — and only
/// that: nothing pads it to the declared length.
pub fn write_payload(
    archive_path: &Path,
    entry: &SalvagedEntry,
    compressed_len: u64,
    out: &mut dyn Write,
) -> Result<bool> {
    // Refused BEFORE `archive_path` is opened — `entries.rs`'s
    // `salvage_caps_tests` probes every salvage-capable container with a
    // codec-less entry and a path that does not exist.
    if entry.meta.codec != Some(STORED) {
        return Err(Error::Unsupported(format!(
            "entry `{}` carries codec {:?}; this build's ar salvage writer writes stored \
             members only",
            entry.meta.name, entry.meta.codec
        )));
    }
    // Not `unwrap_or(0)`: with an expected length of 0, `stream_bounded_copy`
    // reports success having written nothing.
    let Some(expected) = entry.meta.size else {
        return Err(Error::Corrupt(format!(
            "entry `{}` carries no declared size; this scanner sets one for every candidate, \
             so its own invariant does not hold for this entry",
            entry.meta.name
        )));
    };
    let mut f = File::open(archive_path)?;
    let Ok(file_len) = f.seek(SeekFrom::End(0)) else {
        return Ok(false);
    };
    if f.seek(SeekFrom::Start(entry.payload_start)).is_err() {
        return Ok(false);
    }
    let readable_len = compressed_len.min(file_len.saturating_sub(entry.payload_start));
    let truncated = readable_len < compressed_len;
    let completed = stream_bounded_copy((&mut f).take(readable_len), expected, out)?;
    Ok(completed && !truncated)
}

/// Runs [`ArSalvage`] over `src` and annotates the result — the whole
/// scanner, matching every other format's `salvage_*` entry point — with the
/// walk's stop, if it made one, on [`SalvageOutcome::walk_stop`].
pub fn salvage_ar(src: &mut dyn SeekRead, policy: &SalvagePolicy) -> Result<SalvageOutcome> {
    let mut scanner = ArSalvage::new();
    let mut outcome = salvage_all(&mut scanner, src, policy)?;
    let stop = scanner.stop.take();
    // Fix round 1, I3: nothing recovered, and the walk stopped at a record
    // it RECOGNISES in a shape this build cannot read — a claim about this
    // BUILD (exit 3), never "nothing recoverable" about the archive (exit 5),
    // which may be perfectly healthy. A mixed run keeps its ordinary code
    // and carries the stop for the note (Ruling S-X).
    if outcome.entries.is_empty()
        && let Some(stop) = &stop
        && stop.kind == WalkStopKind::UnsupportedShape
    {
        return Err(Error::Unsupported(format!(
            "this build's ar salvage scanner stopped at offset {} before recovering anything: \
             {}. That is a shape this build does not read, so this says nothing about damage \
             — the archive may be perfectly healthy",
            stop.offset, stop.cause
        )));
    }
    outcome.walk_stop = stop;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use stuffr_core::salvage::describe_walk_stop;
    use stuffr_core::testing::SharedBuf;
    use stuffr_core::{
        Container, CreateOpts, EntryMeta, OpenOpts, PlainSink, ReaderSource, Source,
    };

    use super::*;
    use crate::ar::{Ar, GLOBAL_HEADER};

    fn scan(bytes: &[u8]) -> SalvageOutcome {
        salvage_ar(&mut Cursor::new(bytes.to_vec()), &SalvagePolicy::default())
            .expect("an ar walk over in-memory bytes must never be an Err — a refusal is a stop")
    }

    fn names_and_statuses(out: &SalvageOutcome) -> Vec<(String, SalvageStatus)> {
        out.entries
            .iter()
            .map(|e| (e.meta.name.clone(), e.status))
            .collect()
    }

    // -------------------------------------------------------------------
    // Fixture builders.
    //
    // `build_ar` writes through `ar.rs`'s own writer (the `ar` crate's
    // `Builder`), so a test standing on it proves agreement with that crate
    // and nothing more; `member` builds one header by hand, for shapes no
    // writer produces. The reference-writer tests at the end are the
    // independent witnesses.
    // -------------------------------------------------------------------

    fn build_ar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let buf = SharedBuf::new();
        let mut w = Ar
            .create(
                PlainSink::new(Box::new(buf.clone())),
                &CreateOpts::default(),
            )
            .expect("create");
        for (name, data) in entries {
            w.add(&EntryMeta::file(*name), &mut Cursor::new(*data))
                .expect("add");
        }
        w.finish().expect("finish").finish().expect("finish sink");
        buf.contents()
    }

    /// One hand-built member: a 16-byte identifier field (space-padded),
    /// placeholder fields, `size` as declared, then `data` and its pad byte.
    fn member(identifier: &[u8], size: u64, data: &[u8]) -> Vec<u8> {
        assert!(identifier.len() <= 16, "fixture identifier too long");
        let mut out = identifier.to_vec();
        out.resize(16, b' ');
        out.extend_from_slice(
            format!("{:<12}{:<6}{:<6}{:<8}{:<10}`\n", 0, 0, 0, "100644", size).as_bytes(),
        );
        assert_eq!(out.len(), AR_ENTRY_HEADER_LEN);
        out.extend_from_slice(data);
        if data.len() % 2 == 1 {
            out.push(b'\n');
        }
        out
    }

    /// One header alone, with no payload behind it — a thin archive's shape.
    fn member_header(identifier: &[u8], size: u64) -> Vec<u8> {
        let mut out = member(identifier, 0, b"");
        out[48..58].copy_from_slice(format!("{size:<10}").as_bytes());
        out
    }

    /// One member whose MODE field (`[40..48]`, `ar-0.9.0/src/lib.rs:292`)
    /// is `mode`: all spaces is GNU `ar rcs`'s Mach-O `__.SYMDEF` (fix round
    /// 1, I3), which the guard normalises on a symbol table since 0.8.1;
    /// anything else that is not octal, the crate still refuses.
    fn mode_member(identifier: &[u8], data: &[u8], mode: &[u8; 8]) -> Vec<u8> {
        let mut out = member(identifier, data.len() as u64, data);
        out[40..48].copy_from_slice(mode);
        out
    }

    const BLANK_MODE: &[u8; 8] = &[b' '; 8];
    /// A mode the guard does NOT normalise: not blank, and not octal.
    const BAD_MODE: &[u8; 8] = b"zzzzzzzz";

    /// The `#1/20` member carrying `__.SYMDEF SORTED` as its name, plus a
    /// four-byte table, with the given mode.
    fn extended_symbol_table(mode: &[u8; 8]) -> Vec<u8> {
        let mut ext = b"__.SYMDEF SORTED".to_vec();
        ext.resize(20, 0);
        let mut body = ext;
        body.extend_from_slice(b"\0\0\0\0");
        let mut id = b"#1/".to_vec();
        id.extend_from_slice(format!("{:<13}", 20).as_bytes());
        mode_member(&id, &body, mode)
    }

    /// Header offsets of every member of an archive this module did NOT
    /// read — each header's own size field, plus the pad rule — so a test
    /// can place damage without asking the code under test where things are.
    /// Plain (non-extended) names only, which is every fixture it serves.
    fn member_offsets(bytes: &[u8]) -> Vec<usize> {
        let mut at = GLOBAL_HEADER.len();
        let mut out = Vec::new();
        while at + AR_ENTRY_HEADER_LEN <= bytes.len() {
            out.push(at);
            let size: usize = std::str::from_utf8(&bytes[at + 48..at + 58])
                .unwrap()
                .trim_end()
                .parse()
                .unwrap();
            at += AR_ENTRY_HEADER_LEN + size + size % 2;
        }
        out
    }

    /// One member as the ordinary reader reports it: name, size, bytes.
    fn read_through_the_reader(bytes: &[u8]) -> Result<Vec<(String, u64, Vec<u8>)>> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(Cursor::new(bytes.to_vec())));
        let resolved =
            stuffr_core::resolve(src, AR, Ar.caps(), &stuffr_core::StreamPolicy::default())?;
        let mut ar = Ar.open(resolved, &OpenOpts::default())?;
        let mut out = Vec::new();
        while let Some(mut entry) = ar.next_entry()? {
            let meta = entry.meta().clone();
            let mut data = Vec::new();
            entry.reader().read_to_end(&mut data)?;
            out.push((meta.name, meta.size.unwrap_or(0), data));
        }
        Ok(out)
    }

    struct TempArchive(std::path::PathBuf);

    impl TempArchive {
        fn new(bytes: &[u8]) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "stuffr-ar-salvage-{}-{}.a",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::write(&path, bytes).expect("write temp archive");
            TempArchive(path)
        }
    }

    impl Drop for TempArchive {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// Every entry of `outcome` written back out through [`write_payload`]:
    /// `(name, bytes, completed)`.
    fn write_back(bytes: &[u8], outcome: &SalvageOutcome) -> Vec<(String, Vec<u8>, bool)> {
        let archive = TempArchive::new(bytes);
        outcome
            .entries
            .iter()
            .map(|entry| {
                let mut out = Vec::new();
                let completed = write_payload(
                    &archive.0,
                    entry,
                    entry
                        .meta
                        .compressed_size
                        .expect("every candidate declares one"),
                    &mut out,
                )
                .expect("a stored member must write");
                (entry.meta.name.clone(), out, completed)
            })
            .collect()
    }

    const FIVE: [(&str, &[u8]); 5] = [
        ("one.txt", b"first member\n"),
        ("two.txt", b"second"),
        ("three.txt", b"third member, odd"),
        ("four.txt", b"fourth"),
        ("five.txt", b"fifth and last\n"),
    ];

    // -------------------------------------------------------------------
    // Step 1: the limitation, pinned before the capability.
    // -------------------------------------------------------------------

    /// **The brief's first test.** An `ar` with a hole in the middle must
    /// report what precedes the hole, must NOT report anything after it, and
    /// the run must state why.
    ///
    /// Not vacuous in either direction: the members after the hole are
    /// asserted to be INTACT on disk (a scanner that resynchronised on the
    /// two-byte terminator would find them, which is exactly what this
    /// scanner must not do), and the ordinary reader is asserted to refuse
    /// the archive (so there is something here to salvage at all).
    #[test]
    fn a_hole_in_the_middle_reports_what_precedes_it_and_says_why_nothing_after() {
        let bytes = build_ar(&FIVE);
        let offsets = member_offsets(&bytes);
        assert_eq!(offsets.len(), 5);
        let hole = offsets[2];
        let mut damaged = bytes.clone();
        damaged[hole + 48..hole + 58].copy_from_slice(b"garbage!!!");

        for (i, &at) in offsets.iter().enumerate().skip(3) {
            assert_eq!(&damaged[at + 58..at + 60], b"`\n", "member {i} is intact");
            assert!(damaged[at..at + 16].starts_with(FIVE[i].0.as_bytes()));
        }
        assert!(
            read_through_the_reader(&damaged).is_err(),
            "the ordinary reader must refuse the holed archive"
        );

        let out = scan(&damaged);
        assert_eq!(
            names_and_statuses(&out),
            vec![
                ("one.txt".to_string(), SalvageStatus::Unattested),
                ("two.txt".to_string(), SalvageStatus::Unattested),
            ],
            "what precedes the hole, and nothing after it"
        );
        let stop = out
            .walk_stop
            .as_ref()
            .expect("a walk that stopped at a hole must say so");
        assert_eq!(stop.offset, hole as u64);
        assert_eq!(stop.remaining, (damaged.len() - hole) as u64);
        assert_eq!(stop.kind, WalkStopKind::Unreadable);
        let note = describe_walk_stop(stop);
        for needle in [
            format!("offset {hole}"),
            "unreachable by construction".to_string(),
            "not absent".to_string(),
            "file size".to_string(),
        ] {
            assert!(note.contains(&needle), "missing {needle:?}: {note}");
        }
    }

    // -------------------------------------------------------------------
    // What the walk recovers
    // -------------------------------------------------------------------

    /// Healthy: every member, name for name and byte for byte, agreeing with
    /// the ordinary reader exactly, each `Unattested`, and no stop.
    #[test]
    fn a_healthy_archive_agrees_with_the_reader_and_every_member_is_unattested() {
        let long = "a-member-name-longer-than-sixteen-bytes.txt";
        let entries: [(&str, &[u8]); 4] = [
            ("a.txt", b"alpha"),
            ("dir/nested.bin", b"\x00\xff\x00"),
            (long, b"long"),
            ("empty", b""),
        ];
        let bytes = build_ar(&entries);
        let out = scan(&bytes);
        assert!(out.walk_stop.is_none(), "{:?}", out.walk_stop);
        let written = write_back(&bytes, &out);
        let reader = read_through_the_reader(&bytes).unwrap();
        assert_eq!(
            written
                .iter()
                .map(|(n, d, _)| (n.clone(), d.len() as u64, d.clone()))
                .collect::<Vec<_>>(),
            reader
        );
        assert!(written.iter().all(|(_, _, done)| *done));
        assert!(
            out.entries
                .iter()
                .all(|e| e.status == SalvageStatus::Unattested)
        );
        // The header offset is where the member's header really is.
        for e in &out.entries {
            let at = e.offset as usize;
            assert_eq!(&bytes[at + 58..at + 60], b"`\n", "{}", e.meta.name);
        }
    }

    /// A bare global header is a valid empty archive: nothing, and no stop.
    #[test]
    fn an_empty_archive_is_no_entries_and_no_stop() {
        let out = scan(GLOBAL_HEADER);
        assert!(out.entries.is_empty());
        assert!(out.walk_stop.is_none());
    }

    /// The common damage, at every cut point through the last member: a cut
    /// in its PAYLOAD reports it `Partial` with the genuine prefix and no
    /// stop; a cut in its HEADER ends the walk `CutShort`, never
    /// "unreachable". Everything before it is whole either way.
    #[test]
    fn a_truncated_tail_is_recovered_at_every_cut_point() {
        let bytes = build_ar(&FIVE);
        let last = *member_offsets(&bytes).last().unwrap();
        let payload = last + AR_ENTRY_HEADER_LEN;
        let data = FIVE[4].1;
        for cut in last + 1..payload + data.len() {
            let damaged = &bytes[..cut];
            let out = scan(damaged);
            let names: Vec<String> = out.entries.iter().map(|e| e.meta.name.clone()).collect();
            let written = write_back(damaged, &out);
            for (i, (name, body, done)) in written.iter().take(4).enumerate() {
                assert_eq!(
                    (name.as_str(), body.as_slice(), *done),
                    (FIVE[i].0, FIVE[i].1, true),
                    "cut {cut}"
                );
            }
            if cut < payload {
                assert_eq!(names.len(), 4, "cut {cut}: {names:?}");
                let stop = out.walk_stop.as_ref().expect("a cut header is a stop");
                assert_eq!(stop.kind, WalkStopKind::CutShort, "cut {cut}");
                assert_eq!(stop.offset, last as u64, "cut {cut}");
                assert!(!describe_walk_stop(stop).contains("unreachable"));
            } else {
                assert_eq!(names.len(), 5, "cut {cut}: {names:?}");
                assert!(out.walk_stop.is_none(), "cut {cut}: {:?}", out.walk_stop);
                assert_eq!(out.entries[4].status, SalvageStatus::Partial, "cut {cut}");
                let (_, body, done) = &written[4];
                assert!(!done, "cut {cut}");
                assert_eq!(body.as_slice(), &data[..cut - payload], "never padded");
            }
        }
    }

    /// A destroyed FIRST header: nothing is recovered, and the stop says the
    /// whole archive behind offset 8 was never reached — never an `Err`.
    #[test]
    fn a_destroyed_first_header_recovers_nothing_and_says_so() {
        let mut bytes = build_ar(&FIVE);
        bytes[8 + 16..8 + 28].copy_from_slice(b"not-a-time!!");
        let out = scan(&bytes);
        assert!(out.entries.is_empty());
        let stop = out.walk_stop.expect("a stop");
        assert_eq!(
            (stop.offset, stop.kind),
            (8, WalkStopKind::Unreadable),
            "{stop:?}"
        );
        assert!(stop.cause.contains("timestamp"), "{}", stop.cause);
    }

    /// The pad byte after an odd-sized member is checked, as the reader
    /// checks it — and the stop names the PAD's offset, not the header after
    /// it, since that header was never read.
    #[test]
    fn a_damaged_pad_byte_stops_the_walk_at_the_pad() {
        let bytes = build_ar(&FIVE);
        let offsets = member_offsets(&bytes);
        // `three.txt` is 17 bytes, so a pad byte precedes `four.txt`.
        let pad = offsets[3] - 1;
        assert_eq!(bytes[pad], b'\n');
        let mut damaged = bytes.clone();
        damaged[pad] = b'X';
        let out = scan(&damaged);
        assert_eq!(out.entries.len(), 3);
        let stop = out.walk_stop.expect("a stop");
        assert_eq!(stop.offset, pad as u64);
        assert!(stop.cause.contains("padding"), "{}", stop.cause);
    }

    /// Fix round 1, I2: the global header is taken from the file, not
    /// repaired. A damaged one is the ordinary reader's refusal — a stop at
    /// offset 0 and nothing recovered — because those eight bytes DO carry a
    /// fact (`!<thin>\n` is a different format), and overwriting them wrote
    /// a thin archive's next header as a member's content.
    #[test]
    fn a_damaged_global_header_is_not_walked_past() {
        let mut bytes = build_ar(&FIVE);
        bytes[..8].copy_from_slice(b"XXXXXXXX");
        let out = scan(&bytes);
        assert!(out.entries.is_empty(), "{:?}", names_and_statuses(&out));
        let stop = out.walk_stop.expect("a stop");
        assert_eq!(stop.offset, 0);
        assert!(stop.cause.contains("global header"), "{}", stop.cause);
    }

    /// A GNU thin archive (`!<thin>\n`) stores only each member's header —
    /// its content lives in another file — so reading one as an ordinary
    /// archive reports the next header as a member's bytes. It is a shape
    /// this build does not read: exit 3, naming it, and nothing written.
    #[test]
    fn a_thin_archive_is_refused_at_exit_3_naming_it() {
        let mut bytes = b"!<thin>\n".to_vec();
        bytes.extend(member_header(b"a.txt/", 18));
        bytes.extend(member_header(b"bb.bin/", 7));
        let err = salvage_ar(&mut Cursor::new(bytes), &SalvagePolicy::default())
            .expect_err("a thin archive is refused");
        assert_eq!(err.exit_code(), 3, "{err}");
        assert!(matches!(err, Error::Unsupported(_)), "{err:?}");
        assert!(err.to_string().contains("thin"), "{err}");
    }

    /// Fewer than eight bytes: the file ends inside the global header, which
    /// is a cut, not a hole.
    #[test]
    fn a_file_shorter_than_the_global_header_is_cut_short() {
        let out = scan(b"!<ar");
        assert!(out.entries.is_empty());
        let stop = out.walk_stop.expect("a stop");
        assert_eq!((stop.offset, stop.kind), (0, WalkStopKind::CutShort));
    }

    /// A GNU archive, built by hand the way GNU `ar` lays one out: a symbol
    /// table (`/`), a long-name table (`//`), `name/` short names and `/N`
    /// long ones. The walk resolves every name, skips both tables, and
    /// reports each member at its real header.
    #[test]
    fn a_gnu_long_name_table_is_resolved_and_both_tables_skipped() {
        let long_a = "first-long-member-name.o";
        let long_b = "second-long-member-name.o";
        let table = format!("{long_a}/\n{long_b}/\n");
        let mut bytes = GLOBAL_HEADER.to_vec();
        bytes.extend(member(b"/", 4, b"\0\0\0\0"));
        bytes.extend(member(b"//", table.len() as u64, table.as_bytes()));
        bytes.extend(member(b"short.o/", 3, b"abc"));
        let b_index = long_a.len() + 2;
        bytes.extend(member(b"/0", 5, b"AAAAA"));
        bytes.extend(member(format!("/{b_index}").as_bytes(), 2, b"BB"));

        let reader = read_through_the_reader(&bytes).unwrap();
        let out = scan(&bytes);
        assert!(out.walk_stop.is_none(), "{:?}", out.walk_stop);
        let written = write_back(&bytes, &out);
        assert_eq!(
            written
                .iter()
                .map(|(n, d, _)| (n.clone(), d.len() as u64, d.clone()))
                .collect::<Vec<_>>(),
            reader
        );
        assert_eq!(
            reader.iter().map(|r| r.0.as_str()).collect::<Vec<_>>(),
            ["short.o", long_a, long_b]
        );
        for e in &out.entries {
            let at = e.offset as usize;
            assert_eq!(&bytes[at + 58..at + 60], b"`\n", "{}", e.meta.name);
            assert_eq!(e.payload_start, e.offset + AR_ENTRY_HEADER_LEN as u64);
        }
    }

    /// A BSD `#1/N` member's payload starts after its name, and its header
    /// offset is still where the header is.
    #[test]
    fn a_bsd_extended_name_is_resolved_with_the_right_offsets() {
        let name = "a-name-that-needs-the-extended-form.txt";
        let bytes = build_ar(&[("a.txt", b"alpha"), (name, b"payload!")]);
        let out = scan(&bytes);
        let e = &out.entries[1];
        assert_eq!(e.meta.name, name);
        assert_eq!(&bytes[e.offset as usize..e.offset as usize + 3], b"#1/");
        let at = e.payload_start as usize;
        assert_eq!(&bytes[at..at + 8], b"payload!");
    }

    /// A `#1/N` member is padded by its WHOLE size, name included. The walk
    /// reads through `ar.rs`'s guard, which owns that rule; before the guard
    /// reconciled it with the crate's payload-only rule, an odd `N` threw
    /// the walk one byte off and it stopped at the member after. Every
    /// member is found, at its real offsets, byte-exact and `Unattested`.
    #[test]
    fn bsd_members_with_odd_names_are_walked_whole() {
        let mut bytes = GLOBAL_HEADER.to_vec();
        let mut headers = Vec::new();
        for (identifier, body) in [
            (&b"#1/3"[..], &b"abcABCD"[..]),
            (b"#1/5", b"helloHELLO"),
            (b"plain.txt", b"xyz"),
        ] {
            headers.push(bytes.len() as u64);
            bytes.extend(member(identifier, body.len() as u64, body));
        }
        let out = scan(&bytes);
        assert!(out.walk_stop.is_none(), "{:?}", out.walk_stop);
        assert_eq!(
            names_and_statuses(&out),
            [
                ("abc", SalvageStatus::Unattested),
                ("hello", SalvageStatus::Unattested),
                ("plain.txt", SalvageStatus::Unattested)
            ]
            .map(|(n, s)| (n.to_string(), s))
        );
        assert_eq!(
            out.entries.iter().map(|e| e.offset).collect::<Vec<_>>(),
            headers
        );
        assert_eq!(
            write_back(&bytes, &out),
            [
                ("abc", &b"ABCD"[..]),
                ("hello", b"HELLO"),
                ("plain.txt", b"xyz")
            ]
            .map(|(n, d)| (n.to_string(), d.to_vec(), true))
        );
    }

    /// An archive whose last member is `#1/3` with an even payload, and
    /// whose only defect is that member's missing final pad byte: every
    /// member whole, `Unattested`, and no stop — the guard accepts a missing
    /// final pad as the crate accepts its own, so there is no 0-byte
    /// `CutShort` to report.
    #[test]
    fn a_missing_final_pad_after_an_odd_bsd_name_is_no_stop() {
        let mut bytes = GLOBAL_HEADER.to_vec();
        bytes.extend(member(b"plain.txt", 3, b"xyz"));
        bytes.extend(member(b"#1/3", 7, b"abcABCD"));
        assert_eq!(bytes.pop(), Some(b'\n'), "the final pad byte");
        let out = scan(&bytes);
        assert!(out.walk_stop.is_none(), "{:?}", out.walk_stop);
        assert_eq!(
            names_and_statuses(&out),
            [
                ("plain.txt", SalvageStatus::Unattested),
                ("abc", SalvageStatus::Unattested)
            ]
            .map(|(n, s)| (n.to_string(), s))
        );
        assert_eq!(
            write_back(&bytes, &out),
            [("plain.txt", &b"xyz"[..]), ("abc", b"ABCD")].map(|(n, d)| (
                n.to_string(),
                d.to_vec(),
                true
            ))
        );
    }

    // -------------------------------------------------------------------
    // The guard's ceilings: one owner, answered as a stop, never an `Err`
    // and never an allocation.
    // -------------------------------------------------------------------

    /// A `SeekRead` that panics on any single read past `max` — proof the
    /// crate's own `vec![0; N]` for a refused length was never reached (the
    /// guard never asks for more than a header at a time).
    struct PanicsOnBigRead {
        inner: Cursor<Vec<u8>>,
        max: usize,
    }

    impl Read for PanicsOnBigRead {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            assert!(
                buf.len() <= self.max,
                "a single read of {} bytes: the refused allocation was reached",
                buf.len()
            );
            self.inner.read(buf)
        }
    }

    impl Seek for PanicsOnBigRead {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    fn scan_guarded(bytes: Vec<u8>) -> SalvageOutcome {
        let mut src = PanicsOnBigRead {
            inner: Cursor::new(bytes),
            max: 64 * 1024,
        };
        salvage_ar(&mut src, &SalvagePolicy::default()).expect("a refusal is a stop")
    }

    #[test]
    fn an_absurd_bsd_identifier_length_is_a_stop_that_keeps_the_prefix() {
        let mut bytes = build_ar(&[("a.txt", b"alpha"), ("b.txt", b"bravo")]);
        let at = bytes.len() as u64;
        let mut id = b"#1/".to_vec();
        id.extend_from_slice(format!("{:<13}", 1_000_000).as_bytes());
        bytes.extend(member(&id, 1_000_010, b"x"));
        bytes.extend(member(b"after.txt", 5, b"after"));
        let out = scan_guarded(bytes);
        assert_eq!(out.entries.len(), 2);
        let stop = out.walk_stop.expect("a stop");
        assert_eq!((stop.offset, stop.kind), (at, WalkStopKind::Unreadable));
        assert!(stop.cause.contains("65536-byte ceiling"), "{}", stop.cause);
    }

    #[test]
    fn an_absurd_gnu_name_table_is_a_stop_that_keeps_the_prefix() {
        let mut bytes = GLOBAL_HEADER.to_vec();
        bytes.extend(member(b"a.o/", 2, b"aa"));
        let at = bytes.len() as u64;
        bytes.extend(member(b"//", 8_000_000_000, b""));
        bytes.extend(member(b"after.o/", 5, b"after"));
        let out = scan_guarded(bytes);
        assert_eq!(names_and_statuses(&out)[0].0, "a.o");
        assert_eq!(out.entries.len(), 1);
        let stop = out.walk_stop.expect("a stop");
        assert_eq!(stop.offset, at);
        assert!(
            stop.cause.contains("16777216-byte ceiling"),
            "{}",
            stop.cause
        );
    }

    /// `ar-0.9.0`'s unchecked `name_table[start..]` — the 68-byte panic
    /// `ar.rs`'s guard closes — is a stop here too, not a panic.
    #[test]
    fn a_name_table_index_past_the_table_is_a_stop_not_a_panic() {
        let mut bytes = GLOBAL_HEADER.to_vec();
        bytes.extend(member(b"a.o/", 2, b"aa"));
        bytes.extend(member(b"/9999", 2, b"bb"));
        let out = scan(&bytes);
        assert_eq!(out.entries.len(), 1);
        let stop = out.walk_stop.expect("a stop");
        assert!(stop.cause.contains("offset 9999"), "{}", stop.cause);
    }

    /// Noise after a valid global header: nothing, one stop, no panic — and
    /// no phantom, because nothing is searched for.
    #[test]
    fn noise_after_the_global_header_is_one_stop_and_nothing_else() {
        let mut state: u32 = 0xC0FF_EE42;
        let mut bytes = GLOBAL_HEADER.to_vec();
        while bytes.len() < 1 << 20 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            bytes.extend_from_slice(&state.to_le_bytes());
        }
        let out = scan(&bytes);
        assert!(out.entries.is_empty());
        let stop = out.walk_stop.expect("a stop");
        assert_eq!(stop.offset, 8);
    }

    // -------------------------------------------------------------------
    // The status and the write seam
    // -------------------------------------------------------------------

    #[test]
    fn a_wrong_codec_is_refused_before_the_archive_is_opened() {
        let mut meta = EntryMeta::file("x");
        meta.size = Some(1);
        let entry = SalvagedEntry::new(0, 8, 68, meta, SalvageStatus::Unattested);
        let err = write_payload(
            Path::new("/definitely/not/a/real/archive.a"),
            &entry,
            1,
            &mut Vec::new(),
        )
        .expect_err("refused");
        assert!(matches!(err, Error::Unsupported(_)), "{err:?}");
    }

    #[test]
    fn verify_never_answers_complete() {
        let bytes = build_ar(&FIVE);
        let out = scan(&bytes[..bytes.len() - 3]);
        let statuses: Vec<SalvageStatus> = out.entries.iter().map(|e| e.status).collect();
        assert_eq!(
            statuses,
            [
                SalvageStatus::Unattested,
                SalvageStatus::Unattested,
                SalvageStatus::Unattested,
                SalvageStatus::Unattested,
                SalvageStatus::Partial
            ]
        );
    }

    /// Fix round 1, I1: a cut anywhere inside a BSD `#1/N` extended NAME, or
    /// inside a GNU `//` long-name table, is the file ending inside that
    /// record — `CutShort`, never "unreachable". `FIVE`'s short names never
    /// reached either shape, which is how the first sweep missed it.
    #[test]
    fn a_cut_inside_an_extended_name_or_a_name_table_is_cut_short() {
        let bsd = build_ar(&[
            ("a.txt", b"alpha"),
            ("an-extended-name-past-sixteen-bytes.txt", b"payload"),
        ]);
        let last = bsd
            .windows(3)
            .rposition(|w| w == b"#1/")
            .expect("the long name is stored `#1/N`");
        let payload = bsd.windows(7).rposition(|w| w == b"payload").unwrap();
        let table = "first-long-member-name.o/\nsecond-long-member-name.o/\n";
        let mut gnu = GLOBAL_HEADER.to_vec();
        let table_at = gnu.len();
        gnu.extend(member(b"//", table.len() as u64, table.as_bytes()));
        gnu.extend(member(b"/0", 2, b"AA"));
        for (label, bytes, from, to) in [
            ("bsd #1/N", &bsd, last + 1, payload),
            ("gnu //", &gnu, table_at + 1, table_at + 60 + table.len()),
        ] {
            for cut in from..to {
                let out = scan(&bytes[..cut]);
                if let Some(stop) = &out.walk_stop {
                    assert_eq!(
                        stop.kind,
                        WalkStopKind::CutShort,
                        "{label} cut {cut}: {}",
                        describe_walk_stop(stop)
                    );
                    assert!(!describe_walk_stop(stop).contains("unreachable"));
                }
            }
        }
    }

    /// Fix round 1, I3, narrowed in 0.8.1: a symbol table whose header
    /// `ar 0.9.0` cannot parse, in a way the guard does NOT normalise (a mode
    /// that is neither blank nor octal), is a shape this build does not
    /// read. With nothing recovered before it, exit 3 naming it — never
    /// exit 5 "nothing recoverable" over a possibly healthy archive.
    #[test]
    fn an_unparseable_symbol_table_first_is_exit_3_naming_it() {
        for ident in [&b"__.SYMDEF"[..], b"__.SYMDEF SORTED"] {
            let mut bytes = GLOBAL_HEADER.to_vec();
            bytes.extend(mode_member(ident, b"\0\0\0\0", BAD_MODE));
            bytes.extend(member(b"f.o", 3, b"fff"));
            let err = salvage_ar(&mut Cursor::new(bytes), &SalvagePolicy::default())
                .expect_err("an unreadable symbol table with nothing before it is exit 3");
            assert_eq!(err.exit_code(), 3, "{err}");
            let name = std::str::from_utf8(ident).unwrap();
            assert!(err.to_string().contains(name), "{err}");
            assert!(err.to_string().contains("symbol table"), "{err}");
        }
        // The same table in the `#1/N` extended form BSD tools also write.
        let mut bytes = GLOBAL_HEADER.to_vec();
        bytes.extend(extended_symbol_table(BAD_MODE));
        let err =
            salvage_ar(&mut Cursor::new(bytes), &SalvagePolicy::default()).expect_err("exit 3");
        assert_eq!(err.exit_code(), 3, "{err}");
        assert!(err.to_string().contains("__.SYMDEF SORTED"), "{err}");
    }

    /// With members recovered before it, the stop names the symbol table as
    /// its cause rather than calling it a hole.
    #[test]
    fn an_unparseable_symbol_table_after_members_is_named_in_the_stop() {
        let mut bytes = GLOBAL_HEADER.to_vec();
        bytes.extend(member(b"a.o", 2, b"aa"));
        let at = bytes.len() as u64;
        bytes.extend(mode_member(b"__.SYMDEF", b"\0\0\0\0", BAD_MODE));
        bytes.extend(member(b"b.o", 2, b"bb"));
        let out = scan(&bytes);
        assert_eq!(out.entries.len(), 1);
        let stop = out.walk_stop.expect("a stop");
        assert_eq!(stop.offset, at);
        let note = describe_walk_stop(&stop);
        assert!(note.contains("symbol table (`__.SYMDEF`)"), "{note}");
        assert!(note.contains("not evidence of damage"), "{note}");
        assert!(!note.contains("unreachable by construction"), "{note}");
    }

    /// 0.8.1: a BLANK mode on a symbol table is normalised by `ar.rs`'s
    /// guard, so the walk reads past it. Inline, the table is a member the
    /// crate hands back (mode unknown); in `#1/N` form the crate skips it.
    /// A blank mode on an ordinary member is not normalised and still stops
    /// the walk, as `stuffr list` still refuses it.
    #[test]
    fn a_blank_mode_symbol_table_walks_whole_and_an_ordinary_member_does_not() {
        for ident in [&b"__.SYMDEF"[..], b"__.SYMDEF SORTED"] {
            let mut bytes = GLOBAL_HEADER.to_vec();
            bytes.extend(mode_member(ident, b"\0\0\0\0", BLANK_MODE));
            bytes.extend(member(b"f.o", 3, b"fff"));
            let out = scan(&bytes);
            assert!(out.walk_stop.is_none(), "{:?}", out.walk_stop);
            let name = std::str::from_utf8(ident).unwrap();
            let got: Vec<_> = out
                .entries
                .iter()
                .map(|e| (e.meta.name.as_str(), e.meta.mode))
                .collect();
            assert_eq!(got, [(name, None), ("f.o", Some(0o100644))]);
        }

        let mut bytes = GLOBAL_HEADER.to_vec();
        bytes.extend(extended_symbol_table(BLANK_MODE));
        bytes.extend(member(b"f.o", 3, b"fff"));
        let out = scan(&bytes);
        assert!(out.walk_stop.is_none(), "{:?}", out.walk_stop);
        assert_eq!(
            names_and_statuses(&out),
            [("f.o".to_string(), SalvageStatus::Unattested)]
        );

        let mut bytes = GLOBAL_HEADER.to_vec();
        bytes.extend(member(b"a.o", 2, b"aa"));
        let at = bytes.len() as u64;
        bytes.extend(mode_member(b"b.o", b"bb", BLANK_MODE));
        let out = scan(&bytes);
        assert_eq!(out.entries.len(), 1);
        let stop = out
            .walk_stop
            .expect("an ordinary member's blank mode stops the walk");
        assert_eq!((stop.offset, stop.kind), (at, WalkStopKind::Unreadable));
        assert!(
            stop.cause.contains("Invalid file mode field"),
            "{}",
            stop.cause
        );
    }

    /// The real writer behind I3: GNU `ar rcs` over Mach-O objects writes a
    /// `__.SYMDEF` with a blank mode. Since 0.8.1 the guard normalises it,
    /// so the walk is whole: the table is recovered as the member it is
    /// (as `stuffr list` and Apple `ar t` show it), mode unknown, and no
    /// stop. macOS only — an ELF host's GNU `ar`
    /// writes `/` instead, and the hand-built fixtures above pin the shape
    /// there. On macOS the keg-only GNU `ar` and a C compiler are REQUIRED
    /// and their absence fails loudly, like the catalogue's `writers()`
    /// (Ruling 970): this test used to return early without them and pass
    /// having proved nothing.
    #[test]
    fn gnu_ar_s_mach_o_symbol_table_walks_whole() {
        if !cfg!(target_os = "macos") {
            return;
        }
        const GNU_AR_ON_MACOS: &str = "/opt/homebrew/opt/binutils/bin/ar";
        let gnu = std::path::PathBuf::from(GNU_AR_ON_MACOS);
        assert!(
            gnu.is_file(),
            "GNU ar not at {GNU_AR_ON_MACOS} (`brew install binutils`) — without it this \
             test proves nothing about the real writer"
        );
        let cc = which("cc").unwrap_or_else(|| {
            panic!("no `cc` on PATH — this test needs a Mach-O object to archive")
        });
        let dir = tempfile_dir("symdef");
        std::fs::write(dir.0.join("f.c"), "int f(void){return 1;}\n").unwrap();
        let compiled = std::process::Command::new(cc)
            .args(["-c", "-o", "f.o", "f.c"])
            .current_dir(&dir.0)
            .status()
            .unwrap();
        assert!(compiled.success());
        let made = std::process::Command::new(&gnu)
            .args(["rcs", "lib.a", "f.o"])
            .current_dir(&dir.0)
            .status()
            .unwrap();
        assert!(made.success());
        let bytes = std::fs::read(dir.0.join("lib.a")).unwrap();
        assert!(
            bytes[8..].starts_with(b"__.SYMDEF"),
            "GNU ar on macOS no longer writes the Mach-O `__.SYMDEF` first: {:?}",
            String::from_utf8_lossy(&bytes[8..bytes.len().min(68)])
        );
        let out = salvage_ar(&mut Cursor::new(bytes), &SalvagePolicy::default())
            .expect("GNU's Mach-O library walks whole");
        assert!(out.walk_stop.is_none(), "{:?}", out.walk_stop);
        let got: Vec<_> = out
            .entries
            .iter()
            .map(|e| (e.meta.name.as_str(), e.meta.mode.is_some(), e.status))
            .collect();
        assert_eq!(
            got,
            [
                ("__.SYMDEF", false, SalvageStatus::Unattested),
                ("f.o", true, SalvageStatus::Unattested),
            ]
        );
    }

    // -------------------------------------------------------------------
    // Reference writers — the independent witnesses
    // -------------------------------------------------------------------

    fn which(bin: &str) -> Option<std::path::PathBuf> {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path).find_map(|dir| {
            let candidate = dir.join(bin);
            candidate.is_file().then_some(candidate)
        })
    }

    struct TempDir(std::path::PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tempfile_dir(tag: &str) -> TempDir {
        let dir = std::env::temp_dir().join(format!(
            "stuffr-ar-salvage-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    /// What `ar` itself writes — BSD `ar` here (`#1/N` for the long name),
    /// GNU `ar` on the CI runner and from its keg-only install when present
    /// (a `//` long-name table) — is recovered whole, name for name and byte
    /// for byte, each member `Unattested`, agreeing with the ordinary
    /// reader. The same archive with its SECOND member's header destroyed
    /// gives exactly the first member and a stop at that header, with the
    /// later members still on disk: the limitation, on a real writer's
    /// bytes. The system `ar` is REQUIRED (CI installs it).
    #[test]
    fn every_reference_writer_s_archive_is_walked_whole_and_its_hole_stated() {
        let tree = tempfile_dir("tree");
        let long = format!("{}.txt", "l".repeat(40));
        let contents: [(&str, &[u8]); 4] = [
            ("a.txt", b"alpha\n"),
            ("b.bin", b"\x00\xff\x00\x07\x09"),
            (&long, b"long name\n"),
            ("d.txt", b"delta"),
        ];
        for (name, data) in contents {
            std::fs::write(tree.0.join(name), data).unwrap();
        }
        let system = which("ar").unwrap_or_else(|| {
            panic!("no reference `ar` on PATH — this test proved nothing, which is worth knowing")
        });
        // `(writer, extra args, must write a GNU `//` table)`. The keg-only GNU
        // `ar` on macOS writes BSD `#1/N` names for its Mach-O default target
        // (fix round 1, I4: measured — this leg covered `#1/N` twice), so it
        // is asked for an ELF target, which writes a real `//` table.
        let mut writers: Vec<(std::path::PathBuf, Vec<&str>, bool)> = vec![(system, vec![], false)];
        let gnu = std::path::PathBuf::from("/opt/homebrew/opt/binutils/bin/ar");
        if gnu.is_file() {
            writers.push((gnu, vec!["--target=elf64-x86-64"], true));
        }
        for (writer, extra, gnu_table) in &writers {
            let archive = tree.0.join("ref.a");
            let _ = std::fs::remove_file(&archive);
            // `S`: no symbol table — see `ar.rs`'s `we_accept_what_system_ar_writes`
            // for what macOS's `ar` does to non-object files without it.
            let status = std::process::Command::new(writer)
                .args(extra)
                .arg("rcS")
                .arg(&archive)
                .args(contents.iter().map(|(n, _)| *n))
                .current_dir(&tree.0)
                .status()
                .unwrap();
            assert!(status.success(), "{} could not write", writer.display());
            let bytes = std::fs::read(&archive).unwrap();
            if *gnu_table {
                assert_eq!(
                    &bytes[8..10],
                    b"//",
                    "{} did not write a GNU long-name table",
                    writer.display()
                );
            }
            let out = scan(&bytes);
            assert!(
                out.walk_stop.is_none(),
                "{}: {:?}",
                writer.display(),
                out.walk_stop
            );
            let written = write_back(&bytes, &out);
            assert_eq!(
                written
                    .iter()
                    .map(|(n, d, done)| (n.as_str(), d.as_slice(), *done))
                    .collect::<Vec<_>>(),
                contents
                    .iter()
                    .map(|(n, d)| (*n, *d, true))
                    .collect::<Vec<_>>(),
                "{}",
                writer.display()
            );
            assert!(
                out.entries
                    .iter()
                    .all(|e| e.status == SalvageStatus::Unattested)
            );

            let second = out.entries[1].offset as usize;
            let mut holed = bytes.clone();
            holed[second + 16..second + 28].copy_from_slice(b"XXXXXXXXXXXX");
            let out = scan(&holed);
            assert_eq!(
                out.entries
                    .iter()
                    .map(|e| e.meta.name.as_str())
                    .collect::<Vec<_>>(),
                ["a.txt"],
                "{}",
                writer.display()
            );
            let stop = out.walk_stop.expect("a stop");
            assert_eq!(
                (stop.offset, stop.kind),
                (second as u64, WalkStopKind::Unreadable)
            );
            assert!(
                holed.windows(5).any(|w| w == b"delta"),
                "d.txt is still there"
            );
        }
    }

    // -------------------------------------------------------------------
    // Salvage Stage 3 Task 6: the damage catalogue.
    //
    // **Every expectation here is the PRE-DAMAGE state, and none of it
    // comes from this scanner.** [`inputs`] is written to disk, a REAL `ar`
    // archives it, and what each mutation must produce is derived from
    // those input files plus the member geometry [`members`] parses longhand
    // out of the writer's bytes — never from what `salvage_ar` currently
    // returns. The writers are the platform `ar` (BSD here, GNU binutils on
    // the CI runner) and, on macOS, GNU binutils' keg-only `ar` for both its
    // default (Mach-O) target and an ELF one — the two spell a plain member
    // name differently (`name` vs `name/`). All REQUIRED.
    //
    // **ar's header row is NOT "neighbours unaffected"** (controller
    // ruling, Task 6): this scanner walks and cannot cross a hole, by
    // construction (Task 4's stated limit). The row asserts that limit
    // instead — every member BEFORE the corrupted header recovered at its
    // tier, none AFTER, and the walk-stop note saying, with the offset,
    // that they are unreachable by construction.
    // -------------------------------------------------------------------
    mod damage_catalogue {
        use std::path::{Path, PathBuf};

        use super::*;

        /// The files every writer is fed: THE pre-damage state. Each payload
        /// is well over a kilobyte so a flip at its middle is far from any
        /// header; `beta.txt` is odd-sized, so its `\n` pad byte is in play.
        fn inputs() -> Vec<(&'static str, Vec<u8>)> {
            vec![
                (
                    "alpha.txt",
                    (0..200)
                        .flat_map(|i| format!("alpha line {i}\n").into_bytes())
                        .collect(),
                ),
                (
                    "beta.txt",
                    (0..301)
                        .flat_map(|i| format!("beta {i};").into_bytes())
                        .collect(),
                ),
                (
                    "gamma.bin",
                    (0..1500u32).map(|i| ((i * 7 + 3) % 256) as u8).collect(),
                ),
                (
                    "delta.txt",
                    (0..151)
                        .flat_map(|i| format!("delta row {i}\n").into_bytes())
                        .collect(),
                ),
            ]
        }

        /// GNU binutils' keg-only Homebrew `ar` — see `reference-tools.md`.
        const GNU_AR_ON_MACOS: &str = "/opt/homebrew/opt/binutils/bin/ar";

        /// `(writer, extra args)`: the platform `ar`, plus GNU's on macOS
        /// (where the platform's is BSD) for its default target and for ELF.
        fn writers() -> Vec<(PathBuf, Vec<&'static str>)> {
            let platform = which("ar").unwrap_or_else(|| {
                panic!("no reference `ar` on PATH — this catalogue proved nothing")
            });
            let mut out = vec![(platform, vec![])];
            if cfg!(target_os = "macos") {
                let gnu = PathBuf::from(GNU_AR_ON_MACOS);
                assert!(
                    gnu.is_file(),
                    "GNU ar not at {GNU_AR_ON_MACOS} (`brew install binutils`) — without it \
                     this catalogue covers BSD ar alone, and CI runs GNU's"
                );
                out.push((gnu.clone(), vec![]));
                out.push((gnu, vec!["--target=elf64-x86-64"]));
            }
            out
        }

        /// Every writer's archive of [`inputs`] (`rcS`: no symbol table),
        /// `(label, bytes, writer)`.
        fn reference_archives(tag: &str) -> Vec<(String, Vec<u8>, PathBuf)> {
            let tree = tempfile_dir(&format!("catalogue-{tag}"));
            for (name, data) in inputs() {
                std::fs::write(tree.0.join(name), data).unwrap();
            }
            let mut out = Vec::new();
            for (writer, extra) in writers() {
                let archive = tree.0.join("ref.a");
                let _ = std::fs::remove_file(&archive);
                let status = std::process::Command::new(&writer)
                    .args(&extra)
                    .arg("rcS")
                    .arg(&archive)
                    .args(inputs().iter().map(|(n, _)| *n))
                    .current_dir(&tree.0)
                    .status()
                    .unwrap();
                assert!(status.success(), "{} could not write", writer.display());
                out.push((
                    format!("{} {}", writer.display(), extra.join(" ")),
                    std::fs::read(&archive).unwrap(),
                    writer,
                ));
            }
            out
        }

        /// One member's geometry, read by THIS TEST from the raw bytes: its
        /// header's offset and its CONTENT's range (past a BSD `#1/N` name).
        struct Member {
            name: String,
            header: usize,
            content: std::ops::Range<usize>,
        }

        /// Walks an archive by the format's layout — `!<arch>\n`, then
        /// 60-byte headers (name `0..16`, decimal size `48..58`, `` `\n ``
        /// at `58..60`), each body padded to even — resolving the two
        /// plain-name spellings (`name`, GNU's `name/`) and BSD's `#1/N`.
        /// Hand-rolled rather than read through the `ar` crate, which is the
        /// walk under test.
        fn members(bytes: &[u8]) -> Vec<Member> {
            assert_eq!(&bytes[..8], b"!<arch>\n");
            let mut out = Vec::new();
            let mut at = 8usize;
            while at + 60 <= bytes.len() {
                assert_eq!(&bytes[at + 58..at + 60], b"`\n", "a header at {at}");
                let field = |r: std::ops::Range<usize>| {
                    std::str::from_utf8(&bytes[at + r.start..at + r.end])
                        .unwrap()
                        .trim_end()
                        .to_string()
                };
                let size: usize = field(48..58).parse().unwrap();
                let raw = field(0..16);
                let body = at + 60;
                let (name, content) = match raw.strip_prefix("#1/") {
                    Some(n) => {
                        let n: usize = n.parse().unwrap();
                        let name = String::from_utf8(bytes[body..body + n].to_vec()).unwrap();
                        (
                            name.trim_end_matches('\0').to_string(),
                            body + n..body + size,
                        )
                    }
                    None => {
                        assert!(!raw.starts_with('/'), "no symbol or name table expected");
                        (raw.trim_end_matches('/').to_string(), body..body + size)
                    }
                };
                out.push(Member {
                    name,
                    header: at,
                    content,
                });
                at = body + size + size % 2;
            }
            out
        }

        /// `ar p` — the WRITER's own reading of `name` (BSD `ar` does not
        /// find GNU's `name/` spelling) — and whether it exited 0.
        fn platform_extract(writer: &Path, bytes: &[u8], name: &str) -> (bool, Vec<u8>) {
            let dir = tempfile_dir("catalogue-extract");
            let archive = dir.0.join("damaged.a");
            std::fs::write(&archive, bytes).unwrap();
            let out = std::process::Command::new(writer)
                .arg("p")
                .arg(&archive)
                .arg(name)
                .output()
                .unwrap();
            (out.status.success(), out.stdout)
        }

        fn rows(out: &SalvageOutcome) -> Vec<(&str, SalvageStatus)> {
            out.entries
                .iter()
                .map(|e| (e.meta.name.as_str(), e.status))
                .collect()
        }

        fn all_unattested(want: &[(&'static str, Vec<u8>)]) -> Vec<(&'static str, SalvageStatus)> {
            want.iter()
                .map(|(n, _)| (*n, SalvageStatus::Unattested))
                .collect()
        }

        // ---------------------------------------------------------------
        // Step 1: the agreement property.
        // ---------------------------------------------------------------

        /// **Salvage of an UNDAMAGED archive agrees exactly with the
        /// ordinary reader AND with the files that went in** — names and
        /// sizes as `list` reports them, bytes as the input files hold them,
        /// every member `Unattested` (never `Complete`, never `Intact`), and
        /// no walk stop.
        #[test]
        fn salvage_of_every_writer_s_healthy_archive_agrees_with_the_reader_and_the_inputs() {
            let want = inputs();
            for (writer, bytes, _) in reference_archives("agree") {
                let reader = read_through_the_reader(&bytes)
                    .unwrap_or_else(|e| panic!("{writer}: the ordinary reader must walk it: {e}"));
                let out = scan(&bytes);
                assert!(out.walk_stop.is_none(), "{writer}: {:?}", out.walk_stop);
                assert_eq!(
                    out.entries
                        .iter()
                        .map(|e| (e.meta.name.clone(), e.meta.size))
                        .collect::<Vec<_>>(),
                    reader
                        .iter()
                        .map(|(n, s, _)| (n.clone(), Some(*s)))
                        .collect::<Vec<_>>(),
                    "{writer}: salvage and the ordinary reader must describe every member alike"
                );
                assert_eq!(
                    members(&bytes)
                        .iter()
                        .map(|m| m.name.as_str())
                        .collect::<Vec<_>>(),
                    want.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
                    "{writer}: sanity, this test's own geometry finds the inputs in order"
                );
                assert_eq!(rows(&out), all_unattested(&want), "{writer}");
                let written = write_back(&bytes, &out);
                for (i, (name, data)) in want.iter().enumerate() {
                    assert_eq!(&reader[i].2, data, "{writer}: the reader's {name}");
                    assert_eq!(
                        (written[i].1.as_slice(), written[i].2),
                        (data.as_slice(), true),
                        "{writer}: {name}"
                    );
                }
            }
        }

        // ---------------------------------------------------------------
        // Step 2: the mutation catalogue.
        // ---------------------------------------------------------------

        /// Row 1/3 — **a truncated tail.** Cut inside the LAST member's
        /// content: every earlier member `Unattested` with exactly its input
        /// bytes, the cut one `Partial` with exactly the surviving prefix,
        /// and no walk stop (nothing after it is missing from the report).
        #[test]
        fn damage_catalogue_a_truncated_tail() {
            let want = inputs();
            let last = want.len() - 1;
            for (writer, bytes, _) in reference_archives("tail") {
                let content = members(&bytes)[last].content.clone();
                for keep in [0, 1, content.len() / 2, content.len() - 1] {
                    let cut = &bytes[..content.start + keep];
                    let out = scan(cut);
                    let mut expected = all_unattested(&want);
                    expected[last].1 = SalvageStatus::Partial;
                    assert_eq!(rows(&out), expected, "{writer} keep={keep}");
                    assert!(out.walk_stop.is_none(), "{writer}: {:?}", out.walk_stop);
                    let written = write_back(cut, &out);
                    for (i, (name, data)) in want.iter().enumerate().take(last) {
                        assert_eq!(
                            (written[i].1.as_slice(), written[i].2),
                            (data.as_slice(), true),
                            "{writer} {name}"
                        );
                    }
                    assert_eq!(
                        (written[last].1.as_slice(), written[last].2),
                        (&want[last].1[..keep], false),
                        "{writer} keep={keep}: exactly the surviving prefix"
                    );
                }
            }
        }

        /// Row 2/3 — **a byte flipped mid-content. The stage's point.** `ar`
        /// checksums nothing, so the damaged member is a SILENTLY WRONG
        /// FILE. Its tier must not claim otherwise — `Unattested`, never
        /// `Intact` or `Complete` — and its written bytes are asserted to
        /// DIFFER from the input in exactly the flipped byte. The writer's
        /// own `ar p` prints the same wrong bytes at exit 0. Every member takes
        /// its turn.
        #[test]
        fn damage_catalogue_a_byte_flipped_mid_payload() {
            let want = inputs();
            for (writer, bytes, tool) in reference_archives("flip") {
                for (damaged, target) in members(&bytes).iter().enumerate() {
                    let mid = target.content.len() / 2;
                    let mut flipped = bytes.clone();
                    flipped[target.content.start + mid] ^= 0xFF;

                    let out = scan(&flipped);
                    assert_eq!(
                        rows(&out),
                        all_unattested(&want),
                        "{writer} damaged={damaged}"
                    );
                    assert!(out.walk_stop.is_none(), "{writer}: {:?}", out.walk_stop);
                    let written = write_back(&flipped, &out);
                    let mut wrong = want[damaged].1.clone();
                    wrong[mid] ^= 0xFF;
                    assert_ne!(
                        written[damaged].1, want[damaged].1,
                        "{writer}: silently wrong"
                    );
                    assert_eq!(
                        (written[damaged].1.as_slice(), written[damaged].2),
                        (wrong.as_slice(), true),
                        "{writer}: wrong in exactly the flipped byte and no other"
                    );
                    for (i, (name, data)) in want.iter().enumerate() {
                        if i != damaged {
                            assert_eq!(&written[i].1, data, "{writer}: {name}");
                        }
                    }
                    let (ok, printed) = platform_extract(&tool, &flipped, want[damaged].0);
                    assert!(
                        ok && printed == wrong,
                        "{writer}: the writer's own `ar p` prints the same wrong bytes at exit 0 \
                         (exit ok: {ok}, {} bytes)",
                        printed.len()
                    );
                }
            }
        }

        /// Row 3/3 — **a header field corrupted, under ar's stated limit.**
        /// Three fields — the SIZE, the MODE and the MTIME, each made
        /// unparseable — against every member in turn. Every member BEFORE the damage is `Unattested`
        /// with exactly its input bytes; NONE after it is reported; the walk
        /// stops `Unreadable` at exactly that header with every byte from it
        /// to EOF counted, and its note says, with the offset, that those
        /// bytes' entries are unreachable by construction, not absent. The
        /// members after are asserted still on disk, intact, at the offsets
        /// this test's geometry found — so "not reported" is the limit, not
        /// a loss.
        #[test]
        fn damage_catalogue_a_corrupted_header_field() {
            let want = inputs();
            for (writer, bytes, _) in reference_archives("header") {
                let geometry = members(&bytes);
                for (damaged, target) in geometry.iter().enumerate() {
                    let h = target.header;
                    for (field, range, junk) in [
                        ("size", 48..58, &b"garbage!!!"[..]),
                        ("mode", 40..48, &b"rw-r--r-"[..]),
                        ("mtime", 16..28, &b"not-a-time!!"[..]),
                    ] {
                        let mut bad = bytes.clone();
                        bad[h + range.start..h + range.end].copy_from_slice(junk);
                        assert!(
                            read_through_the_reader(&bad).is_err(),
                            "{writer} {field}: sanity, the ordinary reader must refuse it"
                        );
                        let out = scan(&bad);
                        assert_eq!(
                            rows(&out),
                            all_unattested(&want)[..damaged],
                            "{writer} damaged={damaged} {field}: what precedes the hole, and \
                             nothing after it"
                        );
                        let written = write_back(&bad, &out);
                        for (i, (name, data)) in want.iter().enumerate().take(damaged) {
                            assert_eq!(
                                (written[i].1.as_slice(), written[i].2),
                                (data.as_slice(), true),
                                "{writer} {field}: {name}"
                            );
                        }
                        let stop = out
                            .walk_stop
                            .as_ref()
                            .unwrap_or_else(|| panic!("{writer} {field}: a hole must be said"));
                        assert_eq!(
                            (stop.offset, stop.remaining, stop.kind),
                            (h as u64, (bad.len() - h) as u64, WalkStopKind::Unreadable),
                            "{writer} damaged={damaged} {field}"
                        );
                        let note = describe_walk_stop(stop);
                        for needle in [
                            format!("offset {h}"),
                            "unreachable by construction".to_string(),
                            "not absent".to_string(),
                        ] {
                            assert!(
                                note.contains(&needle),
                                "{writer}: missing {needle:?}: {note}"
                            );
                        }
                        for later in &geometry[damaged + 1..] {
                            let data = &want.iter().find(|(n, _)| *n == later.name).unwrap().1;
                            assert_eq!(
                                &bad[later.content.clone()],
                                data.as_slice(),
                                "{writer}: `{}` is still there — unreachable, not lost",
                                later.name
                            );
                        }
                    }
                }
            }
        }

        /// The header field that is NOT refused: a SIZE that still PARSES
        /// but lies (grown by two). The walk believes it, as `list` does, so
        /// the member is reported over what its header claims —
        /// `Unattested`, never a tier that vouches for it — with WRONG
        /// bytes (two of the next header's), and the walk then stops inside
        /// the next header, saying so; nothing after is reported. Middle
        /// members only: grown past the last member, the claim runs off the
        /// end of the file, which is the truncated-tail row's shape.
        #[test]
        fn damage_catalogue_a_size_that_lies_is_believed_and_not_vouched_for() {
            let want = inputs();
            for (writer, bytes, _) in reference_archives("lying-size") {
                let geometry = members(&bytes);
                for (damaged, target) in geometry.iter().enumerate().take(geometry.len() - 1) {
                    let h = target.header;
                    let declared: usize = std::str::from_utf8(&bytes[h + 48..h + 58])
                        .unwrap()
                        .trim_end()
                        .parse()
                        .unwrap();
                    let mut bad = bytes.clone();
                    bad[h + 48..h + 58].copy_from_slice(format!("{:<10}", declared + 2).as_bytes());

                    let out = scan(&bad);
                    assert_eq!(
                        rows(&out),
                        all_unattested(&want)[..=damaged],
                        "{writer} damaged={damaged}"
                    );
                    let written = write_back(&bad, &out);
                    assert_ne!(
                        written[damaged].1, want[damaged].1,
                        "{writer}: the lying member's bytes are wrong, and its tier never said \
                         otherwise"
                    );
                    let stop = out
                        .walk_stop
                        .as_ref()
                        .unwrap_or_else(|| panic!("{writer}: landing mid-header must be said"));
                    assert_eq!(stop.kind, WalkStopKind::Unreadable, "{writer}: {stop:?}");
                    assert!(
                        (stop.offset as usize) > h
                            && (stop.offset as usize) < geometry[damaged + 1].content.start,
                        "{writer}: the stop is where the lie landed: {stop:?}"
                    );
                }
            }
        }

        /// Recorded, not a defect of this scanner: **`ar 0.9.0` never checks
        /// the `` `\n `` terminator** (`lib.rs`'s header read parses fields
        /// `0..58` and ignores `58..60`), so a destroyed terminator is not
        /// damage EITHER verb sees — `list` reads every member and the walk,
        /// being that reader, agrees. Pinned so a crate that starts checking
        /// it moves both at once, visibly. The format's one fixed marker
        /// carries nothing here; the field parses are the whole gate.
        #[test]
        fn a_destroyed_terminator_is_read_by_list_and_salvage_alike() {
            let want = inputs();
            for (writer, bytes, _) in reference_archives("terminator") {
                for target in members(&bytes) {
                    let mut bad = bytes.clone();
                    bad[target.header + 58..target.header + 60].copy_from_slice(b"XX");
                    let reader = read_through_the_reader(&bad)
                        .unwrap_or_else(|e| panic!("{writer}: the reader refused it: {e}"));
                    assert_eq!(reader.len(), want.len(), "{writer}");
                    let out = scan(&bad);
                    assert!(out.walk_stop.is_none(), "{writer}: {:?}", out.walk_stop);
                    assert_eq!(rows(&out), all_unattested(&want), "{writer}");
                }
            }
        }
    }
}
