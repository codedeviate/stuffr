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
//! do its own job, so that adds no ninth mirrored fact about `ar = "=0.9.0"`.
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
//! - A **symbol table** (`/`, `/SYM64/`, `__.SYMDEF`, `__.SYMDEF SORTED`)
//!   whose header `ar 0.9.0` cannot parse — GNU `ar rcs` on Mach-O writes
//!   `__.SYMDEF` with a blank mode, which the crate refuses — ends the walk
//!   with a [`WalkStopKind::UnsupportedShape`] stop naming it; with nothing
//!   recovered before it, the run is exit 3 rather than "nothing
//!   recoverable". `stuffr list` still refuses that archive (a separate
//!   follow-up).
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
//! [`stuffr_core::testing::check_salvage_claim`] permits for
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

use crate::ar::{AR, AR_ENTRY_HEADER_LEN, ArGuardedReader, GuardObserver, entry_meta};

/// The codec an `ar` member carries in [`stuffr_core::EntryMeta::codec`].
/// **Setting it at all is load-bearing**: `entries.rs` hands it to
/// [`write_payload`], which refuses anything else, and an unset codec would
/// make every entry a silent `SkippedNotBuiltIn` — the exact defect ARC
/// shipped in Salvage Stage 2.
pub const STORED: FormatId = FormatId::new("ar-stored");

/// The two offsets the walk needs from [`ArGuardedReader`] — see
/// [`GuardObserver`] for exactly when each is reported.
#[derive(Debug, Clone, Copy, Default)]
struct Marks {
    /// Where the header the crate most recently started to read begins.
    header_at: u64,
    /// Where the last record read whole ends.
    record_end: u64,
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

/// Every symbol-table member identifier the `ar` variants write: GNU's `/`
/// and `/SYM64/`, BSD's `__.SYMDEF` and `__.SYMDEF SORTED` (inline or in the
/// `#1/N` extended form).
const SYMBOL_TABLE_NAMES: [&str; 4] = ["/", "/SYM64/", "__.SYMDEF", "__.SYMDEF SORTED"];

/// The longest `#1/N` name worth reading to recognise a symbol table — the
/// longest of [`SYMBOL_TABLE_NAMES`] rounded up to the four-byte padding BSD
/// writers use, with room to spare. A longer name is no symbol table.
const MAX_SYMBOL_TABLE_EXTENDED_LEN: u64 = 64;

/// Which symbol table, if any, the member header at `offset` names. Read
/// straight from the file, after the walk has stopped there: the crate
/// refused the header, so there is no parsed identifier to consult.
fn symbol_table_at(src: &mut dyn SeekRead, offset: u64, file_len: u64) -> Option<&'static str> {
    let header = read_at(src, offset, AR_ENTRY_HEADER_LEN as u64, file_len)?;
    let mut identifier = header[..16].to_vec();
    while identifier.last() == Some(&b' ') {
        identifier.pop();
    }
    if let Some(len) = identifier.strip_prefix(b"#1/") {
        let len: u64 = std::str::from_utf8(len).ok()?.trim_end().parse().ok()?;
        if len > MAX_SYMBOL_TABLE_EXTENDED_LEN {
            return None;
        }
        identifier = read_at(src, offset + AR_ENTRY_HEADER_LEN as u64, len, file_len)?;
        while identifier.last() == Some(&0) {
            identifier.pop();
        }
    }
    SYMBOL_TABLE_NAMES
        .into_iter()
        .find(|name| name.as_bytes() == identifier.as_slice())
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
                    let header_at = marks.get().header_at;
                    let payload_start = pos.get();
                    candidates.push(candidate(
                        entry.header(),
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
fn candidate(header: &ar::Header, offset: u64, payload_start: u64, file_len: u64) -> Candidate {
    let size = header.size();
    // `Some(n)` always means `n < declared_len`, per the field's contract.
    let available_len = match payload_start.checked_add(size) {
        Some(end) if end <= file_len => None,
        _ => Some(file_len.saturating_sub(payload_start)),
    };
    let mut meta = entry_meta(header);
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

    /// One member whose MODE field is blank, as GNU `ar rcs` writes its
    /// `__.SYMDEF` on Mach-O (fix round 1, I3) — `ar 0.9.0` requires a
    /// non-empty octal mode and refuses it.
    fn blank_mode_member(identifier: &[u8], data: &[u8]) -> Vec<u8> {
        let mut out = member(identifier, data.len() as u64, data);
        out[40..48].copy_from_slice(&[b' '; 8]);
        out
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

    /// Fix round 1, I3: a symbol table whose header `ar 0.9.0` cannot parse
    /// is a shape this build does not read. With nothing recovered before
    /// it, exit 3 naming it — never exit 5 "nothing recoverable" over a
    /// healthy archive.
    #[test]
    fn an_unparseable_symbol_table_first_is_exit_3_naming_it() {
        for ident in [&b"__.SYMDEF"[..], b"__.SYMDEF SORTED"] {
            let mut bytes = GLOBAL_HEADER.to_vec();
            bytes.extend(blank_mode_member(ident, b"\0\0\0\0"));
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
        let mut ext = b"__.SYMDEF SORTED".to_vec();
        ext.resize(20, 0);
        let mut body = ext.clone();
        body.extend_from_slice(b"\0\0\0\0");
        let mut id = b"#1/".to_vec();
        id.extend_from_slice(format!("{:<13}", 20).as_bytes());
        bytes.extend(blank_mode_member(&id, &body));
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
        bytes.extend(blank_mode_member(b"__.SYMDEF", b"\0\0\0\0"));
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

    /// The real writer behind I3, when this machine has it: GNU `ar rcs`
    /// over Mach-O objects writes a `__.SYMDEF` with a blank mode. Needs the
    /// keg-only GNU `ar` and a C compiler; the hand-built fixtures above pin
    /// the same shape everywhere else.
    #[test]
    fn gnu_ar_s_mach_o_symbol_table_is_exit_3_not_5() {
        let gnu = std::path::PathBuf::from("/opt/homebrew/opt/binutils/bin/ar");
        let (true, Some(cc)) = (gnu.is_file(), which("cc")) else {
            return;
        };
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
        if !bytes[8..].starts_with(b"__.SYMDEF") {
            // Not the Mach-O shape (an ELF host writes `/`); nothing to pin.
            return;
        }
        let err = salvage_ar(&mut Cursor::new(bytes), &SalvagePolicy::default())
            .expect_err("GNU's Mach-O symbol table is a shape this build does not read");
        assert_eq!(err.exit_code(), 3, "{err}");
        assert!(err.to_string().contains("__.SYMDEF"), "{err}");
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
}
