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

use std::io::{self, Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use stuffr_core::{
    ArchiveRead, ArchiveWrite, Container, ContainerCaps, CreateOpts, Entry, EntryKind, EntryMeta,
    Error, FidelityReport, FormatId, FormatMeta, MagicRule, OpenOpts, Resolved, Result, Source,
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
        // Leaked deliberately and reclaimed in `ArRead::drop` — see that
        // struct's own doc for why, and `tar.rs`'s module doc for the fuller
        // argument this mirrors.
        let archive: *mut ArArchive = Box::into_raw(Box::new(ar::Archive::new(source)));
        Ok(Box::new(ArRead {
            archive,
            current: None,
            report,
            seekable,
        }))
    }

    fn create(&self, dst: Box<dyn Write + Send>, _o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
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

type ArSource = Box<dyn Source>;
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
    inner: Option<ar::Builder<Box<dyn Write + Send>>>,
    /// Whether `add` was ever called. `ar::Builder` writes the global header
    /// lazily, on the first `append` — with zero entries that never
    /// happens, and the archive would be zero bytes rather than the 8-byte
    /// magic a valid empty archive is. See the module doc.
    wrote_any: bool,
}

impl ArWrite {
    fn builder(&mut self) -> Result<&mut ar::Builder<Box<dyn Write + Send>>> {
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
    fn finish(mut self: Box<Self>) -> Result<()> {
        let builder = self
            .inner
            .take()
            .ok_or_else(|| Error::Usage("ar writer finished twice".into()))?;
        let mut dst = builder.into_inner()?;
        if !self.wrote_any {
            dst.write_all(GLOBAL_HEADER)?;
        }
        dst.flush()?;
        Ok(())
    }
}

/// Forces the BSD extended (`#1/N`) identifier form for a short name that
/// would otherwise collide with `ar`'s OWN GNU-variant reserved syntax.
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
fn write_safe_identifier(mut identifier: Vec<u8>) -> Vec<u8> {
    let ambiguous = identifier.starts_with(b"/") || identifier.ends_with(b"/");
    if ambiguous && identifier.len() <= 16 {
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
    use stuffr_core::{ArchiveRead, CreateOpts, EntryMeta, OpenOpts, ReaderSource, Source};

    fn build_ar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let buf = SharedBuf::new();
        let mut w = Ar
            .create(Box::new(buf.clone()), &CreateOpts::default())
            .expect("create");
        for (name, data) in entries {
            w.add(&EntryMeta::file(*name), &mut std::io::Cursor::new(*data))
                .expect("add");
        }
        w.finish().expect("finish");
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

    #[test]
    fn add_measures_the_payload_when_the_caller_does_not_declare_a_size() {
        let buf = SharedBuf::new();
        let mut w = Ar
            .create(Box::new(buf.clone()), &CreateOpts::default())
            .unwrap();
        let meta = EntryMeta::file("unknown-length.bin");
        assert_eq!(meta.size, None, "the point of this test");
        w.add(
            &meta,
            &mut std::io::Cursor::new(&b"twenty-two bytes long!"[..]),
        )
        .unwrap();
        w.finish().unwrap();

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
        assert!(
            matches!(
                seekable.by_index(0),
                Err(stuffr_core::Error::Unsupported(_))
            ),
            "a seekable source is not the problem — ar has no index to index into"
        );
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
        let bytes = build_ar(&[
            ("a.txt", b"alpha"),
            (spaced_name, b"\x00\xff\x00"),
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
}
