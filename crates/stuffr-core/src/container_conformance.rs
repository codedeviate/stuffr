//! Container conformance: TWO entry points, two property sets, two
//! numberings.
//!
//! The codec equivalent (`conformance.rs`) caught defects at codec two rather
//! than codec nine. Containers vary structurally more than codecs, not less,
//! so the same method applies. Properties skip on EVIDENCE — `ContainerCaps`
//! and measurement — never on trust, exactly as the codec harness does.
//!
//! - [`assert_container_conforms`] — a container that can write its own test
//!   input. Thirteen properties, numbered 1-13 below, raised as
//!   `conformance[{id}] property N: ...`.
//! - [`assert_container_conforms_with`] — a container that CANNOT (every
//!   read-only legacy format). Nine properties, numbered 1-9 in a scheme of
//!   its OWN, raised as `conformance[{id}] fixture property N: ...`.
//!
//! **The two numberings collide and the messages are what tell them apart.**
//! Five numbers mean different things in the two sets — 4 is "`finish`
//! surfaces a write error" in one and "entry enumeration" in the other, 6 is
//! `by_index` honesty against truncation, 7 rung honesty against corruption —
//! so a bare `property 6` sent a reader to the wrong entry in this very list.
//! The read-only set is not a SUBSET of the list below, whatever its own
//! function doc used to say; it is a relabelling. Hence the `fixture` tag on
//! every message the fixture-driven entry point raises, and hence its own
//! enumeration, here rather than in a comment inside the function:
//!
//! 1. Identity, as below.
//! 2. The read-only declaration is honoured: `caps.read` must be true, and a
//!    container declaring `write: false` must have `create()` genuinely
//!    refuse rather than quietly succeed.
//! 3. Magic agreement, against the FIXTURE's own bytes — no round trip,
//!    since the fixture already is the encoded form.
//! 4. Enumeration: names and order match the fixture's manifest.
//! 5. Content: each entry's bytes match the manifest.
//! 6. Truncation, unconditional on `caps.read`, mirroring 9 below.
//! 7. Corruption: a flipped middle byte must not read back byte-identical to
//!    the manifest. GATED on `ContainerCaps::detects_corruption`, exactly as
//!    the codec harness gates its own corruption property — see that field.
//! 8. Error classification: every refusal 2, 6 and 7 provoke must pass
//!    `check_error_is_classified` (never `exit_code`'s `_ => 1` wildcard).
//!    Embedded in those three rather than standalone.
//! 9. Source-error passthrough: a source that fails every read must surface
//!    that failure AS ITSELF, never as corruption and never as a clean end
//!    of archive. The twin of 10 below.
//!
//! Thirteen properties for the write-capable entry point, one function.
//!
//! 1. Identity: `Container::id()` must agree with the `FormatMeta` it is
//!    registered under, or a mismatched registration is completely silent —
//!    every other property would still pass.
//! 2. Magic agreement: what `create()` produces matches AT LEAST ONE
//!    registered magic rule, not necessarily every one — a format with
//!    alternative signatures registers more than one rule and only one need
//!    match.
//! 3. Round trip, checked with zero, one, and two entries — zero first,
//!    because that is where a container most often breaks: a structure with
//!    no entries still needs its header and trailer written.
//! 4. The completion path flushes the underlying writer and surfaces a write
//!    error that `Drop` would otherwise swallow. `ArchiveWrite::finish` no
//!    longer flushes: it writes the container's trailer and HANDS THE
//!    DESTINATION BACK, so the harness chains `Sink::finish` onto it, which
//!    is exactly the pair a real caller runs. Between them they are the last
//!    code with a handle to the destination — pointed at a real hazard: a
//!    container relying on `Drop` to flush loses any error entirely (`zip`'s
//!    own `Drop` finalizes and writes failures to stderr).
//! 5. Forward parse from a genuinely non-seekable source — the streaming
//!    premise itself. The source's `Seek` capability is erased at the type
//!    level, not merely reported `false`, so an implementation cannot quietly
//!    fall back to positioned reads and still pass.
//! 6. `by_index` on a forward-only source must be `Err(NotSeekable)`, not an
//!    entry — returning one would be random access faked over a source that
//!    does not have it.
//! 7. Rung honesty for trailing-index formats: a forward read has not
//!    consulted the format's authoritative end-of-stream index, so it must
//!    not report `Rung::Exact`.
//! 8. Entries stream incrementally: reaching the first entry must not require
//!    the whole archive already in memory. MEASURED by counting bytes
//!    actually pulled from the source, not assumed from an implementation's
//!    shape — this is the property that caught lz4 buffering 4 MiB on the
//!    codec side.
//! 9. Truncation is detected and reported as `io::ErrorKind::InvalidData`,
//!    UNCONDITIONALLY on `caps.read` — the one property a container author
//!    cannot vote themselves out of, mirroring codec property 10. Even a
//!    format with no integrity check at all can usually still detect a
//!    header promising a payload the stream does not deliver. Cut in two
//!    places for two different reasons: at four fractions of a small
//!    fixture, which land in FRAMING, and at the midpoint of a fixture whose
//!    incompressible payload dominates its measured framing, which is proven
//!    to land in PAYLOAD. The second was added with tar (Task 7) because the
//!    first four cannot reach the payload path at all, so a container that
//!    silently accepted a cut inside an entry's data still passed.
//! 10. A genuine source I/O error (a disk failure reading the archive)
//!     passes through as itself and must never be relabelled as corruption —
//!     forgetting this reports a full disk as exit 5 instead of exit 1.
//! 11. Metadata survives to the declared fidelity. Only fields the container
//!     actually reports are checked; a container that does not claim to
//!     carry a field is free to drop it, but one that reports a value must
//!     report the value that was written, not an altered one. The one
//!     exception, and it is narrow: a format that records the entry kind in
//!     the mode field itself (cpio `newc` has nowhere else to put it) may
//!     fold `S_IFREG` into the permission-only mode the fixture writes. The
//!     permission bits are still compared exactly.
//! 12. Hostile entry names (path traversal, absolute paths) survive
//!     VERBATIM. A deliberate INVERSION of the usual instinct: the project's
//!     non-negotiable is "refused, not silently sanitised", and refusal
//!     happens once, at the ops layer, in a later task. A container that
//!     helpfully rewrote `../../etc/passwd` would destroy the evidence that
//!     refusal depends on.
//! 13. `ContainerCaps::stores_dirs` and `stores_symlinks` are BEHAVIOUR, not
//!     a claim: a container declaring either must write an entry of that kind
//!     and read it back as that kind. Until this existed the two fields were
//!     taken on trust, which departs from `CodecCaps::detects_corruption` —
//!     verified by the codec harness rather than believed — and left nothing
//!     failing if a container claimed `stores_dirs: true` and wrote a
//!     zero-byte regular file instead. That is precisely the `ar` failure
//!     mode the fields exist to describe, and `entries.rs` branches on them
//!     to decide between writing an entry and warning that it cannot: a false
//!     claim there produces a directory-shaped FILE, after which every entry
//!     beneath it is unextractable. Skipped on evidence like every other
//!     property here — a container claiming neither is asked for neither.

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::archive::{ArchiveRead, Container, CreateOpts, EntryMeta, OpenOpts, PlainSink};
use crate::error::Result;
use crate::fidelity::Rung;
use crate::format::FormatMeta;
use crate::honesty::check_error_is_classified;
use crate::source::{ReaderSource, SeekRead, Source, SourceCaps};

/// `S_IFMT`: the four top bits of a unix `st_mode` that name the entry's
/// KIND. Property 11 uses it to separate "the container folded in the type
/// bits its format demands", which is allowed, from "the container changed
/// what the entry may be done with", which is not.
const MODE_TYPE_MASK: u32 = 0o170_000;

/// Everything `MODE_TYPE_MASK` does not cover: permissions, setuid, setgid
/// and the sticky bit. Property 11 compares these EXACTLY.
const MODE_PERMISSION_MASK: u32 = 0o7777;

/// `S_IFREG`: the type bits naming a plain file, the only ones property 11's
/// fixture — a plain file — permits a container to add.
const S_IFREG: u32 = 0o100_000;

/// A `'static`, cloneable in-memory destination that can also be told to fail
/// every write once a byte budget is exhausted.
///
/// One type serves both property 3's ordinary destination
/// (`CaptureWriter::new`, read back via `contents()` once `finish()` has
/// consumed it) and property 4's failing one (`CaptureWriter::failing_after`)
/// — `Container::create` takes the destination by value, and although
/// `ArchiveWrite::finish` now hands a `Sink` back rather than dropping it,
/// the harness finishes that immediately, so nothing is left holding the
/// bytes unless the writer itself shares a handle to them.
#[derive(Clone)]
struct CaptureWriter {
    buf: Arc<Mutex<Vec<u8>>>,
    written: Arc<AtomicU64>,
    /// `Some(budget)`: every byte beyond `budget` already written fails.
    /// `None`: never fails.
    fail_after: Option<u64>,
}

impl CaptureWriter {
    fn new() -> Self {
        Self {
            buf: Arc::default(),
            written: Arc::new(AtomicU64::new(0)),
            fail_after: None,
        }
    }

    /// A destination that fails every write once `budget` bytes have already
    /// landed. `budget: 0` fails on the very first write — property 4's
    /// shape, a destination that fails every write.
    fn failing_after(budget: u64) -> Self {
        Self {
            buf: Arc::default(),
            written: Arc::new(AtomicU64::new(0)),
            fail_after: Some(budget),
        }
    }

    fn contents(&self) -> Vec<u8> {
        self.buf
            .lock()
            .expect("CaptureWriter mutex poisoned")
            .clone()
    }
}

impl Write for CaptureWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if let Some(budget) = self.fail_after {
            let already = self.written.load(Ordering::Relaxed);
            if already >= budget {
                return Err(io::Error::other("conformance: CaptureWriter failed"));
            }
            let allowed = ((budget - already).min(data.len() as u64)) as usize;
            self.buf
                .lock()
                .expect("CaptureWriter mutex poisoned")
                .extend_from_slice(&data[..allowed]);
            self.written.fetch_add(allowed as u64, Ordering::Relaxed);
            return Ok(allowed);
        }
        self.buf
            .lock()
            .expect("CaptureWriter mutex poisoned")
            .extend_from_slice(data);
        self.written.fetch_add(data.len() as u64, Ordering::Relaxed);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Writes `entries` through `container` and returns the archive bytes.
///
/// Panics with a generic (non "property N") message on failure: like the
/// codec harness's own `encode`/`decode` helpers, a `create`/`add`/`finish`
/// error here means the container is broken outright, not that one specific
/// property was violated — the properties that actually inspect this output
/// (2, 3) attribute their own failures separately.
fn build(container: &dyn Container, entries: &[(&str, &[u8])]) -> Vec<u8> {
    let id = container.id();
    let cap = CaptureWriter::new();
    let mut w = container
        .create(
            PlainSink::new(Box::new(cap.clone())),
            &CreateOpts::default(),
        )
        .unwrap_or_else(|e| panic!("conformance[{id}] create: {e}"));
    for (name, data) in entries {
        let meta = EntryMeta::file(*name);
        w.add(&meta, &mut io::Cursor::new(*data))
            .unwrap_or_else(|e| panic!("conformance[{id}] add({name}): {e}"));
    }
    w.finish()
        .unwrap_or_else(|e| panic!("conformance[{id}] finish: {e}"))
        .finish()
        .unwrap_or_else(|e| panic!("conformance[{id}] finish (sink): {e}"));
    cap.contents()
}

/// Reads every entry back out of `bytes` through `container`'s own reader,
/// via the ladder — the same path a real caller takes, not a hand-rolled
/// parse. Returns a `Result` rather than panicking internally: property 3
/// needs to attribute a read failure to itself (`property 3: ...`), which it
/// cannot do if this helper has already panicked with a generic message.
fn read_all(container: &dyn Container, bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let src: Box<dyn Source> = Box::new(ReaderSource::new(io::Cursor::new(bytes.to_vec())));
    let resolved = crate::resolve(
        src,
        container.id(),
        container.caps(),
        &crate::StreamPolicy::default(),
    )?;
    let mut ar = container.open(resolved, &OpenOpts::default())?;
    let mut out = Vec::new();
    while let Some(mut entry) = ar.next_entry()? {
        let name = entry.meta().name.clone();
        let mut data = Vec::new();
        entry.reader().read_to_end(&mut data)?;
        out.push((name, data));
    }
    Ok(out)
}

/// Runs `container` through the ladder via [`crate::StreamPolicy::ForwardOnly`]
/// over a source whose `Seek` capability is erased at the type level, then
/// opens it. Properties 5-8 all want the identical "as if reading from a
/// pipe" setup, so they share this rather than each re-deriving it.
///
/// A `Cursor` reporting `SourceCaps { seekable: false, .. }` still physically
/// supports positioned reads underneath; [`ReaderSource`] does not merely
/// report `false`, it stores its inner reader as `Box<dyn Read + Send>`
/// rather than `Box<dyn Read + Seek + Send>`, so there is no `Seek` left for
/// even a broken implementation to fall back on.
///
/// Panics with a generic (non "property N") message on setup failure, for the
/// same reason `build` does: a resolve/open failure here means the container
/// cannot do what `ContainerCaps` claims, not that one specific property was
/// violated.
///
/// `pub` and re-exported from [`crate::testing`] rather than private to this
/// module: a container's own tests in `stuffr-formats` need the IDENTICAL
/// "as if from a pipe" setup the harness uses — `tar.rs`'s rung test is the
/// first — and a hand-rolled second copy over there would be free to drift
/// from this one, which is exactly how a test ends up asserting against a
/// setup the harness no longer uses.
pub fn open_forward_only(container: &dyn Container, bytes: &[u8]) -> Box<dyn ArchiveRead> {
    let id = container.id();
    let src: Box<dyn Source> = Box::new(ReaderSource::new(io::Cursor::new(bytes.to_vec())));
    let resolved = crate::resolve(src, id, container.caps(), &crate::StreamPolicy::ForwardOnly)
        .unwrap_or_else(|e| panic!("conformance[{id}] resolve forward-only: {e}"));
    container
        .open(resolved, &OpenOpts::default())
        .unwrap_or_else(|e| panic!("conformance[{id}] open forward-only: {e}"))
}

/// Reads every entry back through [`open_forward_only`]'s non-seekable
/// source. Property 5 attributes a count mismatch to itself; this only
/// attributes setup and read failures, which mean the container is broken
/// outright.
fn read_all_forward_only(container: &dyn Container, bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let id = container.id();
    let mut ar = open_forward_only(container, bytes);
    let mut out = Vec::new();
    while let Some(mut entry) = ar
        .next_entry()
        .unwrap_or_else(|e| panic!("conformance[{id}] forward-only next_entry: {e}"))
    {
        let name = entry.meta().name.clone();
        let mut data = Vec::new();
        entry
            .reader()
            .read_to_end(&mut data)
            .unwrap_or_else(|e| panic!("conformance[{id}] forward-only entry read: {e}"));
        out.push((name, data));
    }
    out
}

/// A non-seekable source that counts bytes pulled from it, so property 8 can
/// MEASURE how much of an archive an implementation reads before the first
/// entry's data becomes reachable, rather than take streaming on trust.
struct CountingSource {
    inner: io::Cursor<Vec<u8>>,
    count: Arc<AtomicU64>,
}

impl CountingSource {
    fn new(bytes: &[u8]) -> Self {
        Self {
            inner: io::Cursor::new(bytes.to_vec()),
            count: Arc::new(AtomicU64::new(0)),
        }
    }

    /// A handle that still reports the running total after `self` has been
    /// boxed and handed to the ladder.
    fn counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.count)
    }
}

impl Read for CountingSource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

impl Source for CountingSource {
    fn caps(&self) -> SourceCaps {
        SourceCaps {
            seekable: false,
            len: None,
        }
    }

    fn as_seek(&mut self) -> Option<&mut dyn SeekRead> {
        None
    }
}

/// Opens `container` over `source` (forward-only policy) and returns how many
/// bytes were pulled from it by the time the first entry becomes reachable
/// via `next_entry` — before any of THAT entry's own data is read. A
/// container that buffers the whole archive during `open` or the first
/// `next_entry` call will have already consumed the entire source by then.
fn first_entry_source_bytes(container: &dyn Container, source: CountingSource) -> usize {
    let id = container.id();
    let counter = source.counter();
    let src: Box<dyn Source> = Box::new(source);
    let resolved = crate::resolve(src, id, container.caps(), &crate::StreamPolicy::ForwardOnly)
        .unwrap_or_else(|e| panic!("conformance[{id}] resolve forward-only: {e}"));
    let mut ar = container
        .open(resolved, &OpenOpts::default())
        .unwrap_or_else(|e| panic!("conformance[{id}] open forward-only: {e}"));
    ar.next_entry()
        .unwrap_or_else(|e| panic!("conformance[{id}] forward-only next_entry: {e}"))
        .unwrap_or_else(|| panic!("conformance[{id}] forward-only: expected at least one entry"));
    counter.load(Ordering::Relaxed) as usize
}

/// Recovers the `io::ErrorKind` a container's own `crate::Error` was raised
/// from, so properties 9 and 10 can assert on it directly rather than on the
/// error's `Display` text. `Error::Io` unwraps to the original `io::Error`
/// unchanged; `Error::Corrupt` — the classification every container is
/// expected to raise for malformed input, mirroring `Error::from_decode_io`
/// on the codec side — becomes `InvalidData`. Anything else becomes
/// `io::Error::other`, which satisfies neither property's expected kind and
/// so still fails loudly rather than passing by accident.
fn classify_container_error(e: crate::error::Error) -> io::Error {
    match e {
        crate::error::Error::Io(io_err) => io_err,
        crate::error::Error::Corrupt(msg) => io::Error::new(io::ErrorKind::InvalidData, msg),
        other => io::Error::other(other.to_string()),
    }
}

/// Attempts a full read of `bytes` through `container`, returning the first
/// error encountered (classified per [`classify_container_error`]), or `None`
/// if the archive read back with no error at all — which, fed a truncated
/// archive, means the truncation went completely undetected.
fn read_all_expecting_error(container: &dyn Container, bytes: &[u8]) -> Option<io::Error> {
    read_all(container, bytes)
        .err()
        .map(classify_container_error)
}

/// A source whose every read fails with `PermissionDenied`, standing in for a
/// disk that has gone bad partway through reading an archive. Property 10
/// exists to prove a container passes such an error through as itself rather
/// than relabelling it as corruption.
struct FailingSource;

impl Read for FailingSource {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "conformance: FailingSource",
        ))
    }
}

impl Source for FailingSource {
    fn caps(&self) -> SourceCaps {
        SourceCaps {
            seekable: false,
            len: None,
        }
    }

    fn as_seek(&mut self) -> Option<&mut dyn SeekRead> {
        None
    }
}

/// Opens `container` over a [`FailingSource`] and reads it to exhaustion,
/// returning the first error encountered (classified per
/// [`classify_container_error`]), or `None` if the whole archive read back
/// with no error at all — which, fed a source that fails every read, means
/// the failure went completely unnoticed.
///
/// A failure from `resolve` or `open` is RETURNED, not panicked on, unlike
/// every other setup helper in this module. The failing source is the point
/// here, and a container that meets it during setup has surfaced it just as
/// honestly as one that meets it mid-read — the property is that the error
/// arrives as ITSELF, not where it arrives. This matters for a container
/// declaring `needs_seek` over a forward-only source: the ladder spools it,
/// and the spool is what reads the failing source, so `resolve` is where the
/// error appears and panicking there would make the property unrunnable for
/// exactly the container shape (ARJ's) that most needs it.
fn read_all_over_failing_source(container: &dyn Container) -> Option<io::Error> {
    let src: Box<dyn Source> = Box::new(FailingSource);
    let resolved = match crate::resolve(
        src,
        container.id(),
        container.caps(),
        &crate::StreamPolicy::default(),
    ) {
        Ok(r) => r,
        Err(e) => return Some(classify_container_error(e)),
    };
    let mut ar = match container.open(resolved, &OpenOpts::default()) {
        Ok(ar) => ar,
        Err(e) => return Some(classify_container_error(e)),
    };
    loop {
        match ar.next_entry() {
            Ok(Some(mut entry)) => {
                let mut data = Vec::new();
                if let Err(e) = entry.reader().read_to_end(&mut data) {
                    return Some(e);
                }
            }
            Ok(None) => return None,
            Err(e) => return Some(classify_container_error(e)),
        }
    }
}

/// Like [`build`], but takes full [`EntryMeta`] per entry rather than
/// synthesizing a plain file entry — property 11 needs fields (e.g. `mode`)
/// that a bare name cannot express.
fn build_with_meta(container: &dyn Container, entries: &[(EntryMeta, &[u8])]) -> Vec<u8> {
    let id = container.id();
    let cap = CaptureWriter::new();
    let mut w = container
        .create(
            PlainSink::new(Box::new(cap.clone())),
            &CreateOpts::default(),
        )
        .unwrap_or_else(|e| panic!("conformance[{id}] create: {e}"));
    for (meta, data) in entries {
        w.add(meta, &mut io::Cursor::new(*data))
            .unwrap_or_else(|e| panic!("conformance[{id}] add({}): {e}", meta.name));
    }
    w.finish()
        .unwrap_or_else(|e| panic!("conformance[{id}] finish: {e}"))
        .finish()
        .unwrap_or_else(|e| panic!("conformance[{id}] finish (sink): {e}"));
    cap.contents()
}

/// Like [`read_all`], but returns the full [`EntryMeta`] per entry rather
/// than just name and data — property 11 needs to inspect fields such as
/// `mode` that a bare name/data pair drops.
fn read_all_meta(container: &dyn Container, bytes: &[u8]) -> Vec<EntryMeta> {
    let id = container.id();
    let src: Box<dyn Source> = Box::new(ReaderSource::new(io::Cursor::new(bytes.to_vec())));
    let resolved = crate::resolve(
        src,
        container.id(),
        container.caps(),
        &crate::StreamPolicy::default(),
    )
    .unwrap_or_else(|e| panic!("conformance[{id}] resolve: {e}"));
    let mut ar = container
        .open(resolved, &OpenOpts::default())
        .unwrap_or_else(|e| panic!("conformance[{id}] open: {e}"));
    let mut out = Vec::new();
    while let Some(mut entry) = ar
        .next_entry()
        .unwrap_or_else(|e| panic!("conformance[{id}] next_entry: {e}"))
    {
        let meta = entry.meta().clone();
        let mut data = Vec::new();
        entry
            .reader()
            .read_to_end(&mut data)
            .unwrap_or_else(|e| panic!("conformance[{id}] entry read: {e}"));
        out.push(meta);
    }
    out
}

/// Like [`read_all_meta`], but over a SEEKABLE source.
///
/// Property 13 needs this and the other read helpers do not. Every one of them
/// hands the container a [`ReaderSource`], which has no `Seek` to fall back on
/// at the type level — deliberately, because most properties here are about
/// the streaming premise. But `stores_symlinks` is a claim about what the
/// ARCHIVE records, and zip records a symlink's `S_IFLNK` in the central
/// directory's external attributes, which a forward read never reaches: zip's
/// own module doc says a piped read cannot see symlinks at all, and that is
/// the format's limitation, not a false capability claim. Reading back the way
/// a real caller reads a file on disk is what makes the property test the
/// claim rather than the source.
///
/// Seekable in MEMORY (`SpillPolicy::Memory`) rather than through a temp file,
/// so the harness still touches no filesystem.
fn read_all_meta_seekable(container: &dyn Container, bytes: &[u8]) -> Vec<EntryMeta> {
    let id = container.id();
    let forward: Box<dyn Source> = Box::new(ReaderSource::new(io::Cursor::new(bytes.to_vec())));
    let seekable = crate::source::SpillSource::materialize(
        forward,
        &crate::source::SpillPolicy::Memory {
            cap: 64 * 1024 * 1024,
        },
    )
    .unwrap_or_else(|e| panic!("conformance[{id}] materialize: {e}"));
    let resolved = crate::resolve(
        Box::new(seekable),
        container.id(),
        container.caps(),
        &crate::StreamPolicy::default(),
    )
    .unwrap_or_else(|e| panic!("conformance[{id}] resolve (seekable): {e}"));
    let mut ar = container
        .open(resolved, &OpenOpts::default())
        .unwrap_or_else(|e| panic!("conformance[{id}] open (seekable): {e}"));
    let mut out = Vec::new();
    while let Some(mut entry) = ar
        .next_entry()
        .unwrap_or_else(|e| panic!("conformance[{id}] next_entry (seekable): {e}"))
    {
        let meta = entry.meta().clone();
        let mut data = Vec::new();
        entry
            .reader()
            .read_to_end(&mut data)
            .unwrap_or_else(|e| panic!("conformance[{id}] entry read (seekable): {e}"));
        out.push(meta);
    }
    out
}

/// One entry a fixture is known to contain.
///
/// Content is stored inline rather than hashed: fixtures are small by
/// design, a byte comparison gives a far better failure message than a
/// hash mismatch, and it keeps `stuffr-core` free of a digest dependency.
#[derive(Debug, Clone)]
pub struct ExpectedEntry {
    pub name: &'static str,
    pub content: &'static [u8],
}

/// An archive with known contents, for a container that cannot write its own
/// test input.
///
/// **`provenance` is load-bearing, not decoration.** It records where
/// `expected` came from, and it is printed in every failure message this
/// harness raises. A fixture whose expectation was derived from the very
/// crate under test proves only that the crate agrees with itself; saying so
/// at the point of failure is what stops that being mistaken for evidence.
#[derive(Debug, Clone)]
pub struct ContainerFixture {
    pub bytes: &'static [u8],
    pub expected: &'static [ExpectedEntry],
    pub provenance: &'static str,
}

/// Asserts every conformance property that applies to a container which
/// CANNOT write its own test input — the shape every Phase 3 legacy format
/// takes (read-only, `caps.write == false`).
///
/// [`assert_container_conforms`] is unusable here: it calls `build()` inside
/// its `if caps.read` block, and `build()` unwraps `create()`, so a
/// `write: false` container kills the harness outright rather than running a
/// reduced property set (`the_write_gated_entry_point_cannot_run_a_read_only_
/// container` in `mod broken_containers` pins this). This entry point takes a
/// known-good `fixture` instead of building one, and runs the subset of
/// properties that make sense without a write side — deliberately a
/// SEPARATE function from `assert_container_conforms`, not a unified one with
/// more gating, for the same reason the codec side keeps
/// `assert_codec_conforms`/`assert_codec_conforms_with` apart. Its nine
/// properties are a RELABELLING, not a subset — see the module doc.
///
/// Every assertion message begins `conformance[{id}] fixture property N` and
/// includes `fixture provenance: {}`, so a red test says up front how
/// trustworthy its own expectation is — load-bearing where a later fixture's
/// `expected` was derived from the very crate under test. The `fixture` tag
/// is not decoration: this function's nine properties are numbered in a
/// scheme of their own, and five of those numbers mean something else in
/// [`assert_container_conforms`]'s thirteen. See the module doc, which
/// enumerates both.
pub fn assert_container_conforms_with(
    container: &dyn Container,
    meta: &FormatMeta,
    fixture: &ContainerFixture,
) {
    let id = container.id();
    let caps = container.caps();
    let provenance = fixture.provenance;

    // 1. Identity: a mismatched registration is otherwise silent.
    assert_eq!(
        id, meta.id,
        "conformance[{id}] fixture property 1: Container::id() disagrees with its registered \
         FormatMeta (fixture provenance: {provenance})"
    );

    // 2. Read-only declaration: caps.read must be true (this entry point has
    //    nothing to run otherwise), and if the container also declares
    //    write: false, create() must genuinely refuse rather than silently
    //    succeed — a read-only container that writes anyway is lying about
    //    its own caps.
    assert!(
        caps.read,
        "conformance[{id}] fixture property 2: assert_container_conforms_with requires caps.read \
         (fixture provenance: {provenance})"
    );
    if !caps.write {
        let result = container.create(
            PlainSink::new(Box::new(CaptureWriter::new())),
            &CreateOpts::default(),
        );
        match result {
            Ok(_) => panic!(
                "conformance[{id}] fixture property 2: caps.write is false but create() succeeded — \
                 a read-only container must refuse to write, not silently accept \
                 (fixture provenance: {provenance})"
            ),
            Err(e) => {
                if let Err(msg) = check_error_is_classified(&e) {
                    panic!(
                        "conformance[{id}] fixture property 8: create()'s read-only refusal is not \
                         classified: {msg} (fixture provenance: {provenance})"
                    );
                }
            }
        }
    }

    // 3. Magic agreement: AT LEAST ONE registered rule must match the
    //    fixture's own bytes. No round trip needed — the fixture already IS
    //    the encoded form.
    if !meta.magics.is_empty() {
        let hit = meta.magics.iter().any(|r| {
            fixture.bytes.len() >= r.offset + r.bytes.len()
                && &fixture.bytes[r.offset..r.offset + r.bytes.len()] == r.bytes
        });
        assert!(
            hit,
            "conformance[{id}] fixture property 3: no registered magic rule matches the fixture's \
             bytes (fixture provenance: {provenance})"
        );
    }

    // 4 & 5. Enumeration and content: read the fixture back through the
    //    container's own reader and compare against the manifest — this is
    //    the property the manifest exists for; without it the harness only
    //    proves the container returns *something*.
    let got = read_all(container, fixture.bytes).unwrap_or_else(|e| {
        panic!(
            "conformance[{id}] fixture property 4: failed to read the fixture back: {e} \
             (fixture provenance: {provenance})"
        )
    });
    let got_names: Vec<&str> = got.iter().map(|(name, _)| name.as_str()).collect();
    let want_names: Vec<&str> = fixture.expected.iter().map(|e| e.name).collect();
    assert_eq!(
        got_names, want_names,
        "conformance[{id}] fixture property 4: entry names/order disagree with the fixture's \
         manifest (fixture provenance: {provenance})"
    );
    for (got_entry, want_entry) in got.iter().zip(fixture.expected.iter()) {
        assert_eq!(
            &got_entry.1[..],
            want_entry.content,
            "conformance[{id}] fixture property 5: content mismatch for entry {:?} \
             (fixture provenance: {provenance})",
            want_entry.name
        );
    }

    // 6. Truncation. UNCONDITIONAL, mirroring the write-capable harness's own
    //    property 9: the one property a container author cannot vote
    //    themselves out of. The container must either error (classified, not
    //    exit 1) or return fewer entries than the manifest promises;
    //    silently returning the full expected set is the failure.
    let cut = fixture.bytes.len() / 2;
    if cut > 0 {
        match read_all(container, &fixture.bytes[..cut]) {
            Err(e) => {
                if let Err(msg) = check_error_is_classified(&e) {
                    panic!(
                        "conformance[{id}] fixture property 8: truncation error is not classified: \
                         {msg} (fixture provenance: {provenance})"
                    );
                }
            }
            Ok(entries) => {
                assert!(
                    entries.len() < fixture.expected.len(),
                    "conformance[{id}] fixture property 6: a fixture truncated to {cut} of {} bytes \
                     was accepted silently, returning all {} expected entries \
                     (fixture provenance: {provenance})",
                    fixture.bytes.len(),
                    fixture.expected.len(),
                );
            }
        }
    }

    // 7. Corruption: flip the middle byte. Never the expected content
    //    unchanged — an error, a short read, or different content are all
    //    acceptable.
    //
    //    GATED on the declared `ContainerCaps::detects_corruption`, exactly
    //    as the codec harness gates its own corruption property (property 9
    //    there) on `CodecCaps::detects_corruption`. Ungated, this was
    //    stricter than the codec harness applies to the same concept, with
    //    none of the argument that justifies making TRUNCATION unconditional
    //    — a container declaring no integrity check cannot promise to notice
    //    a flipped byte, and a fixture whose midpoint lands in a reserved,
    //    comment or padding field no reader consults would fail a CORRECT
    //    container. Both current fixtures pass only because their midpoints
    //    happen to land under a CRC. The skip is reported, never silent.
    if caps.detects_corruption == crate::format::CorruptionDetection::Never {
        eprintln!(
            "conformance[{id}] fixture property 7: skipped — this container declares \
             CorruptionDetection::Never, so no check exists to prove (fixture \
             provenance: {provenance})"
        );
    } else if !fixture.bytes.is_empty() {
        let mut corrupted = fixture.bytes.to_vec();
        let mid = corrupted.len() / 2;
        corrupted[mid] ^= 0xFF;
        match read_all(container, &corrupted) {
            Err(e) => {
                if let Err(msg) = check_error_is_classified(&e) {
                    panic!(
                        "conformance[{id}] fixture property 8: corruption error is not classified: \
                         {msg} (fixture provenance: {provenance})"
                    );
                }
            }
            Ok(entries) => {
                let unchanged = entries.len() == fixture.expected.len()
                    && entries
                        .iter()
                        .zip(fixture.expected.iter())
                        .all(|(g, w)| g.0 == w.name && g.1 == w.content);
                assert!(
                    !unchanged,
                    "conformance[{id}] fixture property 7: a corrupted fixture (middle byte flipped \
                     at offset {mid} of {}) read back byte-identical to the uncorrupted \
                     expectation — corruption went completely undetected \
                     (fixture provenance: {provenance})",
                    fixture.bytes.len(),
                );
            }
        }
    }

    // 9. A genuine source I/O error passes through as ITSELF, never
    //    relabelled as corruption — the write-capable harness's own property
    //    10, ported here because this is the one claim the read-only formats
    //    argue at length and nothing tested. `lha.rs` and `arj.rs` each carry
    //    a paragraph deriving, from the dependency's source, that folding
    //    `UnexpectedEof -> Corrupt` is safe BECAUSE a real source failure
    //    keeps its own `io::ErrorKind`. Hand-reasoning is exactly what this
    //    harness exists to replace: get it wrong and a failing disk is
    //    reported as a damaged archive (exit 5) instead of an i/o error
    //    (exit 1), which sends a user to re-download a file that was never
    //    the problem.
    //
    //    Needs no fixture: the source fails on its first read, so there is
    //    nothing for it to be a fixture OF.
    {
        let e = read_all_over_failing_source(container).unwrap_or_else(|| {
            panic!(
                "conformance[{id}] fixture property 9: a source that fails every read produced no \
                 error at all — the failure went completely unnoticed \
                 (fixture provenance: {provenance})"
            )
        });
        assert_eq!(
            e.kind(),
            io::ErrorKind::PermissionDenied,
            "conformance[{id}] fixture property 9: a source error surfaced as {:?} rather than \
             passing through — a disk failure must not be reported as corruption \
             (fixture provenance: {provenance})",
            e.kind()
        );
    }
}

pub fn assert_container_conforms(container: &dyn Container, meta: &FormatMeta) {
    let id = container.id();
    let caps = container.caps();

    // 1. Identity: a mismatched registration is otherwise silent.
    assert_eq!(
        id, meta.id,
        "conformance[{id}] property 1: Container::id() disagrees with its registered FormatMeta"
    );

    if caps.write && caps.read {
        // 2. Magic agreement: AT LEAST ONE registered rule must match, not
        //    every one. A container with alternative signatures would
        //    otherwise fail outright on its second rule.
        let bytes = build(container, &[("a.txt", b"alpha")]);
        if !meta.magics.is_empty() {
            let hit = meta.magics.iter().any(|r| {
                bytes.len() >= r.offset + r.bytes.len()
                    && &bytes[r.offset..r.offset + r.bytes.len()] == r.bytes
            });
            assert!(
                hit,
                "conformance[{id}] property 2: no registered magic rule matches what create() \
                 produced"
            );
        }

        // 3. Round trip, EMPTY FIRST. Zero entries is where containers break
        //    for the same reason empty input breaks codecs: the structure
        //    still needs its header and trailer.
        for entries in [
            &[][..],
            &[("a.txt", &b"alpha"[..])][..],
            &[("a.txt", &b"alpha"[..]), ("b/c.bin", &b"\x00\xff\x00"[..])][..],
        ] {
            let bytes = build(container, entries);
            let got = read_all(container, &bytes).unwrap_or_else(|e| {
                panic!(
                    "conformance[{id}] property 3: failed to read back {} entries: {e} (empty \
                     archives are the usual culprit)",
                    entries.len()
                )
            });
            assert_eq!(
                got.len(),
                entries.len(),
                "conformance[{id}] property 3: round trip yielded {} entries, expected {} \
                 (empty archives are the usual culprit)",
                got.len(),
                entries.len()
            );
            for ((want_name, want_data), (got_name, got_data)) in entries.iter().zip(&got) {
                assert_eq!(
                    got_name, want_name,
                    "conformance[{id}] property 3: entry name mismatch"
                );
                assert_eq!(
                    &got_data[..],
                    *want_data,
                    "conformance[{id}] property 3: entry DATA mismatch for {want_name}"
                );
            }
        }

        // 4. finish() flushes AND surfaces a write error that Drop would
        //    swallow. Pointed at a real hazard: zip's own Drop finalizes and
        //    writes failures to stderr, losing them.
        let mut w = container
            .create(
                PlainSink::new(Box::new(CaptureWriter::failing_after(0))),
                &CreateOpts::default(),
            )
            .unwrap_or_else(|e| panic!("conformance[{id}] create: {e}"));
        let meta_e = EntryMeta::file("a.txt");
        let added = w.add(&meta_e, &mut io::Cursor::new(b"alpha".as_slice()));
        // Chained: the container hands the destination back rather than
        // completing it, so the completion path property 4 is about now ends
        // at `Sink::finish` — an error surfacing there is the same error.
        let finished = w.finish().and_then(|sink| sink.finish());
        assert!(
            added.is_err() || finished.is_err(),
            "conformance[{id}] property 4: a destination that fails every write produced \
             neither an add() nor a finish() error"
        );
    }

    if caps.read {
        let bytes = build(
            container,
            &[("a.txt", &b"alpha"[..]), ("b.txt", &b"beta"[..])],
        );

        // 5. Forward parse from a GENUINELY non-seekable source — a real
        //    pipe-shaped reader, not a Cursor pretending to lack Seek. See
        //    `open_forward_only`'s doc comment for why `ReaderSource` is what
        //    makes this structural rather than a mere `caps()` claim.
        if caps.forward_parse {
            let fwd = read_all_forward_only(container, &bytes);
            assert_eq!(
                fwd.len(),
                2,
                "conformance[{id}] property 5: forward parse over a non-seekable source \
                 yielded {} entries, expected 2",
                fwd.len()
            );
        }

        // 6. by_index must return Err(NotSeekable) rather than lie when the
        //    ladder supplied a forward-only source.
        {
            let mut ar = open_forward_only(container, &bytes);
            match ar.by_index(0) {
                Err(crate::error::Error::NotSeekable { .. }) => {}
                Ok(_) => panic!(
                    "conformance[{id}] property 6: by_index() returned an entry from a \
                     forward-only source, claiming random access it does not have"
                ),
                Err(e) => panic!(
                    "conformance[{id}] property 6: by_index() on a forward-only source must \
                     be Err(NotSeekable), got {e:?}"
                ),
            }
        }

        // 7. Rung honesty. A trailing_index container read forward has not
        //    consulted its authoritative index, so it must not report Exact.
        if caps.trailing_index {
            let ar = open_forward_only(container, &bytes);
            let rung = ar.fidelity().rung;
            assert_ne!(
                rung,
                Rung::Exact,
                "conformance[{id}] property 7: a trailing-index container read forward \
                 reported Rung::Exact, but its authoritative index is at the END of the \
                 stream and was never read"
            );
        }

        // 8. Entry data streams incrementally, so `stuffr cat big.tar | head`
        //    does not buffer the archive. Measured by counting bytes pulled
        //    from the source before the FIRST entry's data is available.
        {
            let big = build(container, &[("big.bin", &vec![b'x'; 4 * 1024 * 1024][..])]);
            let counting = CountingSource::new(&big);
            let consumed = first_entry_source_bytes(container, counting);
            assert!(
                consumed < big.len(),
                "conformance[{id}] property 8: reaching the first entry consumed \
                 {consumed} of {} archive bytes — the whole archive was buffered",
                big.len()
            );
        }

        // 9. Truncation. UNCONDITIONAL on caps.read: cutting a stream is
        //    detectable structurally by every container here — a header
        //    promises a payload length the stream does not deliver.
        for cut in [1usize, bytes.len() / 3, bytes.len() / 2, bytes.len() - 1] {
            if cut == 0 || cut >= bytes.len() {
                continue;
            }
            let err = read_all_expecting_error(container, &bytes[..cut]);
            let Some(e) = err else {
                panic!(
                    "conformance[{id}] property 9: an archive truncated at {cut} of {} bytes \
                     was accepted silently",
                    bytes.len()
                )
            };
            assert_eq!(
                e.kind(),
                io::ErrorKind::InvalidData,
                "conformance[{id}] property 9: truncation at {cut} reported as {:?}, must be \
                 InvalidData so the CLI exits 5 rather than reporting a full disk",
                e.kind()
            );
        }

        // 9b. Truncation INSIDE an entry's payload, which the four cuts above
        //     cannot reach: on the small two-entry fixture they all land in a
        //     header or a trailer, so the payload path was never exercised
        //     and property 9 passed on framing checks alone. A cut `.tar.gz`
        //     is ordinary real-world damage, and Phase 1d found seven
        //     separate silent-truncation bugs on the codec side — including
        //     lz4 accepting a cut frame at every 64 KiB boundary while
        //     reporting success — so "some truncation is caught" is not
        //     enough.
        //
        //     The cut offset is PROVEN to land in payload rather than
        //     assumed, from three facts and no knowledge of any particular
        //     container's layout:
        //
        //     1. `framing` is measured — the same entry, same name, with an
        //        EMPTY payload — so it is this container's real per-entry
        //        overhead, not a guess.
        //     2. The payload is incompressible, so a container that
        //        compresses entries (zip) still stores ~`PAYLOAD` bytes of
        //        it; a repetitive payload would deflate to almost nothing
        //        and this construction would collapse.
        //     3. The payload occupies ONE contiguous run: everything before
        //        it plus everything after it is framing, so it starts at or
        //        before `framing` and ends at or after `len - framing`.
        //
        //     With `framing * 4 < len` asserted below, the midpoint is
        //     therefore strictly inside that run. If a future container's
        //     framing grows enough to break that margin, the assertion says
        //     so instead of the cut silently sliding back into a header.
        //
        //     Detection is required by the end of a full read, not
        //     necessarily mid-payload: a streaming container legitimately
        //     discovers the cut when the NEXT record's header comes up short
        //     (which is what `FramedMockContainer` does), and demanding an
        //     error from the payload read itself would fail a correct
        //     implementation.
        if caps.write {
            const PAYLOAD: usize = 64 * 1024;
            let name = "payload-truncation.bin";
            let framing = build(container, &[(name, &[][..])]).len();
            let payload = crate::conformance::incompressible(PAYLOAD);
            let bytes = build(container, &[(name, &payload)]);
            assert!(
                framing * 4 < bytes.len(),
                "conformance[{id}] property 9 (payload): this container's per-entry framing \
                 is {framing} bytes of a {}-byte archive, so a midpoint cut can no longer be \
                 proven to land inside the entry payload — raise PAYLOAD until it can",
                bytes.len()
            );

            let cut = bytes.len() / 2;
            let Some(e) = read_all_expecting_error(container, &bytes[..cut]) else {
                panic!(
                    "conformance[{id}] property 9 (payload): an archive truncated at {cut} \
                     of {} bytes — INSIDE the entry's payload, which starts at or before \
                     {framing} and runs to at or after {} — was accepted silently. The \
                     entry's own header promises {PAYLOAD} bytes the stream does not deliver",
                    bytes.len(),
                    bytes.len() - framing
                )
            };
            assert_eq!(
                e.kind(),
                io::ErrorKind::InvalidData,
                "conformance[{id}] property 9 (payload): truncation inside the entry payload \
                 reported as {:?}, must be InvalidData so the CLI exits 5 rather than \
                 reporting a full disk",
                e.kind()
            );
        }

        // 10. A genuine source I/O error passes through as itself.
        {
            let e = read_all_over_failing_source(container)
                .expect("a source that fails every read must produce an error");
            assert_eq!(
                e.kind(),
                io::ErrorKind::PermissionDenied,
                "conformance[{id}] property 10: a source error surfaced as {:?} rather than \
                 passing through — a disk failure must not be reported as corruption",
                e.kind()
            );
        }

        // 11. Metadata survives to the declared fidelity. Only fields the
        //     container claims to carry are checked; approximation is allowed
        //     on a lossy rung, silent LOSS on an exact one is not.
        //
        //     The fixture's mode is PERMISSION-ONLY (`0o640`, no `S_IFMT`
        //     type bits), which is what `entries.rs`'s `mode_of` hands every
        //     container — it masks to `0o7777` because tar's header field
        //     wants permissions alone. A container whose format records the
        //     entry kind IN the mode field (cpio `newc` has nowhere else to
        //     put it) must therefore be allowed to fold the type bits back
        //     in, and `S_IFREG` here, since the fixture is a plain file.
        //     That is the ONE transformation permitted: the permission bits
        //     are compared exactly, so a container that quietly widens
        //     `0o640` to `0o644` still fails, and the type bits may only
        //     become `S_IFREG` — relabelling the entry as a directory,
        //     symlink or device still fails.
        //
        //     This was not always so, and the reason is worth keeping: the
        //     property used to demand the mode come back BIT-IDENTICAL,
        //     which read as strict and in fact pinned cpio's own interop
        //     defect in place. stuffr's cpio wrote every regular file with
        //     no type bits at all, GNU cpio 2.15 answers `unknown file type`
        //     to that, skips the entry, and exits 0 — so an extraction lost
        //     every file it was asked for and said it succeeded. A property
        //     that forbids the fix is worse than no property.
        if caps.write {
            let mut meta_in = EntryMeta::file("m.txt");
            meta_in.mode = Some(0o640);
            let bytes = build_with_meta(container, &[(meta_in.clone(), &b"m"[..])]);
            let got = read_all_meta(container, &bytes);
            assert_eq!(
                got[0].name, meta_in.name,
                "conformance[{id}] property 11: entry name not preserved"
            );
            if let Some(got_mode) = got[0].mode {
                let want = meta_in.mode.expect("the fixture sets a mode");
                assert_eq!(
                    got_mode & MODE_PERMISSION_MASK,
                    want & MODE_PERMISSION_MASK,
                    "conformance[{id}] property 11: mode reported but altered — wrote \
                     {want:#o}, read back {got_mode:#o}, and the permission bits \
                     differ. Folding in the file-type bits a format needs is allowed; \
                     changing what the entry may be DONE with is not"
                );
                let type_bits = got_mode & MODE_TYPE_MASK;
                assert!(
                    type_bits == 0 || type_bits == S_IFREG,
                    "conformance[{id}] property 11: mode reported but altered — wrote \
                     {want:#o} for a plain FILE, read back {got_mode:#o}, whose type \
                     bits are {type_bits:#o}. A container may add S_IFREG \
                     ({S_IFREG:#o}) where its format records the kind in the mode \
                     field, and may leave the field as given; it may not relabel the \
                     entry as some other kind"
                );
            }
        }

        // 12. Hostile names survive VERBATIM. Deliberate inversion: the
        //     container must not help. Containment is enforced once, in ops,
        //     and it can only refuse what it can still see.
        if caps.write {
            let hostile = ["../../etc/passwd", "/abs/path", "a/../../b"];
            for name in hostile {
                let bytes = build(container, &[(name, &b"x"[..])]);
                let got = read_all(container, &bytes).unwrap_or_else(|e| {
                    panic!("conformance[{id}] property 12: failed to read back {name:?}: {e}")
                });
                assert_eq!(
                    got[0].0, name,
                    "conformance[{id}] property 12: entry name {name:?} came back as {:?}. \
                     Containers must report names EXACTLY as stored — sanitising here \
                     destroys the evidence the ops-layer refusal depends on",
                    got[0].0
                );
            }
        }

        // 13. `stores_dirs`/`stores_symlinks` are behaviour, not a claim.
        //     `entries.rs` writes a directory or a symlink entry when the flag
        //     is set and warns that it cannot when it is not, so a false claim
        //     silently produces a directory-shaped regular FILE — `ar`'s
        //     failure mode, and the reason these fields exist.
        //
        //     The NAME is deliberately not asserted: zip appends a trailing
        //     `/` to a directory entry by convention, which is the container
        //     being correct rather than altering anything. The kind is what
        //     the flag claims, and for a symlink the target too — a link whose
        //     target did not survive points somewhere else on extraction,
        //     which is a loss no `EntryKind` comparison alone would catch.
        //
        //     Empty data, because that is exactly what `entries.rs` hands a
        //     container for these two kinds: a directory has no payload, and a
        //     symlink's target lives in `EntryMeta`, not in the reader.
        if caps.write {
            if caps.stores_dirs {
                let mut meta_in = EntryMeta::file("d");
                meta_in.kind = crate::archive::EntryKind::Dir;
                meta_in.mode = Some(0o755);
                let bytes = build_with_meta(container, &[(meta_in, &[][..])]);
                let got = read_all_meta_seekable(container, &bytes);
                assert_eq!(
                    got.len(),
                    1,
                    "conformance[{id}] property 13 (directories): a directory entry was \
                     written but {} entries read back",
                    got.len()
                );
                assert_eq!(
                    got[0].kind,
                    crate::archive::EntryKind::Dir,
                    "conformance[{id}] property 13 (directories): caps claim stores_dirs, \
                     but a directory entry read back as {:?}. A directory written as a \
                     regular file makes every entry beneath it unextractable — its parent \
                     is a file",
                    got[0].kind
                );
            }
            if caps.stores_symlinks {
                let mut meta_in = EntryMeta::file("l");
                meta_in.kind = crate::archive::EntryKind::Symlink {
                    target: "a.txt".into(),
                };
                let bytes = build_with_meta(container, &[(meta_in, &[][..])]);
                let got = read_all_meta_seekable(container, &bytes);
                assert_eq!(
                    got.len(),
                    1,
                    "conformance[{id}] property 13 (symlinks): a symlink entry was written \
                     but {} entries read back",
                    got.len()
                );
                match &got[0].kind {
                    crate::archive::EntryKind::Symlink { target } => assert_eq!(
                        target, "a.txt",
                        "conformance[{id}] property 13 (symlinks): the link came back \
                         pointing at {target:?}, so the restored link would point \
                         somewhere else"
                    ),
                    other => panic!(
                        "conformance[{id}] property 13 (symlinks): caps claim \
                         stores_symlinks, but a symlink entry read back as {other:?}. \
                         Stored as a regular file, the target text becomes the file's \
                         contents"
                    ),
                }
            }
        }
    }
}

/// Runs `assert_container_conforms` and asserts it panics with a message
/// containing `expected` — not merely that it panics at all.
///
/// `catch_unwind` alone proves nothing about *which* property fired. Checking
/// the panic's own message is what ties each negative test back to the one
/// property it claims to cover — the check Phase 1f's R6 finding exists for:
/// a negative test that delegates to an inadequate double fires a different
/// property and passes while proving nothing.
#[cfg(test)]
fn assert_panics_naming(container: &dyn Container, meta: &FormatMeta, expected: &str) {
    let id = container.id();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_container_conforms(container, meta);
    }));
    match result {
        Ok(()) => panic!(
            "conformance[{id}]: expected assert_container_conforms to panic naming {expected:?}, \
             but it passed"
        ),
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("<non-string panic payload>");
            assert!(
                message.contains(expected),
                "conformance[{id}]: panicked, but the message did not mention {expected:?}: \
                 {message}"
            );
        }
    }
}

/// [`assert_panics_naming`]'s counterpart for the fixture-driven entry point.
/// Needed for the same reason that one is: `catch_unwind` alone proves
/// nothing about *which* property fired, only that something did.
#[cfg(test)]
fn assert_panics_naming_with(
    container: &dyn Container,
    meta: &FormatMeta,
    fixture: &ContainerFixture,
    expected: &str,
) {
    let id = container.id();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_container_conforms_with(container, meta, fixture);
    }));
    match result {
        Ok(()) => panic!(
            "conformance[{id}]: expected assert_container_conforms_with to panic naming \
             {expected:?}, but it passed"
        ),
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("<non-string panic payload>");
            assert!(
                message.contains(expected),
                "conformance[{id}]: panicked, but the message did not mention {expected:?}: \
                 {message}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{FramedMockContainer, framed_container_meta};

    #[test]
    fn a_well_behaved_container_satisfies_properties_one_to_thirteen() {
        assert_container_conforms(&FramedMockContainer, &framed_container_meta());
    }
}

/// Proof that the harness can actually fail, one property at a time.
///
/// Each broken container below delegates to [`FramedMockContainer`] for
/// everything except the one thing it deliberately gets wrong, and
/// [`assert_panics_naming`] confirms the resulting panic names exactly the
/// property that container breaks — not merely that some panic occurred.
#[cfg(test)]
mod broken_containers {
    use super::*;
    use crate::archive::{ArchiveRead, ArchiveWrite, Entry, Sink};
    use crate::error::Error;
    use crate::fidelity::FidelityReport;
    use crate::format::{ContainerCaps, CorruptionDetection, FormatId, MagicRule};
    use crate::ladder::Resolved;
    use crate::testing::{FramedMockContainer, framed_container_meta};
    use std::io::Read;

    /// Shared by every read-only double below, so `assert_container_conforms`
    /// and `assert_container_conforms_with` agree on which id names them.
    const READ_ONLY_DOUBLE: FormatId = FormatId::new("read-only-double");

    fn read_only_meta() -> FormatMeta {
        FormatMeta {
            id: READ_ONLY_DOUBLE,
            kind: crate::format::FormatKind::Container,
            magics: &[],
            extensions: &[],
            priority: 0,
        }
    }

    /// The caps every read-only double here declares, except
    /// [`FalselyWritable`], which spells its own out.
    ///
    /// Shared for ONE reason, and it is not boilerplate: `write: false` is
    /// the condition under which property 2's `create()` check runs at all,
    /// so eight independent copies were eight future chances to write
    /// `write: true` and silently disable that property for one double with
    /// nothing failing to say so. `detects_corruption` is load-bearing the
    /// same way for property 7. Everything ELSE each double duplicates — the
    /// `id()`/`open()`/`create()` glue — stays duplicated on purpose: that
    /// region is the perturbation surface, each double differs from the
    /// others in a different place, and flat copies are what make which
    /// place visible at the point of reading.
    fn read_only_double_caps() -> ContainerCaps {
        ContainerCaps {
            forward_parse: true,
            // These doubles wrap `FramedMockContainer`, whose framing does
            // detect a flipped byte, so property 7 genuinely runs against
            // them — `RestoresKnownContent` exists to fail it.
            detects_corruption: CorruptionDetection::Always,
            ..ContainerCaps::read_only()
        }
    }

    /// `read_only_meta()` with `magics` overridden — `read_only_meta()` itself
    /// declares none, which is what leaves property 3 (magic agreement)
    /// permanently skipped rather than exercised. The two tests right below
    /// `framed_fixture_bytes` are what actually run it, one each way.
    fn read_only_meta_with_magics(magics: &'static [MagicRule]) -> FormatMeta {
        FormatMeta {
            magics,
            ..read_only_meta()
        }
    }

    /// Matches the leading `"FE"` tag every `framed_fixture_bytes` archive
    /// begins with (see [`framed_fixture_bytes`]'s own doc comment for the
    /// wire format) — a real registered rule a well-formed fixture satisfies.
    const FRAMED_FIXTURE_MAGIC: MagicRule = MagicRule {
        offset: 0,
        bytes: b"FE",
        format: READ_ONLY_DOUBLE,
    };

    /// A rule no `framed_fixture_bytes` archive can ever match: every such
    /// archive begins `"FE"`, never `"NO"`, at offset 0 — genuinely ABSENT
    /// from the fixture, not merely checked at the wrong offset (which would
    /// test offset handling, not the "no rule matches" case property 3
    /// exists for).
    const ABSENT_MAGIC: MagicRule = MagicRule {
        offset: 0,
        bytes: b"NO",
        format: READ_ONLY_DOUBLE,
    };

    /// A container that reads but cannot write — the shape every Phase 3
    /// legacy format takes, and the shape that had never existed in this
    /// tree.
    struct ReadOnlyDouble;

    impl Container for ReadOnlyDouble {
        fn id(&self) -> FormatId {
            READ_ONLY_DOUBLE
        }
        fn caps(&self) -> ContainerCaps {
            ContainerCaps {
                read: true,
                write: false,
                forward_parse: false,
                needs_seek: true,
                ..Default::default()
            }
        }
        fn open(&self, _resolved: Resolved, _o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
            Err(Error::Unsupported("read-only-double: no fixture".into()))
        }
        fn create(&self, _dst: Box<dyn Sink>, _o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
            Err(Error::Unsupported("read-only-double cannot write".into()))
        }
    }

    /// `assert_container_conforms` calls `build()` inside its `if caps.read`
    /// block, and `build()` unwraps `create()`. A `write: false` container
    /// therefore kills the harness instead of running a reduced property set.
    ///
    /// This test exists to pin that the OLD entry point is unusable for a
    /// read-only container, which is why `assert_container_conforms_with` had
    /// to be added rather than the gating merely tightened.
    #[test]
    #[should_panic(expected = "create")]
    fn the_write_gated_entry_point_cannot_run_a_read_only_container() {
        assert_container_conforms(&ReadOnlyDouble, &read_only_meta());
    }

    /// The base every later read-only double in this phase wraps, rather than
    /// reimplements from scratch.
    ///
    /// Reuses [`FramedMockContainer`]'s own wire format and `ArchiveRead`
    /// wholesale — the "FE"/"FZ" length-prefixed framing already proven (by
    /// the tests above `mod broken_containers`) to detect truncation and
    /// corruption honestly — so this double's ONLY behavioural difference
    /// from `FramedMockContainer` is refusing to write, which is exactly the
    /// shape every Phase 3 legacy container takes. A hand-rolled second parser
    /// here would have to re-earn that honesty from scratch, and would be
    /// free to drift from the one already proven.
    ///
    /// Holds the fixture it was built from so a WRAPPING double can reach it
    /// — e.g. one that ignores a genuine parse failure and serves the
    /// fixture's own expectation regardless of what the source actually
    /// contained ("ignored truncation"). A double that instead needs to
    /// perturb what a real parse produced (a dropped entry, a renamed entry,
    /// wrong content) wraps the `Box<dyn ArchiveRead>` `open` returns here,
    /// the same way every double in `mod broken_containers` above wraps
    /// `FramedMockContainer`'s.
    struct MockReadOnly {
        fixture: ContainerFixture,
    }

    impl MockReadOnly {
        fn new(fixture: &ContainerFixture) -> Self {
            Self {
                fixture: fixture.clone(),
            }
        }

        /// The fixture this double was built from.
        fn fixture(&self) -> &ContainerFixture {
            &self.fixture
        }
    }

    impl Container for MockReadOnly {
        fn id(&self) -> FormatId {
            READ_ONLY_DOUBLE
        }
        fn caps(&self) -> ContainerCaps {
            read_only_double_caps()
        }
        fn open(&self, resolved: Resolved, o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
            FramedMockContainer.open(resolved, o)
        }
        fn create(&self, _dst: Box<dyn Sink>, _o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
            Err(Error::Unsupported("mock-read-only cannot write".into()))
        }
    }

    /// Builds bytes in `FramedMockContainer`'s own wire format
    /// (`repeat: "FE" | name_len u32le | name | data_len u64le | data`,
    /// `trailer: "FZ"`) by hand, so `MockReadOnly` — a container that cannot
    /// write — has something genuine to read. Leaked rather than a `const`
    /// byte literal: computing it once from the entry list is what keeps this
    /// test's fixture and its manifest (`ExpectedEntry`) impossible to drift
    /// apart by hand-transcription error.
    fn framed_fixture_bytes(entries: &[(&str, &[u8])]) -> &'static [u8] {
        let mut out = Vec::new();
        for (name, data) in entries {
            out.extend_from_slice(b"FE");
            out.extend_from_slice(&(name.len() as u32).to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&(data.len() as u64).to_le_bytes());
            out.extend_from_slice(data);
        }
        out.extend_from_slice(b"FZ");
        Box::leak(out.into_boxed_slice())
    }

    #[test]
    fn the_fixture_entry_point_accepts_a_read_only_container() {
        let fx = ContainerFixture {
            bytes: framed_fixture_bytes(&[("a.txt", b"alpha")]),
            expected: &[ExpectedEntry {
                name: "a.txt",
                content: b"alpha",
            }],
            provenance: "hand-built in this test",
        };
        assert_container_conforms_with(&MockReadOnly::new(&fx), &read_only_meta(), &fx);
    }

    /// Pins the contract the wrapping doubles below depend on: `new`
    /// actually stores what it is given, and `fixture()` hands it back
    /// unaltered. Without this, `MockReadOnly::fixture` would be a field no
    /// test exercises.
    #[test]
    fn mock_read_only_exposes_the_fixture_it_was_built_from() {
        let fx = ContainerFixture {
            bytes: framed_fixture_bytes(&[("a.txt", b"alpha")]),
            expected: &[ExpectedEntry {
                name: "a.txt",
                content: b"alpha",
            }],
            provenance: "mock_read_only_exposes_the_fixture_it_was_built_from",
        };
        let mock = MockReadOnly::new(&fx);
        assert_eq!(mock.fixture().bytes, fx.bytes);
        assert_eq!(mock.fixture().provenance, fx.provenance);
    }

    /// Property 3 (magic agreement) is gated on `!meta.magics.is_empty()`,
    /// and every fixture above declares none — so nothing above ever runs
    /// it. This is the PASSING case: a `FormatMeta` that declares a rule the
    /// fixture's own bytes genuinely satisfy, proving the property executes
    /// and does not wrongly reject a matching fixture — not merely that it
    /// never rejects because it is skipped.
    #[test]
    fn the_fixture_entry_point_checks_magic_agreement_when_the_format_declares_one() {
        let fx = ContainerFixture {
            bytes: framed_fixture_bytes(&[("a.txt", b"alpha")]),
            expected: &[ExpectedEntry {
                name: "a.txt",
                content: b"alpha",
            }],
            provenance: "hand-built in this test",
        };
        let meta = read_only_meta_with_magics(&[FRAMED_FIXTURE_MAGIC]);
        assert_container_conforms_with(&MockReadOnly::new(&fx), &meta, &fx);
    }

    /// The FAILING half: without this, the passing test above only shows the
    /// property does not wrongly reject — it says nothing about whether the
    /// property can actually catch a real mismatch. `ABSENT_MAGIC` names a
    /// rule this fixture's bytes never satisfy at offset 0, so property 3
    /// must panic.
    ///
    /// Mirrors the write-capable harness's own property 2 semantics: AT LEAST
    /// ONE registered rule must match, not every one (a format with
    /// alternative signatures is not failed by its second rule). A single
    /// non-matching rule here is the minimal case of that — zero of one
    /// matching — not a claim that every rule must match.
    #[test]
    fn property_three_catches_a_fixture_that_matches_no_registered_magic() {
        let fx = ContainerFixture {
            bytes: framed_fixture_bytes(&[("a.txt", b"alpha")]),
            expected: &[ExpectedEntry {
                name: "a.txt",
                content: b"alpha",
            }],
            provenance: "hand-built in this test",
        };
        let meta = read_only_meta_with_magics(&[ABSENT_MAGIC]);
        assert_panics_naming_with(&MockReadOnly::new(&fx), &meta, &fx, "fixture property 3");
    }

    // -----------------------------------------------------------------
    // Doubles for `assert_container_conforms_with`'s OWN property set —
    // proving the fixture-driven harness can fail, not just the
    // write-capable one below. Property 3 already has both halves right
    // above.
    //
    // EVERY property that admits a double has one, rather than only the
    // handful whose failure modes look most likely: properties 1, 2, 7 and
    // 8 were at one point hand-reasoned and never exercised by a failing
    // test, which is exactly the gap that let property 3 sit dormant
    // through a whole review round before this file caught it.
    //
    // Every double here delegates to `FramedMockContainer` for parsing —
    // the same wire format `MockReadOnly` itself forwards to — and perturbs
    // exactly one thing, the same style every double above this point in
    // the module already uses for the write-capable harness.
    // -----------------------------------------------------------------

    /// Property 1's fixture-entry-point half. Identical reason to the
    /// write-capable double below: a mismatched `id()` is otherwise
    /// completely silent, and nothing else here would catch it.
    struct WrongIdReadOnly;

    impl Container for WrongIdReadOnly {
        fn id(&self) -> FormatId {
            FormatId::new("wrong-id-read-only")
        }
        fn caps(&self) -> ContainerCaps {
            read_only_double_caps()
        }
        fn open(&self, resolved: Resolved, o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
            FramedMockContainer.open(resolved, o)
        }
        fn create(&self, _dst: Box<dyn Sink>, _o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
            Err(Error::Unsupported("wrong-id-read-only cannot write".into()))
        }
    }

    #[test]
    fn fixture_property_one_catches_a_mismatched_id() {
        let fx = ContainerFixture {
            bytes: framed_fixture_bytes(&[("a.txt", b"alpha")]),
            expected: &[ExpectedEntry {
                name: "a.txt",
                content: b"alpha",
            }],
            provenance: "hand-built in this test",
        };
        assert_panics_naming_with(
            &WrongIdReadOnly,
            &read_only_meta(),
            &fx,
            "fixture property 1",
        );
    }

    /// Property 2's write-refusal half. A container that claims
    /// `caps.write == false` must have `create()` actually refuse — this one
    /// claims read-only and then writes successfully anyway, which is the
    /// dishonesty the check exists to catch. Nothing else in this harness
    /// ever calls `create()`, so without this double the check runs and
    /// never sees a failing case.
    struct FalselyWritable;

    impl Container for FalselyWritable {
        fn id(&self) -> FormatId {
            READ_ONLY_DOUBLE
        }
        fn caps(&self) -> ContainerCaps {
            // NOT `read_only_double_caps()`, deliberately: this double's
            // entire perturbation is the gap between `write: false` here and
            // a `create()` that succeeds anyway, so the claim it lies about
            // is spelled out at the point of reading.
            ContainerCaps {
                read: true,
                write: false,
                forward_parse: true,
                detects_corruption: CorruptionDetection::Always,
                ..Default::default()
            }
        }
        fn open(&self, resolved: Resolved, o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
            FramedMockContainer.open(resolved, o)
        }
        fn create(&self, dst: Box<dyn Sink>, o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
            // BUG: claims caps.write == false but create() succeeds anyway.
            FramedMockContainer.create(dst, o)
        }
    }

    #[test]
    fn fixture_property_two_catches_a_write_that_should_have_been_refused() {
        let fx = ContainerFixture {
            bytes: framed_fixture_bytes(&[("a.txt", b"alpha")]),
            expected: &[ExpectedEntry {
                name: "a.txt",
                content: b"alpha",
            }],
            provenance: "hand-built in this test",
        };
        assert_panics_naming_with(
            &FalselyWritable,
            &read_only_meta(),
            &fx,
            "fixture property 2",
        );
    }

    /// Property 8, isolated from the three properties that embed it (2, 6,
    /// 7): `Error::Io` is unclassified (falls through `exit_code`'s
    /// wildcard to exit 1, "stuffr failed"), so a read-only refusal reported
    /// that way must be caught even though the refusal itself is otherwise
    /// entirely correct.
    struct MisclassifiesRefusal;

    impl Container for MisclassifiesRefusal {
        fn id(&self) -> FormatId {
            READ_ONLY_DOUBLE
        }
        fn caps(&self) -> ContainerCaps {
            read_only_double_caps()
        }
        fn open(&self, resolved: Resolved, o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
            FramedMockContainer.open(resolved, o)
        }
        fn create(&self, _dst: Box<dyn Sink>, _o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
            // BUG: refuses to write (correctly), but as an unclassified
            // error rather than a capability limit.
            Err(Error::Io(io::Error::other(
                "misclassifies-refusal: refuses to write",
            )))
        }
    }

    #[test]
    fn fixture_property_eight_catches_an_unclassified_write_refusal() {
        let fx = ContainerFixture {
            bytes: framed_fixture_bytes(&[("a.txt", b"alpha")]),
            expected: &[ExpectedEntry {
                name: "a.txt",
                content: b"alpha",
            }],
            provenance: "hand-built in this test",
        };
        assert_panics_naming_with(
            &MisclassifiesRefusal,
            &read_only_meta(),
            &fx,
            "fixture property 8",
        );
    }

    /// Property 4 (enumeration), first half: drops the LAST entry. A
    /// one-entry lookahead is enough — the fixture harness has no
    /// incrementality property to trip, so there is no reason to buffer the
    /// whole archive just to recognise "this was the last one".
    struct DropsAnEntry;

    struct DropsAnEntryRead {
        inner: Box<dyn ArchiveRead>,
        pending: Option<(EntryMeta, Vec<u8>)>,
    }

    impl DropsAnEntryRead {
        fn pull(inner: &mut dyn ArchiveRead) -> Result<Option<(EntryMeta, Vec<u8>)>> {
            let Some(mut entry) = inner.next_entry()? else {
                return Ok(None);
            };
            let meta = entry.meta().clone();
            let mut data = Vec::new();
            entry.reader().read_to_end(&mut data)?;
            Ok(Some((meta, data)))
        }
    }

    impl ArchiveRead for DropsAnEntryRead {
        fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
            if self.pending.is_none() {
                self.pending = Self::pull(&mut *self.inner)?;
            }
            let Some(current) = self.pending.take() else {
                return Ok(None);
            };
            // BUG: peeks one entry ahead; if there is none, `current` WAS
            // the last entry, and it is withheld instead of returned.
            self.pending = Self::pull(&mut *self.inner)?;
            if self.pending.is_none() {
                return Ok(None);
            }
            let (meta, data) = current;
            Ok(Some(Entry::new(meta, Box::new(io::Cursor::new(data)))))
        }
        fn by_index(&mut self, index: usize) -> Result<Entry<'_>> {
            self.inner.by_index(index)
        }
        fn fidelity(&self) -> &FidelityReport {
            self.inner.fidelity()
        }
    }

    impl Container for DropsAnEntry {
        fn id(&self) -> FormatId {
            READ_ONLY_DOUBLE
        }
        fn caps(&self) -> ContainerCaps {
            read_only_double_caps()
        }
        fn open(&self, resolved: Resolved, o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
            Ok(Box::new(DropsAnEntryRead {
                inner: FramedMockContainer.open(resolved, o)?,
                pending: None,
            }))
        }
        fn create(&self, _dst: Box<dyn Sink>, _o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
            Err(Error::Unsupported("drops-an-entry cannot write".into()))
        }
    }

    #[test]
    fn fixture_property_four_catches_a_reader_that_drops_the_last_entry() {
        let fx = ContainerFixture {
            bytes: framed_fixture_bytes(&[("a.txt", b"alpha"), ("b.txt", b"beta")]),
            expected: &[
                ExpectedEntry {
                    name: "a.txt",
                    content: b"alpha",
                },
                ExpectedEntry {
                    name: "b.txt",
                    content: b"beta",
                },
            ],
            provenance: "hand-built in this test",
        };
        assert_panics_naming_with(&DropsAnEntry, &read_only_meta(), &fx, "fixture property 4");
    }

    /// Property 4, second half: renames the FIRST entry. `DropsAnEntry`
    /// above changes the entry COUNT; this changes only a NAME — a distinct
    /// way the same `assert_eq!` on the name vector can fail, and the two
    /// together are what stop one bug shape standing in for the other.
    struct RenamesAnEntry;

    struct RenamesAnEntryRead {
        inner: Box<dyn ArchiveRead>,
        seen_first: bool,
    }

    impl ArchiveRead for RenamesAnEntryRead {
        fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
            let Some(entry) = self.inner.next_entry()? else {
                return Ok(None);
            };
            if !self.seen_first {
                self.seen_first = true;
                let mut meta = entry.meta().clone();
                // BUG: the first entry is silently renamed.
                meta.name.push_str("-renamed");
                return Ok(Some(Entry::new(meta, entry.into_reader())));
            }
            Ok(Some(entry))
        }
        fn by_index(&mut self, index: usize) -> Result<Entry<'_>> {
            self.inner.by_index(index)
        }
        fn fidelity(&self) -> &FidelityReport {
            self.inner.fidelity()
        }
    }

    impl Container for RenamesAnEntry {
        fn id(&self) -> FormatId {
            READ_ONLY_DOUBLE
        }
        fn caps(&self) -> ContainerCaps {
            read_only_double_caps()
        }
        fn open(&self, resolved: Resolved, o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
            Ok(Box::new(RenamesAnEntryRead {
                inner: FramedMockContainer.open(resolved, o)?,
                seen_first: false,
            }))
        }
        fn create(&self, _dst: Box<dyn Sink>, _o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
            Err(Error::Unsupported("renames-an-entry cannot write".into()))
        }
    }

    #[test]
    fn fixture_property_four_catches_a_reader_that_renames_the_first_entry() {
        let fx = ContainerFixture {
            bytes: framed_fixture_bytes(&[("a.txt", b"alpha"), ("b.txt", b"beta")]),
            expected: &[
                ExpectedEntry {
                    name: "a.txt",
                    content: b"alpha",
                },
                ExpectedEntry {
                    name: "b.txt",
                    content: b"beta",
                },
            ],
            provenance: "hand-built in this test",
        };
        assert_panics_naming_with(
            &RenamesAnEntry,
            &read_only_meta(),
            &fx,
            "fixture property 4",
        );
    }

    /// Property 5 (content): right names, wrong bytes. This is the double
    /// that matters most — a container which enumerates correctly and
    /// decodes wrongly is exactly what a fixture with no `expected`
    /// content would wave through.
    struct CorruptsContent;

    struct CorruptsContentRead {
        inner: Box<dyn ArchiveRead>,
    }

    impl ArchiveRead for CorruptsContentRead {
        fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
            let Some(mut entry) = self.inner.next_entry()? else {
                return Ok(None);
            };
            let meta = entry.meta().clone();
            let mut data = Vec::new();
            entry.reader().read_to_end(&mut data)?;
            // BUG: the name is reported correctly; the content is not.
            match data.first_mut() {
                Some(byte) => *byte ^= 0xFF,
                None => data.push(0xFF),
            }
            Ok(Some(Entry::new(meta, Box::new(io::Cursor::new(data)))))
        }
        fn by_index(&mut self, index: usize) -> Result<Entry<'_>> {
            self.inner.by_index(index)
        }
        fn fidelity(&self) -> &FidelityReport {
            self.inner.fidelity()
        }
    }

    impl Container for CorruptsContent {
        fn id(&self) -> FormatId {
            READ_ONLY_DOUBLE
        }
        fn caps(&self) -> ContainerCaps {
            read_only_double_caps()
        }
        fn open(&self, resolved: Resolved, o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
            Ok(Box::new(CorruptsContentRead {
                inner: FramedMockContainer.open(resolved, o)?,
            }))
        }
        fn create(&self, _dst: Box<dyn Sink>, _o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
            Err(Error::Unsupported("corrupts-content cannot write".into()))
        }
    }

    #[test]
    fn fixture_property_five_catches_a_reader_that_serves_wrong_content_for_the_right_name() {
        let fx = ContainerFixture {
            bytes: framed_fixture_bytes(&[("a.txt", b"alpha")]),
            expected: &[ExpectedEntry {
                name: "a.txt",
                content: b"alpha",
            }],
            provenance: "hand-built in this test",
        };
        assert_panics_naming_with(
            &CorruptsContent,
            &read_only_meta(),
            &fx,
            "fixture property 5",
        );
    }

    /// Property 6 (truncation): ignores the actual input entirely and
    /// always serves the fixture's own known-good manifest, regardless of
    /// what bytes `open()` was actually handed. The strongest way to violate
    /// property 6 — it does not even look at `resolved`.
    struct IgnoresTruncation {
        known: Vec<(String, Vec<u8>)>,
    }

    impl IgnoresTruncation {
        fn from_fixture(fixture: &ContainerFixture) -> Self {
            Self {
                known: fixture
                    .expected
                    .iter()
                    .map(|e| (e.name.to_string(), e.content.to_vec()))
                    .collect(),
            }
        }
    }

    struct IgnoresTruncationRead {
        known: Vec<(String, Vec<u8>)>,
        pos: usize,
        report: FidelityReport,
    }

    impl ArchiveRead for IgnoresTruncationRead {
        fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
            let Some((name, data)) = self.known.get(self.pos).cloned() else {
                return Ok(None);
            };
            self.pos += 1;
            Ok(Some(Entry::new(
                EntryMeta::file(name),
                Box::new(io::Cursor::new(data)),
            )))
        }
        fn by_index(&mut self, index: usize) -> Result<Entry<'_>> {
            match self.known.get(index).cloned() {
                Some((name, data)) => Ok(Entry::new(
                    EntryMeta::file(name),
                    Box::new(io::Cursor::new(data)),
                )),
                None => Err(Error::EntryNotFound(index.to_string())),
            }
        }
        fn fidelity(&self) -> &FidelityReport {
            &self.report
        }
    }

    impl Container for IgnoresTruncation {
        fn id(&self) -> FormatId {
            READ_ONLY_DOUBLE
        }
        fn caps(&self) -> ContainerCaps {
            read_only_double_caps()
        }
        fn open(&self, _resolved: Resolved, _o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
            // BUG: never looks at the resolved source, so a genuinely
            // truncated (or corrupted) input is served the identical
            // known-good manifest as an untouched one.
            Ok(Box::new(IgnoresTruncationRead {
                known: self.known.clone(),
                pos: 0,
                report: FidelityReport::exact(),
            }))
        }
        fn create(&self, _dst: Box<dyn Sink>, _o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
            Err(Error::Unsupported("ignores-truncation cannot write".into()))
        }
    }

    #[test]
    fn fixture_property_six_catches_a_reader_that_ignores_truncation() {
        let fx = ContainerFixture {
            bytes: framed_fixture_bytes(&[("a.txt", b"alpha"), ("b.txt", b"beta")]),
            expected: &[
                ExpectedEntry {
                    name: "a.txt",
                    content: b"alpha",
                },
                ExpectedEntry {
                    name: "b.txt",
                    content: b"beta",
                },
            ],
            provenance: "hand-built in this test",
        };
        assert_panics_naming_with(
            &IgnoresTruncation::from_fixture(&fx),
            &read_only_meta(),
            &fx,
            "fixture property 6",
        );
    }

    /// Property 7 (corruption), deliberately distinct from `IgnoresTruncation`
    /// above. A double that merely "ignores whatever the input actually
    /// was" trips property 6 FIRST, since it runs before property 7 and
    /// looks identical from a truncated input's point of view — so isolating
    /// property 7 needs a double that tells the two apart.
    ///
    /// This one passes truncation through HONESTLY: it drains whatever the
    /// real, possibly-short payload actually was, so a genuinely truncated
    /// input still surfaces as a real parse error exactly as it would
    /// without this double (see the property-6 test below, which passes).
    /// Only CONTENT is repaired, and only after a structurally successful
    /// parse: the real (possibly byte-flipped) payload is discarded and
    /// replaced with the fixture's own known-good bytes for that entry name.
    /// The fixture's payload is long enough that the harness's middle-byte
    /// flip always lands inside it, never inside the header, so corruption
    /// never prevents the structural parse from succeeding.
    struct RestoresKnownContent {
        known: Vec<(String, Vec<u8>)>,
        /// What this double's `caps()` DECLARES. `Always` is the ordinary
        /// case; `Never` exists to prove property 7's evidence gate is real
        /// — see `a_container_declaring_no_corruption_detection_skips_-
        /// property_seven`.
        declares: CorruptionDetection,
    }

    impl RestoresKnownContent {
        fn from_fixture(fixture: &ContainerFixture) -> Self {
            Self {
                known: fixture
                    .expected
                    .iter()
                    .map(|e| (e.name.to_string(), e.content.to_vec()))
                    .collect(),
                declares: CorruptionDetection::Always,
            }
        }

        /// The same broken reader, declaring no corruption detection at all.
        fn undeclared(fixture: &ContainerFixture) -> Self {
            Self {
                declares: CorruptionDetection::Never,
                ..Self::from_fixture(fixture)
            }
        }
    }

    struct RestoresKnownContentRead {
        inner: Box<dyn ArchiveRead>,
        known: Vec<(String, Vec<u8>)>,
    }

    impl ArchiveRead for RestoresKnownContentRead {
        fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
            let Some(mut entry) = self.inner.next_entry()? else {
                return Ok(None);
            };
            let meta = entry.meta().clone();
            // Drains the REAL (possibly corrupted) payload, so a genuine
            // parse failure or a genuine short read still surfaces exactly
            // as it would without this double.
            let mut real = Vec::new();
            entry.reader().read_to_end(&mut real)?;
            // BUG: substitutes the fixture's own known-good bytes for this
            // entry's name instead of what was actually decoded.
            let content = self
                .known
                .iter()
                .find(|(name, _)| *name == meta.name)
                .map(|(_, data)| data.clone())
                .unwrap_or(real);
            Ok(Some(Entry::new(meta, Box::new(io::Cursor::new(content)))))
        }
        fn by_index(&mut self, index: usize) -> Result<Entry<'_>> {
            self.inner.by_index(index)
        }
        fn fidelity(&self) -> &FidelityReport {
            self.inner.fidelity()
        }
    }

    impl Container for RestoresKnownContent {
        fn id(&self) -> FormatId {
            READ_ONLY_DOUBLE
        }
        fn caps(&self) -> ContainerCaps {
            ContainerCaps {
                detects_corruption: self.declares,
                ..read_only_double_caps()
            }
        }
        fn open(&self, resolved: Resolved, o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
            Ok(Box::new(RestoresKnownContentRead {
                inner: FramedMockContainer.open(resolved, o)?,
                known: self.known.clone(),
            }))
        }
        fn create(&self, _dst: Box<dyn Sink>, _o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
            Err(Error::Unsupported(
                "restores-known-content cannot write".into(),
            ))
        }
    }

    #[test]
    fn fixture_property_seven_catches_a_reader_that_repairs_corrupted_content() {
        // A single 40-byte payload: long enough that the harness's
        // middle-byte flip (at `bytes.len() / 2`) always lands inside the
        // payload, never inside the 15-byte header (`"FE"` + u32 name_len +
        // 1-byte name + u64 data_len), so the real parse below stays
        // structurally intact and only the content differs.
        const PAYLOAD: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn";
        assert_eq!(PAYLOAD.len(), 40);
        let fx = ContainerFixture {
            bytes: framed_fixture_bytes(&[("a", PAYLOAD)]),
            expected: &[ExpectedEntry {
                name: "a",
                content: PAYLOAD,
            }],
            provenance: "hand-built in this test",
        };
        assert_panics_naming_with(
            &RestoresKnownContent::from_fixture(&fx),
            &read_only_meta(),
            &fx,
            "fixture property 7",
        );
    }

    /// The over-strictness half of property 7's evidence gate: the SAME
    /// broken reader, declaring `CorruptionDetection::Never`, must be let
    /// through rather than failed.
    ///
    /// Without this, gating the property would be indistinguishable from
    /// deleting it — a gate that is never observed to skip anything is not
    /// evidence of a gate. It is the container-side twin of the codec
    /// harness's own `detects_corruption == Never` skip, and the reason it
    /// is safe is the same: a format with no integrity check cannot notice a
    /// flipped byte, and demanding it forces a fake.
    #[test]
    fn a_container_declaring_no_corruption_detection_skips_property_seven() {
        const PAYLOAD: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn";
        let fx = ContainerFixture {
            bytes: framed_fixture_bytes(&[("a", PAYLOAD)]),
            expected: &[ExpectedEntry {
                name: "a",
                content: PAYLOAD,
            }],
            provenance: "hand-built in this test",
        };
        // No panic: property 7 is skipped on the declaration, and every
        // other property this double satisfies still runs.
        assert_container_conforms_with(
            &RestoresKnownContent::undeclared(&fx),
            &read_only_meta(),
            &fx,
        );
    }

    /// Property 9 (source-error passthrough): a reader that answers a
    /// genuine i/o failure with a clean end-of-archive.
    ///
    /// This is the shape the property exists to catch, and it is not
    /// hypothetical — it is what a `next_entry` written as
    /// `self.inner.next_entry().unwrap_or(None)`, or one that folds every
    /// error to `Corrupt` on the way past, actually does. A failing disk
    /// then reads back as a valid, empty archive: `stuffr list` prints
    /// nothing at exit 0, and `unpack` makes an empty directory and calls it
    /// done. `lha.rs` and `arj.rs` each argue at length that they do NOT do
    /// this; the double is what makes the argument checkable.
    ///
    /// `RESULT` selects which of the two wrong answers the double gives, so
    /// one double covers both: swallowing the error entirely, and
    /// relabelling it as corruption (exit 5 for a full disk — the error is
    /// reported, but as the wrong thing, and `check_error_is_classified`
    /// cannot see that because `Corrupt` is perfectly well classified).
    struct SwallowsSourceError {
        relabel: bool,
    }

    struct SwallowsSourceErrorRead {
        inner: Box<dyn ArchiveRead>,
        relabel: bool,
        report: FidelityReport,
    }

    impl ArchiveRead for SwallowsSourceErrorRead {
        fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
            match self.inner.next_entry() {
                Ok(entry) => Ok(entry),
                // BUG, both arms: a source failure is not an end of
                // archive, and it is not corruption either.
                Err(_) if self.relabel => Err(Error::Corrupt(
                    "swallows-source-error: archive is corrupt".into(),
                )),
                Err(_) => Ok(None),
            }
        }
        fn by_index(&mut self, index: usize) -> Result<Entry<'_>> {
            self.inner.by_index(index)
        }
        fn fidelity(&self) -> &FidelityReport {
            &self.report
        }
    }

    impl Container for SwallowsSourceError {
        fn id(&self) -> FormatId {
            READ_ONLY_DOUBLE
        }
        fn caps(&self) -> ContainerCaps {
            read_only_double_caps()
        }
        fn open(&self, resolved: Resolved, o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
            let report = resolved.report.clone();
            Ok(Box::new(SwallowsSourceErrorRead {
                inner: FramedMockContainer.open(resolved, o)?,
                relabel: self.relabel,
                report,
            }))
        }
        fn create(&self, _dst: Box<dyn Sink>, _o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
            Err(Error::CapabilityUnavailable {
                format: READ_ONLY_DOUBLE,
                available: "read",
                requested: "written",
            })
        }
    }

    #[test]
    fn fixture_property_nine_catches_a_reader_that_swallows_a_source_error() {
        let fx = ContainerFixture {
            bytes: framed_fixture_bytes(&[("a.txt", b"alpha")]),
            expected: &[ExpectedEntry {
                name: "a.txt",
                content: b"alpha",
            }],
            provenance: "hand-built in this test",
        };
        assert_panics_naming_with(
            &SwallowsSourceError { relabel: false },
            &read_only_meta(),
            &fx,
            "fixture property 9",
        );
    }

    #[test]
    fn fixture_property_nine_catches_a_reader_that_relabels_a_source_error() {
        let fx = ContainerFixture {
            bytes: framed_fixture_bytes(&[("a.txt", b"alpha")]),
            expected: &[ExpectedEntry {
                name: "a.txt",
                content: b"alpha",
            }],
            provenance: "hand-built in this test",
        };
        assert_panics_naming_with(
            &SwallowsSourceError { relabel: true },
            &read_only_meta(),
            &fx,
            "fixture property 9",
        );
    }

    /// Property 1 exists because a mismatched registration is otherwise
    /// completely silent — every other property would still pass.
    struct WrongId;

    impl Container for WrongId {
        fn id(&self) -> FormatId {
            FormatId::new("wrong-id")
        }
        fn caps(&self) -> ContainerCaps {
            FramedMockContainer.caps()
        }
        fn open(&self, resolved: Resolved, o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
            FramedMockContainer.open(resolved, o)
        }
        fn create(&self, dst: Box<dyn Sink>, o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
            FramedMockContainer.create(dst, o)
        }
    }

    #[test]
    fn property_one_catches_an_id_that_disagrees_with_registration() {
        assert_panics_naming(&WrongId, &framed_container_meta(), "property 1");
    }

    /// The empty case specifically: a container that writes no trailer for a
    /// zero-entry archive round trips every NON-empty input correctly.
    struct EmptyBroken;

    struct EmptyBrokenWrite {
        inner: Box<dyn ArchiveWrite>,
        count: usize,
    }

    impl ArchiveWrite for EmptyBrokenWrite {
        fn add(&mut self, meta: &EntryMeta, data: &mut dyn Read) -> Result<()> {
            self.count += 1;
            self.inner.add(meta, data)
        }
        fn finish(self: Box<Self>) -> Result<Box<dyn Sink>> {
            if self.count == 0 {
                // BUG: no entries means no trailer either — the whole
                // structure the reader needs to find is simply never
                // written. `self.inner` is dropped unfinished, so the real
                // destination never sees the trailer; the placeholder handed
                // back keeps the signature honest without writing anything.
                return Ok(PlainSink::new(Box::new(std::io::sink())));
            }
            self.inner.finish()
        }
    }

    impl Container for EmptyBroken {
        fn id(&self) -> FormatId {
            FramedMockContainer.id()
        }
        fn caps(&self) -> ContainerCaps {
            FramedMockContainer.caps()
        }
        fn open(&self, resolved: Resolved, o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
            FramedMockContainer.open(resolved, o)
        }
        fn create(&self, dst: Box<dyn Sink>, o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
            Ok(Box::new(EmptyBrokenWrite {
                inner: FramedMockContainer.create(dst, o)?,
                count: 0,
            }))
        }
    }

    #[test]
    fn property_three_catches_a_container_that_breaks_on_zero_entries() {
        assert_panics_naming(&EmptyBroken, &framed_container_meta(), "property 3");
    }

    /// Property 4 is pointed at a real hazard: `zip`'s own `Drop` finalizes
    /// and writes failures to stderr, so a container relying on Drop would
    /// lose the error entirely.
    struct SwallowsError;

    struct SwallowsErrorWrite {
        inner: Box<dyn ArchiveWrite>,
    }

    impl ArchiveWrite for SwallowsErrorWrite {
        fn add(&mut self, meta: &EntryMeta, data: &mut dyn Read) -> Result<()> {
            // BUG: a real write error from the destination is discarded.
            let _ = self.inner.add(meta, data);
            Ok(())
        }
        fn finish(self: Box<Self>) -> Result<Box<dyn Sink>> {
            // BUG: same, for the trailer write — and for the destination's
            // own completion, since what is handed back here writes nowhere.
            let _ = self.inner.finish();
            Ok(PlainSink::new(Box::new(std::io::sink())))
        }
    }

    impl Container for SwallowsError {
        fn id(&self) -> FormatId {
            FramedMockContainer.id()
        }
        fn caps(&self) -> ContainerCaps {
            FramedMockContainer.caps()
        }
        fn open(&self, resolved: Resolved, o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
            FramedMockContainer.open(resolved, o)
        }
        fn create(&self, dst: Box<dyn Sink>, o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
            Ok(Box::new(SwallowsErrorWrite {
                inner: FramedMockContainer.create(dst, o)?,
            }))
        }
    }

    #[test]
    fn property_four_catches_finish_swallowing_a_write_error() {
        assert_panics_naming(&SwallowsError, &framed_container_meta(), "property 4");
    }

    /// Property 6 exists because a container that returns entry 0 from
    /// `by_index` on a forward-only source is LYING about random access, and
    /// would pass a naive round-trip test while doing it.
    struct FakesSeek;

    struct FakesSeekRead {
        inner: Box<dyn ArchiveRead>,
    }

    impl ArchiveRead for FakesSeekRead {
        fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
            self.inner.next_entry()
        }
        fn by_index(&mut self, _index: usize) -> Result<Entry<'_>> {
            // BUG: claims random access on a forward-only source by quietly
            // reading forward instead of refusing.
            self.inner
                .next_entry()?
                .ok_or_else(|| crate::error::Error::EntryNotFound("0".into()))
        }
        fn fidelity(&self) -> &FidelityReport {
            self.inner.fidelity()
        }
    }

    impl Container for FakesSeek {
        fn id(&self) -> FormatId {
            FramedMockContainer.id()
        }
        fn caps(&self) -> ContainerCaps {
            FramedMockContainer.caps()
        }
        fn open(&self, resolved: Resolved, o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
            Ok(Box::new(FakesSeekRead {
                inner: FramedMockContainer.open(resolved, o)?,
            }))
        }
        fn create(&self, dst: Box<dyn Sink>, o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
            FramedMockContainer.create(dst, o)
        }
    }

    #[test]
    fn property_six_catches_by_index_faking_random_access() {
        assert_panics_naming(&FakesSeek, &framed_container_meta(), "property 6");
    }

    /// Property 7 is the one that matters for zip. A trailing_index container
    /// read forward has NOT consulted its authoritative index, so claiming
    /// Exact is a false fidelity report — and fidelity is a load-bearing
    /// output of this tool, not a cosmetic one.
    struct ClaimsExact;

    struct ClaimsExactRead {
        inner: Box<dyn ArchiveRead>,
        report: FidelityReport,
    }

    impl ArchiveRead for ClaimsExactRead {
        fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
            self.inner.next_entry()
        }
        fn by_index(&mut self, index: usize) -> Result<Entry<'_>> {
            self.inner.by_index(index)
        }
        fn fidelity(&self) -> &FidelityReport {
            // BUG: always claims the authoritative rung, even when opened
            // over a forward-only source that never touched the trailing
            // index.
            &self.report
        }
    }

    impl Container for ClaimsExact {
        fn id(&self) -> FormatId {
            FramedMockContainer.id()
        }
        fn caps(&self) -> ContainerCaps {
            ContainerCaps {
                trailing_index: true,
                ..FramedMockContainer.caps()
            }
        }
        fn open(&self, resolved: Resolved, o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
            let inner = FramedMockContainer.open(resolved, o)?;
            Ok(Box::new(ClaimsExactRead {
                inner,
                report: FidelityReport::exact(),
            }))
        }
        fn create(&self, dst: Box<dyn Sink>, o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
            FramedMockContainer.create(dst, o)
        }
    }

    #[test]
    fn property_seven_catches_a_trailing_index_container_claiming_exact() {
        assert_panics_naming(&ClaimsExact, &framed_container_meta(), "property 7");
    }

    /// Property 8 is what caught lz4 buffering 4 MiB on the codec side.
    struct ReadsToEnd;

    impl Container for ReadsToEnd {
        fn id(&self) -> FormatId {
            FramedMockContainer.id()
        }
        fn caps(&self) -> ContainerCaps {
            FramedMockContainer.caps()
        }
        fn open(&self, resolved: Resolved, o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
            let Resolved {
                mut source,
                rung,
                report,
            } = resolved;
            // BUG: buffers the entire archive before any entry becomes
            // reachable — exactly what property 8 exists to catch.
            let mut buf = Vec::new();
            source.read_to_end(&mut buf)?;
            let refilled: Box<dyn crate::source::Source> =
                Box::new(crate::source::ReaderSource::new(std::io::Cursor::new(buf)));
            FramedMockContainer.open(
                Resolved {
                    source: refilled,
                    rung,
                    report,
                },
                o,
            )
        }
        fn create(&self, dst: Box<dyn Sink>, o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
            FramedMockContainer.create(dst, o)
        }
    }

    #[test]
    fn property_eight_catches_a_container_that_buffers_the_whole_archive() {
        assert_panics_naming(&ReadsToEnd, &framed_container_meta(), "property 8");
    }

    /// Property 9 is unconditional, like codec property 10: the one property
    /// a container author cannot vote themselves out of.
    struct AcceptsTruncation;

    struct AcceptsTruncationRead {
        inner: Box<dyn ArchiveRead>,
    }

    impl ArchiveRead for AcceptsTruncationRead {
        fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
            // BUG: any error reading the next record — including a stream
            // that ran out of bytes mid-header — is treated as a clean end
            // of archive instead of surfacing.
            Ok(self.inner.next_entry().unwrap_or(None))
        }
        fn by_index(&mut self, index: usize) -> Result<Entry<'_>> {
            self.inner.by_index(index)
        }
        fn fidelity(&self) -> &FidelityReport {
            self.inner.fidelity()
        }
    }

    impl Container for AcceptsTruncation {
        fn id(&self) -> FormatId {
            FramedMockContainer.id()
        }
        fn caps(&self) -> ContainerCaps {
            FramedMockContainer.caps()
        }
        fn open(&self, resolved: Resolved, o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
            Ok(Box::new(AcceptsTruncationRead {
                inner: FramedMockContainer.open(resolved, o)?,
            }))
        }
        fn create(&self, dst: Box<dyn Sink>, o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
            FramedMockContainer.create(dst, o)
        }
    }

    #[test]
    fn property_nine_catches_silent_acceptance_of_a_truncated_archive() {
        assert_panics_naming(&AcceptsTruncation, &framed_container_meta(), "property 9");
    }

    /// Property 9's payload cut, proven able to fail on its own.
    ///
    /// [`AcceptsTruncation`] above is caught by the FRAMING cuts, so it says
    /// nothing about whether the payload cut works — pointing both negative
    /// tests at the same double is how a sub-property ends up untested. This
    /// double is the mirror image: it detects every framing cut correctly
    /// (the four fractional cuts all end mid-record on the small fixture, and
    /// those errors propagate untouched) and silently accepts a cut inside an
    /// entry's payload, which is exactly the shape a real container takes
    /// when it SEEKS to the next header instead of reading its way there —
    /// `tar::Archive::entries_with_seek` does precisely that, and a seek past
    /// end-of-file succeeds, after which the missing header reads back as a
    /// clean end of archive.
    ///
    /// The panic must therefore name "property 9 (payload)", not merely
    /// "property 9": that marker is what proves the new cut fired and not one
    /// of the four that were already there.
    struct SwallowsPayloadTruncation;

    /// Turns a short payload read into a clean end of archive, mimicking a
    /// container that skips to the next header by seeking.
    struct SwallowsPayloadTruncationRead {
        inner: Box<dyn ArchiveRead>,
        done: Arc<std::sync::atomic::AtomicBool>,
    }

    struct PaddingReader<'a> {
        entry: Entry<'a>,
        /// Payload bytes the entry's own header promised and has not yet
        /// delivered.
        remaining: u64,
        done: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Read for PaddingReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.entry.reader().read(buf)?;
            // BUG: the payload ended early and that is reported as a
            // complete entry, with the rest of the archive declared over so
            // the missing next header is never looked for.
            if n == 0 && self.remaining > 0 {
                self.done.store(true, Ordering::Relaxed);
            }
            self.remaining = self.remaining.saturating_sub(n as u64);
            Ok(n)
        }
    }

    impl ArchiveRead for SwallowsPayloadTruncationRead {
        fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
            if self.done.load(Ordering::Relaxed) {
                return Ok(None);
            }
            let Some(entry) = self.inner.next_entry()? else {
                return Ok(None);
            };
            let meta = entry.meta().clone();
            let remaining = meta.size.unwrap_or(0);
            let reader = PaddingReader {
                entry,
                remaining,
                done: Arc::clone(&self.done),
            };
            Ok(Some(Entry::new(meta, Box::new(reader))))
        }
        fn by_index(&mut self, index: usize) -> Result<Entry<'_>> {
            self.inner.by_index(index)
        }
        fn fidelity(&self) -> &FidelityReport {
            self.inner.fidelity()
        }
    }

    impl Container for SwallowsPayloadTruncation {
        fn id(&self) -> FormatId {
            FramedMockContainer.id()
        }
        fn caps(&self) -> ContainerCaps {
            FramedMockContainer.caps()
        }
        fn open(&self, resolved: Resolved, o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
            Ok(Box::new(SwallowsPayloadTruncationRead {
                inner: FramedMockContainer.open(resolved, o)?,
                done: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            }))
        }
        fn create(&self, dst: Box<dyn Sink>, o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
            FramedMockContainer.create(dst, o)
        }
    }

    #[test]
    fn property_nine_catches_silent_acceptance_of_a_cut_inside_an_entry_payload() {
        assert_panics_naming(
            &SwallowsPayloadTruncation,
            &framed_container_meta(),
            "property 9 (payload)",
        );
    }

    /// Property 10: a disk error reading the SOURCE must not be reported as
    /// archive corruption. Forget this and a full disk reports as exit 5.
    struct MislabelsSourceErrors;

    struct MislabelsSourceErrorsRead {
        inner: Box<dyn ArchiveRead>,
    }

    impl ArchiveRead for MislabelsSourceErrorsRead {
        fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
            // BUG: every error — including a genuine source I/O failure — is
            // relabelled as archive corruption.
            self.inner
                .next_entry()
                .map_err(|e| crate::error::Error::Corrupt(e.to_string()))
        }
        fn by_index(&mut self, index: usize) -> Result<Entry<'_>> {
            self.inner.by_index(index)
        }
        fn fidelity(&self) -> &FidelityReport {
            self.inner.fidelity()
        }
    }

    impl Container for MislabelsSourceErrors {
        fn id(&self) -> FormatId {
            FramedMockContainer.id()
        }
        fn caps(&self) -> ContainerCaps {
            FramedMockContainer.caps()
        }
        fn open(&self, resolved: Resolved, o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
            Ok(Box::new(MislabelsSourceErrorsRead {
                inner: FramedMockContainer.open(resolved, o)?,
            }))
        }
        fn create(&self, dst: Box<dyn Sink>, o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
            FramedMockContainer.create(dst, o)
        }
    }

    #[test]
    fn property_ten_catches_a_source_error_reported_as_corruption() {
        assert_panics_naming(
            &MislabelsSourceErrors,
            &framed_container_meta(),
            "property 10",
        );
    }

    /// Property 12 is an INVERSION: the container must NOT sanitise. The
    /// README's non-negotiable is "refused, not silently sanitised", so a
    /// parser that rewrote a traversal name would destroy the evidence the
    /// ops-layer refusal runs on.
    struct Sanitises;

    struct SanitisesWrite {
        inner: Box<dyn ArchiveWrite>,
    }

    impl ArchiveWrite for SanitisesWrite {
        fn add(&mut self, meta: &EntryMeta, data: &mut dyn Read) -> Result<()> {
            // BUG: silently rewrites a hostile name instead of storing it
            // verbatim and letting the ops layer refuse it later.
            let mut sanitised = meta.clone();
            sanitised.name = sanitised
                .name
                .replace("..", "")
                .trim_start_matches('/')
                .to_string();
            self.inner.add(&sanitised, data)
        }
        fn finish(self: Box<Self>) -> Result<Box<dyn Sink>> {
            self.inner.finish()
        }
    }

    impl Container for Sanitises {
        fn id(&self) -> FormatId {
            FramedMockContainer.id()
        }
        fn caps(&self) -> ContainerCaps {
            FramedMockContainer.caps()
        }
        fn open(&self, resolved: Resolved, o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
            FramedMockContainer.open(resolved, o)
        }
        fn create(&self, dst: Box<dyn Sink>, o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
            Ok(Box::new(SanitisesWrite {
                inner: FramedMockContainer.create(dst, o)?,
            }))
        }
    }

    #[test]
    fn property_twelve_catches_a_container_that_sanitises_hostile_names() {
        assert_panics_naming(&Sanitises, &framed_container_meta(), "property 12");
    }

    /// Property 13's two halves need two doubles, not one: a container that
    /// claimed both and stored neither would fire on directories and leave the
    /// symlink half never executed — the shape a single shared double has
    /// produced before (Phase 1f's R6).
    ///
    /// Neither double breaks anything. `FramedMockContainer` reconstructs
    /// every entry as `EntryMeta::file(name)` on the way back, which is
    /// exactly the honest behaviour of a wire format with no kind field; all
    /// these add is the FALSE CLAIM in `caps()`, which is the defect property
    /// 13 exists to catch.
    struct ClaimsDirs;

    impl Container for ClaimsDirs {
        fn id(&self) -> FormatId {
            FramedMockContainer.id()
        }
        fn caps(&self) -> ContainerCaps {
            ContainerCaps {
                // BUG: the wire format has no directory entry at all, and a
                // directory handed to it lands as a zero-byte regular file.
                stores_dirs: true,
                ..FramedMockContainer.caps()
            }
        }
        fn open(&self, resolved: Resolved, o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
            FramedMockContainer.open(resolved, o)
        }
        fn create(&self, dst: Box<dyn Sink>, o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
            FramedMockContainer.create(dst, o)
        }
    }

    #[test]
    fn property_thirteen_catches_a_false_stores_dirs_claim() {
        assert_panics_naming(
            &ClaimsDirs,
            &framed_container_meta(),
            "property 13 (directories)",
        );
    }

    struct ClaimsSymlinks;

    impl Container for ClaimsSymlinks {
        fn id(&self) -> FormatId {
            FramedMockContainer.id()
        }
        fn caps(&self) -> ContainerCaps {
            ContainerCaps {
                // BUG: same claim, for links. A link stored as a regular file
                // materialises its target text as the file's contents.
                stores_symlinks: true,
                ..FramedMockContainer.caps()
            }
        }
        fn open(&self, resolved: Resolved, o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
            FramedMockContainer.open(resolved, o)
        }
        fn create(&self, dst: Box<dyn Sink>, o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
            FramedMockContainer.create(dst, o)
        }
    }

    #[test]
    fn property_thirteen_catches_a_false_stores_symlinks_claim() {
        assert_panics_naming(
            &ClaimsSymlinks,
            &framed_container_meta(),
            "property 13 (symlinks)",
        );
    }

    /// Property 11 had no double at all until the cpio `S_IFREG` fix, which
    /// is how it came to be RELAXED without anybody able to see what the
    /// relaxation cost. The two below pin both halves of the relaxed rule.
    ///
    /// Both need a mode on the way back, and `FramedMockContainer`'s wire
    /// format carries none — it honestly reconstructs `EntryMeta::file(name)`
    /// — so each overlays one onto the entries the mock produces. The overlay
    /// keeps the mock's own streaming reader (`Entry::into_reader`) rather
    /// than buffering the payload to fake one: a buffering double would trip
    /// property 8 (incrementality), which runs first, and `assert_panics_naming`
    /// would then pass on the wrong property.
    struct ModeOverlayRead {
        inner: Box<dyn ArchiveRead>,
        /// Applied to every entry's mode on the way out.
        overlay: fn(u32) -> u32,
    }

    impl ArchiveRead for ModeOverlayRead {
        fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
            let overlay = self.overlay;
            let Some(entry) = self.inner.next_entry()? else {
                return Ok(None);
            };
            let mut meta = entry.meta().clone();
            // The mock reports no mode, so the double supplies the one the
            // harness wrote and then damages it — which is exactly what a
            // real container that mishandled the field would look like.
            meta.mode = Some(overlay(meta.mode.unwrap_or(0o640)));
            Ok(Some(Entry::new(meta, entry.into_reader())))
        }

        fn by_index(&mut self, index: usize) -> Result<Entry<'_>> {
            self.inner.by_index(index)
        }

        fn fidelity(&self) -> &FidelityReport {
            self.inner.fidelity()
        }
    }

    struct ModeOverlay(fn(u32) -> u32);

    impl Container for ModeOverlay {
        fn id(&self) -> FormatId {
            FramedMockContainer.id()
        }
        fn caps(&self) -> ContainerCaps {
            FramedMockContainer.caps()
        }
        fn open(&self, resolved: Resolved, o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
            Ok(Box::new(ModeOverlayRead {
                inner: FramedMockContainer.open(resolved, o)?,
                overlay: self.0,
            }))
        }
        fn create(&self, dst: Box<dyn Sink>, o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
            FramedMockContainer.create(dst, o)
        }
    }

    /// The half the property was originally written for, and the half the
    /// relaxation must not have cost: a container that reports `0o644` where
    /// `0o640` was written has silently granted the group a read it never
    /// had. Permission bits are compared EXACTLY.
    #[test]
    fn property_eleven_catches_a_container_that_alters_the_permission_bits() {
        assert_panics_naming(
            &ModeOverlay(|mode| (mode & !0o007) | 0o004),
            &framed_container_meta(),
            "property 11",
        );
    }

    /// The half the relaxation added: `S_IFREG` may be folded in, and
    /// NOTHING else may. A container reporting `S_IFDIR` over a plain file
    /// has relabelled the entry's kind — the defect cpio's own Dir/Symlink
    /// normalisation exists to prevent, in the opposite direction.
    #[test]
    fn property_eleven_catches_a_container_that_relabels_the_entrys_kind() {
        assert_panics_naming(
            &ModeOverlay(|mode| (mode & !0o170_000) | 0o040_000),
            &framed_container_meta(),
            "property 11",
        );
    }
}
