//! Container conformance: one call per container, twelve properties.
//!
//! The codec equivalent (`conformance.rs`) caught defects at codec two rather
//! than codec nine. Containers vary structurally more than codecs, not less,
//! so the same method applies. Properties skip on EVIDENCE — `ContainerCaps`
//! and measurement — never on trust, exactly as the codec harness does.
//!
//! This file carries properties 1-8; Task 3 adds 9-12 to the same
//! [`assert_container_conforms`] function.
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
//! 4. `finish()` flushes the underlying writer and surfaces a write error
//!    that `Drop` would otherwise swallow. `ArchiveWrite::finish` takes the
//!    destination by value (via `Container::create`), so once a caller has
//!    handed it over, `finish` is the last code with a handle to it — pointed
//!    at a real hazard: a container relying on `Drop` to flush loses any
//!    error entirely (`zip`'s own `Drop` finalizes and writes failures to
//!    stderr).
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

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::archive::{ArchiveRead, Container, CreateOpts, EntryMeta, OpenOpts};
use crate::error::Result;
use crate::fidelity::Rung;
use crate::format::FormatMeta;
use crate::source::{ReaderSource, SeekRead, Source, SourceCaps};

/// A `'static`, cloneable in-memory destination that can also be told to fail
/// every write once a byte budget is exhausted.
///
/// One type serves both property 3's ordinary destination
/// (`CaptureWriter::new`, read back via `contents()` once `finish()` has
/// consumed it) and property 4's failing one (`CaptureWriter::failing_after`)
/// — `Container::create` takes the destination by value and
/// `ArchiveWrite::finish` consumes it, so nothing is left holding the bytes
/// unless the writer itself shares a handle to them.
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
        .create(Box::new(cap.clone()), &CreateOpts::default())
        .unwrap_or_else(|e| panic!("conformance[{id}] create: {e}"));
    for (name, data) in entries {
        let meta = EntryMeta::file(*name);
        w.add(&meta, &mut io::Cursor::new(*data))
            .unwrap_or_else(|e| panic!("conformance[{id}] add({name}): {e}"));
    }
    w.finish()
        .unwrap_or_else(|e| panic!("conformance[{id}] finish: {e}"));
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
fn open_forward_only(container: &dyn Container, bytes: &[u8]) -> Box<dyn ArchiveRead> {
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
                Box::new(CaptureWriter::failing_after(0)),
                &CreateOpts::default(),
            )
            .unwrap_or_else(|e| panic!("conformance[{id}] create: {e}"));
        let meta_e = EntryMeta::file("a.txt");
        let added = w.add(&meta_e, &mut io::Cursor::new(b"alpha".as_slice()));
        let finished = w.finish();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{FramedMockContainer, framed_container_meta};

    #[test]
    fn a_well_behaved_container_satisfies_properties_one_to_eight() {
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
    use crate::archive::{ArchiveRead, ArchiveWrite, Entry};
    use crate::fidelity::FidelityReport;
    use crate::format::{ContainerCaps, FormatId};
    use crate::ladder::Resolved;
    use crate::testing::{FramedMockContainer, framed_container_meta};
    use std::io::Read;

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
        fn create(
            &self,
            dst: Box<dyn Write + Send>,
            o: &CreateOpts,
        ) -> Result<Box<dyn ArchiveWrite>> {
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
        fn finish(self: Box<Self>) -> Result<()> {
            if self.count == 0 {
                // BUG: no entries means no trailer either — the whole
                // structure the reader needs to find is simply never
                // written.
                return Ok(());
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
        fn create(
            &self,
            dst: Box<dyn Write + Send>,
            o: &CreateOpts,
        ) -> Result<Box<dyn ArchiveWrite>> {
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
        fn finish(self: Box<Self>) -> Result<()> {
            // BUG: same, for the trailer write.
            let _ = self.inner.finish();
            Ok(())
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
        fn create(
            &self,
            dst: Box<dyn Write + Send>,
            o: &CreateOpts,
        ) -> Result<Box<dyn ArchiveWrite>> {
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
        fn create(
            &self,
            dst: Box<dyn Write + Send>,
            o: &CreateOpts,
        ) -> Result<Box<dyn ArchiveWrite>> {
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
        fn create(
            &self,
            dst: Box<dyn Write + Send>,
            o: &CreateOpts,
        ) -> Result<Box<dyn ArchiveWrite>> {
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
        fn create(
            &self,
            dst: Box<dyn Write + Send>,
            o: &CreateOpts,
        ) -> Result<Box<dyn ArchiveWrite>> {
            FramedMockContainer.create(dst, o)
        }
    }

    #[test]
    fn property_eight_catches_a_container_that_buffers_the_whole_archive() {
        assert_panics_naming(&ReadsToEnd, &framed_container_meta(), "property 8");
    }
}
