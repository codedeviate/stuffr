//! Mock formats for testing the ladder and governor without any real codec.
//!
//! Enabled by `cfg(test)` in this crate and by the `testing` feature for
//! downstream crates.

use std::io::{Read, Write};

use crate::archive::{
    ArchiveRead, ArchiveWrite, Codec, Container, CreateOpts, DecodeOpts, EncodeOpts, Entry,
    EntryMeta, OpenOpts, Sink,
};
use crate::error::{Error, Result};
use crate::fidelity::{Fidelity, FidelityReport, Rung};
use crate::format::{CodecCaps, ContainerCaps, FormatId, FormatMeta, MagicRule};
use crate::ladder::Resolved;
use crate::source::Source;

pub use crate::conformance::{
    assert_codec_conforms, assert_codec_conforms_with, compressible, incompressible,
};
pub use crate::container_conformance::{assert_container_conforms, open_forward_only};

pub const MOCK_CODEC: FormatId = FormatId::new("mock-codec");
pub const MOCK_CONTAINER: FormatId = FormatId::new("mock-container");

/// A symmetric XOR-0xFF "codec". Trivially verifiable, and symmetric so a
/// round-trip bug cannot hide behind a matching pair of mistakes.
pub struct MockCodec;

struct XorReader(Box<dyn Read + Send>);

impl Read for XorReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.0.read(buf)?;
        for b in &mut buf[..n] {
            *b ^= 0xFF;
        }
        Ok(n)
    }
}

struct XorSink(Box<dyn Write + Send>);

impl Write for XorSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let flipped: Vec<u8> = buf.iter().map(|b| b ^ 0xFF).collect();
        self.0.write_all(&flipped)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl Sink for XorSink {
    fn finish(mut self: Box<Self>) -> Result<()> {
        self.0.flush()?;
        Ok(())
    }
}

impl Codec for MockCodec {
    fn id(&self) -> FormatId {
        MOCK_CODEC
    }

    fn caps(&self) -> CodecCaps {
        CodecCaps {
            encode: true,
            decode: true,
            ..Default::default()
        }
    }

    fn decoder(&self, src: Box<dyn Source>, _o: &DecodeOpts) -> Result<Box<dyn Source>> {
        Ok(Box::new(crate::source::StreamOnly::new(XorReader(
            Box::new(src),
        ))))
    }

    fn encoder(&self, dst: Box<dyn Write + Send>, _o: &EncodeOpts) -> Result<Box<dyn Sink>> {
        Ok(Box::new(XorSink(dst)))
    }
}

impl MockCodec {
    /// Stands in for what a real MT codec does: ask the governor for workers,
    /// use them, release. The mock immediately releases; a real codec would
    /// hold the set for the duration of the work.
    pub fn workers_for_opts(&self, o: &DecodeOpts) -> usize {
        match (&o.governor, o.threads) {
            (Some(g), want) => g.acquire_many(want.unwrap_or(1), 0).workers(),
            (None, _) => 1,
        }
    }
}

/// A deliberately ZIP-shaped mock container.
///
/// ```text
/// repeat: "ME" | name_len u16le | name | data_len u64le | data
/// footer: "MI" | count u32le | count * (offset u64le) | "MEND"
/// ```
///
/// `forward_parse` walks the `ME` records; `trailing_index` marks the `MI`
/// footer as authoritative. That combination is what exercises the same ladder
/// branches a real zip does.
pub struct MockContainer;

/// Builds a valid mock archive in memory. Used by tests across the crate.
pub fn mock_archive_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut offsets = Vec::new();
    for (name, data) in entries {
        offsets.push(out.len() as u64);
        out.extend_from_slice(b"ME");
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        out.extend_from_slice(data);
    }
    out.extend_from_slice(b"MI");
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for o in &offsets {
        out.extend_from_slice(&o.to_le_bytes());
    }
    out.extend_from_slice(b"MEND");
    out
}

pub struct MockArchiveRead {
    buf: Vec<u8>,
    pos: usize,
    report: FidelityReport,
    index: Option<Vec<u64>>,
}

impl MockContainer {
    fn parse_index(buf: &[u8]) -> Option<Vec<u64>> {
        if !buf.ends_with(b"MEND") {
            return None;
        }
        // Walk back: MEND(4) + offsets(8*count) + count(4) + "MI"(2)
        let end = buf.len() - 4;
        // Find "MI" by trying each plausible count.
        for count in 0..=((end.saturating_sub(6)) / 8) {
            let start = end.checked_sub(8 * count + 4 + 2)?;
            if &buf[start..start + 2] == b"MI" {
                let declared =
                    u32::from_le_bytes(buf[start + 2..start + 6].try_into().ok()?) as usize;
                if declared != count {
                    continue;
                }
                let mut offsets = Vec::with_capacity(count);
                for i in 0..count {
                    let o = start + 6 + i * 8;
                    offsets.push(u64::from_le_bytes(buf[o..o + 8].try_into().ok()?));
                }
                return Some(offsets);
            }
        }
        None
    }

    /// First offset at which a record marker appears. Used only by the
    /// Degraded rung, where the leading bytes cannot be trusted.
    fn find_first_record(buf: &[u8]) -> Option<usize> {
        buf.windows(2).position(|w| w == b"ME")
    }
}

impl Container for MockContainer {
    fn id(&self) -> FormatId {
        MOCK_CONTAINER
    }

    fn caps(&self) -> ContainerCaps {
        ContainerCaps {
            read: true,
            write: true,
            forward_parse: true,
            trailing_index: true,
            ..Default::default()
        }
    }

    fn open(&self, resolved: Resolved, _o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
        let Resolved {
            mut source,
            rung,
            report,
            ..
        } = resolved;
        let seekable = source.caps().seekable;
        let mut buf = Vec::new();
        source.read_to_end(&mut buf)?;

        // Degraded means "salvage what you can": do not trust the stream to
        // begin at a record boundary, scan for one. Reachable because the
        // ladder only ever selects Degraded for a NON-seekable source — if it
        // were seekable, rung 1 would have returned Exact long before.
        let pos = if rung == Rung::Degraded {
            Self::find_first_record(&buf).unwrap_or(buf.len())
        } else {
            0
        };

        let index = if seekable {
            Self::parse_index(&buf)
        } else {
            None
        };

        // Start from the ladder's report rather than re-deriving it, then add
        // only what parsing itself discovered.
        let mut report = report;
        if seekable && index.is_none() {
            report.warn(Fidelity::TruncatedStream {
                at: buf.len() as u64,
            });
        }

        Ok(Box::new(MockArchiveRead {
            buf,
            pos,
            report,
            index,
        }))
    }

    fn create(&self, dst: Box<dyn Write + Send>, _o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
        Ok(Box::new(MockArchiveWrite {
            dst,
            offsets: Vec::new(),
            written: 0,
        }))
    }
}

impl MockArchiveRead {
    fn read_record_at(&self, at: usize) -> Result<Option<(EntryMeta, usize, usize)>> {
        let b = &self.buf;
        if at + 2 > b.len() || &b[at..at + 2] != b"ME" {
            return Ok(None);
        }
        let name_len = u16::from_le_bytes(
            b[at + 2..at + 4]
                .try_into()
                .map_err(|_| Error::Corrupt("short name_len".into()))?,
        ) as usize;
        let name_at = at + 4;
        let size_at = name_at + name_len;
        if size_at + 8 > b.len() {
            return Err(Error::Corrupt("truncated entry header".into()));
        }
        let name = String::from_utf8_lossy(&b[name_at..size_at]).into_owned();
        let data_len = u64::from_le_bytes(
            b[size_at..size_at + 8]
                .try_into()
                .map_err(|_| Error::Corrupt("short len".into()))?,
        ) as usize;
        let data_at = size_at + 8;
        if data_at + data_len > b.len() {
            return Err(Error::Corrupt("truncated entry data".into()));
        }
        let mut meta = EntryMeta::file(name);
        meta.size = Some(data_len as u64);
        Ok(Some((meta, data_at, data_len)))
    }
}

impl ArchiveRead for MockArchiveRead {
    fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
        let Some((meta, data_at, data_len)) = self.read_record_at(self.pos)? else {
            return Ok(None);
        };
        self.pos = data_at + data_len;
        let slice = &self.buf[data_at..data_at + data_len];
        Ok(Some(Entry::new(
            meta,
            Box::new(std::io::Cursor::new(slice)),
        )))
    }

    fn by_index(&mut self, index: usize) -> Result<Entry<'_>> {
        let offsets = self
            .index
            .as_ref()
            .ok_or(Error::NotSeekable {
                format: MOCK_CONTAINER,
            })?
            .clone();
        let at = *offsets
            .get(index)
            .ok_or_else(|| Error::EntryNotFound(index.to_string()))?;
        let (meta, data_at, data_len) = self
            .read_record_at(at as usize)?
            .ok_or_else(|| Error::Corrupt("index points at a non-record".into()))?;
        let slice = &self.buf[data_at..data_at + data_len];
        Ok(Entry::new(meta, Box::new(std::io::Cursor::new(slice))))
    }

    fn fidelity(&self) -> &FidelityReport {
        &self.report
    }
}

pub struct MockArchiveWrite {
    dst: Box<dyn Write + Send>,
    offsets: Vec<u64>,
    written: u64,
}

impl ArchiveWrite for MockArchiveWrite {
    fn add(&mut self, meta: &EntryMeta, data: &mut dyn Read) -> Result<()> {
        let mut payload = Vec::new();
        data.read_to_end(&mut payload)?;

        self.offsets.push(self.written);
        let name = meta.name.as_bytes();
        self.dst.write_all(b"ME")?;
        self.dst.write_all(&(name.len() as u16).to_le_bytes())?;
        self.dst.write_all(name)?;
        self.dst.write_all(&(payload.len() as u64).to_le_bytes())?;
        self.dst.write_all(&payload)?;
        self.written += 2 + 2 + name.len() as u64 + 8 + payload.len() as u64;
        Ok(())
    }

    fn finish(mut self: Box<Self>) -> Result<()> {
        self.dst.write_all(b"MI")?;
        self.dst
            .write_all(&(self.offsets.len() as u32).to_le_bytes())?;
        for o in &self.offsets {
            self.dst.write_all(&o.to_le_bytes())?;
        }
        self.dst.write_all(b"MEND")?;
        self.dst.flush()?;
        Ok(())
    }
}

/// A well-behaved FRAMED double for the container conformance harness,
/// analogous to `conformance::framed_mock::FramedMock` on the codec side.
///
/// `MockContainer` above stays exactly as it is — governor, ladder and probe
/// tests rely on its shape — but it reads its whole source to end before
/// returning even the first entry, which is fine for those tests and would
/// fail the harness's incrementality property outright (Task 2). This double
/// streams instead: [`ArchiveRead::next_entry`] parses one length-prefixed
/// record at a time and only ever buffers a single entry's payload, never the
/// whole archive.
///
/// Wire format:
/// ```text
/// repeat: "FE" | name_len u32le | name | data_len u64le | data
/// trailer: "FZ"
/// ```
pub struct FramedMockContainer;

pub const FRAMED_CONTAINER: FormatId = FormatId::new("framed-mock-container");

const FRAMED_MAGICS: &[MagicRule] = &[MagicRule {
    offset: 0,
    bytes: b"FE",
    format: FRAMED_CONTAINER,
}];

/// Registration metadata for [`FramedMockContainer`], for
/// `assert_container_conforms(&FramedMockContainer, &framed_container_meta())`.
pub fn framed_container_meta() -> FormatMeta {
    FormatMeta::container(FRAMED_CONTAINER, &["fmc"], FRAMED_MAGICS)
}

impl Container for FramedMockContainer {
    fn id(&self) -> FormatId {
        FRAMED_CONTAINER
    }

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
        Ok(Box::new(FramedArchiveRead {
            source,
            pending: 0,
            report,
        }))
    }

    fn create(&self, dst: Box<dyn Write + Send>, _o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
        Ok(Box::new(FramedArchiveWrite { dst }))
    }
}

struct FramedArchiveWrite {
    dst: Box<dyn Write + Send>,
}

impl ArchiveWrite for FramedArchiveWrite {
    fn add(&mut self, meta: &EntryMeta, data: &mut dyn Read) -> Result<()> {
        let mut payload = Vec::new();
        data.read_to_end(&mut payload)?;
        let name = meta.name.as_bytes();
        self.dst.write_all(b"FE")?;
        self.dst.write_all(&(name.len() as u32).to_le_bytes())?;
        self.dst.write_all(name)?;
        self.dst.write_all(&(payload.len() as u64).to_le_bytes())?;
        self.dst.write_all(&payload)?;
        Ok(())
    }

    fn finish(mut self: Box<Self>) -> Result<()> {
        self.dst.write_all(b"FZ")?;
        self.dst.flush()?;
        Ok(())
    }
}

/// Bounds reads to `*remaining` bytes of `*source`, decrementing it as bytes
/// are actually delivered. Lets [`FramedArchiveRead::next_entry`] tell how
/// many bytes of a partially-read entry still need to be skipped before the
/// next record can be parsed.
struct BoundedReader<'a> {
    source: &'a mut Box<dyn Source>,
    remaining: &'a mut u64,
}

impl Read for BoundedReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if *self.remaining == 0 {
            return Ok(0);
        }
        let cap = (buf.len() as u64).min(*self.remaining) as usize;
        let n = self.source.read(&mut buf[..cap])?;
        *self.remaining -= n as u64;
        Ok(n)
    }
}

/// Streams one length-prefixed record at a time — see the struct's own doc
/// comment on why `MockArchiveRead`'s whole-source read cannot stand in once
/// the incrementality property (Task 2) exists.
struct FramedArchiveRead {
    source: Box<dyn Source>,
    /// Bytes of the current entry's payload not yet delivered to the caller.
    pending: u64,
    report: FidelityReport,
}

impl FramedArchiveRead {
    /// Discards whatever is left of the entry the caller did not fully read,
    /// so the next call starts exactly at the next record's tag.
    fn skip_pending(&mut self) -> Result<()> {
        if self.pending > 0 {
            let mut reader = BoundedReader {
                source: &mut self.source,
                remaining: &mut self.pending,
            };
            std::io::copy(&mut reader, &mut std::io::sink())?;
        }
        Ok(())
    }
}

/// Reads exactly `buf.len()` bytes, reclassifying a bare `UnexpectedEof` —
/// the shape every truncated stream produces once it runs out of bytes
/// mid-record — onto [`Error::Corrupt`], so a cut archive surfaces as
/// `io::ErrorKind::InvalidData` (conformance property 9) rather than a
/// generic `Error::Io`. Any other kind, notably a genuine source failure such
/// as `PermissionDenied`, passes through unchanged as `Error::Io` so it is
/// never mistaken for corruption (property 10).
fn read_exact_or_corrupt(source: &mut Box<dyn Source>, buf: &mut [u8]) -> Result<()> {
    source.read_exact(buf).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            Error::Corrupt("framed mock container: truncated stream".into())
        } else {
            Error::Io(e)
        }
    })
}

impl ArchiveRead for FramedArchiveRead {
    fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
        self.skip_pending()?;

        let mut tag = [0u8; 2];
        read_exact_or_corrupt(&mut self.source, &mut tag)?;
        match &tag {
            b"FZ" => Ok(None),
            b"FE" => {
                let mut len_buf = [0u8; 4];
                read_exact_or_corrupt(&mut self.source, &mut len_buf)?;
                let name_len = u32::from_le_bytes(len_buf) as usize;
                let mut name_buf = vec![0u8; name_len];
                read_exact_or_corrupt(&mut self.source, &mut name_buf)?;
                let name = String::from_utf8_lossy(&name_buf).into_owned();

                let mut dlen_buf = [0u8; 8];
                read_exact_or_corrupt(&mut self.source, &mut dlen_buf)?;
                let data_len = u64::from_le_bytes(dlen_buf);
                self.pending = data_len;

                let mut meta = EntryMeta::file(name);
                meta.size = Some(data_len);

                let reader = BoundedReader {
                    source: &mut self.source,
                    remaining: &mut self.pending,
                };
                Ok(Some(Entry::new(meta, Box::new(reader))))
            }
            _ => Err(Error::Corrupt(
                "framed mock container: unrecognised record tag".into(),
            )),
        }
    }

    fn by_index(&mut self, _index: usize) -> Result<Entry<'_>> {
        // No index is implemented by this double — every consumer of it so
        // far only needs forward iteration.
        Err(Error::NotSeekable {
            format: FRAMED_CONTAINER,
        })
    }

    fn fidelity(&self) -> &FidelityReport {
        &self.report
    }
}

/// A `'static`, cloneable in-memory sink.
///
/// `Codec::encoder` and `Container::create` take `Box<dyn Write + Send>`, which
/// is implicitly `+ 'static`, so a test cannot hand them `&mut local_vec`.
/// Cloning a `SharedBuf` gives the test a handle on whatever the writer wrote.
#[derive(Clone, Default)]
pub struct SharedBuf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl SharedBuf {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn contents(&self) -> Vec<u8> {
        self.0.lock().expect("SharedBuf mutex poisoned").clone()
    }
}

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("SharedBuf mutex poisoned")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A reader that returns at most `chunk` bytes per `read` call, so tests can
/// exercise paths that only appear across several short reads. A `Cursor` hands
/// over everything at once and hides them.
pub struct ChunkedReader {
    data: Vec<u8>,
    pos: usize,
    chunk: usize,
}

impl ChunkedReader {
    pub fn new(data: Vec<u8>, chunk: usize) -> Self {
        assert!(chunk > 0, "chunk must be non-zero");
        Self {
            data,
            pos: 0,
            chunk,
        }
    }
}

impl Read for ChunkedReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.chunk.min(buf.len()).min(self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::ReaderSource;
    use std::io::Read;

    /// Runs `src` through the ladder with `MockContainer`'s own capabilities
    /// and the default policy, producing the `Resolved` that `open` now
    /// requires. Most tests here care about `open`'s behaviour, not the
    /// ladder's, so this keeps that plumbing out of their way.
    fn resolve_default(src: Box<dyn Source>) -> Resolved {
        crate::resolve(
            src,
            MOCK_CONTAINER,
            MockContainer.caps(),
            &Default::default(),
        )
        .unwrap()
    }

    #[test]
    fn a_decoder_returns_a_source_so_capabilities_survive_the_layer() {
        // The point of the Source return type: a decoded stream can report what
        // it supports. The ordinary codec reports no seek; a codec with a frame
        // index would report otherwise, and the ladder could then run between
        // codec and container.
        let encoded: Vec<u8> = b"the quick brown fox".iter().map(|b| b ^ 0xFF).collect();
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(encoded)));
        let dec = MockCodec.decoder(src, &DecodeOpts::default()).unwrap();
        assert!(!dec.caps().seekable);
    }

    #[test]
    fn mock_codec_round_trips() {
        let plain = b"the quick brown fox".to_vec();
        let codec = MockCodec;

        let sink = SharedBuf::new();
        {
            let mut s = codec
                .encoder(Box::new(sink.clone()), &EncodeOpts::default())
                .unwrap();
            std::io::Write::write_all(&mut s, &plain).unwrap();
            s.finish().unwrap();
        }
        let encoded = sink.contents();
        assert_ne!(encoded, plain, "the mock must actually transform the bytes");

        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(encoded)));
        let mut dec = codec.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, plain);
    }

    #[test]
    fn mock_codec_declares_both_directions() {
        let c = MockCodec.caps();
        assert!(c.encode && c.decode);
    }

    #[test]
    fn mock_archive_reads_back_every_entry_in_order() {
        let bytes = mock_archive_bytes(&[("a.txt", b"alpha"), ("b.bin", b"bravo!!")]);
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
        let mut ar = MockContainer
            .open(resolve_default(src), &OpenOpts::default())
            .unwrap();

        let mut seen = Vec::new();
        while let Some(mut e) = ar.next_entry().unwrap() {
            let name = e.meta().name.clone();
            let mut data = Vec::new();
            e.reader().read_to_end(&mut data).unwrap();
            seen.push((name, data));
        }

        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0], ("a.txt".to_string(), b"alpha".to_vec()));
        assert_eq!(seen[1], ("b.bin".to_string(), b"bravo!!".to_vec()));
    }

    #[test]
    fn mock_container_declares_zip_shaped_capabilities() {
        let c = MockContainer.caps();
        assert!(c.read && c.write);
        assert!(c.forward_parse, "must exercise the ForwardOnly rung");
        assert!(c.trailing_index, "must exercise the index-loss warning");
        assert!(!c.needs_seek);
    }

    #[test]
    fn mock_archive_writer_output_is_readable_by_the_reader() {
        let sink = SharedBuf::new();
        {
            let mut w = MockContainer
                .create(Box::new(sink.clone()), &CreateOpts::default())
                .unwrap();
            w.add(&EntryMeta::file("only.txt"), &mut &b"hello"[..])
                .unwrap();
            w.finish().unwrap();
        }
        let buf = sink.contents();
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(buf)));
        let mut ar = MockContainer
            .open(resolve_default(src), &OpenOpts::default())
            .unwrap();
        let mut e = ar.next_entry().unwrap().expect("one entry");
        assert_eq!(e.meta().name, "only.txt");
        let mut data = Vec::new();
        e.reader().read_to_end(&mut data).unwrap();
        assert_eq!(data, b"hello");
    }

    #[test]
    fn traits_are_object_safe() {
        // Regression guard: a `&self`-less or generic method would break every
        // registry lookup, and the failure would surface far from the cause.
        let _c: &dyn Codec = &MockCodec;
        let _k: &dyn Container = &MockContainer;
    }

    #[test]
    fn by_index_reaches_entries_out_of_order_and_agrees_with_sequential_reads() {
        // by_index trusts offsets recorded by the writer. Reading out of order
        // is what distinguishes real random access from an accidental
        // sequential walk, and cross-checking against next_entry proves the
        // two paths agree rather than merely that each returns something.
        let bytes =
            mock_archive_bytes(&[("a.txt", b"alpha"), ("b.bin", b"bravo!!"), ("c.log", b"")]);

        let seekable = || -> Box<dyn Source> {
            let mut f = tempfile::NamedTempFile::new().unwrap();
            std::io::Write::write_all(&mut f, &bytes).unwrap();
            let (_, path) = f.keep().unwrap();
            Box::new(crate::source::FileSource::open(&path).unwrap())
        };

        // Sequential pass, for cross-checking.
        let mut ar = MockContainer
            .open(resolve_default(seekable()), &OpenOpts::default())
            .unwrap();
        let mut sequential = Vec::new();
        while let Some(mut e) = ar.next_entry().unwrap() {
            let name = e.meta().name.clone();
            let mut data = Vec::new();
            e.reader().read_to_end(&mut data).unwrap();
            sequential.push((name, data));
        }

        // Random access, deliberately out of order.
        let mut ar = MockContainer
            .open(resolve_default(seekable()), &OpenOpts::default())
            .unwrap();
        for i in [2usize, 0, 1] {
            let mut e = ar.by_index(i).unwrap();
            let name = e.meta().name.clone();
            let mut data = Vec::new();
            e.reader().read_to_end(&mut data).unwrap();
            assert_eq!(
                (name, data),
                sequential[i].clone(),
                "by_index({i}) disagreed with the sequential read"
            );
        }

        // Past the end is a miss, not a panic or a wrong entry.
        let mut ar = MockContainer
            .open(resolve_default(seekable()), &OpenOpts::default())
            .unwrap();
        assert!(matches!(
            ar.by_index(99),
            Err(crate::Error::EntryNotFound(_))
        ));
    }

    #[test]
    fn open_reports_lossless_fidelity_on_a_seekable_source() {
        let bytes = mock_archive_bytes(&[("a.txt", b"alpha")]);
        let mut f = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut f, &bytes).unwrap();
        let src: Box<dyn Source> = Box::new(crate::source::FileSource::open(f.path()).unwrap());

        let ar = MockContainer
            .open(resolve_default(src), &OpenOpts::default())
            .unwrap();
        let report = ar.fidelity();
        assert_eq!(report.rung, crate::Rung::Exact);
        assert!(
            report.is_lossless(),
            "a seekable source must yield an authoritative, warning-free report"
        );
    }

    #[test]
    fn open_reports_index_and_count_loss_on_a_non_seekable_source() {
        let bytes = mock_archive_bytes(&[("a.txt", b"alpha")]);
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));

        let ar = MockContainer
            .open(resolve_default(src), &OpenOpts::default())
            .unwrap();
        let report = ar.fidelity();
        assert_eq!(report.rung, crate::Rung::ForwardOnly);
        assert!(
            report
                .warnings
                .contains(&crate::Fidelity::TrailingIndexUnread {
                    format: MOCK_CONTAINER
                })
        );
        assert!(
            report
                .warnings
                .contains(&crate::Fidelity::EntryCountUnknown)
        );
    }

    #[test]
    fn a_container_can_see_the_rung_it_was_opened_at() {
        // Before this change the ladder could select Degraded but no container
        // could learn it had been asked for a salvage scan.
        let bytes = mock_archive_bytes(&[("a.txt", b"alpha")]);
        let caps = ContainerCaps {
            degraded_parse: true,
            ..MockContainer.caps()
        };
        let policy = crate::StreamPolicy::Adaptive {
            allow_forward_only: false,
            spill: crate::SpillPolicy::Off,
            allow_degraded: true,
        };
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
        let resolved = crate::resolve(src, MOCK_CONTAINER, caps, &policy).unwrap();
        assert_eq!(resolved.rung, crate::Rung::Degraded);

        let ar = MockContainer.open(resolved, &OpenOpts::default()).unwrap();
        assert_eq!(
            ar.fidelity().rung,
            crate::Rung::Degraded,
            "the rung must reach the container"
        );
    }

    #[test]
    fn a_spilled_read_reports_spilled_without_a_manual_merge() {
        // The ladder spills, so the container sees a SEEKABLE source. Before
        // this change it therefore reported Exact, and the spill was invisible
        // to anyone reading fidelity() alone.
        let bytes = mock_archive_bytes(&[("a.txt", b"alpha")]);
        let policy = crate::StreamPolicy::Adaptive {
            allow_forward_only: false,
            spill: crate::SpillPolicy::default(),
            allow_degraded: true,
        };
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
        let resolved = crate::resolve(src, MOCK_CONTAINER, MockContainer.caps(), &policy).unwrap();
        assert_eq!(resolved.rung, crate::Rung::Spilled);

        let ar = MockContainer.open(resolved, &OpenOpts::default()).unwrap();
        assert_eq!(ar.fidelity().rung, crate::Rung::Spilled);
        assert!(
            ar.fidelity().is_lossless(),
            "spilling costs disk, not accuracy"
        );
    }

    #[test]
    fn the_container_inherits_the_ladders_seed_rather_than_rederiving_it() {
        // The ladder seeds TrailingIndexUnread + EntryCountUnknown from caps.
        // The container must not independently derive the same two — inheriting
        // them is what removes the duplication merge() had to paper over.
        let bytes = mock_archive_bytes(&[("a.txt", b"alpha")]);
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
        let resolved = crate::resolve(
            src,
            MOCK_CONTAINER,
            MockContainer.caps(),
            &Default::default(),
        )
        .unwrap();
        let ar = MockContainer.open(resolved, &OpenOpts::default()).unwrap();

        let n = ar
            .fidelity()
            .warnings
            .iter()
            .filter(|w| matches!(w, crate::Fidelity::EntryCountUnknown))
            .count();
        assert_eq!(n, 1, "EntryCountUnknown must appear exactly once");
    }

    #[test]
    fn degraded_salvages_a_stream_that_forward_only_cannot_parse() {
        // Eight bytes of junk before the first record. A forward parse trusts
        // offset 0 and finds nothing; a salvage scan finds the record. Both
        // sources are non-seekable, so this is the difference the Degraded rung
        // actually buys — and it is reachable, unlike a difference gated on
        // seekability, which the ladder never pairs with Degraded.
        let mut bytes = b"JUNKJUNK".to_vec();
        bytes.extend_from_slice(&mock_archive_bytes(&[("a.txt", b"alpha")]));

        let forward = crate::resolve(
            Box::new(ReaderSource::new(std::io::Cursor::new(bytes.clone()))),
            MOCK_CONTAINER,
            MockContainer.caps(),
            &crate::StreamPolicy::default(),
        )
        .unwrap();
        assert_eq!(forward.rung, crate::Rung::ForwardOnly);
        let mut ar = MockContainer.open(forward, &OpenOpts::default()).unwrap();
        assert!(
            ar.next_entry().unwrap().is_none(),
            "a forward parse cannot start mid-junk"
        );

        let caps = ContainerCaps {
            degraded_parse: true,
            ..MockContainer.caps()
        };
        let policy = crate::StreamPolicy::Adaptive {
            allow_forward_only: false,
            spill: crate::SpillPolicy::Off,
            allow_degraded: true,
        };
        let salvage = crate::resolve(
            Box::new(ReaderSource::new(std::io::Cursor::new(bytes))),
            MOCK_CONTAINER,
            caps,
            &policy,
        )
        .unwrap();
        assert_eq!(salvage.rung, crate::Rung::Degraded);
        let mut ar = MockContainer.open(salvage, &OpenOpts::default()).unwrap();
        let mut e = ar
            .next_entry()
            .unwrap()
            .expect("salvage must recover the record");
        assert_eq!(e.meta().name, "a.txt");
        let mut data = Vec::new();
        e.reader().read_to_end(&mut data).unwrap();
        assert_eq!(data, b"alpha");
    }

    #[test]
    fn a_codec_parallelises_only_when_handed_a_governor() {
        // The seam: no ambient global. Without a governor the codec must not
        // claim workers; with one it draws from the shared budget.
        let plain = b"the quick brown fox".to_vec();

        let solo = DecodeOpts::default();
        assert!(solo.governor.is_none());
        assert_eq!(MockCodec.workers_for_opts(&solo), 1);

        let gov = crate::Governor::new(4, 1024 * 1024 * 1024);
        let opts = DecodeOpts {
            threads: Some(4),
            governor: Some(std::sync::Arc::clone(&gov)),
            ..Default::default()
        };
        assert_eq!(MockCodec.workers_for_opts(&opts), 4);
        assert_eq!(gov.outstanding(), 0, "the lease must be released again");

        // Decoding still works either way.
        let encoded: Vec<u8> = plain.iter().map(|b| b ^ 0xFF).collect();
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(encoded)));
        let mut dec = MockCodec.decoder(src, &opts).unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, plain);
    }

    #[test]
    fn opts_debug_does_not_require_a_debug_bound_on_governor() {
        let gov = crate::Governor::new(2, 1024);
        let o = DecodeOpts {
            threads: None,
            governor: Some(gov),
            ..Default::default()
        };
        assert!(format!("{o:?}").contains("governor"));
    }
}
