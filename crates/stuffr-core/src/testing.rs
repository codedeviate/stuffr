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
use crate::format::{CodecCaps, ContainerCaps, FormatId};
use crate::source::Source;

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

    fn decoder(&self, src: Box<dyn Source>, _o: &DecodeOpts) -> Result<Box<dyn Read + Send>> {
        Ok(Box::new(XorReader(Box::new(src))))
    }

    fn encoder(&self, dst: Box<dyn Write + Send>, _o: &EncodeOpts) -> Result<Box<dyn Sink>> {
        Ok(Box::new(XorSink(dst)))
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

    fn open(&self, mut src: Box<dyn Source>, _o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
        // The mock reads eagerly for simplicity; the ladder is what is under
        // test here, not incremental parsing.
        let seekable = src.caps().seekable;
        let mut buf = Vec::new();
        src.read_to_end(&mut buf)?;

        let index = if seekable {
            Self::parse_index(&buf)
        } else {
            None
        };
        let mut report = if seekable {
            FidelityReport::exact()
        } else {
            let mut r = FidelityReport::new(Rung::ForwardOnly);
            r.warn(Fidelity::TrailingIndexUnread {
                format: MOCK_CONTAINER,
            });
            r.warn(Fidelity::EntryCountUnknown);
            r
        };
        if seekable && index.is_none() {
            report.warn(Fidelity::TruncatedStream {
                at: buf.len() as u64,
            });
        }

        Ok(Box::new(MockArchiveRead {
            buf,
            pos: 0,
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
        let mut ar = MockContainer.open(src, &OpenOpts::default()).unwrap();

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
        let mut ar = MockContainer.open(src, &OpenOpts::default()).unwrap();
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
            .open(seekable(), &OpenOpts::default())
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
            .open(seekable(), &OpenOpts::default())
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
            .open(seekable(), &OpenOpts::default())
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

        let ar = MockContainer.open(src, &OpenOpts::default()).unwrap();
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

        let ar = MockContainer.open(src, &OpenOpts::default()).unwrap();
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
}
