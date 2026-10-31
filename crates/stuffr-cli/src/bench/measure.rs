//! The timing harness for `stuffr bench`: one format at one level, run over
//! the user's input, compressed and decompressed, with only codec work
//! inside a timed region, except the temp file's writes when the output is
//! too large to keep in memory (below).
//!
//! Compression's timed regions hold encoder creation, `write_all` of the
//! input and `Sink::finish` (which consumes the sink, so its teardown is
//! inside too). Decompression's hold decoder creation and reading the
//! decoder to its end into a buffer whose bytes are only counted. Building
//! the destination, opening files, reading streamed input, the temp file's
//! creation and removal, and dropping the decoder are all outside.
//!
//! Each phase is the sum of several timed pieces, each one pair of clock
//! reads. Compression: encoder creation, then one piece per 64 KiB
//! `write_all` of the input, then `finish`. Decompression: one piece per
//! 64 KiB the decoder fills, the decoder's creation in the first, its own
//! reads of the compressed bytes being part of decoding. In memory and
//! streamed alike; streamed, the input's reads fall between the pieces.
//! Otherwise nothing runs between them but the progress report, so the
//! pieces cost every format the same: one pair of clock reads per 64 KiB.
//!
//! Each codec gets the destination its own worst case allows, decided
//! before any timing: memory whenever that worst case (input + 1/8 +
//! 1 KiB, or 2 x input + 1 KiB for `compress`, LZW) fits under the memory
//! left for it, half of `--memory-limit` when the input is held in memory,
//! all of it when the input is streamed. Only past that does its output go
//! to one temp file, and then its writes (to the page cache, through the
//! 64 KiB buffer) fall inside its compression regions, so a row that went
//! to disk is marked ([`Measured::on_disk`]; the table's `*`, the `output`
//! field of JSON and CSV). With `--per-file` each file's stream is decided
//! by its own size. Both destinations have the same shape: a 64 KiB
//! `BufWriter` over a pre-reserved `Vec`, or over the temp file, so a codec
//! that writes in small pieces pays the same either way. Decoding reads the
//! same shape back: the `Vec` as a seekable, sized
//! source, or the temp file through a 64 KiB `BufReader`, so a decoder that
//! reads a byte at a time (LZW's) costs a memory copy per byte, not a
//! system call.
//!
//! Each file's length is taken once, when the input is loaded; every later
//! read stops there, so a file still being written is benched as it was.
//!
//! bench ignores STUFFR_THREADS; threads come only from --threads.
//!
//! With `--threads` above 1, a multi-threaded encoder's workers keep running
//! in the untimed gaps between pieces, so its compression time can be
//! under-reported against a single-threaded one. Streamed, the gaps hold
//! the input's reads; in memory, only the progress report (a clock read,
//! and a redraw at most every 100 ms).

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use stuffr::ops::{CompressOpts, resolved_budget};
use stuffr::source::{GuardedSeek, SeekRead, Source, SourceCaps};
use stuffr::{Codec, DecodeOpts, EncodeOpts, Error, FormatKind, Governor};

use super::score::{Measured, Outcome};
use crate::compat::{CleanupGuard, create_armed};

/// The copy buffer, as `ops` uses.
pub(super) const CHUNK: usize = 64 * 1024;

/// A monotonic clock in nanoseconds; injected so tests can count its reads.
pub trait Clock {
    fn now(&mut self) -> u64;
}

/// The real clock: nanoseconds since it was made.
pub struct RealClock(Instant);

impl RealClock {
    pub fn new() -> Self {
        Self(Instant::now())
    }
}

impl Default for RealClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for RealClock {
    fn now(&mut self) -> u64 {
        u64::try_from(self.0.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }
}

/// The input, in operand order: held in memory (one buffer per file) or
/// streamed from the files.
#[derive(Debug)]
pub enum Input {
    Memory(Vec<Vec<u8>>),
    Files(Vec<Snapshot>),
}

/// A streamed file and its length when the input was loaded: every read of
/// it stops at `len`, so bytes appended later are never benched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub path: PathBuf,
    pub len: u64,
}

impl Snapshot {
    /// The file, opened and limited to its loaded length.
    pub(super) fn open(&self) -> io::Result<io::Take<File>> {
        Ok(File::open(&self.path)?.take(self.len))
    }

    /// [`Snapshot::open`] while the input is loaded: a file that cannot be
    /// opened is the user's to fix, so a usage error naming it.
    fn open_input(&self) -> stuffr::Result<io::Take<File>> {
        self.open().map_err(|e| super::unreadable(&self.path, &e))
    }
}

/// One stream of the files concatenated, or one stream per file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    OneStream,
    PerFile,
}

/// The conditions every row runs under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub mode: Mode,
    /// Runs per row; the reported times are the medians. 0 counts as 1.
    pub repeat: u32,
    /// As `pack --threads`.
    pub threads: Option<usize>,
    pub memory_limit: u64,
}

/// Loads `paths` into memory when their total size is at most half of
/// `memory_limit`, leaving room for the compressed copy; otherwise the input
/// is streamed from the files.
///
/// Also returns the input's size, measured here once: the bytes read into
/// memory, or the files' sizes when streamed. It is the ratio's denominator,
/// and each file's length is snapshotted with it (reads stop there), so a
/// file still growing while the rows run changes neither.
///
/// A file whose size cannot be read, or that cannot be opened, is a usage
/// error naming it (exit 2); only a failing read is an i/o error.
pub fn load_input(paths: &[PathBuf], memory_limit: u64) -> stuffr::Result<(Input, u64)> {
    let mut total = 0u64;
    let mut snaps = Vec::with_capacity(paths.len());
    for p in paths {
        let len = fs::metadata(p).map_err(|e| super::unreadable(p, &e))?.len();
        total = total.saturating_add(len);
        snaps.push(Snapshot {
            path: p.clone(),
            len,
        });
    }
    if total > memory_limit / 2 {
        return Ok((Input::Files(snaps), total));
    }
    let mut parts = Vec::with_capacity(snaps.len());
    for s in &snaps {
        let mut buf = Vec::with_capacity(usize::try_from(s.len).unwrap_or(0));
        s.open_input()?.read_to_end(&mut buf)?;
        parts.push(buf);
    }
    let read = parts.iter().map(|b| b.len() as u64).sum();
    Ok((Input::Memory(parts), read))
}

/// One untimed read of every file, so the first timed run does not pay for
/// a cold cache. Nothing to do for input already in memory. A file that
/// cannot be opened is a usage error naming it, as in [`load_input`].
pub fn warm(input: &Input) -> stuffr::Result<()> {
    if let Input::Files(files) = input {
        let mut buf = vec![0u8; CHUNK];
        for s in files {
            let mut f = s.open_input()?;
            while read_some(&mut f, &mut buf)? > 0 {}
        }
    }
    Ok(())
}

/// Which half of a row's round trip a progress report is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Compress,
    Decompress,
}

/// Compresses and decompresses `input` with `codec` at `level` (`None`: the
/// encoder's own default) under `plan`. Every error, a rejected level
/// included, is a failed row; nothing panics.
///
/// `progress` is called only between timed pieces, never inside one, with
/// `(phase, done, total)`; `total` is the input's size. Each repeat opens
/// with exactly one `(Compress, 0, total)`; after it, `Compress` reports
/// the input bytes the encoder has taken, rising strictly, and `Decompress`
/// the bytes the decoder has given back, never falling; both end at
/// `total` and never pass it. With `Mode::PerFile` the two phases take
/// turns, file by file, each counting on across the files.
pub fn measure(
    codec: &str,
    level: Option<i32>,
    input: &Input,
    plan: &Plan,
    clock: &mut dyn Clock,
    progress: &mut dyn FnMut(Phase, u64, u64),
) -> Outcome {
    match run(codec, level, input, plan, clock, progress) {
        Ok(m) => Outcome::Ok(m),
        Err(e) => Outcome::Failed(e.to_string()),
    }
}

/// One file's input as the harness reads it.
#[derive(Clone, Copy)]
enum Part<'a> {
    Memory(&'a [u8]),
    File(&'a Snapshot),
}

impl Part<'_> {
    /// The length the input was loaded at, never re-read from the file.
    fn len(&self) -> u64 {
        match self {
            Part::Memory(b) => b.len() as u64,
            Part::File(s) => s.len,
        }
    }
}

/// A part as compression takes it: its bytes, or its file opened.
enum Feed<'a> {
    Memory(&'a [u8]),
    File(&'a Snapshot, io::Take<File>),
}

/// Where one stream's compressed output goes. Decided per codec, from its
/// own worst case, before any timing (see [`destination`]), and the same
/// for all of that codec's repeats. A row with any stream on the temp
/// file is marked as such ([`Measured::on_disk`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Dest {
    Memory,
    TempFile,
}

/// Memory whenever `codec`'s worst-case output for `input_len` bytes (see
/// [`output_room`]) fits in the memory left for it: half of `memory_limit`
/// beside input held in memory, all of it when the input is `streamed` (it
/// holds no copy of the input). The temp file only past that, so the
/// reservation never exceeds the budget. Each codec gets the destination
/// its own worst case allows; the row reports which it got.
fn destination(codec: &str, input_len: u64, memory_limit: u64, streamed: bool) -> Dest {
    // Small test inputs always fit; this is how the tests reach the temp
    // file with a memory limit the decoders can still work under.
    #[cfg(test)]
    if tests::FORCE_DISK.with(std::cell::Cell::get) {
        return Dest::TempFile;
    }
    let budget = if streamed {
        memory_limit
    } else {
        memory_limit / 2
    };
    match output_room(codec, input_len) {
        Some(w) if w <= budget => Dest::Memory,
        _ => Dest::TempFile,
    }
}

/// The capacity reserved for `codec`'s output in memory, large enough that
/// the `Vec` never reallocates inside a timed region. LZW (`compress`)
/// writes no code wider than 16 bits and every code stands for at least one
/// input byte, so it never writes more than two bytes per input byte (plus
/// its 3-byte header and the padding at each code-width step); every other
/// codec stays within 1/8 + 1 KiB, which
/// `the_reserved_room_holds_incompressible_output` measures. Reserved pages
/// a codec never writes are never touched. `None`: past `u64`, so it fits
/// nowhere.
fn output_room(codec: &str, input_len: u64) -> Option<u64> {
    match codec {
        "compress" => input_len.checked_mul(2),
        _ => input_len.checked_add(input_len / 8),
    }
    .and_then(|n| n.checked_add(1024))
}

fn run(
    name: &str,
    level: Option<i32>,
    input: &Input,
    plan: &Plan,
    clock: &mut dyn Clock,
    report: &mut dyn FnMut(Phase, u64, u64),
) -> stuffr::Result<Measured> {
    let reg = stuffr::registry();
    let id = reg
        .matrix()
        .into_iter()
        .find(|r| r.kind == FormatKind::Codec && r.id.as_str() == name)
        .map(|r| r.id)
        .ok_or_else(|| Error::Usage(format!("`{name}` is not a codec in this build")))?;
    let codec = reg.require_encoder(id)?;
    reg.require_decoder(id)?;

    let encode = EncodeOpts {
        level,
        governor: governor_for(plan),
        ..Default::default()
    };
    codec.check_encode_opts(&encode)?;
    let decode = DecodeOpts {
        memory_limit: Some(plan.memory_limit),
        ..Default::default()
    };

    let parts: Vec<Part<'_>> = match input {
        Input::Memory(bufs) => bufs.iter().map(|b| Part::Memory(b)).collect(),
        Input::Files(files) => files.iter().map(Part::File).collect(),
    };
    let groups: Vec<&[Part<'_>]> = match plan.mode {
        Mode::OneStream => vec![&parts[..]],
        Mode::PerFile => parts.chunks(1).collect(),
    };
    let group_len = |g: &[Part<'_>]| g.iter().map(Part::len).sum::<u64>();
    let streamed = matches!(input, Input::Files(_));
    let dest = |g: &[Part<'_>]| destination(name, group_len(g), plan.memory_limit, streamed);
    let temp = if groups.iter().any(|g| dest(g) == Dest::TempFile) {
        Some(TempOut::create()?)
    } else {
        None
    };

    let mut buf = vec![0u8; CHUNK];
    let mut bytes_out = None;
    let mut on_disk = false;
    let mut compress = Vec::new();
    let mut decompress = Vec::new();
    let mut progress = Progress::new(report, parts.iter().map(Part::len).sum());
    for _ in 0..plan.repeat.max(1) {
        progress.start();
        let (mut out, mut c_ns, mut d_ns) = (0u64, 0u64, 0u64);
        for group in &groups {
            let expected = group_len(group);
            let job = Job {
                name: id.as_str(),
                codec: codec.as_ref(),
                dest: dest(group),
                encode: &encode,
                decode: &decode,
                temp: temp.as_ref(),
                buf: &mut buf,
            };
            let row = job.run(group, expected, clock, &mut progress)?;
            out += row.bytes_out;
            c_ns += row.compress_ns;
            d_ns += row.decompress_ns;
            on_disk |= row.on_disk;
        }
        bytes_out.get_or_insert(out);
        compress.push(c_ns);
        decompress.push(d_ns);
    }
    Ok(Measured {
        bytes_out: bytes_out.unwrap_or(0),
        compress_ns: median(compress),
        decompress_ns: median(decompress),
        on_disk,
    })
}

/// The encode governor for `plan`: `pack --threads`'s mapping, except that
/// no `--threads` means single-threaded whatever `STUFFR_THREADS` says
/// (`resolved_budget` would read it). With a CLI value the variable is
/// already ignored: `resolve_workers` takes the CLI value first.
pub fn governor_for(plan: &Plan) -> Option<Arc<Governor>> {
    let t = plan.threads?;
    resolved_budget(&CompressOpts {
        threads: Some(t),
        memory_limit: Some(plan.memory_limit),
        ..Default::default()
    })
}

/// The middle value; the lower of the two middles for an even count.
fn median(mut v: Vec<u64>) -> u64 {
    v.sort_unstable();
    v.get(v.len().saturating_sub(1) / 2).copied().unwrap_or(0)
}

/// The progress reports of one row, made between timed pieces only (see
/// [`measure`] for what they promise).
struct Progress<'a> {
    report: &'a mut dyn FnMut(Phase, u64, u64),
    total: u64,
    fed: u64,
    decoded: u64,
}

impl<'a> Progress<'a> {
    fn new(report: &'a mut dyn FnMut(Phase, u64, u64), total: u64) -> Self {
        Self {
            report,
            total,
            fed: 0,
            decoded: 0,
        }
    }

    /// A repeat begins: its one `(Compress, 0, total)`.
    fn start(&mut self) {
        self.fed = 0;
        self.decoded = 0;
        (self.report)(Phase::Compress, 0, self.total);
    }

    /// The encoder took `n` more input bytes.
    fn fed(&mut self, n: usize) {
        let fed = self.fed.saturating_add(n as u64).min(self.total);
        // Never a second `(Compress, 0, _)`: that opens a repeat.
        if fed > self.fed {
            self.fed = fed;
            (self.report)(Phase::Compress, fed, self.total);
        }
    }

    /// The decoder gave back `n` more bytes.
    fn decoded(&mut self, n: usize) {
        self.decoded = self.decoded.saturating_add(n as u64).min(self.total);
        (self.report)(Phase::Decompress, self.decoded, self.total);
    }
}

/// One timed piece: `f` between two clock reads, and nothing else.
fn timed<T>(clock: &mut dyn Clock, f: impl FnOnce() -> T) -> (T, u64) {
    let t0 = clock.now();
    let r = f();
    let t1 = clock.now();
    (r, t1.saturating_sub(t0))
}

/// Everything one stream's round trip needs.
struct Job<'a> {
    name: &'a str,
    codec: &'a dyn Codec,
    dest: Dest,
    encode: &'a EncodeOpts,
    decode: &'a DecodeOpts,
    temp: Option<&'a TempOut>,
    buf: &'a mut [u8],
}

impl Job<'_> {
    /// Compresses `group` as one stream, then decompresses it, checking the
    /// round trip gives back `expected` bytes.
    fn run(
        mut self,
        group: &[Part<'_>],
        expected: u64,
        clock: &mut dyn Clock,
        progress: &mut Progress<'_>,
    ) -> stuffr::Result<Measured> {
        let on_disk = matches!((self.dest, self.temp), (Dest::TempFile, Some(_)));
        let (bytes_out, compress_ns, src) = match (self.dest, self.temp) {
            (Dest::Memory, _) | (Dest::TempFile, None) => {
                // Room for incompressible output, so the outer Vec does not
                // reallocate inside the region. (`TempFile` always comes
                // with a temp file; `run` creates one whenever any group
                // needs it.)
                let room = output_room(self.name, expected).unwrap_or(0);
                let shared = SharedVec::with_capacity(usize::try_from(room).unwrap_or(0));
                let dst = BufWriter::with_capacity(CHUNK, shared.clone());
                let ns = self.compress(group, Box::new(dst), clock, progress)?;
                let bytes = shared.take();
                let len = bytes.len() as u64;
                (len, ns, Box::new(MemSource::new(bytes)) as Box<dyn Source>)
            }
            (Dest::TempFile, Some(temp)) => {
                // Through the descriptor `create` made, never the name
                // again (HOST-9): emptied and rewound for this row.
                let mut file = temp.handle()?;
                file.set_len(0)?;
                file.seek(SeekFrom::Start(0))?;
                let dst = BufWriter::with_capacity(CHUNK, file);
                let ns = self.compress(group, Box::new(dst), clock, progress)?;
                let mut file = temp.handle()?;
                file.seek(SeekFrom::Start(0))?;
                let len = file.metadata()?.len();
                let src = temp_source(GuardedSeek::new(counted(file)), len);
                (len, ns, Box::new(src) as Box<dyn Source>)
            }
        };
        let (decoded, decompress_ns) =
            decode(self.codec, self.decode, src, self.buf, clock, progress)?;
        if decoded != expected {
            return Err(Error::Corrupt(format!(
                "the round trip gave back {decoded} bytes of {expected}"
            )));
        }
        Ok(Measured {
            bytes_out,
            compress_ns,
            decompress_ns,
            on_disk,
        })
    }

    /// The compression pieces' total: encoder creation, one `write_all`
    /// per 64 KiB of input, `finish`. Streamed, each chunk is read between
    /// two pieces.
    fn compress(
        &mut self,
        group: &[Part<'_>],
        dst: Box<dyn Write + Send>,
        clock: &mut dyn Clock,
        progress: &mut Progress<'_>,
    ) -> stuffr::Result<u64> {
        // Files are opened before any timing.
        let mut feeds = Vec::with_capacity(group.len());
        for p in group {
            feeds.push(match p {
                Part::Memory(b) => Feed::Memory(b),
                Part::File(snap) => Feed::File(snap, snap.open()?),
            });
        }
        let (sink, mut ns) = timed(clock, || self.codec.encoder(dst, self.encode));
        let mut sink = sink?;
        for feed in &mut feeds {
            match feed {
                Feed::Memory(b) => {
                    for chunk in b.chunks(CHUNK) {
                        let (r, t) = timed(clock, || sink.write_all(chunk));
                        r?;
                        ns += t;
                        progress.fed(chunk.len());
                    }
                }
                Feed::File(snap, f) => {
                    let mut read = 0u64;
                    loop {
                        let n = read_some(f, self.buf)?;
                        if n == 0 {
                            if read < snap.len {
                                return Err(shrank(snap, read));
                            }
                            break;
                        }
                        read += n as u64;
                        let chunk = &self.buf[..n];
                        let (r, t) = timed(clock, || sink.write_all(chunk));
                        r?;
                        ns += t;
                        progress.fed(n);
                    }
                }
            }
        }
        let (r, t) = timed(clock, || sink.finish());
        r?;
        Ok(ns + t)
    }
}

/// Decompression: one piece per 64 KiB the decoder fills (`buf` is
/// [`CHUNK`] long), the decoder made in the first, until a fill comes back
/// short at the end; the bytes are only counted. Returns the count and the
/// pieces' total. The decoder is dropped outside them.
fn decode(
    codec: &dyn Codec,
    opts: &DecodeOpts,
    src: Box<dyn Source>,
    buf: &mut [u8],
    clock: &mut dyn Clock,
    progress: &mut Progress<'_>,
) -> stuffr::Result<(u64, u64)> {
    let (first, mut ns) = timed(clock, || {
        let mut decoder = codec.decoder(src, opts)?;
        let n = fill(&mut decoder, buf).map_err(Error::from_decode_io)?;
        Ok::<_, Error>((decoder, n))
    });
    let (mut decoder, mut n) = first?;
    let mut total = 0u64;
    loop {
        total += n as u64;
        progress.decoded(n);
        if n < buf.len() {
            break;
        }
        let (r, t) = timed(clock, || fill(&mut decoder, buf));
        ns += t;
        n = r.map_err(Error::from_decode_io)?;
    }
    drop(decoder);
    Ok((total, ns))
}

/// A streamed file ended at `read` bytes, short of the length it was
/// loaded at.
pub(super) fn shrank(snap: &Snapshot, read: u64) -> Error {
    Error::Io(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        format!(
            "{} shrank to {read} bytes from {} while bench ran",
            snap.path.display(),
            snap.len
        ),
    ))
}

/// Reads into `buf` until it is full or the reader ends, retrying
/// `Interrupted`. Short only at the end.
pub(super) fn fill(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// `read`, retried on `Interrupted`.
pub(super) fn read_some(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        match r.read(buf) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            other => return other,
        }
    }
}

/// The in-memory destination: the encoder owns one handle, the harness
/// keeps the other to take the bytes back after `finish`.
#[derive(Clone)]
struct SharedVec(Arc<Mutex<Vec<u8>>>);

impl SharedVec {
    fn with_capacity(n: usize) -> Self {
        Self(Arc::new(Mutex::new(Vec::with_capacity(n))))
    }

    #[cfg(test)]
    fn capacity(&self) -> usize {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).capacity()
    }

    fn take(&self) -> Vec<u8> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

impl Write for SharedVec {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend_from_slice(b);
        Ok(b.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Compressed bytes in memory, as seekable and sized as the [`BufSource`]
/// over the temp file, so a decoder sees the same capabilities either way.
struct MemSource {
    cursor: Cursor<Vec<u8>>,
    len: u64,
}

impl MemSource {
    fn new(bytes: Vec<u8>) -> Self {
        let len = bytes.len() as u64;
        Self {
            cursor: Cursor::new(bytes),
            len,
        }
    }
}

impl Read for MemSource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.cursor.read(buf)
    }
}

impl Seek for MemSource {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.cursor.seek(pos)
    }
}

impl Source for MemSource {
    fn caps(&self) -> SourceCaps {
        SourceCaps {
            seekable: true,
            len: Some(self.len),
        }
    }

    fn as_seek(&mut self) -> Option<&mut dyn SeekRead> {
        Some(self)
    }
}

/// The temp file's compressed bytes as the decoder reads them: through a
/// 64 KiB buffer, so a decoder reading a byte at a time pays a memory copy
/// per byte, as it does from [`MemSource`], not a system call. Seekable and
/// sized like `MemSource`.
pub(super) fn temp_source<R: Read + Seek + Send>(inner: R, len: u64) -> BufSource<R> {
    BufSource {
        inner: BufReader::with_capacity(CHUNK, inner),
        len,
    }
}

pub(super) struct BufSource<R> {
    inner: BufReader<R>,
    len: u64,
}

impl<R: Read> Read for BufSource<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<R: Seek> Seek for BufSource<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

impl<R: Read + Seek + Send> Source for BufSource<R> {
    fn caps(&self) -> SourceCaps {
        SourceCaps {
            seekable: true,
            len: Some(self.len),
        }
    }

    fn as_seek(&mut self) -> Option<&mut dyn SeekRead> {
        Some(self)
    }
}

/// The temp file as `temp_source` reads it. Production: the file itself.
#[cfg(not(test))]
fn counted(file: File) -> File {
    file
}

/// Under test, a file whose reads are counted per thread, so a test sees
/// how many reach it through the path `measure` takes.
#[cfg(test)]
fn counted(file: File) -> tests::CountedFile {
    tests::CountedFile(file)
}

/// The next temp file's `<n>`; also how the tests see whether a run made one.
static TEMP_SEQ: AtomicU32 = AtomicU32::new(0);

/// The streamed run's compressed output, `stuffr-bench-<pid>-<n>` in the
/// temp directory: armed for removal on SIGINT, SIGTERM and SIGHUP while it
/// lives, removed when it drops (a panic included).
pub(super) struct TempOut {
    path: PathBuf,
    /// The descriptor `create` opened (read and write, `create_new`, 0600):
    /// every use of the file goes through it ([`Self::handle`]), never
    /// through the name, so nothing put at the name after the create —
    /// a symlink to a victim file — is ever opened, truncated or written
    /// (HOST-9). Only the memory child, another process, opens it by name,
    /// and checks what it opened (`memory::open_copy`).
    file: File,
    /// Dropped after `drop` has removed the file, so there is no moment the
    /// file exists unarmed.
    _armed: CleanupGuard,
}

impl TempOut {
    pub(super) fn create() -> io::Result<Self> {
        let dir = std::env::temp_dir();
        let mut tries = 0;
        loop {
            let n = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
            let path = dir.join(format!("stuffr-bench-{}-{n}", std::process::id()));
            match create_armed(&path) {
                Ok((file, armed)) => {
                    return Ok(Self {
                        path,
                        file,
                        _armed: armed,
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && tries < 1000 => tries += 1,
                Err(e) => return Err(e),
            }
        }
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// Another handle on the file `create` made (`try_clone`: the same open
    /// file, sharing its offset — callers seek before use).
    pub(super) fn handle(&self) -> io::Result<File> {
        self.file.try_clone()
    }
}

impl Drop for TempOut {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// 0, 10, 20, …: every region it times lasts exactly 10.
    struct FakeClock(u64);

    impl Clock for FakeClock {
        fn now(&mut self) -> u64 {
            let t = self.0;
            self.0 += 10;
            t
        }
    }

    /// Times region `i` (reads `2i` and `2i + 1`) as `durations[i]`.
    struct ScriptClock {
        durations: Vec<u64>,
        reads: usize,
        t: u64,
    }

    impl Clock for ScriptClock {
        fn now(&mut self) -> u64 {
            if self.reads % 2 == 1 {
                self.t += self.durations[self.reads / 2];
            } else {
                self.t += 1_000;
            }
            self.reads += 1;
            self.t
        }
    }

    /// A scratch directory `stuffr-benchtest-<pid>-<n>`, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("stuffr-benchtest-{}-{n}", std::process::id()));
            fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }

        fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let p = self.0.join(name);
            fs::write(&p, bytes).unwrap();
            p
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Serialises the tests that arm the process-wide signal cleanup.
    fn armed_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::compat::ARM_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn text(len: usize, seed: u8) -> Vec<u8> {
        b"the quick brown fox jumps over the lazy dog, "
            .iter()
            .cycle()
            .enumerate()
            .map(|(i, &b)| b.wrapping_add(seed).wrapping_add((i / 997) as u8))
            .take(len)
            .collect()
    }

    fn plan(mode: Mode, repeat: u32) -> Plan {
        Plan {
            mode,
            repeat,
            threads: None,
            memory_limit: 1 << 30,
        }
    }

    thread_local! {
        /// Set by `on_disk`: every output goes to the temp file.
        pub(super) static FORCE_DISK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// Runs `f` with every compressed output sent to the temp file.
    fn on_disk<T>(f: impl FnOnce() -> T) -> T {
        FORCE_DISK.with(|d| d.set(true));
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        FORCE_DISK.with(|d| d.set(false));
        r.unwrap_or_else(|e| std::panic::resume_unwind(e))
    }

    thread_local! {
        /// Reads that reached a temp file on this thread (see `counted`).
        static FILE_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// The temp file under test: counts each read that reaches it.
    pub(super) struct CountedFile(pub(super) File);

    impl Read for CountedFile {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            FILE_READS.with(|r| r.set(r.get() + 1));
            self.0.read(buf)
        }
    }

    impl Seek for CountedFile {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.0.seek(pos)
        }
    }

    /// The temp files created while `f` ran. Hold `armed_lock`: every test
    /// that can create one does.
    fn temps_made(f: impl FnOnce()) -> u32 {
        let before = TEMP_SEQ.load(Ordering::Relaxed);
        f();
        TEMP_SEQ.load(Ordering::Relaxed) - before
    }

    /// Deterministic noise no codec can shrink.
    fn noise(len: usize) -> Vec<u8> {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    fn ok(o: Outcome) -> Measured {
        match o {
            Outcome::Ok(m) => m,
            Outcome::Failed(e) => panic!("failed: {e}"),
        }
    }

    fn run(codec: &str, input: &Input, plan: &Plan) -> Measured {
        ok(measure(
            codec,
            None,
            input,
            plan,
            &mut FakeClock(0),
            &mut |_, _, _| {},
        ))
    }

    fn bench_temps() -> Vec<String> {
        let prefix = format!("stuffr-bench-{}-", std::process::id());
        fs::read_dir(std::env::temp_dir())
            .unwrap()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| n.starts_with(&prefix))
            .collect()
    }

    #[test]
    fn one_stream_compresses_the_concatenation() {
        let (a, b) = (text(20_000, 0), text(30_000, 7));
        let both = [a.clone(), b.clone()].concat();
        let p = plan(Mode::OneStream, 1);
        for codec in ["gzip", "zstd", "bzip2"] {
            let parts = run(codec, &Input::Memory(vec![a.clone(), b.clone()]), &p);
            let whole = run(codec, &Input::Memory(vec![both.clone()]), &p);
            assert_eq!(parts.bytes_out, whole.bytes_out, "{codec}");
        }
    }

    #[test]
    fn per_file_sums_each_file() {
        let (a, b) = (text(20_000, 0), text(30_000, 7));
        let p = plan(Mode::PerFile, 1);
        let both = run("gzip", &Input::Memory(vec![a.clone(), b.clone()]), &p);
        let one = run("gzip", &Input::Memory(vec![a]), &p);
        let two = run("gzip", &Input::Memory(vec![b]), &p);
        assert_eq!(both.bytes_out, one.bytes_out + two.bytes_out);
        let stream = run(
            "gzip",
            &Input::Memory(vec![text(20_000, 0), text(30_000, 7)]),
            &plan(Mode::OneStream, 1),
        );
        assert_ne!(
            both.bytes_out, stream.bytes_out,
            "per-file is not one stream"
        );
        // Per file: encoder creation, one write (each file is under 64 KiB)
        // and `finish` to compress, one fill to decompress; summed.
        assert_eq!(both.compress_ns, 2 * 30);
        assert_eq!(both.decompress_ns, 2 * 10);
    }

    /// Streamed: compression is encoder creation, one region per input
    /// chunk's `write_all` (each 64 KiB read falls between them) and
    /// `finish`; decompression one region per 64 KiB filled, the decoder
    /// made in the first.
    #[test]
    fn a_streamed_run_times_each_write_and_not_the_reads() {
        let _lock = armed_lock();
        let s = Scratch::new();
        // Two chunks: 64 KiB, then 36 KiB.
        let paths = vec![s.file("a", &text(100 * 1024, 6))];
        let files = load_input(&paths, 0).unwrap().0;
        let mut clock = FakeClock(0);
        let m = ok(measure(
            "gzip",
            None,
            &files,
            &plan(Mode::OneStream, 1),
            &mut clock,
            &mut |_, _, _| {},
        ));
        let regions = 1 + 2 + 1;
        // 64 KiB, then 36 KiB: the short fill is the end.
        let fills = 2;
        assert_eq!(m.compress_ns, 10 * regions);
        assert_eq!(m.decompress_ns, 10 * fills);
        assert_eq!(clock.0, 10 * 2 * (regions + fills), "no other clock reads");
    }

    #[test]
    fn no_threads_means_no_governor() {
        // Pinned structurally rather than by exporting STUFFR_THREADS: the
        // lib tests share one environment (edition 2024 `set_var` is
        // unsafe for exactly that reason), and `governor_for` returns
        // before `resolved_budget`, the only reader of the variable, is
        // called.
        assert!(governor_for(&plan(Mode::OneStream, 1)).is_none());
        let two = Plan {
            threads: Some(2),
            ..plan(Mode::OneStream, 1)
        };
        assert!(governor_for(&two).is_some());
    }

    /// In memory, as streamed: encoder creation, one piece per 64 KiB
    /// `write_all` and `finish`; then one piece per 64 KiB the decoder
    /// fills, the decoder made in the first. Each piece is exactly two
    /// clock reads, and there are no others.
    #[test]
    fn the_fake_clock_still_times_only_codec_work() {
        // Three chunks: 64, 64 and 32 KiB.
        let input = Input::Memory(vec![text(160 * 1024, 3)]);
        let mut clock = FakeClock(0);
        let m = ok(measure(
            "gzip",
            None,
            &input,
            &plan(Mode::OneStream, 1),
            &mut clock,
            &mut |_, _, _| {},
        ));
        let compress_pieces = 1 + 3 + 1;
        // 64, 64, then 32 KiB: the short fill is the end.
        let decompress_pieces = 3;
        assert_eq!(m.compress_ns, 10 * compress_pieces);
        assert_eq!(m.decompress_ns, 10 * decompress_pieces);
        assert_eq!(
            clock.0,
            10 * 2 * (compress_pieces + decompress_pieces),
            "two reads per piece, nothing else"
        );
    }

    /// A clock whose reads a progress callback can see: the callback runs
    /// inside a timed region exactly when the count is odd.
    struct SeenClock(std::rc::Rc<std::cell::Cell<u64>>);

    impl Clock for SeenClock {
        fn now(&mut self) -> u64 {
            let n = self.0.get();
            self.0.set(n + 1);
            10 * n
        }
    }

    /// Splits `seen` into repeats at each `(Compress, 0, _)`, the one report
    /// that opens a repeat, and checks each: both phases rise to `total`,
    /// compression strictly after the opening report.
    fn check_reports(seen: &[(Phase, u64, u64)], total: u64, repeats: usize, what: &str) {
        let opens: Vec<usize> = (0..seen.len())
            .filter(|&i| matches!(seen[i], (Phase::Compress, 0, _)))
            .collect();
        assert_eq!(opens.len(), repeats, "{what}: {seen:?}");
        assert_eq!(opens[0], 0, "{what}: the first report opens a repeat");
        for (i, &start) in opens.iter().enumerate() {
            let end = opens.get(i + 1).copied().unwrap_or(seen.len());
            let one = &seen[start..end];
            assert!(one.iter().all(|r| r.2 == total), "{what}: {one:?}");
            let fed: Vec<u64> = one
                .iter()
                .filter(|r| r.0 == Phase::Compress)
                .map(|r| r.1)
                .collect();
            let decoded: Vec<u64> = one
                .iter()
                .filter(|r| r.0 == Phase::Decompress)
                .map(|r| r.1)
                .collect();
            assert!(fed.windows(2).all(|w| w[0] < w[1]), "{what}: {fed:?}");
            assert!(
                decoded.windows(2).all(|w| w[0] <= w[1]),
                "{what}: {decoded:?}"
            );
            assert_eq!(fed.last(), Some(&total), "{what}: compression");
            assert_eq!(decoded.last(), Some(&total), "{what}: decompression");
            assert!(fed.len() > 2 && decoded.len() > 1, "{what}: {one:?}");
        }
    }

    #[test]
    fn progress_is_reported_between_pieces_only() {
        use std::{cell::Cell, rc::Rc};
        let _lock = armed_lock();
        let s = Scratch::new();
        let data = text(160 * 1024, 5);
        let paths = vec![
            s.file("a", &data[..100 * 1024]),
            s.file("b", &data[100 * 1024..]),
        ];
        let memory = load_input(&paths, 1 << 30).unwrap().0;
        let files = load_input(&paths, 0).unwrap().0;
        for (input, disk, name) in [
            (&memory, false, "memory"),
            (&memory, true, "memory, temp file"),
            (&files, false, "streamed"),
            (&files, true, "streamed, temp file"),
        ] {
            for mode in [Mode::OneStream, Mode::PerFile] {
                let reads = Rc::new(Cell::new(0));
                let mut clock = SeenClock(reads.clone());
                let mut seen = Vec::new();
                let mut report = |phase, done, total| {
                    assert_eq!(reads.get() % 2, 0, "a report inside a timed region");
                    seen.push((phase, done, total));
                };
                let p = plan(mode, 2);
                let mut go = || measure("gzip", None, input, &p, &mut clock, &mut report);
                let o = if disk { on_disk(go) } else { go() };
                ok(o);
                check_reports(&seen, data.len() as u64, 2, &format!("{name} {mode:?}"));
            }
        }
    }

    #[test]
    fn repeat_reports_the_median() {
        let input = Input::Memory(vec![text(4096, 1)]);
        // Per run: encoder creation, one write, `finish`, then one fill.
        // Compression 30, 10, 20; decompression 7, 5, 9.
        let mut clock = ScriptClock {
            durations: vec![10, 10, 10, 7, 2, 3, 5, 5, 5, 5, 10, 9],
            reads: 0,
            t: 0,
        };
        let m = ok(measure(
            "gzip",
            None,
            &input,
            &plan(Mode::OneStream, 3),
            &mut clock,
            &mut |_, _, _| {},
        ));
        assert_eq!(m.compress_ns, 20);
        assert_eq!(m.decompress_ns, 7);
        assert_eq!(clock.reads, 24, "two reads per piece, nothing else");
    }

    #[test]
    fn an_even_repeat_reports_the_lower_median() {
        let input = Input::Memory(vec![text(4096, 1)]);
        let mut clock = ScriptClock {
            // Compression 40, 10, 30, 20; decompression 1, 2, 3, 4.
            durations: vec![20, 10, 10, 1, 4, 3, 3, 2, 10, 10, 10, 3, 5, 5, 10, 4],
            reads: 0,
            t: 0,
        };
        let m = ok(measure(
            "gzip",
            None,
            &input,
            &plan(Mode::OneStream, 4),
            &mut clock,
            &mut |_, _, _| {},
        ));
        assert_eq!(m.compress_ns, 20);
        assert_eq!(m.decompress_ns, 2);
    }

    #[test]
    fn a_rejected_level_is_a_failed_row() {
        let input = Input::Memory(vec![text(1024, 0)]);
        let mut clock = FakeClock(0);
        match measure(
            "gzip",
            Some(99),
            &input,
            &plan(Mode::OneStream, 1),
            &mut clock,
            &mut |_, _, _| {},
        ) {
            Outcome::Failed(msg) => assert!(msg.contains("99"), "{msg}"),
            Outcome::Ok(m) => panic!("level 99 accepted: {m:?}"),
        }
        assert_eq!(clock.0, 0, "nothing was timed");
    }

    #[test]
    fn an_unknown_format_is_a_failed_row() {
        let input = Input::Memory(vec![text(1024, 0)]);
        let o = measure(
            "nope",
            None,
            &input,
            &plan(Mode::OneStream, 1),
            &mut FakeClock(0),
            &mut |_, _, _| {},
        );
        assert!(matches!(o, Outcome::Failed(_)), "{o:?}");
    }

    #[test]
    fn streamed_input_matches_memory_input() {
        let _lock = armed_lock();
        let s = Scratch::new();
        let (a, b) = (text(32 * 1024, 2), text(32 * 1024, 9));
        let paths = vec![s.file("a", &a), s.file("b", &b)];
        let files = load_input(&paths, 0).unwrap().0;
        assert!(matches!(files, Input::Files(_)));
        warm(&files).unwrap();
        let memory = load_input(&paths, 1 << 30).unwrap().0;
        assert!(matches!(memory, Input::Memory(_)));
        for mode in [Mode::OneStream, Mode::PerFile] {
            let p = plan(mode, 1);
            for codec in ["gzip", "xz", "lz4"] {
                let want = run(codec, &memory, &p).bytes_out;
                assert_eq!(run(codec, &files, &p).bytes_out, want, "{codec}");
                let disk = on_disk(|| run(codec, &files, &p)).bytes_out;
                assert_eq!(disk, want, "{codec} via the temp file");
            }
        }
    }

    #[test]
    fn the_output_temp_file_is_removed() {
        let _lock = armed_lock();
        let s = Scratch::new();
        let paths = vec![s.file("a", &text(16 * 1024, 4))];
        let files = load_input(&paths, 0).unwrap().0;
        let made = temps_made(|| {
            on_disk(|| run("gzip", &files, &plan(Mode::OneStream, 2)));
        });
        assert_eq!(made, 1);
        assert_eq!(bench_temps(), Vec::<String>::new());
    }

    #[test]
    fn the_temp_guard_removes_on_panic() {
        let _lock = armed_lock();
        let seen = std::sync::Mutex::new(None::<PathBuf>);
        let r = std::panic::catch_unwind(|| {
            let guard = TempOut::create().unwrap();
            *seen.lock().unwrap() = Some(guard.path().to_path_buf());
            assert!(guard.path().exists());
            panic!("mid-run");
        });
        assert!(r.is_err());
        let path = seen.into_inner().unwrap().expect("the guard was created");
        assert!(!path.exists(), "{} survived the panic", path.display());
        #[cfg(unix)]
        assert!(
            crate::compat::armed_path().is_none(),
            "still armed after the panic"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_temp_file_is_armed_for_signals() {
        let _lock = armed_lock();
        let guard = TempOut::create().unwrap();
        let path = guard.path().to_path_buf();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        assert!(
            name.starts_with(&format!("stuffr-bench-{}-", std::process::id())),
            "{name}"
        );
        assert_eq!(crate::compat::armed_path().as_deref(), Some(path.as_path()));
        drop(guard);
        assert!(
            crate::compat::armed_path().is_none(),
            "armed after the drop"
        );
        assert!(!path.exists());
    }

    #[test]
    fn empty_input_measures_without_error() {
        for mode in [Mode::OneStream, Mode::PerFile] {
            for codec in crate::bench::levels::benchable_codecs() {
                let m = run(codec, &Input::Memory(vec![Vec::new()]), &plan(mode, 1));
                assert!(m.bytes_out < 1024, "{codec}: {m:?}");
            }
        }
    }

    #[test]
    fn every_benchable_codec_round_trips_in_both_modes() {
        let _lock = armed_lock();
        let s = Scratch::new();
        let paths = vec![s.file("a", &text(8 * 1024, 5)), s.file("b", &text(4096, 8))];
        let files = load_input(&paths, 0).unwrap().0;
        let memory = load_input(&paths, 1 << 30).unwrap().0;
        for mode in [Mode::OneStream, Mode::PerFile] {
            for codec in crate::bench::levels::benchable_codecs() {
                for input in [&files, &memory] {
                    run(codec, input, &plan(mode, 1));
                    on_disk(|| run(codec, input, &plan(mode, 1)));
                }
            }
        }
    }

    /// Counts the reads that reach the wrapped reader.
    struct CountReads<R> {
        inner: R,
        reads: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl<R: Read> Read for CountReads<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            self.inner.read(buf)
        }
    }

    impl<R: Seek> Seek for CountReads<R> {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    /// LZW's decoder reads one byte per call. Through the temp file's
    /// source those calls must not each reach the file (one system call
    /// per compressed byte made streamed decoding 17-34x slower than the
    /// same decode from memory).
    #[test]
    fn the_temp_file_is_read_in_large_pieces_by_a_byte_reader() {
        let input = text(64 * 1024, 4);
        let codec = stuffr::registry()
            .codec(stuffr::FormatId::new("compress"))
            .expect("compress is in every default build");
        let out = SharedVec::with_capacity(0);
        let mut sink = codec
            .encoder(Box::new(out.clone()), &EncodeOpts::default())
            .unwrap();
        sink.write_all(&input).unwrap();
        sink.finish().unwrap();
        let bytes = out.take();
        let len = bytes.len() as u64;
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let file = CountReads {
            inner: Cursor::new(bytes),
            reads: reads.clone(),
        };
        let src = temp_source(file, len);
        // The shape `MemSource` gives the in-memory path.
        assert_eq!(
            src.caps(),
            SourceCaps {
                seekable: true,
                len: Some(len)
            }
        );
        let mut buf = vec![0u8; CHUNK];
        let (decoded, _) = decode(
            codec.as_ref(),
            &DecodeOpts::default(),
            Box::new(src),
            &mut buf,
            &mut FakeClock(0),
            &mut Progress::new(&mut |_, _, _| {}, input.len() as u64),
        )
        .unwrap();
        assert_eq!(decoded, input.len() as u64);
        let reads = reads.load(Ordering::Relaxed);
        assert!(
            reads as u64 <= len / CHUNK as u64 + 4,
            "{reads} reads reached the file for {len} compressed bytes"
        );
    }

    /// The same check through `measure`: LZW reads its input a byte at a
    /// time, so if the production temp-file path stopped buffering, the
    /// reads reaching the file would be about one per compressed byte.
    #[test]
    fn measure_reads_the_temp_file_in_large_pieces() {
        let _lock = armed_lock();
        let input = Input::Memory(vec![text(64 * 1024, 4)]);
        FILE_READS.with(|r| r.set(0));
        let m = on_disk(|| run("compress", &input, &plan(Mode::OneStream, 1)));
        let reads = FILE_READS.with(std::cell::Cell::get) as u64;
        assert!(m.bytes_out > 4096, "{} compressed bytes", m.bytes_out);
        assert!(reads > 0, "no read reached the temp file");
        assert!(
            reads <= m.bytes_out / CHUNK as u64 + 4,
            "{reads} reads reached the file for {} compressed bytes",
            m.bytes_out
        );
    }

    /// HOST-9: the temp file is used through the descriptor `create` made.
    /// Its name is swapped for a symlink to a victim file mid-run (from the
    /// progress callback, between timed pieces); the later repeats still
    /// write and read the original file, the run succeeds and the victim is
    /// untouched. Reopened by name, the next repeat truncated the victim.
    #[cfg(unix)]
    #[test]
    fn a_symlink_put_at_the_temp_name_is_never_written_through() {
        let _lock = armed_lock();
        let dir = std::env::temp_dir().join(format!("stuffr-benchvictim-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim");
        fs::write(&victim, b"precious").unwrap();
        let input = Input::Memory(vec![text(64 * 1024, 6)]);
        let mut swapped = false;
        let m = on_disk(|| {
            measure(
                "gzip",
                None,
                &input,
                &plan(Mode::OneStream, 3),
                &mut FakeClock(0),
                &mut |_, _, _| {
                    if swapped {
                        return;
                    }
                    if let Some(name) = bench_temps().into_iter().next() {
                        let path = std::env::temp_dir().join(name);
                        fs::remove_file(&path).unwrap();
                        std::os::unix::fs::symlink(&victim, &path).unwrap();
                        swapped = true;
                    }
                },
            )
        });
        let m = ok(m);
        assert!(swapped, "the progress callback never ran");
        assert!(m.on_disk);
        assert_eq!(fs::read(&victim).unwrap(), b"precious");
        let _ = fs::remove_dir_all(&dir);
    }

    /// `compress` can write twice its input; near the limit that must not be
    /// reserved in memory, over the budget. Each codec gets the destination
    /// its own worst case allows: `compress` goes to the temp file and its
    /// row says so; `gzip`, whose worst case fits, stays in memory beside it.
    #[test]
    fn compress_near_the_limit_goes_to_disk_and_is_marked() {
        let _lock = armed_lock();
        let len = 16 * 1024;
        let input = Input::Memory(vec![noise(len)]);
        // The input (16384) is between limit / 4 and limit / 2. gzip's
        // worst case (len + len / 8 + 1 KiB = 19456) fits in that half
        // exactly; compress's (2 * len + 1 KiB = 33792) does not.
        let p = Plan {
            memory_limit: 2 * 19_456,
            ..plan(Mode::OneStream, 1)
        };
        for (codec, want_temps, want_disk) in [("compress", 1, true), ("gzip", 0, false)] {
            let mut m = None;
            let made = temps_made(|| m = Some(run(codec, &input, &p)));
            assert_eq!(made, want_temps, "{codec}");
            assert_eq!(m.unwrap().on_disk, want_disk, "{codec}");
        }
        // Streamed: the whole limit is the budget.
        for (codec, limit, want) in [("gzip", 19_456, 0), ("compress", 33_791, 1)] {
            assert_eq!(
                destination(codec, len as u64, limit, true) == Dest::TempFile,
                want == 1,
                "{codec} streamed at {limit}"
            );
        }
        assert_eq!(
            destination("compress", len as u64, 33_792, true),
            Dest::Memory
        );
    }

    #[test]
    fn the_output_goes_to_memory_whenever_its_worst_case_fits() {
        // 0 bytes in: worst case 1 KiB, which fits under 2048 / 2.
        // Beside input in memory: half the limit.
        assert_eq!(destination("gzip", 0, 2048, false), Dest::Memory);
        assert_eq!(destination("gzip", 0, 2047, false), Dest::TempFile);
        // 8000 + 1000 + 1024.
        assert_eq!(destination("gzip", 8000, 2 * 10_024, false), Dest::Memory);
        assert_eq!(
            destination("gzip", 8000, 2 * 10_024 - 1, false),
            Dest::TempFile
        );
        assert_eq!(
            destination("gzip", u64::MAX, u64::MAX, false),
            Dest::TempFile
        );
        // Streamed input holds no copy: the whole limit.
        assert_eq!(destination("gzip", 8000, 10_024, true), Dest::Memory);
        assert_eq!(destination("gzip", 8000, 10_023, true), Dest::TempFile);
        assert_eq!(
            destination("gzip", u64::MAX, u64::MAX, true),
            Dest::TempFile
        );
    }

    /// Streamed input whose output fits in the whole limit stays off the
    /// disk, one stream included; only output past the limit makes a temp
    /// file.
    #[test]
    fn streamed_input_compresses_to_memory_when_the_output_fits() {
        let _lock = armed_lock();
        let s = Scratch::new();
        let (a, b) = (text(16 * 1024, 1), text(16 * 1024, 2));
        let paths = vec![s.file("a", &a), s.file("b", &b)];
        // 32 KiB is over 40000 / 2, so the input is streamed. One stream's
        // worst case (32768 + 4096 + 1024 = 37888) fits under 40000, not
        // under 37887; each file's (19456) fits under either.
        let files = load_input(&paths, 40_000).unwrap().0;
        assert!(matches!(files, Input::Files(_)));
        let memory = Input::Memory(vec![a, b]);
        for (mode, limit, want_temps) in [
            (Mode::PerFile, 40_000, 0),
            (Mode::OneStream, 40_000, 0),
            (Mode::OneStream, 37_888, 0),
            (Mode::OneStream, 37_887, 1),
        ] {
            let p = Plan {
                memory_limit: limit,
                ..plan(mode, 1)
            };
            let mut got = None;
            let made = temps_made(|| got = Some(run("gzip", &files, &p)));
            assert_eq!(made, want_temps, "{mode:?} at {limit}");
            let want = run("gzip", &memory, &plan(mode, 1)).bytes_out;
            assert_eq!(got.unwrap().bytes_out, want, "{mode:?}");
        }
    }

    /// In-memory input whose output does not fit goes to the temp file too,
    /// for each codec whose own worst case is over the budget.
    #[test]
    fn memory_input_past_the_output_limit_uses_the_temp_file() {
        let _lock = armed_lock();
        let input = Input::Memory(vec![text(16 * 1024, 5)]);
        // The input fits under 32768 / 2; its worst case does not.
        let p = Plan {
            memory_limit: 32 * 1024,
            ..plan(Mode::OneStream, 1)
        };
        for codec in ["gzip", "compress"] {
            let made = temps_made(|| {
                run(codec, &input, &p);
            });
            assert_eq!(made, 1, "{codec}");
        }
    }

    /// The reserved `Vec` must not reallocate inside a timed region, even
    /// on input no codec can shrink, at any level.
    #[test]
    fn the_reserved_room_holds_incompressible_output() {
        let input = noise(64 * 1024);
        let reg = stuffr::registry();
        for name in crate::bench::levels::benchable_codecs() {
            let codec = reg.codec(stuffr::FormatId::new(name)).unwrap();
            let sweep = crate::bench::levels::levels_of(name).unwrap().sweep;
            let levels: Vec<Option<i32>> = if sweep.is_empty() {
                vec![None]
            } else {
                sweep.iter().map(|&l| Some(l)).collect()
            };
            for level in levels {
                let room = output_room(name, input.len() as u64).unwrap() as usize;
                let shared = SharedVec::with_capacity(room);
                let cap = shared.capacity();
                let dst = BufWriter::with_capacity(CHUNK, shared.clone());
                let opts = EncodeOpts {
                    level,
                    ..Default::default()
                };
                let mut sink = codec.encoder(Box::new(dst), &opts).unwrap();
                sink.write_all(&input).unwrap();
                sink.finish().unwrap();
                assert_eq!(shared.capacity(), cap, "{name} {level:?} reallocated");
                assert!(shared.take().len() <= room, "{name} {level:?}");
            }
        }
    }

    /// A log still being written: the rows bench it as it was at load.
    #[test]
    fn a_file_that_grows_after_load_is_benched_at_its_loaded_length() {
        let _lock = armed_lock();
        let s = Scratch::new();
        let original = text(40 * 1024, 3);
        let path = s.file("grow.log", &original);
        let (files, bytes_in) = load_input(std::slice::from_ref(&path), 0).unwrap();
        assert!(matches!(files, Input::Files(_)));
        assert_eq!(bytes_in, original.len() as u64);
        let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&text(10 * 1024, 9)).unwrap();
        drop(f);
        let snapshot = Input::Memory(vec![original]);
        for mode in [Mode::OneStream, Mode::PerFile] {
            let p = plan(mode, 1);
            for codec in ["gzip", "compress"] {
                // Ok: the round trip gave back exactly the loaded length.
                let grown = run(codec, &files, &p);
                assert_eq!(
                    grown.bytes_out,
                    run(codec, &snapshot, &p).bytes_out,
                    "{codec}: the appended bytes were benched"
                );
            }
        }
    }

    #[test]
    fn load_input_splits_at_half_the_memory_limit() {
        let s = Scratch::new();
        let paths = vec![s.file("a", &[1; 100]), s.file("b", &[2; 100])];
        match load_input(&paths, 400).unwrap() {
            (Input::Memory(parts), 200) => {
                assert_eq!(parts, vec![vec![1; 100], vec![2; 100]])
            }
            other => panic!("200 bytes fit in 400 / 2: {other:?}"),
        }
        assert!(matches!(
            load_input(&paths, 399).unwrap(),
            (Input::Files(_), 200)
        ));
    }

    /// Restores a file's mode, so `Scratch` can remove it.
    #[cfg(unix)]
    struct Restore(PathBuf);

    #[cfg(unix)]
    impl Drop for Restore {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o600));
        }
    }

    /// A file that cannot be opened is a usage error naming it, whether
    /// the input is loaded into memory or streamed (opened by `warm`).
    #[cfg(unix)]
    #[test]
    fn an_input_that_cannot_be_opened_is_a_usage_error_naming_it() {
        use std::os::unix::fs::PermissionsExt;
        let s = Scratch::new();
        let locked = s.file("locked.log", b"secret");
        let _restore = Restore(locked.clone());
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        // Root opens it anyway; there is nothing to test.
        if File::open(&locked).is_ok() {
            return;
        }
        let want = format!("{}: cannot read it (", locked.display());
        let usage = |r: stuffr::Result<()>| match r {
            Err(Error::Usage(m)) => m,
            other => panic!("expected a usage error, got {other:?}"),
        };
        let paths = vec![locked.clone()];
        let m = usage(load_input(&paths, 1 << 30).map(drop));
        assert!(m.starts_with(&want), "in memory: {m}");
        // Streamed: loading only reads the size; the warm-up opens it.
        let (files, _) = load_input(&paths, 0).unwrap();
        assert!(matches!(files, Input::Files(_)));
        let m = usage(warm(&files));
        assert!(m.starts_with(&want), "streamed: {m}");
    }
}
