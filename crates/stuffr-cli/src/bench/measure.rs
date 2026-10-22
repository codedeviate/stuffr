//! The timing harness for `stuffr bench`: one format at one level, run over
//! the user's input, compressed and decompressed, with only codec work
//! inside a timed region.
//!
//! A compression region holds encoder creation, `write_all` of the input
//! and `Sink::finish` (which consumes the sink, so its teardown is inside
//! too). A decompression region holds decoder creation and reading the
//! decoder to its end into a buffer whose bytes are only counted. Building
//! the destination, opening files, reading streamed input, the temp file's
//! creation and removal, and dropping the decoder are all outside.
//!
//! In memory, each region is one pair of clock reads. Streamed from disk,
//! the input's reads happen between the encoder's writes, so compression is
//! the sum of several regions (encoder creation, each chunk's `write_all`,
//! `finish`); decompression is still one region, the decoder's own reads of
//! the compressed temp file being part of decoding.
//!
//! Both destinations have the same shape: a 64 KiB `BufWriter` over a `Vec`
//! in memory, or over the temp file when streamed, so a codec that writes in
//! small pieces pays the same in either mode.
//!
//! bench ignores STUFFR_THREADS; threads come only from --threads.
//!
//! With streamed input and `--threads` above 1, a multi-threaded encoder's
//! workers keep running during the untimed input reads between regions, so
//! its compression time can be under-reported against a single-threaded
//! one. In memory there are no such gaps.

use std::fs::{self, File};
use std::io::{self, BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use stuffr::ops::{CompressOpts, resolved_budget};
use stuffr::source::{FileSource, SeekRead, Source, SourceCaps};
use stuffr::{Codec, DecodeOpts, EncodeOpts, Error, FormatKind, Governor};

use super::score::{Measured, Outcome};
use crate::compat::{CleanupGuard, create_armed};

/// The copy buffer, as `ops` uses.
const CHUNK: usize = 64 * 1024;

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
    Files(Vec<PathBuf>),
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
pub fn load_input(paths: &[PathBuf], memory_limit: u64) -> io::Result<Input> {
    let mut total = 0u64;
    for p in paths {
        total = total.saturating_add(fs::metadata(p)?.len());
    }
    if total > memory_limit / 2 {
        return Ok(Input::Files(paths.to_vec()));
    }
    let parts = paths.iter().map(fs::read).collect::<io::Result<_>>()?;
    Ok(Input::Memory(parts))
}

/// One untimed read of every file, so the first timed run does not pay for
/// a cold cache. Nothing to do for input already in memory.
pub fn warm(input: &Input) -> io::Result<()> {
    if let Input::Files(paths) = input {
        let mut buf = vec![0u8; CHUNK];
        for p in paths {
            let mut f = File::open(p)?;
            while read_some(&mut f, &mut buf)? > 0 {}
        }
    }
    Ok(())
}

/// Compresses and decompresses `input` with `codec` at `level` (`None`: the
/// encoder's own default) under `plan`. Every error, a rejected level
/// included, is a failed row; nothing panics.
pub fn measure(
    codec: &str,
    level: Option<i32>,
    input: &Input,
    plan: &Plan,
    clock: &mut dyn Clock,
) -> Outcome {
    match run(codec, level, input, plan, clock) {
        Ok(m) => Outcome::Ok(m),
        Err(e) => Outcome::Failed(e.to_string()),
    }
}

/// One file's input as the harness reads it.
#[derive(Clone, Copy)]
enum Part<'a> {
    Memory(&'a [u8]),
    File(&'a Path),
}

impl Part<'_> {
    fn len(&self) -> io::Result<u64> {
        match self {
            Part::Memory(b) => Ok(b.len() as u64),
            Part::File(p) => Ok(fs::metadata(p)?.len()),
        }
    }
}

fn run(
    name: &str,
    level: Option<i32>,
    input: &Input,
    plan: &Plan,
    clock: &mut dyn Clock,
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
        Input::Files(paths) => paths.iter().map(|p| Part::File(p)).collect(),
    };
    let groups: Vec<&[Part<'_>]> = match plan.mode {
        Mode::OneStream => vec![&parts[..]],
        Mode::PerFile => parts.chunks(1).collect(),
    };
    let temp = match input {
        Input::Memory(_) => None,
        Input::Files(_) => Some(TempOut::create()?.0),
    };

    let mut buf = vec![0u8; CHUNK];
    let mut bytes_out = None;
    let mut compress = Vec::new();
    let mut decompress = Vec::new();
    for _ in 0..plan.repeat.max(1) {
        let (mut out, mut c_ns, mut d_ns) = (0u64, 0u64, 0u64);
        for group in &groups {
            let expected = group
                .iter()
                .try_fold(0u64, |n, p| Ok::<_, io::Error>(n + p.len()?))?;
            let job = Job {
                codec: codec.as_ref(),
                encode: &encode,
                decode: &decode,
                temp: temp.as_ref(),
                buf: &mut buf,
            };
            let row = job.run(group, expected, clock)?;
            out += row.bytes_out;
            c_ns += row.compress_ns;
            d_ns += row.decompress_ns;
        }
        bytes_out.get_or_insert(out);
        compress.push(c_ns);
        decompress.push(d_ns);
    }
    Ok(Measured {
        bytes_out: bytes_out.unwrap_or(0),
        compress_ns: median(compress),
        decompress_ns: median(decompress),
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

/// Everything one stream's round trip needs.
struct Job<'a> {
    codec: &'a dyn Codec,
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
    ) -> stuffr::Result<Measured> {
        let (bytes_out, compress_ns, src) = match self.temp {
            None => {
                // Room for incompressible output, so the outer Vec does not
                // reallocate inside the region.
                let room = expected.saturating_add(expected / 8).saturating_add(1024);
                let shared = SharedVec::with_capacity(usize::try_from(room).unwrap_or(0));
                let dst = BufWriter::with_capacity(CHUNK, shared.clone());
                let ns = self.compress(group, Box::new(dst), clock)?;
                let bytes = shared.take();
                let len = bytes.len() as u64;
                (len, ns, Box::new(MemSource::new(bytes)) as Box<dyn Source>)
            }
            Some(temp) => {
                let file = File::options()
                    .write(true)
                    .truncate(true)
                    .open(temp.path())?;
                let dst = BufWriter::with_capacity(CHUNK, file);
                let ns = self.compress(group, Box::new(dst), clock)?;
                let src = FileSource::open(temp.path())?;
                (
                    src.caps().len.unwrap_or(0),
                    ns,
                    Box::new(src) as Box<dyn Source>,
                )
            }
        };
        let (decoded, decompress_ns) = decode(self.codec, self.decode, src, self.buf, clock)?;
        if decoded != expected {
            return Err(Error::Corrupt(format!(
                "the round trip gave back {decoded} bytes of {expected}"
            )));
        }
        Ok(Measured {
            bytes_out,
            compress_ns,
            decompress_ns,
        })
    }

    /// The compression regions' total. In memory: one region. Streamed: the
    /// file reads fall between regions.
    fn compress(
        &mut self,
        group: &[Part<'_>],
        dst: Box<dyn Write + Send>,
        clock: &mut dyn Clock,
    ) -> stuffr::Result<u64> {
        if let Some(bufs) = group
            .iter()
            .map(|p| match p {
                Part::Memory(b) => Some(*b),
                Part::File(_) => None,
            })
            .collect::<Option<Vec<&[u8]>>>()
        {
            let t0 = clock.now();
            let mut sink = self.codec.encoder(dst, self.encode)?;
            for b in &bufs {
                for chunk in b.chunks(CHUNK) {
                    sink.write_all(chunk)?;
                }
            }
            sink.finish()?;
            let t1 = clock.now();
            return Ok(t1.saturating_sub(t0));
        }

        let mut files = Vec::with_capacity(group.len());
        // Not in memory, so every part is a file: an input is one or the other.
        for p in group {
            if let Part::File(path) = p {
                files.push(File::open(path)?);
            }
        }
        let t0 = clock.now();
        let mut sink = self.codec.encoder(dst, self.encode)?;
        let t1 = clock.now();
        let mut ns = t1.saturating_sub(t0);
        for f in &mut files {
            loop {
                let n = read_some(f, self.buf)?;
                if n == 0 {
                    break;
                }
                let t0 = clock.now();
                sink.write_all(&self.buf[..n])?;
                let t1 = clock.now();
                ns += t1.saturating_sub(t0);
            }
        }
        let t0 = clock.now();
        sink.finish()?;
        let t1 = clock.now();
        Ok(ns + t1.saturating_sub(t0))
    }
}

/// One region: decoder creation and reading it to its end, the bytes only
/// counted. Returns the count and the region's length.
fn decode(
    codec: &dyn Codec,
    opts: &DecodeOpts,
    src: Box<dyn Source>,
    buf: &mut [u8],
    clock: &mut dyn Clock,
) -> stuffr::Result<(u64, u64)> {
    let t0 = clock.now();
    let mut decoder = codec.decoder(src, opts)?;
    let mut total = 0u64;
    loop {
        match decoder.read(buf) {
            Ok(0) => break,
            Ok(n) => total += n as u64,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Error::from_decode_io(e)),
        }
    }
    let t1 = clock.now();
    drop(decoder);
    Ok((total, t1.saturating_sub(t0)))
}

/// `read`, retried on `Interrupted`.
fn read_some(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
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

/// Compressed bytes in memory, as seekable and sized as the `FileSource`
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

/// The streamed run's compressed output, `stuffr-bench-<pid>-<n>` in the
/// temp directory: armed for removal on SIGINT, SIGTERM and SIGHUP while it
/// lives, removed when it drops (a panic included).
struct TempOut {
    path: PathBuf,
    /// Dropped after `drop` has removed the file, so there is no moment the
    /// file exists unarmed.
    _armed: CleanupGuard,
}

impl TempOut {
    fn create() -> io::Result<(Self, File)> {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir();
        let mut tries = 0;
        loop {
            let n = N.fetch_add(1, Ordering::Relaxed);
            let path = dir.join(format!("stuffr-bench-{}-{n}", std::process::id()));
            match create_armed(&path) {
                Ok((file, armed)) => {
                    return Ok((
                        Self {
                            path,
                            _armed: armed,
                        },
                        file,
                    ));
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && tries < 1000 => tries += 1,
                Err(e) => return Err(e),
            }
        }
    }

    fn path(&self) -> &Path {
        &self.path
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

    fn ok(o: Outcome) -> Measured {
        match o {
            Outcome::Ok(m) => m,
            Outcome::Failed(e) => panic!("failed: {e}"),
        }
    }

    fn run(codec: &str, input: &Input, plan: &Plan) -> Measured {
        ok(measure(codec, None, input, plan, &mut FakeClock(0)))
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
        // One compression and one decompression region per file, summed.
        assert_eq!(both.compress_ns, 20);
        assert_eq!(both.decompress_ns, 20);
    }

    /// Streamed: compression is encoder creation, one region per input
    /// chunk's `write_all` (each 64 KiB read falls between them) and
    /// `finish`; decompression is one region.
    #[test]
    fn a_streamed_run_times_each_write_and_not_the_reads() {
        let _lock = armed_lock();
        let s = Scratch::new();
        // Two chunks: 64 KiB, then 36 KiB.
        let paths = vec![s.file("a", &text(100 * 1024, 6))];
        let files = load_input(&paths, 0).unwrap();
        let mut clock = FakeClock(0);
        let m = ok(measure(
            "gzip",
            None,
            &files,
            &plan(Mode::OneStream, 1),
            &mut clock,
        ));
        let regions = 1 + 2 + 1;
        assert_eq!(m.compress_ns, 10 * regions);
        assert_eq!(m.decompress_ns, 10);
        assert_eq!(clock.0, 10 * 2 * (regions + 1), "no other clock reads");
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

    #[test]
    fn the_fake_clock_times_exactly_one_region_each() {
        let input = Input::Memory(vec![text(64 * 1024, 3)]);
        let m = run("gzip", &input, &plan(Mode::OneStream, 1));
        assert_eq!(m.compress_ns, 10);
        assert_eq!(m.decompress_ns, 10);
    }

    #[test]
    fn repeat_reports_the_median() {
        let input = Input::Memory(vec![text(4096, 1)]);
        // Regions alternate compress, decompress across the three runs.
        let mut clock = ScriptClock {
            durations: vec![30, 7, 10, 5, 20, 9],
            reads: 0,
            t: 0,
        };
        let m = ok(measure(
            "gzip",
            None,
            &input,
            &plan(Mode::OneStream, 3),
            &mut clock,
        ));
        assert_eq!(m.compress_ns, 20);
        assert_eq!(m.decompress_ns, 7);
        assert_eq!(clock.reads, 12, "two reads per region, nothing else");
    }

    #[test]
    fn an_even_repeat_reports_the_lower_median() {
        let input = Input::Memory(vec![text(4096, 1)]);
        let mut clock = ScriptClock {
            durations: vec![40, 1, 10, 2, 30, 3, 20, 4],
            reads: 0,
            t: 0,
        };
        let m = ok(measure(
            "gzip",
            None,
            &input,
            &plan(Mode::OneStream, 4),
            &mut clock,
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
        );
        assert!(matches!(o, Outcome::Failed(_)), "{o:?}");
    }

    #[test]
    fn streamed_input_matches_memory_input() {
        let _lock = armed_lock();
        let s = Scratch::new();
        let (a, b) = (text(32 * 1024, 2), text(32 * 1024, 9));
        let paths = vec![s.file("a", &a), s.file("b", &b)];
        let files = load_input(&paths, 0).unwrap();
        assert!(matches!(files, Input::Files(_)));
        warm(&files).unwrap();
        let memory = load_input(&paths, 1 << 30).unwrap();
        assert!(matches!(memory, Input::Memory(_)));
        for mode in [Mode::OneStream, Mode::PerFile] {
            let p = plan(mode, 1);
            for codec in ["gzip", "xz", "lz4"] {
                assert_eq!(
                    run(codec, &files, &p).bytes_out,
                    run(codec, &memory, &p).bytes_out,
                    "{codec}"
                );
            }
        }
    }

    #[test]
    fn the_output_temp_file_is_removed() {
        let _lock = armed_lock();
        let s = Scratch::new();
        let paths = vec![s.file("a", &text(16 * 1024, 4))];
        let files = load_input(&paths, 0).unwrap();
        run("gzip", &files, &plan(Mode::OneStream, 2));
        assert_eq!(bench_temps(), Vec::<String>::new());
    }

    #[test]
    fn the_temp_guard_removes_on_panic() {
        let _lock = armed_lock();
        let seen = std::sync::Mutex::new(None::<PathBuf>);
        let r = std::panic::catch_unwind(|| {
            let (guard, _file) = TempOut::create().unwrap();
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
        let (guard, _file) = TempOut::create().unwrap();
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
        let files = load_input(&paths, 0).unwrap();
        let memory = load_input(&paths, 1 << 30).unwrap();
        for mode in [Mode::OneStream, Mode::PerFile] {
            for codec in crate::bench::levels::benchable_codecs() {
                for input in [&files, &memory] {
                    run(codec, input, &plan(mode, 1));
                }
            }
        }
    }

    #[test]
    fn load_input_splits_at_half_the_memory_limit() {
        let s = Scratch::new();
        let paths = vec![s.file("a", &[1; 100]), s.file("b", &[2; 100])];
        match load_input(&paths, 400).unwrap() {
            Input::Memory(parts) => assert_eq!(parts, vec![vec![1; 100], vec![2; 100]]),
            Input::Files(_) => panic!("200 bytes fit in 400 / 2"),
        }
        assert!(matches!(load_input(&paths, 399).unwrap(), Input::Files(_)));
    }
}
