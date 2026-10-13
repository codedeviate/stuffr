//! fileio.c and fileio_asyncio.c: compressing, decompressing and testing
//! over files and standard streams, as zstd 1.5.7 drives libzstd.
//!
//! Ported in fileio.c's shape: [`compress_files`] is
//! `FIO_compressFilename`/`FIO_compressMultipleFilenames` (one libzstd
//! context for every file, created as `FIO_createCResources` creates it),
//! [`decompress_files`] is `FIO_decompressFilename`/
//! `FIO_decompressMultipleFilenames`, and below them the source checks, the
//! destination (`FIO_openDstFile`: the console, the overwrite prompt, the
//! same-file guard), the frame loops and the summaries. The read side
//! ([`ReadPool`]) reads as `AIO_ReadPool_fillBuffer` does, one job of
//! `ZSTD_CStreamInSize()`/`ZSTD_DStreamInSize()` bytes at a time, because
//! what libzstd is handed per call decides some of its answers (a cut-short
//! frame's "premature end" against a decoding error). The write side is
//! `AIO_fwriteSparse` with its 32 KiB segment rule.
//!
//! Where stuffr differs from fileio.c, on purpose:
//!
//! - A regular destination is written to a temporary file in its directory
//!   (`host::create_temp_armed_exit`, so SIGINT removes it, zstd's
//!   `INThandler`) and published under its name once complete; zstd writes
//!   the name itself. The tree afterwards is the same: a failure removes
//!   the output (zstd: `FIO_removeFile`), an `EXM_THROW` while writing
//!   leaves what was written (zstd exits leaving its partial file). An
//!   existing destination that is not a regular file (`/dev/null`), and the
//!   single output of `-o` with several inputs (which zstd never arms), are
//!   written in place as zstd writes them.
//! - Spec deviation 3: an input that is also the output is never lost.
//!   `FIO_openDstFile` already refuses a destination that is its source;
//!   the one output of several inputs (`-o`), which zstd opens without that
//!   check, is refused the same way when it is one of the inputs.
//! - gzip, xz, lzma and lz4 frames go through [`FrameCodec`], which
//!   `formats.rs` implements as fileio.c's `FIO_compressGzFrame`,
//!   `FIO_compressLzmaFrame`, `FIO_compressLz4Frame` and their decoding
//!   counterparts.
//! - The progress line is drawn as `DISPLAYUPDATE` draws it, once per
//!   coder call this port makes (each `ZSTD_compressStream2` call when
//!   compressing, as fileio.c's inner loop); its terminal behaviour is
//!   Task 9's.
//! - `--adapt` follows `FIO_compressZstdFrame`'s adaptive loop (R10): the
//!   frame's progression every `REFRESH_RATE`, the level one step at a
//!   time between `--adapt=min=`/`max=`.

use std::fs::{self, File, Metadata};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use stuffr::zstd_opts::{
    self, CParamKey, DecodeOptions, Decoder, EncodeOptions, Encoder, EndOp, FrameHeader, Ldm,
    ParamSwitch, ZstdError,
};

use super::cli::Prefs;
use super::cli::{CType, Command, NULMARK, Progress, STDINMARK, STDOUTMARK};
use super::display::{self, Display, exm_throw};
use super::messages::{self as m, printf};
use super::util::{self, FILESIZE_UNKNOWN, Hrs, PATH_SEP, human_size};
use crate::compat::host::{self, CleanupGuard, Host, create_temp_armed_exit, strerror};

/// An `EXM_THROW`: the message is printed, the process exits with this code
/// (not through `CLEAN_RETURN`, so `-p` does not pause).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Thrown(pub(crate) i32);

/// A fileio.c step that may `EXM_THROW`.
pub(crate) type Fio<T> = Result<T, Thrown>;

/// `ZSTD_BLOCKSIZE_MAX`.
const BLOCKSIZE_MAX: usize = zstd_opts::BLOCKSIZE_MAX;
/// `ZSTD_CStreamInSize()`.
pub(crate) const CSTREAM_IN_SIZE: usize = BLOCKSIZE_MAX;
/// `ZSTD_DStreamInSize()`: a block and its header.
pub(crate) const DSTREAM_IN_SIZE: usize = BLOCKSIZE_MAX + 3;
/// `ZSTD_DStreamOutSize()`.
pub(crate) const DSTREAM_OUT_SIZE: usize = BLOCKSIZE_MAX;
/// `ZSTD_error_parameter_unsupported`.
const PARAMETER_UNSUPPORTED: u32 = 40;
/// `ZSTD_FRAMEHEADERSIZE_MAX`.
const FRAMEHEADERSIZE_MAX: usize = 18;
/// fileio.c: `DICTSIZE_MAX`.
const DICTSIZE_MAX: u64 = 32 << 20;
/// fileio.c: `ADAPT_WINDOWLOG_DEFAULT`.
const ADAPT_WINDOWLOG_DEFAULT: u32 = 23;
/// `ZSTD_WINDOWLOG_LIMIT_DEFAULT`, the window `--long` asks for.
const WINDOWLOG_LIMIT_DEFAULT: u32 = 27;
/// fileio_common.h: `REFRESH_RATE`, a sixth of a second.
const REFRESH_RATE: Duration = Duration::from_micros(1_000_000 / 6);
/// `LZ4_MAGICNUMBER`.
const LZ4_MAGIC: u32 = 0x184D_2204;
/// The legacy frame magics a zstd built with `ZSTD_LEGACY_SUPPORT=5`
/// (v0.5 to v0.7) recognises, as the reference is built.
#[cfg(feature = "zstd-c")]
const LEGACY_MAGICS: [u32; 3] = [0xFD2F_B525, 0xFD2F_B526, 0xFD2F_B527];

// ---- the foreign formats' hook ----

/// The formats `FIO_decompressFrames` recognises by magic besides zstd's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Foreign {
    Gzip,
    Xz,
    Lzma,
    Lz4,
}

/// The per-format frame coders fileio.c calls for `--format=gzip|xz|lzma|lz4`
/// and for those magics when decompressing: `FIO_compressGzFrame`,
/// `FIO_compressLzmaFrame`, `FIO_compressLz4Frame` and their decompressing
/// counterparts. They read from the [`ReadPool`] and write through
/// [`Io::write_block`] as the zstd frame loops do.
pub(crate) trait FrameCodec {
    /// Compress the whole input as one `ctype` frame (never
    /// [`CType::Zstd`]): returns the bytes read and the bytes written.
    fn compress(
        &mut self,
        io: &mut Io<'_>,
        rp: &mut ReadPool,
        ctype: CType,
        src_name: &[u8],
        file_size: u64,
        level: i32,
    ) -> Fio<(u64, u64)>;

    /// Decode one `kind` frame: its decoded size, or `None` for
    /// `FIO_ERROR_FRAME_DECODING` (the message already said).
    fn decompress(
        &mut self,
        io: &mut Io<'_>,
        rp: &mut ReadPool,
        kind: Foreign,
        src_name: &[u8],
    ) -> Fio<Option<u64>>;
}

/// The frame coders this build has.
fn frame_codec() -> Box<dyn FrameCodec> {
    Box::new(super::formats::Formats)
}

// ---- the read pool ----

/// fileio_asyncio.c's read pool, read synchronously: the input arrives in
/// jobs of `job` bytes (each filled unless the input ends), and
/// [`ReadPool::fill`] adds one job when fewer than it was asked for are
/// loaded, as `AIO_ReadPool_fillBuffer` does.
pub(crate) struct ReadPool {
    src: Box<dyn Read>,
    buf: Vec<u8>,
    start: usize,
    eof: bool,
    job: usize,
}

impl ReadPool {
    pub(crate) fn new(src: Box<dyn Read>, job: usize) -> Self {
        ReadPool {
            src,
            buf: Vec::new(),
            start: 0,
            eof: false,
            job,
        }
    }

    /// `srcBuffer`, `srcBufferLoaded` bytes.
    pub(crate) fn loaded(&self) -> &[u8] {
        &self.buf[self.start..]
    }

    /// Puts `bytes` back in front of what is loaded: input a decoder took
    /// but its frame did not use.
    pub(crate) fn give_back(&mut self, bytes: &[u8]) {
        self.buf
            .splice(self.start..self.start, bytes.iter().copied());
    }

    /// `AIO_ReadPool_consumeBytes`.
    pub(crate) fn consume(&mut self, n: usize) {
        self.start = (self.start + n).min(self.buf.len());
    }

    /// `AIO_ReadPool_fillBuffer`: when fewer than `min(n, job)` bytes are
    /// loaded, one more job is read and appended. Returns the bytes added.
    pub(crate) fn fill(&mut self, n: usize) -> io::Result<usize> {
        let n = n.min(self.job);
        if self.loaded().len() >= n || self.eof {
            return Ok(0);
        }
        if self.start > 0 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        let before = self.buf.len();
        self.buf.resize(before + self.job, 0);
        let mut got = 0;
        while got < self.job {
            match self.src.read(&mut self.buf[before + got..]) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(k) => got += k,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    self.buf.truncate(before + got);
                    return Err(e);
                }
            }
        }
        self.buf.truncate(before + got);
        Ok(got)
    }
}

// ---- the write side ----

/// Where the write pool writes.
enum Sink {
    /// No file set (`AIO_WritePool_getFile` is NULL).
    Unset,
    /// Standard output.
    Stdout,
    /// A file.
    File(Box<FileSink>),
}

/// An open destination file.
struct FileSink {
    w: FileW,
    /// The temporary the output is written to, published as `path` at the
    /// end; `None` when written in place.
    tmp: Option<PathBuf>,
    /// The destination.
    path: PathBuf,
    /// Its name as given (for messages).
    name: Vec<u8>,
    /// The interrupt arm (`addHandler`).
    guard: Option<CleanupGuard>,
}

enum FileW {
    /// The real process's file.
    Raw(File),
    /// A sandboxed run's, charged to its output budget.
    Capped(BufWriter<Box<dyn Write + Send>>),
}

impl FileW {
    fn write_all(&mut self, b: &[u8]) -> io::Result<()> {
        match self {
            FileW::Raw(f) => f.write_all(b),
            FileW::Capped(w) => w.write_all(b),
        }
    }

    /// `LONG_SEEK(file, n, SEEK_CUR)`; a sandboxed file writes the zeros.
    fn skip(&mut self, n: u64) -> io::Result<()> {
        match self {
            FileW::Raw(f) => {
                let n =
                    i64::try_from(n).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
                f.seek(SeekFrom::Current(n)).map(drop)
            }
            FileW::Capped(w) => {
                let zeros = [0u8; 8192];
                let mut left = n;
                while left > 0 {
                    let k = left.min(zeros.len() as u64) as usize;
                    w.write_all(&zeros[..k])?;
                    left -= k as u64;
                }
                Ok(())
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            FileW::Raw(_) => Ok(()),
            FileW::Capped(w) => w.flush(),
        }
    }
}

/// The input `UTIL_requireUserConfirmation` reads its answer from.
enum Answers {
    Real,
    Bytes(io::Cursor<Vec<u8>>),
}

// ---- the context ----

/// fileio.c's state for one run: `FIO_prefs_t`, `FIO_ctx_t`,
/// `g_display_prefs`, the write pool and the process's streams.
pub(crate) struct Io<'a> {
    /// `FIO_prefs_t` (fileio.c changes a few as it goes).
    pub(crate) prefs: Prefs,
    /// `g_display_prefs.displayLevel`.
    pub(crate) d: Display,
    /// `g_utilDisplayLevel`.
    pub(crate) util_level: i32,
    pub(crate) host: &'a mut Host,
    out: &'a mut dyn Write,
    pub(crate) err: &'a mut dyn Write,
    // FIO_ctx_t
    curr_file_idx: usize,
    nb_files_processed: usize,
    total_in: u64,
    total_out: u64,
    // the write pool
    sink: Sink,
    stored_skips: u64,
    /// The clock `g_displayClock` is read from ([`Display::update`] takes
    /// its milliseconds).
    clock: Instant,
    answers: Option<Answers>,
    codec: Option<Box<dyn FrameCodec>>,
}

/// The C `printf` of `fmt` into bytes.
fn sprintf(fmt: &str, args: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    printf(&mut v, fmt, args);
    v
}

/// `%-20s`.
fn left20(name: &[u8]) -> Vec<u8> {
    let mut v = name.to_vec();
    while v.len() < 20 {
        v.push(b' ');
    }
    v
}

/// `%6.*f%s`.
fn hrs6(h: &Hrs) -> String {
    format!("{}{}", h.value_w(6), h.suffix)
}

/// `%6.*f%4s`.
fn hrs6_4(h: &Hrs) -> String {
    format!("{}{:>4}", h.value_w(6), h.suffix)
}

/// The process's CPU time so far (`clock()`), in seconds.
fn cpu_seconds() -> f64 {
    #[cfg(unix)]
    {
        // SAFETY: a zeroed rusage is a valid out-parameter; getrusage only
        // writes it.
        let ru = unsafe {
            let mut ru: libc::rusage = std::mem::zeroed();
            libc::getrusage(libc::RUSAGE_SELF, &mut ru);
            ru
        };
        let t = |tv: libc::timeval| tv.tv_sec as f64 + tv.tv_usec as f64 / 1e6;
        t(ru.ru_utime) + t(ru.ru_stime)
    }
    #[cfg(not(unix))]
    {
        0.0
    }
}

/// `0666 & ~umask`: a new file's mode when zstd creates it with
/// `DEFAULT_FILE_PERMISSIONS`.
#[cfg(unix)]
fn default_file_mode() -> u32 {
    // SAFETY: umask only swaps the process's file mode mask; it is put back
    // at once.
    let mask = unsafe {
        let mask = libc::umask(0);
        libc::umask(mask);
        mask
    };
    // `mode_t` is `u16` on Apple's platforms, `u32` on Linux.
    #[allow(clippy::useless_conversion)]
    let mask = u32::from(mask);
    0o666 & !mask
}

/// `FIO_highbit64`: the position of the highest set bit (0 for 0).
fn highbit64(v: u64) -> u32 {
    if v == 0 { 0 } else { 63 - v.leading_zeros() }
}

impl<'a> Io<'a> {
    fn new(
        cmd: &Command,
        host: &'a mut Host,
        out: &'a mut dyn Write,
        err: &'a mut dyn Write,
    ) -> Self {
        Io {
            prefs: cmd.prefs.clone(),
            d: Display::new(cmd.display_level),
            util_level: cmd.prefs.util_level,
            host,
            out,
            err,
            curr_file_idx: 0,
            nb_files_processed: 0,
            total_in: 0,
            total_out: 0,
            sink: Sink::Unset,
            stored_skips: 0,
            clock: Instant::now(),
            answers: None,
            codec: Some(frame_codec()),
        }
    }

    /// `EXM_THROW(code, fmt, args…)`.
    pub(crate) fn exm(&mut self, code: i32, fmt: &str, args: &[&[u8]]) -> Thrown {
        exm_throw(&self.d, self.err, code, &sprintf(fmt, args));
        Thrown(code)
    }

    /// `CHECK`: a libzstd error is `EXM_THROW(11, ZSTD_getErrorName)`.
    fn check(&mut self, e: ZstdError) -> Thrown {
        match e {
            // The pure tier's encoder with a dictionary or prefix (spec
            // deviation 7).
            ZstdError::Unsupported("dictionary") => self.exm(1, m::PURE_NO_DICTIONARY, &[]),
            // Anything else a backend cannot do is libzstd's own answer
            // for it, `parameter_unsupported`, through CHECK.
            ZstdError::Unsupported(_) => {
                let name = zstd_opts::error_name(PARAMETER_UNSUPPORTED);
                self.exm(11, m::ERROR_NAME, &[name.as_bytes()])
            }
            e => {
                let name = e.to_string();
                self.exm(11, m::ERROR_NAME, &[name.as_bytes()])
            }
        }
    }

    /// `DISPLAYLEVEL(l, …)`.
    fn say(&mut self, l: i32, fmt: &str, args: &[&[u8]]) {
        self.d.at(l, self.err, fmt, args);
    }

    pub(crate) fn human(&self, size: u64) -> Hrs {
        human_size(size, self.util_level)
    }

    // ---- display (fileio_common.h) ----

    /// `SHOULD_DISPLAY_SUMMARY()`.
    fn should_display_summary(&self) -> bool {
        self.d.level >= 2 || self.prefs.progress == Progress::Always
    }

    /// `SHOULD_DISPLAY_PROGRESS()`.
    fn should_display_progress(&self) -> bool {
        self.prefs.progress != Progress::Never && self.should_display_summary()
    }

    /// `DISPLAY_PROGRESS(…)`.
    fn display_progress(&mut self, fmt: &str, args: &[&[u8]]) {
        if self.should_display_progress() {
            self.say(1, fmt, args);
        }
    }

    /// `DISPLAY_SUMMARY(…)`.
    fn display_summary(&mut self, fmt: &str, args: &[&[u8]]) {
        if self.should_display_summary() {
            self.say(1, fmt, args);
        }
    }

    /// `DISPLAY_PROGRESS("\r%79s\r", "")`.
    fn clear_progress(&mut self) {
        let blank = " ".repeat(79);
        self.display_progress(m::CLEAR_LINE, &[blank.as_bytes()]);
    }

    /// The injected clock's reading, in milliseconds.
    fn now_ms(&self) -> u64 {
        self.clock.elapsed().as_millis() as u64
    }

    /// `READY_FOR_UPDATE()`.
    fn ready_for_update(&self) -> bool {
        self.d.ready_for_update(self.now_ms())
    }

    /// `DISPLAY_PROGRESS` of a whole line already rendered (a refresh is
    /// several `DISPLAY_PROGRESS` calls under one condition).
    fn display_progress_line(&mut self, line: &[u8]) {
        if self.should_display_progress() && self.d.level >= 1 {
            let _ = self.err.write_all(line);
        }
    }

    /// `DISPLAYUPDATE_PROGRESS(…)`.
    pub(crate) fn display_update_progress(&mut self, fmt: &str, args: &[&[u8]]) {
        if self.should_display_progress() && self.prefs.progress != Progress::Never {
            let now = self.now_ms();
            self.d.update(now, self.err, |w| printf(w, fmt, args));
        }
    }

    /// `DISPLAYUPDATE_PROGRESS` of a line rendered by `display.rs`.
    fn display_update_line(&mut self, line: &[u8]) {
        if self.should_display_progress() && self.prefs.progress != Progress::Never {
            let now = self.now_ms();
            self.d.update(now, self.err, |w| {
                let _ = w.write_all(line);
            });
        }
    }

    /// `FIO_shouldDisplayFileSummary`.
    fn should_display_file_summary(&self) -> bool {
        self.prefs.nb_files_total <= 1 || self.d.level >= 3
    }

    /// `FIO_shouldDisplayMultipleFileSummary`.
    fn should_display_multiple_file_summary(&self) -> bool {
        self.nb_files_processed >= 1 && self.prefs.nb_files_total > 1
    }

    // ---- reading ----

    /// `AIO_ReadPool_fillBuffer`, a read failure being `EXM_THROW(37)`.
    pub(crate) fn fill(&mut self, rp: &mut ReadPool, n: usize) -> Fio<usize> {
        rp.fill(n).map_err(|_| self.exm(37, m::READ_ERROR, &[]))
    }

    /// `getchar()` on standard input, for `UTIL_requireUserConfirmation`.
    fn getchar(&mut self) -> Option<u8> {
        if self.answers.is_none() {
            self.answers = Some(match self.host {
                Host::Real => Answers::Real,
                Host::Sandbox(s) => {
                    Answers::Bytes(io::Cursor::new(s.stdin.take().unwrap_or_default()))
                }
            });
        }
        let mut b = [0u8; 1];
        let n = match self.answers.as_mut().expect("set above") {
            Answers::Real => io::stdin().lock().read(&mut b),
            Answers::Bytes(c) => c.read(&mut b),
        };
        matches!(n, Ok(1)).then_some(b[0])
    }

    /// `UTIL_requireUserConfirmation`: 0 to proceed, 1 to abort.
    fn require_confirmation(&mut self, prompt: &str, abort: &str) -> bool {
        if self.prefs.has_stdin_input {
            printf(self.err, m::STDIN_IS_AN_INPUT, &[]);
            return true;
        }
        printf(self.err, prompt, &[]);
        let mut ch = self.getchar();
        // `strchr("yY", ch)`: EOF is not found; a NUL finds the terminator.
        let aborted = !matches!(ch, Some(b'y' | b'Y' | 0));
        if aborted {
            printf(self.err, m::CONFIRM_ABORT, &[abort.as_bytes()]);
        }
        while let Some(c) = ch {
            if c == b'\n' {
                break;
            }
            ch = self.getchar();
        }
        aborted
    }

    // ---- writing (fileio_asyncio.c) ----

    /// The current sink's raw write.
    fn raw_write(&mut self, b: &[u8]) -> io::Result<()> {
        match &mut self.sink {
            Sink::Unset => Ok(()),
            Sink::Stdout => self.out.write_all(b),
            Sink::File(f) => f.w.write_all(b),
        }
    }

    /// `LONG_SEEK(file, n, SEEK_CUR)` on the current sink.
    fn skip(&mut self, n: u64) -> io::Result<()> {
        match &mut self.sink {
            Sink::Unset => Ok(()),
            Sink::File(f) => f.w.skip(n),
            Sink::Stdout => {
                #[cfg(unix)]
                if matches!(self.host, Host::Real) {
                    self.out.flush()?;
                    let n = libc::off_t::try_from(n)
                        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
                    // SAFETY: lseek on the process's standard output only
                    // moves its offset.
                    if unsafe { libc::lseek(1, n, libc::SEEK_CUR) } < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    return Ok(());
                }
                // A sandbox's standard output is a pipe.
                Err(io::Error::from(io::ErrorKind::Unsupported))
            }
        }
    }

    /// `AIO_fwriteSparse` (through the write pool): a block of decoded or
    /// compressed bytes. In test mode nothing is written (a sandbox charges
    /// its budget); without sparse support the bytes are written as they
    /// are; with it, each 32 KiB segment's leading zero words become a skip.
    pub(crate) fn write_block(&mut self, buf: &[u8]) -> Fio<()> {
        if self.prefs.test_mode {
            return self
                .host
                .charge(buf.len() as u64)
                .map_err(|e| self.exm(70, m::WRITE_BLOCK_FAILED, &[&strerror(&e)]));
        }
        if self.prefs.sparse == 0 {
            return self
                .raw_write(buf)
                .map_err(|e| self.exm(70, m::WRITE_BLOCK_FAILED, &[&strerror(&e)]));
        }
        const WORD: usize = std::mem::size_of::<usize>();
        const SEGMENT_WORDS: usize = (32 << 10) / WORD;
        const GB: u64 = 1 << 30;
        if self.stored_skips > GB {
            if self.skip(GB).is_err() {
                return Err(self.exm(91, m::SKIP_1GB_FAILED, &[]));
            }
            self.stored_skips -= GB;
        }
        let words = buf.len() / WORD;
        let word_at = |i: usize| &buf[i * WORD..(i + 1) * WORD];
        let mut at = 0;
        while at < words {
            let seg = SEGMENT_WORDS.min(words - at);
            let nb0 = (at..at + seg)
                .take_while(|&i| word_at(i).iter().all(|&b| b == 0))
                .count();
            self.stored_skips += (nb0 * WORD) as u64;
            if nb0 != seg {
                if self.skip(self.stored_skips).is_err() {
                    return Err(self.exm(92, m::SPARSE_SKIP_FAILED, &[]));
                }
                self.stored_skips = 0;
                let rest = &buf[(at + nb0) * WORD..(at + seg) * WORD];
                if let Err(e) = self.raw_write(rest) {
                    return Err(self.exm(93, m::SPARSE_WRITE_FAILED, &[&strerror(&e)]));
                }
            }
            at += seg;
        }
        let tail = &buf[words * WORD..];
        if !tail.is_empty() {
            let zeros = tail.iter().take_while(|&&b| b == 0).count();
            self.stored_skips += zeros as u64;
            if zeros != tail.len() {
                if self.skip(self.stored_skips).is_err() {
                    return Err(self.exm(92, m::SPARSE_SKIP_FAILED, &[]));
                }
                if let Err(e) = self.raw_write(&tail[zeros..]) {
                    return Err(self.exm(95, m::SPARSE_END_WRITE_FAILED, &[&strerror(&e)]));
                }
                self.stored_skips = 0;
            }
        }
        Ok(())
    }

    /// `AIO_WritePool_sparseWriteEnd`: a pending skip ends with an explicit
    /// last zero.
    pub(crate) fn sparse_end(&mut self) -> Fio<()> {
        if self.stored_skips > 0 {
            let n = self.stored_skips;
            self.stored_skips = 0;
            if self.skip(n - 1).is_err() {
                return Err(self.exm(69, m::FINAL_SKIP_FAILED, &[]));
            }
            if let Err(e) = self.raw_write(&[0]) {
                return Err(self.exm(69, m::LAST_ZERO_FAILED, &[&strerror(&e)]));
            }
        }
        Ok(())
    }

    /// `AIO_WritePool_closeFile`: the last skip, then the close (a flush for
    /// standard output). The sink becomes unset; a file's sink is returned
    /// for publishing.
    ///
    /// The last skip's `EXM_THROW(69)` ends the run as zstd's `exit(69)`
    /// does, the output left as written ([`Io::abandon_sink`]). Every frame
    /// loop ends its own skip, so nothing is pending here in practice.
    fn close_sink(&mut self) -> Fio<(io::Result<()>, Option<Box<FileSink>>)> {
        if let Err(t) = self.sparse_end() {
            self.abandon_sink();
            return Err(t);
        }
        let sink = std::mem::replace(&mut self.sink, Sink::Unset);
        Ok(match sink {
            Sink::Unset => (Ok(()), None),
            Sink::Stdout => (self.out.flush(), None),
            Sink::File(mut f) => (f.w.flush(), Some(f)),
        })
    }

    /// An `EXM_THROW` while a destination is open: zstd exits leaving the
    /// file as written, so the temporary is published as it stands.
    fn abandon_sink(&mut self) {
        let sink = std::mem::replace(&mut self.sink, Sink::Unset);
        match sink {
            Sink::File(mut f) => {
                let _ = f.w.flush();
                drop(f.guard.take());
                if let Some(tmp) = f.tmp.take() {
                    let _ = fs::rename(&tmp, &f.path);
                }
            }
            Sink::Stdout => {
                let _ = self.out.flush();
            }
            Sink::Unset => {}
        }
    }

    // ---- files ----

    /// `FIO_removeFile`: a name that cannot be stat'ed, or is not a regular
    /// file, is said and left (and counts as removed).
    fn remove_file(&mut self, name: &[u8]) -> io::Result<()> {
        let meta = match util::stat(self.host, name) {
            Ok(m) => m,
            Err(_) => {
                self.say(2, m::REMOVE_STAT_FAILED, &[name]);
                return Ok(());
            }
        };
        if !meta.is_file() {
            self.say(2, m::REMOVE_NOT_REGULAR, &[name]);
            return Ok(());
        }
        fs::remove_file(self.host.path(name))
    }

    /// `FIO_openSrcFile`: the input as a [`ReadPool`] of `job`-byte reads,
    /// and its metadata (`None` for standard input); `None` when refused.
    fn open_src(&mut self, name: &[u8], job: usize) -> Option<(ReadPool, Option<Metadata>)> {
        if name == STDINMARK {
            self.say(4, m::USING_STDIN, &[]);
            let input = self.host.stdin();
            return Some((ReadPool::new(Box::new(input), job), None));
        }
        let meta = match util::stat(self.host, name) {
            Ok(m) => m,
            Err(e) => {
                self.say(1, m::CANT_STAT, &[name, &strerror(&e)]);
                return None;
            }
        };
        let accepted = meta.is_file()
            || util::is_fifo_stat(&meta)
            || (self.prefs.allow_block_devices && util::is_block_dev_stat(&meta));
        if !accepted {
            self.say(1, m::NOT_REGULAR, &[name]);
            return None;
        }
        let path = self.host.path(name);
        match File::open(&path) {
            Ok(f) => {
                let f = self.host.track(&path, f);
                Some((ReadPool::new(Box::new(f), job), Some(meta)))
            }
            Err(e) => {
                self.say(1, m::NAME_ERRNO, &[name, &strerror(&e)]);
                None
            }
        }
    }

    /// `FIO_openDstFile`: the destination set as the sink, or false when
    /// refused (said). `src` is the input, for the same-file guard; a
    /// `transfer` destination is created `0600` (its input's mode follows),
    /// any other with `0666` less the umask. `in_place` writes the name
    /// itself, as zstd does for the one output of several inputs.
    fn open_dst(
        &mut self,
        src: Option<&[u8]>,
        dst: &[u8],
        transfer: bool,
        in_place: bool,
    ) -> Fio<bool> {
        if self.prefs.test_mode {
            return Ok(false);
        }
        if dst == STDOUTMARK {
            self.say(4, m::USING_STDOUT, &[]);
            if self.prefs.sparse == 1 {
                self.prefs.sparse = 0;
                self.say(4, m::SPARSE_OFF_STDOUT, &[]);
            }
            self.sink = Sink::Stdout;
            return Ok(true);
        }
        if let Some(src) = src
            && util::is_same_file(self.host, src, dst)
        {
            self.say(1, m::REFUSING_OVERWRITE_INPUT, &[]);
            return Ok(false);
        }
        let is_reg = util::is_regular_file(self.host, dst);
        if self.prefs.sparse == 1 {
            self.prefs.sparse = super::cli::SPARSE_DEFAULT;
            if !is_reg {
                self.prefs.sparse = 0;
                self.say(4, m::SPARSE_OFF_NOT_FILE, &[]);
            }
        }
        if is_reg {
            if cfg!(not(windows)) && dst == NULMARK {
                return Err(self.exm(40, m::NUL_IS_REGULAR, &[dst]));
            }
            if !self.prefs.overwrite {
                if self.d.level <= 1 {
                    self.say(1, m::NOT_OVERWRITTEN, &[dst]);
                    return Ok(false);
                }
                printf(self.err, m::ALREADY_EXISTS, &[dst]);
                if self.require_confirmation(m::OVERWRITE_PROMPT, m::OVERWRITE_ABORT) {
                    return Ok(false);
                }
            }
            let _ = self.remove_file(dst);
        }
        let path = self.host.path(dst);
        let sandboxed = matches!(self.host, Host::Sandbox(_));
        // The modes below are unix's; elsewhere the defaults stand.
        #[cfg(not(unix))]
        let _ = transfer;
        // Anything still at the name (a device, a directory, a link to
        // nowhere) is opened as zstd opens it, in place.
        let in_place = in_place || fs::symlink_metadata(&path).is_ok();
        let (file, tmp, guard) = if in_place {
            let mut o = File::options();
            o.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(if transfer { 0o600 } else { 0o666 });
            }
            match o.open(&path) {
                Ok(f) => (f, None, None),
                Err(e) => {
                    self.say(1, m::OPEN_DST_FAILED, &[dst, &strerror(&e)]);
                    return Ok(false);
                }
            }
        } else {
            let dir = match path.parent() {
                Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
                _ => PathBuf::from("."),
            };
            match create_temp_armed_exit(&dir, "zstd", self.host) {
                Ok((tmp, f, g)) => {
                    #[cfg(unix)]
                    if !transfer {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = f.set_permissions(fs::Permissions::from_mode(default_file_mode()));
                    }
                    (f, Some(tmp), Some(g))
                }
                Err(e) => {
                    self.say(1, m::OPEN_DST_FAILED, &[dst, &strerror(&e)]);
                    return Ok(false);
                }
            }
        };
        let w = if sandboxed {
            FileW::Capped(self.host.out_writer(Some(file)))
        } else {
            FileW::Raw(file)
        };
        self.sink = Sink::File(Box::new(FileSink {
            w,
            tmp,
            path,
            name: dst.to_vec(),
            guard,
        }));
        Ok(true)
    }

    /// `addHandler(dstFileName)` for a destination opened in place: armed
    /// only when it is a regular file.
    fn arm_in_place(&mut self) {
        if let Sink::File(f) = &mut self.sink
            && f.tmp.is_none()
            && f.guard.is_none()
        {
            f.guard = Some(host::arm_cleanup_exit(self.host, &f.path));
        }
    }

    /// The end of `FIO_compressFilename_dstFile`/`FIO_decompressDstFile`:
    /// `clearHandler`, the input's owner and mode, the close, its times,
    /// and on failure the output removed; on success the temporary
    /// published. A temporary stays armed until it is published or removed
    /// (zstd's file is complete once it clears its handler; the temporary
    /// is not, until it has its name); one written in place is disarmed
    /// first, as zstd disarms.
    fn release_dst(
        &mut self,
        transfer: Option<&Metadata>,
        mut result: i32,
        trace_close: bool,
    ) -> Fio<i32> {
        let mut guard = None;
        if let Sink::File(f) = &mut self.sink {
            guard = f.guard.take();
            if f.tmp.is_none() {
                drop(guard.take());
            }
            if let (Some(meta), FileW::Raw(file)) = (transfer, &f.w) {
                set_fd_stat(file, meta);
            }
        }
        let name = match &self.sink {
            Sink::File(f) => f.name.clone(),
            _ => STDOUTMARK.to_vec(),
        };
        if trace_close {
            self.say(6, m::CLOSING_DST, &[&name]);
        }
        let (closed, file) = self.close_sink()?;
        if let Err(e) = closed {
            self.say(1, m::NAME_ERRNO, &[&name, &strerror(&e)]);
            result = 1;
        }
        let Some(f) = file else {
            return Ok(result);
        };
        let target = f.tmp.clone().unwrap_or_else(|| f.path.clone());
        if let Some(meta) = transfer {
            set_times(&target, meta);
        }
        if result != 0 {
            match &f.tmp {
                Some(tmp) => {
                    let _ = fs::remove_file(tmp);
                }
                None => {
                    let _ = self.remove_file(&name);
                }
            }
            return Ok(result);
        }
        if let Some(tmp) = &f.tmp
            && let Err(e) = host::publish(tmp, &f.path, true)
        {
            let _ = fs::remove_file(tmp);
            drop(guard);
            self.say(1, m::NAME_ERRNO, &[&name, &strerror(&e)]);
            return Ok(1);
        }
        drop(guard);
        Ok(result)
    }

    /// `FIO_multiFilesConcatWarning`: true to abort.
    fn multi_files_concat_warning(&mut self, out_name: &[u8], cutoff: i32) -> Fio<bool> {
        if self.prefs.has_stdout_output && self.prefs.remove_src {
            return Err(self.exm(43, m::RM_TO_STDOUT, &[]));
        }
        if self.prefs.test_mode {
            if self.prefs.remove_src {
                return Err(self.exm(43, m::RM_IN_TEST, &[]));
            }
            return Ok(false);
        }
        if self.prefs.nb_files_total == 1 {
            return Ok(false);
        }
        if self.prefs.has_stdout_output {
            self.say(2, m::CONCAT_STDOUT, &[]);
        } else {
            self.say(2, m::CONCAT_FILE, &[out_name]);
        }
        self.say(2, m::CONCAT_NO_NAMES, &[]);
        if self.prefs.remove_src {
            self.say(2, m::CONCAT_NOT_REMOVED, &[]);
            self.prefs.remove_src = false;
        }
        if self.prefs.has_stdout_output || self.prefs.overwrite {
            return Ok(false);
        }
        if self.d.level <= cutoff {
            self.say(1, m::CONCAT_LOSES_METADATA, &[]);
            self.say(1, m::CONCAT_ABORTING, &[]);
            return Ok(true);
        }
        Ok(self.require_confirmation(m::PROCEED_PROMPT, m::PROCEED_ABORT))
    }

    /// Spec deviation 3 for the one output of several inputs: true (said
    /// as `FIO_openDstFile`'s same-file refusal) when `out` is one of them.
    fn output_is_an_input(&mut self, out: &[u8], inputs: &[Vec<u8>]) -> bool {
        if out == STDOUTMARK {
            return false;
        }
        let Ok(o) = util::stat(self.host, out) else {
            return false;
        };
        let hit = inputs.iter().any(|i| {
            i != STDINMARK
                && util::stat(self.host, i).is_ok_and(|s| util::is_same_file_stat(i, out, &s, &o))
        });
        if hit {
            self.say(1, m::REFUSING_OVERWRITE_INPUT, &[]);
        }
        hit
    }

    /// `FIO_checkFilenameCollisions`.
    fn check_filename_collisions(&mut self, names: &[Vec<u8>]) {
        let mut base: Vec<&[u8]> = names
            .iter()
            .map(|n| match n.iter().rposition(|&b| b == PATH_SEP) {
                Some(at) => &n[at + 1..],
                None => &n[..],
            })
            .collect();
        base.sort();
        for w in base.windows(2) {
            if w[0] == w[1] {
                let n = w[0].to_vec();
                self.say(2, m::SAME_FILENAME, &[&n]);
            }
        }
    }

    // ---- dictionaries ----

    /// `FIO_getDictFileStat`.
    fn dict_stat(&mut self, name: Option<&[u8]>) -> Fio<Option<Metadata>> {
        let Some(name) = name else { return Ok(None) };
        match util::stat(self.host, name) {
            Err(e) => Err(self.exm(31, m::DICT_STAT_FAILED, &[name, &strerror(&e)])),
            Ok(meta) if !meta.is_file() => Err(self.exm(32, m::DICT_NOT_REGULAR, &[name])),
            Ok(meta) => Ok(Some(meta)),
        }
    }

    /// `FIO_setDictBufferMalloc`: the dictionary's bytes.
    fn load_dict(&mut self, name: Option<&[u8]>, meta: Option<&Metadata>) -> Fio<Option<Vec<u8>>> {
        let (Some(name), Some(meta)) = (name, meta) else {
            return Ok(None);
        };
        self.say(4, m::LOADING_DICT, &[name]);
        // Counted under the sandbox (`Host::track`): the fuzz target's read
        // bound allows the dictionary or prefix one read.
        let path = self.host.path(name);
        let mut f = match File::open(&path) {
            Ok(f) => self.host.track(&path, f),
            Err(e) => return Err(self.exm(33, m::DICT_OPEN_FAILED, &[name, &strerror(&e)])),
        };
        let size = util::file_size_stat(meta);
        let max = if self.prefs.patch_from_mode {
            u64::from(self.prefs.memory_limit)
        } else {
            DICTSIZE_MAX
        };
        if size > max {
            let max = (max as u32).to_string();
            return Err(self.exm(34, m::DICT_TOO_LARGE, &[name, max.as_bytes()]));
        }
        let mut buf = vec![0u8; size as usize];
        let mut got = 0;
        while got < buf.len() {
            match f.read(&mut buf[got..]) {
                Ok(0) => break,
                Ok(k) => got += k,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(self.exm(35, m::DICT_READ_FAILED, &[name, &strerror(&e)])),
            }
        }
        if got != buf.len() {
            let e = io::Error::from_raw_os_error(0);
            return Err(self.exm(35, m::DICT_READ_FAILED, &[name, &strerror(&e)]));
        }
        Ok(Some(buf))
    }

    /// `FIO_adjustMemLimitForPatchFromMode`.
    fn adjust_mem_limit_for_patch_from(&mut self, dict_size: u64, max_src: u64) -> Fio<()> {
        let max_size = u64::from(self.prefs.memory_limit).max(dict_size.max(max_src));
        if max_size == FILESIZE_UNKNOWN {
            return Err(self.exm(42, m::PATCH_FROM_STDIN, &[]));
        }
        let max_window = 1u64 << zstd_opts::WINDOWLOG_MAX;
        if max_size > max_window {
            let gb = (max_window >> 30).to_string();
            return Err(self.exm(42, m::PATCH_FROM_TOO_LARGE, &[gb.as_bytes()]));
        }
        self.prefs.memory_limit = max_size as u32;
        Ok(())
    }
}

/// `UTIL_setFDStat`: group, then permissions (`& 0777`), then owner; every
/// failure ignored.
fn set_fd_stat(file: &File, meta: &Metadata) {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if !file.metadata().is_ok_and(|m| m.is_file()) {
            return;
        }
        let fd = file.as_raw_fd();
        // SAFETY: fchown on a descriptor this file owns; -1 leaves that id.
        unsafe { libc::fchown(fd, u32::MAX, meta.gid()) };
        let _ = file.set_permissions(fs::Permissions::from_mode(meta.mode() & 0o777));
        // SAFETY: as above.
        unsafe { libc::fchown(fd, meta.uid(), u32::MAX) };
    }
    #[cfg(not(unix))]
    {
        let _ = file.set_permissions(meta.permissions());
    }
}

/// `UTIL_utime`, by path as util.c does it (a destination already given
/// the input's mode, read-only included, is not opened again): the access
/// time now, the modification time the input's. Where
/// `PLATFORM_POSIX_VERSION` is 200809L (Linux, the BSDs), util.c uses
/// `utimensat` with `UTIME_NOW` and `st_mtim`; on Apple's platforms
/// (200112L) `utime`, whole seconds: `time(NULL)` and `st_mtime`. Failures
/// are ignored, as zstd ignores them.
fn set_times(path: &Path, meta: &Metadata) {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;
        let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return;
        };
        #[cfg(target_vendor = "apple")]
        {
            let buf = libc::utimbuf {
                // SAFETY: time with a null pointer only returns the time.
                actime: unsafe { libc::time(std::ptr::null_mut()) },
                modtime: meta.mtime() as libc::time_t,
            };
            // SAFETY: `c` is a NUL-terminated path and `buf` a valid
            // utimbuf; utime only reads them.
            unsafe { libc::utime(c.as_ptr(), &buf) };
        }
        #[cfg(not(target_vendor = "apple"))]
        {
            let times = [
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_NOW,
                },
                libc::timespec {
                    tv_sec: meta.mtime() as libc::time_t,
                    tv_nsec: meta.mtime_nsec() as _,
                },
            ];
            // SAFETY: `c` is a NUL-terminated path and `times` two valid
            // timespecs; utimensat only reads them.
            unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) };
        }
    }
    #[cfg(not(unix))]
    {
        let mut times = fs::FileTimes::new().set_accessed(std::time::SystemTime::now());
        if let Ok(t) = meta.modified() {
            times = times.set_modified(t);
        }
        if let Ok(f) = File::options().write(true).open(path) {
            let _ = f.set_times(times);
        }
    }
}

/// `FIO_createFilename_fromOutDir`: `dir`, a separator unless it ends with
/// one, and `path`'s last component.
fn filename_from_out_dir(path: &[u8], dir: &[u8]) -> Vec<u8> {
    let mut start = match path.iter().rposition(|&b| b == PATH_SEP) {
        Some(at) => &path[at + 1..],
        None => path,
    };
    if cfg!(windows)
        && let Some(at) = start.iter().rposition(|&b| b == b'/')
    {
        start = &start[at + 1..];
    }
    let mut v = dir.to_vec();
    if dir.last() != Some(&PATH_SEP) {
        v.push(PATH_SEP);
    }
    v.extend_from_slice(start);
    v
}

/// `FIO_determineCompressedName`.
fn compressed_name(src: &[u8], out_dir: Option<&[u8]>, suffix: &str) -> Vec<u8> {
    if src == STDINMARK {
        return STDOUTMARK.to_vec();
    }
    let mut v = match out_dir {
        Some(d) => filename_from_out_dir(src, d),
        None => src.to_vec(),
    };
    v.extend_from_slice(suffix.as_bytes());
    v
}

// ---- compression ----

/// `cRess_t`: the one context every file is compressed with.
struct CRess {
    enc: Encoder,
    dict_name: Option<Vec<u8>>,
    dict_meta: Option<Metadata>,
    /// `comprParams.windowLog` as set (0: the level's).
    window_log: u32,
    level: i32,
}

/// `FIO_compressZstdFrame`'s `speedChange_e`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Speed {
    NoChange,
    Slower,
    Faster,
}

/// `FIO_compressZstdFrame`'s adaptive-mode statistics, one set per frame.
struct Adapt {
    previous_update: zstd_opts::Progress,
    previous_correction: zstd_opts::Progress,
    speed: Speed,
    flush_waiting: bool,
    input_presented: u32,
    input_blocked: u32,
    last_job_id: u32,
    last_time: Instant,
}

impl Adapt {
    fn new() -> Self {
        Adapt {
            previous_update: zstd_opts::Progress::default(),
            previous_correction: zstd_opts::Progress::default(),
            speed: Speed::NoChange,
            flush_waiting: false,
            input_presented: 0,
            input_blocked: 0,
            last_job_id: 0,
            last_time: Instant::now(),
        }
    }
}

/// libzstd 1.5.7's `ZSTD_CCtxParams_setParameter` range checks for the
/// parameters `FIO_createCResources` sets before the worker count, in that
/// order: `Err` for the first out of bound (`parameter_outOfBound`). The C
/// tier would answer the same from libzstd; checking here keeps the pure
/// tier, which ignores the values, answering as the reference does.
fn check_cparam_bounds(o: &EncodeOptions) -> Result<(), ZstdError> {
    let oob = || Err(ZstdError::lib(zstd_opts::code::PARAMETER_OUT_OF_BOUND));
    let within = |v: i64, lo: i64, hi: i64| (lo..=hi).contains(&v);
    let tcb = i64::from(o.target_cblock_size as i32);
    if tcb != 0 && !within(tcb.max(1340), 1340, 1 << 17) {
        return oob();
    }
    let l = o.ldm_params;
    let nz = |v: u32, lo: i64, hi: i64| {
        let v = i64::from(v as i32);
        v == 0 || within(v, lo, hi)
    };
    if !(nz(l.hash_log, 6, 30)
        && nz(l.min_match, 4, 4096)
        && nz(l.bucket_size_log, 1, 8)
        && nz(l.hash_rate_log, 0, 25))
    {
        return oob();
    }
    let cp = |k| o.cparam(k);
    if !(nz(cp(CParamKey::WindowLog), 10, 31)
        && nz(cp(CParamKey::ChainLog), 6, 30)
        && nz(cp(CParamKey::HashLog), 6, 30)
        && nz(cp(CParamKey::SearchLog), 1, 30)
        && nz(cp(CParamKey::MinMatch), 3, 7)
        && within(i64::from(cp(CParamKey::TargetLength) as i32), 0, 1 << 17)
        && nz(cp(CParamKey::Strategy), 1, 9))
    {
        return oob();
    }
    Ok(())
}

impl Io<'_> {
    /// `FIO_adjustParamsForPatchFromMode`.
    fn adjust_params_for_patch_from(
        &mut self,
        window_log: &mut u32,
        dict_size: u64,
        max_src: u64,
        level: i32,
    ) -> Fio<()> {
        let file_window_log = highbit64(max_src) + 1;
        let cparams = zstd_opts::default_cparams(
            level,
            (max_src != FILESIZE_UNKNOWN).then_some(max_src),
            dict_size as usize,
        );
        self.adjust_mem_limit_for_patch_from(dict_size, max_src)?;
        if file_window_log > zstd_opts::WINDOWLOG_MAX {
            self.say(1, m::MAX_WINDOW_LOG_EXCEEDED, &[]);
        }
        *window_log = file_window_log.clamp(10, zstd_opts::WINDOWLOG_MAX);
        let bt_scale = u32::from(cparams.strategy >= zstd_opts::Strategy::Btlazy2);
        if file_window_log > cparams.chain_log.saturating_sub(bt_scale) {
            if !self.prefs.ldm {
                self.say(2, m::LONG_MODE_TRIGGERED, &[]);
            }
            self.prefs.ldm = true;
        }
        if cparams.strategy >= zstd_opts::Strategy::Btopt {
            self.say(4, m::OPTIMAL_PARSER_NOTES, &[b"30", b"30", b"0"]);
        }
        Ok(())
    }

    /// `FIO_createCResources`.
    fn create_cresources(&mut self, cmd: &Command, max_src: u64, level: i32) -> Fio<CRess> {
        self.say(6, m::CREATE_CRESOURCES, &[]);
        let dict_name = cmd.dict_file.clone();
        let dict_meta = self.dict_stat(dict_name.as_deref())?;
        let mut window_log = cmd.cparam(CParamKey::WindowLog);
        if self.prefs.patch_from_mode {
            let dict_size = dict_meta
                .as_ref()
                .map_or(FILESIZE_UNKNOWN, util::file_size_stat);
            let ss = self.prefs.stream_size;
            self.adjust_params_for_patch_from(
                &mut window_log,
                dict_size,
                if ss > 0 { ss } else { max_src },
                level,
            )?;
        }
        let dict = self.load_dict(dict_name.as_deref(), dict_meta.as_ref())?;
        if self.prefs.adapt && !self.prefs.ldm && window_log == 0 {
            window_log = ADAPT_WINDOWLOG_DEFAULT;
        }
        let p = &self.prefs;
        let mut overrides: Vec<(CParamKey, u32)> = cmd
            .cparams_overrides
            .iter()
            .copied()
            .filter(|(k, _)| *k != CParamKey::WindowLog)
            .collect();
        if window_log != 0 {
            overrides.push((CParamKey::WindowLog, window_log));
        }
        let (dictionary, prefix) = if p.patch_from_mode {
            (None, dict)
        } else {
            (dict, None)
        };
        let opts = EncodeOptions {
            level,
            overrides,
            checksum: p.checksum != 0,
            content_size: p.content_size,
            dict_id: p.dict_id,
            workers: p.workers as u32,
            job_size: p.job_size as i32 as u32,
            overlap_log: p.overlap_log.map(|v| v as i32),
            rsyncable: p.rsyncable,
            target_cblock_size: p.target_cblock_size as u32,
            src_size_hint: Some(p.size_hint as u64),
            pledged_size: None,
            ldm: if p.ldm {
                ParamSwitch::Enable
            } else {
                ParamSwitch::Auto
            },
            ldm_params: Ldm {
                hash_log: p.ldm_hash_log,
                min_match: p.ldm_min_match,
                bucket_size_log: p.ldm_bucket_size_log.unwrap_or(0),
                hash_rate_log: p.ldm_hash_rate_log.unwrap_or(0),
            },
            row_match_finder: p.row_match_finder,
            literal_compression: p.literal_compression,
            dictionary,
            prefix,
        };
        if let Err(e) = check_cparam_bounds(&opts) {
            return Err(self.check(e));
        }
        let workers = self.prefs.workers.to_string();
        self.say(5, m::SET_NB_WORKERS, &[workers.as_bytes()]);
        if let Some(ov) = self.prefs.overlap_log {
            let ov = ov.to_string();
            self.say(3, m::SET_OVERLAP_LOG, &[ov.as_bytes()]);
        }
        let enc = Encoder::new(&opts).map_err(|e| self.check(e))?;
        Ok(CRess {
            enc,
            dict_name,
            dict_meta,
            window_log,
            level,
        })
    }

    /// `FIO_compressZstdFrame`: returns the compressed size; `readsize`
    /// counts the input read.
    fn compress_zstd_frame(
        &mut self,
        ress: &mut CRess,
        rp: &mut ReadPool,
        src_name: &[u8],
        file_size: u64,
        readsize: &mut u64,
    ) -> Fio<u64> {
        let level = ress.level;
        let mut compressed = 0u64;
        let mut directive = EndOp::Continue;
        let mut pledged = FILESIZE_UNKNOWN;
        self.say(6, m::USING_ZSTD_FORMAT, &[]);
        if file_size != FILESIZE_UNKNOWN {
            pledged = file_size;
            if let Err(e) = ress.enc.set_pledged_size(Some(file_size)) {
                return Err(self.check(e));
            }
        } else if self.prefs.stream_size > 0 {
            pledged = self.prefs.stream_size;
            if let Err(e) = ress.enc.set_pledged_size(Some(pledged)) {
                return Err(self.check(e));
            }
        }
        if self.d.level >= 4 {
            let window_log = if ress.window_log != 0 {
                ress.window_log
            } else if self.prefs.ldm {
                WINDOWLOG_LIMIT_DEFAULT
            } else {
                let size = (file_size != FILESIZE_UNKNOWN).then_some(file_size);
                zstd_opts::default_cparams(level, size, 0).window_log
            };
            let window = (1u64 << window_log).min(pledged).max(1);
            let h = self.human(window).plain();
            self.say(4, m::DECOMPRESSION_MEMORY, &[h.as_bytes()]);
        }
        let mut adapt = Adapt::new();
        let mut level = level;
        loop {
            let in_size = self.fill(rp, CSTREAM_IN_SIZE)?;
            let n = in_size.to_string();
            self.say(6, m::FREAD_BYTES, &[n.as_bytes()]);
            *readsize += in_size as u64;
            if rp.loaded().is_empty() || *readsize == file_size {
                directive = EndOp::End;
            }
            let input = rp.loaded();
            let mut pos = 0;
            let mut still_to_flush = 1;
            while pos != input.len() || (directive == EndOp::End && still_to_flush != 0) {
                let old_pos = pos;
                let mut out = Vec::new();
                let to_flush_now = ress.enc.to_flush_now();
                still_to_flush = match ress
                    .enc
                    .compress_stream2(input, &mut pos, &mut out, directive)
                {
                    Ok(r) => r,
                    Err(e) => return Err(self.check(e)),
                };
                adapt.input_presented += 1;
                if old_pos == pos {
                    adapt.input_blocked += 1;
                }
                if to_flush_now == 0 {
                    adapt.flush_waiting = true;
                }
                let end = match directive {
                    EndOp::Continue => "0",
                    EndOp::Flush => "1",
                    EndOp::End => "2",
                };
                let (p, s, o) = (
                    pos.to_string(),
                    input.len().to_string(),
                    out.len().to_string(),
                );
                self.say(
                    6,
                    m::COMPRESS_GENERIC,
                    &[end.as_bytes(), p.as_bytes(), s.as_bytes(), o.as_bytes()],
                );
                if !out.is_empty() {
                    self.write_block(&out)?;
                    compressed += out.len() as u64;
                }
                if self.prefs.adapt && adapt.last_time.elapsed() > REFRESH_RATE {
                    self.adapt_level(&mut adapt, &mut ress.enc, &mut level);
                }
                if self.should_display_progress() && self.ready_for_update() {
                    self.compress_progress(&ress.enc, src_name, file_size, level);
                }
            }
            let input_len = input.len();
            rp.consume(input_len);
            if directive == EndOp::End {
                break;
            }
        }
        if file_size != FILESIZE_UNKNOWN && *readsize != file_size {
            let (a, b) = (readsize.to_string(), file_size.to_string());
            return Err(self.exm(27, m::INCOMPLETE_READ, &[a.as_bytes(), b.as_bytes()]));
        }
        self.sparse_end()?;
        Ok(compressed)
    }

    /// `FIO_compressZstdFrame`'s adaptive mode (`--adapt`, R10): every
    /// `REFRESH_RATE`, read the frame's progression and move the level one
    /// step, slower (higher) when compression waits on output or input,
    /// faster (lower) when the input is often blocked while output keeps
    /// up. libzstd applies a new level from its next job. On the pure tier
    /// the progression has no jobs, so the level never moves.
    fn adapt_level(&mut self, a: &mut Adapt, enc: &mut Encoder, level: &mut i32) {
        let zfp = enc.progression();
        a.last_time = Instant::now();
        let n = |v: u64| v.to_string();
        if zfp.current_job_id > 1 {
            let newly_produced = zfp.produced.wrapping_sub(a.previous_update.produced);
            let newly_flushed = zfp.flushed.wrapping_sub(a.previous_update.flushed);
            if zfp.consumed == a.previous_update.consumed && zfp.nb_active_workers == 0 {
                self.say(6, m::ADAPT_ALL_BUFFERS_FULL, &[]);
                a.speed = Speed::Slower;
            }
            a.previous_update = zfp;
            if newly_produced > newly_flushed.wrapping_mul(9) / 8 && !a.flush_waiting {
                let (p, f) = (n(newly_produced), n(newly_flushed));
                self.say(6, m::ADAPT_FASTER_THAN_FLUSH, &[p.as_bytes(), f.as_bytes()]);
                a.speed = Speed::Slower;
            }
            a.flush_waiting = false;
        }
        if zfp.current_job_id > a.last_job_id {
            self.say(6, m::ADAPT_CHECK, &[]);
            if i64::from(zfp.current_job_id) > i64::from(self.prefs.workers) + 1 {
                if a.input_blocked == 0 {
                    self.say(6, m::ADAPT_INPUT_NEVER_BLOCKED, &[]);
                    a.speed = Speed::Slower;
                } else if a.speed == Speed::NoChange {
                    let p = a.previous_correction;
                    let ingested = zfp.ingested.wrapping_sub(p.ingested);
                    let consumed = zfp.consumed.wrapping_sub(p.consumed);
                    let produced = zfp.produced.wrapping_sub(p.produced);
                    let flushed = zfp.flushed.wrapping_sub(p.flushed);
                    a.previous_correction = zfp;
                    let share = f64::from(a.input_blocked) / f64::from(a.input_presented) * 100.0;
                    // `%u` of each 64-bit figure, as fileio.c casts them.
                    let u = |v: u64| (v as u32).to_string();
                    let args = [
                        a.input_blocked.to_string(),
                        a.input_presented.to_string(),
                        format!("{share:.2}"),
                        u(ingested),
                        u(consumed),
                        u(flushed),
                        u(produced),
                    ];
                    let args: Vec<&[u8]> = args.iter().map(|s| s.as_bytes()).collect();
                    self.say(6, m::ADAPT_INPUT_BLOCKED, &args);
                    if a.input_blocked > a.input_presented / 8
                        && flushed.wrapping_mul(33) / 32 > produced
                        && ingested.wrapping_mul(33) / 32 > consumed
                    {
                        let args = [n(ingested), n(consumed), n(produced), n(flushed)];
                        let args: Vec<&[u8]> = args.iter().map(|s| s.as_bytes()).collect();
                        self.say(6, m::ADAPT_RECOMMEND_FASTER, &args);
                        a.speed = Speed::Faster;
                    }
                }
                a.input_blocked = 0;
                a.input_presented = 0;
            }
            if a.speed == Speed::Slower {
                self.say(6, m::ADAPT_SLOWER, &[]);
                *level = (*level + 1)
                    .min(zstd_opts::MAX_CLEVEL)
                    .min(self.prefs.adapt_max);
                *level += i32::from(*level == 0);
                // fileio.c ignores the result.
                let _ = enc.set_level(*level);
            }
            if a.speed == Speed::Faster {
                self.say(6, m::ADAPT_FASTER, &[]);
                *level = (*level - 1).max(self.prefs.adapt_min);
                *level -= i32::from(*level == 0);
                let _ = enc.set_level(*level);
            }
            a.speed = Speed::NoChange;
            a.last_job_id = zfp.current_job_id;
        }
    }

    /// `FIO_compressZstdFrame`'s progress notification.
    fn compress_progress(&mut self, enc: &Encoder, src_name: &[u8], file_size: u64, level: i32) {
        let z = enc.progression();
        let now = self.now_ms();
        self.d.delay_next_update(now);
        let line = display::compress_progress_line(&display::CompressProgress {
            display_level: self.d.level,
            util_level: self.util_level,
            nb_files_total: self.prefs.nb_files_total,
            curr_file_idx: self.curr_file_idx,
            src_name,
            file_size,
            level,
            ingested: z.ingested,
            consumed: z.consumed,
            produced: z.produced,
        });
        self.display_progress_line(&line);
    }

    /// `FIO_compressFilename_internal`.
    fn compress_internal(
        &mut self,
        ress: &mut CRess,
        rp: &mut ReadPool,
        dst: &[u8],
        src: &[u8],
    ) -> Fio<i32> {
        let start = Instant::now();
        let cpu_start = cpu_seconds();
        let mut readsize = 0u64;
        let file_size = util::file_size(self.host, src);
        let fs_text = file_size.to_string();
        self.say(5, m::SRC_BYTES, &[src, fs_text.as_bytes()]);
        let compressed = match self.prefs.ctype {
            CType::Zstd => self.compress_zstd_frame(ress, rp, src, file_size, &mut readsize)?,
            ctype => {
                let mut codec = self.codec.take().expect("the codec is home");
                let r = codec.compress(self, rp, ctype, src, file_size, ress.level);
                self.codec = Some(codec);
                let (read, written) = r?;
                readsize = read;
                written
            }
        };
        self.total_in += readsize;
        self.total_out += compressed;
        self.clear_progress();
        if self.should_display_file_summary() {
            let (hi, ho) = (hrs6(&self.human(readsize)), hrs6(&self.human(compressed)));
            let name = left20(src);
            if readsize == 0 {
                self.display_summary(
                    m::SUMMARY_EMPTY,
                    &[&name, hi.as_bytes(), ho.as_bytes(), dst],
                );
            } else {
                let ratio = format!("{:6.2}", compressed as f64 / readsize as f64 * 100.0);
                self.display_summary(
                    m::SUMMARY,
                    &[&name, ratio.as_bytes(), hi.as_bytes(), ho.as_bytes(), dst],
                );
            }
        }
        let secs = start.elapsed().as_secs_f64();
        let cpu = (cpu_seconds() - cpu_start) / secs * 100.0;
        let (t, c) = (format!("{secs:.2}"), format!("{cpu:.0}"));
        self.say(4, m::COMPLETED, &[&left20(src), t.as_bytes(), c.as_bytes()]);
        Ok(0)
    }

    /// `FIO_compressFilename_dstFile`.
    fn compress_dst_file(
        &mut self,
        ress: &mut CRess,
        rp: &mut ReadPool,
        dst: &[u8],
        src: &[u8],
        src_meta: Option<&Metadata>,
    ) -> Fio<i32> {
        let mut close = false;
        let mut transfer = None;
        if matches!(self.sink, Sink::Unset) {
            if src != STDINMARK && dst != STDOUTMARK && src_meta.is_some_and(Metadata::is_file) {
                transfer = src_meta;
            }
            close = true;
            self.say(6, m::OPENING_DST, &[dst]);
            if !self.open_dst(Some(src), dst, transfer.is_some(), false)? {
                return Ok(1);
            }
            self.arm_in_place();
        }
        let result = match self.compress_internal(ress, rp, dst, src) {
            Ok(r) => r,
            Err(t) => {
                if close {
                    self.abandon_sink();
                }
                return Err(t);
            }
        };
        if close {
            return self.release_dst(transfer, result, true);
        }
        Ok(result)
    }

    /// `FIO_compressFilename_srcFile`.
    fn compress_src_file(&mut self, ress: &mut CRess, dst: &[u8], src: &[u8]) -> Fio<i32> {
        self.say(6, m::COMPRESS_SRC_FILE, &[src]);
        if src != STDINMARK
            && let Ok(meta) = util::stat(self.host, src)
        {
            if meta.is_dir() {
                self.say(1, m::IS_A_DIRECTORY, &[src]);
                return Ok(1);
            }
            if let (Some(dn), Some(dm)) = (&ress.dict_name, &ress.dict_meta)
                && util::is_same_file_stat(src, dn, &meta, dm)
            {
                self.say(1, m::INPUT_IS_DICTIONARY, &[src]);
                return Ok(1);
            }
        }
        if self.prefs.exclude_compressed && util::is_compressed_file(src, m::COMPRESSED_EXTENSIONS)
        {
            self.say(4, m::ALREADY_COMPRESSED, &[src]);
            return Ok(0);
        }
        let Some((mut rp, meta)) = self.open_src(src, CSTREAM_IN_SIZE) else {
            return Ok(1);
        };
        let result = self.compress_dst_file(ress, &mut rp, dst, src, meta.as_ref())?;
        drop(rp);
        if self.prefs.remove_src
            && result == 0
            && src != STDINMARK
            && let Err(e) = self.remove_file(src)
        {
            return Err(self.exm(1, m::RM_FAILED, &[src, &strerror(&e)]));
        }
        Ok(result)
    }
}

/// `UTIL_getLargestFileSize` (an unknown size is the largest).
fn largest_file_size(host: &Host, names: &[Vec<u8>]) -> u64 {
    names
        .iter()
        .map(|n| util::file_size(host, n))
        .max()
        .unwrap_or(0)
}

/// zstdcli.c's compression call: `FIO_compressFilename` for one input with
/// `-o` (or `-c`), else `FIO_compressMultipleFilenames`. Returns the
/// operation's result, or the `EXM_THROW` that ended it.
pub(crate) fn compress_files(
    cmd: &Command,
    host: &mut Host,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Fio<i32> {
    let mut io = Io::new(cmd, host, out, err);
    let files = &cmd.files;
    if files.len() == 1
        && let Some(out_name) = &cmd.out_file
    {
        let size = util::file_size(io.host, &files[0]);
        let mut ress = io.create_cresources(cmd, size, cmd.level)?;
        return io.compress_src_file(&mut ress, out_name, &files[0]);
    }
    let largest = largest_file_size(io.host, files);
    let mut ress = io.create_cresources(cmd, largest, cmd.level)?;
    let mut error = 0;
    if let Some(out_name) = &cmd.out_file {
        if io.multi_files_concat_warning(out_name, 1)? {
            return Ok(1);
        }
        if io.output_is_an_input(out_name, files) || !io.open_dst(None, out_name, false, true)? {
            error = 1;
        } else {
            while io.curr_file_idx < io.prefs.nb_files_total {
                let src = &files[io.curr_file_idx];
                let status = match io.compress_src_file(&mut ress, out_name, src) {
                    Ok(s) => s,
                    Err(t) => {
                        io.abandon_sink();
                        return Err(t);
                    }
                };
                if status == 0 {
                    io.nb_files_processed += 1;
                }
                error |= status;
                io.curr_file_idx += 1;
            }
            let (closed, file) = io.close_sink()?;
            drop(file);
            if let Err(e) = closed {
                return Err(io.exm(29, m::CLOSE_FAILED, &[&strerror(&e), out_name]));
            }
        }
    } else {
        if let Some(root) = &cmd.out_dir_mirror {
            util::mirror_source_dirs(io.host, files, root, io.err);
        }
        while io.curr_file_idx < io.prefs.nb_files_total {
            let src = &files[io.curr_file_idx];
            let dst = if let Some(root) = &cmd.out_dir_mirror {
                match util::mirrored_dest_dir(src, root) {
                    Some(dir) => compressed_name(src, Some(&dir), cmd.suffix),
                    None => {
                        io.say(2, m::MIRROR_CANNOT_COMPRESS, &[src, root]);
                        error = 1;
                        io.curr_file_idx += 1;
                        continue;
                    }
                }
            } else {
                compressed_name(src, cmd.out_dir_flat.as_deref(), cmd.suffix)
            };
            let status = io.compress_src_file(&mut ress, &dst, src)?;
            if status == 0 {
                io.nb_files_processed += 1;
            }
            error |= status;
            io.curr_file_idx += 1;
        }
        if cmd.out_dir_flat.is_some() {
            io.check_filename_collisions(files);
        }
    }
    if io.should_display_multiple_file_summary() {
        let (hi, ho) = (
            hrs6_4(&io.human(io.total_in)),
            hrs6_4(&io.human(io.total_out)),
        );
        let n = format!("{:3}", io.nb_files_processed);
        io.clear_progress();
        if io.total_in == 0 {
            io.display_summary(
                m::FILES_COMPRESSED_EMPTY,
                &[n.as_bytes(), hi.as_bytes(), ho.as_bytes()],
            );
        } else {
            let r = format!("{:.2}", io.total_out as f64 / io.total_in as f64 * 100.0);
            io.display_summary(
                m::FILES_COMPRESSED,
                &[n.as_bytes(), r.as_bytes(), hi.as_bytes(), ho.as_bytes()],
            );
        }
    }
    Ok(error)
}

// ---- decompression ----

/// `ZSTD_isFrame`: a zstd or skippable frame, or (on the C tier) a legacy
/// v0.5-v0.7 one.
fn is_zstd_frame(b: &[u8]) -> bool {
    if b.len() < 4 {
        return false;
    }
    let magic = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    if magic == zstd_opts::MAGIC || magic & 0xFFFF_FFF0 == zstd_opts::MAGIC_SKIPPABLE_START {
        return true;
    }
    #[cfg(feature = "zstd-c")]
    if LEGACY_MAGICS.contains(&magic) {
        return true;
    }
    false
}

/// `FIO_determineDstName`: `None` (said) for an unknown suffix.
fn decompressed_name(io: &mut Io<'_>, src: &[u8], out_dir: Option<&[u8]>) -> Option<Vec<u8>> {
    if src == STDINMARK {
        return Some(STDOUTMARK.to_vec());
    }
    let unknown = |io: &mut Io<'_>| {
        io.say(1, m::UNKNOWN_SUFFIX, &[src, m::SUFFIX_LIST_STR.as_bytes()]);
        None
    };
    let Some(dot) = src.iter().rposition(|&b| b == b'.') else {
        return unknown(io);
    };
    let suffix = &src[dot..];
    let Some(matched) = m::SUFFIX_LIST.iter().find(|s| s.as_bytes() == suffix) else {
        return unknown(io);
    };
    if src.len() <= suffix.len() {
        return unknown(io);
    }
    let dst_suffix: &[u8] = if matched.as_bytes()[1] == b't' {
        m::TAR_SUFFIX.as_bytes()
    } else {
        b""
    };
    let base = match out_dir {
        Some(d) => filename_from_out_dir(src, d),
        None => src.to_vec(),
    };
    let mut v = base[..base.len() - suffix.len()].to_vec();
    v.extend_from_slice(dst_suffix);
    Some(v)
}

impl Io<'_> {
    /// `FIO_createDResources`.
    fn create_dresources(&mut self, cmd: &Command) -> Fio<Decoder> {
        let dict_name = cmd.dict_file.clone();
        let dict_meta = self.dict_stat(dict_name.as_deref())?;
        if self.prefs.patch_from_mode {
            let dict_size = dict_meta
                .as_ref()
                .map_or(FILESIZE_UNKNOWN, util::file_size_stat);
            self.adjust_mem_limit_for_patch_from(dict_size, 0)?;
        }
        // ZSTD_DCtx_setMaxWindowSize's own bounds, checked where fileio.c
        // sets it: before the dictionary is read.
        let limit = u64::from(self.prefs.memory_limit);
        if !(1 << zstd_opts::WINDOWLOG_ABSOLUTEMIN..=1 << zstd_opts::WINDOWLOG_MAX).contains(&limit)
        {
            return Err(self.check(ZstdError::lib(zstd_opts::code::PARAMETER_OUT_OF_BOUND)));
        }
        let dict = self.load_dict(dict_name.as_deref(), dict_meta.as_ref())?;
        let (dictionary, prefix) = if self.prefs.patch_from_mode {
            (None, dict)
        } else {
            (dict, None)
        };
        let opts = DecodeOptions {
            max_window_size: limit,
            ignore_checksum: self.prefs.checksum == 0,
            dictionary,
            prefix,
        };
        Decoder::new(&opts).map_err(|e| self.check(e))
    }

    /// `FIO_passThrough`.
    fn pass_through(&mut self, rp: &mut ReadPool) -> Fio<i32> {
        let block = (64 << 10).min(DSTREAM_IN_SIZE).min(DSTREAM_OUT_SIZE);
        self.fill(rp, block)?;
        while !rp.loaded().is_empty() {
            let n = block.min(rp.loaded().len());
            let chunk = rp.loaded()[..n].to_vec();
            self.write_block(&chunk)?;
            rp.consume(n);
            self.fill(rp, block)?;
        }
        self.sparse_end()?;
        Ok(0)
    }

    /// `FIO_zstdErrorHelp`: the window-too-large hint, from the frame
    /// header at the start of what is loaded.
    fn zstd_error_help(&mut self, e: &ZstdError, loaded: &[u8], src: &[u8]) {
        if e.code() != Some(zstd_opts::code::WINDOW_TOO_LARGE) {
            return;
        }
        if let Ok(FrameHeader::Zstd { window_size, .. }) = zstd_opts::frame_header(loaded) {
            let window_log =
                highbit64(window_size) + u32::from(window_size & window_size.wrapping_sub(1) != 0);
            let (ws, ml) = (window_size.to_string(), self.prefs.memory_limit.to_string());
            self.say(1, m::WINDOW_TOO_LARGE, &[src, ws.as_bytes(), ml.as_bytes()]);
            if window_log <= zstd_opts::WINDOWLOG_MAX {
                let mb = (window_size >> 20) + u64::from(window_size & ((1 << 20) - 1) != 0);
                let (wl, mb) = (window_log.to_string(), mb.to_string());
                self.say(1, m::WINDOW_HINT, &[src, wl.as_bytes(), mb.as_bytes()]);
                return;
            }
        }
        let max = zstd_opts::WINDOWLOG_MAX.to_string();
        self.say(1, m::WINDOW_LOG_TOO_LARGE, &[src, max.as_bytes()]);
    }

    /// `FIO_decompressZstdFrame`: the frame's decoded size, or `None` for
    /// `FIO_ERROR_FRAME_DECODING`.
    fn decompress_zstd_frame(
        &mut self,
        dec: &mut Decoder,
        rp: &mut ReadPool,
        src: &[u8],
        already: u64,
    ) -> Fio<Option<u64>> {
        let mut frame_size = 0u64;
        dec.reset();
        self.fill(rp, FRAMEHEADERSIZE_MAX)?;
        loop {
            let mut out = Vec::new();
            let r = dec.decompress_stream(rp.loaded(), &mut out);
            // `hrs` is read before this pass adds its output to the frame.
            let shown = already + frame_size;
            let (consumed, hint) = match r {
                Ok(x) => x,
                Err(e) => {
                    let name = e.to_string();
                    self.say(1, m::DECODING_ERROR, &[src, name.as_bytes()]);
                    let loaded = rp.loaded().to_vec();
                    self.zstd_error_help(&e, &loaded, src);
                    return Ok(None);
                }
            };
            self.write_block(&out)?;
            frame_size += out.len() as u64;
            let line = display::decompress_progress_line(
                self.d.level,
                self.util_level,
                self.prefs.nb_files_total,
                self.curr_file_idx,
                src,
                shown,
            );
            self.display_update_line(&line);
            rp.consume(consumed);
            if hint == 0 {
                break;
            }
            let to_decode = hint.min(DSTREAM_IN_SIZE);
            if rp.loaded().len() < to_decode && self.fill(rp, to_decode)? == 0 {
                self.say(1, m::PREMATURE_END, &[src]);
                return Ok(None);
            }
        }
        self.sparse_end()?;
        Ok(Some(frame_size))
    }

    /// `FIO_decompressFrames`: 0, or 1 on an error (said).
    fn decompress_frames(
        &mut self,
        dec: &mut Decoder,
        rp: &mut ReadPool,
        dst: &[u8],
        src: &[u8],
    ) -> Fio<i32> {
        let mut read_something = false;
        let mut filesize = 0u64;
        let pass = match self.prefs.pass_through {
            -1 => self.prefs.overwrite && dst == STDOUTMARK,
            p => p != 0,
        };
        loop {
            self.fill(rp, 4)?;
            let buf = rp.loaded();
            if buf.is_empty() {
                if !read_something {
                    self.say(1, m::UNEXPECTED_EOF, &[src]);
                    return Ok(1);
                }
                break;
            }
            read_something = true;
            if buf.len() < 4 {
                if pass {
                    return self.pass_through(rp);
                }
                self.say(1, m::UNKNOWN_HEADER, &[src]);
                return Ok(1);
            }
            let foreign = if is_zstd_frame(buf) {
                None
            } else if buf[0] == 31 && buf[1] == 139 {
                Some(Foreign::Gzip)
            } else if buf[0] == 0xFD && buf[1] == 0x37 {
                Some(Foreign::Xz)
            } else if buf[0] == 0x5D && buf[1] == 0x00 {
                Some(Foreign::Lzma)
            } else if u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) == LZ4_MAGIC {
                Some(Foreign::Lz4)
            } else if pass {
                return self.pass_through(rp);
            } else {
                self.say(1, m::UNSUPPORTED_FORMAT, &[src]);
                return Ok(1);
            };
            let size = match foreign {
                None => self.decompress_zstd_frame(dec, rp, src, filesize)?,
                Some(kind) => {
                    let mut codec = self.codec.take().expect("the codec is home");
                    let r = codec.decompress(self, rp, kind, src);
                    self.codec = Some(codec);
                    r?
                }
            };
            match size {
                Some(n) => filesize += n,
                None => return Ok(1),
            }
        }
        self.total_out += filesize;
        self.clear_progress();
        if self.should_display_file_summary() {
            let n = filesize.to_string();
            self.display_summary(m::DECOMPRESSED_BYTES, &[&left20(src), n.as_bytes()]);
        }
        Ok(0)
    }

    /// `FIO_decompressDstFile`.
    fn decompress_dst_file(
        &mut self,
        dec: &mut Decoder,
        rp: &mut ReadPool,
        dst: &[u8],
        src: &[u8],
        src_meta: Option<&Metadata>,
    ) -> Fio<i32> {
        let mut release = false;
        let mut transfer = None;
        if matches!(self.sink, Sink::Unset) && !self.prefs.test_mode {
            if src != STDINMARK && dst != STDOUTMARK && src_meta.is_some_and(Metadata::is_file) {
                transfer = src_meta;
            }
            release = true;
            if !self.open_dst(Some(src), dst, transfer.is_some(), false)? {
                return Ok(1);
            }
            self.arm_in_place();
        }
        let result = match self.decompress_frames(dec, rp, dst, src) {
            Ok(r) => r,
            Err(t) => {
                if release {
                    self.abandon_sink();
                }
                return Err(t);
            }
        };
        if release {
            return self.release_dst(transfer, result, false);
        }
        Ok(result)
    }

    /// `FIO_decompressSrcFile`.
    fn decompress_src_file(&mut self, dec: &mut Decoder, dst: &[u8], src: &[u8]) -> Fio<i32> {
        if util::is_directory(self.host, src) {
            self.say(1, m::IS_A_DIRECTORY, &[src]);
            return Ok(1);
        }
        let Some((mut rp, meta)) = self.open_src(src, DSTREAM_IN_SIZE) else {
            return Ok(1);
        };
        let result = self.decompress_dst_file(dec, &mut rp, dst, src, meta.as_ref())?;
        drop(rp);
        if self.prefs.remove_src
            && result == 0
            && src != STDINMARK
            && let Err(e) = self.remove_file(src)
        {
            self.say(1, m::NAME_ERRNO, &[src, &strerror(&e)]);
            return Ok(1);
        }
        Ok(result)
    }
}

/// zstdcli.c's decompression (and `-t`) call: `FIO_decompressFilename` for
/// one input with an output name, else `FIO_decompressMultipleFilenames`.
pub(crate) fn decompress_files(
    cmd: &Command,
    host: &mut Host,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Fio<i32> {
    let mut io = Io::new(cmd, host, out, err);
    let files = &cmd.files;
    let mut dec = io.create_dresources(cmd)?;
    if files.len() == 1
        && let Some(out_name) = &cmd.out_file
    {
        return io.decompress_src_file(&mut dec, out_name, &files[0]);
    }
    let mut error = 0;
    if let Some(out_name) = &cmd.out_file {
        if io.multi_files_concat_warning(out_name, 1)? {
            return Ok(1);
        }
        if !io.prefs.test_mode
            && (io.output_is_an_input(out_name, files)
                || !io.open_dst(None, out_name, false, true)?)
        {
            return Err(io.exm(19, m::CANNOT_OPEN, &[out_name]));
        }
        while io.curr_file_idx < io.prefs.nb_files_total {
            let src = &files[io.curr_file_idx];
            let status = match io.decompress_src_file(&mut dec, out_name, src) {
                Ok(s) => s,
                Err(t) => {
                    io.abandon_sink();
                    return Err(t);
                }
            };
            if status == 0 {
                io.nb_files_processed += 1;
            }
            error |= status;
            io.curr_file_idx += 1;
        }
        if !io.prefs.test_mode {
            let (closed, file) = io.close_sink()?;
            drop(file);
            if let Err(e) = closed {
                return Err(io.exm(72, m::CLOSE_OUTPUT_FAILED, &[&strerror(&e)]));
            }
        }
    } else {
        if let Some(root) = &cmd.out_dir_mirror {
            util::mirror_source_dirs(io.host, files, root, io.err);
        }
        while io.curr_file_idx < io.prefs.nb_files_total {
            let src = &files[io.curr_file_idx];
            let dst = if let Some(root) = &cmd.out_dir_mirror {
                match util::mirrored_dest_dir(src, root) {
                    Some(dir) => decompressed_name(&mut io, src, Some(&dir)),
                    None => {
                        io.say(2, m::MIRROR_CANNOT_DECOMPRESS, &[src, root]);
                        None
                    }
                }
            } else {
                decompressed_name(&mut io, src, cmd.out_dir_flat.as_deref())
            };
            let Some(dst) = dst else {
                error = 1;
                io.curr_file_idx += 1;
                continue;
            };
            let status = io.decompress_src_file(&mut dec, &dst, src)?;
            if status == 0 {
                io.nb_files_processed += 1;
            }
            error |= status;
            io.curr_file_idx += 1;
        }
        if cmd.out_dir_flat.is_some() {
            io.check_filename_collisions(files);
        }
    }
    if io.should_display_multiple_file_summary() {
        io.clear_progress();
        let (n, t) = (
            io.nb_files_processed.to_string(),
            format!("{:6}", io.total_out),
        );
        io.display_summary(m::FILES_DECOMPRESSED, &[n.as_bytes(), t.as_bytes()]);
    }
    Ok(error)
}

#[cfg(test)]
mod tests;
