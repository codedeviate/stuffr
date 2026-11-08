//! Compressing, decompressing and testing over files and streams: every
//! rule of what is opened, in which order, what is asked, what is kept and
//! what the run's exit code becomes. The stream decoder itself (the magic
//! numbers, legacy and skippable frames, mozlz4, trailing data) is in
//! `decode.rs`.
//!
//! **Clean room.** Every rule here was recovered from the man page
//! (`lz4.1`), `lz4 -H` and probes of the 1.10.0 binary (Task 2's and Task
//! 4's tables in `.claude/rules/compat.md`, "lz4 1.10.0 probes"), then of
//! the 1.11.0 one (the 2026-11-08 probe, 0.26.0 Tasks 4 and 5); lz4's
//! `programs/` was never read. Each rule names its probe.
//!
//! The rules, in short (all probed):
//! - **Order.** Compression opens the input, then the output; decompression
//!   and test open the output first, then the input (`lz4 -d -f nosuch.lz4
//!   a` truncates `a`, `unlz4 nosuch.lz4` leaves an empty `nosuch`). A `-D`
//!   dictionary is read once, after the single-file announcement and before
//!   anything else is opened.
//! - **Outputs** are written directly under their names, with no temporary
//!   file; an interrupt kills the run (no handler, ruling T2-a) and leaves
//!   the partial output, as lz4 does. An output of a named regular file is
//!   created 0600, and once its input succeeded it gets the input's
//!   modification time and permission bits (and owner where allowed); its
//!   access time is the run's. A failed one stays 0600 with the run's time;
//!   one from standard input is created 0666 less the umask and keeps the
//!   run's time ([`output_mode`]).
//! - **An existing output** is asked about at display level 2 and up (the
//!   answer read from standard input, terminal or not: R11; `y` or `Y`
//!   first, the rest of the line consumed); below it, refused with a line
//!   printed at every level. `-f` opens it over. An output that is the
//!   input itself is refused before that (lz4 1.11.0's refusal; for standard
//!   input redirected from it, spec deviation 3).
//! - **The exit code** is the number of inputs that failed (`lz4 -m a n1 n2
//!   n3 e` exits 3); an `Error N` ends the run at once with N, and the
//!   hidden `-p` pauses only after a run that was not ended that way.
//! - **Display level 2 drops to 1** when the output is standard output or
//!   several inputs are named (`lz4 -c a`, `lz4 -m a` print no summary;
//!   `lz4 -t a.lz4 -` does, its output being discarded).
//! - **`--rm`** removes a named input once it succeeded (also after `-c`),
//!   never after `-t`, a decode that met undecodable trailing data, or for
//!   standard input (1.11.0; 1.10.0 removed in the first two cases and
//!   removed the name `stdin`, or said `Error 50`).
//! - **Sparse output** (decompression only; on for files, off for standard
//!   output unless `--sparse`): runs of zero words become seeks, and the
//!   last skip ends with a written zero. lz4 seeks before each piece of data
//!   it writes, an empty skip included, so a pipe fails at the first one.
//!
//! The lines of display levels 2 and up (ruling P3: the announcement, the
//! `\r`-refreshed progress, the cleared line, the summaries, and levels 3
//! and 4's thread line, `Done in` and notes) are `display.rs`'s: this file
//! says when, that one says what and at which pace.

use std::fs::{self, File, Metadata};
use std::io::{self, Read, Seek, SeekFrom, Write};

use stuffr::lz4_opts::{EncodeOptions, Encoder, FRAME_CHUNK, LEGACY_BLOCK_SIZE};

use super::cli::{self, Command, Op, Plan, STDINMARK, Target};
use super::decode;
use super::display::{Display, Timer};
use super::messages::{self as m, printf};
use crate::compat::host::{self, Host, Kind};

/// What one input's processing read and wrote, for the summaries and for
/// `Done in`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stats {
    /// Bytes read from the input.
    pub read: u64,
    /// Bytes written to the output (or discarded, under `-t`).
    pub written: u64,
}

/// How one input's processing went wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Fail {
    /// This input failed (its line is printed); the run goes on, and the
    /// failure counts in the exit code.
    File,
    /// `Error N : ...` was printed: the run ends now with exit N.
    Exit(i32),
}

/// How a run of [`compress_files`] or [`decompress_files`] ended: the exit
/// code, and whether `-p`'s pause follows (not after an `Error N`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ended {
    pub code: i32,
    pub pause: bool,
}

/// The bytes read from an input at once (the decoder is fed smaller
/// slices: `decode.rs`).
const READ_SIZE: usize = 64 << 10;

/// A walk deeper than this stops. Since lz4 1.11.0 a walk follows no
/// symbolic link to a directory, so only a real tree this deep reaches it;
/// the cap is a guard, not a rule of lz4's.
const WALK_DEPTH_MAX: usize = 256;

// ---- inputs ----

/// Where an input's bytes come from.
enum Origin {
    /// A named file (counted in a sandbox: [`Host::track`]).
    File(host::InFile),
    /// The process's standard input.
    Stdin(File),
    /// Standard input that could not be had as a file, or a sandbox's.
    Stream(Box<dyn Read>),
}

/// An [`Origin`] with C stdio's sticky end of input.
struct Reader {
    origin: Origin,
    eof: bool,
    /// A read failed (the input ended there).
    failed: bool,
    /// The bytes still to be read where the input is read as it was when
    /// opened (`--mmap`, [`Src::limit_to`]); `None`: to its end.
    left: Option<u64>,
}

impl Reader {
    /// One read; an error ends the input, as a short read does (probe: `lz4
    /// -dc <&-` decodes nothing, exit 0), and is remembered in `failed`.
    fn read(&mut self, buf: &mut [u8]) -> usize {
        let buf = match self.left {
            Some(0) => {
                self.eof = true;
                return 0;
            }
            Some(left) => {
                let n = usize::try_from(left).map_or(buf.len(), |l| l.min(buf.len()));
                &mut buf[..n]
            }
            None => buf,
        };
        let n = self.read_some(buf);
        if let Some(left) = &mut self.left {
            *left -= n as u64;
        }
        n
    }

    fn read_some(&mut self, buf: &mut [u8]) -> usize {
        while !self.eof {
            let r = match &mut self.origin {
                Origin::File(f) => f.read(buf),
                Origin::Stdin(f) => f.read(buf),
                Origin::Stream(r) => r.read(buf),
            };
            match r {
                Ok(0) => self.eof = true,
                Ok(n) => return n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => {
                    self.eof = true;
                    self.failed = true;
                }
            }
        }
        0
    }

    /// Seek `n` bytes on, where the origin can: `Ok(false)`, and no seek,
    /// when that is past the file's end (lz4 1.11.0: `Error 43`).
    fn seek_on(&mut self, n: u64) -> io::Result<bool> {
        let off = i64::try_from(n).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let f: &mut dyn SeekFile = match &mut self.origin {
            Origin::File(f) => f,
            Origin::Stdin(f) => f,
            Origin::Stream(_) => return Err(io::Error::from(io::ErrorKind::Unsupported)),
        };
        let at = f.stream_position()?;
        let len = f.size()?;
        if at.checked_add(n).is_none_or(|end| end > len) {
            return Ok(false);
        }
        f.seek(SeekFrom::Current(off))?;
        Ok(true)
    }
}

/// A file that can be seeked and measured (an input's [`Origin`]).
trait SeekFile: Seek {
    fn size(&self) -> io::Result<u64>;
}

impl SeekFile for File {
    fn size(&self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }
}

impl SeekFile for host::InFile {
    fn size(&self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }
}

/// An input, read [`READ_SIZE`] at a time and handed out in slices. The
/// count of bytes taken (`taken`) is what `ftell` would say, for
/// [`m::AT_POSITION`].
pub(super) struct Src {
    reader: Reader,
    buf: Vec<u8>,
    at: usize,
    taken: u64,
    /// A regular file: seekable, and its offset known (lz4 seeks over a
    /// skippable frame and says where trailing data starts only then).
    pub(super) seekable: bool,
}

impl Src {
    fn new(origin: Origin, seekable: bool) -> Src {
        Src {
            reader: Reader {
                origin,
                eof: false,
                failed: false,
                left: None,
            },
            buf: Vec::new(),
            at: 0,
            taken: 0,
            seekable,
        }
    }

    /// The bytes buffered, after reading until at least `want` are (or the
    /// input ends).
    pub(super) fn fill(&mut self, want: usize) -> &[u8] {
        if self.buf.len() - self.at < want && !self.reader.eof {
            self.buf.drain(..self.at);
            self.at = 0;
            while self.buf.len() < want && !self.reader.eof {
                let have = self.buf.len();
                self.buf.resize(have + READ_SIZE.max(want - have), 0);
                let n = self.reader.read(&mut self.buf[have..]);
                self.buf.truncate(have + n);
            }
        }
        &self.buf[self.at..]
    }

    /// Mark `n` buffered bytes as used.
    pub(super) fn consume(&mut self, n: usize) {
        let n = n.min(self.buf.len() - self.at);
        self.at += n;
        self.taken += n as u64;
    }

    /// Read no more than `n` bytes from here (`--mmap`: a file is
    /// compressed as long as it was when opened; probe, 1.11.0: `lz4 f`
    /// with `f` appended to meanwhile writes the bytes it had, `--no-mmap`
    /// the bytes it then read).
    fn limit_to(&mut self, n: u64) {
        self.reader.left = Some(n);
    }

    /// The open file's metadata now (`fstat`): a named input's, or
    /// standard input's descriptor's (never its name's).
    fn fstat(&self) -> Option<Metadata> {
        match &self.reader.origin {
            Origin::File(f) => f.metadata().ok(),
            Origin::Stdin(f) => f.metadata().ok(),
            Origin::Stream(_) => None,
        }
    }

    /// The bytes taken so far (`ftell`).
    pub(super) fn taken(&self) -> u64 {
        self.taken
    }

    /// One byte, or `None` at the end.
    fn byte(&mut self) -> Option<u8> {
        let b = *self.fill(1).first()?;
        self.consume(1);
        Some(b)
    }

    /// Fill `out` from the input: what a full read gives, short only at the
    /// end.
    fn read_full(&mut self, out: &mut [u8]) -> usize {
        let mut n = 0;
        // What is buffered first (a prompt may have read ahead).
        let have = (self.buf.len() - self.at).min(out.len());
        out[..have].copy_from_slice(&self.buf[self.at..self.at + have]);
        self.consume(have);
        n += have;
        while n < out.len() {
            let k = self.reader.read(&mut out[n..]);
            if k == 0 {
                break;
            }
            n += k;
            self.taken += k as u64;
        }
        n
    }

    /// Pass over `n` bytes: a seek on a file, reading them elsewhere.
    /// `false` when the input ends first (probe: `cat skip_trunc.lz4 | lz4
    /// -dc` is `Error 43`, and with lz4 1.11.0 `lz4 -t skip_trunc.lz4` too,
    /// where 1.10.0 seeked past the file's end and exited 0).
    pub(super) fn skip(&mut self, n: u64) -> bool {
        let buffered = (self.buf.len() - self.at) as u64;
        if n <= buffered {
            self.consume(n as usize);
            return true;
        }
        let rest = n - buffered;
        self.consume(buffered as usize);
        if self.seekable {
            match self.reader.seek_on(rest) {
                Ok(true) => {
                    self.taken += rest;
                    return true;
                }
                Ok(false) => return false,
                Err(_) => {}
            }
        }
        let mut left = rest;
        let mut scratch = vec![0u8; READ_SIZE];
        while left > 0 {
            let want = left.min(READ_SIZE as u64) as usize;
            let k = self.reader.read(&mut scratch[..want]);
            if k == 0 {
                return false;
            }
            left -= k as u64;
            self.taken += k as u64;
        }
        true
    }
}

// ---- outputs ----

/// Where one input's output goes.
enum SinkKind {
    /// Standard output: the run's writer, or, under `--sparse`, the
    /// descriptor itself (`stdout_file`) so that it can be seeked.
    Stdout(Option<File>),
    /// Discarded (`-t`, `null`); a sandbox counts it against its budget.
    Null,
    /// A file, through the host's writer (a sandbox's budget applies).
    File(io::BufWriter<Box<dyn Write + Send>>),
    /// A file of the real process written sparsely: seeked and written
    /// directly.
    SparseFile(File),
}

/// One input's output.
pub(super) struct Sink {
    kind: SinkKind,
    /// Sparse writing (`--[no-]sparse`): decompression only.
    sparse: bool,
    /// Zero bytes passed over and not yet seeked.
    skips: u64,
    /// The error a failed write ends the run with (`Error 46` compressing,
    /// `Error 70` decoding).
    write_error: (&'static str, i32),
    /// A second descriptor of a file output, for its metadata (HOST-8: set
    /// by descriptor, never by name; deviation 10).
    fd: Option<host::OutFd>,
}

/// A sandbox's standard output is a pipe: it cannot be seeked.
fn espipe() -> io::Error {
    #[cfg(unix)]
    {
        io::Error::from_raw_os_error(libc::ESPIPE)
    }
    #[cfg(not(unix))]
    {
        io::Error::from(io::ErrorKind::Unsupported)
    }
}

impl Sink {
    /// The plain bytes of a write.
    fn raw(&mut self, out: &mut dyn Write, data: &[u8]) -> io::Result<()> {
        match &mut self.kind {
            SinkKind::Stdout(None) => out.write_all(data),
            SinkKind::Stdout(Some(f)) | SinkKind::SparseFile(f) => f.write_all(data),
            SinkKind::File(w) => w.write_all(data),
            SinkKind::Null => Ok(()),
        }
    }

    /// Move the output's offset `n` bytes on (a seek, even of 0 bytes, as
    /// lz4's).
    fn seek_on(&mut self, out: &mut dyn Write, n: u64) -> io::Result<()> {
        let off = i64::try_from(n).unwrap_or(i64::MAX);
        match &mut self.kind {
            SinkKind::Stdout(Some(f)) | SinkKind::SparseFile(f) => {
                f.seek(SeekFrom::Current(off)).map(drop)
            }
            // A sandbox's standard output is a pipe.
            SinkKind::Stdout(None) => {
                let _ = out.flush();
                Err(espipe())
            }
            // A sandbox's file: the zeros are written (the bytes are the
            // same; a sandbox has no holes).
            SinkKind::File(w) => {
                let zeros = [0u8; 4096];
                let mut left = n;
                while left > 0 {
                    let k = left.min(zeros.len() as u64) as usize;
                    w.write_all(&zeros[..k])?;
                    left -= k as u64;
                }
                Ok(())
            }
            SinkKind::Null => Ok(()),
        }
    }

    /// Write `data`, sparsely if asked (probe: `lz4 --sparse -dc X | cat`:
    /// data in whole 8-byte words is preceded by a seek, `Error 72` if it
    /// fails; data in the bytes after the last whole word by one too,
    /// `Error 74`).
    pub(super) fn write(&mut self, run: &mut Run, data: &[u8]) -> Result<(), Fail> {
        if let SinkKind::Null = self.kind {
            return run
                .host
                .charge(data.len() as u64)
                .map_err(|_| run.exm(self.write_error.1, self.write_error.0, &[]));
        }
        if !self.sparse {
            return self
                .raw(run.out, data)
                .map_err(|_| run.exm(self.write_error.1, self.write_error.0, &[]));
        }
        const WORD: usize = 8;
        const SEGMENT: usize = 32 << 10;
        let words = data.len() / WORD * WORD;
        for seg in data[..words].chunks(SEGMENT) {
            let zeros = seg
                .chunks(WORD)
                .take_while(|w| w.iter().all(|&b| b == 0))
                .count()
                * WORD;
            self.skips += zeros as u64;
            if zeros != seg.len() {
                let n = std::mem::take(&mut self.skips);
                if let Err(e) = self.seek_on(run.out, n) {
                    let code = e.raw_os_error().unwrap_or(0).to_string();
                    return Err(run.exm(
                        72,
                        m::E72_SPARSE_SKIP,
                        &[code.as_bytes(), &host::strerror(&e)],
                    ));
                }
                if self.raw(run.out, &seg[zeros..]).is_err() {
                    return Err(run.exm(self.write_error.1, self.write_error.0, &[]));
                }
            }
        }
        let tail = &data[words..];
        let zeros = tail.iter().take_while(|&&b| b == 0).count();
        self.skips += zeros as u64;
        if zeros != tail.len() {
            let n = std::mem::take(&mut self.skips);
            if self.seek_on(run.out, n).is_err() {
                return Err(run.exm(74, m::E74_SPARSE_TAIL_SKIP, &[]));
            }
            if self.raw(run.out, &tail[zeros..]).is_err() {
                return Err(run.exm(self.write_error.1, self.write_error.0, &[]));
            }
        }
        Ok(())
    }

    /// The end of the output: a pending skip ends with a written zero
    /// (probe: `lz4 --sparse -dc zeros.lz4 | cat` is `Error 69`), then
    /// everything is flushed.
    fn finish(&mut self, run: &mut Run) -> Result<(), Fail> {
        if self.skips > 0 {
            let n = std::mem::take(&mut self.skips);
            if self.seek_on(run.out, n - 1).is_err() || self.raw(run.out, &[0]).is_err() {
                return Err(run.exm(69, m::E69_FINAL_SKIP, &[]));
            }
        }
        self.flush(run.out)
            .map_err(|_| run.exm(self.write_error.1, self.write_error.0, &[]))
    }

    /// Flush what is buffered (also what a failing run decoded before its
    /// fault: it stays, as lz4's does at best).
    fn flush(&mut self, out: &mut dyn Write) -> io::Result<()> {
        match &mut self.kind {
            SinkKind::Stdout(None) => out.flush(),
            SinkKind::Stdout(Some(f)) | SinkKind::SparseFile(f) => f.flush(),
            SinkKind::File(w) => w.flush(),
            SinkKind::Null => Ok(()),
        }
    }
}

/// The mode a new output file is created with: 0600 when its input is a
/// named regular file (it is given the input's mode once it succeeded),
/// else 0666 less the umask.
///
/// probe (1.11.0; the 2026-11-08 probe's §1.11): `lz4 -d bad.lz4 o`, `lz4
/// -d unreadable.lz4 o` (the name stats, the open fails) leave `o` 0600
/// with the run's time, `lz4 -d nosuch.lz4 o` and every output from
/// standard input (a pipe, or redirected from a file: `lz4 -d - o <
/// b.lz4`) 0644 with the run's time, successful or not; a legacy frame
/// (`-l`) is created and finished as any other (1.10.0 created every output
/// 0666 less the umask and left `-l`'s so).
fn output_mode(named_input: Option<&Metadata>) -> u32 {
    if named_input.is_some_and(Metadata::is_file) {
        0o600
    } else {
        0o666
    }
}

// ---- a source that changed while it was compressed (1.11.0) ----

/// What became of a regular input while it was compressed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct Change {
    /// The open file itself changed: its size, or its modification or
    /// status-change time in seconds (a rename moves the latter).
    pub modified: bool,
    /// It is now shorter than it was.
    pub shrunk: bool,
    /// The name is now another file, or none.
    pub replaced: bool,
}

/// What `before` (the input's `fstat` when opened) became: `now` is the
/// open file's `fstat` at the end, `by_name` the name's `stat`.
///
/// probe (1.11.0, `lz4 -12 -T1 f` over 30 MB, `f` changed 0.2 to 1.3 s
/// in): an append, a truncation, a rewrite in place, `utime` to another
/// second and `chmod` are seen, `utime` or `chmod` within the second the
/// file was written are not (seconds are compared, the status-change time
/// too: `chmod` 1.3 s in is seen every time); a rename with another file
/// put in its place is `renamed or replaced`, and from another second on
/// (the rename moves the file's own status-change time) the file counts
/// as modified as well (`--no-frame-crc`: a warning at 0.2-0.4 s, `Error
/// 54` at 0.6-1.1 s). So anything else that moves the status-change time
/// meanwhile (an extended attribute, an ACL, another hard link, set by a
/// backup or indexing agent) counts too; only `chmod` and the rename were
/// probed.
pub(super) fn source_change(
    before: &Metadata,
    now: Option<Metadata>,
    by_name: Option<Metadata>,
) -> Change {
    let replaced = by_name
        .as_ref()
        .is_none_or(|n| host::same_file(before, n) == Some(false));
    let Some(now) = now else {
        return Change {
            replaced,
            ..Change::default()
        };
    };
    #[cfg(unix)]
    let modified = {
        use std::os::unix::fs::MetadataExt;
        (before.size(), before.mtime(), before.ctime()) != (now.size(), now.mtime(), now.ctime())
    };
    #[cfg(not(unix))]
    let modified = {
        let secs = |m: &Metadata| {
            m.modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
        };
        (before.len(), secs(before)) != (now.len(), secs(&now))
    };
    Change {
        modified,
        shrunk: now.len() < before.len(),
        replaced,
    }
}

/// What lz4 1.11.0 makes of a [`Change`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Verdict {
    Fine,
    /// The warning (display level 2), the output kept, and the input too
    /// under `--rm` ([`m::SOURCE_KEPT`]).
    Warn(&'static str),
    /// [`m::E54_SOURCE_MODIFIED`]: the output removed, the run ends with 54.
    Fail,
}

/// probe (1.11.0, the 2026-11-08 probe's §1.13 table and Task 4's
/// reruns): a mapped file (`mapped`: the default; not `--no-mmap`, not
/// `-l`) that was itself modified is `Error 54` when it shrank or has no
/// content checksum (`--no-frame-crc`); every other change is a warning,
/// `renamed or replaced` before `modified`. Read without a map, every
/// change is a warning. `--single-thread` behaves as the default.
pub(super) fn verdict(c: Change, mapped: bool, checksum: bool) -> Verdict {
    if mapped && c.modified && (c.shrunk || !checksum) {
        Verdict::Fail
    } else if c.replaced {
        Verdict::Warn(m::SOURCE_REPLACED)
    } else if c.modified {
        Verdict::Warn(m::SOURCE_MODIFIED)
    } else {
        Verdict::Fine
    }
}

// ---- the run ----

/// What every input of a run shares.
pub(super) struct Run<'a> {
    pub(super) cmd: &'a Command,
    pub(super) host: &'a mut Host,
    pub(super) out: &'a mut dyn Write,
    pub(super) err: &'a mut dyn Write,
    /// The display level after the run's own adjustment (module doc).
    pub(super) level: i32,
    /// Standard input, once opened: prompts and data read the same bytes
    /// (probe: `printf 'y\nhello' | lz4 - e` with `e` present answers `y`
    /// and compresses `hello`).
    stdin: Option<Src>,
    /// The `-D` dictionary's last 64 KiB (all liblz4 keeps).
    pub(super) dict: Option<Vec<u8>>,
    /// The progress line's refresh gate (`display.rs`).
    pub(super) display: Display,
    /// The run's clocks: the gate's and `Done in`'s.
    pub(super) timer: Timer,
    /// Bytes handled so far, for `Done in`'s speed: read when compressing,
    /// decoded when decoding (probe: `lz4 -v -d -m` over 2000 bytes at
    /// 0.00 s says several MiB/s, which only the decoded size gives).
    pub(super) total: u64,
}

impl<'a> Run<'a> {
    /// A run over `cmd`'s inputs at display level `level`.
    pub(super) fn new(
        cmd: &'a Command,
        host: &'a mut Host,
        out: &'a mut dyn Write,
        err: &'a mut dyn Write,
        level: i32,
    ) -> Run<'a> {
        let timer = Timer::start(matches!(host, Host::Real));
        Run {
            cmd,
            host,
            out,
            err,
            level,
            stdin: None,
            dict: None,
            display: Display::new(level),
            timer,
            total: 0,
        }
    }
}

impl Run<'_> {
    /// `Error N : ...` at display level 1: the run ends with N.
    pub(super) fn exm(&mut self, code: i32, fmt: &str, args: &[&[u8]]) -> Fail {
        if self.level >= 1 {
            printf(self.err, fmt, args);
        }
        Fail::Exit(code)
    }

    /// A line at display level `min` and up.
    pub(super) fn say(&mut self, min: i32, fmt: &str, args: &[&[u8]]) {
        if self.level >= min {
            printf(self.err, fmt, args);
        }
    }

    /// An input that failed: its line at display level 1.
    fn fail(&mut self, fmt: &str, args: &[&[u8]]) -> Fail {
        self.say(1, fmt, args);
        Fail::File
    }

    /// Standard input, opened once for the whole run.
    fn take_stdin(&mut self) -> Src {
        if let Some(s) = self.stdin.take() {
            return s;
        }
        match self.host {
            Host::Real => match host::stdin_file() {
                Ok(f) => {
                    let seekable = host::kind_of(&f) == Kind::Regular;
                    Src::new(Origin::Stdin(f), seekable)
                }
                Err(_) => Src::new(Origin::Stream(Box::new(io::stdin())), false),
            },
            Host::Sandbox(s) => {
                let bytes = s.stdin.take().unwrap_or_default();
                Src::new(Origin::Stream(Box::new(io::Cursor::new(bytes))), false)
            }
        }
    }

    /// Standard input's metadata, where there is a file behind it.
    fn stdin_meta(&self) -> Option<Metadata> {
        match self.host {
            Host::Real => host::stdin_file().ok()?.metadata().ok(),
            Host::Sandbox(_) => None,
        }
    }

    /// R11: the answer to the overwrite question, from standard input:
    /// `y` or `Y` first is yes, and the rest of its line is used up; any
    /// other byte is no, and only it is used (probe: `printf 'yxz\ny' | lz4
    /// -v -m a e` answers yes twice, `printf 'n\ny\n' | ...` no twice,
    /// `printf yy | ...` yes then no).
    fn confirm(&mut self) -> bool {
        let mut src = self.take_stdin();
        let yes = matches!(src.byte(), Some(b'y' | b'Y'));
        if yes {
            while !matches!(src.byte(), None | Some(b'\n')) {}
        }
        self.stdin = Some(src);
        yes
    }

    /// Open the input `name`: the source (`None` for standard input, which
    /// the caller takes when it reads it: [`Run::take_stdin`]) and its
    /// metadata, if it has any.
    fn open_input(&mut self, name: &[u8]) -> Result<(Option<Src>, Option<Metadata>), Fail> {
        if name == STDINMARK {
            // probe: `lz4 -vv - o` (display level 4), as the input opens:
            // before the overwrite question when compressing, after it when
            // decoding (the output is opened first then).
            self.say(4, m::USING_STDIN, &[]);
            return Ok((None, self.stdin_meta()));
        }
        let path = self.host.path(name);
        let f = match File::open(&path) {
            Ok(f) => f,
            Err(e) => return Err(self.fail(m::OPEN_INPUT_FAILED, &[name, &host::strerror(&e)])),
        };
        let meta = f.metadata().ok();
        // probe: `lz4 d`, `lz4 -d d.lz4 o`.
        if meta.as_ref().is_some_and(Metadata::is_dir) {
            return Err(self.fail(m::IS_A_DIRECTORY, &[name]));
        }
        let seekable = meta.as_ref().is_some_and(Metadata::is_file);
        let f = self.host.track(&path, f);
        Ok((Some(Src::new(Origin::File(f), seekable)), meta))
    }

    /// Give standard input back for the rest of the run.
    fn put_back(&mut self, name: &[u8], src: Src) {
        if name == STDINMARK {
            self.stdin = Some(src);
        }
    }

    /// Create the output `name`, asking first if it exists (module doc).
    /// `input` is the input's metadata, for deviation 3. Deviation 10: a
    /// symlink at `name`, dangling or not, exists, and is replaced, never
    /// written through; a new file is created with `mode` ([`output_mode`]).
    /// The `bool` says whether this run created it.
    fn open_output(
        &mut self,
        name: &[u8],
        input: Option<&Metadata>,
        mode: u32,
    ) -> Result<(File, bool), Fail> {
        let path = self.host.path(name);
        if host::output_exists(&path) {
            // The input is never opened over (lz4 1.11.0's refusal, also
            // through a link; for standard input redirected from the output
            // file, spec deviation 3).
            if let Some(i) = input
                && let Ok(existing) = fs::metadata(&path)
                && host::same_file(i, &existing) == Some(true)
            {
                return Err(self.fail(m::SAME_FILE, &[name]));
            }
            if !self.cmd.force {
                if self.level <= 1 {
                    printf(self.err, m::ALREADY_EXISTS, &[name]);
                    return Err(Fail::File);
                }
                printf(self.err, m::OVERWRITE_PROMPT, &[name]);
                if !self.confirm() {
                    printf(self.err, m::NOT_OVERWRITTEN, &[]);
                    return Err(Fail::File);
                }
            }
        }
        host::create_output(&path, mode)
            .map_err(|e| self.fail(m::OPEN_OUTPUT_FAILED, &[name, &host::strerror(&e)]))
    }

    /// Display level 4: standard output is the output, and sparse writing
    /// was not asked for either way (probe: `lz4 -vv -c a` says both lines,
    /// `--sparse -c` and `--no-sparse -c` only the first).
    pub(super) fn stdout_note(&mut self) {
        self.say(4, m::USING_STDOUT, &[]);
        if self.cmd.sparse.is_none() {
            self.say(4, m::SPARSE_DISABLED, &[]);
        }
    }

    /// The sink for `target`. `input` is the input's metadata, standard
    /// input's included (the same-file check); `named` says the input is a
    /// file named on the command line ([`output_mode`]); `decoding` selects
    /// sparse writing and the write error.
    fn open_sink(
        &mut self,
        target: &Target,
        input: Option<&Metadata>,
        named: bool,
        decoding: bool,
    ) -> Result<Sink, Fail> {
        // lz4 -H: "--[no-]sparse : sparse mode (default:enabled on file,
        // disabled on stdout)"; probe: compressing never seeks (`lz4
        // --sparse -c zeros | cat` succeeds).
        let sparse_asked = decoding && self.cmd.sparse != Some(false);
        let mut fd = None;
        let write_error = if decoding {
            (m::E70_WRITE_DECODED, 70)
        } else {
            (m::E46_WRITE_COMPRESSED, 46)
        };
        let (kind, sparse) = match target {
            Target::Null => (SinkKind::Null, false),
            Target::Stdout => {
                // probe: `lz4 -vv -c a`, `lz4 -vv -c -m a b` (display level
                // 4): compressing says it for every file written to standard
                // output; decoding said it once, at the start of the run
                // ([`announce_run`]).
                if !decoding {
                    self.stdout_note();
                }
                let sparse = decoding && self.cmd.sparse == Some(true);
                let fd = match (&*self.host, sparse) {
                    (Host::Real, true) => {
                        let _ = self.out.flush();
                        stdout_file()
                    }
                    _ => None,
                };
                (SinkKind::Stdout(fd), sparse)
            }
            Target::File(name) => {
                let mode = output_mode(input.filter(|_| named));
                let (f, _) = self.open_output(name, input, mode)?;
                // A failed run leaves a created output 0600, as lz4 1.11.0
                // does ([`output_mode`]): never widened.
                fd = host::OutFd::new(&f, false, None);
                match self.host {
                    Host::Real if sparse_asked => (SinkKind::SparseFile(f), true),
                    _ => (SinkKind::File(self.host.out_writer(Some(f))), sparse_asked),
                }
            }
        };
        Ok(Sink {
            kind,
            sparse,
            skips: 0,
            write_error,
            fd,
        })
    }

    /// The output's finishing touches (probe: `lz4 a`, `lz4 -d b.lz4`, `lz4
    /// a o` over an existing `o`, 1.11.0 `lz4 -l a`): the input's
    /// modification time, permission bits and owner (a refused `chown` is
    /// ignored); the access time is left as the run made it. Only for a
    /// file named on the command line (`input` is `None` for standard
    /// input), once its input succeeded (1.11.0: not after a failed open, an
    /// `Error N` or undecodable trailing data). Failures are ignored, as lz4
    /// reports none. Set through the output's own descriptor `fd` (HOST-8),
    /// never by name.
    fn copy_metadata(target: &Target, input: Option<&Metadata>, fd: Option<&mut host::OutFd>) {
        let (Target::File(_), Some(meta), Some(fd)) = (target, input, fd) else {
            return;
        };
        let f = fd.file();
        // Only a regular file to a regular file (probe: `lz4 -f b fifo`
        // leaves the FIFO's own mode; a device is never touched).
        if !meta.is_file() || !f.metadata().is_ok_and(|m| m.is_file()) {
            return;
        }
        if let Ok(t) = meta.modified() {
            let _ = f.set_times(fs::FileTimes::new().set_modified(t));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let _ = std::os::unix::fs::fchown(f, Some(meta.uid()), Some(meta.gid()));
        }
        let _ = f.set_permissions(meta.permissions());
        fd.settle();
    }

    /// `--rm`: remove the input once it succeeded (probe, 1.11.0: `lz4 -c
    /// --rm a > x` and `lz4 -d --rm b.lz4` remove it; `lz4 -t --rm b.lz4`,
    /// standard input (`lz4 -c --rm < a`, a file named `stdin` beside it
    /// or not, silent) and a decode followed by undecodable data keep it;
    /// 1.10.0 removed after `-t` and the undecodable case, and removed the
    /// name `stdin` or said `Error 50`). A failed removal is `Error 50`.
    fn remove_input(&mut self, name: &[u8], op: Op) -> Result<(), Fail> {
        if !self.cmd.remove || op == Op::Test || name == STDINMARK {
            return Ok(());
        }
        match fs::remove_file(self.host.path(name)) {
            Ok(()) => Ok(()),
            Err(e) => Err(self.exm(50, m::E50_REMOVE, &[name, &host::strerror(&e)])),
        }
    }

    /// `-D`: read the dictionary, keeping its last 64 KiB (all liblz4
    /// uses: spike S2), through [`Host::track`] (R9). probe: `lz4 -D nosuch
    /// a` prints the open's line, then `Error 27`; `-D d` says `d` is a
    /// directory first.
    fn load_dictionary(&mut self) -> Result<(), Fail> {
        let Some(name) = self.cmd.dict_file.clone() else {
            return Ok(());
        };
        let path = self.host.path(&name);
        let f = match File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                self.say(1, m::OPEN_INPUT_FAILED, &[&name, &host::strerror(&e)]);
                return Err(self.exm(27, m::E27_DICTIONARY, &[]));
            }
        };
        if f.metadata().is_ok_and(|m| m.is_dir()) {
            self.say(1, m::IS_A_DIRECTORY, &[&name]);
            return Err(self.exm(27, m::E27_DICTIONARY, &[]));
        }
        const KEEP: usize = 64 << 10;
        let mut f = self.host.track(&path, f);
        let mut dict = Vec::new();
        let mut buf = vec![0u8; READ_SIZE];
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    dict.extend_from_slice(&buf[..n]);
                    let excess = dict.len().saturating_sub(KEEP);
                    dict.drain(..excess);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err(self.exm(27, m::E27_DICTIONARY, &[])),
            }
        }
        self.dict = Some(dict);
        Ok(())
    }

    /// The inputs, with `-r`'s directories walked (probe: `lz4 -r d`: every
    /// entry in the order the directory lists it, hidden ones too, a
    /// directory's files where it stands, symbolic links to files followed;
    /// the list is made before anything is written, so new outputs are not
    /// inputs). A symbolic link to a directory met in the walk is not
    /// followed and is warned about at every display level
    /// ([`m::RECURSIVE_DIR_LINK`], probe 1.11.0: `lz4 -qqq -r d`; 1.10.0
    /// followed it); one named as an operand is walked (`lz4 -r d/lnk`).
    /// Where that finds no file at all, the names stand as they
    /// were given (probe: `lz4 -m -r e1 e2` over two empty directories says
    /// `e1 is a directory -- ignored` for each, exit 2; `--list -r e1` says
    /// `e1 is not a regular file`; with another file named, an empty
    /// directory vanishes: `--list -r e1 plain.lz4` lists `plain.lz4`).
    pub(super) fn expand(&mut self, names: &[Vec<u8>]) -> Vec<Vec<u8>> {
        if !self.cmd.recursive {
            return names.to_vec();
        }
        let mut out = Vec::new();
        for name in names {
            let is_dir = name.as_slice() != STDINMARK
                && fs::metadata(self.host.path(name)).is_ok_and(|m| m.is_dir());
            if is_dir {
                self.walk(name, 0, &mut out);
            } else {
                out.push(name.clone());
            }
        }
        if out.is_empty() {
            return names.to_vec();
        }
        out
    }

    fn walk(&mut self, dir: &[u8], depth: usize, out: &mut Vec<Vec<u8>>) {
        if depth >= WALK_DEPTH_MAX {
            return;
        }
        let Ok(entries) = fs::read_dir(self.host.path(dir)) else {
            return;
        };
        for entry in entries.flatten() {
            let mut child = dir.to_vec();
            child.push(b'/');
            child.extend_from_slice(entry.file_name().as_encoded_bytes());
            let is_dir = fs::metadata(self.host.path(&child)).is_ok_and(|m| m.is_dir());
            let is_link = entry.file_type().is_ok_and(|t| t.is_symlink());
            if is_dir && is_link {
                printf(self.err, m::RECURSIVE_DIR_LINK, &[&child]);
            } else if is_dir {
                self.walk(&child, depth + 1, out);
            } else {
                out.push(child);
            }
        }
    }

    // ---- compression ----

    /// Compress `name` into `target`.
    fn compress_one(&mut self, name: &[u8], target: &Target) -> Result<Stats, Fail> {
        let (mut src, meta) = self.open_input(name)?;
        // A named regular file is read as long as it was when opened, as
        // lz4 maps it, unless `--no-mmap` (or `-l`, which reads to the end:
        // probe, 1.11.0, `lz4 -l f` with `f` appended to meanwhile writes
        // the bytes appended too). Standard input redirected from a regular
        // file is never mapped: it is read to its end, and checked through
        // its descriptor only (probe, 1.11.0, Task 5 review: `lz4 - o.lz4 <
        // f` with `f` appended to, touched or truncated meanwhile warns
        // `stdin : file modified during processing`, never Error 54, also
        // under `--no-frame-crc`; `f` renamed and replaced meanwhile says
        // nothing; an unchanged `f` says nothing).
        let named = name != STDINMARK;
        let regular = meta.as_ref().filter(|m| m.is_file());
        let mapped = self.cmd.mmap && !self.cmd.opts.legacy && named;
        if let (Some(s), Some(m), true) = (src.as_mut(), regular, mapped) {
            s.limit_to(m.len());
        }
        let (r, mut fd, change) = match self.open_sink(target, meta.as_ref(), named, false) {
            Ok(mut sink) => {
                // Standard input is taken only now: the overwrite question
                // reads it first (probe: `printf 'y\nhello' | lz4 - e`
                // compresses `hello`).
                let mut src = src.unwrap_or_else(|| self.take_stdin());
                let stable = mapped && regular.is_some();
                let r = self.compress_from(name, &mut src, meta.as_ref(), stable, &mut sink);
                let change = match (regular, &r) {
                    // Standard input is never stat'ed by name (no file
                    // named `stdin` is looked at): never `replaced`.
                    (Some(before), Ok(_)) => {
                        let by_name = if named {
                            self.stat_name(name)
                        } else {
                            Some(before.clone())
                        };
                        source_change(before, src.fstat(), by_name)
                    }
                    _ => Change::default(),
                };
                self.put_back(name, src);
                (r, sink.fd.take(), change)
            }
            Err(f) => (Err(f), None, Change::default()),
        };
        let stats = r?;
        let kept = match verdict(change, mapped, self.cmd.opts.content_checksum) {
            Verdict::Fine => false,
            Verdict::Warn(fmt) => {
                let kept: &[u8] = if self.cmd.remove {
                    m::SOURCE_KEPT.as_bytes()
                } else {
                    b""
                };
                self.say(2, fmt, &[name, kept]);
                true
            }
            Verdict::Fail => {
                drop(fd);
                if let Target::File(out) = target {
                    let _ = fs::remove_file(self.host.path(out));
                }
                return Err(self.exm(54, m::E54_SOURCE_MODIFIED, &[name]));
            }
        };
        // probe (1.11.0): `lz4 -l a` gets `a`'s time and mode too (1.10.0
        // left the run's time and the default mode).
        Self::copy_metadata(target, meta.as_ref().filter(|_| named), fd.as_mut());
        drop(fd);
        self.total += stats.read;
        self.show_compress_summary(&stats);
        if !kept {
            self.remove_input(name, Op::Compress)?;
        }
        Ok(stats)
    }

    /// `name`'s metadata now, by name (following links, as the input was
    /// opened).
    fn stat_name(&self, name: &[u8]) -> Option<Metadata> {
        fs::metadata(self.host.path(name)).ok()
    }

    /// `stable`: the input is a mapped file (lz4 hands its last update to
    /// liblz4 as stable until the frame ends: `Encoder::end_of_input`).
    fn compress_from(
        &mut self,
        name: &[u8],
        src: &mut Src,
        meta: Option<&Metadata>,
        stable: bool,
        sink: &mut Sink,
    ) -> Result<Stats, Fail> {
        let mut opts = EncodeOptions {
            // probe: `cat big | lz4 --content-size -c` records no size, `lz4
            // --content-size big` and `lz4 --content-size < big` do: the size
            // of a regular file, standard input's included.
            content_size: meta
                .filter(|m| self.cmd.content_size && m.is_file())
                .map(Metadata::len),
            dictionary: self.dict.clone(),
            ..self
                .cmd
                .encode_options(matches!(self.host, Host::Sandbox(_)))
        };
        // lz4.1 (1.11.0), `-T#`: "no more threads than the jobs of each
        // file (1 MB, or a single block when larger)". probe (1.11.0,
        // `-vvvv -T1`/`-T3`): a file of one job and independent blocks is
        // compressed by the calling thread (its refresh is `--single-thread`'s:
        // 100,000 bytes `-B4` 43.30%, 1 MiB `-B4` 66.05%, 1 MiB `-B6`
        // 75.63%, also standard input redirected from such a file); 1 MiB
        // + 1 byte is two jobs, threaded (`0.00%`); linked blocks stay
        // threaded even in one job (100,000 bytes `-B4 -BD` `0.01%`), and a
        // pipe's size is unknown. Independent blocks are the same bytes
        // either way (§4).
        let job = (1usize << 20).max(opts.block_size_id().bytes());
        if let Some(len) = meta.filter(|m| m.is_file()).map(Metadata::len)
            && opts.workers > 0
            && !opts.block_linked
            && len <= job as u64
        {
            opts.workers = 0;
        }
        let legacy = opts.legacy;
        // probe: `lz4 -v --content-size - o < pipe`, `... /dev/null o`
        // (display level 3, once the output is open): a frame that was to
        // record the size of an input that has none. Not for a legacy frame
        // (no size field), nor for a regular file.
        if self.cmd.content_size && !legacy && opts.content_size.is_none() {
            self.say(3, m::CONTENT_SIZE_UNKNOWN, &[]);
        }
        let Ok(mut enc) = Encoder::new(&opts) else {
            return Err(self.exm(46, m::E46_WRITE_COMPRESSED, &[]));
        };
        if legacy {
            return self.compress_legacy(src, sink, &mut enc);
        }
        // lz4_opts: a frame's input is read one update at a time, 4 MiB or
        // a custom `-B#`'s size.
        let chunk = opts.update_size.unwrap_or(FRAME_CHUNK);
        let mut buf = vec![0u8; chunk];
        let mut packed = Vec::new();
        let mut stats = Stats::default();
        let mut first = true;
        // The progress figures (probe, 1.11.0: `lz4 -vvvv` over 1 MiB and 9
        // MiB + 123 bytes of text, threaded and `--single-thread`, `-B4`,
        // `-B6`, `-B7`, `-BD`; a custom `-B32` and `-B1024` over 4000 and
        // 20000 bytes): a streamed frame draws a refresh after each update,
        // over all the input read so far and every byte written so far, the
        // header included (`-B32`'s first is 43 of 32 bytes); threaded, that
        // is what liblz4's workers have handed back by then (`0.00%` for
        // the first 4 MiB here). The last update is compressed before its
        // refresh, the end mark and checksum after it. A one-shot frame
        // (shorter than a block) is drawn once complete, over all of it.
        // (1.10.0 drew each job over the input before it, blocks only.)
        let mut streamed = false;
        loop {
            let n = src.read_full(&mut buf);
            // probe: `lz4 -c <&-` (a frame).
            if n == 0 && first && src.reader.failed {
                return Err(self.exm(
                    40,
                    m::E40_FIRST_CHUNK,
                    &[chunk.to_string().as_bytes(), name],
                ));
            }
            first = false;
            if n == 0 {
                break;
            }
            stats.read += n as u64;
            if enc.update(&buf[..n], &mut packed).is_err()
                || (n < chunk && enc.end_of_input(&mut packed, stable).is_err())
            {
                return Err(self.exm(46, m::E46_WRITE_COMPRESSED, &[]));
            }
            sink.write(self, &packed)?;
            stats.written += packed.len() as u64;
            packed.clear();
            // The header is out once the frame is streamed.
            streamed |= stats.written > 0;
            if streamed {
                self.show_read_progress_at(stats.read, stats.written, false);
            }
            if n < chunk {
                break;
            }
        }
        if enc.finish(&mut packed).is_err() {
            return Err(self.exm(46, m::E46_WRITE_COMPRESSED, &[]));
        }
        sink.write(self, &packed)?;
        stats.written += packed.len() as u64;
        // probe: a one-shot frame (the empty one too: `lz4 e` says
        // `1500.00%`) draws one refresh once complete, over the whole input.
        if !streamed {
            self.show_read_progress_at(stats.read, stats.written, true);
        }
        sink.finish(self)?;
        Ok(stats)
    }

    /// `-l`: the legacy format, read 8 MiB at a time (one block each).
    /// probe (1.10.0, unchanged in 1.11.0): a refresh is drawn once a job's
    /// block is written, over the input read before that job; the figure
    /// counts everything written, the magic too; a last, partial job is
    /// drawn after `finish`, and an empty input draws none (`lz4 -l e`).
    fn compress_legacy(
        &mut self,
        src: &mut Src,
        sink: &mut Sink,
        enc: &mut Encoder,
    ) -> Result<Stats, Fail> {
        let chunk = LEGACY_BLOCK_SIZE;
        let mut buf = vec![0u8; chunk];
        let mut packed = Vec::new();
        let mut stats = Stats::default();
        let mut before = 0u64;
        let mut last_job = None;
        loop {
            // probe: `lz4 -l -c <&-` writes an empty legacy frame.
            let n = src.read_full(&mut buf);
            if n == 0 {
                break;
            }
            stats.read += n as u64;
            if enc.update(&buf[..n], &mut packed).is_err() {
                return Err(self.exm(46, m::E46_WRITE_COMPRESSED, &[]));
            }
            sink.write(self, &packed)?;
            stats.written += packed.len() as u64;
            packed.clear();
            if n == chunk {
                self.show_read_progress_at(before, stats.written, false);
            } else {
                last_job = Some(before);
            }
            before = stats.read;
            if n < chunk {
                break;
            }
        }
        if enc.finish(&mut packed).is_err() {
            return Err(self.exm(46, m::E46_WRITE_COMPRESSED, &[]));
        }
        sink.write(self, &packed)?;
        stats.written += packed.len() as u64;
        if let Some(before) = last_job {
            self.show_read_progress_at(before, stats.written, false);
        }
        sink.finish(self)?;
        Ok(stats)
    }

    // ---- decompression and test ----

    /// Decode `name` into `target` (`-t`: discarded, or standard output
    /// under `-m`). `Ok(false)` when undecodable data followed the frames
    /// (the input then counts as failed, though it was finished).
    fn decompress_one(&mut self, name: &[u8], target: &Target) -> Result<(Stats, bool), Fail> {
        // probe: the output is opened before the input is.
        let named = name != STDINMARK;
        let pre = if named {
            fs::metadata(self.host.path(name)).ok()
        } else {
            self.stdin_meta()
        };
        let mut sink = self.open_sink(target, pre.as_ref(), named, true)?;
        let (src, meta) = match self.open_input(name) {
            Ok(v) => v,
            Err(f) => {
                // probe (1.11.0): `lz4 -d u.lz4` with `u.lz4` unreadable
                // leaves an empty `u`, 0600, with the run's time (1.10.0
                // gave it `u.lz4`'s mode and time).
                let _ = sink.flush(self.out);
                return Err(f);
            }
        };
        let mut src = src.unwrap_or_else(|| self.take_stdin());
        // probe: `lz4 -dcf a`, `lz4cat a` copy what is no lz4 stream; `lz4
        // -df a y` and `lz4 -tf a` do not.
        let passthrough = self.cmd.force && *target == Target::Stdout;
        let r = decode::stream(self, &mut src, &mut sink, passthrough);
        self.put_back(name, src);
        let decoded = match r {
            Ok(d) => d,
            Err(f) => {
                // What was decoded before the fault stays (deviation list).
                let _ = sink.flush(self.out);
                return Err(f);
            }
        };
        sink.finish(self)?;
        let mut fd = sink.fd.take();
        drop(sink);
        let stats = Stats {
            read: decoded.read,
            written: decoded.written,
        };
        if !decoded.undecodable {
            Self::copy_metadata(target, meta.as_ref().filter(|_| named), fd.as_mut());
        }
        drop(fd);
        self.total += stats.written;
        self.show_decode_summary(name, &stats);
        if !decoded.undecodable {
            let op = if self.cmd.mode == cli::Mode::Test {
                Op::Test
            } else {
                Op::Decompress
            };
            self.remove_input(name, op)?;
        }
        Ok((stats, !decoded.undecodable))
    }
}

/// Standard output's descriptor as a file, for `--sparse`'s seeks.
fn stdout_file() -> Option<File> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        io::stdout()
            .as_fd()
            .try_clone_to_owned()
            .ok()
            .map(File::from)
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// The display level of a run: lz4 drops its default 2 to 1 when the
/// output is standard output or several inputs are named (probe: `lz4 -c
/// a`, `lz4 a -`, `lz4 -m a` print no summary; `lz4 -v -c a` (3) still
/// does; `lz4 -t a.lz4 -` discards and prints it).
fn run_level(cmd: &Command, plan: &Plan) -> i32 {
    if cmd.display_level == cli::DISPLAY_LEVEL_DEFAULT
        && (plan.target == Target::Stdout || cmd.multiple)
    {
        1
    } else {
        cmd.display_level
    }
}

/// Compress every input of `cmd` as `plan` says.
pub(crate) fn compress_files(
    cmd: &Command,
    plan: &Plan,
    host: &mut Host,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Ended {
    run_files(cmd, plan, host, out, err)
}

/// Decompress or test (`plan.op`) every input of `cmd` as `plan` says.
pub(crate) fn decompress_files(
    cmd: &Command,
    plan: &Plan,
    host: &mut Host,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Ended {
    run_files(cmd, plan, host, out, err)
}

fn run_files(
    cmd: &Command,
    plan: &Plan,
    host: &mut Host,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Ended {
    let mut run = Run::new(cmd, host, out, err, run_level(cmd, plan));
    match files(&mut run, plan) {
        Ok(failed) => Ended {
            code: i32::try_from(failed).unwrap_or(i32::MAX),
            pause: cmd.pause,
        },
        Err(code) => Ended { code, pause: false },
    }
}

/// The run's inputs in turn: the number that failed, or the `Error N` that
/// ended the run.
fn files(run: &mut Run, plan: &Plan) -> Result<usize, i32> {
    let cmd = run.cmd;
    let one = |run: &mut Run, name: &[u8], target: &Target| -> Result<bool, Fail> {
        match plan.op {
            Op::Compress => run.compress_one(name, target).map(|_| true),
            Op::Decompress | Op::Test => run.decompress_one(name, target).map(|(_, ok)| ok),
            // `--list` is `list.rs`'s (Task 5); `mod.rs` never sends it here.
            Op::List => Ok(false),
        }
    };
    // An input that failed counts; an `Error N` ends the run.
    let tally = |failed: &mut usize, r: Result<bool, Fail>| -> Result<(), i32> {
        match r {
            Ok(true) => Ok(()),
            Ok(false) | Err(Fail::File) => {
                *failed += 1;
                Ok(())
            }
            Err(Fail::Exit(code)) => Err(code),
        }
    };
    let mut failed = 0usize;
    // `Done in` follows every compression, every decode that had `-m`
    // operands, and (1.11.0) a single decode that succeeded (probe: `lz4 -v
    // -d a.lz4 o`, `-v -t a.lz4`, `-v -t -m` of standard input, `lz4 -v -d
    // -m a.lz4 nosuch.lz4` and `lz4cat -v a.lz4` say it; `lz4 -v -d
    // nosuch.lz4 o`, a declined overwrite, the same-file refusal and
    // undecodable trailing data say none, where 1.10.0 said it exactly
    // there); not when an `Error N` ended the run.
    let done = |run: &mut Run, failed: usize| {
        if plan.op == Op::Compress || cmd.from_list || failed == 0 {
            run.show_done();
        }
    };
    if !cmd.from_list {
        let name = cmd.inputs.first().map_or(STDINMARK, Vec::as_slice);
        if plan.derived
            && let Target::File(out_name) = &plan.target
        {
            let fmt = if plan.op == Op::Compress {
                m::COMPRESSED_FILENAME
            } else {
                m::DECODING_FILE
            };
            run.say(2, fmt, &[out_name]);
        }
        run.announce_run(plan, &[]);
        if let Err(Fail::Exit(code)) = run.load_dictionary() {
            return Err(code);
        }
        let r = one(run, name, &plan.target);
        tally(&mut failed, r)?;
        done(run, failed);
        return Ok(failed);
    }
    let names = run.expand(&cmd.inputs);
    run.announce_run(plan, &names);
    if let Err(Fail::Exit(code)) = run.load_dictionary() {
        return Err(code);
    }
    for name in names {
        // probe: `lz4 -m stdin e` writes both to standard output, `lz4 -m e
        // stdin` writes `e.lz4` and `stdin.lz4`: the plan made from the first
        // input says standard output for all.
        let target = if plan.target == Target::Stdout {
            Some(Target::Stdout)
        } else {
            cli::list_target(cmd, plan.op, &name)
        };
        let Some(target) = target else {
            run.say(1, m::EXTENSION_MISMATCH, &[&name]);
            failed += 1;
            continue;
        };
        let r = one(run, &name, &target);
        tally(&mut failed, r)?;
    }
    done(run, failed);
    Ok(failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The §1.13 table of the 2026-11-08 probe (lz4 1.11.0), row by row:
    /// mapped with the checksum, mapped without it, and read.
    #[test]
    fn a_changed_source_is_a_warning_or_error_54() {
        let c = |modified, shrunk, replaced| Change {
            modified,
            shrunk,
            replaced,
        };
        let warn = Verdict::Warn(m::SOURCE_MODIFIED);
        let renamed = Verdict::Warn(m::SOURCE_REPLACED);
        let fine = Verdict::Fine;
        let fail = Verdict::Fail;
        for (change, mapped_crc, mapped_no_crc, read) in [
            (c(false, false, false), fine, fine, fine),
            (c(true, false, false), warn, fail, warn),
            (c(true, true, false), fail, fail, warn),
            // A rename within the second: only the name says so.
            (c(false, false, true), renamed, renamed, renamed),
            // From another second the file's status-change time moved.
            (c(true, false, true), renamed, fail, renamed),
        ] {
            assert_eq!(verdict(change, true, true), mapped_crc, "{change:?}");
            assert_eq!(verdict(change, true, false), mapped_no_crc, "{change:?}");
            assert_eq!(verdict(change, false, true), read, "{change:?}");
            assert_eq!(verdict(change, false, false), read, "{change:?}");
        }
    }

    /// What `source_change` sees: size, seconds of the modification and
    /// status-change times, and the name's file.
    #[test]
    fn a_source_change_is_seen_by_size_time_and_identity() {
        let dir = std::env::temp_dir().join(format!("stuffr-lz4-change-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let f = dir.join("f");
        fs::write(&f, b"0123456789").unwrap();
        let open = File::open(&f).unwrap();
        let before = open.metadata().unwrap();
        let now = || (open.metadata().ok(), fs::metadata(&f).ok());
        let ch = |modified, shrunk, replaced| Change {
            modified,
            shrunk,
            replaced,
        };
        let (a, b) = now();
        assert_eq!(source_change(&before, a, b), Change::default());
        fs::OpenOptions::new()
            .append(true)
            .open(&f)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        let (a, b) = now();
        assert_eq!(source_change(&before, a, b), ch(true, false, false));
        File::create(&f).unwrap().write_all(b"0123").unwrap();
        let (a, b) = now();
        assert_eq!(source_change(&before, a, b), ch(true, true, false));
        let old = fs::FileTimes::new()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000));
        let g = dir.join("g");
        fs::write(&g, b"0123456789").unwrap();
        let open_g = File::open(&g).unwrap();
        let before_g = open_g.metadata().unwrap();
        File::options()
            .write(true)
            .open(&g)
            .unwrap()
            .set_times(old)
            .unwrap();
        assert_eq!(
            source_change(&before_g, open_g.metadata().ok(), fs::metadata(&g).ok()),
            ch(true, false, false)
        );
        // A rename alone: the name, and the file's own status change only
        // once a second has passed (not tested: it would take one).
        let h = dir.join("h");
        fs::write(&h, b"0123456789").unwrap();
        let open_h = File::open(&h).unwrap();
        let before_h = open_h.metadata().unwrap();
        fs::rename(&h, dir.join("h.old")).unwrap();
        let c = source_change(&before_h, open_h.metadata().ok(), fs::metadata(&h).ok());
        assert!(c.replaced && !c.shrunk, "{c:?}");
        fs::rename(&f, dir.join("f.old")).unwrap();
        fs::write(&f, b"new").unwrap();
        let (a, b) = now();
        assert!(source_change(&before, a, b).replaced);
        fs::remove_file(&f).unwrap();
        let (a, b) = now();
        assert!(source_change(&before, a, b).replaced);
        // Standard input is judged by its descriptor alone (`by_name` is
        // its own `before`): its name gone or replaced is never seen, its
        // file appended to is.
        let c = source_change(&before, open.metadata().ok(), Some(before.clone()));
        assert!(!c.replaced && c.modified, "{c:?}");
        assert_eq!(verdict(c, false, false), Verdict::Warn(m::SOURCE_MODIFIED));
        let _ = fs::remove_dir_all(&dir);
    }

    /// lz4 1.11.0 (probe §1.11): an output whose input is a named regular
    /// file, a frame, a legacy frame or a decode, is created 0600 (its mode
    /// comes once the input succeeded, through its descriptor); from
    /// standard input (`None`), a FIFO or a directory, 0666 less the umask.
    #[test]
    fn an_output_of_a_regular_file_is_created_owner_only() {
        let dir = std::env::temp_dir().join(format!("stuffr-lz4-mode-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("a");
        fs::write(&file, b"x").unwrap();
        let reg = fs::metadata(&file).unwrap();
        let dirm = fs::metadata(&dir).unwrap();
        assert_eq!(output_mode(Some(&reg)), 0o600);
        assert_eq!(output_mode(None), 0o666);
        assert_eq!(output_mode(Some(&dirm)), 0o666);
        let _ = fs::remove_dir_all(&dir);
    }
}
