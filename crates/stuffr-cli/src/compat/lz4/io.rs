//! Compressing, decompressing and testing over files and streams: every
//! rule of what is opened, in which order, what is asked, what is kept and
//! what the run's exit code becomes. The stream decoder itself (the magic
//! numbers, legacy and skippable frames, trailing data) is in `decode.rs`.
//!
//! **Clean room.** Every rule here was recovered from the man page
//! (`lz4.1`), `lz4 -H` and probes of the 1.10.0 binary (Task 2's and Task
//! 4's tables in `.claude/rules/compat.md`, "lz4 1.10.0 probes"); lz4's
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
//!   the partial output, as lz4 does. A finished file output gets the
//!   input's modification time and permission bits (and owner where
//!   allowed); its access time is the run's.
//! - **An existing output** is asked about at display level 2 and up (the
//!   answer read from standard input, terminal or not: R11; `y` or `Y`
//!   first, the rest of the line consumed); below it, refused with a line
//!   printed at every level. `-f` opens it over. An output that is the
//!   input itself is never opened (spec deviation 3).
//! - **The exit code** is the number of inputs that failed (`lz4 -m a n1 n2
//!   n3 e` exits 3); an `Error N` ends the run at once with N, and the
//!   hidden `-p` pauses only after a run that was not ended that way.
//! - **Display level 2 drops to 1** when the output is standard output or
//!   several inputs are named (`lz4 -c a`, `lz4 -m a` print no summary;
//!   `lz4 -t a.lz4 -` does, its output being discarded).
//! - **`--rm`** removes an input once it was processed (also after `-t`,
//!   `-c`, and a decode that met undecodable trailing data); standard input
//!   is removed by its name, `stdin`, as lz4 does: a file named `stdin` in
//!   the working directory is deleted (probe: `lz4 -c --rm < a` with a file
//!   `stdin` present), and with none it is `Error 50`.
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

use stuffr::lz4_opts::{
    EncodeOptions, Encoder, FRAME_CHUNK, LEGACY_BLOCK_SIZE, parse_frame_header,
};

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

/// probe: `lz4 -r d` with a symlink loop inside is lz4's own business; a
/// walk deeper than this stops. The cap bounds depth only: two symlinks to
/// `.` still give exponentially many paths, and `lz4 -r` then runs
/// effectively forever, as the reference does.
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
}

impl Reader {
    /// One read; an error ends the input, as a short read does (probe: `lz4
    /// -dc <&-` decodes nothing, exit 0), and is remembered in `failed`.
    fn read(&mut self, buf: &mut [u8]) -> usize {
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

    /// Seek `n` bytes on, where the origin can.
    fn seek_on(&mut self, n: u64) -> io::Result<u64> {
        let off = i64::try_from(n).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        match &mut self.origin {
            Origin::File(f) => f.seek(SeekFrom::Current(off)),
            Origin::Stdin(f) => f.seek(SeekFrom::Current(off)),
            Origin::Stream(_) => Err(io::Error::from(io::ErrorKind::Unsupported)),
        }
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

    /// Pass over `n` bytes: a seek on a file (past its end is no error:
    /// probe `lz4 -t skip_trunc.lz4` exits 0), reading them elsewhere.
    /// `false` when a stream ends first (probe: `cat skip_trunc.lz4 | lz4
    /// -dc` is `Error 43`).
    pub(super) fn skip(&mut self, n: u64) -> bool {
        let buffered = (self.buf.len() - self.at) as u64;
        if n <= buffered {
            self.consume(n as usize);
            return true;
        }
        let rest = n - buffered;
        self.consume(buffered as usize);
        if self.seekable && self.reader.seek_on(rest).is_ok() {
            self.taken += rest;
            return true;
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
    /// The error a failed write ends the run with (`Error 38` compressing,
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

/// The mode a new output file is created with (deviation 10, HOST-4):
/// 0600 when it will be given the input's mode at the end (from a regular
/// file, a frame or a decode; legacy compression keeps lz4's default), else
/// lz4's 0666 less the umask.
fn output_mode(input: Option<&Metadata>, decoding: bool, legacy: bool) -> u32 {
    if input.is_some_and(Metadata::is_file) && (decoding || !legacy) {
        0o600
    } else {
        0o666
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
            // Spec deviation 3: the input is never opened over.
            if let Some(i) = input
                && let Ok(existing) = fs::metadata(&path)
                && host::same_file(i, &existing) == Some(true)
            {
                printf(self.err, m::SAME_FILE, &[name]);
                return Err(Fail::File);
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

    /// The sink for `target`. `input` is the input's metadata (deviation
    /// 3); `decoding` selects sparse writing and the write error.
    fn open_sink(
        &mut self,
        target: &Target,
        input: Option<&Metadata>,
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
            (m::E38_WRITE_COMPRESSED, 38)
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
                let mode = output_mode(input, decoding, self.cmd.opts.legacy);
                let (f, fresh) = self.open_output(name, input, mode)?;
                #[cfg(unix)]
                let input_mode = {
                    use std::os::unix::fs::PermissionsExt;
                    input.map(|m| m.permissions().mode())
                };
                #[cfg(not(unix))]
                let input_mode = None;
                fd = host::OutFd::new(&f, fresh && mode == 0o600, input_mode);
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
    /// a o` over an existing `o`): the input's modification time,
    /// permission bits and owner (a refused `chown` is ignored); the
    /// access time is left as the run made it. Only for a file read from a
    /// file. Failures are ignored, as lz4 reports none. Set through the
    /// output's own descriptor `fd` (HOST-8), never by name.
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

    /// `--rm`: remove the input once processed (probe: `lz4 -c --rm < a`
    /// removes the name `stdin`, `Error 50` when there is none).
    fn remove_input(&mut self, name: &[u8]) -> Result<(), Fail> {
        if !self.cmd.remove {
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
    /// directory's files where it stands, symbolic links followed; the
    /// list is made before anything is written, so new outputs are not
    /// inputs). Where that finds no file at all, the names stand as they
    /// were given (probe: `lz4 -m -r e1 e2` over two empty directories says
    /// `e1 is a directory -- ignored` for each, exit 2; `--list -r e1` says
    /// `e1 is not a regular file`; with another file named, an empty
    /// directory vanishes: `--list -r e1 plain.lz4` lists `plain.lz4`).
    pub(super) fn expand(&self, names: &[Vec<u8>]) -> Vec<Vec<u8>> {
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

    fn walk(&self, dir: &[u8], depth: usize, out: &mut Vec<Vec<u8>>) {
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
            if fs::metadata(self.host.path(&child)).is_ok_and(|m| m.is_dir()) {
                self.walk(&child, depth + 1, out);
            } else {
                out.push(child);
            }
        }
    }

    // ---- compression ----

    /// Compress `name` into `target`.
    fn compress_one(&mut self, name: &[u8], target: &Target) -> Result<Stats, Fail> {
        let (src, meta) = self.open_input(name)?;
        let (r, mut fd) = match self.open_sink(target, meta.as_ref(), false) {
            Ok(mut sink) => {
                // Standard input is taken only now: the overwrite question
                // reads it first (probe: `printf 'y\nhello' | lz4 - e`
                // compresses `hello`).
                let mut src = src.unwrap_or_else(|| self.take_stdin());
                let r = self.compress_from(name, &mut src, meta.as_ref(), &mut sink);
                self.put_back(name, src);
                (r, sink.fd.take())
            }
            Err(f) => (Err(f), None),
        };
        let stats = r?;
        // probe: `lz4 -l a` leaves `a.lz4` with the run's time and the
        // default mode; a frame gets the input's.
        if !self.cmd.opts.legacy {
            Self::copy_metadata(target, meta.as_ref(), fd.as_mut());
        }
        drop(fd);
        self.total += stats.read;
        self.show_compress_summary(&stats);
        self.remove_input(name)?;
        Ok(stats)
    }

    fn compress_from(
        &mut self,
        name: &[u8],
        src: &mut Src,
        meta: Option<&Metadata>,
        sink: &mut Sink,
    ) -> Result<Stats, Fail> {
        let opts = EncodeOptions {
            // probe: `cat big | lz4 --content-size -c` records no size, `lz4
            // --content-size big` and `lz4 --content-size < big` do: the size
            // of a regular file, standard input's included.
            content_size: meta
                .filter(|m| self.cmd.content_size && m.is_file())
                .map(Metadata::len),
            dictionary: self.dict.clone(),
            ..self.cmd.opts.clone()
        };
        let legacy = opts.legacy;
        // probe: `lz4 -v --content-size - o < pipe`, `... /dev/null o`
        // (display level 3, once the output is open): a frame that was to
        // record the size of an input that has none. Not for a legacy frame
        // (no size field), nor for a regular file.
        if self.cmd.content_size && !legacy && opts.content_size.is_none() {
            self.say(3, m::CONTENT_SIZE_UNKNOWN, &[]);
        }
        let Ok(mut enc) = Encoder::new(&opts) else {
            return Err(self.exm(38, m::E38_WRITE_COMPRESSED, &[]));
        };
        // lz4_opts: a frame's input is read 4 MiB at a time, a legacy
        // frame's 8 MiB (one block each).
        let chunk = if legacy {
            LEGACY_BLOCK_SIZE
        } else {
            FRAME_CHUNK
        };
        let mut buf = vec![0u8; chunk];
        let mut packed = Vec::new();
        let mut stats = Stats::default();
        let mut first = true;
        // The progress figures (probe: `lz4 -T1 -vvvv` over generated text
        // of 2, 4, 4 MiB + 1, 8, 8 MiB + 1 and 9 MiB, `-l`, `-BD`,
        // `--content-size` and `--no-frame-crc`, a job's size swept byte by
        // byte across a rounding boundary of its ratio): a refresh is drawn
        // once a job's blocks are written, over the input read before that
        // job (`0 MiB ==> inf%` first). A streamed frame's figure counts its
        // blocks only, neither its header nor its end mark and checksum; a
        // legacy frame's counts everything, the magic too; a one-shot frame
        // (input under 4 MiB) is drawn once complete, over all of it.
        let mut before = 0u64;
        // The frame is streamed in jobs (it had a whole job of input).
        let mut streamed = false;
        // A streamed frame's header, and its end mark and checksum.
        let (mut header, mut trailer) = (0u64, 0u64);
        // A last, partial job of a streamed or legacy frame: the encoder
        // writes its blocks only in `finish`, so it is drawn after that.
        let mut last_job = None;
        loop {
            let n = src.read_full(&mut buf);
            // probe: `lz4 -c <&-` (a frame; `lz4 -l -c <&-` writes an empty
            // legacy frame instead).
            if n == 0 && first && !legacy && src.reader.failed {
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
            if enc.update(&buf[..n], &mut packed).is_err() {
                return Err(self.exm(38, m::E38_WRITE_COMPRESSED, &[]));
            }
            sink.write(self, &packed)?;
            stats.written += packed.len() as u64;
            if !legacy && !streamed && n == chunk {
                streamed = true;
                // The first job's output opens with the header.
                let parsed = parse_frame_header(&packed);
                debug_assert!(
                    matches!(parsed, Ok(Some(_))),
                    "the first job of a streamed frame opens with its header"
                );
                if let Ok(Some(h)) = parsed {
                    header = h.header_len as u64;
                    trailer = if h.content_checksum { 8 } else { 4 };
                }
            }
            packed.clear();
            if legacy || streamed {
                if n == chunk {
                    let blocks = stats.written.saturating_sub(header);
                    self.show_read_progress_at(before, blocks, false);
                } else {
                    last_job = Some(before);
                }
            }
            before = stats.read;
            if n < chunk {
                break;
            }
        }
        if enc.finish(&mut packed).is_err() {
            return Err(self.exm(38, m::E38_WRITE_COMPRESSED, &[]));
        }
        sink.write(self, &packed)?;
        stats.written += packed.len() as u64;
        // probe: a one-shot frame (input under 4 MiB, the empty one too:
        // `lz4 e` says `1500.00%`) draws one refresh once complete, over the
        // whole input; a legacy frame only per job it compressed (`lz4 -l e`
        // shows none).
        if let Some(before) = last_job {
            let blocks = stats.written.saturating_sub(header + trailer);
            self.show_read_progress_at(before, blocks, false);
        } else if !legacy && !streamed {
            self.show_read_progress_at(stats.read, stats.written, true);
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
        let pre = if name == STDINMARK {
            self.stdin_meta()
        } else {
            fs::metadata(self.host.path(name)).ok()
        };
        let mut sink = self.open_sink(target, pre.as_ref(), true)?;
        let (src, meta) = match self.open_input(name) {
            Ok(v) => v,
            Err(f) => {
                // probe: `lz4 -d u.lz4` with `u.lz4` unreadable leaves an
                // empty `u` with `u.lz4`'s mode and time (a directory's are
                // not copied: `lz4 -d -f dd.lz4 o`).
                let _ = sink.flush(self.out);
                Self::copy_metadata(target, pre.as_ref(), sink.fd.as_mut());
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
        Self::copy_metadata(target, meta.as_ref(), fd.as_mut());
        drop(fd);
        self.total += stats.written;
        self.show_decode_summary(name, &stats);
        self.remove_input(name)?;
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
    // `Done in` follows every compression and every decode that had `-m`
    // operands or an input that failed (probe: `lz4 -v -d a.lz4 o` says
    // none, `lz4 -v -d -m a.lz4`, `lz4 -v -d nosuch.lz4 o` and `lz4cat -v
    // a.lz4` say it; `-dm -`, which lists no operand, says none); not when
    // an `Error N` ended the run.
    let done = |run: &mut Run, failed: usize| {
        if plan.op == Op::Compress || cmd.from_list || failed > 0 {
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

    /// Deviation 10: a frame or a decode from a regular file is created
    /// 0600 (its mode comes at the end, through its descriptor); from
    /// standard input, a FIFO, or legacy compression, lz4's 0666.
    #[test]
    fn a_frame_from_a_regular_file_is_created_owner_only() {
        let dir = std::env::temp_dir().join(format!("stuffr-lz4-mode-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("a");
        fs::write(&file, b"x").unwrap();
        let reg = fs::metadata(&file).unwrap();
        let dirm = fs::metadata(&dir).unwrap();
        assert_eq!(output_mode(Some(&reg), false, false), 0o600);
        assert_eq!(output_mode(Some(&reg), true, false), 0o600);
        assert_eq!(output_mode(Some(&reg), true, true), 0o600);
        assert_eq!(output_mode(Some(&reg), false, true), 0o666);
        assert_eq!(output_mode(None, false, false), 0o666);
        assert_eq!(output_mode(Some(&dirm), true, false), 0o666);
        let _ = fs::remove_dir_all(&dir);
    }
}
