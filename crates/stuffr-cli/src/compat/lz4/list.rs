//! `--list`: what lz4 1.10.0 prints about the frames in each file, without
//! decoding any of them.
//!
//! **Clean room.** Every rule below was recovered by probing the 1.10.0
//! binary with hand-made files (the cases are in `.claude/rules/compat.md`,
//! "lz4 1.10.0 probes", and in `tests/compat_lz4.rs`); lz4's `programs/` was
//! never read. Messages are in `messages.rs`.
//!
//! **What it does** (all probed):
//! - Only regular files are listed (`stat`, so a symbolic link to one is);
//!   a name that is none (missing, a directory, `/dev/null`) is `lz4: NAME
//!   is not a regular file` and ends the run with exit 1, as does the first
//!   file that fails any other way: **the files after it are not read**.
//!   Standard input given as no operand, or as `-`, lists nothing: only the
//!   table header is printed. The operand `stdin` is standard input as a
//!   file: listed (as `stdin`, from its current offset) when it is
//!   redirected from a regular file, "not a regular file" when it is a pipe
//!   or a device (a file of that name is never read). `-r` expands directories as
//!   it does for compression ([`Run::expand`]); display names are the base
//!   name (after the last `/`), error messages carry the name as given.
//! - A **walker** reads frame after frame and never decodes: a modern frame
//!   is its header (checked as liblz4 checks it) and its block-size words
//!   (the top bit is the "stored" flag; a word of 0, with or without it, is
//!   the end mark), seeking over each block and block checksum, over the
//!   content checksum after the end mark; a legacy frame is a run of
//!   block-size words (at most 8 MiB each) up to a word that is a magic
//!   number or the end of the file; a skippable frame is its size word and
//!   that many bytes. A seek past the end of the file is no error: the next
//!   read finds nothing and the file ends. Memory is a 64 KiB window and a
//!   few counters whatever the input, and a seek only ever moves forward, so
//!   a hostile size (a skippable frame of 4 GiB, a block of 2 GiB) costs
//!   one seek.
//! - A frame's **size** is the distance the walker moved (not clamped to the
//!   file: a block cut short still counts as long as it said); a skippable
//!   frame's is `size + 8` in 32 bits (probe: size `0xFFFFFFFF` says 7).
//!   The content size in a header counts only when it is not 0 (probe: a
//!   header saying 0 lists as `-`).
//! - **Failures**, in the order they are met (probed with every prefix of a
//!   frame: `tests/compat_lz4.rs`, the `--list` cut rows):
//!   - no byte where a magic number belongs ends the file (an empty file is
//!     not recognized); one to three are `Error 40`;
//!   - an unknown magic number is not recognized, with a line first at
//!     display level 3 (`Stream followed by undecodable data at position N`,
//!     also when it is the file's first);
//!   - a frame's magic number alone is `Error 71`; with a header cut after
//!     one to three bytes, `Error 72` when its flags promise a content size
//!     and not recognized when not; a header cut anywhere else, a header
//!     liblz4 refuses, a header carrying a dictionary ID but no content size
//!     (liblz4 accepts it; lz4 does not), and a header with no byte at all
//!     after it are not recognized;
//!   - a legacy frame with no block, or with a word cut short or too large,
//!     is not recognized, with `Corrupted legacy frame` first for the last
//!     two; a skippable magic number with its size cut is `Error 42`.
//! - The block-size word is read into a 4-byte buffer the walker keeps: a
//!   word cut short by the end of the file is completed from what the
//!   buffer held, which is the frame's previous block-size word (zero at
//!   the first block). lz4's buffer is the same until a frame has come
//!   before; then it holds garbage the reference does not even repeat
//!   (probe: `frame + frame header + 1 byte`), so only the **-v frame size
//!   of a file cut inside a block-size word** can differ (deviation 8).
//! - The table: without `-v` one row per file after a header printed once
//!   (compressed = the file's size, not the frames'); with display level 3
//!   and up (`-v`) a `name(i/n)` line and one row per frame as it is met,
//!   then a blank line if the file went through. A file that failed leaves
//!   what was printed and, without `-v`, prints no row. `-q` and `-qq` do
//!   not touch the tables (standard output); they silence the errors
//!   (level 1 and 0).

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};

use stuffr::lz4_opts::{
    LEGACY_BLOCK_SIZE, LEGACY_MAGIC, MAGIC, is_skippable_magic, parse_frame_header,
};

use super::cli::{Command, STDINMARK};
use super::io::{Ended, Fail, Run};
use super::messages::{self as m, printf};
use crate::compat::host::{self, Host};

/// Where a file's bytes come from: a file, or standard input redirected
/// from one.
trait Input: Read + Seek {}
impl<T: Read + Seek> Input for T {}

/// The window the walker reads through.
const WINDOW: usize = 64 << 10;

/// The header bytes after the magic number the walker needs to see: the
/// largest header (19 bytes) less the magic, and one byte more (a header
/// with nothing after it is not recognized).
const PEEK: usize = 16;

/// What a frame is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Frame,
    Legacy,
    Skippable,
}

/// One frame, as listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FrameInfo {
    kind: Kind,
    /// The distance the walker moved (module doc).
    size: u64,
    /// A modern frame's block size ID and `linked` flag.
    block: Option<(u8, bool)>,
    /// A modern frame has a content checksum.
    checksum: bool,
    /// A modern frame's content size, 0 when unknown.
    content: u64,
}

/// Why a walk stopped before the end of the file (module doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    NotRecognized,
    CorruptLegacy,
    /// Bytes that are no frame; the position past the magic number's four
    /// bytes.
    Trailing(u64),
    /// Error 40.
    MagicUnreadable,
    /// Error 42.
    SkipSize,
    /// Error 71.
    MagicOnly,
    /// Error 72.
    HeaderCut,
}

/// A file read through a window at absolute positions.
struct Window<R> {
    r: R,
    /// Where the file's position 0 is in `r` (standard input redirected
    /// from a file may start anywhere: probe `lz4 --list stdin`).
    base: u64,
    buf: Vec<u8>,
    start: u64,
}

impl<R: Read + Seek> Window<R> {
    fn new(mut r: R) -> Window<R> {
        let base = r.stream_position().unwrap_or(0);
        Window {
            r,
            base,
            buf: Vec::new(),
            start: 0,
        }
    }

    /// Read up to `out.len()` bytes at `pos`: short only at the end of the
    /// file (a read error ends it too, as lz4 sees end of file).
    fn read_at(&mut self, pos: u64, out: &mut [u8]) -> usize {
        let mut n = 0;
        while n < out.len() {
            let p = pos.saturating_add(n as u64);
            if p >= self.start && p - self.start < self.buf.len() as u64 {
                let off = (p - self.start) as usize;
                let k = (self.buf.len() - off).min(out.len() - n);
                out[n..n + k].copy_from_slice(&self.buf[off..off + k]);
                n += k;
            } else if !self.fill(p) {
                break;
            }
        }
        n
    }

    /// Load the window at `p`; `false` at or past the end of the file.
    fn fill(&mut self, p: u64) -> bool {
        self.buf.clear();
        if self
            .r
            .seek(SeekFrom::Start(self.base.saturating_add(p)))
            .is_err()
        {
            return false;
        }
        self.buf.resize(WINDOW, 0);
        loop {
            match self.r.read(&mut self.buf) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Ok(0) | Err(_) => {
                    self.buf.clear();
                    return false;
                }
                Ok(k) => {
                    self.buf.truncate(k);
                    self.start = p;
                    return true;
                }
            }
        }
    }
}

/// The walker over one file.
struct Walker<R> {
    win: Window<R>,
    /// Where the next frame's magic number is.
    pos: u64,
    /// The block-size word buffer (module doc).
    word: [u8; 4],
    frames: u64,
}

impl<R: Read + Seek> Walker<R> {
    fn new(r: R) -> Walker<R> {
        Walker {
            win: Window::new(r),
            pos: 0,
            word: [0; 4],
            frames: 0,
        }
    }

    /// The next frame; `None` at the end of the file.
    fn next_frame(&mut self) -> Result<Option<FrameInfo>, Stop> {
        let start = self.pos;
        let mut magic = [0u8; 4];
        match self.win.read_at(start, &mut magic) {
            0 if self.frames == 0 => return Err(Stop::NotRecognized),
            0 => return Ok(None),
            4 => {}
            _ => return Err(Stop::MagicUnreadable),
        }
        let value = u32::from_le_bytes(magic);
        let info = if value == MAGIC {
            self.modern(start, magic)?
        } else if value == LEGACY_MAGIC {
            self.legacy(start)?
        } else if is_skippable_magic(value) {
            self.skippable(start)?
        } else {
            // probe: `lz4 --list -v notlz4` says it at position 4, as it
            // does after a frame.
            return Err(Stop::Trailing(start + 4));
        };
        self.frames += 1;
        Ok(Some(info))
    }

    /// A modern frame whose magic number is at `start`.
    fn modern(&mut self, start: u64, magic: [u8; 4]) -> Result<FrameInfo, Stop> {
        let mut head = [0u8; PEEK];
        let k = self.win.read_at(start + 4, &mut head);
        if k == 0 {
            return Err(Stop::MagicOnly);
        }
        let content_size = head[0] & 8 != 0;
        let dictionary = head[0] & 1 != 0;
        if k < 4 {
            return Err(if content_size {
                Stop::HeaderCut
            } else {
                Stop::NotRecognized
            });
        }
        // probe: a dictionary ID without a content size is never listed.
        if dictionary && !content_size {
            return Err(Stop::NotRecognized);
        }
        // The bytes after the magic number: FLG, BD, the fields, HC.
        let after = 3 + if content_size { 8 } else { 0 } + if dictionary { 4 } else { 0 };
        // probe: the header must be followed by at least one byte.
        if k <= after {
            return Err(Stop::NotRecognized);
        }
        let mut full = [0u8; 4 + PEEK];
        full[..4].copy_from_slice(&magic);
        full[4..4 + after].copy_from_slice(&head[..after]);
        let Ok(Some(h)) = parse_frame_header(&full[..4 + after]) else {
            return Err(Stop::NotRecognized);
        };
        let mut p = start + h.header_len as u64;
        let mut first = true;
        loop {
            let mut w = [0u8; 4];
            let n = self.win.read_at(p, &mut w);
            if n == 0 {
                // probe: a frame with no word at all is not recognized; a
                // later word missing just ends the frame.
                if first {
                    return Err(Stop::NotRecognized);
                }
                break;
            }
            // probe: a word cut short keeps the rest of the last (module
            // doc).
            self.word[..n].copy_from_slice(&w[..n]);
            p += 4;
            first = false;
            let size = u64::from(u32::from_le_bytes(self.word) & 0x7FFF_FFFF);
            if size == 0 {
                if h.content_checksum {
                    p += 4;
                }
                break;
            }
            p += size + if h.block_checksum { 4 } else { 0 };
        }
        self.pos = p;
        Ok(FrameInfo {
            kind: Kind::Frame,
            size: p - start,
            block: Some((h.block_size.id(), h.block_linked)),
            checksum: h.content_checksum,
            // probe: a content size of 0 lists as unknown.
            content: h.content_size.unwrap_or(0),
        })
    }

    /// A legacy frame whose magic number is at `start`.
    fn legacy(&mut self, start: u64) -> Result<FrameInfo, Stop> {
        let mut p = start + 4;
        let mut first = true;
        loop {
            let mut w = [0u8; 4];
            let n = self.win.read_at(p, &mut w);
            if n == 0 {
                if first {
                    return Err(Stop::NotRecognized);
                }
                break;
            }
            if n < 4 {
                return Err(Stop::CorruptLegacy);
            }
            let v = u32::from_le_bytes(w);
            if v == MAGIC || v == LEGACY_MAGIC || is_skippable_magic(v) {
                if first {
                    return Err(Stop::NotRecognized);
                }
                break;
            }
            if v as usize > LEGACY_BLOCK_SIZE {
                return Err(Stop::CorruptLegacy);
            }
            p += 4 + u64::from(v);
            first = false;
        }
        self.pos = p;
        Ok(FrameInfo {
            kind: Kind::Legacy,
            size: p - start,
            block: None,
            checksum: false,
            content: 0,
        })
    }

    /// A skippable frame whose magic number is at `start`.
    fn skippable(&mut self, start: u64) -> Result<FrameInfo, Stop> {
        let mut w = [0u8; 4];
        if self.win.read_at(start + 4, &mut w) < 4 {
            return Err(Stop::SkipSize);
        }
        let size = u32::from_le_bytes(w);
        self.pos = start + 8 + u64::from(size);
        Ok(FrameInfo {
            kind: Kind::Skippable,
            // probe: `size + 8` in 32 bits.
            size: u64::from(size.wrapping_add(8)),
            block: None,
            checksum: false,
            content: 0,
        })
    }
}

/// What a file's table row says, built frame by frame.
#[derive(Debug, Default)]
struct Totals {
    count: u64,
    /// The first frame's kind, and whether all are that kind.
    kind: Option<Kind>,
    kind_same: bool,
    /// The first frame's block cell source, and whether all are the same.
    block: Option<Option<(u8, bool)>>,
    block_same: bool,
    /// Every frame is modern and says its content size.
    known: bool,
    /// The sum of the content sizes, wrapping (probe: two frames of
    /// 2^63 sum to 0 and list as `0.00`, ratio `inf`).
    content: u64,
}

impl Totals {
    fn new() -> Totals {
        Totals {
            kind_same: true,
            block_same: true,
            known: true,
            ..Totals::default()
        }
    }

    fn add(&mut self, f: &FrameInfo) {
        self.count += 1;
        match self.kind {
            None => self.kind = Some(f.kind),
            Some(k) => self.kind_same &= k == f.kind,
        }
        match self.block {
            None => self.block = Some(f.block),
            Some(b) => self.block_same &= b == f.block,
        }
        self.known &= f.kind == Kind::Frame && f.content != 0;
        self.content = self.content.wrapping_add(f.content);
    }
}

/// `s` right-aligned in `width` columns.
fn pad(s: &str, width: usize) -> Vec<u8> {
    format!("{s:>width$}").into_bytes()
}

/// The type cell.
fn kind_cell(k: Kind) -> &'static str {
    match k {
        Kind::Frame => m::TYPE_FRAME,
        Kind::Legacy => m::TYPE_LEGACY,
        Kind::Skippable => m::TYPE_SKIPPABLE,
    }
}

/// The block cell: `B7I`, or `-`.
fn block_cell(b: Option<(u8, bool)>) -> String {
    match b {
        Some((id, linked)) => format!(
            "{}{id}{}",
            m::BLOCK_PREFIX,
            if linked {
                m::BLOCK_LINKED
            } else {
                m::BLOCK_INDEPENDENT
            }
        ),
        None => m::CELL_NONE.to_string(),
    }
}

/// A size as the compact table shows it (probe: `28.00`, `1.00K`,
/// `1024.00K` for 1 MiB less one byte, `38.15M`, up to `16.00E`): `%.2f`
/// of the size divided by 1024 as often as it takes to get below 1024,
/// and the unit of that many divisions (none below 1 KiB).
fn size_cell(n: u64) -> String {
    const UNITS: [&str; 7] = ["", "K", "M", "G", "T", "P", "E"];
    let mut v = n as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit + 1 < UNITS.len() {
        v /= 1024.0;
        unit += 1;
    }
    format!("{v:.2}{}", UNITS[unit])
}

/// `part / whole * 100` as `%.2f` (probe: `100.23`; a whole of 0 is
/// `inf`).
fn ratio_cell(part: u64, whole: u64) -> String {
    format!("{:.2}", part as f64 / whole as f64 * 100.0)
}

/// The base name: after the last `/`.
fn base_name(name: &[u8]) -> &[u8] {
    name.iter()
        .rposition(|&b| b == b'/')
        .map_or(name, |i| &name[i + 1..])
}

/// The per-frame row of `--list -v`.
fn print_frame_row(run: &mut Run, index: u64, f: &FrameInfo) {
    let index = pad(&index.to_string(), 10);
    let kind = pad(kind_cell(f.kind), 14);
    let block = pad(&block_cell(f.block), 5);
    let checksum = pad(
        if f.checksum {
            m::CHECKSUM_XXH32
        } else {
            m::CELL_NONE
        },
        8,
    );
    let size = pad(&f.size.to_string(), 20);
    let known = f.kind == Kind::Frame && f.content != 0;
    let (content, ratio) = if known {
        (f.content.to_string(), ratio_cell(f.size, f.content))
    } else {
        (m::CELL_NONE.to_string(), m::CELL_NONE.to_string())
    };
    let content = pad(&content, 20);
    let ratio = pad(&ratio, 9);
    let fmt = match (f.kind, known) {
        (Kind::Frame, true) => m::LIST_FRAME_KNOWN,
        (Kind::Frame, false) => m::LIST_FRAME_UNKNOWN,
        _ => m::LIST_FRAME_OTHER,
    };
    printf(
        run.out,
        fmt,
        &[&index, &kind, &block, &checksum, &size, &content, &ratio],
    );
}

/// The row of a file in the compact table; `file_size` is the file's.
fn print_file_row(run: &mut Run, name: &[u8], t: &Totals, file_size: u64) {
    let count = pad(&t.count.to_string(), 10);
    let kind = match t.kind {
        Some(k) if t.kind_same => kind_cell(k),
        _ => m::CELL_NONE,
    };
    let kind = pad(kind, 14);
    let block = match t.block {
        Some(b) if t.block_same => block_cell(b),
        _ => m::CELL_NONE.to_string(),
    };
    let block = pad(&block, 5);
    let size = pad(&size_cell(file_size), 11);
    let (content, ratio) = if t.known {
        (size_cell(t.content), ratio_cell(file_size, t.content))
    } else {
        (m::CELL_NONE.to_string(), m::CELL_NONE.to_string())
    };
    let content = pad(&content, 13);
    let ratio = pad(&ratio, 8);
    let fmt = if t.known {
        m::LIST_ROW_KNOWN
    } else {
        m::LIST_ROW_UNKNOWN
    };
    printf(
        run.out,
        fmt,
        &[
            &count,
            &kind,
            &block,
            &size,
            &content,
            &ratio,
            base_name(name),
        ],
    );
}

/// The messages for `stop` on the file `name`, and how the run ends.
fn report(run: &mut Run, name: &[u8], stop: Stop) -> Fail {
    match stop {
        Stop::NotRecognized => {}
        Stop::CorruptLegacy => run.say(1, m::LIST_CORRUPTED_LEGACY, &[]),
        Stop::Trailing(at) => {
            run.say(3, m::UNDECODABLE, &[]);
            run.say(3, m::AT_POSITION, &[at.to_string().as_bytes()]);
            run.say(3, m::NEWLINE, &[]);
        }
        Stop::MagicUnreadable => return run.exm(40, m::E40_MAGIC_UNREADABLE, &[]),
        Stop::SkipSize => return run.exm(42, m::E42_SKIPPABLE_SIZE, &[]),
        Stop::MagicOnly => return run.exm(71, m::E71_READING, &[name]),
        Stop::HeaderCut => return run.exm(72, m::E72_READING, &[name]),
    }
    run.say(1, m::LIST_NOT_RECOGNIZED, &[name]);
    Fail::File
}

/// A file's metadata and, if it could be opened, its bytes.
type Opened = (fs::Metadata, Result<Box<dyn Input>, io::Error>);

/// The file `name` as `--list` reads it, and its metadata: a regular file
/// (a symbolic link to one counts), or, for the operand `stdin` (which
/// lz4 takes for standard input: probe `lz4 --list stdin < cs.lz4` lists it
/// as `stdin`, a pipe or `/dev/null` is `lz4: stdin is not a regular
/// file`), standard input when that is one. `None`: not a regular file.
fn open_regular(run: &mut Run, name: &[u8]) -> Option<Opened> {
    if name == STDINMARK {
        return match run.host {
            Host::Real => {
                let f = host::stdin_file().ok()?;
                let meta = f.metadata().ok().filter(fs::Metadata::is_file)?;
                Some((meta, Ok(Box::new(f))))
            }
            // A sandbox's standard input is a pipe.
            Host::Sandbox(_) => None,
        };
    }
    let path = run.host.path(name);
    // probe: a missing name, a directory, a device, all the same line.
    let meta = fs::metadata(&path).ok().filter(fs::Metadata::is_file)?;
    let host = &*run.host;
    let file = File::open(&path).map(|f| -> Box<dyn Input> { Box::new(host.track(&path, f)) });
    Some((meta, file))
}

/// List `name`, the `index`th of `total`.
fn list_one(run: &mut Run, name: &[u8], index: usize, total: usize) -> Result<(), Fail> {
    let verbose = run.level >= 3;
    let Some((meta, file)) = open_regular(run, name) else {
        run.say(1, m::LIST_NOT_REGULAR, &[name]);
        return Err(Fail::File);
    };
    if verbose {
        printf(
            run.out,
            m::LIST_FILE_VERBOSE,
            &[
                base_name(name),
                index.to_string().as_bytes(),
                total.to_string().as_bytes(),
            ],
        );
        printf(run.out, m::LIST_HEADER_VERBOSE, &[]);
    }
    // Deviation 9: lz4 aborts on an assertion when a regular file cannot
    // be opened (probe: mode 000); stuffr names the error and ends the run
    // with exit 1.
    let file = match file {
        Ok(f) => f,
        Err(e) => {
            run.say(1, m::OPEN_INPUT_FAILED, &[name, &host::strerror(&e)]);
            return Err(Fail::File);
        }
    };
    let mut walker = Walker::new(file);
    let mut totals = Totals::new();
    loop {
        match walker.next_frame() {
            Ok(Some(frame)) => {
                totals.add(&frame);
                if verbose {
                    print_frame_row(run, totals.count, &frame);
                }
            }
            Ok(None) => break,
            Err(stop) => return Err(report(run, name, stop)),
        }
    }
    if verbose {
        printf(run.out, m::LIST_FILE_END, &[]);
    } else {
        print_file_row(run, name, &totals, meta.len());
    }
    Ok(())
}

/// `--list` over every input of `cmd` (module doc): standard input lists
/// nothing, and the first file that fails ends the run.
pub(crate) fn list_files(
    cmd: &Command,
    host: &mut Host,
    out: &mut dyn io::Write,
    err: &mut dyn io::Write,
) -> Ended {
    let mut run = Run::new(cmd, host, out, err, cmd.display_level);
    // probe: the compact table's header comes first, once, even for
    // standard input; `-v` has none.
    if run.level < 3 {
        printf(run.out, m::LIST_HEADER, &[]);
    }
    let mut result = Ok(());
    if cmd.from_list {
        let names = run.expand(&cmd.inputs);
        let total = names.len();
        for (i, name) in names.iter().enumerate() {
            result = list_one(&mut run, name, i + 1, total);
            if result.is_err() {
                break;
            }
        }
    }
    match result {
        Ok(()) | Err(Fail::File) => Ended {
            code: i32::from(result.is_err()),
            pause: cmd.pause,
        },
        Err(Fail::Exit(code)) => Ended { code, pause: false },
    }
}

#[cfg(test)]
mod tests;
