//! `zstd -l`: `FIO_listMultipleFiles` and what it calls (`FIO_listFile`,
//! `getFileInfo`, `FIO_analyzeFrames`, `displayInfo`), ported from zstd
//! 1.5.7 `programs/fileio.c` (BSD-3-Clause, Meta Platforms, Inc.;
//! `LICENSE-zstd`).
//!
//! A header-only walker: a frame's header (through
//! [`stuffr::zstd_opts::frame_header`], `ZSTD_getFrameHeader` on both
//! tiers), its 3-byte block headers with a seek over each block, the
//! checksum field, and skippable frames by their declared size. Nothing is
//! decoded, nothing is allocated for a declared size, and each step reads
//! at most 18 bytes.
//!
//! Where zstd's own behaviour is undefined or unbounded:
//!
//! - a skippable frame of 5 to 7 bytes at the end of a file reads its size
//!   from bytes beyond the read (zstd reads an uninitialised stack buffer);
//!   those bytes are the buffer's earlier contents, zero for the first
//!   read;
//! - a skippable frame whose size is `0xFFFFFFF8` makes zstd seek to its own
//!   start and loop forever; here it is "could not find end of skippable
//!   frame" (a frame parsing error, exit 1).

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};

use stuffr::zstd_opts::{self, FrameHeader};

use super::cli::{Command, STDINMARK};
use super::display::Display;
use super::messages::{self as m, printf};
use super::util::{self, Hrs};
use crate::compat::host::{self, Host};

/// `ZSTD_FRAMEHEADERSIZE_MAX`.
const FRAMEHEADERSIZE_MAX: usize = 18;
/// `ZSTD_FRAMEHEADERSIZE_MIN(ZSTD_f_zstd1)`: the prefix, and one byte more.
const FRAMEHEADERSIZE_MIN: usize = 6;
/// `ZSTD_CONTENTSIZE_UNKNOWN` and `ZSTD_CONTENTSIZE_ERROR` are the two top
/// values; a header that records one reads as "unavailable".
const CONTENTSIZE_ERROR: u64 = u64::MAX - 1;

/// `fileInfo_t`.
#[derive(Debug, Default, Clone)]
struct Info {
    decompressed: u64,
    compressed: u64,
    window: u64,
    frames: i32,
    skippable: i32,
    decomp_unavailable: bool,
    uses_check: bool,
    checksum: [u8; 4],
    nb_files: u32,
    dict_id: u32,
}

/// `InfoError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InfoError {
    Success,
    FrameError,
    NotZstd,
    FileError,
    Truncated,
}

/// A `FILE*` as `FIO_analyzeFrames` uses it: `fread`'s short reads and end
/// of file flag, `fseek` and `ftell`.
struct Stream<'a, R> {
    inner: &'a mut R,
    pos: u64,
    eof: bool,
}

impl<R: Read + Seek> Stream<'_, R> {
    /// `fread(buf, 1, buf.len(), f)`: the bytes read. A short read sets
    /// `eof` when the file ended (not when it failed).
    fn read(&mut self, buf: &mut [u8]) -> usize {
        let mut got = 0;
        while got < buf.len() {
            match self.inner.read(&mut buf[got..]) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(n) => got += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        self.pos += got as u64;
        got
    }

    /// `fseek(f, to, SEEK_SET)`; clears the end of file flag. Seeking past
    /// the end succeeds, as on a regular file.
    fn seek_to(&mut self, to: u64) -> bool {
        if self.inner.seek(SeekFrom::Start(to)).is_err() {
            return false;
        }
        self.pos = to;
        self.eof = false;
        true
    }

    /// `fseek(f, by, SEEK_CUR)` with a forward `by`.
    fn skip(&mut self, by: u64) -> bool {
        match self.pos.checked_add(by) {
            Some(to) => self.seek_to(to),
            None => false,
        }
    }
}

/// `ERROR_IF`: the message at display level 1, and the result.
fn fail(d: &Display, err: &mut dyn Write, msg: &str, args: &[&[u8]], e: InfoError) -> InfoError {
    d.at(1, err, msg, args);
    e
}

/// `FIO_analyzeFrames`: walk every frame of `src`, whose size is
/// `info.compressed`.
fn analyze_frames<R: Read + Seek>(
    info: &mut Info,
    src: &mut R,
    d: &Display,
    err: &mut dyn Write,
) -> InfoError {
    use InfoError::{FrameError, NotZstd, Success, Truncated};
    let mut s = Stream {
        inner: src,
        pos: 0,
        eof: false,
    };
    // Declared once, as in C: a short read leaves the rest as it was.
    let mut header = [0u8; FRAMEHEADERSIZE_MAX];
    loop {
        let start = s.pos;
        let n = s.read(&mut header);
        if n < FRAMEHEADERSIZE_MIN {
            if s.eof && n == 0 && info.compressed > 0 {
                if s.pos != info.compressed {
                    let (at, size) = (s.pos.to_string(), info.compressed.to_string());
                    return fail(
                        d,
                        err,
                        m::LIST_BEYOND_END,
                        &[at.as_bytes(), size.as_bytes()],
                        Truncated,
                    );
                }
                return Success;
            }
            if s.eof {
                return fail(d, err, m::LIST_INCOMPLETE, &[], NotZstd);
            }
            return fail(d, err, m::LIST_OUT_OF_FRAMES, &[], FrameError);
        }
        let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        if magic == zstd_opts::MAGIC {
            let parsed = zstd_opts::frame_header(&header[..n]);
            // ZSTD_getFrameContentSize.
            match parsed {
                Ok(FrameHeader::Zstd {
                    content_size: Some(c),
                    ..
                }) if c < CONTENTSIZE_ERROR => {
                    info.decompressed = info.decompressed.wrapping_add(c);
                }
                _ => info.decomp_unavailable = true,
            }
            let Ok(FrameHeader::Zstd {
                header_size,
                window_size,
                dict_id,
                ..
            }) = parsed
            else {
                return fail(d, err, m::LIST_HEADER_UNDECODABLE, &[], FrameError);
            };
            if info.dict_id != 0 && info.dict_id != dict_id {
                printf(err, m::LIST_DICTID_WARNING, &[]);
                info.dict_id = 0;
            } else {
                info.dict_id = dict_id;
            }
            info.window = window_size;
            // Move to the end of the frame header (never forward of the
            // bytes read: `frame_header` found the whole header in them).
            if !s.seek_to(start + header_size as u64) {
                return FrameError;
            }
            // Skip all blocks in the frame.
            loop {
                let mut bh = [0u8; 3];
                if s.read(&mut bh) != 3 {
                    return fail(d, err, m::LIST_BLOCK_HEADER, &[], FrameError);
                }
                let block = u32::from_le_bytes([bh[0], bh[1], bh[2], 0]);
                let kind = (block >> 1) & 3;
                if kind == 3 {
                    return fail(d, err, m::LIST_BLOCK_TYPE, &[], FrameError);
                }
                let size = if kind == 1 { 1 } else { u64::from(block >> 3) };
                if !s.skip(size) {
                    return fail(d, err, m::LIST_BLOCK_SKIP, &[], FrameError);
                }
                if block & 1 == 1 {
                    break;
                }
            }
            // Check if a checksum is used.
            if header[4] & 4 != 0 {
                info.uses_check = true;
                if s.read(&mut info.checksum) != 4 {
                    return fail(d, err, m::LIST_CHECKSUM, &[], FrameError);
                }
            }
            info.frames = info.frames.wrapping_add(1);
        } else if magic & 0xFFFF_FFF0 == zstd_opts::MAGIC_SKIPPABLE_START {
            let frame_size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
            // `8 + frameSize` is 32-bit arithmetic in C, and wraps.
            let end = u64::from(8u32.wrapping_add(frame_size));
            if end == 0 || !s.seek_to(start + end) {
                return fail(d, err, m::LIST_SKIPPABLE_END, &[], FrameError);
            }
            info.skippable = info.skippable.wrapping_add(1);
        } else {
            return NotZstd;
        }
    }
}

/// `getFileInfo` and `getFileInfo_fileConfirmed`.
fn file_info(
    info: &mut Info,
    host: &Host,
    name: &[u8],
    d: &Display,
    err: &mut dyn Write,
) -> InfoError {
    if !util::is_regular_file(host, name) {
        return fail(d, err, m::LIST_NOT_A_FILE, &[name], InfoError::FileError);
    }
    // FIO_openSrcFile(NULL, …).
    let meta = match util::stat(host, name) {
        Ok(meta) => meta,
        Err(e) => {
            d.at(1, err, m::CANT_STAT, &[name, &host::strerror(&e)]);
            return fail(d, err, m::LIST_CANT_OPEN, &[name], InfoError::FileError);
        }
    };
    let path = host.path(name);
    let file = match File::open(&path) {
        Ok(f) => host.track(&path, f),
        Err(e) => {
            d.at(1, err, m::NAME_ERRNO, &[name, &host::strerror(&e)]);
            return fail(d, err, m::LIST_CANT_OPEN, &[name], InfoError::FileError);
        }
    };
    let mut file = file;
    info.compressed = util::file_size_stat(&meta);
    let status = analyze_frames(info, &mut file, d, err);
    info.nb_files = 1;
    status
}

/// `%6d`.
fn d6(n: i32) -> String {
    format!("{n:>6}")
}

/// `%5d`.
fn d5(n: i32) -> String {
    format!("{n:>5}")
}

/// `%<precision>f` of a ratio, as `%5.3f`.
fn ratio3(r: f64) -> String {
    format!("{r:5.3}")
}

/// The ratio of two sizes, `0` for an empty compressed size.
fn ratio_of(decompressed: u64, compressed: u64) -> f64 {
    if compressed == 0 {
        0.0
    } else {
        decompressed as f64 / compressed as f64
    }
}

/// `%4s` of a size's suffix.
fn suffix4(h: &Hrs) -> String {
    format!("{:>4}", h.suffix)
}

/// `displayInfo`.
fn display_info(
    name: &[u8],
    info: &Info,
    display_level: i32,
    out: &mut dyn Write,
    util_level: i32,
) {
    let window = util::human_size(info.window, util_level);
    let compressed = util::human_size(info.compressed, util_level);
    let decompressed = util::human_size(info.decompressed, util_level);
    let ratio = ratio_of(info.decompressed, info.compressed);
    let check: &str = if info.uses_check { "XXH64" } else { "None" };
    let frames = info.skippable.wrapping_add(info.frames);
    if display_level <= 2 {
        if !info.decomp_unavailable {
            printf(
                out,
                m::LIST_ROW,
                &[
                    d6(frames).as_bytes(),
                    d5(info.skippable).as_bytes(),
                    compressed.value_w(6).as_bytes(),
                    suffix4(&compressed).as_bytes(),
                    decompressed.value_w(8).as_bytes(),
                    suffix4(&decompressed).as_bytes(),
                    ratio3(ratio).as_bytes(),
                    format!("{check:>5}").as_bytes(),
                    name,
                ],
            );
        } else {
            printf(
                out,
                m::LIST_ROW_NO_DECOMP,
                &[
                    d6(frames).as_bytes(),
                    d5(info.skippable).as_bytes(),
                    compressed.value_w(6).as_bytes(),
                    suffix4(&compressed).as_bytes(),
                    format!("{check:>5}").as_bytes(),
                    name,
                ],
            );
        }
        return;
    }
    printf(out, m::LIST_V_NAME, &[name]);
    printf(out, m::LIST_V_FRAMES, &[info.frames.to_string().as_bytes()]);
    if info.skippable != 0 {
        printf(
            out,
            m::LIST_V_SKIPPABLE,
            &[info.skippable.to_string().as_bytes()],
        );
    }
    printf(
        out,
        m::LIST_V_DICTID,
        &[info.dict_id.to_string().as_bytes()],
    );
    for (fmt, hrs, bytes) in [
        (m::LIST_V_WINDOW, &window, info.window),
        (m::LIST_V_COMPRESSED, &compressed, info.compressed),
    ] {
        printf(
            out,
            fmt,
            &[
                format!("{:.*}", hrs.precision, hrs.value).as_bytes(),
                hrs.suffix.as_bytes(),
                bytes.to_string().as_bytes(),
            ],
        );
    }
    if !info.decomp_unavailable {
        printf(
            out,
            m::LIST_V_DECOMPRESSED,
            &[
                format!("{:.*}", decompressed.precision, decompressed.value).as_bytes(),
                decompressed.suffix.as_bytes(),
                info.decompressed.to_string().as_bytes(),
            ],
        );
        printf(out, m::LIST_V_RATIO, &[format!("{ratio:.4}").as_bytes()]);
    }
    if info.uses_check && info.frames == 1 {
        let c = info.checksum;
        let hex = format!("{:02x}{:02x}{:02x}{:02x}", c[3], c[2], c[1], c[0]);
        printf(
            out,
            m::LIST_V_CHECK_VALUE,
            &[check.as_bytes(), hex.as_bytes()],
        );
    } else {
        printf(out, m::LIST_V_CHECK, &[check.as_bytes()]);
    }
    printf(out, m::LIST_V_END, &[]);
}

/// `FIO_addFInfo`.
fn add_info(a: &Info, b: &Info) -> Info {
    Info {
        frames: a.frames.wrapping_add(b.frames),
        skippable: a.skippable.wrapping_add(b.skippable),
        compressed: a.compressed.wrapping_add(b.compressed),
        decompressed: a.decompressed.wrapping_add(b.decompressed),
        decomp_unavailable: a.decomp_unavailable | b.decomp_unavailable,
        uses_check: a.uses_check & b.uses_check,
        nb_files: a.nb_files.wrapping_add(b.nb_files),
        ..Info::default()
    }
}

/// `FIO_listFile`: 0 or 1.
fn list_file(
    total: &mut Info,
    host: &Host,
    name: &[u8],
    (d, level): (&Display, i32),
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let mut info = Info::default();
    let status = file_info(&mut info, host, name, d, err);
    let blank = |out: &mut dyn Write| {
        if level > 2 {
            printf(out, m::LIST_V_END, &[]);
        }
    };
    match status {
        InfoError::FrameError => d.at(1, err, m::LIST_PARSE_ERROR, &[name]),
        InfoError::NotZstd => {
            printf(out, m::LIST_NOT_ZSTD, &[name]);
            blank(out);
            return 1;
        }
        InfoError::FileError => {
            blank(out);
            return 1;
        }
        InfoError::Truncated => {
            printf(out, m::LIST_TRUNCATED, &[name]);
            blank(out);
            return 1;
        }
        InfoError::Success => {}
    }
    display_info(name, &info, level, out, level);
    *total = add_info(total, &info);
    i32::from(status != InfoError::Success)
}

/// `FIO_listMultipleFiles` (`--list`, `-l`): the exit code.
pub(crate) fn list_files(
    cmd: &Command,
    host: &mut Host,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    // The notification level the display functions see: fileio.c's own
    // (`g_display_prefs`, 2 until zstdcli.c's `FIO_setNotificationLevel`,
    // which runs after this operation), not `-q`'s or `-v`'s.
    let d = Display::new(2);
    let level = cmd.display_level;
    let files = &cmd.files;
    // Ensure no specified input is stdin (needs fseek() capability).
    if files.iter().any(|f| f == STDINMARK) {
        d.at(1, err, m::LIST_NO_STDIN, &[]);
        return 1;
    }
    if files.is_empty() {
        if !(cmd.prefs.fake_stdin_console || host.stdin_is_tty()) {
            d.at(1, err, m::LIST_NO_STDIN, &[]);
        }
        d.at(1, err, m::LIST_NO_FILES, &[]);
        return 1;
    }
    if level <= 2 {
        printf(out, m::LIST_HEADER, &[]);
    }
    let mut error = 0;
    let mut total = Info {
        uses_check: true,
        ..Info::default()
    };
    for name in files {
        error |= list_file(&mut total, host, name, (&d, level), out, err);
    }
    if files.len() > 1 && level <= 2 {
        let compressed = util::human_size(total.compressed, level);
        let decompressed = util::human_size(total.decompressed, level);
        let ratio = ratio_of(total.decompressed, total.compressed);
        let check = if total.uses_check { "XXH64" } else { "" };
        let frames = total.skippable.wrapping_add(total.frames);
        let nb = total.nb_files.to_string();
        printf(out, m::LIST_RULE, &[]);
        if total.decomp_unavailable {
            printf(
                out,
                m::LIST_TOTAL_NO_DECOMP,
                &[
                    d6(frames).as_bytes(),
                    d5(total.skippable).as_bytes(),
                    compressed.value_w(6).as_bytes(),
                    suffix4(&compressed).as_bytes(),
                    format!("{check:>5}").as_bytes(),
                    nb.as_bytes(),
                ],
            );
        } else {
            printf(
                out,
                m::LIST_TOTAL,
                &[
                    d6(frames).as_bytes(),
                    d5(total.skippable).as_bytes(),
                    compressed.value_w(6).as_bytes(),
                    suffix4(&compressed).as_bytes(),
                    decompressed.value_w(8).as_bytes(),
                    suffix4(&decompressed).as_bytes(),
                    ratio3(ratio).as_bytes(),
                    format!("{check:>5}").as_bytes(),
                    nb.as_bytes(),
                ],
            );
        }
    }
    error
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A frame from its parts (nothing is checked).
    fn hand(
        fhd: u8,
        window: Option<u8>,
        did: &[u8],
        fcs: &[u8],
        blocks: &[u8],
        check: &[u8],
    ) -> Vec<u8> {
        let mut v = vec![0x28, 0xb5, 0x2f, 0xfd, fhd];
        v.extend(window);
        v.extend_from_slice(did);
        v.extend_from_slice(fcs);
        v.extend_from_slice(blocks);
        v.extend_from_slice(check);
        v
    }

    fn block(kind: u32, last: bool, size: u32, payload: &[u8]) -> Vec<u8> {
        let h = u32::from(last) | (kind << 1) | (size << 3);
        let mut v = h.to_le_bytes()[..3].to_vec();
        v.extend_from_slice(payload);
        v
    }

    fn skip(len: u32) -> Vec<u8> {
        let mut v = vec![0x5f, 0x2a, 0x4d, 0x18];
        v.extend_from_slice(&len.to_le_bytes());
        v.extend(std::iter::repeat_n(0, len as usize));
        v
    }

    fn walk(data: &[u8]) -> (Info, InfoError, String) {
        let mut info = Info {
            compressed: data.len() as u64,
            ..Info::default()
        };
        let mut err = Vec::new();
        let d = Display::new(2);
        let status = analyze_frames(&mut info, &mut Cursor::new(data), &d, &mut err);
        (info, status, String::from_utf8(err).unwrap())
    }

    fn render(name: &str, data: &[u8], level: i32) -> String {
        let mut info = Info {
            compressed: data.len() as u64,
            ..Info::default()
        };
        let d = Display::new(2);
        analyze_frames(&mut info, &mut Cursor::new(data), &d, &mut Vec::new());
        let mut out = Vec::new();
        display_info(name.as_bytes(), &info, level, &mut out, level);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn content_size_fields_of_every_width() {
        let b = block(0, true, 2, b"ab");
        // Flag 0 not single-segment: none; single-segment: one byte.
        let (i, e, _) = walk(&hand(0x00, Some(0), &[], &[], &b, &[]));
        assert_eq!(
            (e, i.decomp_unavailable, i.frames),
            (InfoError::Success, true, 1)
        );
        let (i, _, _) = walk(&hand(0x20, None, &[], &[200], &b, &[]));
        assert_eq!((i.decompressed, i.window), (200, 200));
        // Flag 1: two bytes plus 256; flag 2: four; flag 3: eight.
        let (i, _, _) = walk(&hand(0x60, None, &[], &[1, 0], &b, &[]));
        assert_eq!(i.decompressed, 257);
        let (i, _, _) = walk(&hand(0xa0, None, &[], &[1, 1, 0, 0], &b, &[]));
        assert_eq!(i.decompressed, 257);
        let (i, _, _) = walk(&hand(0xe0, None, &[], &[1, 0, 0, 0, 1, 0, 0, 0], &b, &[]));
        assert_eq!(i.decompressed, (1 << 32) + 1);
        // The "unknown" and "error" sizes are unavailable, not summed.
        for v in [u64::MAX, u64::MAX - 1] {
            let (i, e, _) = walk(&hand(0xe0, None, &[], &v.to_le_bytes(), &b, &[]));
            assert_eq!(
                (e, i.decomp_unavailable, i.decompressed),
                (InfoError::Success, true, 0)
            );
        }
    }

    #[test]
    fn dictionary_id_fields_of_every_width() {
        let b = block(0, true, 1, b"a");
        for (code, bytes, id) in [
            (1u8, &[7u8][..], 7u32),
            (2, &[1, 2][..], 0x0201),
            (3, &[1, 2, 3, 4][..], 0x0403_0201),
        ] {
            let (i, e, _) = walk(&hand(0x20 | code, None, bytes, &[1], &b, &[]));
            assert_eq!((e, i.dict_id), (InfoError::Success, id), "code {code}");
        }
        let mut two = hand(0x21, None, &[7], &[1], &b, &[]);
        two.extend(hand(0x21, None, &[8], &[1], &b, &[]));
        let (i, e, err) = walk(&two);
        assert_eq!((e, i.dict_id, i.frames), (InfoError::Success, 0, 2));
        assert_eq!(err, m::LIST_DICTID_WARNING);
    }

    #[test]
    fn a_truncated_block_header_is_a_frame_error() {
        let whole = hand(0x20, None, &[], &[2], &block(0, true, 2, b"ab"), &[]);
        // Header 6 bytes; cut inside the 3-byte block header.
        for cut in [6, 7, 8] {
            let (i, e, err) = walk(&whole[..cut]);
            assert_eq!(e, InfoError::FrameError, "cut {cut}");
            assert_eq!(err, m::LIST_BLOCK_HEADER);
            assert_eq!(i.frames, 0);
        }
        // Cut inside the block: the skip succeeds, the next read finds
        // the end, past the file's size.
        let (_, e, err) = walk(&whole[..10]);
        assert_eq!(e, InfoError::Truncated);
        assert_eq!(
            err,
            "Error: seeked to position 11, which is beyond file size of 10\n \n"
        );
    }

    #[test]
    fn skippable_only_and_the_wrap() {
        let mut two = skip(0);
        two.extend(skip(9));
        let (i, e, _) = walk(&two);
        assert_eq!(
            (e, i.skippable, i.frames, i.decomp_unavailable),
            (InfoError::Success, 2, 0, false)
        );
        // A wrapped size steps back into the file; a size of exactly
        // 2^32 - 8 would never advance.
        let wrap = |size: u32| {
            let mut v = vec![0x50, 0x2a, 0x4d, 0x18];
            v.extend_from_slice(&size.to_le_bytes());
            v.extend_from_slice(&[0; 10]);
            walk(&v)
        };
        let (_, e, err) = wrap(0xffff_fff8);
        assert_eq!(
            (e, err.as_str()),
            (InfoError::FrameError, m::LIST_SKIPPABLE_END)
        );
        let (_, e, _) = wrap(0xffff_fff9);
        assert_eq!(e, InfoError::NotZstd);
    }

    #[test]
    fn reserved_bit_block_type_and_empty_are_refused() {
        let b = block(0, true, 2, b"ab");
        let (i, e, err) = walk(&hand(0x08, Some(0), &[], &[], &b, &[]));
        assert_eq!(
            (e, err.as_str()),
            (InfoError::FrameError, m::LIST_HEADER_UNDECODABLE)
        );
        assert!(i.decomp_unavailable);
        let (_, e, err) = walk(&hand(0x20, None, &[], &[2], &block(3, true, 2, b"ab"), &[]));
        assert_eq!(
            (e, err.as_str()),
            (InfoError::FrameError, m::LIST_BLOCK_TYPE)
        );
        let (_, e, err) = walk(b"");
        assert_eq!((e, err.as_str()), (InfoError::NotZstd, m::LIST_INCOMPLETE));
        let (_, e, _) = walk(b"abcdefghijklmnopqrstuvwxyz");
        assert_eq!(e, InfoError::NotZstd);
    }

    #[test]
    fn checksum_is_read_and_shown_for_one_frame() {
        let b = block(1, true, 100, b"x");
        let data = hand(0x24, None, &[], &[100], &b, &[0x78, 0x56, 0x34, 0x12]);
        let (i, e, _) = walk(&data);
        assert_eq!(
            (e, i.uses_check, i.checksum),
            (InfoError::Success, true, [0x78, 0x56, 0x34, 0x12])
        );
        let v = render("f", &data, 3);
        assert!(v.contains("Check: XXH64 12345678\n"), "{v}");
        let mut two = data.clone();
        two.extend(&data);
        assert!(render("f", &two, 3).contains("Check: XXH64\n"));
    }

    /// `"%6d  %5d  %6s%4s  %8s%4s  %5s  %5s  %s\n"` written out.
    fn row(
        frames: i32,
        skips: i32,
        c: (&str, &str),
        u: (&str, &str),
        ratio: &str,
        check: &str,
        name: &str,
    ) -> String {
        format!(
            "{frames:>6}  {skips:>5}  {:>6}{:>4}  {:>8}{:>4}  {ratio:>5}  {check:>5}  {name}\n",
            c.0, c.1, u.0, u.1
        )
    }

    #[test]
    fn rows_are_padded_as_printf_pads() {
        // 7-byte header (content size 1744 + 256), a 4-byte RLE block, a
        // 4-byte checksum: 15 bytes holding 2000.
        let data = hand(
            0x64,
            None,
            &[],
            &[0xd0, 0x06],
            &block(1, true, 2000, b"x"),
            &[0; 4],
        );
        assert_eq!(data.len(), 15);
        let mut info = Info {
            compressed: 15,
            ..Info::default()
        };
        let d = Display::new(2);
        analyze_frames(&mut info, &mut Cursor::new(&data), &d, &mut Vec::new());
        assert_eq!(info.decompressed, 2000);
        let mut out = Vec::new();
        display_info(b"x.zst", &info, 2, &mut out, 2);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            row(
                1,
                0,
                ("15", " B"),
                ("1.95", " KiB"),
                "133.333",
                "XXH64",
                "x.zst"
            )
        );
        // Precision follows UTIL_makeHumanReadableSize (1.000 MiB: a value of
        // exactly 1 gets three digits, measured against the reference).
        info.compressed = 3000;
        info.decompressed = 1 << 20;
        let mut out = Vec::new();
        display_info(b"y", &info, 2, &mut out, 2);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            row(
                1,
                0,
                ("2.93", " KiB"),
                ("1.000", " MiB"),
                "349.525",
                "XXH64",
                "y"
            )
        );
    }
}
