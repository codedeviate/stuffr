//! fileio.c's foreign frames: `--format=gzip|xz|lzma|lz4` when
//! compressing, and the gzip, xz, lzma and lz4 frames `FIO_decompressFrames`
//! recognises by magic when decompressing, ported from zstd 1.5.7's
//! `FIO_compressGzFrame`, `FIO_compressLzmaFrame`, `FIO_compressLz4Frame`,
//! `FIO_decompressGzFrame`, `FIO_decompressLzmaFrame` and
//! `FIO_decompressLz4Frame`, as the reference (built with zlib, liblzma and
//! liblz4) runs them.
//!
//! **Compressing.**
//!
//! - gzip: zlib's `deflateInit2(level, Z_DEFLATED, 15 + 16, 8,
//!   Z_DEFAULT_STRATEGY)`, the level clamped to 9 above and passed as it is
//!   below: 0 is stored blocks, -1 zlib's default (6), anything lower
//!   `deflateInit2 error -2` (`EXM_THROW(71)`). The deflate stream is C
//!   zlib's on the C tier (`stuffr::zlib_c`, `zlib-c`), byte-identical to
//!   the reference's (spike S2), and flate2's elsewhere; the gzip header
//!   and trailer are written here as zlib writes them for that stream (no
//!   name, MTIME 0, XFL from the level, the OS byte zlib is built with).
//! - xz and lzma: `lzma_easy_encoder(level, LZMA_CHECK_CRC64)` and
//!   `lzma_alone_encoder` over `lzma_lzma_preset(level)`, the level clamped
//!   to 0..=9, through `stuffr::xz_opts` (liblzma 5.8.4 on the C tier, as
//!   the reference links).
//! - lz4: `lz4_flex`'s frame encoder with liblz4's frame settings as
//!   fileio.c sets them, so the frame descriptor is the reference's byte for
//!   byte: 64 KiB linked blocks, the content size when the input's is known
//!   and non-zero, a content checksum only for `checksumFlag` 1 (`-C` sets
//!   2, which `LZ4F_compressBegin` masks to no checksum). The blocks are
//!   `lz4_flex`'s fast compressor's at every level (liblz4 switches to HC
//!   from level 3): compatible, never identical (R11; R11's "4 MiB,
//!   block-independent" was read from the `lz4` tool, not from
//!   `FIO_compressLz4Frame`, whose settings the binary shows).
//!
//! **Decompressing.** Each frame is read as fileio.c's loops read it: the
//! decoder is handed whatever the read pool holds, a whole read job at a
//! time, and stops exactly at the frame's end, so what follows (another
//! frame of any kind, stream padding, garbage) goes back to
//! `FIO_decompressFrames`. Output goes out as each zlib/liblzma/liblz4 call
//! hands it over, into 128 KiB buffers, and the call that fails loses what
//! it decoded: here the output a failing job decoded is written in whole
//! `ZSTD_DStreamOutSize()` buffers and the rest dropped.
//!
//! - gzip: one member (`inflateInit2(15 + 16)`), the header and trailer
//!   checked here as zlib checks them (method, reserved flags, the header
//!   CRC, the CRC-32 and ISIZE), each failure `inflate error -3`, the input
//!   ending inside the member `premature gz end`. The deflate data is
//!   flate2's on both tiers (zlib's own inflate is not linked; both reject
//!   the same malformed streams with `Z_DATA_ERROR`).
//! - xz and lzma: `lzma_stream_decoder(UINT64_MAX, 0)` (one stream, no
//!   check warnings) and `lzma_alone_decoder(UINT64_MAX)` through
//!   `stuffr::xz_opts`, the return codes printed as liblzma's numbers.
//! - lz4: liblz4 1.10.0's `LZ4F_decompress` frame layer is ported here (its
//!   checks in its order, its `LZ4F_getErrorName` names), the blocks
//!   decoded by `lz4_flex`.
//!
//! **A sandboxed run** (the fuzz target) bounds liblzma's memory whatever
//! the input or the level says: decoders run under a 256 MiB limit (an
//! input asking for more is `lzma_code decoding error 6`), and compression
//! uses at most preset 6.

use std::cell::RefCell;
use std::io::{self, Write};
use std::rc::Rc;

use flate2::{Crc, Decompress, FlushDecompress, Status};
use stuffr::lz4_frame::{
    BlockMode, BlockSize, FrameEncoder, FrameInfo, decompress_into, decompress_into_with_dict,
};
use stuffr::xz_opts::{self, Check, DecodeOptions, EncodeOptions, Filter, Format, Lzma, XzError};

use super::cli::CType;
use super::fileio::{
    CSTREAM_IN_SIZE, DSTREAM_IN_SIZE, DSTREAM_OUT_SIZE, Fio, Foreign, FrameCodec, Io, ReadPool,
};
use super::messages as m;
use super::util::FILESIZE_UNKNOWN;
use crate::compat::host::Host;

/// The frame coders of a zstd built with zlib, liblzma and liblz4.
pub(crate) struct Formats;

impl FrameCodec for Formats {
    fn compress(
        &mut self,
        io: &mut Io<'_>,
        rp: &mut ReadPool,
        ctype: CType,
        src_name: &[u8],
        file_size: u64,
        level: i32,
    ) -> Fio<(u64, u64)> {
        match ctype {
            CType::Gzip => compress_gz(io, rp, src_name, file_size, level),
            CType::Lz4 => compress_lz4(io, rp, src_name, file_size, level),
            CType::Lzma => compress_lzma(io, rp, src_name, file_size, level, true),
            CType::Xz | CType::Zstd => compress_lzma(io, rp, src_name, file_size, level, false),
        }
    }

    fn decompress(
        &mut self,
        io: &mut Io<'_>,
        rp: &mut ReadPool,
        kind: Foreign,
        src_name: &[u8],
    ) -> Fio<Option<u64>> {
        match kind {
            Foreign::Gzip => decode_frame(io, rp, kind, src_name, &mut GzMember::new()),
            Foreign::Lz4 => decode_frame(io, rp, kind, src_name, &mut Lz4Member::new()),
            Foreign::Xz | Foreign::Lzma => {
                let plain = kind == Foreign::Lzma;
                let opts = DecodeOptions {
                    format: if plain { Format::Lzma } else { Format::Xz },
                    memlimit: memlimit(io.host),
                    single_stream: true,
                    ..DecodeOptions::default()
                };
                match xz_opts::Decoder::new(&opts) {
                    Ok(dec) => decode_frame(
                        io,
                        rp,
                        kind,
                        src_name,
                        &mut LzmaMember {
                            dec,
                            fed: 0,
                            back: 0,
                        },
                    ),
                    Err(e) => {
                        let what = if plain {
                            m::LZMA_ALONE_DECODER
                        } else {
                            m::LZMA_STREAM_DECODER
                        };
                        let code = lzma_ret(&e).to_string();
                        io.d.at(
                            1,
                            io.err,
                            m::LZMA_DECODER_INIT_ERROR,
                            &[what.as_bytes(), src_name, code.as_bytes()],
                        );
                        Ok(None)
                    }
                }
            }
        }
    }
}

/// The decoders' memory limit: none (`UINT64_MAX`), or 256 MiB in a
/// sandboxed run.
fn memlimit(host: &Host) -> u64 {
    match host {
        Host::Real => u64::MAX,
        Host::Sandbox(_) => 256 << 20,
    }
}

// ---- shared ----

/// An in-memory writer the encoders write to and the frame loops drain.
#[derive(Clone, Default)]
struct Shared(Rc<RefCell<Vec<u8>>>);

impl Shared {
    fn take(&self) -> Vec<u8> {
        std::mem::take(&mut *self.0.borrow_mut())
    }
}

impl Write for Shared {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(b);
        Ok(b.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// `%.2f` of `part / whole * 100`, as C's `printf` prints it (0/0 is NaN).
fn pct(part: u64, whole: u64) -> String {
    let v = part as f64 / whole as f64 * 100.0;
    if v.is_nan() {
        m::NAN.to_owned()
    } else if v.is_infinite() {
        m::INF.to_owned()
    } else {
        format!("{v:.2}")
    }
}

/// The compressing loops' `DISPLAYUPDATE_PROGRESS`: `gz` picks
/// `FIO_compressGzFrame`'s texts (a trailing space), else the lzma and lz4
/// loops'.
fn read_progress(io: &mut Io<'_>, gz: bool, read: u64, file_size: u64, written: u64) {
    let mb = ((read >> 20) as u32).to_string();
    let r = pct(written, read);
    if file_size == FILESIZE_UNKNOWN {
        let fmt = if gz { m::GZ_PROGRESS } else { m::READ_PROGRESS };
        io.display_update_progress(fmt, &[mb.as_bytes(), r.as_bytes()]);
    } else {
        let of = ((file_size >> 20) as u32).to_string();
        let fmt = if gz {
            m::GZ_PROGRESS_OF
        } else {
            m::READ_PROGRESS_OF
        };
        io.display_update_progress(fmt, &[mb.as_bytes(), of.as_bytes(), r.as_bytes()]);
    }
}

/// Writes what an encoder produced; returns its length.
fn drain(io: &mut Io<'_>, sink: &Shared) -> Fio<u64> {
    let out = sink.take();
    if !out.is_empty() {
        io.write_block(&out)?;
    }
    Ok(out.len() as u64)
}

// ---- gzip ----

/// `ZSTD_CStreamOutSize()`, the compressing write pool's buffer: each
/// `deflate` call's output room, which decides level 0's stored blocks.
#[cfg(feature = "zlib-c")]
const CSTREAM_OUT_SIZE: usize = (128 << 10) + (128 << 10 >> 8) + 3 + 4;

/// `--format=gzip`'s stream on the C tier: C zlib with `windowBits`
/// 15 + 16, which writes the gzip header and trailer itself, as
/// `deflateInit2` does for zstd.
#[cfg(feature = "zlib-c")]
struct GzWriter(stuffr::zlib_c::RawDeflate<Shared>);

#[cfg(feature = "zlib-c")]
impl GzWriter {
    fn new(sink: Shared, level: u32) -> io::Result<Self> {
        stuffr::zlib_c::RawDeflate::with_options(sink, level, 15 + 16, CSTREAM_OUT_SIZE)
            .map(GzWriter)
    }

    fn write(&mut self, b: &[u8]) -> io::Result<()> {
        self.0.write_all(b)
    }

    fn finish(self) -> io::Result<()> {
        self.0.finish().map(drop)
    }
}

/// zlib's `OS_CODE` (zutil.h) on the platform it is built for: 19 on
/// Apple's (zlib 1.2.12 onwards), 10 on Windows, 3 (Unix) elsewhere.
#[cfg(not(feature = "zlib-c"))]
const OS_CODE: u8 = if cfg!(target_vendor = "apple") {
    19
} else if cfg!(windows) {
    10
} else {
    3
};

/// `--format=gzip`'s stream off the C tier: flate2's raw deflate, inside
/// the header and trailer zlib's `deflate` writes for the level (no name,
/// MTIME 0, XFL 2 at level 9 and 4 below 2, the OS byte).
#[cfg(not(feature = "zlib-c"))]
struct GzWriter {
    enc: flate2::write::DeflateEncoder<Shared>,
    sink: Shared,
    crc: Crc,
}

#[cfg(not(feature = "zlib-c"))]
impl GzWriter {
    fn new(sink: Shared, level: u32) -> io::Result<Self> {
        let xfl = match level {
            9 => 2,
            0 | 1 => 4,
            _ => 0,
        };
        sink.0
            .borrow_mut()
            .extend_from_slice(&[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, xfl, OS_CODE]);
        Ok(GzWriter {
            enc: flate2::write::DeflateEncoder::new(sink.clone(), flate2::Compression::new(level)),
            sink,
            crc: Crc::new(),
        })
    }

    fn write(&mut self, b: &[u8]) -> io::Result<()> {
        self.crc.update(b);
        self.enc.write_all(b)
    }

    fn finish(self) -> io::Result<()> {
        self.enc.finish()?;
        let mut out = self.sink.0.borrow_mut();
        out.extend_from_slice(&self.crc.sum().to_le_bytes());
        out.extend_from_slice(&self.crc.amount().to_le_bytes());
        Ok(())
    }
}

/// `FIO_compressGzFrame`: (bytes read, bytes written).
fn compress_gz(
    io: &mut Io<'_>,
    rp: &mut ReadPool,
    src: &[u8],
    file_size: u64,
    level: i32,
) -> Fio<(u64, u64)> {
    let level = level.min(9);
    // `deflateInit2` takes -1 for its default and refuses anything lower
    // with `Z_STREAM_ERROR`.
    if level < -1 {
        return Err(io.exm(71, m::GZ_DEFLATE_INIT, &[src, b"-2"]));
    }
    let level = if level == -1 { 6 } else { level as u32 };
    let sink = Shared::default();
    let Ok(mut gz) = GzWriter::new(sink.clone(), level) else {
        return Err(io.exm(71, m::GZ_DEFLATE_INIT, &[src, b"-2"]));
    };
    let (mut read, mut written) = (0u64, 0u64);
    loop {
        io.fill(rp, CSTREAM_IN_SIZE)?;
        let n = rp.loaded().len();
        if n == 0 {
            break;
        }
        read += n as u64;
        if gz.write(rp.loaded()).is_err() {
            return Err(io.exm(72, m::GZ_DEFLATE_ERROR, &[src, b"-2"]));
        }
        rp.consume(n);
        written += drain(io, &sink)?;
        read_progress(io, true, read, file_size, written);
    }
    if gz.finish().is_err() {
        return Err(io.exm(77, m::GZ_DEFLATE_ERROR, &[src, b"-2"]));
    }
    written += drain(io, &sink)?;
    io.sparse_end()?;
    Ok((read, written))
}

// ---- xz and lzma ----

/// An [`XzError`] as the `lzma_ret` it stands for.
fn lzma_ret(e: &XzError) -> i32 {
    match e {
        XzError::UnsupportedCheck(_) => 3,
        XzError::Mem { .. } => 5,
        XzError::MemLimit { .. } => 6,
        XzError::Format => 7,
        XzError::Options => 8,
        XzError::Data => 9,
        XzError::BufError => 10,
        XzError::Prog | XzError::Io(_) => 11,
    }
}

/// `FIO_compressLzmaFrame`: `plain` is `.lzma`, else `.xz`.
fn compress_lzma(
    io: &mut Io<'_>,
    rp: &mut ReadPool,
    src: &[u8],
    file_size: u64,
    level: i32,
    plain: bool,
) -> Fio<(u64, u64)> {
    let mut level = level.clamp(0, 9) as u32;
    if matches!(io.host, Host::Sandbox(_)) {
        level = level.min(6);
    }
    let Some(preset) = Lzma::preset(level, false) else {
        return Err(io.exm(81, m::LZMA_PRESET_ERROR, &[src]));
    };
    let opts = if plain {
        EncodeOptions {
            format: Format::Lzma,
            filters: vec![Filter::Lzma1(preset)],
            ..EncodeOptions::default()
        }
    } else {
        EncodeOptions {
            format: Format::Xz,
            filters: vec![Filter::Lzma2(preset)],
            check: Check::Crc64,
            threads: 0,
            ..EncodeOptions::default()
        }
    };
    let mut enc = match xz_opts::Encoder::new(&opts) {
        Ok(e) => e,
        Err(e) => {
            let code = lzma_ret(&e).to_string();
            let (n, fmt) = if plain {
                (82, m::LZMA_ALONE_ENCODER_ERROR)
            } else {
                (83, m::LZMA_EASY_ENCODER_ERROR)
            };
            return Err(io.exm(n, fmt, &[src, code.as_bytes()]));
        }
    };
    let (mut read, mut written) = (0u64, 0u64);
    let mut out = Vec::new();
    loop {
        io.fill(rp, CSTREAM_IN_SIZE)?;
        let n = rp.loaded().len();
        let r = if n == 0 {
            enc.finish(&mut out)
        } else {
            read += n as u64;
            enc.feed(rp.loaded(), &mut out)
        };
        if let Err(e) = r {
            let code = lzma_ret(&e).to_string();
            return Err(io.exm(84, m::LZMA_ENCODING_ERROR, &[src, code.as_bytes()]));
        }
        rp.consume(n);
        if !out.is_empty() {
            io.write_block(&out)?;
            written += out.len() as u64;
            out.clear();
        }
        read_progress(io, false, read, file_size, written);
        if n == 0 {
            break;
        }
    }
    io.sparse_end()?;
    Ok((read, written))
}

// ---- lz4 ----

/// `FIO_LZ4_GetBlockSize_FromBlockId(LZ4F_max64KB)`.
const LZ4_BLOCK: usize = 64 << 10;

/// `FIO_compressLz4Frame`. The level is liblz4's choice of compressor,
/// which `lz4_flex` does not have (module doc).
fn compress_lz4(
    io: &mut Io<'_>,
    rp: &mut ReadPool,
    src: &[u8],
    file_size: u64,
    _level: i32,
) -> Fio<(u64, u64)> {
    let content_size = (file_size != FILESIZE_UNKNOWN && file_size != 0).then_some(file_size);
    let info = FrameInfo::new()
        .block_size(BlockSize::Max64KB)
        .block_mode(BlockMode::Linked)
        .content_checksum(io.prefs.checksum == 1)
        .content_size(content_size);
    let sink = Shared::default();
    let mut enc = FrameEncoder::with_frame_info(info, sink.clone());
    let (mut read, mut written) = (0u64, 0u64);
    read += io.fill(rp, LZ4_BLOCK)? as u64;
    while !rp.loaded().is_empty() {
        let n = LZ4_BLOCK.min(rp.loaded().len());
        if enc.write_all(&rp.loaded()[..n]).is_err() {
            return Err(io.exm(
                35,
                m::LZ4_COMPRESS_FAILED,
                &[src, m::LZ4F_GENERIC.as_bytes()],
            ));
        }
        written += drain(io, &sink)?;
        read_progress(io, false, read, file_size, written);
        rp.consume(n);
        read += io.fill(rp, LZ4_BLOCK)? as u64;
    }
    // liblz4 records the size it was told; `lz4_flex` refuses a frame whose
    // content does not match it (an input that changed size while read).
    if enc.finish().is_err() {
        return Err(io.exm(
            38,
            m::LZ4_END_FAILED,
            &[src, m::LZ4F_FRAME_SIZE_WRONG.as_bytes()],
        ));
    }
    written += drain(io, &sink)?;
    io.sparse_end()?;
    Ok((read, written))
}

// ---- decompressing ----

/// Why a frame failed: zlib's `Z_BUF_ERROR` or liblzma's
/// `LZMA_BUF_ERROR` (the input ended inside it), another return code, an
/// `LZ4F_getErrorName`, or an LZ4 frame the input ended inside.
enum Fail {
    BufError,
    Code(i32),
    Lz4(&'static str),
    Unfinished,
}

/// One frame's decoder, fed a read job at a time.
trait Member {
    /// Decodes `input`, appending the output to `out`: `Some(used)` when
    /// the frame ended after `used` bytes of it, else `None` (all of it
    /// taken).
    fn step(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<Option<usize>, Fail>;

    /// The input is over inside the frame (zlib's and liblzma's
    /// `*_FINISH` with nothing left).
    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), Fail>;

    /// Once the frame has ended: how many bytes of the input fed before
    /// the call that ended it the frame did not use (the pure tier's LZMA
    /// decoder reads ahead), to go back to the read pool.
    fn unused(&self) -> usize {
        0
    }
}

/// The most input a decoder reads ahead of a frame's end ([`Member::unused`];
/// `lzma-rust2` reads up to 40 bytes).
const READ_AHEAD: usize = 64;

/// The frame loops of `FIO_decompressGzFrame`, `FIO_decompressLzmaFrame`
/// and `FIO_decompressLz4Frame`: the decoded size, or `None` for
/// `FIO_ERROR_FRAME_DECODING` (said).
fn decode_frame(
    io: &mut Io<'_>,
    rp: &mut ReadPool,
    kind: Foreign,
    src: &[u8],
    dec: &mut dyn Member,
) -> Fio<Option<u64>> {
    let progress = kind == Foreign::Lz4;
    let mut total = 0u64;
    let mut out = Vec::new();
    // The last bytes consumed, for a decoder that read ahead of its end.
    let mut tail: Vec<u8> = Vec::new();
    let give_back = |rp: &mut ReadPool, tail: &[u8], dec: &dyn Member| {
        let back = dec.unused().min(tail.len());
        if back > 0 {
            rp.give_back(&tail[tail.len() - back..]);
        }
    };
    let failed = loop {
        if rp.loaded().is_empty() {
            io.fill(rp, DSTREAM_IN_SIZE)?;
            if rp.loaded().is_empty() {
                match dec.finish(&mut out) {
                    Ok(()) => {
                        give_back(rp, &tail, dec);
                        emit(io, &out, progress, &mut total)?;
                        break None;
                    }
                    Err(f) => {
                        emit_failed(io, &out, kind, &mut total)?;
                        break Some(f);
                    }
                }
            }
        }
        let n = rp.loaded().len();
        match dec.step(rp.loaded(), &mut out) {
            Ok(None) => {
                tail.extend_from_slice(&rp.loaded()[n.saturating_sub(READ_AHEAD)..]);
                if tail.len() > READ_AHEAD {
                    tail.drain(..tail.len() - READ_AHEAD);
                }
                rp.consume(n);
                emit(io, &out, progress, &mut total)?;
                out.clear();
            }
            Ok(Some(used)) => {
                rp.consume(used);
                give_back(rp, &tail, dec);
                emit(io, &out, progress, &mut total)?;
                break None;
            }
            Err(f) => {
                emit_failed(io, &out, kind, &mut total)?;
                break Some(f);
            }
        }
    };
    io.sparse_end()?;
    let Some(f) = failed else {
        return Ok(Some(total));
    };
    let lzma = matches!(kind, Foreign::Xz | Foreign::Lzma);
    match f {
        Fail::BufError if lzma => io.d.at(1, io.err, m::LZMA_PREMATURE, &[src]),
        Fail::BufError => io.d.at(1, io.err, m::GZ_PREMATURE, &[src]),
        Fail::Code(c) => {
            let fmt = if lzma {
                m::LZMA_DECODING_ERROR
            } else {
                m::GZ_INFLATE_ERROR
            };
            let c = c.to_string();
            io.d.at(1, io.err, fmt, &[src, c.as_bytes()]);
        }
        Fail::Lz4(name) => io.d.at(
            1,
            io.err,
            m::LZ4_DECOMPRESSION_ERROR,
            &[src, name.as_bytes()],
        ),
        Fail::Unfinished => io.d.at(1, io.err, m::LZ4_UNFINISHED, &[src]),
    }
    Ok(None)
}

/// Writes a job's output as the decoders hand it over, in
/// `ZSTD_DStreamOutSize()` buffers (with lz4's progress line per buffer).
fn emit(io: &mut Io<'_>, out: &[u8], progress: bool, total: &mut u64) -> Fio<()> {
    for chunk in out.chunks(DSTREAM_OUT_SIZE) {
        io.write_block(chunk)?;
        *total += chunk.len() as u64;
        if progress {
            let h = io.human(*total).plain();
            io.display_update_progress(m::LZ4_PROGRESS, &[h.as_bytes()]);
        }
    }
    Ok(())
}

/// What a failing job got out: the buffers filled by the calls before the
/// failing one, whose own output is lost. zlib and liblz4 go on checking
/// past a full buffer (an end of block, a trailer, a corrupt code or block
/// needs no room), so the call that fills the last buffer can be the one
/// that fails; liblzma decodes nothing once the buffer is full, so a
/// filled buffer is always handed over.
fn emit_failed(io: &mut Io<'_>, out: &[u8], kind: Foreign, total: &mut u64) -> Fio<()> {
    let b = DSTREAM_OUT_SIZE;
    let keep = match kind {
        Foreign::Xz | Foreign::Lzma => out.len() / b * b,
        Foreign::Gzip | Foreign::Lz4 => out.len().saturating_sub(1) / b * b,
    };
    emit(io, &out[..keep], kind == Foreign::Lz4, total)
}

/// Where a gzip member is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GzSt {
    Head,
    XLen,
    Extra,
    Name,
    Comment,
    HCrc,
    Body,
    Trailer,
    Done,
}

/// One gzip member, read as zlib's `inflate` (`windowBits` 15 + 16) reads
/// it.
struct GzMember {
    st: GzSt,
    /// Bytes into the current field.
    at: usize,
    flags: u8,
    xlen: usize,
    field: [u8; 10],
    /// CRC-32 of the header so far (`FHCRC`).
    hcrc: Crc,
    inflate: Decompress,
    /// CRC-32 and length of the output.
    crc: Crc,
}

/// zlib's `Z_DATA_ERROR`.
const Z_DATA_ERROR: i32 = -3;

impl GzMember {
    fn new() -> Self {
        GzMember {
            st: GzSt::Head,
            at: 0,
            flags: 0,
            xlen: 0,
            field: [0; 10],
            hcrc: Crc::new(),
            inflate: Decompress::new(false),
            crc: Crc::new(),
        }
    }

    /// The header field after `from`, by the flags.
    fn next_field(&mut self, from: GzSt) {
        let order = [
            (GzSt::XLen, 0x04),
            (GzSt::Name, 0x08),
            (GzSt::Comment, 0x10),
            (GzSt::HCrc, 0x02),
        ];
        let rank = |s: GzSt| match s {
            GzSt::Head => 0,
            GzSt::XLen | GzSt::Extra => 1,
            GzSt::Name => 2,
            GzSt::Comment => 3,
            _ => 4,
        };
        self.at = 0;
        self.st = order
            .iter()
            .enumerate()
            .find(|(i, (_, bit))| *i + 1 > rank(from) && self.flags & bit != 0)
            .map_or(GzSt::Body, |(_, (s, _))| *s);
    }

    /// One header or trailer byte.
    fn byte(&mut self, b: u8) -> Result<(), Fail> {
        match self.st {
            GzSt::Head => {
                self.hcrc.update(&[b]);
                self.field[self.at] = b;
                self.at += 1;
                if self.at == 4 {
                    // NEEDBITS(16) on the method and the flags together.
                    if self.field[2] != 8 || self.field[3] & 0xe0 != 0 {
                        return Err(Fail::Code(Z_DATA_ERROR));
                    }
                    self.flags = self.field[3];
                }
                if self.at == 10 {
                    self.next_field(GzSt::Head);
                }
            }
            GzSt::XLen => {
                self.hcrc.update(&[b]);
                self.field[self.at] = b;
                self.at += 1;
                if self.at == 2 {
                    self.xlen = usize::from(u16::from_le_bytes([self.field[0], self.field[1]]));
                    self.at = 0;
                    self.st = GzSt::Extra;
                    if self.xlen == 0 {
                        self.next_field(GzSt::Extra);
                    }
                }
            }
            GzSt::Extra => {
                self.hcrc.update(&[b]);
                self.at += 1;
                if self.at == self.xlen {
                    self.next_field(GzSt::Extra);
                }
            }
            GzSt::Name | GzSt::Comment => {
                self.hcrc.update(&[b]);
                if b == 0 {
                    self.next_field(self.st);
                }
            }
            GzSt::HCrc => {
                self.field[self.at] = b;
                self.at += 1;
                if self.at == 2 {
                    let want = u16::from_le_bytes([self.field[0], self.field[1]]);
                    if u32::from(want) != self.hcrc.sum() & 0xffff {
                        return Err(Fail::Code(Z_DATA_ERROR));
                    }
                    self.at = 0;
                    self.st = GzSt::Body;
                }
            }
            GzSt::Trailer => {
                self.field[self.at] = b;
                self.at += 1;
                let word = |f: &[u8; 10], at: usize| {
                    u32::from_le_bytes([f[at], f[at + 1], f[at + 2], f[at + 3]])
                };
                if self.at == 4 && word(&self.field, 0) != self.crc.sum() {
                    return Err(Fail::Code(Z_DATA_ERROR));
                }
                if self.at == 8 {
                    if word(&self.field, 4) != self.crc.amount() {
                        return Err(Fail::Code(Z_DATA_ERROR));
                    }
                    self.st = GzSt::Done;
                }
            }
            GzSt::Body | GzSt::Done => {}
        }
        Ok(())
    }

    /// Inflates from `input`; returns the bytes taken.
    fn body(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<usize, Fail> {
        let mut used = 0;
        loop {
            out.reserve(DSTREAM_OUT_SIZE);
            let start = out.len();
            let room = out.capacity() - start;
            let before = self.inflate.total_in();
            let st = self
                .inflate
                .decompress_vec(&input[used..], out, FlushDecompress::None)
                .map_err(|_| Fail::Code(Z_DATA_ERROR))?;
            let took = (self.inflate.total_in() - before) as usize;
            used += took;
            let made = out.len() - start;
            self.crc.update(&out[start..]);
            if st == Status::StreamEnd {
                self.st = GzSt::Trailer;
                self.at = 0;
                return Ok(used);
            }
            if used == input.len() && made < room {
                return Ok(used);
            }
            if took == 0 && made == 0 {
                // No progress with input and room: not a deflate stream.
                return Err(Fail::Code(Z_DATA_ERROR));
            }
        }
    }
}

impl Member for GzMember {
    fn step(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<Option<usize>, Fail> {
        let mut i = 0;
        while i < input.len() && self.st != GzSt::Done {
            if self.st == GzSt::Body {
                i += self.body(&input[i..], out)?;
            } else {
                self.byte(input[i])?;
                i += 1;
            }
        }
        Ok((self.st == GzSt::Done).then_some(i))
    }

    fn finish(&mut self, _out: &mut Vec<u8>) -> Result<(), Fail> {
        if self.st == GzSt::Done {
            Ok(())
        } else {
            Err(Fail::BufError)
        }
    }
}

/// One xz stream or `.lzma` file through liblzma.
struct LzmaMember {
    dec: xz_opts::Decoder,
    /// Bytes handed to the decoder before this job.
    fed: u64,
    /// [`Member::unused`].
    back: usize,
}

impl LzmaMember {
    fn fail(e: &XzError) -> Fail {
        match e {
            XzError::BufError => Fail::BufError,
            e => Fail::Code(lzma_ret(e)),
        }
    }
}

impl Member for LzmaMember {
    fn step(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<Option<usize>, Fail> {
        self.dec.feed(input, out).map_err(|e| Self::fail(&e))?;
        if self.dec.finished() {
            let used = self.dec.progress().in_bytes;
            self.back = self.fed.saturating_sub(used) as usize;
            let used = used.saturating_sub(self.fed);
            return Ok(Some((used as usize).min(input.len())));
        }
        self.fed += input.len() as u64;
        Ok(None)
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), Fail> {
        self.dec.finish(out).map_err(|e| Self::fail(&e))?;
        if self.dec.finished() {
            self.back = self.fed.saturating_sub(self.dec.progress().in_bytes) as usize;
            Ok(())
        } else {
            Err(Fail::BufError)
        }
    }

    fn unused(&self) -> usize {
        self.back
    }
}

/// Where an LZ4 frame is (`dStage`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum L4 {
    Header,
    BlockHeader,
    /// A compressed block of `size` bytes (and its checksum).
    Block,
    /// An uncompressed block, `left` bytes still to copy.
    Copy,
    BlockCrc,
    Suffix,
    Done,
}

/// One LZ4 frame, read as liblz4 1.10.0's `LZ4F_decompress` reads it.
struct Lz4Member {
    st: L4,
    /// The bytes of the unit being gathered (header, block header, block,
    /// checksum).
    buf: Vec<u8>,
    /// The frame header's size, once its first seven bytes are in.
    fhs: usize,
    block_checksum: bool,
    content_checksum: bool,
    linked: bool,
    max_block: usize,
    content_size: u64,
    decoded: u64,
    size: usize,
    left: usize,
    content_hash: Xxh32,
    block_hash: Xxh32,
    /// The last 64 KiB of output (linked blocks' dictionary).
    dict: Vec<u8>,
    block_out: Vec<u8>,
}

impl Lz4Member {
    fn new() -> Self {
        Lz4Member {
            st: L4::Header,
            buf: Vec::new(),
            fhs: 0,
            block_checksum: false,
            content_checksum: false,
            linked: false,
            max_block: 0,
            content_size: 0,
            decoded: 0,
            size: 0,
            left: 0,
            content_hash: Xxh32::new(0),
            block_hash: Xxh32::new(0),
            dict: Vec::new(),
            block_out: Vec::new(),
        }
    }

    /// Gathers `input` into `buf` until it holds `need` bytes.
    fn gather(&mut self, input: &[u8], i: &mut usize, need: usize) -> bool {
        let take = need.saturating_sub(self.buf.len()).min(input.len() - *i);
        self.buf.extend_from_slice(&input[*i..*i + take]);
        *i += take;
        self.buf.len() >= need
    }

    /// Decoded bytes: counted, hashed and kept for the next linked block.
    fn produced(&mut self, data: &[u8], out: &mut Vec<u8>) {
        out.extend_from_slice(data);
        self.decoded += data.len() as u64;
        if self.content_checksum {
            self.content_hash.update(data);
        }
        if self.linked {
            self.dict.extend_from_slice(data);
            if self.dict.len() > 2 * LZ4_BLOCK {
                self.dict.drain(..self.dict.len() - LZ4_BLOCK);
            }
        }
    }

    /// `LZ4F_decodeHeader`, once `buf` holds `fhs` bytes (or seven, for
    /// the flag checks).
    fn header(&mut self) -> Result<(), Fail> {
        let flg = self.buf[4];
        if self.fhs == 0 {
            if (flg >> 1) & 1 != 0 {
                return Err(Fail::Lz4(m::LZ4F_RESERVED_FLAG_SET));
            }
            if (flg >> 6) & 3 != 1 {
                return Err(Fail::Lz4(m::LZ4F_HEADER_VERSION_WRONG));
            }
            self.fhs =
                7 + if flg & 0x08 != 0 { 8 } else { 0 } + if flg & 0x01 != 0 { 4 } else { 0 };
            return Ok(());
        }
        let bd = self.buf[5];
        if bd >> 7 != 0 {
            return Err(Fail::Lz4(m::LZ4F_RESERVED_FLAG_SET));
        }
        let id = (bd >> 4) & 7;
        if id < 4 {
            return Err(Fail::Lz4(m::LZ4F_MAX_BLOCK_SIZE_INVALID));
        }
        if bd & 0x0f != 0 {
            return Err(Fail::Lz4(m::LZ4F_RESERVED_FLAG_SET));
        }
        let hc = (xxh32(&self.buf[4..self.fhs - 1], 0) >> 8) as u8;
        if hc != self.buf[self.fhs - 1] {
            return Err(Fail::Lz4(m::LZ4F_HEADER_CHECKSUM_INVALID));
        }
        self.linked = (flg >> 5) & 1 == 0;
        self.block_checksum = (flg >> 4) & 1 != 0;
        self.content_checksum = (flg >> 2) & 1 != 0;
        self.content_size = if flg & 0x08 != 0 {
            u64::from_le_bytes(self.buf[6..14].try_into().expect("eight bytes"))
        } else {
            0
        };
        self.max_block = 1 << (8 + 2 * usize::from(id));
        Ok(())
    }

    /// `dstage_getSuffix`'s entry: the decoded size against the header's.
    fn end_mark(&mut self) -> Result<(), Fail> {
        if self.content_size != 0 && self.decoded != self.content_size {
            return Err(Fail::Lz4(m::LZ4F_FRAME_SIZE_WRONG));
        }
        self.st = if self.content_checksum {
            L4::Suffix
        } else {
            L4::Done
        };
        Ok(())
    }
}

impl Member for Lz4Member {
    fn step(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<Option<usize>, Fail> {
        let mut i = 0;
        loop {
            match self.st {
                L4::Done => return Ok(Some(i)),
                L4::Header => {
                    let need = if self.fhs == 0 { 7 } else { self.fhs };
                    if !self.gather(input, &mut i, need) {
                        return Ok(None);
                    }
                    let had = self.fhs;
                    self.header()?;
                    if had != 0 {
                        self.buf.clear();
                        self.st = L4::BlockHeader;
                    }
                }
                L4::BlockHeader => {
                    if !self.gather(input, &mut i, 4) {
                        return Ok(None);
                    }
                    let word = u32::from_le_bytes(self.buf[..4].try_into().expect("four"));
                    self.buf.clear();
                    let size = (word & 0x7FFF_FFFF) as usize;
                    if size == 0 {
                        self.end_mark()?;
                        continue;
                    }
                    if size > self.max_block {
                        return Err(Fail::Lz4(m::LZ4F_MAX_BLOCK_SIZE_INVALID));
                    }
                    self.size = size;
                    if word & 0x8000_0000 != 0 {
                        self.left = size;
                        self.block_hash = Xxh32::new(0);
                        self.st = L4::Copy;
                    } else {
                        self.st = L4::Block;
                    }
                }
                L4::Copy => {
                    let take = self.left.min(input.len() - i);
                    if take == 0 {
                        return Ok(None);
                    }
                    let data = &input[i..i + take];
                    if self.block_checksum {
                        self.block_hash.update(data);
                    }
                    self.produced(data, out);
                    i += take;
                    self.left -= take;
                    if self.left == 0 {
                        self.st = if self.block_checksum {
                            L4::BlockCrc
                        } else {
                            L4::BlockHeader
                        };
                    }
                }
                L4::BlockCrc => {
                    if !self.gather(input, &mut i, 4) {
                        return Ok(None);
                    }
                    let want = u32::from_le_bytes(self.buf[..4].try_into().expect("four"));
                    self.buf.clear();
                    if want != self.block_hash.digest() {
                        return Err(Fail::Lz4(m::LZ4F_BLOCK_CHECKSUM_INVALID));
                    }
                    self.st = L4::BlockHeader;
                }
                L4::Block => {
                    let need = self.size + if self.block_checksum { 4 } else { 0 };
                    if !self.gather(input, &mut i, need) {
                        return Ok(None);
                    }
                    let data = std::mem::take(&mut self.buf);
                    let block = &data[..self.size];
                    if self.block_checksum {
                        let want = u32::from_le_bytes(data[self.size..].try_into().expect("four"));
                        if want != xxh32(block, 0) {
                            return Err(Fail::Lz4(m::LZ4F_BLOCK_CHECKSUM_INVALID));
                        }
                    }
                    let mut dec = std::mem::take(&mut self.block_out);
                    dec.resize(self.max_block, 0);
                    let r = if self.linked {
                        let at = self.dict.len().saturating_sub(LZ4_BLOCK);
                        decompress_into_with_dict(block, &mut dec, &self.dict[at..])
                    } else {
                        decompress_into(block, &mut dec)
                    };
                    let n = r.map_err(|_| Fail::Lz4(m::LZ4F_DECOMPRESSION_FAILED))?;
                    self.produced(&dec[..n], out);
                    self.block_out = dec;
                    self.st = L4::BlockHeader;
                }
                L4::Suffix => {
                    if !self.gather(input, &mut i, 4) {
                        return Ok(None);
                    }
                    let want = u32::from_le_bytes(self.buf[..4].try_into().expect("four"));
                    self.buf.clear();
                    if want != self.content_hash.digest() {
                        return Err(Fail::Lz4(m::LZ4F_CONTENT_CHECKSUM_INVALID));
                    }
                    self.st = L4::Done;
                }
            }
        }
    }

    fn finish(&mut self, _out: &mut Vec<u8>) -> Result<(), Fail> {
        if self.st == L4::Done {
            Ok(())
        } else {
            Err(Fail::Unfinished)
        }
    }
}

// ---- XXH32 (the LZ4 frame's checksums) ----

const P1: u32 = 0x9E37_79B1;
const P2: u32 = 0x85EB_CA77;
const P3: u32 = 0xC2B2_AE3D;
const P4: u32 = 0x27D4_EB2F;
const P5: u32 = 0x1656_67B1;

/// XXH32, streaming.
#[derive(Clone)]
struct Xxh32 {
    acc: [u32; 4],
    mem: [u8; 16],
    len: usize,
    total: u64,
    seed: u32,
}

fn xxh_round(acc: u32, lane: u32) -> u32 {
    acc.wrapping_add(lane.wrapping_mul(P2))
        .rotate_left(13)
        .wrapping_mul(P1)
}

fn lane(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

impl Xxh32 {
    fn new(seed: u32) -> Self {
        Xxh32 {
            acc: [
                seed.wrapping_add(P1).wrapping_add(P2),
                seed.wrapping_add(P2),
                seed,
                seed.wrapping_sub(P1),
            ],
            mem: [0; 16],
            len: 0,
            total: 0,
            seed,
        }
    }

    fn stripe(&mut self, s: &[u8]) {
        for (k, acc) in self.acc.iter_mut().enumerate() {
            *acc = xxh_round(*acc, lane(&s[4 * k..]));
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total += data.len() as u64;
        if self.len > 0 {
            let take = (16 - self.len).min(data.len());
            self.mem[self.len..self.len + take].copy_from_slice(&data[..take]);
            self.len += take;
            data = &data[take..];
            if self.len < 16 {
                return;
            }
            let m = self.mem;
            self.stripe(&m);
            self.len = 0;
        }
        let mut chunks = data.chunks_exact(16);
        for c in &mut chunks {
            self.stripe(c);
        }
        let rest = chunks.remainder();
        self.mem[..rest.len()].copy_from_slice(rest);
        self.len = rest.len();
    }

    fn digest(&self) -> u32 {
        let mut h = if self.total >= 16 {
            let [a, b, c, d] = self.acc;
            a.rotate_left(1)
                .wrapping_add(b.rotate_left(7))
                .wrapping_add(c.rotate_left(12))
                .wrapping_add(d.rotate_left(18))
        } else {
            self.seed.wrapping_add(P5)
        };
        h = h.wrapping_add(self.total as u32);
        let mut rest = &self.mem[..self.len];
        while rest.len() >= 4 {
            h = h
                .wrapping_add(lane(rest).wrapping_mul(P3))
                .rotate_left(17)
                .wrapping_mul(P4);
            rest = &rest[4..];
        }
        for &b in rest {
            h = h
                .wrapping_add(u32::from(b).wrapping_mul(P5))
                .rotate_left(11)
                .wrapping_mul(P1);
        }
        h ^= h >> 15;
        h = h.wrapping_mul(P2);
        h ^= h >> 13;
        h = h.wrapping_mul(P3);
        h ^ (h >> 16)
    }
}

/// XXH32 of `data`.
fn xxh32(data: &[u8], seed: u32) -> u32 {
    let mut h = Xxh32::new(seed);
    h.update(data);
    h.digest()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xxh32_matches_the_reference_vectors() {
        // xxhash's own sanity values.
        assert_eq!(xxh32(b"", 0), 0x02CC_5D05);
        assert_eq!(xxh32(b"a", 0), 0x550D_7456);
        assert_eq!(xxh32(b"abc", 0), 0x32D1_53FF);
        assert_eq!(
            xxh32(b"Nobody inspects the spammish repetition", 0),
            0xE229_3B2F
        );
        // Streaming in uneven pieces gives the one-shot value.
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
        let mut h = Xxh32::new(0);
        for piece in data.chunks(13) {
            h.update(piece);
        }
        assert_eq!(h.digest(), xxh32(&data, 0));
    }

    #[test]
    fn the_lz4_header_checksum_is_liblz4s() {
        // `zstd --format=lz4 -c < 5000-byte input`'s descriptor: FLG 0x44,
        // BD 0x40, HC 0x5e (the reference's bytes).
        assert_eq!((xxh32(&[0x44, 0x40], 0) >> 8) as u8, 0x5e);
    }

    /// An lz4 frame of `lz4_flex`'s (linked, checksummed) decodes here
    /// whole, in any job sizes, and stops at its end.
    #[test]
    fn lz4_frames_decode_in_any_pieces() {
        let data: Vec<u8> = (0..300_000u32)
            .map(|i| if i % 7 == 0 { (i / 7) as u8 } else { b'q' })
            .collect();
        let sink = Shared::default();
        let info = FrameInfo::new()
            .block_size(BlockSize::Max64KB)
            .block_mode(BlockMode::Linked)
            .content_checksum(true)
            .content_size(Some(data.len() as u64));
        let mut e = FrameEncoder::with_frame_info(info, sink.clone());
        e.write_all(&data).unwrap();
        e.finish().unwrap();
        let mut frame = sink.take();
        let len = frame.len();
        frame.extend_from_slice(b"tail");
        for piece in [1, 7, 4096, 1 << 20] {
            let mut d = Lz4Member::new();
            let mut out = Vec::new();
            let mut at = 0;
            let used = loop {
                let end = (at + piece).min(frame.len());
                match d.step(&frame[at..end], &mut out) {
                    Ok(Some(u)) => break at + u,
                    Ok(None) => at = end,
                    Err(_) => panic!("piece {piece}: failed"),
                }
            };
            assert_eq!(used, len, "piece {piece}");
            assert!(out == data, "piece {piece}: output differs");
        }
    }

    /// A gzip member of flate2's, with every optional header field,
    /// decodes in any job sizes and stops at its trailer.
    #[test]
    fn gzip_members_decode_in_any_pieces() {
        let data = b"hello hello hello gzip\n".repeat(500);
        let mut gz = flate2::GzBuilder::new()
            .filename("n")
            .comment("c")
            .extra(vec![1, 2, 3])
            .write(Vec::new(), flate2::Compression::default());
        gz.write_all(&data).unwrap();
        let mut v = gz.finish().unwrap();
        let len = v.len();
        v.extend_from_slice(b"next");
        for piece in [1, 3, 64, 1 << 20] {
            let mut d = GzMember::new();
            let mut out = Vec::new();
            let mut at = 0;
            let used = loop {
                let end = (at + piece).min(v.len());
                match d.step(&v[at..end], &mut out) {
                    Ok(Some(u)) => break at + u,
                    Ok(None) => at = end,
                    Err(_) => panic!("piece {piece}: failed"),
                }
            };
            assert_eq!(used, len, "piece {piece}");
            assert_eq!(out, data, "piece {piece}");
        }
    }
}
