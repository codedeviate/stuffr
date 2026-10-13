//! The pure tier: `ruzstd` 0.9.0 behind the same interface as `c`, with the
//! limits spec deviation 6 states — see the parent module's doc.

use std::io::Write;

use ruzstd::decoding::{BlockDecodingStrategy, Dictionary, FrameDecoder};
use ruzstd::encoding::{CompressionLevel, FrameCompressor};

use super::{
    BLOCKSIZE_MAX, DecodeOptions, EncodeOptions, EndOp, FrameHeader, FrameHeaderError, Progress,
    TrainParams, Trained, WINDOWLOG_ABSOLUTEMIN, WINDOWLOG_MAX, ZstdError, code, frame_header,
};

/// The libzstd this tier answers for: `"1.5.7"` (R7).
pub fn libzstd_version() -> &'static str {
    "1.5.7"
}

/// Not on this tier: `ZstdError::Unsupported("train")`.
pub fn train(_samples: &[u8], _sizes: &[usize], _p: &TrainParams) -> Result<Trained, ZstdError> {
    Err(ZstdError::Unsupported("train"))
}

/// A `Write` adapter that removes a frame's content checksum as it passes:
/// it clears the checksum bit (bit 2) of the frame header descriptor, the
/// byte at offset 4, and holds back the last four bytes written, which
/// [`ChecksumStrip::finish`] drops. With `keep` it passes everything
/// through unchanged. One frame per adapter.
pub struct ChecksumStrip<W: Write> {
    inner: W,
    keep: bool,
    seen: u64,
    held: Vec<u8>,
}

impl<W: Write> ChecksumStrip<W> {
    /// An adapter over `inner`; `keep` leaves the checksum in place.
    pub fn new(inner: W, keep: bool) -> Self {
        ChecksumStrip {
            inner,
            keep,
            seen: 0,
            held: Vec::with_capacity(8),
        }
    }

    /// Ends the frame: drops the held-back checksum, or writes it when
    /// keeping. Returns the inner writer.
    pub fn finish(mut self) -> std::io::Result<W> {
        if self.keep {
            self.inner.write_all(&self.held)?;
        }
        Ok(self.inner)
    }
}

impl<W: Write> Write for ChecksumStrip<W> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.keep {
            return self.inner.write(data);
        }
        let start = self.held.len();
        self.held.extend_from_slice(data);
        if self.seen <= 4 && self.seen + data.len() as u64 > 4 {
            self.held[start + (4 - self.seen) as usize] &= !0x04;
        }
        self.seen += data.len() as u64;
        if self.held.len() > 4 {
            let cut = self.held.len() - 4;
            self.inner.write_all(&self.held[..cut])?;
            self.held.drain(..cut);
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// `ruzstd`'s `Fastest` encoder behind [`super::c::Encoder`]'s interface.
/// It buffers each frame's input and compresses it at [`EndOp::End`], one
/// frame per `End`; every parameter but the checksum flag is ignored.
pub struct Encoder {
    buf: Vec<u8>,
    checksum: bool,
    ingested: u64,
    produced: u64,
}

impl std::fmt::Debug for Encoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Encoder").finish_non_exhaustive()
    }
}

impl Encoder {
    /// An encoder for `o`; a dictionary or prefix is
    /// `ZstdError::Unsupported("dictionary")`.
    pub fn new(o: &EncodeOptions) -> Result<Encoder, ZstdError> {
        if o.dictionary.is_some() || o.prefix.is_some() {
            return Err(ZstdError::Unsupported("dictionary"));
        }
        Ok(Encoder {
            buf: Vec::new(),
            checksum: o.checksum,
            ingested: 0,
            produced: 0,
        })
    }

    /// Accepted and ignored: this tier never records a content size.
    pub fn set_pledged_size(&mut self, _size: Option<u64>) -> Result<(), ZstdError> {
        Ok(())
    }

    /// Takes all of `input`; at [`EndOp::End`] appends the whole frame to
    /// `out`. [`EndOp::Flush`] cannot flush part of a `ruzstd` frame and
    /// does nothing. Always returns `0`.
    pub fn compress_stream(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
        end: EndOp,
    ) -> Result<usize, ZstdError> {
        self.buf.extend_from_slice(input);
        self.ingested += input.len() as u64;
        if end == EndOp::End {
            let before = out.len();
            let mut strip = ChecksumStrip::new(&mut *out, self.checksum);
            {
                let mut c = FrameCompressor::new(CompressionLevel::Fastest);
                c.set_source(self.buf.as_slice());
                c.set_drain(&mut strip);
                // Writing to a Vec cannot fail, so the compressor's own
                // `write_all(..).unwrap()` cannot panic here.
                c.compress();
            }
            strip.finish()?;
            self.produced += (out.len() - before) as u64;
            self.buf.clear();
        }
        Ok(0)
    }

    /// Bytes taken and frame bytes produced; this tier has no workers.
    pub fn progression(&self) -> Progress {
        Progress {
            ingested: self.ingested,
            consumed: self.ingested,
            produced: self.produced,
            flushed: self.produced,
            current_job_id: 0,
            nb_active_workers: 0,
        }
    }

    /// Always `0`: nothing is ever waiting in a worker.
    pub fn to_flush_now(&self) -> usize {
        0
    }

    /// Accepted and ignored (`--adapt` runs at `Fastest`).
    pub fn set_level(&mut self, _level: i32) -> Result<(), ZstdError> {
        Ok(())
    }
}

/// The entropy-table header of a formatted dictionary: zstd 1.5.7's
/// `--train --maxdict=4096` over the `zstd_opts` tests' sample set
/// (`tests/data/zstd_opts/dict4k.dict`), truncated to
/// `ZDICT_getDictHeaderSize` (113 bytes, the three repeat offsets last).
/// `ruzstd`'s `Dictionary` can only be built by parsing one (its table
/// types are not nameable), so a raw-content dictionary or prefix is this
/// header parsed, with its ID, content and repeat offsets replaced. Its
/// tables are never consulted for a frame libzstd wrote against raw
/// content, which carries its own; a crafted frame that repeats a table it
/// never sent decodes against these where libzstd reports
/// `dictionary_corrupted`, and its checksum, if any, then fails.
const RAW_DICT_TEMPLATE: &[u8] = &[
    0x37, 0xa4, 0x30, 0xec, 0xde, 0x23, 0x06, 0x62, 0x1c, 0x10, 0xd8, 0x4a, 0x92, 0x0e, 0x0c, 0xc3,
    0x30, 0x0c, 0x83, 0x4b, 0xc4, 0xb6, 0x4d, 0xf6, 0x43, 0x7e, 0xbc, 0xfd, 0xde, 0xcd, 0x9e, 0x49,
    0x52, 0x39, 0xf2, 0x54, 0x07, 0x23, 0x00, 0x00, 0x30, 0x50, 0x80, 0xe0, 0x80, 0x11, 0xa5, 0x5c,
    0xb6, 0x0e, 0x00, 0x04, 0xe0, 0xd0, 0xd4, 0x49, 0xc3, 0x14, 0x0d, 0x54, 0x31, 0x86, 0x0c, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x34, 0x75, 0x4a, 0xd5, 0x1c, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
    0x00,
];

/// libzstd's repeat offsets for raw content (`repStartValue`).
const RAW_REP_OFFSETS: [u32; 3] = [1, 4, 8];

/// A `ruzstd` dictionary that is `content` as raw content, under `id`.
fn raw_dictionary(id: u32, content: &[u8]) -> Dictionary {
    let mut d = Dictionary::decode_dict(RAW_DICT_TEMPLATE)
        .expect("RAW_DICT_TEMPLATE is a valid dictionary header (tested)");
    d.id = id;
    d.dict_content = content.to_vec();
    d.offset_hist = RAW_REP_OFFSETS;
    d
}

/// The dictionary a [`Decoder`] holds, as libzstd's `dctx->dictID` sees it.
enum Dict {
    None,
    /// A formatted dictionary, added to the `FrameDecoder` under its ID.
    Formatted(u32),
    /// Raw content (`dictID` 0).
    Raw(Vec<u8>),
}

/// Where a [`Decoder`] is in the stream.
enum State {
    /// Before a frame header.
    Start,
    /// Inside a skippable frame, with this many bytes still to skip.
    Skip(u64),
    /// Inside a zstd frame, between blocks.
    Blocks {
        checksum: bool,
        content_size: Option<u64>,
        /// The code for more output than the content size declares.
        overflow: u32,
        block_max: u64,
        produced: u64,
    },
}

/// `ruzstd`'s `FrameDecoder` in a frame loop that answers as
/// `ZSTD_decompressStream` does — see the parent module's doc.
pub struct Decoder {
    fd: FrameDecoder,
    max_window: u64,
    ignore_checksum: bool,
    dict: Dict,
    /// The `--patch-from` prefix, until the first frame takes it.
    prefix: Option<Vec<u8>>,
    /// The bytes of the unit being gathered: a header or one block.
    pending: Vec<u8>,
    /// The frame being started began at this call's first input byte, so
    /// libzstd's single-pass shortcut could apply to it.
    fresh: bool,
    state: State,
}

/// `ZSTD_findFrameCompressedSize` for a zstd frame at the start of `src`:
/// its whole size, header to checksum, or `None` if `src` holds less or the
/// frame is malformed.
fn frame_compressed_size(src: &[u8]) -> Option<usize> {
    let FrameHeader::Zstd {
        header_size,
        checksum,
        ..
    } = frame_header(src).ok()?
    else {
        return None;
    };
    let mut pos = header_size;
    loop {
        let b = src.get(pos..pos + 3)?;
        let bh = u32::from(b[0]) | u32::from(b[1]) << 8 | u32::from(b[2]) << 16;
        let block_type = (bh >> 1) & 3;
        let wire = match block_type {
            1 => 1,
            3 => return None,
            _ => (bh >> 3) as usize,
        };
        pos += 3 + wire;
        if bh & 1 != 0 {
            return Some(pos + if checksum { 4 } else { 0 });
        }
    }
}

/// A `FrameDecoderError` as the libzstd code `fileio.c` would print.
fn map_err(e: &ruzstd::decoding::errors::FrameDecoderError) -> ZstdError {
    use ruzstd::decoding::errors::FrameDecoderError as E;
    match e {
        E::DictNotProvided { .. } => ZstdError::lib(code::DICTIONARY_WRONG),
        E::WindowSizeTooBig { .. } => ZstdError::lib(code::WINDOW_TOO_LARGE),
        _ => ZstdError::lib(code::CORRUPTION_DETECTED),
    }
}

impl std::fmt::Debug for Decoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decoder").finish_non_exhaustive()
    }
}

impl Decoder {
    /// A decoder for `o`. A dictionary with the dictionary magic that does
    /// not parse is `memory_allocation`, libzstd's answer when
    /// `ZSTD_createDDict` fails inside `ZSTD_DCtx_loadDictionary`.
    pub fn new(o: &DecodeOptions) -> Result<Decoder, ZstdError> {
        // ZSTD_DCtx_setMaxWindowSize's bounds.
        if !(1 << WINDOWLOG_ABSOLUTEMIN..=1 << WINDOWLOG_MAX).contains(&o.max_window_size) {
            return Err(ZstdError::lib(code::PARAMETER_OUT_OF_BOUND));
        }
        let mut fd = FrameDecoder::new();
        // The limit is checked here, against the header, before `ruzstd`
        // allocates; its own default (100 MiB) must not refuse first.
        fd.set_max_window_size(u64::MAX);
        let mut dict = Dict::None;
        if let Some(d) = &o.dictionary {
            // `ZSTD_dct_auto`: eight bytes or more starting with the
            // dictionary magic are a formatted dictionary, anything else raw
            // content.
            if d.len() >= 8 && d[..4] == super::MAGIC_DICTIONARY.to_le_bytes() {
                let parsed = Dictionary::decode_dict(d)
                    .map_err(|_| ZstdError::lib(code::MEMORY_ALLOCATION))?;
                let id = parsed.id;
                fd.add_dict(parsed).map_err(|e| map_err(&e))?;
                dict = Dict::Formatted(id);
            } else {
                dict = Dict::Raw(d.clone());
            }
        }
        Ok(Decoder {
            fd,
            max_window: o.max_window_size,
            ignore_checksum: o.ignore_checksum,
            dict,
            prefix: o.prefix.clone(),
            pending: Vec::new(),
            fresh: false,
            state: State::Start,
        })
    }

    /// Back to the start of a frame; the dictionary stays, a prefix already
    /// used stays used, as `ZSTD_DCtx_reset(ZSTD_reset_session_only)`.
    pub fn reset(&mut self) {
        self.pending.clear();
        self.state = State::Start;
    }

    /// Takes up to `want` bytes of the current unit from `input[*used..]`;
    /// true once `pending` holds `want` bytes.
    fn gather(&mut self, input: &[u8], used: &mut usize, want: usize) -> bool {
        let take = want
            .saturating_sub(self.pending.len())
            .min(input.len() - *used);
        self.pending.extend_from_slice(&input[*used..*used + take]);
        *used += take;
        self.pending.len() >= want
    }

    /// As [`super::c::Decoder::decompress_stream`]: decodes at most one
    /// block per call (at most 128 KiB, plus the rest of the window when a
    /// frame ends), and returns `(consumed, hint)` with `hint == 0` exactly
    /// when a frame has ended, never consuming past it.
    pub fn decompress_stream(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(usize, usize), ZstdError> {
        let r = self.step(input, out);
        if r.is_err() {
            self.reset();
        }
        r
    }

    fn step(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(usize, usize), ZstdError> {
        let mut used = 0;
        loop {
            match self.state {
                State::Start => {
                    if self.pending.is_empty() {
                        self.fresh = used == 0;
                    }
                    let header = match frame_header(&self.pending) {
                        Err(FrameHeaderError::Incomplete(want)) => {
                            if !self.gather(input, &mut used, want) {
                                // The header spans calls: no shortcut.
                                self.fresh = false;
                                return Ok((used, want - self.pending.len()));
                            }
                            continue;
                        }
                        Err(FrameHeaderError::Lib(c)) => return Err(ZstdError::lib(c)),
                        Ok(h) => h,
                    };
                    self.start_frame(header, input)?;
                }
                State::Skip(left) => {
                    let take = left.min((input.len() - used) as u64);
                    used += take as usize;
                    if take == left {
                        self.state = State::Start;
                        return Ok((used, 0));
                    }
                    self.state = State::Skip(left - take);
                    return Ok((used, (left - take).min(BLOCKSIZE_MAX as u64) as usize));
                }
                State::Blocks {
                    checksum,
                    content_size,
                    overflow,
                    block_max,
                    produced,
                } => {
                    if !self.gather(input, &mut used, 3) {
                        return Ok((used, 3 - self.pending.len()));
                    }
                    let bh = u32::from(self.pending[0])
                        | u32::from(self.pending[1]) << 8
                        | u32::from(self.pending[2]) << 16;
                    let last = bh & 1 != 0;
                    let block_type = (bh >> 1) & 3;
                    let size = u64::from(bh >> 3);
                    if block_type == 3 || size > block_max {
                        return Err(ZstdError::lib(code::CORRUPTION_DETECTED));
                    }
                    let wire = if block_type == 1 { 1 } else { size as usize };
                    let want = 3 + wire + if last && checksum { 4 } else { 0 };
                    if !self.gather(input, &mut used, want) {
                        return Ok((used, want - self.pending.len()));
                    }
                    let mut src = self.pending.as_slice();
                    self.fd
                        .decode_blocks(&mut src, BlockDecodingStrategy::UptoBlocks(1))
                        .map_err(|e| map_err(&e))?;
                    self.pending.clear();
                    let before = out.len();
                    if let Some(bytes) = self.fd.collect() {
                        out.extend_from_slice(&bytes);
                    }
                    let produced = produced + (out.len() - before) as u64;
                    if !last {
                        self.state = State::Blocks {
                            checksum,
                            content_size,
                            overflow,
                            block_max,
                            produced,
                        };
                        return Ok((used, 3));
                    }
                    if let Some(fcs) = content_size
                        && fcs != produced
                    {
                        return Err(ZstdError::lib(if produced > fcs {
                            overflow
                        } else {
                            code::CORRUPTION_DETECTED
                        }));
                    }
                    if checksum
                        && !self.ignore_checksum
                        && crate::zstd_pure::checksum_mismatch(&self.fd).is_some()
                    {
                        return Err(ZstdError::lib(code::CHECKSUM_WRONG));
                    }
                    self.state = State::Start;
                    return Ok((used, 0));
                }
            }
        }
    }

    /// A complete header is in `pending`: check it as
    /// `ZSTD_decompressStream` does and start `ruzstd` on it. `input` is
    /// this call's, for libzstd's single-pass shortcut.
    fn start_frame(&mut self, header: FrameHeader, input: &[u8]) -> Result<(), ZstdError> {
        let (header_size, window_size, content_size, frame_dict, checksum) = match header {
            FrameHeader::Skippable { content_size, .. } => {
                self.pending.clear();
                self.state = State::Skip(u64::from(content_size));
                return Ok(());
            }
            FrameHeader::Zstd {
                header_size,
                window_size,
                content_size,
                dict_id,
                checksum,
                ..
            } => (header_size, window_size, content_size, dict_id, checksum),
        };
        let window = window_size.max(1 << WINDOWLOG_ABSOLUTEMIN);
        if window > self.max_window {
            return Err(ZstdError::lib(code::WINDOW_TOO_LARGE));
        }
        // `dctx->dictID`: a formatted dictionary's ID, else 0.
        let loaded = match self.dict {
            Dict::Formatted(id) => id,
            _ => 0,
        };
        if frame_dict != 0 && frame_dict != loaded {
            return Err(ZstdError::lib(code::DICTIONARY_WRONG));
        }
        self.fd
            .reset(&self.pending[..header_size])
            .map_err(|e| map_err(&e))?;
        // A prefix serves the first frame only; a dictionary every frame.
        if let Some(p) = self.prefix.take() {
            self.fd
                .add_dict(raw_dictionary(0, &p))
                .map_err(|e| map_err(&e))?;
            self.fd.force_dict(0).map_err(|e| map_err(&e))?;
        } else {
            match &self.dict {
                Dict::None => {}
                Dict::Formatted(id) => self.fd.force_dict(*id).map_err(|e| map_err(&e))?,
                Dict::Raw(content) => {
                    let d = raw_dictionary(0, content);
                    self.fd.add_dict(d).map_err(|e| map_err(&e))?;
                    self.fd.force_dict(0).map_err(|e| map_err(&e))?;
                }
            }
        }
        self.pending.clear();
        // More output than the content size declares: libzstd's
        // single-pass shortcut (the whole frame in this call's input, the
        // content fitting `ZSTD_DStreamOutSize()`) finds it at the end, as
        // corruption; streaming into a buffer sized to the content size
        // (`ZSTD_decodingBufferSize_min`) runs out of room first. The
        // streaming verdict comes at the frame's end here, not at the block
        // that overflows, so less of the output precedes it in libzstd.
        let block_max = window.min(BLOCKSIZE_MAX as u64);
        let overflow = match content_size {
            Some(fcs)
                if !(self.fresh
                    && fcs <= BLOCKSIZE_MAX as u64
                    && frame_compressed_size(input).is_some_and(|n| n <= input.len()))
                    && fcs <= window + 2 * block_max + 64 =>
            {
                code::DST_SIZE_TOO_SMALL
            }
            _ => code::CORRUPTION_DETECTED,
        };
        self.state = State::Blocks {
            checksum,
            content_size,
            overflow,
            block_max,
            produced: 0,
        };
        Ok(())
    }
}
