//! The pure tier: this crate's own LZ4 frame writer and reader over
//! `lz4_flex::block`, following `doc/lz4_Frame_format.md` (liblz4 1.10.0,
//! BSD-2-Clause) — no liblz4 code is ported.
//!
//! The writer lays a frame out exactly as the C tier does (the header,
//! including the one-shot rule's block size and block mode, block sizes,
//! checksums, the end mark) but compresses every block with `lz4_flex`'s
//! one compressor, whatever the level (spec deviation 6: compatible, not
//! byte-identical). A block that does not shrink is stored uncompressed.
//! Linked blocks are compressed against the previous 64 KiB of input; a
//! `-D` dictionary's last 64 KiB serve every block of an independent frame
//! and the first of a linked one, as liblz4 uses it.
//!
//! The reader is a state machine that consumes exactly the bytes of one
//! frame and gathers each piece before it acts on it. A block-size word is
//! checked against the frame's declared maximum before a byte is reserved
//! for the block; the hint is `0` only after the end mark (and the content
//! checksum) — a truncated frame never looks finished. Every fault maps onto
//! the `LZ4F_errorCodes` value liblz4 reports for it (`LZ4F_decodeHeader`,
//! `LZ4F_decompress` in `lib/lz4frame.c`).

use std::hash::Hasher;

use lz4_flex::block;
use twox_hash::XxHash32;

use super::{
    BlockSizeId, DecodeOptions, EncodeOptions, FRAME_CHUNK, FrameHeader, HEADER_SIZE_MIN,
    LEGACY_BLOCK_BOUND, LEGACY_BLOCK_SIZE, LEGACY_MAGIC, Lz4Error, Lz4fError, MAGIC,
    is_skippable_magic, le32, parse_frame_header, write_frame_header, xxh32,
};

/// The liblz4 version the C tier links, reported as-is on this tier (R7).
pub fn liblz4_version() -> &'static str {
    "1.10.0"
}

/// LZ4's window: how far back a match may reach.
const WINDOW: usize = 64 << 10;

/// The last `WINDOW` bytes of `d`.
fn tail(d: &[u8]) -> &[u8] {
    &d[d.len().saturating_sub(WINDOW)..]
}

/// Appends `data` to `history`, keeping only the last `WINDOW` bytes.
fn remember(history: &mut Vec<u8>, data: &[u8]) {
    if data.len() >= WINDOW {
        history.clear();
        history.extend_from_slice(tail(data));
    } else {
        history.extend_from_slice(data);
        let excess = history.len().saturating_sub(WINDOW);
        history.drain(..excess);
    }
}

/// One LZ4 block of `src` against `dict` into `dst` (resized to fit): the
/// compressed length.
fn compress_block(src: &[u8], dict: &[u8], dst: &mut Vec<u8>) -> Result<usize, Lz4Error> {
    dst.resize(block::get_maximum_output_size(src.len()), 0);
    // `compress_into_with_dict` needs a dictionary of at least one match's
    // length (`lz4_flex`'s own vector entry point falls back the same way).
    let r = if dict.len() >= 4 {
        block::compress_into_with_dict(src, dst, dict)
    } else {
        block::compress_into(src, dst)
    };
    r.map_err(|_| Lz4Error::Lib(Lz4fError::Generic))
}

/// One legacy block through `lz4_flex`: the decoded length, or
/// [`Lz4fError::DecompressionFailed`].
pub(super) fn legacy_block_decode(src: &[u8], dst: &mut [u8]) -> Result<usize, Lz4Error> {
    if src.is_empty() {
        return Err(Lz4Error::Lib(Lz4fError::DecompressionFailed));
    }
    block::decompress_into(src, dst).map_err(|_| Lz4Error::Lib(Lz4fError::DecompressionFailed))
}

/// An lz4 encoder with the CLI's frame layout (or [`Encoder::new_plain`]'s,
/// or the legacy format's).
pub struct Encoder {
    block_size: BlockSizeId,
    linked: bool,
    block_checksum: bool,
    content_checksum: bool,
    content_size: Option<u64>,
    legacy: bool,
    plain: bool,
    /// The `-D` dictionary's last 64 KiB.
    dictionary: Vec<u8>,
    /// Input not yet compressed.
    pending: Vec<u8>,
    /// The header (or legacy magic) has been written.
    started: bool,
    /// The block size and mode of the frame being written.
    frame_block: BlockSizeId,
    frame_linked: bool,
    /// The last 64 KiB of the frame's input so far (linked blocks).
    history: Vec<u8>,
    /// The content checksum so far.
    checksum: XxHash32,
    scratch: Vec<u8>,
}

impl Encoder {
    /// An encoder for `o`. The level is accepted and does not change the
    /// bytes (deviation 6).
    pub fn new(o: &EncodeOptions) -> Result<Encoder, Lz4Error> {
        let block_size = o.block_size_id();
        Ok(Encoder {
            block_size,
            linked: o.block_linked,
            block_checksum: o.block_checksum,
            content_checksum: o.content_checksum,
            content_size: o.content_size,
            legacy: o.legacy,
            plain: false,
            dictionary: o
                .dictionary
                .as_deref()
                .filter(|_| !o.legacy)
                .map(|d| tail(d).to_vec())
                .unwrap_or_default(),
            pending: Vec::new(),
            started: false,
            frame_block: block_size,
            frame_linked: o.block_linked,
            history: Vec::new(),
            checksum: XxHash32::with_seed(0),
            scratch: Vec::new(),
        })
    }

    /// Plain frames, as the C tier's `new_plain` (what zstd's
    /// `--format=lz4` writes): never one-shot, so the header is exactly
    /// `o`'s. `legacy` is ignored.
    pub fn new_plain(o: &EncodeOptions) -> Result<Encoder, Lz4Error> {
        let mut e = Encoder::new(&EncodeOptions {
            legacy: false,
            ..o.clone()
        })?;
        e.plain = true;
        Ok(e)
    }

    /// Writes the frame header (or the legacy magic) on first call.
    ///
    /// As on the C tier, a frame's header waits until 4 MiB of input have
    /// arrived (an input that ends sooner is laid out as a one-shot frame by
    /// [`Encoder::finish`]); a plain frame's is written at once.
    pub fn update(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), Lz4Error> {
        self.pending.extend_from_slice(input);
        if self.legacy {
            if !self.started {
                out.extend_from_slice(&LEGACY_MAGIC.to_le_bytes());
                self.started = true;
            }
            return self.drain(LEGACY_BLOCK_SIZE, out);
        }
        if !self.started && (self.plain || self.pending.len() >= FRAME_CHUNK) {
            self.begin(self.block_size, self.linked, self.content_size, out);
        }
        if self.started {
            self.drain(self.frame_block.bytes(), out)?;
        }
        Ok(())
    }

    /// Ends the frame: the last block, the end mark and the content
    /// checksum. The encoder can then start another frame.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), Lz4Error> {
        let r = self.finish_inner(out);
        self.pending.clear();
        self.started = false;
        self.history.clear();
        self.checksum = XxHash32::with_seed(0);
        r
    }

    fn finish_inner(&mut self, out: &mut Vec<u8>) -> Result<(), Lz4Error> {
        if self.legacy {
            if !self.started {
                out.extend_from_slice(&LEGACY_MAGIC.to_le_bytes());
            }
            let rest = std::mem::take(&mut self.pending);
            if !rest.is_empty() {
                self.legacy_block(&rest, out)?;
            }
            return Ok(());
        }
        if !self.started {
            if self.plain {
                self.begin(self.block_size, self.linked, self.content_size, out);
            } else {
                // One shot (`LZ4F_compressFrame`): the smallest block size
                // that holds the input, independent if it is one block, and
                // the true content size if one was asked for.
                let n = self.pending.len();
                let id = self.block_size.optimal_for(n);
                let linked = self.linked && n > id.bytes();
                let size = self.content_size.map(|_| n as u64);
                self.begin(id, linked, size, out);
            }
        }
        self.drain(self.frame_block.bytes(), out)?;
        let rest = std::mem::take(&mut self.pending);
        if !rest.is_empty() {
            self.frame_block_out(&rest, out)?;
        }
        out.extend_from_slice(&[0; 4]);
        if self.content_checksum {
            out.extend_from_slice(&self.checksum.finish_32().to_le_bytes());
        }
        Ok(())
    }

    /// The frame header.
    fn begin(&mut self, id: BlockSizeId, linked: bool, size: Option<u64>, out: &mut Vec<u8>) {
        write_frame_header(
            &FrameHeader {
                block_size: id,
                block_linked: linked,
                block_checksum: self.block_checksum,
                content_checksum: self.content_checksum,
                // A content size of 0 means "unknown" (LZ4F_frameInfo_t);
                // liblz4 writes no field for it.
                content_size: size.filter(|&n| n != 0),
                dict_id: None,
                header_len: 0,
            },
            out,
        );
        self.frame_block = id;
        self.frame_linked = linked;
        self.started = true;
    }

    /// Compresses every whole `unit` of pending input.
    fn drain(&mut self, unit: usize, out: &mut Vec<u8>) -> Result<(), Lz4Error> {
        let pending = std::mem::take(&mut self.pending);
        let mut at = 0;
        let mut r = Ok(());
        while pending.len() - at >= unit && r.is_ok() {
            let piece = &pending[at..at + unit];
            r = if self.legacy {
                self.legacy_block(piece, out)
            } else {
                self.frame_block_out(piece, out)
            };
            at += unit;
        }
        self.pending = pending;
        self.pending.drain(..at);
        r
    }

    /// One frame block: its size word (the high bit for a stored block),
    /// the data, and its checksum if the frame has them.
    fn frame_block_out(&mut self, src: &[u8], out: &mut Vec<u8>) -> Result<(), Lz4Error> {
        let dict: &[u8] = if self.frame_linked && !self.history.is_empty() {
            &self.history
        } else {
            &self.dictionary
        };
        let n = compress_block(src, dict, &mut self.scratch)?;
        let start = out.len();
        if n < src.len() {
            out.extend_from_slice(&(n as u32).to_le_bytes());
            out.extend_from_slice(&self.scratch[..n]);
        } else {
            out.extend_from_slice(&(src.len() as u32 | 0x8000_0000).to_le_bytes());
            out.extend_from_slice(src);
        }
        if self.block_checksum {
            let sum = xxh32(&out[start + 4..]);
            out.extend_from_slice(&sum.to_le_bytes());
        }
        if self.content_checksum {
            self.checksum.write(src);
        }
        if self.frame_linked {
            remember(&mut self.history, src);
        }
        Ok(())
    }

    /// One legacy block (always compressed): the size, then the block.
    fn legacy_block(&mut self, src: &[u8], out: &mut Vec<u8>) -> Result<(), Lz4Error> {
        let n = compress_block(src, &[], &mut self.scratch)?;
        if n > LEGACY_BLOCK_BOUND {
            return Err(Lz4Error::Lib(Lz4fError::Generic));
        }
        out.extend_from_slice(&(n as u32).to_le_bytes());
        out.extend_from_slice(&self.scratch[..n]);
        Ok(())
    }
}

/// Where a [`Decoder`] stands in its frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Gathering the header: `need` bytes in all (7 until the flags say
    /// more; 8 for a skippable frame's magic and size).
    Header { need: usize },
    /// Gathering a block-size word.
    BlockSize,
    /// Gathering a block of `len` bytes (its checksum included).
    Block { len: usize, stored: bool },
    /// Gathering the content checksum.
    Checksum,
    /// Skipping a skippable frame's `left` bytes.
    Skip { left: usize },
}

/// An lz4 frame decoder with `LZ4F_decompress`' contract.
pub struct Decoder {
    /// The `-D` dictionary's last 64 KiB.
    dictionary: Vec<u8>,
    stage: Stage,
    /// The bytes of the piece being gathered.
    buf: Vec<u8>,
    /// The current frame's header, once read.
    header: Option<FrameHeader>,
    /// The last 64 KiB decoded (linked blocks), or the dictionary.
    history: Vec<u8>,
    checksum: XxHash32,
    /// Bytes decoded in the current frame.
    produced: u64,
    /// One block's decoded bytes.
    block: Vec<u8>,
}

impl Decoder {
    /// A decoder for `o`.
    pub fn new(o: &DecodeOptions) -> Result<Decoder, Lz4Error> {
        Ok(Decoder {
            dictionary: o
                .dictionary
                .as_deref()
                .map(|d| tail(d).to_vec())
                .unwrap_or_default(),
            stage: Stage::Header {
                need: HEADER_SIZE_MIN,
            },
            buf: Vec::new(),
            header: None,
            history: Vec::new(),
            checksum: XxHash32::with_seed(0),
            produced: 0,
            block: Vec::new(),
        })
    }

    /// LZ4F_decompress semantics: returns (consumed, hint); hint 0 = the frame ended.
    /// Skippable frames are consumed whole (hint 0, nothing produced). Legacy frames:
    /// the caller detects 0x184C2102 and uses `LegacyDecoder`.
    ///
    /// Consumes `input` up to the end of the current frame and no further,
    /// appending what it decodes to `out`. After an error the decoder must
    /// be [`reset`](Decoder::reset) before it is used again.
    pub fn decompress(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(usize, usize), Lz4Error> {
        let mut pos = 0;
        loop {
            if let Stage::Skip { left } = self.stage {
                let take = left.min(input.len() - pos);
                pos += take;
                let left = left - take;
                if left == 0 {
                    self.reset();
                    return Ok((pos, 0));
                }
                self.stage = Stage::Skip { left };
                return Ok((pos, left));
            }
            let want = self.want();
            let take = (want - self.buf.len()).min(input.len() - pos);
            self.buf.extend_from_slice(&input[pos..pos + take]);
            pos += take;
            if self.buf.len() < want {
                return Ok((pos, self.hint(want)));
            }
            if self.step(out)? {
                self.reset();
                return Ok((pos, 0));
            }
        }
    }

    /// How many bytes the current piece needs in all.
    fn want(&self) -> usize {
        match self.stage {
            Stage::Header { need } => need,
            Stage::BlockSize | Stage::Checksum => 4,
            Stage::Block { len, .. } => len,
            Stage::Skip { .. } => 0,
        }
    }

    /// The hint while `want` bytes are being gathered: the rest of the
    /// piece, plus the next block's size word where one follows.
    fn hint(&self, want: usize) -> usize {
        let rest = want - self.buf.len();
        match self.stage {
            Stage::Checksum => rest,
            _ => rest + 4,
        }
    }

    /// Acts on a gathered piece; `true` once the frame has ended.
    fn step(&mut self, out: &mut Vec<u8>) -> Result<bool, Lz4Error> {
        match self.stage {
            Stage::Header { need } => {
                let magic = le32(&self.buf, 0);
                if is_skippable_magic(magic) {
                    if need < 8 {
                        self.stage = Stage::Header { need: 8 };
                    } else {
                        let left = le32(&self.buf, 4) as usize;
                        self.buf.clear();
                        self.stage = Stage::Skip { left };
                    }
                    return Ok(false);
                }
                if magic != MAGIC {
                    return Err(Lz4fError::FrameTypeUnknown.into());
                }
                match parse_frame_header(&self.buf)? {
                    None => {
                        // FLG says the header is longer: 11, 15 or 19.
                        let flg = self.buf[4];
                        let len = HEADER_SIZE_MIN
                            + if flg & 8 != 0 { 8 } else { 0 }
                            + if flg & 1 != 0 { 4 } else { 0 };
                        self.stage = Stage::Header { need: len };
                    }
                    Some(h) => {
                        self.header = Some(h);
                        self.history.clear();
                        self.history.extend_from_slice(&self.dictionary);
                        self.checksum = XxHash32::with_seed(0);
                        self.produced = 0;
                        self.buf.clear();
                        self.stage = Stage::BlockSize;
                    }
                }
                Ok(false)
            }
            Stage::BlockSize => {
                let h = self.frame();
                let word = le32(&self.buf, 0);
                self.buf.clear();
                if word == 0 {
                    // LZ4F checks a recorded size only if it is non-zero.
                    if let Some(n) = h.content_size.filter(|&n| n != 0)
                        && n != self.produced
                    {
                        return Err(Lz4fError::FrameSizeWrong.into());
                    }
                    if !h.content_checksum {
                        return Ok(true);
                    }
                    self.stage = Stage::Checksum;
                    return Ok(false);
                }
                let len = (word & 0x7FFF_FFFF) as usize;
                // Checked before anything is reserved for the block.
                if len > h.block_size.bytes() {
                    return Err(Lz4fError::MaxBlockSizeInvalid.into());
                }
                let stored = word & 0x8000_0000 != 0;
                if !stored && len == 0 {
                    return Err(Lz4fError::DecompressionFailed.into());
                }
                let crc = if h.block_checksum { 4 } else { 0 };
                self.stage = Stage::Block {
                    len: len + crc,
                    stored,
                };
                Ok(false)
            }
            Stage::Block { stored, .. } => {
                let h = self.frame();
                let data_len = self.buf.len() - if h.block_checksum { 4 } else { 0 };
                if h.block_checksum && xxh32(&self.buf[..data_len]) != le32(&self.buf, data_len) {
                    return Err(Lz4fError::BlockChecksumInvalid.into());
                }
                let data = &self.buf[..data_len];
                let decoded: &[u8] = if stored {
                    data
                } else {
                    self.block.resize(h.block_size.bytes(), 0);
                    let r = if self.history.is_empty() {
                        block::decompress_into(data, &mut self.block)
                    } else {
                        block::decompress_into_with_dict(data, &mut self.block, &self.history)
                    };
                    let n = r.map_err(|_| Lz4Error::Lib(Lz4fError::DecompressionFailed))?;
                    &self.block[..n]
                };
                if h.content_checksum {
                    self.checksum.write(decoded);
                }
                self.produced += decoded.len() as u64;
                out.extend_from_slice(decoded);
                if h.block_linked {
                    remember(&mut self.history, decoded);
                }
                self.buf.clear();
                self.stage = Stage::BlockSize;
                Ok(false)
            }
            Stage::Checksum => {
                if le32(&self.buf, 0) != self.checksum.finish_32() {
                    return Err(Lz4fError::ContentChecksumInvalid.into());
                }
                Ok(true)
            }
            Stage::Skip { .. } => unreachable!("handled by decompress"),
        }
    }

    /// The current frame's header: set before any block stage.
    fn frame(&self) -> FrameHeader {
        self.header.unwrap_or(FrameHeader {
            block_size: BlockSizeId::Max64Kb,
            block_linked: false,
            block_checksum: false,
            content_checksum: false,
            content_size: None,
            dict_id: None,
            header_len: 0,
        })
    }

    /// Abandons any frame in progress (`LZ4F_resetDecompressionContext`).
    pub fn reset(&mut self) {
        self.stage = Stage::Header {
            need: HEADER_SIZE_MIN,
        };
        self.buf.clear();
        self.header = None;
        self.history.clear();
        self.produced = 0;
    }
}
