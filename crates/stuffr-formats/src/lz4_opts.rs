//! The `lz4` tool's options seam: what the lz4 1.10.0 CLI hands liblz4, as
//! Rust types, and a streaming encoder and decoder that take them.
//!
//! This is the layer the `stuffr` binary's lz4 compatibility family drives.
//! It is not the registered `lz4` codec (`lz4.rs`), which keeps its own
//! behaviour; it exposes exactly the knobs the CLI turns and reports
//! liblz4's frame error codes the way the CLI prints them
//! (`LZ4F_getErrorName`).
//!
//! The types, [`parse_frame_header`], [`LegacyDecoder`] and the constants
//! are tier-independent. [`Encoder`], [`Decoder`] and [`liblz4_version`] are
//! the C tier's (`lz4-c`, in `c`) whenever it is compiled, else the pure
//! tier's (in `pure`). Not part of the stable API.
//!
//! ## What the CLI does with liblz4 (measured, spike S1)
//!
//! Everything below was found by comparing this module's output with
//! `/opt/homebrew/opt/lz4/bin/lz4` 1.10.0, never by reading the CLI's source
//! (GPL-2.0-or-later, not read; see `LICENSE-lz4` in `stuffr-cli`):
//!
//! - **Small inputs are one `LZ4F_compressFrame` call.** The CLI reads its
//!   input [`FRAME_CHUNK`] (4 MiB) at a time. An input that ends inside the
//!   first chunk (shorter than 4 MiB, whatever the block size) is compressed
//!   in one shot, which shrinks the block size ID to the smallest that holds
//!   the input (never below 64 KiB, never above the one asked for), makes a
//!   single-block frame independent even under `-BD`, and writes the content
//!   size (the true one) only if it was asked for.
//! - **Larger inputs are streamed in 4 MiB jobs** (lz4 1.10.0 is
//!   multithreaded, and its bytes do not depend on `-T#`): the header is
//!   `LZ4F_compressBegin`'s, at exactly the block size asked for; each job
//!   is compressed as a frame of its own (`LZ4F_compressBegin_usingDict`,
//!   one `LZ4F_compressUpdate`, `LZ4F_compressEnd`), whose blocks become the
//!   frame's; the end mark and the content checksum close it. Under `-BD` a
//!   job is begun against the previous 64 KiB of input lying immediately
//!   before it in memory, so liblz4 continues that prefix (a detached copy of
//!   the same 64 KiB gives different bytes). [`Encoder`] reproduces this
//!   whatever slices its caller feeds it, so it writes nothing until 4 MiB
//!   have arrived or [`Encoder::finish`] is called.
//! - **`-D`** (spike S2) is digested once (`LZ4F_createCDict`) and used for
//!   the one-shot frame, every job of an independent frame and the first
//!   job of a linked one. liblz4 keeps only a dictionary's last 64 KiB, so
//!   the whole file and its last 64 KiB give the same frame.
//! - **`autoFlush`** is unobservable on every path above (0 and 1 give the
//!   same bytes); it is left at 0.
//! - **zstd 1.5.7's `--format=lz4`** (spike S4) is plain `LZ4F` streaming
//!   instead — one `LZ4F_compressUpdate` per 64 KiB block, never one-shot —
//!   which [`Encoder::new_plain`] reproduces.
//! - **`-B#` with a byte count** (`32` up) only chooses the block size ID: the
//!   smallest of 64 KiB, 256 KiB, 1 MiB and 4 MiB that holds `#` bytes (4 MiB
//!   for anything larger). Blocks are then that ID's size; the input is not
//!   cut at `#` bytes. See [`BlockSizeId::for_bytes`].
//! - **Legacy (`-l`)**: the magic, then the input in 8 MiB pieces, each
//!   compressed as one block (always compressed, even when larger).
//!
//! ## The pure tier
//!
//! Its own frame writer and reader over `lz4_flex::block`, following
//! `doc/lz4_Frame_format.md`: the same frame layout, block sizes, flags,
//! checksums and one-shot rule as the C tier, with `lz4_flex`'s single
//! compressor for every level (spec deviation 6: compatible, not
//! byte-identical). The reader checks every block-size word against the
//! frame's declared maximum before it allocates, and a truncated frame is an
//! error, never a short success.

#[cfg(feature = "lz4-c")]
pub mod c;
#[cfg(not(feature = "lz4-c"))]
pub mod pure;

#[cfg(feature = "lz4-c")]
use c::legacy_block_decode;
#[cfg(feature = "lz4-c")]
pub use c::{Decoder, Encoder, liblz4_version};
#[cfg(not(feature = "lz4-c"))]
use pure::legacy_block_decode;
#[cfg(not(feature = "lz4-c"))]
pub use pure::{Decoder, Encoder, liblz4_version};

/// The LZ4 frame magic number (`LZ4F_MAGICNUMBER`).
pub const MAGIC: u32 = 0x184D_2204;
/// The legacy frame's magic number (`lz4 -l`).
pub const LEGACY_MAGIC: u32 = 0x184C_2102;
/// The first skippable-frame magic (`LZ4F_MAGIC_SKIPPABLE_START`); the
/// sixteen values from it up are all skippable.
pub const SKIPPABLE_MAGIC_START: u32 = 0x184D_2A50;
/// `true` for the sixteen skippable-frame magic numbers.
pub fn is_skippable_magic(magic: u32) -> bool {
    magic & 0xFFFF_FFF0 == SKIPPABLE_MAGIC_START
}
/// A legacy block's uncompressed size: every block but the last holds
/// exactly this much.
pub const LEGACY_BLOCK_SIZE: usize = 8 << 20;
/// The largest compressed legacy block: `LZ4_COMPRESSBOUND(8 MiB)`.
pub const LEGACY_BLOCK_BOUND: usize = compress_bound(LEGACY_BLOCK_SIZE);
/// How much input the CLI reads before it commits to streaming a frame
/// (module doc, spike S1).
pub const FRAME_CHUNK: usize = 4 << 20;
/// The smallest frame header (`minFHSize`): magic, FLG, BD, HC.
pub const HEADER_SIZE_MIN: usize = 7;
/// The largest frame header (`maxFHSize`): plus content size and dict ID.
pub const HEADER_SIZE_MAX: usize = 19;

/// `LZ4_COMPRESSBOUND(n)`: the worst-case size of one compressed block.
pub const fn compress_bound(n: usize) -> usize {
    n + n / 255 + 16
}

/// Frame block-size IDs (lz4_Frame_format.md): 4 = 64 KiB … 7 = 4 MiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BlockSizeId {
    /// 64 KiB (`-B4`).
    Max64Kb = 4,
    /// 256 KiB (`-B5`).
    Max256Kb = 5,
    /// 1 MiB (`-B6`).
    Max1Mb = 6,
    /// 4 MiB (`-B7`, the CLI's default).
    Max4Mb = 7,
}

impl BlockSizeId {
    /// The ID numbered `id` (4..=7), as the frame descriptor's BD byte
    /// stores it.
    pub fn from_id(id: u8) -> Option<BlockSizeId> {
        Some(match id {
            4 => BlockSizeId::Max64Kb,
            5 => BlockSizeId::Max256Kb,
            6 => BlockSizeId::Max1Mb,
            7 => BlockSizeId::Max4Mb,
            _ => return None,
        })
    }

    /// The ID's number (4..=7).
    pub fn id(self) -> u8 {
        self as u8
    }

    /// The largest block this ID allows, in bytes (`LZ4F_getBlockSize`).
    pub fn bytes(self) -> usize {
        match self {
            BlockSizeId::Max64Kb => 64 << 10,
            BlockSizeId::Max256Kb => 256 << 10,
            BlockSizeId::Max1Mb => 1 << 20,
            BlockSizeId::Max4Mb => 4 << 20,
        }
    }

    /// The ID `-B#` chooses for a byte count `#` (spike S1, probed:
    /// `lz4 -B32`, `-B65536` → 4; `-B65537`, `-B100000`, `-B262144` → 5;
    /// `-B300000` → 6; `-B1048577`, `-B5000000` → 7): the smallest ID whose
    /// blocks hold `bytes`, 4 MiB for anything larger.
    pub fn for_bytes(bytes: u32) -> BlockSizeId {
        [
            BlockSizeId::Max64Kb,
            BlockSizeId::Max256Kb,
            BlockSizeId::Max1Mb,
        ]
        .into_iter()
        .find(|id| bytes as usize <= id.bytes())
        .unwrap_or(BlockSizeId::Max4Mb)
    }

    /// `LZ4F_optimalBSID`: what a one-shot frame of `src_size` bytes uses
    /// when `self` was asked for — the smallest ID holding `src_size`, never
    /// above `self`.
    pub fn optimal_for(self, src_size: usize) -> BlockSizeId {
        let mut id = BlockSizeId::Max64Kb;
        while id < self {
            if src_size <= id.bytes() {
                return id;
            }
            id = BlockSizeId::from_id(id.id() + 1).unwrap_or(BlockSizeId::Max4Mb);
        }
        self
    }
}

/// What [`Encoder::new`] builds: the preferences the lz4 CLI gives liblz4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodeOptions {
    /// lz4's level as the CLI passes it: --fast=N is -N; 0..=2 fast; 3..=12 HC (C tier).
    pub level: i32,
    /// The block size ID (`-B4`..`-B7`), unless [`block_bytes`](Self::block_bytes)
    /// is set.
    pub block_size: BlockSizeId,
    /// -B# with a byte count (≥ 32): spike S1 found it only chooses the frame's
    /// block size ID ([`BlockSizeId::for_bytes`]), which then overrides
    /// [`block_size`](Self::block_size); the input is not chunked at `#` bytes.
    pub block_bytes: Option<u32>,
    /// `-BD`: linked blocks.
    pub block_linked: bool,
    /// `-BX`: a checksum after every block.
    pub block_checksum: bool,
    /// `--[no-]frame-crc`: the content checksum (the CLI's default is on).
    pub content_checksum: bool,
    /// `--content-size` with the source size known: the size the header
    /// records. A frame compressed in one shot (module doc) records its true
    /// size instead, as `LZ4F_compressFrame` corrects it.
    pub content_size: Option<u64>,
    /// `--favor-decSpeed` (HC levels 10 and up only, in liblz4).
    pub favor_dec_speed: bool,
    /// -D, as the CLI loads it. Spike S2: the whole file and its last 64 KiB
    /// give the same frame (liblz4 keeps only the last 64 KiB), so either may
    /// be passed.
    pub dictionary: Option<Vec<u8>>,
    /// `-l`: the legacy format. Every other frame option is ignored.
    pub legacy: bool,
}

impl Default for EncodeOptions {
    /// `lz4` with no options: level 1, 4 MiB independent blocks, the
    /// content checksum on, no block checksum, no content size.
    fn default() -> Self {
        EncodeOptions {
            level: 1,
            block_size: BlockSizeId::Max4Mb,
            block_bytes: None,
            block_linked: false,
            block_checksum: false,
            content_checksum: true,
            content_size: None,
            favor_dec_speed: false,
            dictionary: None,
            legacy: false,
        }
    }
}

impl EncodeOptions {
    /// The block size ID the frame is asked for: [`block_bytes`](Self::block_bytes)'s
    /// if set, else [`block_size`](Self::block_size).
    pub fn block_size_id(&self) -> BlockSizeId {
        self.block_bytes
            .map_or(self.block_size, BlockSizeId::for_bytes)
    }
}

/// What [`Decoder::new`] builds.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DecodeOptions {
    /// `-D`: the dictionary every frame is decoded with
    /// (`LZ4F_decompress_usingDict`); only its last 64 KiB matter.
    pub dictionary: Option<Vec<u8>>,
}

macro_rules! lz4f_errors {
    ($($variant:ident = $code:literal => $name:literal,)*) => {
        /// LZ4F_errorCodes from lib/lz4frame.h (BSD); the pure tier maps its faults onto the same codes.
        ///
        /// In `LZ4F_LIST_ERRORS`' order (checked against the vendored
        /// liblz4 1.10.0 header); the discriminant is the code
        /// `LZ4F_getErrorCode` returns.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Lz4fError {
            $(
                #[doc = concat!("`", $name, "`.")]
                $variant = $code,
            )*
        }

        impl Lz4fError {
            /// LZ4F_getErrorName's text ("ERROR_frameType_unknown", …).
            pub fn name(self) -> &'static str {
                match self {
                    $(Lz4fError::$variant => $name,)*
                }
            }

            /// The error numbered `code` (`LZ4F_getErrorCode`'s value);
            /// [`Lz4fError::Generic`] for anything outside the list.
            pub fn from_code(code: usize) -> Lz4fError {
                match code {
                    $($code => Lz4fError::$variant,)*
                    _ => Lz4fError::Generic,
                }
            }

            /// The code `LZ4F_getErrorCode` returns for this error.
            pub fn code(self) -> usize {
                self as usize
            }
        }
    };
}

lz4f_errors! {
    Generic = 1 => "ERROR_GENERIC",
    MaxBlockSizeInvalid = 2 => "ERROR_maxBlockSize_invalid",
    BlockModeInvalid = 3 => "ERROR_blockMode_invalid",
    ParameterInvalid = 4 => "ERROR_parameter_invalid",
    CompressionLevelInvalid = 5 => "ERROR_compressionLevel_invalid",
    HeaderVersionWrong = 6 => "ERROR_headerVersion_wrong",
    BlockChecksumInvalid = 7 => "ERROR_blockChecksum_invalid",
    ReservedFlagSet = 8 => "ERROR_reservedFlag_set",
    AllocationFailed = 9 => "ERROR_allocation_failed",
    SrcSizeTooLarge = 10 => "ERROR_srcSize_tooLarge",
    DstMaxSizeTooSmall = 11 => "ERROR_dstMaxSize_tooSmall",
    FrameHeaderIncomplete = 12 => "ERROR_frameHeader_incomplete",
    FrameTypeUnknown = 13 => "ERROR_frameType_unknown",
    FrameSizeWrong = 14 => "ERROR_frameSize_wrong",
    SrcPtrWrong = 15 => "ERROR_srcPtr_wrong",
    DecompressionFailed = 16 => "ERROR_decompressionFailed",
    HeaderChecksumInvalid = 17 => "ERROR_headerChecksum_invalid",
    ContentChecksumInvalid = 18 => "ERROR_contentChecksum_invalid",
    FrameDecodingAlreadyStarted = 19 => "ERROR_frameDecoding_alreadyStarted",
    CompressionStateUninitialized = 20 => "ERROR_compressionState_uninitialized",
    ParameterNull = 21 => "ERROR_parameter_null",
    IoWrite = 22 => "ERROR_io_write",
    IoRead = 23 => "ERROR_io_read",
}

/// What every fallible call in this module returns.
#[derive(Debug)]
pub enum Lz4Error {
    /// A liblz4 frame error (or the pure tier's equivalent).
    Lib(Lz4fError),
    /// An I/O error.
    Io(std::io::Error),
}

impl std::fmt::Display for Lz4Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Lz4Error::Lib(e) => f.write_str(e.name()),
            Lz4Error::Io(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Lz4Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Lz4Error::Lib(_) => None,
            Lz4Error::Io(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for Lz4Error {
    fn from(e: std::io::Error) -> Self {
        Lz4Error::Io(e)
    }
}

impl From<Lz4fError> for Lz4Error {
    fn from(e: Lz4fError) -> Self {
        Lz4Error::Lib(e)
    }
}

/// An LZ4 frame's header, as [`parse_frame_header`] reads it
/// (`LZ4F_frameInfo_t` plus the header's length).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// The largest block the frame may hold.
    pub block_size: BlockSizeId,
    /// Blocks may refer to earlier ones (`blockMode == LZ4F_blockLinked`).
    pub block_linked: bool,
    /// Every block is followed by its checksum.
    pub block_checksum: bool,
    /// The frame ends with a content checksum.
    pub content_checksum: bool,
    /// The content size field, if present.
    pub content_size: Option<u64>,
    /// The dictionary ID field, if present.
    pub dict_id: Option<u32>,
    /// The header's length in bytes, magic included (7..=19).
    pub header_len: usize,
}

/// xxHash32 of `data` with seed 0, the checksum every LZ4 frame field uses.
pub(crate) fn xxh32(data: &[u8]) -> u32 {
    twox_hash::XxHash32::oneshot(0, data)
}

/// Reads a little-endian `u32` at `at`.
pub(crate) fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// Both tiers; used by --list and the pure decoder. Ok(None) = need more bytes.
///
/// `bytes` starts at a frame's magic number. Validation follows
/// `LZ4F_decodeHeader` (`lib/lz4frame.c`) in its order: the magic (a
/// skippable or legacy magic is [`Lz4fError::FrameTypeUnknown`] here — the
/// caller tells those apart by the magic first), FLG's reserved bit, the
/// version, BD's reserved bit, the block size ID, BD's low reserved bits,
/// then the header checksum.
pub fn parse_frame_header(bytes: &[u8]) -> Result<Option<FrameHeader>, Lz4Error> {
    if bytes.len() < HEADER_SIZE_MIN {
        // LZ4F_decodeHeader cannot judge fewer bytes than minFHSize, but a
        // wrong magic is already wrong at four.
        if bytes.len() >= 4 && le32(bytes, 0) != MAGIC {
            return Err(Lz4fError::FrameTypeUnknown.into());
        }
        return Ok(None);
    }
    if le32(bytes, 0) != MAGIC {
        return Err(Lz4fError::FrameTypeUnknown.into());
    }
    let flg = bytes[4];
    if (flg >> 1) & 1 != 0 {
        return Err(Lz4fError::ReservedFlagSet.into());
    }
    if (flg >> 6) & 3 != 1 {
        return Err(Lz4fError::HeaderVersionWrong.into());
    }
    let has_size = (flg >> 3) & 1 != 0;
    let has_dict = flg & 1 != 0;
    let header_len = HEADER_SIZE_MIN + if has_size { 8 } else { 0 } + if has_dict { 4 } else { 0 };
    if bytes.len() < header_len {
        return Ok(None);
    }
    let bd = bytes[5];
    if (bd >> 7) & 1 != 0 {
        return Err(Lz4fError::ReservedFlagSet.into());
    }
    let block_size = BlockSizeId::from_id((bd >> 4) & 7).ok_or(Lz4fError::MaxBlockSizeInvalid)?;
    if bd & 0x0F != 0 {
        return Err(Lz4fError::ReservedFlagSet.into());
    }
    let hc = (xxh32(&bytes[4..header_len - 1]) >> 8) as u8;
    if hc != bytes[header_len - 1] {
        return Err(Lz4fError::HeaderChecksumInvalid.into());
    }
    let mut at = 6;
    let content_size = has_size.then(|| {
        let v = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap_or([0; 8]));
        at += 8;
        v
    });
    let dict_id = has_dict.then(|| le32(bytes, at));
    Ok(Some(FrameHeader {
        block_size,
        block_linked: (flg >> 5) & 1 == 0,
        block_checksum: (flg >> 4) & 1 != 0,
        content_checksum: (flg >> 2) & 1 != 0,
        content_size,
        dict_id,
        header_len,
    }))
}

/// Writes a frame header for `info` (the pure writer's, and a test
/// helper's): FLG, BD, the optional fields, and the header checksum.
#[cfg(any(test, not(feature = "lz4-c")))]
pub(crate) fn write_frame_header(info: &FrameHeader, out: &mut Vec<u8>) {
    let start = out.len();
    out.extend_from_slice(&MAGIC.to_le_bytes());
    let flg = (1u8 << 6)
        | (u8::from(!info.block_linked) << 5)
        | (u8::from(info.block_checksum) << 4)
        | (u8::from(info.content_size.is_some()) << 3)
        | (u8::from(info.content_checksum) << 2)
        | u8::from(info.dict_id.is_some());
    out.push(flg);
    out.push(info.block_size.id() << 4);
    if let Some(n) = info.content_size {
        out.extend_from_slice(&n.to_le_bytes());
    }
    if let Some(id) = info.dict_id {
        out.extend_from_slice(&id.to_le_bytes());
    }
    let hc = (xxh32(&out[start + 4..]) >> 8) as u8;
    out.push(hc);
}

/// Where a [`LegacyDecoder`] stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegacyStage {
    /// Reading the magic number (`have` bytes of it so far).
    Magic,
    /// Reading a block-size word.
    Size,
    /// Reading a block of `n` compressed bytes.
    Block(usize),
    /// The frame ended: a word that cannot be a block size followed.
    Done,
}

/// The legacy frame's block loop (`lz4 -l`'s format): the magic, then
/// blocks of a 4-byte little-endian compressed size and that many bytes,
/// each decoding to at most 8 MiB. Every size word is checked against
/// `LZ4_compressBound(8 MiB)` before anything is allocated for it.
///
/// The frame has no end mark (lz4_Frame_format.md, "Legacy frame"): it ends
/// at end of input, or where a word too large to be a block size stands —
/// a following frame's magic number. [`LegacyDecoder::decompress`] then
/// returns a hint of `0` *without* consuming that word, so the caller reads
/// it as the next frame's magic (or rejects it as garbage).
#[derive(Debug)]
pub struct LegacyDecoder {
    stage: LegacyStage,
    /// The bytes of the current magic, size word or block gathered so far.
    buf: Vec<u8>,
}

impl Default for LegacyDecoder {
    fn default() -> Self {
        LegacyDecoder::new()
    }
}

impl LegacyDecoder {
    /// A decoder expecting the legacy magic number first.
    pub fn new() -> LegacyDecoder {
        LegacyDecoder {
            stage: LegacyStage::Magic,
            buf: Vec::new(),
        }
    }

    /// `true` between blocks: end of input here ends the frame cleanly.
    /// Anywhere else (inside the magic, a size word or a block) end of
    /// input is a truncated frame.
    pub fn at_block_boundary(&self) -> bool {
        matches!(self.stage, LegacyStage::Size | LegacyStage::Done) && self.buf.is_empty()
    }

    /// Decodes from `input`, appending to `out`. Returns `(consumed, hint)`:
    /// `hint` is the number of bytes the decoder wants next, `0` once the
    /// frame has ended (the word that ended it is not consumed).
    /// [`Lz4fError::FrameTypeUnknown`] if `input` does not start with the
    /// legacy magic; [`Lz4fError::DecompressionFailed`] for a corrupt block.
    pub fn decompress(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(usize, usize), Lz4Error> {
        let mut pos = 0;
        loop {
            let want = match self.stage {
                LegacyStage::Done => return Ok((pos, 0)),
                LegacyStage::Magic | LegacyStage::Size => 4,
                LegacyStage::Block(n) => n,
            };
            let take = (want - self.buf.len()).min(input.len() - pos);
            self.buf.extend_from_slice(&input[pos..pos + take]);
            pos += take;
            if self.buf.len() < want {
                return Ok((pos, want - self.buf.len()));
            }
            match self.stage {
                LegacyStage::Magic => {
                    if le32(&self.buf, 0) != LEGACY_MAGIC {
                        return Err(Lz4fError::FrameTypeUnknown.into());
                    }
                    self.stage = LegacyStage::Size;
                }
                LegacyStage::Size => {
                    let n = le32(&self.buf, 0) as usize;
                    if n > LEGACY_BLOCK_BOUND {
                        // Not a block: the next frame's magic. Give it back.
                        pos -= 4;
                        self.buf.clear();
                        self.stage = LegacyStage::Done;
                        return Ok((pos, 0));
                    }
                    self.stage = LegacyStage::Block(n);
                }
                LegacyStage::Block(_) => {
                    let start = out.len();
                    out.resize(start + LEGACY_BLOCK_SIZE, 0);
                    match legacy_block_decode(&self.buf, &mut out[start..]) {
                        Ok(n) => out.truncate(start + n),
                        Err(e) => {
                            out.truncate(start);
                            return Err(e);
                        }
                    }
                    self.stage = LegacyStage::Size;
                }
                LegacyStage::Done => unreachable!("returned above"),
            }
            self.buf.clear();
        }
    }
}

#[cfg(test)]
mod tests;
