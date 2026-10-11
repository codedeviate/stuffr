//! The pure tier of [`super`]: the same [`Encoder`], [`Decoder`],
//! [`encoder_memusage`], [`decoder_memusage`] and [`liblzma_version`] as
//! `c`, over `lzma-rust2` 0.20.1 and no C at all.
//!
//! What it promises is the spec's pure-tier promise: the compressed bytes
//! are *compatible*, not identical — `xz` 5.8.4 decodes them to the input,
//! and the container fields this layer controls (the stream flags and so the
//! check, the format, the Block boundaries, each Block's filter chain) are
//! what the C tier writes. The decoder's verdicts are liblzma's: the same
//! [`XzError`] for the same input, with the memory figures liblzma reports
//! (`xz_opts::memusage` is liblzma's formulas, ported).
//!
//! ## The containers are this module's own
//!
//! `.xz` (Stream Header, Block Headers, Index, Stream Footer, Stream
//! Padding), `.lzma`'s 13-byte header and `.lz`'s member framing are written
//! and parsed here, ported from liblzma 5.8.4's `stream_decoder.c`,
//! `block_decoder.c`, `block_header_decoder.c`, `index_hash.c`,
//! `alone_decoder.c`, `lzip_decoder.c` and their encoder counterparts, so
//! that every check and every error is liblzma's. `lzma-rust2` supplies the
//! LZMA1 and LZMA2 coders and the BCJ and delta filters underneath
//! (`Lzma2Writer`, `LzmaWriter`, `BcjWriter`, `DeltaWriter`; `Lzma2Stream`,
//! `LzmaStream`, `StreamFilter`), and `XzWriterMt` for the threaded encoder.
//! The checks (CRC32, CRC64, SHA-256) are computed in `xz_opts::check`.
//!
//! ## Option mappings `lzma-rust2` cannot express exactly
//!
//! - **Match finder:** `lzma-rust2` has HC4 and BT4 only. `hc3` encodes
//!   with HC4; `bt2` and `bt3` with BT4. The memory figures are still
//!   liblzma's for the finder asked for.
//! - **`nice_len`:** clamped to `8..=273`, `lzma-rust2`'s range (liblzma
//!   accepts `2..=273`).
//! - **`depth`:** passed through as `depth_limit` (`0` is the encoder's own
//!   default, as in liblzma, though the defaults differ).
//! - **The threaded encoder** (`threads ≥ 1`) is `XzWriterMt`, whose Blocks
//!   are at least the dictionary size: a `--block-size` below it is raised
//!   to it. Its output does not depend on the thread count, as liblzma's
//!   does not. It encodes LZMA2 alone: 0.20.1's workers never run the
//!   pre-filters its Block Headers name (their output does not decode), and
//!   it cannot switch chains. So a threaded encode with a BCJ or delta
//!   filter, or with a `--block-list`, runs this module's single-threaded
//!   container writer with the threaded encoder's Block boundaries
//!   (`--block-size`, or the chains' `lzma_mt_block_size`, cut at each list
//!   entry), serially.
//! - **Block Headers:** the single-threaded writer, like liblzma's, records
//!   no sizes in them; `XzWriterMt`'s are its own.
//! - **Preset dictionaries:** encoding takes them; decoding raw LZMA2 with
//!   one is [`XzError::Options`] (`Lzma2Stream` has no preset dictionary).
//!   `xz` itself never sets one.
//! - **`flush`** (`LZMA_SYNC_FLUSH`) is `Lzma2Writer::flush`, which ends
//!   the current LZMA2 chunk. It is refused as liblzma refuses it:
//!   [`XzError::Prog`] from the threaded and `.lzma` encoders, which do not
//!   take the action; [`XzError::Options`] from a chain with LZMA1 or a BCJ
//!   filter — in `.xz` only while a Block is open, as `stream_encoder.c`
//!   answers a flush between Blocks without asking the chain.
//!
//! ## Decoding: liblzma's verdicts, with these known differences
//!
//! - **Threads:** decoding is always single-threaded. liblzma's threaded
//!   decoder produces the same output; its `MemLimit.needed` after a refusal
//!   is the same as long as every earlier Block ran in its direct mode,
//!   which is always so at one thread. At two or more, a refusal after
//!   Blocks it decoded threaded can report more (its cached buffers), a
//!   figure that depends on timing in liblzma itself.
//! - **`.lzma` with a known size and an end marker:** liblzma accepts the
//!   marker (`LZMA_LZMA1EXT_ALLOW_EOPM`); `LzmaStream` does not, so the
//!   pure tier calls it corrupt. No encoder `xz` knows writes it.
//! - **A dictionary above 4 GiB - 16:** `LzmaStream` caps the window at
//!   `0xFFFF_FFF0`, which changes nothing for any stream shorter than that.
//!
//! XZ Utils 5.8.4 (`src/liblzma/`), 0BSD.

mod dec;
mod enc;

pub use super::memusage::{decoder_memusage, encoder_memusage};
pub use dec::Decoder;
pub use enc::Encoder;

use super::{Bcj, Lzma, MatchFinder, Mode, XzError};
use lzma_rust2::{EncodeMode, LzmaOptions, MfType};

/// The liblzma this tier answers for: `"5.8.4"`, the version whose
/// formulas, verdicts and container bytes it ports.
pub fn liblzma_version() -> &'static str {
    "5.8.4"
}

/// `xz`'s limit as liblzma holds it: `0` and `u64::MAX` are no limit.
fn limit_of(memlimit: u64) -> u64 {
    if memlimit == 0 { u64::MAX } else { memlimit }
}

/// The `lzma-rust2` options nearest `l` (see the module doc).
fn lzma_options(l: &Lzma) -> LzmaOptions {
    LzmaOptions {
        dict_size: l.dict_size,
        lc: l.lc,
        lp: l.lp,
        pb: l.pb,
        mode: match l.mode {
            Mode::Fast => EncodeMode::Fast,
            Mode::Normal => EncodeMode::Normal,
        },
        nice_len: l
            .nice_len
            .clamp(LzmaOptions::NICE_LEN_MIN, LzmaOptions::NICE_LEN_MAX),
        mf: match l.mf {
            MatchFinder::Hc3 | MatchFinder::Hc4 => MfType::Hc4,
            MatchFinder::Bt2 | MatchFinder::Bt3 | MatchFinder::Bt4 => MfType::Bt4,
        },
        depth_limit: i32::try_from(l.depth).unwrap_or(i32::MAX),
        preset_dict: l.preset_dict.clone(),
    }
}

/// The `.xz` Filter ID of a BCJ filter (`api/lzma/bcj.h`).
fn bcj_id(kind: Bcj) -> u64 {
    match kind {
        Bcj::X86 => 0x04,
        Bcj::PowerPc => 0x05,
        Bcj::Ia64 => 0x06,
        Bcj::Arm => 0x07,
        Bcj::ArmThumb => 0x08,
        Bcj::Sparc => 0x09,
        Bcj::Arm64 => 0x0A,
        Bcj::RiscV => 0x0B,
    }
}

/// Whether `start` suits `kind`: `lzma_simple_coder_init` refuses a
/// `start_offset` that is not a multiple of the filter's alignment
/// (`simple/*.c`) with `LZMA_OPTIONS_ERROR`, encoding and decoding alike.
fn bcj_aligned(kind: Bcj, start: u32) -> bool {
    let alignment = match kind {
        Bcj::X86 => 1,
        Bcj::ArmThumb | Bcj::RiscV => 2,
        Bcj::PowerPc | Bcj::Arm | Bcj::Arm64 | Bcj::Sparc => 4,
        Bcj::Ia64 => 16,
    };
    start.is_multiple_of(alignment)
}

/// The `lzma-rust2` filter type of a BCJ filter.
fn bcj_type(kind: Bcj) -> lzma_rust2::FilterType {
    use lzma_rust2::FilterType as T;
    match kind {
        Bcj::X86 => T::BcjX86,
        Bcj::PowerPc => T::BcjPpc,
        Bcj::Ia64 => T::BcjIa64,
        Bcj::Arm => T::BcjArm,
        Bcj::ArmThumb => T::BcjArmThumb,
        Bcj::Sparc => T::BcjSparc,
        Bcj::Arm64 => T::BcjArm64,
        Bcj::RiscV => T::BcjRiscv,
    }
}

/// An `lzma-rust2` I/O error from a coder, as liblzma would have said it:
/// running out of input at the end is `LZMA_BUF_ERROR`, a refused
/// allocation `LZMA_MEM_ERROR`, anything else corrupt data.
fn coder_error(e: &std::io::Error) -> XzError {
    match e.kind() {
        std::io::ErrorKind::UnexpectedEof => XzError::BufError,
        std::io::ErrorKind::OutOfMemory => XzError::Mem { needed: 0 },
        _ => XzError::Data,
    }
}

/// `lzma_vli_size`: the bytes `v` takes as a `.xz` variable-length integer.
fn vli_size(mut v: u64) -> u64 {
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

/// `lzma_vli_encode`, appended to `out`.
fn vli_encode(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// The `.xz` Stream Header magic and the Stream Footer magic.
const HEADER_MAGIC: [u8; 6] = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];
const FOOTER_MAGIC: [u8; 2] = [0x59, 0x5A];
