//! The `xz` tool's options seam: what XZ Utils 5.8.4's `xz` hands liblzma,
//! as Rust types, and a streaming encoder and decoder that take them.
//!
//! This is the layer the `stuffr` binary's xz compatibility family drives.
//! It is not the registered `xz`/`lzma` codecs (`xz_c.rs`, `xz_pure.rs`,
//! `lzma_c.rs`, `lzma_pure.rs`), which keep their own behaviour; it exposes
//! exactly the knobs `xz`'s `coder.c` turns — a filter chain of up to four
//! filters, the check, the thread count, `--block-size`, `--block-list` with
//! `--filters1..9`, the memory limits — and reports liblzma's return codes
//! as [`XzError`] the way `coder.c`'s `coder_normal`/`message_strm` read
//! them.
//!
//! The types and [`Lzma::preset`] are tier-independent. [`Encoder`],
//! [`Decoder`], [`encoder_memusage`], [`decoder_memusage`] and
//! [`liblzma_version`] are the C tier's (`xz-c`, in `c`) whenever it is
//! compiled, else the pure tier's (`xz-pure`, in `pure`), as the
//! registered codecs pick theirs; `physmem` and `cputhreads` exist on
//! the C tier only. [`memusage`] is liblzma's formulas on either tier,
//! with [`Profile`] choosing this build's liblzma or the reference `xz`'s
//! figures ([`decoder_memusage_with`], [`encoder_memusage_with`]). The pure
//! tier is compiled whenever `xz-pure` is, so an
//! `--all-features` build tests the two against each other. Not part of
//! the stable API.
//!
//! Ported from XZ Utils 5.8.4 (`src/xz/coder.c`,
//! `src/liblzma/lzma/lzma_encoder_presets.c`, and, for the pure tier,
//! `src/liblzma/` as `pure` and `memusage` list), 0BSD.

#[cfg(feature = "xz-c")]
pub mod c;
#[cfg(feature = "xz-pure")]
mod check;
pub mod memusage;
#[cfg(feature = "xz-pure")]
pub mod pure;
#[cfg(feature = "xz-c")]
pub use c::{
    Decoder, Encoder, cputhreads, decoder_memusage, encoder_memusage, liblzma_version, physmem,
};
pub use memusage::{Profile, decoder_memusage_with, encoder_memusage_with};
#[cfg(all(feature = "xz-pure", not(feature = "xz-c")))]
pub use pure::{Decoder, Encoder, decoder_memusage, encoder_memusage, liblzma_version};

/// The container (`--format`). [`Format::Lzip`] decodes only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// `.xz`.
    Xz,
    /// `.lzma` (LZMA_Alone).
    Lzma,
    /// No container: the filter chain's output alone.
    Raw,
    /// `.lz`, decode only.
    Lzip,
}

/// The integrity check (`--check`), as liblzma numbers them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    /// `LZMA_CHECK_NONE` (0).
    None,
    /// `LZMA_CHECK_CRC32` (1).
    Crc32,
    /// `LZMA_CHECK_CRC64` (4), `xz`'s default.
    Crc64,
    /// `LZMA_CHECK_SHA256` (10).
    Sha256,
}

impl Check {
    /// The check's ID in the stream flags (`lzma_check`).
    pub fn id(self) -> u32 {
        match self {
            Check::None => 0,
            Check::Crc32 => 1,
            Check::Crc64 => 4,
            Check::Sha256 => 10,
        }
    }
}

/// The LZMA match finder (`mf=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchFinder {
    /// `LZMA_MF_HC3`.
    Hc3,
    /// `LZMA_MF_HC4`.
    Hc4,
    /// `LZMA_MF_BT2`.
    Bt2,
    /// `LZMA_MF_BT3`.
    Bt3,
    /// `LZMA_MF_BT4`.
    Bt4,
}

/// The LZMA compression mode (`mode=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `LZMA_MODE_FAST`.
    Fast,
    /// `LZMA_MODE_NORMAL`.
    Normal,
}

/// `lzma_options_lzma`: the options of an LZMA1 or LZMA2 filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lzma {
    /// Dictionary size in bytes.
    pub dict_size: u32,
    /// Literal context bits.
    pub lc: u32,
    /// Literal position bits.
    pub lp: u32,
    /// Position bits.
    pub pb: u32,
    /// Compression mode.
    pub mode: Mode,
    /// Nice length of a match.
    pub nice_len: u32,
    /// Match finder.
    pub mf: MatchFinder,
    /// Maximum match finder search depth (0 = the encoder picks).
    pub depth: u32,
    /// A preset dictionary (`preset_dict`), if any.
    pub preset_dict: Option<Vec<u8>>,
}

impl Lzma {
    /// `lzma_lzma_preset(level | (extreme ? LZMA_PRESET_EXTREME : 0))`:
    /// the options behind `xz -<level>[e]`, or `None` for a level above 9.
    pub fn preset(level: u32, extreme: bool) -> Option<Lzma> {
        if level > 9 {
            return None;
        }
        const DICT_POW2: [u8; 10] = [18, 20, 21, 22, 22, 23, 23, 24, 25, 26];
        let (mut mode, mut mf, mut nice_len, mut depth) = if level <= 3 {
            const DEPTHS: [u32; 4] = [4, 8, 24, 48];
            (
                Mode::Fast,
                if level == 0 {
                    MatchFinder::Hc3
                } else {
                    MatchFinder::Hc4
                },
                if level <= 1 { 128 } else { 273 },
                DEPTHS[level as usize],
            )
        } else {
            let nice = match level {
                4 => 16,
                5 => 32,
                _ => 64,
            };
            (Mode::Normal, MatchFinder::Bt4, nice, 0)
        };
        if extreme {
            mode = Mode::Normal;
            mf = MatchFinder::Bt4;
            if level == 3 || level == 5 {
                nice_len = 192;
                depth = 0;
            } else {
                nice_len = 273;
                depth = 512;
            }
        }
        Some(Lzma {
            dict_size: 1 << DICT_POW2[level as usize],
            lc: 3,
            lp: 0,
            pb: 2,
            mode,
            nice_len,
            mf,
            depth,
            preset_dict: None,
        })
    }
}

/// A branch/call/jump (BCJ) filter's architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bcj {
    /// `LZMA_FILTER_X86`.
    X86,
    /// `LZMA_FILTER_POWERPC`.
    PowerPc,
    /// `LZMA_FILTER_IA64`.
    Ia64,
    /// `LZMA_FILTER_ARM`.
    Arm,
    /// `LZMA_FILTER_ARMTHUMB`.
    ArmThumb,
    /// `LZMA_FILTER_ARM64`.
    Arm64,
    /// `LZMA_FILTER_SPARC`.
    Sparc,
    /// `LZMA_FILTER_RISCV`.
    RiscV,
}

/// One filter of a chain (`lzma_filter`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    /// `LZMA_FILTER_LZMA1`, with the end-of-payload marker (`.lzma`, raw).
    Lzma1(Lzma),
    /// `LZMA_FILTER_LZMA1EXT`. `xz` never builds it; here it carries
    /// `LZMA_LZMA1EXT_ALLOW_EOPM` and an unknown uncompressed size, so it
    /// encodes and decodes as LZMA1 does.
    Lzma1Ext(Lzma),
    /// `LZMA_FILTER_LZMA2`.
    Lzma2(Lzma),
    /// A BCJ filter with its `start_offset`.
    Bcj {
        /// Architecture.
        kind: Bcj,
        /// `lzma_options_bcj.start_offset`.
        start: u32,
    },
    /// `LZMA_FILTER_DELTA` (byte-wise) with its distance.
    Delta {
        /// `lzma_options_delta.dist`, 1..=256.
        dist: u32,
    },
}

/// What [`Encoder::new`] builds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodeOptions {
    /// The container. [`Format::Lzip`] is refused ([`XzError::Options`]).
    pub format: Format,
    /// The default filter chain, 1..=4 filters, the last LZMA1 or LZMA2.
    /// With [`Format::Lzma`] it must be exactly one [`Filter::Lzma1`].
    pub filters: Vec<Filter>,
    /// The integrity check (`.xz` only).
    pub check: Check,
    /// `0` is the single-threaded `lzma_stream_encoder` (`xz -T1`); `n ≥ 1`
    /// is `lzma_stream_encoder_mt` with `n` threads, `.xz` only. The bytes
    /// of the threaded encoder do not depend on `n`.
    pub threads: u32,
    /// `--block-size`: `0` is the encoder's default. Single-threaded, a new
    /// Block starts after this many input bytes (`LZMA_FULL_BARRIER`);
    /// threaded, it is `lzma_mt.block_size`.
    pub block_size: u64,
    /// `--block-list`, already parsed: each entry is a Block's uncompressed
    /// size (non-zero; `u64::MAX` for `xz`'s trailing `0`) and its filter
    /// chain (`None` = [`EncodeOptions::filters`], `Some` = a
    /// `--filtersN` chain). After the last entry its size and chain repeat,
    /// as `coder.c`'s `split_block` does. `.xz` only.
    pub block_list: Vec<(u64, Option<Vec<Filter>>)>,
    /// `--flush-timeout`, carried for the caller, which owns the clock and
    /// calls [`Encoder::flush`]; the encoder itself never reads it.
    pub flush_timeout_ms: u64,
    /// A hard memory limit (`0` or `u64::MAX`: none). [`Encoder::new`]
    /// refuses a setup whose [`encoder_memusage`] exceeds it with
    /// [`XzError::MemLimit`]; adjusting the settings down to fit is the
    /// caller's (`coder_set_compression_settings`).
    pub memlimit: u64,
}

impl Default for EncodeOptions {
    /// `xz -T1 -6`: `.xz`, LZMA2 preset 6, CRC64, single-threaded.
    fn default() -> Self {
        EncodeOptions {
            format: Format::Xz,
            filters: vec![Filter::Lzma2(Lzma::preset(6, false).expect("6 ≤ 9"))],
            check: Check::Crc64,
            threads: 0,
            block_size: 0,
            block_list: Vec::new(),
            flush_timeout_ms: 0,
            memlimit: u64::MAX,
        }
    }
}

/// What [`Decoder::new`] builds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeOptions {
    /// The container, unless [`DecodeOptions::auto`].
    pub format: Format,
    /// Detect the container from the input instead: `.lz` by its magic,
    /// anything else through `lzma_auto_decoder` (`.xz` or `.lzma`).
    pub auto: bool,
    /// The filter chain for [`Format::Raw`].
    pub raw_filters: Vec<Filter>,
    /// The memory limit (`0` or `u64::MAX`: none); for `.xz` it is
    /// `lzma_mt.memlimit_stop`.
    pub memlimit: u64,
    /// `--single-stream`: no `LZMA_CONCATENATED`, and input after the first
    /// stream is left unconsumed rather than an error.
    pub single_stream: bool,
    /// `--ignore-check`: `LZMA_IGNORE_CHECK` instead of
    /// `LZMA_TELL_UNSUPPORTED_CHECK`.
    pub ignore_check: bool,
    /// `lzma_mt.threads` for `.xz` (`0` counts as `1`). At one thread the
    /// decoder runs single-threaded, as `xz -T1` does.
    pub threads: u32,
    /// `lzma_mt.memlimit_threading` when `threads ≥ 2` (`xz`'s
    /// `hardware_memlimit_mtdec_get`); unused at one thread, where `xz`
    /// passes `0`.
    pub memlimit_threading: u64,
}

impl Default for DecodeOptions {
    /// `.xz`, no limit, concatenated, checks verified, one thread.
    fn default() -> Self {
        DecodeOptions {
            format: Format::Xz,
            auto: false,
            raw_filters: Vec::new(),
            memlimit: u64::MAX,
            single_stream: false,
            ignore_check: false,
            threads: 1,
            memlimit_threading: 0,
        }
    }
}

/// Bytes in and out so far (`lzma_get_progress`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Progress {
    /// Input bytes consumed.
    pub in_bytes: u64,
    /// Output bytes produced.
    pub out_bytes: u64,
}

/// A liblzma return code as `xz` reads it (`message_strm`).
#[derive(Debug)]
pub enum XzError {
    /// `LZMA_MEM_ERROR`; `needed` is the coder's `lzma_memusage` (0 when
    /// unknown).
    Mem {
        /// Bytes the coder reported needing.
        needed: u64,
    },
    /// `LZMA_MEMLIMIT_ERROR`, or a setup refused against the limit.
    MemLimit {
        /// `lzma_memusage`: what it would have needed.
        needed: u64,
        /// The limit in force.
        limit: u64,
    },
    /// `LZMA_FORMAT_ERROR`: file format not recognized.
    Format,
    /// `LZMA_OPTIONS_ERROR`: unsupported options.
    Options,
    /// `LZMA_DATA_ERROR`: compressed data is corrupt (also trailing garbage
    /// after a stream that may not have any).
    Data,
    /// `LZMA_BUF_ERROR`: unexpected end of input.
    BufError,
    /// `LZMA_UNSUPPORTED_CHECK` where it is fatal (an encoder's check), with
    /// the check ID.
    UnsupportedCheck(u32),
    /// `LZMA_PROG_ERROR`, or any return code `xz` treats as a bug.
    Prog,
    /// An I/O failure around the coder.
    Io(std::io::Error),
}

impl std::fmt::Display for XzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XzError::Mem { .. } => f.write_str("Cannot allocate memory"),
            XzError::MemLimit { .. } => f.write_str("Memory usage limit reached"),
            XzError::Format => f.write_str("File format not recognized"),
            XzError::Options => f.write_str("Unsupported options"),
            XzError::Data => f.write_str("Compressed data is corrupt"),
            XzError::BufError => f.write_str("Unexpected end of input"),
            XzError::UnsupportedCheck(id) => {
                write!(f, "Unsupported type of integrity check ({id})")
            }
            XzError::Prog => f.write_str("Internal error (bug)"),
            XzError::Io(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for XzError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            XzError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for XzError {
    fn from(e: std::io::Error) -> Self {
        XzError::Io(e)
    }
}

#[cfg(test)]
mod tests;
