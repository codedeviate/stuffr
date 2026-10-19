//! The `zstd` tool's options seam: what zstd 1.5.7's `programs/fileio.c`
//! and `dibio.c` hand libzstd, as Rust types, and a streaming encoder,
//! decoder and dictionary trainer that take them.
//!
//! This is the layer the `stuffr` binary's zstd compatibility family
//! drives. It is not the registered `zstd` codec (`zstd_c.rs`,
//! `zstd_pure.rs`), which keeps its own behaviour; it exposes exactly the
//! knobs the CLI turns and reports libzstd's error codes the way
//! `fileio.c` prints them (`ZSTD_getErrorName`).
//!
//! The types, [`default_cparams`] (libzstd's `clevels.h` table and
//! `ZSTD_getCParams`' size adjustment), [`dict_id`], [`frame_header`] and
//! [`error_name`] are tier-independent. [`Encoder`], [`Decoder`], [`train`]
//! and [`libzstd_version`] are the C tier's (`zstd-c`, in `c`) whenever it
//! is compiled, else the pure tier's (`zstd-pure`, in `pure`), the same
//! exclusivity `register_all` applies to the registered codec. Not part of
//! the stable API.
//!
//! ## The C tier
//!
//! libzstd 1.5.7 itself, vendored by `zstd-sys`, driven through `zstd_sys`
//! directly: `fileio.c` sets parameters `zstd_safe::CParameter` cannot
//! spell (`0` for "the level's default" on every compression parameter, and
//! the three-way `ZSTD_ParamSwitch_e`). [`Encoder::new`] sets them in
//! `FIO_createCResources`' order — the frame flags, the level, then
//! `targetCBlockSize`, `srcSizeHint`, the LDM parameters, the row match
//! finder, the seven compression parameters, literal compression, dedicated
//! dictionary search, then `nbWorkers`, `jobSize`, `overlapLog` and
//! `rsyncable` — then the dictionary or prefix, then the pledged size as
//! `FIO_compressZstdFrame` does. Measured (Task 1's spike S3) against
//! `/opt/homebrew/opt/zstd/bin/zstd` 1.5.7: byte-identical at levels 1, 3
//! and 19, at the default worker count, `-T1`, `-T4`, `--single-thread` and
//! `zstdmt`, on text, binary, random and empty input, and on 48 MiB of text
//! with 2, 3 and 4 workers (whose output does not depend on the count).
//!
//! **Training's notifications** go to the C library's own stderr (fd 2), not
//! through any Rust writer: libzstd's cover and fastcover optimisers print
//! their own lines (`Trying 5 different sets of parameters` at level 2, the
//! `k=`/epoch lines at `-v`) through `DISPLAYLEVEL`. [`TrainParams::notification`]
//! is passed to `ZDICT_params_t.notificationLevel` unchanged, so the caller
//! chooses: the CLI passes its display level under a real host, where fd 2
//! is the terminal both write to, and `0` in the sandbox, where stderr is
//! captured and the fuzz oracle does not compare it. `dibio.c`'s own lines
//! are the caller's to print.
//!
//! ## The pure tier
//!
//! `ruzstd` 0.9.0. [`Encoder`] is its `Fastest` matcher, one frame per
//! [`EndOp::End`], whatever the level (spec deviation 6); every other
//! compression parameter is accepted and ignored, the frame never records a
//! content size, and the window is 128 KiB. `checksum: false` is honoured by
//! an adapter that clears the descriptor's checksum bit and drops the four
//! trailing bytes. A dictionary or prefix for encoding is
//! [`ZstdError::Unsupported`], as is [`train`].
//!
//! [`Decoder`] is this crate's own frame loop over `ruzstd`'s
//! `FrameDecoder`: it skips skippable frames, checks the window against the
//! limit before `ruzstd` allocates one, compares the content checksum
//! (`ruzstd` never does), checks the declared content size, and maps every
//! failure onto the libzstd code `fileio.c` would print. A formatted
//! dictionary decodes through `ruzstd`; a raw-content dictionary or a
//! `--patch-from` prefix decodes through a hand-built `ruzstd` dictionary
//! with libzstd's raw-content repeat offsets `[1, 4, 8]` (spike S1).
//!
//! The `clevels.h` table is ported from zstd 1.5.7 (BSD-3-Clause, Meta
//! Platforms, Inc.; `LICENSE-zstd-clevels`).

mod clevels;

#[cfg(feature = "zstd-c")]
pub mod c;
#[cfg(all(feature = "zstd-pure", not(feature = "zstd-c")))]
pub mod pure;

#[cfg(feature = "zstd-c")]
pub use c::{Decoder, Encoder, libzstd_version, train};
#[cfg(all(feature = "zstd-pure", not(feature = "zstd-c")))]
pub use pure::{Decoder, Encoder, libzstd_version, train};

/// The zstd frame magic number (`ZSTD_MAGICNUMBER`).
pub const MAGIC: u32 = 0xFD2F_B528;
/// A dictionary's magic number (`ZSTD_MAGIC_DICTIONARY`).
pub const MAGIC_DICTIONARY: u32 = 0xEC30_A437;
/// The first skippable-frame magic (`ZSTD_MAGIC_SKIPPABLE_START`); the
/// sixteen values from it up are all skippable.
pub const MAGIC_SKIPPABLE_START: u32 = 0x184D_2A50;
/// `ZSTD_BLOCKSIZE_MAX`: no block regenerates more than 128 KiB.
pub const BLOCKSIZE_MAX: usize = 128 << 10;
/// `ZSTD_WINDOWLOG_MAX`: 31 on a 64-bit target, 30 on a 32-bit one
/// (`ZSTD_WINDOWLOG_MAX_32`).
pub const WINDOWLOG_MAX: u32 = if cfg!(target_pointer_width = "32") {
    30
} else {
    31
};
/// `ZSTD_WINDOWLOG_ABSOLUTEMIN`.
pub const WINDOWLOG_ABSOLUTEMIN: u32 = 10;
/// `ZSTD_minCLevel()`: `-ZSTD_TARGETLENGTH_MAX`.
pub const MIN_CLEVEL: i32 = -(BLOCKSIZE_MAX as i32);
/// `ZSTD_maxCLevel()`.
pub const MAX_CLEVEL: i32 = 22;
/// `ZSTD_CLEVEL_DEFAULT`.
pub const CLEVEL_DEFAULT: i32 = 3;

/// `ZSTD_strategy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strategy {
    /// `ZSTD_fast` (1).
    Fast = 1,
    /// `ZSTD_dfast`.
    Dfast,
    /// `ZSTD_greedy`.
    Greedy,
    /// `ZSTD_lazy`.
    Lazy,
    /// `ZSTD_lazy2`.
    Lazy2,
    /// `ZSTD_btlazy2`.
    Btlazy2,
    /// `ZSTD_btopt`.
    Btopt,
    /// `ZSTD_btultra`.
    Btultra,
    /// `ZSTD_btultra2` (9).
    Btultra2,
}

impl Strategy {
    /// The strategy numbered `n` (1..=9), as `--zstd=strat=` takes it.
    pub fn from_u32(n: u32) -> Option<Strategy> {
        use Strategy::*;
        Some(match n {
            1 => Fast,
            2 => Dfast,
            3 => Greedy,
            4 => Lazy,
            5 => Lazy2,
            6 => Btlazy2,
            7 => Btopt,
            8 => Btultra,
            9 => Btultra2,
            _ => return None,
        })
    }
}

/// `ZSTD_compressionParameters`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CParams {
    /// `windowLog`.
    pub window_log: u32,
    /// `chainLog`.
    pub chain_log: u32,
    /// `hashLog`.
    pub hash_log: u32,
    /// `searchLog`.
    pub search_log: u32,
    /// `minMatch`.
    pub min_match: u32,
    /// `targetLength`.
    pub target_length: u32,
    /// `strategy`.
    pub strategy: Strategy,
}

/// libzstd's default compression parameters for `level`, adjusted for a
/// source of `src_size` bytes and a dictionary of `dict_size`:
/// `ZSTD_getCParams(level, src_size, dict_size)` on a 64-bit target, from
/// the ported `clevels.h` table on both tiers. `None` and `Some(0)` are
/// both an unknown size, as `ZSTD_getCParams` reads `0`.
pub fn default_cparams(level: i32, src_size: Option<u64>, dict_size: usize) -> CParams {
    clevels::get_cparams(level, src_size.unwrap_or(0), dict_size as u64)
}

/// `ZSTD_ParamSwitch_e`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ParamSwitch {
    /// `ZSTD_ps_auto` (0): libzstd decides.
    #[default]
    Auto,
    /// `ZSTD_ps_enable` (1).
    Enable,
    /// `ZSTD_ps_disable` (2).
    Disable,
}

impl ParamSwitch {
    /// The value `ZSTD_CCtx_setParameter` takes.
    pub fn value(self) -> i32 {
        match self {
            ParamSwitch::Auto => 0,
            ParamSwitch::Enable => 1,
            ParamSwitch::Disable => 2,
        }
    }
}

/// The long-distance-matching parameters (`--zstd=ldmHashLog=` and so on).
/// `0` everywhere is "libzstd's default"; `bucket_size_log` and
/// `hash_rate_log` at `0` are not set at all, as `fileio.c` skips its
/// `FIO_LDM_PARAM_NOTSET`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Ldm {
    /// `ZSTD_c_ldmHashLog`.
    pub hash_log: u32,
    /// `ZSTD_c_ldmMinMatch`.
    pub min_match: u32,
    /// `ZSTD_c_ldmBucketSizeLog`.
    pub bucket_size_log: u32,
    /// `ZSTD_c_ldmHashRateLog`.
    pub hash_rate_log: u32,
}

/// One of the seven compression parameters `--zstd=` (and `--long=N`, for
/// the window) overrides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CParamKey {
    /// `ZSTD_c_windowLog` (`wlog=`, `--long=N`).
    WindowLog,
    /// `ZSTD_c_chainLog` (`clog=`).
    ChainLog,
    /// `ZSTD_c_hashLog` (`hlog=`).
    HashLog,
    /// `ZSTD_c_searchLog` (`slog=`).
    SearchLog,
    /// `ZSTD_c_minMatch` (`mml=`).
    MinMatch,
    /// `ZSTD_c_targetLength` (`tlen=`).
    TargetLength,
    /// `ZSTD_c_strategy` (`strat=`), 1..=9.
    Strategy,
}

/// What [`Encoder::new`] builds: `FIO_prefs_t` plus the level, as
/// `FIO_createCResources` reads them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodeOptions {
    /// `ZSTD_c_compressionLevel`.
    pub level: i32,
    /// The compression-parameter overrides (`comprParams`). `fileio.c` sets
    /// all seven after the level, `0` (the level's own value) for any not
    /// given; a key given twice takes its last value.
    pub overrides: Vec<(CParamKey, u32)>,
    /// `ZSTD_c_checksumFlag` (the CLI's default is on).
    pub checksum: bool,
    /// `ZSTD_c_contentSizeFlag`.
    pub content_size: bool,
    /// `ZSTD_c_dictIDFlag`.
    pub dict_id: bool,
    /// `ZSTD_c_nbWorkers`: `0` is single-threaded (`--single-thread`),
    /// `n ≥ 1` is libzstd's multi-threaded mode with `n` workers.
    pub workers: u32,
    /// `ZSTD_c_jobSize` (`-B#`/`--jobsize`), `0` for the default.
    pub job_size: u32,
    /// `ZSTD_c_overlapLog`, set only when given.
    pub overlap_log: Option<i32>,
    /// `ZSTD_c_rsyncable`.
    pub rsyncable: bool,
    /// `ZSTD_c_targetCBlockSize`, `0` for none.
    pub target_cblock_size: u32,
    /// `ZSTD_c_srcSizeHint` (`--size-hint=`), clamped to `INT_MAX` as
    /// `FIO_setSrcSizeHint` stores it.
    pub src_size_hint: Option<u64>,
    /// `ZSTD_CCtx_setPledgedSrcSize`: the file's size, or `--stream-size=`.
    /// [`Encoder::set_pledged_size`] sets it again for each further frame.
    pub pledged_size: Option<u64>,
    /// `ZSTD_c_enableLongDistanceMatching` (`--long` is
    /// [`ParamSwitch::Enable`]).
    pub ldm: ParamSwitch,
    /// The LDM parameters.
    pub ldm_params: Ldm,
    /// `ZSTD_c_useRowMatchFinder`.
    pub row_match_finder: ParamSwitch,
    /// `ZSTD_c_literalCompressionMode`.
    pub literal_compression: ParamSwitch,
    /// `-D`: a dictionary (`ZSTD_CCtx_loadDictionary_byReference`), used
    /// for every frame. Mutually exclusive with `prefix` in `fileio.c`.
    pub dictionary: Option<Vec<u8>>,
    /// `--patch-from`: a prefix (`ZSTD_CCtx_refPrefix`), used for the first
    /// frame only, as libzstd uses a referenced prefix once.
    pub prefix: Option<Vec<u8>>,
}

impl Default for EncodeOptions {
    /// `zstd -3 --single-thread` on a stream: checksum, content size and
    /// dictionary ID on, every parameter at libzstd's default.
    fn default() -> Self {
        EncodeOptions {
            level: CLEVEL_DEFAULT,
            overrides: Vec::new(),
            checksum: true,
            content_size: true,
            dict_id: true,
            workers: 0,
            job_size: 0,
            overlap_log: None,
            rsyncable: false,
            target_cblock_size: 0,
            src_size_hint: None,
            pledged_size: None,
            ldm: ParamSwitch::Auto,
            ldm_params: Ldm::default(),
            row_match_finder: ParamSwitch::Auto,
            literal_compression: ParamSwitch::Auto,
            dictionary: None,
            prefix: None,
        }
    }
}

impl EncodeOptions {
    /// The value `fileio.c` sets for `key`: the last override, else `0`.
    pub fn cparam(&self, key: CParamKey) -> u32 {
        self.overrides
            .iter()
            .rev()
            .find(|(k, _)| *k == key)
            .map_or(0, |&(_, v)| v)
    }
}

/// `ZSTD_EndDirective`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndOp {
    /// `ZSTD_e_continue`.
    Continue,
    /// `ZSTD_e_flush`.
    Flush,
    /// `ZSTD_e_end`: finish the frame.
    End,
}

/// One `ZSTD_compressStream2` call, as [`Encoder::compress_stream_each`]
/// reports it: `fileio.c`'s display-level-6 trace prints these fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamCall {
    /// The directive (`ZSTD_EndDirective`).
    pub end: EndOp,
    /// `inBuff.pos` after the call.
    pub input_pos: usize,
    /// `inBuff.size`.
    pub input_size: usize,
    /// `outBuff.pos`: the bytes the call produced.
    pub produced: usize,
}

/// What [`Decoder::new`] builds: `FIO_createDResources`' settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeOptions {
    /// `ZSTD_DCtx_setMaxWindowSize`, in bytes (`--memory=`, `--long=N` as
    /// `1 << N`; the CLI's default is `1 << 27`). A frame whose window is
    /// larger is refused with `frameParameter_windowTooLarge` before any
    /// window is allocated. Must be within `1 << 10..=1 << 31`
    /// (`parameter_outOfBound` otherwise).
    pub max_window_size: u64,
    /// `ZSTD_d_forceIgnoreChecksum` (`--no-check` when decompressing).
    pub ignore_checksum: bool,
    /// `-D`: a dictionary (`ZSTD_DCtx_loadDictionary_byReference`), used for
    /// every frame; without the dictionary magic it is raw content.
    pub dictionary: Option<Vec<u8>>,
    /// `--patch-from`: a raw-content prefix (`ZSTD_DCtx_refPrefix`), used
    /// for the first frame only — libzstd uses a referenced prefix once, so
    /// a second frame that needs it is corrupt.
    pub prefix: Option<Vec<u8>>,
}

impl Default for DecodeOptions {
    /// The CLI's defaults: a 128 MiB window limit, checksums verified.
    fn default() -> Self {
        DecodeOptions {
            max_window_size: 1 << 27,
            ignore_checksum: false,
            dictionary: None,
            prefix: None,
        }
    }
}

/// `ZSTD_frameProgression`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Progress {
    /// Input bytes the encoder has taken.
    pub ingested: u64,
    /// Input bytes actually compressed.
    pub consumed: u64,
    /// Compressed bytes generated.
    pub produced: u64,
    /// Compressed bytes flushed out.
    pub flushed: u64,
    /// The last started job (multi-threaded only).
    pub current_job_id: u32,
    /// Workers busy now (multi-threaded only).
    pub nb_active_workers: u32,
}

/// The algorithm `--train*` selects, with `zstdcli.c`'s parsed parameters.
/// `k = 0` or `d = 0` asks for the optimising search (`--optimize-cover`
/// semantics), as `zstdcli.c` decides.
#[derive(Debug, Clone, PartialEq)]
pub enum TrainAlgo {
    /// `--train` / `--train-fastcover[=…]` (`ZDICT_fastCover_params_t`).
    Fastcover {
        /// Segment size.
        k: u32,
        /// dmer size.
        d: u32,
        /// log2 of the frequency array size.
        f: u32,
        /// Optimisation steps.
        steps: u32,
        /// Training/testing split, `0 < split ≤ 1`.
        split: f64,
        /// Acceleration, 1..=10.
        accel: u32,
        /// `shrink[=N]`: shrink the dictionary, allowing `N` percent
        /// regression (`shrinkDictMaxRegression`).
        shrink: Option<u32>,
    },
    /// `--train-cover[=…]` (`ZDICT_cover_params_t`).
    Cover {
        /// Segment size.
        k: u32,
        /// dmer size.
        d: u32,
        /// Optimisation steps.
        steps: u32,
        /// Training/testing split.
        split: f64,
        /// `shrink[=N]`.
        shrink: Option<u32>,
    },
    /// `--train-legacy[=s]` (`ZDICT_legacy_params_t`).
    Legacy {
        /// `selectivityLevel`.
        selectivity: u32,
    },
}

/// Everything `DiB_trainFromFiles` hands the trainer besides the samples.
#[derive(Debug, Clone, PartialEq)]
pub struct TrainParams {
    /// The algorithm and its parameters.
    pub algo: TrainAlgo,
    /// Run the optimising search (cover and fastcover only).
    pub optimize: bool,
    /// `--maxdict`: the dictionary's maximum size.
    pub max_dict: usize,
    /// `--dictID` (`0`: random, as libzstd picks).
    pub dict_id: u32,
    /// `ZDICT_params_t.compressionLevel` (`-#` while training).
    pub level: i32,
    /// `nbThreads` for the optimising search.
    pub threads: u32,
    /// `ZDICT_params_t.notificationLevel` (see the module doc).
    pub notification: u32,
}

/// A trained dictionary and the parameters the trainer settled on (the
/// optimising search writes them back, and `dibio.c` prints them).
#[derive(Debug, Clone, PartialEq)]
pub struct Trained {
    /// The dictionary.
    pub dict: Vec<u8>,
    /// `k`.
    pub chosen_k: u32,
    /// `d`.
    pub chosen_d: u32,
    /// `f` (fastcover).
    pub chosen_f: u32,
    /// `accel` (fastcover).
    pub chosen_accel: u32,
    /// `steps`.
    pub chosen_steps: u32,
    /// `splitPoint`.
    pub chosen_split: f64,
}

/// A failure as `fileio.c` sees it.
#[derive(Debug)]
pub enum ZstdError {
    /// libzstd's error code (`ZSTD_getErrorCode`) and its name
    /// (`ZSTD_getErrorName`), which zstd's messages print verbatim; the
    /// pure tier maps its errors onto the same codes.
    Lib {
        /// `ZSTD_ErrorCode`.
        code: u32,
        /// `ZSTD_getErrorString(code)`.
        name: &'static str,
    },
    /// Not available on the pure tier: `"dictionary"` (encoding with a
    /// dictionary or prefix) or `"train"`.
    Unsupported(&'static str),
    /// An I/O failure around the coder.
    Io(std::io::Error),
}

impl ZstdError {
    /// The [`ZstdError::Lib`] for `code`.
    pub fn lib(code: u32) -> ZstdError {
        ZstdError::Lib {
            code,
            name: error_name(code),
        }
    }

    /// The libzstd error code, for [`ZstdError::Lib`].
    pub fn code(&self) -> Option<u32> {
        match self {
            ZstdError::Lib { code, .. } => Some(*code),
            _ => None,
        }
    }
}

impl std::fmt::Display for ZstdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZstdError::Lib { name, .. } => f.write_str(name),
            ZstdError::Unsupported(what) => {
                write!(
                    f,
                    "{what} is not available in this build (stuffr pure tier)"
                )
            }
            ZstdError::Io(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ZstdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ZstdError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ZstdError {
    fn from(e: std::io::Error) -> Self {
        ZstdError::Io(e)
    }
}

/// `ZSTD_ErrorCode` values this module raises by name.
pub mod code {
    /// `ZSTD_error_prefix_unknown`.
    pub const PREFIX_UNKNOWN: u32 = 10;
    /// `ZSTD_error_frameParameter_unsupported`.
    pub const FRAME_PARAMETER_UNSUPPORTED: u32 = 14;
    /// `ZSTD_error_frameParameter_windowTooLarge`.
    pub const WINDOW_TOO_LARGE: u32 = 16;
    /// `ZSTD_error_corruption_detected`.
    pub const CORRUPTION_DETECTED: u32 = 20;
    /// `ZSTD_error_checksum_wrong`.
    pub const CHECKSUM_WRONG: u32 = 22;
    /// `ZSTD_error_dictionary_corrupted`.
    pub const DICTIONARY_CORRUPTED: u32 = 30;
    /// `ZSTD_error_dictionary_wrong`.
    pub const DICTIONARY_WRONG: u32 = 32;
    /// `ZSTD_error_parameter_outOfBound`.
    pub const PARAMETER_OUT_OF_BOUND: u32 = 42;
    /// `ZSTD_error_memory_allocation`.
    pub const MEMORY_ALLOCATION: u32 = 64;
    /// `ZSTD_error_dstSize_tooSmall`.
    pub const DST_SIZE_TOO_SMALL: u32 = 70;
    /// `ZSTD_error_srcSize_wrong`.
    pub const SRC_SIZE_WRONG: u32 = 72;
}

/// `ZSTD_getErrorString(code)`: libzstd 1.5.7's `ERR_getErrorString`
/// table, on both tiers.
pub fn error_name(code: u32) -> &'static str {
    match code {
        0 => "No error detected",
        1 => "Error (generic)",
        10 => "Unknown frame descriptor",
        12 => "Version not supported",
        14 => "Unsupported frame parameter",
        16 => "Frame requires too much memory for decoding",
        20 => "Data corruption detected",
        22 => "Restored data doesn't match checksum",
        24 => "Header of Literals' block doesn't respect format specification",
        40 => "Unsupported parameter",
        41 => "Unsupported combination of parameters",
        42 => "Parameter is out of bound",
        62 => "Context should be init first",
        64 => "Allocation error : not enough memory",
        66 => "workSpace buffer is not large enough",
        60 => "Operation not authorized at current processing stage",
        44 => "tableLog requires too much memory : unsupported",
        46 => "Unsupported max Symbol Value : too large",
        48 => "Specified maxSymbolValue is too small",
        49 => "This mode cannot generate an uncompressed block",
        50 => "pledged buffer stability condition is not respected",
        30 => "Dictionary is corrupted",
        32 => "Dictionary mismatch",
        34 => "Cannot create Dictionary from provided samples",
        70 => "Destination buffer is too small",
        72 => "Src size is incorrect",
        74 => "Operation on NULL destination buffer",
        80 => "Operation made no progress over multiple calls, due to output buffer being full",
        82 => "Operation made no progress over multiple calls, due to input being empty",
        100 => "Frame index is too large",
        102 => "An I/O error occurred when reading/seeking",
        104 => "Destination buffer is wrong",
        105 => "Source buffer is wrong",
        106 => "Block-level external sequence producer returned an error code",
        107 => "External sequences are not valid",
        _ => "Unspecified error code",
    }
}

/// `ZDICT_getDictID`: the ID a formatted dictionary declares, or `0` for
/// raw content (shorter than eight bytes, or without the dictionary
/// magic). A header read, on both tiers.
pub fn dict_id(dict: &[u8]) -> u32 {
    if dict.len() < 8
        || u32::from_le_bytes([dict[0], dict[1], dict[2], dict[3]]) != MAGIC_DICTIONARY
    {
        return 0;
    }
    u32::from_le_bytes([dict[4], dict[5], dict[6], dict[7]])
}

/// What [`frame_header`] reads at the start of a frame
/// (`ZSTD_FrameHeader`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameHeader {
    /// A zstd frame (`ZSTD_frame`).
    Zstd {
        /// The header's size in bytes, magic included.
        header_size: usize,
        /// `Window_Size`; for a single-segment frame, the content size.
        window_size: u64,
        /// `Frame_Content_Size`, if the header records it.
        content_size: Option<u64>,
        /// `Dictionary_ID` (`0`: none).
        dict_id: u32,
        /// `Content_Checksum_flag`.
        checksum: bool,
        /// `Single_Segment_flag`.
        single_segment: bool,
    },
    /// A skippable frame (`ZSTD_skippableFrame`) of `content_size` bytes
    /// after its eight-byte header.
    Skippable {
        /// The magic's low nibble.
        variant: u32,
        /// `Frame_Size`.
        content_size: u32,
    },
}

/// Why [`frame_header`] returned no header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameHeaderError {
    /// `src` is too short: this many bytes are wanted
    /// (`ZSTD_getFrameHeader`'s positive return).
    Incomplete(usize),
    /// The libzstd error code: `prefix_unknown` (not a zstd or skippable
    /// frame), `frameParameter_unsupported` (the reserved bit) or
    /// `frameParameter_windowTooLarge` (a window log above 31).
    Lib(u32),
}

/// `ZSTD_getFrameHeader` (format `ZSTD_f_zstd1`, 64-bit): the header at
/// the start of `src`, on both tiers.
pub fn frame_header(src: &[u8]) -> Result<FrameHeader, FrameHeaderError> {
    const MIN_INPUT: usize = 5;
    if src.len() < MIN_INPUT {
        if !src.is_empty() {
            // Fewer bytes than a header: they must still begin a supported
            // magic, checked with the missing bytes taken from it.
            let n = src.len().min(4);
            let mut hbuf = MAGIC.to_le_bytes();
            hbuf[..n].copy_from_slice(&src[..n]);
            if u32::from_le_bytes(hbuf) != MAGIC {
                let mut hbuf = MAGIC_SKIPPABLE_START.to_le_bytes();
                hbuf[..n].copy_from_slice(&src[..n]);
                if u32::from_le_bytes(hbuf) & 0xFFFF_FFF0 != MAGIC_SKIPPABLE_START {
                    return Err(FrameHeaderError::Lib(code::PREFIX_UNKNOWN));
                }
            }
        }
        return Err(FrameHeaderError::Incomplete(MIN_INPUT));
    }
    let magic = u32::from_le_bytes([src[0], src[1], src[2], src[3]]);
    if magic != MAGIC {
        if magic & 0xFFFF_FFF0 == MAGIC_SKIPPABLE_START {
            if src.len() < 8 {
                return Err(FrameHeaderError::Incomplete(8));
            }
            return Ok(FrameHeader::Skippable {
                variant: magic - MAGIC_SKIPPABLE_START,
                content_size: u32::from_le_bytes([src[4], src[5], src[6], src[7]]),
            });
        }
        return Err(FrameHeaderError::Lib(code::PREFIX_UNKNOWN));
    }
    let fhd = src[4];
    let dict_id_code = usize::from(fhd & 3);
    let checksum = fhd & 4 != 0;
    let single_segment = fhd & 0x20 != 0;
    let fcs_id = usize::from(fhd >> 6);
    const DID_SIZE: [usize; 4] = [0, 1, 2, 4];
    const FCS_SIZE: [usize; 4] = [0, 2, 4, 8];
    let fcs_size = FCS_SIZE[fcs_id] + usize::from(single_segment && fcs_id == 0);
    let header_size = MIN_INPUT + usize::from(!single_segment) + DID_SIZE[dict_id_code] + fcs_size;
    if src.len() < header_size {
        return Err(FrameHeaderError::Incomplete(header_size));
    }
    if fhd & 0x08 != 0 {
        return Err(FrameHeaderError::Lib(code::FRAME_PARAMETER_UNSUPPORTED));
    }
    let mut pos = MIN_INPUT;
    let mut window_size = 0u64;
    if !single_segment {
        let wl = src[pos];
        pos += 1;
        let window_log = u32::from(wl >> 3) + WINDOWLOG_ABSOLUTEMIN;
        if window_log > WINDOWLOG_MAX {
            return Err(FrameHeaderError::Lib(code::WINDOW_TOO_LARGE));
        }
        window_size = 1u64 << window_log;
        window_size += (window_size >> 3) * u64::from(wl & 7);
    }
    let le = |b: &[u8]| {
        b.iter()
            .rev()
            .fold(0u64, |acc, &x| (acc << 8) | u64::from(x))
    };
    let dict_id = le(&src[pos..pos + DID_SIZE[dict_id_code]]) as u32;
    pos += DID_SIZE[dict_id_code];
    let content_size = match fcs_size {
        0 => None,
        2 => Some(le(&src[pos..pos + 2]) + 256),
        n => Some(le(&src[pos..pos + n])),
    };
    if single_segment {
        window_size = content_size.unwrap_or(0);
    }
    Ok(FrameHeader::Zstd {
        header_size,
        window_size,
        content_size,
        dict_id,
        checksum,
        single_segment,
    })
}

#[cfg(test)]
mod tests;
