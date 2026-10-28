//! The `brotli` tool's options seam: what brotli 1.2.1's `c/tools/brotli.c`
//! hands libbrotli, as Rust types, and the streaming encoder and decoder
//! that take them.
//!
//! This is the layer the `stuffr` binary's brotli compatibility family
//! drives. It is not the registered `brotli` codec (`brotli.rs`), which keeps
//! its own behaviour; it exposes exactly the calls the tool makes —
//! `BrotliEncoderCompressStream` with the tool's operations, the decoder's
//! metadata callbacks (`-C`), raw dictionaries (`-D`), the large-window
//! extension — and reports decoder errors by libbrotli's number and
//! `BrotliDecoderErrorString` name.
//!
//! The types, constants, [`window_for_length`] and [`error_name`] are
//! tier-independent. [`Encoder`], [`Decoder`] and [`PreparedDictionary`] are
//! the C tier's (`brotli-c`, in `c`: libbrotli 1.2.1 vendored under
//! `c/brotli-1.2.1/`, byte-identical to the tool) whenever it is compiled,
//! else the pure tier's (in `pure`: the `brotli` crate, compatible but not
//! byte-identical). Not part of the stable API.
//!
//! ## What the pure tier can do (Task 1's spikes, Rulings T1-b..e)
//!
//! - **`-D` is refused** ([`Refused::Dictionary`], both directions): the
//!   crate's encoder panics with small dictionaries at some qualities, and
//!   its decoder misreads the reference's dictionary streams below a 24-bit
//!   window.
//! - **`-C` works.** Encoding emits the metadata block as libbrotli does.
//!   The crate's decoder has no metadata callbacks, so while callbacks are
//!   set [`Decoder::decompress_stream`] feeds the crate one byte per call and
//!   reads the metadata block off its public state (`is_metadata`,
//!   `meta_block_remaining_len`, the running state's name). Slow, and only
//!   while callbacks are set.
//! - **`--large_window` works** on both sides.
//! - **Error names** map by number through libbrotli's own list
//!   ([`error_name`]); the crate's -15 (`PADDING_2`) raised while it is still
//!   in a meta-block header is libbrotli's -14 (`PADDING_1`). libbrotli's
//!   -10 (`BLOCK_LENGTH_2`) has no counterpart: the crate accepts those
//!   streams or fails later (a stated deviation).

#[cfg(feature = "brotli-c")]
mod c;
#[cfg(not(feature = "brotli-c"))]
mod pure;

#[cfg(feature = "brotli-c")]
pub use c::{Decoder, Encoder, PreparedDictionary};
#[cfg(not(feature = "brotli-c"))]
pub use pure::{Decoder, Encoder, PreparedDictionary};

/// `BROTLI_MIN_WINDOW_BITS`.
pub const MIN_WINDOW_BITS: u32 = 10;
/// `BROTLI_MAX_WINDOW_BITS`: the largest window without the large-window
/// extension.
pub const MAX_WINDOW_BITS: u32 = 24;
/// `BROTLI_LARGE_MAX_WINDOW_BITS`.
pub const LARGE_MAX_WINDOW_BITS: u32 = 30;
/// The tool's dictionary size limit (`kMaxDictionarySize` in `brotli.c`):
/// `BROTLI_MAX_DISTANCE - BROTLI_MAX_BACKWARD_LIMIT(24)`, which it prints
/// in `dictionary [%s] is larger than maximum allowed: %d`.
pub const MAX_DICTIONARY_SIZE: usize = 0x3FF_FFFC - ((1 << 24) - WINDOW_GAP);
/// `BROTLI_WINDOW_GAP`: `BROTLI_MAX_BACKWARD_LIMIT(w)` is `(1 << w) - 16`.
const WINDOW_GAP: usize = 16;

/// The libbrotli version this seam speaks for, on both tiers.
pub fn version() -> (u32, u32, u32) {
    (1, 2, 1)
}

/// The window the tool picks when `-w` is unset or 0: from
/// [`MIN_WINDOW_BITS`] up while the window's backward limit
/// (`(1 << w) - 16`) is below the input length, stopping at
/// [`MAX_WINDOW_BITS`]; [`MAX_WINDOW_BITS`] when the length is unknown
/// (standard input).
pub fn window_for_length(len: Option<u64>) -> u32 {
    let Some(len) = len else {
        return MAX_WINDOW_BITS;
    };
    let mut w = MIN_WINDOW_BITS;
    while (1u64 << w) - (WINDOW_GAP as u64) < len {
        w += 1;
        if w == MAX_WINDOW_BITS {
            break;
        }
    }
    w
}

/// `BrotliEncoderOperation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// `BROTLI_OPERATION_PROCESS`.
    Process,
    /// `BROTLI_OPERATION_FLUSH`.
    Flush,
    /// `BROTLI_OPERATION_FINISH`.
    Finish,
    /// `BROTLI_OPERATION_EMIT_METADATA`: the input is a metadata block's
    /// contents (`-C`), which must be consumed whole in one call.
    EmitMetadata,
}

/// The encoder parameters the tool sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderParams {
    /// `BROTLI_PARAM_QUALITY` (0..=11).
    pub quality: u32,
    /// `BROTLI_PARAM_LGWIN`.
    pub lgwin: u32,
    /// `BROTLI_PARAM_LARGE_WINDOW` (set by the tool only for `lgwin > 24`).
    pub large_window: bool,
    /// `BROTLI_PARAM_SIZE_HINT`, set only when present (the tool: the input
    /// length capped at `1 << 30`, for a non-empty input of known length).
    pub size_hint: Option<u32>,
}

/// `BrotliDecoderResult`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamResult {
    /// `BROTLI_DECODER_RESULT_ERROR`: see [`Decoder::error`].
    Error,
    /// `BROTLI_DECODER_RESULT_SUCCESS`: the stream ended (input may remain).
    Success,
    /// `BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT`.
    NeedsMoreInput,
    /// `BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT`.
    NeedsMoreOutput,
}

/// A decoder error: libbrotli's `BrotliDecoderErrorCode` and the text
/// `BrotliDecoderErrorString` returns for it, prefix and all (for example
/// `_ERROR_FORMAT_PADDING_2`); the tool strips a leading `_ERROR_`
/// (`PrettyDecoderErrorString`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecoderError {
    /// The error code (negative for errors).
    pub code: i32,
    /// `BrotliDecoderErrorString(code)`.
    pub name: &'static str,
}

/// Why an encoder, decoder or dictionary could not be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// libbrotli returned no instance (the tool prints `out of memory`).
    OutOfMemory,
    /// The pure tier cannot check a comment (`-C`). Unused today: Task 1
    /// found it can.
    Comment,
    /// The pure tier cannot use a raw dictionary (`-D`).
    Dictionary,
    /// The pure tier cannot use the large-window extension. Unused today:
    /// Task 1 found it can.
    LargeWindow,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Refused::OutOfMemory => "out of memory",
            Refused::Comment => "comments are not supported by this build",
            Refused::Dictionary => "dictionaries are not supported by this build",
            Refused::LargeWindow => "large windows are not supported by this build",
        })
    }
}

impl std::error::Error for Refused {}

/// `BrotliDecoderErrorString(code)`, from libbrotli 1.2.1's
/// `BROTLI_DECODER_ERROR_CODES_LIST` (`include/brotli/decode.h`): the
/// prefix and name stringified together, `INVALID` for anything else. The
/// pure tier names its errors with it; the C tier asks libbrotli, and a
/// test holds the two equal.
pub fn error_name(code: i32) -> &'static str {
    match code {
        0 => "_NO_ERROR",
        1 => "_SUCCESS",
        2 => "_NEEDS_MORE_INPUT",
        3 => "_NEEDS_MORE_OUTPUT",
        -1 => "_ERROR_FORMAT_EXUBERANT_NIBBLE",
        -2 => "_ERROR_FORMAT_RESERVED",
        -3 => "_ERROR_FORMAT_EXUBERANT_META_NIBBLE",
        -4 => "_ERROR_FORMAT_SIMPLE_HUFFMAN_ALPHABET",
        -5 => "_ERROR_FORMAT_SIMPLE_HUFFMAN_SAME",
        -6 => "_ERROR_FORMAT_CL_SPACE",
        -7 => "_ERROR_FORMAT_HUFFMAN_SPACE",
        -8 => "_ERROR_FORMAT_CONTEXT_MAP_REPEAT",
        -9 => "_ERROR_FORMAT_BLOCK_LENGTH_1",
        -10 => "_ERROR_FORMAT_BLOCK_LENGTH_2",
        -11 => "_ERROR_FORMAT_TRANSFORM",
        -12 => "_ERROR_FORMAT_DICTIONARY",
        -13 => "_ERROR_FORMAT_WINDOW_BITS",
        -14 => "_ERROR_FORMAT_PADDING_1",
        -15 => "_ERROR_FORMAT_PADDING_2",
        -16 => "_ERROR_FORMAT_DISTANCE",
        -17 => "_ERROR_FORMAT_BLOCK_SWITCH",
        -18 => "_ERROR_COMPOUND_DICTIONARY",
        -19 => "_ERROR_DICTIONARY_NOT_SET",
        -20 => "_ERROR_INVALID_ARGUMENTS",
        -21 => "_ERROR_ALLOC_CONTEXT_MODES",
        -22 => "_ERROR_ALLOC_TREE_GROUPS",
        -25 => "_ERROR_ALLOC_CONTEXT_MAP",
        -26 => "_ERROR_ALLOC_RING_BUFFER_1",
        -27 => "_ERROR_ALLOC_RING_BUFFER_2",
        -30 => "_ERROR_ALLOC_BLOCK_TYPE_TREES",
        -31 => "_ERROR_UNREACHABLE",
        _ => "INVALID",
    }
}

/// `Decoder::set_metadata_callbacks`' `on_start`: a metadata block's length.
pub(crate) type OnMetadataStart = Box<dyn FnMut(usize)>;
/// `Decoder::set_metadata_callbacks`' `on_chunk`: some of its contents.
pub(crate) type OnMetadataChunk = Box<dyn FnMut(&[u8])>;

/// Advances `output` past its first `n` bytes.
fn advance_out(output: &mut &mut [u8], n: usize) {
    let out = std::mem::take(output);
    *output = &mut out[n..];
}

#[cfg(test)]
mod tests;
