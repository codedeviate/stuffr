//! The pure tier: the `brotli` crate (8.x, its decoder `brotli-decompressor`
//! 5.x) driven with the same parameters as the C tier. Compatible with
//! libbrotli, not byte-identical. What it refuses and how it reads metadata
//! and names errors is in the parent module's doc.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use brotli::enc::StandardAlloc;
use brotli::enc::encode::{
    BrotliEncoderOperation, BrotliEncoderParameter, BrotliEncoderStateStruct,
};
use brotli::enc::interface::{InputPair, PredictionModeContextMap, StaticCommand};
use brotli::{BrotliDecompressStream, BrotliResult, BrotliState, InputReferenceMut};

use super::{
    DecoderError, EncoderParams, OnMetadataChunk, OnMetadataStart, Operation, Refused,
    StreamResult, advance_out, error_name,
};

/// A raw dictionary prepared for the encoder. The pure tier refuses
/// dictionaries, so none is ever made.
pub struct PreparedDictionary {
    never: std::convert::Infallible,
}

impl PreparedDictionary {
    /// Always [`Refused::Dictionary`] on this tier (Ruling T1-b).
    pub fn new(_raw: &[u8], _quality: u32) -> Result<Self, Refused> {
        Err(Refused::Dictionary)
    }
}

/// The crate's encoder with the tool's parameters.
pub struct Encoder {
    state: Box<BrotliEncoderStateStruct<StandardAlloc>>,
}

impl Encoder {
    /// The crate's encoder with quality, `LARGE_WINDOW` when asked, `LGWIN`
    /// and `SIZE_HINT` when present. A dictionary cannot reach here: none can
    /// be made on this tier.
    pub fn new(p: &EncoderParams, dict: Option<&PreparedDictionary>) -> Result<Encoder, Refused> {
        if let Some(d) = dict {
            match d.never {}
        }
        let mut state = Box::new(BrotliEncoderStateStruct::new(StandardAlloc::default()));
        state.set_parameter(BrotliEncoderParameter::BROTLI_PARAM_QUALITY, p.quality);
        if p.large_window {
            state.set_parameter(BrotliEncoderParameter::BROTLI_PARAM_LARGE_WINDOW, 1);
        }
        state.set_parameter(BrotliEncoderParameter::BROTLI_PARAM_LGWIN, p.lgwin);
        if let Some(hint) = p.size_hint {
            state.set_parameter(BrotliEncoderParameter::BROTLI_PARAM_SIZE_HINT, hint);
        }
        Ok(Encoder { state })
    }

    /// `BrotliEncoderCompressStream`: advances `input` and `output` past
    /// what it used. `false` is the encoder's failure.
    pub fn compress_stream(
        &mut self,
        op: Operation,
        input: &mut &[u8],
        output: &mut &mut [u8],
    ) -> bool {
        // The crate writes a one-byte metadata block's header as a
        // zero-byte one (`nbits` 0 where libbrotli 1.2.1 has 1), so the
        // byte that follows corrupts the stream: refused instead, which the
        // tool reports as `failed to emit metadata` (the pure tier's `-C`
        // with a comment of one byte).
        if op == Operation::EmitMetadata && input.len() == 1 {
            return false;
        }
        let op = match op {
            Operation::Process => BrotliEncoderOperation::BROTLI_OPERATION_PROCESS,
            Operation::Flush => BrotliEncoderOperation::BROTLI_OPERATION_FLUSH,
            Operation::Finish => BrotliEncoderOperation::BROTLI_OPERATION_FINISH,
            Operation::EmitMetadata => BrotliEncoderOperation::BROTLI_OPERATION_EMIT_METADATA,
        };
        let mut available_in = input.len();
        let mut in_offset = 0;
        let mut available_out = output.len();
        let mut out_offset = 0;
        let mut total_out = None;
        let mut no_callback = |_: &mut PredictionModeContextMap<InputReferenceMut>,
                               _: &mut [StaticCommand],
                               _: InputPair,
                               _: &mut StandardAlloc| ();
        let ok = self.state.compress_stream(
            op,
            &mut available_in,
            input,
            &mut in_offset,
            &mut available_out,
            output,
            &mut out_offset,
            &mut total_out,
            &mut no_callback,
        );
        *input = &input[in_offset..];
        advance_out(output, out_offset);
        ok
    }

    /// `BrotliEncoderIsFinished`.
    pub fn is_finished(&self) -> bool {
        self.state.is_finished()
    }
}

type State = BrotliState<StandardAlloc, StandardAlloc, StandardAlloc>;

/// The running state's name while a metadata block's contents are read.
const STATE_METADATA: &str = "BROTLI_STATE_METADATA";
/// The running state's name while (or before) a meta-block header is read.
const STATE_METABLOCK_HEADER: &str = "BROTLI_STATE_METABLOCK_HEADER";

/// The metadata callbacks and what the per-byte reading knows.
struct Metadata {
    on_start: OnMetadataStart,
    on_chunk: OnMetadataChunk,
    /// Bytes still to come in the metadata block whose start was reported.
    current: Option<i32>,
    /// `is_metadata` has been seen clear since the last start was reported:
    /// a zero-length block seen complete now is a new one.
    armed: bool,
    /// Hash of the header sub-state's discriminant when it is
    /// `BROTLI_STATE_METABLOCK_HEADER_NONE` (between headers). The crate's
    /// sub-state type is neither nameable nor `Debug`, so it is compared by
    /// discriminant, taken from a fresh state.
    header_none: u64,
}

fn discriminant_hash<T>(v: &T) -> u64 {
    let mut h = DefaultHasher::new();
    std::mem::discriminant(v).hash(&mut h);
    h.finish()
}

fn state_name(s: &State) -> String {
    format!("{:?}", s.state)
}

impl Metadata {
    /// Reports what one call of the crate's decoder did to metadata. `fed`
    /// is the byte it was given, if any (the per-byte reading never gives
    /// it more).
    fn observe(&mut self, s: &State, fed: Option<u8>, consumed: bool) {
        if s.is_metadata == 0 {
            self.armed = true;
            if let Some(left) = self.current.take() {
                // The block ended and the next header began in one call:
                // impossible a byte at a time, but keep the count honest.
                self.chunk(left, fed);
            }
            return;
        }
        let name = state_name(s);
        let in_block = name == STATE_METADATA;
        let remaining = s.meta_block_remaining_len.max(0);
        if let Some(left) = self.current {
            let now = if in_block { remaining } else { 0 };
            self.chunk(left - now, fed);
            self.current = in_block.then_some(now);
            if !in_block {
                self.armed = false;
            }
            return;
        }
        if in_block {
            // A header just completed (always at a byte boundary, so no
            // content byte was read in the same call).
            (self.on_start)(remaining as usize);
            self.current = Some(remaining);
            self.armed = false;
        } else if remaining == 0
            && name == STATE_METABLOCK_HEADER
            && discriminant_hash(&s.substate_metablock_header) == self.header_none
            && (consumed || self.armed)
        {
            // A zero-length metadata block: its header completed and the
            // crate went straight on to the next header.
            (self.on_start)(0);
            self.armed = false;
        }
    }

    fn chunk(&mut self, n: i32, fed: Option<u8>) {
        if n > 0
            && let Some(b) = fed
        {
            (self.on_chunk)(&[b]);
        }
    }
}

/// The crate's decoder as `brotli.c` sets libbrotli's up.
pub struct Decoder {
    state: Box<State>,
    metadata: Option<Metadata>,
}

impl Decoder {
    /// A decoder accepting the large-window extension when asked (the tool
    /// always asks). A dictionary is [`Refused::Dictionary`] on this tier
    /// (Ruling T1-b).
    pub fn new(large_window: bool, dict: Option<&[u8]>) -> Result<Decoder, Refused> {
        if dict.is_some() {
            return Err(Refused::Dictionary);
        }
        let alloc = || StandardAlloc::default();
        let state = if large_window {
            BrotliState::new(alloc(), alloc(), alloc())
        } else {
            BrotliState::new_strict(alloc(), alloc(), alloc())
        };
        Ok(Decoder {
            state: Box::new(state),
            metadata: None,
        })
    }

    /// Metadata callbacks, as libbrotli's `BrotliDecoderSetMetadataCallbacks`
    /// calls them. From here on the decoder is fed one byte per call of the
    /// crate (module doc).
    pub fn set_metadata_callbacks(
        &mut self,
        on_start: OnMetadataStart,
        on_chunk: OnMetadataChunk,
    ) -> Result<(), Refused> {
        let alloc = || StandardAlloc::default();
        let fresh: State = BrotliState::new_strict(alloc(), alloc(), alloc());
        let header_none = discriminant_hash(&fresh.substate_metablock_header);
        self.metadata = Some(Metadata {
            on_start,
            on_chunk,
            current: None,
            armed: true,
            header_none,
        });
        Ok(())
    }

    /// One call of the crate's decoder over `input` and `output`; advances
    /// both. Returns the result and whether input was consumed.
    fn step(&mut self, input: &mut &[u8], output: &mut &mut [u8]) -> (BrotliResult, bool) {
        let mut available_in = input.len();
        let mut in_offset = 0;
        let mut available_out = output.len();
        let mut out_offset = 0;
        let mut total_out = 0;
        let r = BrotliDecompressStream(
            &mut available_in,
            &mut in_offset,
            input,
            &mut available_out,
            &mut out_offset,
            output,
            &mut total_out,
            &mut self.state,
        );
        *input = &input[in_offset..];
        advance_out(output, out_offset);
        (r, in_offset > 0)
    }

    /// `BrotliDecoderDecompressStream`: advances `input` and `output` past
    /// what it used.
    pub fn decompress_stream(&mut self, input: &mut &[u8], output: &mut &mut [u8]) -> StreamResult {
        if self.metadata.is_none() {
            return convert(self.step(input, output).0);
        }
        // First drain whatever the bytes already read allow, with no new
        // input: then each byte fed below is read by itself, and a metadata
        // header always ends at the end of the byte that completes it.
        let mut empty: &[u8] = &[];
        let (mut r, _) = self.step(&mut empty, output);
        self.observe(None, false);
        loop {
            match r {
                BrotliResult::NeedsMoreInput if !input.is_empty() => {}
                other => return convert(other),
            }
            let byte = input[0];
            let mut one = &input[..1];
            let (next, consumed) = self.step(&mut one, output);
            if consumed {
                *input = &input[1..];
            }
            self.observe(Some(byte).filter(|_| consumed), consumed);
            // A decoder that asks for more input while refusing the byte it
            // was given would spin here for ever: answered as an error, so
            // hostile input cannot hang the loop whatever the crate does.
            if !consumed && matches!(next, BrotliResult::NeedsMoreInput) {
                return StreamResult::Error;
            }
            r = next;
        }
    }

    fn observe(&mut self, fed: Option<u8>, consumed: bool) {
        if let Some(m) = self.metadata.as_mut() {
            m.observe(&self.state, fed, consumed);
        }
    }

    /// The decoder's error by libbrotli's number and name. The crate's -15
    /// (`PADDING_2`) raised in a meta-block header is libbrotli's -14
    /// (`PADDING_1`, Ruling T1-e).
    pub fn error(&self) -> DecoderError {
        let mut code = self.state.error_code as i32;
        if code == -15 && state_name(&self.state) == STATE_METABLOCK_HEADER {
            code = -14;
        }
        DecoderError {
            code,
            name: error_name(code),
        }
    }
}

fn convert(r: BrotliResult) -> StreamResult {
    match r {
        BrotliResult::ResultSuccess => StreamResult::Success,
        BrotliResult::NeedsMoreInput => StreamResult::NeedsMoreInput,
        BrotliResult::NeedsMoreOutput => StreamResult::NeedsMoreOutput,
        BrotliResult::ResultFailure => StreamResult::Error,
    }
}
