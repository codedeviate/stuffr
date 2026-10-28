//! The C tier: libbrotli 1.2.1, vendored under `c/brotli-1.2.1/` and
//! compiled by `build.rs` into `libbrotli_vendored.a`, driven with the calls
//! `c/tools/brotli.c` makes.
//!
//! The functions are declared by hand from `include/brotli/{encode,decode,
//! shared_dictionary}.h`. libbrotli keeps pointers to what it is given: a
//! prepared dictionary points into its raw bytes, an encoder at the prepared
//! dictionary attached to it, a decoder into its raw dictionary and at the
//! metadata callbacks' context. Each of those lives in a heap allocation
//! owned beside the pointer that uses it ([`PreparedDictionary`] behind an
//! `Arc` the encoder clones), and every `Drop` destroys the libbrotli object
//! before its fields are freed.
//!
//! Every `unsafe` block is an FFI call into libbrotli and states the
//! invariant it relies on.

use std::any::Any;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::ptr::{self, NonNull};
use std::sync::Arc;

use super::{
    DecoderError, EncoderParams, OnMetadataChunk, OnMetadataStart, Operation, Refused,
    StreamResult, advance_out,
};

/// `BrotliEncoderState` (opaque).
#[repr(C)]
struct EncoderState {
    _private: [u8; 0],
}
/// `BrotliDecoderState` (opaque).
#[repr(C)]
struct DecoderState {
    _private: [u8; 0],
}
/// `BrotliEncoderPreparedDictionary` (opaque).
#[repr(C)]
struct PreparedState {
    _private: [u8; 0],
}

type AllocFunc = Option<unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void>;
type FreeFunc = Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>;
type MetadataStartFunc = Option<unsafe extern "C" fn(*mut c_void, usize)>;
type MetadataChunkFunc = Option<unsafe extern "C" fn(*mut c_void, *const u8, usize)>;

// `BrotliEncoderParameter` (encode.h).
const PARAM_QUALITY: c_int = 1;
const PARAM_LGWIN: c_int = 2;
const PARAM_SIZE_HINT: c_int = 5;
const PARAM_LARGE_WINDOW: c_int = 6;
// `BrotliDecoderParameter` (decode.h).
const DECODER_PARAM_LARGE_WINDOW: c_int = 1;
// `BrotliSharedDictionaryType` (shared_dictionary.h).
const SHARED_DICTIONARY_RAW: c_int = 0;
// `BrotliDecoderResult` (decode.h).
const RESULT_ERROR: c_int = 0;
const RESULT_SUCCESS: c_int = 1;
const RESULT_NEEDS_MORE_INPUT: c_int = 2;

// The libbrotli functions `brotli.c` 1.2.1 calls. Enums are C `int`s and
// `BROTLI_BOOL` is `int` (types.h).
unsafe extern "C" {
    fn BrotliEncoderCreateInstance(
        alloc_func: AllocFunc,
        free_func: FreeFunc,
        opaque: *mut c_void,
    ) -> *mut EncoderState;
    fn BrotliEncoderDestroyInstance(state: *mut EncoderState);
    fn BrotliEncoderSetParameter(state: *mut EncoderState, param: c_int, value: u32) -> c_int;
    fn BrotliEncoderCompressStream(
        state: *mut EncoderState,
        op: c_int,
        available_in: *mut usize,
        next_in: *mut *const u8,
        available_out: *mut usize,
        next_out: *mut *mut u8,
        total_out: *mut usize,
    ) -> c_int;
    fn BrotliEncoderIsFinished(state: *mut EncoderState) -> c_int;
    fn BrotliEncoderPrepareDictionary(
        dictionary_type: c_int,
        data_size: usize,
        data: *const u8,
        quality: c_int,
        alloc_func: AllocFunc,
        free_func: FreeFunc,
        opaque: *mut c_void,
    ) -> *mut PreparedState;
    fn BrotliEncoderDestroyPreparedDictionary(dictionary: *mut PreparedState);
    fn BrotliEncoderAttachPreparedDictionary(
        state: *mut EncoderState,
        dictionary: *const PreparedState,
    ) -> c_int;

    fn BrotliDecoderCreateInstance(
        alloc_func: AllocFunc,
        free_func: FreeFunc,
        opaque: *mut c_void,
    ) -> *mut DecoderState;
    fn BrotliDecoderDestroyInstance(state: *mut DecoderState);
    fn BrotliDecoderSetParameter(state: *mut DecoderState, param: c_int, value: u32) -> c_int;
    fn BrotliDecoderAttachDictionary(
        state: *mut DecoderState,
        dictionary_type: c_int,
        data_size: usize,
        data: *const u8,
    ) -> c_int;
    fn BrotliDecoderSetMetadataCallbacks(
        state: *mut DecoderState,
        start_func: MetadataStartFunc,
        chunk_func: MetadataChunkFunc,
        opaque: *mut c_void,
    );
    fn BrotliDecoderDecompressStream(
        state: *mut DecoderState,
        available_in: *mut usize,
        next_in: *mut *const u8,
        available_out: *mut usize,
        next_out: *mut *mut u8,
        total_out: *mut usize,
    ) -> c_int;
    fn BrotliDecoderGetErrorCode(state: *const DecoderState) -> c_int;
    fn BrotliDecoderErrorString(code: c_int) -> *const c_char;
}

/// `BrotliDecoderErrorString(code)`.
pub(super) fn libbrotli_error_name(code: i32) -> &'static str {
    // SAFETY: the function returns a pointer to a string literal for every
    // input (`INVALID` for unknown codes), NUL-terminated and static.
    let s = unsafe { CStr::from_ptr(BrotliDecoderErrorString(code)) };
    s.to_str().unwrap_or("INVALID")
}

/// The prepared dictionary and the raw bytes it points into.
struct Prepared {
    ptr: NonNull<PreparedState>,
    _raw: Box<[u8]>,
}

// SAFETY: a prepared dictionary is immutable once made; libbrotli only reads
// it, from whichever thread drives the encoder it is attached to.
unsafe impl Send for Prepared {}
// SAFETY: as above, shared reads only.
unsafe impl Sync for Prepared {}

impl Drop for Prepared {
    fn drop(&mut self) {
        // SAFETY: `ptr` came from `BrotliEncoderPrepareDictionary` and is
        // destroyed once; every encoder it was attached to holds an `Arc` of
        // this, so none is alive any more.
        unsafe { BrotliEncoderDestroyPreparedDictionary(self.ptr.as_ptr()) }
    }
}

/// A raw dictionary prepared for the encoder
/// (`BrotliEncoderPrepareDictionary(BROTLI_SHARED_DICTIONARY_RAW, …)`).
pub struct PreparedDictionary {
    inner: Arc<Prepared>,
}

impl PreparedDictionary {
    /// Prepares `raw` at `quality` (the tool passes `BROTLI_MAX_QUALITY`).
    /// The bytes are copied: libbrotli keeps pointing into them.
    pub fn new(raw: &[u8], quality: u32) -> Result<Self, Refused> {
        let raw: Box<[u8]> = raw.into();
        // SAFETY: `raw` is valid for `raw.len()` bytes and outlives the
        // prepared dictionary (both live in `Prepared`, which destroys the
        // dictionary first); default allocator.
        let ptr = unsafe {
            BrotliEncoderPrepareDictionary(
                SHARED_DICTIONARY_RAW,
                raw.len(),
                raw.as_ptr(),
                quality.min(c_int::MAX as u32) as c_int,
                None,
                None,
                ptr::null_mut(),
            )
        };
        let ptr = NonNull::new(ptr).ok_or(Refused::OutOfMemory)?;
        Ok(PreparedDictionary {
            inner: Arc::new(Prepared { ptr, _raw: raw }),
        })
    }
}

/// `BrotliEncoderState` with the tool's parameters.
pub struct Encoder {
    state: NonNull<EncoderState>,
    _dictionary: Option<Arc<Prepared>>,
}

// SAFETY: the encoder state is used through `&mut self` only and is not tied
// to the thread that made it; the attached dictionary is `Send + Sync`.
unsafe impl Send for Encoder {}

impl Encoder {
    /// `BrotliEncoderCreateInstance`, then the parameters `brotli.c` sets:
    /// quality, `LARGE_WINDOW` when asked, `LGWIN`, `SIZE_HINT` when
    /// present, and the dictionary attached. Fails only when libbrotli
    /// returns no instance.
    pub fn new(p: &EncoderParams, dict: Option<&PreparedDictionary>) -> Result<Encoder, Refused> {
        // SAFETY: default allocator; a null result is handled.
        let state = unsafe { BrotliEncoderCreateInstance(None, None, ptr::null_mut()) };
        let state = NonNull::new(state).ok_or(Refused::OutOfMemory)?;
        let s = state.as_ptr();
        // SAFETY (each call): `s` is a live encoder state not yet used to
        // compress. The tool ignores these results; so do we.
        unsafe {
            BrotliEncoderSetParameter(s, PARAM_QUALITY, p.quality);
            if p.large_window {
                BrotliEncoderSetParameter(s, PARAM_LARGE_WINDOW, 1);
            }
            BrotliEncoderSetParameter(s, PARAM_LGWIN, p.lgwin);
            if let Some(hint) = p.size_hint {
                BrotliEncoderSetParameter(s, PARAM_SIZE_HINT, hint);
            }
        }
        let dictionary = dict.map(|d| Arc::clone(&d.inner));
        if let Some(d) = &dictionary {
            // SAFETY: `s` is live and unused; the prepared dictionary is kept
            // alive by the `Arc` stored beside the state.
            unsafe { BrotliEncoderAttachPreparedDictionary(s, d.ptr.as_ptr()) };
        }
        Ok(Encoder {
            state,
            _dictionary: dictionary,
        })
    }

    /// `BrotliEncoderCompressStream`: advances `input` and `output` past
    /// what it used. `false` is libbrotli's failure.
    pub fn compress_stream(
        &mut self,
        op: Operation,
        input: &mut &[u8],
        output: &mut &mut [u8],
    ) -> bool {
        let op = match op {
            Operation::Process => 0,
            Operation::Flush => 1,
            Operation::Finish => 2,
            Operation::EmitMetadata => 3,
        };
        let mut available_in = input.len();
        let mut next_in = input.as_ptr();
        let mut available_out = output.len();
        let mut next_out = output.as_mut_ptr();
        // SAFETY: `next_in`/`available_in` describe `input` and
        // `next_out`/`available_out` describe `output`, both valid for the
        // call; libbrotli advances them within those bounds and keeps no
        // pointer into either after it returns.
        let ok = unsafe {
            BrotliEncoderCompressStream(
                self.state.as_ptr(),
                op,
                &mut available_in,
                &mut next_in,
                &mut available_out,
                &mut next_out,
                ptr::null_mut(),
            )
        };
        *input = &input[input.len() - available_in..];
        let produced = output.len() - available_out;
        advance_out(output, produced);
        ok != 0
    }

    /// `BrotliEncoderIsFinished`.
    pub fn is_finished(&self) -> bool {
        // SAFETY: the state is live; the call only reads it.
        unsafe { BrotliEncoderIsFinished(self.state.as_ptr()) != 0 }
    }
}

impl Drop for Encoder {
    fn drop(&mut self) {
        // SAFETY: made by `BrotliEncoderCreateInstance`, destroyed once,
        // before the dictionary `Arc` is released.
        unsafe { BrotliEncoderDestroyInstance(self.state.as_ptr()) }
    }
}

/// What the metadata trampolines reach through libbrotli's `opaque`.
struct Callbacks {
    on_start: OnMetadataStart,
    on_chunk: OnMetadataChunk,
    /// A panic out of a callback, caught at the C boundary and resumed once
    /// libbrotli has returned.
    panic: Option<Box<dyn Any + Send>>,
}

unsafe extern "C" fn on_metadata_start(opaque: *mut c_void, size: usize) {
    // SAFETY: `opaque` is the `Callbacks` box the decoder owns, registered
    // with this function and alive for as long as the decoder state is; it
    // is called only during `BrotliDecoderDecompressStream`, while no other
    // reference to it exists.
    let cb = unsafe { &mut *opaque.cast::<Callbacks>() };
    if cb.panic.is_some() {
        return;
    }
    if let Err(p) = catch_unwind(AssertUnwindSafe(|| (cb.on_start)(size))) {
        cb.panic = Some(p);
    }
}

unsafe extern "C" fn on_metadata_chunk(opaque: *mut c_void, data: *const u8, size: usize) {
    // SAFETY: as in `on_metadata_start`.
    let cb = unsafe { &mut *opaque.cast::<Callbacks>() };
    if cb.panic.is_some() {
        return;
    }
    let chunk: &[u8] = if size == 0 {
        &[]
    } else {
        // SAFETY: libbrotli passes `size` readable bytes at `data`.
        unsafe { std::slice::from_raw_parts(data, size) }
    };
    if let Err(p) = catch_unwind(AssertUnwindSafe(|| (cb.on_chunk)(chunk))) {
        cb.panic = Some(p);
    }
}

/// `BrotliDecoderState` as `brotli.c` sets it up.
pub struct Decoder {
    state: NonNull<DecoderState>,
    _dictionary: Option<Box<[u8]>>,
    callbacks: Option<Box<Callbacks>>,
}

impl Decoder {
    /// `BrotliDecoderCreateInstance`, `LARGE_WINDOW` when asked (the tool
    /// always asks), and a raw dictionary attached (copied: libbrotli keeps
    /// pointing into it). Fails only when libbrotli returns no instance.
    pub fn new(large_window: bool, dict: Option<&[u8]>) -> Result<Decoder, Refused> {
        // SAFETY: default allocator; a null result is handled.
        let state = unsafe { BrotliDecoderCreateInstance(None, None, ptr::null_mut()) };
        let state = NonNull::new(state).ok_or(Refused::OutOfMemory)?;
        let mut decoder = Decoder {
            state,
            _dictionary: None,
            callbacks: None,
        };
        if large_window {
            // SAFETY: a live, unused decoder state.
            unsafe { BrotliDecoderSetParameter(state.as_ptr(), DECODER_PARAM_LARGE_WINDOW, 1) };
        }
        if let Some(d) = dict {
            let raw: Box<[u8]> = d.into();
            // SAFETY: a live, unused decoder state; `raw` is valid for its
            // length and stored beside the state, which is destroyed first.
            // The tool ignores the result; so do we.
            unsafe {
                BrotliDecoderAttachDictionary(
                    state.as_ptr(),
                    SHARED_DICTIONARY_RAW,
                    raw.len(),
                    raw.as_ptr(),
                )
            };
            decoder._dictionary = Some(raw);
        }
        Ok(decoder)
    }

    /// `BrotliDecoderSetMetadataCallbacks`: `on_start` gets each metadata
    /// block's length once its header is read, `on_chunk` its contents as
    /// they arrive. Never refused on this tier.
    pub fn set_metadata_callbacks(
        &mut self,
        on_start: OnMetadataStart,
        on_chunk: OnMetadataChunk,
    ) -> Result<(), Refused> {
        let mut cb = Box::new(Callbacks {
            on_start,
            on_chunk,
            panic: None,
        });
        let opaque = ptr::from_mut::<Callbacks>(&mut *cb).cast::<c_void>();
        // SAFETY: a live decoder state; `opaque` points into a box stored in
        // `self` (replacing any earlier one only after libbrotli has been
        // pointed at the new one), alive until the state is destroyed.
        unsafe {
            BrotliDecoderSetMetadataCallbacks(
                self.state.as_ptr(),
                Some(on_metadata_start),
                Some(on_metadata_chunk),
                opaque,
            )
        };
        self.callbacks = Some(cb);
        Ok(())
    }

    /// `BrotliDecoderDecompressStream`: advances `input` and `output` past
    /// what it used.
    pub fn decompress_stream(&mut self, input: &mut &[u8], output: &mut &mut [u8]) -> StreamResult {
        let mut available_in = input.len();
        let mut next_in = input.as_ptr();
        let mut available_out = output.len();
        let mut next_out = output.as_mut_ptr();
        // SAFETY: the pointers and counts describe `input` and `output`,
        // valid for the call; libbrotli copies what it must keep into its
        // own buffers. The callbacks' box is alive and not otherwise
        // borrowed during the call.
        let r = unsafe {
            BrotliDecoderDecompressStream(
                self.state.as_ptr(),
                &mut available_in,
                &mut next_in,
                &mut available_out,
                &mut next_out,
                ptr::null_mut(),
            )
        };
        *input = &input[input.len() - available_in..];
        let produced = output.len() - available_out;
        advance_out(output, produced);
        if let Some(p) = self.callbacks.as_mut().and_then(|cb| cb.panic.take()) {
            resume_unwind(p);
        }
        match r {
            RESULT_ERROR => StreamResult::Error,
            RESULT_SUCCESS => StreamResult::Success,
            RESULT_NEEDS_MORE_INPUT => StreamResult::NeedsMoreInput,
            _ => StreamResult::NeedsMoreOutput,
        }
    }

    /// `BrotliDecoderGetErrorCode` and its `BrotliDecoderErrorString`.
    pub fn error(&self) -> DecoderError {
        // SAFETY: a live decoder state; the call only reads it.
        let code = unsafe { BrotliDecoderGetErrorCode(self.state.as_ptr()) };
        DecoderError {
            code,
            name: libbrotli_error_name(code),
        }
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        // SAFETY: made by `BrotliDecoderCreateInstance`, destroyed once,
        // before the dictionary and callbacks it points at are freed.
        unsafe { BrotliDecoderDestroyInstance(self.state.as_ptr()) }
    }
}
