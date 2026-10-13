//! The C tier: libzstd 1.5.7 (`zstd-sys`, vendored and built whole), driven
//! through `zstd_sys` as `programs/fileio.c` and `dibio.c` drive it.
//!
//! Every `unsafe` block below is an FFI call into libzstd, and each states
//! the invariant it relies on. The contexts own their buffers: a dictionary
//! or prefix handed to libzstd by reference lives in a `Box<[u8]>` beside
//! the context, so its address is stable and outlives every use.

use std::ffi::{CStr, c_int, c_uint, c_void};
use std::ptr::NonNull;

use zstd::zstd_safe::zstd_sys as sys;

use super::{
    CParamKey, DecodeOptions, EncodeOptions, EndOp, Progress, StreamCall, TrainAlgo, TrainParams,
    Trained, ZstdError, code,
};

/// `ZSTD_versionString()`: the libzstd this build links, `"1.5.7"`.
pub fn libzstd_version() -> &'static str {
    // SAFETY: ZSTD_versionString returns a pointer to a static,
    // NUL-terminated ASCII string that lives for the whole program.
    let s = unsafe { CStr::from_ptr(sys::ZSTD_versionString()) };
    s.to_str().unwrap_or("?")
}

/// libzstd's `size_t` result as a `Result`: `ZSTD_isError` decides, and the
/// code is `0 - result` (`ERR_getErrorCode`), computed here rather than
/// through the `ZSTD_ErrorCode` enum so no out-of-range value is ever
/// materialised as a Rust enum.
fn check(r: usize) -> Result<usize, ZstdError> {
    // SAFETY: ZSTD_isError only compares its argument with a constant.
    if unsafe { sys::ZSTD_isError(r) } != 0 {
        Err(ZstdError::lib(0usize.wrapping_sub(r) as u32))
    } else {
        Ok(r)
    }
}

/// `ZDICT_isError` and the same code computation, for the trainers.
fn check_zdict(r: usize) -> Result<usize, ZstdError> {
    // SAFETY: ZDICT_isError only compares its argument with a constant.
    if unsafe { sys::ZDICT_isError(r) } != 0 {
        Err(ZstdError::lib(0usize.wrapping_sub(r) as u32))
    } else {
        Ok(r)
    }
}

/// Makes room for at least `n` more bytes past `out.len()`.
fn spare(out: &mut Vec<u8>, n: usize) {
    if out.capacity() - out.len() < n {
        out.reserve(n);
    }
}

/// `bytes` in a boxed slice with one spare trailing byte that libzstd is
/// never told about. libzstd decides whether an input continues a
/// referenced prefix or dictionary by address alone (`ZSTD_window_update`,
/// `zstd_compress_internal.h`: `src != window->nextSrc`), so an input
/// allocated exactly at `ptr + len` is compressed as contiguous and the
/// output changes. The spare byte is ours, so nothing else can begin there.
fn guarded(bytes: &[u8]) -> Box<[u8]> {
    let mut v = Vec::with_capacity(bytes.len() + 1);
    v.extend_from_slice(bytes);
    v.push(0);
    v.into_boxed_slice()
}

/// A compression context with `fileio.c`'s parameters
/// (`FIO_createCResources`, `FIO_compressZstdFrame`).
pub struct Encoder {
    cctx: NonNull<sys::ZSTD_CCtx>,
    /// Referenced by libzstd (`loadDictionary_byReference`) for every frame;
    /// one byte longer than the dictionary (see [`guarded`]).
    _dictionary: Option<Box<[u8]>>,
    /// Referenced by libzstd (`refPrefix`) for the first frame; one byte
    /// longer than the prefix (see [`guarded`]).
    _prefix: Option<Box<[u8]>>,
}

// SAFETY: a ZSTD_CCtx has no thread affinity (zstd-safe declares its CCtx
// Send for the same reason); the buffers it references are owned here and
// move with it.
unsafe impl Send for Encoder {}

impl std::fmt::Debug for Encoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Encoder").finish_non_exhaustive()
    }
}

impl Drop for Encoder {
    fn drop(&mut self) {
        // SAFETY: cctx came from ZSTD_createCCtx and is freed exactly once;
        // the referenced buffers are dropped after this body runs.
        unsafe { sys::ZSTD_freeCCtx(self.cctx.as_ptr()) };
    }
}

impl Encoder {
    /// A context set up as `FIO_createCResources` sets it, then the pledged
    /// size as `FIO_compressZstdFrame` sets it.
    pub fn new(o: &EncodeOptions) -> Result<Encoder, ZstdError> {
        // SAFETY: ZSTD_createCCtx takes no arguments; null means no memory.
        let cctx = NonNull::new(unsafe { sys::ZSTD_createCCtx() })
            .ok_or_else(|| ZstdError::lib(code::MEMORY_ALLOCATION))?;
        let mut e = Encoder {
            cctx,
            _dictionary: o.dictionary.as_deref().map(guarded),
            _prefix: o.prefix.as_deref().map(guarded),
        };
        use sys::ZSTD_cParameter::*;
        e.set(ZSTD_c_contentSizeFlag, i32::from(o.content_size))?;
        e.set(ZSTD_c_dictIDFlag, i32::from(o.dict_id))?;
        e.set(ZSTD_c_checksumFlag, i32::from(o.checksum))?;
        e.set(ZSTD_c_compressionLevel, o.level)?;
        e.set(ZSTD_c_targetCBlockSize, o.target_cblock_size as i32)?;
        // ZSTD_c_srcSizeHint; FIO_setSrcSizeHint clamps to INT_MAX.
        e.set(
            ZSTD_c_experimentalParam7,
            o.src_size_hint.map_or(0, |h| h.min(i32::MAX as u64) as i32),
        )?;
        e.set(ZSTD_c_enableLongDistanceMatching, o.ldm.value())?;
        e.set(ZSTD_c_ldmHashLog, o.ldm_params.hash_log as i32)?;
        e.set(ZSTD_c_ldmMinMatch, o.ldm_params.min_match as i32)?;
        if o.ldm_params.bucket_size_log != 0 {
            e.set(ZSTD_c_ldmBucketSizeLog, o.ldm_params.bucket_size_log as i32)?;
        }
        if o.ldm_params.hash_rate_log != 0 {
            e.set(ZSTD_c_ldmHashRateLog, o.ldm_params.hash_rate_log as i32)?;
        }
        // ZSTD_c_useRowMatchFinder.
        e.set(ZSTD_c_experimentalParam14, o.row_match_finder.value())?;
        e.set(ZSTD_c_windowLog, o.cparam(CParamKey::WindowLog) as i32)?;
        e.set(ZSTD_c_chainLog, o.cparam(CParamKey::ChainLog) as i32)?;
        e.set(ZSTD_c_hashLog, o.cparam(CParamKey::HashLog) as i32)?;
        e.set(ZSTD_c_searchLog, o.cparam(CParamKey::SearchLog) as i32)?;
        e.set(ZSTD_c_minMatch, o.cparam(CParamKey::MinMatch) as i32)?;
        e.set(
            ZSTD_c_targetLength,
            o.cparam(CParamKey::TargetLength) as i32,
        )?;
        e.set(ZSTD_c_strategy, o.cparam(CParamKey::Strategy) as i32)?;
        // ZSTD_c_literalCompressionMode.
        e.set(ZSTD_c_experimentalParam5, o.literal_compression.value())?;
        // ZSTD_c_enableDedicatedDictSearch, always 1 in fileio.c.
        e.set(ZSTD_c_experimentalParam8, 1)?;
        e.set(ZSTD_c_nbWorkers, o.workers as i32)?;
        e.set(ZSTD_c_jobSize, o.job_size as i32)?;
        if let Some(log) = o.overlap_log {
            e.set(ZSTD_c_overlapLog, log)?;
        }
        // ZSTD_c_rsyncable.
        e.set(ZSTD_c_experimentalParam1, i32::from(o.rsyncable))?;
        if let Some(p) = &e._prefix {
            // SAFETY: the prefix is a boxed slice owned by `e`, so the
            // pointer and length stay valid for as long as the context can
            // read them; libzstd only reads them. The length passed leaves
            // out the guard byte, which is inside the allocation.
            check(unsafe {
                sys::ZSTD_CCtx_refPrefix(e.cctx.as_ptr(), p.as_ptr().cast::<c_void>(), p.len() - 1)
            })?;
        } else {
            let (ptr, len) = e
                ._dictionary
                .as_ref()
                .map_or((std::ptr::null(), 0), |d| (d.as_ptr(), d.len() - 1));
            // SAFETY: as for the prefix: the dictionary is owned by `e` and
            // outlives the context's use of it; (null, 0) clears it, as
            // fileio.c's call without `-D` does.
            check(unsafe {
                sys::ZSTD_CCtx_loadDictionary_byReference(
                    e.cctx.as_ptr(),
                    ptr.cast::<c_void>(),
                    len,
                )
            })?;
        }
        e.set_pledged_size(o.pledged_size)?;
        Ok(e)
    }

    fn set(&mut self, param: sys::ZSTD_cParameter, value: c_int) -> Result<(), ZstdError> {
        // SAFETY: cctx is a live context owned by self; `param` is one of
        // the enum's own values, and libzstd range-checks `value`.
        check(unsafe { sys::ZSTD_CCtx_setParameter(self.cctx.as_ptr(), param, value) }).map(drop)
    }

    /// `ZSTD_CCtx_setPledgedSrcSize` for the next frame (`None`: unknown),
    /// as `FIO_compressZstdFrame` sets it for each file. Only between
    /// frames.
    pub fn set_pledged_size(&mut self, size: Option<u64>) -> Result<(), ZstdError> {
        let size = size.unwrap_or(sys::ZSTD_CONTENTSIZE_UNKNOWN as u64);
        // SAFETY: cctx is a live context owned by self.
        check(unsafe { sys::ZSTD_CCtx_setPledgedSrcSize(self.cctx.as_ptr(), size) }).map(drop)
    }

    /// Compresses all of `input`, appending what libzstd emits to `out`:
    /// `ZSTD_compressStream2` until the input is consumed and, for
    /// [`EndOp::Flush`] and [`EndOp::End`], until nothing remains to
    /// flush. Returns libzstd's last "still to flush" figure (`0` once a
    /// flush or the frame is complete). After [`EndOp::End`] the next call
    /// starts a new frame.
    pub fn compress_stream(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
        end: EndOp,
    ) -> Result<usize, ZstdError> {
        self.compress_stream_each(input, out, end, &mut |_| {})
    }

    /// [`Encoder::compress_stream`], telling `each` about every
    /// `ZSTD_compressStream2` call made (`fileio.c`'s display level 6
    /// traces them).
    pub fn compress_stream_each(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
        end: EndOp,
        each: &mut dyn FnMut(StreamCall),
    ) -> Result<usize, ZstdError> {
        let mut pos = 0;
        loop {
            let before = out.len();
            let remaining = self.compress_stream2(input, &mut pos, out, end)?;
            each(StreamCall {
                end,
                input_pos: pos,
                input_size: input.len(),
                produced: out.len() - before,
            });
            let input_done = pos == input.len();
            if input_done && (end == EndOp::Continue || remaining == 0) {
                return Ok(remaining);
            }
        }
    }

    /// One `ZSTD_compressStream2` call, as `fileio.c`'s inner loop makes
    /// it: takes what it can of `input[*pos..]` (advancing `*pos`) and
    /// appends at most `ZSTD_CStreamOutSize()` bytes to `out`, `fileio.c`'s
    /// write buffer. Returns libzstd's "still to flush" figure.
    pub fn compress_stream2(
        &mut self,
        input: &[u8],
        pos: &mut usize,
        out: &mut Vec<u8>,
        end: EndOp,
    ) -> Result<usize, ZstdError> {
        let directive = match end {
            EndOp::Continue => sys::ZSTD_EndDirective::ZSTD_e_continue,
            EndOp::Flush => sys::ZSTD_EndDirective::ZSTD_e_flush,
            EndOp::End => sys::ZSTD_EndDirective::ZSTD_e_end,
        };
        let mut inb = sys::ZSTD_inBuffer {
            src: input.as_ptr().cast::<c_void>(),
            size: input.len(),
            pos: (*pos).min(input.len()),
        };
        // SAFETY: a pure size query.
        let chunk = unsafe { sys::ZSTD_CStreamOutSize() };
        spare(out, chunk);
        let len = out.len();
        let mut outb = sys::ZSTD_outBuffer {
            // SAFETY: `len` is within the allocation, so the offset pointer
            // stays inside it.
            dst: unsafe { out.as_mut_ptr().add(len) }.cast::<c_void>(),
            // fileio.c's write buffer is exactly this size.
            size: chunk,
            pos: 0,
        };
        // SAFETY: cctx is live; inb describes `input`, which outlives the
        // call, with `pos` clamped to its length; outb describes `chunk`
        // bytes of the vector's spare capacity (reserved above), which
        // libzstd writes at most `size` bytes of.
        let r = check(unsafe {
            sys::ZSTD_compressStream2(self.cctx.as_ptr(), &mut outb, &mut inb, directive)
        });
        // SAFETY: libzstd initialised exactly `outb.pos` bytes past `len`
        // (its contract, error or not).
        unsafe { out.set_len(len + outb.pos) };
        *pos = inb.pos;
        r
    }

    /// `ZSTD_getFrameProgression`.
    pub fn progression(&self) -> Progress {
        // SAFETY: cctx is live; the call only reads it.
        let p = unsafe { sys::ZSTD_getFrameProgression(self.cctx.as_ptr()) };
        Progress {
            ingested: p.ingested,
            consumed: p.consumed,
            produced: p.produced,
            flushed: p.flushed,
            current_job_id: p.currentJobID,
            nb_active_workers: p.nbActiveWorkers,
        }
    }

    /// `ZSTD_toFlushNow`: compressed bytes ready to flush right now
    /// (multi-threaded only; `0` single-threaded).
    pub fn to_flush_now(&self) -> usize {
        // SAFETY: cctx is live; the call only reads it.
        unsafe { sys::ZSTD_toFlushNow(self.cctx.as_ptr()) }
    }

    /// `ZSTD_c_compressionLevel`, which libzstd allows mid-frame in
    /// multi-threaded mode (`--adapt`); it applies from the next job.
    pub fn set_level(&mut self, level: i32) -> Result<(), ZstdError> {
        self.set(sys::ZSTD_cParameter::ZSTD_c_compressionLevel, level)
    }
}

/// A decompression context with `fileio.c`'s settings
/// (`FIO_createDResources`).
pub struct Decoder {
    dctx: NonNull<sys::ZSTD_DCtx>,
    _dictionary: Option<Box<[u8]>>,
    _prefix: Option<Box<[u8]>>,
}

// SAFETY: as for Encoder: a ZSTD_DCtx has no thread affinity and the
// buffers it references are owned here.
unsafe impl Send for Decoder {}

impl std::fmt::Debug for Decoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decoder").finish_non_exhaustive()
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        // SAFETY: dctx came from ZSTD_createDCtx and is freed exactly once.
        unsafe { sys::ZSTD_freeDCtx(self.dctx.as_ptr()) };
    }
}

impl Decoder {
    /// A context set up as `FIO_createDResources` sets it: the window
    /// limit, `forceIgnoreChecksum`, a session reset, then the prefix or the
    /// dictionary.
    pub fn new(o: &DecodeOptions) -> Result<Decoder, ZstdError> {
        // SAFETY: ZSTD_createDCtx takes no arguments; null means no memory.
        let dctx = NonNull::new(unsafe { sys::ZSTD_createDCtx() })
            .ok_or_else(|| ZstdError::lib(code::MEMORY_ALLOCATION))?;
        let d = Decoder {
            dctx,
            _dictionary: o.dictionary.clone().map(Vec::into_boxed_slice),
            _prefix: o.prefix.clone().map(Vec::into_boxed_slice),
        };
        let max = usize::try_from(o.max_window_size).unwrap_or(usize::MAX);
        // SAFETY: dctx is live; libzstd range-checks the size.
        check(unsafe { sys::ZSTD_DCtx_setMaxWindowSize(d.dctx.as_ptr(), max) })?;
        // SAFETY: dctx is live; ZSTD_d_forceIgnoreChecksum takes 0 or 1.
        check(unsafe {
            sys::ZSTD_DCtx_setParameter(
                d.dctx.as_ptr(),
                sys::ZSTD_dParameter::ZSTD_d_experimentalParam3,
                c_int::from(o.ignore_checksum),
            )
        })?;
        // SAFETY: dctx is live.
        check(unsafe {
            sys::ZSTD_DCtx_reset(
                d.dctx.as_ptr(),
                sys::ZSTD_ResetDirective::ZSTD_reset_session_only,
            )
        })?;
        if let Some(p) = &d._prefix {
            // SAFETY: the prefix is a boxed slice owned by `d`, valid for as
            // long as the context can read it.
            check(unsafe {
                sys::ZSTD_DCtx_refPrefix(d.dctx.as_ptr(), p.as_ptr().cast::<c_void>(), p.len())
            })?;
        } else {
            let (ptr, len) = d
                ._dictionary
                .as_ref()
                .map_or((std::ptr::null(), 0), |b| (b.as_ptr(), b.len()));
            // SAFETY: the dictionary is owned by `d` and outlives the
            // context's use of it; (null, 0) clears it.
            check(unsafe {
                sys::ZSTD_DCtx_loadDictionary_byReference(
                    d.dctx.as_ptr(),
                    ptr.cast::<c_void>(),
                    len,
                )
            })?;
        }
        Ok(d)
    }

    /// One `ZSTD_decompressStream` call: decodes from `input`, appending at
    /// most `ZSTD_DStreamOutSize()` bytes to `out`, the size of `fileio.c`'s
    /// write buffer. Returns the input bytes consumed and libzstd's
    /// hint, which is `0` exactly when a frame (zstd or skippable) has been
    /// decoded and flushed entirely; the call stops there, leaving any
    /// later frame's bytes unconsumed. A non-zero hint with input left means
    /// "call again"; with none, "more input is needed".
    pub fn decompress_stream(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(usize, usize), ZstdError> {
        // SAFETY: a pure size query.
        let chunk = unsafe { sys::ZSTD_DStreamOutSize() };
        spare(out, chunk);
        let len = out.len();
        let mut inb = sys::ZSTD_inBuffer {
            src: input.as_ptr().cast::<c_void>(),
            size: input.len(),
            pos: 0,
        };
        let mut outb = sys::ZSTD_outBuffer {
            // SAFETY: `len` is within the allocation.
            dst: unsafe { out.as_mut_ptr().add(len) }.cast::<c_void>(),
            // fileio.c's write buffer is exactly this size, and libzstd's
            // single-pass shortcut (and so some error codes) depends on it.
            size: chunk,
            pos: 0,
        };
        // SAFETY: dctx is live; inb describes `input`, outb `chunk` bytes of
        // the vector's spare capacity (reserved above), which libzstd writes
        // at most `size` bytes of.
        let r =
            check(unsafe { sys::ZSTD_decompressStream(self.dctx.as_ptr(), &mut outb, &mut inb) });
        // SAFETY: libzstd initialised exactly `outb.pos` bytes past `len`.
        unsafe { out.set_len(len + outb.pos) };
        Ok((inb.pos, r?))
    }

    /// `ZSTD_DCtx_reset(ZSTD_reset_session_only)`, as
    /// `FIO_decompressZstdFrame` does before each frame: the dictionary
    /// stays, a prefix already used stays used.
    pub fn reset(&mut self) {
        // SAFETY: dctx is live; a session reset cannot fail.
        unsafe {
            sys::ZSTD_DCtx_reset(
                self.dctx.as_ptr(),
                sys::ZSTD_ResetDirective::ZSTD_reset_session_only,
            )
        };
    }
}

/// `DiB_fillNoise`: the guard band `dibio.c` writes after the samples for
/// the legacy trainer.
fn fill_noise(buf: &mut [u8]) {
    const PRIME1: u32 = 2_654_435_761;
    const PRIME2: u32 = 2_246_822_519;
    let mut acc = PRIME1;
    for b in buf {
        acc = acc.wrapping_mul(PRIME2);
        *b = (acc >> 21) as u8;
    }
}

/// `dibio.c`'s `NOISELENGTH`.
const NOISE_LENGTH: usize = 32;

/// `DiB_trainFromFiles`' trainer call: `ZDICT_trainFromBuffer_legacy`,
/// `ZDICT_(optimize)TrainFromBuffer_cover` or `_fastCover`, as
/// [`TrainParams`] selects. `samples` holds the samples back to back and
/// `sizes` their lengths, in the order `dibio.c` loaded them.
pub fn train(samples: &[u8], sizes: &[usize], p: &TrainParams) -> Result<Trained, ZstdError> {
    let total = sizes.iter().try_fold(0usize, |acc, &s| acc.checked_add(s));
    if total.is_none_or(|t| t > samples.len()) {
        return Err(ZstdError::lib(code::SRC_SIZE_WRONG));
    }
    let nb = c_uint::try_from(sizes.len()).map_err(|_| ZstdError::lib(code::SRC_SIZE_WRONG))?;
    let mut dict = vec![0u8; p.max_dict];
    let z = sys::ZDICT_params_t {
        compressionLevel: p.level,
        notificationLevel: p.notification,
        dictID: p.dict_id,
    };
    let mut trained = Trained {
        dict: Vec::new(),
        chosen_k: 0,
        chosen_d: 0,
        chosen_f: 0,
        chosen_accel: 0,
        chosen_steps: 0,
        chosen_split: 0.0,
    };
    let size = match p.algo {
        TrainAlgo::Legacy { selectivity } => {
            let mut buf = Vec::with_capacity(samples.len() + NOISE_LENGTH);
            buf.extend_from_slice(samples);
            let at = buf.len();
            buf.resize(at + NOISE_LENGTH, 0);
            fill_noise(&mut buf[at..]);
            let params = sys::ZDICT_legacy_params_t {
                selectivityLevel: selectivity,
                zParams: z,
            };
            // SAFETY: dict has max_dict writable bytes; buf holds the sum of
            // `sizes` (checked above) plus the 32-byte guard band the legacy
            // trainer reads past the end; sizes has `nb` entries.
            check_zdict(unsafe {
                sys::ZDICT_trainFromBuffer_legacy(
                    dict.as_mut_ptr().cast::<c_void>(),
                    dict.len(),
                    buf.as_ptr().cast::<c_void>(),
                    sizes.as_ptr(),
                    nb,
                    params,
                )
            })?
        }
        TrainAlgo::Cover {
            k,
            d,
            steps,
            split,
            shrink,
        } => {
            let mut params = sys::ZDICT_cover_params_t {
                k,
                d,
                steps,
                nbThreads: p.threads,
                splitPoint: split,
                shrinkDict: c_uint::from(shrink.is_some()),
                shrinkDictMaxRegression: shrink.unwrap_or(1),
                zParams: z,
            };
            // SAFETY: dict has max_dict writable bytes; samples holds the sum
            // of `sizes` (checked above); sizes has `nb` entries; params is a
            // live, initialised struct the optimiser may write back into.
            let r = check_zdict(unsafe {
                if p.optimize {
                    sys::ZDICT_optimizeTrainFromBuffer_cover(
                        dict.as_mut_ptr().cast::<c_void>(),
                        dict.len(),
                        samples.as_ptr().cast::<c_void>(),
                        sizes.as_ptr(),
                        nb,
                        &mut params,
                    )
                } else {
                    sys::ZDICT_trainFromBuffer_cover(
                        dict.as_mut_ptr().cast::<c_void>(),
                        dict.len(),
                        samples.as_ptr().cast::<c_void>(),
                        sizes.as_ptr(),
                        nb,
                        params,
                    )
                }
            })?;
            trained.chosen_k = params.k;
            trained.chosen_d = params.d;
            trained.chosen_steps = params.steps;
            trained.chosen_split = params.splitPoint;
            r
        }
        TrainAlgo::Fastcover {
            k,
            d,
            f,
            steps,
            split,
            accel,
            shrink,
        } => {
            let mut params = sys::ZDICT_fastCover_params_t {
                k,
                d,
                f,
                steps,
                nbThreads: p.threads,
                splitPoint: split,
                accel,
                shrinkDict: c_uint::from(shrink.is_some()),
                shrinkDictMaxRegression: shrink.unwrap_or(1),
                zParams: z,
            };
            // SAFETY: as for cover.
            let r = check_zdict(unsafe {
                if p.optimize {
                    sys::ZDICT_optimizeTrainFromBuffer_fastCover(
                        dict.as_mut_ptr().cast::<c_void>(),
                        dict.len(),
                        samples.as_ptr().cast::<c_void>(),
                        sizes.as_ptr(),
                        nb,
                        &mut params,
                    )
                } else {
                    sys::ZDICT_trainFromBuffer_fastCover(
                        dict.as_mut_ptr().cast::<c_void>(),
                        dict.len(),
                        samples.as_ptr().cast::<c_void>(),
                        sizes.as_ptr(),
                        nb,
                        params,
                    )
                }
            })?;
            trained.chosen_k = params.k;
            trained.chosen_d = params.d;
            trained.chosen_f = params.f;
            trained.chosen_accel = params.accel;
            trained.chosen_steps = params.steps;
            trained.chosen_split = params.splitPoint;
            r
        }
    };
    dict.truncate(size);
    trained.dict = dict;
    Ok(trained)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(n: usize) -> Vec<u8> {
        (0..n).map(|i| b"abcdefgh stuff "[i * 7 % 15]).collect()
    }

    #[test]
    fn guarded_keeps_one_unreferenced_byte() {
        assert_eq!(&*guarded(b"abc"), b"abc\0");
        assert_eq!(guarded(b"").len(), 1);
    }

    #[test]
    fn prefix_and_dictionary_end_in_a_byte_nobody_else_can_own() {
        let old = text(5000);
        let o = EncodeOptions {
            prefix: Some(old.clone()),
            ..EncodeOptions::default()
        };
        let e = Encoder::new(&o).unwrap();
        assert_eq!(e._prefix.as_deref().unwrap().len(), old.len() + 1);
        let o = EncodeOptions {
            dictionary: Some(old.clone()),
            ..EncodeOptions::default()
        };
        let e = Encoder::new(&o).unwrap();
        assert_eq!(e._dictionary.as_deref().unwrap().len(), old.len() + 1);
        // Empty ones still build.
        let o = EncodeOptions {
            prefix: Some(Vec::new()),
            dictionary: Some(Vec::new()),
            ..EncodeOptions::default()
        };
        Encoder::new(&o).unwrap();
    }

    /// Two fresh encoders given the same prefix and input write the same
    /// frame. (That the prefix's guard byte is excluded, `len - 1`, is
    /// pinned by the byte-identical C-tier `--patch-from` cases.)
    #[test]
    fn prefix_output_is_the_same_from_two_fresh_encoders() {
        let old = text(40_000);
        let input = text(4000);
        let o = EncodeOptions {
            level: 19,
            prefix: Some(old),
            pledged_size: Some(input.len() as u64),
            ..EncodeOptions::default()
        };
        let mut outs = Vec::new();
        for _ in 0..2 {
            let mut e = Encoder::new(&o).unwrap();
            let separate = input.clone();
            let mut out = Vec::new();
            e.compress_stream(&separate, &mut out, EndOp::End).unwrap();
            outs.push(out);
        }
        assert_eq!(outs[0], outs[1]);
    }
}
