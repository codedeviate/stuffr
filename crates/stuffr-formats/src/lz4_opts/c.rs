//! The C tier: liblz4 1.11.0, vendored under `c/lz4-1.11.0/` and built by
//! this crate's `build.rs`, driven through its frame API the way the lz4
//! CLI drives it (measured against the reference binary; the CLI's source
//! was not read).
//!
//! Every function is declared below from 1.11.0's `lib/lz4frame.h`,
//! `lib/lz4.h` and `lib/lz4hc.h`. The vendored library's exports all carry
//! a `stuffr_` prefix (`c/lz4-1.11.0/stuffr-prefix.h`), so each declaration
//! names its symbol with `#[link_name = "stuffr_…"]`: another liblz4 in the
//! same binary (`lz4-sys`, say) cannot clash with this one.
//!
//! Every `unsafe` block is an FFI call into liblz4 and states the invariant
//! it relies on. The contexts own what liblz4 points at: a decoding
//! dictionary lives in a `Box<[u8]>` beside the context, so its address is
//! stable for as long as the context uses it.

use std::ffi::{c_char, c_int, c_uint};
use std::ptr::NonNull;

use super::{
    DecodeOptions, EncodeOptions, FRAME_CHUNK, LEGACY_BLOCK_BOUND, LEGACY_BLOCK_SIZE, LEGACY_MAGIC,
    Lz4Error, Lz4fError,
};

/// `LZ4F_cctx` (opaque).
#[repr(C)]
struct Cctx {
    _private: [u8; 0],
}

/// `LZ4F_dctx` (opaque).
#[repr(C)]
struct Dctx {
    _private: [u8; 0],
}

/// `LZ4F_CDict` (opaque).
#[repr(C)]
struct CDict {
    _private: [u8; 0],
}

/// `LZ4F_frameInfo_t` with plain integers for its enums (each a C `int`
/// sized enum), so whatever liblz4 writes is a valid Rust value.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct FrameInfo {
    pub block_size_id: c_uint,
    pub block_mode: c_uint,
    pub content_checksum_flag: c_uint,
    pub frame_type: c_uint,
    pub content_size: u64,
    pub dict_id: c_uint,
    pub block_checksum_flag: c_uint,
}

/// `LZ4F_preferences_t` (lz4frame.h 1.11.0): 1.10.0's `reserved[3]` became
/// `nbWorkers`, `reserved1`, `reserved0`, with the same layout.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct Preferences {
    frame_info: FrameInfo,
    compression_level: c_int,
    auto_flush: c_uint,
    favor_dec_speed: c_uint,
    nb_workers: c_uint,
    reserved1: c_uint,
    reserved0: c_uint,
}

/// `LZ4F_compressOptions_t` / `LZ4F_decompressOptions_t`: four
/// `unsigned`s. Only their size is pinned here; every call passes NULL.
#[cfg(test)]
#[repr(C)]
struct FourUnsigned {
    _a: [c_uint; 4],
}

/// `LZ4F_VERSION`.
const LZ4F_VERSION: c_uint = 100;

unsafe extern "C" {
    #[link_name = "stuffr_LZ4_versionNumber"]
    fn LZ4_versionNumber() -> c_int;
    #[link_name = "stuffr_LZ4F_isError"]
    fn LZ4F_isError(code: usize) -> c_uint;
    #[cfg(test)]
    #[link_name = "stuffr_LZ4F_getErrorName"]
    fn LZ4F_getErrorName(code: usize) -> *const c_char;
    #[cfg(test)]
    #[link_name = "stuffr_LZ4F_getMaxNbWorkers"]
    fn LZ4F_getMaxNbWorkers() -> c_uint;

    #[link_name = "stuffr_LZ4F_createCompressionContext"]
    fn LZ4F_createCompressionContext(cctx: *mut *mut Cctx, version: c_uint) -> usize;
    #[link_name = "stuffr_LZ4F_freeCompressionContext"]
    fn LZ4F_freeCompressionContext(cctx: *mut Cctx) -> usize;
    #[link_name = "stuffr_LZ4F_compressBegin"]
    fn LZ4F_compressBegin(
        cctx: *mut Cctx,
        dst: *mut u8,
        dst_capacity: usize,
        prefs: *const Preferences,
    ) -> usize;
    #[link_name = "stuffr_LZ4F_compressBegin_usingCDict"]
    fn LZ4F_compressBegin_usingCDict(
        cctx: *mut Cctx,
        dst: *mut u8,
        dst_capacity: usize,
        cdict: *const CDict,
        prefs: *const Preferences,
    ) -> usize;
    #[link_name = "stuffr_LZ4F_compressBound"]
    fn LZ4F_compressBound(src_size: usize, prefs: *const Preferences) -> usize;
    #[link_name = "stuffr_LZ4F_compressUpdate"]
    fn LZ4F_compressUpdate(
        cctx: *mut Cctx,
        dst: *mut u8,
        dst_capacity: usize,
        src: *const u8,
        src_size: usize,
        opts: *const c_uint,
    ) -> usize;
    #[link_name = "stuffr_LZ4F_compressEnd"]
    fn LZ4F_compressEnd(
        cctx: *mut Cctx,
        dst: *mut u8,
        dst_capacity: usize,
        opts: *const c_uint,
    ) -> usize;
    #[link_name = "stuffr_LZ4F_compressFrame_usingCDict"]
    fn LZ4F_compressFrame_usingCDict(
        cctx: *mut Cctx,
        dst: *mut u8,
        dst_capacity: usize,
        src: *const u8,
        src_size: usize,
        cdict: *const CDict,
        prefs: *const Preferences,
    ) -> usize;
    #[link_name = "stuffr_LZ4F_compressFrameBound"]
    fn LZ4F_compressFrameBound(src_size: usize, prefs: *const Preferences) -> usize;
    #[link_name = "stuffr_LZ4F_createCDict"]
    fn LZ4F_createCDict(dict: *const u8, dict_size: usize) -> *mut CDict;
    #[link_name = "stuffr_LZ4F_freeCDict"]
    fn LZ4F_freeCDict(cdict: *mut CDict);

    #[link_name = "stuffr_LZ4F_createDecompressionContext"]
    fn LZ4F_createDecompressionContext(dctx: *mut *mut Dctx, version: c_uint) -> usize;
    #[link_name = "stuffr_LZ4F_freeDecompressionContext"]
    fn LZ4F_freeDecompressionContext(dctx: *mut Dctx) -> usize;
    #[link_name = "stuffr_LZ4F_decompress"]
    fn LZ4F_decompress(
        dctx: *mut Dctx,
        dst: *mut u8,
        dst_size: *mut usize,
        src: *const u8,
        src_size: *mut usize,
        opts: *const c_uint,
    ) -> usize;
    #[link_name = "stuffr_LZ4F_decompress_usingDict"]
    fn LZ4F_decompress_usingDict(
        dctx: *mut Dctx,
        dst: *mut u8,
        dst_size: *mut usize,
        src: *const u8,
        src_size: *mut usize,
        dict: *const u8,
        dict_size: usize,
        opts: *const c_uint,
    ) -> usize;
    #[link_name = "stuffr_LZ4F_resetDecompressionContext"]
    fn LZ4F_resetDecompressionContext(dctx: *mut Dctx);
    #[cfg(test)]
    #[link_name = "stuffr_LZ4F_getFrameInfo"]
    fn LZ4F_getFrameInfo(
        dctx: *mut Dctx,
        info: *mut FrameInfo,
        src: *const u8,
        src_size: *mut usize,
    ) -> usize;

    #[link_name = "stuffr_LZ4_compress_fast"]
    fn LZ4_compress_fast(
        src: *const c_char,
        dst: *mut c_char,
        src_size: c_int,
        dst_capacity: c_int,
        acceleration: c_int,
    ) -> c_int;
    #[link_name = "stuffr_LZ4_compress_HC"]
    fn LZ4_compress_HC(
        src: *const c_char,
        dst: *mut c_char,
        src_size: c_int,
        dst_capacity: c_int,
        level: c_int,
    ) -> c_int;
    #[link_name = "stuffr_LZ4_decompress_safe"]
    fn LZ4_decompress_safe(
        src: *const c_char,
        dst: *mut c_char,
        compressed_size: c_int,
        dst_capacity: c_int,
    ) -> c_int;
}

/// `LZ4_versionNumber()` rendered as liblz4 renders it: `"1.11.0"` for
/// `11100` (R7).
pub fn liblz4_version() -> &'static str {
    // SAFETY: LZ4_versionNumber takes no arguments and returns a constant.
    let n = unsafe { LZ4_versionNumber() };
    match n {
        11100 => "1.11.0",
        _ => "unknown",
    }
}

/// liblz4's frame-API `size_t` result as a `Result`: an error is
/// `(size_t)-code` (`LZ4F_isError`, `LZ4F_getErrorCode`).
fn check(r: usize) -> Result<usize, Lz4Error> {
    // SAFETY: LZ4F_isError only compares its argument with a constant.
    if unsafe { LZ4F_isError(r) } != 0 {
        Err(Lz4Error::Lib(Lz4fError::from_code(0usize.wrapping_sub(r))))
    } else {
        Ok(r)
    }
}

/// `LZ4F_preferences_t` for `o`.
fn preferences(o: &Settings, content_size: u64) -> Preferences {
    Preferences {
        frame_info: FrameInfo {
            block_size_id: c_uint::from(o.block_size.id()),
            // LZ4F_blockLinked = 0, LZ4F_blockIndependent = 1.
            block_mode: c_uint::from(!o.linked),
            content_checksum_flag: c_uint::from(o.content_checksum),
            frame_type: 0,
            content_size,
            dict_id: 0,
            block_checksum_flag: c_uint::from(o.block_checksum),
        },
        // liblz4 1.11.0 maps every `int` safely (`LZ4F_levelToAcceleration`
        // caps a negative level before negating it; levels above 12 count
        // as 12), so the CLI's level goes through as it is.
        compression_level: o.level,
        auto_flush: c_uint::from(o.flush_each_update),
        favor_dec_speed: c_uint::from(o.favor_dec_speed),
        nb_workers: o.workers,
        reserved1: 0,
        reserved0: 0,
    }
}

/// [`EncodeOptions`] without the dictionary, which the context keeps as a
/// `CDict`.
#[derive(Debug, Clone, Copy)]
struct Settings {
    level: i32,
    block_size: super::BlockSizeId,
    linked: bool,
    block_checksum: bool,
    content_checksum: bool,
    content_size: Option<u64>,
    favor_dec_speed: bool,
    legacy: bool,
    workers: c_uint,
    update_size: usize,
    flush_each_update: bool,
}

/// An lz4 compression context with the CLI's settings: frames (the module
/// doc of `lz4_opts` for the one-shot rule and the update schedule) or the
/// legacy format.
pub struct Encoder {
    cctx: NonNull<Cctx>,
    /// The `-D` dictionary, digested (`LZ4F_createCDict` copies it).
    cdict: Option<NonNull<CDict>>,
    settings: Settings,
    /// [`Encoder::new_plain`]'s frames.
    plain: bool,
    /// Input not yet compressed: less than one update (8 MiB for legacy).
    pending: Vec<u8>,
    /// The last update, handed to liblz4 as stable until the frame ends
    /// ([`Encoder::end_of_input`] with `stable`): its jobs may read it in
    /// place, so it is kept, untouched, until [`Encoder::finish`] (or the
    /// context's drop, which joins the workers first) is done with it.
    held: Vec<u8>,
    /// The frame header (or legacy magic) has been written.
    started: bool,
    /// Output scratch, reused.
    scratch: Vec<u8>,
}

// SAFETY: the context is owned exclusively by this value. liblz4's worker
// threads (nbWorkers >= 1) belong to the context and are only driven from
// the thread calling into it, which may change between calls.
unsafe impl Send for Encoder {}

impl Drop for Encoder {
    fn drop(&mut self) {
        // SAFETY: cctx came from LZ4F_createCompressionContext and cdict
        // from LZ4F_createCDict; each is freed exactly once, here (freeing
        // the context also joins its worker threads, before `held`, which
        // they may read, is dropped with the fields after this).
        unsafe {
            LZ4F_freeCompressionContext(self.cctx.as_ptr());
            if let Some(d) = self.cdict {
                LZ4F_freeCDict(d.as_ptr());
            }
        }
    }
}

impl Encoder {
    /// A context for `o`.
    pub fn new(o: &EncodeOptions) -> Result<Encoder, Lz4Error> {
        let mut ctx: *mut Cctx = std::ptr::null_mut();
        // SAFETY: ctx is a valid out-pointer; LZ4F_VERSION is the version
        // these declarations were written for.
        check(unsafe { LZ4F_createCompressionContext(&mut ctx, LZ4F_VERSION) })?;
        let cctx = NonNull::new(ctx).ok_or(Lz4Error::Lib(Lz4fError::AllocationFailed))?;
        let mut e = Encoder {
            cctx,
            cdict: None,
            plain: false,
            settings: Settings {
                level: o.level,
                block_size: o.block_size_id(),
                linked: o.block_linked,
                block_checksum: o.block_checksum,
                content_checksum: o.content_checksum,
                content_size: o.content_size,
                favor_dec_speed: o.favor_dec_speed,
                legacy: o.legacy,
                workers: o.workers,
                update_size: o.update_size.unwrap_or(FRAME_CHUNK).max(1),
                flush_each_update: o.flush_each_update,
            },
            pending: Vec::new(),
            held: Vec::new(),
            started: false,
            scratch: Vec::new(),
        };
        if let (Some(d), false) = (&o.dictionary, o.legacy) {
            // SAFETY: d is a live slice of d.len() bytes; LZ4F_createCDict
            // copies what it keeps, so d need not outlive the call.
            let p = unsafe { LZ4F_createCDict(d.as_ptr(), d.len()) };
            e.cdict = Some(NonNull::new(p).ok_or(Lz4Error::Lib(Lz4fError::AllocationFailed))?);
        }
        Ok(e)
    }

    /// A context for plain `LZ4F` streaming, not the lz4 CLI's: the header
    /// on the first call, one `LZ4F_compressUpdate` per block's worth of
    /// input, `LZ4F_compressEnd` — never one-shot, single-threaded
    /// (`nbWorkers` 0, whatever `o` says), so the block size, mode and
    /// content size are exactly `o`'s. This is what zstd 1.5.7's
    /// `--format=lz4` writes (spike S4: byte-identical to `zstd --format=lz4
    /// -c FILE` at levels 1, 3, 9 and 19 with `level` capped at 12,
    /// `block_size` 64 KiB, `block_linked`, the content checksum and the
    /// file's size). `legacy`, `update_size` and `flush_each_update` are
    /// ignored.
    pub fn new_plain(o: &EncodeOptions) -> Result<Encoder, Lz4Error> {
        let mut e = Encoder::new(&EncodeOptions {
            legacy: false,
            workers: 0,
            update_size: None,
            flush_each_update: false,
            ..o.clone()
        })?;
        e.plain = true;
        Ok(e)
    }

    fn chunk_size(&self) -> usize {
        if self.settings.legacy {
            LEGACY_BLOCK_SIZE
        } else if self.plain {
            self.settings.block_size.bytes()
        } else {
            self.settings.update_size
        }
    }

    /// Writes the frame header (or the legacy magic) on first call.
    ///
    /// For a frame, "first" means once a whole update's worth (4 MiB, or
    /// [`EncodeOptions::update_size`]) has arrived: an input that ends
    /// sooner is written by [`Encoder::finish`], as one
    /// `LZ4F_compressFrame` call if it is shorter than one block (the
    /// module doc of `lz4_opts`). Whatever slices the caller feeds, the
    /// output is the same.
    pub fn update(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), Lz4Error> {
        if self.plain && !self.started {
            // `LZ4F_compressBegin` comes before the first update: zstd
            // counts the header as written when it reports progress.
            self.begin(out)?;
        }
        let chunk = self.chunk_size();
        let mut input = input;
        if !self.pending.is_empty() {
            let take = (chunk - self.pending.len()).min(input.len());
            self.pending.extend_from_slice(&input[..take]);
            input = &input[take..];
            if self.pending.len() == chunk {
                let full = std::mem::take(&mut self.pending);
                let r = self.push_chunk(&full, out);
                self.pending = full;
                self.pending.clear();
                r?;
            }
        }
        while input.len() >= chunk {
            self.push_chunk(&input[..chunk], out)?;
            input = &input[chunk..];
        }
        self.pending.extend_from_slice(input);
        Ok(())
    }

    /// Ends the frame: the last update, the end mark and the content
    /// checksum (a one-shot frame is written whole here). The context can
    /// then start another frame.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), Lz4Error> {
        let pending = std::mem::take(&mut self.pending);
        let r = if self.settings.legacy {
            self.finish_legacy(&pending, out)
        } else if !self.started && !self.plain && pending.len() < self.settings.block_size.bytes() {
            self.one_shot(&pending, out)
        } else {
            self.finish_stream(&pending, out)
        };
        self.pending = pending;
        self.pending.clear();
        // A completed `end` has waited for every job: the stable input is
        // free. After a failure it stays until the drop (workers joined
        // first, as `Drop::drop` runs before the fields are dropped).
        if r.is_ok() {
            self.held = Vec::new();
        }
        self.started = false;
        r
    }

    /// The input ends here: compress what is held as lz4 1.11.0 does before
    /// its last refresh, so that only the end is left for
    /// [`Encoder::finish`]. A streamed frame's last, partial update goes to
    /// `LZ4F_compressUpdate` now (an input shorter than an update but of a
    /// block or more is begun first); an input shorter than a block stays
    /// for the one-shot frame, and legacy and plain frames are left as
    /// they are. The bytes are those of `finish` alone; only when they
    /// appear changes (probe, 1.11.0: `lz4 -vvvv --single-thread -B4` over
    /// 9 MiB + 123 refreshes at 9 MiB with the last update's blocks
    /// counted, `-B7` without its last, still buffered, block).
    ///
    /// `stable` hands that update to liblz4 as `LZ4F_srcStableUntilFlush`,
    /// as lz4 does for a memory-mapped file: its workers read it in place
    /// instead of a copy, so less is back by the time this returns (probe,
    /// 1.11.0: `lz4 -vvvv -T1 -B4` over 2.5 MB refreshes `0.00%`,
    /// `--no-mmap` `27.71%`, the copy's figure). The bytes do not change
    /// (liblz4's own guarantee, and Task 3's re-probe).
    #[doc(hidden)]
    pub fn end_of_input(&mut self, out: &mut Vec<u8>, stable: bool) -> Result<(), Lz4Error> {
        if self.settings.legacy
            || self.plain
            || (!self.started && self.pending.len() < self.settings.block_size.bytes())
        {
            return Ok(());
        }
        if !self.started {
            self.begin(out)?;
        }
        let pending = std::mem::take(&mut self.pending);
        if pending.is_empty() {
            self.pending = pending;
            return Ok(());
        }
        if stable {
            // Moving the Vec keeps its heap buffer where it is.
            let r = self.compress_update_with(&pending, out, true);
            self.held = pending;
            return r;
        }
        let r = self.compress_update(&pending, out);
        self.pending = pending;
        self.pending.clear();
        r
    }

    /// One whole chunk.
    fn push_chunk(&mut self, chunk: &[u8], out: &mut Vec<u8>) -> Result<(), Lz4Error> {
        if self.settings.legacy {
            if !self.started {
                out.extend_from_slice(&LEGACY_MAGIC.to_le_bytes());
                self.started = true;
            }
            return self.legacy_block(chunk, out);
        }
        if !self.started {
            self.begin(out)?;
        }
        self.compress_update(chunk, out)
    }

    /// `LZ4F_compressBegin` (with the `-D` dictionary, if any): the streamed
    /// frame's header, with the content size if one was given.
    fn begin(&mut self, out: &mut Vec<u8>) -> Result<(), Lz4Error> {
        let prefs = preferences(&self.settings, self.settings.content_size.unwrap_or(0));
        let mut hdr = [0u8; super::HEADER_SIZE_MAX];
        let n = match self.cdict {
            // SAFETY: cctx and the CDict are live; hdr has
            // LZ4F_HEADER_SIZE_MAX bytes of room, as the API requires;
            // prefs outlives the call.
            Some(cd) => check(unsafe {
                LZ4F_compressBegin_usingCDict(
                    self.cctx.as_ptr(),
                    hdr.as_mut_ptr(),
                    hdr.len(),
                    cd.as_ptr(),
                    &prefs,
                )
            })?,
            // SAFETY: as above, without a dictionary.
            None => check(unsafe {
                LZ4F_compressBegin(self.cctx.as_ptr(), hdr.as_mut_ptr(), hdr.len(), &prefs)
            })?,
        };
        out.extend_from_slice(&hdr[..n]);
        self.started = true;
        Ok(())
    }

    /// `LZ4F_compressUpdate` on the context, the source unstable (liblz4
    /// copies what it keeps).
    fn compress_update(&mut self, src: &[u8], out: &mut Vec<u8>) -> Result<(), Lz4Error> {
        self.compress_update_with(src, out, false)
    }

    /// `LZ4F_compressUpdate`; `stable`: `src` stays as it is until the
    /// frame ends (`LZ4F_srcStableUntilFlush`, the caller's promise:
    /// [`Encoder::end_of_input`] keeps it in `held`).
    fn compress_update_with(
        &mut self,
        src: &[u8],
        out: &mut Vec<u8>,
        stable: bool,
    ) -> Result<(), Lz4Error> {
        // LZ4F_compressOptions_t: stableSrc, uncompressed, reserved1,
        // reserved0 (lz4frame.h 1.11.0); 2 = LZ4F_srcStableUntilFlush.
        let options: [c_uint; 4] = [if stable { 2 } else { 0 }, 0, 0, 0];
        let prefs = preferences(&self.settings, 0);
        // SAFETY: prefs is a valid preferences struct for the call.
        let bound = unsafe { LZ4F_compressBound(src.len(), &prefs) };
        self.scratch.resize(bound, 0);
        // SAFETY: cctx is live and begun; scratch has
        // LZ4F_compressBound(src.len()) bytes, which guarantees success
        // (with workers too: completed jobs that do not fit are deferred);
        // src is live, and with `stable` stays so until the frame ends (the
        // caller keeps it in `held`, freed only after `LZ4F_compressEnd` or
        // after the context, which joins its workers, is freed); options
        // is a valid LZ4F_compressOptions_t (four unsigned).
        let n = check(unsafe {
            LZ4F_compressUpdate(
                self.cctx.as_ptr(),
                self.scratch.as_mut_ptr(),
                bound,
                src.as_ptr(),
                src.len(),
                options.as_ptr(),
            )
        })?;
        out.extend_from_slice(&self.scratch[..n]);
        Ok(())
    }

    /// `LZ4F_compressEnd`, called until done: each call fills the buffer or
    /// completes the frame, and one that returns exactly the buffer's size
    /// may have more to give (lz4frame.h 1.11.0; with workers a call emits
    /// at least one job per `LZ4F_compressBound(0)`). The call after a
    /// completed one that filled the buffer returns 0.
    fn end(&mut self, out: &mut Vec<u8>) -> Result<(), Lz4Error> {
        let prefs = preferences(&self.settings, 0);
        // SAFETY: prefs is a valid preferences struct for the call.
        let cap = unsafe { LZ4F_compressBound(0, &prefs) };
        self.scratch.resize(cap, 0);
        loop {
            let (ctx, dst) = (self.cctx.as_ptr(), self.scratch.as_mut_ptr());
            // SAFETY: cctx is live with a frame in progress; scratch has
            // cap (> 0) bytes; NULL options are allowed.
            let n = check(unsafe { LZ4F_compressEnd(ctx, dst, cap, std::ptr::null()) })?;
            out.extend_from_slice(&self.scratch[..n]);
            if n < cap {
                return Ok(());
            }
        }
    }

    /// The rest of a streamed frame: the header if nothing came (a plain
    /// frame), the last partial update, then `LZ4F_compressEnd`.
    fn finish_stream(&mut self, rest: &[u8], out: &mut Vec<u8>) -> Result<(), Lz4Error> {
        if !self.started {
            self.begin(out)?;
        }
        if !rest.is_empty() {
            self.compress_update(rest, out)?;
        }
        self.end(out)
    }

    /// `LZ4F_compressFrame_usingCDict` over the whole (short) input.
    fn one_shot(&mut self, src: &[u8], out: &mut Vec<u8>) -> Result<(), Lz4Error> {
        // compressFrame replaces any non-zero content size with the true one.
        let prefs = preferences(
            &self.settings,
            u64::from(self.settings.content_size.is_some()),
        );
        // SAFETY: prefs is a valid preferences struct for the call.
        let bound = unsafe { LZ4F_compressFrameBound(src.len(), &prefs) };
        self.scratch.resize(bound, 0);
        let cdict = self
            .cdict
            .map_or(std::ptr::null(), |d| d.as_ptr().cast_const());
        // SAFETY: cctx is live; scratch has LZ4F_compressFrameBound bytes,
        // as the function requires; src is a live slice; cdict is live or
        // NULL (no dictionary), both allowed; prefs outlives the call.
        let n = check(unsafe {
            LZ4F_compressFrame_usingCDict(
                self.cctx.as_ptr(),
                self.scratch.as_mut_ptr(),
                bound,
                src.as_ptr(),
                src.len(),
                cdict,
                &prefs,
            )
        })?;
        out.extend_from_slice(&self.scratch[..n]);
        Ok(())
    }

    /// One legacy block: the compressed size, then the block.
    fn legacy_block(&mut self, src: &[u8], out: &mut Vec<u8>) -> Result<(), Lz4Error> {
        self.scratch.resize(LEGACY_BLOCK_BOUND, 0);
        let len = src.len() as c_int;
        let cap = LEGACY_BLOCK_BOUND as c_int;
        let n = if self.settings.level < LEGACY_HC_MIN {
            // SAFETY: src is a live slice of `len` (≤ 8 MiB) bytes; scratch
            // has LZ4_COMPRESSBOUND(8 MiB) bytes, the most any block needs.
            unsafe {
                LZ4_compress_fast(
                    src.as_ptr().cast(),
                    self.scratch.as_mut_ptr().cast(),
                    len,
                    cap,
                    legacy_acceleration(self.settings.level),
                )
            }
        } else {
            // SAFETY: as above, through the HC compressor.
            unsafe {
                LZ4_compress_HC(
                    src.as_ptr().cast(),
                    self.scratch.as_mut_ptr().cast(),
                    len,
                    cap,
                    self.settings.level,
                )
            }
        };
        if n <= 0 {
            return Err(Lz4Error::Lib(Lz4fError::Generic));
        }
        out.extend_from_slice(&(n as u32).to_le_bytes());
        out.extend_from_slice(&self.scratch[..n as usize]);
        Ok(())
    }

    /// The legacy frame's end: the magic (if no block was written yet) and
    /// the last, partial block.
    fn finish_legacy(&mut self, rest: &[u8], out: &mut Vec<u8>) -> Result<(), Lz4Error> {
        if !self.started {
            out.extend_from_slice(&LEGACY_MAGIC.to_le_bytes());
        }
        if !rest.is_empty() {
            self.legacy_block(rest, out)?;
        }
        Ok(())
    }
}

/// The first level the legacy format compresses with `LZ4_compress_HC`
/// (2026-11-08 probe: lz4 1.11.0's `-l -2` is `LZ4_compress_HC` at level 2,
/// liblz4's mid-way compressor; 1.10.0's was `-l -1`'s bytes).
const LEGACY_HC_MIN: i32 = 2;

/// `LZ4_ACCELERATION_MAX` (`lib/lz4.c`): liblz4 caps every acceleration
/// here.
const LZ4_ACCELERATION_MAX: c_int = 65_537;

/// `LZ4_compress_fast`'s acceleration for a legacy level below
/// [`LEGACY_HC_MIN`]: 1 for levels 0 and 1, `-level + 1` for a negative
/// one, capped at [`LZ4_ACCELERATION_MAX`] — `LZ4F_levelToAcceleration`'s
/// rule (`lib/lz4frame.c` 1.11.0), which the frame path applies itself.
/// 2026-11-08 probe (`lz4 -q -c -l LEVEL`, 1.11.0): `--fast=3` is
/// acceleration 4 (1.10.0's was 3); `--fast=65535`, `--fast=65536` and
/// `--fast=2147483647` (`i32::MIN + 1`) give the same bytes. The CLI
/// refuses `i32::MIN` (`--fast=2147483648`) before compressing; here it is
/// capped like the rest, without the overflow `-level + 1` would be.
fn legacy_acceleration(level: i32) -> c_int {
    if level >= 0 {
        1
    } else if level < 1 - LZ4_ACCELERATION_MAX {
        LZ4_ACCELERATION_MAX
    } else {
        1 - level
    }
}

/// One legacy or mozlz4 block through `LZ4_decompress_safe`: the decoded
/// length, or [`Lz4fError::DecompressionFailed`].
pub(super) fn legacy_block_decode(src: &[u8], dst: &mut [u8]) -> Result<usize, Lz4Error> {
    if c_int::try_from(src.len()).is_err() || c_int::try_from(dst.len()).is_err() {
        return Err(Lz4Error::Lib(Lz4fError::DecompressionFailed));
    }
    // SAFETY: src and dst are live slices of the lengths passed, both
    // within c_int (checked above; the callers keep src to
    // LZ4_COMPRESSBOUND(8 MiB) for a legacy block and to
    // `mozlz4_block_bound(MOZLZ4_SIZE_MAX)` for a mozlz4 one);
    // LZ4_decompress_safe never reads or writes past them.
    let n = unsafe {
        LZ4_decompress_safe(
            src.as_ptr().cast(),
            dst.as_mut_ptr().cast(),
            src.len() as c_int,
            dst.len() as c_int,
        )
    };
    usize::try_from(n).map_err(|_| Lz4Error::Lib(Lz4fError::DecompressionFailed))
}

/// The decoder's output scratch: what one `LZ4F_decompress` call may write.
const DST_CHUNK: usize = 256 << 10;

/// An lz4 frame decompression context (`LZ4F_decompress` semantics).
pub struct Decoder {
    dctx: NonNull<Dctx>,
    /// The `-D` dictionary, referenced by liblz4 in place for each frame.
    dict: Option<Box<[u8]>>,
    scratch: Vec<u8>,
}

// SAFETY: the context and dictionary are owned exclusively by this value.
unsafe impl Send for Decoder {}

impl Drop for Decoder {
    fn drop(&mut self) {
        // SAFETY: dctx came from LZ4F_createDecompressionContext and is
        // freed exactly once, here.
        unsafe {
            LZ4F_freeDecompressionContext(self.dctx.as_ptr());
        }
    }
}

impl Decoder {
    /// A context for `o`.
    pub fn new(o: &DecodeOptions) -> Result<Decoder, Lz4Error> {
        let mut ctx: *mut Dctx = std::ptr::null_mut();
        // SAFETY: ctx is a valid out-pointer; LZ4F_VERSION matches.
        check(unsafe { LZ4F_createDecompressionContext(&mut ctx, LZ4F_VERSION) })?;
        let dctx = NonNull::new(ctx).ok_or(Lz4Error::Lib(Lz4fError::AllocationFailed))?;
        Ok(Decoder {
            dctx,
            dict: o.dictionary.as_deref().map(Box::from),
            scratch: vec![0; DST_CHUNK],
        })
    }

    /// LZ4F_decompress semantics: returns (consumed, hint); hint 0 = the frame ended.
    /// Skippable frames are consumed whole (hint 0, nothing produced). Legacy frames:
    /// the caller detects 0x184C2102 and uses `LegacyDecoder`.
    ///
    /// Decodes until `input` is consumed or the frame ends, appending
    /// everything decoded to `out`. After an error the context must be
    /// [`reset`](Decoder::reset) before it is used again.
    pub fn decompress(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(usize, usize), Lz4Error> {
        let mut pos = 0;
        loop {
            let mut src_size = input.len() - pos;
            let mut dst_size = self.scratch.len();
            let src = input[pos..].as_ptr();
            let dst = self.scratch.as_mut_ptr();
            let hint = match &self.dict {
                // SAFETY: dctx is live; dst has dst_size bytes and src
                // src_size; the dictionary is a Box owned by self, so its
                // address is stable for every call of the frame; NULL
                // options are allowed.
                Some(d) => check(unsafe {
                    LZ4F_decompress_usingDict(
                        self.dctx.as_ptr(),
                        dst,
                        &mut dst_size,
                        src,
                        &mut src_size,
                        d.as_ptr(),
                        d.len(),
                        std::ptr::null(),
                    )
                })?,
                // SAFETY: as above, without a dictionary.
                None => check(unsafe {
                    LZ4F_decompress(
                        self.dctx.as_ptr(),
                        dst,
                        &mut dst_size,
                        src,
                        &mut src_size,
                        std::ptr::null(),
                    )
                })?,
            };
            out.extend_from_slice(&self.scratch[..dst_size]);
            pos += src_size;
            if hint == 0 {
                return Ok((pos, 0));
            }
            // More output may be waiting only if the scratch filled.
            if dst_size < self.scratch.len() && (pos == input.len() || src_size == 0) {
                return Ok((pos, hint));
            }
        }
    }

    /// `LZ4F_resetDecompressionContext`: abandons any frame in progress.
    pub fn reset(&mut self) {
        // SAFETY: dctx is live; the call always succeeds.
        unsafe { LZ4F_resetDecompressionContext(self.dctx.as_ptr()) }
    }

    /// `LZ4F_getFrameInfo` on a fresh context, for the tests that compare
    /// it with [`super::parse_frame_header`]: the frame info and the bytes
    /// consumed, or the error.
    #[cfg(test)]
    pub(super) fn frame_info(bytes: &[u8]) -> Result<(FrameInfo, usize), Lz4Error> {
        let d = Decoder::new(&DecodeOptions::default())?;
        let mut info = FrameInfo::default();
        let mut n = bytes.len();
        // SAFETY: dctx is fresh; info is a valid out-struct with
        // LZ4F_frameInfo_t's layout; bytes is live for n bytes.
        check(unsafe { LZ4F_getFrameInfo(d.dctx.as_ptr(), &mut info, bytes.as_ptr(), &mut n) })?;
        Ok((info, n))
    }
}

/// `LZ4F_getErrorName` for an error code (the tests' check of
/// [`Lz4fError::name`]).
#[cfg(test)]
pub(super) fn error_name(code: usize) -> String {
    // SAFETY: LZ4F_getErrorName returns a pointer into a static table of
    // NUL-terminated strings for any value.
    let p = unsafe { LZ4F_getErrorName(0usize.wrapping_sub(code)) };
    // SAFETY: as above: a static NUL-terminated string.
    unsafe { std::ffi::CStr::from_ptr(p) }
        .to_string_lossy()
        .into_owned()
}

/// UNSAFE-4 (2026-10-31 audit): the declarations above are written by hand
/// against liblz4 1.11.0's `lib/lz4frame.h`; these pin the library they
/// link and the layouts they assume, so a re-vendored liblz4 that moves
/// either fails here.
#[cfg(test)]
mod layout_tests {
    use std::mem::{align_of, offset_of, size_of};

    use super::{FourUnsigned, FrameInfo, Preferences};

    #[test]
    fn the_linked_liblz4_is_the_one_the_declarations_were_written_for() {
        // SAFETY: LZ4_versionNumber takes no arguments and returns a constant.
        assert_eq!(unsafe { super::LZ4_versionNumber() }, 11100);
    }

    /// `LZ4F_MULTITHREAD` is on wherever `build.rs` turns it on (unix
    /// targets): `-T#` then gets real worker threads.
    #[test]
    fn multithreading_is_compiled_in_on_unix() {
        // SAFETY: LZ4F_getMaxNbWorkers takes no arguments and returns a
        // constant.
        let max = unsafe { super::LZ4F_getMaxNbWorkers() };
        if cfg!(unix) {
            assert_eq!(
                max,
                if cfg!(target_pointer_width = "64") {
                    1024
                } else {
                    128
                }
            );
        } else {
            assert_eq!(max, 0);
        }
    }

    #[test]
    fn preferences_match_lz4frame_h_1_11_0() {
        // `LZ4F_frameInfo_t` (four enums, `unsigned long long contentSize`,
        // `unsigned dictID`, an enum: 32 bytes, 8-aligned), then `int
        // compressionLevel`, `unsigned autoFlush`, `unsigned favorDecSpeed`,
        // `unsigned nbWorkers`, `unsigned reserved1`, `unsigned reserved0`:
        // 56 bytes.
        assert_eq!(size_of::<FrameInfo>(), 32);
        assert_eq!(align_of::<FrameInfo>(), 8);
        assert_eq!(offset_of!(FrameInfo, content_size), 16);
        assert_eq!(offset_of!(FrameInfo, dict_id), 24);
        assert_eq!(offset_of!(FrameInfo, block_checksum_flag), 28);
        assert_eq!(size_of::<Preferences>(), 56);
        assert_eq!(align_of::<Preferences>(), 8);
        assert_eq!(offset_of!(Preferences, compression_level), 32);
        assert_eq!(offset_of!(Preferences, auto_flush), 36);
        assert_eq!(offset_of!(Preferences, favor_dec_speed), 40);
        assert_eq!(offset_of!(Preferences, nb_workers), 44);
        assert_eq!(offset_of!(Preferences, reserved0), 52);
        // `LZ4F_compressOptions_t` and `LZ4F_decompressOptions_t`: four
        // `unsigned`s each, passed only as NULL here.
        assert_eq!(size_of::<FourUnsigned>(), 16);
    }
}
