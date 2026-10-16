//! The C tier: liblz4 1.10.0 (`lz4-sys`, vendored and built whole), driven
//! through its frame API the way the lz4 CLI drives it (spike S1, measured
//! against the reference binary; the CLI's source was not read).
//!
//! `lz4-sys` declares the core frame API; the entry points it lacks — the
//! one-shot `LZ4F_compressFrame_usingCDict`, the dictionary API that is
//! stable since liblz4 1.10 (`LZ4F_createCDict`, `LZ4F_freeCDict`,
//! `LZ4F_compressBegin_usingCDict`, `LZ4F_decompress_usingDict`) and
//! `LZ4F_resetDecompressionContext` — are declared below from
//! `lib/lz4frame.h`, and resolve against the same static `liblz4.a`.
//!
//! Every `unsafe` block is an FFI call into liblz4 and states the invariant
//! it relies on. The contexts own what liblz4 points at: a decoding
//! dictionary lives in a `Box<[u8]>` beside the context, so its address is
//! stable for as long as the context uses it.

use std::ffi::{c_int, c_uint, c_void};
use std::ptr::NonNull;

use lz4_sys as sys;

use super::{
    DecodeOptions, EncodeOptions, FRAME_CHUNK, LEGACY_BLOCK_BOUND, LEGACY_BLOCK_SIZE, LEGACY_MAGIC,
    Lz4Error, Lz4fError,
};

/// `LZ4F_CDict` (opaque).
#[repr(C)]
struct CDict {
    _private: [u8; 0],
}

// The declarations `lz4-sys` 1.11.1 does not make, with lib/lz4frame.h's
// signatures (liblz4 1.10.0). Contexts are `void*` here, as `lz4-sys`'s own
// context types wrap a `*mut c_void`.
unsafe extern "C" {
    fn LZ4F_compressFrame_usingCDict(
        cctx: *mut c_void,
        dst: *mut u8,
        dst_capacity: usize,
        src: *const u8,
        src_size: usize,
        cdict: *const CDict,
        prefs: *const sys::LZ4FPreferences,
    ) -> usize;
    fn LZ4F_compressFrameBound(src_size: usize, prefs: *const sys::LZ4FPreferences) -> usize;
    fn LZ4F_createCDict(dict: *const u8, dict_size: usize) -> *mut CDict;
    fn LZ4F_freeCDict(cdict: *mut CDict);
    fn LZ4F_compressBegin_usingDict(
        cctx: *mut c_void,
        dst: *mut u8,
        dst_capacity: usize,
        dict: *const u8,
        dict_size: usize,
        prefs: *const sys::LZ4FPreferences,
    ) -> usize;
    fn LZ4F_compressBegin_usingCDict(
        cctx: *mut c_void,
        dst: *mut u8,
        dst_capacity: usize,
        cdict: *const CDict,
        prefs: *const sys::LZ4FPreferences,
    ) -> usize;
    fn LZ4F_decompress_usingDict(
        dctx: *mut c_void,
        dst: *mut u8,
        dst_size: *mut usize,
        src: *const u8,
        src_size: *mut usize,
        dict: *const u8,
        dict_size: usize,
        opts: *const sys::LZ4FDecompressOptions,
    ) -> usize;
    fn LZ4F_resetDecompressionContext(dctx: *mut c_void);
    #[cfg(test)]
    fn LZ4F_getFrameInfo(
        dctx: *mut c_void,
        info: *mut FrameInfo,
        src: *const u8,
        src_size: *mut usize,
    ) -> usize;
}

/// `LZ4F_frameInfo_t` with plain integers for its enums, so whatever
/// liblz4 writes is a valid Rust value (the tests' `LZ4F_getFrameInfo`).
#[cfg(test)]
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

/// `LZ4_versionNumber()` rendered as liblz4 renders it: `"1.10.0"` for
/// `11000` (R7).
pub fn liblz4_version() -> &'static str {
    // SAFETY: LZ4_versionNumber takes no arguments and returns a constant.
    let n = unsafe { sys::LZ4_versionNumber() };
    match n {
        11000 => "1.10.0",
        _ => "unknown",
    }
}

/// liblz4's frame-API `size_t` result as a `Result`: an error is
/// `(size_t)-code` (`LZ4F_isError`, `LZ4F_getErrorCode`).
fn check(r: usize) -> Result<usize, Lz4Error> {
    // SAFETY: LZ4F_isError only compares its argument with a constant.
    if unsafe { sys::LZ4F_isError(r) } != 0 {
        Err(Lz4Error::Lib(Lz4fError::from_code(0usize.wrapping_sub(r))))
    } else {
        Ok(r)
    }
}

/// `LZ4F_preferences_t` for `o`. `compressionLevel` is a C `int`;
/// `lz4-sys` spells it `c_uint`, which has the same size and alignment, so
/// a negative (`--fast`) level is passed as its bit pattern.
fn preferences(o: &Settings, content_size: u64) -> sys::LZ4FPreferences {
    sys::LZ4FPreferences {
        frame_info: sys::LZ4FFrameInfo {
            block_size_id: match o.block_size.id() {
                4 => sys::BlockSize::Max64KB,
                5 => sys::BlockSize::Max256KB,
                6 => sys::BlockSize::Max1MB,
                _ => sys::BlockSize::Max4MB,
            },
            block_mode: if o.linked {
                sys::BlockMode::Linked
            } else {
                sys::BlockMode::Independent
            },
            content_checksum_flag: if o.content_checksum {
                sys::ContentChecksum::ChecksumEnabled
            } else {
                sys::ContentChecksum::NoChecksum
            },
            frame_type: sys::FrameType::Frame,
            content_size,
            dict_id: 0,
            block_checksum_flag: if o.block_checksum {
                sys::BlockChecksum::BlockChecksumEnabled
            } else {
                sys::BlockChecksum::NoBlockChecksum
            },
        },
        compression_level: o.level as c_uint,
        auto_flush: AUTO_FLUSH,
        favor_dec_speed: c_uint::from(o.favor_dec_speed),
        reserved: [0; 3],
    }
}

/// `autoFlush`: unobservable on every path the CLI takes (spike S1 found 0
/// and 1 byte-identical), so liblz4's default.
const AUTO_FLUSH: c_uint = 0;

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
}

/// An lz4 compression context with the CLI's settings: frames (the module
/// doc of `lz4_opts` for the one-shot rule and the 4 MiB jobs) or the
/// legacy format.
pub struct Encoder {
    /// Writes the frame header, and compresses a one-shot frame.
    cctx: NonNull<c_void>,
    /// Compresses each 4 MiB job of a streamed frame.
    job: NonNull<c_void>,
    /// The `-D` dictionary, digested (`LZ4F_createCDict` copies it).
    cdict: Option<NonNull<CDict>>,
    settings: Settings,
    /// [`Encoder::new_plain`]'s frames.
    plain: bool,
    /// Input not yet compressed: less than one chunk (4 MiB for a frame,
    /// 8 MiB for legacy).
    pending: Vec<u8>,
    /// The frame header (or legacy magic) has been written.
    started: bool,
    /// The last 64 KiB of a streamed frame's input so far: the next job's
    /// dictionary when blocks are linked.
    history: Vec<u8>,
    /// A streamed frame's content checksum so far.
    checksum: twox_hash::XxHash32,
    /// Output scratch, reused.
    scratch: Vec<u8>,
}

// SAFETY: the contexts are owned exclusively by this value and liblz4 keeps
// no thread-affine state in them.
unsafe impl Send for Encoder {}

impl Drop for Encoder {
    fn drop(&mut self) {
        // SAFETY: cctx and job came from LZ4F_createCompressionContext and
        // cdict from LZ4F_createCDict; each is freed exactly once, here.
        unsafe {
            sys::LZ4F_freeCompressionContext(sys::LZ4FCompressionContext(self.cctx.as_ptr()));
            sys::LZ4F_freeCompressionContext(sys::LZ4FCompressionContext(self.job.as_ptr()));
            if let Some(d) = self.cdict {
                LZ4F_freeCDict(d.as_ptr());
            }
        }
    }
}

/// `LZ4F_createCompressionContext`.
fn create_cctx() -> Result<NonNull<c_void>, Lz4Error> {
    let mut ctx = sys::LZ4FCompressionContext(std::ptr::null_mut());
    // SAFETY: ctx is a valid out-pointer; LZ4F_VERSION is the version this
    // header set declares.
    check(unsafe { sys::LZ4F_createCompressionContext(&mut ctx, sys::LZ4F_VERSION) })?;
    NonNull::new(ctx.0).ok_or(Lz4Error::Lib(Lz4fError::AllocationFailed))
}

/// What a 4 MiB job is compressed against.
#[derive(Clone, Copy)]
enum JobDict<'a> {
    None,
    /// The digested `-D` dictionary.
    CDict(NonNull<CDict>),
    /// Raw bytes (`LZ4F_compressBegin_usingDict`).
    Raw(&'a [u8]),
}

impl Encoder {
    /// A context for `o`.
    pub fn new(o: &EncodeOptions) -> Result<Encoder, Lz4Error> {
        let cctx = create_cctx()?;
        let job = match create_cctx() {
            Ok(j) => j,
            Err(e) => {
                // SAFETY: cctx was just created and is freed once.
                unsafe {
                    sys::LZ4F_freeCompressionContext(sys::LZ4FCompressionContext(cctx.as_ptr()))
                };
                return Err(e);
            }
        };
        let mut e = Encoder {
            cctx,
            job,
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
            },
            pending: Vec::new(),
            started: false,
            history: Vec::new(),
            checksum: twox_hash::XxHash32::with_seed(0),
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
    /// input, `LZ4F_compressEnd` — never one-shot, so the block size, mode
    /// and content size are exactly `o`'s. This is what zstd 1.5.7's
    /// `--format=lz4` writes (spike S4: byte-identical to
    /// `/opt/homebrew/opt/zstd/bin/zstd --format=lz4 -c FILE` at levels 1,
    /// 3, 9 and 19 with `level` capped at 12, `block_size` 64 KiB,
    /// `block_linked`, the content checksum and the file's size). `legacy`
    /// is ignored.
    pub fn new_plain(o: &EncodeOptions) -> Result<Encoder, Lz4Error> {
        let mut e = Encoder::new(&EncodeOptions {
            legacy: false,
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
            FRAME_CHUNK
        }
    }

    /// Writes the frame header (or the legacy magic) on first call.
    ///
    /// For a frame, "first" means once a whole 4 MiB chunk has arrived: an
    /// input that ends sooner is one `LZ4F_compressFrame` call, written by
    /// [`Encoder::finish`] (the module doc of `lz4_opts`). Whatever slices
    /// the caller feeds, the output is the same.
    pub fn update(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), Lz4Error> {
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

    /// Ends the frame: the last block, the end mark and the content
    /// checksum (a one-shot frame is written whole here). The context can
    /// then start another frame.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), Lz4Error> {
        let pending = std::mem::take(&mut self.pending);
        let r = if self.settings.legacy {
            self.finish_legacy(&pending, out)
        } else if self.plain {
            self.finish_plain(&pending, out)
        } else if !self.started {
            self.one_shot(&pending, out)
        } else {
            self.finish_stream(&pending, out)
        };
        self.pending = pending;
        self.pending.clear();
        self.started = false;
        self.history.clear();
        self.checksum = twox_hash::XxHash32::with_seed(0);
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
        if self.plain {
            self.compress_update(chunk, out)
        } else {
            self.compress_job(chunk, out)
        }
    }

    /// `LZ4F_compressBegin`: the streamed frame's header, with the content
    /// size if one was given.
    fn begin(&mut self, out: &mut Vec<u8>) -> Result<(), Lz4Error> {
        let prefs = preferences(&self.settings, self.settings.content_size.unwrap_or(0));
        let mut hdr = [0u8; super::HEADER_SIZE_MAX];
        let n = match (self.plain, self.cdict) {
            // SAFETY: cctx and the CDict are live; hdr has
            // LZ4F_HEADER_SIZE_MAX bytes of room, as the API requires;
            // prefs outlives the call.
            (true, Some(cd)) => check(unsafe {
                LZ4F_compressBegin_usingCDict(
                    self.cctx.as_ptr(),
                    hdr.as_mut_ptr(),
                    hdr.len(),
                    cd.as_ptr(),
                    &prefs,
                )
            })?,
            // SAFETY: as above, without a dictionary (a job-compressed
            // frame applies its dictionary per job).
            _ => check(unsafe {
                sys::LZ4F_compressBegin(
                    sys::LZ4FCompressionContext(self.cctx.as_ptr()),
                    hdr.as_mut_ptr(),
                    hdr.len(),
                    &prefs,
                )
            })?,
        };
        out.extend_from_slice(&hdr[..n]);
        self.started = true;
        Ok(())
    }

    /// One job of a streamed frame (spike S1): `job` compressed as a frame
    /// of its own by the job context — begun against the previous 64 KiB of
    /// input when blocks are linked (the `-D` dictionary for the first job),
    /// against the `-D` dictionary when they are independent — whose blocks,
    /// stripped of that frame's header and end mark, are this frame's next
    /// blocks.
    fn compress_job(&mut self, job: &[u8], out: &mut Vec<u8>) -> Result<(), Lz4Error> {
        let mut settings = self.settings;
        settings.content_checksum = false;
        settings.content_size = None;
        let prefs = preferences(&settings, 0);
        // The previous 64 KiB sit immediately before the job in memory, as
        // the reference's do: liblz4 then compresses the job as a
        // continuation of that prefix rather than against a detached
        // dictionary, which changes the bytes (spike S1, `-B4 -BD -9`).
        let mut window = std::mem::take(&mut self.history);
        let prefix = window.len();
        if self.settings.linked && prefix > 0 {
            window.extend_from_slice(job);
        }
        let (dict, src) = match (self.settings.linked, self.cdict) {
            (true, _) if prefix > 0 => (JobDict::Raw(&window[..prefix]), &window[prefix..]),
            // Every job under independent blocks, and the first under
            // linked ones, starts from the digested `-D` dictionary (spike
            // S2; a raw `LZ4F_compressBegin_usingDict` differs).
            (_, Some(cd)) => (JobDict::CDict(cd), job),
            _ => (JobDict::None, job),
        };
        // SAFETY: prefs is a valid preferences struct for both calls.
        let bound = unsafe {
            sys::LZ4F_compressBound(src.len(), &prefs) + sys::LZ4F_compressBound(0, &prefs)
        };
        self.scratch.resize(super::HEADER_SIZE_MAX + bound, 0);
        let r = job_frame(self.job, &mut self.scratch, src, dict, &prefs);
        if self.settings.linked {
            if prefix == 0 {
                window.extend_from_slice(&job[job.len().saturating_sub(HISTORY)..]);
            }
            let excess = window.len().saturating_sub(HISTORY);
            window.drain(..excess);
        }
        self.history = window;
        let (h, n) = r?;
        out.extend_from_slice(&self.scratch[h..h + n]);
        if self.settings.content_checksum {
            std::hash::Hasher::write(&mut self.checksum, job);
        }
        Ok(())
    }

    /// `LZ4F_compressUpdate` on the main context (a plain frame).
    fn compress_update(&mut self, src: &[u8], out: &mut Vec<u8>) -> Result<(), Lz4Error> {
        let prefs = preferences(&self.settings, 0);
        // SAFETY: prefs is a valid preferences struct for the call.
        let bound = unsafe { sys::LZ4F_compressBound(src.len(), &prefs) };
        self.scratch.resize(bound, 0);
        // SAFETY: cctx is live and begun; scratch has
        // LZ4F_compressBound(src.len()) bytes, as the API requires; src is
        // live; NULL options are allowed.
        let n = check(unsafe {
            sys::LZ4F_compressUpdate(
                sys::LZ4FCompressionContext(self.cctx.as_ptr()),
                self.scratch.as_mut_ptr(),
                bound,
                src.as_ptr(),
                src.len(),
                std::ptr::null(),
            )
        })?;
        out.extend_from_slice(&self.scratch[..n]);
        Ok(())
    }

    /// The rest of a plain frame: the header if nothing came, the last
    /// partial block, then `LZ4F_compressEnd`.
    fn finish_plain(&mut self, rest: &[u8], out: &mut Vec<u8>) -> Result<(), Lz4Error> {
        if !self.started {
            self.begin(out)?;
        }
        if !rest.is_empty() {
            self.compress_update(rest, out)?;
        }
        let prefs = preferences(&self.settings, 0);
        // SAFETY: prefs is a valid preferences struct for the call.
        let bound = unsafe { sys::LZ4F_compressBound(0, &prefs) };
        self.scratch.resize(bound, 0);
        // SAFETY: cctx is live and begun; scratch has
        // LZ4F_compressBound(0) bytes, the bound for a flush and the end
        // mark and checksum; NULL options are allowed.
        let n = check(unsafe {
            sys::LZ4F_compressEnd(
                sys::LZ4FCompressionContext(self.cctx.as_ptr()),
                self.scratch.as_mut_ptr(),
                bound,
                std::ptr::null(),
            )
        })?;
        out.extend_from_slice(&self.scratch[..n]);
        Ok(())
    }

    /// The rest of a streamed frame: the last, partial job, the end mark
    /// and the content checksum.
    fn finish_stream(&mut self, rest: &[u8], out: &mut Vec<u8>) -> Result<(), Lz4Error> {
        if !rest.is_empty() {
            self.compress_job(rest, out)?;
        }
        out.extend_from_slice(&[0; 4]);
        if self.settings.content_checksum {
            out.extend_from_slice(&self.checksum.finish_32().to_le_bytes());
        }
        Ok(())
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
                sys::LZ4_compress_fast(
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
                sys::LZ4_compress_HC(
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

/// Compresses `job` into `scratch` as a frame of its own (through `job_ctx`): returns
/// where its blocks start and how long they are (the end mark left
/// out).
fn job_frame(
    job_ctx: NonNull<c_void>,
    scratch: &mut [u8],
    job: &[u8],
    dict: JobDict<'_>,
    prefs: &sys::LZ4FPreferences,
) -> Result<(usize, usize), Lz4Error> {
    let ctx = job_ctx.as_ptr();
    let dst = scratch.as_mut_ptr();
    let cap = scratch.len();
    let h = check(match dict {
        // SAFETY: ctx is live; dst has cap ≥ LZ4F_HEADER_SIZE_MAX
        // bytes; prefs outlives the call.
        JobDict::None => unsafe {
            sys::LZ4F_compressBegin(sys::LZ4FCompressionContext(ctx), dst, cap, prefs)
        },
        // SAFETY: as above; the CDict is live for the whole session.
        JobDict::CDict(cd) => unsafe {
            LZ4F_compressBegin_usingCDict(ctx, dst, cap, cd.as_ptr(), prefs)
        },
        // SAFETY: as above; `d` outlives the session, which ends with
        // the compressEnd below.
        JobDict::Raw(d) => unsafe {
            LZ4F_compressBegin_usingDict(ctx, dst, cap, d.as_ptr(), d.len(), prefs)
        },
    })?;
    // SAFETY: the session is begun; dst + h has cap - h bytes, at least
    // LZ4F_compressBound(job.len()) as the API requires; job is live;
    // NULL options are allowed.
    let n = check(unsafe {
        sys::LZ4F_compressUpdate(
            sys::LZ4FCompressionContext(ctx),
            dst.add(h),
            cap - h,
            job.as_ptr(),
            job.len(),
            std::ptr::null(),
        )
    })?;
    // SAFETY: as above; what is left is at least LZ4F_compressBound(0),
    // the bound for the flush and the end mark.
    let m = check(unsafe {
        sys::LZ4F_compressEnd(
            sys::LZ4FCompressionContext(ctx),
            dst.add(h + n),
            cap - h - n,
            std::ptr::null(),
        )
    })?;
    Ok((h, n + m - 4))
}

/// How much input a linked job sees before it: LZ4's 64 KiB window.
const HISTORY: usize = 64 << 10;

/// The first level the legacy format compresses with `LZ4_compress_HC`
/// (spike S1).
const LEGACY_HC_MIN: i32 = 3;

/// `LZ4_compress_fast`'s acceleration for a legacy level below
/// [`LEGACY_HC_MIN`] (spike S1).
fn legacy_acceleration(level: i32) -> c_int {
    if level < 0 { -level } else { 1 }
}

/// One legacy block through `LZ4_decompress_safe`: the decoded length, or
/// [`Lz4fError::DecompressionFailed`].
pub(super) fn legacy_block_decode(src: &[u8], dst: &mut [u8]) -> Result<usize, Lz4Error> {
    // SAFETY: src and dst are live slices of the lengths passed (src ≤
    // LZ4_COMPRESSBOUND(8 MiB), dst = 8 MiB, both within c_int);
    // LZ4_decompress_safe never reads or writes past them.
    let n = unsafe {
        sys::LZ4_decompress_safe(
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
    dctx: NonNull<c_void>,
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
            sys::LZ4F_freeDecompressionContext(sys::LZ4FDecompressionContext(self.dctx.as_ptr()));
        }
    }
}

impl Decoder {
    /// A context for `o`.
    pub fn new(o: &DecodeOptions) -> Result<Decoder, Lz4Error> {
        let mut ctx = sys::LZ4FDecompressionContext(std::ptr::null_mut());
        // SAFETY: ctx is a valid out-pointer; LZ4F_VERSION matches.
        check(unsafe { sys::LZ4F_createDecompressionContext(&mut ctx, sys::LZ4F_VERSION) })?;
        let dctx = NonNull::new(ctx.0).ok_or(Lz4Error::Lib(Lz4fError::AllocationFailed))?;
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
                    sys::LZ4F_decompress(
                        sys::LZ4FDecompressionContext(self.dctx.as_ptr()),
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
