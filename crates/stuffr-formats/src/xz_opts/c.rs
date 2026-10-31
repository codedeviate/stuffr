//! The C tier of [`super`]: liblzma 5.8.4, statically built by
//! `liblzma-sys`, driven the way `xz`'s `coder.c` drives it.
//!
//! The `liblzma` crate does not re-export its `liblzma-sys` bindings, and
//! what it wraps safely lacks what `xz` needs (preset dictionaries, BCJ
//! start offsets, `lzma_filters_update`, `lzma_memusage`, the memusage
//! functions), so `ffi` declares the symbols this module calls. They
//! resolve against the `liblzma.a` that `liblzma-sys` links into every
//! build with `xz-c`. The struct layouts are liblzma's public ABI (5.8.4's
//! `api/lzma/*.h`), reserved fields included.
//!
//! Miri cannot run FFI; `make miri` never builds this module.

use std::collections::VecDeque;
use std::ffi::c_void;
use std::ptr;

use super::{
    Bcj, Check, DecodeOptions, EncodeOptions, Filter, Format, Lzma, MatchFinder, Mode, Progress,
    XzError,
};

/// The liblzma symbols and structs this module uses (`api/lzma/*.h`).
#[allow(non_camel_case_types)]
mod ffi {
    use std::ffi::{c_char, c_void};

    #[cfg(target_env = "msvc")]
    pub type Enum = std::ffi::c_int;
    #[cfg(not(target_env = "msvc"))]
    pub type Enum = std::ffi::c_uint;
    pub type lzma_ret = Enum;
    pub type lzma_action = Enum;

    pub const LZMA_OK: lzma_ret = 0;
    pub const LZMA_STREAM_END: lzma_ret = 1;
    pub const LZMA_UNSUPPORTED_CHECK: lzma_ret = 3;
    pub const LZMA_MEM_ERROR: lzma_ret = 5;
    pub const LZMA_MEMLIMIT_ERROR: lzma_ret = 6;
    pub const LZMA_FORMAT_ERROR: lzma_ret = 7;
    pub const LZMA_OPTIONS_ERROR: lzma_ret = 8;
    pub const LZMA_DATA_ERROR: lzma_ret = 9;
    pub const LZMA_BUF_ERROR: lzma_ret = 10;

    pub const LZMA_RUN: lzma_action = 0;
    pub const LZMA_SYNC_FLUSH: lzma_action = 1;
    pub const LZMA_FINISH: lzma_action = 3;
    pub const LZMA_FULL_BARRIER: lzma_action = 4;

    pub const LZMA_TELL_UNSUPPORTED_CHECK: u32 = 0x02;
    pub const LZMA_CONCATENATED: u32 = 0x08;
    pub const LZMA_IGNORE_CHECK: u32 = 0x10;

    pub const LZMA_VLI_UNKNOWN: u64 = u64::MAX;
    pub const LZMA_FILTER_LZMA1: u64 = 0x4000_0000_0000_0001;
    pub const LZMA_FILTER_LZMA1EXT: u64 = 0x4000_0000_0000_0002;
    pub const LZMA_FILTER_LZMA2: u64 = 0x21;
    pub const LZMA_FILTER_DELTA: u64 = 0x03;
    pub const LZMA_LZMA1EXT_ALLOW_EOPM: u32 = 0x01;

    #[repr(C)]
    pub struct lzma_stream {
        pub next_in: *const u8,
        pub avail_in: usize,
        pub total_in: u64,
        pub next_out: *mut u8,
        pub avail_out: usize,
        pub total_out: u64,
        pub allocator: *const c_void,
        pub internal: *mut c_void,
        pub reserved_ptr1: *mut c_void,
        pub reserved_ptr2: *mut c_void,
        pub reserved_ptr3: *mut c_void,
        pub reserved_ptr4: *mut c_void,
        pub seek_pos: u64,
        pub reserved_int2: u64,
        pub reserved_int3: usize,
        pub reserved_int4: usize,
        pub reserved_enum1: Enum,
        pub reserved_enum2: Enum,
    }

    #[repr(C)]
    pub struct lzma_filter {
        pub id: u64,
        pub options: *mut c_void,
    }

    #[repr(C)]
    pub struct lzma_options_lzma {
        pub dict_size: u32,
        pub preset_dict: *const u8,
        pub preset_dict_size: u32,
        pub lc: u32,
        pub lp: u32,
        pub pb: u32,
        pub mode: Enum,
        pub nice_len: u32,
        pub mf: Enum,
        pub depth: u32,
        pub ext_flags: u32,
        pub ext_size_low: u32,
        pub ext_size_high: u32,
        pub reserved_int4: u32,
        pub reserved_int5: u32,
        pub reserved_int6: u32,
        pub reserved_int7: u32,
        pub reserved_int8: u32,
        pub reserved_enum1: Enum,
        pub reserved_enum2: Enum,
        pub reserved_enum3: Enum,
        pub reserved_enum4: Enum,
        pub reserved_ptr1: *mut c_void,
        pub reserved_ptr2: *mut c_void,
    }

    #[repr(C)]
    pub struct lzma_options_bcj {
        pub start_offset: u32,
    }

    #[repr(C)]
    pub struct lzma_options_delta {
        pub type_: Enum,
        pub dist: u32,
        pub reserved_int1: u32,
        pub reserved_int2: u32,
        pub reserved_int3: u32,
        pub reserved_int4: u32,
        pub reserved_ptr1: *mut c_void,
        pub reserved_ptr2: *mut c_void,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct lzma_mt {
        pub flags: u32,
        pub threads: u32,
        pub block_size: u64,
        pub timeout: u32,
        pub preset: u32,
        pub filters: *const lzma_filter,
        pub check: Enum,
        pub reserved_enum1: Enum,
        pub reserved_enum2: Enum,
        pub reserved_enum3: Enum,
        pub reserved_int1: u32,
        pub reserved_int2: u32,
        pub reserved_int3: u32,
        pub reserved_int4: u32,
        pub memlimit_threading: u64,
        pub memlimit_stop: u64,
        pub reserved_int7: u64,
        pub reserved_int8: u64,
        pub reserved_ptr1: *mut c_void,
        pub reserved_ptr2: *mut c_void,
        pub reserved_ptr3: *mut c_void,
        pub reserved_ptr4: *mut c_void,
    }

    unsafe extern "C" {
        pub fn lzma_code(strm: *mut lzma_stream, action: lzma_action) -> lzma_ret;
        pub fn lzma_end(strm: *mut lzma_stream);
        pub fn lzma_get_progress(strm: *mut lzma_stream, pin: *mut u64, pout: *mut u64);
        pub fn lzma_memusage(strm: *const lzma_stream) -> u64;
        pub fn lzma_memlimit_get(strm: *const lzma_stream) -> u64;
        pub fn lzma_get_check(strm: *const lzma_stream) -> Enum;

        pub fn lzma_stream_encoder(
            strm: *mut lzma_stream,
            filters: *const lzma_filter,
            check: Enum,
        ) -> lzma_ret;
        pub fn lzma_stream_encoder_mt(strm: *mut lzma_stream, options: *const lzma_mt) -> lzma_ret;
        pub fn lzma_stream_encoder_mt_memusage(options: *const lzma_mt) -> u64;
        pub fn lzma_mt_block_size(filters: *const lzma_filter) -> u64;
        pub fn lzma_alone_encoder(
            strm: *mut lzma_stream,
            options: *const lzma_options_lzma,
        ) -> lzma_ret;
        pub fn lzma_raw_encoder(strm: *mut lzma_stream, filters: *const lzma_filter) -> lzma_ret;
        pub fn lzma_raw_encoder_memusage(filters: *const lzma_filter) -> u64;
        pub fn lzma_filters_update(strm: *mut lzma_stream, filters: *const lzma_filter)
        -> lzma_ret;

        pub fn lzma_stream_decoder_mt(strm: *mut lzma_stream, options: *const lzma_mt) -> lzma_ret;
        pub fn lzma_alone_decoder(strm: *mut lzma_stream, memlimit: u64) -> lzma_ret;
        pub fn lzma_lzip_decoder(strm: *mut lzma_stream, memlimit: u64, flags: u32) -> lzma_ret;
        pub fn lzma_auto_decoder(strm: *mut lzma_stream, memlimit: u64, flags: u32) -> lzma_ret;
        pub fn lzma_raw_decoder(strm: *mut lzma_stream, filters: *const lzma_filter) -> lzma_ret;
        pub fn lzma_raw_decoder_memusage(filters: *const lzma_filter) -> u64;

        pub fn lzma_version_string() -> *const c_char;
        pub fn lzma_physmem() -> u64;
        pub fn lzma_cputhreads() -> u32;
        #[cfg(test)]
        pub fn lzma_lzma_preset(options: *mut lzma_options_lzma, preset: u32) -> u8;
    }
}

/// `xz`'s `lzma_mt.timeout` (`coder.c`'s `mt_options`). It bounds how long
/// one `lzma_code` call may block; the bytes do not depend on it.
const MT_TIMEOUT_MS: u32 = 300;

/// Output room offered per `lzma_code` call.
const OUT_CHUNK: usize = 64 * 1024;

/// `0` and `u64::MAX` both mean no limit, as `hardware_memlimit_get` reads
/// them.
fn limit_of(memlimit: u64) -> u64 {
    if memlimit == 0 { u64::MAX } else { memlimit }
}

fn mode_of(m: Mode) -> ffi::Enum {
    match m {
        Mode::Fast => 1,
        Mode::Normal => 2,
    }
}

fn mf_of(mf: MatchFinder) -> ffi::Enum {
    match mf {
        MatchFinder::Hc3 => 0x03,
        MatchFinder::Hc4 => 0x04,
        MatchFinder::Bt2 => 0x12,
        MatchFinder::Bt3 => 0x13,
        MatchFinder::Bt4 => 0x14,
    }
}

fn bcj_id(kind: Bcj) -> u64 {
    match kind {
        Bcj::X86 => 0x04,
        Bcj::PowerPc => 0x05,
        Bcj::Ia64 => 0x06,
        Bcj::Arm => 0x07,
        Bcj::ArmThumb => 0x08,
        Bcj::Sparc => 0x09,
        Bcj::Arm64 => 0x0a,
        Bcj::RiscV => 0x0b,
    }
}

fn check_of(c: Check) -> ffi::Enum {
    c.id() as ffi::Enum
}

/// An `lzma_options_lzma` carrying `l`, every reserved field zero as
/// liblzma requires.
fn options_lzma(l: &Lzma, dict: Option<&[u8]>) -> ffi::lzma_options_lzma {
    ffi::lzma_options_lzma {
        dict_size: l.dict_size,
        preset_dict: dict.map_or(ptr::null(), <[u8]>::as_ptr),
        preset_dict_size: dict.map_or(0, |d| d.len() as u32),
        lc: l.lc,
        lp: l.lp,
        pb: l.pb,
        mode: mode_of(l.mode),
        nice_len: l.nice_len,
        mf: mf_of(l.mf),
        depth: l.depth,
        ext_flags: 0,
        ext_size_low: 0,
        ext_size_high: 0,
        reserved_int4: 0,
        reserved_int5: 0,
        reserved_int6: 0,
        reserved_int7: 0,
        reserved_int8: 0,
        reserved_enum1: 0,
        reserved_enum2: 0,
        reserved_enum3: 0,
        reserved_enum4: 0,
        reserved_ptr1: ptr::null_mut(),
        reserved_ptr2: ptr::null_mut(),
    }
}

/// One filter's options, heap-pinned so the pointer in the `lzma_filter`
/// array stays valid as long as the [`CChain`] lives. liblzma copies the
/// option structs but not a preset dictionary, which the threaded encoder
/// and `lzma_filters_update` read later, so the dictionary is owned here
/// too. Never read from Rust: the fields exist to own the memory.
#[allow(dead_code)]
enum COpts {
    Lzma(Box<ffi::lzma_options_lzma>, Option<Box<[u8]>>),
    Bcj(Box<ffi::lzma_options_bcj>),
    Delta(Box<ffi::lzma_options_delta>),
}

/// A filter chain as liblzma takes it: the `lzma_filter` array, terminated
/// by `LZMA_VLI_UNKNOWN`, and the options it points into.
struct CChain {
    filters: Vec<ffi::lzma_filter>,
    _opts: Vec<COpts>,
}

impl CChain {
    fn new(chain: &[Filter]) -> CChain {
        let mut filters = Vec::with_capacity(chain.len() + 1);
        let mut opts = Vec::with_capacity(chain.len());
        for f in chain {
            let (id, options): (u64, *mut c_void) = match f {
                Filter::Lzma1(l) | Filter::Lzma1Ext(l) | Filter::Lzma2(l) => {
                    let dict: Option<Box<[u8]>> = l.preset_dict.as_deref().map(Box::from);
                    let mut o = Box::new(options_lzma(l, dict.as_deref()));
                    let id = match f {
                        Filter::Lzma1(_) => ffi::LZMA_FILTER_LZMA1,
                        Filter::Lzma1Ext(_) => {
                            // The end marker allowed and the size unknown:
                            // LZMA1's behaviour on both sides.
                            o.ext_flags = ffi::LZMA_LZMA1EXT_ALLOW_EOPM;
                            o.ext_size_low = u32::MAX;
                            o.ext_size_high = u32::MAX;
                            ffi::LZMA_FILTER_LZMA1EXT
                        }
                        _ => ffi::LZMA_FILTER_LZMA2,
                    };
                    let p = ptr::from_mut(&mut *o).cast();
                    opts.push(COpts::Lzma(o, dict));
                    (id, p)
                }
                Filter::Bcj { kind, start } => {
                    let mut o = Box::new(ffi::lzma_options_bcj {
                        start_offset: *start,
                    });
                    let p = ptr::from_mut(&mut *o).cast();
                    opts.push(COpts::Bcj(o));
                    (bcj_id(*kind), p)
                }
                Filter::Delta { dist } => {
                    let mut o = Box::new(ffi::lzma_options_delta {
                        type_: 0, // LZMA_DELTA_TYPE_BYTE
                        dist: *dist,
                        reserved_int1: 0,
                        reserved_int2: 0,
                        reserved_int3: 0,
                        reserved_int4: 0,
                        reserved_ptr1: ptr::null_mut(),
                        reserved_ptr2: ptr::null_mut(),
                    });
                    let p = ptr::from_mut(&mut *o).cast();
                    opts.push(COpts::Delta(o));
                    (ffi::LZMA_FILTER_DELTA, p)
                }
            };
            filters.push(ffi::lzma_filter { id, options });
        }
        filters.push(ffi::lzma_filter {
            id: ffi::LZMA_VLI_UNKNOWN,
            options: ptr::null_mut(),
        });
        CChain {
            filters,
            _opts: opts,
        }
    }

    fn as_ptr(&self) -> *const ffi::lzma_filter {
        self.filters.as_ptr()
    }

    /// The options for `lzma_alone_encoder`, if the chain is exactly one
    /// LZMA1 (what `coder_set_compression_settings` insists on for
    /// `.lzma`).
    fn sole_lzma1(&self) -> Option<*const ffi::lzma_options_lzma> {
        (self.filters.len() == 2 && self.filters[0].id == ffi::LZMA_FILTER_LZMA1)
            .then(|| self.filters[0].options.cast_const().cast())
    }
}

/// An encoder's filter chains: index 0 is [`EncodeOptions::filters`], the
/// rest the distinct `--filtersN` chains of the block list; `list` is the
/// block list as `(size, chain index)`, and `used` the chains actually
/// used (`coder.c`'s `chains_used_mask`). The block list is `.xz`'s only.
struct Chains {
    chains: Vec<CChain>,
    list: Vec<(u64, usize)>,
    used: Vec<usize>,
}

impl Chains {
    fn new(o: &EncodeOptions) -> Chains {
        let mut src: Vec<&[Filter]> = vec![&o.filters];
        let mut list = Vec::new();
        if o.format == Format::Xz {
            for (size, chain) in &o.block_list {
                let chain = chain.as_deref().unwrap_or(&o.filters);
                let i = match src.iter().position(|c| *c == chain) {
                    Some(i) => i,
                    None => {
                        src.push(chain);
                        src.len() - 1
                    }
                };
                list.push((*size, i));
            }
        }
        let mut used: Vec<usize> = if list.is_empty() {
            vec![0]
        } else {
            list.iter().map(|&(_, i)| i).collect()
        };
        used.sort_unstable();
        used.dedup();
        Chains {
            chains: src.into_iter().map(CChain::new).collect(),
            list,
            used,
        }
    }

    /// The chain the stream starts with (`coder_init`'s `active_filters`).
    fn first(&self) -> &CChain {
        &self.chains[self.list.first().map_or(0, |&(_, i)| i)]
    }

    /// `lzma_mt.block_size` as `coder_set_compression_settings` sets it:
    /// the option, or else the largest `lzma_mt_block_size` of the used
    /// chains, capped at the block list's largest entry. `None` when a
    /// chain is unsupported.
    fn mt_block_size(&self, block_size: u64) -> Option<u64> {
        if block_size != 0 {
            return Some(block_size);
        }
        let mut size = 0;
        for &i in &self.used {
            // SAFETY: a terminated chain whose options outlive the call.
            let s = unsafe { ffi::lzma_mt_block_size(self.chains[i].as_ptr()) };
            if s == u64::MAX {
                return None;
            }
            size = size.max(s);
        }
        let largest = self.list.iter().map(|&(s, _)| s).max().unwrap_or(0);
        if largest > 0 && size > largest {
            size = largest;
        }
        Some(size)
    }

    /// The `lzma_mt` the threaded `.xz` encoder gets, `filters` unset;
    /// `Ok(None)` when `o` is not threaded `.xz`.
    fn mt(&self, o: &EncodeOptions) -> Result<Option<ffi::lzma_mt>, XzError> {
        if o.format != Format::Xz || o.threads == 0 {
            return Ok(None);
        }
        let mut m = mt_options();
        m.threads = o.threads;
        m.block_size = self.mt_block_size(o.block_size).ok_or(XzError::Options)?;
        m.check = check_of(o.check);
        Ok(Some(m))
    }

    /// `get_chains_memusage(.., encode = true)`: the largest encoder
    /// memusage of the used chains, threaded or not.
    fn memusage(&self, o: &EncodeOptions) -> Option<u64> {
        if o.format == Format::Lzip {
            return None;
        }
        let mt = self.mt(o).ok()?;
        let mut max = 0;
        for &i in &self.used {
            let chain = self.chains[i].as_ptr();
            let usage = match mt {
                Some(m) => {
                    let m = ffi::lzma_mt {
                        filters: chain,
                        ..m
                    };
                    // SAFETY: a valid `lzma_mt` over a terminated chain.
                    unsafe { ffi::lzma_stream_encoder_mt_memusage(&raw const m) }
                }
                // SAFETY: a terminated chain whose options outlive the call.
                None => unsafe { ffi::lzma_raw_encoder_memusage(chain) },
            };
            if usage == u64::MAX {
                return None;
            }
            max = max.max(usage);
        }
        Some(max)
    }
}

/// An `lzma_mt` with every field zero but `xz`'s timeout.
fn mt_options() -> ffi::lzma_mt {
    ffi::lzma_mt {
        flags: 0,
        threads: 0,
        block_size: 0,
        timeout: MT_TIMEOUT_MS,
        preset: 0,
        filters: ptr::null(),
        check: 0,
        reserved_enum1: 0,
        reserved_enum2: 0,
        reserved_enum3: 0,
        reserved_int1: 0,
        reserved_int2: 0,
        reserved_int3: 0,
        reserved_int4: 0,
        memlimit_threading: 0,
        memlimit_stop: 0,
        reserved_int7: 0,
        reserved_int8: 0,
        reserved_ptr1: ptr::null_mut(),
        reserved_ptr2: ptr::null_mut(),
        reserved_ptr3: ptr::null_mut(),
        reserved_ptr4: ptr::null_mut(),
    }
}

/// The encoder's memory usage for `o` (`lzma_raw_encoder_memusage`, or
/// `lzma_stream_encoder_mt_memusage` threaded), the largest over the chains
/// in use; `None` for an unsupported chain or options, or [`Format::Lzip`].
pub fn encoder_memusage(o: &EncodeOptions) -> Option<u64> {
    Chains::new(o).memusage(o)
}

/// `lzma_raw_decoder_memusage(filters)`; `None` for an unsupported chain.
pub fn decoder_memusage(filters: &[Filter]) -> Option<u64> {
    let chain = CChain::new(filters);
    // SAFETY: a terminated chain whose options outlive the call.
    let usage = unsafe { ffi::lzma_raw_decoder_memusage(chain.as_ptr()) };
    (usage != u64::MAX).then_some(usage)
}

/// `lzma_version_string()`: `"5.8.4"` for the liblzma this build links.
pub fn liblzma_version() -> &'static str {
    // SAFETY: liblzma returns a pointer to a static NUL-terminated string.
    unsafe { std::ffi::CStr::from_ptr(ffi::lzma_version_string()) }
        .to_str()
        .unwrap_or("")
}

/// `lzma_physmem()`: the machine's RAM in bytes, `0` if unknown — which,
/// on unix, it always is here: `liblzma-sys` builds `tuklib_physmem.c`
/// with no `TUKLIB_PHYSMEM_*` method defined.
pub fn physmem() -> u64 {
    // SAFETY: no arguments, no state.
    unsafe { ffi::lzma_physmem() }
}

/// `lzma_cputhreads()`: the machine's hardware threads, `0` if unknown —
/// on unix, always, for the same reason as [`physmem`].
pub fn cputhreads() -> u32 {
    // SAFETY: no arguments, no state.
    unsafe { ffi::lzma_cputhreads() }
}

/// An `lzma_stream`, heap-pinned, and the calls `coder.c` makes on it.
struct Strm(Box<ffi::lzma_stream>);

impl Strm {
    /// `LZMA_STREAM_INIT`.
    fn new() -> Strm {
        // SAFETY: all-zero is `LZMA_STREAM_INIT`: null pointers, zero
        // counts, zero enums.
        Strm(Box::new(unsafe { std::mem::zeroed() }))
    }

    fn raw(&mut self) -> *mut ffi::lzma_stream {
        &raw mut *self.0
    }

    fn initialised(&self) -> bool {
        !self.0.internal.is_null()
    }

    fn progress(&self) -> Progress {
        if !self.initialised() {
            return Progress::default();
        }
        let (mut pin, mut pout) = (0, 0);
        // `lzma_get_progress` takes a mutable stream but writes only
        // through the two out-pointers.
        let s = ptr::from_ref(&*self.0).cast_mut();
        // SAFETY: an initialised stream and two valid out-pointers.
        unsafe { ffi::lzma_get_progress(s, &raw mut pin, &raw mut pout) };
        Progress {
            in_bytes: pin,
            out_bytes: pout,
        }
    }

    fn memusage(&self) -> u64 {
        if !self.initialised() {
            return 0;
        }
        // SAFETY: an initialised stream.
        unsafe { ffi::lzma_memusage(&*self.0) }
    }

    fn memlimit(&self) -> u64 {
        if !self.initialised() {
            return 0;
        }
        // SAFETY: an initialised stream.
        unsafe { ffi::lzma_memlimit_get(&*self.0) }
    }

    fn check(&self) -> u32 {
        if !self.initialised() {
            return 0;
        }
        // SAFETY: an initialised stream.
        unsafe { ffi::lzma_get_check(&*self.0) as u32 }
    }

    /// `ret` as `message_strm` reads it; `LZMA_MEMLIMIT_ERROR` carries
    /// `lzma_memusage` as `message_mem_needed` prints it.
    fn error(&self, ret: ffi::lzma_ret) -> XzError {
        match ret {
            ffi::LZMA_MEM_ERROR => XzError::Mem {
                needed: self.memusage(),
            },
            ffi::LZMA_MEMLIMIT_ERROR => XzError::MemLimit {
                needed: self.memusage(),
                limit: self.memlimit(),
            },
            ffi::LZMA_FORMAT_ERROR => XzError::Format,
            ffi::LZMA_OPTIONS_ERROR => XzError::Options,
            ffi::LZMA_DATA_ERROR => XzError::Data,
            ffi::LZMA_BUF_ERROR => XzError::BufError,
            ffi::LZMA_UNSUPPORTED_CHECK => XzError::UnsupportedCheck(self.check()),
            _ => XzError::Prog,
        }
    }

    /// One `lzma_code(action)` over `input`, appending to `out`: how much
    /// of `input` it consumed, the `lzma_ret`, and whether it filled all
    /// the output room it was offered.
    fn code_once(
        &mut self,
        input: &[u8],
        action: ffi::lzma_action,
        out: &mut Vec<u8>,
    ) -> (usize, ffi::lzma_ret, bool) {
        out.reserve(OUT_CHUNK);
        let spare = out.spare_capacity_mut();
        let room = spare.len();
        self.0.next_in = input.as_ptr();
        self.0.avail_in = input.len();
        self.0.next_out = spare.as_mut_ptr().cast();
        self.0.avail_out = room;
        // SAFETY: the stream is initialised; `next_in`/`avail_in` describe
        // `input` and `next_out`/`avail_out` the spare capacity of `out`,
        // both live for the call.
        let ret = unsafe { ffi::lzma_code(self.raw(), action) };
        let full = self.0.avail_out == 0;
        let made = room - self.0.avail_out;
        let used = input.len() - self.0.avail_in;
        // SAFETY: liblzma initialised the first `made` spare bytes.
        unsafe { out.set_len(out.len() + made) };
        self.0.next_in = ptr::null();
        self.0.avail_in = 0;
        self.0.next_out = ptr::null_mut();
        self.0.avail_out = 0;
        (used, ret, full)
    }

    /// `lzma_code(action)` with no output room: `next_out` null,
    /// `avail_out` 0, as `coder_init`'s probe calls it. Returns the bytes
    /// consumed and the return code.
    fn code_no_room(&mut self, input: &[u8], action: ffi::lzma_action) -> (usize, ffi::lzma_ret) {
        self.0.next_in = input.as_ptr();
        self.0.avail_in = input.len();
        self.0.next_out = ptr::null_mut();
        self.0.avail_out = 0;
        // SAFETY: the stream is initialised; `next_in`/`avail_in` describe
        // `input`, which lives for the call; there is no output buffer.
        let ret = unsafe { ffi::lzma_code(self.raw(), action) };
        let used = input.len() - self.0.avail_in;
        self.0.next_in = ptr::null();
        self.0.avail_in = 0;
        (used, ret)
    }

    /// `lzma_code(action)` with no more input until it says
    /// `LZMA_STREAM_END` (a barrier, a flush, the finish).
    fn drain(&mut self, action: ffi::lzma_action, out: &mut Vec<u8>) -> Result<(), XzError> {
        loop {
            match self.code_once(&[], action, out).1 {
                ffi::LZMA_OK => {}
                ffi::LZMA_STREAM_END => return Ok(()),
                ret => return Err(self.error(ret)),
            }
        }
    }
}

impl Drop for Strm {
    fn drop(&mut self) {
        // SAFETY: `lzma_end` accepts a stream in any state, initialised or
        // still `LZMA_STREAM_INIT`.
        unsafe { ffi::lzma_end(self.raw()) };
    }
}

/// A streaming encoder over [`EncodeOptions`], `coder.c`'s
/// `coder_init`/`coder_normal` for `MODE_COMPRESS`: `.xz` through
/// `lzma_stream_encoder` (`threads == 0`) or `lzma_stream_encoder_mt`,
/// `.lzma` through `lzma_alone_encoder`, raw through `lzma_raw_encoder`.
/// `--block-size` and `--block-list` cut Blocks with `LZMA_FULL_BARRIER`
/// and switch chains with `lzma_filters_update`, as `split_block` does.
///
/// The bytes depend on the options and the input, never on how the input
/// is split across [`Encoder::feed`] calls. On an error `out` keeps what
/// was produced before it, and the encoder takes no more calls.
pub struct Encoder {
    strm: Strm,
    chains: Chains,
    /// Threaded `.xz`: liblzma cuts `--block-size` Blocks itself.
    mt: bool,
    block_size: u64,
    /// Bytes left in this Block, `u64::MAX` for no cut (`.xz` only).
    block_remaining: u64,
    /// What is left of a list entry split by `--block-size`.
    next_block_remaining: u64,
    list_pos: usize,
    done: bool,
}

// SAFETY: the `lzma_stream` and the options it points at are owned by the
// encoder (heap-pinned) and only touched through `&mut self`; liblzma's
// threaded coder synchronises its own threads.
unsafe impl Send for Encoder {}

impl std::fmt::Debug for Encoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Encoder").finish_non_exhaustive()
    }
}

impl Encoder {
    /// Initialises the encoder. An [`XzError`] is the `lzma_ret` the
    /// initialiser returned; [`XzError::Options`] an unsupported chain or
    /// [`Format::Lzip`]; [`XzError::MemLimit`] an [`encoder_memusage`]
    /// over [`EncodeOptions::memlimit`].
    pub fn new(o: &EncodeOptions) -> Result<Encoder, XzError> {
        if o.format == Format::Lzip {
            return Err(XzError::Options);
        }
        let chains = Chains::new(o);
        let needed = chains.memusage(o).ok_or(XzError::Options)?;
        let limit = limit_of(o.memlimit);
        if needed > limit {
            return Err(XzError::MemLimit { needed, limit });
        }
        let mt = chains.mt(o)?;
        let mut strm = Strm::new();
        let first = chains.first().as_ptr();
        // SAFETY: each initialiser gets an `LZMA_STREAM_INIT` stream and a
        // terminated chain (or options) the encoder owns for as long as the
        // stream lives.
        let ret = unsafe {
            match (o.format, mt) {
                (Format::Xz, Some(m)) => {
                    let m = ffi::lzma_mt {
                        filters: first,
                        ..m
                    };
                    ffi::lzma_stream_encoder_mt(strm.raw(), &raw const m)
                }
                (Format::Xz, None) => {
                    ffi::lzma_stream_encoder(strm.raw(), first, check_of(o.check))
                }
                (Format::Lzma, _) => match chains.chains[0].sole_lzma1() {
                    Some(opts) => ffi::lzma_alone_encoder(strm.raw(), opts),
                    None => return Err(XzError::Options),
                },
                (Format::Raw, _) => ffi::lzma_raw_encoder(strm.raw(), first),
                (Format::Lzip, _) => unreachable!("refused above"),
            }
        };
        if ret != ffi::LZMA_OK {
            return Err(strm.error(ret));
        }
        // `coder_normal`'s set-up of `block_remaining`.
        let mut block_remaining = u64::MAX;
        let mut next_block_remaining = 0;
        if o.format == Format::Xz {
            if mt.is_none() && o.block_size > 0 {
                block_remaining = o.block_size;
            }
            if let Some(&(size, _)) = chains.list.first() {
                if block_remaining < size {
                    next_block_remaining = size - block_remaining;
                } else {
                    block_remaining = size;
                }
            }
        }
        Ok(Encoder {
            strm,
            chains,
            mt: mt.is_some(),
            block_size: o.block_size,
            block_remaining,
            next_block_remaining,
            list_pos: 0,
            done: false,
        })
    }

    /// Compresses `input`, appending what liblzma emits to `out`.
    pub fn feed(&mut self, mut input: &[u8], out: &mut Vec<u8>) -> Result<(), XzError> {
        if self.done {
            return Err(XzError::Prog);
        }
        while !input.is_empty() {
            let take =
                usize::try_from(self.block_remaining).map_or(input.len(), |r| r.min(input.len()));
            let (mut piece, rest) = input.split_at(take);
            input = rest;
            loop {
                let (used, ret, full) = self.strm.code_once(piece, ffi::LZMA_RUN, out);
                if ret != ffi::LZMA_OK {
                    self.done = true;
                    return Err(self.strm.error(ret));
                }
                piece = &piece[used..];
                if piece.is_empty() && !full {
                    break;
                }
            }
            if self.block_remaining != u64::MAX {
                self.block_remaining -= take as u64;
                if self.block_remaining == 0 {
                    self.barrier(out)?;
                }
            }
        }
        Ok(())
    }

    /// `LZMA_FULL_BARRIER`, then the next Block's size and chain:
    /// `coder_normal`'s `LZMA_STREAM_END` arm.
    fn barrier(&mut self, out: &mut Vec<u8>) -> Result<(), XzError> {
        if let Err(e) = self.strm.drain(ffi::LZMA_FULL_BARRIER, out) {
            self.done = true;
            return Err(e);
        }
        if self.chains.list.is_empty() {
            self.block_remaining = self.block_size;
            return Ok(());
        }
        self.split_block()
    }

    /// `coder.c`'s `split_block`.
    fn split_block(&mut self) -> Result<(), XzError> {
        if self.next_block_remaining > 0 {
            self.block_remaining = self.next_block_remaining.min(self.block_size);
            self.next_block_remaining -= self.block_remaining;
            return Ok(());
        }
        let list = &self.chains.list;
        if self.list_pos + 1 < list.len() {
            self.list_pos += 1;
            let (prev, next) = (list[self.list_pos - 1].1, list[self.list_pos].1);
            if prev != next {
                let chain = self.chains.chains[next].as_ptr();
                // SAFETY: an initialised stream and a terminated chain the
                // encoder owns.
                let ret = unsafe { ffi::lzma_filters_update(self.strm.raw(), chain) };
                if ret != ffi::LZMA_OK {
                    self.done = true;
                    return Err(self.strm.error(ret));
                }
            }
        }
        self.block_remaining = list[self.list_pos].0;
        if !self.mt && self.block_size > 0 && self.block_remaining > self.block_size {
            self.next_block_remaining = self.block_remaining - self.block_size;
            self.block_remaining = self.block_size;
        }
        Ok(())
    }

    /// `LZMA_SYNC_FLUSH`: everything fed so far becomes decodable from
    /// `out` and the Block goes on — what `coder_normal` does when
    /// `--flush-timeout` expires. liblzma refuses it ([`XzError::Prog`])
    /// to the threaded encoder and to chains other than LZMA2 and Delta.
    pub fn flush(&mut self, out: &mut Vec<u8>) -> Result<(), XzError> {
        if self.done {
            return Err(XzError::Prog);
        }
        let r = self.strm.drain(ffi::LZMA_SYNC_FLUSH, out);
        self.done = r.is_err();
        r
    }

    /// `LZMA_FINISH`: the rest of the stream, through its footer.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), XzError> {
        if self.done {
            return Err(XzError::Prog);
        }
        self.done = true;
        self.strm.drain(ffi::LZMA_FINISH, out)
    }

    /// Bytes in and out so far (`lzma_get_progress`).
    pub fn progress(&self) -> Progress {
        self.strm.progress()
    }
}

/// Where a [`Decoder`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DState {
    /// `auto`, holding the first bytes until `.lz` can be told apart.
    Sniffing,
    Running,
    /// `LZMA_STREAM_END` seen.
    Ended,
    /// An error was returned; nothing more is decoded.
    Failed,
}

/// The `.lz` magic (`coder.c`'s `is_format_lzip`).
const LZIP_MAGIC: &[u8; 4] = b"LZIP";

/// A streaming decoder over [`DecodeOptions`], `coder.c`'s `coder_init`/
/// `coder_normal` for `MODE_DECOMPRESS`: `.xz` through
/// `lzma_stream_decoder_mt` (single-threaded at one thread, as `xz -T1`
/// runs it), `.lzma` through `lzma_alone_decoder`, `.lz` through
/// `lzma_lzip_decoder`, raw through `lzma_raw_decoder`, `auto` through
/// `lzma_auto_decoder` — except `.lz`, recognised here by its magic,
/// because the liblzma `liblzma-sys` builds is configured without
/// `HAVE_LZIP_DECODER` and its auto decoder would take `.lz` for `.lzma`.
/// The flags are `xz`'s: `LZMA_CONCATENATED` unless `single_stream`, and
/// `LZMA_IGNORE_CHECK` or else `LZMA_TELL_UNSUPPORTED_CHECK`.
///
/// Input left after `LZMA_STREAM_END` is [`XzError::Data`], unless
/// `single_stream` or `.lz`, where it is left unconsumed
/// ([`Decoder::progress`]'s `in_bytes` says how much was used). On an
/// error `out` keeps everything decoded before it, as `coder_normal` writes
/// it out, and the decoder takes no more calls.
pub struct Decoder {
    strm: Strm,
    opts: DecodeOptions,
    /// The raw chain, owned for the raw decoder's lifetime.
    raw: Option<CChain>,
    state: DState,
    /// `auto`'s first bytes, before the format is known.
    sniff: Vec<u8>,
    allow_trailing: bool,
    warnings: VecDeque<u32>,
}

// SAFETY: as for `Encoder`.
unsafe impl Send for Decoder {}

impl std::fmt::Debug for Decoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decoder")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl Decoder {
    /// Initialises the decoder (for `auto`, once four bytes are in). A raw
    /// chain whose `decoder_memusage` exceeds the limit is
    /// [`XzError::MemLimit`], as `coder_set_compression_settings` refuses
    /// it; `auto` with [`Format::Raw`] is [`XzError::Options`].
    pub fn new(o: &DecodeOptions) -> Result<Decoder, XzError> {
        let mut d = Decoder {
            strm: Strm::new(),
            opts: o.clone(),
            raw: None,
            state: DState::Sniffing,
            sniff: Vec::new(),
            allow_trailing: o.single_stream,
            warnings: VecDeque::new(),
        };
        if o.auto {
            if o.format == Format::Raw {
                return Err(XzError::Options);
            }
        } else {
            d.init(Some(o.format))?;
        }
        Ok(d)
    }

    /// `coder_init`'s initialiser for `format` (`None`: `lzma_auto_decoder`).
    fn init(&mut self, format: Option<Format>) -> Result<(), XzError> {
        let limit = limit_of(self.opts.memlimit);
        let mut flags = if self.opts.ignore_check {
            ffi::LZMA_IGNORE_CHECK
        } else {
            ffi::LZMA_TELL_UNSUPPORTED_CHECK
        };
        if !self.opts.single_stream {
            flags |= ffi::LZMA_CONCATENATED;
        }
        if format == Some(Format::Raw) {
            let chain = CChain::new(&self.opts.raw_filters);
            // SAFETY: a terminated chain whose options outlive the call.
            let needed = unsafe { ffi::lzma_raw_decoder_memusage(chain.as_ptr()) };
            if needed == u64::MAX {
                self.state = DState::Failed;
                return Err(XzError::Options);
            }
            if needed > limit {
                self.state = DState::Failed;
                return Err(XzError::MemLimit { needed, limit });
            }
            self.raw = Some(chain);
        }
        if format == Some(Format::Lzip) {
            self.allow_trailing = true;
        }
        let s = self.strm.raw();
        // SAFETY: each initialiser gets an `LZMA_STREAM_INIT` stream; the
        // raw chain lives in `self.raw` for the stream's lifetime.
        let ret = unsafe {
            match format {
                None => ffi::lzma_auto_decoder(s, limit, flags),
                Some(Format::Xz) => {
                    let threads = self.opts.threads.max(1);
                    let mut m = mt_options();
                    m.flags = flags;
                    m.threads = threads;
                    m.memlimit_stop = limit;
                    m.memlimit_threading = if threads == 1 {
                        0
                    } else {
                        self.opts.memlimit_threading
                    };
                    ffi::lzma_stream_decoder_mt(s, &raw const m)
                }
                Some(Format::Lzma) => ffi::lzma_alone_decoder(s, limit),
                Some(Format::Lzip) => ffi::lzma_lzip_decoder(s, limit, flags),
                Some(Format::Raw) => {
                    let chain = self.raw.as_ref().expect("built above");
                    ffi::lzma_raw_decoder(s, chain.as_ptr())
                }
            }
        };
        if ret != ffi::LZMA_OK {
            self.state = DState::Failed;
            return Err(self.strm.error(ret));
        }
        self.state = DState::Running;
        Ok(())
    }

    /// `auto` with the first bytes in: `.lz` by its magic, anything else
    /// `lzma_auto_decoder`. Returns the held bytes.
    fn init_auto(&mut self) -> Result<Vec<u8>, XzError> {
        let format = self.sniff.starts_with(LZIP_MAGIC).then_some(Format::Lzip);
        self.init(format)?;
        Ok(std::mem::take(&mut self.sniff))
    }

    /// Decompresses `input`, appending the output to `out`.
    pub fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), XzError> {
        if self.state != DState::Sniffing {
            return self.code(input, ffi::LZMA_RUN, out);
        }
        self.sniff.extend_from_slice(input);
        if self.sniff.len() < LZIP_MAGIC.len() {
            return Ok(());
        }
        let held = self.init_auto()?;
        self.code(&held, ffi::LZMA_RUN, out)
    }

    /// `coder_init`'s header probe: one `lzma_code(LZMA_RUN)` over `input`
    /// with no output room (`next_out = NULL, avail_out = 0`), repeated
    /// while it says `LZMA_UNSUPPORTED_CHECK` (each a warning, as
    /// `take_unsupported_check_warning` hands them out). `LZMA_STREAM_END`
    /// is success and the stream stays open, so the next call returns it
    /// again, as `coder_normal`'s does. Returns the bytes consumed; what is
    /// left is the caller's to `feed`. Any other return ends the decoder.
    /// On a decoder still sniffing (`auto`) it is [`XzError::Prog`].
    pub fn probe(&mut self, input: &[u8]) -> (usize, Result<(), XzError>) {
        if self.state != DState::Running {
            return (0, Err(XzError::Prog));
        }
        let mut used = 0;
        loop {
            let (n, ret) = self.strm.code_no_room(&input[used..], ffi::LZMA_RUN);
            used += n;
            match ret {
                ffi::LZMA_UNSUPPORTED_CHECK => self.warnings.push_back(self.strm.check()),
                ffi::LZMA_OK | ffi::LZMA_STREAM_END => return (used, Ok(())),
                ret => {
                    self.state = DState::Failed;
                    return (used, Err(self.strm.error(ret)));
                }
            }
        }
    }

    /// `LZMA_FINISH`: the input is over. A stream cut short is
    /// [`XzError::BufError`].
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), XzError> {
        let held = if self.state == DState::Sniffing {
            self.init_auto()?
        } else {
            Vec::new()
        };
        self.code(&held, ffi::LZMA_FINISH, out)
    }

    /// `lzma_code(action)` over all of `input`, reading each return code
    /// as `coder_normal` does.
    fn code(
        &mut self,
        mut input: &[u8],
        action: ffi::lzma_action,
        out: &mut Vec<u8>,
    ) -> Result<(), XzError> {
        match self.state {
            DState::Failed | DState::Sniffing => return Err(XzError::Prog),
            DState::Ended => {
                // Input after the end: corrupt, unless trailing data may
                // follow.
                if !input.is_empty() && !self.allow_trailing {
                    self.state = DState::Failed;
                    return Err(XzError::Data);
                }
                return Ok(());
            }
            DState::Running => {}
        }
        loop {
            let (used, ret, full) = self.strm.code_once(input, action, out);
            input = &input[used..];
            match ret {
                ffi::LZMA_OK => {
                    if action == ffi::LZMA_RUN && input.is_empty() && !full {
                        return Ok(());
                    }
                }
                ffi::LZMA_UNSUPPORTED_CHECK => self.warnings.push_back(self.strm.check()),
                ffi::LZMA_STREAM_END => {
                    if !input.is_empty() && !self.allow_trailing {
                        self.state = DState::Failed;
                        return Err(XzError::Data);
                    }
                    self.state = DState::Ended;
                    return Ok(());
                }
                ret => {
                    self.state = DState::Failed;
                    return Err(self.strm.error(ret));
                }
            }
        }
    }

    /// Bytes in and out so far (`lzma_get_progress`).
    pub fn progress(&self) -> Progress {
        self.strm.progress()
    }

    /// Whether the stream has ended (`LZMA_STREAM_END`): any input fed
    /// after it is left unconsumed, or refused. [`Decoder::progress`] is no
    /// substitute while a threaded `.xz` decoder's workers lag behind.
    pub fn finished(&self) -> bool {
        self.state == DState::Ended
    }

    /// The check ID of the oldest `LZMA_UNSUPPORTED_CHECK` not yet taken —
    /// a warning in `xz`, once per stream that has one.
    pub fn take_unsupported_check_warning(&mut self) -> Option<u32> {
        self.warnings.pop_front()
    }
}

/// `lzma_lzma_preset` itself, to pin [`Lzma::preset`] against.
#[cfg(test)]
pub(super) fn lzma_preset_of_liblzma(level: u32, extreme: bool) -> Option<Lzma> {
    let mut o = options_lzma(&Lzma::preset(0, false).expect("0 ≤ 9"), None);
    let preset = level | if extreme { 1 << 31 } else { 0 };
    // SAFETY: a valid options struct for liblzma to fill.
    if unsafe { ffi::lzma_lzma_preset(&raw mut o, preset) } != 0 {
        return None;
    }
    let mode = match o.mode {
        1 => Mode::Fast,
        _ => Mode::Normal,
    };
    let mf = match o.mf {
        0x03 => MatchFinder::Hc3,
        0x04 => MatchFinder::Hc4,
        0x12 => MatchFinder::Bt2,
        0x13 => MatchFinder::Bt3,
        _ => MatchFinder::Bt4,
    };
    Some(Lzma {
        dict_size: o.dict_size,
        lc: o.lc,
        lp: o.lp,
        pb: o.pb,
        mode,
        nice_len: o.nice_len,
        mf,
        depth: o.depth,
        preset_dict: (!o.preset_dict.is_null()).then(Vec::new),
    })
}

/// UNSAFE-4 (2026-10-31 audit): `ffi`'s structs are written by hand from
/// liblzma 5.8.4's `api/lzma/*.h`. `liblzma-sys` (the crate that builds the
/// linked `liblzma.a`) declares its own — a second, independent
/// transcription — so their sizes, alignments and the offsets of the fields
/// both name publicly must agree. `liblzma-sys` declares no
/// `lzma_options_delta`, so that one is checked against `delta.h` directly.
#[cfg(test)]
mod layout_tests {
    use std::ffi::c_void;
    use std::mem::{align_of, offset_of, size_of};

    use super::ffi;
    use liblzma_sys as sys;

    macro_rules! same_layout {
        ($ours:ty, $theirs:ty, [$($field:ident),* $(,)?]) => {{
            assert_eq!(size_of::<$ours>(), size_of::<$theirs>(), "size of {}", stringify!($ours));
            assert_eq!(align_of::<$ours>(), align_of::<$theirs>(), "align of {}", stringify!($ours));
            $(
                assert_eq!(
                    offset_of!($ours, $field),
                    offset_of!($theirs, $field),
                    "{}.{}",
                    stringify!($ours),
                    stringify!($field)
                );
            )*
        }};
    }

    #[test]
    fn the_linked_liblzma_is_the_one_the_declarations_were_written_for() {
        // SAFETY: lzma_version_number takes no arguments and returns a constant.
        // 5.8.4 is 50080042 (major·10^7 + minor·10^4 + patch·10 + stable 2).
        assert_eq!(unsafe { sys::lzma_version_number() }, 50_080_042);
    }

    #[test]
    fn the_hand_declared_structs_match_liblzma_sys() {
        same_layout!(
            ffi::lzma_stream,
            sys::lzma_stream,
            [
                next_in, avail_in, total_in, next_out, avail_out, total_out, allocator
            ]
        );
        same_layout!(ffi::lzma_filter, sys::lzma_filter, [id, options]);
        same_layout!(
            ffi::lzma_options_lzma,
            sys::lzma_options_lzma,
            [
                dict_size,
                preset_dict,
                preset_dict_size,
                lc,
                lp,
                pb,
                mode,
                nice_len,
                mf,
                depth
            ]
        );
        same_layout!(
            ffi::lzma_mt,
            sys::lzma_mt,
            [
                flags,
                threads,
                block_size,
                timeout,
                preset,
                filters,
                check,
                memlimit_threading,
                memlimit_stop,
            ]
        );
        same_layout!(ffi::lzma_options_bcj, sys::lzma_options_bcj, [start_offset]);
    }

    #[test]
    fn lzma_options_delta_matches_delta_h() {
        // `lzma_options_delta` (5.8.4 `api/lzma/delta.h`): an enum `type`,
        // `uint32_t dist`, four reserved `uint32_t`s, two reserved pointers.
        let ptr = size_of::<*mut c_void>();
        assert_eq!(offset_of!(ffi::lzma_options_delta, dist), 4);
        assert_eq!(offset_of!(ffi::lzma_options_delta, reserved_ptr1), 24);
        assert_eq!(size_of::<ffi::lzma_options_delta>(), 24 + 2 * ptr);
        assert_eq!(
            align_of::<ffi::lzma_options_delta>(),
            align_of::<*mut c_void>()
        );
    }
}
