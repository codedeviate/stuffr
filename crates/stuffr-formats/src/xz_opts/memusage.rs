//! liblzma 5.8.4's memory-usage formulas, ported: the figures `xz` prints
//! ("N MiB of memory is required", `--list`'s memory column, `-vv`) and the
//! limits it enforces come from these.
//!
//! Every function names the C function it ports. Two builds of liblzma
//! disagree by a few bytes, so every figure is for a [`Profile`]:
//!
//! - [`Profile::LiblzmaSys`] is the liblzma `liblzma-sys` 0.4.9 compiles
//!   into this build: `memusage_formulas_match_liblzma` pins it against
//!   `c::` in every `--all-features` run. The unsuffixed
//!   [`decoder_memusage`]/[`encoder_memusage`] are this profile, and the
//!   pure tier's `MemLimit.needed` too, so the two tiers report alike.
//! - [`Profile::Reference`] is `xz` 5.8.4 built by its own `configure` on
//!   the host target — the binary the compatibility promise is made
//!   against. What the CLI prints comes from this one.
//!
//! What differs between them (`liblzma-sys`'s `config.h` against
//! `configure`'s):
//!
//! - `LZ_DICT_EXTRA` (`lz/lz_decoder.h`): 32 bytes when
//!   `LZMA_LZ_DECODER_CONFIG` is 2, which needs
//!   `TUKLIB_FAST_UNALIGNED_ACCESS`, `HAVE_IMMINTRIN_H` and SSE2 — what
//!   `configure` finds on x86 and x86-64 and `liblzma-sys` never defines.
//!   0 otherwise.
//! - `mythread_cond` (`common/mythread.h`) carries a `clockid_t clk_id`
//!   when `HAVE_CLOCK_GETTIME` is defined: by `configure` on Linux and
//!   macOS, by `liblzma-sys` only on Solaris. The threaded encoder's
//!   `lzma_stream_coder` and each `worker_thread` hold one, so its figure
//!   moves by `8 * (threads + 1)` (the 4-byte field padded to the struct's
//!   8-byte alignment).
//!
//! The struct sizes themselves are per target. Each was measured (macOS
//! arm64) as the residual of the C function against the formula without
//! it, and the threaded encoder's two are split into what does not depend
//! on the platform's thread types plus `pthread_mutex_t` and
//! `pthread_cond_t` (or Windows' `CRITICAL_SECTION` and
//! `CONDITION_VARIABLE`), whose sizes are the platform ABI's: see
//! [`MUTEX`] and [`COND`].
//!
//! XZ Utils 5.8.4 (`src/liblzma/`), 0BSD: see `LICENSE-xz-memusage`.

use super::{EncodeOptions, Filter, Format, Lzma, MatchFinder};

/// `LZMA_MEMUSAGE_BASE` (`common/common.h`).
pub const MEMUSAGE_BASE: u64 = 1 << 15;

/// `LZMA_THREADS_MAX` (`common/common.h`).
const THREADS_MAX: u32 = 16384;

/// `LZMA_VLI_MAX` (`api/lzma/vli.h`).
const VLI_MAX: u64 = u64::MAX / 2;

/// `MATCH_LEN_MIN`/`MATCH_LEN_MAX` (`lzma/lzma_common.h`).
const MATCH_LEN_MIN: u32 = 2;
const MATCH_LEN_MAX: u32 = 273;

/// `OPTS` (`lzma/lzma_encoder_private.h`) and `LOOP_INPUT_MAX`
/// (`lzma/lzma_encoder.c`).
const OPTS: u32 = 1 << 12;
const LOOP_INPUT_MAX: u32 = OPTS + 1;

/// `HASH_2_SIZE`/`HASH_3_SIZE` (`lz/lz_encoder_hash.h`).
const HASH_2_SIZE: u32 = 1 << 10;
const HASH_3_SIZE: u32 = 1 << 16;

/// `LZ_DICT_REPEAT_MAX` (`lz/lz_decoder.h`).
const LZ_DICT_REPEAT_MAX: u64 = 288;

/// `sizeof(lzma_lzma1_decoder) + sizeof(lzma_coder)` of `lz_decoder.c`.
const LZMA1_DECODER_STRUCTS: u64 = 32_640;
/// `sizeof(lzma_lzma2_coder)` of `lzma2_decoder.c`.
const LZMA2_DECODER_STRUCT: u64 = 184;
/// `sizeof(lzma_delta_coder)` (`delta/delta_private.h`).
const DELTA_CODER_STRUCT: u64 = 352;
/// `sizeof(lzma_lzma1_encoder) + sizeof(lzma_coder)` of `lz_encoder.c`.
const LZMA1_ENCODER_STRUCTS: u64 = 249_792;
/// `sizeof(lzma_lzma2_coder)` of `lzma2_encoder.c`.
const LZMA2_ENCODER_STRUCT: u64 = 65_704;
/// `sizeof(lzma_stream_coder)` of `stream_encoder_mt.c` less its
/// `mythread_mutex` and `mythread_cond`: 584 measured on macOS arm64,
/// less 64 + 48.
const MT_STREAM_CODER_REST: u64 = 472;
/// `sizeof(worker_thread)` of `stream_encoder_mt.c` plus the two
/// `sizeof(lzma_outbuf)` its output queue keeps per thread
/// (`GET_BUFS_LIMIT`), less the worker's `mythread_mutex` and
/// `mythread_cond`: 688 measured on macOS arm64, less 64 + 48.
const MT_PER_THREAD_REST: u64 = 576;

/// `sizeof(pthread_mutex_t)`, `mythread_mutex` on POSIX: 64 on macOS, 40
/// on glibc and musl x86-64, 48 on glibc aarch64; Windows'
/// `CRITICAL_SECTION` is 40. Other targets are taken as 40, unverified.
#[cfg(target_vendor = "apple")]
pub const MUTEX: u64 = 64;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub const MUTEX: u64 = 48;
#[cfg(not(any(
    target_vendor = "apple",
    all(target_os = "linux", target_arch = "aarch64")
)))]
pub const MUTEX: u64 = 40;

/// `sizeof(pthread_cond_t)`: 48 on macOS and glibc (x86-64 and aarch64)
/// alike; Windows' `CONDITION_VARIABLE` is 8.
#[cfg(windows)]
pub const COND: u64 = 8;
#[cfg(not(windows))]
pub const COND: u64 = 48;

/// Whose liblzma a figure is for (see the module doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// The liblzma `liblzma-sys` compiles into this build.
    LiblzmaSys,
    /// `xz` 5.8.4 built by its own `configure` on the host target.
    Reference,
}

impl Profile {
    /// `LZ_DICT_EXTRA`.
    fn lz_dict_extra(self) -> u64 {
        let config2 = cfg!(any(
            target_arch = "x86_64",
            all(target_arch = "x86", target_feature = "sse2")
        ));
        if self == Profile::Reference && config2 {
            32
        } else {
            0
        }
    }

    /// `sizeof(mythread_cond)`: the condition variable, with `clk_id`
    /// padded in where `HAVE_CLOCK_GETTIME` is defined.
    fn cond(self) -> u64 {
        let clock = cfg!(any(target_os = "linux", target_vendor = "apple"));
        if self == Profile::Reference && clock {
            COND + 8
        } else {
            COND
        }
    }

    fn mt_stream_coder(self) -> u64 {
        MT_STREAM_CODER_REST + MUTEX + self.cond()
    }

    fn mt_per_thread(self) -> u64 {
        MT_PER_THREAD_REST + MUTEX + self.cond()
    }
}

/// What a filter adds when it has no memusage function: 1 KiB
/// (`lzma_raw_coder_memusage`).
const NO_MEMUSAGE_FILTER: u64 = 1024;

/// `is_lclppb_valid` (`lzma/lzma_common.h`).
fn lclppb_valid(l: &Lzma) -> bool {
    l.lc <= 4 && l.lp <= 4 && l.lc + l.lp <= 4 && l.pb <= 4
}

/// `lzma_lz_decoder_memusage` (`lz/lz_decoder.c`) plus
/// `lzma_lzma_decoder_memusage_nocheck` (`lzma/lzma_decoder.c`): what
/// `.lzma` and `.lz` add `LZMA_MEMUSAGE_BASE` to for their `needed`.
pub fn lzma_decoder_memusage_nocheck(profile: Profile, dict_size: u32) -> u64 {
    LZMA1_DECODER_STRUCTS + u64::from(dict_size) + 2 * LZ_DICT_REPEAT_MAX + profile.lz_dict_extra()
}

/// The `match_finder` value liblzma gives each [`MatchFinder`].
fn mf_id(mf: MatchFinder) -> u32 {
    match mf {
        MatchFinder::Hc3 => 0x03,
        MatchFinder::Hc4 => 0x04,
        MatchFinder::Bt2 => 0x12,
        MatchFinder::Bt3 => 0x13,
        MatchFinder::Bt4 => 0x14,
    }
}

/// `IS_ENC_DICT_SIZE_VALID` (`lz/lz_encoder.h`).
fn enc_dict_size_valid(size: u32) -> bool {
    (4096..=(1 << 30) + (1 << 29)).contains(&size)
}

/// `lzma_lz_encoder_memusage` (`lz/lz_encoder.c`), through
/// `lz_encoder_prepare`'s size computation, for the `lzma_lz_options`
/// `set_lz_options` (`lzma/lzma_encoder.c`) builds.
fn lz_encoder_memusage(l: &Lzma) -> Option<u64> {
    let mf = mf_id(l.mf);
    let hash_bytes = mf & 0x0F;
    let nice_len = hash_bytes.max(l.nice_len);
    if !enc_dict_size_valid(l.dict_size) || nice_len > MATCH_LEN_MAX {
        return None;
    }
    let keep_size_before = OPTS + l.dict_size;
    let keep_size_after = LOOP_INPUT_MAX + MATCH_LEN_MAX;
    let mut reserve = l.dict_size / 2;
    if reserve > 1 << 30 {
        reserve /= 2;
    }
    reserve += (OPTS + MATCH_LEN_MAX + LOOP_INPUT_MAX) / 2 + (1 << 19);
    let size = keep_size_before + reserve + keep_size_after;
    let cyclic_size = l.dict_size + 1;
    let is_bt = mf & 0x10 != 0;
    let mut hs: u32;
    if hash_bytes == 2 {
        hs = 0xFFFF;
    } else {
        hs = l.dict_size - 1;
        hs |= hs >> 1;
        hs |= hs >> 2;
        hs |= hs >> 4;
        hs |= hs >> 8;
        hs >>= 1;
        hs |= 0xFFFF;
        if hs > 1 << 24 {
            if hash_bytes == 3 {
                hs = (1 << 24) - 1;
            } else {
                hs >>= 1;
            }
        }
    }
    hs += 1;
    if hash_bytes > 2 {
        hs += HASH_2_SIZE;
    }
    if hash_bytes > 3 {
        hs += HASH_3_SIZE;
    }
    let sons_count = if is_bt { cyclic_size * 2 } else { cyclic_size };
    Some((u64::from(hs) + u64::from(sons_count)) * 4 + u64::from(size))
}

/// `lzma_lzma_encoder_memusage` (`lzma/lzma_encoder.c`), with
/// `is_options_valid`.
fn lzma_encoder_memusage(l: &Lzma) -> Option<u64> {
    if !lclppb_valid(l) || !(MATCH_LEN_MIN..=MATCH_LEN_MAX).contains(&l.nice_len) {
        return None;
    }
    Some(LZMA1_ENCODER_STRUCTS + lz_encoder_memusage(l)?)
}

/// `lzma_validate_chain` (`common/filter_common.c`): 1..=4 filters, only
/// the last an LZ filter, which it must be.
pub(crate) fn chain_valid(filters: &[Filter]) -> bool {
    let Some((last, rest)) = filters.split_last() else {
        return false;
    };
    filters.len() <= 4 && is_lz(last) && !rest.iter().any(is_lz)
}

fn is_lz(f: &Filter) -> bool {
    matches!(f, Filter::Lzma1(_) | Filter::Lzma1Ext(_) | Filter::Lzma2(_))
}

/// `lzma_delta_coder_memusage` (`delta/delta_common.c`).
fn delta_memusage(dist: u32) -> Option<u64> {
    (1..=256).contains(&dist).then_some(DELTA_CODER_STRUCT)
}

/// `lzma_raw_decoder_memusage` (`common/filter_decoder.c`), through
/// `lzma_raw_coder_memusage` (`common/filter_common.c`) and the decoders'
/// memusage functions; `None` is liblzma's `UINT64_MAX`.
pub fn decoder_memusage(filters: &[Filter]) -> Option<u64> {
    decoder_memusage_with(Profile::LiblzmaSys, filters)
}

/// [`decoder_memusage`] for `profile`.
pub fn decoder_memusage_with(profile: Profile, filters: &[Filter]) -> Option<u64> {
    if !chain_valid(filters) {
        return None;
    }
    let mut total = 0u64;
    for f in filters {
        total += match f {
            // `lzma_lzma_decoder_memusage`.
            Filter::Lzma1(l) | Filter::Lzma1Ext(l) => {
                if !lclppb_valid(l) {
                    return None;
                }
                lzma_decoder_memusage_nocheck(profile, l.dict_size)
            }
            // `lzma_lzma2_decoder_memusage`: no validation at all.
            Filter::Lzma2(l) => {
                LZMA2_DECODER_STRUCT + lzma_decoder_memusage_nocheck(profile, l.dict_size)
            }
            Filter::Bcj { .. } => NO_MEMUSAGE_FILTER,
            Filter::Delta { dist } => delta_memusage(*dist)?,
        };
    }
    Some(total + MEMUSAGE_BASE)
}

/// `lzma_raw_encoder_memusage` (`common/filter_encoder.c`).
pub(crate) fn raw_encoder_memusage(filters: &[Filter]) -> Option<u64> {
    if !chain_valid(filters) {
        return None;
    }
    let mut total = 0u64;
    for f in filters {
        total += match f {
            Filter::Lzma1(l) | Filter::Lzma1Ext(l) => lzma_encoder_memusage(l)?,
            // `lzma_lzma2_encoder_memusage`.
            Filter::Lzma2(l) => LZMA2_ENCODER_STRUCT + lzma_encoder_memusage(l)?,
            Filter::Bcj { .. } => NO_MEMUSAGE_FILTER,
            Filter::Delta { dist } => delta_memusage(*dist)?,
        };
    }
    Some(total + MEMUSAGE_BASE)
}

/// `lzma_mt_block_size` (`common/filter_encoder.c`) with
/// `lzma_lzma2_block_size` (`lzma/lzma2_encoder.c`), the only filter that
/// has a block size; `None` is `UINT64_MAX`.
pub fn mt_block_size(filters: &[Filter]) -> Option<u64> {
    let mut max = 0;
    for f in filters {
        if let Filter::Lzma2(l) = f {
            if !enc_dict_size_valid(l.dict_size) {
                return None;
            }
            max = max.max((u64::from(l.dict_size) * 3).max(1 << 20));
        }
    }
    (max != 0).then_some(max)
}

/// `lzma_block_buffer_bound64` (`common/block_buffer_encoder.c`), with
/// `lzma2_bound`; `0` is overflow.
fn block_buffer_bound64(uncompressed_size: u64) -> u64 {
    // `COMPRESSED_SIZE_MAX` (`common/block_encoder.h`).
    const COMPRESSED_SIZE_MAX: u64 = (VLI_MAX - 1024 - 64) & !3;
    // `HEADERS_BOUND`: (1 + 1 + 2 * LZMA_VLI_BYTES_MAX + 3 + 4
    // + LZMA_CHECK_SIZE_MAX + 3) & ~3.
    const HEADERS_BOUND: u64 = (1 + 1 + 2 * 9 + 3 + 4 + 64 + 3) & !3;
    // `LZMA2_CHUNK_MAX`, `LZMA2_HEADER_UNCOMPRESSED`.
    const CHUNK_MAX: u64 = 1 << 16;
    const HEADER_UNCOMPRESSED: u64 = 3;
    if uncompressed_size > COMPRESSED_SIZE_MAX {
        return 0;
    }
    let overhead = uncompressed_size.div_ceil(CHUNK_MAX) * HEADER_UNCOMPRESSED + 1;
    if COMPRESSED_SIZE_MAX - overhead < uncompressed_size {
        return 0;
    }
    let lzma2_size = (uncompressed_size + overhead + 3) & !3;
    HEADERS_BOUND + lzma2_size
}

/// `lzma_stream_encoder_mt_memusage` (`common/stream_encoder_mt.c`), with
/// `get_options` and `lzma_outq_memusage` (`common/outqueue.c`), for an
/// `lzma_mt` of `threads`, `block_size` (`0`: the chain's
/// [`mt_block_size`]) and `filters`.
pub(crate) fn stream_encoder_mt_memusage(
    profile: Profile,
    threads: u32,
    block_size: u64,
    filters: &[Filter],
) -> Option<u64> {
    if threads == 0 || threads > THREADS_MAX {
        return None;
    }
    let block_size = if block_size > 0 {
        block_size
    } else {
        mt_block_size(filters)?
    };
    // `BLOCK_SIZE_MAX`.
    if block_size > u64::MAX / u64::from(THREADS_MAX) {
        return None;
    }
    let outbuf_size_max = block_buffer_bound64(block_size);
    if outbuf_size_max == 0 {
        return None;
    }
    let threads = u64::from(threads);
    let inbuf_memusage = threads * block_size;
    let filters_memusage = raw_encoder_memusage(filters)?.wrapping_mul(threads);
    // `lzma_outq_memusage`: GET_BUFS_LIMIT(threads) = 2 * threads buffers.
    let limit = u64::MAX / (2 * u64::from(THREADS_MAX)) / 2;
    if outbuf_size_max > limit {
        return None;
    }
    let outq_memusage = 2 * threads * outbuf_size_max;
    let total = MEMUSAGE_BASE + profile.mt_stream_coder() + threads * profile.mt_per_thread();
    total
        .checked_add(inbuf_memusage)?
        .checked_add(filters_memusage)?
        .checked_add(outq_memusage)
}

/// [`super::encoder_memusage`]: what `coder.c`'s
/// `coder_set_compression_settings` computes for `o` — the largest
/// memusage over the chains the block list uses, threaded or not, with
/// `lzma_mt.block_size` as it sets it.
pub fn encoder_memusage(o: &EncodeOptions) -> Option<u64> {
    encoder_memusage_with(Profile::LiblzmaSys, o)
}

/// [`encoder_memusage`] for `profile`.
pub fn encoder_memusage_with(profile: Profile, o: &EncodeOptions) -> Option<u64> {
    if o.format == Format::Lzip {
        return None;
    }
    let chains = used_chains(o);
    let threaded = o.format == Format::Xz && o.threads > 0;
    let block_size = if threaded {
        mt_block_size_for(o, &chains)?
    } else {
        0
    };
    let mut max = 0;
    for chain in chains {
        let usage = if threaded {
            stream_encoder_mt_memusage(profile, o.threads, block_size, chain)?
        } else {
            raw_encoder_memusage(chain)?
        };
        max = max.max(usage);
    }
    Some(max)
}

/// The chains `o` encodes with (`coder.c`'s `chains_used_mask`): the
/// default chain without a block list, else each distinct chain the list
/// names. The block list is `.xz`'s only.
pub(crate) fn used_chains(o: &EncodeOptions) -> Vec<&[Filter]> {
    if o.format != Format::Xz || o.block_list.is_empty() {
        return vec![&o.filters];
    }
    let mut used: Vec<&[Filter]> = Vec::new();
    for (_, chain) in &o.block_list {
        let chain = chain.as_deref().unwrap_or(&o.filters);
        if !used.contains(&chain) {
            used.push(chain);
        }
    }
    used
}

/// `lzma_mt.block_size` as `coder_set_compression_settings` sets it: the
/// option, or the largest [`mt_block_size`] of the used chains capped at
/// the block list's largest entry.
pub(crate) fn mt_block_size_for(o: &EncodeOptions, chains: &[&[Filter]]) -> Option<u64> {
    if o.block_size != 0 {
        return Some(o.block_size);
    }
    let mut size = 0;
    for chain in chains {
        size = size.max(mt_block_size(chain)?);
    }
    let largest = o.block_list.iter().map(|&(s, _)| s).max().unwrap_or(0);
    if largest > 0 && size > largest {
        size = largest;
    }
    Some(size)
}
