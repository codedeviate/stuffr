//! libzstd 1.5.7's default compression parameters: the
//! `ZSTD_defaultCParameters` table from `lib/compress/clevels.h`, ported
//! verbatim, and `ZSTD_getCParams` with the parts of
//! `ZSTD_adjustCParams_internal` it reaches (`lib/compress/zstd_compress.c`,
//! mode `ZSTD_cpm_unknown`, row match finder `ZSTD_ps_auto`, a 64-bit
//! target, no `ZSTD_EXCLUDE_*` strategy). Both tiers use it, for
//! `--show-default-cparams`; the C tier's tests hold it to libzstd's own.
//!
//! Copyright (c) Meta Platforms, Inc. and affiliates. All rights reserved.
//! BSD-3-Clause (zstd's BSD licence); see `LICENSE-zstd-clevels`.

use super::{CParams, MIN_CLEVEL, Strategy, WINDOWLOG_ABSOLUTEMIN, WINDOWLOG_MAX};
use Strategy::*;

const fn cp(w: u32, c: u32, h: u32, s: u32, l: u32, tl: u32, strategy: Strategy) -> CParams {
    CParams {
        window_log: w,
        chain_log: c,
        hash_log: h,
        search_log: s,
        min_match: l,
        target_length: tl,
        strategy,
    }
}

/// `ZSTD_MAX_CLEVEL`.
const MAX_CLEVEL: usize = 22;

/// `ZSTD_defaultCParameters[4][ZSTD_MAX_CLEVEL + 1]`.
#[rustfmt::skip]
static DEFAULT_CPARAMETERS: [[CParams; MAX_CLEVEL + 1]; 4] = [
[   // "default" - for any srcSize > 256 KB
    //  W,  C,  H,  S,  L, TL, strat
    cp(19, 12, 13,  1,  6,  1, Fast    ),  // base for negative levels
    cp(19, 13, 14,  1,  7,  0, Fast    ),  // level  1
    cp(20, 15, 16,  1,  6,  0, Fast    ),  // level  2
    cp(21, 16, 17,  1,  5,  0, Dfast   ),  // level  3
    cp(21, 18, 18,  1,  5,  0, Dfast   ),  // level  4
    cp(21, 18, 19,  3,  5,  2, Greedy  ),  // level  5
    cp(21, 18, 19,  3,  5,  4, Lazy    ),  // level  6
    cp(21, 19, 20,  4,  5,  8, Lazy    ),  // level  7
    cp(21, 19, 20,  4,  5, 16, Lazy2   ),  // level  8
    cp(22, 20, 21,  4,  5, 16, Lazy2   ),  // level  9
    cp(22, 21, 22,  5,  5, 16, Lazy2   ),  // level 10
    cp(22, 21, 22,  6,  5, 16, Lazy2   ),  // level 11
    cp(22, 22, 23,  6,  5, 32, Lazy2   ),  // level 12
    cp(22, 22, 22,  4,  5, 32, Btlazy2 ),  // level 13
    cp(22, 22, 23,  5,  5, 32, Btlazy2 ),  // level 14
    cp(22, 23, 23,  6,  5, 32, Btlazy2 ),  // level 15
    cp(22, 22, 22,  5,  5, 48, Btopt   ),  // level 16
    cp(23, 23, 22,  5,  4, 64, Btopt   ),  // level 17
    cp(23, 23, 22,  6,  3, 64, Btultra ),  // level 18
    cp(23, 24, 22,  7,  3,256, Btultra2),  // level 19
    cp(25, 25, 23,  7,  3,256, Btultra2),  // level 20
    cp(26, 26, 24,  7,  3,512, Btultra2),  // level 21
    cp(27, 27, 25,  9,  3,999, Btultra2),  // level 22
],
[   // for srcSize <= 256 KB
    //  W,  C,  H,  S,  L,  T, strat
    cp(18, 12, 13,  1,  5,  1, Fast    ),  // base for negative levels
    cp(18, 13, 14,  1,  6,  0, Fast    ),  // level  1
    cp(18, 14, 14,  1,  5,  0, Dfast   ),  // level  2
    cp(18, 16, 16,  1,  4,  0, Dfast   ),  // level  3
    cp(18, 16, 17,  3,  5,  2, Greedy  ),  // level  4.
    cp(18, 17, 18,  5,  5,  2, Greedy  ),  // level  5.
    cp(18, 18, 19,  3,  5,  4, Lazy    ),  // level  6.
    cp(18, 18, 19,  4,  4,  4, Lazy    ),  // level  7
    cp(18, 18, 19,  4,  4,  8, Lazy2   ),  // level  8
    cp(18, 18, 19,  5,  4,  8, Lazy2   ),  // level  9
    cp(18, 18, 19,  6,  4,  8, Lazy2   ),  // level 10
    cp(18, 18, 19,  5,  4, 12, Btlazy2 ),  // level 11.
    cp(18, 19, 19,  7,  4, 12, Btlazy2 ),  // level 12.
    cp(18, 18, 19,  4,  4, 16, Btopt   ),  // level 13
    cp(18, 18, 19,  4,  3, 32, Btopt   ),  // level 14.
    cp(18, 18, 19,  6,  3,128, Btopt   ),  // level 15.
    cp(18, 19, 19,  6,  3,128, Btultra ),  // level 16.
    cp(18, 19, 19,  8,  3,256, Btultra ),  // level 17.
    cp(18, 19, 19,  6,  3,128, Btultra2),  // level 18.
    cp(18, 19, 19,  8,  3,256, Btultra2),  // level 19.
    cp(18, 19, 19, 10,  3,512, Btultra2),  // level 20.
    cp(18, 19, 19, 12,  3,512, Btultra2),  // level 21.
    cp(18, 19, 19, 13,  3,999, Btultra2),  // level 22.
],
[   // for srcSize <= 128 KB
    //  W,  C,  H,  S,  L,  T, strat
    cp(17, 12, 12,  1,  5,  1, Fast    ),  // base for negative levels
    cp(17, 12, 13,  1,  6,  0, Fast    ),  // level  1
    cp(17, 13, 15,  1,  5,  0, Fast    ),  // level  2
    cp(17, 15, 16,  2,  5,  0, Dfast   ),  // level  3
    cp(17, 17, 17,  2,  4,  0, Dfast   ),  // level  4
    cp(17, 16, 17,  3,  4,  2, Greedy  ),  // level  5
    cp(17, 16, 17,  3,  4,  4, Lazy    ),  // level  6
    cp(17, 16, 17,  3,  4,  8, Lazy2   ),  // level  7
    cp(17, 16, 17,  4,  4,  8, Lazy2   ),  // level  8
    cp(17, 16, 17,  5,  4,  8, Lazy2   ),  // level  9
    cp(17, 16, 17,  6,  4,  8, Lazy2   ),  // level 10
    cp(17, 17, 17,  5,  4,  8, Btlazy2 ),  // level 11
    cp(17, 18, 17,  7,  4, 12, Btlazy2 ),  // level 12
    cp(17, 18, 17,  3,  4, 12, Btopt   ),  // level 13.
    cp(17, 18, 17,  4,  3, 32, Btopt   ),  // level 14.
    cp(17, 18, 17,  6,  3,256, Btopt   ),  // level 15.
    cp(17, 18, 17,  6,  3,128, Btultra ),  // level 16.
    cp(17, 18, 17,  8,  3,256, Btultra ),  // level 17.
    cp(17, 18, 17, 10,  3,512, Btultra ),  // level 18.
    cp(17, 18, 17,  5,  3,256, Btultra2),  // level 19.
    cp(17, 18, 17,  7,  3,512, Btultra2),  // level 20.
    cp(17, 18, 17,  9,  3,512, Btultra2),  // level 21.
    cp(17, 18, 17, 11,  3,999, Btultra2),  // level 22.
],
[   // for srcSize <= 16 KB
    //  W,  C,  H,  S,  L,  T, strat
    cp(14, 12, 13,  1,  5,  1, Fast    ),  // base for negative levels
    cp(14, 14, 15,  1,  5,  0, Fast    ),  // level  1
    cp(14, 14, 15,  1,  4,  0, Fast    ),  // level  2
    cp(14, 14, 15,  2,  4,  0, Dfast   ),  // level  3
    cp(14, 14, 14,  4,  4,  2, Greedy  ),  // level  4
    cp(14, 14, 14,  3,  4,  4, Lazy    ),  // level  5.
    cp(14, 14, 14,  4,  4,  8, Lazy2   ),  // level  6
    cp(14, 14, 14,  6,  4,  8, Lazy2   ),  // level  7
    cp(14, 14, 14,  8,  4,  8, Lazy2   ),  // level  8.
    cp(14, 15, 14,  5,  4,  8, Btlazy2 ),  // level  9.
    cp(14, 15, 14,  9,  4,  8, Btlazy2 ),  // level 10.
    cp(14, 15, 14,  3,  4, 12, Btopt   ),  // level 11.
    cp(14, 15, 14,  4,  3, 24, Btopt   ),  // level 12.
    cp(14, 15, 14,  5,  3, 32, Btultra ),  // level 13.
    cp(14, 15, 15,  6,  3, 64, Btultra ),  // level 14.
    cp(14, 15, 15,  7,  3,256, Btultra ),  // level 15.
    cp(14, 15, 15,  5,  3, 48, Btultra2),  // level 16.
    cp(14, 15, 15,  6,  3,128, Btultra2),  // level 17.
    cp(14, 15, 15,  7,  3,256, Btultra2),  // level 18.
    cp(14, 15, 15,  8,  3,256, Btultra2),  // level 19.
    cp(14, 15, 15,  8,  3,512, Btultra2),  // level 20.
    cp(14, 15, 15,  9,  3,512, Btultra2),  // level 21.
    cp(14, 15, 15, 10,  3,999, Btultra2),  // level 22.
],
];

/// `ZSTD_CONTENTSIZE_UNKNOWN`.
const UNKNOWN: u64 = u64::MAX;
/// `ZSTD_HASHLOG_MIN`.
const HASHLOG_MIN: u32 = 6;
/// `ZSTD_ROW_HASH_TAG_BITS`.
const ROW_HASH_TAG_BITS: u32 = 8;

/// `ZSTD_highbit32`, for a non-zero `v`.
fn highbit32(v: u32) -> u32 {
    31 - v.leading_zeros()
}

/// `ZSTD_getCParams(level, src_size_hint, dict_size)`.
pub(super) fn get_cparams(level: i32, src_size_hint: u64, dict_size: u64) -> CParams {
    let src_size = if src_size_hint == 0 {
        UNKNOWN
    } else {
        src_size_hint
    };
    // ZSTD_getCParamRowSize, mode ZSTD_cpm_unknown.
    let r_size = if src_size == UNKNOWN && dict_size == 0 {
        UNKNOWN
    } else {
        let added = if src_size == UNKNOWN && dict_size > 0 {
            500
        } else {
            0
        };
        src_size.wrapping_add(dict_size).wrapping_add(added)
    };
    let table = usize::from(r_size <= 256 << 10)
        + usize::from(r_size <= 128 << 10)
        + usize::from(r_size <= 16 << 10);
    let row = if level == 0 {
        super::CLEVEL_DEFAULT as usize
    } else if level < 0 {
        0
    } else {
        (level as usize).min(MAX_CLEVEL)
    };
    let mut c = DEFAULT_CPARAMETERS[table][row];
    if level < 0 {
        c.target_length = level.max(MIN_CLEVEL).unsigned_abs();
    }
    adjust(c, src_size, dict_size)
}

/// `ZSTD_dictAndWindowLog`. The sums are C's `U64` arithmetic, which
/// wraps: the zstd CLI passes a dictionary file of unknown size as
/// `UTIL_FILESIZE_UNKNOWN` (`u64::MAX`) to `--show-default-cparams`.
fn dict_and_window_log(window_log: u32, src_size: u64, dict_size: u64) -> u32 {
    if dict_size == 0 {
        return window_log;
    }
    let window_size = 1u64 << window_log;
    let dict_and_window = dict_size.wrapping_add(window_size);
    if window_size >= dict_size.wrapping_add(src_size) {
        window_log
    } else if dict_and_window >= 1u64 << WINDOWLOG_MAX {
        WINDOWLOG_MAX
    } else {
        highbit32((dict_and_window as u32).wrapping_sub(1)) + 1
    }
}

/// `ZSTD_adjustCParams_internal`, mode `ZSTD_cpm_unknown`, row match
/// finder `ZSTD_ps_auto`.
fn adjust(mut c: CParams, src_size: u64, dict_size: u64) -> CParams {
    let max_window_resize = 1u64 << (WINDOWLOG_MAX - 1);
    if src_size <= max_window_resize && dict_size <= max_window_resize {
        let t_size = (src_size + dict_size) as u32;
        let hash_size_min = 1u32 << HASHLOG_MIN;
        let src_log = if t_size < hash_size_min {
            HASHLOG_MIN
        } else {
            highbit32(t_size - 1) + 1
        };
        if c.window_log > src_log {
            c.window_log = src_log;
        }
    }
    if src_size != UNKNOWN {
        let dict_and_window = dict_and_window_log(c.window_log, src_size, dict_size);
        let cycle_log = c.chain_log - u32::from(c.strategy >= Btlazy2);
        if c.hash_log > dict_and_window + 1 {
            c.hash_log = dict_and_window + 1;
        }
        if cycle_log > dict_and_window {
            c.chain_log -= cycle_log - dict_and_window;
        }
    }
    if c.window_log < WINDOWLOG_ABSOLUTEMIN {
        c.window_log = WINDOWLOG_ABSOLUTEMIN;
    }
    // `ZSTD_ps_auto` is assumed enabled here; the row match finder serves
    // greedy, lazy and lazy2.
    if (Greedy..=Lazy2).contains(&c.strategy) {
        let row_log = c.search_log.clamp(4, 6);
        let max_hash_log = 32 - ROW_HASH_TAG_BITS + row_log;
        if c.hash_log > max_hash_log {
            c.hash_log = max_hash_log;
        }
    }
    c
}
