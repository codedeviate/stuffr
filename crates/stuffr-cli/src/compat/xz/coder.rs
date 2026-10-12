//! `coder.c`: the coder's settings (`coder_set_compression_settings`), the
//! input's format (`coder_init`'s detection) and the compress, decompress
//! and test loop over one input (`coder_run`, `coder_normal`,
//! `coder_passthru`), from XZ Utils 5.8.4 (0BSD, `LICENSE-xz`). The bytes
//! come from `stuffr::xz_opts`, which takes exactly what `coder.c` hands
//! liblzma; files are `file_io.rs`'s.
//!
//! **Memory figures** are the reference build's (Ruling P5): every
//! decision `coder_set_compression_settings` makes against a limit (fewer
//! threads, single-threaded, a smaller dictionary, a refusal) and every
//! figure it prints uses `Profile::Reference`, on both tiers, so the bytes
//! depend only on what xz's would. The encoder is then built with no limit
//! of its own.
//!
//! **The header probe.** `coder_init` decodes the headers before the output
//! is opened (`lzma_code` with no output room), so an unknown format, an
//! unsupported check (a warning), or a first Block over the memory limit is
//! said before any output exists, and `-f` has removed nothing. Here the
//! first chunk is fed a byte at a time until the decoder makes its first
//! byte of output; an error before then is the probe's. The difference: a
//! corrupt LZMA2 chunk header or range-coder start before the first byte of
//! output, which xz finds only once the output is open, is said before it
//! is opened, so with `-f` an existing output survives and without it the
//! corruption is said rather than "File exists".
//!
//! **Feeding.** The xz_opts coders append all their output per call, so
//! input goes in at most [`DECODE_PIECE`] bytes at a time when decoding
//! (bounding what one call can expand to) and in [`IO_BUFFER_SIZE`]
//! chunks when encoding. Output reaches `file_io` in `IO_BUFFER_SIZE`
//! chunks, as `coder_write_output` passes it, so sparse output is judged
//! on the same chunks as xz's.

use std::io::Write;
use std::panic::{AssertUnwindSafe, catch_unwind};

use stuffr::xz_opts::memusage::{MEMUSAGE_BASE, lzma_decoder_memusage_nocheck, mt_block_size};
use stuffr::xz_opts::{
    Check, DecodeOptions, Decoder, EncodeOptions, Encoder, Filter, Format, Lzma, Profile, XzError,
    decoder_memusage_with, encoder_memusage_with,
};

use super::args::{Args, CoderSettings, FormatChoice, OpMode};
use super::file_io::{FilePair, IO_BUFFER_SIZE};
use super::hardware::round_up_to_mib;
use super::message::{self, Messages, Verbosity, mask_nonprint};
use super::messages as m;
use crate::compat::host::Host;

/// `NUM_FILTER_CHAIN_MAX`: the default chain and `--filters1..9`.
const CHAINS: usize = 10;

/// The most input one decoder call is given.
const DECODE_PIECE: usize = 512;

/// The used chains of `c` (`chains_used_mask`).
fn used(c: &CoderSettings) -> impl Iterator<Item = usize> + '_ {
    (0..CHAINS).filter(|i| c.chains_used_mask & (1 << i) != 0)
}

/// Chain `i` of `c`: the default one or a `--filtersN` one.
fn chain_of(c: &CoderSettings, i: usize) -> &[Filter] {
    if i == 0 {
        &c.chain
    } else {
        c.chains[i].as_deref().unwrap_or(&[])
    }
}

fn chain_mut(c: &mut CoderSettings, i: usize) -> &mut Vec<Filter> {
    if i == 0 {
        &mut c.chain
    } else {
        c.chains[i].get_or_insert_with(Vec::new)
    }
}

fn is_lzma(f: &Filter) -> bool {
    matches!(f, Filter::Lzma1(_) | Filter::Lzma1Ext(_) | Filter::Lzma2(_))
}

/// An LZMA filter's dictionary size ([`is_lzma`] filters only).
fn dict_size(f: &mut Filter) -> &mut u32 {
    match f {
        Filter::Lzma1(l) | Filter::Lzma1Ext(l) | Filter::Lzma2(l) => &mut l.dict_size,
        _ => unreachable!("only LZMA filters have a dictionary"),
    }
}

/// One chain's encoder memusage, the reference build's: the threaded
/// encoder's with `mt` = (threads, block size), else the raw encoder's.
fn chain_memusage(chain: &[Filter], mt: Option<(u32, u64)>) -> Option<u64> {
    let o = match mt {
        Some((threads, block_size)) => EncodeOptions {
            format: Format::Xz,
            filters: chain.to_vec(),
            threads,
            block_size,
            ..EncodeOptions::default()
        },
        None => EncodeOptions {
            format: Format::Raw,
            filters: chain.to_vec(),
            ..EncodeOptions::default()
        },
    };
    encoder_memusage_with(Profile::Reference, &o)
}

/// coder.c: get_chains_memusage (encoding): each used chain's figure into
/// `usages`, and the largest; `None` (`UINT64_MAX`) when any is invalid.
fn chains_memusage(
    c: &CoderSettings,
    usages: &mut [Option<u64>; CHAINS],
    mt: Option<(u32, u64)>,
) -> Option<u64> {
    let mut max = Some(0);
    for i in used(c) {
        let u = chain_memusage(chain_of(c, i), mt);
        usages[i] = u;
        max = max.zip(u).map(|(a, b)| a.max(b));
    }
    max
}

fn num(n: u64) -> Vec<u8> {
    n.to_string().into_bytes()
}

/// coder.c: memlimit_too_small: said, and the run ends with exit 1.
fn memlimit_too_small(limits_memlimit: u64, usage: u64, msg: &Messages, err: &mut dyn Write) -> u8 {
    msg.message(err, Verbosity::Error, m::MEMLIMIT_TOO_LOW, &[]);
    msg.mem_needed(err, Verbosity::Error, usage, limits_memlimit);
    message::Status::Error as u8
}

/// coder.c: coder_set_compression_settings, called by args_parse when
/// compressing and when decoding raw data: the default check, the chains
/// in use, the preset as a chain, the format's chain rules,
/// `--flush-timeout`'s, and the memory usage against the limit (fewer
/// threads, then single-threaded, then smaller dictionaries, or a
/// refusal). `Err` is the exit code once the refusal is said.
pub(crate) fn set_compression_settings(
    a: &mut Args,
    msg: &Messages,
    err: &mut dyn Write,
) -> Result<(), u8> {
    let (op, format) = (a.op, a.format);
    let c = &mut a.coder;
    // CRC64 is the default; this build always supports it.
    if c.check.is_none() {
        c.check = Some(Check::Crc64);
    }
    if c.block_list.is_some() {
        let missing = (c.block_list_chain_mask ^ c.chains_used_mask) & c.block_list_chain_mask;
        if missing != 0 {
            let n = num(u64::from(missing.trailing_zeros()));
            return Err(msg.fatal(err, m::CHAIN_NOT_SPECIFIED, &[&n, &n]));
        }
        c.chains_used_mask &= c.block_list_chain_mask;
    } else {
        c.chains_used_mask = 1;
    }
    if c.chain.is_empty() && c.chains_used_mask & 1 != 0 {
        if format == FormatChoice::Raw {
            msg.message(err, Verbosity::Warning, m::RAW_PRESET, &[]);
            msg.message(err, Verbosity::Warning, m::RAW_PRESET_VARIES, &[]);
        }
        let Some(opt) = Lzma::preset(c.preset, c.extreme) else {
            return Err(msg.fatal(err, m::BUG, &[]));
        };
        c.chain = vec![if format == FormatChoice::Lzma {
            Filter::Lzma1(opt)
        } else {
            Filter::Lzma2(opt)
        }];
    }
    if format == FormatChoice::Lzma
        && !(c.chain.len() == 1 && matches!(c.chain[0], Filter::Lzma1(_)))
    {
        return Err(msg.fatal(err, m::LZMA_NEEDS_LZMA1, &[]));
    }
    if format == FormatChoice::Xz
        && c.chains_used_mask & 1 != 0
        && c.chain.iter().any(|f| matches!(f, Filter::Lzma1(_)))
    {
        return Err(msg.fatal(err, m::LZMA1_NOT_IN_XZ, &[]));
    }
    if c.chains_used_mask & 1 != 0 {
        msg.filters_show(err, Verbosity::Debug, &c.chain);
    }
    if op == OpMode::Compress && c.flush_timeout != 0 {
        for i in used(c).collect::<Vec<_>>() {
            let ok = chain_of(c, i)
                .iter()
                .all(|f| matches!(f, Filter::Lzma2(_) | Filter::Delta { .. }));
            if !ok {
                return Err(msg.fatal(err, m::FLUSH_INCOMPATIBLE, &[&num(i as u64)]));
            }
        }
        if c.limits.threads_is_mt() {
            msg.message(err, Verbosity::Warning, m::FLUSH_SINGLE_THREADED, &[]);
            c.limits.threads_set(1);
        }
    }

    let mut memory_limit = c.limits.memlimit_get(op);
    let mut usages = [None; CHAINS];
    let mut mt = None;
    let memory_usage = if op == OpMode::Compress {
        if format == FormatChoice::Xz && c.limits.threads_is_mt() {
            memory_limit = c.limits.memlimit_mtenc_get();
            let threads = c.limits.threads_get();
            let mut block_size = c.block_size;
            if block_size == 0 {
                for i in used(c) {
                    match mt_block_size(chain_of(c, i)) {
                        Some(size) => block_size = block_size.max(size),
                        None => {
                            return Err(msg.fatal(err, m::UNSUPPORTED_CHAIN_N, &[&num(i as u64)]));
                        }
                    }
                }
                if c.block_list_largest > 0 && block_size > c.block_list_largest {
                    block_size = c.block_list_largest;
                }
            }
            mt = Some((threads, block_size));
            let usage = chains_memusage(c, &mut usages, mt);
            if usage.is_some() {
                msg.message(
                    err,
                    Verbosity::Debug,
                    m::USING_THREADS,
                    &[&num(threads.into())],
                );
            }
            usage
        } else {
            chains_memusage(c, &mut usages, None)
        }
    } else {
        decoder_memusage_with(Profile::Reference, &c.chain)
    };
    let Some(mut memory_usage) = memory_usage else {
        return Err(msg.fatal(err, m::UNSUPPORTED_CHAIN, &[]));
    };
    let shown_limit = c.limits.memlimit_get(op);
    msg.mem_needed(err, Verbosity::Debug, memory_usage, shown_limit);
    if op == OpMode::Compress && msg.verbosity >= Verbosity::Debug {
        let decmem = used(c).try_fold(0u64, |max, i| {
            decoder_memusage_with(Profile::Reference, chain_of(c, i)).map(|u| max.max(u))
        });
        if let Some(d) = decmem {
            msg.message(
                err,
                Verbosity::Debug,
                m::DECOMPRESSION_NEEDS,
                &[&num(round_up_to_mib(d))],
            );
        }
    }
    c.mt_threads = mt.map_or(0, |(threads, _)| threads);
    if memory_usage <= memory_limit {
        return Ok(());
    }
    if format == FormatChoice::Raw {
        return Err(memlimit_too_small(shown_limit, memory_usage, msg, err));
    }

    if let Some((threads, block_size)) = mt {
        // Fewer threads first: the output does not change.
        let mut t = threads;
        while t > 1 {
            t -= 1;
            memory_usage = chains_memusage(c, &mut usages, Some((t, block_size)))
                .ok_or_else(|| msg.fatal(err, m::BUG, &[]))?;
            if memory_usage <= memory_limit {
                msg.message(
                    err,
                    Verbosity::Debug,
                    m::REDUCED_THREADS,
                    &[
                        &num(threads.into()),
                        &num(t.into()),
                        &num(round_up_to_mib(memory_limit)),
                    ],
                );
                c.mt_threads = t;
                return Ok(());
            }
        }
        c.mt_threads = t;
        // The automatic limit only lowers the thread count; at one thread
        // it is ignored, so -T0 never fails and never changes the output.
        if c.limits.memlimit_mtenc_is_default() {
            msg.message(
                err,
                Verbosity::Debug,
                m::REDUCED_TO_ONE,
                &[
                    &num(threads.into()),
                    &num(round_up_to_mib(memory_limit)),
                    &num(round_up_to_mib(memory_usage)),
                ],
            );
            return Ok(());
        }
        // Single-threaded output differs, which --no-adjust forbids.
        if !c.auto_adjust {
            return Err(memlimit_too_small(shown_limit, memory_usage, msg, err));
        }
        c.limits.threads_set(1);
        c.mt_threads = 0;
        memory_usage =
            chains_memusage(c, &mut usages, None).ok_or_else(|| msg.fatal(err, m::BUG, &[]))?;
        msg.message(
            err,
            Verbosity::Warning,
            m::SINGLE_THREADED_FOR_LIMIT,
            &[&num(round_up_to_mib(memory_limit))],
        );
    }
    if memory_usage <= memory_limit {
        return Ok(());
    }
    if !c.auto_adjust {
        return Err(memlimit_too_small(shown_limit, memory_usage, msg, err));
    }

    // A smaller dictionary for each chain over the limit, a MiB at a time.
    for i in used(c).collect::<Vec<_>>() {
        let usage = usages[i].unwrap_or(u64::MAX);
        if usage <= memory_limit {
            continue;
        }
        let chain = chain_mut(c, i);
        let Some(j) = chain.iter().position(is_lzma) else {
            return Err(memlimit_too_small(shown_limit, usage, msg, err));
        };
        let lzma_num: &[u8] = if matches!(chain[j], Filter::Lzma2(_)) {
            b"2"
        } else {
            b"1"
        };
        let orig = *dict_size(&mut chain[j]);
        *dict_size(&mut chain[j]) &= !((1u32 << 20) - 1);
        let mut usage = usage;
        loop {
            if *dict_size(&mut chain[j]) < 1 << 20 {
                return Err(memlimit_too_small(shown_limit, usage, msg, err));
            }
            usage = chain_memusage(chain, None).ok_or_else(|| msg.fatal(err, m::BUG, &[]))?;
            if usage <= memory_limit {
                break;
            }
            *dict_size(&mut chain[j]) -= 1 << 20;
        }
        usages[i] = Some(usage);
        let from = num(u64::from(orig >> 20));
        let to = num(u64::from(*dict_size(&mut chain[j]) >> 20));
        let limit = num(round_up_to_mib(memory_limit));
        if i == 0 {
            msg.message(
                err,
                Verbosity::Warning,
                m::ADJUSTED_DICT,
                &[lzma_num, &from, &to, &limit],
            );
        } else {
            let n = num(i as u64);
            msg.message(
                err,
                Verbosity::Warning,
                m::ADJUSTED_DICT_N,
                &[lzma_num, &n, &from, &to, &limit],
            );
        }
    }
    Ok(())
}

// ---- detection ----

/// coder.c: is_format_xz: the six-byte magic.
fn is_format_xz(b: &[u8]) -> bool {
    b.starts_with(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00])
}

/// coder.c: is_format_lzip: `LZIP`.
fn is_format_lzip(b: &[u8]) -> bool {
    b.starts_with(b"LZIP")
}

/// coder.c: is_format_lzma: a 13-byte header whose LZMA1 properties decode
/// (lzma_lzma_lclppb_decode), whose dictionary is 2^n, 2^n + 2^(n-1) or
/// `UINT32_MAX`, and whose uncompressed size, if known, is under 256 GiB.
fn is_format_lzma(b: &[u8]) -> bool {
    if b.len() < 13 {
        return false;
    }
    let mut byte = u32::from(b[0]);
    if byte > (4 * 5 + 4) * 9 + 8 {
        return false;
    }
    let pb = byte / (9 * 5);
    byte -= pb * 9 * 5;
    let lp = byte / 9;
    let lc = byte - lp * 9;
    if lc + lp > 4 {
        return false;
    }
    let dict_size = u32::from_le_bytes([b[1], b[2], b[3], b[4]]);
    if dict_size != u32::MAX {
        let mut d = dict_size.wrapping_sub(1);
        d |= d >> 2;
        d |= d >> 3;
        d |= d >> 4;
        d |= d >> 8;
        d |= d >> 16;
        d = d.wrapping_add(1);
        if d != dict_size || dict_size == 0 {
            return false;
        }
    }
    let size = u64::from_le_bytes(b[5..13].try_into().expect("8 bytes"));
    size == u64::MAX || size <= 1 << 38
}

// ---- running a file ----

/// What `coder_init` set up.
enum Coder {
    Encode(Box<Encoder>),
    /// A decoder, the bytes of the first chunk the header probe fed it,
    /// the output it made doing so, and an error that came with output
    /// (the normal loop's to say, once the output is written).
    Decode {
        dec: Box<Decoder>,
        fed: usize,
        out: Vec<u8>,
        pending: Result<(), XzError>,
        allow_trailing: bool,
    },
    /// `-dcf` on input of no known format: copied as it is.
    Passthru,
}

/// What `lzma_memusage` reported as the reference build would: the
/// decoders' figures past `LZMA_MEMUSAGE_BASE` hold one LZ dictionary,
/// whose bookkeeping (`LZ_DICT_EXTRA`) is the one thing the two builds
/// count differently (Ruling P5).
fn needed_by_reference(needed: u64) -> u64 {
    if needed <= MEMUSAGE_BASE {
        return needed;
    }
    let extra = lzma_decoder_memusage_nocheck(Profile::Reference, 0)
        - lzma_decoder_memusage_nocheck(Profile::LiblzmaSys, 0);
    needed + extra
}

/// coder.c's `message_error("%s: %s", src_name, message_strm(ret))`, with
/// the memory needed after a memory-limit refusal.
fn report(a: &Args, pair: &FilePair, e: &XzError, msg: &mut Messages, err: &mut dyn Write) {
    msg.error(
        err,
        m::NAME_COLON,
        &[&mask_nonprint(&pair.src_name), &message::strm(e)],
    );
    if let XzError::MemLimit { needed, .. } = e {
        let limit = a.coder.limits.memlimit_get(a.op);
        msg.mem_needed(err, Verbosity::Error, needed_by_reference(*needed), limit);
    }
}

/// The unsupported-check warnings the decoder has collected, in order.
fn warn_checks(dec: &mut Decoder, pair: &FilePair, msg: &mut Messages, err: &mut dyn Write) {
    while dec.take_unsupported_check_warning().is_some() {
        msg.warning(
            err,
            m::NAME_COLON,
            &[
                &mask_nonprint(&pair.src_name),
                m::STRM_UNSUPPORTED_CHECK.as_bytes(),
            ],
        );
    }
}

/// What `std::thread::spawn` panics with when the system refuses a thread
/// (`expect("failed to spawn thread")`).
const SPAWN_FAILED: &str = "failed to spawn thread";

/// Whether a panic's payload is [`SPAWN_FAILED`]'s.
fn is_spawn_failure(payload: &(dyn std::any::Any + Send)) -> bool {
    payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .is_some_and(|s| s.starts_with(SPAWN_FAILED))
}

/// A panic hook, as `std::panic::take_hook` returns it.
type PanicHook = Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Send + Sync>;

/// One panic hook swap at a time: the hook is the process's.
static HOOK_SWAP: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Ruling P10, for the real process's threaded encoder: while the guard
/// lives, a panic hook is in place that swallows only a refused thread's
/// panic (the pure tier's thread pool, `std::thread::spawn`) and hands
/// every other panic to the hook it replaced. It is put in once for a run
/// of encoder calls and the replaced hook itself is put back once, on every
/// path. Inactive (a sandbox, or no threads), it does nothing at all.
struct SpawnGuard {
    /// The hook in force before, while ours is installed.
    prev: Option<std::sync::Arc<PanicHook>>,
    /// Held while our hook is in place: one swap at a time.
    lock: Option<std::sync::MutexGuard<'static, ()>>,
    /// A refused thread's panic was caught: the encoder is in no known
    /// state, so it is leaked rather than dropped.
    panicked: bool,
}

impl SpawnGuard {
    fn new(active: bool) -> SpawnGuard {
        let mut g = SpawnGuard {
            prev: None,
            lock: None,
            panicked: false,
        };
        if active {
            g.lock = Some(HOOK_SWAP.lock().unwrap_or_else(|p| p.into_inner()));
            let prev = std::sync::Arc::new(std::panic::take_hook());
            let to_prev = prev.clone();
            std::panic::set_hook(Box::new(move |info| {
                if !is_spawn_failure(info.payload()) {
                    to_prev(info);
                }
            }));
            g.prev = Some(prev);
        }
        g
    }

    /// One encoder call. A refused thread's panic becomes liblzma's
    /// `LZMA_MEM_ERROR` (what a refused `pthread_create` gives on the C
    /// tier); any other panic is re-raised, the replaced hook back first.
    fn call<T>(&mut self, f: impl FnOnce() -> Result<T, XzError>) -> Result<T, XzError> {
        if self.prev.is_none() {
            return f();
        }
        match catch_unwind(AssertUnwindSafe(f)) {
            Ok(v) => v,
            Err(p) if is_spawn_failure(&*p) => {
                self.panicked = true;
                Err(XzError::Mem { needed: 0 })
            }
            Err(p) => {
                self.restore();
                std::panic::resume_unwind(p)
            }
        }
    }

    /// Put the replaced hook itself back, and let the next swap in.
    fn restore(&mut self) {
        if let Some(prev) = self.prev.take() {
            // Ours holds the other reference; once it is gone the original
            // box is ours again.
            drop(std::panic::take_hook());
            match std::sync::Arc::try_unwrap(prev) {
                Ok(hook) => std::panic::set_hook(hook),
                Err(shared) => std::panic::set_hook(Box::new(move |info| shared(info))),
            }
        }
        self.lock = None;
    }
}

impl Drop for SpawnGuard {
    fn drop(&mut self) {
        // `call` restores before re-raising; the hook cannot be set from a
        // panicking thread.
        if !std::thread::panicking() {
            self.restore();
        }
    }
}

/// The options `coder_init` builds the encoder from.
fn encode_options(a: &Args) -> EncodeOptions {
    let c = &a.coder;
    let format = match a.format {
        FormatChoice::Lzma => Format::Lzma,
        FormatChoice::Raw => Format::Raw,
        _ => Format::Xz,
    };
    let xz = format == Format::Xz;
    // The default chain is always set; it stays empty only when the block
    // list never uses it, and then any valid chain will do.
    let filters = if c.chain.is_empty() {
        vec![Filter::Lzma2(
            Lzma::preset(6, false).expect("6 is a preset"),
        )]
    } else {
        c.chain.clone()
    };
    let block_list = match (&c.block_list, xz) {
        (Some(list), true) => list
            .iter()
            .map(|e| {
                let chain = (e.chain != 0).then(|| chain_of(c, usize::from(e.chain)).to_vec());
                (e.size, chain)
            })
            .collect(),
        _ => Vec::new(),
    };
    EncodeOptions {
        format,
        filters,
        check: c.check.unwrap_or(Check::Crc64),
        threads: if xz && c.limits.threads_is_mt() {
            c.mt_threads
        } else {
            0
        },
        block_size: c.block_size,
        block_list,
        flush_timeout_ms: c.flush_timeout,
        memlimit: u64::MAX,
    }
}

/// coder.c: coder_init: the encoder, or the input's format and its
/// decoder with the headers decoded. `None` once the failure is said.
fn init(
    a: &Args,
    real: bool,
    pair: &FilePair,
    first: &[u8],
    msg: &mut Messages,
    err: &mut dyn Write,
) -> Option<Coder> {
    if a.op == OpMode::Compress {
        let o = encode_options(a);
        let mut guard = SpawnGuard::new(real && o.threads > 0);
        return match guard.call(|| Encoder::new(&o)) {
            Ok(e) => Some(Coder::Encode(Box::new(e))),
            Err(e) => {
                report(a, pair, &e, msg, err);
                None
            }
        };
    }
    let format = match a.format {
        FormatChoice::Auto if is_format_xz(first) => Some(Format::Xz),
        FormatChoice::Auto if is_format_lzip(first) => Some(Format::Lzip),
        FormatChoice::Auto if is_format_lzma(first) => Some(Format::Lzma),
        FormatChoice::Auto => None,
        FormatChoice::Xz => is_format_xz(first).then_some(Format::Xz),
        FormatChoice::Lzma => is_format_lzma(first).then_some(Format::Lzma),
        FormatChoice::Lzip => is_format_lzip(first).then_some(Format::Lzip),
        FormatChoice::Raw => Some(Format::Raw),
    };
    let Some(format) = format else {
        if a.op == OpMode::Decompress && a.to_stdout && a.force {
            return Some(Coder::Passthru);
        }
        report(a, pair, &XzError::Format, msg, err);
        return None;
    };
    let l = &a.coder.limits;
    let threads = l.threads_get();
    let o = DecodeOptions {
        format,
        auto: false,
        raw_filters: if format == Format::Raw {
            a.coder.chain.clone()
        } else {
            Vec::new()
        },
        memlimit: l.memlimit_get(OpMode::Decompress),
        single_stream: a.single_stream,
        ignore_check: a.ignore_check,
        threads,
        memlimit_threading: if threads == 1 {
            0
        } else {
            l.memlimit_mtdec_get()
        },
    };
    let mut dec = match Decoder::new(&o) {
        Ok(d) => Box::new(d),
        Err(e) => {
            report(a, pair, &e, msg, err);
            return None;
        }
    };
    let mut out = Vec::new();
    let mut fed = 0;
    let mut pending = Ok(());
    if format != Format::Raw {
        // The header probe: up to the first byte of output (or the end of
        // a stream with none).
        while fed < first.len() && out.is_empty() && !dec.finished() {
            let r = dec.feed(&first[fed..=fed], &mut out);
            fed += 1;
            warn_checks(&mut dec, pair, msg, err);
            if let Err(e) = r {
                // With output made, the error is coder_normal's.
                if out.is_empty() {
                    report(a, pair, &e, msg, err);
                    return None;
                }
                pending = Err(e);
            }
        }
    }
    Some(Coder::Decode {
        dec,
        fed,
        out,
        pending,
        allow_trailing: a.single_stream || format == Format::Lzip,
    })
}

/// coder.c: coder_run for one input, `name` (`None`: standard input).
pub(crate) fn run(
    a: &Args,
    name: Option<&[u8]>,
    host: &mut Host,
    msg: &mut Messages,
    err: &mut dyn Write,
) {
    let Some(mut pair) = FilePair::open_src(a, name, host, msg, err) else {
        return;
    };
    let real = matches!(host, Host::Real);
    let mut success = false;
    let mut first = vec![0u8; IO_BUFFER_SIZE];
    let read = if a.op == OpMode::Compress {
        Some(0)
    } else {
        pair.read(&mut first, msg, err)
    };
    if let Some(n) = read {
        first.truncate(n);
        if let Some(coder) = init(a, real, &pair, &first, msg, err)
            && (a.op == OpMode::Test || pair.open_dest(a, host, msg, err))
        {
            success = match coder {
                Coder::Encode(mut enc) => {
                    let mut guard = SpawnGuard::new(real && encode_options(a).threads > 0);
                    let ok = encode(a, &mut pair, &mut enc, &mut guard, msg, err);
                    let panicked = guard.panicked;
                    drop(guard);
                    if panicked {
                        std::mem::forget(enc);
                    }
                    ok
                }
                Coder::Decode {
                    mut dec,
                    fed,
                    out,
                    pending,
                    allow_trailing,
                } => {
                    let mut d = Decoding {
                        a,
                        host,
                        stage: Vec::with_capacity(IO_BUFFER_SIZE),
                        read: first.len() as u64,
                        allow_trailing,
                    };
                    d.run(&mut pair, &mut dec, &first[fed..], (out, pending), msg, err)
                }
                Coder::Passthru => passthru(&mut pair, first, msg, err),
            };
        }
    }
    pair.close(a, success, msg, err);
}

/// coder.c: coder_normal compressing: read, encode, write; flush when
/// `--flush-timeout` expires, finish at the end of the input.
fn encode(
    a: &Args,
    pair: &mut FilePair,
    enc: &mut Encoder,
    guard: &mut SpawnGuard,
    msg: &mut Messages,
    err: &mut dyn Write,
) -> bool {
    let mut buf = vec![0u8; IO_BUFFER_SIZE];
    let mut out = Vec::new();
    loop {
        let Some(n) = pair.read(&mut buf, msg, err) else {
            return false;
        };
        let mut r = guard.call(|| enc.feed(&buf[..n], &mut out));
        let end = pair.src_eof;
        if r.is_ok() && end {
            r = guard.call(|| enc.finish(&mut out));
        } else if r.is_ok() && pair.flush_needed {
            r = guard.call(|| enc.flush(&mut out));
            pair.src_has_seen_input = false;
            pair.flush_needed = false;
        }
        // The output so far is written even when something went wrong.
        let written = pair.write(&out, msg, err);
        out.clear();
        if !written {
            return false;
        }
        if let Err(e) = r {
            report(a, pair, &e, msg, err);
            return false;
        }
        if end {
            return true;
        }
    }
}

/// coder.c: coder_passthru: the first chunk and the rest of the input,
/// as they are, to standard output.
fn passthru(
    pair: &mut FilePair,
    mut buf: Vec<u8>,
    msg: &mut Messages,
    err: &mut dyn Write,
) -> bool {
    let mut n = buf.len();
    buf.resize(IO_BUFFER_SIZE, 0);
    while n != 0 {
        if !pair.write(&buf[..n], msg, err) {
            return false;
        }
        match pair.read(&mut buf, msg, err) {
            Some(k) => n = k,
            None => return false,
        }
    }
    true
}

/// coder.c: coder_normal decompressing or testing.
struct Decoding<'a> {
    a: &'a Args,
    host: &'a Host,
    /// `out_buf`: output not yet written, less than [`IO_BUFFER_SIZE`].
    stage: Vec<u8>,
    /// Bytes read from the input so far.
    read: u64,
    /// `allow_trailing_input`: `--single-stream`, or `.lz`.
    allow_trailing: bool,
}

impl Decoding<'_> {
    /// coder.c: coder_write_output for each full buffer of `out`, which
    /// is then empty; under `-t` nothing is written.
    fn emit(
        &mut self,
        pair: &mut FilePair,
        out: &mut Vec<u8>,
        msg: &mut Messages,
        err: &mut dyn Write,
    ) -> bool {
        self.stage.append(out);
        let full = self.stage.len() - self.stage.len() % IO_BUFFER_SIZE;
        let ok = self.write(pair, full, msg, err);
        self.stage.drain(..full);
        ok
    }

    /// The first `n` staged bytes, in [`IO_BUFFER_SIZE`] chunks.
    fn write(
        &mut self,
        pair: &mut FilePair,
        n: usize,
        msg: &mut Messages,
        err: &mut dyn Write,
    ) -> bool {
        if self.a.op == OpMode::Test {
            // Decoded bytes go nowhere; a sandbox still counts them.
            return match self.host.charge(n as u64) {
                Ok(()) => true,
                Err(e) => {
                    pair.write_failed(&e, msg, err);
                    false
                }
            };
        }
        self.stage[..n]
            .chunks(IO_BUFFER_SIZE)
            .all(|chunk| pair.write(chunk, msg, err))
    }

    /// The staged rest: what coder_write_output writes when coding stops.
    fn flush(&mut self, pair: &mut FilePair, msg: &mut Messages, err: &mut dyn Write) -> bool {
        let n = self.stage.len();
        let ok = self.write(pair, n, msg, err);
        self.stage.clear();
        ok
    }

    /// After a decoder call: its warnings, its output, and its verdict
    /// (said, with the output written first). `Some(success)` when coding
    /// stops.
    fn step(
        &mut self,
        pair: &mut FilePair,
        dec: &mut Decoder,
        r: Result<(), XzError>,
        out: &mut Vec<u8>,
        msg: &mut Messages,
        err: &mut dyn Write,
    ) -> Option<bool> {
        warn_checks(dec, pair, msg, err);
        if !self.emit(pair, out, msg, err) {
            return Some(false);
        }
        if let Err(e) = r {
            if self.flush(pair, msg, err) {
                report(self.a, pair, &e, msg, err);
            }
            return Some(false);
        }
        None
    }

    /// Whether the stream has ended where input may follow it, unread
    /// (`allow_trailing_input`); otherwise the decoder refuses what follows.
    fn ended(&self, dec: &Decoder) -> bool {
        self.allow_trailing && dec.finished()
    }

    /// coder_normal's loop: the probe's output and verdict, the rest of the
    /// first chunk, then a chunk at a time until the input ends, then
    /// `LZMA_FINISH`.
    fn run(
        &mut self,
        pair: &mut FilePair,
        dec: &mut Decoder,
        rest_of_first: &[u8],
        (mut out, pending): (Vec<u8>, Result<(), XzError>),
        msg: &mut Messages,
        err: &mut dyn Write,
    ) -> bool {
        // The probe's output, and its error if it had one.
        if let Some(ok) = self.step(pair, dec, pending, &mut out, msg, err) {
            return ok;
        }
        if self.ended(dec) {
            return self.done(pair, dec, msg, err);
        }
        let mut chunk = rest_of_first.to_vec();
        let mut buf = vec![0u8; IO_BUFFER_SIZE];
        loop {
            for piece in chunk.chunks(DECODE_PIECE) {
                let r = dec.feed(piece, &mut out);
                if let Some(ok) = self.step(pair, dec, r, &mut out, msg, err) {
                    return ok;
                }
                if self.ended(dec) {
                    return self.done(pair, dec, msg, err);
                }
            }
            if pair.src_eof {
                break;
            }
            let Some(n) = pair.read(&mut buf, msg, err) else {
                return false;
            };
            self.read += n as u64;
            chunk.clear();
            chunk.extend_from_slice(&buf[..n]);
        }
        let r = dec.finish(&mut out);
        if let Some(ok) = self.step(pair, dec, r, &mut out, msg, err) {
            return ok;
        }
        self.done(pair, dec, msg, err)
    }

    /// The stream is over: hand back what was read past it (io_fix_src_pos)
    /// and write the rest.
    fn done(
        &mut self,
        pair: &mut FilePair,
        dec: &Decoder,
        msg: &mut Messages,
        err: &mut dyn Write,
    ) -> bool {
        if self.allow_trailing {
            pair.fix_src_pos(self.read.saturating_sub(dec.progress().in_bytes));
        }
        self.flush(pair, msg, err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lzma_detection_follows_is_format_lzma() {
        let header = |props: u8, dict: u32, size: u64| {
            let mut h = vec![props];
            h.extend_from_slice(&dict.to_le_bytes());
            h.extend_from_slice(&size.to_le_bytes());
            h
        };
        assert!(is_format_lzma(&header(0x5d, 1 << 23, u64::MAX)));
        assert!(is_format_lzma(&header(0x5d, 3 << 22, 1000)));
        assert!(is_format_lzma(&header(0x5d, u32::MAX, 1 << 38)));
        assert!(!is_format_lzma(&header(0x5d, (1 << 23) + 1, u64::MAX)));
        assert!(!is_format_lzma(&header(0x5d, 0, u64::MAX)));
        assert!(!is_format_lzma(&header(225, 1 << 23, u64::MAX)));
        // lc 4 + lp 1.
        assert!(!is_format_lzma(&header(13, 1 << 23, u64::MAX)));
        assert!(!is_format_lzma(&header(0x5d, 1 << 23, (1 << 38) + 1)));
        assert!(!is_format_lzma(&header(0x5d, 1 << 23, 5)[..12]));
    }

    /// The address of a hook, to tell the original from a wrapper.
    fn hook_addr(h: &PanicHook) -> *const () {
        let r: &(dyn Fn(&std::panic::PanicHookInfo<'_>) + Send + Sync) = &**h;
        (r as *const (dyn Fn(&std::panic::PanicHookInfo<'_>) + Send + Sync)).cast::<()>()
    }

    /// Ruling P10: a refused thread's panic becomes `LZMA_MEM_ERROR`
    /// without reaching the previous hook; any other panic reaches it and
    /// goes on; inactive, nothing is caught. Every guard puts the very hook
    /// it replaced back, however many calls it made, so hooks never nest.
    /// The test's own hook counts only payloads carrying its marker.
    #[test]
    fn only_a_refused_thread_is_swallowed() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SEEN: AtomicUsize = AtomicUsize::new(0);
        const MARK: &str = "xz-guard-test";
        let spawn =
            || -> Result<(), XzError> { std::panic::panic_any(format!("{SPAWN_FAILED}: {MARK}")) };
        let other = || -> Result<(), XzError> { std::panic::panic_any(format!("bug: {MARK}")) };
        let lock = HOOK_SWAP.lock().unwrap_or_else(|p| p.into_inner());
        let outer = std::panic::take_hook();
        // Not zero-sized, so its box has an address of its own.
        let mark = MARK.to_owned();
        let mine: PanicHook = Box::new(move |info| {
            let p = info.payload();
            if p.downcast_ref::<String>()
                .is_some_and(|s| s.contains(&mark))
            {
                SEEN.fetch_add(1, Ordering::SeqCst);
            }
        });
        let addr = hook_addr(&mine);
        std::panic::set_hook(mine);
        drop(lock);
        let current = || {
            let _lock = HOOK_SWAP.lock().unwrap_or_else(|p| p.into_inner());
            let h = std::panic::take_hook();
            let a = hook_addr(&h);
            std::panic::set_hook(h);
            a
        };

        let mut g = SpawnGuard::new(true);
        assert!(matches!(g.call(spawn), Err(XzError::Mem { needed: 0 })));
        assert!(g.panicked);
        for _ in 0..1000 {
            g.call(|| Ok(())).unwrap();
        }
        drop(g);
        assert_eq!(
            SEEN.load(Ordering::SeqCst),
            0,
            "the spawn panic reached the hook"
        );
        assert_eq!(current(), addr, "the replaced hook was not put back");

        for _ in 0..1000 {
            SpawnGuard::new(true).call(|| Ok(())).unwrap();
        }
        assert_eq!(current(), addr, "hooks nest across guards");

        let caught = catch_unwind(AssertUnwindSafe(|| {
            let mut g = SpawnGuard::new(true);
            g.call(other)
        }));
        let payload = caught.expect_err("another panic was swallowed");
        assert_eq!(
            payload.downcast_ref::<String>().unwrap(),
            &format!("bug: {MARK}")
        );
        assert_eq!(
            SEEN.load(Ordering::SeqCst),
            1,
            "another panic missed the hook"
        );
        assert_eq!(current(), addr, "a re-raise left the guard's hook");

        let caught = catch_unwind(AssertUnwindSafe(|| SpawnGuard::new(false).call(spawn)));
        assert!(caught.is_err(), "an inactive guard caught a panic");
        assert_eq!(SEEN.load(Ordering::SeqCst), 2);

        let _lock = HOOK_SWAP.lock().unwrap_or_else(|p| p.into_inner());
        drop(std::panic::take_hook());
        std::panic::set_hook(outer);
    }

    #[test]
    fn the_reference_build_counts_its_dictionary_bookkeeping() {
        assert_eq!(needed_by_reference(MEMUSAGE_BASE), MEMUSAGE_BASE);
        let extra = lzma_decoder_memusage_nocheck(Profile::Reference, 0)
            - lzma_decoder_memusage_nocheck(Profile::LiblzmaSys, 0);
        assert_eq!(needed_by_reference(70 << 20), (70 << 20) + extra);
    }
}
