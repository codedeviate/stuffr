//! dibio.c: `--train`, `--train-cover`, `--train-fastcover` and
//! `--train-legacy`, as zstd 1.5.7 builds a dictionary from sample files.
//!
//! Ported in dibio.c's order: the sample names are shuffled with its fixed
//! seed (`DiB_shuffle`), measured (`DiB_fileStats`: one sample per file, or
//! `-B#` chunks of each), the amount to load is bounded (`DiB_findMaxMem`,
//! 2 GB, `-M#`), the refusals and warnings are printed, the samples are
//! loaded (`DiB_loadFiles`), and libzstd's trainer runs on them through
//! `stuffr::zstd_opts::train`; the dictionary is written by
//! `DiB_saveDict`. The trainer itself prints its own notifications (the
//! "Trying 5 different sets of parameters" line and the rest) on the C
//! library's standard error at the display level, as zstd's does, so a
//! real run's standard error is the reference's.
//!
//! Defined-but-odd behaviour kept: a sample that cannot be measured (a
//! missing file, a directory without `-r`) counts as a sample of size -1
//! in `DiB_fileStats`' totals and is then skipped when loading; dibio.c's
//! `EXM_THROW` prints `Error N : …` whatever the display level.
//!
//! `DiB_findMaxMem` probes `malloc` downwards from the estimate; this port
//! takes the estimate's first probe as granted, which is what the
//! reference sees whenever its first `malloc` succeeds.
//!
//! The pure tier (spec deviation 7) answers as a zstd built with
//! `ZSTD_NODICT`: `--train` prints `training mode not available`, exit 1,
//! and the other three options are not options there (`cli.rs`).
//!
//! In a sandbox (R9), at most 256 KiB of samples are loaded, the
//! optimiser runs at most 4 steps with at most 2 threads, and libzstd's
//! own notifications are off (standard error is captured there).

use std::fs::File;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

use stuffr::zstd_opts::{self, TrainAlgo, TrainParams};

use super::cli::{Command, DictType};
use super::display::Display;
use super::fileio::{Fio, Thrown};
use super::messages::{self as m, printf};
use super::util::{self, FILESIZE_UNKNOWN};
use crate::compat::host::{Host, strerror};

/// dibio.c: `SAMPLESIZE_MAX`.
const SAMPLESIZE_MAX: i64 = 128 << 10;
/// dibio.c: `MEMMULT` (legacy).
const MEMMULT: u64 = 11;
/// dibio.c: `COVER_MEMMULT`.
const COVER_MEMMULT: u64 = 9;
/// dibio.c: `FASTCOVER_MEMMULT`.
const FASTCOVER_MEMMULT: u64 = 1;
/// dibio.c: `g_maxMemory` on a 64-bit target, `(512 MB) << sizeof(size_t)`.
const MAX_MEMORY: u64 = (512 << 20) << 8;
/// dibio.c: `NOISELENGTH`.
const NOISE_LENGTH: u64 = 32;
/// dibio.c: `MAX_SAMPLES_SIZE`.
const MAX_SAMPLES_SIZE: i64 = 2 << 30;
/// dibio.c: `g_refreshRate`, a sixth of a second.
const REFRESH_RATE: Duration = Duration::from_micros(1_000_000 / 6);
/// libzstd's `kSteps`: the optimiser's step count when `steps=0`.
const DEFAULT_STEPS: u32 = 40;

/// dibio.c's `EXM_THROW`: `Error N : msg\n` on standard error at every
/// display level, then exit `N`.
fn exm(err: &mut dyn Write, code: i32, fmt: &str, args: &[&[u8]]) -> Thrown {
    printf(err, m::DIB_EXM_ERROR, &[code.to_string().as_bytes()]);
    printf(err, fmt, args);
    printf(err, m::DIB_EXM_END, &[]);
    Thrown(code)
}

/// dibio.c: `DiB_rand`.
fn dib_rand(src: &mut u32) -> u32 {
    const PRIME1: u32 = 2_654_435_761;
    const PRIME2: u32 = 2_246_822_519;
    let mut r = *src;
    r = r.wrapping_mul(PRIME1);
    r ^= PRIME2;
    r = r.rotate_left(13);
    *src = r;
    r >> 5
}

/// dibio.c: `DiB_shuffle`, with its fixed seed: the order the samples are
/// measured and loaded in.
fn shuffle(names: &mut [Vec<u8>]) {
    let mut seed: u32 = 0xFD2F_B528;
    for i in (1..names.len()).rev() {
        let j = dib_rand(&mut seed) as usize % (i + 1);
        names.swap(i, j);
    }
}

/// dibio.c: `DiB_getFileSize`: the size, or -1 when unknown.
fn sample_size(host: &Host, name: &[u8]) -> i64 {
    match util::file_size(host, name) {
        FILESIZE_UNKNOWN => -1,
        s => s as i64,
    }
}

/// dibio.c: `fileStats`.
#[derive(Debug, Default, PartialEq, Eq)]
struct FileStats {
    total_size_to_load: i64,
    nb_samples: i32,
    one_sample_too_large: bool,
}

/// dibio.c: `DiB_fileStats`, in C's arithmetic (a size of -1 included).
fn file_stats(
    host: &Host,
    names: &[Vec<u8>],
    chunk: u64,
    d: &Display,
    err: &mut dyn Write,
) -> FileStats {
    let mut fs = FileStats::default();
    for name in names {
        let size = sample_size(host, name);
        if size == 0 {
            d.at(3, err, m::DIB_ZERO_SIZE, &[name]);
            continue;
        }
        // `(fileSize + chunkSize-1) / chunkSize` in size_t, then `(int)`.
        if let Some(n) = (size as u64)
            .wrapping_add(chunk.wrapping_sub(1))
            .checked_div(chunk)
        {
            fs.nb_samples = fs.nb_samples.wrapping_add(n as i32);
            fs.total_size_to_load = fs.total_size_to_load.wrapping_add(size);
        } else {
            if size > SAMPLESIZE_MAX {
                fs.one_sample_too_large |= size > 2 * SAMPLESIZE_MAX;
                let kb = (SAMPLESIZE_MAX >> 10).to_string();
                d.at(3, err, m::DIB_TOO_LARGE_LIMITING, &[name, kb.as_bytes()]);
            }
            fs.nb_samples = fs.nb_samples.wrapping_add(1);
            fs.total_size_to_load = fs.total_size_to_load.wrapping_add(size.min(SAMPLESIZE_MAX));
        }
    }
    let (n, kb, s) = (
        (names.len() as i32).to_string(),
        ((fs.total_size_to_load / 1024) as i32).to_string(),
        fs.nb_samples.to_string(),
    );
    d.at(
        4,
        err,
        m::DIB_FOUND,
        &[n.as_bytes(), kb.as_bytes(), s.as_bytes()],
    );
    fs
}

/// dibio.c: `DiB_findMaxMem`, its first `malloc` granted.
fn find_max_mem(required: u64) -> u64 {
    const STEP: u64 = 8 << 20;
    let required = (((required >> 23) + 1) << 23).wrapping_add(STEP);
    required.min(MAX_MEMORY) - STEP
}

/// What `DiB_loadFiles` loaded: the samples back to back and their sizes.
struct Loaded {
    buf: Vec<u8>,
    sizes: Vec<usize>,
}

/// `DISPLAYUPDATE`'s clock: the first update always prints.
struct Updates {
    last: Option<Instant>,
}

impl Updates {
    fn show(&mut self, d: &Display, err: &mut dyn Write, fmt: &str, args: &[&[u8]]) {
        if d.level >= 2 && (self.last.is_none_or(|t| t.elapsed() > REFRESH_RATE) || d.level >= 4) {
            self.last = Some(Instant::now());
            printf(err, fmt, args);
            if d.level >= 4 {
                let _ = err.flush();
            }
        }
    }
}

/// Read exactly `n` bytes of `f` into `buf`, as `fread` either returns
/// them all or fewer.
fn read_n(f: &mut dyn Read, buf: &mut Vec<u8>, n: usize) -> bool {
    let start = buf.len();
    buf.resize(start + n, 0);
    let mut got = 0;
    while got < n {
        match f.read(&mut buf[start + got..]) {
            Ok(0) => break,
            Ok(k) => got += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    buf.truncate(start + got);
    got == n
}

/// dibio.c: `DiB_loadFiles`: at most `buffer_size` bytes, at most
/// `sst_size` samples.
#[allow(clippy::too_many_arguments)]
fn load_files(
    host: &Host,
    buffer_size: u64,
    sst_size: i32,
    names: &[Vec<u8>],
    chunk: u64,
    d: &Display,
    err: &mut dyn Write,
) -> Fio<Loaded> {
    let mut l = Loaded {
        buf: Vec::new(),
        sizes: Vec::new(),
    };
    let mut total: u64 = 0;
    let mut updates = Updates { last: None };
    let loaded_count = |l: &Loaded| l.sizes.len() as i64;
    for name in names {
        if loaded_count(&l) >= i64::from(sst_size) {
            break;
        }
        let size = sample_size(host, name);
        if size <= 0 {
            continue;
        }
        let path = host.path(name);
        let mut f = match File::open(&path) {
            Ok(f) => host.track(&path, f),
            Err(e) => return Err(exm(err, 10, m::DIB_OPEN_FAILED, &[name, &strerror(&e)])),
        };
        updates.show(d, err, m::DIB_LOADING, &[name]);
        let size = size as u64;
        let mut file_loaded = if chunk > 0 {
            size.min(chunk)
        } else {
            size.min(SAMPLESIZE_MAX as u64)
        };
        if total + file_loaded > buffer_size {
            break;
        }
        if !read_n(&mut f, &mut l.buf, file_loaded as usize) {
            return Err(exm(err, 11, m::DIB_READ_FAILED, &[name]));
        }
        l.sizes.push(file_loaded as usize);
        total += file_loaded;
        if chunk > 0 {
            while file_loaded < size && loaded_count(&l) < i64::from(sst_size) {
                let piece = (size - file_loaded).min(chunk);
                if total + piece > buffer_size {
                    break;
                }
                if !read_n(&mut f, &mut l.buf, piece as usize) {
                    return Err(exm(err, 11, m::DIB_READ_FAILED, &[name]));
                }
                l.sizes.push(piece as usize);
                total += piece;
                file_loaded += piece;
            }
        }
    }
    d.at(2, err, m::DIB_CLEAR, &[]);
    let (kb, n) = (
        ((total / 1024) as i32).to_string(),
        l.sizes.len().to_string(),
    );
    d.at(4, err, m::DIB_LOADED, &[kb.as_bytes(), n.as_bytes()]);
    Ok(l)
}

/// dibio.c: `DiB_saveDict`.
fn save_dict(host: &Host, name: &[u8], dict: &[u8], err: &mut dyn Write) -> Fio<()> {
    let Ok(f) = File::create(host.path(name)) else {
        return Err(exm(err, 3, m::DIB_CANNOT_OPEN, &[name]));
    };
    let mut w = host.out_writer(Some(f));
    if w.write_all(dict).is_err() {
        return Err(exm(err, 4, m::DIB_WRITE_ERROR, &[name]));
    }
    if w.flush().is_err() {
        return Err(exm(err, 5, m::DIB_FLUSH_ERROR, &[name]));
    }
    Ok(())
}

/// zstdcli.c's training call and dibio.c: `DiB_trainFromFiles`. Returns
/// the operation's result (0, or 1 when the trainer fails), or the
/// `EXM_THROW` that ended it.
pub(crate) fn train_files(cmd: &Command, host: &mut Host, err: &mut dyn Write) -> Fio<i32> {
    let d = Display::new(cmd.display_level);
    if cfg!(not(feature = "zstd-c")) {
        // zstdcli.c, built with ZSTD_NODICT.
        d.at(1, err, m::TRAINING_NOT_AVAILABLE, &[]);
        return Ok(1);
    }
    let t = cmd
        .train
        .as_ref()
        .expect("the training operation has its parameters");
    let out_name = cmd.out_file.as_deref().unwrap_or_default();
    let chunk = cmd.prefs.job_size;
    let sandbox = cmd.limits;

    // zstdcli.c: the parameters, as main fills them.
    let workers = match sandbox {
        Some(l) => cmd.prefs.workers.min(l.workers),
        None => cmd.prefs.workers,
    };
    let (algo, optimize, mem_mult) = match t.dict {
        DictType::Cover => {
            let optimize = matches!(t.cover, TrainAlgo::Cover { k, d, .. } if k == 0 || d == 0);
            (t.cover.clone(), optimize, COVER_MEMMULT)
        }
        DictType::FastCover => {
            let optimize =
                matches!(t.fastcover, TrainAlgo::Fastcover { k, d, .. } if k == 0 || d == 0);
            (t.fastcover.clone(), optimize, FASTCOVER_MEMMULT)
        }
        DictType::Legacy => (
            TrainAlgo::Legacy {
                selectivity: t.selectivity,
            },
            false,
            MEMMULT,
        ),
    };
    let algo = match (sandbox, algo) {
        // R9: at most 4 optimiser steps.
        (
            Some(l),
            TrainAlgo::Cover {
                k,
                d,
                steps,
                split,
                shrink,
            },
        ) if optimize => TrainAlgo::Cover {
            k,
            d,
            steps: cap_steps(steps, l.train_steps),
            split,
            shrink,
        },
        (
            Some(l),
            TrainAlgo::Fastcover {
                k,
                d,
                f,
                steps,
                split,
                accel,
                shrink,
            },
        ) if optimize => TrainAlgo::Fastcover {
            k,
            d,
            f,
            steps: cap_steps(steps, l.train_steps),
            split,
            accel,
            shrink,
        },
        (_, a) => a,
    };
    let params = TrainParams {
        algo,
        optimize,
        max_dict: t.max_dict as usize,
        dict_id: t.dict_id,
        level: t.level,
        threads: workers as u32,
        // `(unsigned)g_displayLevel`; libzstd's lines are off in a sandbox.
        notification: if sandbox.is_some() {
            0
        } else {
            cmd.display_level as u32
        },
    };

    let mut names = cmd.files.clone();
    d.at(3, err, m::DIB_SHUFFLING, &[]);
    shuffle(&mut names);
    let fs = file_stats(host, &names, chunk, &d, err);

    let max_mem = find_max_mem((fs.total_size_to_load as u64).wrapping_mul(mem_mult)) / mem_mult;
    let mut loaded_size = (max_mem as i64)
        .min(fs.total_size_to_load)
        .min(MAX_SAMPLES_SIZE) as u64;
    let mem_limit = cmd.prefs.memory_limit;
    if mem_limit != 0 {
        let mb = (mem_limit >> 20).to_string();
        d.at(2, err, m::DIB_MANUAL_MEMORY_LIMIT, &[mb.as_bytes()]);
        loaded_size = loaded_size.min(u64::from(mem_limit));
    }
    if let Some(l) = sandbox {
        // R9: at most 256 KiB of samples.
        loaded_size = loaded_size.min(l.train_bytes);
    }
    // `malloc(loadedSize + NOISELENGTH)` and `malloc(nbSamples *
    // sizeof(size_t))`: a negative total (unmeasurable samples) wraps the
    // first to a size no allocator grants, or to a small one it does.
    if loaded_size.wrapping_add(NOISE_LENGTH) > MAX_SAMPLES_SIZE as u64 + NOISE_LENGTH
        || fs.nb_samples < 0
    {
        return Err(exm(err, 12, m::DIB_NOT_ENOUGH_MEMORY, &[]));
    }
    if fs.one_sample_too_large {
        let max = SAMPLESIZE_MAX.to_string();
        d.at(2, err, m::DIB_VERY_LARGE, &[max.as_bytes()]);
    }
    if fs.nb_samples < 5 {
        d.at(2, err, m::DIB_TOO_FEW, &[]);
        return Err(exm(err, 14, m::DIB_TOO_FEW_SAMPLES, &[]));
    }
    if fs.total_size_to_load < i64::from(t.max_dict) * 8 {
        d.at(2, err, m::DIB_DATA_TOO_SMALL, &[]);
    }
    if (loaded_size as i64) < fs.total_size_to_load {
        let (all, some) = (
            ((fs.total_size_to_load / (1 << 20)) as u32).to_string(),
            ((loaded_size >> 20) as u32).to_string(),
        );
        d.at(
            1,
            err,
            m::DIB_SET_TOO_LARGE,
            &[all.as_bytes(), some.as_bytes()],
        );
    }

    let loaded = load_files(host, loaded_size, fs.nb_samples, &names, chunk, &d, err)?;
    // libzstd writes its notifications on the same descriptor.
    let _ = err.flush();
    let trained = match zstd_opts::train(&loaded.buf, &loaded.sizes, &params) {
        Ok(t) => t,
        Err(e) => {
            d.at(1, err, m::DIB_TRAINING_FAILED, &[e.to_string().as_bytes()]);
            return Ok(1);
        }
    };
    if optimize {
        let n = |v: u32| v.to_string();
        let split = n((trained.chosen_split * 100.0) as u32);
        if t.dict == DictType::Cover {
            let args = [
                n(trained.chosen_k),
                n(trained.chosen_d),
                n(trained.chosen_steps),
                split,
            ];
            let args: Vec<&[u8]> = args.iter().map(|a| a.as_bytes()).collect();
            d.at(2, err, m::DIB_COVER_CHOSEN, &args);
        } else {
            let args = [
                n(trained.chosen_k),
                n(trained.chosen_d),
                n(trained.chosen_f),
                n(trained.chosen_steps),
                split,
                n(trained.chosen_accel),
            ];
            let args: Vec<&[u8]> = args.iter().map(|a| a.as_bytes()).collect();
            d.at(2, err, m::DIB_FASTCOVER_CHOSEN, &args);
        }
    }
    let size = (trained.dict.len() as u32).to_string();
    d.at(2, err, m::DIB_SAVE, &[size.as_bytes(), out_name]);
    save_dict(host, out_name, &trained.dict, err)?;
    Ok(0)
}

/// R9: `steps` at most `max` (libzstd reads `0` as [`DEFAULT_STEPS`]).
fn cap_steps(steps: u32, max: u32) -> u32 {
    let steps = if steps == 0 { DEFAULT_STEPS } else { steps };
    steps.min(max)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first name after `DiB_shuffle`, as the reference's
    /// `Loading %s...` line shows it: measured with zstd 1.5.7 over
    /// `s000`..`s099` and `s000`..`s049`.
    #[test]
    fn shuffle_matches_the_reference() {
        let names = |n: usize| -> Vec<Vec<u8>> {
            (0..n).map(|i| format!("s{i:03}").into_bytes()).collect()
        };
        let mut hundred = names(100);
        shuffle(&mut hundred);
        assert_eq!(hundred[0], b"s032");
        let mut fifty = names(50);
        shuffle(&mut fifty);
        assert_eq!(fifty[0], b"s047");
        let mut sorted = hundred.clone();
        sorted.sort();
        assert_eq!(sorted, names(100), "a permutation");
        let mut one = names(1);
        shuffle(&mut one);
        assert_eq!(one, names(1));
        shuffle(&mut []);
    }

    #[test]
    fn find_max_mem_rounds_up_to_8_mib() {
        assert_eq!(find_max_mem(0), 8 << 20);
        assert_eq!(find_max_mem(1), 8 << 20);
        assert_eq!(find_max_mem((8 << 20) - 1), 8 << 20);
        assert_eq!(find_max_mem(8 << 20), 16 << 20);
        assert_eq!(find_max_mem(u64::MAX - (1 << 30)), MAX_MEMORY - (8 << 20));
    }

    #[test]
    fn cap_steps_reads_zero_as_libzstds_default() {
        assert_eq!(cap_steps(0, 4), 4);
        assert_eq!(cap_steps(2, 4), 2);
        assert_eq!(cap_steps(100, 4), 4);
    }
}
