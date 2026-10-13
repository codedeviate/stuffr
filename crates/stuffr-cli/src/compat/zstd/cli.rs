//! zstdcli.c: the program name's presets, `ZSTD_CLEVEL`/`ZSTD_NBTHREADS`,
//! the argument loop with its number and parameter-string parsers, the
//! help texts, `-V`, and `--show-default-cparams`' printer, ported in
//! zstdcli.c's order.
//!
//! zstd does not use `getopt`: every error text is its own, the same on
//! every system. Short options aggregate (`-19dkv`); a digit run is a
//! compression level; `-o`, `-D` and the long options taking a value read
//! it after `=` or from the next argument (`NEXT_FIELD`), and a next
//! argument starting with `-` is refused. Long options are matched as
//! zstdcli.c matches them, many by prefix (`longCommandWArg`), so
//! `--memlimit-decompress=5` is `--memlimit` followed by text that is not
//! `=` and takes the next argument, as in zstd.
//!
//! Built as zstd is configured for the reference (the Global
//! Constraints): gzip, lzma, lz4, multi-threading and file lists on, and
//! `ZSTD_NOBENCH`/`ZSTD_NOTRACE` defined (R13): `-b`, `-e#`, `-i#` and
//! `--trace` are unknown options, as in such a build. `-B#`, `-S` and
//! `-p#` keep the reference's meaning (`-B#` is also the job size, `-S`
//! and `-p#`'s number only reach the benchmark), so they are accepted as
//! the reference accepts them.

use std::ffi::OsString;
use std::io::Write;

use stuffr::zstd_opts::{self, CParamKey, ParamSwitch, TrainAlgo};

use super::messages::{self as m, printf};
use super::util::Cores;

/// fileio.h: `stdinmark`, the name standing for standard input.
pub(crate) const STDINMARK: &[u8] = b"/*stdin*\\";
/// fileio.h: `stdoutmark`, the name standing for standard output.
pub(crate) const STDOUTMARK: &[u8] = b"/*stdout*\\";
/// fileio.h: `nulmark`, where `-t` writes.
#[cfg(windows)]
pub(crate) const NULMARK: &[u8] = b"NUL";
/// fileio.h: `nulmark`, where `-t` writes.
#[cfg(not(windows))]
pub(crate) const NULMARK: &[u8] = b"/dev/null";

/// zstdcli.c: `ZSTDCLI_CLEVEL_DEFAULT`.
const CLEVEL_DEFAULT: i32 = 3;
/// zstdcli.c: `ZSTDCLI_CLEVEL_MAX`, the highest level without `--ultra`.
pub(crate) const CLEVEL_MAX: i32 = 19;
/// zstdcli.c: `DISPLAY_LEVEL_DEFAULT`.
pub(crate) const DISPLAY_LEVEL_DEFAULT: i32 = 2;
/// zstdcli.c: `g_defaultDictName`.
const DEFAULT_DICT_NAME: &[u8] = b"dictionary";
/// zstdcli.c: `g_defaultMaxDictSize`.
const DEFAULT_MAX_DICT_SIZE: u32 = 110 << 10;
/// zstdcli.c: `g_defaultDictCLevel`.
const DEFAULT_DICT_CLEVEL: i32 = 3;
/// zstdcli.c: `g_defaultSelectivityLevel`.
const DEFAULT_SELECTIVITY: u32 = 9;
/// zstdcli.c: `g_defaultMaxWindowLog`.
pub(crate) const DEFAULT_MAX_WINDOW_LOG: u32 = 27;
/// zstdcli.c: `OVERLAP_LOG_DEFAULT`, "not given".
const OVERLAP_LOG_DEFAULT: u32 = 9999;
/// zstdcli.c: `LDM_PARAM_DEFAULT`, "not given" where 0 is a value.
const LDM_PARAM_DEFAULT: u32 = 9999;
/// platform.h: `ZSTD_SPARSE_DEFAULT`, 0 on Apple's platforms.
#[cfg(target_vendor = "apple")]
pub(crate) const SPARSE_DEFAULT: i32 = 0;
/// platform.h: `ZSTD_SPARSE_DEFAULT`, 1 elsewhere.
#[cfg(not(target_vendor = "apple"))]
pub(crate) const SPARSE_DEFAULT: i32 = 1;

/// The seven `--zstd=` parameters in `ZSTD_compressionParameters`' order.
const CPARAM_KEYS: [CParamKey; 7] = [
    CParamKey::WindowLog,
    CParamKey::ChainLog,
    CParamKey::HashLog,
    CParamKey::SearchLog,
    CParamKey::MinMatch,
    CParamKey::TargetLength,
    CParamKey::Strategy,
];

/// zstdcli.c: `zstd_operation_mode`. `zom_bench` is absent: with
/// `ZSTD_NOBENCH` nothing selects it (R13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operation {
    Compress,
    Decompress,
    Test,
    List,
    Train,
}

/// fileio_types.h: `FIO_compressionType_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CType {
    Zstd,
    Gzip,
    Xz,
    Lzma,
    Lz4,
}

impl CType {
    /// The enum's C value, which indexes fileio.c's tables.
    pub(crate) fn index(self) -> usize {
        self as usize
    }
}

/// fileio_types.h: `FIO_progressSetting_e`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Progress {
    Auto,
    Never,
    Always,
}

/// zstdcli.c: `dictType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DictType {
    Cover,
    FastCover,
    Legacy,
}

/// What `--train*` hands `DiB_trainFromFiles` (Task 8).
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)] // Read by Task 8 (dibio.rs).
pub(crate) struct TrainCmd {
    /// `dict`: the algorithm selected last.
    pub dict: DictType,
    /// `coverParams` (a [`TrainAlgo::Cover`]).
    pub cover: TrainAlgo,
    /// `fastCoverParams` (a [`TrainAlgo::Fastcover`]).
    pub fastcover: TrainAlgo,
    /// `dictSelect` (`--train-legacy=s=`, `-s#`).
    pub selectivity: u32,
    /// `maxDictSize` (`--maxdict`).
    pub max_dict: u32,
    /// `dictID` (`--dictID`).
    pub dict_id: u32,
    /// `dictCLevel`: the level digits and `--fast=N` set, not `--fast`.
    pub level: i32,
}

/// Everything zstdcli.c hands fileio.c through `FIO_set*`
/// (`FIO_prefs_t`, with `FIO_ctx_t`'s and `g_display_prefs`' fields),
/// filled by [`parse`] and by `main` after it, as zstdcli.c fills them.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)] // Read by Tasks 5-9 (fileio, formats, dibio, display).
pub(crate) struct Prefs {
    /// `compressionType`.
    pub ctype: CType,
    /// `overwrite` (`-f`, and the `cat` names).
    pub overwrite: bool,
    /// `sparseFileSupport`: 0 never, 1 automatic, 2 forced.
    pub sparse: i32,
    /// `dictIDFlag`.
    pub dict_id: bool,
    /// `checksumFlag`: 0 `--no-check`, 1 the default, 2 `--check`/`-C`.
    pub checksum: i32,
    /// `removeSrcFile`.
    pub remove_src: bool,
    /// `memLimit`: `-M`/`--memory` as given (0: not given) until `main`
    /// resolves it.
    pub memory_limit: u32,
    /// `nbWorkers`, as the C `int` (`-T` takes any 32-bit value).
    pub workers: i32,
    /// `blockSize` (`-B#`, `--block-size`), the job size.
    pub job_size: u64,
    /// `overlapLog`, when given (`--zstd=ovlog=`).
    pub overlap_log: Option<u32>,
    /// `adaptiveMode`.
    pub adapt: bool,
    /// `minAdaptLevel`.
    pub adapt_min: i32,
    /// `maxAdaptLevel`.
    pub adapt_max: i32,
    /// `rsyncable`.
    pub rsyncable: bool,
    /// `ldmFlag` (`--long`).
    pub ldm: bool,
    /// `ldmHashLog`.
    pub ldm_hash_log: u32,
    /// `ldmMinMatch`.
    pub ldm_min_match: u32,
    /// `ldmBucketSizeLog`, when given.
    pub ldm_bucket_size_log: Option<u32>,
    /// `ldmHashRateLog`, when given.
    pub ldm_hash_rate_log: Option<u32>,
    /// `streamSrcSize` (`--stream-size`, 0: none).
    pub stream_size: u64,
    /// `targetCBlockSize`.
    pub target_cblock_size: u64,
    /// `srcSizeHint`, `MIN(INT_MAX, --size-hint)`.
    pub size_hint: i32,
    /// `testMode`.
    pub test_mode: bool,
    /// `literalCompressionMode`.
    pub literal_compression: ParamSwitch,
    /// `useRowMatchFinder`.
    pub row_match_finder: ParamSwitch,
    /// `excludeCompressedFiles`.
    pub exclude_compressed: bool,
    /// `allowBlockDevices`.
    pub allow_block_devices: bool,
    /// `asyncIO` (accepted, no visible effect: spec deviation 5).
    pub async_io: bool,
    /// `passThrough`: -1 not set, 0, 1.
    pub pass_through: i32,
    /// `mmapDict`.
    pub mmap_dict: ParamSwitch,
    /// `patchFromMode`.
    pub patch_from_mode: bool,
    /// `contentSize`.
    pub content_size: bool,
    /// `g_display_prefs.progressSetting`.
    pub progress: Progress,
    /// `FIO_ctx_t.hasStdinInput`.
    pub has_stdin_input: bool,
    /// `FIO_ctx_t.hasStdoutOutput`.
    pub has_stdout_output: bool,
    /// `FIO_ctx_t.nbFilesTotal`.
    pub nb_files_total: usize,
    /// `--fake-stdin-is-console`.
    pub fake_stdin_console: bool,
    /// `--fake-stdout-is-console`.
    pub fake_stdout_console: bool,
    /// `--fake-stderr-is-console`.
    pub fake_stderr_console: bool,
    /// `--trace-file-stat` (`g_traceFileStat`).
    pub trace_file_stat: bool,
    /// `g_utilDisplayLevel`: the display level as zstdcli.c sets it after
    /// the arguments, before `main` lowers it for standard output.
    pub util_level: i32,
}

impl Default for Prefs {
    /// fileio.c: FIO_createPreferences, FIO_createContext and
    /// `g_display_prefs`' initial values.
    fn default() -> Self {
        Prefs {
            ctype: CType::Zstd,
            overwrite: false,
            sparse: SPARSE_DEFAULT,
            dict_id: true,
            checksum: 1,
            remove_src: false,
            memory_limit: 0,
            workers: 1,
            job_size: 0,
            overlap_log: None,
            adapt: false,
            adapt_min: -50,
            adapt_max: 22,
            rsyncable: false,
            ldm: false,
            ldm_hash_log: 0,
            ldm_min_match: 0,
            ldm_bucket_size_log: None,
            ldm_hash_rate_log: None,
            stream_size: 0,
            target_cblock_size: 0,
            size_hint: 0,
            test_mode: false,
            literal_compression: ParamSwitch::Auto,
            row_match_finder: ParamSwitch::Auto,
            exclude_compressed: false,
            allow_block_devices: false,
            async_io: true,
            pass_through: -1,
            mmap_dict: ParamSwitch::Auto,
            patch_from_mode: false,
            content_size: true,
            progress: Progress::Auto,
            has_stdin_input: false,
            has_stdout_output: false,
            nb_files_total: 1,
            fake_stdin_console: false,
            fake_stdout_console: false,
            fake_stderr_console: false,
            trace_file_stat: false,
            util_level: DISPLAY_LEVEL_DEFAULT,
        }
    }
}

/// R9's input-independent bounds for a sandboxed run (`run_in_counted`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // `train_*` read by Task 8 (dibio.rs).
pub(crate) struct Limits {
    /// The decoder's window-log maximum (a lower `--memory`/`--long`
    /// stands).
    pub window_log_max: u32,
    /// `--train*` sample bytes in total.
    pub train_bytes: u64,
    /// `--train*` optimiser `steps`.
    pub train_steps: u32,
    /// Compression workers.
    pub workers: i32,
}

impl Limits {
    /// R9's values.
    pub(crate) const SANDBOX: Limits = Limits {
        window_log_max: 24,
        train_bytes: 256 << 10,
        train_steps: 4,
        workers: 2,
    };
}

/// The parsed command line: zstdcli.c's `main` locals at the point the
/// operation starts.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)] // Read by Tasks 5-8 (fileio, list, dibio).
pub(crate) struct Command {
    /// `operation`.
    pub op: Operation,
    /// The preferences.
    pub prefs: Prefs,
    /// `cLevel`.
    pub level: i32,
    /// `ultra` (`--ultra`, `--long`, `--patch-from`, `--max`).
    pub ultra: bool,
    /// `filenames`: operands, standard input as [`STDINMARK`].
    pub files: Vec<Vec<u8>>,
    /// `outFileName` (standard output as [`STDOUTMARK`]).
    pub out_file: Option<Vec<u8>>,
    /// `outDirName` (`--output-dir-flat`).
    pub out_dir_flat: Option<Vec<u8>>,
    /// `outMirroredDirName` (`--output-dir-mirror`).
    pub out_dir_mirror: Option<Vec<u8>>,
    /// `dictFileName` (`-D`; `--patch-from`'s file once `main` resolves it).
    pub dict_file: Option<Vec<u8>>,
    /// `patchFromDictFileName`.
    pub patch_from: Option<Vec<u8>>,
    /// `suffix`.
    pub suffix: &'static str,
    /// `recursive` (`-r`).
    pub recursive: bool,
    /// `followLinks`.
    pub follow_links: bool,
    /// `forceStdin`.
    pub force_stdin: bool,
    /// `forceStdout`.
    pub force_stdout: bool,
    /// `g_displayLevel`.
    pub display_level: i32,
    /// `compressionParams`: the non-zero fields, in the struct's order.
    pub cparams_overrides: Vec<(CParamKey, u32)>,
    /// `--train*`'s parameters, when the operation is training.
    pub train: Option<TrainCmd>,
    /// `--show-default-cparams`.
    pub show_default_cparams: bool,
    /// `file_of_names` (`--filelist`).
    pub filelists: Vec<Vec<u8>>,
    /// `main_pause` (`-p`): wait for enter at the end.
    pub main_pause: bool,
    /// `nbInputFileNames`, set by `main`.
    pub nb_input_files: usize,
    /// R9's bounds, under `Host::Sandbox` only.
    pub limits: Option<Limits>,
}

impl Command {
    /// `compressionParams.<key>`: 0 when not given.
    pub(crate) fn cparam(&self, key: CParamKey) -> u32 {
        self.cparams_overrides
            .iter()
            .find(|(k, _)| *k == key)
            .map_or(0, |&(_, v)| v)
    }
}

/// How the run ends before (or instead of) its operation: zstdcli.c's
/// `CLEAN_RETURN(code)` (`clean`: through `_end`, which waits for enter
/// under `-p`) or `exit(code)` (errorOut, `EXM_THROW`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stop {
    pub code: i32,
    pub clean: bool,
    /// `main_pause` at the stop.
    pub pause: bool,
}

/// zstdcli.c: lastNameFromPath, after the last `/` and then the last `\`.
pub(crate) fn last_name_from_path(path: &[u8]) -> &[u8] {
    let mut name = path;
    if let Some(at) = name.iter().rposition(|&b| b == b'/') {
        name = &name[at + 1..];
    }
    if let Some(at) = name.iter().rposition(|&b| b == b'\\') {
        name = &name[at + 1..];
    }
    name
}

/// zstdcli.c: exeNameMatch: `name` starts with `test`, followed by the end
/// or a `.`.
pub(crate) fn exe_name_match(name: &str, test: &str) -> bool {
    name.strip_prefix(test)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
}

/// The byte at `p`, or 0 past the end (C's terminator).
fn at(s: &[u8], p: usize) -> u8 {
    s.get(p).copied().unwrap_or(0)
}

/// zstdcli.c: readU32FromCharChecked: digits with an optional `K`/`M`
/// (then `i`, then `B`) suffix, advancing `p`; `None` on overflow.
fn read_u32_checked(s: &[u8], p: &mut usize) -> Option<u32> {
    let mut result: u32 = 0;
    while at(s, *p).is_ascii_digit() {
        let last = result;
        if result > u32::MAX / 10 {
            return None;
        }
        result = result
            .wrapping_mul(10)
            .wrapping_add(u32::from(at(s, *p) - b'0'));
        if result < last {
            return None;
        }
        *p += 1;
    }
    if matches!(at(s, *p), b'K' | b'M') {
        let max_k = u32::MAX >> 10;
        if result > max_k {
            return None;
        }
        result <<= 10;
        if at(s, *p) == b'M' {
            if result > max_k {
                return None;
            }
            result <<= 10;
        }
        *p += 1;
        if at(s, *p) == b'i' {
            *p += 1;
        }
        if at(s, *p) == b'B' {
            *p += 1;
        }
    }
    Some(result)
}

/// zstdcli.c: readSizeTFromCharChecked (a 64-bit `size_t`).
fn read_size_checked(s: &[u8], p: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
    while at(s, *p).is_ascii_digit() {
        let last = result;
        if result > u64::MAX / 10 {
            return None;
        }
        result = result
            .wrapping_mul(10)
            .wrapping_add(u64::from(at(s, *p) - b'0'));
        if result < last {
            return None;
        }
        *p += 1;
    }
    if matches!(at(s, *p), b'K' | b'M') {
        let max_k = u64::MAX >> 10;
        if result > max_k {
            return None;
        }
        result <<= 10;
        if at(s, *p) == b'M' {
            if result > max_k {
                return None;
            }
            result <<= 10;
        }
        *p += 1;
        if at(s, *p) == b'i' {
            *p += 1;
        }
        if at(s, *p) == b'B' {
            *p += 1;
        }
    }
    Some(result)
}

/// The parser's display state and error stream: what zstdcli.c's
/// `DISPLAYLEVEL`, errorOut and badUsage reach.
struct Ctx<'a> {
    /// `g_displayLevel`.
    level: i32,
    /// `programName`.
    program: &'a str,
    err: &'a mut dyn Write,
}

impl Ctx<'_> {
    fn display(&mut self, l: i32, fmt: &str, args: &[&[u8]]) {
        if self.level >= l {
            printf(self.err, fmt, args);
        }
    }

    /// zstdcli.c: errorOut: the message at level 1, then `exit(1)`.
    fn error_out(&mut self, msg: &str) -> Stop {
        self.display(1, m::ERROR_OUT, &[msg.as_bytes()]);
        Stop {
            code: 1,
            clean: false,
            pause: false,
        }
    }

    /// zstdcli.c: badUsage: the parameter at level 1, the short usage on
    /// standard error from level 2.
    fn bad_usage(&mut self, parameter: &[u8]) {
        self.display(1, m::INCORRECT_PARAMETER, &[parameter]);
        if self.level >= 2 {
            usage(self.err, self.program);
        }
    }

    /// zstdcli.c: readU32FromChar.
    fn read_u32(&mut self, s: &[u8], p: &mut usize) -> Result<u32, Stop> {
        read_u32_checked(s, p).ok_or_else(|| self.error_out(m::OVERFLOW_U32))
    }

    /// zstdcli.c: readIntFromChar.
    fn read_int(&mut self, s: &[u8], p: &mut usize) -> Result<i32, Stop> {
        let mut sign = 1i32;
        if at(s, *p) == b'-' {
            *p += 1;
            sign = -1;
        }
        let r = read_u32_checked(s, p).ok_or_else(|| self.error_out(m::OVERFLOW_INT))?;
        Ok((r as i32).wrapping_mul(sign))
    }

    /// zstdcli.c: readSizeTFromChar.
    fn read_size(&mut self, s: &[u8], p: &mut usize) -> Result<u64, Stop> {
        read_size_checked(s, p).ok_or_else(|| self.error_out(m::OVERFLOW_SIZE_T))
    }
}

/// zstdcli.c: init_cLevel: `ZSTD_CLEVEL`, warned about at the default
/// display level (it is read before any `-q`).
fn init_clevel(env: &dyn Fn(&str) -> Option<OsString>, ctx: &mut Ctx) -> i32 {
    const NAME: &str = "ZSTD_CLEVEL";
    let Some(value) = env(NAME) else {
        return CLEVEL_DEFAULT;
    };
    let v = value.as_encoded_bytes();
    let v = &v[..v.iter().position(|&b| b == 0).unwrap_or(v.len())];
    let mut p = 0;
    let mut sign = 1i32;
    match at(v, 0) {
        b'-' => {
            sign = -1;
            p = 1;
        }
        b'+' => p = 1,
        _ => {}
    }
    if at(v, p).is_ascii_digit() {
        match read_u32_checked(v, &mut p) {
            None => {
                ctx.display(2, m::ENV_TOO_LARGE, &[NAME.as_bytes(), v]);
                return CLEVEL_DEFAULT;
            }
            Some(abs) if p == v.len() => return sign.wrapping_mul(abs as i32),
            Some(_) => {}
        }
    }
    ctx.display(2, m::ENV_NOT_INT, &[NAME.as_bytes(), v]);
    CLEVEL_DEFAULT
}

/// zstdcli.c: default_nbThreads: `ZSTD_NBTHREADS`, else
/// `ZSTDCLI_NBTHREADS_DEFAULT`.
fn default_nb_threads(env: &dyn Fn(&str) -> Option<OsString>, cores: Cores, ctx: &mut Ctx) -> u32 {
    const NAME: &str = "ZSTD_NBTHREADS";
    let Some(value) = env(NAME) else {
        return cores.default_workers();
    };
    let v = value.as_encoded_bytes();
    let v = &v[..v.iter().position(|&b| b == 0).unwrap_or(v.len())];
    if at(v, 0).is_ascii_digit() {
        let mut p = 0;
        match read_u32_checked(v, &mut p) {
            None => {
                ctx.display(2, m::ENV_TOO_LARGE, &[NAME.as_bytes(), v]);
                return cores.default_workers();
            }
            Some(n) if p == v.len() => return n,
            Some(_) => {}
        }
    }
    ctx.display(2, m::ENV_NOT_UNSIGNED, &[NAME.as_bytes(), v]);
    cores.default_workers()
}

/// zstdcli.c: defaultCoverParams.
fn default_cover() -> TrainAlgo {
    TrainAlgo::Cover {
        k: 0,
        d: 8,
        steps: 4,
        split: 1.0,
        shrink: None,
    }
}

/// zstdcli.c: defaultFastCoverParams.
fn default_fastcover() -> TrainAlgo {
    TrainAlgo::Fastcover {
        k: 0,
        d: 8,
        f: 20,
        steps: 4,
        split: 0.75,
        accel: 1,
        shrink: None,
    }
}

/// `longCommandWArg`: the rest of `s` after `prefix`, if `s` starts with it.
fn long_arg<'s>(s: &'s [u8], prefix: &str) -> Option<&'s [u8]> {
    s.strip_prefix(prefix.as_bytes())
}

/// A train parameter string's fields, zero-initialised (`memset`):
/// `k`, `d`, `f`, `steps`, the split percentage, `accel`, and `shrink`
/// with its regression.
#[derive(Default)]
struct DictFields {
    k: u32,
    d: u32,
    f: u32,
    steps: u32,
    split: f64,
    accel: u32,
    shrink: Option<u32>,
}

/// zstdcli.c: parseCoverParameters (`fast`: parseFastCoverParameters,
/// which also takes `f=` and `accel=`). `Ok(None)` is a malformed string.
fn parse_cover(ctx: &mut Ctx, s: &[u8], fast: bool) -> Result<Option<DictFields>, Stop> {
    const DEFAULT_REGRESSION: u32 = 1;
    let mut f = DictFields::default();
    let mut p = 0;
    loop {
        let rest = &s[p..];
        let keys: &[&str] = if fast {
            &["k=", "d=", "f=", "steps=", "accel="]
        } else {
            &["k=", "d=", "steps="]
        };
        if let Some(key) = keys.iter().find(|k| rest.starts_with(k.as_bytes())) {
            p += key.len();
            let v = ctx.read_u32(s, &mut p)?;
            match *key {
                "k=" => f.k = v,
                "d=" => f.d = v,
                "f=" => f.f = v,
                "steps=" => f.steps = v,
                _ => f.accel = v,
            }
        } else if rest.starts_with(b"split=") {
            p += 6;
            let pct = ctx.read_u32(s, &mut p)?;
            f.split = f64::from(pct) / 100.0;
        } else if rest.starts_with(b"shrink") {
            p += 6;
            let mut regression = DEFAULT_REGRESSION;
            if at(s, p) == b'=' {
                p += 1;
                regression = ctx.read_u32(s, &mut p)?;
            }
            f.shrink = Some(regression);
        } else {
            return Ok(None);
        }
        if at(s, p) == b',' {
            p += 1;
            continue;
        }
        break;
    }
    if p != s.len() {
        return Ok(None);
    }
    let n = |v: u32| v.to_string();
    let split = n((f.split * 100.0) as u32);
    let shrink = n(f.shrink.unwrap_or(0));
    if fast {
        let args = [
            n(f.k),
            n(f.d),
            n(f.f),
            n(f.steps),
            split,
            n(f.accel),
            shrink,
        ];
        let args: Vec<&[u8]> = args.iter().map(|a| a.as_bytes()).collect();
        ctx.display(4, m::FASTCOVER_PARAMS, &args);
    } else {
        let args = [n(f.k), n(f.d), n(f.steps), split, shrink];
        let args: Vec<&[u8]> = args.iter().map(|a| a.as_bytes()).collect();
        ctx.display(4, m::COVER_PARAMS, &args);
    }
    Ok(Some(f))
}

/// zstdcli.c: parseAdaptParameters. `Ok(false)` is a malformed string.
fn parse_adapt(ctx: &mut Ctx, s: &[u8], min: &mut i32, max: &mut i32) -> Result<bool, Stop> {
    let mut p = 0;
    loop {
        let rest = &s[p..];
        if rest.starts_with(b"min=") {
            p += 4;
            *min = ctx.read_int(s, &mut p)?;
        } else if rest.starts_with(b"max=") {
            p += 4;
            *max = ctx.read_int(s, &mut p)?;
        } else {
            ctx.display(4, m::INVALID_CPARAM, &[]);
            return Ok(false);
        }
        if at(s, p) == b',' {
            p += 1;
            continue;
        }
        break;
    }
    if p != s.len() {
        return Ok(false);
    }
    if *min > *max {
        ctx.display(4, m::INCOHERENT_ADAPT, &[]);
        return Ok(false);
    }
    Ok(true)
}

/// zstdcli.c's globals the `--zstd=` string also sets.
struct LdmGlobals {
    overlap_log: u32,
    ldm_hash_log: u32,
    ldm_min_match: u32,
    ldm_bucket_size_log: u32,
    ldm_hash_rate_log: u32,
}

/// zstdcli.c: parseCompressionParameters. `Ok(false)` is a malformed
/// string; fields set before the fault stay set, as in zstd.
fn parse_cparams(
    ctx: &mut Ctx,
    s: &[u8],
    params: &mut [u32; 7],
    g: &mut LdmGlobals,
) -> Result<bool, Stop> {
    // (long name, short name, slot): 0..7 are `params`, 7.. the globals.
    const KEYS: [(&str, &str); 12] = [
        ("windowLog=", "wlog="),
        ("chainLog=", "clog="),
        ("hashLog=", "hlog="),
        ("searchLog=", "slog="),
        ("minMatch=", "mml="),
        ("targetLength=", "tlen="),
        ("strategy=", "strat="),
        ("overlapLog=", "ovlog="),
        ("ldmHashLog=", "lhlog="),
        ("ldmMinMatch=", "lmml="),
        ("ldmBucketSizeLog=", "lblog="),
        ("ldmHashRateLog=", "lhrlog="),
    ];
    let mut p = 0;
    loop {
        let rest = &s[p..];
        let Some((slot, len)) = KEYS.iter().enumerate().find_map(|(i, (long, short))| {
            if rest.starts_with(long.as_bytes()) {
                Some((i, long.len()))
            } else if rest.starts_with(short.as_bytes()) {
                Some((i, short.len()))
            } else {
                None
            }
        }) else {
            ctx.display(4, m::INVALID_CPARAM, &[]);
            return Ok(false);
        };
        p += len;
        let v = ctx.read_u32(s, &mut p)?;
        match slot {
            0..=6 => params[slot] = v,
            7 => g.overlap_log = v,
            8 => g.ldm_hash_log = v,
            9 => g.ldm_min_match = v,
            10 => g.ldm_bucket_size_log = v,
            _ => g.ldm_hash_rate_log = v,
        }
        if at(s, p) == b',' {
            p += 1;
            continue;
        }
        break;
    }
    Ok(p == s.len())
}

/// `NEXT_FIELD`: the value after `=` in `arg` from `*pos` (moving `*pos`
/// to the end), else the next argument, which must exist and must not
/// start with `-`.
fn next_field<'a>(
    ctx: &mut Ctx,
    arg: &'a [u8],
    pos: &mut usize,
    args: &'a [Vec<u8>],
    arg_nb: &mut usize,
    pause: bool,
) -> Result<&'a [u8], Stop> {
    let clean = |code| Stop {
        code,
        clean: true,
        pause,
    };
    if at(arg, *pos) == b'=' {
        let v = &arg[*pos + 1..];
        *pos = arg.len();
        return Ok(v);
    }
    *arg_nb += 1;
    let Some(next) = args.get(*arg_nb) else {
        ctx.display(1, m::MISSING_ARGUMENT, &[]);
        return Err(clean(1));
    };
    if next.first() == Some(&b'-') {
        ctx.display(1, m::SEPARATED, &[]);
        return Err(clean(1));
    }
    Ok(next)
}

/// `NEXT_UINT32`/`NEXT_TSIZE`'s check: the whole value must be read.
fn whole_number<T>(ctx: &mut Ctx, v: T, s: &[u8], p: usize) -> Result<T, Stop> {
    if p != s.len() {
        return Err(ctx.error_out(m::ONLY_NUMERIC));
    }
    Ok(v)
}

/// zstdcli.c: main, from the program name's presets to the worker count:
/// `ZSTD_CLEVEL`, the arguments in order, the welcome line (`-v`), the
/// thread count with `ZSTD_NBTHREADS`. `-h`, `-H` and `-V` print to `out`
/// and stop the run (exit 0), as does every refusal (with its code);
/// messages go to `err`. `program` is the invoked name, directory
/// stripped (`lastNameFromPath`).
pub(crate) fn parse(
    program: &str,
    env: &dyn Fn(&str) -> Option<OsString>,
    args: &[OsString],
    cores: Cores,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<Command, Stop> {
    // A C argument ends at its first NUL.
    let args: Vec<Vec<u8>> = args
        .iter()
        .map(|a| {
            let b = a.as_encoded_bytes();
            b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())].to_vec()
        })
        .collect();
    let mut ctx = Ctx {
        level: DISPLAY_LEVEL_DEFAULT,
        program,
        err,
    };
    let mut prefs = Prefs::default();
    let (mut follow_links, mut force_stdin, mut force_stdout) = (false, false, false);
    let (mut ldm_flag, mut main_pause, mut adapt, mut rsyncable) = (false, false, false, false);
    let (mut adapt_min, mut adapt_max) = (zstd_opts::MIN_CLEVEL, zstd_opts::MAX_CLEVEL);
    let (mut next_are_files, mut single_thread, mut default_logical) = (false, false, false);
    let (mut show_default_cparams, mut ultra, mut content_size) = (false, false, true);
    let mut remove_src = false;
    let mut mmap_dict = ParamSwitch::Auto;
    let mut row_match_finder = ParamSwitch::Auto;
    let mut ctype = CType::Zstd;
    let mut nb_workers: i32 = -1;
    let mut block_size: u64 = 0;
    let mut progress = Progress::Auto;
    let mut op = Operation::Compress;
    let mut params = [0u32; 7];
    let mut level = init_clevel(env, &mut ctx);
    let mut recursive = false;
    let mut mem_limit: u32 = 0;
    let mut files: Vec<Vec<u8>> = Vec::new();
    let mut filelists: Vec<Vec<u8>> = Vec::new();
    let mut out_file: Option<Vec<u8>> = None;
    let mut out_dir_flat: Option<Vec<u8>> = None;
    let mut out_dir_mirror: Option<Vec<u8>> = None;
    let mut dict_file: Option<Vec<u8>> = None;
    let mut patch_from: Option<Vec<u8>> = None;
    let mut suffix = ".zst";
    let mut max_dict = DEFAULT_MAX_DICT_SIZE;
    let mut dict_id: u32 = 0;
    let mut stream_size: u64 = 0;
    let mut target_cblock: u64 = 0;
    let mut size_hint: u64 = 0;
    let mut dict_clevel = DEFAULT_DICT_CLEVEL;
    let mut dict_select = DEFAULT_SELECTIVITY;
    let mut cover = default_cover();
    let mut fastcover = default_fastcover();
    let mut dict = DictType::FastCover;
    let mut literals = ParamSwitch::Auto;
    let mut g = LdmGlobals {
        overlap_log: OVERLAP_LOG_DEFAULT,
        ldm_hash_log: 0,
        ldm_min_match: 0,
        ldm_bucket_size_log: LDM_PARAM_DEFAULT,
        ldm_hash_rate_log: LDM_PARAM_DEFAULT,
    };

    // The presets by name. The `cat` names: decompress to standard output,
    // overwrite, follow links, pass through, display level 1.
    let is = |test: &str| exe_name_match(program, test);
    let cat = |prefs: &mut Prefs, op: &mut Operation, out: &mut Option<Vec<u8>>, l: &mut i32| {
        *op = Operation::Decompress;
        prefs.overwrite = true;
        prefs.pass_through = 1;
        *out = Some(STDOUTMARK.to_vec());
        *l = 1;
    };
    if is("zstdmt") {
        nb_workers = 0;
        single_thread = false;
    }
    if is("unzstd") {
        op = Operation::Decompress;
    }
    for name in ["zstdcat", "zcat"] {
        if is(name) {
            cat(&mut prefs, &mut op, &mut out_file, &mut ctx.level);
            force_stdout = true;
            follow_links = true;
        }
    }
    if is("gzip") {
        suffix = ".gz";
        ctype = CType::Gzip;
        remove_src = true;
        level = 6;
        dict_clevel = 6;
    }
    if is("gunzip") {
        op = Operation::Decompress;
        remove_src = true;
    }
    if is("gzcat") {
        cat(&mut prefs, &mut op, &mut out_file, &mut ctx.level);
        force_stdout = true;
        follow_links = true;
    }
    if is("lzma") {
        suffix = ".lzma";
        ctype = CType::Lzma;
        remove_src = true;
    }
    if is("unlzma") {
        op = Operation::Decompress;
        ctype = CType::Lzma;
        remove_src = true;
    }
    if is("xz") {
        suffix = ".xz";
        ctype = CType::Xz;
        remove_src = true;
    }
    if is("unxz") {
        op = Operation::Decompress;
        ctype = CType::Xz;
        remove_src = true;
    }
    if is("lz4") {
        suffix = ".lz4";
        ctype = CType::Lz4;
    }
    if is("unlz4") {
        op = Operation::Decompress;
        ctype = CType::Lz4;
    }

    let mut arg_nb = 0;
    while arg_nb < args.len() {
        let arg: &[u8] = &args[arg_nb];
        let clean = |code, pause| Stop {
            code,
            clean: true,
            pause,
        };
        if next_are_files {
            files.push(arg.to_vec());
            arg_nb += 1;
            continue;
        }
        if arg == b"-" {
            files.push(STDINMARK.to_vec());
            arg_nb += 1;
            continue;
        }
        if at(arg, 0) != b'-' {
            files.push(arg.to_vec());
            arg_nb += 1;
            continue;
        }

        if at(arg, 1) == b'-' {
            // Long commands.
            let a = arg;
            match a {
                b"--" => next_are_files = true,
                b"--list" => op = Operation::List,
                b"--compress" => op = Operation::Compress,
                b"--decompress" | b"--uncompress" => op = Operation::Decompress,
                b"--force" => {
                    prefs.overwrite = true;
                    force_stdin = true;
                    force_stdout = true;
                    follow_links = true;
                    prefs.allow_block_devices = true;
                }
                b"--version" => {
                    print_version(out, ctx.level);
                    return Err(clean(0, main_pause));
                }
                b"--help" => {
                    usage_advanced(out, program);
                    return Err(clean(0, main_pause));
                }
                b"--verbose" => ctx.level += 1,
                b"--quiet" => ctx.level -= 1,
                b"--stdout" => {
                    force_stdout = true;
                    out_file = Some(STDOUTMARK.to_vec());
                }
                b"--ultra" => ultra = true,
                b"--check" => prefs.checksum = 2,
                b"--no-check" => prefs.checksum = 0,
                b"--sparse" => prefs.sparse = 2,
                b"--no-sparse" => prefs.sparse = 0,
                b"--pass-through" => prefs.pass_through = 1,
                b"--no-pass-through" => prefs.pass_through = 0,
                b"--test" => op = Operation::Test,
                b"--asyncio" => prefs.async_io = true,
                b"--no-asyncio" => prefs.async_io = false,
                b"--train" => {
                    op = Operation::Train;
                    out_file.get_or_insert_with(|| DEFAULT_DICT_NAME.to_vec());
                }
                b"--no-dictID" => prefs.dict_id = false,
                b"--keep" => remove_src = false,
                b"--rm" => remove_src = true,
                // Only the benchmark reads it.
                b"--priority=rt" => {}
                b"--show-default-cparams" => show_default_cparams = true,
                b"--content-size" => content_size = true,
                b"--no-content-size" => content_size = false,
                b"--adapt" => adapt = true,
                b"--no-row-match-finder" => row_match_finder = ParamSwitch::Disable,
                b"--row-match-finder" => row_match_finder = ParamSwitch::Enable,
                _ => {
                    match long_with_value(LongCtx {
                        ctx: &mut ctx,
                        arg: a,
                        args: &args,
                        arg_nb: &mut arg_nb,
                        program,
                        st: LongState {
                            prefs: &mut prefs,
                            op: &mut op,
                            out_file: &mut out_file,
                            out_dir_flat: &mut out_dir_flat,
                            out_dir_mirror: &mut out_dir_mirror,
                            patch_from: &mut patch_from,
                            filelists: &mut filelists,
                            suffix: &mut suffix,
                            ctype: &mut ctype,
                            adapt: &mut adapt,
                            adapt_min: &mut adapt_min,
                            adapt_max: &mut adapt_max,
                            nb_workers: &mut nb_workers,
                            single_thread: &mut single_thread,
                            mmap_dict: &mut mmap_dict,
                            level: &mut level,
                            dict_clevel: &mut dict_clevel,
                            rsyncable: &mut rsyncable,
                            literals: &mut literals,
                            progress: &mut progress,
                            ultra: &mut ultra,
                            ldm_flag: &mut ldm_flag,
                            params: &mut params,
                            g: &mut g,
                            cover: &mut cover,
                            fastcover: &mut fastcover,
                            dict: &mut dict,
                            dict_select: &mut dict_select,
                            mem_limit: &mut mem_limit,
                            block_size: &mut block_size,
                            max_dict: &mut max_dict,
                            dict_id: &mut dict_id,
                            stream_size: &mut stream_size,
                            target_cblock: &mut target_cblock,
                            size_hint: &mut size_hint,
                            default_logical: &mut default_logical,
                            main_pause,
                        },
                    })? {
                        Long::Handled => {}
                        Long::Bad => {
                            ctx.bad_usage(arg);
                            return Err(clean(1, main_pause));
                        }
                    }
                }
            }
            arg_nb += 1;
            continue;
        }

        // Short commands, aggregated.
        let mut p = 1;
        while p < arg.len() {
            let c = arg[p];
            if c.is_ascii_digit() {
                level = ctx.read_u32(arg, &mut p)? as i32;
                dict_clevel = level;
                continue;
            }
            match c {
                b'V' => {
                    print_version(out, ctx.level);
                    return Err(clean(0, main_pause));
                }
                b'H' => {
                    usage_advanced(out, program);
                    return Err(clean(0, main_pause));
                }
                b'h' => {
                    usage(out, program);
                    return Err(clean(0, main_pause));
                }
                b'z' => {
                    op = Operation::Compress;
                    p += 1;
                }
                b'd' => {
                    op = Operation::Decompress;
                    p += 1;
                }
                b'c' => {
                    force_stdout = true;
                    out_file = Some(STDOUTMARK.to_vec());
                    p += 1;
                }
                b'o' => {
                    p += 1;
                    let v = next_field(&mut ctx, arg, &mut p, &args, &mut arg_nb, main_pause)?;
                    out_file = Some(v.to_vec());
                }
                b'n' => p += 1,
                b'D' => {
                    p += 1;
                    let v = next_field(&mut ctx, arg, &mut p, &args, &mut arg_nb, main_pause)?;
                    dict_file = Some(v.to_vec());
                }
                b'f' => {
                    prefs.overwrite = true;
                    force_stdin = true;
                    force_stdout = true;
                    follow_links = true;
                    prefs.allow_block_devices = true;
                    p += 1;
                }
                b'v' => {
                    ctx.level += 1;
                    p += 1;
                }
                b'q' => {
                    ctx.level -= 1;
                    p += 1;
                }
                b'k' => {
                    remove_src = false;
                    p += 1;
                }
                b'C' => {
                    prefs.checksum = 2;
                    p += 1;
                }
                b't' => {
                    op = Operation::Test;
                    p += 1;
                }
                b'M' => {
                    p += 1;
                    mem_limit = ctx.read_u32(arg, &mut p)?;
                }
                b'l' => {
                    op = Operation::List;
                    p += 1;
                }
                b'r' => {
                    recursive = true;
                    p += 1;
                }
                // The reference's (benchmark) build: `-B#` is also the job
                // size, `-S` only reaches the benchmark.
                b'B' => {
                    p += 1;
                    block_size = u64::from(ctx.read_u32(arg, &mut p)?);
                }
                b'S' => p += 1,
                b'T' => {
                    p += 1;
                    nb_workers = ctx.read_u32(arg, &mut p)? as i32;
                }
                b's' => {
                    p += 1;
                    dict_select = ctx.read_u32(arg, &mut p)?;
                }
                // `-p#` sets a benchmark parameter in the reference's build;
                // `-p` alone pauses at the end.
                b'p' => {
                    p += 1;
                    if at(arg, p).is_ascii_digit() {
                        ctx.read_u32(arg, &mut p)?;
                    } else {
                        main_pause = true;
                    }
                }
                // The synthetic sample's compressibility: benchmark only.
                b'P' => {
                    p += 1;
                    ctx.read_u32(arg, &mut p)?;
                }
                _ => {
                    ctx.bad_usage(&[b'-', c]);
                    return Err(clean(1, main_pause));
                }
            }
        }
        arg_nb += 1;
    }

    // The welcome line (`-v`).
    ctx.display(3, m::WELCOME, &[env!("CARGO_PKG_VERSION").as_bytes()]);

    if op == Operation::Decompress && nb_workers > 1 {
        ctx.display(2, m::DECOMPRESS_NO_MT, &[]);
    }
    if nb_workers == 0 && !single_thread {
        if default_logical {
            nb_workers = cores.logical as i32;
            ctx.display(3, m::LOGICAL_CORES, &[nb_workers.to_string().as_bytes()]);
        } else {
            nb_workers = cores.physical as i32;
            ctx.display(3, m::PHYSICAL_CORES, &[nb_workers.to_string().as_bytes()]);
        }
    }
    if nb_workers == -1 {
        nb_workers = if op == Operation::Decompress {
            1
        } else {
            default_nb_threads(env, cores, &mut ctx) as i32
        };
    }
    ctx.display(
        4,
        m::COMPRESSING_WITH,
        &[(nb_workers as u32).to_string().as_bytes()],
    );

    prefs.workers = nb_workers;
    prefs.job_size = block_size;
    prefs.overlap_log = (g.overlap_log != OVERLAP_LOG_DEFAULT).then_some(g.overlap_log);
    prefs.adapt = adapt;
    prefs.adapt_min = adapt_min;
    prefs.adapt_max = adapt_max;
    prefs.rsyncable = rsyncable;
    prefs.ldm = ldm_flag;
    prefs.ldm_hash_log = g.ldm_hash_log;
    prefs.ldm_min_match = g.ldm_min_match;
    prefs.ldm_bucket_size_log =
        (g.ldm_bucket_size_log != LDM_PARAM_DEFAULT).then_some(g.ldm_bucket_size_log);
    prefs.ldm_hash_rate_log =
        (g.ldm_hash_rate_log != LDM_PARAM_DEFAULT).then_some(g.ldm_hash_rate_log);
    prefs.stream_size = stream_size;
    prefs.target_cblock_size = target_cblock;
    prefs.size_hint = size_hint.min(i32::MAX as u64) as i32;
    prefs.literal_compression = literals;
    prefs.row_match_finder = row_match_finder;
    prefs.mmap_dict = mmap_dict;
    prefs.content_size = content_size;
    prefs.progress = progress;
    prefs.ctype = ctype;
    prefs.memory_limit = mem_limit;
    prefs.remove_src = remove_src;
    let train = (op == Operation::Train).then_some(TrainCmd {
        dict,
        cover,
        fastcover,
        selectivity: dict_select,
        max_dict,
        dict_id,
        level: dict_clevel,
    });
    Ok(Command {
        op,
        prefs,
        level,
        ultra,
        files,
        out_file,
        out_dir_flat,
        out_dir_mirror,
        dict_file,
        patch_from,
        suffix,
        recursive,
        follow_links,
        force_stdin,
        force_stdout,
        display_level: ctx.level,
        cparams_overrides: CPARAM_KEYS
            .iter()
            .zip(params)
            .filter(|&(_, v)| v != 0)
            .map(|(&k, v)| (k, v))
            .collect(),
        train,
        show_default_cparams,
        filelists,
        main_pause,
        nb_input_files: 0,
        limits: None,
    })
}

/// What a long option with a value did.
enum Long {
    Handled,
    /// Not an option zstd knows, or a malformed value: badUsage.
    Bad,
}

/// The `main` locals the long options with values set.
struct LongState<'a> {
    prefs: &'a mut Prefs,
    op: &'a mut Operation,
    out_file: &'a mut Option<Vec<u8>>,
    out_dir_flat: &'a mut Option<Vec<u8>>,
    out_dir_mirror: &'a mut Option<Vec<u8>>,
    patch_from: &'a mut Option<Vec<u8>>,
    filelists: &'a mut Vec<Vec<u8>>,
    suffix: &'a mut &'static str,
    ctype: &'a mut CType,
    adapt: &'a mut bool,
    adapt_min: &'a mut i32,
    adapt_max: &'a mut i32,
    nb_workers: &'a mut i32,
    single_thread: &'a mut bool,
    mmap_dict: &'a mut ParamSwitch,
    level: &'a mut i32,
    dict_clevel: &'a mut i32,
    rsyncable: &'a mut bool,
    literals: &'a mut ParamSwitch,
    progress: &'a mut Progress,
    ultra: &'a mut bool,
    ldm_flag: &'a mut bool,
    params: &'a mut [u32; 7],
    g: &'a mut LdmGlobals,
    cover: &'a mut TrainAlgo,
    fastcover: &'a mut TrainAlgo,
    dict: &'a mut DictType,
    dict_select: &'a mut u32,
    mem_limit: &'a mut u32,
    block_size: &'a mut u64,
    max_dict: &'a mut u32,
    dict_id: &'a mut u32,
    stream_size: &'a mut u64,
    target_cblock: &'a mut u64,
    size_hint: &'a mut u64,
    default_logical: &'a mut bool,
    main_pause: bool,
}

/// [`long_with_value`]'s inputs.
struct LongCtx<'a, 'c> {
    ctx: &'a mut Ctx<'c>,
    arg: &'a [u8],
    args: &'a [Vec<u8>],
    arg_nb: &'a mut usize,
    program: &'a str,
    st: LongState<'a>,
}

/// zstdcli.c: main, the long options after the exact-match ones, in its
/// order: `--adapt=`, the format and switch options, `--max`, the
/// `--train-*` family, the options taking a value, `--long`, `--fast`,
/// `--filelist`.
fn long_with_value(l: LongCtx) -> Result<Long, Stop> {
    let LongCtx {
        ctx,
        arg,
        args,
        arg_nb,
        program,
        st,
    } = l;
    let pause = st.main_pause;
    let clean = |code| Stop {
        code,
        clean: true,
        pause,
    };
    if let Some(rest) = long_arg(arg, "--adapt=") {
        *st.adapt = true;
        return Ok(if parse_adapt(ctx, rest, st.adapt_min, st.adapt_max)? {
            Long::Handled
        } else {
            Long::Bad
        });
    }
    let gz = exe_name_match(program, "gzip");
    match arg {
        b"--single-thread" => {
            *st.nb_workers = 0;
            *st.single_thread = true;
        }
        b"--format=zstd" => {
            *st.suffix = ".zst";
            *st.ctype = CType::Zstd;
        }
        b"--mmap-dict" => *st.mmap_dict = ParamSwitch::Enable,
        b"--no-mmap-dict" => *st.mmap_dict = ParamSwitch::Disable,
        b"--format=gzip" => {
            *st.suffix = ".gz";
            *st.ctype = CType::Gzip;
        }
        b"--best" if gz => {
            *st.level = 9;
            *st.dict_clevel = 9;
        }
        b"--no-name" if gz => {}
        b"--format=lzma" => {
            *st.suffix = ".lzma";
            *st.ctype = CType::Lzma;
        }
        b"--format=xz" => {
            *st.suffix = ".xz";
            *st.ctype = CType::Xz;
        }
        b"--format=lz4" => {
            *st.suffix = ".lz4";
            *st.ctype = CType::Lz4;
        }
        b"--rsyncable" => *st.rsyncable = true,
        b"--compress-literals" => *st.literals = ParamSwitch::Enable,
        b"--no-compress-literals" => *st.literals = ParamSwitch::Disable,
        b"--no-progress" => *st.progress = Progress::Never,
        b"--progress" => *st.progress = Progress::Always,
        b"--exclude-compressed" => st.prefs.exclude_compressed = true,
        b"--fake-stdin-is-console" => st.prefs.fake_stdin_console = true,
        b"--fake-stdout-is-console" => st.prefs.fake_stdout_console = true,
        b"--fake-stderr-is-console" => st.prefs.fake_stderr_console = true,
        b"--trace-file-stat" => st.prefs.trace_file_stat = true,
        b"--max" => {
            *st.ultra = true;
            *st.ldm_flag = true;
            // setMaxCompression, 64-bit limits.
            *st.params = [
                zstd_opts::WINDOWLOG_MAX,
                30,
                30,
                30,
                3,
                zstd_opts::BLOCKSIZE_MAX as u32,
                9,
            ];
            st.g.overlap_log = 9;
            st.g.ldm_hash_log = 30;
            st.g.ldm_hash_rate_log = 0;
            st.g.ldm_min_match = 16;
            st.g.ldm_bucket_size_log = 8;
        }
        _ => return long_with_value_2(ctx, arg, args, arg_nb, st, clean),
    }
    Ok(Long::Handled)
}

/// [`long_with_value`], from the `--train-*` family on.
fn long_with_value_2(
    ctx: &mut Ctx,
    arg: &[u8],
    args: &[Vec<u8>],
    arg_nb: &mut usize,
    st: LongState,
    clean: impl Fn(i32) -> Stop,
) -> Result<Long, Stop> {
    let pause = st.main_pause;
    let train = |op: &mut Operation, out: &mut Option<Vec<u8>>| {
        *op = Operation::Train;
        out.get_or_insert_with(|| DEFAULT_DICT_NAME.to_vec());
    };
    for (prefix, kind) in [
        ("--train-cover", DictType::Cover),
        ("--train-fastcover", DictType::FastCover),
        ("--train-legacy", DictType::Legacy),
    ] {
        let Some(rest) = long_arg(arg, prefix) else {
            continue;
        };
        train(st.op, st.out_file);
        *st.dict = kind;
        if rest.is_empty() {
            match kind {
                DictType::Cover => {
                    *st.cover = cover_algo(DictFields::default(), false);
                }
                DictType::FastCover => {
                    *st.fastcover = cover_algo(DictFields::default(), true);
                }
                DictType::Legacy => {}
            }
            return Ok(Long::Handled);
        }
        let Some(value) = rest.strip_prefix(b"=") else {
            return Ok(Long::Bad);
        };
        match kind {
            DictType::Cover | DictType::FastCover => {
                let fast = kind == DictType::FastCover;
                let Some(fields) = parse_cover(ctx, value, fast)? else {
                    return Ok(Long::Bad);
                };
                let slot = if fast {
                    &mut *st.fastcover
                } else {
                    &mut *st.cover
                };
                *slot = cover_algo(fields, fast);
            }
            DictType::Legacy => {
                // parseLegacyParameters.
                let mut p = if value.starts_with(b"s=") {
                    2
                } else if value.starts_with(b"selectivity=") {
                    12
                } else {
                    return Ok(Long::Bad);
                };
                *st.dict_select = ctx.read_u32(value, &mut p)?;
                if p != value.len() {
                    return Ok(Long::Bad);
                }
                ctx.display(
                    4,
                    m::LEGACY_PARAMS,
                    &[st.dict_select.to_string().as_bytes()],
                );
            }
        }
        return Ok(Long::Handled);
    }

    // NEXT_UINT32 / NEXT_TSIZE.
    macro_rules! next_u32 {
        ($rest:expr) => {{
            let mut pos = arg.len() - $rest.len();
            let v = next_field(ctx, arg, &mut pos, args, arg_nb, pause)?;
            let mut p = 0;
            let n = ctx.read_u32(v, &mut p)?;
            whole_number(ctx, n, v, p)?
        }};
    }
    macro_rules! next_size {
        ($rest:expr) => {{
            let mut pos = arg.len() - $rest.len();
            let v = next_field(ctx, arg, &mut pos, args, arg_nb, pause)?;
            let mut p = 0;
            let n = ctx.read_size(v, &mut p)?;
            whole_number(ctx, n, v, p)?
        }};
    }
    macro_rules! next_text {
        ($rest:expr) => {{
            let mut pos = arg.len() - $rest.len();
            next_field(ctx, arg, &mut pos, args, arg_nb, pause)?
        }};
    }

    if let Some(rest) = long_arg(arg, "--threads") {
        *st.nb_workers = next_u32!(rest) as i32;
    } else if let Some(rest) = long_arg(arg, "--memlimit") {
        // Also `--memlimit-decompress`, which this prefix takes first.
        *st.mem_limit = next_u32!(rest);
    } else if let Some(rest) = long_arg(arg, "--memory") {
        *st.mem_limit = next_u32!(rest);
    } else if let Some(rest) = long_arg(arg, "--block-size") {
        *st.block_size = next_size!(rest);
    } else if let Some(rest) = long_arg(arg, "--maxdict") {
        *st.max_dict = next_u32!(rest);
    } else if let Some(rest) = long_arg(arg, "--dictID") {
        *st.dict_id = next_u32!(rest);
    } else if let Some(rest) = long_arg(arg, "--zstd=") {
        if !parse_cparams(ctx, rest, st.params, st.g)? {
            return Ok(Long::Bad);
        }
        *st.ctype = CType::Zstd;
    } else if let Some(rest) = long_arg(arg, "--stream-size") {
        *st.stream_size = next_size!(rest);
    } else if let Some(rest) = long_arg(arg, "--target-compressed-block-size") {
        *st.target_cblock = next_size!(rest);
    } else if let Some(rest) = long_arg(arg, "--size-hint") {
        *st.size_hint = next_size!(rest);
    } else if let Some(rest) = long_arg(arg, "--output-dir-flat") {
        let v = next_text!(rest);
        if v.is_empty() {
            ctx.display(1, m::EMPTY_OUTPUT_DIR, &[]);
            return Err(clean(1));
        }
        *st.out_dir_flat = Some(v.to_vec());
    } else if let Some(rest) = long_arg(arg, "--auto-threads") {
        let v = next_text!(rest);
        if v == b"logical" {
            *st.default_logical = true;
        }
    } else if let Some(rest) = long_arg(arg, "--output-dir-mirror").filter(|_| !cfg!(windows)) {
        let v = next_text!(rest);
        if v.is_empty() {
            ctx.display(1, m::EMPTY_OUTPUT_DIR, &[]);
            return Err(clean(1));
        }
        *st.out_dir_mirror = Some(v.to_vec());
    } else if let Some(rest) = long_arg(arg, "--patch-from") {
        *st.patch_from = Some(next_text!(rest).to_vec());
        *st.ultra = true;
    } else if let Some(rest) = long_arg(arg, "--long") {
        *st.ldm_flag = true;
        *st.ultra = true;
        let window_log = if let Some(v) = rest.strip_prefix(b"=") {
            let mut p = 0;
            ctx.read_u32(v, &mut p)?
        } else if !rest.is_empty() {
            return Ok(Long::Bad);
        } else {
            DEFAULT_MAX_WINDOW_LOG
        };
        if st.params[0] == 0 {
            st.params[0] = window_log;
        }
    } else if let Some(rest) = long_arg(arg, "--fast") {
        if let Some(v) = rest.strip_prefix(b"=") {
            let max_fast = zstd_opts::MIN_CLEVEL.unsigned_abs();
            let mut p = 0;
            let fast = ctx.read_u32(v, &mut p)?.min(max_fast);
            if fast == 0 {
                return Ok(Long::Bad);
            }
            *st.level = -(fast as i32);
            *st.dict_clevel = *st.level;
        } else if !rest.is_empty() {
            return Ok(Long::Bad);
        } else {
            *st.level = -1;
        }
    } else if let Some(rest) = long_arg(arg, "--filelist") {
        st.filelists.push(next_text!(rest).to_vec());
    } else {
        return Ok(Long::Bad);
    }
    Ok(Long::Handled)
}

/// The [`TrainAlgo`] for a cover (`fast`: fastcover) parameter set.
fn cover_algo(f: DictFields, fast: bool) -> TrainAlgo {
    if fast {
        TrainAlgo::Fastcover {
            k: f.k,
            d: f.d,
            f: f.f,
            steps: f.steps,
            split: f.split,
            accel: f.accel,
            shrink: f.shrink,
        }
    } else {
        TrainAlgo::Cover {
            k: f.k,
            d: f.d,
            steps: f.steps,
            split: f.split,
            shrink: f.shrink,
        }
    }
}

/// zstdcli.c: usage, to `f` (standard output for `-h`, standard error
/// after an incorrect parameter).
pub(crate) fn usage(f: &mut dyn Write, program: &str) {
    printf(f, m::USAGE_HEAD, &[program.as_bytes()]);
    if exe_name_match(program, "gzip") {
        printf(f, m::USAGE_GZ_NO_NAME, &[]);
    }
    printf(
        f,
        m::USAGE_TAIL,
        &[
            CLEVEL_MAX.to_string().as_bytes(),
            CLEVEL_DEFAULT.to_string().as_bytes(),
        ],
    );
}

/// zstdcli.c: usageAdvanced (`-H`, `--help`), for a build with
/// `ZSTD_NOBENCH` and `ZSTD_NOTRACE` (R13).
pub(crate) fn usage_advanced(out: &mut dyn Write, program: &str) {
    printf(out, m::WELCOME, &[env!("CARGO_PKG_VERSION").as_bytes()]);
    printf(out, m::ADV_AFTER_BANNER, &[]);
    usage(out, program);
    printf(out, m::ADV_OPTIONS, &[]);
    printf(out, m::ADV_FILELIST, &[]);
    if !cfg!(windows) {
        printf(out, m::ADV_MIRROR, &[]);
    }
    printf(out, m::ADV_ASYNCIO, &[]);
    printf(out, m::ADV_CHECK, &[]);
    let n = |v: i64| v.to_string();
    printf(
        out,
        m::ADV_COMPRESSION,
        &[
            n(CLEVEL_MAX.into()).as_bytes(),
            n(zstd_opts::MAX_CLEVEL.into()).as_bytes(),
            b"1",
        ],
    );
    if exe_name_match(program, "gzip") {
        printf(out, m::ADV_GZ_BEST, &[]);
    }
    printf(
        out,
        m::ADV_COMPRESSION_REST,
        &[n(DEFAULT_MAX_WINDOW_LOG.into()).as_bytes()],
    );
    printf(out, m::ADV_DECOMPRESSION, &[]);
    printf(
        out,
        if SPARSE_DEFAULT != 0 {
            m::ADV_SPARSE_ON
        } else {
            m::ADV_SPARSE_OFF
        },
        &[],
    );
    let cat = ["zstdcat", "zcat", "gzcat"]
        .iter()
        .any(|c| exe_name_match(program, c));
    printf(
        out,
        m::ADV_PASS_THROUGH,
        &[if cat { m::ENABLED } else { m::DISABLED }.as_bytes()],
    );
    printf(
        out,
        m::ADV_DICTIONARY,
        &[
            n(DEFAULT_SELECTIVITY.into()).as_bytes(),
            DEFAULT_DICT_NAME,
            n(DEFAULT_MAX_DICT_SIZE.into()).as_bytes(),
        ],
    );
}

/// zstdcli.c's `_POSIX_C_SOURCE` as printVersion sees it: platform.h
/// defines it as `200809L` on Linux (and Cygwin) when the build has not;
/// elsewhere it is not defined.
#[cfg(any(target_os = "linux", target_os = "android"))]
const POSIX_C_SOURCE: Option<i64> = Some(200809);
/// zstdcli.c's `_POSIX_C_SOURCE`: not defined off Linux.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const POSIX_C_SOURCE: Option<i64> = None;

/// `_POSIX_VERSION` from the system's `<unistd.h>`: 200112L on Apple's
/// platforms (observed: zstd 1.5.7 on macOS prints it), 200809L from glibc
/// under `_POSIX_C_SOURCE 200809L` and from the BSDs' headers; Windows has
/// none.
#[cfg(target_vendor = "apple")]
const POSIX_VERSION: Option<i64> = Some(200112);
/// `_POSIX_VERSION` (see above).
#[cfg(all(unix, not(target_vendor = "apple")))]
const POSIX_VERSION: Option<i64> = Some(200809);
/// `_POSIX_VERSION` (see above).
#[cfg(not(unix))]
const POSIX_VERSION: Option<i64> = None;

/// platform.h's `PLATFORM_POSIX_VERSION`: forced to 200112L on Apple's
/// platforms, `_POSIX_VERSION` on the other unix systems, 0 on Windows.
#[cfg(unix)]
const PLATFORM_POSIX_VERSION: i64 = match POSIX_VERSION {
    Some(v) => v,
    None => 1,
};
/// platform.h's `PLATFORM_POSIX_VERSION` (see above).
#[cfg(not(unix))]
const PLATFORM_POSIX_VERSION: i64 = 0;

/// zstdcli.c: printVersion at display level `level`: the version alone
/// below the default level, the banner from it, the formats line from 3,
/// and from 4 the POSIX lines. The three library-version lines zstd
/// prints first at level 4 (the zlib, lz4 and lzma it links) describe
/// zstd's own build and are not printed (spec deviation 1, ruling T4-a).
pub(crate) fn print_version(out: &mut dyn Write, level: i32) {
    if level < DISPLAY_LEVEL_DEFAULT {
        printf(out, m::VERSION_ONLY, &[m::VERSION_STRING.as_bytes()]);
        return;
    }
    printf(out, m::WELCOME, &[env!("CARGO_PKG_VERSION").as_bytes()]);
    if level >= 3 {
        printf(out, m::SUPPORTS, &[]);
        if level >= 4 {
            if let Some(v) = POSIX_C_SOURCE {
                printf(out, m::POSIX_C_SOURCE, &[v.to_string().as_bytes()]);
            }
            if let Some(v) = POSIX_VERSION {
                printf(out, m::POSIX_VERSION, &[v.to_string().as_bytes()]);
            }
            printf(
                out,
                m::PLATFORM_POSIX_VERSION,
                &[PLATFORM_POSIX_VERSION.to_string().as_bytes()],
            );
        }
    }
}

/// zstdcli.c: printDefaultCParams: `name` (as printed), its size (`None`:
/// unknown, `UTIL_FILESIZE_UNKNOWN`), the dictionary's size (`u64::MAX`
/// for a dictionary file whose size is unknown, as zstd passes it on).
pub(crate) fn print_default_cparams(
    err: &mut dyn Write,
    name: &[u8],
    size: Option<u64>,
    dict_size: u64,
    level: i32,
) {
    let c = zstd_opts::default_cparams(level, size, dict_size as usize);
    match size {
        Some(s) => printf(err, m::CPARAMS_SIZE, &[name, s.to_string().as_bytes()]),
        None => printf(err, m::CPARAMS_UNKNOWN, &[name]),
    }
    let strat = c.strategy as u32;
    let v = [
        c.window_log,
        c.chain_log,
        c.hash_log,
        c.search_log,
        c.min_match,
        c.target_length,
    ]
    .map(|x| x.to_string());
    let s = strat.to_string();
    printf(
        err,
        m::CPARAMS_LINES,
        &[
            v[0].as_bytes(),
            v[1].as_bytes(),
            v[2].as_bytes(),
            v[3].as_bytes(),
            v[4].as_bytes(),
            v[5].as_bytes(),
            m::STRATEGY_MAP[strat as usize].as_bytes(),
            s.as_bytes(),
        ],
    );
}

/// zstdcli.c: printActualCParams (display level 4): the level's defaults
/// for the sizes, each overridden by a non-zero `--zstd=` value, printed
/// as `%d` (so a value past `INT_MAX` prints negative, as in zstd).
pub(crate) fn print_actual_cparams(
    err: &mut dyn Write,
    size: Option<u64>,
    dict_size: u64,
    level: i32,
    cmd: &Command,
) {
    let c = zstd_opts::default_cparams(level, size, dict_size as usize);
    let pick = |key, default: u32| match cmd.cparam(key) {
        0 => default,
        v => v,
    };
    let v = [
        pick(CParamKey::WindowLog, c.window_log),
        pick(CParamKey::ChainLog, c.chain_log),
        pick(CParamKey::HashLog, c.hash_log),
        pick(CParamKey::SearchLog, c.search_log),
        pick(CParamKey::MinMatch, c.min_match),
        pick(CParamKey::TargetLength, c.target_length),
        pick(CParamKey::Strategy, c.strategy as u32),
    ]
    .map(|x| (x as i32).to_string());
    let args: Vec<&[u8]> = v.iter().map(|s| s.as_bytes()).collect();
    printf(err, m::ACTUAL_CPARAMS, &args);
}

#[cfg(test)]
mod tests;
