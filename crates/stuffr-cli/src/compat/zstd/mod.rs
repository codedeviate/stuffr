//! The zstd family (`zstd`, `unzstd`, `zstdcat`, `zstdmt`): stuffr
//! behaving as zstd 1.5.7's command line tool.
//!
//! Ported from zstd 1.5.7 `programs/` by Yann Collet and the zstd
//! contributors (Meta Platforms, Inc.; BSD-3-Clause, the licence ships as
//! `LICENSE-zstd`), one module per C file: `cli.rs` (zstdcli.c's argument
//! parsing, help texts and parameter printers), `util.rs` (util.c),
//! `display.rs` (fileio_common.h's display macros) and this module
//! (zstdcli.c's `main` after the arguments). Every string is in
//! `messages.rs`. libzstd itself is reached through
//! `stuffr::zstd_opts`.
//!
//! **Names** (spec section 1): the four map to this family, and the
//! presets come from the invoked name by zstdcli.c's `exeNameMatch` (the
//! name, then the end or a `.`): `unzstd` decompresses, `zstdcat`
//! decompresses to standard output with pass-through at display level 1,
//! `zstdmt` compresses with `-T0`. zstdcli.c's gzip, xz, lzma and lz4
//! presets are ported too, though dispatch never reaches them (those names
//! belong to other families).
//!
//! **The machine** (R3): the real process counts its cores as util.c does
//! (`util::Cores::detect`); a sandboxed run ([`run_in_counted`]) sees 8
//! logical and 4 physical cores.
//!
//! Known deviations (the source of truth; the README and the spec mirror
//! this list):
//!
//! 1. The banner names stuffr wherever zstd prints `WELCOME_MESSAGE`
//!    (`-V`, `-vV`, `-vvV`, the first line of `-H`, and `-v`'s welcome
//!    line on standard error): `*** Zstandard CLI (stuffr X.Y.Z; zstd
//!    1.5.7 compatible) (64-bit) v1.5.7, by Yann Collet ***`. `-qV` prints
//!    exactly `1.5.7`, and `-vV`'s "supports:" line is zstd's. `-vvV`
//!    prints zstd's POSIX lines for the platform, but not its three
//!    library-version lines (the zlib, lz4 and lzma zstd links), which
//!    describe zstd's own build.
//! 2. The `-v` summary's timing fields vary from run to run, as they do
//!    between two runs of zstd.
//! 3. An input that is also the output is never lost.
//! 4. Closed standard streams and a parent that ignores SIGPIPE: the Rust
//!    runtime reopens a closed standard descriptor on `/dev/null` and
//!    resets SIGPIPE before `main`, so neither is seen.
//! 5. Out of scope, refused as a zstd built with `ZSTD_NOBENCH` and
//!    `ZSTD_NOTRACE` refuses them: `-b`, `-e#`, `-i#` ("Incorrect
//!    parameter: -b", exit 1) and `--trace` ("Incorrect parameter:
//!    --trace"); `-H` omits their lines. `-B#`, `-S` and `-p#` keep the
//!    reference's meaning. `--[no-]asyncio` is accepted and has no visible
//!    effect. `--trace-file-stat` is accepted and prints no trace.
//!
//! Spec deviation 7, the pure tier (`zstd-pure` without `zstd-c`), as far
//! as compressing and decompressing go (`fileio.rs`):
//!
//! - Every level compresses with `ruzstd`'s `Fastest`, so the sizes and
//!   ratios in the summaries and in `-vvvvvv`'s trace are the tier's own;
//!   the reference decodes every frame. The compression parameters are
//!   range-checked as libzstd checks them, then ignored.
//! - Compressing with `-D` or `--patch-from` is refused, after everything
//!   zstd prints first: `zstd: error 1 : dictionary compression is not
//!   available in this build (stuffr pure tier)`.
//! - A legacy frame (v0.5 to v0.7) is `unsupported format`, what a zstd
//!   built without legacy support says.
//! - A corrupt frame whose blocks overflow the output libzstd sized from
//!   its header can be named `Data corruption detected` where libzstd says
//!   `Destination buffer is too small`.
//! - `--format=gzip|xz|lzma` write flate2's and `xz_opts`' pure encoders'
//!   bytes, which the reference decodes (compatible, not identical; the
//!   summaries' sizes are the tier's own).
//! - An xz or lzma frame that fails to decode (the xz family's P6 and P9):
//!   what is written before the error can be a strict prefix of what
//!   liblzma writes, and corruption in the last bytes of a `.lzma` reads as
//!   the input ending there (`premature lzma end`, the jobs before it
//!   written) where liblzma says `lzma_code decoding error 9`.
//!
//! The foreign formats on both tiers (`formats.rs`; spec "Promises"):
//! `--format=gzip` is zlib's bytes with `zlib-c`, `--format=xz|lzma`
//! liblzma's with `xz-c`; `--format=lz4` is compatible only on every tier:
//! `lz4_flex`'s fast compressor at every level, inside liblz4's frame
//! descriptor (64 KiB linked blocks, content size, content checksum as
//! fileio.c sets them). A gzip member's deflate data is decoded by flate2
//! on every tier, its header and trailer checked as zlib checks them.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use stuffr::zstd_opts::{self, CParamKey};

use super::CountedRun;
use super::host::{Host, SANDBOX_OUTPUT_CAP, Sandbox, reset_sigpipe};

pub(crate) mod cli;
pub(crate) mod display;
pub(crate) mod fileio;
mod formats;
mod messages;
pub(crate) mod util;

use cli::{Command, Limits, Operation, Progress, STDINMARK, STDOUTMARK, Stop};
use display::{Display, exm_throw};
use messages::{self as m, printf};
use util::Cores;

/// Entry point for the four names; `name` is the canonical invoked name,
/// `argv0` the program as invoked (its last component is zstd's
/// `programName`) and `args` the arguments after it.
pub fn run(name: &'static str, argv0: &OsStr, args: Vec<OsString>) -> ExitCode {
    // zstd dies of SIGPIPE writing to a closed pipe.
    reset_sigpipe();
    let argv0 = if argv0.is_empty() {
        name.as_bytes()
    } else {
        argv0.as_encoded_bytes()
    };
    let env = |k: &str| std::env::var_os(k);
    let mut err = io::stderr();
    let code = main(
        argv0,
        &args,
        &env,
        &mut Host::Real,
        Cores::detect(),
        None,
        &mut err,
    );
    // The process's exit status is the code's low byte, as `exit()` makes
    // it.
    ExitCode::from(code as u8)
}

/// [`run`] without the process: operands resolve against `dir`, standard
/// input is `stdin` (a pipe), standard output and error are captured and
/// returned with the exit code, neither is a terminal, `env` stands in for
/// the environment (`ZSTD_CLEVEL`, `ZSTD_NBTHREADS`) and `SIGPIPE` is left
/// alone. The machine is R3's fixed 8 logical and 4 physical cores.
///
/// R9's input-independent bounds hold whatever the arguments say: the
/// decoder's window log is at most 24 (16 MiB; a lower `--memory` or
/// `--long` stands), `--train*` loads at most 256 KiB of samples with at
/// most 4 optimiser steps, and compression runs at most 2 workers; xz and
/// lzma frames decode under a 256 MiB memory limit and compress at preset
/// 6 at most (`formats.rs`). Standard output and output files share the [`SANDBOX_OUTPUT_CAP`]
/// budget. No signal handler is installed. For the fuzz target; not a
/// stable interface.
#[doc(hidden)]
pub fn run_in_counted(
    dir: &Path,
    name: &'static str,
    args: &[OsString],
    stdin: &[u8],
    env: &dyn Fn(&str) -> Option<OsString>,
) -> CountedRun {
    let stdout = Arc::new(Mutex::new(Vec::new()));
    let reads = Arc::new(Mutex::new(BTreeMap::new()));
    let mut host = Host::Sandbox(Sandbox {
        dir: dir.to_path_buf(),
        stdin: Some(stdin.to_vec()),
        stdout: stdout.clone(),
        budget: Arc::new(AtomicU64::new(SANDBOX_OUTPUT_CAP)),
        reads: reads.clone(),
    });
    let mut err = Vec::new();
    let code = main(
        name.as_bytes(),
        args,
        env,
        &mut host,
        Cores::SANDBOX,
        Some(Limits::SANDBOX),
        &mut err,
    );
    drop(host);
    let out = std::mem::take(&mut *stdout.lock().unwrap_or_else(|p| p.into_inner()));
    let reads = std::mem::take(&mut *reads.lock().unwrap_or_else(|p| p.into_inner()));
    (code, out, err, reads)
}

/// zstdcli.c: main, below the process boundary. Returns the exit code.
fn main(
    argv0: &[u8],
    args: &[OsString],
    env: &dyn Fn(&str) -> Option<OsString>,
    host: &mut Host,
    cores: Cores,
    limits: Option<Limits>,
    err: &mut dyn Write,
) -> i32 {
    let program = String::from_utf8_lossy(cli::last_name_from_path(argv0)).into_owned();
    let mut out = host.out_writer(None);
    let stop = match cli::parse(&program, env, args, cores, &mut out, err) {
        Ok(mut cmd) => {
            cmd.limits = limits;
            execute(&mut cmd, host, &mut out, err)
        }
        Err(stop) => stop,
    };
    let _ = out.flush();
    if stop.clean && stop.pause {
        wait_enter(host, err);
    }
    stop.code
}

/// zstdcli.c: waitEnter, for `-p`.
fn wait_enter(host: &mut Host, err: &mut dyn Write) {
    printf(err, m::PRESS_ENTER, &[]);
    let mut byte = [0u8; 1];
    let _ = host.stdin().read(&mut byte);
}

/// Ruling P1 scaffolding: an operation whose task is not done yet, exit 1
/// (the message in debug builds only). Tasks 5-8 replace every call.
fn todo(err: &mut dyn Write, what: &str, task: &str) -> i32 {
    if cfg!(debug_assertions) {
        printf(err, m::TODO, &[what.as_bytes(), task.as_bytes()]);
    }
    1
}

/// UTIL_isLink and UTIL_isFIFO: whether `name` is a symbolic link (lstat)
/// that does not lead to a FIFO (stat). Never on Windows, as util.c.
fn is_link_not_fifo(host: &Host, name: &[u8]) -> bool {
    util::is_link(host, name) && !util::is_fifo(host, name)
}

/// UTIL_getFileSize: a regular file's size (following links), else
/// unknown.
fn file_size(host: &Host, name: &[u8]) -> Option<u64> {
    Some(util::file_size(host, name)).filter(|&s| s != util::FILESIZE_UNKNOWN)
}

/// An operation's result as `main` ends it: `CLEAN_RETURN` with the
/// result, or the `EXM_THROW` exit.
fn finish(r: fileio::Fio<i32>, pause: bool) -> Stop {
    match r {
        Ok(code) => Stop {
            code,
            clean: true,
            pause,
        },
        Err(fileio::Thrown(code)) => Stop {
            code,
            clean: false,
            pause,
        },
    }
}

/// zstdcli.c: main, from the symbolic-link filter to the operation.
fn execute(cmd: &mut Command, host: &mut Host, out: &mut dyn Write, err: &mut dyn Write) -> Stop {
    let pause = cmd.main_pause;
    let clean = |code| Stop {
        code,
        clean: true,
        pause,
    };
    let exit = |code| Stop {
        code,
        clean: false,
        pause,
    };
    let mut d = Display {
        level: cmd.display_level,
    };
    // g_utilDisplayLevel.
    cmd.prefs.util_level = cmd.display_level;
    let util_level = cmd.display_level;

    if !cmd.follow_links {
        let total = cmd.files.len();
        let mut kept = Vec::with_capacity(total);
        for name in std::mem::take(&mut cmd.files) {
            if is_link_not_fifo(host, &name) {
                d.at(2, err, m::SYMLINK_IGNORED, &[&name]);
            } else {
                kept.push(name);
            }
        }
        cmd.files = kept;
        if cmd.files.is_empty() && total > 0 {
            return clean(1);
        }
    }
    for list in std::mem::take(&mut cmd.filelists) {
        match util::names_from_file(host, &list, util_level, err) {
            Some(names) => cmd.files.extend(names),
            None => {
                d.at(1, err, m::ERROR_READING, &[&list]);
                return clean(1);
            }
        }
    }
    cmd.nb_input_files = cmd.files.len();
    if cmd.recursive {
        let names = std::mem::take(&mut cmd.files);
        cmd.files = util::expand_names(host, names, cmd.follow_links, util_level, err);
    }

    match cmd.op {
        Operation::List => return clean(todo(err, "--list", "7")),
        Operation::Train => return clean(todo(err, "--train", "8")),
        Operation::Test => {
            cmd.prefs.test_mode = true;
            cmd.out_file = Some(cli::NULMARK.to_vec());
            cmd.prefs.remove_src = false;
        }
        Operation::Compress | Operation::Decompress => {}
    }

    if cmd.files.is_empty() {
        if cmd.nb_input_files > 0 {
            d.at(1, err, m::NO_INPUT_LEFT, &[]);
            return clean(0);
        }
        cmd.files.push(STDINMARK.to_vec());
    }
    if cmd.files.len() == 1 && cmd.files[0] == STDINMARK && cmd.out_file.is_none() {
        cmd.out_file = Some(STDOUTMARK.to_vec());
    }

    let has_stdin = cmd.files.iter().any(|f| f == STDINMARK);
    if !cmd.force_stdin && has_stdin && (cmd.prefs.fake_stdin_console || host.stdin_is_tty()) {
        d.at(1, err, m::STDIN_CONSOLE, &[]);
        return clean(1);
    }
    if cmd.out_file.as_deref().is_none_or(|o| o == STDOUTMARK)
        && (cmd.prefs.fake_stdout_console || host.stdout_is_tty())
        && has_stdin
        && !cmd.force_stdout
        && cmd.op != Operation::Decompress
    {
        d.at(1, err, m::STDOUT_CONSOLE, &[]);
        return clean(1);
    }

    let max_level = if cmd.ultra {
        zstd_opts::MAX_CLEVEL
    } else {
        cli::CLEVEL_MAX
    };
    if cmd.level > max_level {
        d.at(
            2,
            err,
            m::LEVEL_REDUCED,
            &[max_level.to_string().as_bytes()],
        );
        cmd.level = max_level;
    }

    if cmd.show_default_cparams && cmd.op == Operation::Decompress {
        d.at(1, err, m::CPARAMS_DECOMPRESS, &[]);
        return clean(1);
    }
    if cmd.dict_file.is_some() && cmd.patch_from.is_some() {
        d.at(1, err, m::DICT_AND_PATCH, &[]);
        return clean(1);
    }
    if cmd.patch_from.is_some() && cmd.files.len() > 1 {
        d.at(1, err, m::PATCH_MULTIPLE, &[]);
        return clean(1);
    }

    let has_stdout = cmd.out_file.as_deref() == Some(STDOUTMARK);
    if has_stdout && d.level == 2 {
        d.level = 1;
    }
    cmd.display_level = d.level;
    let stderr_console = cmd.prefs.fake_stderr_console || host.stderr_is_tty();
    if !stderr_console && cmd.prefs.progress != Progress::Always {
        cmd.prefs.progress = Progress::Never;
    }
    if has_stdout && cmd.prefs.remove_src {
        d.at(3, err, m::SRC_KEPT_STDOUT, &[]);
        cmd.prefs.remove_src = false;
    }
    cmd.prefs.has_stdout_output = has_stdout;
    cmd.prefs.nb_files_total = cmd.files.len();
    cmd.prefs.has_stdin_input = has_stdin;
    cmd.prefs.patch_from_mode = cmd.patch_from.is_some();
    if cmd.prefs.memory_limit == 0 {
        let wlog = cmd.cparam(CParamKey::WindowLog);
        cmd.prefs.memory_limit = if wlog == 0 {
            1 << cli::DEFAULT_MAX_WINDOW_LOG
        } else {
            1u32 << (wlog & 31)
        };
    }
    if cmd.patch_from.is_some() {
        cmd.dict_file = cmd.patch_from.clone();
    }

    if cmd.op != Operation::Compress {
        if let Some(l) = cmd.limits {
            // R9: the decoder's window log at most 24.
            cmd.prefs.memory_limit = cmd.prefs.memory_limit.min(1 << l.window_log_max);
        }
        return finish(fileio::decompress_files(cmd, host, out, err), pause);
    }

    // FIO_setCompressionType .. FIO_setSparseWrite, with their messages.
    if let Some(l) = cmd.limits
        && cmd.prefs.workers > l.workers
    {
        // R9: at most 2 workers in the sandbox.
        cmd.prefs.workers = l.workers;
    }
    let workers = cmd.prefs.workers;
    // FIO_setBlockSize takes `(int)blockSize`.
    if cmd.prefs.job_size as i32 != 0 && workers == 0 {
        d.at(2, err, m::BLOCK_SIZE_USELESS, &[]);
    }
    if let Some(ovlog) = cmd.prefs.overlap_log
        && ovlog != 0
        && workers == 0
    {
        d.at(2, err, m::OVERLAP_LOG_USELESS, &[]);
    }
    if cmd.prefs.adapt && workers == 0 {
        return exit(exm_throw(&d, err, 1, m::ADAPT_SINGLE_THREAD.as_bytes()));
    }
    if cmd.prefs.rsyncable && workers == 0 {
        return exit(exm_throw(&d, err, 1, m::RSYNCABLE_SINGLE_THREAD.as_bytes()));
    }
    cmd.prefs.sparse = 0;
    if cmd.prefs.adapt_min > cmd.level {
        cmd.level = cmd.prefs.adapt_min;
    }
    if cmd.prefs.adapt_max < cmd.level {
        cmd.level = cmd.prefs.adapt_max;
    }

    if cmd.show_default_cparams || d.level >= 4 {
        let dict_size = cmd
            .dict_file
            .as_deref()
            .map_or(0, |f| file_size(host, f).unwrap_or(u64::MAX));
        for name in &cmd.files {
            let size = file_size(host, name);
            if cmd.show_default_cparams {
                cli::print_default_cparams(err, name, size, dict_size, cmd.level);
            }
            if d.level >= 4 {
                cli::print_actual_cparams(err, size, dict_size, cmd.level, cmd);
            }
        }
    }
    if d.level >= 4 {
        display_compression_parameters(cmd, err);
    }
    finish(fileio::compress_files(cmd, host, out, err), pause)
}

/// fileio.c: FIO_displayCompressionParameters (display level 4).
fn display_compression_parameters(cmd: &Command, err: &mut dyn Write) {
    let p = &cmd.prefs;
    let n = |v: i64| v.to_string();
    printf(
        err,
        m::DCP_FORMAT,
        &[m::FORMAT_OPTIONS[p.ctype.index()].as_bytes()],
    );
    printf(err, m::DCP_SPARSE[p.sparse.clamp(0, 2) as usize], &[]);
    if !p.dict_id {
        printf(err, m::DCP_NO_DICT_ID, &[]);
    }
    printf(err, m::DCP_CHECKSUM[p.checksum.clamp(0, 2) as usize], &[]);
    printf(
        err,
        m::DCP_BLOCK_SIZE,
        &[n(i64::from(p.job_size as i32)).as_bytes()],
    );
    if p.adapt {
        printf(
            err,
            m::DCP_ADAPT,
            &[
                n(p.adapt_min.into()).as_bytes(),
                n(p.adapt_max.into()).as_bytes(),
            ],
        );
    }
    printf(
        err,
        m::DCP_ROW_MATCH_FINDER[p.row_match_finder.value() as usize],
        &[],
    );
    if p.rsyncable {
        printf(err, m::DCP_RSYNCABLE, &[]);
    }
    if p.stream_size != 0 {
        printf(
            err,
            m::DCP_STREAM_SIZE,
            &[n((p.stream_size as u32).into()).as_bytes()],
        );
    }
    if p.size_hint != 0 {
        printf(err, m::DCP_SIZE_HINT, &[n(p.size_hint.into()).as_bytes()]);
    }
    if p.target_cblock_size != 0 {
        printf(
            err,
            m::DCP_TARGET_CBLOCK,
            &[n((p.target_cblock_size as u32).into()).as_bytes()],
        );
    }
    printf(
        err,
        m::DCP_LITERALS[p.literal_compression.value() as usize],
        &[],
    );
    let memory = if p.memory_limit != 0 {
        p.memory_limit
    } else {
        128 << 20
    };
    printf(err, m::DCP_MEMORY, &[n(memory.into()).as_bytes()]);
    printf(err, m::DCP_THREADS, &[n(p.workers.into()).as_bytes()]);
    if p.exclude_compressed {
        printf(err, m::DCP_EXCLUDE, &[]);
    }
    printf(
        err,
        m::DCP_CONTENT_SIZE,
        &[if p.content_size { "" } else { m::DCP_NO }.as_bytes()],
    );
}

#[cfg(test)]
mod tests;
