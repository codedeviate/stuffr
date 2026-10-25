//! Peak memory for `stuffr bench`, measured in untimed child processes.
//!
//! After a row's timed runs, the parent runs the row once more, once for
//! compression and once for decompression, each in a child: bench's own
//! executable re-run as `stuffr __bench-memory-child <job>` (see
//! [`ChildJob::to_args`]). `getrusage`'s `ru_maxrss` is a per-process
//! high-water mark, which is why each measurement needs a fresh process,
//! and why one per file in `--per-file` mode (the row reports the largest).
//!
//! **What a child measures.** Its 64 KiB read buffer, its 64 KiB output
//! buffer and its open files (the compress child's output file included)
//! are made first; then it samples its peak resident set as the baseline (the
//! high-water so far, which is its current size, since nothing has run
//! yet), runs the codec to the end, and reports the peak minus that
//! baseline, saturating at 0. So the number is the codec's resident working
//! memory plus a few small fixed buffers; memory reserved but never touched
//! does not count. The compress child streams the input from the files
//! (each read stops at the length snapshotted at load, as in the timed
//! runs), so an encoder that buffers its whole input (the pure-tier zstd
//! encoder) shows memory growing with the input: that is what using it
//! costs. The compress child writes its compressed output to a guarded
//! temp file the parent created and armed, `stuffr-bench-<pid>-<n>`; the
//! decompress child then reads that file through the same 64 KiB buffered
//! source the timed runs use. So the row is compressed once more, not
//! twice (ruling F8), and a compress child that fails leaves nothing for
//! the decompress side, which then shows `-` too.
//!
//! **Same conditions as the timed runs**: level, `--threads` (through
//! [`governor_for`]) and `--memory-limit`. The backend is not sent: the
//! child is the same executable, so it has the same one.
//!
//! **The wire.** The child prints one line on stdout, `ok <bytes>` or
//! `err <text>`, and exits 0 or 1 to match. Anything else (a crash, a
//! signal, no line) is a failed measurement. A failure never fails the row:
//! its cell is `-` and the text goes to [`Memory::error`]. A refusal by
//! `--memory-limit` (an `Error::ResourceLimit`) reads `refused by
//! --memory-limit: …`, so it is told apart from a crash.
//!
//! A debug build's child refuses, as `bench` does, so this path is not
//! reachable from the CLI tests; [`Runner`] lets the parent's logic be
//! tested with a fake, and [`child_main`] is tested in-process.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};

use stuffr::source::{GuardedSeek, Source};
use stuffr::{Codec, DecodeOpts, EncodeOpts, Error, FormatKind};

use super::measure::{
    CHUNK, Mode, Plan, Snapshot, TempOut, fill, governor_for, read_some, shrank, temp_source,
};
use super::score::Memory;

/// The hidden first argument that makes the binary a memory child. Not a
/// clap subcommand: `main` checks for it before clap parses, so it is in no
/// help text and the examples page's guard (which walks clap) never sees it.
pub const CHILD_ARG: &str = "__bench-memory-child";

/// What a debug build's child answers: its numbers would be meaningless.
const DEBUG_CHILD_REFUSAL: &str = "memory runs from a debug build are meaningless";

/// The pid of the memory child the parent is waiting for, 0 when none. Set
/// once the child is spawned, cleared once it has been waited for; the
/// signal cleanup reads it to kill the child before bench dies.
pub static RUNNING_CHILD: AtomicI32 = AtomicI32::new(0);

/// Which half of the round trip a child measures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Compress,
    Decompress,
}

impl Side {
    fn word(self) -> &'static str {
        match self {
            Side::Compress => "compress",
            Side::Decompress => "decompress",
        }
    }
}

/// What one child runs. Compress: `files` concatenated as one stream,
/// written to `out` (discarded when `None`). Decompress: exactly one file,
/// the compressed copy; `out` is `None`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChildJob {
    pub side: Side,
    pub codec: &'static str,
    pub level: Option<i32>,
    pub threads: Option<usize>,
    pub memory_limit: u64,
    pub out: Option<PathBuf>,
    pub files: Vec<Snapshot>,
}

/// `-` for an absent level or thread count on the wire.
const NONE: &str = "-";

impl ChildJob {
    /// The arguments after [`CHILD_ARG`]:
    /// `<side> <codec> <level|-> <threads|-> <memory-limit> <out|-> [<len> <path>]…`,
    /// `side` being `compress` or `decompress`, every number in decimal.
    /// The decompress side ignores the level (the parent sends `-`). `out`
    /// is `-` for none; the parent's is always an absolute temp path.
    /// Paths go as they are (not through UTF-8), each its own argument.
    pub fn to_args(&self) -> Vec<OsString> {
        let opt = |v: Option<String>| OsString::from(v.unwrap_or_else(|| NONE.to_string()));
        let mut args = vec![
            OsString::from(self.side.word()),
            OsString::from(self.codec),
            opt(self.level.map(|l| l.to_string())),
            opt(self.threads.map(|t| t.to_string())),
            OsString::from(self.memory_limit.to_string()),
            self.out
                .clone()
                .map_or_else(|| OsString::from(NONE), PathBuf::into_os_string),
        ];
        for s in &self.files {
            args.push(OsString::from(s.len.to_string()));
            args.push(s.path.clone().into_os_string());
        }
        args
    }

    /// Parses [`ChildJob::to_args`]'s form back. The codec must be one of
    /// this build's.
    pub fn from_args(args: &[OsString]) -> Result<Self, String> {
        fn text<'a>(a: Option<&'a OsString>, what: &str) -> Result<&'a str, String> {
            a.ok_or_else(|| format!("missing {what}"))?
                .to_str()
                .ok_or_else(|| format!("{what} is not UTF-8"))
        }
        fn num<T: std::str::FromStr>(s: &str, what: &str) -> Result<T, String> {
            s.parse().map_err(|_| format!("bad {what} `{s}`"))
        }
        fn opt<T: std::str::FromStr>(s: &str, what: &str) -> Result<Option<T>, String> {
            if s == NONE {
                Ok(None)
            } else {
                num(s, what).map(Some)
            }
        }
        let mut it = args.iter();
        let side = match text(it.next(), "side")? {
            "compress" => Side::Compress,
            "decompress" => Side::Decompress,
            other => return Err(format!("bad side `{other}`")),
        };
        let codec = codec_id(text(it.next(), "codec")?)?.as_str();
        let level = opt(text(it.next(), "level")?, "level")?;
        let threads = opt(text(it.next(), "threads")?, "threads")?;
        let memory_limit = num(text(it.next(), "memory limit")?, "memory limit")?;
        let out = it.next().ok_or("missing output")?;
        let out = (out != NONE).then(|| PathBuf::from(out));
        let mut files = Vec::new();
        while let Some(len) = it.next() {
            let len = num(text(Some(len), "length")?, "length")?;
            let path = it.next().ok_or("a length without its path")?;
            files.push(Snapshot {
                path: path.into(),
                len,
            });
        }
        Ok(Self {
            side,
            codec,
            level,
            threads,
            memory_limit,
            out,
            files,
        })
    }

    /// The plan the timed runs used, as far as a child needs it.
    fn plan(&self) -> Plan {
        Plan {
            mode: Mode::OneStream,
            repeat: 1,
            threads: self.threads,
            memory_limit: self.memory_limit,
        }
    }
}

/// `name` as this build's codec id.
fn codec_id(name: &str) -> Result<stuffr::FormatId, String> {
    stuffr::registry()
        .matrix()
        .into_iter()
        .find(|r| r.kind == FormatKind::Codec && r.id.as_str() == name)
        .map(|r| r.id)
        .ok_or_else(|| format!("`{name}` is not a codec in this build"))
}

/// A child's stdout line: `Some(Ok(n))` for `ok <n>`, `Some(Err(text))` for
/// `err <text>` (text not empty), `None` for anything else.
pub fn parse_reply(stdout: &[u8]) -> Option<Result<u64, String>> {
    let line = std::str::from_utf8(stdout).ok()?.lines().next()?;
    if let Some(n) = line.strip_prefix("ok ") {
        if !n.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        return n.parse().ok().map(Ok);
    }
    let text = line.strip_prefix("err ")?.trim();
    (!text.is_empty()).then(|| Err(text.to_string()))
}

/// A child's result as its one stdout line (no newline inside).
fn reply_line(r: &Result<u64, String>) -> String {
    match r {
        Ok(n) => format!("ok {n}"),
        Err(e) => format!("err {}", e.replace(['\n', '\r'], " ")),
    }
}

/// How a measurement failure reads in `mem_error`: a refusal by
/// `--memory-limit` (`ResourceLimit`, which is also what an allocation
/// failure becomes) says so; everything else is its own message.
pub fn describe(e: &Error) -> String {
    match e {
        Error::ResourceLimit(s) => format!("refused by --memory-limit: {s}"),
        other => other.to_string(),
    }
}

/// A finished child: its reply when it gave a well-formed one and its exit
/// status agrees (0 for `ok`, failure for `err`); otherwise a failure
/// naming `status` and the first line of its stderr, if any.
pub fn interpret(success: bool, status: &str, stdout: &[u8], stderr: &[u8]) -> Result<u64, String> {
    match (parse_reply(stdout), success) {
        (Some(Ok(n)), true) => Ok(n),
        (Some(Err(e)), false) => Err(e),
        _ => {
            let why = String::from_utf8_lossy(stderr);
            match why.lines().map(str::trim).find(|l| !l.is_empty()) {
                Some(line) => Err(format!("the memory run failed ({status}): {line}")),
                None => Err(format!("the memory run failed ({status})")),
            }
        }
    }
}

/// The hidden entry `main` calls first: `None` unless `args[1]` is
/// [`CHILD_ARG`]; otherwise runs the child, prints its reply line and
/// returns its exit code. A debug build refuses.
pub fn child_entry(args: &[OsString]) -> Option<ExitCode> {
    if args.get(1).map(OsString::as_os_str) != Some(OsStr::new(CHILD_ARG)) {
        return None;
    }
    // A malformed job is a usage error (exit 2): exit 1 is reserved for
    // stuffr itself failing. The parent takes any non-zero exit with `err`.
    let (result, usage) = if cfg!(debug_assertions) {
        (Err(DEBUG_CHILD_REFUSAL.to_string()), None)
    } else {
        match ChildJob::from_args(&args[2..]) {
            Ok(job) => (child_main(job), None),
            Err(e) => (Err(e), Some(ExitCode::from(2))),
        }
    };
    let mut out = io::stdout().lock();
    let printed = writeln!(out, "{}", reply_line(&result)).and_then(|()| out.flush());
    Some(match usage {
        Some(code) => code,
        None if result.is_ok() && printed.is_ok() => ExitCode::SUCCESS,
        None => ExitCode::FAILURE,
    })
}

/// The child: runs `job` and returns its peak resident memory above the
/// baseline (see the module doc), in bytes.
pub fn child_main(job: ChildJob) -> Result<u64, String> {
    let reg = stuffr::registry();
    let id = codec_id(job.codec)?;
    match job.side {
        Side::Compress => {
            let codec = reg.require_encoder(id).map_err(|e| describe(&e))?;
            let encode = EncodeOpts {
                level: job.level,
                governor: governor_for(&job.plan()),
                ..Default::default()
            };
            codec.check_encode_opts(&encode).map_err(|e| describe(&e))?;
            compress_child(codec.as_ref(), &encode, &job.files, job.out.as_deref())
                .map_err(|e| describe(&e))
        }
        Side::Decompress => {
            let codec = reg.require_decoder(id).map_err(|e| describe(&e))?;
            let decode = DecodeOpts {
                memory_limit: Some(job.memory_limit),
                ..Default::default()
            };
            let [copy] = &job.files[..] else {
                return Err(format!(
                    "a decompress run takes one file, not {}",
                    job.files.len()
                ));
            };
            decompress_child(codec.as_ref(), &decode, copy).map_err(|e| describe(&e))
        }
    }
}

/// Streams `files` through the encoder into `out` (the parent's temp file,
/// which it already created: opened here, truncated), or into a discarding
/// sink when there is none.
fn compress_child(
    codec: &dyn Codec,
    encode: &EncodeOpts,
    files: &[Snapshot],
    out: Option<&Path>,
) -> stuffr::Result<u64> {
    let mut feeds = files
        .iter()
        .map(|s| s.open().map(|f| (s, f)))
        .collect::<io::Result<Vec<_>>>()?;
    let mut buf = vec![0u8; CHUNK];
    let dst: Box<dyn Write + Send> = match out {
        Some(path) => Box::new(File::options().write(true).truncate(true).open(path)?),
        None => Box::new(io::sink()),
    };
    let dst = BufWriter::with_capacity(CHUNK, dst);
    let baseline = baseline_rss()?;
    let mut sink = codec.encoder(Box::new(dst), encode)?;
    for (snap, f) in &mut feeds {
        feed(snap, f, &mut buf, &mut *sink)?;
    }
    sink.finish()?;
    Ok(peak_rss()?.saturating_sub(baseline))
}

/// Reads `copy` through the decoder to its end, discarding the output.
fn decompress_child(
    codec: &dyn Codec,
    decode: &DecodeOpts,
    copy: &Snapshot,
) -> stuffr::Result<u64> {
    let src: Box<dyn Source> = Box::new(temp_source(
        GuardedSeek::new(File::open(&copy.path)?),
        copy.len,
    ));
    let mut buf = vec![0u8; CHUNK];
    let baseline = baseline_rss()?;
    let mut decoder = codec.decoder(src, decode)?;
    while fill(&mut decoder, &mut buf).map_err(Error::from_decode_io)? == buf.len() {}
    drop(decoder);
    Ok(peak_rss()?.saturating_sub(baseline))
}

/// Writes all of `f` (`snap` opened) to `sink` through `buf`; a file that
/// ends short of its loaded length is an error, as in the timed runs.
fn feed(
    snap: &Snapshot,
    f: &mut io::Take<File>,
    buf: &mut [u8],
    sink: &mut dyn Write,
) -> stuffr::Result<()> {
    let mut read = 0u64;
    loop {
        let n = read_some(f, buf)?;
        if n == 0 {
            break;
        }
        read += n as u64;
        sink.write_all(&buf[..n])?;
    }
    if read < snap.len {
        return Err(shrank(snap, read));
    }
    Ok(())
}

/// Whether this platform's memory figures have been verified: macOS
/// (`ru_maxrss`) and Linux (`/proc/self/status`). Elsewhere (the BSDs, and
/// off unix) bench reports memory as not measured (ruling F9).
pub const MEASURES: bool = cfg!(any(target_vendor = "apple", target_os = "linux"));

/// The resident size just before the codec starts, in bytes.
///
/// macOS: `ru_maxrss`, the high-water so far, which is the current size
/// since nothing has run yet. Linux: `VmRSS` from `/proc/self/status`, not
/// `ru_maxrss`: exec copies the spawning process's high-water mark into the
/// new image's `ru_maxrss` (fs/exec.c, `setmax_mm_hiwater_rss`), so there it
/// starts at bench's own lifetime peak and would swallow the codec's.
fn baseline_rss() -> io::Result<u64> {
    #[cfg(target_os = "linux")]
    {
        proc_status_bytes(b"VmRSS:")
    }
    #[cfg(not(target_os = "linux"))]
    {
        peak_rss()
    }
}

/// The address space's peak resident size so far, in bytes. macOS:
/// `ru_maxrss` (bytes there). Linux: `VmHWM` from `/proc/self/status`, the
/// high-water of this address space only, fresh at exec.
#[cfg(target_vendor = "apple")]
fn peak_rss() -> io::Result<u64> {
    // SAFETY: `getrusage` only writes the `rusage` it is given, which is
    // plain data and valid zeroed.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: as above; `usage` is a valid, writable `rusage`.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(u64::try_from(usage.ru_maxrss).unwrap_or(0))
}

#[cfg(target_os = "linux")]
fn peak_rss() -> io::Result<u64> {
    proc_status_bytes(b"VmHWM:")
}

/// Elsewhere memory is not measured; bench never starts a child there.
#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn peak_rss() -> io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "memory is not measured on this platform",
    ))
}

/// `field` (with its colon, e.g. `VmHWM:`) of `/proc/self/status`, given
/// there in kB, as bytes. Read into a buffer on the stack, so sampling
/// allocates nothing on the heap that the codec's figure could include.
#[cfg(target_os = "linux")]
fn proc_status_bytes(field: &[u8]) -> io::Result<u64> {
    use std::io::Read;
    let mut buf = [0u8; 8192];
    let mut f = File::open("/proc/self/status")?;
    let mut len = 0;
    while len < buf.len() {
        match f.read(&mut buf[len..]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    status_field_kib(&buf[..len], field)
        .map(|kib| kib.saturating_mul(1024))
        .ok_or_else(|| io::Error::other("no memory figure in /proc/self/status"))
}

/// The number on the line starting with `field` in a `/proc/<pid>/status`
/// text (`VmHWM:\t   1234 kB`), in kB.
#[cfg(any(target_os = "linux", test))]
fn status_field_kib(text: &[u8], field: &[u8]) -> Option<u64> {
    let line = text.split(|&b| b == b'\n').find(|l| l.starts_with(field))?;
    let rest = line[field.len()..].trim_ascii_start();
    let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    rest[..digits].iter().try_fold(0u64, |n, &b| {
        n.checked_mul(10)?.checked_add(u64::from(b - b'0'))
    })
}

/// Runs one child job and returns its reply. The real one spawns a
/// process ([`ProcessRunner`]); tests inject a fake.
pub trait Runner {
    fn run(&mut self, job: &ChildJob) -> Result<u64, String>;
}

/// Runs each job as `<this executable> __bench-memory-child …`, with stdin
/// closed and stdout and stderr captured, keeping its pid in
/// [`RUNNING_CHILD`] while it runs. The executable is resolved once, when
/// the runner is made at the start of the run, and reused for every child.
pub struct ProcessRunner {
    exe: Result<PathBuf, String>,
}

impl Default for ProcessRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessRunner {
    pub fn new() -> Self {
        Self {
            exe: std::env::current_exe()
                .map_err(|e| format!("cannot find bench's own executable: {e}")),
        }
    }
}

impl Runner for ProcessRunner {
    fn run(&mut self, job: &ChildJob) -> Result<u64, String> {
        let exe = self.exe.clone()?;
        // Bench's signals are held back from the spawn until the pid is
        // stored, so a signal sent to bench alone in between is delivered
        // with the pid known, and the cleanup kills the child (no orphan).
        // The child does not inherit the mask: std resets it before exec.
        let child = crate::compat::with_run_signals_held(|| {
            let child = Command::new(exe)
                .arg(CHILD_ARG)
                .args(job.to_args())
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            RUNNING_CHILD.store(i32::try_from(child.id()).unwrap_or(0), Ordering::SeqCst);
            Ok::<_, io::Error>(child)
        })
        .map_err(|e| format!("cannot start the memory run: {e}"))?;
        // Known window, accepted (ruling F7): `wait_with_output` reaps the
        // child before the clear below, so a signal arriving in between
        // makes the cleanup `kill()` a pid that is no longer ours. It lasts
        // microseconds and pids are handed out sequentially, so reuse
        // inside it is theoretical. Clearing before the wait instead would
        // leave the child running (orphaned) on a bare SIGTERM to bench.
        let out = child.wait_with_output();
        RUNNING_CHILD.store(0, Ordering::SeqCst);
        let out = out.map_err(|e| format!("the memory run failed: {e}"))?;
        interpret(
            out.status.success(),
            &out.status.to_string(),
            &out.stdout,
            &out.stderr,
        )
    }
}

/// [`measure_memory_with`] with real child processes (`runner`). Only
/// where [`MEASURES`]: elsewhere the caller reports memory as not measured.
pub fn measure_memory(
    runner: &mut ProcessRunner,
    codec: &'static str,
    level: Option<i32>,
    plan: &Plan,
    input_files: &[Snapshot],
) -> Memory {
    measure_memory_with(runner, codec, level, plan, input_files)
}

/// One row's memory under `plan`: a compress child and a decompress child
/// per stream (`plan.mode`: one stream over every file, or one per file),
/// reporting each side's largest peak. Per stream the parent creates an
/// armed temp file, the compress child writes the compressed stream into
/// it, and the decompress child reads it back; it is removed before the
/// next stream begins. Strictly after the row's timed runs.
///
/// A side whose child fails for any stream is `None`, and the first
/// failure's text, prefixed by its side, is `error`. A failed decompress
/// child leaves the compress side standing; a failed compress child (or a
/// temp file that cannot be made) leaves no copy, so both sides are `None`.
/// Never an error of its own.
pub fn measure_memory_with(
    runner: &mut dyn Runner,
    codec: &'static str,
    level: Option<i32>,
    plan: &Plan,
    input_files: &[Snapshot],
) -> Memory {
    // bench always has at least one input; with none there is nothing to
    // measure, and a zero would wrongly win "least memory".
    if input_files.is_empty() {
        return Memory {
            error: Some("no input to measure".into()),
            ..Memory::default()
        };
    }
    let streams: Vec<&[Snapshot]> = match plan.mode {
        Mode::OneStream => vec![input_files],
        Mode::PerFile => input_files.chunks(1).collect(),
    };
    // The decompress side has no level: it is sent as `-`.
    let job = |side, out, files| ChildJob {
        side,
        codec,
        level: if side == Side::Compress { level } else { None },
        threads: plan.threads,
        memory_limit: plan.memory_limit,
        out,
        files,
    };
    let mut compress = Some(0u64);
    let mut decompress = Some(0u64);
    let mut error = None;
    let mut fail = |side: Side, e: String, cell: &mut Option<u64>| {
        *cell = None;
        error.get_or_insert_with(|| format!("{}: {e}", side.word()));
    };
    for files in streams {
        let Some(peak) = compress else { break };
        // The copy lives until this stream's decompress child is done; the
        // compress child opens it by name, so the parent's handle closes.
        let copy = match TempOut::create() {
            Ok((copy, _file)) => copy,
            Err(e) => {
                fail(
                    Side::Compress,
                    format!("cannot make the temp file: {e}"),
                    &mut compress,
                );
                decompress = None;
                break;
            }
        };
        let out = Some(copy.path().to_path_buf());
        match runner.run(&job(Side::Compress, out, files.to_vec())) {
            Ok(n) => compress = Some(peak.max(n)),
            Err(e) => {
                fail(
                    Side::Compress,
                    format!("{e} (so no decompress run)"),
                    &mut compress,
                );
                decompress = None;
                break;
            }
        }
        if let Some(peak) = decompress {
            let r = std::fs::metadata(copy.path())
                .map_err(|e| format!("cannot read the compressed copy: {e}"))
                .and_then(|m| {
                    let snap = Snapshot {
                        path: copy.path().to_path_buf(),
                        len: m.len(),
                    };
                    runner.run(&job(Side::Decompress, None, vec![snap]))
                });
            match r {
                Ok(n) => decompress = Some(peak.max(n)),
                Err(e) => fail(Side::Decompress, e, &mut decompress),
            }
        }
    }
    Memory {
        compress,
        decompress,
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A scratch directory `stuffr-benchmem-<pid>-<n>`, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("stuffr-benchmem-{}-{n}", std::process::id()));
            fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }

        fn file(&self, name: &str, bytes: &[u8]) -> Snapshot {
            let path = self.0.join(name);
            fs::write(&path, bytes).unwrap();
            Snapshot {
                path,
                len: bytes.len() as u64,
            }
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Serialises the tests that arm the process-wide signal cleanup (the
    /// parent's temp copies are armed).
    fn armed_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::compat::ARM_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn text(len: usize, seed: u8) -> Vec<u8> {
        b"the quick brown fox jumps over the lazy dog, "
            .iter()
            .cycle()
            .enumerate()
            .map(|(i, &b)| b.wrapping_add(seed).wrapping_add((i / 997) as u8))
            .take(len)
            .collect()
    }

    fn plan(mode: Mode) -> Plan {
        Plan {
            mode,
            repeat: 1,
            threads: None,
            memory_limit: 1 << 30,
        }
    }

    #[test]
    fn measure_memory_with_no_input_files_measures_nothing() {
        struct Counting(u32);
        impl Runner for Counting {
            fn run(&mut self, _job: &ChildJob) -> Result<u64, String> {
                self.0 += 1;
                Ok(1)
            }
        }
        let mut stub = Counting(0);
        let got = measure_memory_with(&mut stub, "lz4", None, &plan(Mode::OneStream), &[]);
        assert_eq!(
            got,
            Memory {
                compress: None,
                decompress: None,
                error: Some("no input to measure".to_string()),
            }
        );
        assert_eq!(stub.0, 0);
    }

    fn bench_temps() -> Vec<String> {
        let prefix = format!("stuffr-bench-{}-", std::process::id());
        fs::read_dir(std::env::temp_dir())
            .unwrap()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| n.starts_with(&prefix))
            .collect()
    }

    /// A runner that answers from `answer` and records every job it saw,
    /// with whether each job's files (and output) existed while it ran. A
    /// compress job that succeeds writes a stand-in copy to its output, as
    /// the real child writes the compressed stream there.
    struct Fake<F: FnMut(&ChildJob) -> Result<u64, String>> {
        answer: F,
        seen: Vec<(ChildJob, bool)>,
    }

    impl<F: FnMut(&ChildJob) -> Result<u64, String>> Runner for Fake<F> {
        fn run(&mut self, job: &ChildJob) -> Result<u64, String> {
            let present = job.files.iter().all(|s| s.path.exists())
                && job.out.as_ref().is_none_or(|o| o.exists());
            self.seen.push((job.clone(), present));
            let r = (self.answer)(job);
            if let (Ok(_), Some(out)) = (&r, &job.out) {
                fs::write(out, b"copy").unwrap();
            }
            r
        }
    }

    fn fake<F: FnMut(&ChildJob) -> Result<u64, String>>(answer: F) -> Fake<F> {
        Fake {
            answer,
            seen: Vec::new(),
        }
    }

    #[test]
    fn child_args_round_trip() {
        #[cfg(unix)]
        let odd: PathBuf = {
            use std::os::unix::ffi::OsStringExt;
            OsString::from_vec(b"/tmp/a b\xff/-c".to_vec()).into()
        };
        #[cfg(not(unix))]
        let odd = PathBuf::from("C:\\a b\\-c");
        let jobs = [
            ChildJob {
                side: Side::Compress,
                codec: "xz",
                level: Some(9),
                threads: Some(4),
                memory_limit: 123_456_789,
                out: Some(odd.join("out")),
                files: vec![
                    Snapshot {
                        path: odd.clone(),
                        len: 7,
                    },
                    Snapshot {
                        path: PathBuf::from("-"),
                        len: 0,
                    },
                ],
            },
            ChildJob {
                side: Side::Decompress,
                codec: "zstd",
                level: Some(-5),
                threads: None,
                memory_limit: u64::MAX,
                out: None,
                files: vec![Snapshot {
                    path: odd,
                    len: u64::MAX,
                }],
            },
            ChildJob {
                side: Side::Compress,
                codec: "lz4",
                level: None,
                threads: None,
                memory_limit: 0,
                out: None,
                files: Vec::new(),
            },
        ];
        for job in jobs {
            let args = job.to_args();
            assert_eq!(ChildJob::from_args(&args), Ok(job.clone()), "{args:?}");
        }
        // Not a codec of this build, a bad side, a missing output, a
        // missing length, a bad level.
        for bad in [
            &["compress", "nope", "-", "-", "1", "-"][..],
            &["sideways", "lz4", "-", "-", "1", "-"],
            &["compress", "lz4", "-", "-", "1"],
            &["compress", "lz4", "-", "-", "1", "/out", "/x"],
            &["compress", "lz4", "x", "-", "1", "-"],
        ] {
            let args: Vec<OsString> = bad.iter().map(OsString::from).collect();
            assert!(ChildJob::from_args(&args).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn proc_status_fields_parse_in_kib() {
        // The kernel pads the numbers with spaces; built, not spelled, so
        // no literal carries a run of them.
        let pad = " ".repeat(4);
        let status = format!(
            "Name:\tstuffr\nVmPeak:\t{pad}123456 kB\nVmHWM:\t{pad}6372 kB\nVmRSS:\t{pad}6100 kB\n"
        );
        let status = status.as_bytes();
        assert_eq!(status_field_kib(status, b"VmHWM:"), Some(6372));
        assert_eq!(status_field_kib(status, b"VmRSS:"), Some(6100));
        assert_eq!(status_field_kib(status, b"VmSwap:"), None);
        assert_eq!(status_field_kib(b"VmHWM:\t kB\n", b"VmHWM:"), None);
    }

    #[test]
    fn child_reply_parses_ok_and_err() {
        assert_eq!(parse_reply(b"ok 12345\n"), Some(Ok(12345)));
        assert_eq!(parse_reply(b"ok 0\n"), Some(Ok(0)));
        assert_eq!(
            parse_reply(b"err refused by --memory-limit: too big\n"),
            Some(Err("refused by --memory-limit: too big".into()))
        );
        for junk in [
            &b""[..],
            b"ok\n",
            b"ok -3\n",
            b"ok 12x\n",
            b"hello\n",
            b"err \n",
        ] {
            assert_eq!(
                parse_reply(junk),
                None,
                "{:?}",
                String::from_utf8_lossy(junk)
            );
        }
    }

    /// The env vars that make [`memory_probe`] run, and the prefix its
    /// reply line carries in libtest's captured output.
    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    const PROBE_CODEC: &str = "STUFFR_BENCH_MEMORY_PROBE_CODEC";
    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    const PROBE_LEVEL: &str = "STUFFR_BENCH_MEMORY_PROBE_LEVEL";
    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    const PROBE_FILE: &str = "STUFFR_BENCH_MEMORY_PROBE_FILE";
    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    const PROBE_MARK: &str = "memory-probe-reply: ";

    /// Not a test of its own: [`fresh_processes_measure_xz_9_above_lz4`]
    /// re-runs this test binary with only this test, so the compress child
    /// it runs has a process (and an `ru_maxrss` high-water mark) to
    /// itself. Prints the child's reply line after [`PROBE_MARK`]. Does
    /// nothing without the env vars.
    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    #[test]
    #[ignore = "a probe that fresh_processes_measure_xz_9_above_lz4 runs in its own process"]
    fn memory_probe() {
        let (Ok(codec), Ok(level), Some(file)) = (
            std::env::var(PROBE_CODEC),
            std::env::var(PROBE_LEVEL),
            std::env::var_os(PROBE_FILE),
        ) else {
            return;
        };
        let path = PathBuf::from(file);
        let len = fs::metadata(&path).unwrap().len();
        let args: Vec<OsString> = ["compress", &codec, &level, "-", "1073741824", "-"]
            .iter()
            .map(OsString::from)
            .chain([OsString::from(len.to_string()), path.into_os_string()])
            .collect();
        let job = ChildJob::from_args(&args).unwrap();
        println!("{PROBE_MARK}{}", reply_line(&child_main(job)));
    }

    /// The compress child's figures for xz -9 and lz4 over 1 MiB, each
    /// from a fresh process running [`memory_probe`]: xz -9's encoder (a
    /// 64 MiB dictionary's hash table) touches more than lz4's. Each figure
    /// is that process's own peak above its own baseline, so no other test
    /// can move it.
    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    #[test]
    fn fresh_processes_measure_xz_9_above_lz4() {
        let dir = Scratch::new();
        let input = dir.file("in", &text(1 << 20, 3));
        let probe = |codec: &str, level: &str| -> u64 {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "bench::memory::tests::memory_probe",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(PROBE_CODEC, codec)
                .env(PROBE_LEVEL, level)
                .env(PROBE_FILE, &input.path)
                .stdin(std::process::Stdio::null())
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            let reply = stdout
                .lines()
                .find_map(|l| l.split_once(PROBE_MARK).map(|(_, r)| r));
            match reply.and_then(|r| parse_reply(r.as_bytes())) {
                Some(Ok(n)) if out.status.success() => n,
                _ => panic!(
                    "{codec} probe gave no `ok` reply ({}):\n--- stdout\n{stdout}\n--- stderr\n{}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr)
                ),
            }
        };
        let lz4 = probe("lz4", "-");
        let xz = probe("xz", "9");
        assert!(xz > lz4, "xz -9 {xz} vs lz4 {lz4}");
    }

    /// `input` compressed by the compress child (in-process) into the
    /// existing file `name` in `dir`, as the parent's temp file is filled.
    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    fn compressed_by_the_child(
        dir: &Scratch,
        name: &str,
        codec: &'static str,
        level: Option<i32>,
        input: &Snapshot,
    ) -> Snapshot {
        let out = dir.file(name, b"stale bytes the child must truncate");
        let c = child_main(ChildJob {
            side: Side::Compress,
            codec,
            level,
            threads: None,
            memory_limit: 1 << 30,
            out: Some(out.path.clone()),
            files: vec![input.clone()],
        });
        assert!(c.is_ok(), "{codec}: {c:?}");
        let len = fs::metadata(&out.path).unwrap().len();
        Snapshot {
            path: out.path,
            len,
        }
    }

    /// The compress child writes the compressed stream to its output file
    /// (truncating what was there), and the decompress child runs to the
    /// end over it and gets the input back. Only that each succeeds is
    /// checked of the figures: in-process, they are this whole test
    /// binary's high-water mark, shared with every test beside it.
    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    #[test]
    fn the_compress_child_writes_the_copy_the_decompress_child_reads() {
        let dir = Scratch::new();
        let original = text(1 << 20, 3);
        let input = dir.file("in", &original);
        for (codec, level) in [("lz4", None), ("xz", Some(9))] {
            let copy = compressed_by_the_child(&dir, codec, codec, level, &input);
            let id = codec_id(codec).unwrap();
            let decoder = stuffr::registry().require_decoder(id).unwrap();
            let mut back = Vec::new();
            let src: Box<dyn Source> = Box::new(temp_source(
                GuardedSeek::new(File::open(&copy.path).unwrap()),
                copy.len,
            ));
            io::Read::read_to_end(
                &mut decoder.decoder(src, &DecodeOpts::default()).unwrap(),
                &mut back,
            )
            .unwrap();
            assert!(
                back == original,
                "{codec}: the copy does not decode to the input"
            );
            let d = child_main(ChildJob {
                side: Side::Decompress,
                codec,
                level: None,
                threads: None,
                memory_limit: 1 << 30,
                out: None,
                files: vec![copy],
            });
            assert!(d.is_ok(), "{codec}: {d:?}");
        }
    }

    #[test]
    fn per_file_reports_the_maximum() {
        let _g = armed_lock();
        let dir = Scratch::new();
        let files = vec![
            dir.file("a", &text(10_000, 0)),
            dir.file("b", &text(30_000, 1)),
            dir.file("c", &text(20_000, 2)),
        ];
        // Compress answers 100 x the file's length; decompress answers by
        // order: 5, 9, 2.
        let mut d = [5u64, 9, 2].into_iter();
        let mut r = fake(|job: &ChildJob| match job.side {
            Side::Compress => Ok(job.files[0].len * 100),
            Side::Decompress => Ok(d.next().unwrap()),
        });
        let m = measure_memory_with(&mut r, "gzip", Some(6), &plan(Mode::PerFile), &files);
        assert_eq!(
            m,
            Memory {
                compress: Some(3_000_000),
                decompress: Some(9),
                error: None
            }
        );
        // One child pair per file, each child given exactly its one file
        // (compress: the input, writing to the temp copy; decompress: that
        // copy, present, at the length the compress child left it).
        let sides: Vec<Side> = r.seen.iter().map(|(j, _)| j.side).collect();
        use Side::{Compress as C, Decompress as D};
        assert_eq!(sides, [C, D, C, D, C, D]);
        for (i, (job, present)) in r.seen.iter().enumerate() {
            assert_eq!(job.files.len(), 1);
            assert!(present, "job {i}'s file and output should exist");
            let level = (job.side == Side::Compress).then_some(6);
            assert_eq!((job.codec, job.level), ("gzip", level));
            if job.side == Side::Compress {
                assert_eq!(job.files[0], files[i / 2]);
                assert!(job.out.is_some(), "a compress child writes the copy");
            } else {
                assert_eq!(job.out, None);
                assert_eq!(job.files[0].len, 4, "the length the compress child wrote");
                assert_eq!(Some(&job.files[0].path), r.seen[i - 1].0.out.as_ref());
            }
        }

        // One stream: one pair, the compress child given every file.
        let mut r = fake(|job: &ChildJob| Ok(job.files.iter().map(|s| s.len).sum()));
        let m = measure_memory_with(&mut r, "gzip", None, &plan(Mode::OneStream), &files);
        assert_eq!(m.compress, Some(60_000));
        assert!(m.decompress.is_some_and(|n| n > 0));
        assert_eq!(r.seen.len(), 2);
        assert_eq!(r.seen[0].0.files, files);
        assert_eq!(r.seen[1].0.files.len(), 1);
    }

    #[test]
    fn a_failed_child_gives_dashes_and_an_error() {
        let _g = armed_lock();
        let dir = Scratch::new();
        let files = vec![
            dir.file("a", &text(10_000, 0)),
            dir.file("b", &text(10_000, 1)),
        ];
        // The second file's compress child fails: it left no copy, so
        // there is no decompress run for that file and both cells are
        // dashes (ruling F8); the error says why.
        let mut n = 0;
        let mut r = fake(|job: &ChildJob| match job.side {
            Side::Compress => {
                n += 1;
                if n == 2 {
                    Err("the memory run failed (signal: 9 (SIGKILL))".into())
                } else {
                    Ok(10)
                }
            }
            Side::Decompress => Ok(20),
        });
        let m = measure_memory_with(&mut r, "gzip", None, &plan(Mode::PerFile), &files);
        assert_eq!(m.compress, None);
        assert_eq!(m.decompress, None);
        let e = m.error.unwrap();
        assert!(e.starts_with("compress: ") && e.contains("SIGKILL"), "{e}");
        assert!(e.contains("no decompress run"), "{e}");
        // No child ran after the failure: two compress, one decompress.
        assert_eq!(r.seen.len(), 3);

        // A failed decompress child leaves the compress side standing
        // (spec call 16).
        let mut r = fake(|job: &ChildJob| match job.side {
            Side::Compress => Ok(10),
            Side::Decompress => Err("the memory run failed (exit status: 1)".into()),
        });
        let m = measure_memory_with(&mut r, "gzip", None, &plan(Mode::PerFile), &files);
        assert_eq!((m.compress, m.decompress), (Some(10), None));
        assert!(m.error.unwrap().starts_with("decompress: "));

        // Both sides failing: two dashes.
        let mut r = fake(|_: &ChildJob| Err("boom".to_string()));
        let m = measure_memory_with(&mut r, "gzip", None, &plan(Mode::OneStream), &files);
        assert_eq!((m.compress, m.decompress), (None, None));
        assert!(m.error.unwrap().contains("boom"));

        // A child that printed no reply, or exited badly, is a failure.
        assert!(interpret(false, "exit status: 101", b"", b"thread 'main' panicked\n").is_err());
        assert!(interpret(true, "exit status: 0", b"garbage\n", b"").is_err());
        assert!(interpret(false, "signal: 9 (SIGKILL)", b"ok 5\n", b"").is_err());
        assert_eq!(interpret(true, "exit status: 0", b"ok 5\n", b""), Ok(5));
        assert_eq!(
            interpret(false, "exit status: 1", b"err nope\n", b""),
            Err("nope".into())
        );
    }

    #[test]
    fn a_refusal_names_the_memory_limit() {
        let refusal = describe(&stuffr::Error::ResourceLimit(
            "xz: header declares a dictionary needing 64 MiB".into(),
        ));
        assert!(
            refusal.starts_with("refused by --memory-limit"),
            "{refusal}"
        );
        assert!(refusal.contains("64 MiB"), "{refusal}");
        // Anything else keeps its own text.
        let corrupt = describe(&stuffr::Error::Corrupt("bad".into()));
        assert!(!corrupt.contains("--memory-limit"), "{corrupt}");

        // The parent carries the child's refusal into the row's error.
        let _g = armed_lock();
        let dir = Scratch::new();
        let files = vec![dir.file("a", &text(10_000, 0))];
        let mut r = fake(|job: &ChildJob| match job.side {
            Side::Compress => Err(refusal.clone()),
            Side::Decompress => Ok(1),
        });
        let m = measure_memory_with(&mut r, "gzip", None, &plan(Mode::OneStream), &files);
        assert_eq!(m.compress, None);
        assert!(
            m.error.unwrap().contains("refused by --memory-limit"),
            "the refusal is distinguishable from a crash"
        );
    }

    /// The pure xz decoder refuses a header whose dictionary exceeds the
    /// limit; the child reports that as a refusal. (The C tier's decoder
    /// takes no limit, so this is pure-tier only.)
    #[cfg(all(
        any(target_vendor = "apple", target_os = "linux"),
        not(feature = "xz-c")
    ))]
    #[test]
    fn a_child_refusal_names_the_memory_limit() {
        let dir = Scratch::new();
        let input = dir.file("in", &text(100_000, 0));
        let copy = compressed_by_the_child(&dir, "in.xz", "xz", Some(9), &input);
        let r = child_main(ChildJob {
            side: Side::Decompress,
            codec: "xz",
            level: None,
            threads: None,
            memory_limit: 1 << 20,
            out: None,
            files: vec![copy],
        });
        let e = r.unwrap_err();
        assert!(e.starts_with("refused by --memory-limit"), "{e}");
    }

    #[test]
    fn temp_copies_are_removed() {
        let _g = armed_lock();
        let dir = Scratch::new();
        let files = vec![
            dir.file("a", &text(10_000, 0)),
            dir.file("b", &text(10_000, 1)),
        ];
        assert_eq!(bench_temps(), Vec::<String>::new());
        for mode in [Mode::OneStream, Mode::PerFile] {
            // While a decompress child runs, its copy exists and is the
            // only bench temp file: per-file copies do not pile up.
            let mut r = fake(|job: &ChildJob| {
                if job.side == Side::Decompress {
                    assert_eq!(bench_temps().len(), 1);
                }
                Ok(1)
            });
            let m = measure_memory_with(&mut r, "gzip", None, &plan(mode), &files);
            assert_eq!(m.error, None);
            assert!(r.seen.iter().all(|(_, present)| *present));
            assert_eq!(bench_temps(), Vec::<String>::new(), "{mode:?}");
        }
        // A failed child removes its copy too.
        let mut r = fake(|_: &ChildJob| Err("boom".to_string()));
        let _ = measure_memory_with(&mut r, "gzip", None, &plan(Mode::PerFile), &files);
        assert_eq!(bench_temps(), Vec::<String>::new());
    }
}
