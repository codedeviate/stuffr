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
//! buffer (writing to a sink that discards) and its open files are made
//! first; then it samples its peak resident set as the baseline (the
//! high-water so far, which is its current size, since nothing has run
//! yet), runs the codec to the end, and reports the peak minus that
//! baseline, saturating at 0. So the number is the codec's resident working
//! memory plus a few small fixed buffers; memory reserved but never touched
//! does not count. The compress child streams the input from the files
//! (each read stops at the length snapshotted at load, as in the timed
//! runs), so an encoder that buffers its whole input (the pure-tier zstd
//! encoder) shows memory growing with the input: that is what using it
//! costs. The decompress child reads a compressed copy the parent wrote
//! (untimed) to a guarded temp file, `stuffr-bench-<pid>-<n>`, through the
//! same 64 KiB buffered source the timed runs use.
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
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};

use stuffr::source::{GuardedSeek, Source};
use stuffr::{Codec, DecodeOpts, EncodeOpts, Error, FormatKind};

use super::measure::{
    CHUNK, Mode, Plan, Snapshot, TempOut, fill, governor_for, read_some, temp_source,
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

/// What one child runs. Compress: `files` concatenated as one stream.
/// Decompress: exactly one file, the compressed copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChildJob {
    pub side: Side,
    pub codec: &'static str,
    pub level: Option<i32>,
    pub threads: Option<usize>,
    pub memory_limit: u64,
    pub files: Vec<Snapshot>,
}

/// `-` for an absent level or thread count on the wire.
const NONE: &str = "-";

impl ChildJob {
    /// The arguments after [`CHILD_ARG`]:
    /// `<side> <codec> <level|-> <threads|-> <memory-limit> [<len> <path>]…`,
    /// `side` being `compress` or `decompress`, every number in decimal.
    /// Paths go as they are (not through UTF-8), each its own argument.
    pub fn to_args(&self) -> Vec<OsString> {
        let opt = |v: Option<String>| OsString::from(v.unwrap_or_else(|| NONE.to_string()));
        let mut args = vec![
            OsString::from(self.side.word()),
            OsString::from(self.codec),
            opt(self.level.map(|l| l.to_string())),
            opt(self.threads.map(|t| t.to_string())),
            OsString::from(self.memory_limit.to_string()),
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
    let result = if cfg!(debug_assertions) {
        Err(DEBUG_CHILD_REFUSAL.to_string())
    } else {
        ChildJob::from_args(&args[2..]).and_then(child_main)
    };
    let mut out = io::stdout().lock();
    let printed = writeln!(out, "{}", reply_line(&result)).and_then(|()| out.flush());
    Some(if result.is_ok() && printed.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
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
            compress_child(codec.as_ref(), &encode, &job.files).map_err(|e| describe(&e))
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

/// Streams `files` through the encoder into a discarding sink.
fn compress_child(
    codec: &dyn Codec,
    encode: &EncodeOpts,
    files: &[Snapshot],
) -> stuffr::Result<u64> {
    let mut feeds = files
        .iter()
        .map(|s| s.open().map(|f| (s, f)))
        .collect::<io::Result<Vec<_>>>()?;
    let mut buf = vec![0u8; CHUNK];
    let dst = BufWriter::with_capacity(CHUNK, io::sink());
    let baseline = peak_rss()?;
    let mut sink = codec.encoder(Box::new(dst), encode)?;
    for (snap, f) in &mut feeds {
        let mut read = 0u64;
        loop {
            let n = read_some(f, &mut buf)?;
            if n == 0 {
                break;
            }
            read += n as u64;
            sink.write_all(&buf[..n])?;
        }
        if read < snap.len {
            return Err(shrank(snap, read));
        }
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
    let baseline = peak_rss()?;
    let mut decoder = codec.decoder(src, decode)?;
    while fill(&mut decoder, &mut buf).map_err(Error::from_decode_io)? == buf.len() {}
    drop(decoder);
    Ok(peak_rss()?.saturating_sub(baseline))
}

fn shrank(snap: &Snapshot, read: u64) -> Error {
    Error::Io(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        format!(
            "{} shrank to {read} bytes from {} while bench ran",
            snap.path.display(),
            snap.len
        ),
    ))
}

/// This process's peak resident set so far, in bytes: `ru_maxrss`, which
/// macOS (and iOS) give in bytes and Linux and the BSDs in KiB.
#[cfg(unix)]
fn peak_rss() -> io::Result<u64> {
    // SAFETY: `getrusage` only writes the `rusage` it is given, which is
    // plain data and valid zeroed.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: as above; `usage` is a valid, writable `rusage`.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let unit = if cfg!(target_vendor = "apple") {
        1
    } else {
        1024
    };
    Ok(u64::try_from(usage.ru_maxrss)
        .unwrap_or(0)
        .saturating_mul(unit))
}

/// Off unix there is no `ru_maxrss`; bench does not measure memory there.
#[cfg(not(unix))]
fn peak_rss() -> io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "memory is not measured on this platform",
    ))
}

/// Runs one child job and returns its reply. The real one spawns a
/// process ([`ProcessRunner`]); tests inject a fake.
pub trait Runner {
    fn run(&mut self, job: &ChildJob) -> Result<u64, String>;
}

/// Runs each job as `<this executable> __bench-memory-child …`, with stdin
/// closed and stdout and stderr captured, keeping its pid in
/// [`RUNNING_CHILD`] while it runs.
pub struct ProcessRunner;

impl Runner for ProcessRunner {
    fn run(&mut self, job: &ChildJob) -> Result<u64, String> {
        let exe = std::env::current_exe()
            .map_err(|e| format!("cannot find bench's own executable: {e}"))?;
        let child = Command::new(exe)
            .arg(CHILD_ARG)
            .args(job.to_args())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot start the memory run: {e}"))?;
        RUNNING_CHILD.store(i32::try_from(child.id()).unwrap_or(0), Ordering::SeqCst);
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

/// [`measure_memory_with`] with real child processes. Unix only in use:
/// off unix the caller reports memory as not measured instead.
pub fn measure_memory(
    codec: &'static str,
    level: Option<i32>,
    plan: &Plan,
    input_files: &[Snapshot],
) -> Memory {
    measure_memory_with(&mut ProcessRunner, codec, level, plan, input_files)
}

/// One row's memory under `plan`: a compress child and a decompress child
/// per stream (`plan.mode`: one stream over every file, or one per file),
/// reporting each side's largest peak. Between the two, the parent writes
/// the stream's compressed copy to a guarded temp file (untimed; removed
/// before the next stream begins). Strictly after the row's timed runs.
///
/// A side whose child (or copy) fails for any stream is `None`, and the
/// first failure's text, prefixed by its side, is `error`; the other side
/// still stands. Never an error of its own.
pub fn measure_memory_with(
    runner: &mut dyn Runner,
    codec: &'static str,
    level: Option<i32>,
    plan: &Plan,
    input_files: &[Snapshot],
) -> Memory {
    let streams: Vec<&[Snapshot]> = match plan.mode {
        Mode::OneStream => vec![input_files],
        Mode::PerFile => input_files.chunks(1).collect(),
    };
    let job = |side, files| ChildJob {
        side,
        codec,
        level,
        threads: plan.threads,
        memory_limit: plan.memory_limit,
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
        if let Some(peak) = compress {
            match runner.run(&job(Side::Compress, files.to_vec())) {
                Ok(n) => compress = Some(peak.max(n)),
                Err(e) => fail(Side::Compress, e, &mut compress),
            }
        }
        if let Some(peak) = decompress {
            // The copy lives until this stream's decompress child is done.
            let r = write_copy(codec, level, plan, files)
                .map_err(|e| describe(&e))
                .and_then(|(copy, len)| {
                    let snap = Snapshot {
                        path: copy.path().to_path_buf(),
                        len,
                    };
                    runner.run(&job(Side::Decompress, vec![snap]))
                });
            match r {
                Ok(n) => decompress = Some(peak.max(n)),
                Err(e) => fail(Side::Decompress, e, &mut decompress),
            }
        }
        if compress.is_none() && decompress.is_none() {
            break;
        }
    }
    Memory {
        compress,
        decompress,
        error,
    }
}

/// `files` compressed as one stream, as the timed runs compress them, into
/// a new guarded temp file; returns it with its length.
fn write_copy(
    codec: &str,
    level: Option<i32>,
    plan: &Plan,
    files: &[Snapshot],
) -> stuffr::Result<(TempOut, u64)> {
    let codec = stuffr::registry().require_encoder(codec_id(codec).map_err(Error::Usage)?)?;
    let encode = EncodeOpts {
        level,
        governor: governor_for(plan),
        ..Default::default()
    };
    codec.check_encode_opts(&encode)?;
    let (temp, file) = TempOut::create()?;
    let mut sink = codec.encoder(Box::new(BufWriter::with_capacity(CHUNK, file)), &encode)?;
    let mut buf = vec![0u8; CHUNK];
    for snap in files {
        let mut f = snap.open()?;
        let mut read = 0u64;
        loop {
            let n = read_some(&mut f, &mut buf)?;
            if n == 0 {
                break;
            }
            read += n as u64;
            sink.write_all(&buf[..n])?;
        }
        if read < snap.len {
            return Err(shrank(snap, read));
        }
    }
    sink.finish()?;
    let len = std::fs::metadata(temp.path())?.len();
    Ok((temp, len))
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

    fn bench_temps() -> Vec<String> {
        let prefix = format!("stuffr-bench-{}-", std::process::id());
        fs::read_dir(std::env::temp_dir())
            .unwrap()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| n.starts_with(&prefix))
            .collect()
    }

    /// A runner that answers from `answer` and records every job it saw,
    /// with whether each job's files existed while it ran.
    struct Fake<F: FnMut(&ChildJob) -> Result<u64, String>> {
        answer: F,
        seen: Vec<(ChildJob, bool)>,
    }

    impl<F: FnMut(&ChildJob) -> Result<u64, String>> Runner for Fake<F> {
        fn run(&mut self, job: &ChildJob) -> Result<u64, String> {
            let present = job.files.iter().all(|s| s.path.exists());
            self.seen.push((job.clone(), present));
            (self.answer)(job)
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
                files: Vec::new(),
            },
        ];
        for job in jobs {
            let args = job.to_args();
            assert_eq!(ChildJob::from_args(&args), Ok(job.clone()), "{args:?}");
        }
        // Not a codec of this build, a bad side, a missing length.
        for bad in [
            &["compress", "nope", "-", "-", "1"][..],
            &["sideways", "lz4", "-", "-", "1"],
            &["compress", "lz4", "-", "-", "1", "/x"],
            &["compress", "lz4", "x", "-", "1"],
        ] {
            let args: Vec<OsString> = bad.iter().map(OsString::from).collect();
            assert!(ChildJob::from_args(&args).is_err(), "{bad:?}");
        }
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

    /// In-process, so a weak check: `ru_maxrss` is this whole test
    /// process's high-water mark, shared with every other test running
    /// beside it, so the figures here only show the child path runs and
    /// that xz -9's encoder (a 64 MiB dictionary) touches more than lz4's.
    /// The real figures come from the release-build manual run, where each
    /// child is its own process.
    #[cfg(unix)]
    #[test]
    fn child_main_measures_lz4_and_xz_in_process() {
        use std::io::Write;
        let dir = Scratch::new();
        let input = dir.file("in", &text(1 << 20, 3));
        let job = |side, codec, level, files| ChildJob {
            side,
            codec,
            level,
            threads: None,
            memory_limit: 1 << 30,
            files,
        };
        let lz4 = child_main(job(Side::Compress, "lz4", None, vec![input.clone()]));
        let xz = child_main(job(Side::Compress, "xz", Some(9), vec![input.clone()]));
        let (lz4, xz) = (lz4.unwrap(), xz.unwrap());
        assert!(xz > lz4, "xz -9 {xz} vs lz4 {lz4}");

        // The decompress side reads a compressed copy.
        for (codec, level) in [("lz4", None), ("xz", Some(9))] {
            let mut enc = Vec::new();
            {
                let reg = stuffr::registry();
                let id = reg
                    .matrix()
                    .into_iter()
                    .find(|r| r.id.as_str() == codec)
                    .unwrap()
                    .id;
                let opts = stuffr::EncodeOpts {
                    level,
                    ..Default::default()
                };
                let shared = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
                struct W(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
                impl Write for W {
                    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                        self.0.lock().unwrap().extend_from_slice(b);
                        Ok(b.len())
                    }
                    fn flush(&mut self) -> std::io::Result<()> {
                        Ok(())
                    }
                }
                let mut sink = reg
                    .require_encoder(id)
                    .unwrap()
                    .encoder(Box::new(W(shared.clone())), &opts)
                    .unwrap();
                sink.write_all(&fs::read(&input.path).unwrap()).unwrap();
                sink.finish().unwrap();
                enc.extend_from_slice(&shared.lock().unwrap());
            }
            let copy = dir.file(&format!("in.{codec}"), &enc);
            let d = child_main(job(Side::Decompress, codec, level, vec![copy]));
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
        // (compress: the input; decompress: the temp copy, present).
        let sides: Vec<Side> = r.seen.iter().map(|(j, _)| j.side).collect();
        use Side::{Compress as C, Decompress as D};
        assert_eq!(sides, [C, D, C, D, C, D]);
        for (i, (job, present)) in r.seen.iter().enumerate() {
            assert_eq!(job.files.len(), 1);
            assert!(present, "job {i}'s file was missing");
            assert_eq!((job.codec, job.level), ("gzip", Some(6)));
            if job.side == Side::Compress {
                assert_eq!(job.files[0], files[i / 2]);
            } else {
                assert!(job.files[0].len > 0);
                assert_ne!(job.files[0].path, files[i / 2].path);
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
        // The second file's compress child fails: the compress cell is a
        // dash, the decompress one still stands (spec call 16).
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
        assert_eq!(m.decompress, Some(20));
        let e = m.error.unwrap();
        assert!(e.contains("compress") && e.contains("SIGKILL"), "{e}");

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

        // A codec the parent cannot even make its copy with.
        let mut r = fake(|_: &ChildJob| Ok(1));
        let m = measure_memory_with(&mut r, "nope", None, &plan(Mode::OneStream), &files);
        assert_eq!(m.decompress, None);
        assert!(m.error.is_some());
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
    #[cfg(all(unix, not(feature = "xz-c")))]
    #[test]
    fn a_child_refusal_names_the_memory_limit() {
        use std::io::Write;
        let dir = Scratch::new();
        let input = dir.file("in", &text(100_000, 0));
        let reg = stuffr::registry();
        let id = reg
            .matrix()
            .into_iter()
            .find(|r| r.id.as_str() == "xz")
            .unwrap()
            .id;
        let path = dir.0.join("in.xz");
        let out = fs::File::create(&path).unwrap();
        let mut sink = reg
            .require_encoder(id)
            .unwrap()
            .encoder(
                Box::new(out),
                &stuffr::EncodeOpts {
                    level: Some(9),
                    ..Default::default()
                },
            )
            .unwrap();
        sink.write_all(&fs::read(&input.path).unwrap()).unwrap();
        sink.finish().unwrap();
        let len = fs::metadata(&path).unwrap().len();
        let r = child_main(ChildJob {
            side: Side::Decompress,
            codec: "xz",
            level: Some(9),
            threads: None,
            memory_limit: 1 << 20,
            files: vec![Snapshot { path, len }],
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
