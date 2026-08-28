//! The operations layer: the pipeline assembled once, for the CLI and for
//! library consumers alike.
//!
//! An orchestration that lives only inside a binary forces every library user
//! to rebuild it. `compress`, `decompress` and `inspect` are the operations the
//! `stf` command performs, and they are public API.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use stuffr_core::{
    EncodeOpts, Error, FidelityReport, FileSource, FormatId, FormatKind, ReaderSource, Registry,
    Result, Source,
};

/// Per-process counter mixed into the temp file name alongside the pid, so
/// two concurrent `compress` calls in the same process (this is public
/// library API, not just the single-threaded `stf` binary) get distinct temp
/// paths on the very first attempt rather than racing to the same one.
static NEXT_TMP: AtomicU64 = AtomicU64::new(0);

/// How many colliding temp names `Output::create` will step over before
/// giving up. Debris from a crashed run (or a recycled pid) should not
/// permanently lock a destination out of being compressed to; a bound this
/// generous only ever bites on something more structurally wrong.
const MAX_TMP_ATTEMPTS: u32 = 100;

/// Where bytes come from. `Stdin` is what `-` means on the command line.
pub enum Input {
    Path(PathBuf),
    Stdin,
}

impl Input {
    pub fn open(&self) -> Result<Box<dyn Source>> {
        match self {
            Input::Path(p) => Ok(Box::new(FileSource::open(p)?)),
            Input::Stdin => Ok(Box::new(ReaderSource::new(std::io::stdin()))),
        }
    }

    /// The path, when there is one. Detection uses it as a hint; a pipe has none.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Input::Path(p) => Some(p),
            Input::Stdin => None,
        }
    }
}

/// Where bytes go.
pub enum Output {
    Path(PathBuf),
    Stdout,
}

/// A destination, plus what to do when the write finishes or fails.
///
/// `Output::Path` writes to a temp file beside the real destination and only
/// renames onto it once the caller confirms the write succeeded; `finish`
/// carries the temp path so a failure can remove it without ever touching the
/// real destination, and `target` carries the final path the rename lands on.
pub(crate) struct Opened {
    pub(crate) writer: Box<dyn Write + Send>,
    pub(crate) finish: Option<Finish>,
}

/// What `Opened::writer` is actually writing to, and where it must end up.
pub(crate) struct Finish {
    /// The temp path currently being written. Removed on failure.
    pub(crate) tmp: PathBuf,
    /// The real destination. Renamed onto only after a successful write.
    pub(crate) target: PathBuf,
}

impl Output {
    /// Opens the destination, refusing an existing file unless `force`.
    ///
    /// The check runs before any work, so a refused command does nothing at all
    /// rather than truncating and then complaining. For `Output::Path` the
    /// real bytes land in a temp file beside the destination; the caller must
    /// rename it onto the destination on success (see `discard` for failure).
    pub(crate) fn create(&self, force: bool) -> Result<Opened> {
        match self {
            Output::Stdout => Ok(Opened {
                writer: Box::new(std::io::stdout()),
                finish: None,
            }),
            Output::Path(p) => {
                let exists = p.exists();
                if !force && exists {
                    return Err(Error::Usage(format!(
                        "{} already exists; pass --force to overwrite",
                        p.display()
                    )));
                }
                // Read the destination's permissions BEFORE creating or
                // renaming anything: once the rename happens the original
                // inode is gone and there is nothing left to read them from.
                let carry_over_perms = if exists {
                    Some(std::fs::metadata(p)?.permissions())
                } else {
                    None
                };

                let parent = match p.parent() {
                    Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
                    _ => PathBuf::from("."),
                };
                let file_name = p
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();

                // Uniqueness by pid alone is only per-process: two threads in
                // the same process racing to compress to the same
                // destination would compute the identical temp path and
                // silently stomp each other's in-flight write. A per-process
                // counter alongside the pid gives concurrent callers in one
                // process distinct paths on the first try; `create_new`
                // makes a collision (or leftover debris from a crashed run,
                // or a recycled pid) a hard error instead of a silent
                // truncate, and the bounded retry below steps over that
                // debris rather than letting it permanently lock the
                // destination out of being compressed to at all.
                let (tmp, f) = {
                    let mut attempt = 0u32;
                    loop {
                        let n = NEXT_TMP.fetch_add(1, Ordering::Relaxed);
                        let candidate =
                            parent.join(format!(".{}.{}.{}.tmp", std::process::id(), n, file_name));
                        match std::fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&candidate)
                        {
                            Ok(f) => break (candidate, f),
                            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                                attempt += 1;
                                if attempt >= MAX_TMP_ATTEMPTS {
                                    return Err(Error::from(e));
                                }
                            }
                            Err(e) => return Err(Error::from(e)),
                        }
                    }
                };
                if let Some(perms) = carry_over_perms {
                    std::fs::set_permissions(&tmp, perms)?;
                }
                Ok(Opened {
                    writer: Box::new(f),
                    finish: Some(Finish {
                        tmp,
                        target: p.clone(),
                    }),
                })
            }
        }
    }
}

/// Removes the temp file left by a failed write, leaving the real destination
/// exactly as it was — untouched if it existed, still absent if it did not.
pub(crate) fn discard(finish: Option<Finish>) {
    if let Some(f) = finish {
        let _ = std::fs::remove_file(f.tmp);
    }
}

/// Publishes a successful write: renames the temp file onto the destination.
///
/// Must only be called after every byte (including any trailer) is written
/// and flushed — the rename is what makes the file visible under its real
/// name, so it has to be the last thing that happens on the success path.
pub(crate) fn publish(finish: Option<Finish>) -> Result<()> {
    if let Some(f) = finish {
        std::fs::rename(&f.tmp, &f.target)?;
    }
    Ok(())
}

/// Counts bytes on their way out, so `bytes_out` is correct for stdout too.
pub(crate) struct CountingWriter {
    inner: Box<dyn Write + Send>,
    count: Arc<AtomicU64>,
}

impl CountingWriter {
    pub(crate) fn new(inner: Box<dyn Write + Send>) -> (Self, Arc<AtomicU64>) {
        let count = Arc::new(AtomicU64::new(0));
        (
            Self {
                inner,
                count: Arc::clone(&count),
            },
            count,
        )
    }
}

impl Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.count.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[derive(Clone, Debug, Default)]
pub struct CompressOpts {
    /// An explicit format. Wins over any extension — a flag is the more
    /// specific statement of intent, and an extension is only ever a hint.
    pub format: Option<FormatId>,
    pub level: Option<i32>,
    pub force: bool,
}

/// What an operation did.
#[derive(Clone, Debug)]
pub struct Outcome {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub format: FormatId,
    pub fidelity: FidelityReport,
}

/// Chooses the output format: explicit flag, else the output extension, else
/// the only codec in the build.
fn choose_format(reg: &Registry, dst: &Output, explicit: Option<FormatId>) -> Result<FormatId> {
    if let Some(f) = explicit {
        return Ok(f);
    }
    if let Output::Path(p) = dst {
        if let Some(id) = p
            .extension()
            .and_then(|e| e.to_str())
            .and_then(|e| reg.by_extension(e))
        {
            return Ok(id);
        }
    }
    // While one codec is registered, defaulting to it is unambiguous. This
    // becomes a usage error on its own the moment 1c adds a second.
    let codecs: Vec<FormatId> = reg
        .matrix()
        .into_iter()
        .filter(|r| r.kind == FormatKind::Codec)
        .map(|r| r.id)
        .collect();
    match codecs.len() {
        1 => Ok(codecs[0]),
        0 => Err(Error::Usage("this build contains no codecs".into())),
        _ => Err(Error::Usage(
            "cannot infer the output format; pass --format or name the output with a known extension"
                .into(),
        )),
    }
}

/// Compresses `src` into `dst`.
pub fn compress(src: Input, dst: Output, o: &CompressOpts) -> Result<Outcome> {
    let registry = crate::registry();
    let format = choose_format(&registry, &dst, o.format)?;
    let codec = registry.require_codec(format)?;

    let mut reader = src.open()?;
    let opened = dst.create(o.force)?;
    let (counted, written) = CountingWriter::new(opened.writer);

    let encode = EncodeOpts {
        level: o.level,
        ..Default::default()
    };

    let run = || -> Result<u64> {
        let mut sink = codec.encoder(Box::new(counted), &encode)?;
        let mut buf = vec![0u8; 64 * 1024];
        let mut total_in = 0u64;
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            total_in += n as u64;
            sink.write_all(&buf[..n])?;
        }
        // Writes gzip's CRC and length trailer, then flushes the underlying
        // writer — see the contract documented on `Sink::finish`. The writer
        // was handed away by value above, so `finish` is the only place left
        // that can flush it.
        sink.finish()?;
        Ok(total_in)
    };

    match run() {
        Ok(bytes_in) => {
            // Rename onto the final path only now: every byte, including the
            // trailer, has been written AND flushed (guaranteed by `finish`
            // above). Publishing any earlier risks a truncated file visible
            // under the real name.
            publish(opened.finish)?;
            Ok(Outcome {
                bytes_in,
                bytes_out: written.load(Ordering::Relaxed),
                format,
                fidelity: FidelityReport::exact(),
            })
        }
        Err(e) => {
            discard(opened.finish);
            Err(e)
        }
    }
}
