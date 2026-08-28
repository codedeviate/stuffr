//! The operations layer: the pipeline assembled once, for the CLI and for
//! library consumers alike.
//!
//! An orchestration that lives only inside a binary forces every library user
//! to rebuild it. `compress`, `decompress` and `inspect` are the operations the
//! `stf` command performs, and they are public API.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use stuffr_core::{
    EncodeOpts, Error, FidelityReport, FileSource, FormatId, FormatKind, ReaderSource, Registry,
    Result, Source,
};

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

/// A destination, plus the path to remove if the write fails partway.
pub(crate) struct Opened {
    pub(crate) writer: Box<dyn Write + Send>,
    pub(crate) cleanup: Option<PathBuf>,
}

impl Output {
    /// Opens the destination, refusing an existing file unless `force`.
    ///
    /// The check runs before any work, so a refused command does nothing at all
    /// rather than truncating and then complaining.
    pub(crate) fn create(&self, force: bool) -> Result<Opened> {
        match self {
            Output::Stdout => Ok(Opened {
                writer: Box::new(std::io::stdout()),
                cleanup: None,
            }),
            Output::Path(p) => {
                if !force && p.exists() {
                    return Err(Error::Usage(format!(
                        "{} already exists; pass --force to overwrite",
                        p.display()
                    )));
                }
                let f = File::create(p)?;
                Ok(Opened {
                    writer: Box::new(f),
                    cleanup: Some(p.clone()),
                })
            }
        }
    }
}

/// Removes a partial output after a failed write.
///
/// Without this a transient failure becomes permanent: the file left behind
/// would make the overwrite guard refuse the retry.
pub(crate) fn discard(cleanup: Option<PathBuf>) {
    if let Some(p) = cleanup {
        let _ = std::fs::remove_file(p);
    }
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
    let cleanup = opened.cleanup.clone();
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
        // Not optional: this writes gzip's CRC and length trailer.
        sink.finish()?;
        Ok(total_in)
    };

    match run() {
        Ok(bytes_in) => Ok(Outcome {
            bytes_in,
            bytes_out: written.load(Ordering::Relaxed),
            format,
            fidelity: FidelityReport::exact(),
        }),
        Err(e) => {
            discard(cleanup);
            Err(e)
        }
    }
}
