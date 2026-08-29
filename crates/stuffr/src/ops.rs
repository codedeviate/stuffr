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
    Chain, Counting, DEFAULT_MAX_RATIO, DecodeOpts, EncodeOpts, Error, FidelityReport, FileSource,
    FormatId, FormatKind, RatioGuard, ReaderSource, Registry, Result, Rung, Source,
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
    /// A second handle on the temp file, kept so `publish` can `sync_all()`
    /// after the codec has consumed the writer it was handed.
    pub(crate) handle: Option<std::fs::File>,
    /// Whether `publish` should fsync at all. See `CompressOpts::sync` /
    /// `DecompressOpts::sync` for what turning it off costs.
    pub(crate) sync: bool,
}

impl Output {
    /// Opens the destination, refusing an existing file unless `force`.
    ///
    /// The check runs before any work, so a refused command does nothing at all
    /// rather than truncating and then complaining. For `Output::Path` the
    /// real bytes land in a temp file beside the destination; the caller must
    /// rename it onto the destination on success (see `discard` for failure).
    ///
    /// **A non-regular destination trades away that crash safety.** A symlink,
    /// a device node or a FIFO takes the direct-write branch with `finish:
    /// None`, because renaming onto one would replace it rather than write
    /// through it — which is the whole point for `-o /dev/null` and for a
    /// `latest.gz -> archives/….gz` link. The cost is that a failure partway
    /// through leaves the target truncated, where a plain file would have been
    /// left untouched. It applies even to a symlink pointing *at* a regular
    /// file, since `symlink_metadata` reports the link, never its target.
    /// Closing that gap means resolving the link and renaming onto the
    /// resolved path, which brings link chains, relative targets and its own
    /// TOCTOU window along with it — deferred rather than rushed.
    ///
    /// `sync` is carried through unchanged into the returned `Opened`'s
    /// `Finish` (when there is one), for `publish` to act on later — see its
    /// docs for what turning it off costs.
    pub(crate) fn create(&self, force: bool, sync: bool) -> Result<Opened> {
        match self {
            Output::Stdout => Ok(Opened {
                writer: Box::new(std::io::stdout()),
                finish: None,
            }),
            Output::Path(p) => {
                // `symlink_metadata` inspects the path itself rather than
                // following a symlink to its target. That is what both
                // checks below need: whether something already sits at this
                // exact path (a dangling symlink counts as "exists", unlike
                // `Path::exists`, which follows the link and silently reports
                // "absent" for one), and whether that something is a plain
                // regular file — the only case the temp-then-rename dance
                // below is safe for.
                let link_meta = std::fs::symlink_metadata(p);
                let exists = link_meta.is_ok();
                if !force && exists {
                    return Err(Error::Usage(format!(
                        "{} already exists; pass --force to overwrite",
                        p.display()
                    )));
                }

                // A destination that already exists but is not a regular
                // file — `/dev/null`, a FIFO, a block/character device — can
                // never be the target of a rename (renaming a temp file onto
                // `/dev/null` fails outright), and a destination that IS a
                // symlink must be written *through* it: temp-then-rename
                // would silently replace the symlink itself with a plain
                // file, clobbering whatever pointed at it (e.g.
                // `latest.gz -> archives/….gz`). Either way, skip the temp
                // file and the rename entirely and write straight through the
                // path, truncating (or creating, for a dangling symlink) in
                // place.
                let write_direct = link_meta.as_ref().is_ok_and(|m| !m.is_file());
                if write_direct {
                    let f = std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(p)?;
                    return Ok(Opened {
                        writer: Box::new(f),
                        finish: None,
                    });
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
                        let mut opts = std::fs::OpenOptions::new();
                        opts.write(true).create_new(true);
                        // Create the temp file at mode 0600 from the start.
                        // Creating it at the default `0o666 & !umask` (usually
                        // 0644) and narrowing permissions afterwards leaves a
                        // window, between creation and the later
                        // `set_permissions` call below, where another local
                        // user can open the world/group-readable temp file and
                        // keep reading from that descriptor even after
                        // permissions are narrowed — a permission change never
                        // revokes an already-open fd. Starting at 0600 closes
                        // that window; the block below still widens the mode
                        // afterwards to match a pre-existing destination's own
                        // permissions.
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::OpenOptionsExt;
                            opts.mode(0o600);
                        }
                        match opts.open(&candidate) {
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
                // A second handle on the same temp file, taken before `f` is
                // boxed away as the writer, so `publish` can `sync_all()` it
                // after the codec has finished writing through the writer.
                let handle = f.try_clone()?;
                Ok(Opened {
                    writer: Box::new(f),
                    finish: Some(Finish {
                        tmp,
                        target: p.clone(),
                        handle: Some(handle),
                        sync,
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

/// Publishes a successful write: fsyncs the data, renames the temp file onto
/// the destination, then fsyncs the directory entry.
///
/// Must only be called after every byte (including any trailer) is written
/// and flushed — the rename is what makes the file visible under its real
/// name, so it has to be the last thing that happens on the success path.
///
/// **Durability, not just visibility.** Renaming without syncing first means
/// a crash can make the rename durable while the data behind it is not,
/// leaving a zero-length or partial file under the real name — exactly what
/// temp-then-rename exists to prevent. So the order here is: sync the temp
/// file's data, THEN rename, THEN (on unix) sync the directory entry so the
/// rename itself survives a crash. A sync after the rename would be a weaker
/// guarantee wearing the same name.
///
/// The directory fsync is unix-only — opening a directory as a `File` is not
/// portable to Windows. On Windows the file sync plus the rename is the
/// guarantee available; the two platforms are NOT equivalent here, and callers
/// should not assume otherwise.
///
/// **Even on unix, the directory fsync is best-effort, unlike the file
/// sync.** A failed `File::open` on the directory or a failed `sync_all` on
/// it is silently dropped, where the temp file's own `sync_all` above is a
/// hard error via `?`. That asymmetry is deliberate: the file sync protects
/// the data itself, so a failure there must stop the publish before the
/// rename makes anything visible. The directory sync only protects the
/// durability of the *rename* — its worst case, if skipped or if it silently
/// fails, is a crash that leaves the destination pointing at its previous
/// consistent state (old content, or absent) rather than at today's data,
/// not a corrupted file. That is a durability gap, not a correctness one, so
/// it is not worth failing an otherwise-successful publish over.
///
/// When `Finish::sync` is `false` (`--no-sync`), neither fsync runs: the
/// rename still happens, but a crash immediately after it can leave a
/// zero-length or partial file under the real name. That trade is the whole
/// point of the flag — speed for bulk or scratch work, in exchange for the
/// durability guarantee this function otherwise provides.
pub(crate) fn publish(finish: Option<Finish>) -> Result<()> {
    let Some(f) = finish else { return Ok(()) };

    // Order matters: the data must be durable BEFORE the rename that publishes
    // it, or a crash can leave the name pointing at a file whose contents never
    // reached the disk — the exact outcome temp-then-rename exists to prevent.
    // Nested `if`s rather than a let-chain: MSRV 1.85, let-chains land in 1.88.
    if f.sync {
        if let Some(h) = &f.handle {
            h.sync_all()?;
        }
    }

    if let Err(e) = std::fs::rename(&f.tmp, &f.target) {
        // The rename itself failed, so nothing was published: remove the
        // temp file rather than leaving it to strand on disk forever —
        // the caller only ever branches on success (`publish`) vs.
        // failure (`discard`), never both.
        let _ = std::fs::remove_file(&f.tmp);
        return Err(Error::from(e));
    }

    // Then the directory entry itself. Opening a directory as a File is not
    // portable, so this is unix-only: on Windows the file sync above plus the
    // rename is the guarantee available, and the docs must say so rather than
    // implying both platforms get the same promise.
    #[cfg(unix)]
    if f.sync {
        if let Some(dir) = f.target.parent() {
            let dir = if dir.as_os_str().is_empty() {
                std::path::Path::new(".")
            } else {
                dir
            };
            if let Ok(d) = std::fs::File::open(dir) {
                let _ = d.sync_all();
            }
        }
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

#[derive(Clone, Debug)]
pub struct CompressOpts {
    /// An explicit format. Wins over any extension — a flag is the more
    /// specific statement of intent, and an extension is only ever a hint.
    pub format: Option<FormatId>,
    pub level: Option<i32>,
    pub force: bool,
    /// Fsync the output before publishing it, so a crash cannot leave a
    /// zero-length or partial file under the real name. Defaults to `true`;
    /// `--no-sync` trades this durability guarantee for speed on bulk or
    /// scratch work — see `publish`.
    pub sync: bool,
}

impl Default for CompressOpts {
    fn default() -> Self {
        Self {
            format: None,
            level: None,
            force: false,
            sync: true,
        }
    }
}

/// What an operation did.
#[derive(Clone, Debug)]
pub struct Outcome {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub format: FormatId,
    pub fidelity: FidelityReport,
}

/// The build's one codec, or a usage error naming what to do about zero or
/// several.
///
/// While exactly one codec is registered, defaulting to it is unambiguous.
/// This becomes a usage error on its own the moment 1c adds a second.
fn default_format_in(reg: &Registry) -> Result<FormatId> {
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
    default_format_in(reg)
}

/// What to use as the output format when nothing names one: the build's one
/// codec.
///
/// A library consumer asks the same question `choose_format` answers
/// internally for `compress` — e.g. the CLI, falling back for `stf pack` when
/// neither `-o` nor `--format` was given — and duplicating the answer in the
/// binary is how the two would drift apart.
pub fn default_format() -> Result<FormatId> {
    default_format_in(crate::registry())
}

/// Compresses `src` into `dst`, using the build's default registry.
pub fn compress(src: Input, dst: Output, o: &CompressOpts) -> Result<Outcome> {
    compress_with(crate::registry(), src, dst, o)
}

/// Compresses `src` into `dst`, consulting `registry` rather than the
/// build's default — the hook a library consumer uses to hand `stf` a codec
/// it does not ship, or a deliberately reduced set.
pub fn compress_with(
    registry: &Registry,
    src: Input,
    dst: Output,
    o: &CompressOpts,
) -> Result<Outcome> {
    let format = choose_format(registry, &dst, o.format)?;
    let codec = registry.require_encoder(format)?;
    let encode = EncodeOpts {
        level: o.level,
        ..Default::default()
    };
    // Before any filesystem work: a rejected option must cost nothing.
    codec.check_encode_opts(&encode)?;

    let mut reader = src.open()?;
    // Computed from the source's actual seekability, the same way
    // `decompress` computes it — not assumed. `stf pack - -o x.gz` reads a
    // pipe, and claiming `Exact` for that would be a rung `compress` invented
    // rather than one it observed.
    let rung = if reader.caps().seekable {
        Rung::Exact
    } else {
        Rung::ForwardOnly
    };
    let opened = dst.create(o.force, o.sync)?;
    let (counted, written) = CountingWriter::new(opened.writer);

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
                fidelity: FidelityReport::new(rung),
            })
        }
        Err(e) => {
            discard(opened.finish);
            Err(e)
        }
    }
}

#[derive(Clone, Debug)]
pub struct DecompressOpts {
    /// An explicit format, overriding detection.
    pub format: Option<FormatId>,
    pub force: bool,
    /// Expansion ratio past which the decode is refused. See
    /// [`stuffr_core::RatioGuard`].
    pub max_ratio: u64,
    /// Fsync the output before publishing it, so a crash cannot leave a
    /// zero-length or partial file under the real name. Defaults to `true`;
    /// `--no-sync` trades this durability guarantee for speed on bulk or
    /// scratch work — see `publish`.
    pub sync: bool,
}

impl Default for DecompressOpts {
    fn default() -> Self {
        Self {
            format: None,
            force: false,
            max_ratio: DEFAULT_MAX_RATIO,
            sync: true,
        }
    }
}

/// Resolves the format of a probed stream, rejecting what this build cannot do.
///
/// `Chain` is `#[non_exhaustive]` and this crate is not its defining crate, so
/// the match needs a wildcard arm even though only three variants exist today
/// — a fourth added upstream must fail loudly here rather than fail to compile
/// silently-wrong.
fn codec_for(reg: &Registry, path: Option<&Path>, prefix: &[u8]) -> Result<FormatId> {
    match stuffr_core::resolve_chain(reg, path, prefix)? {
        Chain::Codec { codec, .. } => Ok(codec),
        Chain::Container { container } => Err(Error::Unsupported(format!(
            "`{container}` is a container; this build has codecs only (containers arrive in Phase 2)"
        ))),
        Chain::Raw => Err(Error::UnknownFormat {
            seen: "no codec layer".into(),
        }),
        _ => Err(Error::Unsupported(
            "unrecognised chain shape; this build does not know how to decode it".into(),
        )),
    }
}

/// Decompresses `src` into `dst`, using the build's default registry.
pub fn decompress(src: Input, dst: Output, o: &DecompressOpts) -> Result<Outcome> {
    decompress_with(crate::registry(), src, dst, o)
}

/// Decompresses `src` into `dst`, consulting `registry` rather than the
/// build's default.
pub fn decompress_with(
    registry: &Registry,
    src: Input,
    dst: Output,
    o: &DecompressOpts,
) -> Result<Outcome> {
    let path = src.path().map(Path::to_path_buf);

    let source = src.open()?;
    // Read the rung from the RAW source's capabilities, before `probe` runs.
    // In today's `probe`, a seekable source is handed back unwrapped (so caps
    // read afterwards would happen to still agree), but a pipe is wrapped in
    // a `PeekSource` whose `caps()` hardcodes `seekable: false`. Reading here,
    // first, is the order that stays correct regardless of how `probe`'s
    // wrapping evolves, rather than one that depends on today's wrapper
    // reporting the same thing the raw source did.
    let rung = if source.caps().seekable {
        Rung::Exact
    } else {
        Rung::ForwardOnly
    };

    let (prefix, source) = stuffr_core::probe(source)?;
    let format = match o.format {
        Some(f) => f,
        None => codec_for(registry, path.as_deref(), &prefix)?,
    };
    let codec = registry.require_decoder(format)?;

    let (counting, consumed) = Counting::new(source);
    let mut decoder = codec.decoder(Box::new(counting), &DecodeOpts::default())?;
    let mut guard = RatioGuard::new(Arc::clone(&consumed), o.max_ratio);

    let opened = dst.create(o.force, o.sync)?;
    let finish = opened.finish;
    let mut writer = opened.writer;

    let mut run = || -> Result<()> {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = decoder.read(&mut buf).map_err(Error::from_decode_io)?;
            if n == 0 {
                break;
            }
            guard.record(n)?;
            writer.write_all(&buf[..n])?;
        }
        // `Sink::finish`'s flush contract is the write side; a decode writes
        // straight to the destination rather than through a `Sink`, so it
        // has to flush itself before publishing.
        writer.flush()?;
        Ok(())
    };

    match run() {
        Ok(()) => {
            // Rename onto the final path only now: every byte has been
            // written AND flushed. Publishing earlier risks a truncated file
            // visible under the real name.
            publish(finish)?;
            Ok(Outcome {
                bytes_in: consumed.load(Ordering::Relaxed),
                bytes_out: guard.produced(),
                format,
                fidelity: FidelityReport::new(rung),
            })
        }
        Err(e) => {
            discard(finish);
            Err(e)
        }
    }
}

/// How `inspect` arrived at its answer.
///
/// `stf info` could not previously say this, so an empty `.gz` and a text file
/// named `.gz` reported identically and only `unpack` failed. Extension-as-
/// fallback is the documented design; the answer's provenance should still be
/// visible.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[non_exhaustive]
pub enum Detection {
    /// Leading bytes matched a registered magic rule.
    Magic,
    /// No magic matched; the path's extension decided.
    Extension,
    /// The caller named the format and detection was not consulted.
    Explicit,
}

/// What `stf info` reports.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Inspection {
    pub format: FormatId,
    /// The resolved pipeline, e.g. `"gzip"` or `"tar over gzip"`.
    pub chain: String,
    /// Flattened so `rung` and `warnings` land at the top level of the
    /// serialized object — the shape a consumer of the old hand-rolled JSON
    /// already expected, rather than a nested `"fidelity"` object nobody
    /// asked for. `Inspection` has no standalone `rung` field of its own:
    /// `Outcome` (the `compress`/`decompress` result) already reads the rung
    /// off its own `fidelity` this way, and a second field holding the same
    /// value by convention rather than by type would invite the two to drift.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub fidelity: FidelityReport,
    /// Input size, when the source knows it. A pipe does not.
    pub bytes_in: Option<u64>,
    /// How the format above was decided.
    pub detected_by: Detection,
}

/// Identifies a stream without decoding it, using the build's default
/// registry.
pub fn inspect(src: Input) -> Result<Inspection> {
    inspect_with(crate::registry(), src)
}

/// Identifies a stream without decoding it, consulting `registry` rather
/// than the build's default.
pub fn inspect_with(registry: &Registry, src: Input) -> Result<Inspection> {
    let path = src.path().map(Path::to_path_buf);

    let source = src.open()?;
    // Read BEFORE `probe`, for the same reason as in `decompress`: this is
    // the rung of the raw input, not of whatever wrapper detection happens to
    // apply on top of it.
    let caps = source.caps();
    let rung = if caps.seekable {
        Rung::Exact
    } else {
        Rung::ForwardOnly
    };

    let (prefix, _rest) = stuffr_core::probe(source)?;
    // Mirrors the first branch of `resolve_chain`'s own decision: the outer
    // format comes from the magic-hit set whenever that set is non-empty
    // (even when a tie among magic hits was later broken by the extension),
    // and only falls back to the path's extension when nothing matched by
    // magic at all. `inspect` takes no explicit format today, so `Explicit`
    // is unreachable from here — that is correct; it exists for the
    // `--format` override arriving in 1d.
    let detected_by = if registry.match_magic(&prefix).is_empty() {
        Detection::Extension
    } else {
        Detection::Magic
    };
    let chain = stuffr_core::resolve_chain(registry, path.as_deref(), &prefix)?;
    let format = match &chain {
        Chain::Codec { codec, .. } => *codec,
        Chain::Container { container } => *container,
        Chain::Raw => {
            return Err(Error::UnknownFormat {
                seen: "no codec layer".into(),
            });
        }
        _ => {
            return Err(Error::Unsupported(
                "unrecognised chain shape; this build does not know how to describe it".into(),
            ));
        }
    };

    Ok(Inspection {
        format,
        chain: chain.describe(),
        fidelity: FidelityReport::new(rung),
        bytes_in: caps.len,
        detected_by,
    })
}

/// The extension a format's output should carry, e.g. `"gz"` for gzip.
pub fn primary_extension(format: FormatId) -> Option<&'static str> {
    crate::registry()
        .matrix()
        .into_iter()
        .find(|r| r.id == format)
        .and_then(|r| r.extensions.first().copied())
}

/// Where `stf pack INPUT` writes when no `-o` is given.
///
/// Appends rather than replaces, so `notes.txt` becomes `notes.txt.gz` and
/// unpacking returns the original name.
pub fn suggest_packed(input: &Path, format: FormatId) -> Result<PathBuf> {
    let ext = primary_extension(format)
        .ok_or_else(|| Error::Usage(format!("`{format}` has no registered extension; pass -o")))?;
    let mut name = input.as_os_str().to_os_string();
    name.push(".");
    name.push(ext);
    Ok(PathBuf::from(name))
}

/// Where `stf unpack INPUT` writes when no `-o` is given.
pub fn suggest_unpacked(input: &Path) -> Result<PathBuf> {
    let known = input
        .extension()
        .and_then(|e| e.to_str())
        .and_then(|e| crate::registry().by_extension(e))
        .is_some();
    if known {
        Ok(input.with_extension(""))
    } else {
        Err(Error::Usage(format!(
            "cannot infer an output name from `{}`; pass -o",
            input.display()
        )))
    }
}
