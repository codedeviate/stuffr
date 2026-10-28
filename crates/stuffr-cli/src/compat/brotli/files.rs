//! The brotli tool's file handling, ported from `c/tools/brotli.c` of
//! brotli 1.2.1 (MIT): `NextFile`, `OpenFiles` (`OpenInputFile`,
//! `OpenOutputFile`), `CloseFiles`, `CopyStat`, `FileSize`,
//! `ReadDictionary` and `PrintablePath`. Compression and decompression
//! share it.
//!
//! Every path goes through [`Host`]: operands resolve against a sandbox's
//! directory there, inputs are counted ([`Host::track`]), standard input
//! and output are the host's.
//!
//! Where stuffr departs from the reference:
//! - **An output that is the input itself is refused** (ruling T1-f,
//!   deviation 4): with `-f` the reference opens the output `O_TRUNC`
//!   before reading, so `brotli -f -o a a` (or a hard link, or a symlink to
//!   the input as the output) truncates the input, and `-d` then unlinks
//!   it. stuffr compares the two by device and inode before the output is
//!   opened for writing and prints [`m::SAME_FILE`], exit 1. Without `-f`
//!   the reference's `O_EXCL` refusal already protects the input and is
//!   kept as it is. Likewise an output that is a later input operand
//!   (`brotli -f a a.br`, `-df a.br a`) is refused before it is opened
//!   ([`m::LATER_INPUT`], ruling T4-f): the reference overwrites that input
//!   before reading it.
//! - **`-j` keeps the input when closing the output failed** (ruling T4-g):
//!   the reference unlinks it even after `fclose` reported ENOSPC or EIO,
//!   leaving only a truncated output.
//! - **Standard output is never closed.** The reference `fclose`s it after
//!   a file, so `brotli - -` (two inputs both standard input, both written
//!   to standard output) dies of a null `FILE*` on the second; stuffr
//!   writes the second stream too.

use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};

use stuffr::brotli_opts::{Decoder, MAX_DICTIONARY_SIZE, PreparedDictionary, Refused};

use super::cli::{self, Command, Params};
use super::messages as m;
use crate::compat::host::{self, Host, InFile, Input, printf};

/// `PrintablePath`: the path's bytes, `con` for standard input or output.
pub(super) fn printable_path(path: Option<&OsStr>) -> Cow<'_, [u8]> {
    match path {
        Some(p) => Cow::Borrowed(cli::bytes(p)),
        None => Cow::Borrowed(b"con"),
    }
}

/// An open input: a file or standard input, read the way `fread` reads it
/// (a request is filled unless the input ends or fails; end of file is
/// sticky, `feof`).
pub(super) struct InputFile {
    src: Src,
    eof: bool,
}

enum Src {
    File(InFile),
    Stdin(Input),
}

impl InputFile {
    fn new(src: Src) -> Self {
        InputFile { src, eof: false }
    }

    /// `fread(buf, 1, buf.len(), f)`: how many bytes were read, and the
    /// error that stopped the read early (`ferror`), if one did.
    pub(super) fn fill(&mut self, buf: &mut [u8]) -> (usize, Option<io::Error>) {
        let mut n = 0;
        while n < buf.len() && !self.eof {
            let r = match &mut self.src {
                Src::File(f) => f.read(&mut buf[n..]),
                Src::Stdin(s) => s.read(&mut buf[n..]),
            };
            match r {
                Ok(0) => self.eof = true,
                Ok(k) => n += k,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return (n, Some(e)),
            }
        }
        (n, None)
    }

    /// `feof`: a read has met the end of the input.
    pub(super) fn eof(&self) -> bool {
        self.eof
    }
}

/// An open output: a file or standard output, buffered as stdio buffers.
pub(super) type OutputFile = BufWriter<Box<dyn Write + Send>>;

/// The parts of the reference's `Context` the file loop keeps.
pub(super) struct Ctx<'a> {
    pub(super) p: &'a Params,
    pub(super) host: &'a mut Host,
    pub(super) err: &'a mut dyn Write,
    /// Inputs used so far (`iterator`).
    iterator: usize,
    /// A name could not be mapped (`iterator_error`): the run fails.
    pub(super) iterator_error: bool,
    /// `current_input_path`; `None` is standard input.
    pub(super) input_path: Option<OsString>,
    /// `current_output_path`; `None` is standard output.
    pub(super) output_path: Option<OsString>,
    /// `input_file_length`: -1 when it cannot be known.
    pub(super) input_file_length: i64,
    pub(super) fin: Option<InputFile>,
    pub(super) fout: Option<OutputFile>,
    /// The raw dictionary (`-D`), read once.
    pub(super) dictionary: Option<Vec<u8>>,
    /// The dictionary prepared for the encoder (compression only).
    pub(super) prepared: Option<PreparedDictionary>,
    pub(super) total_in: u64,
    pub(super) total_out: u64,
    pub(super) start_time: f64,
    pub(super) end_time: f64,
}

impl<'a> Ctx<'a> {
    pub(super) fn new(p: &'a Params, host: &'a mut Host, err: &'a mut dyn Write) -> Self {
        Ctx {
            p,
            host,
            err,
            iterator: 0,
            iterator_error: false,
            input_path: None,
            output_path: None,
            input_file_length: -1,
            fin: None,
            fout: None,
            dictionary: None,
            prepared: None,
            total_in: 0,
            total_out: 0,
            start_time: 0.0,
            end_time: 0.0,
        }
    }

    /// `fprintf(stderr, fmt, ...)`.
    pub(super) fn say(&mut self, fmt: &str, args: &[&[u8]]) {
        printf(self.err, fmt, args);
    }

    /// The current input's printable path.
    pub(super) fn input_name(&self) -> Vec<u8> {
        printable_path(self.input_path.as_deref()).into_owned()
    }

    /// The current output's printable path.
    pub(super) fn output_name(&self) -> Vec<u8> {
        printable_path(self.output_path.as_deref()).into_owned()
    }
}

/// `FileSize`: the length `fseek(SEEK_END)` + `ftell` give, -1 when the
/// file cannot be opened or seeked. A FIFO or socket is -1 without being
/// opened (the reference's `fopen` would wait for a writer; its `fseek`
/// then fails anyway).
pub(super) fn file_size(host: &Host, path: &OsStr) -> i64 {
    let path = host.path(cli::bytes(path));
    let Ok(meta) = fs::metadata(&path) else {
        return -1;
    };
    if meta.is_file() {
        return i64::try_from(meta.len()).unwrap_or(i64::MAX);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        let t = meta.file_type();
        if t.is_fifo() || t.is_socket() {
            return -1;
        }
    }
    File::open(&path)
        .and_then(|mut f| f.seek(SeekFrom::End(0)))
        .map_or(-1, |n| i64::try_from(n).unwrap_or(i64::MAX))
}

/// `NextFile`: the next input and the output it goes to; `false` when the
/// inputs are done or a name cannot be mapped (then `iterator_error`).
pub(super) fn next_file(ctx: &mut Ctx) -> bool {
    let p = ctx.p;
    ctx.iterator += 1;
    ctx.input_file_length = -1;

    // No input path: read from standard input.
    if p.inputs.is_empty() {
        if ctx.iterator > 1 {
            return false;
        }
        ctx.input_path = None;
        ctx.output_path = p.output_path.clone();
        return true;
    }
    let Some(arg) = p.inputs.get(ctx.iterator - 1) else {
        return false;
    };
    let arg_bytes = cli::bytes(arg);
    if arg_bytes == b"-" {
        ctx.input_path = None;
        ctx.output_path = p.output_path.clone();
        return true;
    }

    ctx.input_path = Some(arg.clone());
    ctx.input_file_length = file_size(ctx.host, arg);
    ctx.output_path = p.output_path.clone();
    if p.output_path.is_some() || p.write_to_stdout {
        return true;
    }

    let mut name = arg_bytes.to_vec();
    let suffix = cli::bytes(&p.suffix);
    if p.decompress {
        // The suffix must end the file name (after the last `/` or `\`).
        let base_len = cli::file_name(&name).len();
        if base_len < suffix.len() + 1 {
            ctx.say(m::EMPTY_OUTPUT_NAME, &[arg_bytes]);
            ctx.iterator_error = true;
            return false;
        }
        if !name.ends_with(suffix) {
            ctx.say(m::SUFFIX_MISMATCH, &[arg_bytes]);
            ctx.iterator_error = true;
            return false;
        }
        name.truncate(name.len() - suffix.len());
    } else {
        name.extend_from_slice(suffix);
    }
    ctx.output_path = Some(cli::os(&name));
    true
}

/// `OpenFiles`: the input, then (unless testing) the output. Each failure
/// is printed; `false` if either failed.
pub(super) fn open_files(ctx: &mut Ctx) -> bool {
    let Some(input_meta) = open_input(ctx) else {
        return false;
    };
    if ctx.p.test_integrity {
        return true;
    }
    open_output(ctx, input_meta.as_ref())
}

/// `OpenInputFile`. `Some` (with the input's metadata, if it has any) when
/// it opened.
fn open_input(ctx: &mut Ctx) -> Option<Option<Metadata>> {
    let Some(name) = ctx.input_path.clone() else {
        let meta = match ctx.host {
            Host::Real => host::stdin_file().ok().and_then(|f| f.metadata().ok()),
            Host::Sandbox(_) => None,
        };
        ctx.fin = Some(InputFile::new(Src::Stdin(ctx.host.stdin())));
        return Some(meta);
    };
    let path = ctx.host.path(cli::bytes(&name));
    match File::open(&path) {
        Ok(f) => {
            let meta = f.metadata().ok();
            ctx.fin = Some(InputFile::new(Src::File(ctx.host.track(&path, f))));
            Some(meta)
        }
        Err(e) => {
            ctx.say(
                m::OPEN_INPUT_FAILED,
                &[cli::bytes(&name), &host::strerror(&e)],
            );
            None
        }
    }
}

/// The first input operand after the current one (not `-`) that is the
/// file `output` describes (ruling T4-f).
fn later_input_at(ctx: &Ctx, output: &Metadata) -> Option<OsString> {
    ctx.p
        .inputs
        .iter()
        .skip(ctx.iterator)
        .filter(|a| cli::bytes(a) != b"-")
        .find(|a| {
            fs::metadata(ctx.host.path(cli::bytes(a)))
                .is_ok_and(|i| host::same_file(&i, output) == Some(true))
        })
        .cloned()
}

/// `OpenOutputFile`: standard output, or `open(O_CREAT | O_WRONLY |
/// O_TRUNC, 0600)` with `O_EXCL` unless `-f`. Before a forced open the
/// output is checked against the input (module doc).
fn open_output(ctx: &mut Ctx, input: Option<&Metadata>) -> bool {
    let Some(name) = ctx.output_path.clone() else {
        ctx.fout = Some(ctx.host.out_writer(None));
        return true;
    };
    let path = ctx.host.path(cli::bytes(&name));
    let force = ctx.p.force_overwrite;
    if force
        && let Some(i) = input
        && let Ok(o) = fs::metadata(&path)
        && host::same_file(i, &o) == Some(true)
    {
        let input_name = ctx.input_name();
        ctx.say(m::SAME_FILE, &[&input_name]);
        return false;
    }
    if force
        && let Ok(o) = fs::metadata(&path)
        && let Some(later) = later_input_at(ctx, &o)
    {
        let input_name = ctx.input_name();
        ctx.say(m::LATER_INPUT, &[cli::bytes(&later), &input_name]);
        return false;
    }
    let mut opts = File::options();
    opts.write(true).truncate(true);
    if force {
        opts.create(true);
    } else {
        opts.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(&path) {
        Ok(f) => {
            ctx.fout = Some(ctx.host.out_writer(Some(f)));
            true
        }
        Err(e) => {
            ctx.say(
                m::OPEN_OUTPUT_FAILED,
                &[cli::bytes(&name), &host::strerror(&e)],
            );
            false
        }
    }
}

/// `CloseFiles`: close the output (unlink it when `rm_output`, else copy
/// the input's attributes unless `-n`), close the input, unlink it when
/// `rm_input` and the output closed cleanly (T4-g). `false` if closing the
/// output failed.
pub(super) fn close_files(ctx: &mut Ctx, rm_input: bool, rm_output: bool) -> bool {
    let mut is_ok = true;
    if !ctx.p.test_integrity
        && let Some(mut out) = ctx.fout.take()
    {
        if let Err(e) = out.flush() {
            let name = ctx.output_name();
            ctx.say(m::FCLOSE_FAILED, &[&name, &host::strerror(&e)]);
            is_ok = false;
        }
        // The buffer is flushed (or its failure reported): what is left is
        // dropped with the descriptor.
        drop(out.into_parts());
        if rm_output && let Some(o) = &ctx.output_path {
            let _ = fs::remove_file(ctx.host.path(cli::bytes(o)));
        }
        // TOCTOU, as in the reference: the times can only be set by path.
        if !rm_output && is_ok && ctx.p.copy_stat {
            copy_stat(ctx);
        }
    }
    ctx.fout = None;
    ctx.fin = None;
    // Ruling T4-g: the input goes only once its output is safely closed
    // (the reference unlinks it even after a failed `fclose`).
    if rm_input
        && is_ok
        && let Some(i) = &ctx.input_path
    {
        let _ = fs::remove_file(ctx.host.path(cli::bytes(i)));
    }
    is_ok
}

/// `CopyStat`: the input's access and modification times, permission
/// bits, group and owner onto the output, each failure but the times'
/// printed. Nothing for standard input or output, or when the input cannot
/// be `stat`ed.
///
/// The times follow the reference's build: `HAVE_UTIMENSAT` holds only
/// where `_POSIX_C_SOURCE >= 200809L` is defined, which glibc's headers do
/// by default and macOS's and the BSDs' do not. So on glibc the times are
/// set with nanoseconds and `AT_SYMLINK_NOFOLLOW` (`utimensat`); elsewhere
/// in whole seconds through a symlink (`utime`): probed, Homebrew's 1.2.1
/// on macOS leaves the nanoseconds 0.
pub(super) fn copy_stat(ctx: &mut Ctx) {
    let (Some(input), Some(output)) = (ctx.input_path.clone(), ctx.output_path.clone()) else {
        return;
    };
    let Ok(meta) = fs::metadata(ctx.host.path(cli::bytes(&input))) else {
        return;
    };
    let out = ctx.host.path(cli::bytes(&output));
    let name = cli::bytes(&output);
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let glibc = cfg!(all(target_os = "linux", target_env = "gnu"));
        let nsec = |n: i64| if glibc { n } else { 0 };
        if let Ok(c) = std::ffi::CString::new(out.as_os_str().as_bytes()) {
            let times = [
                libc::timespec {
                    tv_sec: meta.atime() as libc::time_t,
                    tv_nsec: nsec(meta.atime_nsec()) as _,
                },
                libc::timespec {
                    tv_sec: meta.mtime() as libc::time_t,
                    tv_nsec: nsec(meta.mtime_nsec()) as _,
                },
            ];
            let flags = if glibc { libc::AT_SYMLINK_NOFOLLOW } else { 0 };
            // SAFETY: `c` is a NUL-terminated path and `times` two valid
            // timespecs, both alive for the call. The result is ignored, as
            // the reference ignores it.
            unsafe {
                libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), flags);
            }
        }
        let mode = fs::Permissions::from_mode(meta.mode() & 0o777);
        if let Err(e) = fs::set_permissions(&out, mode) {
            ctx.say(m::ACCESS_BITS_FAILED, &[name, &host::strerror(&e)]);
        }
        if let Err(e) = std::os::unix::fs::chown(&out, None, Some(meta.gid())) {
            ctx.say(m::GROUP_FAILED, &[name, &host::strerror(&e)]);
        }
        if let Err(e) = std::os::unix::fs::chown(&out, Some(meta.uid()), None) {
            ctx.say(m::USER_FAILED, &[name, &host::strerror(&e)]);
        }
    }
    #[cfg(not(unix))]
    {
        // `utime`; `chmod`/`chown` are `(0)` on Windows in the reference.
        let _ = name;
        let _ = host::set_times(&meta, &out);
    }
}

/// `ReadDictionary`: read `-D`'s file once, before any input (`-D` beyond
/// `MAX_DICTIONARY_SIZE` refused unread), and prepare it for the encoder
/// when compressing. The pure tier refuses a dictionary here, in both
/// directions, once the file has been read (ruling T1-b).
pub(super) fn read_dictionary(ctx: &mut Ctx, command: Command) -> bool {
    let Some(dp) = ctx.p.dictionary_path.clone() else {
        return true;
    };
    let name = cli::bytes(&dp);
    let path = ctx.host.path(name);
    let file = match File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            ctx.say(m::OPEN_DICTIONARY_FAILED, &[name, &host::strerror(&e)]);
            return false;
        }
    };
    let size = file_size(ctx.host, &dp);
    if size == -1 {
        ctx.say(m::DICTIONARY_SIZE_UNKNOWN, &[name]);
        return false;
    }
    if size > MAX_DICTIONARY_SIZE as i64 {
        let max = MAX_DICTIONARY_SIZE.to_string();
        ctx.say(m::DICTIONARY_TOO_LARGE, &[name, max.as_bytes()]);
        return false;
    }
    let size = usize::try_from(size).unwrap_or(0);
    let mut buffer = vec![0u8; size];
    let mut file = ctx.host.track(&path, file);
    let mut got = 0;
    while got < size {
        match file.read(&mut buffer[got..]) {
            Ok(0) => break,
            Ok(k) => got += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                ctx.say(m::READ_DICTIONARY_FAILED, &[name, &host::strerror(&e)]);
                return false;
            }
        }
    }
    if got != size {
        // A short read with no error: `errno` says nothing more.
        ctx.say(m::READ_DICTIONARY_FAILED, &[name, &host::errno_text(0)]);
        return false;
    }
    if command == Command::Compress {
        match PreparedDictionary::new(&buffer, m::MAX_QUALITY) {
            Ok(d) => ctx.prepared = Some(d),
            Err(Refused::Dictionary) => {
                ctx.say(m::DICTIONARY_PURE_TIER, &[]);
                return false;
            }
            Err(_) => {
                ctx.say(m::PREPARE_DICTIONARY_FAILED, &[name]);
                return false;
            }
        }
    } else if let Err(Refused::Dictionary) = Decoder::new(true, Some(&[])) {
        ctx.say(m::DICTIONARY_PURE_TIER, &[]);
        return false;
    }
    ctx.dictionary = Some(buffer);
    true
}
