//! `main`'s operand loop, `compress`, `decompress`, `setfile` and
//! `permission`, from Apple's `compress.c` (file_cmds-479, BSD-3-Clause,
//! `LICENSE-compress-bsd`), each in the order the C makes its calls, since
//! the order decides which message a failure prints.
//!
//! stdio is modelled where it shows: the input is read in `BUFSIZ` (1024)
//! pieces, and decompression in 1024-byte `zread` calls, a failing one's
//! bytes lost (`funopen`'s buffer is `BUFSIZ`, so `-c` output before a
//! failure is whole 1024-byte pieces).

use std::fs::{self, File, Metadata};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use super::args::{Settings, Style};
use super::lzw::{self, Decoder, Encoder, ZFail};
use super::messages as m;
use crate::compat::host::{self, CleanupGuard, Host};

/// `MAXPATHLEN`: `main`'s name buffer, terminator included.
const MAXPATHLEN: usize = 1024;

/// stdio's `BUFSIZ`: `compress`'s and `decompress`'s buffers.
const BUFSIZ: usize = 1024;

/// stdio's buffer for a terminal when `fstat` gives no block size.
const TTY_BUFSIZ: usize = 65536;

/// `strerror(EINVAL)`, what `zopen`'s range check and a bad code print.
const EINVAL_TEXT: &[u8] = b"Invalid argument";

/// The signals that remove the temporary of deviation A2: Apple has no
/// handler (ruling E3), but that file is stuffr's own, not Apple's output.
#[cfg(unix)]
const TEMP_SIGNALS: host::Signals = &[libc::SIGINT, libc::SIGTERM, libc::SIGHUP];
#[cfg(not(unix))]
const TEMP_SIGNALS: host::Signals = &[];

/// A file argument of `compress`/`decompress`: standard input or output
/// (`/dev/stdin`, `/dev/stdout` in the C), or a name.
#[derive(Clone, Copy)]
enum Name<'a> {
    Std,
    File(&'a [u8]),
}

impl<'a> Name<'a> {
    /// What the messages call it: the name, or the device the C opens.
    fn shown(self, output: bool) -> &'a [u8] {
        match (self, output) {
            (Name::File(b), _) => b,
            (Name::Std, false) => b"/dev/stdin",
            (Name::Std, true) => b"/dev/stdout",
        }
    }
}

/// Where an output goes while it is written.
enum Target {
    /// The named output itself (`fopen(out, "w")`).
    Direct(PathBuf),
    /// Deviation A2: a temporary beside it, renamed over it when complete.
    Temp {
        tmp: PathBuf,
        out: PathBuf,
        _guard: CleanupGuard,
    },
    Stdout,
}

impl Target {
    /// The file a failure removes and the size check reads.
    fn written(&self) -> Option<&Path> {
        match self {
            Target::Direct(p) => Some(p),
            Target::Temp { tmp, .. } => Some(tmp),
            Target::Stdout => None,
        }
    }
}

/// stdio's line buffering, which `fopen("/dev/stdout", "w")` gets on a
/// terminal (`__smakebuf`'s `__SLBF`): every line goes out in a `write` of
/// its own as soon as its newline arrives, and a longer stretch without
/// one whenever the buffer (the terminal's block size) fills. How the
/// writes are cut is visible: macOS's terminal driver, its queue full in
/// the middle of turning `\n` into `\r\n`, can repeat the `\r`, so
/// stdout's 64 KiB writes and Apple's lines show different bytes.
struct LineBuffered<W: Write> {
    inner: W,
    buf: Vec<u8>,
    cap: usize,
}

impl<W: Write> Write for LineBuffered<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        for piece in data.split_inclusive(|&b| b == b'\n') {
            let mut rest = piece;
            while !rest.is_empty() {
                let n = rest.len().min(self.cap - self.buf.len());
                self.buf.extend_from_slice(&rest[..n]);
                rest = &rest[n..];
                if self.buf.len() == self.cap {
                    self.flush()?;
                }
            }
            if piece.ends_with(b"\n") {
                self.flush()?;
            }
        }
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        let r = self.inner.write_all(&self.buf);
        self.buf.clear();
        r?;
        self.inner.flush()
    }
}

/// The run's state: compress.c's globals and the process around them.
struct Run<'h, 'e> {
    name: &'static str,
    host: &'h mut Host,
    err: &'e mut dyn Write,
    /// `eval`: the exit code, last writer wins.
    eval: u8,
    force: bool,
    verbose: bool,
    cat: bool,
    bits: i32,
}

/// `main` after `getopt`.
pub(super) fn execute(name: &'static str, s: Settings, host: &mut Host, err: &mut dyn Write) -> u8 {
    let mut r = Run {
        name,
        host,
        err,
        eval: 0,
        force: s.force,
        verbose: s.verbose,
        cat: s.cat,
        bits: s.bits,
    };
    if s.operands.is_empty() {
        r.cat = true;
        match s.style {
            Style::Compress => r.compress(Name::Std, Name::Std),
            Style::Decompress => r.decompress(Name::Std, Name::Std),
        }
        return r.eval;
    }
    // "The UNIX standard requires that `uncompress -c` be able to have
    // multiple file parameters given."
    if r.cat && s.style == Style::Compress && s.operands.len() > 1 {
        r.errx(m::C_ONE_FILE);
        return 1;
    }
    for op in &s.operands {
        let op = op.as_slice();
        match s.style {
            Style::Compress => {
                if op == b"-" {
                    r.cat = true;
                    r.compress(Name::Std, Name::Std);
                } else if r.cat {
                    r.compress(Name::File(op), Name::Std);
                } else if has_z_suffix(op) {
                    r.cwarnx(m::TRAILING_Z, &[op]);
                } else if op.len() > MAXPATHLEN - 3 {
                    r.cwarnx(m::NAME_TOO_LONG, &[op]);
                } else {
                    let newname = [op, b".Z"].concat();
                    r.compress(Name::File(op), Name::File(&newname));
                }
            }
            Style::Decompress => {
                if op == b"-" {
                    r.cat = true;
                    r.decompress(Name::Std, Name::Std);
                } else if !has_z_suffix(op) {
                    if op.len() > MAXPATHLEN - 3 {
                        r.cwarnx(m::NAME_TOO_LONG, &[op]);
                        continue;
                    }
                    let newname = [op, b".Z"].concat();
                    let out = if r.cat { Name::Std } else { Name::File(op) };
                    r.decompress(Name::File(&newname), out);
                } else {
                    if op.len() - 2 > MAXPATHLEN - 1 {
                        r.cwarnx(m::NAME_TOO_LONG, &[op]);
                        continue;
                    }
                    let base = &op[..op.len() - 2];
                    let out = if r.cat { Name::Std } else { Name::File(base) };
                    r.decompress(Name::File(op), out);
                }
            }
        }
    }
    r.eval
}

/// `(p = strrchr(name, '.')) != NULL && !strcmp(p, ".Z")`.
fn has_z_suffix(name: &[u8]) -> bool {
    name.iter()
        .rposition(|&b| b == b'.')
        .is_some_and(|i| &name[i..] == b".Z")
}

/// `fread(buf, 1, buf.len(), fp)`: as many bytes as there are up to the
/// buffer's size, and the error that stopped it short, if any.
fn fread(fp: &mut dyn Read, buf: &mut [u8]) -> (usize, Option<io::Error>) {
    let mut got = 0;
    while got < buf.len() {
        match fp.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return (got, Some(e)),
        }
    }
    (got, None)
}

/// C's `%.0f` of a ratio (NaN and infinity as Apple's printf spells them).
fn percent(x: f64) -> String {
    if x.is_nan() {
        "nan".into()
    } else if x.is_infinite() {
        if x < 0.0 { "-inf" } else { "inf" }.into()
    } else {
        format!("{x:.0}")
    }
}

impl Run<'_, '_> {
    fn path(&self, b: &[u8]) -> PathBuf {
        self.host.path(b)
    }

    /// `cwarnx`: the message after the program name; exit 1.
    fn cwarnx(&mut self, fmt: &str, args: &[&[u8]]) {
        m::printf(self.err, m::PREFIX, &[self.name.as_bytes()]);
        m::printf(self.err, fmt, args);
        let _ = self.err.write_all(m::NEWLINE.as_bytes());
        self.eval = 1;
    }

    /// `cwarn`: the message, then `strerror(errno)` (`text`); exit 1.
    fn cwarn(&mut self, fmt: &str, args: &[&[u8]], text: &[u8]) {
        m::printf(self.err, m::PREFIX, &[self.name.as_bytes()]);
        m::printf(self.err, fmt, args);
        m::printf(self.err, m::ERRNO_SUFFIX, &[text]);
        self.eval = 1;
    }

    /// `cwarn("%s", name)` for an I/O failure.
    fn cwarn_io(&mut self, name: &[u8], e: &io::Error) {
        self.cwarn("%s", &[name], &host::strerror(e));
    }

    /// `errx(1, msg)`: the caller returns 1.
    fn errx(&mut self, msg: &str) {
        m::printf(self.err, m::PREFIX, &[self.name.as_bytes()]);
        let _ = self.err.write_all(msg.as_bytes());
        let _ = self.err.write_all(m::NEWLINE.as_bytes());
    }

    /// `exists = !stat(out, &sb)` and the refusal of an existing regular
    /// output: `Err(())` when refused (the message printed), else the
    /// output's `stat` and `oreg`.
    fn check_output(&mut self, out: Name) -> Result<(Option<Metadata>, bool), ()> {
        let Name::File(o) = out else {
            // `/dev/stdout`, written only under `cat`: never refused, and
            // never removed, so `oreg` is never asked.
            return Ok((None, false));
        };
        let sb = fs::metadata(self.path(o)).ok();
        let is_reg = sb.as_ref().is_some_and(Metadata::is_file);
        if !self.force && is_reg && !self.cat && !self.permission(o) {
            self.cwarnx(m::ALREADY_EXISTS, &[o]);
            return Err(());
        }
        let oreg = sb.is_none() || is_reg;
        Ok((sb, oreg))
    }

    /// `permission`: ask on standard error when it is a terminal, read the
    /// answer's first byte from standard input (`rpmatch` in the C locale:
    /// `y` or `Y`), the rest of the line consumed.
    fn permission(&mut self, fname: &[u8]) -> bool {
        if !self.host.stderr_is_tty() {
            return false;
        }
        m::printf(self.err, m::OVERWRITE, &[fname]);
        let _ = self.err.flush();
        // Only the process has a terminal (`stderr_is_tty`), so this is
        // the real standard input, through stdio's buffer as `getchar`.
        let mut stdin = io::stdin().lock();
        let mut first = None;
        loop {
            let mut b = [0u8; 1];
            match stdin.read(&mut b) {
                Ok(1) => {
                    first.get_or_insert(b[0]);
                    if b[0] == b'\n' {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                _ => break,
            }
        }
        matches!(first, Some(b'y' | b'Y'))
    }

    /// The writer for an output opened as `file`, or standard output: the
    /// host's, line-buffered when standard output is a terminal, as stdio
    /// buffers it.
    fn writer(&self, file: Option<File>) -> Box<dyn Write> {
        if file.is_none() && self.host.stdout_is_tty() {
            let inner = host::stdout_writer();
            #[cfg(unix)]
            let cap = {
                use std::os::fd::AsFd;
                use std::os::unix::fs::MetadataExt;
                io::stdout()
                    .as_fd()
                    .try_clone_to_owned()
                    .ok()
                    .and_then(|fd| File::from(fd).metadata().ok())
                    .map_or(TTY_BUFSIZ, |m| (m.blksize() as usize).clamp(1, 1 << 20))
            };
            #[cfg(not(unix))]
            let cap = TTY_BUFSIZ;
            return Box::new(LineBuffered {
                inner,
                buf: Vec::with_capacity(cap),
                cap,
            });
        }
        Box::new(self.host.out_writer(file))
    }

    /// Open where the output is written: the output itself, or for
    /// deviation A2 (the output is the input, through a link) a temporary
    /// beside it.
    fn open_output(&mut self, out: Name, same: bool) -> io::Result<(Target, Option<File>)> {
        let Name::File(o) = out else {
            return Ok((Target::Stdout, None));
        };
        let path = self.path(o);
        if same {
            let dir = match path.parent() {
                Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
                _ => PathBuf::from("."),
            };
            let (tmp, f, guard) =
                host::create_temp_armed(self.host, &dir, "compress", TEMP_SIGNALS)?;
            return Ok((
                Target::Temp {
                    tmp,
                    out: path,
                    _guard: guard,
                },
                Some(f),
            ));
        }
        let f = File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        Ok((Target::Direct(path), Some(f)))
    }

    /// The failure path's `unlink(out)` (only a regular output not
    /// standard output), and a temporary's removal.
    fn discard(&self, target: &Target, oreg: bool) {
        match target {
            Target::Direct(p) if !self.cat && oreg => {
                let _ = fs::remove_file(p);
            }
            Target::Temp { tmp, .. } => {
                let _ = fs::remove_file(tmp);
            }
            _ => {}
        }
    }

    /// A finished temporary takes the output's name (deviation A2).
    fn publish(&mut self, target: &Target, shown: &[u8]) -> bool {
        if let Target::Temp { tmp, out, .. } = target
            && let Err(e) = fs::rename(tmp, out)
        {
            self.cwarn_io(shown, &e);
            let _ = fs::remove_file(tmp);
            return false;
        }
        true
    }

    /// Open the input: standard input, or `fopen(in, "r")` then
    /// `stat(in)`. `None` once the failure is reported.
    fn open_input(&mut self, inp: Name) -> Option<(Box<dyn Read>, Option<Metadata>)> {
        match inp {
            Name::Std => Some((Box::new(self.host.stdin()), None)),
            Name::File(i) => {
                let p = self.path(i);
                let f = match File::open(&p) {
                    Ok(f) => f,
                    Err(e) => {
                        self.cwarn_io(i, &e);
                        return None;
                    }
                };
                // "DON'T FSTAT!": the path, as the C has it.
                let meta = match fs::metadata(&p) {
                    Ok(m) => m,
                    Err(e) => {
                        self.cwarn_io(i, &e);
                        return None;
                    }
                };
                Some((Box::new(self.host.track(&p, f)), Some(meta)))
            }
        }
    }

    /// Deviation A2: the output exists and is the input itself (a symbolic
    /// or hard link between the two), which Apple would truncate before
    /// reading it.
    fn is_same(&self, sb: &Option<Metadata>, isb: &Option<Metadata>) -> bool {
        match (sb, isb) {
            (Some(o), Some(i)) if !self.cat && i.is_file() => host::same_file(i, o) == Some(true),
            _ => false,
        }
    }

    /// `compress(in, out, bits)`.
    fn compress(&mut self, inp: Name, out: Name) {
        let (in_shown, out_shown) = (inp.shown(false), out.shown(true));
        let Ok((sb, oreg)) = self.check_output(out) else {
            return;
        };
        let Some((mut input, isb)) = self.open_input(inp) else {
            return;
        };
        let isreg = oreg && isb.as_ref().is_some_and(Metadata::is_file);
        // `zopen(out, "w", bits)`: the range check comes first.
        if !lzw::bits_in_range(self.bits) {
            self.cwarn("%s", &[out_shown], EINVAL_TEXT);
            return;
        }
        let same = self.is_same(&sb, &isb);
        let (target, file) = match self.open_output(out, same) {
            Ok(t) => t,
            Err(e) => {
                self.cwarn_io(out_shown, &e);
                return;
            }
        };
        let mut enc = Encoder::new(self.writer(file), self.bits);
        let mut buf = [0u8; BUFSIZ];
        let failed = loop {
            let (n, rerr) = fread(&mut *input, &mut buf);
            if n > 0
                && let Err(e) = enc.write(&buf[..n])
            {
                self.cwarn_io(out_shown, &e);
                break true;
            }
            if let Some(e) = rerr {
                self.cwarn_io(in_shown, &e);
                break true;
            }
            if n == 0 {
                break false;
            }
        };
        drop(input);
        if failed {
            // `fclose(ofp)` on the way out: standard output gets the last
            // code and the buffer's rest, a file is removed first.
            if matches!(target, Target::Stdout) {
                let _ = enc.finish();
            }
            drop(enc);
            self.discard(&target, oreg);
            return;
        }
        if let Err(e) = enc.finish() {
            self.cwarn_io(out_shown, &e);
            let _ = enc.get_mut().flush();
            drop(enc);
            self.discard(&target, oreg);
            return;
        }
        drop(enc);
        let (Some(written), Some(isb)) = (target.written(), isb.as_ref()) else {
            return;
        };
        if self.cat || !isreg {
            return;
        }
        let size = match fs::metadata(written) {
            Ok(m) => m.len(),
            Err(e) => {
                self.cwarn_io(out_shown, &e);
                return;
            }
        };
        if !self.force && size >= isb.len() {
            if self.verbose {
                m::printf(self.err, m::WOULD_GROW, &[in_shown]);
            }
            self.eval = 2;
            if let Err(e) = fs::remove_file(written)
                && !matches!(target, Target::Temp { .. })
            {
                self.cwarn_io(out_shown, &e);
            }
            return;
        }
        if !self.publish(&target, out_shown) {
            return;
        }
        let Name::File(i) = inp else { return };
        let out_path = self.path(out_shown);
        self.setfile(out_shown, &out_path, isb);
        if let Err(e) = fs::remove_file(self.path(i)) {
            self.cwarn_io(i, &e);
        }
        if self.verbose {
            self.stats(out_shown, isb.len(), size);
        }
    }

    /// `decompress(in, out, bits)`.
    fn decompress(&mut self, inp: Name, out: Name) {
        let (in_shown, out_shown) = (inp.shown(false), out.shown(true));
        let Ok((sb, oreg)) = self.check_output(out) else {
            return;
        };
        // `zopen(in, "r", bits)`: the range check, then `fopen`.
        if !lzw::bits_in_range(self.bits) {
            self.cwarn("%s", &[in_shown], EINVAL_TEXT);
            return;
        }
        let Some((input, isb)) = self.open_input(inp) else {
            return;
        };
        let isreg = oreg && isb.as_ref().is_some_and(Metadata::is_file);
        let mut dec = Decoder::new(BufReader::with_capacity(BUFSIZ * 4, input));
        let mut buf = [0u8; BUFSIZ];
        // The first piece is read before the output is created.
        let nr = match dec.zread(&mut buf) {
            Ok(n) => n,
            Err(f) => {
                self.cwarn("%s", &[in_shown], zfail_text(f));
                return;
            }
        };
        // Only a header and nothing else reads 0 here: Apple refuses it
        // with a stale `errno`; stuffr writes the empty output it encodes
        // (deviation A3).
        debug_assert!(nr > 0 || dec.was_empty());
        let same = self.is_same(&sb, &isb);
        let (target, file) = match self.open_output(out, same) {
            Ok(t) => t,
            Err(e) => {
                self.cwarn_io(out_shown, &e);
                return;
            }
        };
        let mut w = self.writer(file);
        if let Err(e) = w.write_all(&buf[..nr]) {
            // Apple returns here without removing the output; only
            // stuffr's own temporary goes.
            self.cwarn_io(out_shown, &e);
            drop(w);
            self.discard(&target, false);
            return;
        }
        let failed = loop {
            match dec.zread(&mut buf) {
                Ok(0) => break false,
                Ok(n) => {
                    if let Err(e) = w.write_all(&buf[..n]) {
                        self.cwarn_io(out_shown, &e);
                        break true;
                    }
                }
                Err(f) => {
                    self.cwarn("%s", &[in_shown], zfail_text(f));
                    break true;
                }
            }
        };
        drop(dec);
        let flushed = if failed {
            // `fclose(ofp)` on the way out flushes what was written.
            let _ = w.flush();
            false
        } else {
            match w.flush() {
                Ok(()) => true,
                Err(e) => {
                    self.cwarn_io(out_shown, &e);
                    false
                }
            }
        };
        drop(w);
        if !flushed {
            self.discard(&target, oreg);
            return;
        }
        let Some(isb) = isb.as_ref() else { return };
        if self.cat || !isreg {
            return;
        }
        if !self.publish(&target, out_shown) {
            return;
        }
        let Name::File(i) = inp else { return };
        let out_path = self.path(out_shown);
        self.setfile(out_shown, &out_path, isb);
        if let Err(e) = fs::remove_file(self.path(i)) {
            self.cwarn_io(i, &e);
        }
        if self.verbose {
            // An unchecked `stat(out, &sb)`: a failure keeps the input's.
            let size = fs::metadata(&out_path).map_or(isb.len(), |m| m.len());
            self.stats(out_shown, isb.len(), size);
        }
    }

    /// The `-v` line: output / input as a whole percentage when the output
    /// is smaller, else input / output, in `float` as the C has it.
    fn stats(&mut self, out_shown: &[u8], isize: u64, osize: u64) {
        m::printf(self.err, m::STATS_NAME, &[out_shown]);
        if isize > osize {
            let pct = f64::from(osize as f32 / isize as f32) * 100.0;
            m::printf(self.err, m::STATS_COMPRESSION, &[percent(pct).as_bytes()]);
        } else {
            let pct = f64::from(isize as f32 / osize as f32) * 100.0;
            m::printf(self.err, m::STATS_EXPANSION, &[percent(pct).as_bytes()]);
        }
    }

    /// `setfile(name, fs)`: times, owner (a refusal drops set-id bits),
    /// mode, file flags, each by path, each failure a warning.
    fn setfile(&mut self, shown: &[u8], path: &Path, fs: &Metadata) {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            use std::os::unix::fs::MetadataExt;
            let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
                return;
            };
            let errno = || io::Error::last_os_error().raw_os_error().unwrap_or(0);
            let mut mode = fs.mode() & 0o6777;
            let times = [
                libc::timespec {
                    tv_sec: fs.atime() as libc::time_t,
                    tv_nsec: fs.atime_nsec() as libc::c_long,
                },
                libc::timespec {
                    tv_sec: fs.mtime() as libc::time_t,
                    tv_nsec: fs.mtime_nsec() as libc::c_long,
                },
            ];
            // SAFETY: `c` is a NUL-terminated path and `times` two timespecs.
            if unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) } != 0 {
                let e = host::errno_text(errno());
                self.cwarn(m::UTIMENSAT, &[shown], &e);
            }
            // SAFETY: as above.
            if unsafe { libc::chown(c.as_ptr(), fs.uid(), fs.gid()) } != 0 {
                let n = errno();
                if n != libc::EPERM {
                    self.cwarn(m::CHOWN, &[shown], &host::errno_text(n));
                }
                mode &= !0o6000;
            }
            // SAFETY: as above.
            if unsafe { libc::chmod(c.as_ptr(), mode as libc::mode_t) } != 0 {
                let n = errno();
                if n != libc::EOPNOTSUPP {
                    self.cwarn(m::CHMOD, &[shown], &host::errno_text(n));
                }
            }
            #[cfg(target_os = "macos")]
            {
                use std::os::macos::fs::MetadataExt as _;
                // SAFETY: as above.
                if unsafe { libc::chflags(c.as_ptr(), fs.st_flags() as _) } != 0 {
                    let n = errno();
                    if n != libc::EOPNOTSUPP {
                        self.cwarn(m::CHFLAGS, &[shown], &host::errno_text(n));
                    }
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (shown, path, fs);
        }
    }
}

/// `strerror` of the `errno` a failing `zread` set.
fn zfail_text(f: ZFail) -> &'static [u8] {
    match f {
        ZFail::Format => m::EFTYPE_TEXT.as_bytes(),
        ZFail::Code => EINVAL_TEXT,
    }
}
