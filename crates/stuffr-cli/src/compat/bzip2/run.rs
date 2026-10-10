//! The file loop: `compress`, `uncompress` and `testf` from bzip2.c, with
//! their checks in bzip2's order, and `compressStream`, `uncompressStream`
//! and `testStream` over stuffr's bzip2 codec.
//!
//! Output is written under a temporary name in the output's directory and
//! renamed into place on success, so a failure never leaves a partial file
//! behind. bzip2 writes the real name and deletes it on failure, which ends
//! in the same file tree; it is created mode 0600 either way.

use std::fs::{self, File, Metadata};
use std::io::{self, BufRead, BufWriter, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use stuffr::bzip2_stream::{StreamError, StreamReader};
use stuffr::{EncodeOpts, FormatId};

use super::args::{MAX_NAME, OpMode, Settings, SrcMode};
use super::messages::{self as m, printf};
use super::streams::{
    Counting, Input, Kind, c_remove, count_hard_links, errno_text, not_a_standard_file, out_writer,
    path, set_times, strerror,
};
use crate::compat::{copy_metadata_from, stdin_is_tty, stdout_is_tty};

/// `BZ_MAX_UNUSED`: libbzip2's read size, and bzip2's output chunk.
pub(super) const CHUNK: usize = 5000;

/// `zSuffix` and `unzSuffix`.
const SUFFIXES: [(&[u8], &[u8]); 4] = [
    (b".bz2", b""),
    (b".bz", b""),
    (b".tbz2", b".tar"),
    (b".tbz", b".tar"),
];

/// bzip2 has stopped (`exit` in bzip2.c); the code is in [`Bz::exit`].
pub(super) struct Fatal;
type Step = Result<(), Fatal>;

/// What ended a stream function early, reported by its caller once the
/// streams are closed (bzip2.c's `errhandler` cases).
enum Failure {
    Io(io::Error),
    Crc,
    /// The input's kind decides `perror`'s text.
    Eof(Kind),
    Memory,
    Panic(&'static str),
}

impl From<io::Error> for Failure {
    fn from(e: io::Error) -> Self {
        Failure::Io(e)
    }
}

/// Run the operation `s` describes; returns the exit code.
pub(super) fn execute(prog: &'static str, s: Settings, err: &mut dyn Write) -> u8 {
    let files = s.files.clone();
    let mut bz = Bz {
        prog,
        s,
        num_files: files.len(),
        exit: 0,
        processed: 0,
        in_name: b"(none)".to_vec(),
        out_name: b"(none)".to_vec(),
        pending: None,
        unz_fails: false,
        test_fails: false,
        err,
    };
    let _ = bz.main(&files);
    bz.exit
}

struct Bz<'a> {
    prog: &'static str,
    s: Settings,
    num_files: usize,
    /// `exitValue`: the worst code so far.
    exit: u8,
    /// `numFilesProcessed`.
    processed: usize,
    in_name: Vec<u8>,
    out_name: Vec<u8>,
    /// The temporary output while bzip2 would delete its output on a fatal
    /// error (`deleteOutputOnInterrupt`).
    pending: Option<PathBuf>,
    unz_fails: bool,
    test_fails: bool,
    err: &'a mut dyn Write,
}

impl Bz<'_> {
    fn main(&mut self, files: &[Vec<u8>]) -> Step {
        match self.s.op {
            OpMode::Compress => {
                if self.s.src == SrcMode::I2O {
                    self.compress(None)?;
                } else {
                    for f in files {
                        self.processed += 1;
                        self.compress(Some(f))?;
                    }
                }
            }
            OpMode::Decompress => {
                self.unz_fails = false;
                if self.s.src == SrcMode::I2O {
                    self.uncompress(None)?;
                } else {
                    for f in files {
                        self.processed += 1;
                        self.uncompress(Some(f))?;
                    }
                }
                if self.unz_fails {
                    self.set_exit(2);
                }
            }
            OpMode::Test => {
                self.test_fails = false;
                if self.s.src == SrcMode::I2O {
                    self.testf(None)?;
                } else {
                    for f in files {
                        self.processed += 1;
                        self.testf(Some(f))?;
                    }
                }
                if self.test_fails {
                    if self.s.noisy {
                        self.say(m::TEST_FAILS_ADVICE, &[]);
                    }
                    self.set_exit(2);
                }
            }
        }
        Ok(())
    }

    fn say(&mut self, fmt: &str, args: &[&[u8]]) {
        printf(self.err, fmt, args);
    }

    /// `setExit`.
    fn set_exit(&mut self, v: u8) {
        self.exit = self.exit.max(v);
    }

    fn p(&self) -> &'static [u8] {
        self.prog.as_bytes()
    }

    /// `copyFileName`'s length check, which ends the run.
    fn check_name(&mut self, name: &[u8]) -> Step {
        if name.len() > MAX_NAME {
            self.say(m::NAME_TOO_LONG, &[name, MAX_NAME.to_string().as_bytes()]);
            self.set_exit(1);
            return Err(Fatal);
        }
        Ok(())
    }

    /// The `-v` prefix and `pad`.
    fn verbose_prefix(&mut self) {
        if self.s.verbosity >= 1 {
            let name = self.in_name.clone();
            self.say(m::VERBOSE_PREFIX, &[&name]);
            let pad = self.s.longest.saturating_sub(name.len());
            let _ = self.err.write_all(&vec![b' '; pad]);
        }
    }

    /// A refusal that sets exit 1 and moves on to the next file.
    fn refuse(&mut self, fmt: &str, args: &[&[u8]]) {
        self.say(fmt, args);
        self.set_exit(1);
    }

    fn refuse_tty(&mut self, fmt: &str) {
        let p = self.p();
        self.say(fmt, &[p]);
        self.say(m::FOR_HELP, &[p, p]);
        self.set_exit(1);
    }

    /// Create the temporary output for `out_name` in its directory, mode
    /// 0600. Fails as bzip2's `O_CREAT|O_EXCL` open of `out_name` would.
    fn create_output(&self) -> io::Result<(PathBuf, File)> {
        let out = path(&self.out_name);
        if self.out_name.is_empty() {
            return Err(io::Error::from_raw_os_error(2)); // ENOENT
        }
        if fs::symlink_metadata(&out).is_ok() {
            return Err(io::Error::from_raw_os_error(17)); // EEXIST
        }
        let dir = match out.parent() {
            Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let mut opts = File::options();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        for n in 0u32.. {
            let tmp = dir.join(format!(".stuffr-bzip2-{}-{n}.tmp", std::process::id()));
            match opts.open(&tmp) {
                Ok(f) => return Ok((tmp, f)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && n < 1000 => {}
                Err(e) => return Err(e),
            }
        }
        unreachable!("the loop returns")
    }

    /// The checks `compress` and `uncompress` share after the name mapping,
    /// up to saving the input's metadata. `None`: refused, move on.
    fn common_checks(&mut self, compressing: bool, cant_guess: bool) -> Result<Option<()>, Fatal> {
        let (p, inp, out) = (self.p(), self.in_name.clone(), self.out_name.clone());
        let src = self.s.src;
        if src != SrcMode::I2O
            && let Err(e) = File::open(path(&inp))
        {
            self.refuse(m::CANT_OPEN_INPUT, &[p, &inp, &strerror(&e)]);
            return Ok(None);
        }
        if compressing {
            for (z, _) in SUFFIXES {
                if inp.ends_with(z) {
                    if self.s.noisy {
                        self.say(m::HAS_SUFFIX, &[p, &inp, z]);
                    }
                    self.set_exit(1);
                    return Ok(None);
                }
            }
        }
        if src != SrcMode::I2O && fs::metadata(path(&inp)).is_ok_and(|md| md.is_dir()) {
            self.refuse(m::IS_DIRECTORY, &[p, &inp]);
            return Ok(None);
        }
        if src == SrcMode::F2F && !self.s.force && not_a_standard_file(&path(&inp)) {
            if self.s.noisy {
                self.say(m::NOT_NORMAL_FILE, &[p, &inp]);
            }
            self.set_exit(1);
            return Ok(None);
        }
        if cant_guess && self.s.noisy {
            self.say(m::CANT_GUESS, &[p, &inp, &out]);
        }
        if src == SrcMode::F2F && File::open(path(&out)).is_ok() {
            if self.s.force {
                c_remove(&path(&out));
            } else {
                self.refuse(m::OUTPUT_EXISTS, &[p, &out]);
                return Ok(None);
            }
        }
        if src == SrcMode::F2F && !self.s.force {
            let n = count_hard_links(&path(&inp));
            if n > 0 {
                let s: &[u8] = if n > 1 { b"s" } else { b"" };
                self.refuse(m::HARD_LINKS, &[p, &inp, n.to_string().as_bytes(), s]);
                return Ok(None);
            }
        }
        Ok(Some(()))
    }

    /// `saveInputFileMetaInfo` (stat, following symlinks).
    fn save_meta(&mut self) -> Result<Option<Metadata>, Fatal> {
        if self.s.src != SrcMode::F2F {
            return Ok(None);
        }
        match fs::metadata(path(&self.in_name)) {
            Ok(md) => Ok(Some(md)),
            Err(e) => Err(self.fail(Failure::Io(e))),
        }
    }

    /// Open the input and output for a file-to-file run, reporting a refusal
    /// as bzip2 does (the output's failure first). `None`: move on.
    fn open_f2f(&mut self) -> Option<(File, PathBuf, File)> {
        let p = self.p();
        let inp = File::open(path(&self.in_name));
        let out = match self.create_output() {
            Ok(o) => o,
            Err(e) => {
                let name = self.out_name.clone();
                self.refuse(m::CANT_CREATE_OUTPUT, &[p, &name, &strerror(&e)]);
                return None;
            }
        };
        match inp {
            Ok(f) => Some((f, out.0, out.1)),
            Err(e) => {
                drop(out.1);
                let _ = fs::remove_file(&out.0);
                let name = self.in_name.clone();
                self.refuse(m::CANT_OPEN_INPUT, &[p, &name, &strerror(&e)]);
                None
            }
        }
    }

    /// Publish the finished temporary output under its name, then remove the
    /// input unless it is kept (the tail of `compress` and `uncompress`).
    /// `Ok(false)`: the output appeared meanwhile and was refused.
    ///
    /// Without `-f`, publishing must not replace anything: bzip2 creates its
    /// output with `O_EXCL`, so a file that appears after the existence check
    /// is refused, never clobbered. A rename would silently replace it, so the
    /// temporary is hard-linked to the name instead, which fails with
    /// `EEXIST` exactly where bzip2's open would, and then unlinked. Where the
    /// filesystem has no hard links, rename is the fallback. With `-f`, bzip2
    /// has already removed any existing output, and rename keeps that intent.
    fn commit(&mut self) -> Result<bool, Fatal> {
        if let Some(tmp) = self.pending.clone() {
            let out = path(&self.out_name);
            let published = if self.s.force {
                fs::rename(&tmp, &out)
            } else {
                match fs::hard_link(&tmp, &out) {
                    Ok(()) => fs::remove_file(&tmp),
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                        self.pending = None;
                        let _ = fs::remove_file(&tmp);
                        let (p, o) = (self.p(), self.out_name.clone());
                        self.refuse(m::OUTPUT_EXISTS, &[p, &o]);
                        return Ok(false);
                    }
                    Err(_) => fs::rename(&tmp, &out),
                }
            };
            if let Err(e) = published {
                return Err(self.fail(Failure::Io(e)));
            }
        }
        self.pending = None;
        if !self.s.keep
            && let Err(e) = fs::remove_file(path(&self.in_name))
        {
            return Err(self.fail(Failure::Io(e)));
        }
        Ok(true)
    }

    // ---- compress ----

    fn compress(&mut self, name: Option<&[u8]>) -> Step {
        self.pending = None;
        match (self.s.src, name) {
            (SrcMode::F2F, Some(n)) => {
                self.check_name(n)?;
                self.in_name = n.to_vec();
                self.out_name = [n, b".bz2"].concat();
            }
            (SrcMode::F2O, Some(n)) => {
                self.check_name(n)?;
                self.in_name = n.to_vec();
                self.out_name = b"(stdout)".to_vec();
            }
            _ => {
                self.in_name = b"(stdin)".to_vec();
                self.out_name = b"(stdout)".to_vec();
            }
        }
        if self.common_checks(true, false)?.is_none() {
            return Ok(());
        }
        let meta = self.save_meta()?;

        let (input, out_file): (Box<dyn Read>, Option<File>) = match self.s.src {
            SrcMode::I2O => {
                if stdout_is_tty() {
                    self.refuse_tty(m::NO_TTY_OUTPUT);
                    return Ok(());
                }
                (Box::new(Input::stdin()), None)
            }
            SrcMode::F2O => {
                let inp = File::open(path(&self.in_name));
                if stdout_is_tty() {
                    self.refuse_tty(m::NO_TTY_OUTPUT);
                    return Ok(());
                }
                match inp {
                    Ok(f) => (Box::new(f), None),
                    Err(e) => {
                        let (p, n) = (self.p(), self.in_name.clone());
                        self.refuse(m::CANT_OPEN_INPUT, &[p, &n, &strerror(&e)]);
                        return Ok(());
                    }
                }
            }
            SrcMode::F2F => {
                let Some((inp, tmp, out)) = self.open_f2f() else {
                    return Ok(());
                };
                self.pending = Some(tmp);
                (Box::new(inp), Some(out))
            }
        };

        self.verbose_prefix();
        let r = self.compress_stream(input, out_file, meta.as_ref());
        match r {
            Ok((nin, nout)) => {
                if self.s.verbosity >= 1 {
                    if nin == 0 {
                        self.say(m::NO_DATA, &[]);
                    } else {
                        let line = m::stats(nin, nout);
                        let _ = self.err.write_all(line.as_bytes());
                    }
                }
            }
            Err(f) => return Err(self.fail(f)),
        }
        if self.s.src == SrcMode::F2F {
            self.commit()?;
        }
        Ok(())
    }

    /// `compressStream`: encode at the chosen level through stuffr's bzip2
    /// codec, then (to a file) apply the saved attributes. Returns
    /// `(nbytes_in, nbytes_out)`.
    fn compress_stream(
        &mut self,
        mut input: Box<dyn Read>,
        out_file: Option<File>,
        meta: Option<&Metadata>,
    ) -> Result<(u64, u64), Failure> {
        let Some(codec) = stuffr::registry().codec(FormatId::new("bzip2")) else {
            return Err(Failure::Panic("compress:unexpected error"));
        };
        let nout = Arc::new(AtomicU64::new(0));
        let dst = Counting {
            inner: out_writer(out_file),
            n: nout.clone(),
        };
        let opts = EncodeOpts {
            level: Some(self.s.level as i32),
            ..EncodeOpts::default()
        };
        let mut enc = codec
            .encoder(Box::new(dst), &opts)
            .map_err(|_| Failure::Panic("compress:unexpected error"))?;
        let mut nin = 0u64;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = match input.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Failure::Io(e)),
            };
            nin += n as u64;
            enc.write_all(&buf[..n])?;
        }
        match enc.finish() {
            Ok(()) => {}
            Err(stuffr::Error::Io(e)) => return Err(Failure::Io(e)),
            Err(_) => return Err(Failure::Panic("compress:unexpected error")),
        }
        if let (Some(meta), Some(tmp)) = (meta, self.pending.as_deref()) {
            copy_metadata_from(meta, tmp)?;
        }
        Ok((nin, nout.load(Ordering::Relaxed)))
    }

    // ---- uncompress ----

    fn uncompress(&mut self, name: Option<&[u8]>) -> Step {
        self.pending = None;
        let mut cant_guess = false;
        match (self.s.src, name) {
            (SrcMode::F2F, Some(n)) => {
                self.check_name(n)?;
                self.in_name = n.to_vec();
                self.out_name = match SUFFIXES.iter().find(|(z, _)| n.ends_with(z)) {
                    Some((z, u)) => [&n[..n.len() - z.len()], u].concat(),
                    None => {
                        cant_guess = true;
                        [n, b".out"].concat()
                    }
                };
            }
            (SrcMode::F2O, Some(n)) => {
                self.check_name(n)?;
                self.in_name = n.to_vec();
                self.out_name = b"(stdout)".to_vec();
            }
            _ => {
                self.in_name = b"(stdin)".to_vec();
                self.out_name = b"(stdout)".to_vec();
            }
        }
        if self.common_checks(false, cant_guess)?.is_none() {
            return Ok(());
        }
        let meta = self.save_meta()?;

        let (mut input, out_file) = match self.s.src {
            SrcMode::I2O => {
                if stdin_is_tty() {
                    self.refuse_tty(m::NO_TTY_INPUT);
                    return Ok(());
                }
                (Input::stdin(), None)
            }
            SrcMode::F2O => match File::open(path(&self.in_name)) {
                Ok(f) => (Input::file(f), None),
                Err(e) => {
                    let (p, n) = (self.p(), self.in_name.clone());
                    self.refuse(m::CANT_OPEN_INPUT_NOSPACE, &[p, &n, &strerror(&e)]);
                    return Ok(());
                }
            },
            SrcMode::F2F => {
                let Some((inp, tmp, out)) = self.open_f2f() else {
                    return Ok(());
                };
                self.pending = Some(tmp);
                (Input::file(inp), Some(out))
            }
        };

        self.verbose_prefix();
        let mut out = out_writer(out_file);
        let r = self.uncompress_stream(&mut input, &mut out, meta.as_ref());
        drop(out);
        let magic_ok = match r {
            Ok(ok) => ok,
            Err(f) => return Err(self.fail(f)),
        };

        if magic_ok {
            if self.s.src == SrcMode::F2F && !self.commit()? {
                return Ok(());
            }
        } else {
            self.unz_fails = true;
            if let Some(tmp) = self.pending.take()
                && let Err(e) = fs::remove_file(&tmp)
            {
                return Err(self.fail(Failure::Io(e)));
            }
        }

        if magic_ok {
            if self.s.verbosity >= 1 {
                self.say(m::DONE, &[]);
            }
        } else {
            self.set_exit(2);
            if self.s.verbosity >= 1 {
                self.say(m::NOT_BZIP2_VERBOSE, &[]);
            } else {
                let (p, n) = (self.p(), self.in_name.clone());
                self.say(m::NOT_BZIP2, &[p, &n]);
            }
        }
        Ok(())
    }

    /// `uncompressStream`. `Ok(false)`: the first stream is not bzip2.
    fn uncompress_stream(
        &mut self,
        input: &mut Input,
        out: &mut BufWriter<Box<dyn Write + Send>>,
        meta: Option<&Metadata>,
    ) -> Result<bool, Failure> {
        let mut obuf = vec![0u8; CHUNK];
        let mut stream_no = 0u32;
        loop {
            let mut sr = StreamReader::new(self.s.small);
            stream_no += 1;
            loop {
                match sr.read(input, &mut obuf) {
                    Ok((n, end)) => {
                        out.write_all(&obuf[..n])?;
                        if end {
                            break;
                        }
                    }
                    Err(StreamError::Magic) => {
                        if self.s.force {
                            // `trycat`: not bzip2 (or garbage after it) and
                            // `-f`: copy the input as it is.
                            input.copy_raw(out)?;
                            return self.close_ok(out, meta);
                        }
                        if stream_no == 1 {
                            out.flush()?;
                            return Ok(false);
                        }
                        if self.s.noisy {
                            let (p, n) = (self.p(), self.in_name.clone());
                            self.say(m::TRAILING_GARBAGE, &[p, &n]);
                        }
                        // bzip2 closes the output here without applying the
                        // saved mode and owner; only the times follow.
                        out.flush()?;
                        if let (Some(meta), Some(tmp)) = (meta, self.pending.as_deref()) {
                            set_times(meta, tmp)?;
                        }
                        return Ok(true);
                    }
                    Err(e) => return Err(stream_failure(e, input.kind)),
                }
            }
            if input.fill_buf()?.is_empty() {
                break;
            }
        }
        self.close_ok(out, meta)
    }

    /// `closeok`: flush, then (to a file) apply the saved attributes.
    fn close_ok(
        &mut self,
        out: &mut BufWriter<Box<dyn Write + Send>>,
        meta: Option<&Metadata>,
    ) -> Result<bool, Failure> {
        out.flush()?;
        if let (Some(meta), Some(tmp)) = (meta, self.pending.as_deref()) {
            copy_metadata_from(meta, tmp)?;
        }
        Ok(true)
    }

    // ---- test ----

    fn testf(&mut self, name: Option<&[u8]>) -> Step {
        self.pending = None;
        self.out_name = b"(none)".to_vec();
        match name {
            Some(n) if self.s.src != SrcMode::I2O => {
                self.check_name(n)?;
                self.in_name = n.to_vec();
            }
            _ => self.in_name = b"(stdin)".to_vec(),
        }
        let (p, inp) = (self.p(), self.in_name.clone());
        if self.s.src != SrcMode::I2O {
            if let Err(e) = File::open(path(&inp)) {
                self.refuse(m::CANT_OPEN_INPUT_TEST, &[p, &inp, &strerror(&e)]);
                return Ok(());
            }
            if fs::metadata(path(&inp)).is_ok_and(|md| md.is_dir()) {
                self.refuse(m::IS_DIRECTORY, &[p, &inp]);
                return Ok(());
            }
        }
        let mut input = if self.s.src == SrcMode::I2O {
            if stdin_is_tty() {
                self.refuse_tty(m::NO_TTY_INPUT);
                return Ok(());
            }
            Input::stdin()
        } else {
            match File::open(path(&inp)) {
                Ok(f) => Input::file(f),
                Err(e) => {
                    self.refuse(m::CANT_OPEN_INPUT_NOSPACE, &[p, &inp, &strerror(&e)]);
                    return Ok(());
                }
            }
        };

        self.verbose_prefix();
        let all_ok = self.test_stream(&mut input)?;
        if all_ok && self.s.verbosity >= 1 {
            self.say(m::OK, &[]);
        }
        if !all_ok {
            self.test_fails = true;
        }
        Ok(())
    }

    /// `testStream`. A damaged file is a result, not a stop.
    fn test_stream(&mut self, input: &mut Input) -> Result<bool, Fatal> {
        let mut obuf = vec![0u8; CHUNK];
        let mut stream_no = 0u32;
        let e = 'streams: loop {
            let mut sr = StreamReader::new(self.s.small);
            stream_no += 1;
            loop {
                match sr.read(input, &mut obuf) {
                    Ok((_, true)) => break,
                    Ok(_) => {}
                    Err(e) => break 'streams e,
                }
            }
            match input.fill_buf() {
                Ok([]) => return Ok(true),
                Ok(_) => {}
                // An error before `errhandler`: no prefix.
                Err(e) => return Err(self.fail(Failure::Io(e))),
            }
        };

        // `errhandler`.
        let (p, n) = (self.p(), self.in_name.clone());
        if self.s.verbosity == 0 {
            self.say(m::TEST_PREFIX, &[p, &n]);
        }
        match e {
            StreamError::Data => {
                self.say(m::TEST_CRC, &[]);
                Ok(false)
            }
            StreamError::UnexpectedEof => {
                self.say(m::TEST_EOF, &[]);
                Ok(false)
            }
            StreamError::Magic if stream_no == 1 => {
                self.say(m::TEST_MAGIC, &[]);
                Ok(false)
            }
            StreamError::Magic => {
                if self.s.noisy {
                    self.say(m::TEST_TRAILING_GARBAGE, &[]);
                }
                Ok(true)
            }
            StreamError::Memory => Err(self.fail(Failure::Memory)),
            StreamError::Io(e) => Err(self.fail(Failure::Io(e))),
            _ => Err(self.fail(Failure::Panic("test:unexpected error"))),
        }
    }

    // ---- failures ----

    /// `showFileNames`.
    fn show_file_names(&mut self) {
        if self.s.noisy {
            let (i, o) = (self.in_name.clone(), self.out_name.clone());
            self.say(m::SHOW_FILE_NAMES, &[&i, &o]);
        }
    }

    /// `cadvise`.
    fn cadvise(&mut self) {
        if self.s.noisy {
            self.say(m::CADVISE, &[]);
        }
    }

    /// `perror(progName)`, given `strerror(errno)`.
    fn perror(&mut self, text: &[u8]) {
        let p = self.p();
        self.say(m::PERROR, &[p, text]);
    }

    /// The errno `perror` reports for a cut-short stream. Nothing set it on
    /// purpose; it is whatever the C library's stdio left behind, measured
    /// against bzip2 1.0.8 on macOS: 0 writing a file; otherwise by the
    /// input's kind, `EINVAL` for a regular file, `ENOTTY` for a device and
    /// `ENOTSUP` for a pipe. Elsewhere it is unmeasured, and 0 is used.
    fn eof_errno(&self, kind: Kind) -> i32 {
        if !cfg!(target_os = "macos") || self.s.src == SrcMode::F2F {
            return 0;
        }
        match kind {
            Kind::Regular => 22, // EINVAL
            Kind::Device => 25,  // ENOTTY
            Kind::Pipe => 45,    // ENOTSUP
        }
    }

    /// Report a failure the way bzip2.c's handler for it does, then
    /// `cleanUpAndFail`.
    fn fail(&mut self, f: Failure) -> Fatal {
        let p = self.p();
        match f {
            Failure::Io(e) => {
                self.say(m::IO_ERROR, &[p]);
                self.perror(&strerror(&e));
                self.show_file_names();
                self.clean_up_and_fail(1)
            }
            Failure::Crc => {
                self.say(m::CRC_ERROR, &[p]);
                self.show_file_names();
                self.cadvise();
                self.clean_up_and_fail(2)
            }
            Failure::Eof(kind) => {
                if self.s.noisy {
                    self.say(m::STREAM_EOF, &[p]);
                    let n = self.eof_errno(kind);
                    self.perror(&errno_text(n));
                    self.show_file_names();
                    self.cadvise();
                }
                self.clean_up_and_fail(2)
            }
            Failure::Memory => {
                self.say(m::OUT_OF_MEMORY, &[p]);
                self.show_file_names();
                self.clean_up_and_fail(1)
            }
            Failure::Panic(what) => {
                self.say(m::PANIC, &[p, what.as_bytes()]);
                self.show_file_names();
                self.clean_up_and_fail(3)
            }
        }
    }

    /// `cleanUpAndFail`.
    fn clean_up_and_fail(&mut self, ec: u8) -> Fatal {
        let p = self.p();
        if self.s.src == SrcMode::F2F
            && self.s.op != OpMode::Test
            && let Some(tmp) = self.pending.take()
        {
            let out = self.out_name.clone();
            if fs::metadata(path(&self.in_name)).is_ok() {
                if self.s.noisy {
                    self.say(m::DELETING_OUTPUT, &[p, &out]);
                }
                if fs::remove_file(&tmp).is_err() {
                    self.say(m::DELETION_FAILED, &[p]);
                }
            } else {
                // bzip2 keeps the partial output when the input has gone.
                let _ = fs::rename(&tmp, path(&out));
                self.say(m::DELETION_SUPPRESSED, &[p]);
                self.say(m::SINCE_INPUT_GONE, &[p]);
                self.say(m::MAY_BE_INCOMPLETE, &[p, &out]);
                self.say(m::SUGGEST_TEST, &[p]);
            }
        }
        if self.s.noisy && self.num_files > 0 && self.processed < self.num_files {
            let (n, left) = (
                self.num_files.to_string(),
                (self.num_files - self.processed).to_string(),
            );
            self.say(m::NOT_PROCESSED, &[p, p, n.as_bytes(), left.as_bytes()]);
        }
        self.set_exit(ec);
        Fatal
    }
}

/// A stream error other than a bad magic, as a [`Failure`].
fn stream_failure(e: StreamError, kind: Kind) -> Failure {
    match e {
        StreamError::Data => Failure::Crc,
        StreamError::UnexpectedEof => Failure::Eof(kind),
        StreamError::Memory => Failure::Memory,
        StreamError::Io(e) => Failure::Io(e),
        _ => Failure::Panic("decompress:unexpected error"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(force: bool) -> Settings {
        Settings {
            op: OpMode::Compress,
            src: SrcMode::F2F,
            verbosity: 0,
            keep: true,
            small: false,
            force,
            noisy: true,
            level: 9,
            longest: 7,
            files: vec![],
        }
    }

    /// An output that appears between the existence check and publishing is
    /// refused, as bzip2's `O_EXCL` open would refuse it, never clobbered.
    #[test]
    fn publishing_never_replaces_an_output_that_appeared_meanwhile() {
        let dir = std::env::temp_dir().join(format!("stuffr-bz-commit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let (tmp, out) = (dir.join(".tmp"), dir.join("a.bz2"));
        for force in [false, true] {
            fs::write(&tmp, b"new").unwrap();
            fs::write(&out, b"appeared").unwrap();
            let mut err = Vec::new();
            let mut bz = Bz {
                prog: "bzip2",
                s: settings(force),
                num_files: 1,
                exit: 0,
                processed: 1,
                in_name: b"a".to_vec(),
                out_name: out.as_os_str().as_encoded_bytes().to_vec(),
                pending: Some(tmp.clone()),
                unz_fails: false,
                test_fails: false,
                err: &mut err,
            };
            let published = bz.commit().ok().unwrap();
            let exit = bz.exit;
            let msg = String::from_utf8(err).unwrap();
            assert!(!tmp.exists(), "force={force}: the temporary is left");
            if force {
                assert!(published);
                assert_eq!(fs::read(&out).unwrap(), b"new");
                assert_eq!(exit, 0);
            } else {
                assert!(!published);
                assert_eq!(fs::read(&out).unwrap(), b"appeared");
                assert_eq!(exit, 1);
                assert_eq!(
                    msg,
                    format!("bzip2: Output file {} already exists.\n", out.display())
                );
            }
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
