//! `main` after its option loop, `comprexx`, `compdir`, `prratio`,
//! `read_error`, `write_error` and `abort_compress`, from ncompress 5.0's
//! `compress.c` (the Unlicense, `LICENSE-ncompress`) with Ubuntu's 5.0-1
//! build: `stat` where upstream's `-DLSTAT` build calls `lstat`
//! (`fix-softlinks.patch`), so symbolic links are followed. Each in the
//! order the C makes its calls, since the order decides which message a
//! failure prints.
//!
//! The C's I/O is `read(2)` and `write(2)` on descriptors, so the data
//! here goes through one read and one flushed write per C call
//! (`lzw::read_once`, `lzw::put`); `printf` text (`-r`'s `unreadable`) is
//! stdio's, held until the run ends when standard output is not a
//! terminal. `abort_compress()` exits the process: here it ends the run
//! ([`Abort`]) after removing the armed output.

use std::fs::{self, File, Metadata};
use std::io::{self, Read, Write};
use std::path::PathBuf;

use super::args::Settings;
use super::lzw::{self, Corrupt, Counts, DecTables, EncTables, End, Fail};
use super::messages as m;
use crate::compat::host::{self, CleanupGuard, Host};

/// `abort_compress()` was called: the run is over, exit 1.
struct Abort;

/// The run's state: `compress.c`'s globals and the process around them.
struct Run<'h, 'e> {
    host: &'h mut Host,
    err: &'e mut dyn Write,
    s: Settings,
    /// `fgnd_flag`: SIGINT was not ignored at start.
    fgnd: bool,
    /// `exit_code`: -1 until something is processed, last writer wins.
    exit_code: i32,
    /// `ifname`: the input's name, empty for standard input.
    ifname: Vec<u8>,
    /// `ofname`, while an output is known.
    ofname: Option<Vec<u8>>,
    /// `remove_ofname`: the output a failure removes, armed for the
    /// signal handler too.
    armed: Option<CleanupGuard>,
    /// `inbuf`, shared by both coders and the overwrite question.
    inbuf: Vec<u8>,
    enc: Option<EncTables>,
    dec: Option<DecTables>,
    /// `printf` to standard output (stdio, flushed at exit).
    stdio: Vec<u8>,
}

/// `main` from its file list on: every operand through `comprexx`, or
/// standard input to standard output. The exit code.
pub(super) fn execute(s: Settings, host: &mut Host, err: &mut dyn Write) -> u8 {
    let fgnd = host::install_abort_exit(host);
    let mut r = Run {
        host,
        err,
        s,
        fgnd,
        exit_code: -1,
        ifname: Vec::new(),
        ofname: None,
        armed: None,
        inbuf: vec![0; lzw::INBUF_ALLOC],
        enc: None,
        dec: None,
        stdio: Vec::new(),
    };
    let code = match r.main() {
        Ok(()) => {
            if r.s.recursive && r.exit_code == -1 {
                let _ = r.err.write_all(m::NO_FILES_RECURSIVE.as_bytes());
            }
            if r.exit_code == -1 {
                1
            } else {
                r.exit_code as u8
            }
        }
        Err(Abort) => 1,
    };
    r.flush_stdio();
    code
}

/// `prratio`: `num / den` as a percentage with two decimals, in the C's
/// fixed point (`q` an `int`).
fn prratio(num: i64, den: i64) -> Vec<u8> {
    let mut q: i32 = if den > 0 {
        if num > 214_748 {
            (num / (den / 10000)) as i32
        } else {
            (10000 * num / den) as i32
        }
    } else {
        10000
    };
    let mut s = Vec::new();
    if q < 0 {
        s.push(b'-');
        q = q.wrapping_neg();
    }
    s.extend_from_slice(format!("{}.{:02}%", q / 100, q % 100).as_bytes());
    s
}

/// `(p = name + len - 2) == ".Z"`, for a name of two bytes or more.
fn has_z_suffix(name: &[u8]) -> bool {
    name.len() >= 2 && name.ends_with(b".Z")
}

impl Run<'_, '_> {
    fn path(&self, b: &[u8]) -> PathBuf {
        self.host.path(b)
    }

    fn say(&mut self, fmt: &str, args: &[&[u8]]) {
        m::printf(self.err, fmt, args);
    }

    /// `perror(s)` for `e`.
    fn perror(&mut self, s: &[u8], e: &io::Error) {
        let text = host::strerror(e);
        self.perror_text(s, &text);
    }

    /// `perror(s)` with `strerror`'s `text`: an empty `s` prints the text
    /// alone, as `perror` leaves out the colon then.
    fn perror_text(&mut self, s: &[u8], text: &[u8]) {
        if s.is_empty() {
            self.say(m::PERROR_BARE, &[text]);
        } else {
            self.say(m::PERROR, &[s, text]);
        }
    }

    /// Hand `printf`'s pending text to standard output.
    fn flush_stdio(&mut self) {
        if !self.stdio.is_empty() {
            let mut w = self.host.out_writer(None);
            let _ = w.write_all(&std::mem::take(&mut self.stdio));
            let _ = w.flush();
        }
    }

    /// `abort_compress()`: the armed output removed, the run over.
    fn abort(&mut self) -> Abort {
        if self.armed.take().is_some()
            && let Some(o) = &self.ofname
        {
            let _ = fs::remove_file(self.path(o));
        }
        Abort
    }

    /// A coder's failure: `read_error()`, `write_error()` or the corrupt
    /// input lines, then `abort_compress()`.
    fn fail(&mut self, f: Fail) -> Abort {
        match f {
            Fail::Read(e) => {
                let _ = self.err.write_all(m::READ_ERROR.as_bytes());
                let who = if self.ifname.is_empty() {
                    b"stdin".to_vec()
                } else {
                    self.ifname.clone()
                };
                self.perror(&who, &e);
            }
            Fail::Write(e) => {
                let _ = self.err.write_all(m::WRITE_ERROR.as_bytes());
                let who = self.ofname.clone().unwrap_or_else(|| b"stdout".to_vec());
                self.perror(&who, &e);
            }
            Fail::Corrupt(c) => {
                match c {
                    Corrupt::FirstCode(code) => {
                        let code = code.to_string();
                        self.say(m::FIRST_CODE, &[code.as_bytes()]);
                    }
                    Corrupt::Code {
                        insize,
                        posbits,
                        bytes,
                    } => {
                        let n: Vec<String> = [insize.to_string(), posbits.to_string()]
                            .into_iter()
                            .chain(bytes.iter().map(|b| format!("{b:02X}")))
                            .chain([(posbits & 7).to_string()])
                            .collect();
                        let args: Vec<&[u8]> = n.iter().map(|s| s.as_bytes()).collect();
                        self.say(m::BAD_CODE, &args);
                    }
                    Corrupt::Chain => {}
                }
                let _ = self.err.write_all(m::CORRUPT_INPUT.as_bytes());
            }
        }
        self.abort()
    }

    /// `main`'s operand loop or its standard-input branch.
    fn main(&mut self) -> Result<(), Abort> {
        let files = std::mem::take(&mut self.s.files);
        if !files.is_empty() {
            for f in &files {
                self.comprexx(f)?;
            }
            return Ok(());
        }
        self.ifname.clear();
        self.exit_code = 0;
        let mut input = self.stdin_reader();
        let mut out = self.host.out_writer(None);
        if !self.s.decomp {
            let c = self.compress(&mut *input, &mut out)?;
            if !self.s.zcat && !self.s.quiet {
                let pct = prratio(c.bytes_in - c.bytes_out, c.bytes_in);
                let _ = self.err.write_all(m::STDIN_COMPRESSION.as_bytes());
                let _ = self.err.write_all(&pct);
                let _ = self.err.write_all(m::NEWLINE.as_bytes());
            }
            if c.bytes_out >= c.bytes_in && !self.s.force {
                self.exit_code = 2;
            }
        } else {
            self.decompress(&mut *input, &mut out)?;
        }
        Ok(())
    }

    /// File descriptor 0, read with `read(2)`: the real one, or a
    /// sandbox's bytes.
    fn stdin_reader(&mut self) -> Box<dyn Read> {
        match self.host {
            Host::Real => match host::stdin_file() {
                Ok(f) => Box::new(f),
                Err(_) => Box::new(io::stdin()),
            },
            Host::Sandbox(_) => Box::new(self.host.stdin()),
        }
    }

    fn compress(&mut self, input: &mut dyn Read, out: &mut dyn Write) -> Result<Counts, Abort> {
        let t = self.enc.get_or_insert_with(EncTables::new);
        let r = lzw::compress(input, out, &mut self.inbuf, i64::from(self.s.maxbits), t);
        r.map_err(|f| self.fail(f))
    }

    /// `decompress()` with its two messages: how it ended and `bytes_in`.
    fn decompress(
        &mut self,
        input: &mut dyn Read,
        out: &mut dyn Write,
    ) -> Result<(End, i64), Abort> {
        let t = self.dec.get_or_insert_with(DecTables::new);
        let (end, bytes_in) =
            lzw::decompress(input, out, &mut self.inbuf, t).map_err(|f| self.fail(f))?;
        let who = if self.ifname.is_empty() {
            b"stdin".to_vec()
        } else {
            self.ifname.clone()
        };
        match end {
            End::NotCompressed => {
                self.say(m::NOT_COMPRESSED, &[&who]);
                self.exit_code = 1;
            }
            End::TooManyBits(bits) => {
                let bits = bits.to_string();
                self.say(m::TOO_MANY_BITS, &[&who, bits.as_bytes(), b"16"]);
                self.exit_code = 4;
            }
            End::Done | End::Empty => {}
        }
        Ok((end, bytes_in))
    }

    /// `comprexx(fileptr)`: one operand.
    fn comprexx(&mut self, fileptr: &[u8]) -> Result<(), Abort> {
        match self.comprexx_inner(fileptr) {
            Ok(Some(())) => Ok(()),
            // `error:`
            Ok(None) => {
                self.ofname = None;
                self.armed = None;
                self.exit_code = 1;
                Ok(())
            }
            Err(a) => Err(a),
        }
    }

    /// `comprexx` up to its `error:` label: `Ok(None)` is a jump there.
    fn comprexx_inner(&mut self, fileptr: &[u8]) -> Result<Option<()>, Abort> {
        let mut tempname = fileptr.to_vec();
        let mut has_z = has_z_suffix(&tempname);
        // Ubuntu's build: `lstat` is `stat`.
        let infstat = match fs::metadata(self.path(&tempname)) {
            Ok(st) => st,
            Err(e) => {
                if self.s.decomp && e.kind() == io::ErrorKind::NotFound && !has_z {
                    // The name without `.Z`: try it with.
                    tempname.extend_from_slice(b".Z");
                    has_z = true;
                    match fs::metadata(self.path(&tempname)) {
                        Ok(st) if st.is_file() => st,
                        Ok(_) => {
                            self.say(m::NOT_REGULAR, &[&tempname]);
                            return Ok(None);
                        }
                        Err(e) => {
                            self.perror(&tempname, &e);
                            return Ok(None);
                        }
                    }
                } else {
                    self.perror(&tempname, &e);
                    return Ok(None);
                }
            }
        };

        if infstat.is_dir() {
            if self.s.recursive {
                self.compdir(&tempname)?;
            } else if !self.s.quiet {
                self.say(m::IS_DIRECTORY, &[&tempname]);
            }
            return Ok(Some(()));
        }
        if !infstat.is_file() {
            self.say(m::NOT_DIR_OR_REGULAR, &[&tempname]);
            return Ok(Some(()));
        }

        let ofname = if self.s.decomp {
            if !self.s.zcat && !has_z {
                if self.s.recursive {
                    return Ok(Some(()));
                }
                if !self.s.quiet {
                    self.say(m::NO_Z_SUFFIX, &[&tempname]);
                }
                return Ok(None);
            }
            let mut o = tempname.clone();
            if has_z {
                o.truncate(o.len() - 2);
            }
            o
        } else {
            if !self.s.zcat {
                if has_z {
                    if !self.s.recursive {
                        self.say(m::HAS_Z_SUFFIX, &[&tempname]);
                    }
                    return Ok(Some(()));
                }
                let others = nlink(&infstat).saturating_sub(1);
                if others > 0 && !self.s.force {
                    let n = others.to_string();
                    self.say(m::OTHER_LINKS, &[&tempname, n.as_bytes()]);
                    return Ok(None);
                }
            }
            [&tempname[..], b".Z"].concat()
        };
        self.ofname = Some(ofname.clone());

        let in_path = self.path(&tempname);
        let fdin = match File::open(&in_path) {
            Ok(f) => f,
            Err(e) => {
                self.perror(&tempname, &e);
                return Ok(None);
            }
        };
        let mut fdin = self.host.track(&in_path, fdin);
        self.ifname = tempname.clone();

        let out_path = self.path(&ofname);
        let mut out = if !self.s.zcat {
            // `access(ofname, F_OK)`: follows a link.
            if fs::metadata(&out_path).is_ok() {
                if !self.s.force {
                    self.inbuf[0] = b'n';
                    self.say(m::ALREADY_EXISTS, &[&ofname]);
                    if self.fgnd && self.host.stdin_is_tty() {
                        self.say(m::OVERWRITE, &[&ofname]);
                        let _ = self.err.flush();
                        self.read_answer();
                    }
                    if self.inbuf[0] != b'y' {
                        self.say(m::NOT_OVERWRITTEN, &[&ofname]);
                        return Ok(None);
                    }
                }
                if let Err(e) = fs::remove_file(&out_path) {
                    let _ = self.err.write_all(m::CANT_REMOVE.as_bytes());
                    self.perror(&ofname, &e);
                    return Ok(None);
                }
            }
            let file = match host::create_excl_armed(self.host, &out_path) {
                Ok((f, guard)) => {
                    self.armed = Some(guard);
                    f
                }
                Err(e) => {
                    self.perror(&tempname, &e);
                    return Ok(None);
                }
            };
            if !self.s.quiet {
                self.say(m::NAME, &[&tempname]);
            }
            self.host.out_writer(Some(file))
        } else {
            self.host.out_writer(None)
        };

        let (bytes_in, bytes_out, end) = if !self.s.decomp {
            let c = self.compress(&mut fdin, &mut out)?;
            (c.bytes_in, c.bytes_out, End::Done)
        } else {
            let (end, bytes_in) = self.decompress(&mut fdin, &mut out)?;
            (bytes_in, 0, end)
        };
        drop(fdin);
        if let Err(e) = out.flush() {
            return Err(self.fail(Fail::Write(e)));
        }
        drop(out);

        let refused = matches!(end, End::NotCompressed | End::TooManyBits(_));
        if bytes_in == 0 && !self.s.force {
            if self.armed.take().is_some() {
                if !self.s.quiet {
                    self.say(m::NO_COMPRESSION, &[&tempname]);
                }
                if let Err(e) = fs::remove_file(&out_path) {
                    let _ = self.err.write_all(m::UNLINK_ERROR_NL.as_bytes());
                    self.perror(&ofname, &e);
                }
                self.exit_code = 2;
            }
        } else if !self.s.zcat && self.s.decomp && refused {
            // Deviation N4: ncompress takes the refused input for a
            // success here, removing it and keeping the empty output.
            // stuffr removes its empty output and keeps the input.
            self.armed = None;
            let _ = fs::remove_file(&out_path);
        } else if !self.s.zcat {
            if !self.s.decomp && bytes_out >= bytes_in && !self.s.force {
                // No compression: remove file.Z.
                if !self.s.quiet {
                    self.say(m::NO_COMPRESSION, &[&tempname]);
                }
                if let Err(e) = fs::remove_file(&out_path) {
                    let _ = self.err.write_all(m::UNLINK_ERROR.as_bytes());
                    self.perror(&ofname, &e);
                }
                self.armed = None;
                self.exit_code = 2;
            } else {
                if !self.s.quiet {
                    self.say(m::REPLACED_WITH, &[&ofname]);
                    if !self.s.decomp {
                        let pct = prratio(bytes_in - bytes_out, bytes_in);
                        let _ = self.err.write_all(m::COMPRESSION.as_bytes());
                        let _ = self.err.write_all(&pct);
                    }
                    let _ = self.err.write_all(m::NEWLINE.as_bytes());
                }
                self.copy_stat(&ofname, &infstat);
                self.armed = None;
                if !self.s.keep
                    && let Err(e) = fs::remove_file(&in_path)
                {
                    let _ = self.err.write_all(m::UNLINK_ERROR_NL.as_bytes());
                    self.perror(&tempname, &e);
                }
            }
        }
        if self.exit_code == -1 {
            self.exit_code = 0;
        }
        self.armed = None;
        self.ofname = None;
        Ok(Some(()))
    }

    /// The question's answer: one byte from descriptor 0 into `inbuf[0]`,
    /// then bytes into `inbuf[1]` until a newline (none after a newline
    /// first). A failed or empty read is `perror("stdin")`.
    fn read_answer(&mut self) {
        let mut b = [0u8; 1];
        match read0(&mut b) {
            Ok(1) => {
                self.inbuf[0] = b[0];
                if b[0] != b'\n' {
                    loop {
                        match read0(&mut b) {
                            Ok(1) => {
                                self.inbuf[1] = b[0];
                                if b[0] == b'\n' {
                                    break;
                                }
                            }
                            r => {
                                self.perror_read(r);
                                break;
                            }
                        }
                    }
                }
            }
            r => self.perror_read(r),
        }
    }

    /// `perror("stdin")` after a read that gave nothing: the error, or for
    /// an end of input `errno`'s value, which nothing has set (0).
    fn perror_read(&mut self, r: io::Result<usize>) {
        let text = match r {
            Err(e) => host::strerror(&e),
            Ok(_) => host::errno_text(0),
        };
        self.perror_text(b"stdin", &text);
    }

    /// `utime`, `chmod` (`st_mode & 07777`), `chown`, each by name, each
    /// failure reported and ignored.
    fn copy_stat(&mut self, ofname: &[u8], st: &Metadata) {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            use std::os::unix::fs::MetadataExt;
            let path = self.path(ofname);
            let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
                return;
            };
            let last = || io::Error::last_os_error();
            let times = libc::utimbuf {
                actime: st.atime() as libc::time_t,
                modtime: st.mtime() as libc::time_t,
            };
            // SAFETY: `c` is a NUL-terminated path and `times` a utimbuf.
            if unsafe { libc::utime(c.as_ptr(), &times) } != 0 {
                let e = last();
                let _ = self.err.write_all(m::UTIME_ERROR.as_bytes());
                self.perror(ofname, &e);
            }
            // SAFETY: as above.
            if unsafe { libc::chmod(c.as_ptr(), (st.mode() & 0o7777) as libc::mode_t) } != 0 {
                let e = last();
                let _ = self.err.write_all(m::CHMOD_ERROR.as_bytes());
                self.perror(ofname, &e);
            }
            // SAFETY: as above.
            if unsafe { libc::chown(c.as_ptr(), st.uid(), st.gid()) } != 0 {
                let e = last();
                let _ = self.err.write_all(m::CHOWN_ERROR.as_bytes());
                self.perror(ofname, &e);
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (ofname, st);
        }
    }

    /// `compdir(dir)`: every entry of `dir` (`.` and `..` left out),
    /// `dir/name`, through `comprexx`, in `readdir` order. A directory that
    /// cannot be opened is `printf`'d to standard output.
    fn compdir(&mut self, dir: &[u8]) -> Result<(), Abort> {
        let entries = match fs::read_dir(self.path(dir)) {
            Ok(rd) => rd,
            Err(_) => {
                let mut line = Vec::new();
                m::printf(&mut line, m::UNREADABLE, &[dir]);
                self.stdio.extend_from_slice(&line);
                if self.host.stdout_is_tty() {
                    // Line-buffered at a terminal.
                    self.flush_stdio();
                }
                return Ok(());
            }
        };
        for e in entries {
            let Ok(e) = e else { break };
            let name = [dir, b"/", e.file_name().as_encoded_bytes()].concat();
            self.comprexx(&name)?;
        }
        Ok(())
    }
}

/// `read(0, buf, 1)` on the process's standard input.
fn read0(b: &mut [u8; 1]) -> io::Result<usize> {
    #[cfg(unix)]
    {
        // SAFETY: reads at most one byte into `b`, which we own.
        let n = unsafe { libc::read(0, b.as_mut_ptr().cast(), 1) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
    #[cfg(not(unix))]
    {
        io::stdin().read(b)
    }
}

/// `st_nlink`.
fn nlink(st: &Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        st.nlink()
    }
    #[cfg(not(unix))]
    {
        let _ = st;
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `prratio` in the C's fixed point: two decimals, the sign first, the
    /// large-number branch, and 100% for an empty input.
    #[test]
    fn prratio_is_fixed_point() {
        assert_eq!(prratio(50_000 - 21_313, 50_000), b"57.37%");
        assert_eq!(prratio(1 - 5, 1), b"-400.00%");
        assert_eq!(prratio(4096 - 5632, 4096), b"-37.50%");
        assert_eq!(prratio(0, 0), b"100.00%");
        assert_eq!(prratio(-3, 0), b"100.00%");
        assert_eq!(prratio(1_000_000, 2_000_000), b"50.00%");
    }
}
