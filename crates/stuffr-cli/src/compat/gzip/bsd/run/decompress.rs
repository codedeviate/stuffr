//! Decompression, `-t` and `-l`, ported from Apple's `gzip.c`
//! (file_cmds-479): `handle_stdin`, `file_uncompress`, `gz_uncompress`,
//! `cat_fd`, `print_test`, `print_list` and `print_list_out`, and the
//! foreign decoders as `gzip.c` drives them: `unbzip2.c`, `unxz.c`,
//! `unpack.c`, `unlz.c` and `zuncompress.c`.
//!
//! **Two ways a failure ends.** A gzip failure is a warning (exit 1, the
//! run goes on) and removes the output. The foreign decoders' failures
//! are mostly `maybe_err`/`maybe_errx`, which `exit(2)` on the spot: the
//! run stops, the input stays, and the output file keeps what was written
//! (0600, as created); [`Fatal`] carries that up to `main`.
//!
//! **What reaches the output before a failure** is each decoder's own
//! write pattern: `gz_uncompress` writes whole 64 KiB buffers and a
//! member's last one (so a cut-short member shows nothing of its last
//! buffer); `unbzip2` what each `BZ2_bzDecompress` call made, a failing
//! call's lost; `.Z` whole 64 KiB `fread`s, a failing one lost; pack,
//! lzip and xz everything decoded.
//!
//! `gz_uncompress` is a byte-at-a-time state machine, not the member
//! layer: Apple checks no FHCRC (it skips the two bytes), ignores the
//! reserved flag bits, accepts the old `1f 9e` magic for every member, and
//! takes any byte other than `1f` where a member would start as trailing
//! garbage, NULs too ("trailing garbage ignored", exit 2).

use std::fs::{self, File, Metadata};
use std::io::{self, Read, Seek, SeekFrom, Write};

use flate2::{Decompress, FlushDecompress, Status};
use stuffr::bzip2_stream::{RawStream, StreamError};
use stuffr::pack_stream::{PackError, PackReader};

use super::super::list::{ctime_short, unxz_len};
use super::super::messages::{self as m, printf};
use super::super::{unlz, zread::ZRead};
use super::{BUFLEN, Gz, PATH_MAX, create_exclusive, eexist, print_ratio};
use crate::compat::gzip::member::Lookahead;
use crate::compat::gzip::sniff::{self, Detected, Flavour};
use crate::compat::host::{Host, Published, SANDBOX_OUTPUT_CAP, publish, stdin_file};

/// `exit(2)` from `maybe_err`/`maybe_errx`: the message is printed (unless
/// `-q`), the run stops.
#[derive(Debug)]
pub(in crate::compat::gzip::bsd) struct Fatal;

/// `print_list`'s statics: the header not yet printed, and the totals.
#[derive(Debug)]
pub(in crate::compat::gzip::bsd) struct ListTotals {
    first: bool,
    in_tot: u64,
    out_tot: u64,
}

impl Default for ListTotals {
    fn default() -> Self {
        ListTotals {
            first: true,
            in_tot: 0,
            out_tot: 0,
        }
    }
}

/// `print_list`'s descriptor: a file, standard input, or `-1` (the totals).
enum ListFd<'f> {
    File(&'f mut File),
    Stdin,
    Totals,
}

/// The suffixes `check_suffix(file, 1)` tries after `suffixes[0]`, with
/// the name each one translates to.
const XLATE: [(&[u8], &[u8]); 13] = [
    (b".gz", b""),
    (b".z", b""),
    (b"-gz", b""),
    (b"-z", b""),
    (b"_z", b""),
    (b".taz", b".tar"),
    (b".tgz", b".tar"),
    (b".bz2", b""),
    (b".tbz", b".tar"),
    (b".tbz2", b".tar"),
    (b".Z", b""),
    (b".xz", b""),
    (b".lz", b""),
];

/// `ORIG_NAME` in the flags byte.
const ORIG_NAME: u8 = 0x08;
const EXTRA_FIELD: u8 = 0x04;
const COMMENT: u8 = 0x10;
const HEAD_CRC: u8 = 0x02;

/// `GZIP_TIMESTAMP` and `GZIP_ORIGNAME`: fixed offsets `-N` reads, which
/// assume no FEXTRA.
const GZIP_TIMESTAMP: u64 = 4;
const GZIP_ORIGNAME: u64 = 10;

/// A sandboxed `unxz`'s memory limit (Apple's is `UINT64_MAX`): past any
/// preset's dictionary, short of what a hostile header could claim.
#[cfg(feature = "xz-c")]
const SANDBOX_XZ_MEMLIMIT: u64 = 128 << 20;

/// `BUFSIZ` on macOS: `unxz`'s buffers.
const BUFSIZ: usize = 1024;

/// `lzma_ret` values `unxz` tells apart (`lzma/base.h`). The C tier reads
/// them from liblzma; the pure tier's header check makes four of them.
#[cfg(feature = "xz-c")]
const LZMA_OK: u32 = 0;
#[cfg(feature = "xz-c")]
const LZMA_STREAM_END: u32 = 1;
#[cfg(not(feature = "xz-c"))]
const LZMA_UNSUPPORTED_CHECK: u32 = 3;
#[cfg(feature = "xz-c")]
const LZMA_MEM_ERROR: u32 = 5;
#[cfg(feature = "xz-c")]
const LZMA_MEMLIMIT_ERROR: u32 = 6;
const LZMA_FORMAT_ERROR: u32 = 7;
const LZMA_OPTIONS_ERROR: u32 = 8;
const LZMA_DATA_ERROR: u32 = 9;
#[cfg(feature = "xz-c")]
const LZMA_BUF_ERROR: u32 = 10;

/// One `read(2)`: what the input has, up to `buf.len()`; `EINTR` retried.
fn read_once(r: &mut dyn Read, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        match r.read(buf) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            other => return other,
        }
    }
}

/// `read_retry`, and a regular file's single `read`: up to `buf.len()`,
/// stopping only at the end of the input.
fn read_full(r: &mut dyn Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut got = 0;
    while got < buf.len() {
        match read_once(r, &mut buf[got..])? {
            0 => break,
            n => got += n,
        }
    }
    Ok(got)
}

/// `file_gettype`, through the sniffer's Apple table (a format this build
/// lacks is unknown).
fn file_gettype(four: &[u8]) -> Detected {
    let mut la = Lookahead::new(four);
    sniff::detect(&mut la, Flavour::Bsd).unwrap_or(Detected::Unknown)
}

fn enotty() -> i32 {
    #[cfg(unix)]
    {
        libc::ENOTTY
    }
    #[cfg(not(unix))]
    {
        25
    }
}

impl Gz<'_> {
    /// `maybe_err`: [`Gz::warn`]'s line, then exit 2.
    fn err_exit(&mut self, fmt: &str, args: &[&[u8]], e: &io::Error) -> Fatal {
        self.warn(fmt, args, e);
        Fatal
    }

    /// `maybe_errx`: [`Gz::warnx`]'s line, then exit 2.
    fn errx_exit(&mut self, fmt: &str, args: &[&[u8]]) -> Fatal {
        self.warnx(fmt, args);
        Fatal
    }

    /// `check_suffix(file, 1)`: the name without the first suffix of the
    /// table it ends with (`.tgz`, `.taz`, `.tbz`, `.tbz2` becoming
    /// `.tar`), or `None`.
    fn check_suffix_xlate(&self, file: &[u8]) -> Option<Vec<u8>> {
        let last: &[u8] = if self.s.empty_last_suffix {
            b""
        } else {
            b".gz"
        };
        let first: &[u8] = &self.s.suffix;
        std::iter::once((first, &b""[..]))
            .chain(XLATE)
            .chain(std::iter::once((last, &b""[..])))
            .find(|(suf, _)| suf.len() < file.len() && file.ends_with(suf))
            .map(|(suf, normal)| [&file[..file.len() - suf.len()], normal].concat())
    }

    // ---- handle_stdin ----

    /// `handle_stdin`: standard input to standard output (or listed).
    pub(super) fn handle_stdin(&mut self) -> Result<(), Fatal> {
        if !self.s.force && !self.s.list {
            if self.host.stdin_is_tty() {
                self.warnx(m::STDIN_IS_TERMINAL, &[]);
                return Ok(());
            }
            // `isatty` said no: `ENOTTY`.
            self.errno = enotty();
        }
        let (in_size, mtime) = match self.host {
            Host::Real => match stdin_file().and_then(|f| f.metadata()) {
                Ok(md) if md.is_file() => (md.len(), mtime_secs(&md)),
                Ok(md) => (0, mtime_secs(&md)),
                Err(e) => {
                    self.warn(m::FSTAT, &[], &e);
                    return Ok(());
                }
            },
            // A sandbox's standard input is a pipe made now.
            Host::Sandbox(_) => (0, now_secs()),
        };
        if self.s.list {
            self.print_list(ListFd::Stdin, in_size, m::STDIN_NAME.as_bytes(), mtime);
            return Ok(());
        }
        let mut input: Box<dyn Read + Send> = match self.host {
            Host::Real => match stdin_file() {
                Ok(f) => Box::new(f),
                Err(_) => Box::new(self.host.stdin()),
            },
            Host::Sandbox(_) => Box::new(self.host.stdin()),
        };
        let mut four = [0u8; 4];
        match read_full(&mut input, &mut four) {
            Err(e) => {
                self.warn(m::CANT_READ_STDIN, &[], &e);
                return Ok(());
            }
            Ok(4) => {}
            Ok(_) => {
                self.warnx(m::STDIN_UNEXPECTED_EOF, &[]);
                return Ok(());
            }
        }
        let mut out = self.take_stdout();
        let r = self.decode_stdin(&mut input, &four, &mut out);
        self.stdout = Some(out);
        // `goto out`: nothing more to say.
        let Some((usize, gsize)) = r? else {
            return Ok(());
        };
        if self.s.verbose
            && !self.s.test
            && let (Some(u), Some(g)) = (usize, gsize)
        {
            self.print_verbage(None, None, u, g);
        }
        if self.s.verbose && self.s.test {
            self.print_test(m::STDIN_NAME.as_bytes(), usize.is_some());
        }
        Ok(())
    }

    /// `handle_stdin`'s switch: `(usize, gsize)`, each `None` where gzip
    /// has -1, or `None` for its `goto out`.
    fn decode_stdin(
        &mut self,
        input: &mut Box<dyn Read + Send>,
        four: &[u8; 4],
        out: &mut dyn Write,
    ) -> Result<Option<StdinSizes>, Fatal> {
        Ok(Some(match file_gettype(four) {
            Detected::Gzip => {
                let (u, g) = self.gz_uncompress(input, four, out, m::STDIN_NAME.as_bytes());
                (u, Some(g))
            }
            Detected::Bzip2 => {
                let (u, g) = self.unbzip2(input, four, out)?;
                (u, Some(g))
            }
            Detected::Compress => {
                // To stdio's `stdout`; `ferror(in)` is not looked at here.
                let z = self.zuncompress(input, four, out);
                (z.usize, Some(z.compressed))
            }
            Detected::Pack => {
                // `gsize` starts uninitialised in `handle_stdin` and
                // `unpack` adds to it (undefined behaviour): counted from
                // 0 here.
                let (u, g) = self.unpack(input, four, out)?;
                (u, Some(g))
            }
            Detected::Xz => {
                let owned = std::mem::replace(input, Box::new(io::empty()));
                let (u, g) = self.unxz(owned, four, out)?;
                (Some(u), Some(g))
            }
            Detected::Lzip => {
                let (u, g) = self.unlz(input, four, out);
                (u, g)
            }
            _ => {
                if !self.s.force {
                    self.warnx(m::UNKNOWN_FORMAT, &[]);
                    return Ok(None);
                }
                let mut gsize = 0;
                let u = self.cat_fd(four, input, 0, &mut gsize);
                (u, Some(gsize))
            }
        }))
    }

    // ---- file_uncompress ----

    /// `file_uncompress`: the bytes written (or tested), or `None` where
    /// gzip returns -1; `outfile` is the output's name (for `-v`).
    pub(super) fn file_uncompress(
        &mut self,
        file: &[u8],
        outfile: &mut Vec<u8>,
    ) -> Result<Option<u64>, Fatal> {
        let path = self.host.path(file);
        let mut fd = match File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                self.set_errno(&e);
                self.warn(m::CANT_OPEN, &[file], &e);
                return Ok(None);
            }
        };
        let isb = match fd.metadata() {
            Ok(md) => md,
            Err(e) => {
                self.warn(m::CANT_STAT_FILE, &[file], &e);
                return Ok(None);
            }
        };
        let in_size = if isb.is_file() { isb.len() } else { 0 };
        *outfile = file.to_vec();
        match self.check_suffix_xlate(file) {
            Some(name) => *outfile = name,
            None if !(self.s.to_stdout || self.s.list) => {
                self.warnx(m::UNKNOWN_SUFFIX, &[file]);
                return Ok(None);
            }
            None => {}
        }
        let mut four = [0u8; 4];
        match read_full(&mut fd, &mut four) {
            Ok(4) => {}
            // "we don't want to fail here": -f says nothing, keeps the code.
            _ if self.s.force => return Ok(None),
            Err(e) => {
                self.warn(m::CANT_READ, &[file], &e);
                return Ok(None);
            }
            Ok(_) => {
                self.warnx(m::UNEXPECTED_EOF, &[file]);
                return Ok(None);
            }
        }
        let method = file_gettype(&four);
        if !self.s.force && method == Detected::Unknown {
            self.warnx(m::NOT_IN_GZIP_FORMAT, &[file]);
            return Ok(None);
        }
        let mut timestamp = 0u32;
        if method == Detected::Gzip && self.s.restore_name {
            let mut ts = [0u8; 4];
            match pread(&mut fd, &mut ts, GZIP_TIMESTAMP) {
                Ok(4) => {}
                Ok(_) => {
                    self.warnx(m::UNEXPECTED_EOF, &[file]);
                    return Ok(None);
                }
                Err(e) => {
                    if !self.s.force {
                        self.warn(m::CANT_READ, &[file], &e);
                    }
                    return Ok(None);
                }
            }
            timestamp = u32::from_le_bytes(ts);
            if four[3] & ORIG_NAME != 0 {
                let mut name = vec![0u8; PATH_MAX];
                let got = match pread(&mut fd, &mut name, GZIP_ORIGNAME) {
                    Ok(n) => n,
                    Err(e) => {
                        self.warn(m::CANT_READ, &[file], &e);
                        return Ok(None);
                    }
                };
                // Nothing read leaves `name` unset in gzip (undefined
                // behaviour): taken as no name.
                let name = &name[..got];
                let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
                if !name.is_empty() {
                    // The stored name's last component, in the input's
                    // directory, cut to `PATH_MAX - 1` bytes.
                    let nf = name.rsplit(|&b| b == b'/').next().unwrap_or(name);
                    let dp = file.iter().rposition(|&b| b == b'/').map_or(0, |i| i + 1);
                    let mut o = [&file[..dp], nf].concat();
                    o.truncate(PATH_MAX - 1);
                    *outfile = o;
                }
            }
        }
        let _ = fd.seek(SeekFrom::Start(0));
        let mut mtime_override = None;
        let mut replace_input = false;
        if !self.s.to_stdout || self.s.list {
            let links = super::nlink(&isb);
            if links > 1 && !self.s.list && !self.s.force {
                let others = (links - 1).to_string();
                self.warnx(m::HAS_LINKS_UNCOMPRESS, &[file, others.as_bytes()]);
                return Ok(None);
            }
            if !self.s.no_name && timestamp != 0 {
                mtime_override = Some(i64::from(timestamp));
            }
            if !self.s.list {
                let out_path = self.host.path(outfile);
                match self.check_outfile(outfile, &out_path, &isb) {
                    Some(same) => replace_input = same,
                    None => return Ok(None),
                }
            }
        }
        // The output: standard output (-c, -t), nothing (-l), or a new
        // file under a temporary name.
        let mut tmp = None;
        if !self.s.to_stdout && !self.s.list {
            let out_path = self.host.path(outfile);
            match create_exclusive(&out_path, replace_input) {
                Ok(t) => tmp = Some(t),
                Err(e) => {
                    self.set_errno(&e);
                    self.warn(m::CANT_OPEN_OUTPUT, &[outfile], &e);
                    return Ok(None);
                }
            }
        }
        let mut out: io::BufWriter<Box<dyn Write + Send>> = match &tmp {
            Some((_, f)) => match f.try_clone() {
                Ok(f) => self.host.out_writer(Some(f)),
                Err(e) => {
                    self.warn(m::CANT_OPEN_OUTPUT, &[outfile], &e);
                    if let Some((t, _)) = &tmp {
                        let _ = fs::remove_file(t);
                    }
                    return Ok(None);
                }
            },
            None => self.take_stdout(),
        };
        let mtime = mtime_override.unwrap_or_else(|| mtime_secs(&isb));
        let decoded = self.decode_file(method, &mut fd, file, outfile, in_size, mtime, &mut out);
        let _ = out.flush();
        if tmp.is_none() {
            self.stdout = Some(out);
        } else {
            drop(out);
        }
        let size = match decoded {
            Err(Fatal) => {
                // `exit(2)`: what was written stays, as created (0600),
                // unless it would replace the input itself.
                if let Some((t, _)) = &tmp {
                    let out_path = self.host.path(outfile);
                    if replace_input || publish(t, &out_path, false).is_err() {
                        let _ = fs::remove_file(t);
                    }
                }
                return Err(Fatal);
            }
            Ok(Decoded::Lose) => {
                if let Some((t, _)) = &tmp {
                    let _ = fs::remove_file(t);
                }
                return Ok(None);
            }
            Ok(Decoded::Failed) => {
                if let Some((t, _)) = &tmp {
                    let _ = fs::remove_file(t);
                }
                self.warnx(m::UNCOMPRESS_FAILED, &[file]);
                return Ok(None);
            }
            Ok(Decoded::Size(n)) => n,
        };
        let Some((tmp_path, tmp_file)) = tmp else {
            // Tested, or to standard output: that is all.
            return Ok(Some(size));
        };
        let on_disk = match tmp_file.metadata() {
            Ok(md) => md.len(),
            Err(e) => {
                let _ = fs::remove_file(&tmp_path);
                self.warn(m::COULDNT_OPEN_LEAVING, &[outfile], &e);
                return Ok(None);
            }
        };
        if on_disk != size {
            let _ = fs::remove_file(&tmp_path);
            let (a, b) = (size.to_string(), on_disk.to_string());
            self.warnx(m::DIFFERENT_SIZE, &[a.as_bytes(), b.as_bytes()]);
            return Ok(None);
        }
        let out_path = self.host.path(outfile);
        match publish(&tmp_path, &out_path, replace_input) {
            Ok(Published::Done) => {}
            Ok(Published::Exists) => {
                let e = io::Error::from_raw_os_error(eexist());
                self.warn(m::COULDNT_OPEN_LEAVING, &[outfile], &e);
                return Ok(None);
            }
            Err(e) => {
                let _ = fs::remove_file(&tmp_path);
                self.warn(m::COULDNT_OPEN_LEAVING, &[outfile], &e);
                return Ok(None);
            }
        }
        self.copymodes(&tmp_file, &isb, mtime_override, outfile);
        drop(fd);
        self.unlink_input(&path, &isb, &out_path);
        Ok(Some(size))
    }

    /// `file_uncompress`'s switch on the format, from `fd`'s start.
    #[allow(clippy::too_many_arguments)]
    fn decode_file(
        &mut self,
        method: Detected,
        fd: &mut File,
        file: &[u8],
        outfile: &[u8],
        in_size: u64,
        mtime: i64,
        out: &mut dyn Write,
    ) -> Result<Decoded, Fatal> {
        let list = self.s.list;
        let lose = |g: &mut Self, msg: &str| {
            g.warnx(msg, &[]);
            Ok(Decoded::Lose)
        };
        Ok(match method {
            Detected::Bzip2 => {
                if list {
                    return lose(self, m::NO_L_BZIP2);
                }
                Decoded::from(self.unbzip2(fd, &[], out)?.0)
            }
            Detected::Compress => {
                if list {
                    return lose(self, m::NO_L_COMPRESS);
                }
                let z = self.zuncompress(fd, &[], out);
                if z.failed {
                    // `ferror(in)`: zread's `EFTYPE`.
                    let e = io::Error::from_raw_os_error(eftype());
                    self.warn(m::FAILED_INFILE, &[], &e);
                    return Ok(Decoded::Lose);
                }
                Decoded::from(z.usize)
            }
            Detected::Pack => {
                if list {
                    return lose(self, m::NO_L_PACK);
                }
                Decoded::from(self.unpack(fd, &[], out)?.0)
            }
            Detected::Xz => {
                if list {
                    let size = unxz_len(fd);
                    if !self.s.test {
                        self.print_list_out(in_size, size, file);
                        return Ok(Decoded::Lose);
                    }
                    Decoded::Size(size)
                } else {
                    let owned: Box<dyn Read + Send> = match fd.try_clone() {
                        Ok(f) => Box::new(f),
                        Err(e) => return Err(self.err_exit(m::XZ_READ_FAILED, &[], &e)),
                    };
                    Decoded::Size(self.unxz(owned, &[], out)?.0)
                }
            }
            Detected::Lzip => {
                if list {
                    return lose(self, m::NO_L_LZIP);
                }
                Decoded::from(self.unlz(fd, &[], out).0)
            }
            Detected::Gzip => {
                if list {
                    self.print_list(ListFd::File(fd), in_size, outfile, mtime);
                    if !self.s.test {
                        return Ok(Decoded::Lose);
                    }
                }
                Decoded::from(self.gz_uncompress(fd, &[], out, file).0)
            }
            _ => {
                if list {
                    return lose(self, m::NO_L_UNKNOWN);
                }
                // To standard output whatever the output is.
                let mut stdout = self.take_stdout();
                let mut gsize = 0;
                let n = self.cat_fd_to(&[], fd, 3, &mut gsize, &mut stdout);
                self.stdout = Some(stdout);
                Decoded::from(n)
            }
        })
    }

    // ---- gz_uncompress ----

    /// `gz_uncompress`: `(bytes out, or None for -1; bytes read)`.
    fn gz_uncompress(
        &mut self,
        input: &mut dyn Read,
        pre: &[u8],
        out: &mut dyn Write,
        filename: &[u8],
    ) -> (Option<u64>, u64) {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        enum St {
            Magic0,
            Magic1,
            Method,
            Flags,
            Skipping,
            Extra,
            Extra2,
            Extra3,
            OrigName,
            Comment,
            HeadCrc1,
            HeadCrc2,
            Init,
            Read,
            Crc,
            Len,
        }
        let mut inbuf = vec![0u8; BUFLEN];
        let mut obuf = vec![0u8; BUFLEN];
        inbuf[..pre.len()].copy_from_slice(pre);
        let (mut beg, mut end) = (0usize, pre.len());
        let mut ofill = 0usize;
        let mut in_tot = pre.len() as u64;
        let mut out_tot = 0u64;
        let mut out_sub_tot = 0u32;
        let mut state = St::Magic0;
        let mut flags = 0u8;
        let mut skip_count = 0usize;
        let mut done_reading = false;
        let mut needmore = false;
        let mut crc = flate2::Crc::new();
        let mut z: Option<Decompress> = None;
        let fail = loop {
            if (beg == end || needmore) && !done_reading {
                inbuf.copy_within(beg..end, 0);
                end -= beg;
                beg = 0;
                match read_once(input, &mut inbuf[end..]) {
                    Ok(0) => done_reading = true,
                    Ok(n) => {
                        end += n;
                        in_tot += n as u64;
                    }
                    Err(e) => {
                        self.warn(m::FAILED_TO_READ, &[], &e);
                        break true;
                    }
                }
                needmore = false;
            }
            if beg == end {
                if done_reading && state != St::Magic0 {
                    self.warnx(m::UNEXPECTED_EOF, &[filename]);
                    break true;
                }
                break false;
            }
            let b = inbuf[beg];
            match state {
                St::Magic0 => {
                    if b != 0x1f {
                        // `in_tot > 0` always holds here: gzip read first.
                        self.warnx(m::TRAILING_GARBAGE, &[filename]);
                        self.exit_value = 2;
                        break false;
                    }
                    beg += 1;
                    state = St::Magic1;
                    out_sub_tot = 0;
                    crc = flate2::Crc::new();
                }
                St::Magic1 => {
                    if b != 0x8b && b != 0x9e {
                        self.warnx(m::NOT_GZIPED_MAGIC1, &[]);
                        break true;
                    }
                    beg += 1;
                    state = St::Method;
                }
                St::Method => {
                    if b != 8 {
                        self.warnx(m::UNKNOWN_METHOD, &[]);
                        break true;
                    }
                    beg += 1;
                    state = St::Flags;
                }
                St::Flags => {
                    flags = b;
                    beg += 1;
                    skip_count = 6;
                    state = St::Skipping;
                }
                St::Skipping | St::Extra3 | St::HeadCrc2 => {
                    if skip_count > 0 {
                        skip_count -= 1;
                        beg += 1;
                    } else {
                        state = match state {
                            St::Skipping => St::Extra,
                            St::Extra3 => St::OrigName,
                            _ => St::Init,
                        };
                    }
                }
                St::Extra => {
                    if flags & EXTRA_FIELD == 0 {
                        state = St::OrigName;
                    } else {
                        skip_count = usize::from(b);
                        beg += 1;
                        state = St::Extra2;
                    }
                }
                St::Extra2 => {
                    skip_count |= usize::from(b) << 8;
                    beg += 1;
                    state = St::Extra3;
                }
                St::OrigName | St::Comment => {
                    let bit = if state == St::OrigName {
                        ORIG_NAME
                    } else {
                        COMMENT
                    };
                    let next = if state == St::OrigName {
                        St::Comment
                    } else {
                        St::HeadCrc1
                    };
                    if flags & bit == 0 {
                        state = next;
                    } else {
                        if b == 0 {
                            state = next;
                        }
                        beg += 1;
                    }
                }
                St::HeadCrc1 => {
                    skip_count = if flags & HEAD_CRC != 0 { 2 } else { 0 };
                    state = St::HeadCrc2;
                }
                St::Init => {
                    z = Some(Decompress::new(false));
                    state = St::Read;
                }
                St::Read => {
                    let Some(d) = z.as_mut() else {
                        break true;
                    };
                    let (in0, out0) = (d.total_in(), d.total_out());
                    let res =
                        d.decompress(&inbuf[beg..end], &mut obuf[ofill..], FlushDecompress::None);
                    let used = (d.total_in() - in0) as usize;
                    let made = (d.total_out() - out0) as usize;
                    beg += used;
                    ofill += made;
                    let ended = match res {
                        Err(_) => {
                            self.warnx(m::DATA_STREAM_ERROR, &[]);
                            break true;
                        }
                        Ok(Status::StreamEnd) => true,
                        Ok(_) => {
                            // zlib's `Z_BUF_ERROR` under `Z_FINISH`: keep
                            // filling the buffer. No progress with input
                            // and room left would be a stream zlib calls
                            // corrupt; it must not spin.
                            if used == 0 && made == 0 && beg < end && ofill < BUFLEN {
                                self.warnx(m::DATA_STREAM_ERROR, &[]);
                                break true;
                            }
                            if ofill < BUFLEN && !done_reading {
                                continue;
                            }
                            false
                        }
                    };
                    if ofill != 0 {
                        crc.update(&obuf[..ofill]);
                        let w = if self.s.test {
                            self.host.charge(ofill as u64)
                        } else {
                            out.write_all(&obuf[..ofill]).and_then(|()| out.flush())
                        };
                        if let Err(e) = w {
                            self.warn(m::ERROR_WRITING, &[], &e);
                            break true;
                        }
                        out_tot += ofill as u64;
                        out_sub_tot = out_sub_tot.wrapping_add(ofill as u32);
                        ofill = 0;
                    }
                    if ended {
                        z = None;
                        state = St::Crc;
                    }
                }
                St::Crc | St::Len => {
                    if end - beg < 4 {
                        if !done_reading {
                            needmore = true;
                            continue;
                        }
                        self.warnx(m::TRUNCATED_INPUT, &[]);
                        break true;
                    }
                    let v = u32::from_le_bytes([
                        inbuf[beg],
                        inbuf[beg + 1],
                        inbuf[beg + 2],
                        inbuf[beg + 3],
                    ]);
                    if state == St::Crc {
                        if v != crc.sum() {
                            self.warnx(m::CRC_ERROR, &[]);
                            break true;
                        }
                        beg += 4;
                        if beg == end && done_reading {
                            break false;
                        }
                        state = St::Len;
                    } else {
                        if v != out_sub_tot {
                            self.warnx(m::LENGTH_ERROR, &[]);
                            break true;
                        }
                        beg += 4;
                        state = St::Magic0;
                    }
                }
            }
        };
        ((!fail).then_some(out_tot), in_tot)
    }

    // ---- cat_fd ----

    /// `cat_fd` to standard output: `pre`, then the rest of `input`.
    fn cat_fd(
        &mut self,
        pre: &[u8],
        input: &mut dyn Read,
        fd: i32,
        gsize: &mut u64,
    ) -> Option<u64> {
        let mut stdout = self.take_stdout();
        let n = self.cat_fd_to(pre, input, fd, gsize, &mut stdout);
        self.stdout = Some(stdout);
        n
    }

    fn cat_fd_to(
        &mut self,
        pre: &[u8],
        input: &mut dyn Read,
        fd: i32,
        gsize: &mut u64,
        stdout: &mut dyn Write,
    ) -> Option<u64> {
        let mut in_tot = pre.len() as u64;
        if let Err(e) = stdout.write_all(pre).and_then(|()| stdout.flush()) {
            self.warn(m::WRITE_TO_STDOUT, &[], &e);
            return None;
        }
        let mut buf = vec![0u8; BUFLEN];
        loop {
            let n = match read_once(input, &mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    let fd = fd.to_string();
                    self.warn(m::READ_FROM_FD, &[fd.as_bytes()], &e);
                    break;
                }
            };
            if let Err(e) = stdout.write_all(&buf[..n]).and_then(|()| stdout.flush()) {
                self.warn(m::WRITE_TO_STDOUT, &[], &e);
                break;
            }
            in_tot += n as u64;
        }
        *gsize = in_tot;
        Some(in_tot)
    }

    // ---- unbzip2 ----

    /// `unbzip2`: `(bytes out, or None; bytes in)`. Failures in the data
    /// are warnings; a cut-short stream and read/write errors exit.
    fn unbzip2(
        &mut self,
        input: &mut dyn Read,
        pre: &[u8],
        out: &mut dyn Write,
    ) -> Result<(Option<u64>, u64), Fatal> {
        let mut inbuf = vec![0u8; BUFLEN];
        let mut outbuf = vec![0u8; BUFLEN];
        inbuf[..pre.len()].copy_from_slice(pre);
        let (mut beg, mut end) = (0usize, pre.len());
        let mut bytes_in = pre.len() as u64;
        let mut bytes_out = 0u64;
        let mut eof = false;
        let mut cold = false;
        let mut raw = RawStream::new();
        loop {
            if beg == end && !eof {
                // One `read` of 64 KiB: a regular file's is whole.
                let n = match read_full(input, &mut inbuf) {
                    Ok(n) => n,
                    Err(e) => return Err(self.err_exit(m::BZ_READ, &[], &e)),
                };
                eof = n == 0;
                bytes_in += n as u64;
                beg = 0;
                end = n;
            }
            let (used, made, mut ended) = match raw.decompress(&inbuf[beg..end], &mut outbuf) {
                Ok(r) => r,
                Err(e) => {
                    let msg = match e {
                        StreamError::Data => m::BZ_DATA_ERROR,
                        StreamError::Magic => m::BZ_MAGIC_ERROR,
                        StreamError::Memory => m::BZ_MEMORY,
                        _ => {
                            self.warnx(m::BZ_UNKNOWN, &[b"-1"]);
                            return Ok((None, bytes_in));
                        }
                    };
                    self.warnx(msg, &[]);
                    return Ok((None, bytes_in));
                }
            };
            beg += used;
            if !ended && eof {
                // After a stream's end, the end of the file is the end.
                if cold {
                    ended = true;
                } else {
                    return Err(self.errx_exit(m::BZ_TRUNCATED, &[]));
                }
            }
            cold = false;
            if made > 0 {
                let w = if self.s.test {
                    self.host.charge(made as u64)
                } else {
                    out.write_all(&outbuf[..made]).and_then(|()| out.flush())
                };
                if let Err(e) = w {
                    return Err(self.err_exit(m::BZ_WRITE, &[], &e));
                }
                if !self.s.test {
                    bytes_out += made as u64;
                }
            }
            if ended {
                if eof {
                    return Ok((Some(bytes_out), bytes_in));
                }
                // Another stream may follow.
                raw = RawStream::new();
                cold = true;
            }
        }
    }
}

impl Gz<'_> {
    // ---- zuncompress ----

    /// `zuncompress`: 64 KiB `fread`s of the `.Z` stream (one `zread` each;
    /// a failing one's bytes are lost) written unless `-t`.
    fn zuncompress(&mut self, input: &mut dyn Read, pre: &[u8], out: &mut dyn Write) -> ZOut {
        let mut z = ZRead::new(input, pre);
        let mut buf = vec![0u8; BUFLEN];
        let mut bout = 0u64;
        let mut failed = false;
        let mut write_failed = false;
        loop {
            match z.zread(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let w = if self.s.test {
                        self.host.charge(n as u64)
                    } else {
                        out.write_all(&buf[..n]).and_then(|()| out.flush())
                    };
                    if w.is_err() {
                        write_failed = true;
                        break;
                    }
                    bout += n as u64;
                }
                Err(()) => {
                    failed = true;
                    break;
                }
            }
        }
        ZOut {
            usize: (!write_failed).then_some(bout),
            compressed: z.total_compressed,
            failed,
        }
    }

    // ---- unpack ----

    /// `unpack`: `(the header's length, bytes in)`; every failure exits.
    fn unpack(
        &mut self,
        input: &mut dyn Read,
        pre: &[u8],
        out: &mut dyn Write,
    ) -> Result<(Option<u64>, u64), Fatal> {
        let mut src = Counted {
            inner: pre.chain(input),
            n: 0,
        };
        let mut p = match PackReader::new(&mut src) {
            Ok(p) => p,
            Err(e) => return Err(self.pack_failure(e)),
        };
        let len = u64::from(p.original_len());
        let mut buf = vec![0u8; BUFLEN];
        // `fputc`'s failures go unseen; the bytes after one are dropped.
        let mut write_ok = true;
        loop {
            match p.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if write_ok {
                        write_ok = out.write_all(&buf[..n]).and_then(|()| out.flush()).is_ok();
                    }
                }
                Err(e) => {
                    let pe = e
                        .into_inner()
                        .and_then(|i| i.downcast::<PackError>().ok())
                        .map_or(PackError::Corrupt(m::PACK_PREMATURE_EOF), |b| *b);
                    return Err(self.pack_failure(pe));
                }
            }
        }
        drop(p);
        Ok((Some(len), src.n))
    }

    /// unpack.c's words for `e`, and the exit.
    fn pack_failure(&mut self, e: PackError) -> Fatal {
        match e {
            // A header short of seven bytes: unpack.c reads the levels
            // byte it never filled (undefined behaviour); Apple's binary
            // has been seen to call it insane every time.
            PackError::BadHeader(_) => self.errx_exit(m::PACK_INSANE_LEVELS, &[]),
            PackError::Corrupt(why) => {
                // `PackReader` words its failures as unpack.c does.
                let msg = [
                    m::PACK_INSANE_LEVELS,
                    m::PACK_BAD_TABLE,
                    m::PACK_TABLE_TRUNCATED,
                    m::PACK_CORRUPT,
                    m::PACK_PREMATURE_EOF,
                ]
                .into_iter()
                .find(|&w| w == why)
                .unwrap_or(m::PACK_CORRUPT);
                self.errx_exit(msg, &[])
            }
            // `maybe_err`: with whatever `errno` the last failed call left.
            PackError::Truncated => {
                let e = io::Error::from_raw_os_error(self.errno);
                self.err_exit(m::PACK_TRUNCATED, &[], &e)
            }
            PackError::Io(e) => self.err_exit(m::PACK_TRUNCATED, &[], &e),
            PackError::BadMagic => self.errx_exit(m::PACK_CORRUPT, &[]),
        }
    }

    // ---- unxz ----

    /// `unxz`: `(bytes out, bytes in)`; every failure exits, after what was
    /// decoded is written (`unxz` writes before it checks the result).
    ///
    /// On the C tier this is `unxz` itself over liblzma, Apple's decoder:
    /// one `read` of `BUFSIZ` bytes, a first `lzma_code` with no output
    /// space that judges the headers ("Can't read headers (N)"), then
    /// `BUFSIZ` at a time. Elsewhere the stream header is judged by hand
    /// and the rest is stuffr's xz decoder, whose failures carry no
    /// `lzma_ret`: one met at the end of the input is "Unexpected end of
    /// input", any other "File is corrupt" (Implementer ruling: the pure
    /// tier cannot tell `LZMA_BUF_ERROR` from `LZMA_DATA_ERROR` otherwise).
    fn unxz(
        &mut self,
        mut input: Box<dyn Read + Send>,
        pre: &[u8],
        out: &mut dyn Write,
    ) -> Result<(u64, u64), Fatal> {
        let mut first = vec![0u8; BUFSIZ];
        first[..pre.len()].copy_from_slice(pre);
        let n = match read_full(&mut input, &mut first[pre.len()..]) {
            Ok(n) => n,
            Err(e) => return Err(self.err_exit(m::XZ_READ_FAILED, &[], &e)),
        };
        first.truncate(pre.len() + n);
        #[cfg(feature = "xz-c")]
        {
            self.unxz_liblzma(input, first, out)
        }
        #[cfg(not(feature = "xz-c"))]
        {
            self.unxz_decoder(input, first, out)
        }
    }

    #[cfg(feature = "xz-c")]
    fn unxz_liblzma(
        &mut self,
        mut input: Box<dyn Read + Send>,
        first: Vec<u8>,
        out: &mut dyn Write,
    ) -> Result<(u64, u64), Fatal> {
        let mut bytes_in = first.len() as u64;
        let mut ibuf = first;
        ibuf.resize(BUFSIZ, 0);
        let mut end = bytes_in as usize;
        // Apple's `UINT64_MAX`; a sandboxed run is bounded.
        let memlimit = self.sandbox_bound(SANDBOX_XZ_MEMLIMIT);
        let mut strm = match stuffr::xz_stream::RawXz::new(memlimit) {
            Ok(s) => s,
            Err(ret) => {
                let ret = ret.to_string();
                return Err(self.errx_exit(m::XZ_CANT_INITIALIZE, &[ret.as_bytes()]));
            }
        };
        let (mut pos, _, ret) = strm.code(&ibuf[..end], &mut [], false);
        if ret != LZMA_OK {
            let ret = ret.to_string();
            return Err(self.errx_exit(m::XZ_CANT_READ_HEADERS, &[ret.as_bytes()]));
        }
        let mut obuf = vec![0u8; BUFSIZ];
        let mut ofill = 0usize;
        let mut bytes_out = 0u64;
        let mut finish = false;
        loop {
            if pos == end {
                pos = 0;
                end = match read_full(&mut input, &mut ibuf) {
                    Ok(k) => k,
                    Err(e) => return Err(self.err_exit(m::XZ_READ_FAILED, &[], &e)),
                };
                if end == 0 {
                    finish = true;
                } else {
                    bytes_in += end as u64;
                }
            }
            let (used, made, mut ret) = strm.code(&ibuf[pos..end], &mut obuf[ofill..], finish);
            pos += used;
            ofill += made;
            if ofill == BUFSIZ || ret != LZMA_OK {
                if let Err(e) = out.write_all(&obuf[..ofill]).and_then(|()| out.flush()) {
                    return Err(self.err_exit(m::XZ_WRITE_FAILED, &[], &e));
                }
                bytes_out += ofill as u64;
                ofill = 0;
            }
            if ret == LZMA_OK {
                continue;
            }
            if ret == LZMA_STREAM_END {
                // Nothing may follow the last stream.
                let mut one = [0u8; 1];
                if pos != end || read_once(&mut input, &mut one).unwrap_or(0) != 0 {
                    ret = LZMA_DATA_ERROR;
                } else {
                    return Ok((bytes_out, bytes_in));
                }
            }
            return Err(self.xz_ret_failure(ret));
        }
    }

    /// `unxz`'s words for an `lzma_ret`, and the exit.
    #[cfg(feature = "xz-c")]
    fn xz_ret_failure(&mut self, ret: u32) -> Fatal {
        let msg = match ret {
            // `strerror(ENOMEM)`.
            LZMA_MEM_ERROR => {
                let text = crate::compat::host::errno_text(enomem());
                return self.errx_exit(m::PATH_ONLY, &[&text]);
            }
            LZMA_FORMAT_ERROR => m::XZ_FORMAT,
            LZMA_OPTIONS_ERROR => m::XZ_OPTIONS,
            LZMA_DATA_ERROR => m::XZ_CORRUPT,
            LZMA_BUF_ERROR => m::XZ_UNEXPECTED_END,
            LZMA_MEMLIMIT_ERROR => m::XZ_MEMLIMIT,
            other => {
                let n = other.to_string();
                return self.errx_exit(m::XZ_UNKNOWN, &[n.as_bytes()]);
            }
        };
        self.errx_exit(msg, &[])
    }

    #[cfg(not(feature = "xz-c"))]
    fn unxz_decoder(
        &mut self,
        input: Box<dyn Read + Send>,
        first: Vec<u8>,
        out: &mut dyn Write,
    ) -> Result<(u64, u64), Fatal> {
        if let Some(code) = xz_header_error(&first) {
            let code = code.to_string();
            return Err(self.errx_exit(m::XZ_CANT_READ_HEADERS, &[code.as_bytes()]));
        }
        let head = first.len() as u64;
        let read = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let at_end = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let src = io::Cursor::new(first).chain(CountedSend {
            inner: input,
            n: read.clone(),
            eof: at_end.clone(),
        });
        let bytes_in = || head + read.load(std::sync::atomic::Ordering::Relaxed);
        let ended = || at_end.load(std::sync::atomic::Ordering::Relaxed);
        let mut dec = match sniff::foreign_reader(Detected::Xz, Box::new(io::BufReader::new(src))) {
            Ok(d) => d,
            Err(_) => return Err(self.errx_exit(xz_words(ended()), &[])),
        };
        let mut obuf = vec![0u8; BUFSIZ];
        let mut bytes_out = 0u64;
        loop {
            match read_once(&mut dec, &mut obuf) {
                Ok(0) => return Ok((bytes_out, bytes_in())),
                Ok(k) => {
                    if let Err(e) = out.write_all(&obuf[..k]).and_then(|()| out.flush()) {
                        return Err(self.err_exit(m::XZ_WRITE_FAILED, &[], &e));
                    }
                    bytes_out += k as u64;
                }
                Err(_) => return Err(self.errx_exit(xz_words(ended()), &[])),
            }
        }
    }

    // ---- unlz ----

    /// `unlz`: `(bytes out, member size)`, both `None` on a failure (which
    /// says nothing). A failed write fails the member (see `unlz.rs`).
    fn unlz(
        &mut self,
        input: &mut dyn Read,
        pre: &[u8],
        out: &mut dyn Write,
    ) -> (Option<u64>, Option<u64>) {
        let mut flushing = FlushEach(out);
        let bound = self.sandbox_bound(SANDBOX_OUTPUT_CAP);
        match unlz::unlz(input, pre, &mut flushing, bound) {
            Ok(Some((size, member))) => (Some(size), Some(member)),
            Ok(None) | Err(_) => (None, None),
        }
    }

    /// `u64::MAX` for the real process, `bound` in a sandbox (the fuzz
    /// target's, where a few bytes must not claim hundreds of MiB).
    fn sandbox_bound(&self, bound: u64) -> u64 {
        match self.host {
            Host::Real => u64::MAX,
            Host::Sandbox(_) => bound,
        }
    }

    // ---- -t, -l ----

    /// `print_test`: on standard error whatever `-q` says; a failure makes
    /// the code 1.
    pub(super) fn print_test(&mut self, file: &[u8], ok: bool) {
        if self.exit_value == 0 && !ok {
            self.exit_value = 1;
        }
        let tabs = if file.len() < 7 {
            m::TABS_SHORT
        } else {
            m::TAB_LONG
        };
        let verdict = if ok { m::OK } else { m::NOT_OK };
        printf(
            self.err,
            m::TEST_LINE,
            &[file, tabs.as_bytes(), verdict.as_bytes()],
        );
        let _ = self.err.flush();
    }

    /// `print_list`: the header on the first call, then one line from the
    /// last eight bytes of `fd` (CRC32 and ISIZE: the last member's), or
    /// the totals. `out` is the compressed size, `ts` the date `-v` shows.
    fn print_list(&mut self, fd: ListFd<'_>, out: u64, outfile: &[u8], ts: i64) {
        let mut stdout = self.take_stdout();
        if self.list.first {
            if self.s.verbose {
                printf(&mut stdout, m::LIST_VERBOSE_HEADER, &[]);
            }
            if !self.s.quiet {
                printf(&mut stdout, m::LIST_HEADER, &[]);
            }
        }
        self.list.first = false;
        let totals = matches!(fd, ListFd::Totals);
        let (mut usize, mut crc, mut out) = (0u64, 0u32, out);
        match fd {
            ListFd::Totals => {
                usize = self.list.in_tot;
                out = self.list.out_tot;
            }
            ListFd::File(f) => {
                if f.seek(SeekFrom::End(-8)).is_ok() {
                    let mut buf = [0u8; 8];
                    match read_full(f, &mut buf) {
                        Err(e) => self.warn(m::READ_OF_SIZE, &[], &e),
                        Ok(8) => {
                            usize = u64::from(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]));
                            crc = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                        }
                        Ok(_) => self.warnx(m::READ_OF_SIZE, &[]),
                    }
                }
            }
            ListFd::Stdin => {
                // `lseek` works on a regular file only; a pipe lists 0.
                if let Host::Real = self.host
                    && let Ok(mut f) = stdin_file()
                    && f.seek(SeekFrom::End(-8)).is_ok()
                {
                    let mut buf = [0u8; 8];
                    match read_full(&mut f, &mut buf) {
                        Err(e) => self.warn(m::READ_OF_SIZE, &[], &e),
                        Ok(8) => {
                            usize = u64::from(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]));
                            crc = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                        }
                        Ok(_) => self.warnx(m::READ_OF_SIZE, &[]),
                    }
                }
            }
        }
        if self.s.verbose && totals {
            printf(&mut stdout, m::LIST_VERBOSE_TOTALS, &[]);
        } else if self.s.verbose {
            let crc = format!("{crc:08x}");
            let date = ctime_short(ts);
            printf(
                &mut stdout,
                m::LIST_VERBOSE_ROW,
                &[crc.as_bytes(), date.as_bytes()],
            );
        }
        self.list.in_tot += usize;
        self.list.out_tot += out;
        self.stdout = Some(stdout);
        self.print_list_out(out, usize, outfile);
    }

    /// `main`'s `print_list(-1, 0, "(totals)", 0)`.
    pub(super) fn print_list_totals(&mut self) {
        self.print_list(ListFd::Totals, 0, m::TOTALS.as_bytes(), 0);
    }

    /// `print_list_out`: compressed and uncompressed sizes, the ratio, the
    /// name.
    fn print_list_out(&mut self, out: u64, usize: u64, outfile: &[u8]) {
        let mut stdout = self.take_stdout();
        let (o, u) = (format!("{out:12}"), format!("{usize:12}"));
        printf(&mut stdout, m::LIST_ROW, &[o.as_bytes(), u.as_bytes()]);
        let r = format!("{:>5}", print_ratio(usize, out));
        printf(&mut stdout, m::RATIO, &[r.as_bytes()]);
        printf(&mut stdout, m::LIST_NAME, &[outfile]);
        self.stdout = Some(stdout);
    }
}

/// A writer that flushes after every write: stdio's `fwrite` to a file
/// flushes on `fclose`, which every path reaches.
struct FlushEach<'w>(&'w mut dyn Write);

impl Write for FlushEach<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// A `Send` reader that counts what passes, and says when it met the end,
/// for a decoder that owns it.
#[cfg(not(feature = "xz-c"))]
struct CountedSend {
    inner: Box<dyn Read + Send>,
    n: std::sync::Arc<std::sync::atomic::AtomicU64>,
    eof: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(not(feature = "xz-c"))]
impl Read for CountedSend {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let k = self.inner.read(buf)?;
        if k == 0 && !buf.is_empty() {
            self.eof.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        self.n
            .fetch_add(k as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(k)
    }
}

/// The pure tier's guess at `unxz`'s words: a failure met once the input
/// has ended is `LZMA_BUF_ERROR`'s.
#[cfg(not(feature = "xz-c"))]
fn xz_words(at_end: bool) -> &'static str {
    if at_end {
        m::XZ_UNEXPECTED_END
    } else {
        m::XZ_CORRUPT
    }
}

/// What `zuncompress` left.
struct ZOut {
    /// Bytes decoded, or `None` where a write failed (-1).
    usize: Option<u64>,
    /// `total_compressed_bytes`.
    compressed: u64,
    /// `zread` failed (`ferror(in)`).
    failed: bool,
}

/// A reader that counts what passes.
struct Counted<R> {
    inner: R,
    n: u64,
}

impl<R: Read> Read for Counted<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let k = self.inner.read(buf)?;
        self.n += k as u64;
        Ok(k)
    }
}

/// The pure tier's stand-in for the first `lzma_code`: the `lzma_ret` it
/// gives on `first` (up to `BUFSIZ`
/// bytes), judging the stream header only: `None` when it is whole and
/// good, or shorter than its twelve bytes (the decoder then waits, and the
/// end of the input says so).
#[cfg(not(feature = "xz-c"))]
fn xz_header_error(first: &[u8]) -> Option<u32> {
    if first.len() < 12 {
        return None;
    }
    if first[..6] != [0xfd, b'7', b'z', b'X', b'Z', 0] {
        return Some(LZMA_FORMAT_ERROR);
    }
    let mut c = flate2::Crc::new();
    c.update(&first[6..8]);
    if c.sum() != u32::from_le_bytes([first[8], first[9], first[10], first[11]]) {
        return Some(LZMA_DATA_ERROR);
    }
    if first[6] != 0 || first[7] & 0xf0 != 0 {
        return Some(LZMA_OPTIONS_ERROR);
    }
    // `LZMA_TELL_UNSUPPORTED_CHECK`: liblzma checks none, CRC32, CRC64
    // and SHA-256.
    if !matches!(first[7], 0 | 1 | 4 | 10) {
        return Some(LZMA_UNSUPPORTED_CHECK);
    }
    None
}

/// `handle_stdin`'s `usize` and `gsize`, each `None` where gzip has -1.
type StdinSizes = (Option<u64>, Option<u64>);

/// What a decoder left `file_uncompress` with.
enum Decoded {
    /// `size`, bytes written (or tested).
    Size(u64),
    /// -1: "uncompress failed".
    Failed,
    /// `goto lose`: said already, or nothing to say.
    Lose,
}

impl From<Option<u64>> for Decoded {
    fn from(o: Option<u64>) -> Self {
        o.map_or(Decoded::Failed, Decoded::Size)
    }
}

/// `pread`: up to `buf.len()` bytes at `pos`, short at the end of the file.
fn pread(f: &mut File, buf: &mut [u8], pos: u64) -> io::Result<usize> {
    f.seek(SeekFrom::Start(pos))?;
    read_full(f, buf)
}

fn mtime_secs(md: &Metadata) -> i64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        md.mtime()
    }
    #[cfg(not(unix))]
    {
        i64::from(super::mtime_of(md))
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

#[cfg(feature = "xz-c")]
fn enomem() -> i32 {
    #[cfg(unix)]
    {
        libc::ENOMEM
    }
    #[cfg(not(unix))]
    {
        12
    }
}

fn eftype() -> i32 {
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "ios"
    ))]
    {
        libc::EFTYPE
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "ios"
    )))]
    {
        79
    }
}
