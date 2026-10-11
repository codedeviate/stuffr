//! Decompression (`-d`, `gunzip`, `zcat`), `-t` and `-l` in GNU gzip 1.15's
//! file loop, as the binary was observed to behave (`messages.rs` names the
//! command behind each string; GNU's source is never read).
//!
//! - **Operands:** one that does not exist and has no gzip suffix is looked
//!   for with `-S`'s suffix, then `.gz`, `.z`, `-z` and `.Z` appended, in
//!   that order; if none exists the error names it with `-S`'s suffix
//!   (`gzip -d f` decompresses `f.z` when that is all there is; `gzip -d
//!   nonexist` says `nonexist.gz: No such file or directory`).
//! - **`-t` and `-l` read as `-c` does:** they follow symbolic links and
//!   take hard-linked and non-regular inputs. Only `-d` without `-c` needs
//!   the suffix (`gzip -d f.x`: "unknown suffix -- ignored", exit 2, `-q`
//!   silent and exit 0), and under `-r` every mode but `-c` skips an input
//!   without one (said only with `-v`, then exit 2).
//! - **Output names:** the suffix comes off; `.tgz` and `.taz` (any case)
//!   become `.tar`. With `-N` the stored name is used instead: its last
//!   component only (a trailing `/` kept, so such a name fails to be
//!   created), in the operand's directory, so a stored `../x` or `/tmp/x`
//!   is written as `x` beside the input. `-N` also restores the stored time
//!   when it is not 0.
//! - **Standard input** is never named: `-v` prints neither name nor ratio
//!   under `-d` (`-t` still says ` OK`), and `-l` names it `stdout`. A
//!   terminal there is refused under `-d` and `-t` unless `-f` (the run
//!   stops); `-l` reads it.

use std::fs::{self, File, Metadata};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use super::super::args::Mode;
use super::super::decode::{self, Counted, Fail, Note, Progress};
use super::super::list::Entry;
use super::super::messages::{self as m, PROGRAM, printf, quote};
use super::{Gz, Step, Stop, open_input, parent_of};
use crate::compat::gzip::member::{Header, Lookahead};
use crate::compat::host::{Host, InFile, Input, create_temp, stdin_file, strerror};

/// What is appended, after `-S`'s suffix, to an operand that does not
/// exist (observed: `gzip -dc f` finds `f.gz`, `f.z`, `f-z` and, on a
/// case-sensitive file system, `f.Z`, in that order; never `f-gz`, `f_z`,
/// `f.tgz` or `f.taz`).
const SEARCH: [&[u8]; 4] = [b".gz", b".z", b"-z", b".Z"];

/// Where `-t` and `-l` decode to: nowhere, charged to a sandbox's budget
/// as output would be.
struct Charged<'h>(&'h Host);

impl Write for Charged<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.charge(buf.len() as u64)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// An input's modification time in seconds.
fn mtime_secs(meta: &Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs() as i64)
}

/// The last component of a stored name, as GNU takes it: after the last
/// `/` that is not at the end (observed: `../x` gives `x`, `a/b/` gives
/// `b/`, `dir/` stays `dir/`), and nothing for a name of slashes only
/// (`/` under `-dN` on `s/in.gz` names `s/`).
fn stored_base(name: &[u8]) -> &[u8] {
    let Some(last) = name.iter().rposition(|&b| b != b'/') else {
        return b"";
    };
    match name[..last].iter().rposition(|&b| b == b'/') {
        Some(slash) => &name[slash + 1..],
        None => name,
    }
}

/// The longest path `-N` restores, the operand's directory part and the
/// whole stored name together, less one (observed with GNU 1.15 under
/// `-dN` and `-lN`: a stored name of 1023 bytes is used for `n.gz` and
/// 1024 refused; 1021/1022 for `./n.gz`, 1019/1020 for `sub/n.gz`; a
/// 1204-byte `d/d/.../base` is refused although its last component is
/// short).
const MAX_PATH_LEN: usize = 1024;

/// Whether `-N` must refuse `h`'s stored name for an operand whose
/// directory part is `dir`: "corrupted input -- file name too large".
fn name_too_large(dir: &[u8], h: Option<&Header>) -> bool {
    h.and_then(|h| h.name.as_deref())
        .is_some_and(|n| dir.len() + n.len() >= MAX_PATH_LEN)
}

/// The operand's directory part, `/` included (empty for a bare name).
fn dir_part(name: &[u8]) -> &[u8] {
    match name.iter().rposition(|&b| b == b'/') {
        Some(i) => &name[..=i],
        None => b"",
    }
}

impl Gz<'_> {
    /// One operand under `-d`, `-t` or `-l`.
    pub(super) fn treat_compressed(&mut self, operand: &[u8]) -> Step {
        let to_out = self.s.to_stdout || self.s.mode != Mode::Decompress;
        let follow = self.s.force || to_out;
        let (name, path, file, meta) = match self.open_compressed(operand, follow) {
            Ok(x) => x,
            Err((shown, e)) => {
                self.error(m::OPEN_FAILED, &[PROGRAM, &quote(&shown), &strerror(&e)]);
                return Ok(());
            }
        };
        let qname = quote(&name);
        if meta.is_dir() {
            drop(file);
            if self.s.recursive {
                return self.recurse(&name);
            }
            self.warn(m::IS_DIRECTORY, &[PROGRAM, &qname]);
            return Ok(());
        }
        if !to_out && !self.file_checks(&qname, &meta) {
            return Ok(());
        }
        let suffix = self.suffix_of(&name);
        if suffix.is_none() && !self.s.to_stdout {
            if self.s.recursive {
                if self.s.verbose > 0 {
                    self.say(m::UNKNOWN_SUFFIX, &[PROGRAM, &qname]);
                    self.warned();
                }
                return Ok(());
            }
            if self.s.mode == Mode::Decompress {
                if !self.s.quiet {
                    self.say(m::UNKNOWN_SUFFIX, &[PROGRAM, &qname]);
                    self.warned();
                }
                return Ok(());
            }
        }
        if self.s.mode == Mode::Decompress && !self.s.to_stdout {
            let suffix = suffix.unwrap_or_default();
            return self.decompress_file(&name, &path, file, &meta, &suffix);
        }
        let size = meta.is_file().then_some(meta.len());
        let named = Named {
            operand: &name,
            suffix: suffix.as_deref(),
        };
        self.time_stamp = mtime_secs(&meta);
        self.decode_unfiled(&qname, Some(named), Input::file(file), size)
    }

    /// Exit 2 unless already worse.
    fn warned(&mut self) {
        if self.exit == 0 {
            self.exit = 2;
        }
    }

    /// Open an operand, searching for it with a suffix when it does not
    /// exist and has none. `Err` carries the name to report.
    #[allow(clippy::type_complexity)]
    fn open_compressed(
        &mut self,
        name: &[u8],
        follow: bool,
    ) -> Result<(Vec<u8>, PathBuf, InFile, Metadata), (Vec<u8>, io::Error)> {
        let host = &*self.host;
        let try_open = |n: &[u8]| -> io::Result<(PathBuf, InFile, Metadata)> {
            let p = host.path(n);
            let f = open_input(host, &p, follow)?;
            let md = f.metadata()?;
            Ok((p, f, md))
        };
        match try_open(name) {
            Ok((p, f, md)) => Ok((name.to_vec(), p, f, md)),
            Err(e) if e.kind() == io::ErrorKind::NotFound && self.suffix_of(name).is_none() => {
                let custom = self.s.suffix.clone();
                for suf in std::iter::once(custom.as_slice()).chain(SEARCH) {
                    let n = [name, suf].concat();
                    match try_open(&n) {
                        Ok((p, f, md)) => return Ok((n, p, f, md)),
                        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                        Err(e) => return Err((n, e)),
                    }
                }
                Err(([name, &custom].concat(), e))
            }
            Err(e) => Err((name.to_vec(), e)),
        }
    }

    /// The output (or `-l`) name for `operand`: the stored name's last
    /// component in the operand's directory under `-N`, else the operand
    /// less its suffix (`.tgz`/`.taz` to `.tar`), else the operand.
    fn output_name(&self, operand: &[u8], suffix: Option<&[u8]>, h: Option<&Header>) -> Vec<u8> {
        if self.s.restore
            && let Some(stored) = h.and_then(|h| h.name.as_deref())
        {
            return [dir_part(operand), stored_base(stored)].concat();
        }
        match suffix {
            Some(suf) => {
                let stem = &operand[..operand.len() - suf.len()];
                if suf.eq_ignore_ascii_case(b".tgz") || suf.eq_ignore_ascii_case(b".taz") {
                    [stem, b".tar"].concat()
                } else {
                    stem.to_vec()
                }
            }
            None => operand.to_vec(),
        }
    }

    /// The modification time to restore: under `-N`, the last stored one
    /// that is not 0.
    fn stored_time(&self, stamp: Option<u32>) -> Option<u32> {
        stamp.filter(|_| self.s.restore)
    }

    /// Standard input under `-d`, `-t` or `-l`.
    pub(super) fn decompress_stdin(&mut self) -> Step {
        if self.s.mode != Mode::List
            && !self.s.force
            && (self.host.stdin_is_tty() || self.s.presume_tty)
        {
            if !self.s.quiet {
                self.say(m::NOT_FROM_TERMINAL, &[PROGRAM, PROGRAM]);
            }
            self.exit = 1;
            return Err(Stop);
        }
        // A regular file on standard input gives `-lv` its time; a pipe
        // leaves the last input's (observed: `gzip -lv a.gz - < pipe` dates
        // standard input as `a.gz`; alone, as time 0).
        if let Host::Real = self.host
            && let Some(md) = stdin_file()
                .ok()
                .and_then(|f| f.metadata().ok())
                .filter(Metadata::is_file)
        {
            self.time_stamp = mtime_secs(&md);
        }
        let input = self.host.stdin();
        self.decode_unfiled(b"stdin", None, input, None)
    }

    /// Decode one input to standard output (`-dc`, standard input) or
    /// nowhere (`-t`, `-l`). `named` is `None` for standard input, which
    /// `-v` does not name. `size` is the compressed size when known (a
    /// regular file's), else the bytes read count.
    fn decode_unfiled(
        &mut self,
        qname: &[u8],
        named: Option<Named<'_>>,
        input: Input,
        size: Option<u64>,
    ) -> Step {
        let mode = self.s.mode;
        let (counted, read) = Counted::new(input);
        let mut st = Lookahead::new(counted);
        let copy_ok = self.s.force && mode != Mode::List;
        let opened = {
            let mut noter = self.noter(qname, false);
            decode::open(&mut st, copy_ok, &mut |n| noter.note(n))
        };
        let opened = match opened {
            Ok(o) => o,
            Err(f) => {
                let step = self.refused(f, qname, m::STDOUT_NAME);
                // Observed: standard input refused at its header (not gzip,
                // an unknown method, an encrypted zip) ends the run in
                // every mode (`gzip -tv - a.gz < text` never tests `a.gz`).
                return if named.is_none() { Err(Stop) } else { step };
            }
        };
        if mode == Mode::List
            && self.s.restore
            && name_too_large(
                named.as_ref().map_or(b"", |n| dir_part(n.operand)),
                opened.header.as_ref(),
            )
        {
            return self.refused(Fail::NameTooLarge, qname, m::STDOUT_NAME);
        }
        let header = opened.header.clone();
        if named.is_some() && self.s.verbose > 0 && mode != Mode::List {
            self.say(m::VERBOSE_NAME, &[qname]);
        }
        let mut progress = Progress::default();
        let (verbose, quiet) = (self.s.verbose > 0, self.s.quiet);
        let host = &*self.host;
        let mut noter = Noter {
            qname,
            verbose,
            quiet,
            err: &mut *self.err,
            exit: &mut self.exit,
            file_mode: false,
            zip_more: false,
            unclean: false,
        };
        let mut note = |n| noter.note(n);
        let r = if mode == Mode::Decompress {
            let out = self.stdout.get_or_insert_with(|| host.out_writer(None));
            decode::finish(st, opened, copy_ok, out, &mut note, &mut progress)
        } else {
            let mut sink = Charged(host);
            decode::finish(st, opened, copy_ok, &mut sink, &mut note, &mut progress)
        };
        let unclean = noter.unclean;
        let done = match r {
            Ok(d) => d,
            Err(f) => {
                let fatal = f.fatal(mode == Mode::Decompress);
                let step = self.report(f, qname, m::STDOUT_NAME);
                if mode == Mode::List && !fatal {
                    self.list_failed(named.is_none(), progress.header_bytes);
                }
                return step;
            }
        };
        let size = size.unwrap_or_else(|| read.load(std::sync::atomic::Ordering::Relaxed));
        let compressed = size.saturating_sub(done.header_bytes);
        match mode {
            Mode::Decompress => {
                if named.is_some() {
                    self.verbose_done(done.out, compressed, m::STDOUT_NAME);
                }
            }
            Mode::Test => {
                // Observed: `gzip -tv < x` with data after the member says
                // the warning and no ` OK`; for a file, ` OK` follows it.
                if self.s.verbose > 0 && !(unclean && named.is_none()) {
                    self.say(m::TEST_OK, &[]);
                }
            }
            Mode::List => {
                if unclean {
                    self.list_failed(named.is_none(), done.header_bytes);
                    return Ok(());
                }
                let name = match named {
                    Some(n) => self.output_name(n.operand, n.suffix, header.as_ref()),
                    None => match header.as_ref().and_then(|h| h.name.as_deref()) {
                        Some(stored) if self.s.restore => stored_base(stored).to_vec(),
                        _ => m::LIST_STDIN_NAME.to_vec(),
                    },
                };
                if let Some(t) = self.stored_time(progress.stamp) {
                    self.time_stamp = i64::from(t);
                }
                let time = self.time_stamp;
                let name = quote(&name);
                let e = Entry {
                    method: done.method,
                    crc: done.crc,
                    time,
                    compressed: size,
                    uncompressed: done.out,
                    header_bytes: done.header_bytes,
                    name: &name,
                };
                self.list_line(&e);
            }
            Mode::Compress => {}
        }
        Ok(())
    }

    fn list_line(&mut self, e: &Entry<'_>) {
        let (verbose, quiet) = (self.s.verbose > 0, self.s.quiet);
        let mut list = std::mem::take(&mut self.list);
        list.line(self.stdout_writer(), verbose, quiet, e);
        self.list = list;
    }

    fn list_failed(&mut self, stdin: bool, header_bytes: u64) {
        let (verbose, quiet) = (self.s.verbose > 0, self.s.quiet);
        let mut list = std::mem::take(&mut self.list);
        list.failed(self.stdout_writer(), verbose, quiet, stdin, header_bytes);
        self.list = list;
    }

    /// `-d` to a file: `name` (which has `suffix`) to its output name,
    /// written under a temporary name and published only when complete.
    fn decompress_file(
        &mut self,
        name: &[u8],
        path: &Path,
        file: InFile,
        meta: &Metadata,
        suffix: &[u8],
    ) -> Step {
        let qname = quote(name);
        let (counted, _) = Counted::new(Input::file(file));
        let mut st = Lookahead::new(counted);
        let opened = {
            let mut noter = self.noter(&qname, true);
            decode::open(&mut st, false, &mut |n| noter.note(n))
        };
        let opened = match opened {
            Ok(o) => o,
            Err(f) => return self.refused(f, &qname, b""),
        };
        if self.s.restore && name_too_large(dir_part(name), opened.header.as_ref()) {
            return self.refused(Fail::NameTooLarge, &qname, b"");
        }
        let out_name = self.output_name(name, Some(suffix), opened.header.as_ref());
        let qout = quote(&out_name);
        let out_path = self.host.path(&out_name);
        let Some(replace) = self.may_write(&out_path, &qout, path, meta) else {
            return Ok(());
        };
        // A stored name that is empty or ends in `/` cannot be a file: GNU
        // fails creating it (observed: an empty FNAME under `-N` gives
        // `gzip: '': No such file or directory`). Ask the system for the
        // same error.
        if out_name.is_empty() || out_name.ends_with(b"/") {
            let e = match File::options().write(true).create_new(true).open(&out_path) {
                Ok(_) => {
                    let _ = fs::remove_file(&out_path);
                    io::Error::from(io::ErrorKind::InvalidInput)
                }
                Err(e) => e,
            };
            self.error(m::CREATE_FAILED, &[PROGRAM, &qout, &strerror(&e)]);
            return Ok(());
        }
        let (tmp, tmp_file) = match create_temp(&parent_of(&out_path), "gzip") {
            Ok(t) => t,
            Err(e) => {
                self.error(m::CREATE_FAILED, &[PROGRAM, &qout, &strerror(&e)]);
                return Ok(());
            }
        };
        // This output, not the last, is now the one a failure removes.
        self.stale = None;
        if self.s.verbose > 0 {
            self.say(m::VERBOSE_NAME, &[&qname]);
        }
        let mut progress = Progress::default();
        let more = {
            let mut w = self.host.out_writer(Some(tmp_file));
            let mut noter = Noter {
                qname: &qname,
                verbose: self.s.verbose > 0,
                quiet: self.s.quiet,
                err: &mut *self.err,
                exit: &mut self.exit,
                file_mode: true,
                zip_more: false,
                unclean: false,
            };
            let r = decode::finish(
                st,
                opened,
                false,
                &mut w,
                &mut |n| noter.note(n),
                &mut progress,
            )
            .and_then(|d| w.flush().map(|()| d).map_err(Fail::Write));
            (r, noter.zip_more)
        };
        let (r, more) = more;
        let mtime = self
            .stored_time(progress.stamp)
            .map(|t| UNIX_EPOCH + Duration::from_secs(u64::from(t)));
        if more {
            // Observed: a zip with a second entry is refused whole when
            // decompressing to a file (and the run stops).
            let _ = fs::remove_file(&tmp);
            self.say(m::ZIP_MORE_UNCHANGED, &[PROGRAM, &qname]);
            self.exit = 1;
            return Err(Stop);
        }
        let done = match r {
            Ok(d) => d,
            Err(f) => {
                // A later member whose header is refused (method, flags,
                // a `.Z` header's bits):
                // what was decoded is kept and the input removed, as on
                // success but exit 1 and no ratio; under `-k` the output
                // goes instead (observed: `gzip -d` and `gzip -dk` on a
                // member followed by `1f 8b` and `junk`).
                let later_header = matches!(
                    f,
                    Fail::UnknownMethod(_)
                        | Fail::Encrypted
                        | Fail::Flags(_)
                        | Fail::HeaderCrc(..)
                        | Fail::ZBits(_)
                );
                if later_header && !self.s.keep {
                    let step = self.report(f, &qname, &qout);
                    self.commit(&tmp, &out_path, &qout, meta, mtime, replace, path, &qname);
                    return step;
                }
                let _ = fs::remove_file(&tmp);
                return self.report(f, &qname, &qout);
            }
        };
        if self.commit(&tmp, &out_path, &qout, meta, mtime, replace, path, &qname) {
            if self.s.keep {
                self.stale = Some(out_path);
            }
            let compressed = meta.len().saturating_sub(done.header_bytes);
            self.verbose_done(done.out, compressed, &qout);
        }
        Ok(())
    }

    /// A failure at the header stage. One that ends the run also removes
    /// the last output written under `-k` (observed: `gzip -dk a.gz b.gz
    /// cut.gz`, where `cut.gz` ends inside its header, leaves `a` and not
    /// `b`; without `-k`, or when the failure comes later, it stays).
    fn refused(&mut self, f: Fail, qname: &[u8], qout: &[u8]) -> Step {
        let step = self.report(f, qname, qout);
        if step.is_err()
            && let Some(p) = self.stale.take()
        {
            let _ = fs::remove_file(p);
        }
        step
    }

    /// A [`Noter`] for `qname` on this run's settings.
    fn noter<'n>(&'n mut self, qname: &'n [u8], file_mode: bool) -> Noter<'n> {
        Noter {
            qname,
            verbose: self.s.verbose > 0,
            quiet: self.s.quiet,
            err: &mut *self.err,
            exit: &mut self.exit,
            file_mode,
            zip_more: false,
            unclean: false,
        }
    }

    /// Report a failure (exit 1); `Err(Stop)` when it ends the run. `qout`
    /// names the output for a write failure.
    fn report(&mut self, f: Fail, qname: &[u8], qout: &[u8]) -> Step {
        let fatal = f.fatal(self.s.mode == Mode::Decompress);
        let p = PROGRAM;
        match &f {
            Fail::Eof => self.error(m::UNEXPECTED_EOF, &[p, qname]),
            Fail::FormatViolated => self.error(m::FORMAT_VIOLATED, &[p, qname]),
            Fail::Crc => self.error(m::CRC_ERROR, &[p, qname]),
            Fail::Length | Fail::PackLength => self.error(m::LENGTH_ERROR, &[p, qname]),
            Fail::CrcLength => self.error(m::CRC_LENGTH_ERROR, &[p, qname]),
            Fail::NotGzip => self.error(m::NOT_GZIP, &[p, qname]),
            Fail::UnknownMethod(n) => {
                let n = n.to_string();
                self.error(m::UNKNOWN_METHOD, &[p, qname, n.as_bytes()]);
            }
            Fail::Encrypted => self.error(m::ENCRYPTED, &[p, qname]),
            Fail::Flags(f) => {
                let f = format!("{f:x}");
                self.error(m::HAS_FLAGS, &[p, qname, f.as_bytes()]);
            }
            Fail::HeaderCrc(stored, computed) => {
                let (a, b) = (format!("{stored:04x}"), format!("{computed:04x}"));
                self.error(m::HEADER_CRC, &[p, qname, a.as_bytes(), b.as_bytes()]);
            }
            Fail::ZipEncrypted => self.error(m::ZIP_ENCRYPTED, &[p, qname]),
            Fail::ZipMethod => self.error(m::ZIP_METHOD, &[p, qname]),
            Fail::Zip64 => self.error(m::ZIP64, &[p, qname]),
            Fail::ZipInvalid => self.error(m::ZIP_INVALID, &[p, qname]),
            Fail::ZBits(b) => {
                let b = b.to_string();
                self.error(m::Z_BITS, &[p, qname, b.as_bytes(), b"16"]);
            }
            // Observed: the hint only when decompressing to a file and some
            // output was written (not for a code past the table at once).
            Fail::ZCorrupt(n) if *n > 0 && self.s.mode == Mode::Decompress && !self.s.to_stdout => {
                self.error(m::Z_CORRUPT_FILE, &[p, qname]);
            }
            Fail::ZCorrupt(_) => self.error(m::Z_CORRUPT, &[p, qname]),
            Fail::PackFew => self.error(m::PACK_FEW, &[p, qname]),
            Fail::PackMany => self.error(m::PACK_MANY, &[p, qname]),
            Fail::PackBitLength => self.error(m::PACK_BIT_LENGTH, &[p, qname]),
            Fail::NameTooLarge => self.error(m::NAME_TOO_LARGE, &[p, qname]),
            Fail::Read(e) => self.error(m::IO_FAILED, &[p, qname, &strerror(e)]),
            Fail::Write(e) => self.error(m::IO_FAILED, &[p, qout, &strerror(e)]),
        }
        if fatal { Err(Stop) } else { Ok(()) }
    }
}

/// Says what decoding notes the moment it is noted, so nothing is kept per
/// member (fix round 1: a stream of a million FEXTRA members once kept a
/// million notes). As GNU does: FEXTRA's length only under `-v`; trailing
/// zeros only under `-v` (then exit 2); trailing garbage, unknown `.Z`
/// flags and a zip's second entry as warnings, except that to a file the
/// second entry is a refusal the caller reports (`zip_more`).
struct Noter<'e> {
    qname: &'e [u8],
    verbose: bool,
    quiet: bool,
    err: &'e mut dyn Write,
    exit: &'e mut u8,
    file_mode: bool,
    /// A zip's second entry, when decoding to a file.
    zip_more: bool,
    /// Data followed the last member (zeros or not).
    unclean: bool,
}

impl Noter<'_> {
    fn say(&mut self, fmt: &str, args: &[&[u8]]) {
        printf(self.err, fmt, args);
    }

    fn warn(&mut self, fmt: &str, args: &[&[u8]]) {
        if !self.quiet {
            self.say(fmt, args);
        }
        if *self.exit == 0 {
            *self.exit = 2;
        }
    }

    fn note(&mut self, n: Note) {
        let q = self.qname;
        match n {
            Note::Extra(len) => {
                if self.verbose {
                    let len = len.to_string();
                    self.say(m::EXTRA_FIELD, &[PROGRAM, q, len.as_bytes()]);
                }
            }
            Note::ZFlags(f) => {
                let f = format!("{f:x}");
                self.warn(m::Z_FLAGS, &[PROGRAM, q, f.as_bytes()]);
            }
            Note::TrailingGarbage => {
                self.unclean = true;
                self.warn(m::TRAILING_GARBAGE, &[PROGRAM, q]);
            }
            Note::TrailingZeros => {
                self.unclean = true;
                if self.verbose {
                    self.say(m::TRAILING_ZEROS, &[PROGRAM, q]);
                    if *self.exit == 0 {
                        *self.exit = 2;
                    }
                }
            }
            Note::ZipMore if self.file_mode => self.zip_more = true,
            Note::ZipMore => self.warn(m::ZIP_MORE, &[PROGRAM, q]),
        }
    }
}

/// A named input's operand and the suffix it has, for `-l`'s name.
#[derive(Clone, Copy)]
struct Named<'a> {
    operand: &'a [u8],
    suffix: Option<&'a [u8]>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each is the name GNU 1.15 created or tried for `gzip -dN` on a
    /// member storing that name.
    #[test]
    fn a_stored_name_keeps_its_last_component() {
        for (stored, base) in [
            (&b"orig.txt"[..], &b"orig.txt"[..]),
            (b"../up.txt", b"up.txt"),
            (b"/tmp/x", b"x"),
            (b"sub/x", b"x"),
            (b"dir/", b"dir/"),
            (b"a/b/", b"b/"),
            (b"", b""),
            (b"..", b".."),
            (b"/", b""),
            (b"//", b""),
        ] {
            assert_eq!(stored_base(stored), base, "{stored:?}");
        }
        assert_eq!(dir_part(b"s/a.gz"), b"s/");
        assert_eq!(dir_part(b"a.gz"), b"");
    }
}
