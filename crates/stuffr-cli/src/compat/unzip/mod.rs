//! The unzip family (`unzip`, `zipinfo`, `funzip`): stuffr behaving as the
//! platform's Info-ZIP UnZip 6.00.
//!
//! **A port** of Apple's `zip-33` tree (`unzip/unzip60/`, the Info-ZIP
//! licence version 2009-Jan-02, `LICENSE-infozip`; this is an altered
//! version, marked as such by every banner). Each ported function carries
//! `// port: <file>.c:<function>`, each Apple change `// apple:
//! <file>.c:<line>`, each Ubuntu difference `// ubuntu: <patch>` or `//
//! ubuntu: -D<DEFINE>`, and each rule taken from the binary rather than the
//! source `// probe: <command>`; where the two disagree, the binary wins.
//! Every string is in `messages.rs`.
//!
//! **Flavours** ([`Flavour`], `flavour.rs`): Apple's `/usr/bin/unzip` on
//! macOS and the BSDs, Ubuntu 24.04's `6.0-28ubuntu4.1` elsewhere
//! ([`default_flavour`]), or as `STUFFR_UNZIP_FLAVOR` (`apple`, `ubuntu`)
//! says; [`run`] reads it once, and anything else in it is refused, exit 1,
//! in stuffr's own words. Ubuntu's build options and patches are flavour
//! checks at the points they change behaviour (R13: filled by Tasks 13 and
//! 14; until then those checks give Apple's answer).
//!
//! **G becomes `Uz`** (R5): Info-ZIP's global `G` (and its `uO`
//! options) is one value per run, holding the host, the flavour, the
//! options and the state, so a sandboxed run ([`run_in_counted`]) touches
//! nothing of the process.
//!
//! **Built so far** (0.16.0 Tasks 7 to 10): the names, the flavour, the
//! command line (`unzip.c`'s `unzip()` front half and `uz_opts()`,
//! `zipinfo.c`'s `zi_opts()`, `envargs.c`), the usage screens, `-hh`, the
//! `-v` screen and funzip's usage (Task 7); opening archives, wildcard
//! archive names, the end records, Zip64, the central directory walk,
//! wildcards and unzip's listings `-l`, `-v`, `-z`, `-T` (`process.rs`,
//! `unix/mod.rs`, `matching.rs`, `list.rs`, `fileio.rs`: Task 8); zipinfo's
//! listings, every format, the totals and the `-v` report (`zipinfo/`:
//! Task 9); testing and extraction (`extract/`: `extract.c`, `fileio.c`'s
//! output side, crypt.c's `decrypt()`; `unix/mapname.rs`, `unix/attrs.rs`:
//! `unix.c`'s names, paths, modes, times and symlinks; `unix/beneath.rs`:
//! the resolve-beneath walk every change goes through; Task 10).

//! Known deviations (the source of truth; the README and the spec mirror
//! this list):
//!
//! 1. SIGPIPE: `run` restores SIGPIPE's default action, as the other
//!    families do; under a parent that ignores SIGPIPE, unzip sees `EPIPE`
//!    and stuffr still dies of the signal (the Rust runtime ignores it
//!    before `main`, so the inherited disposition cannot be told apart).
//! 2. The first banner line of each program's usage and `-v` names stuffr
//!    and says it is altered (Info-ZIP licence clause 3):
//!    `UnZip 6.00 of 20 April 2009, by stuffr X.Y.Z (altered; original by
//!    Info-ZIP, with modifications by Apple Inc.).` (Ubuntu: `(altered;
//!    Debian's build, original by Info-ZIP).`), and likewise for zipinfo
//!    and funzip.
//! 3. Pre-existing symlinks: the Ubuntu flavour also stays beneath the
//!    extraction root, as Apple's does.
//! 4. The archive being read is never overwritten.
//! 5. `-O`/`-I` (Ubuntu) convert names through `iconv(3)`; they are
//!    unavailable on Windows.
//! 6. Locale-dependent output is identical under `C`, `C.UTF-8` and
//!    `en_US.UTF-8` only.
//! 7. On macOS the Ubuntu flavour also propagates the archive's quarantine
//!    attribute (R9), as Apple's does.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use super::CountedRun;
use super::host::{self, Host, SANDBOX_OUTPUT_CAP, Sandbox};

pub(crate) mod cli;
mod extract;
mod fileio;
pub(crate) mod flavour;
mod list;
mod matching;
mod messages;
mod process;
mod unix;
mod zipinfo;

pub use flavour::Flavour;
use messages::{self as m, printf};

/// The environment variable that overrides [`default_flavour`].
const FLAVOR_VAR: &str = "STUFFR_UNZIP_FLAVOR";

// unzip.h's PK_* exit codes (those the front end returns).
/// unzip.h:PK_OK, no error.
pub(crate) const PK_OK: i32 = 0;
/// unzip.h:PK_COOL, no error (the usage screen was asked for).
pub(crate) const PK_COOL: i32 = 0;
/// unzip.h:PK_WARN, a warning.
pub(crate) const PK_WARN: i32 = 1;
/// unzip.h:PK_ERR, an error in the archive.
pub(crate) const PK_ERR: i32 = 2;
/// unzip.h:PK_BADERR, a severe error.
pub(crate) const PK_BADERR: i32 = 3;
/// unzip.h:PK_NOZIP, the archive was not found.
pub(crate) const PK_NOZIP: i32 = 9;
/// unzip.h:PK_PARAM, bad or illegal parameters.
pub(crate) const PK_PARAM: i32 = 10;
/// unzip.h:PK_FIND, no files found.
pub(crate) const PK_FIND: i32 = 11;
/// unzip.h:PK_EOF, an unexpected end of the archive.
pub(crate) const PK_EOF: i32 = 51;
/// unzpriv.h:IZ_DIR, the archive operand is a directory (never an exit
/// code: `process_zipfiles()` counts it).
pub(crate) const IZ_DIR: i32 = 76;

// unzpriv.h's message flag bits, read by `Uz::info` (fileio.c's
// `UzpMessagePrnt`).
/// unzpriv.h:MSG_STDERR, bit 0: standard error (standard output under `-t`).
pub(crate) const MSG_STDERR: u32 = 0x0001;
/// unzpriv.h:MSG_LNEWLN, bit 5: a leading newline when not at the start of
/// a line.
pub(crate) const MSG_LNEWLN: u32 = 0x0020;
/// unzpriv.h:MSG_TNEWLN, bit 6: a trailing newline when the text lacks one.
pub(crate) const MSG_TNEWLN: u32 = 0x0040;

/// The exit codes the family can return under Apple's flavour (the plan's
/// Global Constraints): 0–3, 4–8 (`PK_MEM*`, only where the reference gives
/// them), 9–11, 50, 51, 80–82. For the `compat` fuzz target (Task 15).
#[doc(hidden)]
pub const EXIT_CODES_APPLE: &[i32] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 50, 51, 80, 81, 82];
/// [`EXIT_CODES_APPLE`] plus 12 (`PK_BOMB`, ubuntu:
/// 23-cve-2019-13232-zip-bomb-with-overlapped-entries.patch).
#[doc(hidden)]
pub const EXIT_CODES_UBUNTU: &[i32] =
    &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 50, 51, 80, 81, 82];

/// The flavour a build uses when `STUFFR_UNZIP_FLAVOR` is unset or empty:
/// Apple on macOS and the BSDs, Ubuntu everywhere else, Windows included.
pub fn default_flavour() -> Flavour {
    if cfg!(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )) {
        Flavour::Apple
    } else {
        Flavour::Ubuntu
    }
}

/// The flavour `STUFFR_UNZIP_FLAVOR`'s value selects: `apple` or `ubuntu`,
/// the default when unset or empty, and `Err(value)` for anything else.
pub(crate) fn flavour_from(value: Option<OsString>) -> Result<Flavour, OsString> {
    match value {
        None => Ok(default_flavour()),
        Some(v) if v.is_empty() => Ok(default_flavour()),
        Some(v) if v == "apple" => Ok(Flavour::Apple),
        Some(v) if v == "ubuntu" => Ok(Flavour::Ubuntu),
        Some(v) => Err(v),
    }
}

/// One run's state: Info-ZIP's `G` (globals.h `Uz_Globs`) with its `uO`
/// ([`cli::Options`]), R5. Tasks 8–14 add the archive state; what is here is
/// what the command line and the message layer need, and the window the
/// decoders will share.
pub(crate) struct Uz<'a> {
    /// The process, or a sandbox's stand-ins for it.
    pub(crate) host: Host,
    /// Which reference this run behaves as.
    pub(crate) flavour: Flavour,
    /// `G.UzO` (`uO`): the options.
    pub(crate) o: cli::Options,
    /// `getenv`: the process's environment, or a sandbox's stand-in.
    pub(crate) env: &'a dyn Fn(&str) -> Option<OsString>,
    /// Standard output (stdio's `stdout`), flushed after every message as
    /// `UzpMessagePrnt` does.
    pub(crate) out: BufWriter<Box<dyn Write + Send>>,
    /// Standard error.
    pub(crate) err: &'a mut dyn Write,
    /// `G.sol`: the last message ended a line (`TRUE` at start).
    pub(crate) sol: bool,
    /// `G.noargs`: the command line had no arguments at all.
    pub(crate) noargs: bool,
    /// `G.extract_flag`: the run extracts (no `-c -t -l -v -z -T`, not
    /// zipinfo).
    pub(crate) extract_flag: bool,
    /// `G.process_all_files`: no names were given after the archive.
    pub(crate) process_all_files: bool,
    /// `G.native_is_utf8` (ubuntu: -DUTF8_MAYBE_NATIVE): the locale's
    /// codeset is UTF-8 (`fileio::init_locale`; `false` under `LANG=C` and
    /// in a sandbox).
    /// Apple's `fnfilter()` reads the same fact through `isprint()`.
    pub(crate) native_is_utf8: bool,
    /// `G.unicode_escape_all` (ubuntu: -DUNICODE_WCHAR): `-U` given once.
    #[allow(dead_code)]
    pub(crate) unicode_escape_all: bool,
    /// `checkdir()`'s state: the extraction root (`G.rootpath`,
    /// `G.rootlen`, Apple's `G.rootdir`: apple: globals.c:164, `-1` at
    /// start) and the path being built (`unix/mapname.rs`).
    pub(crate) ck: unix::mapname::Checkdir,
    /// `G.qf`, what the archive's quarantine gives what is extracted from
    /// it (P7's rewritten value; `NULL`: none; apple: globals.c:165).
    pub(crate) qf: Option<Vec<u8>>,
    /// `G.overwrite_mode`: query, always or never (`extract::OVERWRT_*`).
    pub(crate) overwrite_mode: i32,
    /// `G.answerbuf`: the last answer read from standard input (kept when
    /// an answer finds the end of input).
    pub(crate) answerbuf: [u8; 10],
    /// Standard input as one stdio stream for the run (`fgets(...,
    /// stdin)`), opened at the first question.
    pub(crate) stdin: Option<host::Input>,
    /// `G.key`: the password tried on encrypted entries.
    pub(crate) key: Option<Vec<u8>>,
    /// `G.nopwd`: no more prompting (`-P`, or "skip all").
    pub(crate) nopwd: bool,
    /// `G.newzip`: no encrypted entry of this archive seen yet.
    pub(crate) newzip: bool,
    /// The run ends with this code: readbyte()'s `EXIT(PK_BADERR)` after a
    /// read error.
    pub(crate) abort: Option<i32>,
    /// What `Info()` formatted into `slide` while a decoder held it, in
    /// order: written to its front when it comes back (P13).
    /// Each is an offset, the bytes and whether a NUL follows them.
    pub(crate) pending_slide: Vec<(usize, Vec<u8>, bool)>,
    /// `G.area.Slide`: the one window every decoder writes into and the
    /// message layer formats into (rulings P13/P16), at least
    /// `stuffr::infozip::WSIZE`, reused across entries. `fnfilter()` and
    /// `do_string()` write into it as the C does.
    pub(crate) slide: Box<[u8]>,
    /// The archive input: `G.zipfd`, `G.inbuf` and `readbuf()`'s state.
    pub(crate) zin: fileio::ZipIn,
    /// `G.wildzipfn`: the archive operand as given.
    pub(crate) wildzipfn: Vec<u8>,
    /// `G.zipfn`: the archive being processed.
    pub(crate) zipfn: Vec<u8>,
    /// `G.pfnames[0..G.filespecs]`: the include patterns.
    pub(crate) pfnames: Vec<Vec<u8>>,
    /// `G.pxnames[0..G.xfilespecs]`: the exclude patterns.
    pub(crate) pxnames: Vec<Vec<u8>>,
    /// `G.no_ecrec`: an earlier candidate had no end record (so the last
    /// chance says "cannot find zipfile directory").
    pub(crate) no_ecrec: bool,
    /// `G.ecrec`: the end-of-central-directory record.
    pub(crate) ecrec: process::Ecrec,
    /// `G.lrec`: the last local header read (getZip64Data() reads it too).
    pub(crate) lrec: process::Lrec,
    /// `G.csize`: the entry's compressed bytes left (a C `zoff_t`).
    pub(crate) csize: i64,
    /// `G.real_ecrec_offset`: where the end record was found.
    pub(crate) real_ecrec_offset: i64,
    /// `G.expect_ecrec_offset`: where the directory says it should be.
    pub(crate) expect_ecrec_offset: i64,
    /// `G.sig`: the last signature read (bytes a short read did not
    /// replace are the earlier ones).
    pub(crate) sig: [u8; 4],
    /// `G.filename`, `FILNAMSIZ` bytes (`flavour::filnamsiz`): the entry's
    /// name as a C string, the bytes past its NUL left from earlier names.
    pub(crate) filename: Vec<u8>,
    /// `G.crec.relative_offset_local_header` as zipinfo's loop last left
    /// it (after `getZip64Data()` for a selected entry): `zipinfo()` starts
    /// the next archive's `endprev` at 4 when it is 4.
    pub(crate) crec_relative_offset_local_header: u64,
}

impl<'a> Uz<'a> {
    // port: globals.c:globalsCtor
    /// A run's `G` as `globalsCtor()` and Apple's `apple_globals_ctor()`
    /// leave it.
    pub(crate) fn new(
        host: Host,
        flavour: Flavour,
        env: &'a dyn Fn(&str) -> Option<OsString>,
        err: &'a mut dyn Write,
    ) -> Uz<'a> {
        let out = host.out_writer(None);
        Uz {
            host,
            flavour,
            o: cli::Options::new(),
            env,
            out,
            err,
            sol: true, // at start of line
            noargs: false,
            extract_flag: false,
            process_all_files: false,
            native_is_utf8: false,
            unicode_escape_all: false,
            // apple: globals.c:164 (`G.rootdir = -1`)
            ck: unix::mapname::Checkdir::default(),
            // apple: globals.c:165 (`G.qf = NULL`)
            qf: None,
            overwrite_mode: extract::OVERWRT_QUERY,
            answerbuf: [0; 10],
            stdin: None,
            key: None,
            nopwd: false,
            newzip: false,
            abort: None,
            pending_slide: Vec::new(),
            slide: vec![0u8; stuffr::infozip::WSIZE].into_boxed_slice(),
            zin: fileio::ZipIn::new(),
            wildzipfn: Vec::new(),
            zipfn: Vec::new(),
            pfnames: Vec::new(),
            pxnames: Vec::new(),
            no_ecrec: false,
            ecrec: process::Ecrec::default(),
            lrec: process::Lrec::default(),
            csize: 0,
            real_ecrec_offset: 0,
            expect_ecrec_offset: 0,
            sig: [0; 4],
            filename: vec![0u8; flavour::filnamsiz(flavour)],
            crec_relative_offset_local_header: 0,
        }
    }

    /// `Info(slide, flag, ((char *)slide, ...))`: the message formatted into
    /// `slide`'s front (and its NUL), as the C's `sprintf` puts it there
    /// (P13), then printed ([`Uz::print_raw`]).
    pub(crate) fn info(&mut self, flag: u32, buf: &[u8]) {
        let owned: Vec<u8>;
        let buf = if flag & MSG_TNEWLN != 0
            && ((buf.is_empty() && !self.sol) || (!buf.is_empty() && buf.last() != Some(&b'\n')))
        {
            // UzpMessagePrnt appends the newline in the buffer itself
            owned = [buf, b"\n"].concat();
            &owned[..]
        } else {
            buf
        };
        self.put_in_slide(buf);
        self.print_raw(flag & !MSG_TNEWLN, buf);
    }

    /// `buf` at `slide`'s front with a NUL after it (or, while a decoder
    /// holds the window, kept for [`Uz::restore_slide`]).
    fn put_in_slide(&mut self, buf: &[u8]) {
        self.put_slide_at(0, buf, true);
    }

    /// `buf` into `slide` at `at`, and a NUL after it when `nul` and it
    /// fits: what `sprintf()` and `fnfilter()` write there. While a decoder
    /// holds the window (`slide` empty) it is kept for
    /// [`Uz::restore_slide`]; a write past the window's end is the C's
    /// never-reached case and is dropped.
    pub(crate) fn put_slide_at(&mut self, at: usize, buf: &[u8], nul: bool) {
        if self.slide.is_empty() {
            self.pending_slide.push((at, buf.to_vec(), nul));
            return;
        }
        let end = at + buf.len();
        if end <= self.slide.len() {
            self.slide[at..end].copy_from_slice(buf);
            if nul && end < self.slide.len() {
                self.slide[end] = 0;
            }
        }
    }

    /// The window is back from a decoder: what `Info()` and `fnfilter()`
    /// wrote meanwhile goes to it, in order (P13).
    pub(crate) fn restore_slide(&mut self) {
        for (at, b, nul) in std::mem::take(&mut self.pending_slide) {
            self.put_slide_at(at, &b, nul);
        }
    }

    // port: fileio.c:UzpMessagePrnt
    /// `(*G.message)(&G, buf, size, flag)`: print `buf` to standard error
    /// when `flag` has [`MSG_STDERR`] and `-t` is not set, else to standard
    /// output, with the leading and trailing newlines `flag` asks for, and
    /// flush. Write errors are ignored, as every `Info()` caller ignores
    /// them. (`-M`'s pager is Task 11's.)
    pub(crate) fn print_raw(&mut self, flag: u32, buf: &[u8]) {
        let to_stderr = flag & MSG_STDERR != 0 && !self.o.tflag;
        let owned: Vec<u8>;
        let buf = if flag & MSG_TNEWLN != 0
            && ((buf.is_empty() && !self.sol) || (!buf.is_empty() && buf.last() != Some(&b'\n')))
        {
            owned = [buf, b"\n"].concat();
            &owned[..]
        } else {
            buf
        };
        // error output from testing redirected:  also send to stderr
        let also_stderr = flag & MSG_STDERR != 0
            && self.o.tflag
            && !self.host.stdout_is_tty()
            && self.host.stderr_is_tty();
        if flag & MSG_LNEWLN != 0 && !self.sol {
            // not at start of line:  want newline
            self.write(to_stderr, b"\n");
            if also_stderr {
                let _ = self.err.write_all(b"\n");
                let _ = self.err.flush();
            }
            self.sol = true;
        }
        if !buf.is_empty() {
            self.write(to_stderr, buf);
            if also_stderr {
                let _ = self.err.write_all(buf);
                let _ = self.err.flush();
            }
            self.sol = buf.last() == Some(&b'\n');
        }
    }

    /// `(*G.message)(&G, rawbuf, size, 0)` for `-c` and `-p`'s data:
    /// standard output, flushed; a failed write is returned (flush() then
    /// gives up on the entry).
    pub(crate) fn print_data(&mut self, buf: &[u8]) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        self.out.write_all(buf)?;
        self.out.flush()?;
        self.sol = buf.last() == Some(&b'\n');
        Ok(())
    }

    /// [`Uz::info`] of `fmt` with its `%s`/`%d` filled from `args`.
    pub(crate) fn info_fmt(&mut self, flag: u32, fmt: &str, args: &[&[u8]]) {
        let mut buf = Vec::new();
        printf(&mut buf, fmt, args);
        self.info(flag, &buf);
    }

    /// One message to one stream, flushed (`WriteTxtErr` + `fflush`).
    fn write(&mut self, to_stderr: bool, buf: &[u8]) {
        if to_stderr {
            let _ = self.err.write_all(buf);
            let _ = self.err.flush();
        } else {
            let _ = self.out.write_all(buf);
            let _ = self.out.flush();
        }
    }
}

/// Entry point for `unzip`, `zipinfo` and `funzip`; `name` is the
/// canonical invoked name, `argv0` the program as invoked (unzip.c reads
/// its last component for ZipInfo mode) and `args` the arguments after it.
pub fn run(name: &'static str, argv0: &OsStr, args: Vec<OsString>) -> ExitCode {
    // Deviation 1: as the other families.
    host::reset_sigpipe();
    let env = |k: &str| std::env::var_os(k);
    let mut err = io::stderr();
    let flavour = match flavour_from(env(FLAVOR_VAR)) {
        Ok(f) => f,
        Err(v) => {
            printf(
                &mut err,
                m::FLAVOR_REFUSED,
                &[name.as_bytes(), v.as_encoded_bytes()],
            );
            return ExitCode::from(1);
        }
    };
    let argv0 = if argv0.is_empty() {
        name.as_bytes()
    } else {
        argv0.as_encoded_bytes()
    };
    let code = main(flavour, name, argv0, &args, &env, Host::Real, &mut err);
    // The process's exit status is the code's low byte, as `exit()` makes
    // it (every code here is below 256).
    ExitCode::from(code as u8)
}

/// [`run`] without the process, as `flavour` (R7): operands resolve against
/// `dir`, standard input is `stdin` (a pipe of bytes), standard output and
/// error are captured and returned with the exit code and what each input
/// read, neither is a terminal, `env` stands in for the environment
/// (`UNZIP`, `UNZIPOPT`, `ZIPINFO`, `ZIPINFOOPT`; `STUFFR_UNZIP_FLAVOR` is
/// not consulted), no signal is touched, and standard output and output
/// files share the [`SANDBOX_OUTPUT_CAP`] budget. For the fuzz target; not
/// a stable interface.
#[doc(hidden)]
pub fn run_in_counted(
    flavour: Flavour,
    dir: &Path,
    name: &'static str,
    args: &[OsString],
    stdin: &[u8],
    env: &dyn Fn(&str) -> Option<OsString>,
) -> CountedRun {
    let stdout = Arc::new(Mutex::new(Vec::new()));
    let reads = Arc::new(Mutex::new(BTreeMap::new()));
    let host = Host::Sandbox(Sandbox {
        dir: dir.to_path_buf(),
        stdin: Some(stdin.to_vec()),
        stdout: stdout.clone(),
        budget: Arc::new(AtomicU64::new(SANDBOX_OUTPUT_CAP)),
        reads: reads.clone(),
    });
    let mut err = Vec::new();
    let code = main(flavour, name, name.as_bytes(), args, env, host, &mut err);
    let out = std::mem::take(&mut *stdout.lock().unwrap_or_else(|p| p.into_inner()));
    let reads = std::mem::take(&mut *reads.lock().unwrap_or_else(|p| p.into_inner()));
    (code, out, err, reads)
}

/// The run below the process boundary. Returns the exit code.
fn main(
    flavour: Flavour,
    name: &str,
    argv0: &[u8],
    args: &[OsString],
    env: &dyn Fn(&str) -> Option<OsString>,
    host: Host,
    err: &mut dyn Write,
) -> i32 {
    if name == "funzip" {
        return funzip(flavour, args, &host, err);
    }
    let mut uz = Uz::new(host, flavour, env, err);
    uz.native_is_utf8 = fileio::init_locale(&uz.host);
    let code = unzip(&mut uz, argv0, args);
    let _ = uz.out.flush();
    code
}

/// Whether `s` begins with `prefix`, ignoring ASCII case (`STRNICMP(s,
/// prefix, n) == 0` with `n` the prefix's length).
fn starts_with_ignore_case(s: &[u8], prefix: &[u8]) -> bool {
    s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix)
}

// port: unzip.c:unzip
/// unzip.c's `unzip()`: ZipInfo mode or UnZip mode, the command line, then
/// the archives.
fn unzip(uz: &mut Uz, argv0: &[u8], args: &[OsString]) -> i32 {
    // The program name's last component (after `DIR_END`).
    let start = argv0
        .iter()
        .rposition(|&b| b == b'/' || (cfg!(windows) && b == b'\\'))
        .map_or(0, |i| i + 1);
    let p = &argv0[start..];
    let zipinfo = starts_with_ignore_case(p, b"zipinfo")
        || starts_with_ignore_case(p, b"ii")
        || args
            .first()
            .is_some_and(|a| a.as_encoded_bytes().starts_with(b"-Z"));
    let parsed = if zipinfo {
        cli::parse_zipinfo(uz, args)
    } else {
        cli::parse_unzip(uz, args)
    };
    match parsed {
        Ok(p) => process_zipfiles(uz, &p),
        Err(code) => code,
    }
}

/// `process.c`'s `process_zipfiles()`.
fn process_zipfiles(uz: &mut Uz, parsed: &cli::Parsed) -> i32 {
    process::process_zipfiles(uz, parsed)
}

// port: funzip.c:main
/// funzip: its usage when there is no input file and standard input is a
/// terminal (exit 3), else, until Task 12, a placeholder (exit 3).
fn funzip(flavour: Flavour, args: &[OsString], host: &Host, err: &mut dyn Write) -> i32 {
    let a = cli::parse_funzip(args);
    // if no file argument and stdin not redirected, give the user help
    if a.input.is_none() && host.stdin_is_tty() {
        printf(
            err,
            flavour::funzip_banner(flavour),
            &[env!("CARGO_PKG_VERSION").as_bytes()],
        );
        let _ = err.write_all(m::FUNZIP_USAGE.as_bytes());
        return 3;
    }
    let _ = err.write_all(m::FUNZIP_NOT_BUILT_YET.as_bytes());
    3
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(f: Flavour, name: &'static str, args: &[&str]) -> (i32, String, String) {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let dir = std::env::temp_dir();
        let (code, out, err, _) = run_in_counted(f, &dir, name, &args, b"", &|_| None);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn the_default_flavour_follows_the_platform() {
        let apple = cfg!(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly"
        ));
        let want = if apple {
            Flavour::Apple
        } else {
            Flavour::Ubuntu
        };
        assert_eq!(default_flavour(), want);
    }

    /// Each flavour's banners say whose build they alter (R2), with this
    /// stuffr's version.
    #[test]
    fn banners_name_stuffr_and_the_build() {
        let v = env!("CARGO_PKG_VERSION");
        let (code, out, err) = run(Flavour::Apple, "unzip", &[]);
        assert_eq!((code, err.as_str()), (0, ""));
        let want = format!(
            "UnZip 6.00 of 20 April 2009, by stuffr {v} (altered; original by Info-ZIP, \
             with modifications by Apple Inc.).\nPlease report bugs to Apple.\n\nUsage: "
        );
        assert!(out.starts_with(&want), "{out}");
        let (_, out, _) = run(Flavour::Ubuntu, "unzip", &["-h"]);
        let want = format!(
            "UnZip 6.00 of 20 April 2009, by stuffr {v} (altered; Debian's build, original \
             by Info-ZIP).\n\nUsage: "
        );
        assert!(out.starts_with(&want), "{out}");
        let (code, out, _) = run(Flavour::Apple, "zipinfo", &[]);
        assert_eq!(code, 0);
        assert!(
            out.starts_with(&format!(
                "ZipInfo 3.00 of 20 April 2009, by stuffr {v} (altered; original by Greg \
                 Roelofs and the Info-ZIP group, with modifications by Apple Inc.).\n\nList"
            )),
            "{out}"
        );
        let (_, out, _) = run(Flavour::Ubuntu, "unzip", &["-Z"]);
        assert!(
            out.starts_with(&format!(
                "ZipInfo 3.00 of 20 April 2009, by stuffr {v} (altered; Debian's build, \
                 original by Greg Roelofs and the Info-ZIP group).\n"
            )),
            "{out}"
        );
        let (_, out, _) = run(Flavour::Ubuntu, "unzip", &["-v"]);
        assert!(
            out.contains("\nCompiled with gcc 13.2.0 for Unix (Linux ELF).\n\n"),
            "{out}"
        );
    }

    /// A command line that gets past the parser (an archive operand,
    /// funzip without a terminal) does not panic and exits with one of the
    /// flavour's codes. What it answers is the archive tasks' to pin.
    #[test]
    fn past_the_parser_a_run_never_panics() {
        for f in [Flavour::Apple, Flavour::Ubuntu] {
            let codes = match f {
                Flavour::Apple => EXIT_CODES_APPLE,
                Flavour::Ubuntu => EXIT_CODES_UBUNTU,
            };
            for (name, args) in [
                ("funzip", &[][..]),
                ("unzip", &["-l", "a.zip", "x", "-x", "y"]),
                ("zipinfo", &["a.zip"]),
            ] {
                let (code, _, _) = run(f, name, args);
                assert!(codes.contains(&code), "{f:?} {name} {args:?}: exit {code}");
            }
        }
    }

    /// The exit-code tables differ by `PK_BOMB` only.
    #[test]
    fn ubuntu_adds_only_pk_bomb() {
        let extra: Vec<i32> = EXIT_CODES_UBUNTU
            .iter()
            .copied()
            .filter(|c| !EXIT_CODES_APPLE.contains(c))
            .collect();
        assert_eq!(extra, [12]);
        assert!(
            EXIT_CODES_APPLE
                .iter()
                .all(|c| EXIT_CODES_UBUNTU.contains(c))
        );
    }
}
