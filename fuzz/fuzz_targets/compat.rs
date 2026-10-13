//! The compatibility families, run in-process: the bzip2 family (0.11.0
//! Task 6: `bzip2`, `bunzip2`, `bzcat`, `bzip2recover`), the gzip family
//! (0.12.0 Task 11: `gzip`, `gunzip`, `zcat`, `gzcat`, each as GNU and as
//! Apple/BSD) and the xz family (0.13.0 Task 9: `xz`, `unxz`, `xzcat`,
//! `lzma`, `unlzma`, `lzcat`), through `stuffr_cli::compat::run_in_counted`
//! and `bzip2recover::recover`.
//!
//! The only fuzz coverage of `stuffr::bzip2_stream::StreamReader`, the
//! libbzip2-shaped decoder only the compat layer reaches, and of the gzip
//! personalities' own decoders: GNU's member reader, pack and `.Z` paths and
//! its zip entry; Apple's `gz_uncompress` state machine, `unlz`, `zread`, the
//! xz index reader behind `-l`, and the raw bzip2/xz/pack steps; and of
//! the xz family's argument parser, coder, `--files` reader and `--list`
//! walk (`index.rs`, and `list.rs`'s `-vv` Block Header reads, which must
//! never panic: Ruling P14). Under `Host::Sandbox` the xz encoder's panics
//! are not caught (Ruling P10), so they reach the fuzzer.
//!
//! An input is `[tool][argc][token; argc][file mask] ++ payload`, decoded by
//! `stuffr_core::testing::decode_compat_case` (whose tables are the wire
//! format of the seeds `crates/stuffr/tests/fuzz_corpus.rs` writes). The
//! tool byte also picks the gzip flavour, `(byte / names) & 1` (R7). Each
//! file the mask names is created holding the payload; with the mask's stdin
//! bit, standard input carries it too. The xz family's five files take a
//! second mask byte, there only when the argument-count byte is past 8
//! (`COMPAT_FILES`).
//!
//! Asserted, for every input:
//!
//! - no panic;
//! - the exit code is one the tool has: 0-2 for the bzip2 family (`0` ok,
//!   `1` environment, `2` corrupt; `3` is bzip2's internal-panic exit, which
//!   only a stuffr defect reaches), 0 or 1 for bzip2recover,
//!   0-2 for the xz family (main.c and message.c: 0 ok, 1 error, 2 warning),
//!   and 0-2 for the gzip family in both flavours (GNU: 0 ok, 1 error, 2
//!   warning; Apple's `gzip.c` exits only through `exit(exit_value)` with
//!   0, 1 or 2, `maybe_err[x]`'s `exit(2)`, `err(1)`/`errx(1)`, and `exit(0)`
//!   after usage, version and licence; its decoders `unbzip2.c`, `unxz.c`,
//!   `unpack.c`, `unlz.c` and `zuncompress.c` add none; stuffr's own 3-7
//!   must never appear);
//! - nothing is created, changed or removed outside the run's directory:
//!   each run gets a fresh directory inside a per-process sandbox parent, and
//!   `check_extraction_contained` walks the parent afterwards (the parent is
//!   removed at the end of every iteration); no name the tools could write
//!   appears in, changes in or vanishes from the real working directory;
//! - bzip2recover reads its input at most twice (two opens, at most
//!   `2 × len` bytes: its two passes) and within `check_scan_is_linear`'s
//!   bound, creates at most 50000 outputs, and writes at most the input's
//!   bytes plus a fixed per-output frame;
//! - the gzip family opens each input at most twice, and reads at most
//!   `2 × len` bytes of it, per operand that can name it (see
//!   `check_gzip_reads`, and its doc for what each mode was measured at);
//!   it opens no file an operand cannot name; it leaves no `.stuffr-gzip-*`
//!   temporary behind, and (unless `-N` lets a member's stored name choose
//!   the output) no name in the run's directory that `could_be_written`
//!   does not allow;
//! - a failed gzip-family run with one operand leaves no partial output
//!   (`check_gzip_no_partial`, whose doc says exactly which runs it judges
//!   and which it cannot): `could_be_written` alone cannot see one, because
//!   a partial output has a legitimate output's name. Apple's partial
//!   outputs after a foreign-format failure (`maybe_err`, exit 2, for
//!   `.bz2`, `.xz`, lzip, pack and `.Z`: Ruling T10-2) are allowed;
//! - the xz family opens each input at most twice per operand that names
//!   it (an argument in operand position, or a name `--files`/`--files0`
//!   read from standard input or from the file `--files=FILE`/
//!   `--files0=FILE` names; one more open and read per such token for the
//!   list itself), reads at most `2 × len` of it per operand
//!   when compressing, decompressing or testing, and within
//!   `xz_list_bound` under `--list` (`check_xz_reads` says why `--list` is
//!   not linear); it leaves no `.stuffr-xz-*` temporary and no name
//!   `could_be_written` does not allow; and standard output plus every new
//!   or changed file stays within the 8 MiB output budget
//!   (`check_xz_budget`). A `--files`/`--files0` case whose names (standard
//!   input, or the list file when it exists) hold a `/` is not run: such a
//!   name could leave the run's directory.
//!
//! **Memory under the xz names (Ruling P7).** libFuzzer's RSS limit
//! (2 GiB by default) is the bound, and each verb stays inside it by a
//! limit stuffr applies or by the token table:
//!
//! - compress: the most memory a case can ask for is a preset's, `-9`/`-9e`
//!   (a 64 MiB dictionary, about 674 MiB per encoder reserved); no token
//!   sets a larger dictionary (`--lzma2=dict=4KiB` is the only one) or
//!   more than the sandbox's two threads (`Hardware::SANDBOX`, R3). The
//!   encoder's tables are allocated untouched and an input is at most
//!   64 KiB, so only what the input reaches becomes resident: the seeds,
//!   `-T0 -9` among them, peak at 296 MB.
//! - decompress and test: the sandbox caps the decoder's memory limit at
//!   256 MiB (`SANDBOX_DECODER_CAP`) whatever `--memlimit*` says, single-
//!   and multi-threaded, so a header declaring a larger dictionary is
//!   refused before it is allocated (measured: a 250 MiB dictionary is
//!   refused, exit 1). Below the cap the pure tier zero-fills what it
//!   allocates: a 192 MiB dictionary peaked at 489 MB, two runs of it
//!   counted with ASan's quarantine. What is decoded goes to the 8 MiB
//!   budget, `-t` included.
//! - list: the Index walk stores a Record only once its bytes are read
//!   (`index.rs`) and is held to the same 256 MiB limit
//!   (`hardware_memlimit_get(MODE_LIST)`); `-vv` reads at most 1024
//!   bytes of a Block at a time and allocates nothing from a declared
//!   size.
//!
//! Inputs past `COMPAT_FUZZ_MAX_INPUT` (64 KiB; see its doc) are skipped.
//! Both families' output, to standard output and files together, is capped
//! by `run_in` itself (8 MiB, failing as a full disk does: exit 1), because
//! a bzip2 stream of a few dozen bytes can expand to tens of MiB, and a
//! payload is written up to seven times over plus standard input; the bytes
//! `-t` decodes are charged to the same budget (`Host::charge`).

#![no_main]

use std::cell::Cell;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::OnceLock;
use std::time::SystemTime;

use libfuzzer_sys::fuzz_target;
use stuffr_cli::compat::{self, bzip2recover, gzip::Flavour};
use stuffr_core::testing::{
    COMPAT_FILES, COMPAT_FUZZ_MAX_INPUT, COMPAT_TOKENS, check_extraction_contained,
    check_scan_is_linear, decode_compat_case,
};

/// `BZ_MAX_HANDLED_BLOCKS`: bzip2recover writes no more outputs than this.
const MAX_HANDLED_BLOCKS: u64 = 50_000;

/// What one recovered stream adds to its block's bits: `BZh9` (4), the block
/// magic (6), the end-of-stream magic (6), the combined CRC (4), and one
/// byte for a block whose bits end mid-byte.
const RECOVER_FRAME: u64 = 4 + 6 + 6 + 4 + 1;

/// The per-process sandbox parent. Each iteration creates it, makes its run
/// directory inside, and removes the whole parent at the end, so only a
/// crash leaves it behind. Per pid, so `-jobs` workers never share one.
fn sandbox() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        std::env::temp_dir().join(format!("stuffr-fuzz-compat-{}", std::process::id()))
    })
}

/// The suffixes the tools add or strip, beyond the tokens (any token can be
/// `-S`'s suffix): bzip2's, `.out`, both gzips' tables and `.tar`.
const SUFFIXES: &[&str] = &[
    ".bz2", ".bz", ".tbz2", ".tbz", ".out", ".gz", ".tgz", ".taz", ".z", ".Z", "-gz", "-z", "_z",
    ".xz", ".lz", ".tar", ".txz", ".lzma", ".tlz",
];

/// Suffixes a decompressor maps to `.tar` rather than strip.
const TAR_SUFFIXES: &[&str] = &[".tbz2", ".tbz", ".tgz", ".taz", ".txz", ".tlz"];

/// Whether `name` is one the tools could write in their working directory:
/// a `COMPAT_FILES` name or one derived from it (a suffix or token stripped,
/// or mapped to `.tar`; then a suffix or token added: gzip's `-S` takes any
/// token), a bzip2recover output (`rec` and five digits), or a temporary
/// (`.stuffr-bzip2-*`, `.stuffr-gzip-*`, `.stuffr-xz-*`).
///
/// Generous on purpose: it is the real working directory's snapshot filter
/// (a superset only snapshots more) and the run directory's stray-file
/// check (where it has to admit every output a run may legitimately leave,
/// Apple's kept partial outputs included).
fn could_be_written(name: &str) -> bool {
    could_be_written_with(name, false)
}

/// `could_be_written`, with the name and every table name compared
/// lowercased: a case-insensitive filesystem opens `a.xz` for `A.XZ`.
fn could_be_written_folded(name: &str) -> bool {
    could_be_written_with(name, true)
}

fn could_be_written_with(name: &str, fold: bool) -> bool {
    let key = |s: &str| {
        if fold {
            s.to_ascii_lowercase()
        } else {
            s.to_owned()
        }
    };
    let name = key(name);
    let name = name.as_str();
    let affixes = || SUFFIXES.iter().chain(COMPAT_TOKENS);
    let mut bases: Vec<String> = Vec::new();
    for f in COMPAT_FILES {
        bases.push(key(f));
        for s in affixes() {
            // A token equal to the whole name (`a`, `a.gz`) strips to
            // nothing, which is no base: it would admit every affix alone.
            if let Some(stem) = f.strip_suffix(s).filter(|stem| !stem.is_empty()) {
                bases.push(key(stem));
            }
        }
        for t in TAR_SUFFIXES {
            if let Some(stem) = f.strip_suffix(t) {
                bases.push(key(&format!("{stem}.tar")));
            }
        }
    }
    let rec = name
        .strip_prefix("rec")
        .is_some_and(|r| r.len() >= 5 && r.as_bytes()[..5].iter().all(u8::is_ascii_digit));
    rec || name.starts_with(".stuffr-bzip2-")
        || name.starts_with(".stuffr-gzip-")
        || name.starts_with(".stuffr-xz-")
        || bases.iter().any(|b| {
            name == b
                || name
                    .strip_prefix(b.as_str())
                    .is_some_and(|rest| affixes().any(|s| key(s) == rest))
        })
}

/// Names the tools could write, each with its length and modification time.
type Snapshot = BTreeMap<OsString, (u64, Option<SystemTime>)>;

/// Every name in `dir` the tools could write, with its length and
/// modification time.
fn writable_names(dir: &Path) -> Snapshot {
    let Ok(listing) = std::fs::read_dir(dir) else {
        return BTreeMap::new();
    };
    listing
        .flatten()
        .filter(|e| could_be_written(&e.file_name().to_string_lossy()))
        .map(|e| {
            let meta = std::fs::symlink_metadata(e.path()).ok();
            let len = meta.as_ref().map_or(0, |m| m.len());
            let mtime = meta.and_then(|m| m.modified().ok());
            (e.file_name(), (len, mtime))
        })
        .collect()
}

/// The real working directory's writable names before the first run.
fn cwd_before() -> &'static (PathBuf, Snapshot) {
    static CWD: OnceLock<(PathBuf, Snapshot)> = OnceLock::new();
    CWD.get_or_init(|| {
        let cwd = std::env::current_dir().expect("current dir");
        let names = writable_names(&cwd);
        (cwd, names)
    })
}

/// No name the tools could write (an operand, an output, a temporary) has
/// appeared in, changed in or vanished from the real working directory.
/// Only such names are compared, so libFuzzer's own files never trip it.
fn check_cwd_untouched() {
    let (cwd, before) = cwd_before();
    let now = writable_names(cwd);
    assert!(
        &now == before,
        "compat: the real working directory {cwd:?} changed: before {before:?}, now {now:?}"
    );
}

/// bzip2recover's file system, inside the run's directory, counting what
/// it opens, reads, creates and writes.
struct CountedFs {
    dir: PathBuf,
    opens: u64,
    read: Rc<Cell<u64>>,
    created: u64,
    written: Rc<Cell<u64>>,
}

struct CountedRead(File, Rc<Cell<u64>>);

impl Read for CountedRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.0.read(buf)?;
        self.1.set(self.1.get() + n as u64);
        Ok(n)
    }
}

struct CountedWrite(File, Rc<Cell<u64>>);

impl Write for CountedWrite {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.0.write(buf)?;
        self.1.set(self.1.get() + n as u64);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

fn os_path(name: &[u8]) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    PathBuf::from(std::ffi::OsStr::from_bytes(name))
}

impl bzip2recover::Fs for CountedFs {
    fn open(&mut self, name: &[u8]) -> io::Result<Box<dyn Read>> {
        self.opens += 1;
        let f = File::open(self.dir.join(os_path(name)))?;
        Ok(Box::new(CountedRead(f, self.read.clone())))
    }
    fn create(&mut self, name: &[u8]) -> io::Result<Box<dyn Write>> {
        self.created += 1;
        let f = File::create(self.dir.join(os_path(name)))?;
        Ok(Box::new(CountedWrite(f, self.written.clone())))
    }
}

/// bzip2recover through the counted file system, held to its bounds.
fn run_recover(dir: &Path, args: &[&str]) {
    let mut fs = CountedFs {
        dir: dir.to_path_buf(),
        opens: 0,
        read: Rc::new(Cell::new(0)),
        created: 0,
        written: Rc::new(Cell::new(0)),
    };
    let argv: Vec<Vec<u8>> = args.iter().map(|a| a.as_bytes().to_vec()).collect();
    let mut err = Vec::new();
    let code = bzip2recover::recover(b"bzip2recover", &argv, &mut fs, &mut err);
    let why = || String::from_utf8_lossy(&err).into_owned();
    assert!(
        code <= 1,
        "bzip2recover: exit {code} is not 0 or 1\n{}",
        why()
    );

    // The one input a run can open is its sole operand.
    let len = match args {
        [name] => std::fs::metadata(dir.join(name)).map_or(0, |m| m.len()),
        _ => 0,
    };
    let (opens, read) = (fs.opens, fs.read.get());
    assert!(
        opens <= 2,
        "bzip2recover: {opens} opens, past its two passes"
    );
    assert!(
        read <= 2 * len,
        "bzip2recover: read {read} bytes of a {len}-byte input, past its two passes"
    );
    check_scan_is_linear(read, len).expect("bzip2recover: linear read");

    let (created, written) = (fs.created, fs.written.get());
    assert!(
        created <= MAX_HANDLED_BLOCKS,
        "bzip2recover: {created} outputs"
    );
    assert!(
        written <= len + RECOVER_FRAME * created,
        "bzip2recover: wrote {written} bytes in {created} outputs from a {len}-byte input"
    );
}

/// The bzip2 family through `run_in`.
fn run_bzip2(dir: &Path, name: &str, args: &[&str], stdin: &[u8]) {
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let (code, _out, err) = compat::run_in(dir, name, args, stdin, Flavour::Gnu)
        .expect("a COMPAT_NAMES entry is a compat name");
    assert!(
        (0..=2).contains(&code),
        "{name}: exit {code} is not a bzip2 exit code a hostile input may give (0 ok, 1 environment, 2 corrupt; 3 is bzip2's internal-panic exit, which only a stuffr defect reaches)\n{}",
        String::from_utf8_lossy(&err)
    );
}

/// The arguments in operand position: after `--`, everything; before it,
/// `-` alone (standard input; no file name starts with it, so it names no
/// path in the read bound) and anything not starting with `-` that is not
/// `-S`/`--suffix`'s value (both getopts permute).
fn operands<'a>(args: &[&'a str]) -> Vec<&'a str> {
    let mut out = Vec::new();
    let (mut after_dashes, mut suffix_value) = (false, false);
    for &a in args {
        if suffix_value {
            suffix_value = false;
        } else if after_dashes {
            out.push(a);
        } else if a == "--" {
            after_dashes = true;
        } else if a == "-S" || a == "--suffix" {
            suffix_value = true;
        } else if a == "-" || !a.starts_with('-') {
            out.push(a);
        }
    }
    out
}

/// Every file in `dir` with its contents.
type Contents = BTreeMap<OsString, Vec<u8>>;

fn contents(dir: &Path) -> Contents {
    let Ok(listing) = std::fs::read_dir(dir) else {
        return BTreeMap::new();
    };
    listing
        .flatten()
        .filter_map(|e| Some((e.file_name(), std::fs::read(e.path()).ok()?)))
        .collect()
}

/// The texts GNU gives a later member's refused header (`gnu/messages.rs`:
/// `UNKNOWN_METHOD`, `ENCRYPTED`, `HAS_FLAGS`, `HEADER_CRC`, `Z_BITS`), the
/// one exit-1 failure after which GNU keeps what it decoded.
const GNU_LATER_HEADER: &[&str] = &[
    "unknown method",
    "is encrypted -- not supported",
    "has flags 0x",
    "header checksum 0x",
    "can only handle",
];

/// The gzip family through `run_in_counted`, as `flavour`.
fn run_gzip(dir: &Path, name: &str, flavour: u8, args: &[&str], stdin: &[u8], payload: &[u8]) {
    let before = contents(dir);
    let flavour = if flavour == 0 {
        Flavour::Gnu
    } else {
        Flavour::Bsd
    };
    let os_args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let (code, _out, err, reads) = compat::run_in_counted(dir, name, os_args, stdin, flavour)
        .expect("a COMPAT_NAMES entry is a compat name");
    let why = || String::from_utf8_lossy(&err).into_owned();
    if std::env::var_os("STUFFR_FUZZ_COMPAT_TRACE").is_some() {
        eprintln!("compat: {name} {flavour:?} {args:?} -> {code}");
        for (path, r) in &reads {
            eprintln!("compat:   {path:?} {r:?}");
        }
    }
    assert!(
        (0..=2).contains(&code),
        "{name} ({flavour:?}): exit {code} is not a gzip exit code\n{}",
        why()
    );
    check_gzip_reads(dir, name, flavour, args, &reads);
    check_gzip_leftovers(dir, name, flavour, args);
    check_gzip_no_partial(dir, name, flavour, args, code, &err, payload, &before);
}

/// A failed run leaves no partial output: a run whose only operand
/// (`operands`) is one file, so that standard input is not read, creates
/// or changes no file in its directory when it fails,
/// where "fails" is:
///
/// - GNU: exit 1, unless standard error carries a later member's header
///   refusal (`GNU_LATER_HEADER`), after which GNU keeps the members
///   decoded so far and removes the input (Task 8, observed: `gzip -d` on a
///   member followed by `1f 8b` and junk). Every other GNU exit-1 failure
///   (truncation, corrupt data, CRC or length, a write error, a refused
///   first header) removes the temporary. Exit 2 is warnings only (trailing
///   garbage, a suffix note): the output is whole.
/// - BSD: exit 1 when the operand holds a gzip member (`1f 8b` or `1f 9e`;
///   every case file holds the payload). Apple's gzip failures are
///   `maybe_warn[x]`, exit 1, output unlinked. Exit 2 is not judged: it is
///   trailing garbage after whole members (output kept, whole), or a
///   foreign format's `maybe_err`, whose partial output Ruling T10-2 keeps;
///   and a foreign-format payload is not judged at all.
///
/// Not detected: a partial output in a run with several operands (which
/// one failed is not known from outside, and an earlier one's output is
/// legitimate), in a run that reads standard input at all (a `-` operand,
/// or no operand: its failure may follow a file operand's whole output, as
/// in `gunzip a.gz -` with an empty standard input), or one that a GNU
/// later-header refusal's message accompanies.
#[allow(clippy::too_many_arguments)]
fn check_gzip_no_partial(
    dir: &Path,
    name: &str,
    flavour: Flavour,
    args: &[&str],
    code: i32,
    err: &[u8],
    payload: &[u8],
    before: &Contents,
) {
    let operands = operands(args);
    if operands.len() != 1 || operands.contains(&"-") || code != 1 {
        return;
    }
    let text = String::from_utf8_lossy(err);
    let judged = match flavour {
        Flavour::Gnu => !GNU_LATER_HEADER.iter().any(|m| text.contains(m)),
        _ => payload.starts_with(&[0x1f, 0x8b]) || payload.starts_with(&[0x1f, 0x9e]),
    };
    if !judged {
        return;
    }
    for (n, bytes) in contents(dir) {
        assert!(
            before.get(&n) == Some(&bytes),
            "{name} ({flavour:?}) {args:?}: failed (exit 1) and left {n:?} \
             ({} bytes) new or changed\n{text}",
            bytes.len()
        );
    }
}

/// The gzip family's read bound: for every path a run opened, at most two
/// opens and `2 × len` bytes read per operand that can name it, where an
/// operand (an argument in operand position, `operands`) can name a path when the path's file name starts with it (the
/// operand itself, or the operand plus a suffix a missing operand is
/// retried with: GNU's suffix search, Apple's `.gz`/`-S` retry and `zcat`'s
/// `.Z`), and `len` is the largest length the file had when opened (a run
/// can rewrite a file a later operand opens: `gzip -f a a.gz`). A path no
/// operand can name must not be opened at all.
///
/// Measured over the seeds and the 20-minute run (both flavours; the
/// report of 0.12.0 Task 11 has the table): every mode opens an operand
/// once. GNU reads it once (compress, `-d`, `-t`, `-l`, `-r`). Apple's
/// decompression reads the first 4 bytes, then (gzip) the 4-byte
/// timestamp at offset 4 and, under `-N`, up to 1024 bytes of name at
/// offset 10, then rewinds and decodes from the start: under `2 × len` for
/// every length. Apple's `-l` reads the last 8 bytes (gzip) or walks the xz
/// indexes backwards from the footer (each index read once, the stream
/// padding and headers in 12-byte steps), under `len`; `-lt` lists and
/// then tests from where the listing left the descriptor. So no mode needs
/// a bound looser than `2 × len`.
fn check_gzip_reads(
    dir: &Path,
    name: &str,
    flavour: Flavour,
    args: &[&str],
    reads: &BTreeMap<PathBuf, compat::InputReads>,
) {
    for (path, r) in reads {
        let file = path
            .strip_prefix(dir)
            .ok()
            .and_then(|p| p.to_str())
            .unwrap_or_else(|| panic!("{name} ({flavour:?}): opened {path:?}, outside {dir:?}"));
        let operands = operands(args)
            .iter()
            .filter(|a| file.starts_with(**a))
            .count() as u64;
        assert!(
            r.opens <= 2 * operands,
            "{name} ({flavour:?}) {args:?}: {} opens of {file:?}, which {operands} operand(s) can name",
            r.opens
        );
        assert!(
            r.bytes <= 2 * r.len * operands,
            "{name} ({flavour:?}) {args:?}: read {} bytes of the {}-byte {file:?}, \
             which {operands} operand(s) can name",
            r.bytes,
            r.len
        );
    }
}

/// No `.stuffr-gzip-*` temporary survives a run, and (unless `-N` lets a
/// stored name choose an output) every name in the run's directory is one
/// `could_be_written` allows.
fn check_gzip_leftovers(dir: &Path, name: &str, flavour: Flavour, args: &[&str]) {
    let stored_names = args.iter().any(|a| *a == "-N" || *a == "--name");
    let Ok(listing) = std::fs::read_dir(dir) else {
        return;
    };
    for e in listing.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        assert!(
            !n.starts_with(".stuffr-gzip-"),
            "{name} ({flavour:?}) {args:?}: left its temporary {n:?}"
        );
        assert!(
            stored_names || could_be_written(&n),
            "{name} ({flavour:?}) {args:?}: left a stray {n:?}"
        );
    }
}

/// The xz family's operation, as args.c settles it: the invoked name's
/// default, then the last of `-z`/`-d`/`-t`/`-l` (and their long forms).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XzMode {
    Compress,
    Decompress,
    Test,
    List,
}

/// xz's options in the token table that take the next argument when it is
/// not attached (`-S .x`, `-F xz`, `--check crc32`).
const XZ_TAKES_NEXT: &[&str] = &["-S", "--suffix", "-F", "--format", "--check"];

/// The short options of xz 5.8.4 (`args.c`'s `short_opts`) that take an
/// argument: the rest of the cluster, or else the next argument.
const XZ_SHORT_WITH_ARG: &[char] = &['C', 'F', 'M', 'S', 'T'];

/// The xz family's arguments in operand position, and the operation, as
/// getopt_long (permuting: the environment is not read, so no
/// `POSIXLY_CORRECT`) and args.c see them.
fn xz_parse<'a>(name: &str, args: &[&'a str]) -> (Vec<&'a str>, XzMode) {
    let mut mode = match name {
        "unxz" | "xzcat" | "unlzma" | "lzcat" => XzMode::Decompress,
        _ => XzMode::Compress,
    };
    let mut out = Vec::new();
    let (mut after_dashes, mut value) = (false, false);
    for &a in args {
        if value {
            value = false;
        } else if after_dashes || a == "-" || !a.starts_with('-') {
            out.push(a);
        } else if a == "--" {
            after_dashes = true;
        } else if XZ_TAKES_NEXT.contains(&a) {
            value = true;
        } else if let Some(long) = a.strip_prefix("--") {
            match long {
                "compress" => mode = XzMode::Compress,
                "decompress" | "uncompress" => mode = XzMode::Decompress,
                "test" => mode = XzMode::Test,
                "list" => mode = XzMode::List,
                _ => {}
            }
        } else {
            let cluster: Vec<char> = a[1..].chars().collect();
            for (i, c) in cluster.iter().enumerate() {
                match c {
                    'z' => mode = XzMode::Compress,
                    'd' => mode = XzMode::Decompress,
                    't' => mode = XzMode::Test,
                    'l' => mode = XzMode::List,
                    c if XZ_SHORT_WITH_ARG.contains(c) => {
                        value = i + 1 == cluster.len();
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
    (out, mode)
}

/// Whether the run reads file names from standard input (`--files`,
/// `--files0` with no `=FILE`).
fn xz_names_from_stdin(args: &[&str]) -> bool {
    args.iter().any(|a| *a == "--files" || *a == "--files0")
}

/// The list file a `--files=FILE`/`--files0=FILE` token names (the table's
/// only such tokens name `a`).
fn xz_names_file<'a>(args: &[&'a str]) -> Option<&'a str> {
    args.iter().find_map(|a| {
        a.strip_prefix("--files=")
            .or_else(|| a.strip_prefix("--files0="))
    })
}

/// A superset of the names `read_name` splits out of a list: both
/// terminators.
fn xz_list_names(bytes: &[u8]) -> impl Iterator<Item = &str> {
    bytes
        .split(|b| *b == b'\n' || *b == 0)
        .filter_map(|n| std::str::from_utf8(n).ok())
}

/// The xz family through `run_in_counted`.
fn run_xz(dir: &Path, name: &str, args: &[&str], stdin: &[u8]) {
    // `--files`/`--files0` take operands from standard input, or from the
    // file `--files=FILE`/`--files0=FILE` names, which holds the payload:
    // a name holding a `/` could leave the run's directory (`/…`, `../…`),
    // and xz would compress it and remove it. No token holds a `/`
    // (`COMPAT_TOKENS`), so without one every name stays inside. Such a
    // case is not run. A list file that was not created (xz cannot open
    // it) contributes no names and no rule.
    let before = contents(dir);
    let list_file = xz_names_file(args).filter(|f| dir.join(f).is_file());
    // Read before the run: it may compress and remove the list.
    let list_bytes: &[u8] = list_file
        .and_then(|f| before.get(std::ffi::OsStr::new(f)))
        .map_or(&[], |v| v.as_slice());
    if (xz_names_from_stdin(args) && stdin.contains(&b'/')) || list_bytes.contains(&b'/') {
        return;
    }
    let os_args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let (code, out, err, reads) = compat::run_in_counted(dir, name, os_args, stdin, Flavour::Gnu)
        .expect("a COMPAT_NAMES entry is a compat name");
    let why = || String::from_utf8_lossy(&err).into_owned();
    if std::env::var_os("STUFFR_FUZZ_COMPAT_TRACE").is_some() {
        eprintln!("compat: {name} {args:?} -> {code}");
        for (path, r) in &reads {
            eprintln!("compat:   {path:?} {r:?}");
        }
    }
    // xz's exits only (main.c, message.c): 0, 1 error, 2 warning; never
    // stuffr's 3-7.
    assert!(
        (0..=2).contains(&code),
        "{name} {args:?}: exit {code} is not an xz exit code\n{}",
        why()
    );
    let (mut operands, mode) = xz_parse(name, args);
    if xz_names_from_stdin(args) {
        operands.extend(xz_list_names(stdin));
    }
    if list_file.is_some() {
        operands.extend(xz_list_names(list_bytes));
    }
    check_xz_reads(dir, name, args, mode, &operands, list_file, &reads);
    check_xz_leftovers(dir, name, args);
    check_xz_budget(dir, name, args, &out, &before);
}

/// `IO_BUFFER_SIZE` (file_io.h): the window `--list` reads back from each
/// Stream's end to find its padding.
const XZ_IO_BUFFER: u64 = 8192;

/// `LZMA_BLOCK_HEADER_SIZE_MAX`: the most `-vv` reads of one Block Header.
const XZ_BLOCK_HEADER_MAX: u64 = 1024;

/// The most `--list` may read of a `len`-byte file in one open: see
/// `check_xz_reads`.
fn xz_list_bound(len: u64) -> u64 {
    let walk_steps = len / 32 + 1;
    XZ_HEADER_SIZE + len + walk_steps * len.min(XZ_IO_BUFFER) + XZ_BLOCK_HEADER_MAX
}

/// A Stream Header's (and Footer's) size.
const XZ_HEADER_SIZE: u64 = 12;

/// The xz family's read bound, for every path a run opened: at most two
/// opens per operand that names it exactly (xz retries no suffix), and in
/// bytes, with `len` its largest length at an open:
///
/// - compress, decompress and test: at most `2 × len` per operand. Every
///   seed reads each input once (`len`); `2 ×` leaves room for a header
///   probe without letting a second full pass through.
/// - `--list`: at most `xz_list_bound(len)` per operand, which is not
///   linear, because xz's is not. list.c's walk (liblzma's file_info.c,
///   `index.rs`) reads the first Stream Header (12 bytes), then for each
///   Stream from the end: a window of up to `IO_BUFFER_SIZE` bytes back
///   from the Stream's end to measure its padding (whole zero windows are
///   padding and not read again; the last, partial one is), the Footer, the
///   Index and the Stream Header. Footers, Indexes, Headers and padding are
///   disjoint (`len` in all), but each Stream's padding window re-reads up
///   to 8 KiB of what lies before it, as xz's own `reverse_seek` re-reads
///   its 8 KiB `temp` from a new seek. A Stream that decodes is at least
///   32 bytes (Header, an 8-byte Index, Footer), and the first that does not
///   ends the walk, so there are at most `len / 32 + 1` windows. `-vv` then
///   reads each Block's Header (at most 1024 bytes) and Check, inside the
///   Block, except one Block shorter than its Check, whose wrapped Header
///   read takes 1024 bytes wherever they lie and ends the listing. Measured
///   on the seeds: a one-Stream 508-byte file reads 532 (the window takes
///   the Footer and Index once more).
///
/// A path no operand names must not be opened at all.
fn check_xz_reads(
    dir: &Path,
    name: &str,
    args: &[&str],
    mode: XzMode,
    operands: &[&str],
    list_file: Option<&str>,
    reads: &BTreeMap<PathBuf, compat::InputReads>,
) {
    for (path, r) in reads {
        let file = path
            .strip_prefix(dir)
            .ok()
            .and_then(|p| p.to_str())
            .unwrap_or_else(|| panic!("{name}: opened {path:?}, outside {dir:?}"));
        let m = operands.iter().filter(|a| **a == file).count() as u64;
        let per_operand = match mode {
            XzMode::List => xz_list_bound(r.len),
            _ => 2 * r.len,
        };
        // Each `=` token naming this file as the list is one more open, and
        // one more read of the whole file.
        let lists = args
            .iter()
            .filter(|a| xz_names_file(&[**a]) == Some(file) && list_file == Some(file))
            .count() as u64;
        assert!(
            r.opens <= 2 * m + lists,
            "{name} {args:?}: {} opens of {file:?}, which {m} operand(s) name \
             and {lists} list token(s) read",
            r.opens
        );
        assert!(
            r.bytes <= per_operand * m + r.len * lists,
            "{name} {args:?} ({mode:?}): read {} bytes of the {}-byte {file:?}, \
             which {m} operand(s) name and {lists} list token(s) read",
            r.bytes,
            r.len
        );
    }
}

/// Whether the run's directory folds ASCII case in names (macOS's APFS by
/// default): `x` created in the sandbox parent also opens as `X`. Probed
/// once per process.
fn case_insensitive_fs() -> bool {
    static FOLDS: OnceLock<bool> = OnceLock::new();
    *FOLDS.get_or_init(|| {
        let parent = sandbox();
        let _ = std::fs::create_dir_all(parent);
        let probe = parent.join("x-case-probe");
        let folds =
            File::create(&probe).is_ok() && parent.join("X-CASE-PROBE").symlink_metadata().is_ok();
        let _ = std::fs::remove_file(&probe);
        folds
    })
}

/// No `.stuffr-xz-*` temporary survives a run, and every name in the
/// run's directory is one `could_be_written` allows. A name a run reads
/// itself (`--files`, `--files0`, `--files=FILE`) may differ from a table
/// name only by ASCII case: on a case-folding filesystem it opens the
/// table's file, and the output is spelled as the operand was.
fn check_xz_leftovers(dir: &Path, name: &str, args: &[&str]) {
    let Ok(listing) = std::fs::read_dir(dir) else {
        return;
    };
    for e in listing.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        assert!(
            !n.starts_with(".stuffr-xz-"),
            "{name} {args:?}: left its temporary {n:?}"
        );
        assert!(
            could_be_written(&n)
                || (case_insensitive_fs() && !n.contains('/') && could_be_written_folded(&n)),
            "{name} {args:?}: left a stray {n:?}"
        );
    }
}

/// `run_in`'s output budget (`SANDBOX_OUTPUT_CAP`), restated: standard
/// output and every output file together.
const OUTPUT_BUDGET: u64 = 8 * 1024 * 1024;

/// The run kept to its output budget: standard output plus every file
/// that is new or changed in its directory (each written whole through
/// the budget, so its final length is at most what it was charged).
fn check_xz_budget(dir: &Path, name: &str, args: &[&str], out: &[u8], before: &Contents) {
    let written: u64 = contents(dir)
        .into_iter()
        .filter(|(n, bytes)| before.get(n) != Some(bytes))
        .map(|(_, bytes)| bytes.len() as u64)
        .sum();
    let total = out.len() as u64 + written;
    assert!(
        total <= OUTPUT_BUDGET,
        "{name} {args:?}: {} bytes to stdout and {written} to files, past the \
         {OUTPUT_BUDGET}-byte budget",
        out.len()
    );
}

fuzz_target!(|data: &[u8]| {
    if data.len() > COMPAT_FUZZ_MAX_INPUT {
        return;
    }
    let Some(case) = decode_compat_case(data) else {
        return;
    };
    cwd_before();
    let parent = sandbox();
    let _ = std::fs::remove_dir_all(parent);
    std::fs::create_dir_all(parent).expect("create the sandbox parent");
    let dir = parent.join("run");
    std::fs::create_dir(&dir).expect("create the run directory");
    for f in &case.files {
        std::fs::write(dir.join(f), case.payload).expect("write a case file");
    }
    let stdin: &[u8] = if case.stdin { case.payload } else { b"" };

    match case.name {
        "bzip2recover" => run_recover(&dir, &case.args),
        "gzip" | "gunzip" | "zcat" | "gzcat" => run_gzip(
            &dir,
            case.name,
            case.flavour,
            &case.args,
            stdin,
            case.payload,
        ),
        "xz" | "unxz" | "xzcat" | "lzma" | "unlzma" | "lzcat" => {
            run_xz(&dir, case.name, &case.args, stdin)
        }
        "bzip2" | "bunzip2" | "bzcat" => run_bzip2(&dir, case.name, &case.args, stdin),
        other => unreachable!("{other} is in COMPAT_NAMES but has no arm here"),
    }

    check_extraction_contained(parent, &dir, &[]).expect("compat: contained");
    check_cwd_untouched();
    std::fs::remove_dir_all(parent).expect("remove the sandbox parent");
});
