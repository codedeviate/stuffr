//! The compatibility families, run in-process: the bzip2 family (0.11.0
//! Task 6: `bzip2`, `bunzip2`, `bzcat`, `bzip2recover`) and the gzip family
//! (0.12.0 Task 11: `gzip`, `gunzip`, `zcat`, `gzcat`, each as GNU and as
//! Apple/BSD), through `stuffr_cli::compat::run_in_counted` and
//! `bzip2recover::recover`.
//!
//! The only fuzz coverage of `stuffr::bzip2_stream::StreamReader`, the
//! libbzip2-shaped decoder only the compat layer reaches, and of the gzip
//! personalities' own decoders: GNU's member reader, pack and `.Z` paths and
//! its zip entry; Apple's `gz_uncompress` state machine, `unlz`, `zread`, the
//! xz index reader behind `-l`, and the raw bzip2/xz/pack steps.
//!
//! An input is `[tool][argc][token; argc][file mask] ++ payload`, decoded by
//! `stuffr_core::testing::decode_compat_case` (whose tables are the wire
//! format of the seeds `crates/stuffr/tests/fuzz_corpus.rs` writes). The
//! tool byte also picks the gzip flavour, `(byte / names) & 1` (R7). Each
//! file the mask names is created holding the payload; with the mask's stdin
//! bit, standard input carries it too.
//!
//! Asserted, for every input:
//!
//! - no panic;
//! - the exit code is one the tool has: 0-3 for the bzip2 family (`0` ok,
//!   `1` environment, `2` corrupt, `3` internal), 0 or 1 for bzip2recover,
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
//!   `.bz2`, `.xz`, lzip, pack and `.Z`: Ruling T10-2) are allowed.
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
    ".xz", ".lz", ".tar",
];

/// Suffixes a decompressor maps to `.tar` rather than strip.
const TAR_SUFFIXES: &[&str] = &[".tbz2", ".tbz", ".tgz", ".taz"];

/// Whether `name` is one the tools could write in their working directory:
/// a `COMPAT_FILES` name or one derived from it (a suffix or token stripped,
/// or mapped to `.tar`; then a suffix or token added: gzip's `-S` takes any
/// token), a bzip2recover output (`rec` and five digits), or a temporary
/// (`.stuffr-bzip2-*`, `.stuffr-gzip-*`).
///
/// Generous on purpose: it is the real working directory's snapshot filter
/// (a superset only snapshots more) and the run directory's stray-file
/// check (where it has to admit every output a run may legitimately leave,
/// Apple's kept partial outputs included).
fn could_be_written(name: &str) -> bool {
    let affixes = || SUFFIXES.iter().chain(COMPAT_TOKENS);
    let mut bases: Vec<String> = Vec::new();
    for f in COMPAT_FILES {
        bases.push((*f).to_owned());
        for s in affixes() {
            // A token equal to the whole name (`a`, `a.gz`) strips to
            // nothing, which is no base: it would admit every affix alone.
            if let Some(stem) = f.strip_suffix(s).filter(|stem| !stem.is_empty()) {
                bases.push(stem.to_owned());
            }
        }
        for t in TAR_SUFFIXES {
            if let Some(stem) = f.strip_suffix(t) {
                bases.push(format!("{stem}.tar"));
            }
        }
    }
    let rec = name
        .strip_prefix("rec")
        .is_some_and(|r| r.len() >= 5 && r.as_bytes()[..5].iter().all(u8::is_ascii_digit));
    rec || name.starts_with(".stuffr-bzip2-")
        || name.starts_with(".stuffr-gzip-")
        || bases.iter().any(|b| {
            name == b
                || name
                    .strip_prefix(b.as_str())
                    .is_some_and(|rest| affixes().any(|s| *s == rest))
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
        (0..=3).contains(&code),
        "{name}: exit {code} is not a bzip2 exit code\n{}",
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
        _ => run_bzip2(&dir, case.name, &case.args, stdin),
    }

    check_extraction_contained(parent, &dir, &[]).expect("compat: contained");
    check_cwd_untouched();
    std::fs::remove_dir_all(parent).expect("remove the sandbox parent");
});
