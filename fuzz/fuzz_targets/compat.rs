//! The compatibility families, run in-process: the bzip2 family (0.11.0
//! Task 6: `bzip2`, `bunzip2`, `bzcat`, `bzip2recover`), the gzip family
//! (0.12.0 Task 11: `gzip`, `gunzip`, `zcat`, `gzcat`, each as GNU and as
//! Apple/BSD), the xz family (0.13.0 Task 9: `xz`, `unxz`, `xzcat`,
//! `lzma`, `unlzma`, `lzcat`) and the zstd family (0.14.0 Task 10: `zstd`,
//! `unzstd`, `zstdcat`, `zstdmt`) and the lz4 family (0.15.0 Task 8:
//! `lz4`, `unlz4`, `lz4cat`, `lz4c`) and the unzip family (0.16.0 Tasks 7
//! and 15: `unzip`, `zipinfo`, `funzip`, each as Apple's and as Ubuntu's)
//! and the compress family (0.18.0: `compress`, `uncompress`, each as
//! Apple's and as ncompress), through `stuffr_cli::compat::run_in_counted`
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
//! are not caught (Ruling P10), so they reach the fuzzer. And of the zstd
//! family's argument parser, its frame driver over `stuffr::zstd_opts`, the
//! foreign formats it decodes and writes (`--format=gzip|lz4`; gzip, xz,
//! lzma and lz4 input), `--filelist`, `-r`, the `-l` header walker and
//! the dictionary paths, on the tier this crate builds: the pure one
//! (`stuffr-cli` without `zstd-c`), where compressing with `-D` or
//! `--patch-from`, and `--train*`, refuse with exit 1 (spec deviation 7;
//! `-D` and `--patch-from` after reading the dictionary).
//!
//! An input is `[tool][argc][token; argc][file mask] ++ payload`, decoded by
//! `stuffr_core::testing::decode_compat_case` (whose tables are the wire
//! format of the seeds `crates/stuffr/tests/fuzz_corpus.rs` writes). The
//! tool byte also picks the gzip and unzip flavours, `(byte / names) & 1`
//! (R7: 0 GNU or Ubuntu, 1 BSD or Apple), and the compress family's: 0
//! ncompress, 1 Apple (absolute, not relative to the platform's default, so
//! a crash artifact replays the same personality everywhere). Each
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
//!   (`check_budget`). A `--files`/`--files0` case whose names (standard
//!   input, or the list file when it exists) hold a `/` is not run: such a
//!   name could leave the run's directory.
//! - the zstd family exits 0, 1 or 2, or with one of `EXM_THROW`'s codes
//!   (`ZSTD_EXM`; never a code outside them). Its read bound
//!   (`check_zstd_reads`, which says what each mode was measured at): per
//!   operand naming a path exactly, at most two opens, and `2 × len`
//!   bytes when compressing, decompressing or testing, `len` under `-l`
//!   and `--train*`; plus one open and `len` bytes per `-D`/`--patch-from`
//!   value and per `--filelist` value naming it. It leaves no
//!   `.stuffr-zstd-*` temporary and no name `could_be_written` does not
//!   allow (a `--filelist` name counts as a base), and keeps the 8 MiB
//!   output budget. A `--filelist` case whose list holds a `/`, `.` or
//!   `..` is not run (a name could leave the run's directory, or reach a
//!   file under `-r` by a path no operand spells).
//! - the lz4 family exits 0, 1 or one of lz4's own codes
//!   (`stuffr_cli::compat::lz4::EXIT_CODES`, the set the reference was
//!   probed to produce, shared with the differential suite). Its read
//!   bound (`run_lz4`, which says what it was measured at): per operand
//!   naming a path exactly, at most two opens and `2 × len` bytes (`len`
//!   under `--list`), plus one open and `len` bytes per `-D` value naming
//!   it. It leaves no `.stuffr-lz4-*` temporary and no name
//!   `could_be_written` does not allow (every non-flag token is a base: an
//!   operand after the input names the output), and keeps the 8 MiB output
//!   budget. The lz4 family's tokens bring `a.lz4`, the sixteenth
//!   `COMPAT_FILES` entry, which takes a third mask byte (present when the
//!   argument-count byte is at least 18); `-D` takes `d.dict`.
//! - the brotli family exits 0 or 1 (`run_brotli`), leaves no `.stuffr-*`
//!   temporary and no name `could_be_written` does not allow (every non-flag
//!   token is a base), and keeps the 8 MiB output budget. Its tokens bring
//!   `a.br`, the twenty-first `COMPAT_FILES` entry (third mask byte, bit 21),
//!   and the `-q`/`-w`/`-K`/`-C` forms.
//! - the unzip family exits with one of its flavour's reference codes
//!   (`unzip::EXIT_CODES_APPLE`, `unzip::EXIT_CODES_UBUNTU`), reads each
//!   archive within `check_unzip_reads`' bound (not linear: Apple's build
//!   reads an entry once per central record naming it), keeps the output
//!   budget over the whole extracted tree, writes nothing through the
//!   symlinks it extracts, and puts no name in the real working directory
//!   (`run_unzip`). Its tokens bring `a.zip` and `b.zip`, the seventeenth
//!   and eighteenth `COMPAT_FILES` entries, on the third mask byte.
//! - the compress family exits with its personality's codes (Apple 0, 1, 2;
//!   ncompress also 4) and is held to `run_compress`'s oracle, whose doc
//!   lists every rule: reads, leftovers and temporaries, no partial output
//!   after a failure, a success that did something, a stderr line for every
//!   failure, and no input lost (each file a compressing run wrote, and its
//!   standard output, must be read back to the input by both decoders). Its
//!   tokens bring `a.Z` and `b.Z`, the nineteenth and twentieth
//!   `COMPAT_FILES` entries, on the third mask byte (bits 19 and 20), and
//!   the `-b` forms.
//! - the zip family (`zip`, `zipcloak`, `zipnote`, `zipsplit`; flavour byte
//!   absolute, 0 Ubuntu and 1 Apple) exits with a ziperr code
//!   (`zip::EXIT_CODES`, never 1), opens only files an operand names within
//!   `check_zip_reads`' bound (`-FF` at `2 × len + 1 MiB`), makes only names
//!   a token spells (`zip_name_ok`), leaves no `zi??????` temporary, makes at
//!   most as many files as the archive has entries plus three (zipsplit),
//!   keeps the output budget (the `-lf` log's bytes and `-FF`'s reads are
//!   charged to it), and every archive it writes reads back by an
//!   independent walk (`zip_readback::verify_zip`: stored and deflated data
//!   by `infozip::inflate` to the record's size and CRC, and the same bytes
//!   from the `zip` crate unless a name repeats) when its input
//!   archives were whole (`run_zip` says why only then). No token is
//!   absolute or names `..`; names a payload supplies (`-@`, `@a`, an
//!   archive's entries) are kept in the run's directory by the sandbox
//!   (`Host::path`), and `check_extraction_contained` sees nothing outside
//!   change. It adds no `COMPAT_FILES`: `a.zip` and `b.zip` are unzip's.
//!
//! **Memory under the xz names (Ruling P7).** libFuzzer's RSS limit is the
//! bound: 1 GiB in a daytime `make fuzz`, which passes `-rss_limit_mb=1024`
//! (that flag also sets `-malloc_limit_mb` to the same figure), and the
//! 2 GiB default under `FULL=1`. Each verb stays inside it by a limit
//! stuffr applies or by the token table:
//!
//! - compress: the most memory a case can ask for is a preset's, `-9`/`-9e`
//!   (a 64 MiB dictionary, about 674 MiB per encoder reserved); no token
//!   sets a larger dictionary (`--lzma2=dict=4KiB` is the only one) or
//!   more than the sandbox's two threads (`Hardware::SANDBOX`, R3). The
//!   encoder's tables are allocated untouched and an input is at most
//!   64 KiB, so only what the input reaches becomes resident: the seeds,
//!   `-T0 -9` among them, peak at 296 MB. That is why the 1 GiB daytime
//!   limit still fits: two `-9` encoders reserve about 1348 MiB, but the
//!   limit counts resident memory, not reserved, and 296 MB is well under
//!   it. The malloc limit applies to one allocation, and no single one can
//!   exceed the 674 MiB a whole encoder reserves. All seven targets passed
//!   a daytime `make fuzz` at 1024.
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

mod zip_readback;
use stuffr_cli::compat::{self, bzip2recover, compress, gzip::Flavour, unzip, zip};
use stuffr_core::testing::{
    COMPAT_FILES, COMPAT_FUZZ_MAX_INPUT, COMPAT_TOKENS, check_extraction_contained,
    check_scan_is_linear, decode_compat_case,
};
use zip_readback::verify_zip;

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
    ".xz", ".lz", ".tar", ".txz", ".lzma", ".tlz", ".zst", ".tzst", ".lz4", ".tlz4", ".br",
];

/// Suffixes a decompressor maps to `.tar` rather than strip.
const TAR_SUFFIXES: &[&str] = &[
    ".tbz2", ".tbz", ".tgz", ".taz", ".txz", ".tlz", ".tzst", ".tlz4",
];

/// Names the zstd family writes that no table file derives: `--train`'s
/// default output (zstdcli.c's `g_defaultDictName`).
const ZSTD_NAMES: &[&str] = &["dictionary"];

/// Whether `name` is one the tools could write in their working directory:
/// a `COMPAT_FILES` name or one derived from it (a suffix or token stripped,
/// or mapped to `.tar`; then a suffix or token added: gzip's `-S` takes any
/// token), a bzip2recover output (`rec` and five digits), or a temporary
/// (`.stuffr-bzip2-*`, `.stuffr-gzip-*`, `.stuffr-xz-*`, `.stuffr-zstd-*`),
/// or zstd's `dictionary` (`--train`'s default output).
///
/// Generous on purpose: it is the real working directory's snapshot filter
/// (a superset only snapshots more) and the run directory's stray-file
/// check (where it has to admit every output a run may legitimately leave,
/// Apple's kept partial outputs included).
fn could_be_written(name: &str) -> bool {
    could_be_written_with(name, false, &[])
}

/// `could_be_written`, with the name and every table name compared
/// lowercased: a case-insensitive filesystem opens `a.xz` for `A.XZ`.
fn could_be_written_folded(name: &str) -> bool {
    could_be_written_with(name, true, &[])
}

/// `could_be_written`, also taking each of `extra` (names a zstd run read
/// from its `--filelist`) as a base: an earlier operand's output can be a
/// later listed name's input (`a`, `a.zst`: `a.zst.zst`).
fn could_be_written_with(name: &str, fold: bool, extra: &[&str]) -> bool {
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
    for f in COMPAT_FILES.iter().chain(extra) {
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
        || name.starts_with(".stuffr-zstd-")
        || name.starts_with(".stuffr-lz4-")
        || ZSTD_NAMES.iter().any(|n| key(n) == name)
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
        // As `RealFs` (Debian's O_EXCL, 0600; ruling T5): an existing name
        // is refused, never truncated or written through.
        let f = {
            use std::os::unix::fs::OpenOptionsExt;
            File::options()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(self.dir.join(os_path(name)))?
        };
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

/// The brotli family: exit 0 or 1 only (`brotli.c` has no other), no stray
/// name in the run's directory (every non-flag token is a base, as an
/// operand after `-o` or `-S`'s value names a file) and no stuffr temporary.
/// The 8 MiB output budget of `run_in` binds here too, `-t`'s decoded bytes
/// included (a sandbox bound, not the tool's: it ends `failed to write
/// output`, exit 1).
fn run_brotli(dir: &Path, name: &str, args: &[&str], stdin: &[u8]) {
    let os_args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let (code, _out, err) = compat::run_in(dir, name, os_args, stdin, Flavour::Gnu)
        .expect("a COMPAT_NAMES entry is a compat name");
    assert!(
        (0..=1).contains(&code),
        "{name} {args:?}: exit {code} is not 0 or 1\n{}",
        String::from_utf8_lossy(&err)
    );
    let bases: Vec<&str> = args
        .iter()
        .copied()
        .filter(|a| !a.starts_with('-'))
        .collect();
    let Ok(listing) = std::fs::read_dir(dir) else {
        return;
    };
    for e in listing.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        assert!(
            !n.starts_with(".stuffr-"),
            "{name} {args:?}: left its temporary {n:?}"
        );
        assert!(
            could_be_written_with(&n, false, &bases)
                || (case_insensitive_fs() && could_be_written_with(&n, true, &bases)),
            "{name} {args:?}: left a stray {n:?}"
        );
    }
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
    let (code, _out, err, reads) = compat::run_in_counted(
        dir,
        name,
        os_args,
        stdin,
        flavour,
        unzip::default_flavour(),
        compress::default_flavour(),
        zip::default_flavour(),
    )
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
    let (code, out, err, reads) = compat::run_in_counted(
        dir,
        name,
        os_args,
        stdin,
        Flavour::Gnu,
        unzip::default_flavour(),
        compress::default_flavour(),
        zip::default_flavour(),
    )
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
    check_budget(dir, name, args, &out, &before);
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
fn check_budget(dir: &Path, name: &str, args: &[&str], out: &[u8], before: &Contents) {
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

/// zstd's exit codes beyond 0, 1 (an error `main` returns) and 2: every
/// `EXM_THROW` code zstd 1.5.7's `programs/` can reach (fileio.c,
/// dibio.c, zstdcli.c), the Global Constraints' list.
const ZSTD_EXM: &[i32] = &[
    1, 3, 4, 5, 10, 11, 12, 14, 19, 20, 21, 27, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 40, 42, 43,
    60, 69, 70, 71, 72, 74, 77, 79, 81, 82, 83, 84, 91, 92, 93, 95, 100, 101, 102, 103, 104,
];

/// The zstd family's operation, as zstdcli.c settles it: the invoked
/// name's preset, then the last of `-z`/`-d`/`-t`/`-l`/`--train*` (and the
/// long forms).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ZstdMode {
    Compress,
    Decompress,
    Test,
    List,
    Train,
}

/// The arguments of a zstd-family run as zstdcli.c sees them.
#[derive(Debug)]
struct ZstdArgs<'a> {
    /// The arguments in operand position (`-` excluded: standard input).
    operands: Vec<&'a str>,
    /// Each `-D` value and `--patch-from` value: a dictionary or prefix,
    /// read whole once (`FIO_setDictBufferMalloc`).
    dicts: Vec<&'a str>,
    /// Each `--filelist` value: a list of names, read whole once.
    filelists: Vec<&'a str>,
    mode: ZstdMode,
}

/// zstdcli.c's long options that take a value with `=` or, without one,
/// from the next argument (`NEXT_FIELD`, `NEXT_UINT32`, `NEXT_TSIZE`),
/// matched as prefixes in cli.rs's order.
const ZSTD_LONG_WITH_VALUE: &[&str] = &[
    "--threads",
    "--memlimit",
    "--memory",
    "--block-size",
    "--maxdict",
    "--dictID",
    "--stream-size",
    "--target-compressed-block-size",
    "--size-hint",
    "--output-dir-flat",
    "--auto-threads",
    "--output-dir-mirror",
    "--patch-from",
    "--filelist",
];

/// The zstd family's arguments as zstdcli.c parses them (no permuting:
/// operands and options mix freely; `--` makes the rest operands). Only
/// what the read bound needs: which arguments name inputs, dictionaries
/// and lists, and the operation. A value taken from the next argument is
/// no operand. Parse errors stop the run before any file is read, so a
/// case that ends in one is classified however it falls.
fn zstd_parse<'a>(name: &str, args: &[&'a str]) -> ZstdArgs<'a> {
    let mut z = ZstdArgs {
        operands: Vec::new(),
        dicts: Vec::new(),
        filelists: Vec::new(),
        mode: match name {
            "unzstd" | "zstdcat" => ZstdMode::Decompress,
            _ => ZstdMode::Compress,
        },
    };
    let mut after_dashes = false;
    let mut i = 0;
    // The value of the option at `args[i]`: after its `=`, else the next
    // argument (consumed).
    let value = |i: &mut usize, rest: &'a str| -> Option<&'a str> {
        if let Some(v) = rest.strip_prefix('=') {
            Some(v)
        } else {
            *i += 1;
            args.get(*i).copied()
        }
    };
    while i < args.len() {
        let a = args[i];
        if after_dashes || !a.starts_with('-') {
            z.operands.push(a);
        } else if a == "-" {
        } else if a == "--" {
            after_dashes = true;
        } else if let Some(long) = a.strip_prefix("--") {
            match long {
                "list" => z.mode = ZstdMode::List,
                "compress" => z.mode = ZstdMode::Compress,
                "decompress" | "uncompress" => z.mode = ZstdMode::Decompress,
                "test" => z.mode = ZstdMode::Test,
                l if l.starts_with("train") => z.mode = ZstdMode::Train,
                _ => {
                    let found = ZSTD_LONG_WITH_VALUE
                        .iter()
                        .find_map(|p| a.strip_prefix(p).map(|rest| (*p, rest)));
                    if let Some((p, rest)) = found
                        && let Some(v) = value(&mut i, rest)
                    {
                        match p {
                            "--patch-from" => z.dicts.push(v),
                            "--filelist" => z.filelists.push(v),
                            _ => {}
                        }
                    }
                }
            }
        } else {
            let cluster = &a[1..];
            for (k, c) in cluster.char_indices() {
                match c {
                    'z' => z.mode = ZstdMode::Compress,
                    'd' => z.mode = ZstdMode::Decompress,
                    't' => z.mode = ZstdMode::Test,
                    'l' => z.mode = ZstdMode::List,
                    'o' | 'D' => {
                        // `-D=x` takes the rest; `-D x` the next argument,
                        // and the cluster goes on after `D`.
                        let rest = &cluster[k + 1..];
                        if let Some(v) = rest.strip_prefix('=') {
                            if c == 'D' {
                                z.dicts.push(v);
                            }
                            break;
                        }
                        if let Some(v) = value(&mut i, "")
                            && c == 'D'
                        {
                            z.dicts.push(v);
                        }
                    }
                    _ => {}
                }
            }
        }
        i += 1;
    }
    z
}

/// A superset of the names `UTIL_createFileNamesTable_fromFileName` reads
/// from a list: lines, each cut at its first NUL.
fn zstd_list_names(bytes: &[u8]) -> impl Iterator<Item = &str> {
    bytes
        .split(|b| *b == b'\n')
        .filter_map(|l| l.split(|b| *b == 0).next())
        .filter_map(|n| std::str::from_utf8(n).ok())
        .filter(|n| !n.is_empty())
}

/// The zstd family through `run_in_counted`.
fn run_zstd(dir: &Path, name: &str, args: &[&str], stdin: &[u8]) {
    let before = contents(dir);
    let z = zstd_parse(name, args);
    // `--filelist` names come from a case file, which holds the payload: a
    // name holding a `/` could leave the run's directory, and `.`/`..`
    // under `-r` reach files by paths no operand spells. Such a case is not
    // run. A list file that was not created names nothing.
    let mut listed: Vec<&str> = Vec::new();
    for f in &z.filelists {
        if let Some(bytes) = before.get(std::ffi::OsStr::new(f)) {
            listed.extend(zstd_list_names(bytes));
        }
    }
    if listed
        .iter()
        .any(|n| n.contains('/') || *n == "." || *n == "..")
    {
        return;
    }
    let os_args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let (code, out, err, reads) = compat::run_in_counted(
        dir,
        name,
        os_args,
        stdin,
        Flavour::Gnu,
        unzip::default_flavour(),
        compress::default_flavour(),
        zip::default_flavour(),
    )
    .expect("a COMPAT_NAMES entry is a compat name");
    let why = || String::from_utf8_lossy(&err).into_owned();
    if std::env::var_os("STUFFR_FUZZ_COMPAT_TRACE").is_some() {
        eprintln!("compat: {name} {args:?} ({:?}) -> {code}", z.mode);
        for (path, r) in &reads {
            eprintln!("compat:   {path:?} {r:?}");
        }
    }
    // zstd's exits only: 0, `main`'s 1 and 2, and `EXM_THROW`'s codes;
    // never stuffr's 3-7 outside that set's meaning, never a panic's.
    assert!(
        (0..=2).contains(&code) || ZSTD_EXM.contains(&code),
        "{name} {args:?}: exit {code} is not a zstd exit code\n{}",
        why()
    );
    let mut operands = z.operands.clone();
    operands.extend(&listed);
    check_zstd_reads(dir, name, args, &z, &operands, &reads);
    check_zstd_leftovers(dir, name, args, &listed);
    check_budget(dir, name, args, &out, &before);
}

/// The zstd family's read bound, for every path a run opened, with `len`
/// its largest length at an open: per operand that names it exactly (zstd
/// retries no suffix), at most two opens and
///
/// - compress, decompress and test: `2 × len` bytes;
/// - `-l`: `len` bytes (a header walk, never a re-read);
/// - `--train*`: `len` bytes (each sample is read once, at most whole);
///
/// plus, per `-D`/`--patch-from` value naming it, one open and `len` bytes
/// (the dictionary or prefix, read whole once per run), and per
/// `--filelist` value naming it, one open and `len` bytes (the list).
///
/// A path nothing names must not be opened at all.
///
/// Measured (0.14.0 Task 10) over the seeds on this crate's pure tier and,
/// for the paths the pure tier refuses, through `run_in_counted` on the C
/// tier: every mode opens an operand once. Compressing, decompressing
/// (every format, pass-through included) and testing read it once (`len`;
/// less when a frame fails early). `-l` reads the headers only: 25 bytes
/// of a 779-byte one-frame file, 68 of 1804 with a skippable frame and two
/// frames, 8 of a lone 8-byte skippable header. `--train*` reads each
/// sample once, at most whole (a file named three times: three opens,
/// `3 × len`). A dictionary is read once per run whatever the operand
/// count (`-D d.dict a a.gz a.xz`: one open), and a `--patch-from` prefix
/// once even when zstd then refuses it as also the input. The `2 ×` on
/// the coding modes leaves room for a re-read without letting a third
/// pass through; the dictionary and list allowances are exact.
fn check_zstd_reads(
    dir: &Path,
    name: &str,
    args: &[&str],
    z: &ZstdArgs<'_>,
    operands: &[&str],
    reads: &BTreeMap<PathBuf, compat::InputReads>,
) {
    for (path, r) in reads {
        let file = path
            .strip_prefix(dir)
            .ok()
            .and_then(|p| p.to_str())
            .unwrap_or_else(|| panic!("{name}: opened {path:?}, outside {dir:?}"));
        let count = |names: &[&str]| names.iter().filter(|n| **n == file).count() as u64;
        let m = count(operands);
        let once = count(&z.dicts) + count(&z.filelists);
        let per_operand = match z.mode {
            ZstdMode::List | ZstdMode::Train => r.len,
            _ => 2 * r.len,
        };
        assert!(
            r.opens <= 2 * m + once,
            "{name} {args:?} ({:?}): {} opens of {file:?}, which {m} operand(s) \
             and {once} dictionary/list value(s) name",
            z.mode,
            r.opens
        );
        assert!(
            r.bytes <= per_operand * m + r.len * once,
            "{name} {args:?} ({:?}): read {} bytes of the {}-byte {file:?}, \
             which {m} operand(s) and {once} dictionary/list value(s) name",
            z.mode,
            r.bytes,
            r.len
        );
    }
}

/// No `.stuffr-zstd-*` temporary survives a run, and every name in the
/// run's directory is one `could_be_written` allows, with the names a
/// `--filelist` gave as bases too. A listed name may differ from a table
/// name only by ASCII case on a case-folding filesystem (it opens the
/// table's file; the output is spelled as listed), as under xz.
fn check_zstd_leftovers(dir: &Path, name: &str, args: &[&str], listed: &[&str]) {
    let Ok(listing) = std::fs::read_dir(dir) else {
        return;
    };
    for e in listing.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        assert!(
            !n.starts_with(".stuffr-zstd-"),
            "{name} {args:?}: left its temporary {n:?}"
        );
        assert!(
            could_be_written_with(&n, false, listed)
                || (case_insensitive_fs() && could_be_written_with(&n, true, listed)),
            "{name} {args:?}: left a stray {n:?}"
        );
    }
}

/// Whether an lz4 run's operation is `--list`: the last token that sets a
/// mode is `--list`, judged conservatively (a later token that could be a
/// mode, `--decompress`/`--compress`/`--test` or a short cluster holding
/// `d`, `z` or `t`, makes it "not list", which only loosens the bound).
fn lz4_lists(args: &[&str]) -> bool {
    let Some(at) = args.iter().rposition(|a| *a == "--list") else {
        return false;
    };
    !args[at + 1..].iter().any(|a| {
        matches!(*a, "--decompress" | "--compress" | "--test")
            || (a.starts_with('-')
                && !a.starts_with("--")
                && a.bytes().any(|b| matches!(b, b'd' | b'z' | b't')))
    })
}

/// Whether an lz4 run takes several inputs (`-m`, `-r`, `--multiple`,
/// `--list`, `lz4cat`), and whether it decodes or tests (the last of `-d`,
/// `-t`, `-z`, `--list` and their long forms wins; `unlz4` and `lz4cat`
/// start as decoders), `--list` not counting as one. With none of them
/// given, the first input decides, as `compat::lz4::cli::op_for` does: a
/// name ending in `.lz4` decodes, standard input and any other name
/// compress (lz4.1: ".lz4 extension implies --decompress by default").
/// Missing that rule was the 0.17.0 fuzz smoke's `lz4 -m -1 a.lz4 a.lz4`
/// over a legacy frame with a tail: the first input's undecodable tail is
/// hidden at the `-m` level 1 and only the second's `a already exists; not
/// overwritten` shows, so lz4 1.10.0 exits 2 over one line (probed with
/// the case's files), a decode's bound and not a compress's equality.
fn lz4_shape(name: &str, args: &[&str]) -> (bool, bool) {
    let mut several = name == "lz4cat";
    let mut mode: Option<bool> = matches!(name, "unlz4" | "lz4cat").then_some(true);
    let mut first: Option<&str> = None;
    let mut ended = false;
    let mut it = args.iter();
    while let Some(&a) = it.next() {
        if ended {
            first.get_or_insert(a);
            continue;
        }
        match a {
            "--" => ended = true,
            "-D" => {
                it.next();
            }
            "-" => {
                first.get_or_insert(a);
            }
            "--multiple" => several = true,
            "--list" => {
                several = true;
                mode = Some(false);
            }
            "--decompress" | "--uncompress" | "--test" => mode = Some(true),
            "--compress" => mode = Some(false),
            _ if a.starts_with('-') && !a.starts_with("--") => {
                for ch in a[1..].chars() {
                    match ch {
                        'm' | 'r' => several = true,
                        'd' | 't' => mode = Some(true),
                        'z' => mode = Some(false),
                        _ => {}
                    }
                }
            }
            _ if !a.starts_with('-') => {
                first.get_or_insert(a);
            }
            _ => {}
        }
    }
    let decodes = mode.unwrap_or_else(|| first.is_some_and(|f| f.ends_with(".lz4")));
    (several, decodes)
}

/// lz4's display level for these arguments: 2 by default (1 for `lz4cat`),
/// `-v` and `--verbose` add one, `-q` and `--quiet` take one, `-D` takes the
/// next token whole, and `--` ends the options.
fn lz4_display_level(name: &str, args: &[&str]) -> i32 {
    let mut level = if name == "lz4cat" { 1 } else { 2 };
    let mut it = args.iter();
    while let Some(&a) = it.next() {
        match a {
            "--" => break,
            "-D" => {
                it.next();
            }
            "--verbose" => level += 1,
            "--quiet" => level -= 1,
            _ if a.starts_with('-') && !a.starts_with("--") => {
                level += a.bytes().filter(|b| *b == b'v').count() as i32;
                level -= a.bytes().filter(|b| *b == b'q').count() as i32;
            }
            _ => {}
        }
    }
    level
}

/// The arguments with just enough `-q` taken out to bring the display
/// level up to 1, where failure lines show. (Removing every `-q` would
/// raise it to 2 and make `a.lz4` already existing a question read from
/// standard input, a different run.)
fn lz4_unquieted(name: &str, args: &[&str]) -> Vec<String> {
    let mut drop = 1 - lz4_display_level(name, args);
    let mut out: Vec<String> = Vec::new();
    let mut it = args.iter();
    let mut ended = false;
    while let Some(&a) = it.next() {
        if ended {
            out.push(a.to_string());
        } else if a == "--" {
            ended = true;
            out.push(a.to_string());
        } else if a == "-D" {
            out.push(a.to_string());
            if let Some(&d) = it.next() {
                out.push(d.to_string());
            }
        } else if a == "--quiet" && drop > 0 {
            drop -= 1;
        } else if a.starts_with('-') && !a.starts_with("--") && a.len() > 1 {
            let mut kept = String::from("-");
            for ch in a[1..].chars() {
                if ch == 'q' && drop > 0 {
                    drop -= 1;
                } else {
                    kept.push(ch);
                }
            }
            if kept.len() > 1 {
                out.push(kept);
            }
        } else {
            out.push(a.to_string());
        }
    }
    out
}

/// Whether one stderr line, `\r`-refreshes already stripped, is lz4
/// reporting an input as failed. The forms (`messages.rs`; each is one
/// line per failing input under `-m`, `lz4cat` and `--list`):
///
/// - `Error N : ...` (every `E##_*`, `--list`'s `E71_READING` and
///   `E72_READING` among them);
/// - `NAME: STRERROR ` (`OPEN_INPUT_FAILED`), and the same without the
///   blank for `OPEN_OUTPUT_FAILED`;
/// - `lz4: NAME is a directory -- ignored` (`IS_A_DIRECTORY`);
/// - `lz4: NAME is not a regular file` (`LIST_NOT_REGULAR`) and
///   `lz4: NAME: File format not recognized` (`LIST_NOT_RECOGNIZED`;
///   `LIST_CORRUPTED_LEGACY` is a line of its own, `Corrupted legacy frame`,
///   but not a separate failure: `LIST_NOT_RECOGNIZED` follows it);
/// - `Stream followed by undecodable data [at position N]` (`UNDECODABLE`;
///   at display level 2, so after a `\r` refresh at `-v`; it is a failure
///   of the input, and lz4 itself prints it only at level 2);
/// - `File extension doesn't match ...; will not process file: NAME`
///   (`EXTENSION_MISMATCH`);
/// - `NAME already exists; not overwritten` (`ALREADY_EXISTS`), the same
///   after a declined prompt (`NAME already exists; do you want to
///   overwrite (y/N) ?     not overwritten`, one line, `OVERWRITE_PROMPT`
///   then `NOT_OVERWRITTEN`), and `NAME is the input file; not
///   overwritten (stuffr)` (`SAME_FILE`).
fn is_lz4_failure_line(l: &str) -> bool {
    const ERRNO_TEXTS: &[&str] = &[
        "No such file or directory",
        "Permission denied",
        "Is a directory",
        "Not a directory",
        "File name too long",
        "Too many levels of symbolic links",
        "File exists",
        "Read-only file system",
    ];
    let t = l.trim_end();
    t.strip_prefix("Error ")
        .is_some_and(|r| r.starts_with(|c: char| c.is_ascii_digit()))
        || ERRNO_TEXTS.iter().any(|e| t.ends_with(&format!(": {e}")))
        || (t.starts_with("lz4: ")
            && (t.ends_with(" is a directory -- ignored")
                || t.ends_with(" is not a regular file")
                || t.ends_with(": File format not recognized")))
        || t.contains("Stream followed by undecodable data")
        || t.contains("; will not process file: ")
        || t.ends_with("not overwritten")
        || t.ends_with(" is the input file; not overwritten (stuffr)")
}

/// The inputs an lz4 run reports as failed: one stderr line each, in the
/// forms [`is_lz4_failure_line`] lists (lz4 prints one per failing input
/// under `-m`, `lz4cat` and `--list`, and the count is its exit code).
fn lz4_failure_lines(stderr: &[u8]) -> u64 {
    let text = String::from_utf8_lossy(stderr);
    text.split('\n')
        .map(|l| l.rsplit('\r').next().unwrap_or(l))
        .filter(|l| is_lz4_failure_line(l))
        .count() as u64
}

/// The lz4 family (0.15.0), through `compat::run_in_counted` on this
/// crate's pure tier. Asserted:
///
/// - exit is 0, 1 or one of lz4's own (`lz4::EXIT_CODES`, the codes the
///   reference was probed to produce; shared with the differential suite,
///   which checks every recorded row against the same set), or, over
///   several inputs (`-m`, `-r`, `--list`, `lz4cat`), the count of inputs
///   that failed, at most the number of inputs named, and never fewer than
///   the failure lines on stderr (`lz4_failure_lines`), and equal to them.
///   A quiet run hides some lines: `-qq` all of them, and a decode or test
///   (`-d`, `-t`, `unlz4`, `lz4cat`, or a first input ending in `.lz4` with
///   no mode given; not `--list`) at a display level of 2 or below (`-m`,
///   `-r` and `lz4cat` bring the default 2 down to 1) hides `Stream followed
///   by undecodable data`. Such a run is repeated in a fresh directory, with
///   enough `-q` removed to show lines at all and `-v -v` added for a
///   decode, and the exit is held to that loud run's line count (0.17.1
///   Task 3; before it a hidden run only had to satisfy `failed <= code`,
///   so a stuffr 3 for 7 passed). At that level no failure line is still
///   hidden: the others all print at 1 (probed on lz4 1.10.0), and the
///   loud run's exit must equal the quiet one's. The re-run gets an empty
///   standard input unless the case reads it, since level 2 turns `a
///   already exists` into a question read from there;
/// - read bound per path, with `m` the operands (non-`-D` tokens) that name
///   it exactly (lz4 retries no suffix) and `len` its largest length at an
///   open: at most `2m + d` opens and `2 × len × m + len × d` bytes, where
///   `d` counts the `-D` values naming it (a dictionary is read whole
///   once); under `--list` as the operation, `len × m + len × d` bytes (a
///   header walk). A path nothing names is not opened. lz4 reads from
///   standard input and writes through the budget only, so there is no
///   other source of reads;
/// - no `.stuffr-lz4-*` survives, and every name left in the run's
///   directory is one `could_be_written` allows, with the non-flag tokens
///   as bases too: an operand after the input names the output file
///   (`lz4 a crc32` writes `crc32`);
/// - standard output plus every new or changed file stays within the 8 MiB
///   budget.
///
/// Measured (0.15.0 Task 8, `STUFFR_FUZZ_COMPAT_TRACE=1` over the seeds on
/// the pure tier): every mode opens an operand once and reads it once,
/// whole (`len`): compress (4000 of 4000), decompress, test, a concatenated
/// pair of frames (2214 of 2214), a legacy frame (21 of 21), `-m` over two
/// inputs (one open each), and `--list`, which walks the frames and reads
/// the file once (1107 of 1107, plain and `-v`). A dictionary opens once and
/// is read whole once, for compress and decompress alike. The `2 ×` leaves
/// room for a re-read without admitting a third pass; `--list` is held to
/// `len` because it is measured at exactly that.
fn run_lz4(dir: &Path, name: &str, args: &[&str], stdin: &[u8]) {
    let before = contents(dir);
    let os_args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let (code, out, err, reads) = compat::run_in_counted(
        dir,
        name,
        os_args,
        stdin,
        Flavour::Gnu,
        unzip::default_flavour(),
        compress::default_flavour(),
        zip::default_flavour(),
    )
    .expect("a COMPAT_NAMES entry is a compat name");
    let why = || String::from_utf8_lossy(&err).into_owned();
    if std::env::var_os("STUFFR_FUZZ_COMPAT_TRACE").is_some() {
        eprintln!("compat: {name} {args:?} -> {code}");
        for (path, r) in &reads {
            eprintln!("compat:   {path:?} {r:?}");
        }
    }
    // `-D` takes the next token whole (`-D -h` names `-h`).
    let mut dicts: Vec<&str> = Vec::new();
    let mut operands: Vec<&str> = Vec::new();
    let mut inputs = 0usize;
    let mut after_dashes = false;
    let mut it = args.iter();
    while let Some(&a) = it.next() {
        if after_dashes {
            // `--` ends the options: every later token is a name.
            operands.push(a);
            inputs += 1;
        } else if a == "--" {
            after_dashes = true;
        } else if a == "-D" {
            if let Some(&d) = it.next() {
                dicts.push(d);
            }
        } else if a == "-" {
            inputs += 1;
        } else if !a.starts_with('-') {
            operands.push(a);
            inputs += 1;
        }
    }
    // Over several inputs (`-m`, `-r`, `--list`, or `lz4cat`) the exit is
    // the number that failed, and each failure printed one line: `lz4cat -
    // a b c` over four missing names exits 4 (the differential suite's
    // `several_files_one_failing`). A stuffr 3-7 leaking out can no longer
    // pass as a count (0.15.0 Task 8's minor).
    let (several, decodes) = lz4_shape(name, args);
    let lz4_code = code == 0 || code == 1 || stuffr_cli::compat::lz4::EXIT_CODES.contains(&code);
    if several && !lz4_code {
        // lz4 drops its default level 2 to 1 under several inputs, and
        // prints `Stream followed by undecodable data` only at 2 or more.
        let hidden = decodes && lz4_display_level(name, args) <= 2;
        let failed = if hidden || lz4_display_level(name, args) < 1 {
            // The quiet run's stderr misses lines (`-qq` hides all of them,
            // and a quiet decode hides `Stream followed by undecodable
            // data`), so run the same case again, from the directory as it
            // was, loud enough to show them, and hold the exit to that
            // count. Only quiet runs pay for it.
            let again = dir.with_file_name("again");
            let _ = std::fs::remove_dir_all(&again);
            std::fs::create_dir(&again).expect("create the re-run directory");
            for (n, bytes) in &before {
                std::fs::write(again.join(n), bytes).expect("copy a case file");
            }
            let mut loud = lz4_unquieted(name, args);
            if hidden {
                // `-v -v` takes any several-input level (`-m`'s 1, `lz4cat`'s
                // 0: it hides the line at `-v` too) to 2, where the
                // undecodable line shows (probed on lz4 1.10.0: `-m -t
                // a.lz4 a.lz4` over two undecodable tails is silent and
                // exits 2; `-v` prints both lines, `lz4cat` needs `-vv`).
                // Nothing is hidden at 2: the other lines all print at 1.
                // A level above 2 only adds lines of other forms.
                loud.splice(0..0, ["-v".to_string(), "-v".to_string()]);
            }
            // A level of 2 turns `a already exists` into a question read
            // from standard input, and a `y` there would overwrite: a
            // different run than the quiet one, which only refuses. Give
            // the re-run an empty standard input (a declined question)
            // unless the case reads standard input as an input.
            let reads_stdin = inputs == 0 || args.contains(&"-");
            let loud_stdin: &[u8] = if hidden && !reads_stdin { b"" } else { stdin };
            let os_loud: Vec<OsString> = loud.iter().map(OsString::from).collect();
            let (code2, _, err2, _) = compat::run_in_counted(
                &again,
                name,
                os_loud,
                loud_stdin,
                Flavour::Gnu,
                unzip::default_flavour(),
                compress::default_flavour(),
                zip::default_flavour(),
            )
            .expect("a COMPAT_NAMES entry is a compat name");
            assert_eq!(
                code, code2,
                "{name} {args:?}: the loud re-run {loud:?} exits differently"
            );
            let _ = std::fs::remove_dir_all(&again);
            lz4_failure_lines(&err2)
        } else {
            lz4_failure_lines(&err)
        };
        let code = code as u64;
        assert!(
            failed == code,
            "{name} {args:?}: exit {code} but {failed} failure line(s)\n{}",
            why()
        );
        // Standard input stands for a missing operand.
        assert!(
            code <= inputs.max(1) as u64,
            "{name} {args:?}: exit {code} over {inputs} input(s)\n{}",
            why()
        );
    } else {
        assert!(
            lz4_code,
            "{name} {args:?}: exit {code} is not an lz4 exit code\n{}",
            why()
        );
    }
    let list = lz4_lists(args);
    for (path, r) in &reads {
        let file = path
            .strip_prefix(dir)
            .ok()
            .and_then(|p| p.to_str())
            .unwrap_or_else(|| panic!("{name}: opened {path:?}, outside {dir:?}"));
        let count = |names: &[&str]| names.iter().filter(|n| **n == file).count() as u64;
        let (m, d) = (count(&operands), count(&dicts));
        let per_operand = if list { r.len } else { 2 * r.len };
        assert!(
            r.opens <= 2 * m + d,
            "{name} {args:?}: {} opens of {file:?}, which {m} operand(s) and {d} \
             dictionary value(s) name",
            r.opens
        );
        assert!(
            r.bytes <= per_operand * m + r.len * d,
            "{name} {args:?} (list: {list}): read {} bytes of the {}-byte {file:?}, \
             which {m} operand(s) and {d} dictionary value(s) name",
            r.bytes,
            r.len
        );
    }
    // Operands after the input name the output, and `-m` appends `.lz4`
    // to each: every token is a base for a stray-name check.
    let bases: Vec<&str> = operands.iter().chain(&dicts).copied().collect();
    if let Ok(listing) = std::fs::read_dir(dir) {
        for e in listing.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            assert!(
                !n.starts_with(".stuffr-lz4-"),
                "{name} {args:?}: left its temporary {n:?}"
            );
            assert!(
                could_be_written_with(&n, false, &bases)
                    || (case_insensitive_fs() && could_be_written_with(&n, true, &bases)),
                "{name} {args:?}: left a stray {n:?}"
            );
        }
    }
    check_budget(dir, name, args, &out, &before);
}

/// The suffixes unzip and zipinfo retry an archive name with when it does
/// not open as given (`do_wild`: `name`, `name.zip`, `name.ZIP`).
const UNZIP_RETRIES: &[&str] = &["", ".zip", ".ZIP"];

/// `INBUFSIZ` (unzpriv.h): unzip reads its archive in blocks of this size,
/// each from a block boundary.
const UNZIP_INBUFSIZ: u64 = 8192;

/// The central-directory records `bytes` could hold: each `PK\1\2` in it
/// (unzip processes an entry only from a record that starts with one,
/// `process_cdir_file_hdr`; anything else is "expected central file header
/// signature not found"), and what reading each record's entry may cost:
/// its declared compressed size (the u32 at signature + 20, all ones for a
/// Zip64 entry), clamped to the file's `len`, plus its local header (30
/// bytes and the larger of the central record's and the local record's
/// name and extra lengths, the local one looked for at the record's offset
/// and at that offset plus the preamble the end record implies, where
/// unzip's `extra_bytes` puts it), plus `2 × INBUFSIZ` for the blocks either
/// side. A field cut off by the end of the file counts as `len`.
fn central_records(bytes: &[u8], len: u64) -> (u64, u64) {
    let le16 = |at: usize| -> Option<u64> {
        bytes
            .get(at..at + 2)
            .map(|b| u64::from(u16::from_le_bytes([b[0], b[1]])))
    };
    let le32 = |at: usize| -> Option<u64> {
        bytes
            .get(at..at + 4)
            .map(|b| u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
    };
    // The preamble the last end record implies (`extra_bytes`).
    let preamble = bytes
        .windows(4)
        .rposition(|w| w == b"PK\x05\x06")
        .and_then(|at| Some((at as u64).saturating_sub(le32(at + 16)? + le32(at + 12)?)))
        .unwrap_or(0);
    let local_names = |off: u64| -> u64 {
        usize::try_from(off)
            .ok()
            .and_then(|o| Some(le16(o.checked_add(26)?)? + le16(o.checked_add(28)?)?))
            .unwrap_or(0)
    };
    let (mut count, mut charge) = (0u64, 0u64);
    for (at, _) in bytes
        .windows(4)
        .enumerate()
        .filter(|(_, w)| *w == b"PK\x01\x02")
    {
        count += 1;
        let csize = le32(at + 20).unwrap_or(len).min(len);
        let central = match (le16(at + 28), le16(at + 30)) {
            (Some(n), Some(e)) => n + e,
            _ => len,
        };
        let local = le32(at + 42).map_or(len, |off| {
            local_names(off).max(local_names(off.saturating_add(preamble)))
        });
        charge += csize + 30 + central.max(local) + 2 * UNZIP_INBUFSIZ;
    }
    (count, charge)
}

/// Every name the central-directory records in `bytes` give (the name
/// length at signature + 28, the name at + 46, cut by the end of the file):
/// the names an extraction can create.
fn central_names(bytes: &[u8]) -> Vec<&[u8]> {
    bytes
        .windows(4)
        .enumerate()
        .filter(|(_, w)| *w == b"PK\x01\x02")
        .filter_map(|(at, _)| {
            let n = usize::from(u16::from_le_bytes([
                *bytes.get(at + 28)?,
                *bytes.get(at + 29)?,
            ]));
            let from = at + 46;
            bytes.get(from..(from + n).min(bytes.len()))
        })
        .collect()
}

/// Every regular file under `dir`, by path, with its contents.
fn tree_contents(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(d) = pending.pop() {
        let Ok(listing) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in listing.flatten() {
            let Ok(kind) = e.file_type() else { continue };
            if kind.is_dir() {
                pending.push(e.path());
            } else if kind.is_file()
                && let Ok(bytes) = std::fs::read(e.path())
            {
                out.insert(e.path(), bytes);
            }
        }
    }
    out
}

/// Gives every directory under `dir` its owner's read, write and search
/// bits back, and every file its owner's read bit: an archive may set a
/// directory to 0o000 (unzip applies directory modes at the end), which
/// the containment walk could not read and the end of the iteration could
/// not remove, and a file to 0o000, which the budget could not count.
/// Symlinks are not followed.
fn make_traversable(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let set = |p: &Path, bits: u32| {
        if let Ok(meta) = std::fs::symlink_metadata(p) {
            let mode = meta.permissions().mode() | bits;
            let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode));
        }
    };
    let mut pending = vec![dir.to_path_buf()];
    while let Some(d) = pending.pop() {
        set(&d, 0o700);
        let Ok(listing) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in listing.flatten() {
            match e.file_type() {
                Ok(k) if k.is_dir() => pending.push(e.path()),
                Ok(k) if k.is_file() => set(&e.path(), 0o400),
                _ => {}
            }
        }
    }
}

/// The symlinks under `dir` (unzip creates them with whatever text the
/// archive gives, as the references do).
fn symlinks_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(d) = pending.pop() {
        let Ok(listing) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in listing.flatten() {
            let Ok(kind) = e.file_type() else { continue };
            if kind.is_dir() {
                pending.push(e.path());
            } else if kind.is_symlink() {
                out.push(e.path());
            }
        }
    }
    out
}

/// Every top-level name in the real working directory before the first
/// run (taken at the top of every iteration, so before any run), for
/// `check_unzip_cwd`.
fn cwd_names_before() -> &'static std::collections::BTreeSet<OsString> {
    static NAMES: OnceLock<std::collections::BTreeSet<OsString>> = OnceLock::new();
    NAMES.get_or_init(|| {
        let cwd = &cwd_before().0;
        std::fs::read_dir(cwd)
            .map(|l| l.flatten().map(|e| e.file_name()).collect())
            .unwrap_or_default()
    })
}

/// unzip writes names the archive chooses, which `could_be_written` (the
/// real working directory's snapshot filter) does not know: no name the
/// run created at the top of its directory may also have appeared in the
/// real working directory since the first run.
fn check_unzip_cwd(dir: &Path, name: &str, args: &[&str]) {
    let before = cwd_names_before();
    let cwd = &cwd_before().0;
    let Ok(listing) = std::fs::read_dir(dir) else {
        return;
    };
    for e in listing.flatten() {
        let n = e.file_name();
        assert!(
            before.contains(&n) || cwd.join(&n).symlink_metadata().is_err(),
            "{name} {args:?}: {n:?} appeared in the real working directory {cwd:?}"
        );
    }
}

/// The unzip family (0.16.0) through `compat::run_in_counted`, as the
/// flavour the name byte gives (R7: 0 Ubuntu, 1 Apple, the same side as
/// gzip's GNU and BSD). Asserted:
///
/// - the exit is one the flavour's reference gives
///   (`unzip::EXIT_CODES_APPLE`, `unzip::EXIT_CODES_UBUNTU`: 12, `PK_BOMB`,
///   is Ubuntu's alone); stuffr's own 3-7 never appear with their meanings,
///   and a panic is a crash;
/// - the read bound (`check_unzip_reads`);
/// - standard output plus every new or changed file anywhere under the
///   run's directory stays within the 8 MiB budget (an extracted tree is
///   deeper than the other families' outputs);
/// - containment (in `fuzz_target!`, after `make_traversable`), with the
///   symlinks unzip extracted exempt from the "resolves inside" rules: the
///   references create a link with whatever text the archive holds, and
///   writing THROUGH one is what `compat::unzip`'s resolve-beneath walk
///   refuses (both flavours; deviation 3). What the exemption could hide,
///   a write through such a link, is checked instead, by ctime
///   (`check_unzip_links`);
/// - no name the run created appeared in the real working directory
///   (`check_unzip_cwd`).
fn run_unzip(dir: &Path, name: &str, flavour: u8, args: &[&str], stdin: &[u8]) {
    let flavour = if flavour == 0 {
        unzip::Flavour::Ubuntu
    } else {
        unzip::Flavour::Apple
    };
    let before = tree_contents(dir);
    let floor = ctime_floor(dir);
    let os_args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let (code, out, err, reads) = compat::run_in_counted(
        dir,
        name,
        os_args,
        stdin,
        Flavour::Gnu,
        flavour,
        compress::default_flavour(),
        zip::default_flavour(),
    )
    .expect("a COMPAT_NAMES entry is a compat name");
    let why = || String::from_utf8_lossy(&err).into_owned();
    if std::env::var_os("STUFFR_FUZZ_COMPAT_TRACE").is_some() {
        eprintln!("compat: {name} {flavour:?} {args:?} -> {code}");
        for (path, r) in &reads {
            eprintln!("compat:   {path:?} {r:?}");
        }
    }
    let codes = match flavour {
        unzip::Flavour::Apple => unzip::EXIT_CODES_APPLE,
        unzip::Flavour::Ubuntu => unzip::EXIT_CODES_UBUNTU,
    };
    assert!(
        codes.contains(&code),
        "{name} ({flavour:?}) {args:?}: exit {code} is not one the reference gives\n{}",
        why()
    );
    check_unzip_reads(dir, name, flavour, args, &before, &reads);
    make_traversable(dir);
    let written: u64 = tree_contents(dir)
        .into_iter()
        .filter(|(p, bytes)| before.get(p) != Some(bytes))
        .map(|(_, bytes)| bytes.len() as u64)
        .sum();
    assert!(
        out.len() as u64 + written <= OUTPUT_BUDGET,
        "{name} ({flavour:?}) {args:?}: {} bytes to stdout and {written} to files, past the \
         {OUTPUT_BUDGET}-byte budget",
        out.len()
    );
    check_unzip_links(dir, name, flavour, args, &before, floor);
    check_unzip_cwd(dir, name, args);
}

/// The ctime floor of a run: the ctime of a stamp file created (and
/// removed) in the sandbox parent just before it. A ctime from the
/// filesystem's own clock, not `SystemTime::now()`: Linux stamps ctime from
/// the coarse clock (`current_time`), so a write within one tick of a
/// fine-grained `now()` reads as before it (1,995 of 2,000 writes on
/// overlayfs, 1,989 on tmpfs, measured in Docker; 0 on APFS). Compared with
/// `>=`, a write in the stamp's own tick still counts. `i128::MIN` (judge
/// everything) if the stamp cannot be made.
fn ctime_floor(dir: &Path) -> i128 {
    let stamp = dir.with_file_name(".ctime-stamp");
    let floor = std::fs::write(&stamp, b"")
        .and_then(|()| std::fs::symlink_metadata(&stamp))
        .map_or(i128::MIN, |m| ctime_ns(&m));
    let _ = std::fs::remove_file(&stamp);
    floor
}

/// When a path was last changed, as nanoseconds since the epoch: its
/// `ctime`, which no `utimes` can set back (stuffr's unzip restores each
/// entry's archive mtime after writing, so an mtime says nothing) and which
/// setting times itself moves on.
fn ctime_ns(meta: &std::fs::Metadata) -> i128 {
    use std::os::unix::fs::MetadataExt;
    i128::from(meta.ctime()) * 1_000_000_000 + i128::from(meta.ctime_nsec())
}

/// Nothing was written through a symlink the run extracted. A link whose
/// target resolves (`canonicalize`) inside the run's directory is the
/// containment walk's business and skipped; a dangling one names nothing
/// that exists. For one resolving outside:
///
/// - to a non-directory: that file's ctime is from before the run;
/// - to a directory: every path an archive name places under the link
///   (each central-directory name of every case file, cut after a
///   component equal to the link's own name, the rest joined onto the
///   target, component by component) is absent or has a ctime from before
///   the run. The directory's own ctime is not judged: the system's
///   temporary directory above the sandbox changes under other processes.
///
/// "Before the run" is `ctime_floor`'s stamp, from the filesystem's clock.
///
/// A write through a link to an existing outside file or directory is the
/// escape the resolve-beneath walk (`compat::unzip`'s `unix/beneath.rs`,
/// both flavours, deviation 3) refuses; the containment walk, which sees
/// only the sandbox parent, cannot see it.
fn check_unzip_links(
    dir: &Path,
    name: &str,
    flavour: unzip::Flavour,
    args: &[&str],
    before: &BTreeMap<PathBuf, Vec<u8>>,
    floor: i128,
) {
    let links = symlinks_under(dir);
    if links.is_empty() {
        return;
    }
    let Ok(real_dir) = std::fs::canonicalize(dir) else {
        return;
    };
    let names: Vec<&[u8]> = before.values().flat_map(|b| central_names(b)).collect();
    // Only regular files and directories: a device's ctime (`/dev/tty`,
    // `/dev/fd/N`) moves with use, not with a write through the link. And
    // never the run's directory, its ancestors or anything inside it (`m ->
    // ..` with a name `m/run` builds the run's directory itself), which
    // the run changes by right and the containment walk judges.
    let changed = |p: &Path| {
        !(real_dir.starts_with(p) || p.starts_with(&real_dir))
            && std::fs::symlink_metadata(p)
                .is_ok_and(|m| (m.is_file() || m.is_dir()) && ctime_ns(&m) >= floor)
    };
    for link in links {
        let Ok(target) = std::fs::canonicalize(&link) else {
            continue;
        };
        if target.starts_with(&real_dir) {
            continue;
        }
        let fail = |p: &Path| {
            panic!(
                "{name} ({flavour:?}) {args:?}: {p:?}, outside the run's directory through \
                 the extracted link {link:?}, changed during the run"
            )
        };
        if !target.is_dir() {
            if changed(&target) {
                fail(&target);
            }
            continue;
        }
        let Some(own) = link.file_name().map(|n| n.as_encoded_bytes().to_vec()) else {
            continue;
        };
        for n in &names {
            let comps: Vec<&[u8]> = n.split(|b| *b == b'/' || *b == b'\\').collect();
            for (i, c) in comps.iter().enumerate() {
                if *c != own.as_slice() {
                    continue;
                }
                let mut p = target.clone();
                for rest in &comps[i + 1..] {
                    if rest.is_empty() || *rest == b"." || *rest == b".." {
                        break;
                    }
                    p.push(os_path(rest));
                    if changed(&p) {
                        fail(&p);
                    }
                }
            }
        }
    }
}

/// The unzip family's read bound, for every path a run opened: the path's
/// file name is a token plus one of `UNZIP_RETRIES` (`m` such tokens; a
/// path no token names must not be opened at all), and then
///
/// - at most `3 × m` opens (measured: one per archive the run processes;
///   unzip and zipinfo open a name, then its `.zip`/`.ZIP` retry, only when
///   it fails to open, which a sandbox's file never does twice);
/// - at most `(4 × (len + 2 × INBUFSIZ) + records) × m` bytes, where `len`
///   is the file's largest length at an open and `records` is what
///   `central_records` charges the file's contents: each `PK\1\2` record
///   its own declared compressed size (clamped to `len`), its local header
///   and two blocks. The four passes are the end-record search, the Zip64
///   locator and directory, the central directory, and its re-read after a
///   "missing bytes" correction. **Not linear, and no linear bound
///   applies:** Apple's build reads an entry's data once for every central
///   record naming it (it has no overlap check; Ubuntu's patch 23 refuses
///   the second, exit 12), and data that decodes to nothing (deflate's
///   empty stored blocks) costs no output budget, so one 60 KiB entry named
///   by a thousand records reads 60 MB, as Apple's `unzip -t` itself does.
///   But a record is charged only what its entry declares, so a run that
///   re-read the directory or the archive once per entry would not fit; at
///   fuzz scale the block slack hides that for a small archive, which
///   `compat::unzip::process::tests::a_one_block_archive_is_read_in_passes_not_per_entry`
///   pins instead (50 entries in one block: at most `4 × len`). funzip
///   reads its operand once, a stream from start to stop.
///
/// Measured over the seeds (0.16.0 Task 15, `STUFFR_FUZZ_COMPAT_TRACE=1`,
/// both flavours): every run opens its archive once. An archive inside one
/// block is read whole once per pass: the end-record search, the central
/// directory, then each local header's block (entries in one block share
/// it): 3 passes for `-t`, `-p`, extraction and `-l`/`-v`/zipinfo
/// alike (`test-stored` 9,344 of 3,108 bytes, `test-implode` 7,259 of
/// 2,413, `extract-deflate` 1,994 of 658; zipinfo and `-l` 1,336 of 658,
/// 2 passes, no entry data). Ubuntu's overlapped refusal stops at 512 of
/// 246. funzip reads its file operand once (658 of 658).
fn check_unzip_reads(
    dir: &Path,
    name: &str,
    flavour: unzip::Flavour,
    args: &[&str],
    before: &BTreeMap<PathBuf, Vec<u8>>,
    reads: &BTreeMap<PathBuf, compat::InputReads>,
) {
    for (path, r) in reads {
        let file = path
            .strip_prefix(dir)
            .ok()
            .and_then(|p| p.to_str())
            .unwrap_or_else(|| panic!("{name} ({flavour:?}): opened {path:?}, outside {dir:?}"));
        let m = args
            .iter()
            .filter(|t| {
                UNZIP_RETRIES.iter().any(|s| {
                    file == format!("{t}{s}") || file.eq_ignore_ascii_case(&format!("{t}{s}"))
                })
            })
            .count() as u64;
        assert!(
            r.opens <= 3 * m,
            "{name} ({flavour:?}) {args:?}: {} opens of {file:?}, which {m} token(s) name",
            r.opens
        );
        // The contents the run opened: the case file under that name (a
        // case-folding filesystem opens `a.zip` for `a.ZIP`).
        let contents = before.get(path).or_else(|| {
            before
                .iter()
                .find(|(p, _)| {
                    p.to_string_lossy()
                        .eq_ignore_ascii_case(&path.to_string_lossy())
                })
                .map(|(_, b)| b)
        });
        let (count, records) = contents.map_or((0, 0), |b| central_records(b, r.len));
        let passes = 4 * (r.len + 2 * UNZIP_INBUFSIZ);
        assert!(
            r.bytes <= (passes + records) * m,
            "{name} ({flavour:?}) {args:?}: read {} bytes of the {}-byte {file:?} \
             ({count} central records charged {records}), which {m} token(s) name",
            r.bytes,
            r.len
        );
    }
}

/// The compress family's exit codes: Apple's `compress.c` exits only with
/// 0, 1 (`exit_val`, every warning) and 2 (`no saving`); ncompress adds 4,
/// `compressed with N bits, can only handle 16 bits`. Stuffr's own 3-7
/// must never appear.
const COMPRESS_EXIT_APPLE: &[i32] = &[0, 1, 2];
const COMPRESS_EXIT_NCOMPRESS: &[i32] = &[0, 1, 2, 4];

/// What one compress-family command line does, as the personality's own
/// option loop settles it (`apple/args.rs`, `ncompress/args.rs`): Apple's
/// getopt `b:cdfv` (no permutation, the first non-option ends the options,
/// `-` is standard input), ncompress's walk (flags anywhere, `--` ends
/// them, `-` is nothing, `-b` takes the next token).
#[derive(Debug, Default)]
struct CompressShape<'a> {
    /// The operands, `-` (Apple's standard input) included.
    operands: Vec<&'a str>,
    /// `uncompress`, or `-d`.
    decompress: bool,
    /// `-c`.
    cat: bool,
    /// `-r` or `-R` (ncompress only).
    recursive: bool,
    /// The run ends in the option loop (`-V`, `-h`, an unknown flag, `-b`
    /// without a value, Apple's bad `-b` text): no operand is processed.
    ends_in_options: bool,
    /// Standard input is read: no operand, or Apple's `-`.
    stdin: bool,
}

fn compress_shape<'a>(
    flavour: compress::Flavour,
    name: &str,
    args: &[&'a str],
) -> CompressShape<'a> {
    let mut s = CompressShape {
        decompress: name == "uncompress",
        ..CompressShape::default()
    };
    match flavour {
        compress::Flavour::Apple => {
            let mut i = 0;
            'options: while let Some(&a) = args.get(i) {
                if !a.starts_with('-') || a == "-" {
                    break;
                }
                i += 1;
                if a == "--" {
                    break;
                }
                for (k, c) in a.char_indices().skip(1) {
                    match c {
                        'b' => {
                            if k + 1 == a.len() {
                                if i >= args.len() {
                                    s.ends_in_options = true;
                                    break 'options;
                                }
                                i += 1;
                            }
                            continue 'options;
                        }
                        'c' => s.cat = true,
                        'd' => s.decompress = true,
                        'f' | 'v' => {}
                        _ => {
                            s.ends_in_options = true;
                            break 'options;
                        }
                    }
                }
            }
            if !s.ends_in_options {
                s.operands = args[i.min(args.len())..].to_vec();
                s.stdin = s.operands.is_empty() || s.operands.contains(&"-");
                s.cat |= s.operands.contains(&"-");
            }
        }
        compress::Flavour::Ncompress => {
            let mut dashes = false;
            let mut i = 0;
            'walk: while let Some(&a) = args.get(i) {
                if a == "--" {
                    dashes = true;
                } else if !dashes && a.starts_with('-') {
                    for (k, c) in a.char_indices().skip(1) {
                        match c {
                            'b' => {
                                if k + 1 == a.len() {
                                    if i + 1 >= args.len() {
                                        s.ends_in_options = true;
                                        break 'walk;
                                    }
                                    i += 1;
                                }
                                break;
                            }
                            'd' => s.decompress = true,
                            'c' => s.cat = true,
                            'r' | 'R' => s.recursive = true,
                            's' | 'q' | 'v' | 'k' | 'f' | 'F' | 'n' => {}
                            _ => {
                                s.ends_in_options = true;
                                break 'walk;
                            }
                        }
                    }
                } else {
                    s.operands.push(a);
                }
                i += 1;
            }
            if s.ends_in_options {
                s.operands.clear();
            } else {
                s.stdin = s.operands.is_empty();
            }
        }
    }
    s
}

/// What `payload` decompresses to under `flavour`'s decoder: standard
/// input to standard output, no file touched. `None` when the run fails.
fn compress_decode(dir: &Path, flavour: compress::Flavour, payload: &[u8]) -> Option<Vec<u8>> {
    let (code, out, _err, _) = compat::run_in_counted(
        dir,
        "uncompress",
        Vec::new(),
        payload,
        Flavour::Gnu,
        unzip::default_flavour(),
        flavour,
        zip::default_flavour(),
    )
    .expect("uncompress is a compat name");
    (code == 0).then_some(out)
}

/// `stream` is a `.Z` stream of exactly `plain`: both personalities'
/// decoders read it back to it (every valid stream is read by both, ruling
/// E1), whichever one wrote it.
fn check_compress_stream(
    dir: &Path,
    what: &str,
    name: &str,
    args: &[&str],
    stream: &[u8],
    plain: &[u8],
) {
    for decoder in [compress::Flavour::Apple, compress::Flavour::Ncompress] {
        let back = compress_decode(dir, decoder, stream);
        assert!(
            back.as_deref() == Some(plain),
            "{name} {args:?}: {what} is not a stream of the input: the {decoder:?} decoder \
             reads {:?} bytes back, the input has {}",
            back.as_ref().map(Vec::len),
            plain.len()
        );
    }
}

/// The compress family's oracle (0.18.0), after one run:
///
/// - the exit code is the personality's (`COMPRESS_EXIT_*`);
/// - reads: per operand, a path the run opened is one the operand can name
///   (the operand, or with `.Z` added when decompressing), opened at most
///   once and read at most `len` bytes (`check_compress_reads`);
/// - no `.stuffr-compress-*` temporary survives and no name outside
///   `could_be_written` appears;
/// - a failure (exit 1, 2 or 4) of a run with one file operand and no
///   standard input leaves no new or changed file: Apple unlinks its
///   output on every failure but a signal (which `Host::Sandbox` cannot
///   deliver), and ncompress removes it as well (ruling E3 is the signals
///   only), so a partial `.Z` or a half-decoded file is a defect;
/// - a success (exit 0) of such a run, without `-c`, changed something:
///   an output was written or the input consumed. Exempt: a run that ends
///   in the options, and ncompress's `.Z` operand when compressing (`already
///   has .Z suffix -- no change`, exit untouched) and `-r` (names skipped
///   silently);
/// - every exit 1 or 4 has a stderr line, bar ncompress's silent refusal of
///   a name without `.Z` when decompressing;
/// - the input is never lost (spec anti-goal; A2, A4 and N4 are where a
///   reference does lose it): each operand file the run removed is matched
///   by one new or changed file holding its data: a compressed output both
///   decoders read back to the input, or, decompressing, the decoded
///   bytes. The same holds for every compressed output of a compressing
///   run, kept or not, and for standard output when one source feeds it;
/// - standard output plus every new or changed file stays within the 8 MiB
///   budget (`check_budget`).
///
/// Not detected: a partial output in a run with several operands or with
/// standard input (which operand failed is not known from outside).
///
/// Limits: the sandbox cannot send signals, so ruling E3's per-personality
/// partial-output rules (Apple leaves it, ncompress removes it on INT, TERM
/// and HUP) rest on the differential suites of Tasks 2 and 3. The decode
/// round-trip is a self-consistency check (stuffr's decoders read stuffr's
/// streams); that the bytes are the reference's rests on those suites too.
#[allow(clippy::too_many_arguments)]
fn run_compress(dir: &Path, name: &str, flavour: u8, args: &[&str], stdin: &[u8], payload: &[u8]) {
    let flavour = if flavour == 0 {
        compress::Flavour::Ncompress
    } else {
        compress::Flavour::Apple
    };
    let before = contents(dir);
    let os_args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let (code, out, err, reads) = compat::run_in_counted(
        dir,
        name,
        os_args,
        stdin,
        Flavour::Gnu,
        unzip::default_flavour(),
        flavour,
        zip::default_flavour(),
    )
    .expect("a COMPAT_NAMES entry is a compat name");
    let why = String::from_utf8_lossy(&err).into_owned();
    if std::env::var_os("STUFFR_FUZZ_COMPAT_TRACE").is_some() {
        eprintln!("compat: {name} ({flavour:?}) {args:?} -> {code}: {why}");
        for (path, r) in &reads {
            eprintln!("compat:   {path:?} {r:?}");
        }
    }
    let ctx = format!("{name} ({flavour:?}) {args:?}");
    let exits = match flavour {
        compress::Flavour::Apple => COMPRESS_EXIT_APPLE,
        compress::Flavour::Ncompress => COMPRESS_EXIT_NCOMPRESS,
    };
    assert!(
        exits.contains(&code),
        "{ctx}: exit {code} is not a {flavour:?} compress exit code\n{why}"
    );
    let shape = compress_shape(flavour, name, args);
    check_compress_reads(dir, &ctx, &shape, &reads);
    check_compress_leftovers(dir, &ctx);
    check_budget(dir, name, args, &out, &before);

    let after = contents(dir);
    let fresh = |n: &OsString, bytes: &Vec<u8>| before.get(n) != Some(bytes);
    let one_file = shape.operands.len() == 1 && !shape.stdin && !shape.ends_in_options;
    if one_file && code != 0 {
        for (n, bytes) in &after {
            assert!(
                !fresh(n, bytes),
                "{ctx}: failed (exit {code}) and left {n:?} ({} bytes) new or changed\n{why}",
                bytes.len()
            );
        }
    }
    if one_file && code == 0 && !shape.cat {
        let skipped = flavour == compress::Flavour::Ncompress
            && (shape.recursive || (!shape.decompress && shape.operands[0].ends_with(".Z")));
        assert!(
            skipped || after != before,
            "{ctx}: exit 0 and nothing written, nothing removed\n{why}"
        );
    }
    if matches!(code, 1 | 4) {
        // ncompress refuses a regular file without `.Z` silently when
        // decompressing (`-v` says why); a corrupt input is never silent.
        let silent_ok = flavour == compress::Flavour::Ncompress
            && shape.decompress
            && shape
                .operands
                .iter()
                .any(|o| *o != "-" && !o.ends_with(".Z"));
        assert!(
            !err.is_empty() || silent_ok,
            "{ctx}: failed (exit {code}) with no stderr line"
        );
    }

    // The input is never lost.
    let mut removed: Vec<&OsString> = Vec::new();
    for o in shape.operands.iter().filter(|o| **o != "-") {
        let with_z = format!("{o}.Z");
        let candidates = [
            Some(*o),
            (shape.decompress && !o.ends_with(".Z")).then_some(&*with_z),
        ];
        for c in candidates.into_iter().flatten() {
            let key = OsString::from(c);
            if let Some((k, _)) = before.get_key_value(&key)
                && !after.contains_key(k)
                && !removed.contains(&k)
            {
                removed.push(k);
            }
        }
    }
    if !removed.is_empty() {
        let kept = if shape.decompress {
            // The decoded bytes, in a new or changed file.
            let decoded = compress_decode(dir, flavour, payload);
            after
                .iter()
                .filter(|(n, b)| fresh(n, b) && decoded.as_ref() == Some(*b))
                .count()
        } else {
            after
                .iter()
                .filter(|(n, b)| {
                    fresh(n, b)
                        && [compress::Flavour::Apple, compress::Flavour::Ncompress]
                            .iter()
                            .all(|d| compress_decode(dir, *d, b).as_deref() == Some(payload))
                })
                .count()
        };
        assert!(
            kept >= removed.len(),
            "{ctx}: removed {removed:?} but only {kept} new or changed file(s) hold the data\n{why}"
        );
    }
    if !shape.decompress && !shape.ends_in_options {
        // Every file a compressing run wrote is a stream of its input.
        for (n, bytes) in after.iter().filter(|(n, b)| fresh(n, b)) {
            check_compress_stream(dir, &format!("{n:?}"), name, args, bytes, payload);
        }
        // Standard output, when one source feeds it and the run finished.
        if (shape.cat || shape.stdin)
            && shape.operands.len() + usize::from(shape.operands.is_empty()) == 1
            && matches!(code, 0 | 2)
            && !out.is_empty()
        {
            let source = if shape.stdin { stdin } else { payload };
            check_compress_stream(dir, "standard output", name, args, &out, source);
        }
    }
}

/// The compress family's read bound: every path a run opened is one an
/// operand can name (the operand itself, or, when decompressing, the
/// operand plus `.Z`), at most one open and `len` bytes per
/// operand that can name it (`len` the largest length the file had when
/// opened): both personalities read an input once, straight through. Measured
/// over the seeds and a long run of the target (the report of 0.18.0 Task 4
/// has the figures); a looser bound would let a second pass over the input
/// go unseen.
fn check_compress_reads(
    dir: &Path,
    ctx: &str,
    shape: &CompressShape,
    reads: &BTreeMap<PathBuf, compat::InputReads>,
) {
    for (path, r) in reads {
        let file = path
            .strip_prefix(dir)
            .ok()
            .and_then(|p| p.to_str())
            .unwrap_or_else(|| panic!("{ctx}: opened {path:?}, outside {dir:?}"));
        let operands = shape
            .operands
            .iter()
            .filter(|o| {
                **o != "-" && (file == **o || (shape.decompress && file == format!("{}.Z", **o)))
            })
            .count() as u64;
        assert!(
            r.opens <= operands,
            "{ctx}: {} opens of {file:?}, which {operands} operand(s) can name",
            r.opens
        );
        assert!(
            r.bytes <= r.len * operands,
            "{ctx}: read {} bytes of the {}-byte {file:?}, which {operands} operand(s) can name",
            r.bytes,
            r.len
        );
    }
}

/// No `.stuffr-compress-*` temporary (Apple's A2 output) survives a run, and
/// every name in the run's directory is one `could_be_written` allows.
fn check_compress_leftovers(dir: &Path, ctx: &str) {
    let Ok(listing) = std::fs::read_dir(dir) else {
        return;
    };
    for e in listing.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        assert!(
            !n.starts_with(".stuffr-compress-"),
            "{ctx}: left its temporary {n:?}"
        );
        assert!(
            could_be_written(&n)
                || (case_insensitive_fs() && !n.contains('/') && could_be_written_folded(&n)),
            "{ctx}: left a stray {n:?}"
        );
    }
}

/// Tokens that make a zip-family run read names from the case's payload:
/// `-@` (names from standard input) and any `@file` pattern (`-i @a`, `-x
/// @a`, `-R @a`): the payload is every created file and standard input, so
/// the lines of `a` are names. The library's sandbox keeps whatever they
/// spell inside the run's directory (`Host::path`: a root is dropped, `..`
/// is an ordinary name nothing has), and the read bound counts them.
fn zip_names_from_payload(args: &[&str]) -> bool {
    args.iter().any(|t| *t == "-@" || t.starts_with('@'))
}

/// The lines of `payload` as names, as `getnam` splits them (LF or CR).
fn zip_payload_names(payload: &[u8]) -> Vec<&[u8]> {
    payload
        .split(|b| *b == b'\n' || *b == b'\r')
        .filter(|l| !l.is_empty())
        .collect()
}

/// `-FF`'s read allowance beyond twice the archive: Task 8's bound (a
/// descriptor's 24 bytes at a fake signature, doubling search pieces up to
/// the C's 16 KiB, the stream's buffer kept over a seek within it), measured
/// at `2 × len + 1 MiB` at most and enforced by the sandbox, which charges
/// every byte `-FF` reads to the 8 MiB budget.
const ZIP_FF_SLACK: u64 = 1024 * 1024;

/// One `PK\1\2` per entry: the most entries a zipsplit run can place in
/// parts, so the most files it can create (`ZIP_PARTS_SLACK` more: the index
/// and a part for the archive's own end).
fn zip_central_count(payload: &[u8]) -> u64 {
    payload.windows(4).filter(|w| *w == b"PK\x01\x02").count() as u64
}
const ZIP_PARTS_SLACK: u64 = 3;

/// Whether a name the run created is one the zip family may make: a token
/// (`-O a`, `-b`), a token with the `.zip` zip appends to an archive name
/// without an extension, a log (`-lf a` makes `a.log`), zipsplit's index
/// and its parts (`<stem><n>.zip`, the stem a prefix of an archive token's).
fn zip_name_ok(name: &str, tokens: &[&str]) -> bool {
    if tokens
        .iter()
        .any(|t| name == *t || name == format!("{t}.zip") || name == format!("{t}.log"))
    {
        return true;
    }
    if name == "zipsplit.idx" {
        return true;
    }
    if let Some(stem) = name.strip_suffix(".zip") {
        let prefix = stem.trim_end_matches(|c: char| c.is_ascii_digit());
        return !prefix.is_empty()
            && tokens
                .iter()
                .any(|t| t.strip_suffix(".zip").unwrap_or(t).starts_with(prefix));
    }
    false
}

/// A zip temporary: `zi` and six letters or digits (`mkstemp`'s template).
fn is_zip_temp(name: &str) -> bool {
    name.len() == 8
        && name.starts_with("zi")
        && name[2..].bytes().all(|b| b.is_ascii_alphanumeric())
}

/// How many times `sig` occurs in `b` (overlaps counted, as a scan sees
/// them).
fn signature_count(b: &[u8], sig: &[u8; 4]) -> usize {
    b.windows(4).filter(|w| *w == sig).count()
}

/// The mode tokens that make a run copy entries from an archive it did not
/// make (so a damaged input's damage can reach the output): the archive is
/// then read back only if every input archive was whole.
fn zip_looks_like_archive(b: &[u8]) -> bool {
    b.starts_with(b"PK\x03\x04") || b.starts_with(b"PK\x05\x06")
}

/// The zip family's read bound, for every path a run opened. A path is
/// named by `m` operands: tokens equal to it or to it without the `.zip`
/// zip appends, plus, when the run reads names from the payload (`-@`,
/// `@file`), the payload's lines, plus one per `.` token (`-r .` visits
/// every file of the directory). A path nobody names must not be opened.
///
/// Per path, `opens ≤ 4 × m + 2 × records` and `bytes ≤ m × 3 × len + 8 KiB
/// × opens` (`len` the largest length at an open; the figures are what the
/// seeds measured, see `ZIP_READ_*`). `records` counts the central and local
/// header signatures in the file as it was before the run: zipfile.c's
/// `zipcopy` and `readlocal` reopen the archive whenever an entry starts on
/// another disk than the one open ("don't assume reading the right disk"),
/// so records whose disk numbers alternate cost an open each, in each of
/// the two (0.23.0 deep fuzz: `-F a.zip -O b.zip` opened it five times, two
/// of them `zipcopy`'s reopens; the same five since 0.19.0). `-FF` is held to `m × (2 × len + 1 MiB)`
/// and no more: its descriptor search is bounded (Task 8) and charged to
/// the sandbox budget.
fn check_zip_reads(
    dir: &Path,
    name: &str,
    flavour: &str,
    args: &[&str],
    payload: &[u8],
    reads: &BTreeMap<PathBuf, compat::InputReads>,
    before: &BTreeMap<PathBuf, Vec<u8>>,
) {
    let from_payload = zip_names_from_payload(args);
    // The names the payload supplies, as the sandbox resolves them (a root
    // dropped, `..` made an ordinary name): what a run opens for them.
    let lines: Vec<String> = if from_payload {
        zip_payload_names(payload)
            .into_iter()
            .map(|l| String::from_utf8_lossy(&compat::sandbox_name(l)).into_owned())
            .collect()
    } else {
        Vec::new()
    };
    let dots = args.iter().filter(|t| **t == ".").count() as u64;
    let ff = args.contains(&"-FF");
    for (path, r) in reads {
        let file = path
            .strip_prefix(dir)
            .ok()
            .and_then(|p| p.to_str())
            .unwrap_or_else(|| {
                panic!("{name} ({flavour}) {args:?}: opened {path:?}, outside {dir:?}")
            });
        // A token names a file as itself, as the archive zip appends `.zip`
        // to, or as the `@file` of a pattern list. Both sides go through
        // `Path`'s components, which is how the system sees `a//b`, `a/`
        // and `./a`.
        let norm = |s: &str| Path::new(s).components().collect::<PathBuf>();
        let file = norm(file);
        let named = |t: &str| {
            let t = norm(t);
            file == t
                || file
                    .to_str()
                    .and_then(|f| f.strip_suffix(".zip"))
                    .is_some_and(|f| Path::new(f) == t)
                || t.to_str()
                    .and_then(|t| t.strip_prefix('@'))
                    .map(norm)
                    .as_ref()
                    == Some(&file)
        };
        let m = args.iter().filter(|t| named(t)).count() as u64
            + lines.iter().filter(|l| named(l)).count() as u64
            + dots;
        assert!(
            m > 0,
            "{name} ({flavour}) {args:?}: opened {file:?}, which no operand names"
        );
        let records = before.get(path).map_or(0, |b| {
            b.windows(4)
                .filter(|w| *w == b"PK\x01\x02" || *w == b"PK\x03\x04")
                .count() as u64
        });
        assert!(
            r.opens <= ZIP_READ_OPENS * m + 2 * records,
            "{name} ({flavour}) {args:?}: {} opens of {file:?}, which {m} operand(s) name \
             and which held {records} record(s)",
            r.opens
        );
        // `-FF` reads the archive as a stream and scans on past damage:
        // twice its length and a megabyte (Task 8), nothing looser.
        let allowed = if ff {
            m * (2 * r.len + ZIP_FF_SLACK)
        } else {
            m * ZIP_READ_PASSES * r.len + ZIP_READ_BLOCK * r.opens
        };
        assert!(
            r.bytes <= allowed,
            "{name} ({flavour}) {args:?}: read {} bytes of the {}-byte {file:?} in {} open(s), \
             past {allowed} for {m} operand(s)",
            r.bytes,
            r.len,
            r.opens
        );
    }
}

/// The zip family's measured read figures (`STUFFR_FUZZ_COMPAT_TRACE=1`, the
/// seeds in both flavours): at most 4 opens of an archive per operand (`-g`:
/// the old archive, its entries' copy, the temporary's re-read for the new
/// central directory, the final check) and 2.15 passes over it in bytes
/// (`-z`, `-u`, `-g` on the 1,228-byte seed archive read 2,640; zipsplit
/// 4,401 of 2,083). A pass is an end-record search from the tail, the
/// central directory, and each entry's local block once, so the bound is
/// `3 × len` plus one 8 KiB buffer per open for the block granularity of a
/// small archive.
const ZIP_READ_OPENS: u64 = 4;
const ZIP_READ_PASSES: u64 = 3;
const ZIP_READ_BLOCK: u64 = 8192;

/// The zip family (0.19.0) through `compat::run_in_counted`, as the
/// flavour byte says (0 Ubuntu, 1 Apple, absolute: the rule of the unzip and
/// compress families). Asserted:
///
/// - the exit is one of `zip::EXIT_CODES` (the ziperr set: never 1, which
///   would mean stuffr itself failed) and a panic is a crash;
/// - every file the run opened is one an operand names, within the read
///   bound (`check_zip_reads`);
/// - the files the run made are names the family makes (`zip_name_ok`),
///   no zip temporary (`zi` + six characters) survives, no more files than
///   a zipsplit of this archive could make, and standard output plus every
///   new or changed file stays within the 8 MiB budget (the sandbox's own,
///   which the `-lf` log's bytes and `-FF`'s reads are charged to);
/// - every archive written (a new or changed file starting `PK`, and
///   standard output) reads back by `verify_zip`, but only when each
///   archive the run started with was whole itself, since a repair or an
///   update copies an input's damage;
/// - containment (in `fuzz_target!`): nothing outside the run's directory
///   changed. No token is absolute, holds a `/` or names `..`; the names a
///   payload supplies (`-@`, `@file`, an archive's own entries) are kept
///   inside by the sandbox's `Host::path`.
fn run_zip(dir: &Path, name: &str, flavour: u8, args: &[&str], stdin: &[u8], payload: &[u8]) {
    let flavour_name = if flavour == 0 { "ubuntu" } else { "apple" };
    let flavour = if flavour == 0 {
        zip::Flavour::Ubuntu
    } else {
        zip::Flavour::Apple
    };
    let before = tree_contents(dir);
    let os_args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let (code, out, err, reads) = compat::run_in_counted(
        dir,
        name,
        os_args,
        stdin,
        Flavour::Gnu,
        unzip::default_flavour(),
        compress::default_flavour(),
        flavour,
    )
    .expect("a COMPAT_NAMES entry is a compat name");
    let why = || String::from_utf8_lossy(&err).into_owned();
    if std::env::var_os("STUFFR_FUZZ_COMPAT_TRACE").is_some() {
        eprintln!("compat: {name} {flavour_name} {args:?} -> {code}");
        for (path, r) in &reads {
            eprintln!("compat:   {path:?} {r:?}");
        }
    }
    assert!(
        zip::EXIT_CODES.contains(&code),
        "{name} ({flavour_name}) {args:?}: exit {code} is not a ziperr code\n{}",
        why()
    );
    check_zip_reads(dir, name, flavour_name, args, payload, &reads, &before);

    let after = tree_contents(dir);
    let mut created = Vec::new();
    let mut written = out.len() as u64;
    for (p, bytes) in &after {
        if before.get(p) == Some(bytes) {
            continue;
        }
        written += bytes.len() as u64;
        if !before.contains_key(p) {
            created.push(p);
        }
    }
    assert!(
        written <= OUTPUT_BUDGET,
        "{name} ({flavour_name}) {args:?}: {written} bytes written, past the {OUTPUT_BUDGET}-byte budget"
    );
    for p in &created {
        let rel = p
            .strip_prefix(dir)
            .ok()
            .and_then(|r| r.to_str())
            .unwrap_or_else(|| panic!("{name} {args:?}: made {p:?}, outside {dir:?}"));
        assert!(
            !is_zip_temp(rel),
            "{name} ({flavour_name}) {args:?}: left its temporary {rel:?}\n{}",
            why()
        );
        assert!(
            zip_name_ok(rel, args),
            "{name} ({flavour_name}) {args:?}: made a stray {rel:?}\n{}",
            why()
        );
    }
    let cap = zip_central_count(payload) + ZIP_PARTS_SLACK;
    assert!(
        created.len() as u64 <= cap,
        "{name} ({flavour_name}) {args:?}: made {} files from {} entries",
        created.len(),
        cap - ZIP_PARTS_SLACK
    );

    // Read back what was written, if the run's own inputs were whole.
    let repair = args.iter().any(|t| matches!(*t, "-F" | "-FF"));
    // An input archive is any file the run could have read that holds a
    // record signature, however far from the start (a preamble, a cut head)
    // and whatever it is called: `a.Z`, `a.out` and `a` all hold the payload
    // and zip does not append `.zip` to a name that has an extension.
    let inputs_whole = before
        .iter()
        .filter(|(_, b)| {
            [b"PK\x03\x04", b"PK\x01\x02", b"PK\x05\x06"]
                .iter()
                .any(|sig| signature_count(b, sig) > 0)
        })
        .all(|(_, b)| {
            // A repair (`-F`, `-FF`) walks the local headers, not the
            // directory, so its input must have exactly the local and
            // central records the directory counts (anything more, a
            // mutated duplicate or signature bytes in data, is a scan the
            // directory cannot vouch for), and every entry's data checked
            // (an encrypted or unknown-method record's local header may
            // say something else, and the repair believes the local one).
            verify_zip(b).is_ok_and(|v| {
                let (n, unchecked) = (v.entries, v.unchecked);
                !repair
                    || (unchecked == 0
                        && n == signature_count(b, b"PK\x03\x04")
                        && n == signature_count(b, b"PK\x01\x02"))
            })
        });
    if inputs_whole {
        for (p, bytes) in &after {
            if before.get(p) != Some(bytes)
                && zip_looks_like_archive(bytes)
                && let Err(e) = verify_zip(bytes)
            {
                panic!(
                    "{name} ({flavour_name}) {args:?}: wrote {p:?}, which does not read back: {e}\n{}",
                    why()
                );
            }
        }
        // A run that failed has streamed only part of its archive; and
        // `-fz` to standard output writes the Zip64 sizes into the records
        // but an end record with all-ones directory offset and no Zip64 end
        // record, which Zip 3.0 itself does (the references' bytes are
        // identical to ours) and no reader can follow.
        if matches!(code, 0 | 18)
            && !args.contains(&"-fz")
            && zip_looks_like_archive(&out)
            && let Err(e) = verify_zip(&out)
        {
            panic!(
                "{name} ({flavour_name}) {args:?}: wrote an archive to standard output that does not read back: {e}\n{}",
                why()
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > COMPAT_FUZZ_MAX_INPUT {
        return;
    }
    let Some(case) = decode_compat_case(data) else {
        return;
    };
    // `.` is the zip family's directory token (`-r .`); a directory operand
    // is nothing the other families' read bounds were written for (gunzip
    // opens it, reads nothing, and no operand names `""`), so those do not run.
    if case.args.contains(&".") && !matches!(case.name, "zip" | "zipcloak" | "zipnote" | "zipsplit")
    {
        return;
    }
    cwd_before();
    cwd_names_before();
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
        "zstd" | "unzstd" | "zstdcat" | "zstdmt" => run_zstd(&dir, case.name, &case.args, stdin),
        "lz4" | "unlz4" | "lz4cat" | "lz4c" => run_lz4(&dir, case.name, &case.args, stdin),
        "brotli" | "unbrotli" | "brcat" => run_brotli(&dir, case.name, &case.args, stdin),
        "unzip" | "zipinfo" | "funzip" => {
            run_unzip(&dir, case.name, case.flavour, &case.args, stdin)
        }
        "compress" | "uncompress" => run_compress(
            &dir,
            case.name,
            case.flavour,
            &case.args,
            stdin,
            case.payload,
        ),
        "zip" | "zipcloak" | "zipnote" | "zipsplit" => run_zip(
            &dir,
            case.name,
            case.flavour,
            &case.args,
            stdin,
            case.payload,
        ),
        other => unreachable!("{other} is in COMPAT_NAMES but has no arm here"),
    }

    // The unzip family extracts symlinks with the archive's own text
    // (`check_unzip_links` checks nothing was written through one); every
    // other family creates none, and is held to every rule.
    let links: Vec<PathBuf> = if matches!(case.name, "unzip" | "zipinfo" | "funzip") {
        symlinks_under(&dir)
    } else {
        Vec::new()
    };
    let links: Vec<&Path> = links.iter().map(PathBuf::as_path).collect();
    check_extraction_contained(parent, &dir, &links).expect("compat: contained");
    check_cwd_untouched();
    std::fs::remove_dir_all(parent).expect("remove the sandbox parent");
});
