//! The bzip2 compatibility family (0.11.0 Task 6): `bzip2`, `bunzip2`,
//! `bzcat` and `bzip2recover`, run in-process through
//! `stuffr_cli::compat::run_in` and `bzip2recover::recover`.
//!
//! The only fuzz coverage of `stuffr::bzip2_stream::StreamReader`, the
//! libbzip2-shaped decoder only the compat layer reaches: every decompress and
//! test path below goes through it.
//!
//! An input is `[tool][argc][token; argc][file mask] ++ payload`, decoded by
//! `stuffr_core::testing::decode_compat_case` (whose tables are the wire
//! format of the seeds `crates/stuffr/tests/fuzz_corpus.rs` writes). Each
//! file the mask names is created holding the payload; with the mask's stdin
//! bit, standard input carries it too.
//!
//! Asserted, for every input:
//!
//! - no panic;
//! - the exit code is one the tool has: 0-3 for the bzip2 family (`0` ok,
//!   `1` environment, `2` corrupt, `3` internal), 0 or 1 for bzip2recover;
//! - nothing is created, changed or removed outside the run's directory:
//!   each run gets a fresh directory inside a per-process sandbox parent, and
//!   `check_extraction_contained` walks the parent afterwards (the parent is
//!   removed at the end of every iteration); no name the tools could write
//!   appears in, changes in or vanishes from the real working directory;
//! - bzip2recover reads its input at most twice (two opens, at most
//!   `2 × len` bytes: its two passes) and within `check_scan_is_linear`'s
//!   bound, creates at most 50000 outputs, and writes at most the input's
//!   bytes plus a fixed per-output frame.
//!
//! Inputs past `COMPAT_FUZZ_MAX_INPUT` (64 KiB; see its doc) are skipped. The bzip2 family's output, to
//! standard output and files together, is capped by `run_in` itself
//! (8 MiB, failing as a full disk does: bzip2's exit 1), because a bzip2
//! stream of a few dozen bytes can expand to tens of MiB, and a payload is
//! written up to four times over plus standard input.

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
use stuffr_cli::compat::{self, bzip2recover};
use stuffr_core::testing::{
    COMPAT_FILES, COMPAT_FUZZ_MAX_INPUT, check_extraction_contained, check_scan_is_linear,
    decode_compat_case,
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

/// Whether `name` is one the tools could write in their working directory:
/// a `COMPAT_FILES` name or one derived from it (`.bz2` added, a suffix
/// mapped to `.tar` or `.out`, a `.bz2` stripped), a bzip2recover output
/// (`rec` and five digits), or bzip2's temporary (`.stuffr-bzip2-*`).
fn could_be_written(name: &str) -> bool {
    let mut bases: Vec<String> = Vec::new();
    for f in COMPAT_FILES {
        bases.push((*f).to_owned());
        for (z, u) in [
            (".bz2", ""),
            (".bz", ""),
            (".tbz2", ".tar"),
            (".tbz", ".tar"),
        ] {
            if let Some(stem) = f.strip_suffix(z) {
                bases.push(format!("{stem}{u}"));
            }
        }
    }
    let derived = |b: &str| [b.to_owned(), format!("{b}.bz2"), format!("{b}.out")];
    let rec = name
        .strip_prefix("rec")
        .is_some_and(|r| r.len() >= 5 && r.as_bytes()[..5].iter().all(u8::is_ascii_digit));
    rec || name.starts_with(".stuffr-bzip2-")
        || bases.iter().any(|b| derived(b).iter().any(|d| d == name))
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
    let (code, _out, err) =
        compat::run_in(dir, name, args, stdin).expect("a COMPAT_NAMES entry is a compat name");
    assert!(
        (0..=3).contains(&code),
        "{name}: exit {code} is not a bzip2 exit code\n{}",
        String::from_utf8_lossy(&err)
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

    if case.name == "bzip2recover" {
        run_recover(&dir, &case.args);
    } else {
        run_bzip2(&dir, case.name, &case.args, stdin);
    }

    check_extraction_contained(parent, &dir, &[]).expect("compat: contained");
    check_cwd_untouched();
    std::fs::remove_dir_all(parent).expect("remove the sandbox parent");
});
