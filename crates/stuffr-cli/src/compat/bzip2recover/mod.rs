//! `bzip2recover`: stuffr behaving as bzip2recover 1.0.8.
//!
//! Ported from bzip2 1.0.8's `bzip2recover.c`, copyright (C) 1996-2019
//! Julian Seward, under the bzip2 licence reproduced in `LICENSE-bzip2`.
//! `main` is followed line by line, quirks included:
//!
//! - two passes over the input: the first finds every 48-bit block and
//!   end-of-stream magic and records the blocks between them; the second
//!   copies each recorded block's bits into its own stream;
//! - a "block" is whatever lies between two magics and is recorded when it
//!   spans at least 130 bits, measured in unsigned 64-bit arithmetic, so a
//!   magic that follows another within 49 bits wraps round and is recorded
//!   with its end before its start (the second pass then writes nothing for
//!   it);
//! - a block the input ends inside is reported as `(incomplete)` but never
//!   written;
//! - each output is `BZh9`, the block magic, the block's bits, the
//!   end-of-stream magic and, as the combined CRC, the block's own stored
//!   CRC: nothing is decompressed, recompressed or checked;
//! - outputs are `rec%05d` and the input's base name, split at the last
//!   `/`, with `.bz2` appended unless the result already ends in it, opened
//!   as `fopen(.., "wb")` does (created mode 0666 less the umask, or an
//!   existing file truncated). So, as upstream does, an output is written
//!   through a symlink already at its name and truncates a file already
//!   there; Debian's `bzip2recover-race-open-output.diff` refuses both;
//! - the limits: `BZ_MAX_FILENAME` (an operand of 1980 bytes or more is
//!   refused) and `BZ_MAX_HANDLED_BLOCKS` (50000), with their messages; every
//!   failure exits 1.
//!
//! Memory is bounded by the block cap: the input is streamed twice, and only
//! the recorded blocks' bit positions (at most 50000 pairs) are kept.
//!
//! Known deviations from bzip2recover 1.0.8:
//!
//! - At exactly 50000 magics (for example 49999 blocks plus the
//!   end-of-stream marker) with at least 40 bits after the last, 1.0.8
//!   writes past its `bEnd` array and, on macOS, silently drops block 1;
//!   stuffr writes it, as if the arrays were 50001 long.
//! - Like bzip2, a read error is reported with its `strerror` text; a stale
//!   `errno` that the C library left nonzero at a clean end of file (which
//!   would make 1.0.8 report a read error) is not reproduced.
//! - `mallocFail` cannot happen: nothing is allocated per bit or per block
//!   beyond the bounded position list.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

mod bits;
mod messages;

use bits::{BitIn, BitOut};
use messages as m;

/// `BZ_MAX_FILENAME`.
const MAX_FILENAME: usize = 2000;
/// `BZ_MAX_HANDLED_BLOCKS`.
const MAX_HANDLED_BLOCKS: i64 = 50_000;
/// `BLOCK_HEADER_HI`/`_LO`: the block magic, `0x314159265359`.
const BLOCK_MAGIC: u64 = 0x3141_5926_5359;
/// `BLOCK_ENDMARK_HI`/`_LO`: the end-of-stream magic, `0x177245385090`.
const END_MAGIC: u64 = 0x1772_4538_5090;
/// `BZ_SPLIT_SYM`.
const SPLIT: u8 = if cfg!(windows) { b'\\' } else { b'/' };

/// Entry point: `argv0` is the program path as invoked (bzip2recover prints
/// it in full), `args` the arguments after it.
pub fn run(argv0: OsString, args: Vec<OsString>) -> ExitCode {
    // bzip2recover dies of SIGPIPE when stderr is a closed pipe; Rust
    // ignores the signal by default, so restore its default action.
    #[cfg(unix)]
    // SAFETY: setting a signal's disposition to SIG_DFL installs no handler
    // and touches no Rust state; it is done before any other thread or I/O.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let args: Vec<Vec<u8>> = args.iter().map(|a| bytes(a)).collect();
    let code = recover(&bytes(&argv0), &args, &mut RealFs, &mut io::stderr());
    ExitCode::from(code)
}

/// Where the input is read from and the outputs are written to, so the
/// scan can be run (and its reads counted) without a file system.
pub(crate) trait Fs {
    /// `fopen(name, "rb")`.
    fn open(&mut self, name: &[u8]) -> io::Result<Box<dyn Read>>;
    /// `fopen(name, "wb")`.
    fn create(&mut self, name: &[u8]) -> io::Result<Box<dyn Write>>;
}

/// The real file system.
pub(crate) struct RealFs;

impl Fs for RealFs {
    fn open(&mut self, name: &[u8]) -> io::Result<Box<dyn Read>> {
        Ok(Box::new(File::open(path(name))?))
    }
    fn create(&mut self, name: &[u8]) -> io::Result<Box<dyn Write>> {
        // `fopen(.., "wb")`: O_WRONLY|O_CREAT|O_TRUNC, mode 0666 less umask.
        let f = File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path(name))?;
        Ok(Box::new(f))
    }
}

fn bytes(s: &OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        s.as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        s.to_string_lossy().into_owned().into_bytes()
    }
}

fn path(b: &[u8]) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        PathBuf::from(OsStr::from_bytes(b))
    }
    #[cfg(not(unix))]
    {
        PathBuf::from(String::from_utf8_lossy(b).into_owned())
    }
}

/// C's `strerror`: the OS text without Rust's ` (os error N)` suffix.
fn strerror(e: &io::Error) -> Vec<u8> {
    let s = e.to_string();
    match e.raw_os_error() {
        Some(n) => {
            let suffix = format!(" (os error {n})");
            s.strip_suffix(&suffix).unwrap_or(&s).as_bytes().to_vec()
        }
        None => s.into_bytes(),
    }
}

/// The run stopped with this exit code; its message is already printed.
struct Exit(u8);

/// One run of bzip2recover's state over a pair of streams.
struct Recover<'a> {
    prog: &'a [u8],
    in_name: &'a [u8],
    err: &'a mut dyn Write,
}

impl Recover<'_> {
    fn say(&mut self, fmt: &str, args: &[&[u8]]) {
        m::printf(self.err, fmt, args);
    }

    /// `readError` and `writeError`, which print the same text.
    fn io_error(&mut self, e: &io::Error) -> Exit {
        let (p, n) = (self.prog, self.in_name);
        self.say(m::IO_ERROR, &[p, n]);
        self.say(m::PERROR, &[p, &strerror(e)]);
        self.say(m::MAY_BE_INCOMPLETE, &[p]);
        Exit(1)
    }

    fn bit(&mut self, input: &mut BitIn) -> Result<Option<u32>, Exit> {
        input.bit().map_err(|e| self.io_error(&e))
    }
}

/// The blocks the first pass recorded (`rbStart`/`rbEnd`, inclusive bit
/// positions) and its shift register, which the second pass continues.
struct Found {
    blocks: Vec<(u64, u64)>,
    hi: u32,
    lo: u32,
}

/// Shift `b` into the 64-bit window and report whether its low 48 bits
/// are now a block or end-of-stream magic.
fn shift(hi: &mut u32, lo: &mut u32, b: u32) -> bool {
    *hi = (*hi << 1) | (*lo >> 31);
    *lo = (*lo << 1) | (b & 1);
    let w = (u64::from(*hi & 0xffff) << 32) | u64::from(*lo);
    w == BLOCK_MAGIC || w == END_MAGIC
}

/// bzip2recover's `main`, from the argument checks to the end. `prog` is
/// `argv[0]`, `args` the rest. Returns the exit code.
pub(crate) fn recover(prog: &[u8], args: &[Vec<u8>], fs: &mut dyn Fs, err: &mut dyn Write) -> u8 {
    // strncpy into progName[BZ_MAX_FILENAME], then terminated.
    let prog = &prog[..prog.len().min(MAX_FILENAME - 1)];
    m::printf(err, m::BANNER, &[]);
    let [in_name] = args else {
        m::printf(err, m::USAGE, &[prog, prog]);
        m::printf(err, m::USAGE_SIZE, &[]);
        return 1;
    };
    if in_name.len() >= MAX_FILENAME - 20 {
        let n = in_name.len().to_string();
        m::printf(err, m::NAME_TOO_LONG, &[prog, n.as_bytes()]);
        return 1;
    }
    let mut r = Recover { prog, in_name, err };
    match r.both_passes(fs) {
        Ok(()) => 0,
        Err(Exit(c)) => c,
    }
}

impl Recover<'_> {
    fn both_passes(&mut self, fs: &mut dyn Fs) -> Result<(), Exit> {
        let (p, n) = (self.prog, self.in_name);
        let Ok(input) = fs.open(n) else {
            self.say(m::CANT_READ, &[p, n]);
            return Err(Exit(1));
        };
        self.say(m::SEARCHING, &[p]);
        let found = self.find_blocks(&mut BitIn::new(input))?;
        if found.blocks.is_empty() {
            self.say(m::NO_BLOCKS, &[p]);
            return Err(Exit(1));
        }
        self.say(m::SPLITTING, &[p]);
        let Ok(input) = fs.open(n) else {
            self.say(m::CANT_OPEN, &[p, n]);
            return Err(Exit(1));
        };
        self.split(&mut BitIn::new(input), found, fs)?;
        self.say(m::FINISHED, &[p]);
        Ok(())
    }

    /// The first pass: every magic ends the current block and starts the
    /// next. `bitsRead` counts bits including the one just read, so a
    /// block's start is the position of the bit after its magic and its end
    /// the position of the bit before the next.
    fn find_blocks(&mut self, input: &mut BitIn) -> Result<Found, Exit> {
        let (mut hi, mut lo) = (0u32, 0u32);
        let mut bits_read: u64 = 0;
        let mut curr_block: i64 = 0;
        let mut b_start: u64 = 0; // bStart[currBlock]
        let mut blocks: Vec<(u64, u64)> = Vec::new();
        loop {
            let b = self.bit(input)?;
            bits_read = bits_read.wrapping_add(1);
            let Some(b) = b else {
                if bits_read >= b_start && bits_read - b_start >= 40 {
                    let b_end = bits_read - 1;
                    if curr_block > 0 {
                        let c = curr_block.to_string();
                        self.say(
                            m::BLOCK_INCOMPLETE,
                            &[c.as_bytes(), num(b_start).as_bytes(), num(b_end).as_bytes()],
                        );
                    }
                }
                break;
            };
            if shift(&mut hi, &mut lo, b) {
                let b_end = bits_read.saturating_sub(49);
                if curr_block > 0 && b_end.wrapping_sub(b_start) >= 130 {
                    let c = (blocks.len() + 1).to_string();
                    self.say(
                        m::BLOCK,
                        &[c.as_bytes(), num(b_start).as_bytes(), num(b_end).as_bytes()],
                    );
                    blocks.push((b_start, b_end));
                }
                if curr_block >= MAX_HANDLED_BLOCKS {
                    let (p, n) = (self.prog, self.in_name);
                    let max = MAX_HANDLED_BLOCKS.to_string();
                    self.say(m::TOO_MANY_BLOCKS, &[p, n, max.as_bytes(), p, p]);
                    return Err(Exit(1));
                }
                curr_block += 1;
                b_start = bits_read;
            }
        }
        Ok(Found { blocks, hi, lo })
    }

    /// The second pass: copy each recorded block's bits into its own
    /// stream. `bitsRead` here is the position of the bit just read, and is
    /// advanced after it is handled. Past the last block the position list
    /// reads as zero (`rbStart`/`rbEnd` are zero-initialised globals), and
    /// the input is read to its end.
    fn split(&mut self, input: &mut BitIn, found: Found, fs: &mut dyn Fs) -> Result<(), Exit> {
        let Found {
            blocks,
            mut hi,
            mut lo,
        } = found;
        let at = |i: usize| blocks.get(i).copied().unwrap_or((0, 0));
        let mut bits_read: u64 = 0;
        let mut wr_block: usize = 0;
        let mut block_crc: u32 = 0;
        let mut out: Option<BitOut> = None;
        while let Some(b) = self.bit(input)? {
            shift(&mut hi, &mut lo, b);
            let (start, end) = at(wr_block);
            if bits_read == start.wrapping_add(47) {
                block_crc = (hi << 16) | (lo >> 16);
            }
            if let Some(w) = out.as_mut()
                && bits_read >= start
                && bits_read <= end
            {
                w.put_bit(b).map_err(|e| self.io_error(&e))?;
            }
            bits_read = bits_read.wrapping_add(1);
            if bits_read == end.wrapping_add(1) {
                if let Some(mut w) = out.take() {
                    let r: io::Result<()> = (|| {
                        for c in [0x17, 0x72, 0x45, 0x38, 0x50, 0x90] {
                            w.put_u8(c)?;
                        }
                        w.put_u32(block_crc)?;
                        w.close()
                    })();
                    r.map_err(|e| self.io_error(&e))?;
                }
                if wr_block >= blocks.len() {
                    break;
                }
                wr_block += 1;
            } else if bits_read == start {
                let name = out_name(self.in_name, wr_block + 1);
                let k = (wr_block + 1).to_string();
                self.say(m::WRITING, &[k.as_bytes(), &name]);
                let Ok(f) = fs.create(&name) else {
                    let p = self.prog;
                    self.say(m::CANT_WRITE, &[p, &name]);
                    return Err(Exit(1));
                };
                let mut w = BitOut::new(f);
                let r: io::Result<()> = (|| {
                    for c in *b"BZh9" {
                        w.put_u8(c)?;
                    }
                    for c in [0x31, 0x41, 0x59, 0x26, 0x53, 0x59] {
                        w.put_u8(c)?;
                    }
                    Ok(())
                })();
                r.map_err(|e| self.io_error(&e))?;
                out = Some(w);
            }
        }
        Ok(())
    }
}

/// `MaybeUInt64_FMT`.
fn num(n: u64) -> String {
    n.to_string()
}

/// The output name for block `k` (1-based): the input's directory part,
/// `rec%5d` with its spaces made zeros, the input's base name, and `.bz2`
/// unless that already ends the name (`endsInBz2`, which wants more than
/// four bytes).
fn out_name(in_name: &[u8], k: usize) -> Vec<u8> {
    let ofs = in_name
        .iter()
        .rposition(|&c| c == SPLIT)
        .map_or(0, |i| i + 1);
    let mut v = in_name[..ofs].to_vec();
    v.extend_from_slice(format!("rec{k:5}").replace(' ', "0").as_bytes());
    v.extend_from_slice(&in_name[ofs..]);
    if !(v.len() > 4 && v.ends_with(b".bz2")) {
        v.extend_from_slice(b".bz2");
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::rc::Rc;

    /// An in-memory file system that counts every byte read from it.
    #[derive(Default)]
    struct MemFs {
        files: BTreeMap<Vec<u8>, Rc<RefCell<Vec<u8>>>>,
        read: Rc<Cell<u64>>,
        opens: usize,
    }

    struct Counting {
        data: Rc<RefCell<Vec<u8>>>,
        pos: usize,
        read: Rc<Cell<u64>>,
    }
    impl Read for Counting {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let d = self.data.borrow();
            let n = buf.len().min(d.len() - self.pos);
            buf[..n].copy_from_slice(&d[self.pos..self.pos + n]);
            self.pos += n;
            self.read.set(self.read.get() + n as u64);
            Ok(n)
        }
    }

    struct Shared(Rc<RefCell<Vec<u8>>>);
    impl Write for Shared {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Fs for MemFs {
        fn open(&mut self, name: &[u8]) -> io::Result<Box<dyn Read>> {
            self.opens += 1;
            let data = self
                .files
                .get(name)
                .cloned()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
            Ok(Box::new(Counting {
                data,
                pos: 0,
                read: self.read.clone(),
            }))
        }
        fn create(&mut self, name: &[u8]) -> io::Result<Box<dyn Write>> {
            let v = Rc::new(RefCell::new(Vec::new()));
            self.files.insert(name.to_vec(), v.clone());
            Ok(Box::new(Shared(v)))
        }
    }

    /// `BZh9`, then `n` blocks of a magic, a CRC and some bytes, then the
    /// end-of-stream magic and a combined CRC.
    fn synthetic(n: usize, body: usize) -> Vec<u8> {
        let mut v = b"BZh9".to_vec();
        for i in 0..n {
            v.extend_from_slice(&[0x31, 0x41, 0x59, 0x26, 0x53, 0x59]);
            v.extend_from_slice(&(i as u32).wrapping_mul(0x9e37_79b9).to_be_bytes());
            v.extend((0..body).map(|k| (k * 7 + i) as u8 | 0x80));
        }
        v.extend_from_slice(&[0x17, 0x72, 0x45, 0x38, 0x50, 0x90, 1, 2, 3, 4]);
        v
    }

    fn run_mem(data: Vec<u8>) -> (u8, MemFs, String) {
        let mut fs = MemFs::default();
        fs.files
            .insert(b"d.bz2".to_vec(), Rc::new(RefCell::new(data)));
        let mut err = Vec::new();
        let code = recover(b"bzip2recover", &[b"d.bz2".to_vec()], &mut fs, &mut err);
        (code, fs, String::from_utf8(err).unwrap())
    }

    /// The read-amplification bound: the input is read exactly twice,
    /// whatever its shape, and nothing else is read.
    #[test]
    fn the_input_is_read_at_most_twice() {
        for (blocks, body) in [(1, 40), (7, 3000), (300, 25), (2000, 13)] {
            let data = synthetic(blocks, body);
            let len = data.len() as u64;
            let (code, fs, err) = run_mem(data);
            assert_eq!(code, 0, "{err}");
            assert_eq!(fs.opens, 2);
            assert_eq!(fs.read.get(), 2 * len, "{blocks} blocks of {body}");
        }
        // Inputs that stop after the first pass read once.
        for data in [Vec::new(), b"not bzip2 at all".repeat(1000)] {
            let len = data.len() as u64;
            let (code, fs, _) = run_mem(data);
            assert_eq!(code, 1);
            assert_eq!(fs.read.get(), len);
        }
    }

    #[test]
    fn each_block_becomes_a_stream_with_its_crc_as_the_combined_crc() {
        let data = synthetic(2, 30);
        let (code, fs, err) = run_mem(data);
        assert_eq!(code, 0, "{err}");
        let rec1 = fs.files[&b"rec00001d.bz2".to_vec()].borrow().clone();
        let mut want = b"BZh9".to_vec();
        want.extend_from_slice(&[0x31, 0x41, 0x59, 0x26, 0x53, 0x59]);
        let crc = 0u32.to_be_bytes();
        want.extend_from_slice(&crc);
        want.extend((0..30).map(|k| (k * 7) as u8 | 0x80));
        want.extend_from_slice(&[0x17, 0x72, 0x45, 0x38, 0x50, 0x90]);
        want.extend_from_slice(&crc);
        // Byte-aligned, so bsClose's final byte is the CRC's last: no padding.
        assert_eq!(rec1, want);
        let mut line = Vec::new();
        m::printf(&mut line, m::WRITING, &[b"2", b"rec00002d.bz2"]);
        assert!(err.contains(std::str::from_utf8(&line).unwrap()));
        assert!(err.ends_with("bzip2recover: finished\n"));
    }

    #[test]
    fn output_names_split_at_the_last_slash_and_keep_one_bz2() {
        let n = |s: &str, k| String::from_utf8(out_name(s.as_bytes(), k)).unwrap();
        assert_eq!(n("d.bz2", 1), "rec00001d.bz2");
        assert_eq!(n("a/b/d.bz2", 12), "a/b/rec00012d.bz2");
        assert_eq!(n("d.dat", 50000), "rec50000d.dat.bz2");
        assert_eq!(n("my file", 3), "rec00003my file.bz2");
        assert_eq!(n(".bz2", 1), "rec00001.bz2");
        assert_eq!(n("dir/", 1), "dir/rec00001.bz2");
    }

    #[test]
    fn usage_and_length_limits() {
        let mut fs = MemFs::default();
        let mut err = Vec::new();
        assert_eq!(recover(b"/x/bzip2recover", &[], &mut fs, &mut err), 1);
        assert_eq!(
            String::from_utf8(err).unwrap(),
            "bzip2recover 1.0.8: extracts blocks from damaged .bz2 files.\n\
             /x/bzip2recover: usage is `/x/bzip2recover damaged_file_name'.\n\
             \trestrictions on size of recovered file: None\n"
        );
        for (len, refused) in [(1979, false), (1980, true)] {
            let mut err = Vec::new();
            assert_eq!(recover(b"p", &[vec![b'a'; len]], &mut fs, &mut err), 1);
            let err = String::from_utf8(err).unwrap();
            assert_eq!(
                err.contains(&format!("suspiciously (>= {len} chars) long.  Bye!")),
                refused,
                "{err}"
            );
        }
        // progName keeps at most BZ_MAX_FILENAME - 1 bytes.
        let mut err = Vec::new();
        recover(&[b'p'; 2500], &[], &mut fs, &mut err);
        let first = err.split(|&c| c == b'\n').nth(1).unwrap();
        assert!(first.starts_with(&[b'p'; 1999]) && first[1999] == b':');
    }
}
