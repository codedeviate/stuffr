//! `funzip.c` (fUnZip 3.95, Mark Adler): the first entry of a zip archive,
//! or a gzip member, from standard input or a file, to standard output.
//!
//! Apple's `funzip.c` is upstream's byte for byte and no Ubuntu patch
//! touches it (only the manual page and the Makefile), so both flavours
//! run this one port; no build option of Ubuntu's reaches it (probed: the
//! same answers for every input of the Task 12 table on both references).
//! The banner of its usage is the one flavour difference (deviation 2).
//!
//! funzip has its own globals, not unzip's `G` (`out`, `outsiz`,
//! `encrypted`, `G.in`, `G.crc32val`, `slide`): they are [`Funzip`] here.
//! It prints through `fputs()` (unzpriv.h's `Info()` under `FUNZIP`), not
//! `UzpMessagePrnt`, so it writes standard error directly; the text it
//! formats into `slide` first is never read again (every such message is
//! followed by `err()`'s exit), so it is not kept there.
//!
//! Its input is a stdio stream read once, front to back: no seek, one
//! `read(2)` per refill, so a pipe works and memory stays bounded. Its
//! output is written as each window is flushed.
//!
//! The rulings (each pinned by a stuffr-only test):
//! - T12-1: `getc() << 8` of `EOF` (a negative left shift, undefined in
//!   C) is `-256`, two's complement, so a two-byte field cut after its
//!   first byte reads `0xff00 | b`.
//! - T12-2: inflate's `(ulg)c << k` with `k` "negative" (funzip's
//!   encrypted `NEXTBYTE` gives values again after its `EOF`) is taken
//!   modulo 64 (`stuffr::infozip::ByteSource::next_bits`).
//! - T12-3: an encrypted gzip member's check byte is `h[9]` or `h[15]`,
//!   bytes of the header buffer a gzip header never fills (uninitialised):
//!   they read as 0.
//! - T12-4: every failed write to standard output is answered with
//!   "out of space on stdout", exit 9, where the C's buffered stdio loses
//!   a failure in its last `fflush()` (unchecked).

use std::ffi::OsString;
use std::io::{self, Read, Write};

use stuffr::infozip::crypt::{Keys, RAND_HEAD_LEN};
use stuffr::infozip::{self, ByteSource, Stop, WSIZE};

use super::messages::{self as m, printf};
use super::{Uz, cli, flavour, ttyio};
use crate::compat::host::{self, Host};

// PKZIP header definitions
/// two-byte zip lead-in
const ZIPMAG: u16 = 0x4b50;
/// remaining two bytes in zip signature
const LOCREM: u16 = 0x0403;
/// full signature
const LOCSIG: u32 = 0x0403_4b50;
/// offset of bit flag
const LOCFLG: usize = 4;
/// bit for encrypted entry
const CRPFLG: u8 = 1;
/// bit for extended local header
const EXTFLG: u8 = 8;
/// offset of compression method
const LOCHOW: usize = 6;
/// file mod time (for decryption)
const LOCTIM: usize = 8;
/// offset of crc
const LOCCRC: usize = 12;
/// offset of compressed size
const LOCSIZ: usize = 16;
/// offset of uncompressed length
const LOCLEN: usize = 20;
/// offset of file name field length
const LOCFIL: usize = 24;
/// offset of extra field length
const LOCEXT: usize = 26;
/// size of local header, including LOCREM
const LOCHDR: usize = 28;
/// size of extended local header, inc sig
const EXTHDR: usize = 16;

// GZIP header definitions
/// two-byte gzip lead-in
const GZPMAG: u16 = 0x8b1f;
/// offset of method number
const GZPHOW: usize = 0;
/// offset of gzip flags
const GZPFLG: usize = 1;
/// bit for multiple-part gzip file
const GZPMUL: u8 = 2;
/// bit for extra field present
const GZPISX: u8 = 4;
/// bit for filename present
const GZPISF: u8 = 8;
/// bit for comment present
const GZPISC: u8 = 16;
/// bit for encryption
const GZPISE: u8 = 32;
/// length of minimal gzip header
const GZPHDR: usize = 8;

// unzip.h's method numbers
const STORED: u16 = 0;
const DEFLATED: u16 = 8;
const ENHDEFLATED: u16 = 9;

/// stdio's `EOF`.
const EOF: i32 = -1;

/// The stdio buffer funzip's input is read through (one `read(2)` per
/// refill, as `getc()` and `fread()` refill a `FILE`).
const BUFSIZ: usize = 4096;

/// `SH(p)`: a little-endian `ush`.
fn sh(p: &[u8]) -> u16 {
    u16::from(p[0]) | (u16::from(p[1]) << 8)
}

/// `LG(p)`: a little-endian `ulg` of four bytes.
fn lg(p: &[u8]) -> u32 {
    u32::from(sh(p)) | (u32::from(sh(&p[2..])) << 16)
}

/// `n = getc(in); n |= getc(in) << 8;` into an `ush`.
///
/// ruling: T12-1. `EOF << 8` shifts a negative `int` (undefined in C); it
/// is `-256` here, as two's complement gives and as both compilers do, so
/// an `EOF` second byte makes the high byte `0xff`.
fn getc2(inp: &mut In) -> u16 {
    let lo = inp.getc();
    let hi = inp.getc();
    (lo as u16) | ((hi << 8) as u16)
}

/// `G.in`: a stdio stream over standard input or the input file. A read
/// error ends it as end of file does (`getc()` gives `EOF` for both).
struct In {
    src: Box<dyn Read>,
    buf: Box<[u8]>,
    pos: usize,
    len: usize,
    eof: bool,
}

impl In {
    fn new(src: Box<dyn Read>) -> In {
        In {
            src,
            buf: vec![0; BUFSIZ].into_boxed_slice(),
            pos: 0,
            len: 0,
            eof: false,
        }
    }

    /// One refill; `false` at the end of the input (sticky).
    fn fill(&mut self) -> bool {
        while !self.eof {
            match self.src.read(&mut self.buf) {
                Ok(0) => self.eof = true,
                Ok(n) => {
                    self.pos = 0;
                    self.len = n;
                    return true;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => self.eof = true,
            }
        }
        false
    }

    /// `getc(G.in)`.
    fn getc(&mut self) -> i32 {
        if self.pos == self.len && !self.fill() {
            return EOF;
        }
        let c = self.buf[self.pos];
        self.pos += 1;
        i32::from(c)
    }

    /// `fread(out, 1, out.len(), G.in)`: the bytes read, fewer only at the
    /// end of the input.
    fn fread(&mut self, out: &mut [u8]) -> usize {
        let mut n = 0;
        while n < out.len() {
            if self.pos == self.len && !self.fill() {
                break;
            }
            let k = (self.len - self.pos).min(out.len() - n);
            out[n..n + k].copy_from_slice(&self.buf[self.pos..self.pos + k]);
            self.pos += k;
            n += k;
        }
        n
    }
}

/// What inflate reads: crypt.h's `NEXTBYTE` under `FUNZIP`, `getc(G.in)`,
/// or for an encrypted entry `update_keys(getc(G.in) ^ decrypt_byte())`.
struct Src {
    inp: In,
    /// `G.keys` while `encrypted`.
    keys: Option<Keys>,
}

impl Src {
    // port: crypt.h:NEXTBYTE (FUNZIP)
    /// `NEXTBYTE` as the C `int`. At the end of an encrypted input it is
    /// `EOF ^ decrypt_byte()`, which is `EOF` only when that byte is 0
    /// (`update_keys()` masks the value to its low byte, so the keys move
    /// on as for a `0xff` byte).
    fn nextbyte(&mut self) -> i32 {
        let c = self.inp.getc();
        match self.keys.as_mut() {
            None => c,
            Some(k) => {
                let low = k.decrypt_byte((c & 0xff) as u8);
                if c == EOF {
                    EOF ^ i32::from(low ^ 0xff)
                } else {
                    i32::from(low)
                }
            }
        }
    }
}

impl ByteSource for Src {
    fn next_byte(&mut self) -> Option<u8> {
        self.next_bits().map(|c| c as u8)
    }

    fn next_bits(&mut self) -> Option<u64> {
        match self.nextbyte() {
            EOF => None,
            // `(ulg)c`: a negative `int` sign-extends
            c => Some(i64::from(c) as u64),
        }
    }

    /// Unused by inflate (explode reads it); funzip's input has no size.
    fn remaining(&self) -> u64 {
        0
    }
}

/// funzip.c's output globals: `out`, `outsiz` and `G.crc32val`.
struct Out<'w> {
    out: &'w mut dyn Write,
    crc: flate2::Crc,
    /// `outsiz`: total bytes written to out.
    outsiz: u64,
}

/// A write that failed with anything but `EPIPE` (funzip's
/// `!PIPE_ERROR`): `err(9, "out of space on stdout")`.
struct OutOfSpace;

impl Out<'_> {
    // port: funzip.c:flush
    /// `flush(w)`: CRC, write, count. `EPIPE` is no error (`PIPE_ERROR`).
    ///
    /// ruling: T12-4. The C writes through stdio, whose last buffer goes
    /// out in an unchecked `fflush()`, so a failure there (a full disk
    /// under about 4 KiB of output) exits 0 with the data lost; here every
    /// window is written at once and every failure answered.
    fn flush(&mut self, w: &[u8]) -> Result<(), OutOfSpace> {
        self.crc.update(w);
        if !w.is_empty() {
            match self.out.write_all(w).and_then(|()| self.out.flush()) {
                Err(e) if e.kind() != io::ErrorKind::BrokenPipe => return Err(OutOfSpace),
                _ => {}
            }
        }
        self.outsiz += w.len() as u64;
        Ok(())
    }
}

// port: funzip.c:err
/// `err(n, m)`: the message on standard error; the exit code is `n`.
fn err(uz: &mut Uz, n: i32, msg: &str) -> i32 {
    printf(uz.err, m::FUNZIP_ERROR, &[msg.as_bytes()]);
    let _ = uz.err.flush();
    n
}

/// Whether descriptor `fd` is open for reading (or writing):
/// `fdopen(fd, mode)`'s check, which fails with `EBADF` or `EINVAL`.
// probe: `funzip <a.gz 1</dev/null` ("cannot write to stdout") and
// `funzip 0>f` ("cannot find stdin"), exit 2, on both references.
#[cfg(unix)]
fn fdopen_ok(fd: libc::c_int, write: bool) -> bool {
    // SAFETY: F_GETFL only reads the descriptor's status flags.
    let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if fl == -1 {
        return false;
    }
    match fl & libc::O_ACCMODE {
        libc::O_RDWR => true,
        libc::O_WRONLY => write,
        _ => !write,
    }
}

/// `fdopen()` on a real descriptor: off unix there is no such check.
#[cfg(not(unix))]
fn fdopen_ok(_fd: i32, _write: bool) -> bool {
    true
}

// port: funzip.c:main
/// funzip: decompress the first entry of a zip archive, or a gzip member,
/// from standard input or the file named, to standard output. Returns the
/// exit code (`err()`'s, or 0).
///
/// Rust reopens a closed standard descriptor on `/dev/null` before
/// `main`, so the C's "cannot find stdin" and "cannot write to stdout" for
/// a closed one (exit 2) are unreachable; for a descriptor open the wrong
/// way (`0>file`, `1</dev/null`) they are given.
pub(crate) fn funzip(uz: &mut Uz, args: &[OsString]) -> i32 {
    let a = cli::parse_funzip(args);

    // if no file argument and stdin not redirected, give the user help
    if a.input.is_none() && uz.host.stdin_is_tty() {
        printf(
            uz.err,
            flavour::funzip_banner(uz.flavour),
            &[env!("CARGO_PKG_VERSION").as_bytes()],
        );
        let _ = uz.err.write_all(m::FUNZIP_USAGE.as_bytes());
        return 3;
    }

    // prepare to be a binary filter
    let real = matches!(uz.host, Host::Real);
    let src: Box<dyn Read> = if let Some(name) = &a.input {
        let path = uz.host.path(name.as_encoded_bytes());
        match std::fs::File::open(&path) {
            Ok(f) => Box::new(uz.host.track(&path, f)),
            Err(_) => return err(uz, 2, m::FZ_NO_INPUT_FILE),
        }
    } else if real {
        if !fdopen_ok(0, false) {
            return err(uz, 2, m::FZ_NO_STDIN);
        }
        match host::stdin_file() {
            Ok(f) => Box::new(f),
            Err(_) => Box::new(io::stdin()),
        }
    } else {
        Box::new(uz.host.stdin())
    };
    if real && !fdopen_ok(1, true) {
        return err(uz, 2, m::FZ_NO_STDOUT);
    }
    let mut src = Src {
        inp: In::new(src),
        keys: None,
    };
    let code = filter(uz, &mut src, a.password.as_deref());
    let _ = uz.out.flush();
    code
}

/// funzip.c:main from the local header on.
fn filter(uz: &mut Uz, src: &mut Src, password: Option<&[u8]>) -> i32 {
    // first local header (GZPHDR < LOCHDR)
    // ruling: T12-3. The bytes a gzip header never fills are 0.
    // probe: an encrypted gzip member under `funzip -pw`, every check byte
    // 0..=255 (gzenc.py): Ubuntu passes 0 only, every run; Apple passes 0
    // for `h[9]` and changing values for `h[15]`.
    let mut h = [0u8; LOCHDR];
    let g: bool; // true if gzip format
    let method: u16;
    let encrypted: bool;

    // read local header, check validity, and skip name and extra fields
    let n = getc2(&mut src.inp);
    if n == ZIPMAG {
        if src.inp.fread(&mut h) != LOCHDR || sh(&h) != LOCREM {
            return err(uz, 3, m::FZ_INVALID_ZIPFILE);
        }
        method = sh(&h[LOCHOW..]);
        if !matches!(method, STORED | DEFLATED | ENHDEFLATED) {
            return err(uz, 3, m::FZ_NOT_DEFLATED_OR_STORED);
        }
        for _ in 0..sh(&h[LOCFIL..]) {
            src.inp.getc();
        }
        for _ in 0..sh(&h[LOCEXT..]) {
            src.inp.getc();
        }
        g = false;
        encrypted = h[LOCFLG] & CRPFLG != 0;
    } else if n == GZPMAG {
        if src.inp.fread(&mut h[..GZPHDR]) != GZPHDR {
            return err(uz, 3, m::FZ_INVALID_GZIP);
        }
        method = u16::from(h[GZPHOW]);
        if method != DEFLATED && method != ENHDEFLATED {
            return err(uz, 3, m::FZ_GZIP_NOT_DEFLATED);
        }
        if h[GZPFLG] & GZPMUL != 0 {
            return err(uz, 3, m::FZ_MULTI_PART);
        }
        if h[GZPFLG] & GZPISX != 0 {
            for _ in 0..getc2(&mut src.inp) {
                src.inp.getc();
            }
        }
        for flag in [GZPISF, GZPISC] {
            if h[GZPFLG] & flag != 0 {
                loop {
                    let c = src.inp.getc();
                    if c == 0 || c == EOF {
                        break;
                    }
                }
            }
        }
        g = true;
        encrypted = h[GZPFLG] & GZPISE != 0;
    } else {
        return err(uz, 3, m::FZ_NOT_ZIP_OR_GZIP);
    }

    // if entry encrypted, decrypt and validate encryption header
    if encrypted {
        let typed;
        let p: &[u8] = match password {
            Some(p) => p,
            None => {
                let _restore = host::arm_tty_restore(&uz.host, host::FUNZIP_SIGNALS);
                match ttyio::getp(uz, m::FZ_ENTER_PASSWORD.as_bytes()) {
                    Ok(pw) => {
                        typed = pw;
                        typed.key()
                    }
                    Err(_) => return err(uz, 1, m::FZ_NO_TTY),
                }
            }
        };
        // prepare the decryption keys for extraction and check the password
        src.keys = Some(Keys::new(p));
        let mut e: u16 = 0;
        for _ in 0..RAND_HEAD_LEN {
            e = src.nextbyte() as u16;
        }
        let check = if h[LOCFLG] & EXTFLG != 0 {
            h[LOCTIM + 1]
        } else {
            h[LOCCRC + 3]
        };
        if e != u16::from(check) {
            return err(uz, 3, m::FZ_INCORRECT_PASSWORD);
        }
    }

    // prepare output buffer and crc
    let Uz {
        slide, out, err: e, ..
    } = uz;
    let stderr: &mut dyn Write = &mut **e;
    let mut o = Out {
        out: out.get_mut(),
        crc: flate2::Crc::new(),
        outsiz: 0,
    };

    // decompress
    let failed = if g || h[LOCHOW] != 0 {
        // deflated entry
        let mut flush = |w: &[u8]| o.flush(w);
        // inflate.c's MESSAGE under FUNZIP: `fprintf(stderr, str)`
        let mut message = |s: &'static str| {
            let _ = stderr.write_all(s.as_bytes());
            let _ = stderr.flush();
        };
        match infozip::inflate(
            src,
            method == ENHDEFLATED,
            &mut slide[..WSIZE],
            &mut flush,
            &mut message,
        ) {
            Ok(()) => None,
            Err(Stop::Flush(OutOfSpace)) => Some((9, m::FZ_OUT_OF_SPACE)),
            Err(Stop::Code(3)) => Some((1, m::FZ_OUT_OF_MEMORY)),
            Err(_) => Some((4, m::FZ_FORMAT_VIOLATED)),
        }
    } else {
        // stored entry
        stored(src, &h, encrypted, slide, &mut o, stderr)
    };
    let (crc, outsiz) = (o.crc.sum(), o.outsiz);
    if let Some((n, msg)) = failed {
        return err(uz, n, msg);
    }

    // if extended header, get it
    if g {
        if src.inp.fread(&mut h[LOCCRC..LOCCRC + 8]) != 8 {
            return err(uz, 3, m::FZ_GZIP_ENDED);
        }
    } else if h[LOCFLG] & EXTFLG != 0
        && src.inp.fread(&mut h[LOCCRC - 4..LOCCRC - 4 + EXTHDR]) != EXTHDR
    {
        return err(uz, 3, m::FZ_ZIP_ENDED);
    }

    // validate decompression
    if lg(&h[LOCCRC..]) != crc {
        return err(uz, 4, m::FZ_CRC_ERROR);
    }
    if u64::from(lg(&h[if g { LOCSIZ } else { LOCLEN }..])) != outsiz {
        return err(uz, 4, m::FZ_LENGTH_ERROR);
    }

    // check if there are more entries
    if !g && src.inp.fread(&mut h[..4]) == 4 && lg(&h) == LOCSIG {
        let _ = uz.err.write_all(m::FZ_MORE_THAN_ONE.as_bytes());
        let _ = uz.err.flush();
    }
    0
}

/// funzip.c:main's stored entry: its bytes through `slide`, flushed in
/// whole windows and once at the end. `Some((code, message))` for
/// `err()`.
fn stored(
    src: &mut Src,
    h: &[u8; LOCHDR],
    encrypted: bool,
    slide: &mut [u8],
    o: &mut Out,
    stderr: &mut dyn Write,
) -> Option<(i32, &'static str)> {
    let mut n = u64::from(lg(&h[LOCLEN..]));
    let siz = u64::from(lg(&h[LOCSIZ..]));
    // `ulg` arithmetic: an encrypted entry shorter than its header wraps
    let want = if encrypted {
        siz.wrapping_sub(RAND_HEAD_LEN as u64)
    } else {
        siz
    };
    if n != want {
        printf(
            stderr,
            m::FZ_LEN_SIZ,
            &[n.to_string().as_bytes(), siz.to_string().as_bytes()],
        );
        return Some((4, m::FZ_LENGTH_MISMATCH));
    }
    let mut outcnt = 0;
    while n > 0 {
        n -= 1;
        // `ush c = getc(G.in)`: EOF is 0xffff, whose low byte is all
        // `zdecode()` and the store keep
        let c = (src.inp.getc() & 0xff) as u8;
        slide[outcnt] = match src.keys.as_mut() {
            Some(k) => k.decrypt_byte(c),
            None => c,
        };
        outcnt += 1;
        if outcnt == WSIZE {
            // do FlushOutput()
            if o.flush(&slide[..outcnt]).is_err() {
                return Some((9, m::FZ_OUT_OF_SPACE));
            }
            outcnt = 0;
        }
    }
    // flush one last time
    if outcnt > 0 && o.flush(&slide[..outcnt]).is_err() {
        return Some((9, m::FZ_OUT_OF_SPACE));
    }
    None
}

#[cfg(test)]
mod tests;
