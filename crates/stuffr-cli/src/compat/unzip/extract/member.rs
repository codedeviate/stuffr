//! `extract.c`'s one entry: `extract_or_test_member()` (the output opened,
//! the entry decoded through `stuffr::infozip`, the file closed, the CRC
//! checked) and `set_deferred_symlink()`.
//!
//! The decoders write into `uz.slide`, the one window of the run (P13,
//! P16): it is taken out of `Uz` while a decoder holds it, and what
//! `Info()` formats meanwhile reaches its front when it comes back
//! (`Uz::info`). Everything the decoders read comes through
//! [`EntrySrc`](super::output::EntrySrc), `NEXTBYTE` over the archive's
//! buffer.

use std::cell::RefCell;

use stuffr::infozip::{self, Stop};

use super::super::fileio::{self, WSIZE, c_str};
use super::super::messages as m;
use super::super::unix::attrs::{self, SlinkEntry};
use super::super::unix::{beneath, mapname};
use super::super::{PK_COOL, PK_ERR, PK_WARN, Uz, flavour};
use super::output::{self, EntrySrc};
use super::{Ex, PK_DISK, PK_MEM3, pad22, quiet};

/// unzpriv.h's method numbers.
const STORED: u16 = 0;
const SHRUNK: u16 = 1;
const IMPLODED: u16 = 6;
const DEFLATED: u16 = 8;
const ENHDEFLATED: u16 = 9;
/// ubuntu: -DUSE_BZIP2
const BZIPPED: u16 = 12;

/// `ExtractMsg`'s `%8s`: the verb right-aligned in eight columns.
fn verb8(v: &[u8]) -> Vec<u8> {
    let mut out = vec![b' '; 8usize.saturating_sub(v.len())];
    out.extend_from_slice(v);
    out
}

/// The "extracting:" (and friends) line: `ExtractMsg` with `verb`, the
/// name as the flavour shows it, the `-a` kind and, under `-c`, a newline.
fn extract_msg(uz: &mut Uz, ex: &Ex, verb: &[u8], stored: bool) {
    let full = c_str(&uz.filename).to_vec();
    let shown = mapname::shown(uz, &full);
    let kind: &[u8] = if uz.o.aflag != 1 {
        b""
    } else if stored && uz.lrec.ucsize == 0 {
        m::KIND_EMPTY
    } else if ex.pinfo.textfile {
        m::KIND_TEXT
    } else {
        m::KIND_BINARY
    };
    let nl: &[u8] = if uz.o.cflag { b"\n" } else { b"" };
    uz.info_fmt(0, m::EXTRACT_MSG, &[&verb8(verb), &pad22(&shown), kind, nl]);
}

/// The decoder's error line: `ErrUnzipFile` (with the name) when quiet
/// enough that it was not shown yet, else `ErrUnzipNoFile`.
fn decoder_failed(uz: &mut Uz, out_of_memory: bool, what: &str) {
    let why = if out_of_memory {
        m::NOT_ENOUGH_MEM
    } else {
        m::INVALID_COMPR_DATA
    };
    if quiet(uz) {
        let name = c_str(&uz.filename).to_vec();
        let shown = fileio::fnfilter1(uz, &name);
        uz.info_fmt(
            0x401,
            m::ERR_UNZIP_FILE,
            &[why.as_bytes(), what.as_bytes(), &shown],
        );
    } else {
        uz.info_fmt(
            0x401,
            m::ERR_UNZIP_NO_FILE,
            &[why.as_bytes(), what.as_bytes()],
        );
    }
}

/// What a decoder's run ended with, before the C's per-method handling.
enum Ended {
    Ok,
    /// The C function's own nonzero return.
    Code(i32),
    /// explode.c's 5, with `G.used_csize`.
    Length(i64),
}

// port: extract.c:extract_or_test_member
/// `extract_or_test_member()`: the entry at the archive's position (its
/// local header and extra field read, `G.csize` its compressed bytes)
/// tested, written to standard output or extracted into `G.filename`.
/// Returns its PK code.
pub(crate) fn extract_or_test_member(uz: &mut Uz, ex: &mut Ex) -> i32 {
    ex.newfile = true;
    ex.crc = flate2::Crc::new();

    // If file is a (POSIX-compatible) symbolic link and we are extracting
    // to disk, prepare to restore the link.
    ex.symlnk = ex.pinfo.symlink && !uz.o.tflag && !uz.o.cflag && uz.lrec.ucsize > 0;

    if uz.o.tflag {
        if uz.o.qflag == 0 {
            let name = c_str(&uz.filename).to_vec();
            let shown = fileio::fnfilter1(uz, &name);
            uz.info_fmt(
                0,
                m::EXTRACT_MSG,
                &[&verb8(m::VERB_TEST), &pad22(&shown), b"", b""],
            );
        }
    } else if !uz.o.cflag && output::open_outfile(uz, ex) != 0 {
        return PK_DISK;
    }

    // Unpack the file.
    let mut error = decode_entry(uz, ex);
    if uz.abort.is_some() {
        return error;
    }

    // Close the file and set its date and time (not necessarily in that
    // order), and make sure the CRC checked out OK.
    if !uz.o.tflag && !uz.o.cflag {
        // don't close NULL file or stdout
        let r = attrs::close_outfile(uz, ex);
        // apple: extract.c:1984 (T10-2)
        if flavour::close_outfile_replaces_error(uz.flavour) {
            error = r;
        }
    }
    ex.outfile = None;

    // apple: extract.c:1988 (an early return before the disk-full check;
    // upstream has none: it reports a truncated file whatever the code)
    if error > PK_WARN && flavour::close_outfile_replaces_error(uz.flavour) {
        // apple: extract.c:1990
        let full = c_str(&uz.filename).to_vec();
        if let Ok((root, rel)) = mapname::target(uz, &full)
            && let Ok((d, name)) = root.parent(rel)
        {
            let _ = d.unlink(&name, false);
        }
        return error;
    }

    if ex.disk_full != 0 {
        // set by flush()
        if ex.disk_full > 1 {
            // warn user about the incomplete file
            let name = c_str(&uz.filename).to_vec();
            let shown = fileio::fnfilter1(uz, &name);
            uz.info_fmt(0x421, m::FILE_TRUNCATED, &[&shown]);
            error = PK_DISK;
        } else {
            error = PK_WARN;
        }
    }

    if error > PK_WARN {
        // don't print redundant CRC error if error already
        return error;
    }
    let crc = ex.crc.sum();
    if crc != uz.lrec.crc32 {
        // if quiet enough, we haven't output the filename yet:  do it
        if quiet(uz) {
            let name = c_str(&uz.filename).to_vec();
            let shown = fileio::fnfilter1(uz, &name);
            uz.info_fmt(0x401, m::NAME_22, &[&pad22(&shown)]);
        }
        let (a, b) = (format!("{crc:08x}"), format!("{:08x}", uz.lrec.crc32));
        uz.info_fmt(0x401, m::BAD_CRC, &[a.as_bytes(), b.as_bytes()]);
        if ex.pinfo.encrypted {
            uz.info_fmt(0x401, m::MAYBE_BAD_PASSWD, &[]);
        }
        error = PK_ERR;
    } else if uz.o.tflag {
        if let Some(ef) = ex.extra_field.clone() {
            let r = super::extra::test_extra_field(uz, &ef);
            if r > error {
                error = r;
            }
        } else if uz.o.qflag == 0 {
            uz.info_fmt(0, m::OK, &[]);
        }
    } else if uz.o.qflag == 0 && error == 0 {
        // GRR:  is stdout reset to text mode yet?
        uz.info(0, b"\n");
    }

    // ubuntu: 23-cve-2019-13232-zip-bomb-with-overlapped-entries.patch
    if flavour::skips_data_descriptor(uz.flavour) && uz.lrec.general_purpose_bit_flag & 8 != 0 {
        error = skip_data_descriptor(uz, error);
    }
    error
}

/// ubuntu: 23-cve-2019-13232-zip-bomb-with-overlapped-entries.patch: skip
/// over data descriptor (harder than it sounds, due to signature
/// ambiguity). `PK_ERR` when the archive ends first, else `error`.
fn skip_data_descriptor(uz: &mut Uz, error: i32) -> i32 {
    const SIG: u32 = 0x0807_4b50;
    const LOW: u64 = 0xffff_ffff;
    let mut buf = [0u8; 12];
    let mut shy = 12 - fileio::readbuf(uz, &mut buf);
    let word = |at: usize| {
        if shy != 0 {
            0
        } else {
            fileio::makelong(&buf[at..])
        }
    };
    let (crc, clen, ulen) = (word(0), word(4), word(8)); // ulen: or high clen if ZIP64
    let l = uz.lrec;
    let ulen_field = if uz.zip64 { l.csize >> 32 } else { l.ucsize };
    // if not SIG, no signature / if not SIG, have signature, by turns
    if crc == SIG
        && (l.crc32 != SIG
            || (clen == SIG
                && ((l.csize & LOW) != u64::from(SIG)
                    || (ulen == SIG && ulen_field != u64::from(SIG)))))
    {
        // skip four more bytes to account for signature
        shy += 4 - fileio::readbuf(uz, &mut buf[..4]);
    }
    if uz.zip64 {
        // skip eight more for ZIP64
        shy += 8 - fileio::readbuf(uz, &mut buf[..8]);
    }
    if shy != 0 { PK_ERR } else { error }
}

/// The decoder run: `uz.slide` and the archive input taken out of `Uz`
/// for it (and given back after), the flush callback and inflate's
/// messages sharing `Uz` and `Ex` through a `RefCell` (neither runs while
/// the other does).
fn run_decoder(
    uz: &mut Uz,
    ex: &mut Ex,
    decode: impl FnOnce(
        &mut EntrySrc,
        &mut [u8],
        &mut dyn FnMut(&[u8]) -> Result<(), i32>,
        &mut dyn FnMut(&'static str),
    ) -> Result<(), Stop<i32>>,
) -> Ended {
    let mut slide = std::mem::take(&mut uz.slide);
    let mut src = EntrySrc {
        zin: std::mem::take(&mut uz.zin),
        csize: uz.csize,
        keys: ex.keys.take(),
        read_error: false,
    };
    output::defer_leftover_input(&mut src.zin, &mut src.csize); // so NEXTBYTE bounds check will work
    let r = {
        let cell = RefCell::new((&mut *uz, &mut *ex));
        let mut flush = |buf: &[u8]| -> Result<(), i32> {
            let mut g = cell.borrow_mut();
            let (uz, ex) = &mut *g;
            match output::flush(uz, ex, buf, false) {
                0 => Ok(()),
                e => Err(e),
            }
        };
        let mut message = |msg: &'static str| {
            let mut g = cell.borrow_mut();
            let (uz, _) = &mut *g;
            if uz.o.qflag == 0 {
                uz.print_raw(1, msg.as_bytes());
            }
        };
        decode(&mut src, &mut slide, &mut flush, &mut message)
    };
    output::undefer_input(uz, &mut src.zin, &mut src.csize);
    uz.zin = src.zin;
    uz.csize = src.csize;
    ex.keys = src.keys;
    uz.slide = slide;
    uz.restore_slide();
    output::finish_read(uz, src.read_error);
    match r {
        Ok(()) => Ended::Ok,
        Err(Stop::Code(c)) => Ended::Code(c),
        Err(Stop::Flush(e)) => Ended::Code(e),
        Err(Stop::Length { unused }) => Ended::Length((uz.lrec.csize as i64).wrapping_sub(unused)),
    }
}

/// The stored method's loop: `NEXTBYTE` into `slide`, flushed each time it
/// fills and once more at the end.
fn unstore(
    src: &mut EntrySrc,
    slide: &mut [u8],
    flush: &mut dyn FnMut(&[u8]) -> Result<(), i32>,
) -> Result<(), Stop<i32>> {
    use stuffr::infozip::ByteSource;
    let mut outcnt = 0usize;
    let mut error = 0;
    while let Some(b) = src.next_byte() {
        slide[outcnt] = b;
        outcnt += 1;
        if outcnt == WSIZE {
            let r = flush(&slide[..outcnt]);
            outcnt = 0;
            if let Err(e) = r {
                error = e;
                break;
            }
        }
    }
    if outcnt > 0 {
        // flush final (partial) buffer
        if let Err(r) = flush(&slide[..outcnt])
            && error < r
        {
            error = r;
        }
    }
    if error != 0 {
        Err(Stop::Flush(error))
    } else {
        Ok(())
    }
}

/// `UZbunzip2()`'s `DESTROYGLOBALS(); EXIT(PK_MEM3)` (its final loop's
/// answer to an error it has no case for), as the decoder's code: the
/// caller ends the run.
const BZ_EXIT_PK_MEM3: i32 = -PK_MEM3;

// port: extract.c:UZbunzip2
/// ubuntu: -DUSE_BZIP2. The entry's bzip2 stream decoded as the C drives
/// libbzip2 (`stuffr::bzip2_stream::RawStream`, one `BZ2_bzDecompress` a
/// call, R1): straight from the archive's buffer (`G.inptr`, `G.incnt`,
/// refilled by `fillinbuf()`) into `slide`, flushed each time the window
/// fills and once more after the input runs out, then after each call of
/// the final loop. Returns the C's code: 2 for bad data or no data, 3 for
/// memory, a flush's own, or [`BZ_EXIT_PK_MEM3`].
///
/// ruling: T13-2. Two of the C's loops never end once a call can make no
/// more progress: the first, when a call consumes and produces nothing
/// while input is still there (a `BZ_SEQUENCE_ERROR` after the stream
/// ended, its trailing bytes left), and the final one, when the input ran
/// out before the stream's end (`BZ_OK` for ever). probe: `timeout 10
/// unzip -t` of a stream cut in half (in one buffer, and across many)
/// and of a stream followed by 20000 bytes in its entry: killed at 10 s,
/// `testing: s.txt` printed, nothing more. A call with nothing to consume
/// and the same window is the same call (libbzip2 is a state machine), so
/// here such a call ends the decode as running out of data does: 2, the
/// "invalid compressed data to bunzip" answer (T10-9 and T11-4 rule the
/// same way on the C's other endless loops). Pinned by
/// `extract::tests::bzip2_rulings`.
///
/// ruling: T13-3. libbz2-rs-sys reads up to 7 bytes ahead of libbzip2
/// into its 64-bit bit buffer (not across a stream's end), so `next_in`
/// can run ahead of the C's within a stream. What is decoded, and every
/// error, is libbzip2's, and so is every answer here but one: a bad magic
/// whose search (libbzip2 keeps looking for `BZh` + digit) is still
/// running when the entry's last block is read can reach the final loop
/// (exit 6) a few calls before or after the C does. Not reproduced.
fn bunzip2(
    src: &mut EntrySrc,
    slide: &mut [u8],
    flush: &mut dyn FnMut(&[u8]) -> Result<(), i32>,
) -> Result<(), Stop<i32>> {
    use stuffr::bzip2_stream::{RawStream, StreamError};
    // ubuntu: 15-cve-2015-7697.patch
    if src.zin.incnt <= 0 && src.csize <= 0 {
        // avoid an infinite loop
        return Err(Stop::Code(2));
    }
    let wsize = WSIZE;
    let mut next_out = 0usize; // avail_out = wsize - next_out
    let mut next_in = src.zin.inptr;
    // ruling: `bstrm.avail_in = G.incnt` of a negative count (a failed
    // read before the entry) is a huge unsigned length over the buffer's
    // end; here it is 0.
    let mut avail_in = src.zin.incnt.max(0) as usize;
    // BZ2_bzDecompressInit(&bstrm, 0, 0): no allocation can fail here
    let mut bstrm = RawStream::new();
    // `err`: the last call's answer, `BZ_OK` (`Ok(false)`) to begin with
    let mut err: Result<bool, StreamError> = Ok(false);

    let call = |bstrm: &mut RawStream,
                src: &EntrySrc,
                slide: &mut [u8],
                next_in: &mut usize,
                avail_in: &mut usize,
                next_out: &mut usize|
     -> (bool, Result<bool, StreamError>) {
        let end = (*next_in + *avail_in).min(src.zin.inbuf.len());
        let input = &src.zin.inbuf[(*next_in).min(end)..end];
        let (c, p, r) = bstrm.decompress_counted(input, &mut slide[*next_out..wsize]);
        *next_in += c;
        *avail_in -= c;
        *next_out += p;
        (c > 0 || p > 0, r)
    };

    while src.csize > 0 {
        while next_out < wsize {
            let (progress, r) = call(
                &mut bstrm,
                src,
                slide,
                &mut next_in,
                &mut avail_in,
                &mut next_out,
            );
            err = r;
            match &err {
                Err(StreamError::Data) => return Err(Stop::Code(2)),
                Err(StreamError::Memory) => return Err(Stop::Code(3)),
                // "oops!  (bzip(first loop) err = %d)": a Trace only
                _ => {}
            }
            if src.csize <= 0 {
                // "END-of-entry-condition" ?
                break;
            }
            if avail_in == 0 {
                if src.fillinbuf() == 0 {
                    // no "END-condition" yet, but no more data
                    return Err(Stop::Code(2));
                }
                next_in = src.zin.inptr;
                avail_in = src.zin.incnt.max(0) as usize;
            } else if !progress {
                // ruling: T13-2 (the C calls again for ever)
                return Err(Stop::Code(2));
            }
        }
        // flush slide[]
        flush(&slide[..next_out]).map_err(Stop::Flush)?;
        next_out = 0;
    }

    // no more input, so loop until we have all output
    while !matches!(err, Ok(true)) {
        let (progress, r) = call(
            &mut bstrm,
            src,
            slide,
            &mut next_in,
            &mut avail_in,
            &mut next_out,
        );
        err = r;
        match &err {
            Err(StreamError::Data) => return Err(Stop::Code(2)),
            Err(StreamError::Memory) => return Err(Stop::Code(3)),
            // "oops!  (bzip(final loop) err = %d)"
            Err(_) => return Err(Stop::Code(BZ_EXIT_PK_MEM3)),
            Ok(false) if !progress => {
                // ruling: T13-2 (the C calls again for ever)
                return Err(Stop::Code(2));
            }
            Ok(_) => {}
        }
        // final flush of slide[]
        flush(&slide[..next_out]).map_err(Stop::Flush)?;
        next_out = 0;
    }

    src.zin.inptr = next_in;
    // ubuntu: 25-cve-2019-13232-fix-bug-in-uzbunzip2.patch
    src.zin.incnt -= next_in as i64; // reset for other routines
    Ok(())
}

// port: extract.c:extract_or_test_member
/// The entry's data decoded by its method (`G.lrec.compression_method`):
/// stored, shrunk (1), imploded (6), deflated (8), deflate64 (9) or, in
/// the Ubuntu flavour, bzip2 (12), each announced by its
/// "extracting:"/"inflating:"/... line, each failure by the C's message.
/// Any other method is "unknown compression method", `PK_WARN`
/// (`store_info()` has already refused them). Returns the PK code.
pub(crate) fn decode_entry(uz: &mut Uz, ex: &mut Ex) -> i32 {
    let announce = !uz.o.tflag && uz.o.qflag == 0;
    match uz.lrec.compression_method {
        STORED => {
            if announce {
                let verb = if ex.symlnk {
                    m::VERB_LINK
                } else {
                    m::VERB_EXTRACT
                };
                extract_msg(uz, ex, verb, true);
            }
            match run_decoder(uz, ex, |src, slide, flush, _| unstore(src, slide, flush)) {
                Ended::Ok => PK_COOL,
                Ended::Code(e) => e,
                Ended::Length(_) => PK_COOL,
            }
        }
        SHRUNK => {
            if announce {
                extract_msg(uz, ex, m::VERB_UNSHRINK, false);
            }
            match run_decoder(uz, ex, |src, slide, flush, _| {
                infozip::unshrink(src, slide, flush)
            }) {
                Ended::Ok | Ended::Length(_) => PK_COOL,
                Ended::Code(r) => {
                    if r < PK_DISK {
                        decoder_failed(uz, r == PK_MEM3, m::UNSHRINK);
                    }
                    r
                }
            }
        }
        IMPLODED => {
            if announce {
                extract_msg(uz, ex, m::VERB_EXPLOD, false);
            }
            let (flags, ucsize) = (uz.lrec.general_purpose_bit_flag, uz.lrec.ucsize);
            match run_decoder(uz, ex, |src, slide, flush, _| {
                infozip::explode(src, flags, ucsize, slide, flush)
            }) {
                Ended::Ok => PK_COOL,
                Ended::Length(used_csize) => {
                    // treat 5 specially
                    let warning = (used_csize as u64) <= uz.lrec.csize;
                    let what: &[u8] = if warning { b"warning" } else { b"error" };
                    let pad: &[u8] = if warning { b"  " } else { b"" };
                    let (used, uc, cs) = (
                        used_csize.to_string(),
                        uz.lrec.ucsize.to_string(),
                        uz.lrec.csize.to_string(),
                    );
                    if quiet(uz) {
                        let name = c_str(&uz.filename).to_vec();
                        let shown = fileio::fnfilter1(uz, &name);
                        uz.info_fmt(
                            0x401,
                            m::LENGTH_MSG,
                            &[
                                b"",
                                what,
                                used.as_bytes(),
                                uc.as_bytes(),
                                pad,
                                cs.as_bytes(),
                                b" [",
                                &shown,
                                b"]",
                            ],
                        );
                    } else {
                        uz.info_fmt(
                            0x401,
                            m::LENGTH_MSG,
                            &[
                                b"\n",
                                what,
                                used.as_bytes(),
                                uc.as_bytes(),
                                pad,
                                cs.as_bytes(),
                                b"",
                                b"",
                                b".",
                            ],
                        );
                    }
                    if warning { PK_WARN } else { PK_ERR }
                }
                Ended::Code(r) if r < PK_DISK => {
                    decoder_failed(uz, r == 3, m::EXPLODE);
                    if r == 3 { PK_MEM3 } else { PK_ERR }
                }
                Ended::Code(r) => r,
            }
        }
        method @ (DEFLATED | ENHDEFLATED) => {
            if announce {
                extract_msg(uz, ex, m::VERB_INFLAT, false);
            }
            let deflate64 = method == ENHDEFLATED;
            match run_decoder(uz, ex, |src, slide, flush, message| {
                infozip::inflate(src, deflate64, slide, flush, message)
            }) {
                Ended::Ok | Ended::Length(_) => PK_COOL,
                Ended::Code(r) if r < PK_DISK => {
                    decoder_failed(uz, r == 3, m::INFLATE);
                    if r == 3 { PK_MEM3 } else { PK_ERR }
                }
                Ended::Code(r) => r,
            }
        }
        // ubuntu: -DUSE_BZIP2
        BZIPPED if flavour::use_bzip2(uz.flavour) => {
            if announce {
                extract_msg(uz, ex, m::VERB_BUNZIPP, false);
            }
            match run_decoder(uz, ex, |src, slide, flush, _| bunzip2(src, slide, flush)) {
                Ended::Ok | Ended::Length(_) => PK_COOL,
                Ended::Code(BZ_EXIT_PK_MEM3) => {
                    uz.exit_run(PK_MEM3);
                    PK_MEM3
                }
                Ended::Code(r) if r < PK_DISK => {
                    decoder_failed(uz, r == 3, m::BUNZIP);
                    if r == 3 { PK_MEM3 } else { PK_ERR }
                }
                Ended::Code(r) => r,
            }
        }
        _ => {
            // should never get to this point
            let name = c_str(&uz.filename).to_vec();
            let shown = fileio::fnfilter1(uz, &name);
            uz.info_fmt(0x401, m::FILE_UNKNOWN_COMP_METHOD, &[&shown]);
            // (close and delete file before return? no: as the C)
            PK_WARN
        }
    }
}

// port: extract.c:set_deferred_symlink
/// `set_deferred_symlink()`: the placeholder checked (it must still hold
/// exactly the target), removed, and the symlink made in its place, with
/// the archive's quarantine (R9) and its attributes. `PK_ERR` on a failure
/// (counted by Apple's tree only).
pub(crate) fn set_deferred_symlink(uz: &mut Uz, s: &SlinkEntry) -> i32 {
    use std::io::Read;
    let ucsize = s.target.len();
    let placeholder = mapname::target(uz, &s.fname).and_then(|(root, rel)| {
        let f = beneath::open_beneath(root, rel, false)?;
        let (d, name) = root.parent(rel)?;
        Ok((d, name, f))
    });
    // Check that the following conditions are all fulfilled: a) the
    // placeholder file exists, b) the placeholder file contains exactly
    // "ucsize" bytes, c) the placeholder content matches the link target
    // specification as stored in the symlink control structure.
    let ok = match placeholder {
        Ok((d, name, f)) => {
            let mut got = Vec::new();
            let read = f.take(ucsize as u64 + 1).read_to_end(&mut got);
            if matches!(read, Ok(n) if n == ucsize) && c_str(&got) == &s.target[..] {
                Some((d, name))
            } else {
                None
            }
        }
        Err(_) => None,
    };
    let Some((dir, name)) = ok else {
        let shown = fileio::fnfilter1(uz, &s.fname);
        uz.info_fmt(0x201, m::SYM_LNK_WARN_INVALID, &[&shown]);
        return PK_ERR;
    };
    // close and delete placeholder file
    let _ = dir.unlink(&name, false);
    if uz.o.qflag == 0 {
        let shown1 = mapname::shown(uz, &s.fname);
        let shown2 = fileio::fnfilter2(uz, &s.target);
        uz.info_fmt(0, m::SYM_LNK_FINISH, &[&pad22(&shown1), &shown2]);
    }
    if let Err(e) = dir.symlink(&s.target, &name) {
        mapname::perror(uz, m::SYMLINK_ERROR, &e);
        return PK_ERR;
    }
    if let Err(e) = attrs::quarantine_symlink(uz, &dir, &name) {
        // apple: extract.c:2635
        mapname::perror(uz, m::SYMLINK_ERROR, &e);
        let _ = dir.unlink(&name, false);
        return PK_ERR;
    }
    attrs::set_symlnk_attribs(uz, s);
    PK_COOL // can't set time on symlinks
}
