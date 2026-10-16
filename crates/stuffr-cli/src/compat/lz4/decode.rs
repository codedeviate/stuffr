//! One input's stream of lz4 frames, as lz4 1.10.0 reads it: modern frames
//! (through liblz4's frame decoder, or the pure tier's), legacy frames,
//! skippable frames, and whatever follows them.
//!
//! **Clean room.** The rules were recovered by probing the 1.10.0 binary
//! with hand-made streams (Task 2's rows, Task 4's probes; lz4's
//! `programs/` was never read):
//! - A magic number is read at the start and after each legacy or
//!   skippable frame. No bytes at all end the input (an empty file decodes
//!   to nothing, exit 0); one to three are `Error 40`.
//! - A **modern frame** hands the rest of the input to the frame decoder,
//!   which reads frame after frame (and skippable frames) to the end of the
//!   input: what follows a modern frame is judged by liblz4 (`frame` then
//!   legacy, or then 8 zeros, is `Error 34 : ... ERROR_frameType_unknown`;
//!   a frame cut short, or 1 to 6 bytes after one, is `Error 26`).
//!   Probed on a pipe and with the frame ending at 64 KiB, 128 KiB, 4 MiB
//!   and 16 MiB: always so.
//! - A **legacy frame** ends at the end of the input or at a word too large
//!   to be a block size, which is read as the next magic number
//!   (`LegacyDecoder`'s contract).
//! - A **skippable frame** is seeked over in a file (past its end is no
//!   error) and read over elsewhere (ending early is `Error 43`).
//! - An unknown magic number first in the input is `Error 44`, or, under
//!   `-f` with standard output as the output (`lz4cat`, `lz4 -dcf`), the
//!   whole input is copied as it is. After a legacy or skippable frame it
//!   is "Stream followed by undecodable data" at display level 2: the
//!   input is finished (summary, `--rm`) and counts as failed.
//!
//! **Memory** (Review Focus 1 and 4): the decoder is fed small slices
//! ([`FEED`]) and what each call decodes goes to the output before the
//! next, so a call yields at most about one block (4 MiB for a frame,
//! 8 MiB for a legacy block). Every block-size word is checked against its
//! frame's maximum (or `LZ4_compressBound(8 MiB)`) before anything is
//! reserved for it: `stuffr::lz4_opts`.

use stuffr::lz4_opts::{
    DecodeOptions, Decoder, LEGACY_MAGIC, LegacyDecoder, Lz4Error, Lz4fError, MAGIC,
    is_skippable_magic,
};

use super::display::show_decode_progress;
use super::io::{Fail, Run, Sink, Src};
use super::messages as m;

/// Input handed to a decoder per call: small, so that what one call
/// decodes stays about one block whatever the input's ratio.
const FEED: usize = 4 << 10;

/// What one input decoded to.
pub(super) struct Decoded {
    /// Bytes read from the input.
    pub read: u64,
    /// Bytes decoded (written, or discarded under `-t`).
    pub written: u64,
    /// Undecodable bytes followed the last frame (module doc).
    pub undecodable: bool,
}

/// A little-endian word.
fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Decode `src` into `sink`; `passthrough` copies an input that does not
/// start with a known magic number.
pub(super) fn stream(
    run: &mut Run,
    src: &mut Src,
    sink: &mut Sink,
    passthrough: bool,
) -> Result<Decoded, Fail> {
    let mut d = Decoded {
        read: 0,
        written: 0,
        undecodable: false,
    };
    let mut shown = None;
    let mut first = true;
    loop {
        let head = src.fill(4);
        if head.is_empty() {
            break;
        }
        if head.len() < 4 {
            return Err(run.exm(40, m::E40_MAGIC_UNREADABLE, &[]));
        }
        let magic_bytes = [head[0], head[1], head[2], head[3]];
        let magic = le32(&magic_bytes);
        src.consume(4);
        if is_skippable_magic(magic) {
            run.say(4, m::SKIPPABLE_DETECTED, &[]);
            let size = src.fill(4);
            if size.len() < 4 {
                return Err(run.exm(42, m::E42_SKIPPABLE_SIZE, &[]));
            }
            let n = le32(size);
            src.consume(4);
            if !src.skip(u64::from(n)) {
                return Err(run.exm(43, m::E43_SKIP, &[]));
            }
        } else if magic == LEGACY_MAGIC {
            run.say(4, m::LEGACY_DETECTED, &[]);
            legacy(run, src, sink, &mut d)?;
        } else if magic == MAGIC {
            modern(run, src, sink, &magic_bytes, &mut d, &mut shown)?;
            break;
        } else if first && passthrough {
            sink.write(run, &magic_bytes)?;
            d.written += 4;
            loop {
                let rest = src.fill(1);
                if rest.is_empty() {
                    break;
                }
                let n = rest.len();
                sink.write(run, rest)?;
                src.consume(n);
                d.written += n as u64;
            }
            break;
        } else if first {
            return Err(run.exm(44, m::E44_UNRECOGNIZED, &[]));
        } else {
            run.say(2, m::UNDECODABLE, &[]);
            if src.seekable {
                let at = src.taken().to_string();
                run.say(2, m::AT_POSITION, &[at.as_bytes()]);
            }
            run.say(2, m::NEWLINE, &[]);
            d.undecodable = true;
            break;
        }
        first = false;
    }
    d.read = src.taken();
    Ok(d)
}

/// A modern frame and everything after it (module doc). `magic` has been
/// read already and is fed first.
fn modern(
    run: &mut Run,
    src: &mut Src,
    sink: &mut Sink,
    magic: &[u8; 4],
    d: &mut Decoded,
    shown: &mut Option<u64>,
) -> Result<(), Fail> {
    let opts = DecodeOptions {
        dictionary: run.dict.clone(),
    };
    let Ok(mut dec) = Decoder::new(&opts) else {
        let name = Lz4fError::AllocationFailed.name();
        return Err(run.exm(34, m::E34_DECOMPRESSION, &[name.as_bytes()]));
    };
    let mut out = Vec::new();
    let mut hint = match dec.decompress(magic, &mut out) {
        Ok((_, hint)) => hint,
        Err(e) => return Err(failed(run, &e)),
    };
    loop {
        let avail = src.fill(1);
        if avail.is_empty() {
            break;
        }
        let take = avail.len().min(FEED);
        let r = dec.decompress(&avail[..take], &mut out);
        // What was decoded before a fault is written (deviation list).
        let consumed = r.as_ref().map_or(0, |&(n, _)| n);
        src.consume(consumed);
        sink.write(run, &out)?;
        d.written += out.len() as u64;
        out.clear();
        show_decode_progress(run, d.written, true, shown);
        match r {
            // The guard against an endless loop: both backends consume
            // input until the frame ends or the input given is used up (C:
            // LZ4F_decompress always takes bytes when it has output room,
            // and the decoder loops with a fresh 256 KiB scratch; pure: every
            // stage gathers bytes before it acts), so with a nonempty slice
            // nothing consumed cannot happen; if it ever did, the frame is
            // unfinishable, which is Error 26's meaning.
            Ok((0, _)) => return Err(run.exm(26, m::E26_INCOMPLETE, &[])),
            Ok((_, h)) => hint = h,
            Err(e) => return Err(failed(run, &e)),
        }
    }
    // probe: a frame cut short, or bytes after one too few for a header.
    if hint != 0 {
        return Err(run.exm(26, m::E26_INCOMPLETE, &[]));
    }
    Ok(())
}

/// `Error 34` with liblz4's name for the fault.
fn failed(run: &mut Run, e: &Lz4Error) -> Fail {
    let name = match e {
        Lz4Error::Lib(e) => e.name(),
        Lz4Error::Io(_) => Lz4fError::IoRead.name(),
    };
    run.exm(34, m::E34_DECOMPRESSION, &[name.as_bytes()])
}

/// A legacy frame, its magic read already. It ends at the end of the input
/// or before the word that ended it, which is left in `src`.
fn legacy(run: &mut Run, src: &mut Src, sink: &mut Sink, d: &mut Decoded) -> Result<(), Fail> {
    let mut dec = LegacyDecoder::new();
    let mut out = Vec::new();
    // The magic number, already checked.
    if dec
        .decompress(&LEGACY_MAGIC.to_le_bytes(), &mut out)
        .is_err()
    {
        return Err(run.exm(64, m::E64_LEGACY_DECODE, &[]));
    }
    loop {
        let avail = src.fill(4);
        if avail.is_empty() {
            if dec.at_block_boundary() {
                return Ok(());
            }
            // probe: `lz4 -t leg_blk_trunc.lz4`, `leg_8m.lz4`.
            return Err(run.exm(63, m::E63_LEGACY_BLOCK, &[]));
        }
        let take = avail.len().min(FEED);
        let r = dec.decompress(&avail[..take], &mut out);
        let (consumed, hint) = match r {
            Ok(v) => v,
            // probe: `lz4 -t leg_bad.lz4`, `lz4 -t legzero.lz4`.
            Err(_) => return Err(run.exm(64, m::E64_LEGACY_DECODE, &[])),
        };
        src.consume(consumed);
        if !out.is_empty() {
            sink.write(run, &out)?;
            d.written += out.len() as u64;
            out.clear();
            // Every block is a chance (probe: `lz4 -vv -t two_legacy.lz4`
            // draws a refresh after each frame, `Decompressed : 0 MiB` both
            // times; the gate keeps the count down at levels 2 and 3).
            show_decode_progress(run, d.written, false, &mut None);
        }
        if hint == 0 {
            return Ok(());
        }
        // LegacyDecoder's contract: (0, 4) asks for these bytes again with
        // more after them. `fill(4)` gave fewer than four only because the
        // input ended: a size word cut short (probe: `lz4 -t
        // leg_garbage.lz4`, legacy then three bytes).
        if consumed == 0 && take < 4 {
            return Err(run.exm(61, m::E61_LEGACY_SIZE, &[]));
        }
    }
}
