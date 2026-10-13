//! Raw deflate through C zlib (`libz-sys`, statically built from its vendored
//! source), behind the `zlib-c` feature.
//!
//! This exists for one promise: the Apple gzip personality's output is
//! byte-identical to macOS's `/usr/bin/gzip`, which is stock zlib driven as
//! `deflateInit2(level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY)`. miniz_oxide
//! makes a valid stream with different bytes, so the C tier needs zlib's own
//! encoder. flate2's backend is untouched — it stays miniz_oxide everywhere;
//! this module talks to `libz-sys` directly and nothing else uses it.
//!
//! Miri cannot run FFI; `make miri` builds this crate with `--features tar,ar`
//! only, so this module is never compiled there.

use std::alloc::{self, Layout};
use std::ffi::{c_int, c_uint};
use std::io::{self, Write};
use std::ptr;

use libz_sys as z;

const OUT_CHUNK: usize = 64 * 1024;

/// Header in front of every block [`zalloc`] hands out, holding its total
/// size so [`zfree`] can rebuild the `Layout`. 16 keeps the returned pointer
/// at `malloc`'s alignment, which zlib assumes.
const HDR: usize = 16;

/// zlib's allocation callback, over Rust's allocator. libz-sys declares
/// `zalloc`/`zfree` as non-nullable function pointers, so zlib's own default
/// (a null `zalloc`) cannot be spelled; this is the replacement. Memory is
/// zeroed, as `calloc` would give, so nothing zlib reads is uninitialised.
///
/// # Safety
/// Called by zlib only, with the contract of `alloc_func`.
unsafe extern "C" fn zalloc(_opaque: z::voidpf, items: z::uInt, size: z::uInt) -> z::voidpf {
    let Some(total) = (items as usize)
        .checked_mul(size as usize)
        .and_then(|n| n.checked_add(HDR))
    else {
        return ptr::null_mut();
    };
    let Ok(layout) = Layout::from_size_align(total, HDR) else {
        return ptr::null_mut();
    };
    // SAFETY: `layout` has a non-zero size (at least `HDR`).
    let base = unsafe { alloc::alloc_zeroed(layout) };
    if base.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `base` is a fresh allocation of at least `HDR` bytes aligned
    // to 16, so writing a `usize` at its start and offsetting by `HDR` stay
    // inside it.
    unsafe {
        base.cast::<usize>().write(total);
        base.add(HDR).cast()
    }
}

/// zlib's free callback, the inverse of [`zalloc`].
///
/// # Safety
/// `address` is null or a pointer [`zalloc`] returned and not yet freed.
unsafe extern "C" fn zfree(_opaque: z::voidpf, address: z::voidpf) {
    if address.is_null() {
        return;
    }
    // SAFETY: `address` came from `zalloc`, so `HDR` bytes before it is the
    // start of the block, holding the total size that built its `Layout`
    // (already validated there, hence `from_size_align_unchecked`).
    unsafe {
        let base = address.cast::<u8>().sub(HDR);
        let total = base.cast::<usize>().read();
        alloc::dealloc(base, Layout::from_size_align_unchecked(total, HDR));
    }
}

fn zlib_error(what: &str, code: c_int) -> io::Error {
    io::Error::other(format!("zlib {what} failed ({code})"))
}

/// Raw deflate (no zlib/gzip framing) through C zlib:
/// `deflateInit2(level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY)`
/// ([`RawDeflate::with_options`] takes other `windowBits`).
///
/// Writes are `Z_NO_FLUSH`; [`Write::flush`] flushes only the inner writer
/// (a zlib sync flush would change the bytes). [`RawDeflate::finish`] ends
/// the stream and returns the writer; dropping without finishing releases
/// zlib's state without writing the end.
pub struct RawDeflate<W: Write> {
    /// Boxed so it never moves: zlib's internal state holds a pointer back to
    /// it, and `deflate` checks that pointer on every call.
    stream: Box<z::z_stream>,
    /// `Some` until `finish` takes it.
    out: Option<W>,
    buf: Vec<u8>,
    /// Whether `deflateEnd` is still owed (set by a successful init).
    live: bool,
    /// Set when a `deflate` call or a write of its output fails. zlib has
    /// already consumed the input by then and the output may be half
    /// written, so the stream is corrupt: every later `write` and `finish`
    /// refuses rather than emit a silently broken stream.
    poisoned: bool,
}

impl<W: Write> RawDeflate<W> {
    /// A raw-deflate encoder at `level`, 0..=9 (0 is zlib's stored
    /// blocks, which the zstd family's `--format=gzip -0` asks for); any
    /// other level is `InvalidInput`.
    pub fn new(out: W, level: u32) -> io::Result<Self> {
        Self::with_options(out, level, -15, OUT_CHUNK)
    }

    /// As [`RawDeflate::new`], with zlib's `windowBits` (`-15` raw, `31`
    /// gzip: zlib writes the header and trailer itself, as the zstd
    /// family's `--format=gzip` has `deflateInit2` write them) and the size
    /// of the output buffer each `deflate` call gets, which decides the
    /// stored blocks of level 0 (`deflate_stored` copies as much as the
    /// output has room for). `windowBits` outside zlib's ranges is zlib's
    /// `Z_STREAM_ERROR`; a zero `chunk` is `InvalidInput`.
    pub fn with_options(out: W, level: u32, window_bits: i32, chunk: usize) -> io::Result<Self> {
        if chunk == 0 || u32::try_from(chunk).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("deflate output buffer of {chunk} bytes"),
            ));
        }
        if level > 9 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("deflate level {level} is outside 0..=9"),
            ));
        }
        let mut stream = Box::new(z::z_stream {
            next_in: ptr::null_mut(),
            avail_in: 0,
            total_in: 0,
            next_out: ptr::null_mut(),
            avail_out: 0,
            total_out: 0,
            msg: ptr::null_mut(),
            state: ptr::null_mut(),
            zalloc,
            zfree,
            opaque: ptr::null_mut(),
            data_type: 0,
            adler: 0,
            reserved: 0,
        });
        // SAFETY: `stream` is a fully initialised `z_stream` on the heap with
        // valid allocator callbacks; the version and size are libz-sys's own,
        // as `deflateInit2_` requires. On failure zlib frees what it allocated.
        let rc = unsafe {
            z::deflateInit2_(
                &mut *stream,
                level as c_int,
                z::Z_DEFLATED,
                window_bits as c_int,
                8,
                z::Z_DEFAULT_STRATEGY,
                z::zlibVersion(),
                size_of::<z::z_stream>() as c_int,
            )
        };
        if rc != z::Z_OK {
            return Err(match rc {
                z::Z_MEM_ERROR => io::Error::new(io::ErrorKind::OutOfMemory, "zlib deflateInit2"),
                _ => zlib_error("deflateInit2", rc),
            });
        }
        Ok(RawDeflate {
            stream,
            out: Some(out),
            buf: vec![0; chunk],
            live: true,
            poisoned: false,
        })
    }

    /// One `deflate` call over `input` with `flush`, writing whatever it
    /// produced. Returns (zlib's code, bytes consumed, bytes produced).
    fn step(&mut self, input: &[u8], flush: c_int) -> io::Result<(c_int, usize, usize)> {
        if self.poisoned {
            return Err(io::Error::other(
                "deflate stream unusable after an earlier write error",
            ));
        }
        let res = self.step_inner(input, flush);
        if res.is_err() {
            self.poisoned = true;
        }
        res
    }

    fn step_inner(&mut self, input: &[u8], flush: c_int) -> io::Result<(c_int, usize, usize)> {
        let avail_in = c_uint::try_from(input.len()).unwrap_or(c_uint::MAX);
        self.stream.next_in = input.as_ptr().cast_mut();
        self.stream.avail_in = avail_in;
        self.stream.next_out = self.buf.as_mut_ptr();
        self.stream.avail_out = self.buf.len() as c_uint;
        // SAFETY: the stream was initialised by `deflateInit2_` and not ended
        // (`live`); `next_in` covers `avail_in` readable bytes of `input`,
        // which zlib only reads, and `next_out` covers `avail_out` writable
        // bytes of `self.buf`. Both stay valid for the call's duration.
        let rc = unsafe { z::deflate(&mut *self.stream, flush) };
        let used = (avail_in - self.stream.avail_in) as usize;
        let made = self.buf.len() - self.stream.avail_out as usize;
        // Leave no pointer into the caller's buffer behind.
        self.stream.next_in = ptr::null_mut();
        self.stream.avail_in = 0;
        if made > 0 {
            let out = self.out.as_mut().expect("writer present until finish");
            out.write_all(&self.buf[..made])?;
        }
        match rc {
            // `Z_BUF_ERROR` is "no progress possible": not an error, the
            // caller decides whether more output space or input is needed.
            z::Z_OK | z::Z_STREAM_END | z::Z_BUF_ERROR => Ok((rc, used, made)),
            _ => Err(zlib_error("deflate", rc)),
        }
    }

    /// End the stream (`Z_FINISH`), release zlib's state, and return the
    /// writer. The writer is not flushed.
    pub fn finish(mut self) -> io::Result<W> {
        loop {
            let (rc, _, made) = self.step(&[], z::Z_FINISH)?;
            if rc == z::Z_STREAM_END {
                break;
            }
            if rc == z::Z_BUF_ERROR && made == 0 {
                self.poisoned = true;
                return Err(zlib_error("deflate (finish, no progress)", rc));
            }
        }
        self.end();
        Ok(self.out.take().expect("writer present until finish"))
    }

    /// `deflateEnd`, exactly once.
    fn end(&mut self) {
        if self.live {
            self.live = false;
            // SAFETY: the stream was initialised and has not been ended
            // (`live` was true); after this it is never passed to zlib again.
            // The return code only reports a stream ended early, which is
            // what a drop without finish is; nothing to do about it.
            unsafe {
                z::deflateEnd(&mut *self.stream);
            }
        }
    }
}

impl<W: Write> Write for RawDeflate<W> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() && !self.poisoned {
            return Ok(0);
        }
        loop {
            let (rc, used, made) = self.step(input, z::Z_NO_FLUSH)?;
            if used > 0 {
                return Ok(used);
            }
            // Nothing consumed: the output buffer filled and has been
            // written out, so go again. Only no progress at all is a fault.
            if rc == z::Z_BUF_ERROR && made == 0 {
                self.poisoned = true;
                return Err(zlib_error("deflate (no progress)", rc));
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out
            .as_mut()
            .expect("writer present until finish")
            .flush()
    }
}

impl<W: Write> Drop for RawDeflate<W> {
    fn drop(&mut self) {
        self.end();
    }
}
