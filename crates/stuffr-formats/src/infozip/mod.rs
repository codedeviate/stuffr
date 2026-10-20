//! Info-ZIP UnZip 6.0's own decoders, ported for the `stuffr` binary's unzip
//! compatibility family (`unzip`, `zipinfo`, `funzip`), which has to fail on
//! corrupt input exactly where unzip does and leave the same partial output
//! behind. Reached through `stuffr::infozip` only; not part of the public
//! surface.
//!
//! **Licence.** Everything under this module is ported from Info-ZIP UnZip
//! 6.0 (`crypt.c`, `inflate.c`, `explode.c` and `unshrink.c`) and stays
//! under the Info-ZIP licence, version 2009-Jan-02, reproduced in this
//! crate's `LICENSE-infozip`. It is an altered version in that
//! licence's clause 3 sense: a port to Rust, not Info-ZIP's source, and not
//! an Info-ZIP release. Every ported function carries a
//! `// port: <file>.c:<function>` comment naming its original.
//!
//! **The seam.** A decoder reads the entry's bytes through [`ByteSource`]
//! (unzip's `NEXTBYTE`, already decrypted by [`crypt`] where the entry is
//! encrypted), writes only through a flush callback, and reports an early
//! stop as [`Stop`], carrying the C function's own return code unchanged.
//! [`inflate()`] also takes a `message` callback: `inflate.c` prints
//! `(incomplete l-tree)  ` or `(incomplete d-tree)  ` through `MESSAGE`
//! before it stops with code 1, which `unzip -t` shows inside its
//! `testing:` line (probed on both references), and the flush callback
//! cannot carry it. And it takes the caller's `window` (unzip's `slide[]`,
//! at least [`WSIZE`] bytes), which persists across entries in unzip: a
//! corrupt distance reaching before an entry's first byte copies whatever
//! that window holds, never rejected (`inflate.c:1012`).
//!
//! [`explode()`] and [`unshrink()`] take the same window: explode decodes
//! in it as inflate does (but zero-fills, never reads, what lies before the
//! entry's first byte), and unshrink keeps its tables in it, where unzip's
//! `G.area` union puts them over `slide[]`. Neither prints anything, so
//! neither takes a `message`. Explode stops on the uncompressed size and
//! then checks the compressed size, which is why [`ByteSource`] reports
//! [`remaining`](ByteSource::remaining) bytes and [`Stop`] has a
//! [`Length`](Stop::Length) case; unshrink stops at the end of the data and
//! takes no size at all.

pub mod crypt;
mod explode;
mod inflate;
mod unshrink;

pub use explode::explode;
pub use inflate::{INCOMPLETE_D_TREE, INCOMPLETE_L_TREE, WSIZE, inflate};
pub use unshrink::unshrink;

#[cfg(test)]
mod tests;

/// What a decoder reads: unzip's `NEXTBYTE` over `csize` bytes of the entry
/// (already decrypted). `None` is unzip's EOF (`csize` exhausted, or a read
/// error the caller remembers and reports itself). Once it has returned
/// `None` it must keep doing so, as unzip's `readbyte()` does: the decoders'
/// read-beyond-EOF tolerance relies on it.
pub trait ByteSource {
    /// The next byte of the entry, or `None` at unzip's EOF.
    fn next_byte(&mut self) -> Option<u8>;

    /// unzip's `G.csize + G.incnt` before any EOF: the entry's compressed
    /// bytes not yet returned. It is 0 once `next_byte` has returned `None`
    /// at the end of the entry's data; a `None` while it is still positive
    /// is a read that came up short (a truncated archive: `read()` gave 0),
    /// which `readbyte()` answers with `EOF` but without touching
    /// `G.csize`. [`explode()`] reads it at the start (`bd`) and at the end
    /// (its return 5), and counts the end-of-data EOFs itself, as
    /// `readbyte()`'s `G.csize--` does.
    fn remaining(&self) -> u64;
}

impl ByteSource for std::slice::Iter<'_, u8> {
    fn next_byte(&mut self) -> Option<u8> {
        self.next().copied()
    }

    fn remaining(&self) -> u64 {
        self.len() as u64
    }
}

/// Why a decoder stopped early. `Code` is the C function's own nonzero
/// return value (`inflate.c`: 1 incomplete/EOF, 2 bad data, 3 out of memory;
/// `explode.c`: as its returns; `unshrink.c`: its `PK_*` returns), never
/// renumbered. `Flush` carries the flush callback's own error back unchanged
/// (unzip's `PK_DISK` and friends).
#[derive(Debug)]
pub enum Stop<E> {
    /// The C decoder's own nonzero return value.
    Code(i32),
    /// The flush callback's error, unchanged.
    Flush(E),
    /// `explode.c`'s return 5, which `extract.c` treats apart from the other
    /// codes ("treat 5 specially"): every byte was flushed, but the stream
    /// did not end at the compressed size. `unused` is the C's
    /// `G.csize + G.incnt + (k >> 3)` at that point, the compressed bytes
    /// left over (negative when it read past the end), so unzip's
    /// `G.used_csize` is `G.lrec.csize - unused`.
    Length {
        /// `G.csize + G.incnt + (k >> 3)`, never 0.
        unused: i64,
    },
}
