//! Info-ZIP UnZip 6.0's own decoders, ported for the `stuffr` binary's unzip
//! compatibility family (`unzip`, `zipinfo`, `funzip`), which has to fail on
//! corrupt input exactly where unzip does and leave the same partial output
//! behind. Reached through `stuffr::infozip` only; not part of the public
//! surface.
//!
//! **Licence.** Everything under this module is ported from Info-ZIP UnZip
//! 6.0 (`crypt.c` here; `inflate.c`, `explode.c` and `unshrink.c` to follow)
//! and stays under the Info-ZIP licence, version 2009-Jan-02, reproduced in
//! this crate's `LICENSE-infozip`. It is an altered version in that
//! licence's clause 3 sense: a port to Rust, not Info-ZIP's source, and not
//! an Info-ZIP release. Every ported function carries a
//! `// port: <file>.c:<function>` comment naming its original.
//!
//! **The seam.** A decoder reads the entry's bytes through [`ByteSource`]
//! (unzip's `NEXTBYTE`, already decrypted by [`crypt`] where the entry is
//! encrypted), writes only through a flush callback, and reports an early
//! stop as [`Stop`], carrying the C function's own return code unchanged.

pub mod crypt;

#[cfg(test)]
mod tests;

/// What a decoder reads: unzip's `NEXTBYTE` over `csize` bytes of the entry
/// (already decrypted). `None` is unzip's EOF (`csize` exhausted, or a read
/// error the caller remembers and reports itself).
pub trait ByteSource {
    /// The next byte of the entry, or `None` at unzip's EOF.
    fn next_byte(&mut self) -> Option<u8>;
}

impl ByteSource for std::slice::Iter<'_, u8> {
    fn next_byte(&mut self) -> Option<u8> {
        self.next().copied()
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
}
