//! One guard between every seekable [`Source`](super::Source) and the
//! platform's own `seek`.
//!
//! # The class this closes
//!
//! A container reading an indexed archive seeks to positions the ARCHIVE
//! declares: zip's central directory carries a local-header offset per
//! record, zoo's directory chain is a list of absolute file offsets, ARJ
//! skips by a declared length. Those numbers are attacker-controlled, and
//! `std`'s unix `Seek for File` hands `SeekFrom::Start(u64)` to `lseek(2)`
//! after casting it to `off_t`, an `i64`. Any value above [`i64::MAX`]
//! therefore arrives at the kernel NEGATIVE, and the kernel answers
//! `EINVAL` — a genuine `io::Error::Os { code: 22, kind: InvalidInput }`,
//! not a synthesised one.
//!
//! [`crate::Error::from_decode_io`] folds `InvalidData` and `OutOfMemory`
//! and nothing else, so that errno reached `Error::Io` and
//! `Error::exit_code`'s `_ => 1` wildcard: **exit 1, "stuffr failed", for a
//! file that is merely lying about where its entries are.** Measured on the
//! `container` fuzz target's own reproducer, whose zip64 extended-information
//! extra field declares a relative local-header offset of
//! `0xBB47_210D_4F0C_59BF`; `stuffr list`, `test` and `unpack` all exited 1
//! with `i/o error: Invalid argument (os error 22)`.
//!
//! # Why the guard is here and not in the container
//!
//! Three containers own a seek adapter (`zip.rs`'s `SeekAdapter`, `zoo.rs`'s
//! `ZooSeekAdapter`, `arj.rs`'s `ArjGuardedReader`) and each would have
//! needed the identical fold. `Error::from_decode_io`'s own doc comment
//! states the objection to that shape: "putting the decision in N places
//! means the natural code — a bare `?` on an `io::Error` — silently bypasses
//! it, and a convention whose failure mode is invisible is not a
//! convention." A seekable [`Source`](super::Source) hands its seek out
//! through one method, `as_seek`, so wrapping what that method returns makes
//! the guard unbypassable for every container, present and future.
//!
//! # Why an `InvalidInput` from `seek` is never a medium failure
//!
//! `lseek(2)` reports `EINVAL` for exactly one thing: the requested position
//! is not a valid one (a bad `whence`, or a result that is negative or
//! unrepresentable). A failing disk is `EIO`, a revoked file is `EBADF`, a
//! pipe is `ESPIPE`, a permission problem never reaches `seek` at all —
//! every one of those is a different kind and passes through this wrapper
//! untouched. `io::Cursor` agrees: its only `seek` error is
//! `InvalidInput`/"invalid seek to a negative or overflowing position".
//!
//! **`read` is deliberately not touched.** Phase 3a's Task 4b fixed a
//! near-identical misclassification at ONE call site precisely so that a raw
//! source's i/o failure — a real disk error, a permission failure, a broken
//! pipe — would not be relabelled as corruption, and pinned that with two
//! tests. Reads here are a verbatim delegation, so both still hold.

use std::io::{self, ErrorKind, Read, Seek, SeekFrom};

/// The largest absolute position any platform in scope can address: a file
/// offset is an `i64` on every unix and on Windows alike, so a `u64` above
/// this names a location no file can ever hold.
pub const MAX_SEEK_POSITION: u64 = i64::MAX as u64;

/// Wraps a seekable reader so a rejected seek POSITION is reported as
/// malformed input rather than as an i/o failure of the medium.
///
/// See the module doc for the whole argument. Reads delegate verbatim.
#[derive(Debug)]
pub struct GuardedSeek<T> {
    inner: T,
}

impl<T> GuardedSeek<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: Read> Read for GuardedSeek<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<T: Seek> Seek for GuardedSeek<T> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        // Refused BEFORE the syscall, not folded after it, for one reason
        // that is not tidiness: `io::Cursor` accepts
        // `SeekFrom::Start(u64::MAX)` and answers `Ok`, while a `File`
        // answers `EINVAL`. Without this arm the same archive read from a
        // spool that stayed in memory and from one that escalated to a temp
        // file would take two different paths out of the reader — the
        // in-memory one reaching EOF and reporting truncation, the on-disk
        // one reporting an OS failure. One refusal, one message, both rungs.
        if let SeekFrom::Start(target) = pos
            && target > MAX_SEEK_POSITION
        {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "a seek to absolute position {target} is past {MAX_SEEK_POSITION}, the \
                     largest position any file can hold; the input declares a location that \
                     cannot exist"
                ),
            ));
        }
        self.inner.seek(pos).map_err(|e| {
            if e.kind() == ErrorKind::InvalidInput {
                io::Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "the platform refused a seek to {pos:?} as an invalid position ({e}); \
                         the input declares a location that cannot exist"
                    ),
                )
            } else {
                e
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use std::io::Write;

    fn temp_file(bytes: &[u8]) -> std::fs::File {
        let mut f = tempfile::tempfile().unwrap();
        f.write_all(bytes).unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        f
    }

    /// The defect itself, at the layer that produced it: a `u64` above
    /// `i64::MAX` handed to a real file's `seek`.
    #[test]
    fn a_start_past_the_addressable_range_is_malformed_input_not_an_os_failure() {
        let mut g = GuardedSeek::new(temp_file(b"0123456789"));
        let err = g.seek(SeekFrom::Start(MAX_SEEK_POSITION + 1)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData, "{err}");
        assert!(
            err.get_ref().is_some(),
            "the refusal must carry its own message, not a bare errno: {err:?}"
        );

        // The whole point: this classifies, and it classifies as the file's
        // own inconsistency. `Error::exit_code`'s rule — exit 5 is "stuffr
        // read the bytes and they contradict each other", exit 6 is "stuffr
        // declined to ask the allocator" — puts this on 5: nothing is
        // allocated from the offset, and no larger machine makes a position
        // past `i64::MAX` reachable.
        let classified = Error::from_decode_io(err);
        assert!(matches!(classified, Error::Corrupt(_)), "{classified:?}");
        assert_eq!(classified.exit_code(), 5);
    }

    /// The in-memory rung must answer the same thing the on-disk one does.
    /// A bare `Cursor` answers `Ok(u64::MAX)` here, which is what made the
    /// spool's two backings disagree about the same archive.
    #[test]
    fn the_in_memory_backing_refuses_what_a_file_refuses() {
        let mut bare = io::Cursor::new(b"0123456789".to_vec());
        assert!(
            bare.seek(SeekFrom::Start(u64::MAX)).is_ok(),
            "premise: an unguarded Cursor accepts a position no file can hold"
        );

        let mut g = GuardedSeek::new(io::Cursor::new(b"0123456789".to_vec()));
        let err = g.seek(SeekFrom::Start(u64::MAX)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData, "{err}");
    }

    /// The other shape of an invalid position — a relative seek landing
    /// before byte zero — which the platform, not this guard's own arm,
    /// rejects.
    #[test]
    fn a_negative_resulting_position_is_folded_too() {
        let mut g = GuardedSeek::new(temp_file(b"0123456789"));
        let err = g.seek(SeekFrom::End(-1000)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData, "{err}");
        assert_eq!(Error::from_decode_io(err).exit_code(), 5);
    }

    #[test]
    fn an_ordinary_seek_and_read_are_untouched() {
        let mut g = GuardedSeek::new(temp_file(b"0123456789"));
        assert_eq!(g.seek(SeekFrom::Start(4)).unwrap(), 4);
        let mut buf = [0u8; 3];
        g.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"456");
        assert_eq!(g.seek(SeekFrom::End(0)).unwrap(), 10);
        assert_eq!(g.seek(SeekFrom::Current(-2)).unwrap(), 8);
    }

    /// The scope guarantee Task 4b's two pinned tests exist to protect,
    /// asserted here at the new boundary rather than left to be inferred: a
    /// genuine i/o failure of the MEDIUM must keep its kind. A read is
    /// delegated verbatim, and a non-`InvalidInput` seek failure passes
    /// through.
    #[test]
    fn a_medium_failure_keeps_its_kind_in_both_directions() {
        struct Failing;
        impl Read for Failing {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(ErrorKind::PermissionDenied, "disk said no"))
            }
        }
        impl Seek for Failing {
            fn seek(&mut self, _pos: SeekFrom) -> io::Result<u64> {
                Err(io::Error::from_raw_os_error(5)) // EIO
            }
        }

        let mut g = GuardedSeek::new(Failing);
        let read_err = g.read(&mut [0u8; 4]).unwrap_err();
        assert_eq!(read_err.kind(), ErrorKind::PermissionDenied, "{read_err}");
        assert!(matches!(Error::from_decode_io(read_err), Error::Io(_)));

        let seek_err = g.seek(SeekFrom::Start(0)).unwrap_err();
        assert_eq!(seek_err.raw_os_error(), Some(5), "{seek_err:?}");
        assert!(matches!(Error::from_decode_io(seek_err), Error::Io(_)));
    }
}
