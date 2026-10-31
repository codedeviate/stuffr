//! What follows a verified member of a multi-member codec stream — the one
//! rule gzip ([`crate::gzip`]) and bzip2 ([`crate::bzip2`]) share.
//!
//! Both formats are legitimately concatenations, so after each member whose
//! own check verified, the reader must decide what the remaining bytes are.
//! Before PARSE-1 (security audit, 2026-10-31) anything that did not start
//! with the magic ended the stream silently, at exit 0 even under
//! `--strict-fidelity` — so one flipped byte at a member boundary dropped
//! every later member, while the members before it still verified. The rule
//! now has four outcomes:
//!
//! 1. **Nothing** follows: the stream ends.
//! 2. **Another member** follows — the magic, and nothing impossible in the
//!    header fields read behind it: the caller decodes it. A member cut short
//!    inside its header is the member decoder's own truncation error.
//! 3. **A damaged member header** — the magic intact and a field behind it
//!    impossible, or the input ending inside the magic itself — is
//!    `InvalidData` (exit 5), mirroring reference lzip's "Corrupt header in
//!    multimember file" / "Truncated header in multimember file".
//! 4. **Anything else** is read through and ignored. All NUL or all `'X'` is
//!    padding (Finding 7 of the Phase 1e final review: real tools pad this
//!    way, and reference `gzip`/`bzip2` and Python recover the data whole) and
//!    stays silent; any other tail is recorded as
//!    [`Fidelity::TrailingDataIgnored`] with its length, which
//!    `--strict-fidelity` turns into exit 4. The tail is counted while it is
//!    read, never buffered, so an unbounded tail costs O(1) memory.
//!
//! **How many members a stream may start** is bounded too ([`MemberBudget`],
//! the T10 review's N1). Every member gets a fresh decoder — flate2's inflate
//! state is ~40 KiB zeroed, libbz2-rs-sys's `DState` tens of KiB zeroed plus
//! the block buffer it allocates at each stream header — while an empty gzip
//! member is 20 bytes and an empty bzip2 stream 14. A file of a million empty
//! members (20 MB) cost tens of GB of memset with no output at all, so
//! `--max-ratio` (which counts output) never saw it. Reusing the decoder does
//! not close it: `flate2::Decompress::reset` zeroes miniz_oxide's 32 KiB
//! window too (`FullReset`), so a reset member costs nearly what a new one
//! does. The bound is on work instead: [`FREE_MEMBERS`] members are free, and
//! each further one must be paid for by [`BYTES_PER_MEMBER`] bytes read or
//! decoded, or the stream is refused as a resource limit (exit 6). Real
//! multi-member files (pigz, bgzip's 64 KiB blocks, pbzip2's 900 KB blocks,
//! `gzip >>` appends) never come near it.

use std::io::{self, BufRead, ErrorKind, Read};

use stuffr_core::{Fidelity, FidelitySink, FormatId};

/// How much [`PeekBuf`] holds; also the most [`PeekBuf::peek`] may ask for.
const CAP: usize = 64 * 1024;

/// A `BufRead` that can guarantee a short look-ahead.
///
/// `std::io::BufReader::fill_buf` returns whatever is left in its buffer,
/// however little, so a member boundary that lands one byte before the end of
/// a buffer shows a one-byte "tail" that is really the first byte of the next
/// header. [`Self::peek`] refills until it holds the bytes asked for or the
/// input ends, which is what the classification above needs.
pub(crate) struct PeekBuf<R> {
    inner: R,
    buf: Box<[u8]>,
    pos: usize,
    end: usize,
    /// Bytes consumed so far — what [`MemberBudget`] counts as read.
    taken: u64,
}

impl<R: Read> PeekBuf<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self {
            inner,
            buf: vec![0; CAP].into_boxed_slice(),
            pos: 0,
            end: 0,
            taken: 0,
        }
    }

    /// The next `n` bytes without consuming them — fewer only when the input
    /// ends first.
    pub(crate) fn peek(&mut self, n: usize) -> io::Result<&[u8]> {
        assert!(n <= CAP, "peek of {n} bytes exceeds the buffer");
        if self.end - self.pos < n {
            self.buf.copy_within(self.pos..self.end, 0);
            self.end -= self.pos;
            self.pos = 0;
            while self.end < n {
                match self.inner.read(&mut self.buf[self.end..]) {
                    Ok(0) => break,
                    Ok(k) => self.end += k,
                    Err(e) if e.kind() == ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
        }
        let n = n.min(self.end - self.pos);
        Ok(&self.buf[self.pos..self.pos + n])
    }
}

impl<R: Read> Read for PeekBuf<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let avail = self.fill_buf()?;
        let n = avail.len().min(out.len());
        out[..n].copy_from_slice(&avail[..n]);
        self.consume(n);
        Ok(n)
    }
}

impl<R: Read> BufRead for PeekBuf<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.pos == self.end {
            self.pos = 0;
            self.end = 0;
            loop {
                match self.inner.read(&mut self.buf) {
                    Ok(k) => {
                        self.end = k;
                        break;
                    }
                    Err(e) if e.kind() == ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(&self.buf[self.pos..self.end])
    }

    fn consume(&mut self, n: usize) {
        let next = (self.pos + n).min(self.end);
        self.taken += (next - self.pos) as u64;
        self.pos = next;
    }
}

/// Members a stream may start before any has to be paid for — enough for
/// every real multi-member file of tiny members we know of, and at most
/// ~4096 decoder set-ups (a few hundred MB of memset in all) for a hostile
/// one.
pub(crate) const FREE_MEMBERS: u64 = 4096;

/// Bytes read or decoded that pay for one member past [`FREE_MEMBERS`]. A
/// member's set-up is tens of KiB of zeroing, so this keeps the set-up work
/// within roughly a hundred times the bytes the stream actually moves.
pub(crate) const BYTES_PER_MEMBER: u64 = 512;

/// Counts the members a multi-member decoder starts against the bytes it
/// reads and produces; see the module doc for why.
pub(crate) struct MemberBudget {
    format: FormatId,
    /// Members started, the first included.
    started: u64,
    /// Decoded bytes handed to the caller.
    produced: u64,
}

impl MemberBudget {
    /// A budget for a stream whose first member has already been started.
    pub(crate) fn new(format: FormatId) -> Self {
        Self {
            format,
            started: 1,
            produced: 0,
        }
    }

    /// Records `n` decoded bytes handed to the caller.
    pub(crate) fn produced(&mut self, n: usize) {
        self.produced += n as u64;
    }

    /// Charges the member about to start at `r`'s position, or refuses it
    /// (`OutOfMemory`, which `Error::from_decode_io` makes
    /// `Error::ResourceLimit`, exit 6).
    pub(crate) fn start_member<R>(&mut self, r: &PeekBuf<R>) -> io::Result<()> {
        let read = r.taken;
        let allowance = FREE_MEMBERS + (read + self.produced) / BYTES_PER_MEMBER;
        if self.started >= allowance {
            return Err(io::Error::new(
                ErrorKind::OutOfMemory,
                format!(
                    "the {} stream starts more members than its size accounts for: {} members \
                     in {read} bytes read, {} bytes decoded (at most {FREE_MEMBERS}, plus one \
                     per {BYTES_PER_MEMBER} bytes read or decoded); refused, since every member \
                     costs a fresh decoder",
                    self.format,
                    self.started + 1,
                    self.produced
                ),
            ));
        }
        self.started += 1;
        Ok(())
    }

    /// Members started so far, the first included.
    #[cfg(test)]
    pub(crate) fn started(&self) -> u64 {
        self.started
    }
}

/// A format's verdict on the first bytes after a verified member.
pub(crate) enum Header {
    /// The magic, and nothing impossible behind it: decode another member.
    Next,
    /// The magic, and an impossible field behind it.
    Corrupt(&'static str),
    /// Not a member header at all.
    Junk,
}

/// One format's half of the rule: its name, its magic, how many header bytes
/// [`Self::judge`] wants to see, and the judgement itself.
pub(crate) struct Rule {
    pub format: FormatId,
    pub magic: &'static [u8],
    pub header_len: usize,
    /// Judges up to `header_len` bytes (fewer only at the end of the input).
    pub judge: fn(&[u8]) -> Header,
}

/// Decides what follows a verified member; `Ok(true)` means another member
/// starts at the reader's position. See the module doc for the four outcomes.
pub(crate) fn after_member<R: Read>(
    r: &mut PeekBuf<R>,
    rule: &Rule,
    sink: &FidelitySink,
) -> io::Result<bool> {
    let head = r.peek(rule.header_len.max(rule.magic.len()))?;
    let Some(&first) = head.first() else {
        return Ok(false);
    };
    match (rule.judge)(head) {
        Header::Next => return Ok(true),
        Header::Corrupt(why) => return Err(io::Error::new(ErrorKind::InvalidData, why)),
        Header::Junk => {}
    }
    if head.len() < rule.magic.len() && rule.magic.starts_with(head) {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "the {} stream ends inside the magic of a further member: a truncated member header",
                rule.format
            ),
        ));
    }
    let mut padding = first == 0 || first == b'X';
    let mut bytes = 0u64;
    loop {
        let chunk = r.fill_buf()?;
        if chunk.is_empty() {
            break;
        }
        padding = padding && chunk.iter().all(|&b| b == first);
        bytes += chunk.len() as u64;
        let n = chunk.len();
        r.consume(n);
    }
    if !padding {
        sink.warn(Fidelity::TrailingDataIgnored {
            format: rule.format,
            bytes,
        });
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hands out one byte per `read`, the worst a source may do.
    struct Trickle(std::io::Cursor<Vec<u8>>);

    impl Read for Trickle {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let n = out.len().min(1);
            self.0.read(&mut out[..n])
        }
    }

    #[test]
    fn peek_gathers_the_bytes_asked_for_across_short_reads() {
        let mut r = PeekBuf::new(Trickle(std::io::Cursor::new(b"abcdef".to_vec())));
        assert_eq!(r.peek(4).unwrap(), b"abcd");
        assert_eq!(r.fill_buf().unwrap(), b"abcd", "peek did not consume");
        r.consume(3);
        assert_eq!(r.peek(3).unwrap(), b"def");
        assert_eq!(r.peek(10).unwrap(), b"def", "fewer only at the end");
        let mut rest = Vec::new();
        r.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"def");
    }

    #[test]
    fn a_long_tail_is_counted_without_being_kept() {
        let rule = Rule {
            format: FormatId::new("gzip"),
            magic: &[0x1f, 0x8b],
            header_len: 4,
            judge: |_| Header::Junk,
        };
        let tail = vec![7u8; 5 * CAP + 3];
        let mut r = PeekBuf::new(std::io::Cursor::new(tail));
        let sink = FidelitySink::new();
        assert!(!after_member(&mut r, &rule, &sink).unwrap());
        assert_eq!(
            sink.warnings(),
            vec![Fidelity::TrailingDataIgnored {
                format: FormatId::new("gzip"),
                bytes: 5 * CAP as u64 + 3,
            }]
        );
    }
}
