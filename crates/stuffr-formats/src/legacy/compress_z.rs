//! Unix `compress` (`.Z` / LZC). Decode only — see the module doc on
//! `legacy` for why this whole family is.
//!
//! **This codec does NOT decode through `newtua_lzw_z::Decoder`, despite
//! that being this crate's only public streaming type, and the obvious
//! thing to reach for.** Measured directly against this project's own 51-byte
//! `hello.Z` fixture: `Decoder::read` calls `ensure_decoded`, whose own doc
//! says plainly "The full compressed input is read and decoded on the first
//! read call" — and conformance property 8 caught this immediately, the
//! very first time it ran: `first output arrived only after reading 51 of
//! 51 bytes (threshold 12); a read-to-end implementation looks exactly like
//! this`. `Decoder::new(..).read_to_end(..)` is, byte for byte, what the
//! crate's own `decompress`/`decompress_slice` do internally — so `Decoder`
//! buys nothing over them for the one reason it would be reached for:
//! bounding a decompression bomb's peak memory the way `xz_pure.rs` and
//! `lzip.rs` do. Worse, it silently defeats `stuffr`'s own `--max-ratio`
//! guard (`RatioGuard` in `stuffr-core/src/source/limit.rs`): that guard is
//! called by the copy loop once per chunk of DECODED output, specifically so
//! it can refuse a decode before the whole thing materializes — a promise
//! that depends on output actually arriving in bounded increments, which
//! `Decoder` does not provide.
//!
//! So this module ports `newtua-lzw-z 0.1.0`'s own algorithm
//! (`src/decode.rs`'s `lzc_decode`/`decode_codes`) itself, bit for bit, but
//! drives it from a lazily-filled bit accumulator instead of a
//! fully-materialized byte slice: a single `read()` call decodes exactly one
//! LZW code (at most 16 input bits) before appending its output to a small
//! pending buffer and returning, so both a caller's read loop and
//! `RatioGuard` see genuine incremental progress.
//!
//! `newtua-lzw-z` stays a dependency — pinned exactly, like every other
//! legacy dependency here — but as a `[dev-dependencies]` entry (`stuffr-formats/Cargo.toml`), not a
//! `dep:` behind the `compress` feature: its only remaining job is as an
//! independent decode oracle in this module's own tests
//! (`matches_the_crates_own_reference_decoder_across_many_payloads`),
//! `decompress_slice` cross-checked byte-for-byte against this module's own
//! decoder over the fixture plus a battery of payloads the real system
//! `compress` binary produced. It is never linked into a build that does not
//! run this crate's own tests (`cargo tree -p stuffr-formats --features
//! compress -i newtua-lzw-z` shows only a `[dev-dependencies]` edge) — a
//! shipped `legacy`/`full` build calls none of it. That split is a genuine
//! improvement over a single-source fixture, not a downgrade: `.Z` now has
//! TWO independent witnesses backing its correctness, more than any other
//! format in this phase — `/usr/bin/compress` by construction (the fixture
//! itself), and `newtua-lzw-z`, a wholly separate implementation, agreeing
//! with this module's own decoder across every payload the cross-check
//! test sweeps.
//!
//! **There is exactly one payload shape where `newtua-lzw-z` is NOT an
//! oracle, and it is asserted rather than left to be rediscovered:** a
//! `maxbits == 9` stream whose 512-entry dictionary fills. 0.1.0 still
//! carries the `n_bits < maxbits` width-growth clause this module removed
//! (see `a_maxbits_9_stream_decodes_byte_exactly`, which documents the bug
//! and pins the divergence), so it refuses such a stream outright. The real
//! tools side with this module: BSD `compress -b 9`'s bytes are identical to
//! what `SynthZ` writes, and GNU `uncompress` decodes them byte-exactly.
//! Reach for the crate as an oracle anywhere else; not there.
//!
//! ## Truncation: no error, but never garbage — measured, not assumed
//!
//! `CodecCaps::truncation_undetectable` is set for this codec, and it needed
//! new plumbing in `stuffr-core` to exist at all (see that field's own doc):
//! conformance property 10 has no bare skip for any declaration. What this
//! field switches property 10 to is a WEAKER but still falsifiable property:
//! on truncated input, a decoder must either error, or produce a byte
//! sequence that is a genuine PREFIX of what it produces from the
//! untruncated input — never fabricated, reordered or padded bytes. Unix
//! compress's LZW code stream carries no length field, no checksum and no
//! end-of-stream marker, and a prefix of a valid stream decodes through the
//! IDENTICAL state machine as the full stream, stopping for the identical
//! reason (too few bits left for the next code) whether or not more bytes
//! used to follow — so the strict "always error" property is unreachable,
//! measured directly on `hello.Z` (51 bytes): cutting to 1, 25 or 50 bytes,
//! and the genuine, UNCUT 51-byte ending, all leave a handful of unconsumed
//! leftover bits (5, 7, 6 respectively for 25/50/51) — no leftover count, and
//! no leftover VALUE either (the true ending's leftover happened to be
//! all-zero, but so did one of the truncated cuts'), distinguishes a real
//! ending from a cut one. But the weaker, prefix property DOES hold:
//! confirmed independently against two production reference tools, not just
//! this project's own code or `newtua-lzw-z`: `/usr/bin/uncompress -c` and
//! `/usr/bin/gzip -dc` on macOS both exit 0 on the same cut files, and in
//! every case what they emit is a strict prefix of the untruncated decode —
//! `the quick brown fox` (19 bytes) for a 25-byte cut, `the quick brown fox
//! jumps over the lazy dog` (43 bytes, no trailing newline) for a 50-byte
//! cut — never garbage, never reordered, never padded. This is a real,
//! external, cross-validated fact about the format, matching precisely why
//! gzip/zlib/bzip2/snappy all carry a mandatory checksum and Unix compress
//! predates and lacks one.
//!
//! ## Encoding (Phase 3c, Task 5)
//!
//! `LzwEncoder` is a from-scratch block-mode LZW encoder, promoted out of
//! `#[cfg(test)]` where it lived as `SynthZ` — proven byte-for-byte against
//! the real `compress` binary at four `maxbits` values (`the_stream_
//! synthesiser_matches_the_system_encoder_byte_for_byte`) before it was ever
//! wired to a `Sink`. Two changes from its test-only ancestor, both load-
//! bearing:
//!
//! 1. **It streams.** `SynthZ` buffered its whole output in a `Vec<u8>` —
//!    fine for a test encoding a few kilobytes, wrong for a `Sink`, which
//!    must not accumulate an encode of arbitrary length in memory.
//!    `LzwEncoder::output`/`finish` now take the destination buffer as a
//!    parameter instead of owning one, so [`CompressZSink::write`] can flush
//!    each completed group straight to the underlying `Write` and hold onto
//!    nothing bigger than one code group (at most 16 bits) between calls.
//!    Memory is otherwise bounded exactly the way the DECODER's is: the
//!    dictionary (`HashMap<(u32, u8), u32>`) never exceeds `maxmaxcode`
//!    entries (65,536 at `maxbits == 16`), the same ceiling `DictState`'s
//!    `prefix`/`suffix` vectors allocate up front on the read side.
//! 2. **It has no ratio heuristic.** The real encoder decides WHEN to emit a
//!    block-mode CLEAR from a compression-ratio check (`cl_block`), and the
//!    two reference implementations disagree wildly about it (see `SynthZ`'s
//!    own historical doc, preserved on the test helper below). This encoder
//!    never emits one: `block_mode` is still set in the header (matching
//!    both real encoders' default), but the dictionary simply fills and
//!    FREEZES at `maxmaxcode`, encoding every further byte with codes already
//!    in it. That is a real, legal `.Z` stream — the reference decoders
//!    accept a stream with zero CLEARs just as readily as one with several —
//!    and it means this encoder's output is never asserted byte-identical to
//!    a system encoder's on any payload where the ratio heuristic might have
//!    fired (anything at or past `CHECK_GAP == 10,000` input bytes). What
//!    property 2's own round trip and the interop test below DO assert is
//!    that this encoder's output round-trips through this module's own
//!    decoder, and that the real `uncompress` reads it back correctly — both
//!    hold regardless of whether a CLEAR ever appears.
//!
//! `check_encode_opts` maps `EncodeOpts::level` onto `maxbits` (`compress`'s
//! own `-b` flag), rejecting anything outside `9..=16` as `Error::Usage`
//! before either `encoder()` touches a destination — conformance property 6
//! checks the two agree. The default (`level: None`) is `maxbits == 16`, the
//! best ratio the format has, matching every other codec's convention of
//! defaulting to the strongest setting a user doesn't have to ask for.
//!
//! **Level 9 is deliberately not the default and is real.** GNU `ncompress`
//! 5.0 cannot decode its own `-b 9` output once the 512-entry dictionary
//! fills (measured during Phase 3b — see `synth_z`'s doc, kept on the test
//! helper below), which is why this module's own interop test for it
//! resolves GNU `ncompress`'s `uncompress` deliberately rather than through
//! `PATH` — a fixed Homebrew path on macOS (where `PATH`'s own `uncompress`
//! is the BSD implementation), `PATH` resolution everywhere else (where
//! `ncompress` is the only `uncompress` a CI runner has). See
//! `require_gnu_uncompress`'s own doc for why each branch is correct on its
//! platform.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};

use stuffr_core::{
    Codec, CodecCaps, DecodeOpts, EncodeOpts, Error, FormatId, FormatMeta, MagicRule, Result, Sink,
    Source, StreamOnly,
};

pub const COMPRESS: FormatId = FormatId::new("compress");

const COMPRESS_MAGIC_BYTES: &[u8] = &[0x1f, 0x9d];

const COMPRESS_MAGIC: &[MagicRule] = &[MagicRule {
    offset: 0,
    bytes: COMPRESS_MAGIC_BYTES,
    format: COMPRESS,
}];

const BLOCK_MODE_FLAG: u8 = 0x80;
const MAXBITS_MASK: u8 = 0x1f;
const INIT_BITS: u32 = 9;
const MAX_MAXBITS: u32 = 16;
const CLEAR: u32 = 256;

fn invalid_data(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Registration metadata for Unix `compress`.
pub fn meta() -> FormatMeta {
    FormatMeta::codec(COMPRESS, &["z"], COMPRESS_MAGIC)
}

#[derive(Debug)]
pub struct CompressZ;

impl Codec for CompressZ {
    fn id(&self) -> FormatId {
        COMPRESS
    }

    fn caps(&self) -> CodecCaps {
        CodecCaps {
            truncation_undetectable: true,
            ..CodecCaps::round_trip()
        }
    }

    /// See the module doc for why this is [`LzwZReader`], a from-scratch
    /// incremental port of `newtua-lzw-z`'s own algorithm, rather than a
    /// wrapper over that crate's `Decoder`.
    fn decoder(&self, src: Box<dyn Source>, _o: &DecodeOpts) -> Result<Box<dyn Source>> {
        Ok(Box::new(StreamOnly::new(LzwZReader::new(src))))
    }

    /// `compress`'s own `-b` flag: `maxbits` in `9..=16`. `None` (no
    /// `--level`) means 16, the best ratio the format has. Raised before
    /// `encoder()` touches a destination — see the module doc.
    fn check_encode_opts(&self, o: &EncodeOpts) -> Result<()> {
        match o.level {
            Some(n) if !(INIT_BITS as i32..=MAX_MAXBITS as i32).contains(&n) => Err(Error::Usage(
                format!("compress maxbits must be 9-16, got {n}"),
            )),
            _ => Ok(()),
        }
    }

    /// Wraps [`LzwEncoder`] in [`CompressZSink`] — see the module doc for why
    /// the encoder streams instead of buffering, and why it never emits a
    /// block-mode CLEAR.
    fn encoder(&self, mut dst: Box<dyn Write + Send>, o: &EncodeOpts) -> Result<Box<dyn Sink>> {
        self.check_encode_opts(o)?;
        let maxbits = o.level.map(|n| n as u32).unwrap_or(MAX_MAXBITS);
        let (enc, header) = LzwEncoder::new(maxbits);
        dst.write_all(&header)?;
        Ok(Box::new(CompressZSink {
            dst,
            enc,
            scratch: Vec::with_capacity(2),
        }))
    }
}

/// Streaming block-mode LZW encoder. See the module doc's "Encoding" section
/// for what makes this different from `SynthZ`, the test-only ancestor it was
/// promoted from.
///
/// Memory is bounded regardless of input length: `dict` holds at most
/// `maxmaxcode` entries (a `u32` key pair to a `u32` code — the same
/// `2^maxbits` ceiling the decoder's own `prefix`/`suffix` vectors allocate
/// up front), and `acc`/`acc_bits` is a single bit accumulator no wider than
/// one code group. Nothing here grows with the number of bytes encoded.
struct LzwEncoder {
    maxbits: u32,
    maxmaxcode: u32,
    n_bits: u32,
    maxcode: u32,
    free_ent: u32,
    /// The current output group, LSB-first. A group is `n_bits` bytes — at
    /// most 16, so at most 128 bits, which is exactly why this is a `u128`
    /// and not a `u64`.
    acc: u128,
    acc_bits: u32,
    clear_flg: bool,
    dict: HashMap<(u32, u8), u32>,
    /// The LZW "current string" code, as a dictionary index — `None` only
    /// before the first byte has been seen.
    ent: Option<u32>,
}

impl LzwEncoder {
    /// Block mode, always: it is what both real encoders default to, and the
    /// CLEAR code only exists under it — even though this encoder never
    /// emits one (see the module doc). Returns the 3-byte `.Z` header
    /// alongside the fresh encoder state, since the header must reach the
    /// destination exactly once, before any code group.
    fn new(maxbits: u32) -> (Self, [u8; 3]) {
        assert!(
            (INIT_BITS..=MAX_MAXBITS).contains(&maxbits),
            "maxbits {maxbits} outside the format's own 9..=16 — check_encode_opts should \
             have refused this before an encoder was ever constructed"
        );
        (
            Self {
                maxbits,
                maxmaxcode: 1 << maxbits,
                n_bits: INIT_BITS,
                maxcode: (1 << INIT_BITS) - 1,
                free_ent: CLEAR + 1,
                acc: 0,
                acc_bits: 0,
                clear_flg: false,
                dict: HashMap::new(),
                ent: None,
            },
            [
                COMPRESS_MAGIC_BYTES[0],
                COMPRESS_MAGIC_BYTES[1],
                BLOCK_MODE_FLAG | maxbits as u8,
            ],
        )
    }

    /// `compress.c`'s `output()`, arm for arm: write the code, flush a full
    /// group, then — if the next entry would not fit, or a CLEAR is pending —
    /// zero-pad the partial group to `n_bits` bytes (the width the group was
    /// STARTED at, which is why the padding happens before the width
    /// changes) and re-derive the width. Emitted bytes are appended to `out`
    /// rather than owned, which is what makes this streaming: a caller
    /// flushes `out` and clears it after every call instead of letting it
    /// grow for the whole encode.
    fn output(&mut self, code: u32, out: &mut Vec<u8>) {
        self.acc |= u128::from(code) << self.acc_bits;
        self.acc_bits += self.n_bits;
        if self.acc_bits == self.n_bits * 8 {
            self.flush_group(self.n_bits, out);
        }
        if self.free_ent > self.maxcode || self.clear_flg {
            if self.acc_bits > 0 {
                self.flush_group(self.n_bits, out);
            }
            if self.clear_flg {
                self.n_bits = INIT_BITS;
                self.maxcode = (1 << INIT_BITS) - 1;
                self.clear_flg = false;
            } else {
                self.n_bits += 1;
                self.maxcode = if self.n_bits == self.maxbits {
                    self.maxmaxcode
                } else {
                    (1 << self.n_bits) - 1
                };
            }
        }
    }

    fn flush_group(&mut self, bytes: u32, out: &mut Vec<u8>) {
        for i in 0..bytes {
            out.push(((self.acc >> (8 * i)) & 0xff) as u8);
        }
        self.acc = 0;
        self.acc_bits = 0;
    }

    /// Feeds one byte of plaintext through the LZW matcher: extend the
    /// current string if the dictionary already holds `(ent, byte)`,
    /// otherwise emit `ent`'s code, learn the new pair (unless the
    /// dictionary has frozen at `maxmaxcode` — see the module doc), and
    /// start a fresh string at `byte`. Returns `true` only when a code was
    /// actually emitted (never on the very first byte, and never on a
    /// dictionary-hit extension) — the same distinction the real encoder's
    /// `cl_block` ratio check is gated on, which is why the CLEAR-injecting
    /// test helper below keys off it rather than injecting one at an
    /// arbitrary byte offset.
    fn push_byte(&mut self, byte: u8, out: &mut Vec<u8>) -> bool {
        match self.ent {
            None => {
                self.ent = Some(u32::from(byte));
                false
            }
            Some(ent) => {
                if let Some(&next) = self.dict.get(&(ent, byte)) {
                    self.ent = Some(next);
                    false
                } else {
                    self.output(ent, out);
                    if self.free_ent < self.maxmaxcode {
                        self.dict.insert((ent, byte), self.free_ent);
                        self.free_ent += 1;
                    }
                    self.ent = Some(u32::from(byte));
                    true
                }
            }
        }
    }

    /// At end of input only the bytes actually occupied are written — NOT a
    /// zero-padded whole group. That asymmetry with `output`'s padding is the
    /// real encoder's (`writebuf(buf, (offset + 7) / 8)`) and it is what
    /// leaves a genuine `.Z` ending with a handful of unconsumed bits, exactly
    /// as this module's doc describes.
    fn finish(mut self, out: &mut Vec<u8>) {
        if let Some(ent) = self.ent {
            self.output(ent, out);
        }
        if self.acc_bits > 0 {
            let bytes = self.acc_bits.div_ceil(8);
            self.flush_group(bytes, out);
        }
    }
}

/// [`Sink`] over [`LzwEncoder`]. Holds nothing bigger than one call's worth of
/// emitted bytes (at most two code-group flushes, ≤ 32 bytes — see
/// [`LzwEncoder::output`]) between writes: `scratch` is cleared and reused
/// every call rather than accumulating, which is the whole point (see the
/// module doc's "It streams" note).
struct CompressZSink {
    dst: Box<dyn Write + Send>,
    enc: LzwEncoder,
    scratch: Vec<u8>,
}

impl Write for CompressZSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for &byte in buf {
            self.scratch.clear();
            self.enc.push_byte(byte, &mut self.scratch);
            if !self.scratch.is_empty() {
                self.dst.write_all(&self.scratch)?;
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.dst.flush()
    }
}

impl Sink for CompressZSink {
    /// Emits the final (possibly partial) code and its trailing, unpadded
    /// group, then flushes the destination. See [`LzwEncoder::finish`] for
    /// why the tail is never zero-padded to a whole group.
    fn finish(self: Box<Self>) -> Result<()> {
        let CompressZSink {
            mut dst,
            enc,
            scratch: _,
        } = *self;
        let mut tail = Vec::new();
        enc.finish(&mut tail);
        dst.write_all(&tail)?;
        dst.flush()?;
        Ok(())
    }
}

/// Lazily pulls bytes from `R` and serves LSB-first bit groups.
///
/// Mirrors `newtua-lzw-z`'s own `decode::read_code` bit order exactly: bit
/// `i` of a code read starting at absolute stream-bit position `p` is bit
/// `p & 7` of the byte at `p >> 3`, and successive bits (as `p` increases)
/// are the successive bits of the byte stream in order — i.e. standard
/// LSB-first packing. An accumulator that ORs in each new byte shifted left
/// by however many bits are already buffered, then extracts and discards the
/// low `n` bits per `take`, reproduces this exactly, because it never seeks
/// backward — bits are consumed in the same left-to-right stream order the
/// absolute-position formula describes.
struct BitSource<R> {
    inner: R,
    acc: u64,
    acc_bits: u32,
    eof: bool,
}

impl<R: Read> BitSource<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            acc: 0,
            acc_bits: 0,
            eof: false,
        }
    }

    fn fill(&mut self, need: u32) -> io::Result<()> {
        let mut byte = [0u8; 1];
        while self.acc_bits < need && !self.eof {
            match self.inner.read(&mut byte)? {
                0 => self.eof = true,
                _ => {
                    self.acc |= (byte[0] as u64) << self.acc_bits;
                    self.acc_bits += 8;
                }
            }
        }
        Ok(())
    }

    /// Reads `n` bits (`n <= 32`), or `None` if fewer than `n` bits remain
    /// before the source's own EOF — a clean, unremarkable end, exactly the
    /// case `newtua-lzw-z`'s `read_code` returns `None` for.
    fn take(&mut self, n: u32) -> io::Result<Option<u32>> {
        debug_assert!(n <= 32);
        self.fill(n)?;
        if self.acc_bits < n {
            return Ok(None);
        }
        let mask = (1u64 << n) - 1;
        let value = (self.acc & mask) as u32;
        self.acc >>= n;
        self.acc_bits -= n;
        Ok(Some(value))
    }

    /// Discards `n` bits of pure alignment padding. Tolerates running out
    /// partway (nothing left to skip anyway) — the caller's next `take` will
    /// then observe the shortfall on its own, the same as `newtua-lzw-z`'s
    /// bounds-checked `read_code` would.
    fn skip(&mut self, mut n: u64) -> io::Result<()> {
        while n > 0 {
            let chunk = n.min(32) as u32;
            match self.take(chunk)? {
                Some(_) => n -= u64::from(chunk),
                None => return Ok(()),
            }
        }
        Ok(())
    }
}

/// Verbatim port of `newtua-lzw-z`'s `decode::align_to_group` — pure
/// arithmetic over already-consumed bit counts, no data dependency, so it
/// carries over unchanged from the whole-buffer original to this streaming
/// version. See that function's own doc (quoted in the original crate) for
/// the derivation; this is a byte-for-byte copy of its formula.
fn align_to_group(bitpos: u64, n_bits: u32, boff: u64) -> u64 {
    debug_assert!(bitpos > 0, "align_to_group requires a prior code read");
    let g = u64::from(n_bits) * 8;
    let p = bitpos - 1;
    let rel = p - boff;
    let pad = g - (rel + g) % g;
    p + pad
}

/// Mutable LZW dictionary/decode state, live only once the 3-byte header has
/// parsed. Field-for-field the same variables `decode_codes` uses locally,
/// just promoted to persist across `read()` calls.
struct DictState {
    block_mode: bool,
    maxbits: u32,
    maxmaxcode: u32,
    prefix: Vec<u32>,
    suffix: Vec<u8>,
    free_ent: u32,
    n_bits: u32,
    maxcode: u32,
    boff: u64,
    bitpos: u64,
    oldcode: u32,
    finchar: u8,
    stack: Vec<u8>,
    /// Counts block-mode CLEAR codes actually processed. Test-only
    /// instrumentation, not production state: it exists so
    /// `decodes_a_stream_with_block_mode_clears_and_width_growth` can assert
    /// the CLEAR branch (`compress_z.rs`'s own module doc — previously
    /// exercised by NO test in the repo) was genuinely reached, rather than
    /// merely hoping a large enough payload happens to trigger it.
    #[cfg(test)]
    clears_seen: u32,
}

impl DictState {
    fn new(block_mode: bool, maxbits: u32) -> Self {
        let maxmaxcode = 1u32 << maxbits;
        let mut suffix = vec![0u8; maxmaxcode as usize];
        for (i, s) in suffix.iter_mut().enumerate().take(256) {
            *s = i as u8;
        }
        let n_bits = INIT_BITS;
        Self {
            block_mode,
            maxbits,
            maxmaxcode,
            prefix: vec![0u32; maxmaxcode as usize],
            suffix,
            free_ent: if block_mode { CLEAR + 1 } else { 256 },
            n_bits,
            maxcode: (1u32 << n_bits) - 1,
            boff: 0,
            bitpos: 0,
            oldcode: 0,
            finchar: 0,
            stack: Vec::new(),
            #[cfg(test)]
            clears_seen: 0,
        }
    }
}

enum Phase {
    Header,
    FirstCode,
    Running,
    Done,
}

/// Incremental `.Z` decoder. See the module doc for why this exists instead
/// of `newtua_lzw_z::Decoder`.
struct LzwZReader<R> {
    bits: BitSource<R>,
    phase: Phase,
    dict: Option<DictState>,
    pending: VecDeque<u8>,
}

impl<R: Read> LzwZReader<R> {
    /// How many block-mode CLEAR codes this decode actually processed.
    /// Test-only — see [`DictState::clears_seen`]'s doc.
    #[cfg(test)]
    fn clears_seen(&self) -> u32 {
        self.dict.as_ref().map_or(0, |d| d.clears_seen)
    }

    fn new(inner: R) -> Self {
        Self {
            bits: BitSource::new(inner),
            phase: Phase::Header,
            dict: None,
            pending: VecDeque::new(),
        }
    }

    /// Parses the 3-byte header, matching `lzc_decode`'s own staged checks
    /// exactly: an empty source is valid (empty output); one byte is
    /// truncated; two bytes failing to match the magic is `BadMagic` even
    /// before a length-3 check; two correct magic bytes with nothing after is
    /// truncated; a bad `maxbits` is rejected once flags are in hand.
    ///
    /// Returns `Ok(true)` if a body follows, `Ok(false)` for a genuinely
    /// empty source.
    fn parse_header(&mut self) -> io::Result<bool> {
        let Some(b0) = self.bits.take(8)? else {
            return Ok(false);
        };
        let Some(b1) = self.bits.take(8)? else {
            return Err(invalid_data("truncated .Z header"));
        };
        if b0 as u8 != COMPRESS_MAGIC_BYTES[0] || b1 as u8 != COMPRESS_MAGIC_BYTES[1] {
            return Err(invalid_data("not a Unix compress (.Z) stream"));
        }
        let Some(flags) = self.bits.take(8)? else {
            return Err(invalid_data("truncated .Z header"));
        };
        let flags = flags as u8;
        let block_mode = (flags & BLOCK_MODE_FLAG) != 0;
        let maxbits = u32::from(flags & MAXBITS_MASK);
        if !(INIT_BITS..=MAX_MAXBITS).contains(&maxbits) {
            return Err(invalid_data("invalid maxbits (must be 9..=16)"));
        }
        self.dict = Some(DictState::new(block_mode, maxbits));
        Ok(true)
    }

    /// Advances the state machine by exactly one bounded unit of work: parse
    /// the header, read the first literal code, or process one further code.
    /// May append zero or more bytes to `pending`; the caller's `read` loops
    /// on this until `pending` is non-empty or `phase` is `Done`.
    fn advance(&mut self) -> io::Result<()> {
        match self.phase {
            Phase::Header => {
                if self.parse_header()? {
                    self.phase = Phase::FirstCode;
                } else {
                    self.phase = Phase::Done;
                }
                Ok(())
            }
            Phase::FirstCode => {
                let dict = self.dict.as_mut().expect("header parsed before FirstCode");
                match self.bits.take(dict.n_bits)? {
                    None => {
                        self.phase = Phase::Done;
                    }
                    Some(code) => {
                        dict.bitpos += u64::from(dict.n_bits);
                        if code >= 256 {
                            return Err(invalid_data("invalid LZW code in stream"));
                        }
                        dict.oldcode = code;
                        dict.finchar = code as u8;
                        self.pending.push_back(dict.finchar);
                        self.phase = Phase::Running;
                    }
                }
                Ok(())
            }
            Phase::Running => self.advance_running(),
            Phase::Done => Ok(()),
        }
    }

    /// One iteration of `decode_codes`'s `'outer` loop body, verbatim in
    /// logic (including the block-mode CLEAR handling and the KwKwK special
    /// case), adapted to read codes from [`BitSource`] instead of indexing a
    /// fully-materialized slice.
    fn advance_running(&mut self) -> io::Result<()> {
        let dict = self.dict.as_mut().expect("header parsed before Running");

        let raw = match self.bits.take(dict.n_bits)? {
            None => {
                self.phase = Phase::Done;
                return Ok(());
            }
            Some(c) => c,
        };
        dict.bitpos += u64::from(dict.n_bits);
        let mut code = raw;

        if dict.block_mode && code == CLEAR {
            #[cfg(test)]
            {
                dict.clears_seen += 1;
            }
            let new_bp = align_to_group(dict.bitpos, dict.n_bits, dict.boff);
            self.bits.skip(new_bp - dict.bitpos)?;
            dict.boff = new_bp;
            dict.bitpos = new_bp;
            dict.free_ent = CLEAR + 1;
            dict.n_bits = INIT_BITS;
            dict.maxcode = (1u32 << dict.n_bits) - 1;

            let lit = match self.bits.take(dict.n_bits)? {
                None => {
                    self.phase = Phase::Done;
                    return Ok(());
                }
                Some(c) => c,
            };
            dict.bitpos += u64::from(dict.n_bits);
            if lit >= 256 {
                return Err(invalid_data("invalid LZW code in stream"));
            }
            dict.oldcode = lit;
            dict.finchar = lit as u8;
            self.pending.push_back(dict.finchar);
            return Ok(());
        }

        let incode = code;
        if code > dict.free_ent {
            return Err(invalid_data("invalid LZW code in stream"));
        }
        if code == dict.free_ent {
            dict.stack.push(dict.finchar);
            code = dict.oldcode;
        }
        while code >= 256 {
            dict.stack.push(dict.suffix[code as usize]);
            code = dict.prefix[code as usize];
        }
        dict.finchar = code as u8;
        dict.stack.push(dict.finchar);
        while let Some(b) = dict.stack.pop() {
            self.pending.push_back(b);
        }

        if dict.free_ent < dict.maxmaxcode {
            dict.prefix[dict.free_ent as usize] = dict.oldcode;
            dict.suffix[dict.free_ent as usize] = dict.finchar;
            dict.free_ent += 1;
            if dict.free_ent > dict.maxcode {
                let new_bp = align_to_group(dict.bitpos, dict.n_bits, dict.boff);
                self.bits.skip(new_bp - dict.bitpos)?;
                dict.boff = new_bp;
                dict.bitpos = new_bp;
                dict.n_bits += 1;
                dict.maxcode = if dict.n_bits == dict.maxbits {
                    dict.maxmaxcode
                } else {
                    (1u32 << dict.n_bits) - 1
                };
            }
        }

        dict.oldcode = incode;
        Ok(())
    }
}

impl<R: Read> Read for LzwZReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if !self.pending.is_empty() {
                let n = buf.len().min(self.pending.len());
                for slot in buf.iter_mut().take(n) {
                    *slot = self.pending.pop_front().expect("just checked len");
                }
                return Ok(n);
            }
            if matches!(self.phase, Phase::Done) {
                return Ok(0);
            }
            self.advance()?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stuffr_core::ReaderSource;

    const HELLO_Z: &[u8] = include_bytes!("../../fixtures/legacy/hello.Z");
    const HELLO_PLAIN: &[u8] = b"the quick brown fox jumps over the lazy dog\n";

    fn decompress(bytes: &[u8]) -> std::io::Result<Vec<u8>> {
        let src: Box<dyn Source> =
            Box::new(ReaderSource::new(std::io::Cursor::new(bytes.to_vec())));
        let mut dec = CompressZ.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn decodes_the_known_fixture_to_the_known_plaintext() {
        assert_eq!(decompress(HELLO_Z).unwrap(), HELLO_PLAIN);
    }

    #[test]
    fn capabilities_and_metadata_match_the_format() {
        let c = CompressZ.caps();
        assert!(
            c.decode && c.encode,
            "Phase 3c Task 5 gave this codec a real encoder — see the module doc"
        );
        assert!(
            !c.parallel_encode,
            "this encoder has no multi-threaded path; declare it honestly (conformance \
             property 12)"
        );
        assert!(
            c.truncation_undetectable,
            "see this module's doc and CodecCaps::truncation_undetectable's own doc for why"
        );
        let m = meta();
        assert_eq!(m.id, COMPRESS);
        assert_eq!(m.extensions, &["z"]);
    }

    /// A level outside `9..=16` is `Error::Usage` (exit 2), raised by
    /// `check_encode_opts` before `encoder()` ever touches a destination —
    /// conformance property 6 checks the two agree on every level, this test
    /// pins the specific range the format itself defines.
    #[test]
    fn a_level_outside_9_to_16_is_a_usage_error() {
        for level in [i32::MIN, 0, 8, 17, i32::MAX] {
            let opts = EncodeOpts {
                level: Some(level),
                ..Default::default()
            };
            let err = CompressZ.check_encode_opts(&opts).unwrap_err();
            assert!(matches!(err, Error::Usage(_)), "level {level}: got {err:?}");
            assert_eq!(err.exit_code(), 2);
            match CompressZ.encoder(Box::new(stuffr_core::testing::SharedBuf::new()), &opts) {
                Err(err) => assert!(
                    matches!(err, Error::Usage(_)),
                    "level {level}: encoder() must agree with check_encode_opts, got {err:?}"
                ),
                Ok(_) => {
                    panic!("level {level}: encoder() accepted a level check_encode_opts rejects")
                }
            }
        }
        for level in [9, 10, 16] {
            let opts = EncodeOpts {
                level: Some(level),
                ..Default::default()
            };
            CompressZ
                .check_encode_opts(&opts)
                .unwrap_or_else(|e| panic!("level {level} must be accepted: {e}"));
        }
    }

    #[test]
    fn the_decoded_stream_reports_no_seek() {
        let src: Box<dyn Source> =
            Box::new(ReaderSource::new(std::io::Cursor::new(HELLO_Z.to_vec())));
        let dec = CompressZ.decoder(src, &DecodeOpts::default()).unwrap();
        assert!(!dec.caps().seekable);
    }

    #[test]
    fn a_bad_magic_is_reported_as_corrupt() {
        let mut bad = HELLO_Z.to_vec();
        bad[0] = 0x00;
        let err = decompress(&bad).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn an_empty_source_decodes_to_empty_output() {
        assert_eq!(decompress(&[]).unwrap(), b"");
    }

    #[test]
    fn a_single_byte_source_is_reported_as_corrupt_not_panicking() {
        let err = decompress(&[0x1f]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// Was `assert_codec_conforms_with(.., Some(HELLO_Z))` while this codec
    /// was decode-only. With a real encoder it graduates to the FULL
    /// twelve-property harness, round trip (property 2) included — see the
    /// module doc's "Encoding" section for what changes once this runs.
    #[test]
    fn compress_z_conforms_with_an_encoder() {
        stuffr_core::testing::assert_codec_conforms(&CompressZ, &meta());
    }

    /// The system tool must read what we write. This is the external witness
    /// `.Z` has and ARJ does not (ARJ's own fixture has no independent tool
    /// to check it against at all — see `legacy/mod.rs`'s MANIFEST note).
    ///
    /// Deliberately at the DEFAULT level (16), not 9: `SynthZ`'s own doc (see
    /// the historical comment kept on the test helper below) measured that
    /// (N)compress 5.0 cannot decode its own `-b 9` output once the
    /// dictionary fills, so `-b 9` needs its own, separately-justified test —
    /// [`the_system_uncompress_reads_what_we_write_at_maxbits_9`] — rather
    /// than being folded into this one.
    #[test]
    fn the_system_uncompress_reads_what_we_write() {
        let uncompress_bin = require_bin("uncompress");
        let payload = pseudo_random_payload(9_000, 0xFEEDFACE);

        let buf = stuffr_core::testing::SharedBuf::new();
        let mut sink = CompressZ
            .encoder(Box::new(buf.clone()), &EncodeOpts::default())
            .unwrap();
        sink.write_all(&payload).unwrap();
        sink.finish().unwrap();
        let packed = buf.contents();

        assert_eq!(
            system_uncompress(&uncompress_bin, &packed, 500),
            payload,
            "the system `uncompress` must read this build's own `.Z` output back as the \
             original plaintext"
        );

        // Our own decoder must agree too — this is the property 2 round trip
        // already checked, restated here because it is the point of this
        // specific test's name.
        assert_eq!(decompress(&packed).unwrap(), payload);
    }

    /// `maxbits == 9` is the one level where NEITHER real `compress` can
    /// serve as a full round-trip witness (see this module's own doc and
    /// `synth_z`'s historical doc above): BSD `uncompress` refuses any
    /// `maxbits < 12` outright, including its own encoder's `-b 9` output,
    /// and GNU `ncompress` 5.0 cannot decode its OWN `-b 9` output once the
    /// 512-entry dictionary fills. So the only witness able to both accept a
    /// `maxbits == 9` stream and be present on every platform this project
    /// tests on is GNU `ncompress`'s `uncompress` — see
    /// [`require_gnu_uncompress`] for how this resolves it deliberately
    /// rather than through `PATH`, and why that resolves to the SAME binary
    /// on both platforms this project runs on despite the two branches
    /// looking different.
    #[test]
    fn the_system_uncompress_reads_what_we_write_at_maxbits_9() {
        let uncompress_bin = require_gnu_uncompress();
        let payload = pseudo_random_payload(400, 0xFEEDFACE);

        let buf = stuffr_core::testing::SharedBuf::new();
        let opts = EncodeOpts {
            level: Some(9),
            ..Default::default()
        };
        let mut sink = CompressZ.encoder(Box::new(buf.clone()), &opts).unwrap();
        sink.write_all(&payload).unwrap();
        sink.finish().unwrap();
        let packed = buf.contents();

        assert_eq!(
            system_uncompress(&uncompress_bin, &packed, 501),
            payload,
            "GNU ncompress's own uncompress must read this build's maxbits=9 output back as \
             the original plaintext"
        );
        assert_eq!(decompress(&packed).unwrap(), payload);
    }

    /// Direct falsification of property 8's specific concern: read exactly
    /// one byte from the decoder and confirm the underlying SOURCE was not
    /// drained to do it. A regression back to a read-to-end shape (e.g.
    /// reverting to `lzw_z::Decoder`) fails this immediately, the same way
    /// it failed conformance property 8 when first measured.
    #[test]
    fn the_first_byte_of_output_does_not_require_reading_the_whole_input() {
        struct Metered {
            inner: std::io::Cursor<Vec<u8>>,
            served: std::sync::Arc<std::sync::atomic::AtomicU64>,
        }
        impl Read for Metered {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let n = self.inner.read(buf)?;
                self.served
                    .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                Ok(n)
            }
        }
        impl Source for Metered {
            fn caps(&self) -> stuffr_core::SourceCaps {
                stuffr_core::SourceCaps {
                    seekable: false,
                    len: None,
                }
            }
            fn as_seek(&mut self) -> Option<&mut dyn stuffr_core::SeekRead> {
                None
            }
        }

        let served = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let src: Box<dyn Source> = Box::new(Metered {
            inner: std::io::Cursor::new(HELLO_Z.to_vec()),
            served: std::sync::Arc::clone(&served),
        });
        let mut dec = CompressZ.decoder(src, &DecodeOpts::default()).unwrap();
        let mut first = [0u8; 1];
        let n = dec.read(&mut first).unwrap();
        assert_eq!(n, 1);
        assert_eq!(&first, b"t");
        let consumed = served.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            consumed < HELLO_Z.len() as u64,
            "first byte of output required reading {consumed} of {} input bytes — this is the \
             read-to-end shape property 8 exists to catch",
            HELLO_Z.len()
        );
    }

    /// Cross-validates this module's from-scratch incremental decoder
    /// against `newtua-lzw-z`'s own `decompress_slice` — the crate's
    /// full-buffer reference implementation, used here purely as a decode
    /// oracle (see the module doc for why it is not on the production path)
    /// — over both the fixture and a battery of payloads the REAL system
    /// `compress` binary produced, so a bug in this port's bit-for-bit
    /// translation of `decode.rs` cannot hide behind only ever exercising
    /// one fixture.
    #[test]
    fn matches_the_crates_own_reference_decoder_across_many_payloads() {
        assert_eq!(
            decompress(HELLO_Z).unwrap(),
            lzw_z::decompress_slice(HELLO_Z).unwrap(),
            "fixture mismatch against newtua-lzw-z's own decompress_slice"
        );

        let compress_bin = require_bin("compress");
        let payloads: &[&[u8]] = &[
            b"",
            b"a",
            b"aa",
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"the quick brown fox jumps over the lazy dog\n",
        ];
        // A longer, more repetitive payload pushes the code width past its
        // initial 9 bits, exercising the width-growth alignment path
        // (`align_to_group`) that the short fixture above never reaches.
        let repetitive: Vec<u8> = (0..20_000)
            .map(|i| b"abcdefghij"[i % 10])
            .collect::<Vec<u8>>();

        for (i, payload) in payloads
            .iter()
            .map(|p| p.to_vec())
            .chain(std::iter::once(repetitive))
            .enumerate()
        {
            let packed = system_compress(&compress_bin, &payload, i);
            let via_this_module = decompress(&packed)
                .unwrap_or_else(|e| panic!("payload {i}: this module's decoder failed: {e}"));
            let via_crate_oracle = lzw_z::decompress_slice(&packed)
                .unwrap_or_else(|e| panic!("payload {i}: newtua-lzw-z's own decoder failed: {e}"));
            assert_eq!(
                via_this_module, via_crate_oracle,
                "payload {i}: this module's decoder disagrees with newtua-lzw-z's own reference \
                 decoder"
            );
            assert_eq!(
                via_this_module, payload,
                "payload {i}: decoded bytes do not match the original plaintext"
            );
        }
    }

    /// `/usr/bin/compress`/`/usr/bin/uncompress` are present on macOS and
    /// most Linux distributions. Following the `require_bin` convention:
    /// fail loudly if absent rather than skip silently, since a silent skip
    /// proves nothing and CI installs it.
    fn require_bin(name: &str) -> std::path::PathBuf {
        let path = std::env::var_os("PATH").expect("PATH must be set");
        std::env::split_paths(&path)
            .find_map(|dir| {
                let candidate = dir.join(name);
                candidate.is_file().then_some(candidate)
            })
            .unwrap_or_else(|| {
                panic!(
                    "{name} not found on PATH — this test requires it (CI installs it; a \
                     silent skip would prove nothing)"
                )
            })
    }

    /// Resolves GNU `ncompress`'s own `uncompress` — the one witness able to
    /// read a `maxbits == 9` stream back (see `the_system_uncompress_reads_
    /// what_we_write_at_maxbits_9`'s doc for why: BSD `uncompress` refuses
    /// any `maxbits < 12` outright, and GNU `ncompress` 5.0's OWN encoder
    /// output at `-b 9` is unreadable even by itself once the dictionary
    /// fills, so only a stream this crate wrote plus the GNU DECODER
    /// specifically proves anything here).
    ///
    /// Deliberately NOT `require_bin("uncompress")` — resolving through
    /// `PATH` would exercise a DIFFERENT implementation per platform while
    /// looking identical, exactly the shape that has already produced three
    /// Linux-only CI failures this machine could not see (cpio's missing
    /// `S_IFREG`, `ar`'s inline-name collapse, and GNU `uncompress`'s own
    /// maxbits-9 decode defect this project measured once already). Instead:
    ///
    /// - **macOS**: Homebrew's `ncompress` formula is keg-only, so the GNU
    ///   binary sits at this fixed path under NO name on `PATH` at all —
    ///   and macOS's own `/usr/bin/uncompress` on `PATH` is the BSD
    ///   implementation, which would silently make this test pass for the
    ///   wrong reason (refusing outright, not reading successfully) if
    ///   swapped in by accident.
    /// - **Every other platform (CI's Linux runners)**: `ci.yml` installs
    ///   the `ncompress` package unconditionally, and on Debian/Ubuntu that
    ///   package IS the system `uncompress` under the plain name — there is
    ///   no BSD alternative there to collide with, so `PATH` resolution is
    ///   correct and reaches the identical GNU implementation the macOS
    ///   branch reaches by fixed path.
    fn require_gnu_uncompress() -> std::path::PathBuf {
        #[cfg(target_os = "macos")]
        {
            let path = std::path::PathBuf::from("/opt/homebrew/opt/ncompress/bin/uncompress");
            assert!(
                path.is_file(),
                "{path:?} not found — this test requires GNU (N)compress's `uncompress` \
                 specifically, not macOS's own BSD `/usr/bin/uncompress` (see this function's \
                 own doc); `brew install ncompress`"
            );
            path
        }
        #[cfg(not(target_os = "macos"))]
        {
            require_bin("uncompress")
        }
    }

    fn system_compress(compress_bin: &std::path::Path, payload: &[u8], tag: usize) -> Vec<u8> {
        system_compress_args(compress_bin, payload, tag, &[])
    }

    /// [`system_compress`]'s generalisation for a specific `-b maxbits`
    /// (or any other flag `/usr/bin/compress` accepts before `-c`).
    fn system_compress_args(
        compress_bin: &std::path::Path,
        payload: &[u8],
        tag: usize,
        extra_args: &[&str],
    ) -> Vec<u8> {
        let in_path = std::env::temp_dir().join(format!(
            "stuffr-compress-z-{tag}-{}.txt",
            std::process::id()
        ));
        std::fs::write(&in_path, payload).unwrap();
        let out = std::process::Command::new(compress_bin)
            .args(extra_args)
            .arg("-c")
            .arg(&in_path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "tag {tag}: system compress {extra_args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let _ = std::fs::remove_file(&in_path);
        out.stdout
    }

    /// Decompresses `packed` with the system `uncompress`, as the external
    /// witness that a stream this module SYNTHESISED is a genuine `.Z` and
    /// not merely something this module's own decoder happens to like. The
    /// temp file keeps its `.Z` suffix because both `uncompress`
    /// implementations refuse a name without one even under `-c`.
    fn system_uncompress(uncompress_bin: &std::path::Path, packed: &[u8], tag: usize) -> Vec<u8> {
        let in_path =
            std::env::temp_dir().join(format!("stuffr-compress-z-{tag}-{}.Z", std::process::id()));
        std::fs::write(&in_path, packed).unwrap();
        let out = std::process::Command::new(uncompress_bin)
            .arg("-c")
            .arg(&in_path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "tag {tag}: system uncompress rejected a synthesised stream: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let _ = std::fs::remove_file(&in_path);
        out.stdout
    }

    /// Historical note, kept for anyone who reads this test file top to
    /// bottom: this helper used to build its OWN from-scratch LZW encoder
    /// (`SynthZ`), separate from and predating the production one. Phase 3c
    /// Task 5 promoted that engine out of `#[cfg(test)]` into
    /// [`super::LzwEncoder`] and wired it to a real [`stuffr_core::Sink`]
    /// (see the module doc's "Encoding" section) — so this helper now drives
    /// the SAME production type the `Codec::encoder` impl uses, via
    /// [`LzwEncoder::push_byte`]'s public-within-module `bool` return (did
    /// this call actually emit a code, as opposed to extending a dictionary
    /// match?) to place a manual CLEAR at exactly the point the real
    /// encoder's `cl_block` ratio check could fire. That return value is
    /// what lets `clear_after` below skip a CLEAR opportunity on an
    /// iteration that only extended a match — exactly as the original
    /// hand-rolled dictionary loop did by `continue`-ing past the check.
    ///
    /// ## Why this exists at all: the reference tools disagree at `maxbits == 9`
    ///
    /// Both `compress` implementations this project meets write the same
    /// `-b 9` header (`1f 9d 89`), and produce mutually unreadable bytes
    /// under it once the 512-entry dictionary fills. MEASURED, on a
    /// 130 000-byte pseudo-random payload:
    ///
    /// | stream | this module | GNU `uncompress` | BSD `uncompress` |
    /// |---|---|---|---|
    /// | BSD `compress -b 9` | byte-exact | byte-exact | refuses `maxbits < 12` |
    /// | GNU `compress -b 9` | `invalid LZW code` | **`corrupt input`** | refuses `maxbits < 12` |
    ///
    /// The middle cell is the finding: **(N)compress 5.0 cannot decode its
    /// own `-b 9` output.** It is a defect in that encoder, not a second
    /// legal dialect — it begins the moment the dictionary fills (clean at
    /// 300 input bytes, broken at 600 and every size above) and nothing
    /// reads the result. So `-b 9` from the system tool cannot serve as a
    /// reference stream on a machine whose `compress` is (N)compress, which
    /// is every Linux CI runner. BSD's own `uncompress` is no fallback
    /// either: it refuses ANY `maxbits < 12` outright, its own `-b 9` and
    /// `-b 10` output included.
    ///
    /// ## Why growing to 10 bits at `maxbits == 9` is correct
    ///
    /// Because `INIT_BITS == 9`, the ordinary rule — widen when `free_ent`
    /// passes `maxcode`, and only cap `maxcode` at `maxmaxcode` once
    /// `n_bits == maxbits` — makes a maxbits-9 stream widen to 10-bit codes
    /// the instant its 512 entries are used up, and stay there. That reads
    /// like a bug and is not one: it is what `compress.c`'s `output()` and
    /// `getcode()` both do, and BSD `compress -b 9`'s bytes agree with this
    /// encoder's byte for byte, decoded byte-exactly by GNU `uncompress`.
    ///
    /// ## What keeps this from being self-referential
    ///
    /// A synthesiser sharing no code with the production encoder could prove
    /// something a wrapper around that SAME encoder cannot on its own — so
    /// two live guards still carry the external weight, unchanged by this
    /// promotion:
    ///
    /// 1. [`the_stream_synthesiser_matches_the_system_encoder_byte_for_byte`]
    ///    compares this encoder's output with the REAL `compress` binary's,
    ///    byte for byte, at four `maxbits` — an external encoder, agreeing
    ///    exactly.
    /// 2. [`decodes_a_stream_with_block_mode_clears_and_width_growth`] hands
    ///    its synthesised CLEAR-bearing stream to the system `uncompress`
    ///    and requires the original plaintext back — an external decoder,
    ///    agreeing exactly.
    ///
    /// ## Deliberately not modelled: the ratio heuristic
    ///
    /// The real encoder decides WHEN to emit a block-mode CLEAR from a
    /// compression-ratio check (`cl_block`), and the two implementations
    /// disagree wildly about it — on one 130 000-byte payload at `-b 12`,
    /// BSD emits 2 CLEARs and GNU emits 0, which is precisely how the CLEAR
    /// test came to assert against a stream that had none. `clear_after`
    /// places the CLEAR explicitly instead: same wire format, no heuristic,
    /// same answer on every machine. The PRODUCTION encoder
    /// ([`super::LzwEncoder`] as `Codec::encoder` drives it) never calls this
    /// — it has no ratio heuristic at all and simply never emits a CLEAR
    /// (see the module doc).
    ///
    /// Encodes `payload` as a block-mode `.Z` stream at `maxbits`, emitting
    /// one block-mode CLEAR once `clear_after` input bytes have been
    /// consumed (`None` for no CLEAR at all).
    fn synth_z(payload: &[u8], maxbits: u32, clear_after: Option<usize>) -> Vec<u8> {
        let (mut enc, header) = LzwEncoder::new(maxbits);
        let mut out = header.to_vec();
        let Some((&first, rest)) = payload.split_first() else {
            enc.finish(&mut out);
            return out;
        };
        // Seeds `enc.ent` exactly as the first call to `push_byte` would
        // (its `None` branch) — spelled out via the public entry point
        // rather than reaching into the private field directly, so this
        // helper exercises the same code every real write does.
        enc.push_byte(first, &mut out);
        let mut clear_after = clear_after;
        for (i, &c) in rest.iter().enumerate() {
            let emitted = enc.push_byte(c, &mut out);
            if emitted && clear_after.is_some_and(|at| i + 1 >= at) {
                enc.dict.clear();
                enc.free_ent = CLEAR + 1;
                enc.clear_flg = true;
                enc.output(CLEAR, &mut out);
                clear_after = None;
            }
        }
        enc.finish(&mut out);
        out
    }

    /// A deterministic, non-repeating pseudo-random payload over a small
    /// alphabet — high enough entropy that `/usr/bin/compress` fills its
    /// dictionary (and, at `-b 12` over a large enough length, resets it via
    /// block-mode CLEAR) rather than compressing so well the fixed-size
    /// payload never reaches those branches. `xorshift64`, not a crate
    /// dependency: deterministic across runs and platforms, which is what
    /// makes a byte-exact assertion against it meaningful.
    fn pseudo_random_payload(len: usize, seed: u64) -> Vec<u8> {
        const ALPHABET: &[u8] = b"abcdefghijklmnop ";
        let mut state = seed | 1; // xorshift64 requires a non-zero state
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                ALPHABET[(state as usize) % ALPHABET.len()]
            })
            .collect()
    }

    #[test]
    fn a_real_compress_stream_round_trips_against_the_system_tool() {
        // The interop test that matters most: it must be able to fail if the
        // decoder produces WRONG bytes, not merely if it errors. So this
        // compresses several distinct payloads with the real system tool —
        // not just the fixture — and checks the decoded bytes match the
        // ORIGINAL plaintext exactly, byte for byte.
        let compress_bin = require_bin("compress");

        let payloads: &[&[u8]] = &[
            b"",
            b"a",
            b"the quick brown fox jumps over the lazy dog\n",
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ];

        for (i, payload) in payloads.iter().enumerate() {
            let packed = system_compress(&compress_bin, payload, 100 + i);
            let decoded = decompress(&packed).unwrap_or_else(|e| {
                panic!("payload {i}: decoding the system tool's own output failed: {e}")
            });
            assert_eq!(
                &decoded, payload,
                "payload {i}: decoded bytes must match the ORIGINAL plaintext exactly — a \
                 decoder that silently produced different bytes would still pass a test that \
                 only checked for success"
            );
        }
    }

    /// Falsifies `synth_z` against the real thing: at four `maxbits`, its
    /// bytes must be IDENTICAL to what the system `compress` binary writes
    /// for the same payload. Without this, the two tests below would feed
    /// this module's decoder a stream written by this module's own test
    /// code — a closed loop that could agree on a shared mistake and call it
    /// a pass.
    ///
    /// Every payload here is under 10 000 bytes, and that is structural
    /// rather than lucky: `cl_block`'s ratio check is gated on `in_count >=
    /// checkpoint` with `CHECK_GAP == 10 000`, so no implementation's
    /// heuristic can fire below that and the output is the canonical LZW
    /// stream with nothing left to disagree about. 9 000 is then as large as
    /// that bound allows, and it needs to be: at `-b 10` it fills the
    /// dictionary and so exercises the `n_bits == maxbits` maxcode cap,
    /// which a 1 200-byte payload reached at NO maxbits — measured by
    /// breaking the cap and watching this test stay green.
    ///
    /// The 200-byte payload is the `maxbits == 9` case specifically: it is
    /// short enough that the 512-entry dictionary never fills, which is the
    /// only region where (N)compress 5.0's `-b 9` output is still correct
    /// (see `synth_z`'s own doc for the measurement).
    ///
    /// One thing this test does NOT reach, and the CLEAR test below does:
    /// the zero-padding of a partial group. A width transition always lands
    /// exactly on a group boundary — each width holds a power-of-two number
    /// of codes and a group is 8 — so only a CLEAR, which resets at an
    /// arbitrary point, leaves a partial group to pad.
    #[test]
    fn the_stream_synthesiser_matches_the_system_encoder_byte_for_byte() {
        let compress_bin = require_bin("compress");
        let cases: &[(usize, u32)] = &[(200, 9), (9_000, 10), (9_000, 12), (9_000, 16)];

        for (i, &(len, maxbits)) in cases.iter().enumerate() {
            let payload = pseudo_random_payload(len, 0xC0FFEE);
            let theirs = system_compress_args(
                &compress_bin,
                &payload,
                400 + i,
                &["-b", &maxbits.to_string()],
            );
            let ours = synth_z(&payload, maxbits, None);
            assert_eq!(
                ours,
                theirs,
                "maxbits={maxbits}, {len}-byte payload: this test's own encoder wrote {} bytes \
                 and the system `compress` wrote {} — they must agree byte for byte, or the \
                 streams the tests below decode are not real `.Z` streams",
                ours.len(),
                theirs.len()
            );
        }
    }

    /// Regression test for a real bug the review round caught: the width-
    /// growth guard used to read `dict.free_ent > dict.maxcode &&
    /// dict.n_bits < dict.maxbits`. That second clause is FALSE from the
    /// very first code whenever `maxbits == INIT_BITS == 9` (the code width
    /// never has room to grow past what it starts at), so the branch never
    /// ran at all — including its `align_to_group`/bit-skip step, which the
    /// real encoder performs unconditionally at this exact point regardless
    /// of whether the width numerically changes. Skipping it left the
    /// decoder's bit position permanently out of sync with the real stream
    /// the moment the dictionary filled (512 entries), corrupting every code
    /// read after that point.
    ///
    /// The stream is SYNTHESISED rather than taken from the system tool, and
    /// that is not a convenience: (N)compress 5.0 — the `compress` on every
    /// Linux CI runner — writes `-b 9` output that its OWN `uncompress`
    /// rejects as `corrupt input`, while BSD's `uncompress` refuses every
    /// `maxbits < 12` outright. There is no machine on which the system tool
    /// can supply a valid maxbits-9 stream AND read it back. `synth_z`'s
    /// doc carries the full measurement, and
    /// [`the_stream_synthesiser_matches_the_system_encoder_byte_for_byte`]
    /// is what keeps this stream honest.
    #[test]
    fn a_maxbits_9_stream_decodes_byte_exactly() {
        let payload = pseudo_random_payload(40_000, 0xC0FFEE);
        let packed = synth_z(&payload, 9, None);

        let decoded = decompress(&packed)
            .unwrap_or_else(|e| panic!("maxbits=9 stream failed to decode: {e}"));
        assert_eq!(
            decoded, payload,
            "a maxbits=9 stream, once the 512-entry dictionary fills, must still decode \
             byte-exactly"
        );
        // `newtua-lzw-z` — this module's decode oracle everywhere else, and
        // the implementation this port is derived from — still carries the
        // `n_bits < maxbits` clause described above, so it REFUSES this
        // stream. That divergence is asserted rather than left implicit for
        // two reasons: it is the one payload shape where the oracle is not
        // an oracle (a reader who sees it used freely elsewhere needs to
        // know where it stops), and it is what makes the fix above a real
        // improvement over its ancestor rather than a restatement of it.
        // Stable because the dependency is pinned `=0.1.0`; if a bump makes
        // this start passing, the crate has fixed the same bug and this
        // assertion should become an equality against `payload`.
        let oracle = lzw_z::decompress_slice(&packed);
        assert!(
            oracle.is_err(),
            "newtua-lzw-z 0.1.0 is expected to refuse a maxbits=9 stream whose dictionary \
             fills — it has the very `n_bits < maxbits` clause this test's own regression \
             documents. It returned {} bytes instead; re-read this test if the pin moved.",
            oracle.map_or(0, |v| v.len())
        );
    }

    /// Before this test, NO test in the repo exercised the block-mode CLEAR
    /// branch (group alignment, `boff` update, dictionary reset, forced
    /// literal) at all: `hello.Z` has 0 CLEARs and a single code width (9),
    /// and the cross-validation test's own width-growth payload only grows
    /// 9->10, 0 CLEARs.
    ///
    /// It used to ask `compress -b 12` over a large random payload to
    /// produce a CLEAR by its own ratio heuristic, and that is exactly what
    /// broke: on one 130 000-byte payload BSD `compress` emits 2 CLEARs and
    /// (N)compress emits 0, so the branch this test exists for was reached
    /// on one machine and not the other — the vacuity its own assertion
    /// message warned about, arriving as a red CI job. The CLEAR is now
    /// placed explicitly by [`synth_z`], which is deterministic everywhere,
    /// and the stream still grows the code width 9->10->11->12 before the
    /// CLEAR and again after it.
    ///
    /// The external witness here is a decoder rather than an encoder: the
    /// system `uncompress` must return the original plaintext from this
    /// synthesised stream. BOTH implementations accept `maxbits == 12` (it
    /// is 9 and 10 that BSD refuses), so unlike the maxbits-9 test above
    /// this one gets a real third-party decoder's verdict on every machine.
    #[test]
    fn decodes_a_stream_with_block_mode_clears_and_width_growth() {
        let uncompress_bin = require_bin("uncompress");
        let payload = pseudo_random_payload(40_000, 0xBADC0DE);
        let packed = synth_z(&payload, 12, Some(20_000));

        assert_eq!(
            system_uncompress(&uncompress_bin, &packed, 410),
            payload,
            "the system `uncompress` must read this synthesised stream back as the original \
             plaintext — otherwise it is not a real `.Z` and proves nothing about this \
             module's decoder"
        );

        let src: Box<dyn Source> =
            Box::new(ReaderSource::new(std::io::Cursor::new(packed.clone())));
        let mut reader = LzwZReader::new(src);
        let mut decoded = Vec::new();
        reader
            .read_to_end(&mut decoded)
            .unwrap_or_else(|e| panic!("maxbits=12 stream failed to decode: {e}"));

        assert_eq!(
            decoded, payload,
            "a maxbits=12 stream must decode byte-exactly"
        );
        assert!(
            reader.clears_seen() > 0,
            "this payload was expected to force at least one block-mode CLEAR (dictionary \
             reset) — got 0. `synth_z` was asked for one explicitly, so either it stopped \
             emitting it or the decoder stopped recognising it; either way, a run of this \
             test that passes without ever reaching CLEAR proves nothing about that branch"
        );
    }

    /// The system tool's own streams, at every `maxbits` both
    /// implementations can actually write and read — the interop half that
    /// [`a_maxbits_9_stream_decodes_byte_exactly`] gave up when it stopped
    /// asking a binary for its input.
    ///
    /// 10..=16, not 9..=16. `maxbits == 9` is excluded for one measured
    /// reason and not out of caution: (N)compress 5.0's `-b 9` output is
    /// undecodable by (N)compress 5.0 itself once the dictionary fills, so
    /// including it here would assert that this module reads a stream its
    /// own author cannot. See `synth_z`'s doc.
    ///
    /// The payload is large enough that `-b 16` genuinely reaches 16-bit
    /// codes rather than stopping partway up the ladder.
    #[test]
    fn a_system_compress_stream_decodes_byte_exactly_at_every_readable_maxbits() {
        let compress_bin = require_bin("compress");
        let payload = pseudo_random_payload(130_000, 0xC0FFEE);

        for maxbits in 10..=16u32 {
            let packed = system_compress_args(
                &compress_bin,
                &payload,
                420 + maxbits as usize,
                &["-b", &maxbits.to_string()],
            );
            let decoded = decompress(&packed).unwrap_or_else(|e| {
                panic!("maxbits={maxbits}: decoding the system tool's own output failed: {e}")
            });
            assert_eq!(
                decoded, payload,
                "maxbits={maxbits}: decoded bytes must match the ORIGINAL plaintext exactly"
            );
        }
    }
}
