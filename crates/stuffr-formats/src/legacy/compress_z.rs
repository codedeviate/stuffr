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

use std::collections::VecDeque;
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
            ..CodecCaps::decode_only()
        }
    }

    /// See the module doc for why this is [`LzwZReader`], a from-scratch
    /// incremental port of `newtua-lzw-z`'s own algorithm, rather than a
    /// wrapper over that crate's `Decoder`.
    fn decoder(&self, src: Box<dyn Source>, _o: &DecodeOpts) -> Result<Box<dyn Source>> {
        Ok(Box::new(StreamOnly::new(LzwZReader::new(src))))
    }

    /// Unreachable through ops: `Registry::require_encoder` reads
    /// `caps().encode` and refuses first (`CLAUDE.md` mandates registering
    /// through it rather than the raw accessor). This is the trait-level
    /// backstop, and it answers the SAME error the registry raises — it used
    /// to answer `Error::Unsupported` with a carefully-worded sentence no
    /// user could ever reach.
    fn encoder(&self, _dst: Box<dyn Write + Send>, _o: &EncodeOpts) -> Result<Box<dyn Sink>> {
        Err(Error::CapabilityUnavailable {
            format: COMPRESS,
            available: "read",
            requested: "written",
        })
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
        assert!(c.decode && !c.encode);
        assert!(
            c.truncation_undetectable,
            "see this module's doc and CodecCaps::truncation_undetectable's own doc for why"
        );
        let m = meta();
        assert_eq!(m.id, COMPRESS);
        assert_eq!(m.extensions, &["z"]);
    }

    #[test]
    fn encoder_is_refused_as_a_capability_limit_not_a_panic() {
        let opts = EncodeOpts::default();
        match CompressZ.encoder(Box::new(stuffr_core::testing::SharedBuf::new()), &opts) {
            Err(err) => {
                // The SAME variant `Registry::require_encoder` raises — the
                // refusal a user actually meets. This method is unreachable
                // through ops, and used to answer a different, carefully
                // worded `Error::Unsupported` nobody could ever see.
                assert!(
                    matches!(err, Error::CapabilityUnavailable { .. }),
                    "got {err:?}"
                );
                assert_eq!(err.exit_code(), 3);
            }
            Ok(_) => panic!("compress (.Z) must not be able to encode"),
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

    #[test]
    fn compress_z_conforms() {
        stuffr_core::testing::assert_codec_conforms_with(&CompressZ, &meta(), Some(HELLO_Z));
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
    /// Measured directly: a 130 000-byte payload compressed with
    /// `compress -b 9` used to fail (`invalid LZW code in stream`) once
    /// decoded far enough to fill the dictionary; dropping the `n_bits <
    /// maxbits` clause entirely (this codec's own bounds check on `code` is
    /// what keeps indexing memory-safe, not that clause — see `code >
    /// dict.free_ent` above) decodes it byte-exactly, and changes nothing
    /// for `-b 10/12/16` (also covered below and by the cross-validation
    /// test), since for those the clause was true anyway at the point that
    /// matters.
    #[test]
    fn a_maxbits_9_stream_decodes_byte_exactly() {
        let compress_bin = require_bin("compress");
        let payload = pseudo_random_payload(130_000, 0xC0FFEE);
        let packed = system_compress_args(&compress_bin, &payload, 300, &["-b", "9"]);
        let decoded = decompress(&packed)
            .unwrap_or_else(|e| panic!("maxbits=9 stream failed to decode: {e}"));
        assert_eq!(
            decoded, payload,
            "a maxbits=9 stream, once the 512-entry dictionary fills, must still decode \
             byte-exactly"
        );
    }

    /// Before this test, NO test in the repo exercised the block-mode CLEAR
    /// branch (group alignment, `boff` update, dictionary reset, forced
    /// literal) at all: `hello.Z` has 0 CLEARs and a single code width (9),
    /// and the cross-validation test's own width-growth payload only grows
    /// 9->10, 0 CLEARs. `-b 12` over a large, high-entropy payload forces
    /// `compress`'s ratio-triggered dictionary reset repeatedly as it goes,
    /// AND grows the code width from 9 up through 12 — so this asserts the
    /// CLEAR branch was actually reached (not merely hoped for), not just
    /// that the decode happened to succeed.
    #[test]
    fn decodes_a_stream_with_block_mode_clears_and_width_growth() {
        let compress_bin = require_bin("compress");
        let payload = pseudo_random_payload(130_000, 0xBADC0DE);
        let packed = system_compress_args(&compress_bin, &payload, 301, &["-b", "12"]);

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
             reset) — got 0. Either compress's ratio-triggered reset behavior changed, or the \
             payload needs to be larger/more random; either way, a run of this test that \
             passes without ever reaching CLEAR proves nothing about that branch"
        );
    }
}
