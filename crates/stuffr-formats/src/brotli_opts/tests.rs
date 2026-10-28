//! Tests for the brotli options seam, on whichever tier this build compiles.
//!
//! The reference fixtures under `tests/data/brotli/` were written by
//! `/opt/homebrew/bin/brotli` 1.2.1 (`brotli -q Q -c FILE`, and `-C YWJj` for
//! the comment one) from the inputs [`text`] and [`mixed`] build; the
//! ignored [`write_fixture_inputs`] writes those inputs out again, so the
//! fixtures can be regenerated:
//!
//! ```text
//! STUFFR_BROTLI_FIXTURE_DIR=/some/dir cargo test -p stuffr-formats \
//!     --features brotli brotli_opts::tests::write_fixture_inputs -- --ignored
//! brotli -q 0  -c /some/dir/text.txt  > tests/data/brotli/text-q0.br
//! brotli -q 5  -c /some/dir/text.txt  > tests/data/brotli/text-q5.br
//! brotli -q 11 -c /some/dir/text.txt  > tests/data/brotli/text-q11.br
//! brotli -q 9  -c /some/dir/mixed.bin > tests/data/brotli/mixed-q9.br
//! brotli -q 11 -C YWJj -c /some/dir/text.txt > tests/data/brotli/text-q11-comment.br
//! ```

use super::*;

/// The tool's read size (`kFileBufferSize`).
const CHUNK: usize = 1 << 19;

/// xorshift64*: a fixed, dependency-free generator, so the inputs (and with
/// them the recorded fixtures) never depend on a crate's version.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

const WORDS: &[&str] = &[
    "the",
    "quick",
    "brown",
    "fox",
    "jumps",
    "over",
    "lazy",
    "dog",
    "stream",
    "window",
    "block",
    "archive",
    "brotli",
    "compress",
    "literal",
    "context",
    "huffman",
    "distance",
    "metadata",
    "dictionary",
    "quality",
    "buffer",
    "output",
    "input",
    "and",
    "of",
    "a",
    "to",
    "in",
    "is",
    "that",
    "it",
    "with",
    "for",
    "as",
    "was",
    "on",
    "be",
    "at",
    "by",
];

/// 200 KiB of word salad: compressible text.
fn text() -> Vec<u8> {
    let mut rng = Rng(0x5EED_0B07_0011_2026);
    let mut out = Vec::with_capacity(200 << 10);
    let mut on_line = 0;
    while out.len() < 200 << 10 {
        let word = WORDS[(rng.next() % WORDS.len() as u64) as usize];
        out.extend_from_slice(word.as_bytes());
        on_line += 1;
        if on_line == 12 {
            out.push(b'\n');
            on_line = 0;
        } else {
            out.push(b' ');
        }
    }
    out.truncate(200 << 10);
    out
}

/// 1.5 MiB: 16 KiB pieces of [`text`] at moving offsets, every third piece
/// random bytes instead.
fn mixed() -> Vec<u8> {
    let text = text();
    let mut rng = Rng(0xB0_7711_0000_0015);
    let piece = 16 << 10;
    let mut out = Vec::with_capacity(3 << 19);
    let mut i = 0usize;
    while out.len() < 3 << 19 {
        if i % 3 == 2 {
            for _ in 0..piece / 8 {
                out.extend_from_slice(&rng.next().to_le_bytes());
            }
        } else {
            let at = (i * 7919) % (text.len() - piece);
            out.extend_from_slice(&text[at..at + piece]);
        }
        i += 1;
    }
    out.truncate(3 << 19);
    out
}

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/brotli")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The encoder parameters the tool would use for a file of `input.len()`
/// bytes at quality `q` (no `-w`).
fn params_for(input: &[u8], quality: u32) -> EncoderParams {
    let len = input.len() as u64;
    EncoderParams {
        quality,
        lgwin: window_for_length(Some(len)),
        large_window: false,
        size_hint: (len > 0).then(|| len.min(1 << 30) as u32),
    }
}

/// Compresses as the tool does: an optional comment first, then the input in
/// [`CHUNK`] slices with `Process`, the last with `Finish`, into a
/// [`CHUNK`]-sized output buffer.
fn compress(input: &[u8], p: &EncoderParams, comment: Option<&[u8]>) -> Vec<u8> {
    let mut enc = Encoder::new(p, None).expect("encoder");
    let mut out = Vec::new();
    let mut buf = vec![0u8; CHUNK];
    if let Some(c) = comment {
        let mut meta = c;
        let mut o: &mut [u8] = &mut buf;
        assert!(enc.compress_stream(Operation::EmitMetadata, &mut meta, &mut o));
        assert!(meta.is_empty(), "metadata not consumed");
        let used = CHUNK - o.len();
        out.extend_from_slice(&buf[..used]);
    }
    let mut chunks = input.chunks(CHUNK).peekable();
    let mut pending: &[u8] = chunks.next().unwrap_or(&[]);
    loop {
        let is_eof = chunks.peek().is_none();
        let op = if is_eof {
            Operation::Finish
        } else {
            Operation::Process
        };
        let mut o: &mut [u8] = &mut buf;
        assert!(
            enc.compress_stream(op, &mut pending, &mut o),
            "compress failed"
        );
        let used = CHUNK - o.len();
        out.extend_from_slice(&buf[..used]);
        if enc.is_finished() {
            assert!(is_eof && pending.is_empty());
            return out;
        }
        if pending.is_empty() && !is_eof {
            pending = chunks.next().expect("peeked");
        }
    }
}

/// Decodes `input` whole. `Ok(bytes)` on success, else the last result and
/// what had come out.
fn decompress(input: &[u8], dec: &mut Decoder) -> Result<Vec<u8>, (StreamResult, Vec<u8>)> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; CHUNK];
    let mut rest = input;
    loop {
        let mut o: &mut [u8] = &mut buf;
        let r = dec.decompress_stream(&mut rest, &mut o);
        let used = CHUNK - o.len();
        out.extend_from_slice(&buf[..used]);
        match r {
            StreamResult::NeedsMoreOutput => continue,
            StreamResult::Success if rest.is_empty() => return Ok(out),
            other => return Err((other, out)),
        }
    }
}

fn decode(input: &[u8]) -> Vec<u8> {
    let mut dec = Decoder::new(true, None).expect("decoder");
    match decompress(input, &mut dec) {
        Ok(v) => v,
        Err((r, _)) => panic!("decode failed: {r:?} {:?}", dec.error()),
    }
}

#[test]
fn window_for_length_matches_the_tool() {
    for (len, w) in [
        (None, 24),
        (Some(0), 10),
        (Some(1), 10),
        (Some(1008), 10),
        (Some(1009), 11),
        (Some(158_076), 18),
        (Some(300_000), 19),
        (Some(3_000_000), 22),
        (Some(u64::MAX), 24),
    ] {
        assert_eq!(window_for_length(len), w, "{len:?}");
    }
}

#[test]
fn version_is_1_2_1() {
    assert_eq!(version(), (1, 2, 1));
}

#[test]
fn constants_match_the_tool() {
    assert_eq!(MIN_WINDOW_BITS, 10);
    assert_eq!(MAX_WINDOW_BITS, 24);
    assert_eq!(LARGE_MAX_WINDOW_BITS, 30);
    // BROTLI_MAX_DISTANCE - BROTLI_MAX_BACKWARD_LIMIT(24)
    assert_eq!(MAX_DICTIONARY_SIZE, 0x3FF_FFFC - ((1 << 24) - 16));
}

#[test]
fn round_trip_every_quality() {
    let inputs: [(&str, Vec<u8>); 4] = [
        ("empty", Vec::new()),
        ("one byte", vec![b'x']),
        ("text", text()),
        ("mixed", mixed()),
    ];
    for (name, input) in &inputs {
        for q in 0..=11 {
            let packed = compress(input, &params_for(input, q), None);
            assert_eq!(&decode(&packed), input, "{name} at q{q}");
        }
    }
}

#[test]
fn large_window_round_trips() {
    let input = text();
    let p = EncoderParams {
        quality: 5,
        lgwin: 26,
        large_window: true,
        size_hint: None,
    };
    let packed = compress(&input, &p, None);
    assert_eq!(decode(&packed), input);
    // Without the decoder's large-window switch the stream is refused.
    let mut strict = Decoder::new(false, None).expect("decoder");
    assert!(decompress(&packed, &mut strict).is_err());
}

#[test]
fn a_comment_reaches_the_metadata_callbacks() {
    use std::cell::RefCell;
    use std::rc::Rc;
    let input = text();
    let packed = compress(&input, &params_for(&input, 9), Some(b"hello, brotli"));
    let starts = Rc::new(RefCell::new(Vec::new()));
    let chunks = Rc::new(RefCell::new(Vec::new()));
    let mut dec = Decoder::new(true, None).expect("decoder");
    let (s, c) = (starts.clone(), chunks.clone());
    dec.set_metadata_callbacks(
        Box::new(move |n| s.borrow_mut().push(n)),
        Box::new(move |b: &[u8]| c.borrow_mut().extend_from_slice(b)),
    )
    .expect("callbacks");
    assert_eq!(decompress(&packed, &mut dec).ok(), Some(input));
    assert_eq!(starts.borrow()[0], 13);
    assert!(chunks.borrow().starts_with(b"hello, brotli"));
}

#[test]
fn the_reference_comment_stream_decodes_with_callbacks() {
    use std::cell::RefCell;
    use std::rc::Rc;
    let starts = Rc::new(RefCell::new(Vec::new()));
    let chunks = Rc::new(RefCell::new(Vec::new()));
    let mut dec = Decoder::new(true, None).expect("decoder");
    let (s, c) = (starts.clone(), chunks.clone());
    dec.set_metadata_callbacks(
        Box::new(move |n| s.borrow_mut().push(n)),
        Box::new(move |b: &[u8]| c.borrow_mut().extend_from_slice(b)),
    )
    .expect("callbacks");
    let out = decompress(&fixture("text-q11-comment.br"), &mut dec).ok();
    assert_eq!(out, Some(text()));
    assert_eq!(*starts.borrow(), [3]);
    assert_eq!(*chunks.borrow(), b"abc");
}

#[cfg(feature = "brotli-c")]
#[test]
fn c_tier_matches_reference_fixtures() {
    let text = text();
    let mixed = mixed();
    for (name, input, q, comment) in [
        ("text-q0.br", &text, 0, None),
        ("text-q5.br", &text, 5, None),
        ("text-q11.br", &text, 11, None),
        ("mixed-q9.br", &mixed, 9, None),
        ("text-q11-comment.br", &text, 11, Some(&b"abc"[..])),
    ] {
        let ours = compress(input, &params_for(input, q), comment);
        assert!(ours == fixture(name), "{name} differs from the reference");
    }
}

#[cfg(feature = "brotli-c")]
#[test]
fn c_tier_dictionary_round_trips() {
    let input = text();
    let dict = &input[1000..9000];
    let pd = PreparedDictionary::new(dict, 11).expect("prepare");
    let p = params_for(&input, 9);
    let mut enc = Encoder::new(&p, Some(&pd)).expect("encoder");
    drop(pd); // the encoder keeps what it attached alive
    let mut out = vec![0u8; input.len() + 1024];
    let cap = out.len();
    let mut rest = &input[..];
    let mut o: &mut [u8] = &mut out;
    assert!(enc.compress_stream(Operation::Finish, &mut rest, &mut o));
    assert!(enc.is_finished());
    let used = cap - o.len();
    let packed = &out[..used];
    let mut dec = Decoder::new(true, Some(dict)).expect("decoder");
    assert_eq!(decompress(packed, &mut dec).ok(), Some(input.clone()));
    let mut plain = Decoder::new(true, None).expect("decoder");
    assert!(decompress(packed, &mut plain).is_err());
}

#[cfg(not(feature = "brotli-c"))]
#[test]
fn pure_tier_refuses_dictionaries() {
    assert!(matches!(
        PreparedDictionary::new(b"dict", 11),
        Err(Refused::Dictionary)
    ));
    assert!(matches!(
        Decoder::new(true, Some(b"dict")),
        Err(Refused::Dictionary)
    ));
}

#[test]
fn reference_fixtures_decode() {
    for (name, want) in [
        ("text-q0.br", text()),
        ("text-q5.br", text()),
        ("text-q11.br", text()),
        ("mixed-q9.br", mixed()),
        ("text-q11-comment.br", text()),
    ] {
        assert!(decode(&fixture(name)) == want, "{name}");
    }
}

#[test]
fn decoder_error_names() {
    // Cut in half: the decoder wants more input, which the tool reports as
    // `truncated input` (not an error code).
    let packed = fixture("text-q5.br");
    let mut dec = Decoder::new(true, None).expect("decoder");
    let (r, _) = decompress(&packed[..packed.len() / 2], &mut dec).expect_err("truncated");
    assert_eq!(r, StreamResult::NeedsMoreInput);

    // 0xff alone: a 24-bit window and an empty last meta-block, then two
    // set padding bits (the reference: `reason: FORMAT_PADDING_2 (-15)`).
    let mut dec = Decoder::new(true, None).expect("decoder");
    let (r, _) = decompress(&[0xff], &mut dec).expect_err("corrupt");
    assert_eq!(r, StreamResult::Error);
    assert_eq!(
        dec.error(),
        DecoderError {
            code: -15,
            name: "_ERROR_FORMAT_PADDING_2"
        }
    );

    // A metadata block with non-zero padding: -14 on both tiers (the pure
    // tier remaps the crate's -15 by its state, Ruling T1-e). Header bits:
    // WBITS 0 (16), ISLAST 0, MNIBBLES 11 (metadata), reserved 0, MSKIPBYTES
    // 00 (an empty block), then the last bit before the byte boundary set
    // (the reference: `reason: FORMAT_PADDING_1 (-14)`).
    let mut dec = Decoder::new(true, None).expect("decoder");
    let (r, _) = decompress(&[0b1000_1100], &mut dec).expect_err("corrupt");
    assert_eq!(r, StreamResult::Error);
    assert_eq!(
        dec.error(),
        DecoderError {
            code: -14,
            name: "_ERROR_FORMAT_PADDING_1"
        }
    );
}

#[test]
fn error_name_table_matches_libbrotli() {
    assert_eq!(error_name(-6), "_ERROR_FORMAT_CL_SPACE");
    assert_eq!(error_name(-31), "_ERROR_UNREACHABLE");
    assert_eq!(error_name(-18), "_ERROR_COMPOUND_DICTIONARY");
    assert_eq!(error_name(-26), "_ERROR_ALLOC_RING_BUFFER_1");
    assert_eq!(error_name(0), "_NO_ERROR");
    assert_eq!(error_name(-23), "INVALID");
}

/// Writes the fixture inputs for regenerating `tests/data/brotli/` (module
/// doc).
#[test]
#[ignore = "writes the fixture inputs; run by hand"]
fn write_fixture_inputs() {
    let dir = std::env::var_os("STUFFR_BROTLI_FIXTURE_DIR").expect("STUFFR_BROTLI_FIXTURE_DIR");
    let dir = std::path::Path::new(&dir);
    std::fs::write(dir.join("text.txt"), text()).unwrap();
    std::fs::write(dir.join("mixed.bin"), mixed()).unwrap();
}

#[cfg(feature = "brotli-c")]
#[test]
fn error_name_table_is_libbrotlis() {
    for code in -40..=10 {
        assert_eq!(
            error_name(code),
            super::c::libbrotli_error_name(code),
            "{code}"
        );
    }
}

type Seen = std::rc::Rc<std::cell::RefCell<(Vec<usize>, Vec<u8>)>>;

fn watched_decoder() -> (Decoder, Seen) {
    let seen: Seen = Default::default();
    let mut dec = Decoder::new(true, None).expect("decoder");
    let (s, c) = (seen.clone(), seen.clone());
    dec.set_metadata_callbacks(
        Box::new(move |n| s.borrow_mut().0.push(n)),
        Box::new(move |b: &[u8]| c.borrow_mut().1.extend_from_slice(b)),
    )
    .expect("callbacks");
    (dec, seen)
}

#[test]
fn metadata_survives_tiny_buffers() {
    // Three input bytes and seven output bytes a call: output-full stops
    // interleave with the metadata block and the data around it.
    let packed = fixture("text-q11-comment.br");
    let (mut dec, seen) = watched_decoder();
    let mut out = Vec::new();
    let mut pieces = packed.chunks(3);
    let mut rest: &[u8] = &[];
    let mut wants_input = true;
    loop {
        if rest.is_empty() && wants_input {
            match pieces.next() {
                Some(p) => rest = p,
                None => panic!("ran out of input"),
            }
        }
        let mut buf = [0u8; 7];
        let mut o: &mut [u8] = &mut buf;
        let r = dec.decompress_stream(&mut rest, &mut o);
        let used = 7 - o.len();
        out.extend_from_slice(&buf[..used]);
        wants_input = r == StreamResult::NeedsMoreInput;
        match r {
            StreamResult::Success => break,
            StreamResult::NeedsMoreInput | StreamResult::NeedsMoreOutput => {}
            StreamResult::Error => panic!("{:?}", dec.error()),
        }
    }
    assert!(out == text());
    assert_eq!(seen.borrow().0, [3]);
    assert_eq!(seen.borrow().1, b"abc");
}

/// A hand-built stream: a 16-bit window, a zero-length metadata block, a
/// one-byte one, a 23-byte one, `payload` as an uncompressed meta-block,
/// then the empty last meta-block. (The pure tier's encoder writes a
/// corrupt stream for several `EmitMetadata` calls in a row, so the stream
/// is not an encoder's; the tool emits one block at most.)
fn metadata_shapes(payload: &[u8]) -> Vec<u8> {
    assert!(!payload.is_empty() && payload.len() <= 1 << 16);
    let mut out = vec![
        // WBITS 0; ISLAST 0, MNIBBLES 3 (metadata), reserved 0, MSKIPBYTES 0;
        // one padding bit.
        0b0000_1100,
        // ISLAST 0, MNIBBLES 3, reserved 0, MSKIPBYTES 1, then the length
        // less one in the next eight bits (not aligned), then padding.
        0b0001_0110,
        0,
        b'x',
        0b0001_0110 | ((22 & 3) << 6),
        22 >> 2,
    ];
    out.extend_from_slice(b"a longer metadata block");
    // ISLAST 0, MNIBBLES 0 (four nibbles), MLEN-1 in 16 bits,
    // ISUNCOMPRESSED 1, then padding to the byte: 20 bits in three bytes.
    let bits = ((payload.len() as u32 - 1) << 3) | (1 << 19);
    out.extend_from_slice(&bits.to_le_bytes()[..3]);
    out.extend_from_slice(payload);
    // ISLAST 1, ISLASTEMPTY 1.
    out.push(0b11);
    out
}

#[test]
fn metadata_blocks_of_every_shape() {
    let input = b"payload after the metadata".repeat(20);
    let packed = metadata_shapes(&input);
    let mut plain = Decoder::new(true, None).expect("decoder");
    assert_eq!(decompress(&packed, &mut plain).ok().as_ref(), Some(&input));
    let (mut dec, seen) = watched_decoder();
    assert_eq!(decompress(&packed, &mut dec).ok(), Some(input));
    assert_eq!(seen.borrow().0, [0, 1, 23]);
    assert_eq!(seen.borrow().1, b"xa longer metadata block");
}

#[test]
fn a_comment_with_data_round_trips_on_this_tier() {
    let input = text();
    let packed = compress(&input, &params_for(&input, 1), Some(b"tier"));
    let (mut dec, seen) = watched_decoder();
    assert_eq!(decompress(&packed, &mut dec).ok(), Some(input));
    assert_eq!(seen.borrow().0, [4]);
    assert_eq!(seen.borrow().1, b"tier");
}
