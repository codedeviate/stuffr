//! Decoders take a borrowed, non-`Send` source (0.23.0, rulings B1 and B4).
//!
//! The downstream case this pins: a `.Z` (or any codec stream) sitting as a
//! member inside a tar or a zip. An archive member's reader borrows the
//! archive and is not `Send` (`Entry`'s doc in `stuffr-core/src/archive.rs`),
//! so before `Codec::decoder` took `Box<dyn Source + 'a>` no codec could be
//! put over it without first copying the member out whole.
//!
//! An integration test on purpose: everything it reaches has to be `pub`, so
//! it also proves `stuffr_core::decode_reader` and `BorrowedSource` are the
//! public route a caller outside the workspace takes.

use std::io::{Read, Write};

use stuffr_core::{Codec, DecodeOpts, EncodeOpts, Error, FormatKind, Registry, decode_reader};

/// Encodes `plain` with `codec` into memory.
fn encode(codec: &dyn Codec, plain: &[u8]) -> Vec<u8> {
    let buf = stuffr_core::testing::SharedBuf::new();
    let mut sink = codec
        .encoder(Box::new(buf.clone()), &EncodeOpts::default())
        .unwrap_or_else(|e| panic!("{}: encoder: {e}", codec.id()));
    sink.write_all(plain).unwrap();
    sink.finish().unwrap();
    buf.contents()
}

/// Decodes `stream` through a borrow of a local slice: `&mut &buf[..]` is
/// neither `'static` nor owned, which is exactly what `ReaderSource` refuses.
fn decode_borrowed(codec: &dyn Codec, stream: &[u8]) -> Vec<u8> {
    let mut input: &[u8] = stream;
    let mut out = Vec::new();
    decode_reader(codec, &mut input, &DecodeOpts::default())
        .unwrap_or_else(|e| panic!("{}: decoder: {e}", codec.id()))
        .read_to_end(&mut out)
        .unwrap_or_else(|e| panic!("{}: read: {e}", codec.id()));
    out
}

#[test]
fn every_codec_decodes_from_a_borrowed_reader() {
    let mut reg = Registry::new();
    stuffr_formats::register_all(&mut reg);
    let plain = b"borrowed reader payload ".repeat(200);

    let mut exercised = Vec::new();
    let mut offered = 0;
    for row in reg.matrix() {
        if row.kind != FormatKind::Codec || !row.read {
            continue;
        }
        offered += 1;
        let codec = reg.codec(row.id).expect("a matrix row has its codec");
        let stream = if codec.caps().encode {
            encode(codec.as_ref(), &plain)
        } else {
            panic!(
                "{}: decode-only codec with no fixture in this test; add one",
                row.id
            )
        };
        assert_eq!(
            decode_borrowed(codec.as_ref(), &stream),
            plain,
            "{}: borrowed decode must round-trip",
            row.id
        );
        exercised.push(row.id);
    }

    // `compress`'s own checked-in fixture, under the same borrow: the
    // `/usr/bin/compress` bytes trg actually meets, not only our encoder's.
    #[cfg(feature = "compress")]
    {
        let fixture = include_bytes!("../fixtures/legacy/hello.Z");
        let out = decode_borrowed(&stuffr_formats::legacy::compress_z::CompressZ, fixture);
        assert_eq!(
            out, b"the quick brown fox jumps over the lazy dog\n",
            "hello.Z decodes to its plaintext"
        );
    }

    assert_eq!(
        exercised.len(),
        offered,
        "every readable codec was exercised"
    );
    #[cfg(all(
        feature = "gzip",
        feature = "zlib",
        feature = "deflate",
        feature = "bzip2",
        feature = "brotli",
        feature = "lz4",
        feature = "snappy",
        feature = "lzip",
        any(feature = "lzma-c", feature = "lzma-pure"),
        any(feature = "xz-c", feature = "xz-pure"),
        any(feature = "zstd-c", feature = "zstd-pure"),
        feature = "compress"
    ))]
    assert!(
        exercised.len() >= 12,
        "every codec of a full build: {exercised:?}"
    );
}

#[cfg(feature = "compress")]
fn compress_z(plain: &[u8]) -> Vec<u8> {
    encode(&stuffr_formats::legacy::compress_z::CompressZ, plain)
}

#[cfg(all(feature = "compress", feature = "tar"))]
#[test]
fn a_compress_member_inside_a_tar_decodes_through_its_borrowed_entry_reader() {
    use stuffr_core::{Container, OpenOpts, ReaderSource, StreamPolicy, ladder::resolve};
    use stuffr_formats::legacy::compress_z::CompressZ;
    use stuffr_formats::tar::Tar;

    let plain = b"line\n".repeat(500);
    let member = compress_z(&plain);
    let mut tar_bytes = Vec::new();
    {
        let mut b = tar::Builder::new(&mut tar_bytes);
        let mut h = tar::Header::new_ustar();
        h.set_size(member.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, "log.Z", &member[..]).unwrap();
        b.finish().unwrap();
    }

    let src = Box::new(ReaderSource::new(std::io::Cursor::new(tar_bytes)));
    let resolved = resolve(src, Tar.id(), Tar.caps(), &StreamPolicy::default()).unwrap();
    let mut archive = Tar.open(resolved, &OpenOpts::default()).unwrap();
    let mut entry = archive.next_entry().unwrap().expect("one entry");
    assert_eq!(entry.meta().name, "log.Z");

    let mut out = Vec::new();
    decode_reader(&CompressZ, entry.reader(), &DecodeOpts::default())
        .unwrap()
        .read_to_end(&mut out)
        .unwrap();
    assert_eq!(out, plain);
}

#[cfg(all(feature = "compress", feature = "zip"))]
#[test]
fn a_compress_member_inside_a_zip_decodes_through_its_borrowed_entry_reader() {
    use stuffr_core::{Container, OpenOpts, ReaderSource, StreamPolicy, ladder::resolve};
    use stuffr_formats::legacy::compress_z::CompressZ;
    use stuffr_formats::zip::Zip;

    let plain = b"line\n".repeat(500);
    let member = compress_z(&plain);
    let mut zip_bytes = Vec::new();
    {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_bytes));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        w.start_file("log.Z", opts).unwrap();
        w.write_all(&member).unwrap();
        w.finish().unwrap();
    }

    let src = Box::new(ReaderSource::new(std::io::Cursor::new(zip_bytes)));
    let resolved = resolve(src, Zip.id(), Zip.caps(), &StreamPolicy::default()).unwrap();
    let mut archive = Zip.open(resolved, &OpenOpts::default()).unwrap();
    let mut entry = archive.next_entry().unwrap().expect("one entry");
    assert_eq!(entry.meta().name, "log.Z");

    let mut out = Vec::new();
    decode_reader(&CompressZ, entry.reader(), &DecodeOpts::default())
        .unwrap()
        .read_to_end(&mut out)
        .unwrap();
    assert_eq!(out, plain);
}

#[cfg(feature = "compress")]
#[test]
fn a_corrupt_borrowed_member_is_corrupt_not_io() {
    use stuffr_formats::legacy::compress_z::CompressZ;

    let mut stream = compress_z(&b"line\n".repeat(500));
    // Keep the three-byte header (magic + flags) so the decoder starts; flip
    // every body byte so the code stream is nonsense.
    for b in &mut stream[3..] {
        *b ^= 0xFF;
    }
    let mut input: &[u8] = &stream;
    let mut out = Vec::new();
    let err = decode_reader(&CompressZ, &mut input, &DecodeOpts::default())
        .unwrap()
        .read_to_end(&mut out)
        .expect_err("a flipped body must not decode");
    // The plain conversion a bare `?` performs, not `from_decode_io`:
    // `decode_reader` must already have marked the read as decode-side.
    let classified = Error::from(err);
    assert!(matches!(classified, Error::Corrupt(_)), "{classified:?}");
    assert_eq!(classified.exit_code(), 5, "{classified:?}");
}

/// `MockCodec` with its decode half switched off — only `caps` differs.
struct EncodeOnly;

impl Codec for EncodeOnly {
    fn id(&self) -> stuffr_core::FormatId {
        stuffr_core::testing::MOCK_CODEC
    }
    fn caps(&self) -> stuffr_core::CodecCaps {
        stuffr_core::CodecCaps {
            decode: false,
            ..stuffr_core::testing::MockCodec.caps()
        }
    }
    fn decoder<'a>(
        &self,
        src: Box<dyn stuffr_core::Source + 'a>,
        o: &DecodeOpts,
    ) -> stuffr_core::Result<Box<dyn stuffr_core::Source + 'a>> {
        stuffr_core::testing::MockCodec.decoder(src, o)
    }
    fn encoder(
        &self,
        dst: Box<dyn Write + Send>,
        o: &EncodeOpts,
    ) -> stuffr_core::Result<Box<dyn stuffr_core::Sink>> {
        stuffr_core::testing::MockCodec.encoder(dst, o)
    }
}

#[test]
fn decode_reader_refuses_an_encode_only_codec() {
    let mut input: &[u8] = b"anything";
    let Err(err) = decode_reader(&EncodeOnly, &mut input, &DecodeOpts::default()) else {
        panic!("an encode-only codec must be refused");
    };
    assert!(
        matches!(
            err,
            Error::CapabilityUnavailable {
                format,
                available: "written",
                requested: "read",
            } if format == stuffr_core::testing::MOCK_CODEC
        ),
        "{err:?}"
    );
    assert_eq!(err.exit_code(), 3);
}
