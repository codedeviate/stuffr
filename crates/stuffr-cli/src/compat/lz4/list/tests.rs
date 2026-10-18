//! `--list`: the walker on made-up frames, the cells, and whole runs in the
//! sandbox. Every expected figure was read off the 1.10.0 binary (the probe
//! is named where it is not obvious); the differential rows in
//! `tests/compat_lz4.rs` repeat the same shapes against the reference.

use std::ffi::OsString;
use std::io::Cursor;

use super::*;

// ---- made-up files ----

/// xxHash32 with seed 0 (the header checksum), written out so that the
/// fixture does not rest on the code under test.
fn xxh32(data: &[u8]) -> u32 {
    const P: [u32; 5] = [
        2_654_435_761,
        2_246_822_519,
        3_266_489_917,
        668_265_263,
        374_761_393,
    ];
    let word = |i: usize| u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
    let round = |acc: u32, input: u32| {
        acc.wrapping_add(input.wrapping_mul(P[1]))
            .rotate_left(13)
            .wrapping_mul(P[0])
    };
    let mut i = 0;
    let mut h;
    if data.len() >= 16 {
        let mut v = [P[0].wrapping_add(P[1]), P[1], 0, 0u32.wrapping_sub(P[0])];
        while i + 16 <= data.len() {
            for (k, lane) in v.iter_mut().enumerate() {
                *lane = round(*lane, word(i + 4 * k));
            }
            i += 16;
        }
        h = v[0]
            .rotate_left(1)
            .wrapping_add(v[1].rotate_left(7))
            .wrapping_add(v[2].rotate_left(12))
            .wrapping_add(v[3].rotate_left(18));
    } else {
        h = P[4];
    }
    h = h.wrapping_add(data.len() as u32);
    while i + 4 <= data.len() {
        h = h
            .wrapping_add(word(i).wrapping_mul(P[2]))
            .rotate_left(17)
            .wrapping_mul(P[3]);
        i += 4;
    }
    while i < data.len() {
        h = h
            .wrapping_add(u32::from(data[i]).wrapping_mul(P[4]))
            .rotate_left(11)
            .wrapping_mul(P[0]);
        i += 1;
    }
    h ^= h >> 15;
    h = h.wrapping_mul(P[1]);
    h ^= h >> 13;
    h = h.wrapping_mul(P[2]);
    h ^ (h >> 16)
}

/// A frame's shape.
#[derive(Clone)]
struct Shape {
    /// Block size ID, 4 to 7.
    id: u8,
    linked: bool,
    block_checksum: bool,
    content_checksum: bool,
    content_size: Option<u64>,
    dictionary: Option<u32>,
    /// Block sizes, each a stored block of that many bytes.
    blocks: Vec<u32>,
    /// Write the end mark (and the content checksum after it).
    end: bool,
}

impl Shape {
    fn new() -> Shape {
        Shape {
            id: 7,
            linked: false,
            block_checksum: false,
            content_checksum: true,
            content_size: None,
            dictionary: None,
            blocks: vec![3],
            end: true,
        }
    }

    fn header(&self) -> Vec<u8> {
        let flg = 0x40
            | (u8::from(!self.linked) << 5)
            | (u8::from(self.block_checksum) << 4)
            | (u8::from(self.content_size.is_some()) << 3)
            | (u8::from(self.content_checksum) << 2)
            | u8::from(self.dictionary.is_some());
        let mut d = vec![flg, self.id << 4];
        if let Some(n) = self.content_size {
            d.extend_from_slice(&n.to_le_bytes());
        }
        if let Some(n) = self.dictionary {
            d.extend_from_slice(&n.to_le_bytes());
        }
        let hc = (xxh32(&d) >> 8) as u8;
        let mut out = MAGIC.to_le_bytes().to_vec();
        out.extend_from_slice(&d);
        out.push(hc);
        out
    }

    fn bytes(&self) -> Vec<u8> {
        let mut out = self.header();
        for &n in &self.blocks {
            out.extend_from_slice(&(n | 0x8000_0000).to_le_bytes());
            out.resize(out.len() + n as usize, b'x');
            if self.block_checksum {
                out.extend_from_slice(&[0; 4]);
            }
        }
        if self.end {
            out.extend_from_slice(&[0; 4]);
            if self.content_checksum {
                out.extend_from_slice(&[0; 4]);
            }
        }
        out
    }
}

/// A skippable frame of `n` bytes.
fn skippable(n: u32) -> Vec<u8> {
    let mut out = 0x184D_2A50u32.to_le_bytes().to_vec();
    out.extend_from_slice(&n.to_le_bytes());
    out.resize(out.len() + n as usize, b's');
    out
}

/// A legacy frame of blocks of the given compressed sizes.
fn legacy(blocks: &[u32]) -> Vec<u8> {
    let mut out = LEGACY_MAGIC.to_le_bytes().to_vec();
    for &n in blocks {
        out.extend_from_slice(&n.to_le_bytes());
        out.resize(out.len() + n as usize, b'l');
    }
    out
}

/// The frames listed from `file`, and why the walk stopped (`None` at the
/// end of the file).
fn walk(file: &[u8]) -> (Vec<FrameInfo>, Option<Stop>) {
    let mut w = Walker::new(Cursor::new(file.to_vec()));
    let mut frames = Vec::new();
    loop {
        match w.next_frame() {
            Ok(Some(f)) => frames.push(f),
            Ok(None) => return (frames, None),
            Err(s) => return (frames, Some(s)),
        }
    }
}

fn stop_of(file: &[u8]) -> Option<Stop> {
    walk(file).1
}

fn sizes(file: &[u8]) -> Vec<u64> {
    walk(file).0.iter().map(|f| f.size).collect()
}

// ---- modern frames ----

/// probe: `lz4 --list -v` of a plain frame: its length, `B7I`, a content
/// checksum, no content size.
#[test]
fn a_plain_frame() {
    let f = Shape::new().bytes();
    let (frames, stop) = walk(&f);
    assert_eq!(stop, None);
    assert_eq!(
        frames,
        [FrameInfo {
            kind: Kind::Frame,
            size: f.len() as u64,
            block: Some((7, false)),
            checksum: true,
            content: 0,
        }]
    );
}

/// probe: `--content-size`, `-BD`, `-B4`, `--no-crc`: each header field
/// reaches the row; a content size of 0 is "unknown".
#[test]
fn header_fields_reach_the_row() {
    let mut s = Shape::new();
    s.content_size = Some(100);
    s.id = 4;
    s.linked = true;
    s.content_checksum = false;
    let (frames, _) = walk(&s.bytes());
    assert_eq!(frames[0].block, Some((4, true)));
    assert_eq!((frames[0].content, frames[0].checksum), (100, false));
    s.content_size = Some(0);
    assert_eq!(walk(&s.bytes()).0[0].content, 0);
}

/// probe: a block checksum adds 4 bytes after each block, and a content
/// checksum 4 after the end mark; a stored-block flag does not change the
/// size; a block word of 0x80000000 is the end mark.
#[test]
fn blocks_and_checksums_add_up() {
    let mut s = Shape::new();
    s.blocks = vec![10, 5];
    s.block_checksum = true;
    // 7 header + 2 x (4 word + 4 checksum) + 15 data + 4 end + 4 content.
    assert_eq!(sizes(&s.bytes()), [7 + 16 + 15 + 8]);
    s.content_checksum = false;
    assert_eq!(sizes(&s.bytes()), [7 + 16 + 15 + 4]);
    // A stored empty block is the end mark: the bytes after it are a
    // content checksum and then a frame that is none.
    let mut s = Shape::new();
    s.blocks = vec![0, 3];
    let (frames, stop) = walk(&s.bytes());
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].size, 7 + 4 + 4);
    assert_eq!(stop, Some(Stop::Trailing(19)));
}

/// probe: a dictionary ID with a content size is listed (19-byte header);
/// without one, never.
#[test]
fn a_dictionary_id_needs_a_content_size() {
    let mut s = Shape::new();
    s.dictionary = Some(0x1234_5678);
    s.content_size = Some(7);
    let (frames, stop) = walk(&s.bytes());
    assert_eq!((stop, frames[0].content), (None, 7));
    s.content_size = None;
    assert_eq!(stop_of(&s.bytes()), Some(Stop::NotRecognized));
}

/// probe: version, reserved bits, block size IDs 0..3, a bad header
/// checksum: all "not recognized".
#[test]
fn headers_liblz4_refuses() {
    let good = Shape::new().bytes();
    let refuse = |at: usize, v: u8| {
        let mut f = good.clone();
        f[at] = v;
        // Keep the checksum right, so that only the field is wrong.
        let hc = (xxh32(&f[4..6]) >> 8) as u8;
        f[6] = hc;
        stop_of(&f)
    };
    assert_eq!(refuse(4, 0x40 | 0x02), Some(Stop::NotRecognized));
    assert_eq!(refuse(4, 0x20), Some(Stop::NotRecognized));
    assert_eq!(refuse(4, 0x80 | 0x20), Some(Stop::NotRecognized));
    assert_eq!(refuse(5, 0x70 | 1), Some(Stop::NotRecognized));
    assert_eq!(refuse(5, 0x80 | 0x70), Some(Stop::NotRecognized));
    assert_eq!(refuse(5, 0x30), Some(Stop::NotRecognized));
    assert_eq!(refuse(5, 0x00), Some(Stop::NotRecognized));
    let mut bad = good.clone();
    bad[6] ^= 1;
    assert_eq!(stop_of(&bad), Some(Stop::NotRecognized));
}

/// probe: every prefix of a frame with a content size (header 15 bytes):
/// nothing is an empty file, 1 to 3 bytes `Error 40`, the magic alone `71`,
/// 1 to 3 bytes of header `72` (the flags promise a content size), up to
/// the header and its end not recognized, a byte after it a frame.
#[test]
fn every_prefix_of_a_header_with_a_content_size() {
    let mut s = Shape::new();
    s.content_size = Some(14);
    let f = s.bytes();
    for n in 0..=f.len() {
        let want = match n {
            0 => Some(Stop::NotRecognized),
            1..=3 => Some(Stop::MagicUnreadable),
            4 => Some(Stop::MagicOnly),
            5..=7 => Some(Stop::HeaderCut),
            8..=15 => Some(Stop::NotRecognized),
            _ => None,
        };
        assert_eq!(stop_of(&f[..n]), want, "{n} bytes");
    }
}

/// probe: the same without a content size (header 7 bytes): 5 to 7 bytes are
/// not recognized, not `Error 72`.
#[test]
fn every_prefix_of_a_plain_header() {
    let f = Shape::new().bytes();
    for n in 0..=f.len() {
        let want = match n {
            0 => Some(Stop::NotRecognized),
            1..=3 => Some(Stop::MagicUnreadable),
            4 => Some(Stop::MagicOnly),
            5..=7 => Some(Stop::NotRecognized),
            _ => None,
        };
        assert_eq!(stop_of(&f[..n]), want, "{n} bytes");
    }
    // The same cuts after a whole frame are met the same way.
    let mut two = f.clone();
    two.extend_from_slice(&f[..6]);
    assert_eq!(stop_of(&two), Some(Stop::NotRecognized));
}

/// probe: a block or checksum cut short is still counted as long as it
/// said (`lz4 --list -v t_blk.lz4`: the size is the whole frame's, not the
/// file's).
#[test]
fn a_frame_cut_short_counts_what_it_promised() {
    let f = Shape::new().bytes();
    // 7 header + 4 word + 3 data + 4 end + 4 checksum = 22.
    assert_eq!(f.len(), 22);
    assert_eq!(sizes(&f[..14]), [22 - 4 - 4]);
    assert_eq!(sizes(&f[..12]), [22 - 4 - 4]);
    assert_eq!(sizes(&f[..20]), [22]);
    // No end mark at all: the frame ends where the blocks do.
    let mut s = Shape::new();
    s.end = false;
    assert_eq!(sizes(&s.bytes()), [7 + 4 + 3]);
}

/// probe: a word cut short is completed from the buffer, which held the
/// frame's previous word (`lz4 --list -v` of `frame + 1/2/3 bytes`: sizes
/// 132121, 131609, 66073 for a first block of 0x00010203 bytes and the new
/// byte or bytes `07`, `07 00`, `07 00 00`); with no block before it the
/// buffer is zero.
#[test]
fn a_word_cut_short_is_completed_from_the_last() {
    let mut s = Shape::new();
    s.blocks = vec![0x0001_0203];
    s.end = false;
    let head = s.bytes();
    let at = 7 + 4 + 0x0001_0203;
    assert_eq!(head.len(), at);
    for (tail, size) in [
        (&[7u8][..], 132_121),
        (&[7, 0][..], 131_609),
        (&[7, 0, 0][..], 66_073),
        (&[0x34, 0x12][..], 136_262),
    ] {
        let mut f = head.clone();
        f.extend_from_slice(tail);
        assert_eq!(sizes(&f), [size], "{tail:?}");
    }
    let mut s = Shape::new();
    s.blocks = vec![];
    s.end = false;
    let mut f = s.bytes();
    f.push(9);
    assert_eq!(sizes(&f), [7 + 4 + 9]);
}

/// probe: a frame with nothing after its header is not recognized; one
/// byte is a (cut) block word.
#[test]
fn a_header_alone_is_not_a_frame() {
    let mut s = Shape::new();
    s.blocks = vec![];
    s.end = false;
    let mut f = s.bytes();
    assert_eq!(stop_of(&f), Some(Stop::NotRecognized));
    f.push(b'z');
    assert_eq!(sizes(&f), [7 + 4 + 0x7A]);
    // The same after a whole frame.
    let mut two = Shape::new().bytes();
    two.extend_from_slice(&s.bytes());
    let (frames, stop) = walk(&two);
    assert_eq!((frames.len(), stop), (1, Some(Stop::NotRecognized)));
}

/// probe: block-size words are not checked against the frame's maximum, and
/// a seek past the end of the file ends the frame without a word: a block
/// of 2 GiB - 1 in a 64 KiB frame lists, in time proportional to nothing.
#[test]
fn hostile_block_sizes_cost_one_seek() {
    let mut s = Shape::new();
    s.id = 4;
    s.blocks = vec![];
    s.end = false;
    let mut f = s.bytes();
    f.extend_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
    f.extend_from_slice(b"ab");
    assert_eq!(sizes(&f), [7 + 4 + 0x7FFF_FFFF]);
    // The top bit is the stored flag, whatever follows it.
    let mut g = s.bytes();
    g.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    assert_eq!(sizes(&g), [7 + 4 + 0x7FFF_FFFF]);
}

/// probe: a hostile frame whose blocks say 2 GiB each is counted in 64
/// bits (a 6 GiB sparse file listed 6442450968), and the sum is not cut.
#[test]
fn sizes_are_sixty_four_bits() {
    let mut s = Shape::new();
    s.blocks = vec![];
    s.end = false;
    let mut f = s.bytes();
    let word = 0x7FFF_FFFFu32.to_le_bytes();
    f.extend_from_slice(&word);
    // A real reader would need 2 GiB here; the cursor stands in with a
    // short file, so the second word is never reached: one block.
    assert_eq!(sizes(&f), [7 + 4 + 0x7FFF_FFFF]);
}

// ---- skippable and legacy frames ----

/// probe: a skippable frame is 8 bytes and its size; `0x184D2A5F` is one
/// too; the magic number alone, or with its size cut, is `Error 42`; one to
/// three bytes after one are `Error 40`.
#[test]
fn skippable_frames() {
    assert_eq!(sizes(&skippable(10)), [18]);
    assert_eq!(sizes(&skippable(0)), [8]);
    let mut f = skippable(3);
    f[..4].copy_from_slice(&0x184D_2A5Fu32.to_le_bytes());
    assert_eq!(walk(&f).0[0].kind, Kind::Skippable);
    let cut = skippable(3);
    assert_eq!(stop_of(&cut[..4]), Some(Stop::SkipSize));
    assert_eq!(stop_of(&cut[..6]), Some(Stop::SkipSize));
    let mut t = skippable(3);
    t.extend_from_slice(&[1, 1]);
    assert_eq!(stop_of(&t), Some(Stop::MagicUnreadable));
    // A cut area is no error: the size stays what it said.
    assert_eq!(sizes(&cut[..8]), [11]);
    assert_eq!(sizes(&skippable(10)[..12]), [18]);
}

/// probe: a skippable frame of `0xFFFFFFFF` bytes lists as 7 (`size + 8` in
/// 32 bits) and ends the file; `0xFFFFFFF0` is 4294967288.
#[test]
fn a_huge_skippable_frame_wraps_its_size() {
    let mut f = 0x184D_2A50u32.to_le_bytes().to_vec();
    f.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    f.extend_from_slice(b"ab");
    f.extend_from_slice(&Shape::new().bytes());
    let (frames, stop) = walk(&f);
    assert_eq!(
        (stop, frames.iter().map(|f| f.size).collect::<Vec<_>>()),
        (None, vec![7])
    );
    f[4..8].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
    assert_eq!(walk(&f).0[0].size, 4_294_967_288);
}

/// probe: legacy frames: magic, then 4-byte sizes and blocks, to the end of
/// the file or a word that is a magic number; a zero size is a block; more
/// than 8 MiB, or a word cut short, is corrupted; a frame with no block is
/// not recognized, whatever follows.
#[test]
fn legacy_frames() {
    assert_eq!(sizes(&legacy(&[10])), [18]);
    assert_eq!(sizes(&legacy(&[10, 20])), [42]);
    assert_eq!(sizes(&legacy(&[0, 0, 0])), [16]);
    let mut two = legacy(&[3]);
    two.extend_from_slice(&legacy(&[4]));
    assert_eq!(sizes(&two), [11, 12]);
    let mut then = legacy(&[3]);
    then.extend_from_slice(&Shape::new().bytes());
    let (frames, _) = walk(&then);
    assert_eq!(
        frames.iter().map(|f| f.kind).collect::<Vec<_>>(),
        [Kind::Legacy, Kind::Frame]
    );
    let mut then = legacy(&[3]);
    then.extend_from_slice(&skippable(2));
    assert_eq!(walk(&then).0[1].kind, Kind::Skippable);
    // Cut inside a block: still what it said.
    assert_eq!(sizes(&legacy(&[5])[..11]), [13]);

    let magic = LEGACY_MAGIC.to_le_bytes();
    assert_eq!(stop_of(&magic), Some(Stop::NotRecognized));
    let mut f = magic.to_vec();
    f.extend_from_slice(&magic);
    assert_eq!(stop_of(&f), Some(Stop::NotRecognized));
    let mut f = magic.to_vec();
    f.extend_from_slice(&Shape::new().bytes());
    assert_eq!(stop_of(&f), Some(Stop::NotRecognized));
    for n in 1..=3 {
        let mut f = legacy(&[3]);
        f.resize(f.len() + n, 1);
        assert_eq!(stop_of(&f), Some(Stop::CorruptLegacy), "{n}");
        let mut g = magic.to_vec();
        g.resize(4 + n, 1);
        assert_eq!(stop_of(&g), Some(Stop::CorruptLegacy), "{n}");
    }
    // 8 MiB is a block, one more is not (probe: 8388608 / 8388609).
    let mut f = magic.to_vec();
    f.extend_from_slice(&(8u32 << 20).to_le_bytes());
    assert_eq!(sizes(&f), [8 + (8 << 20)]);
    let mut f = magic.to_vec();
    f.extend_from_slice(&((8u32 << 20) + 1).to_le_bytes());
    assert_eq!(stop_of(&f), Some(Stop::CorruptLegacy));
    let mut f = legacy(&[3]);
    f.extend_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(stop_of(&f), Some(Stop::CorruptLegacy));
}

/// probe: bytes that are no frame, after the first or first in the file:
/// `Trailing` with the offset past their four bytes.
#[test]
fn unknown_magic_numbers() {
    assert_eq!(stop_of(b"notlz4 at all"), Some(Stop::Trailing(4)));
    let mut f = Shape::new().bytes();
    f.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(stop_of(&f), Some(Stop::Trailing(22 + 4)));
    let mut f = skippable(3);
    f.extend_from_slice(&[0; 4]);
    assert_eq!(stop_of(&f), Some(Stop::Trailing(15)));
}

/// A hostile file of zero-size legacy blocks is walked once, the window
/// holding 64 KiB whatever its length.
#[test]
fn a_long_run_of_blocks_is_one_pass() {
    let mut f = LEGACY_MAGIC.to_le_bytes().to_vec();
    f.resize(4 + 4 * 300_000, 0);
    assert_eq!(sizes(&f), [4 + 4 * 300_000]);
}

// ---- the cells ----

/// probe: `28.00`, `1023.00`, `1.00K`, `1.50K`, `1024.00K` for 1 MiB - 1,
/// `1.00M`, `1024.00M`, `1.00G`, `38.15M`, `1.00P`, `1.00E`, `16.00E` for
/// 2^64 - 1.
#[test]
fn sizes_in_the_compact_table() {
    for (n, want) in [
        (0, "0.00"),
        (28, "28.00"),
        (1023, "1023.00"),
        (1024, "1.00K"),
        (1025, "1.00K"),
        (1536, "1.50K"),
        ((1 << 20) - 1, "1024.00K"),
        (1 << 20, "1.00M"),
        ((1 << 20) + 5000, "1.00M"),
        ((1 << 30) - 1, "1024.00M"),
        (1 << 30, "1.00G"),
        (40_000_000, "38.15M"),
        (1 << 40, "1.00T"),
        (1 << 50, "1.00P"),
        (1 << 60, "1.00E"),
        (5 << 60, "5.00E"),
        (u64::MAX, "16.00E"),
    ] {
        assert_eq!(size_cell(n), want, "{n}");
    }
}

/// probe: `100.23`, `2.74`, `inf` for a sum that wrapped to 0.
#[test]
fn ratios() {
    assert_eq!(ratio_cell(11_764, 11_737), "100.23");
    assert_eq!(ratio_cell(28, 1023), "2.74");
    assert_eq!(ratio_cell(56, 0), "inf");
    assert_eq!(ratio_cell(28, u64::MAX), "0.00");
}

#[test]
fn base_names() {
    assert_eq!(base_name(b"a.lz4"), b"a.lz4");
    assert_eq!(base_name(b"d/e/a.lz4"), b"a.lz4");
    assert_eq!(base_name(b"./a.lz4"), b"a.lz4");
    assert_eq!(base_name(b"d//a.lz4"), b"a.lz4");
    assert_eq!(base_name(b"d/"), b"");
}

/// probe: types and blocks that differ list as `-`; a content size of 0 in
/// any frame, or any frame that is not modern, makes the content unknown;
/// the sum wraps (two frames of 2^63 are `0.00`).
#[test]
fn totals_collect_like_lz4() {
    let modern = |id, linked, content| FrameInfo {
        kind: Kind::Frame,
        size: 30,
        block: Some((id, linked)),
        checksum: true,
        content,
    };
    let mut t = Totals::new();
    t.add(&modern(7, false, 3));
    t.add(&modern(7, false, 3));
    assert!(t.kind_same && t.block_same && t.known);
    assert_eq!((t.count, t.content), (2, 6));
    t.add(&modern(4, false, 3));
    assert!(t.kind_same && !t.block_same && t.known);
    t.add(&modern(7, false, 0));
    assert!(!t.known);
    let mut t = Totals::new();
    t.add(&modern(7, false, 1 << 63));
    t.add(&modern(7, false, 1 << 63));
    assert!(t.known);
    assert_eq!(t.content, 0);
    let mut t = Totals::new();
    t.add(&modern(7, false, 3));
    t.add(&FrameInfo {
        kind: Kind::Skippable,
        size: 8,
        block: None,
        checksum: false,
        content: 0,
    });
    assert!(!t.kind_same && !t.known);
}

// ---- whole runs in the sandbox ----

struct Dir(std::path::PathBuf);

impl Dir {
    fn new(files: &[(&str, &[u8])]) -> Dir {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("stuffr-lz4-list-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (name, data) in files {
            std::fs::write(dir.join(name), data).unwrap();
        }
        Dir(dir)
    }

    /// Run `lz4 args`: code, standard output, standard error.
    fn run(&self, args: &[&str]) -> (i32, String, String) {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let (code, out, err, _) =
            super::super::run_in_counted(&self.0, "lz4", &args, b"", &|_| None);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The compact table's header, from the messages (its columns are the
/// reference's; the rows below are built cell by cell from the widths the
/// probes showed, so a change of either shows).
const HEADER: &str = m::LIST_HEADER;

/// Right-aligned cells, joined by a blank.
fn cells(spec: &[(&str, usize)]) -> String {
    spec.iter()
        .map(|&(s, w)| format!("{s:>w$}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// `n` blanks.
fn sp(n: usize) -> String {
    " ".repeat(n)
}

/// A compact row: `count type block size content ratio`, then the name after
/// `gap` (`"%  "` and a blank after the name when the ratio is known).
fn compact(t: (&str, &str, &str, &str, &str, &str), known: bool, name: &str) -> String {
    let c = cells(&[
        (t.0, 10),
        (t.1, 14),
        (t.2, 5),
        (t.3, 11),
        (t.4, 13),
        (t.5, 8),
    ]);
    if known {
        format!("{c}%{}{name} \n", sp(2))
    } else {
        format!("{c}{}{name}\n", sp(3))
    }
}

/// A verbose row: `frame type block checksum size content ratio`, then `end`
/// (`%` for a known ratio, a blank for an unknown one of a modern frame,
/// nothing for the others).
fn verbose(t: (&str, &str, &str, &str, &str, &str, &str), end: &str) -> String {
    let c = cells(&[
        (t.0, 10),
        (t.1, 14),
        (t.2, 5),
        (t.3, 8),
        (t.4, 20),
        (t.5, 20),
        (t.6, 9),
    ]);
    format!("{c}{end}\n")
}

/// The verbose table's column line.
const VERBOSE_HEADER: &str = m::LIST_HEADER_VERBOSE;

/// probe: the table of one frame without and with a content size (the
/// trailing blank after the name belongs to the known row), a file of
/// several frames, a legacy and a skippable one.
#[test]
fn the_compact_table() {
    let plain = Shape::new().bytes();
    let mut s = Shape::new();
    s.content_size = Some(100);
    let sized = s.bytes();
    let d = Dir::new(&[
        ("plain.lz4", &plain),
        ("sized.lz4", &sized),
        ("leg.lz4", &legacy(&[10])),
        ("skip.lz4", &skippable(10)),
    ]);
    let (code, out, err) = d.run(&["--list", "plain.lz4", "sized.lz4", "leg.lz4", "skip.lz4"]);
    assert_eq!((code, err.as_str()), (0, ""));
    let want = format!(
        "{HEADER}{}{}{}{}",
        compact(
            ("1", "LZ4Frame", "B7I", "22.00", "-", "-"),
            false,
            "plain.lz4"
        ),
        compact(
            ("1", "LZ4Frame", "B7I", "30.00", "100.00", "30.00"),
            true,
            "sized.lz4"
        ),
        compact(
            ("1", "LegacyFrame", "-", "18.00", "-", "-"),
            false,
            "leg.lz4"
        ),
        compact(
            ("1", "SkippableFrame", "-", "18.00", "-", "-"),
            false,
            "skip.lz4"
        ),
    );
    assert_eq!(out, want);
}

/// probe: `--list -v`: the banner on standard error, `name(i/n)` with the
/// base name, one row per frame, a blank line after a file that went
/// through, and no compact header.
#[test]
fn the_verbose_table() {
    let plain = Shape::new().bytes();
    let mut s = Shape::new();
    s.content_size = Some(100);
    s.block_checksum = true;
    s.linked = true;
    s.content_checksum = false;
    let mut two = plain.clone();
    two.extend_from_slice(&skippable(3));
    two.extend_from_slice(&legacy(&[1]));
    two.extend_from_slice(&s.bytes());
    let d = Dir::new(&[("two.lz4", &two)]);
    std::fs::create_dir(d.0.join("sub")).unwrap();
    std::fs::write(d.0.join("sub/two.lz4"), &plain).unwrap();
    let (code, out, err) = d.run(&["--list", "-v", "two.lz4", "sub/two.lz4"]);
    assert_eq!(code, 0);
    assert!(
        err.starts_with("*** lz4 v1.10.0 64-bit multithread (stuffr "),
        "{err:?}"
    );
    assert_eq!(err.lines().count(), 1, "{err:?}");
    let col = VERBOSE_HEADER;
    let want = format!(
        "two.lz4(1/2)\n{col}{}{}{}{}\ntwo.lz4(2/2)\n{col}{}\n",
        verbose(("1", "LZ4Frame", "B7I", "XXH32", "22", "-", "-"), " "),
        verbose(("2", "SkippableFrame", "-", "-", "11", "-", "-"), ""),
        verbose(("3", "LegacyFrame", "-", "-", "9", "-", "-"), ""),
        verbose(("4", "LZ4Frame", "B7D", "-", "30", "100", "30.00"), "%"),
        verbose(("1", "LZ4Frame", "B7I", "XXH32", "22", "-", "-"), " "),
    );
    assert_eq!(out, want);
}

/// probe: display level 4 adds the two version lines after the banner; the
/// banner and those lines come before a refusal too.
#[test]
fn the_levels() {
    let d = Dir::new(&[("a.lz4", &Shape::new().bytes())]);
    let (_, out, err) = d.run(&["--list", "-vv", "a.lz4"]);
    assert!(out.starts_with("a.lz4(1/1)\n"), "{out:?}");
    let mut lines: Vec<_> = err.lines().collect();
    // probe: the Linux reference adds a line after the banner.
    if cfg!(target_os = "linux") {
        assert_eq!(lines.get(1), Some(&"_POSIX_C_SOURCE defined: 200809L"));
        lines.remove(1);
    }
    assert_eq!(lines.len(), 3, "{err:?}");
    assert!(lines[1].starts_with("_POSIX_VERSION defined: "), "{err:?}");
    assert!(lines[1].ends_with('L'));
    assert_eq!(
        lines[2],
        lines[1].replacen("_POSIX_VERSION", "PLATFORM_POSIX_VERSION", 1)
    );
    // `-q` and `-qq` do not touch the table, only the errors.
    let (code, out, err) = d.run(&["--list", "-qq", "nosuch"]);
    assert_eq!((code, out.as_str(), err.as_str()), (1, HEADER, ""));
    let (code, _, err) = d.run(&["--list", "-q", "nosuch"]);
    assert_eq!(
        (code, err.as_str()),
        (1, "lz4: nosuch is not a regular file \n")
    );
}

/// probe: standard input lists nothing (the header, exit 0); a file named
/// `stdin` is a file; the first failure ends the run, its predecessors'
/// rows stay, its successors are never read; `Error N` exits N.
#[test]
fn failures_end_the_run() {
    let f = Shape::new().bytes();
    let mut sized = Shape::new();
    sized.content_size = Some(14);
    let mut cut = sized.bytes();
    cut.truncate(6);
    let d = Dir::new(&[("a.lz4", &f), ("notlz4", b"hello hello"), ("cut.lz4", &cut)]);
    let (code, out, err) = d.run(&["--list"]);
    assert_eq!((code, out.as_str(), err.as_str()), (0, HEADER, ""));
    let (code, out, _) = d.run(&["--list", "-"]);
    assert_eq!((code, out.as_str()), (0, HEADER));
    let (code, out, err) = d.run(&["--list", "a.lz4", "-", "a.lz4"]);
    assert_eq!((code, err.as_str()), (0, ""));
    assert_eq!(out.matches("a.lz4").count(), 2);
    let (code, _, err) = d.run(&["--list", "stdin"]);
    assert_eq!(
        (code, err.as_str()),
        (1, "lz4: stdin is not a regular file \n")
    );
    let (code, out, err) = d.run(&["--list", "a.lz4", "notlz4", "a.lz4"]);
    assert_eq!(code, 1);
    assert_eq!(out.matches("a.lz4").count(), 1, "{out}");
    assert_eq!(err, "lz4: notlz4: File format not recognized \n");
    let (code, out, err) = d.run(&["--list", "cut.lz4", "a.lz4"]);
    assert_eq!((code, out.as_str()), (72, HEADER));
    assert_eq!(err, "Error 72 : Error reading cut.lz4 \n");
}

/// probe: undecodable bytes after a frame say so only at level 3; a legacy
/// word that is too large says `Corrupted legacy frame` first, at level 1.
#[test]
fn failure_messages_by_level() {
    let mut garb = Shape::new().bytes();
    garb.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let mut leg = legacy(&[3]);
    leg.extend_from_slice(&u32::MAX.to_le_bytes());
    let d = Dir::new(&[("g.lz4", &garb), ("l.lz4", &leg)]);
    let nr = |n: &str| format!("lz4: {n}: File format not recognized \n");
    let (code, _, err) = d.run(&["--list", "g.lz4"]);
    assert_eq!((code, err), (1, nr("g.lz4")));
    let (_, _, err) = d.run(&["--list", "-v", "g.lz4"]);
    assert!(
        err.ends_with(&format!(
            "Stream followed by undecodable data at position 26 \n{}",
            nr("g.lz4")
        )),
        "{err:?}"
    );
    let (_, out, err) = d.run(&["--list", "-q", "l.lz4"]);
    assert_eq!(out, HEADER);
    assert_eq!(err, format!("Corrupted legacy frame \n{}", nr("l.lz4")));
    // A failed file prints the frames before the fault and no blank line.
    let (_, out, _) = d.run(&["--list", "-v", "g.lz4"]);
    assert!(out.ends_with("- \n") && !out.ends_with("\n\n"), "{out:?}");
}

/// `-r` lists a directory's files by their base names, an empty directory
/// alone is named as it is.
#[test]
fn directories() {
    let d = Dir::new(&[]);
    std::fs::create_dir_all(d.0.join("e")).unwrap();
    std::fs::create_dir_all(d.0.join("f")).unwrap();
    std::fs::write(d.0.join("f/a.lz4"), Shape::new().bytes()).unwrap();
    let (code, out, _) = d.run(&["--list", "-r", "f", "e"]);
    assert_eq!(code, 0);
    assert!(out.ends_with(&format!("{}a.lz4\n", sp(3))), "{out:?}");
    let (code, _, err) = d.run(&["--list", "-r", "e"]);
    assert_eq!((code, err.as_str()), (1, "lz4: e is not a regular file \n"));
    let (code, _, err) = d.run(&["--list", "e"]);
    assert_eq!((code, err.as_str()), (1, "lz4: e is not a regular file \n"));
}
