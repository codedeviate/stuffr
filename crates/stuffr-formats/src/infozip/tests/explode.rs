//! `explode.c`: the fixtures, a test-only implode writer for all four
//! variants (ruling P5), and the damage table.

use super::inflate::{XorShift, text};
use crate::infozip::{ByteSource, Stop, WSIZE, explode};

/// What one [`explode`] call did: the C's return code (0 for success, 5
/// for [`Stop::Length`]), `unused` for a 5, and every chunk it flushed.
pub(super) struct Run {
    pub(super) code: i32,
    pub(super) unused: Option<i64>,
    pub(super) chunks: Vec<usize>,
    pub(super) out: Vec<u8>,
}

/// An entry whose data ends `missing` bytes short of its compressed size: a
/// truncated archive, where `readbyte()`'s `read()` gives 0 and `G.csize`
/// stays positive.
pub(super) struct Short<'a> {
    pub(super) data: std::slice::Iter<'a, u8>,
    pub(super) missing: u64,
}

impl ByteSource for Short<'_> {
    fn next_byte(&mut self) -> Option<u8> {
        self.data.next().copied()
    }

    fn remaining(&self) -> u64 {
        self.data.len() as u64 + self.missing
    }
}

fn run_in(input: &[u8], flags: u16, ucsize: u64, missing: u64, window: &mut [u8]) -> Run {
    let mut chunks = Vec::new();
    let mut out = Vec::new();
    let mut src = Short {
        data: input.iter(),
        missing,
    };
    let r = explode(
        &mut src,
        flags,
        ucsize,
        window,
        &mut |c: &[u8]| -> Result<(), ()> {
            chunks.push(c.len());
            out.extend_from_slice(c);
            Ok(())
        },
    );
    let (code, unused) = match r {
        Ok(()) => (0, None),
        Err(Stop::Code(c)) => (c, None),
        Err(Stop::Length { unused }) => (5, Some(unused)),
        Err(Stop::Flush(())) => unreachable!("this flush never fails"),
    };
    Run {
        code,
        unused,
        chunks,
        out,
    }
}

/// [`run_in`] over a zeroed window and a whole entry.
fn run(input: &[u8], flags: u16, ucsize: u64) -> Run {
    run_in(input, flags, ucsize, 0, &mut vec![0; WSIZE])
}

/// The general-purpose flag bits of the four variants: bit 1 the 8K
/// window, bit 2 the literal tree (three trees).
pub(super) const VARIANTS: [(&str, u16); 4] = [
    ("4k-2trees", 0),
    ("4k-3trees", 4),
    ("8k-2trees", 2),
    ("8k-3trees", 6),
];

// ---- a minimal implode writer (ruling P5) ----

/// An LSB-first bit writer, as implode packs its bits.
#[derive(Default)]
pub(super) struct Bits {
    out: Vec<u8>,
    acc: u64,
    n: u32,
}

impl Bits {
    pub(super) fn put(&mut self, v: u32, n: u32) {
        self.acc |= u64::from(v) << self.n;
        self.n += n;
        while self.n >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.n -= 8;
        }
    }

    /// An implode code: `huft_build`'s canonical code, most significant bit
    /// first, every bit inverted (`DECODEHUFT` indexes by `~b`).
    fn code(&mut self, code: u32, len: u32) {
        for i in (0..len).rev() {
            self.put(!(code >> i) & 1, 1);
        }
    }

    pub(super) fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.out.push(self.acc as u8);
        }
        self.out
    }
}

/// `huft_build`'s codes for `lengths` (1..16 each): canonical, shorter
/// codes first, ties by symbol (RFC 1951 3.2.2).
fn canonical(lengths: &[u32]) -> Vec<u32> {
    let mut count = [0u32; 17];
    for &l in lengths {
        count[l as usize] += 1;
    }
    let mut next = [0u32; 17];
    let mut code = 0;
    for bits in 1..17 {
        code = (code + count[bits - 1]) << 1;
        next[bits] = code;
    }
    lengths
        .iter()
        .map(|&l| {
            let c = next[l as usize];
            next[l as usize] += 1;
            c
        })
        .collect()
}

/// A tree's description as `get_tree` reads it: a byte holding the number
/// of (length, count) bytes less one, then each byte `(count-1) << 4 |
/// (length-1)` over runs of up to 16 equal lengths.
fn tree_description(lengths: &[u32]) -> Vec<u8> {
    let mut pairs = Vec::new();
    let mut i = 0;
    while i < lengths.len() {
        let mut j = i + 1;
        while j < lengths.len() && j - i < 16 && lengths[j] == lengths[i] {
            j += 1;
        }
        pairs.push((((j - i - 1) as u8) << 4) | (lengths[i] - 1) as u8);
        i = j;
    }
    let mut v = vec![(pairs.len() - 1) as u8];
    v.extend(pairs);
    v
}

/// The writer's fixed Shannon-Fano trees, all complete. Literals: 64
/// codes of 7 bits (the printable `0x20..0x60`), 64 of 8 (`0x60..0xa0`),
/// 128 of 9, so the literal table (9 bits) is one level. Lengths: 8 codes
/// of 4 bits, 24 of 6, 32 of 8, deeper than the 7-bit base table, so they
/// reach subtables. Distances: 64 codes of 6 bits.
fn fixed_trees() -> ([u32; 256], [u32; 64], [u32; 64]) {
    let mut lit = [9u32; 256];
    lit[0x20..0x60].fill(7);
    lit[0x60..0xa0].fill(8);
    let mut len = [8u32; 64];
    len[..8].fill(4);
    len[8..32].fill(6);
    (lit, len, [6; 64])
}

/// An implode stream being written over [`fixed_trees`]: the trees first,
/// then literals and matches as the caller sends them.
pub(super) struct Encoder {
    w: Bits,
    lit: bool,
    bdl: u32,
    min: usize,
    trees: ([u32; 256], [u32; 64], [u32; 64]),
    codes: (Vec<u32>, Vec<u32>, Vec<u32>),
}

impl Encoder {
    /// The trees' descriptions for variant `flags`, as `explode()` reads
    /// them: the literal tree (with bit 2), the length tree, the distance
    /// tree.
    pub(super) fn new(flags: u16) -> Encoder {
        let lit = flags & 4 != 0;
        let trees = fixed_trees();
        let mut w = Bits::default();
        let mut descs = Vec::new();
        if lit {
            descs.extend(tree_description(&trees.0));
        }
        descs.extend(tree_description(&trees.1));
        descs.extend(tree_description(&trees.2));
        for b in descs {
            w.put(u32::from(b), 8);
        }
        Encoder {
            w,
            lit,
            bdl: if flags & 2 != 0 { 7 } else { 6 },
            min: if lit { 3 } else { 2 },
            codes: (
                canonical(&trees.0),
                canonical(&trees.1),
                canonical(&trees.2),
            ),
            trees,
        }
    }

    /// A literal: a one bit, then the byte coded (literal tree) or as
    /// eight plain bits.
    pub(super) fn literal(&mut self, c: u8) {
        self.w.put(1, 1);
        let c = usize::from(c);
        if self.lit {
            self.w.code(self.codes.0[c], self.trees.0[c]);
        } else {
            self.w.put(c as u32, 8);
        }
    }

    /// A match of `len` bytes (the minimum to 63 + 255 more) at distance
    /// `dist` (1 to the window): a zero bit, the distance's low bits plain,
    /// its high six coded, then the length coded (and its extra byte).
    pub(super) fn copy(&mut self, dist: usize, len: usize) {
        self.w.put(0, 1);
        let d = (dist - 1) as u32;
        self.w.put(d & ((1 << self.bdl) - 1), self.bdl);
        let hi = (d >> self.bdl) as usize;
        self.w.code(self.codes.2[hi], self.trees.2[hi]);
        let l = len - self.min;
        let c = l.min(63);
        self.w.code(self.codes.1[c], self.trees.1[c]);
        if c == 63 {
            self.w.put((l - 63) as u32, 8);
        }
    }

    /// Raw bits, for streams the writer would not make.
    pub(super) fn bits(&mut self, v: u32, n: u32) {
        self.w.put(v, n);
    }

    pub(super) fn finish(self) -> Vec<u8> {
        self.w.finish()
    }
}

/// Implodes `data` as the variant `flags` selects: greedy matches of at
/// least the minimum length (3 with a literal tree, 2 without) and at most
/// 63 + 255 more, within the 4K or 8K window, over [`fixed_trees`]. A
/// test-only writer: it aims at a valid stream, not a small one.
pub(super) fn implode(data: &[u8], flags: u16) -> Vec<u8> {
    let mut enc = Encoder::new(flags);
    let window = 1usize << (enc.bdl + 6);
    let max = enc.min + 63 + 255;
    let mut i = 0;
    while i < data.len() {
        // the longest match, nearest first
        let (mut best, mut best_dist) = (0, 0);
        for dist in 1..=window.min(i) {
            let from = i - dist;
            let mut n = 0;
            while n < max && i + n < data.len() && data[from + n] == data[i + n] {
                n += 1;
            }
            if n > best {
                (best, best_dist) = (n, dist);
            }
        }
        if best >= enc.min {
            enc.copy(best_dist, best);
            i += best;
        } else {
            enc.literal(data[i]);
            i += 1;
        }
    }
    enc.finish()
}

/// The hand-built fixtures' data: text, a 1000-byte repeat of its start
/// from 6000 bytes back (beyond the 4K window, inside the 8K one), a run of
/// 400 bytes (matches past 63 + min, with the extra length byte), and more
/// text: 9400 bytes.
pub(super) fn hand_data() -> Vec<u8> {
    let mut v = text(6000, 61);
    v.extend_from_within(..1000);
    v.extend(std::iter::repeat_n(b'=', 400));
    v.extend(text(2000, 62));
    v
}

/// CRC-32 (ISO-HDLC), bitwise; the zip wrapper's only need.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// A one-entry zip holding `stream` as method `method` with general-purpose
/// flags `flags`, named `name`, for `plain` (its CRC and size), dated
/// 2026-10-20 12:00 and made on Unix with mode 0644, as `zip` would.
pub(super) fn zip_one(name: &str, method: u16, flags: u16, plain: &[u8], stream: &[u8]) -> Vec<u8> {
    let (time, date): (u16, u16) = (12 << 11, ((2026 - 1980) << 9) | (10 << 5) | 20);
    let crc = crc32(plain);
    let fixed = |v: &mut Vec<u8>| {
        v.extend(10u16.to_le_bytes()); // version needed: 1.0
        v.extend(flags.to_le_bytes());
        v.extend(method.to_le_bytes());
        v.extend(time.to_le_bytes());
        v.extend(date.to_le_bytes());
        v.extend(crc.to_le_bytes());
        v.extend((stream.len() as u32).to_le_bytes());
        v.extend((plain.len() as u32).to_le_bytes());
        v.extend((name.len() as u16).to_le_bytes());
        v.extend(0u16.to_le_bytes()); // extra field length
    };
    let mut z = b"PK\x03\x04".to_vec();
    fixed(&mut z);
    z.extend(name.as_bytes());
    z.extend(stream);
    let central_at = z.len() as u32;
    z.extend(b"PK\x01\x02");
    z.extend(0x031eu16.to_le_bytes()); // made by: Unix, 3.0
    fixed(&mut z);
    z.extend(0u16.to_le_bytes()); // comment length
    z.extend(0u16.to_le_bytes()); // disk number start
    z.extend(0u16.to_le_bytes()); // internal attributes
    z.extend((0o100644u32 << 16).to_le_bytes()); // external: regular, 0644
    z.extend(0u32.to_le_bytes()); // local header offset
    z.extend(name.as_bytes());
    let central_len = z.len() as u32 - central_at;
    z.extend(b"PK\x05\x06");
    z.extend([0; 4]); // this disk, central directory's disk
    z.extend(1u16.to_le_bytes());
    z.extend(1u16.to_le_bytes());
    z.extend(central_len.to_le_bytes());
    z.extend(central_at.to_le_bytes());
    z.extend(0u16.to_le_bytes()); // comment length
    z
}

/// The committed hand-built fixture of variant `name`: its file name, and
/// the zip [`implode`] and [`zip_one`] make for it.
fn hand_fixture(name: &str, flags: u16) -> (String, Vec<u8>) {
    let data = hand_data();
    (
        format!("implode-hand-{name}.zip"),
        zip_one("hand.txt", 6, flags, &data, &implode(&data, flags)),
    )
}

/// The general-purpose flags of the first entry of `zip`.
fn first_entry_flags(zip: &[u8]) -> u16 {
    u16::from_le_bytes([zip[6], zip[7]])
}

/// The ucsize of the first entry of `zip`.
fn first_entry_ucsize(zip: &[u8]) -> u64 {
    u64::from(u32::from_le_bytes(zip[22..26].try_into().unwrap()))
}

/// Task 1's implode fixtures (commons-compress): the output is what `unzip
/// -p` gives (the SHA-256s below, from `/usr/bin/unzip -p <zip> |
/// shasum -a 256`, and the same in ubuntu:24.04), in one final chunk.
#[test]
fn explode_fixtures() {
    for (file, flags, len, sha) in [
        (
            "implode-4k-2trees.zip",
            0,
            818,
            "fdb715b10947e98f8bfb104194f9be0cda1b809391a8dc2100d78a25c06c7812",
        ),
        (
            "implode-8k-3trees.zip",
            6,
            11560,
            "3ddf9be5c28fe27dad143a5dc76eea25222ad1dd68934a047064e56ed2fa40c5",
        ),
    ] {
        let Some(zip) = super::fixture(file) else {
            return;
        };
        assert_eq!(first_entry_flags(&zip) & 6, flags, "{file}");
        let r = run(
            super::first_entry_data(&zip),
            first_entry_flags(&zip),
            first_entry_ucsize(&zip),
        );
        assert_eq!((r.code, &r.chunks), (0, &vec![len]), "{file}");
        assert_eq!(super::sha256(&r.out), sha, "{file}");
    }
}

/// All four variants: the two commons-compress fixtures, and the
/// hand-built zip of every variant (two of which no corpus has), accepted
/// by `unzip -t` on both references before they were committed (README).
/// The committed zips are what the writer makes today, byte for byte, and
/// each explodes to [`hand_data`], whose SHA-256 `unzip -p` gives.
#[test]
fn explode_all_four_variants() {
    let data = hand_data();
    assert_eq!(data.len(), 9400);
    assert_eq!(
        super::sha256(&data),
        "5079ff3e18949acca7b9a31962b516f5e2ffc93fe58282e45a3a8278e19f52e1",
        "hand_data() moved: regenerate the hand-built fixtures (README)"
    );
    let mut seen = [false; 4];
    for (name, flags) in VARIANTS {
        let (file, made) = hand_fixture(name, flags);
        let Some(zip) = super::fixture(&file) else {
            return;
        };
        assert!(zip == made, "{file} is not what the writer makes");
        let r = run(super::first_entry_data(&zip), flags, data.len() as u64);
        assert_eq!((r.code, &r.chunks), (0, &vec![data.len()]), "{file}");
        assert!(r.out == data, "{file}");
        seen[usize::from(flags >> 1)] = true;
    }
    for (file, flags) in [("implode-4k-2trees.zip", 0), ("implode-8k-3trees.zip", 6)] {
        let zip = super::fixture(file).unwrap();
        assert_eq!(first_entry_flags(&zip) & 6, flags, "{file}");
        assert_eq!(
            run(
                super::first_entry_data(&zip),
                flags,
                first_entry_ucsize(&zip)
            )
            .code,
            0
        );
    }
    assert_eq!(seen, [true; 4]);
}

/// Writes the four hand-built zips into `$STUFFR_INFOZIP_HAND_OUT`, to be
/// checked with `unzip -t` on both references and then committed (README).
#[test]
#[ignore = "generator for the hand-built implode fixtures; see tests/data/infozip/README"]
fn write_hand_fixtures() {
    let out = std::path::PathBuf::from(
        std::env::var_os("STUFFR_INFOZIP_HAND_OUT").expect("STUFFR_INFOZIP_HAND_OUT"),
    );
    std::fs::create_dir_all(&out).unwrap();
    for (name, flags) in VARIANTS {
        let (file, zip) = hand_fixture(name, flags);
        std::fs::write(out.join(file), zip).unwrap();
    }
}

// ---- damage tables, shared with unshrink's ----

/// Damaged input `i` of `base`, and (kinds 0-3) the bytes it claims past
/// its data: bit flips (0), a truncation where the entry's data ends (1), a
/// truncation where the archive ends, the cut bytes still claimed (2), or
/// inserted bytes (3), placed by a XorShift seeded from `i`. Half the
/// positions fall in the first 96 bytes, where the trees and the first
/// codes are. `kinds` limits the choice to `0..kinds`, and kind `kinds` (when
/// `uc` is given) instead changes the declared uncompressed size, leaving the
/// bytes alone. Returns (input, missing, ucsize, description).
pub(super) fn damage(base: &[u8], i: u64, uc: Option<u64>) -> (Vec<u8>, u64, u64, String) {
    let mut r = XorShift((i + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15));
    let len = base.len() as u64;
    let pos = |r: &mut XorShift, room: u64| {
        if r.next().is_multiple_of(2) {
            r.next() % room.min(96)
        } else {
            r.next() % room
        }
    };
    let mut b = base.to_vec();
    let mut kind = Vec::new();
    let ucsize = uc.unwrap_or(0);
    let kinds = if uc.is_some() { 5 } else { 4 };
    match r.next() % kinds {
        0 => {
            for _ in 0..1 + r.next() % 3 {
                let at = pos(&mut r, len) as usize;
                let bit = r.next() % 8;
                b[at] ^= 1 << bit;
                kind.push(format!("{at}.{bit}"));
            }
            (b, 0, ucsize, format!("flip:{}", kind.join("+")))
        }
        k @ (1 | 2) => {
            let to = (r.next() % len) as usize;
            b.truncate(to);
            let missing = if k == 2 { len - to as u64 } else { 0 };
            let name = if k == 2 { "short" } else { "truncate" };
            (b, missing, ucsize, format!("{name}:{to}"))
        }
        3 => {
            for _ in 0..1 + r.next() % 2 {
                let at = pos(&mut r, b.len() as u64 + 1) as usize;
                let byte = r.next() as u8;
                b.insert(at, byte);
                kind.push(format!("{at}.{byte:02x}"));
            }
            (b, 0, ucsize, format!("insert:{}", kind.join("+")))
        }
        _ => {
            let to = r.next() % (2 * ucsize + 2);
            (b, 0, to, format!("ucsize:{to}"))
        }
    }
}

/// The byte the window starts as for damaged input `i`: zeros for even
/// rows, 0xAA for odd ones (the drivers' `fill` column), so the tables pin
/// what each decoder reads from a window it did not write.
pub(super) fn fill(i: u64) -> u8 {
    if i.is_multiple_of(2) { 0 } else { 0xaa }
}

/// How many damaged inputs each table holds.
pub(super) const DAMAGED: u64 = 200;

/// Reads a damage table from `tests/data/infozip/`: its rows, without the
/// comment lines. `None` when the fixtures are absent.
pub(super) fn table(name: &str) -> Option<Vec<String>> {
    let table = String::from_utf8(super::fixture(name)?).unwrap();
    Some(
        table
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .map(str::to_owned)
            .collect(),
    )
}

/// Writes one decoder's damaged inputs to `$STUFFR_INFOZIP_DAMAGE_OUT/<tag>/`
/// with the drivers' manifest
/// (`NNN|base|flags|ucsize|missing|fill|kind|input-sha256|path`).
pub(super) fn write_inputs(tag: &str, inputs: &[Damaged]) {
    let out = std::path::PathBuf::from(
        std::env::var_os("STUFFR_INFOZIP_DAMAGE_OUT").expect("STUFFR_INFOZIP_DAMAGE_OUT"),
    )
    .join(tag);
    std::fs::create_dir_all(&out).unwrap();
    let mut manifest = String::new();
    for d in inputs {
        let path = out.join(format!("{:03}.in", d.i));
        std::fs::write(&path, &d.input).unwrap();
        manifest += &format!(
            "{:03}|{}|{}|{}|{}|{:02x}|{}|{}|{}\n",
            d.i,
            d.base,
            d.flags,
            d.ucsize,
            d.missing,
            fill(d.i),
            d.kind,
            super::sha256(&d.input),
            path.display()
        );
    }
    std::fs::write(out.join("manifest.txt"), manifest).unwrap();
}

/// One damaged input of a table.
pub(super) struct Damaged {
    pub(super) i: u64,
    pub(super) base: &'static str,
    pub(super) flags: u16,
    pub(super) ucsize: u64,
    pub(super) missing: u64,
    pub(super) input: Vec<u8>,
    pub(super) kind: String,
}

/// The explode table's undamaged streams: the two commons-compress
/// fixtures and the four hand-built ones, (name, file).
const BASES: [(&str, &str); 6] = [
    ("c4k2", "implode-4k-2trees.zip"),
    ("c8k3", "implode-8k-3trees.zip"),
    ("h4k2", "implode-hand-4k-2trees.zip"),
    ("h4k3", "implode-hand-4k-3trees.zip"),
    ("h8k2", "implode-hand-8k-2trees.zip"),
    ("h8k3", "implode-hand-8k-3trees.zip"),
];

/// One explode base: (name, flags, ucsize, stream).
type Base = (&'static str, u16, u64, Vec<u8>);

/// The explode bases.
fn bases() -> Option<Vec<Base>> {
    let mut v = Vec::new();
    for (name, file) in BASES {
        let zip = super::fixture(file)?;
        v.push((
            name,
            first_entry_flags(&zip),
            first_entry_ucsize(&zip),
            super::first_entry_data(&zip).to_vec(),
        ));
    }
    Some(v)
}

/// Damaged inputs `0..DAMAGED`, cycling through [`BASES`].
fn damaged_inputs() -> Option<Vec<Damaged>> {
    let bases = bases()?;
    Some(
        (0..DAMAGED)
            .map(|i| {
                let (base, flags, uc, b) = &bases[(i % BASES.len() as u64) as usize];
                let (input, missing, ucsize, kind) = damage(b, i, Some(*uc));
                Damaged {
                    i,
                    base,
                    flags: *flags,
                    ucsize,
                    missing,
                    input,
                    kind,
                }
            })
            .collect(),
    )
}

/// One row of `explode_damage.txt`, the C driver's output:
/// `NNN|base|kind|input-sha256|rc|used_csize|total|chunks|output-sha256`,
/// `used_csize` (`G.lrec.csize - unused`) only for a 5.
fn row(r: &Run, d: &Damaged) -> String {
    let csize = (d.input.len() as u64 + d.missing) as i64;
    let chunks: Vec<String> = r.chunks.iter().map(usize::to_string).collect();
    format!(
        "{:03}|{}|{}|{}|{}|{}|{}|{}|{}",
        d.i,
        d.base,
        d.kind,
        super::sha256(&d.input),
        r.code,
        r.unused.map_or("-".to_owned(), |u| (csize - u).to_string()),
        r.out.len(),
        if chunks.is_empty() {
            "-".to_owned()
        } else {
            chunks.join(",")
        },
        super::sha256(&r.out),
    )
}

/// Every damaged input gives exactly the C's return code, `G.used_csize`
/// (for a 5) and flushed chunks (lengths and bytes): Info-ZIP's own
/// `explode.c` (with `inflate.c`'s `huft_build`), compiled against a stub
/// `G` (the driver and recipe are in the fixtures' README), recorded in
/// `explode_damage.txt`. The window starts as [`fill`] says, in the driver
/// as here.
#[test]
fn damage_codes_match_the_c() {
    let Some(rows) = table("explode_damage.txt") else {
        return;
    };
    assert_eq!(rows.len() as u64, DAMAGED, "rows in explode_damage.txt");
    for (name, flags, ucsize, b) in bases().unwrap() {
        assert_eq!(run(&b, flags, ucsize).code, 0, "{name} undamaged");
    }
    let mut wrong = Vec::new();
    let mut codes = std::collections::BTreeMap::new();
    for (d, want) in damaged_inputs().unwrap().iter().zip(&rows) {
        let r = run_in(
            &d.input,
            d.flags,
            d.ucsize,
            d.missing,
            &mut vec![fill(d.i); WSIZE],
        );
        *codes.entry(r.code).or_insert(0) += 1;
        let got = row(&r, d);
        if got != *want {
            wrong.push(format!("  want {want}\n  got  {got}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {DAMAGED} rows differ from explode.c:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    // the table exercises the codes explode.c returns on damage
    for code in [0, 1, 4, 5] {
        assert!(
            codes.contains_key(&code),
            "no row with code {code}: {codes:?}"
        );
    }
    eprintln!("explode damage codes: {codes:?}");
}

/// Recipe (README): writes the damaged inputs and the driver's manifest
/// under `$STUFFR_INFOZIP_DAMAGE_OUT/explode/`.
#[test]
#[ignore = "generator for explode_damage.txt; see tests/data/infozip/README"]
fn write_damage_inputs() {
    write_inputs("explode", &damaged_inputs().expect("fixtures"));
}

// ---- hand-built streams for the edge cases the damage table misses ----

/// One hand-built case: name, flags, ucsize, bytes claimed past the data,
/// the window's starting byte, and the stream.
pub(super) struct Hand {
    pub(super) name: &'static str,
    pub(super) flags: u16,
    pub(super) ucsize: u64,
    pub(super) missing: u64,
    pub(super) fill: u8,
    pub(super) stream: Vec<u8>,
}

/// The hand-built explode streams.
fn hand_streams() -> Vec<Hand> {
    let hand = |name, flags, ucsize, missing, fill, stream| Hand {
        name,
        flags,
        ucsize,
        missing,
        fill,
        stream,
    };
    // Bad tree descriptions, each with ucsize 10:
    let trees: [(&str, Vec<u8>); 5] = [
        // get_tree: nothing at all (NEXTBYTE + 1 is 0 pairs, read as
        // 2^32, until the 16 EOF codes of 16 bits overflow l[])
        ("empty", vec![]),
        // get_tree: 5 pairs of 16 codes, 80 lengths for 64
        ("tree-overflow", vec![4, 0xf5, 0xf5, 0xf5, 0xf5, 0xf5]),
        // get_tree: one length for 64
        ("tree-short", vec![0, 0x05]),
        // the length tree: 64 codes of 7 bits, half a code space
        ("tree-incomplete", vec![3, 0xf6, 0xf6, 0xf6, 0xf6]),
        // the length tree: 64 codes of 5 bits, twice the code space
        ("tree-oversubscribed", vec![3, 0xf4, 0xf4, 0xf4, 0xf4]),
    ];
    let mut v: Vec<Hand> = trees
        .into_iter()
        .map(|(name, s)| hand(name, 0, 10, 0, 0, s))
        .collect();
    // the literal tree (three trees): 256 codes of 9 bits, incomplete
    let mut lit = vec![15];
    lit.extend([0xf8; 16]);
    v.push(hand("lit-tree-incomplete", 4, 10, 0, 0, lit));
    // ucsize 0: the trees are read, nothing is decoded, one empty flush
    v.push(hand("ucsize-0", 0, 0, 0, 0, Encoder::new(0).finish()));
    // 'a', then 3 bytes from 5 back, before the entry's start: memzero
    // writes zeros, whatever the window held (0xAA here)
    for (name, fill) in [("before-the-start", 0), ("before-the-start-aa", 0xaa)] {
        let mut e = Encoder::new(0);
        e.literal(b'a');
        e.copy(5, 3);
        v.push(hand(name, 0, 4, 0, fill, e.finish()));
    }
    // 8K, three trees: 'a', 'b', then 8192 back (the longest distance),
    // 321 bytes (the longest length), all before the entry's start: 321
    // zeros, the window's 0xAA unread
    let mut e = Encoder::new(6);
    e.literal(b'a');
    e.literal(b'b');
    e.copy(8192, 321);
    v.push(hand(
        "longest-before-the-start",
        6,
        323,
        0,
        0xaa,
        e.finish(),
    ));
    // 'a', 'b', then copies of 320 from 2 back past the 64 KiB window:
    // flushes of 65536 and the rest
    let mut e = Encoder::new(2);
    e.literal(b'a');
    e.literal(b'b');
    for _ in 0..219 {
        e.copy(2, 320);
    }
    v.push(hand(
        "past-the-window",
        2,
        2 + 219 * 320,
        0,
        0xaa,
        e.finish(),
    ));
    // the last match runs past ucsize: all of it is copied
    let mut e = Encoder::new(0);
    e.literal(b'a');
    e.copy(1, 100);
    v.push(hand("match-past-ucsize", 0, 50, 0, 0, e.finish()));
    // two bytes past the stream's end: 5, a warning (used <= csize)
    let mut e = Encoder::new(0);
    e.literal(b'a');
    e.literal(b'b');
    let mut s = e.finish();
    s.extend([0x55, 0x55]);
    v.push(hand("trailing-bytes", 0, 2, 0, 0, s));
    // ucsize past the stream: EOFs decode as one bits, literals 0xff,
    // until ucsize; 5, an error (used > csize)
    let mut e = Encoder::new(0);
    e.literal(b'a');
    v.push(hand("eof-before-ucsize", 0, 40, 0, 0, e.finish()));
    // the same with a literal tree: ~EOF is code 0, a 7-bit literal
    let mut e = Encoder::new(4);
    e.literal(b'a');
    v.push(hand("eof-before-ucsize-lit", 4, 40, 0, 0, e.finish()));
    // the archive ends where the entry claims 300000 more bytes: G.csize
    // stays positive, and over 200000 it also picks bd = 8 (unobservable)
    let mut e = Encoder::new(0);
    e.literal(b'a');
    e.literal(b'b');
    v.push(hand("short-archive", 0, 2, 300_000, 0, e.finish()));
    // a final partial byte: k >> 3 is 0, the bits left over do not count
    let mut e = Encoder::new(0);
    e.literal(b'a');
    e.bits(0, 3);
    v.push(hand("spare-bits", 0, 1, 0, 0, e.finish()));
    v
}

/// One expected hand-built row: name, code, `G.used_csize`, chunks, and the
/// output's SHA-256.
type Want = (
    &'static str,
    i32,
    Option<i64>,
    &'static [usize],
    &'static str,
);

/// The hand-built streams give what `explode.c` gives. Each expected row is
/// the C driver's (README) over the streams `write_hand_inputs` writes:
/// return code, `G.used_csize` for a 5, the chunks, and the output's
/// SHA-256. The outputs the notes above name are checked byte for byte too.
#[test]
fn hand_built_streams() {
    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    #[rustfmt::skip]
    let want: [Want; 17] = [
        ("empty", 4, None, &[], EMPTY),
        ("tree-overflow", 4, None, &[], EMPTY),
        ("tree-short", 4, None, &[], EMPTY),
        ("tree-incomplete", 1, None, &[], EMPTY),
        ("tree-oversubscribed", 2, None, &[], EMPTY),
        ("lit-tree-incomplete", 1, None, &[], EMPTY),
        ("ucsize-0", 0, None, &[0], EMPTY),
        ("before-the-start", 0, None, &[4],
         "a2d398922901344d08180dc41d3e9d73d8c148c7f6e092835bbb28e02dbcf184"),
        ("before-the-start-aa", 0, None, &[4],
         "a2d398922901344d08180dc41d3e9d73d8c148c7f6e092835bbb28e02dbcf184"),
        ("longest-before-the-start", 0, None, &[323],
         "bc17dae6bf7dfc0171b29d3fc76ba6515353edd88805b1d146402f4e110a468f"),
        ("past-the-window", 0, None, &[65536, 4546],
         "96a3c3d5acdc59daa5145e602b3390f1d8662d9703bf50a741bbcc1684c72563"),
        ("match-past-ucsize", 0, None, &[101],
         "9d0793397991b57a99a07c6e6b4a92bab68dbf605345cd0b87f385a448a726bc"),
        ("trailing-bytes", 5, Some(14), &[2],
         "fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603"),
        ("eof-before-ucsize", 5, Some(56), &[40],
         "0ba8d07491d9072931c01bf2bd05e20b5291783fb9378ec724fcf1bb99e2c0a2"),
        ("eof-before-ucsize-lit", 5, Some(68), &[40],
         "6e638ddd9585d887ffff389d6d65e237622cd67c891d9eef4c5a7ad75b5a411e"),
        ("short-archive", 5, Some(14), &[2],
         "fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603"),
        ("spare-bits", 0, None, &[1],
         "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"),
    ];
    let streams = hand_streams();
    assert_eq!(streams.len(), want.len());
    let mut outs = std::collections::HashMap::new();
    for (h, (name, code, used, chunks, sha)) in streams.iter().zip(&want) {
        assert_eq!(h.name, *name);
        let r = run_in(
            &h.stream,
            h.flags,
            h.ucsize,
            h.missing,
            &mut vec![h.fill; WSIZE],
        );
        let csize = (h.stream.len() as u64 + h.missing) as i64;
        let got_used = r.unused.map(|u| csize - u);
        assert_eq!(
            (r.code, got_used, &r.chunks[..], &super::sha256(&r.out)[..]),
            (*code, *used, *chunks, *sha),
            "{name}"
        );
        outs.insert(*name, r.out);
    }
    // memzero, never the window, before the entry's first byte
    assert_eq!(outs["before-the-start-aa"], [b'a', 0, 0, 0]);
    let mut longest = b"ab".to_vec();
    longest.extend([0; 321]);
    assert_eq!(outs["longest-before-the-start"], longest);
    // past the window: the entry's own bytes, across the wrap
    assert!(
        outs["past-the-window"]
            .iter()
            .copied()
            .eq(b"ab".iter().copied().cycle().take(70082))
    );
    // the whole of the last match, past ucsize
    assert_eq!(outs["match-past-ucsize"], vec![b'a'; 101]);
    // EOFs read as one bits: plain literals of 0xff to ucsize (the
    // stream's own zero padding decodes first, as a match)
    assert!(outs["eof-before-ucsize"].ends_with(&[0xff; 30]));
}

/// Writes the hand-built streams to `$STUFFR_INFOZIP_DAMAGE_OUT/explode-hand/`
/// with the driver's manifest.
#[test]
#[ignore = "writes the hand-built streams for the C driver; see tests/data/infozip/README"]
fn write_hand_inputs() {
    let out = std::path::PathBuf::from(
        std::env::var_os("STUFFR_INFOZIP_DAMAGE_OUT").expect("STUFFR_INFOZIP_DAMAGE_OUT"),
    )
    .join("explode-hand");
    std::fs::create_dir_all(&out).unwrap();
    let mut manifest = String::new();
    for (i, h) in hand_streams().into_iter().enumerate() {
        let path = out.join(format!("{}.in", h.name));
        std::fs::write(&path, &h.stream).unwrap();
        manifest += &format!(
            "{i:03}|{}|{}|{}|{}|{:02x}|hand|{}|{}\n",
            h.name,
            h.flags,
            h.ucsize,
            h.missing,
            h.fill,
            super::sha256(&h.stream),
            path.display()
        );
    }
    std::fs::write(out.join("manifest.txt"), manifest).unwrap();
}

/// Explode never reads the window it is given: over every damaged input and
/// hand-built stream, a window of 0xAA gives what a zeroed one does (the
/// code, `unused`, the chunks and the bytes), because before the first
/// flush a match reaching before the entry's start is zero-filled.
#[test]
fn window_contents_are_never_read() {
    let mut cases: Vec<(Vec<u8>, u16, u64, u64)> = hand_streams()
        .into_iter()
        .map(|h| (h.stream, h.flags, h.ucsize, h.missing))
        .collect();
    if let Some(inputs) = damaged_inputs() {
        cases.extend(
            inputs
                .into_iter()
                .map(|d| (d.input, d.flags, d.ucsize, d.missing)),
        );
    }
    for (i, (input, flags, ucsize, missing)) in cases.iter().enumerate() {
        let zeroed = run_in(input, *flags, *ucsize, *missing, &mut vec![0; WSIZE]);
        let filled = run_in(input, *flags, *ucsize, *missing, &mut vec![0xaa; WSIZE]);
        assert!(
            (zeroed.code, zeroed.unused, &zeroed.chunks, &zeroed.out)
                == (filled.code, filled.unused, &filled.chunks, &filled.out),
            "case {i}"
        );
    }
}

/// A window under `WSIZE` is refused.
#[test]
#[should_panic(expected = "under WSIZE")]
fn short_window_panics() {
    run_in(&[], 0, 1, 0, &mut [0; 100]);
}

/// The binaries' own figures for return 5: `implode-hand-8k-3trees.zip`
/// with its declared size patched to 50 and to 20000 (local and central),
/// `unzip -p` and `unzip -t` on both references print "warning:  79 bytes
/// required to uncompress to 50 bytes; supposed to require 2299 bytes" and
/// "error:  12898 bytes required to uncompress to 20000 bytes", and write
/// 50 and 20000 bytes (probe in compat.md, "Task 5 probes").
#[test]
fn used_csize_is_what_unzip_prints() {
    let Some(zip) = super::fixture("implode-hand-8k-3trees.zip") else {
        return;
    };
    let data = super::first_entry_data(&zip);
    assert_eq!(data.len(), 2299);
    for (ucsize, used, len) in [(50, 79, 50), (20000, 12898, 20000)] {
        let r = run(data, 6, ucsize);
        assert_eq!(r.code, 5, "ucsize {ucsize}");
        assert_eq!(2299 - r.unused.unwrap(), used, "ucsize {ucsize}");
        assert_eq!(r.out.len(), len, "ucsize {ucsize}");
    }
}
