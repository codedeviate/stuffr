//! The damage tables shared by the explode and unshrink tests: the bit
//! writer, the damaged-input generator, and the recorded-table helpers.

use super::inflate::XorShift;

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
    pub(super) fn code(&mut self, code: u32, len: u32) {
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
