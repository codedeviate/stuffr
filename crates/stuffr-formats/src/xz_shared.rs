//! Identity shared by both xz backends: the C one (`xz_c`, Task 4 of Phase
//! 1e, via `liblzma`) and the pure `lzma-rust2` counterpart (`xz_pure`, Task
//! 5).
//!
//! Unlike zstd's pair, xz's pure backend is not a weaker fallback — Task 5's
//! brief describes it as a full codec at ratio parity, so `c-backed` is a
//! speed choice for xz rather than a capability one. That does not change
//! the shape here: whichever backend is compiled in must alone still expose
//! the identical [`FormatId`], magic rule and [`FormatMeta`], because that
//! identity is what makes `--format xz`, magic detection, and `stuffr formats`'
//! single `xz` row work the same regardless of which backend produced the
//! binary. Neither backend module can own it: an `xz-pure`-only build has no
//! `xz_c` module at all, and vice versa, so the shared pieces live here
//! instead and each backend re-exports them under its own name.
//!
//! Gated on `any(feature = "xz-c", feature = "xz-pure")` so this module does
//! not exist — and cannot produce a dead-code warning — in a build with
//! neither.

use stuffr_core::{FormatId, FormatMeta, MagicRule};

/// The identity both backends register under.
pub const XZ: FormatId = FormatId::new("xz");

/// The xz stream header magic, `FD 37 7A 58 5A 00` at offset 0 — reused by
/// both backends' registration metadata for magic detection.
pub(crate) const XZ_MAGIC: &[MagicRule] = &[MagicRule {
    offset: 0,
    bytes: &[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00],
    format: XZ,
}];

/// Registration metadata for xz, shared by both backends.
pub fn xz_meta() -> FormatMeta {
    FormatMeta::codec(XZ, &["xz"], XZ_MAGIC).with_confirm(confirm)
}

/// The stream header behind the magic: stream flags byte 0 is reserved
/// (zero), byte 1's high nibble is reserved (zero; the low nibble is the
/// check type, any of which a decoder must accept), and bytes 8..12 are the
/// little-endian CRC-32 of those two flag bytes.
fn confirm(prefix: &[u8]) -> bool {
    if prefix.get(6).is_some_and(|&b| b != 0) || prefix.get(7).is_some_and(|&b| b & 0xf0 != 0) {
        return false;
    }
    match prefix.get(6..12) {
        Some(h) => crc32(&h[..2]) == u32::from_le_bytes([h[2], h[3], h[4], h[5]]),
        None => true,
    }
}

/// CRC-32/ISO-HDLC, bitwise: two bytes per call is all it ever hashes, and
/// the crate's other copies sit behind container features an xz-only build
/// does not enable.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
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

/// Finds the `xz` binary on `PATH` without shelling out to `which` (not
/// guaranteed present either, and one external dependency is enough).
/// Returns `None` rather than panicking so interop tests skip cleanly on a
/// machine with no `xz` installed, rather than failing the whole suite.
///
/// Lives here, not in either backend module, so both `xz_pure`'s and
/// `xz_c`'s test modules can share one implementation: this module is gated
/// `any(feature = "xz-c", feature = "xz-pure")`, so it compiles whenever
/// either backend's tests could need it.
#[cfg(test)]
pub(crate) fn which_xz() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let candidate = dir.join("xz");
        candidate.is_file().then_some(candidate)
    })
}

#[cfg(test)]
mod confirm_tests {
    use super::*;
    use crate::confirm_test::{assert_every_cut_confirms, assert_never_panics};
    use stuffr_core::ConfirmFn;

    fn confirm() -> ConfirmFn {
        xz_meta().confirm.expect("xz registers a confirm function")
    }

    /// Stream headers as xz writes them, one per check type, with their
    /// CRC-32s as the reference tool computed them.
    const HEADERS: [[u8; 12]; 4] = [
        [
            0xfd, 0x37, 0x7a, 0x58, 0x5a, 0, 0, 0x00, 0xff, 0x12, 0xd9, 0x41,
        ],
        [
            0xfd, 0x37, 0x7a, 0x58, 0x5a, 0, 0, 0x01, 0x69, 0x22, 0xde, 0x36,
        ],
        [
            0xfd, 0x37, 0x7a, 0x58, 0x5a, 0, 0, 0x04, 0xe6, 0xd6, 0xb4, 0x46,
        ],
        [
            0xfd, 0x37, 0x7a, 0x58, 0x5a, 0, 0, 0x0a, 0xe1, 0xfb, 0x0c, 0xa1,
        ],
    ];

    #[test]
    fn confirm_accepts_every_check_type_header() {
        for header in HEADERS {
            assert_every_cut_confirms("xz header", confirm(), &header, 6);
        }
    }

    #[test]
    fn confirm_rejects_magic_plus_noise() {
        let good = HEADERS[2];
        let mut bad = good;
        bad[6] = 1; // stream flags byte 0 is reserved
        assert!(!confirm()(&bad));
        let mut bad = good;
        bad[7] |= 0x10; // byte 1's high nibble is reserved
        assert!(!confirm()(&bad));
        let mut bad = good;
        bad[11] ^= 0x80; // the CRC-32 disagrees
        assert!(!confirm()(&bad));
        let mut noise = good.to_vec();
        noise[6..].copy_from_slice(b"ordina");
        assert!(!confirm()(&noise));
    }

    #[test]
    fn confirm_never_panics_on_short_input() {
        let mut stream = HEADERS[2].to_vec();
        stream.extend_from_slice(&[
            0x02, 0x00, 0x21, 0x01, 0x16, 0, 0, 0, 0x74, 0x2f, 0xe5, 0xa3,
        ]);
        assert_never_panics(confirm(), &stream);
    }
}
