//! CRC-16/ARC — the check ARC, ZOO and LHA all carry.
//!
//! Reflected polynomial 0xA001, init 0, no final xor. Promoted out of
//! `lha.rs`'s test module in Phase 3c, when ARC and ZOO needed it in
//! PRODUCTION code: their per-entry CRC is what verifies this project's
//! decoders against the tool that wrote the archive, so it stopped being a
//! test helper and became the witness.
//!
//! The `#[allow(dead_code)]` this module carried for `crc16_arc` is gone as
//! of Phase 3c Task 6, and the note it carried is worth keeping as history:
//! it existed because `--features lha` on its own had no production caller —
//! LHA's READ path delegates its integrity check to `delharc`'s internal
//! `crc_check()`, so `lha.rs`'s only use was a `#[cfg(test)]` fixture
//! builder. LHA's `-lh5-` ENCODER is that production caller: an LHA header
//! records the CRC-16/ARC of the entry's UNCOMPRESSED bytes, and nothing in
//! `delharc` computes one, because `delharc` cannot write.
// Dead in a build enabling `zip` but none of `lha`/`arc`/`zoo`: Salvage
// Stage 2 Task 1 widened this module's own `#[cfg]` gate (see `mod.rs`) so
// `salvage_verify.rs` can reach `crc16_arc_continued` below, but that
// leaves the WHOLE-BUFFER form (this function) with no production caller in
// such a build — its real callers are the `arc`/`lha` encoders (`arc.rs`'s
// own `next_entry`, `lha.rs`'s `-lh5-` encoder), and `salvage_verify.rs`
// itself uses `crc16_arc_continued` only. `#[allow(dead_code)]` used to sit
// here instead of this `cfg`, which suppresses the warning in every build
// rather than compiling the function out of the one tree that has nothing
// to call it — and this crate's own gate runs `-D warnings`, so a
// suppressed warning is a liability the day something nearby genuinely goes
// dead. Narrower than the module's own gate (which also admits `zip` alone,
// for `crc16_arc_continued`'s sake): only the three formats that actually
// call this whole-buffer form.
#[cfg(any(feature = "lha", feature = "arc", feature = "zoo"))]
pub(crate) fn crc16_arc(data: &[u8]) -> u16 {
    crc16_arc_continued(0, data)
}

/// The same CRC, resumed from a running value.
///
/// zoo's own `addbfcrc` accumulates into a single `crccode` across successive
/// buffers, which is exactly what `portable.c`'s `dir_to_b` needs: a
/// directory record's checksum covers the fixed part and the variable part
/// behind it as one run. Resuming avoids joining two slices into a temporary
/// just to hash them, and it is the shape the C code actually has.
#[allow(dead_code)]
pub(crate) fn crc16_arc_continued(seed: u16, data: &[u8]) -> u16 {
    let mut crc: u16 = seed;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xA001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc16_arc_matches_the_published_check_value() {
        // CRC-16/ARC's standard check: the ASCII string "123456789" -> 0xBB3D.
        // From the CRC RevEng catalogue. An external constant, so a
        // transcription error in the polynomial or the init value cannot
        // hide behind our own expectations.
        assert_eq!(crc16_arc(b"123456789"), 0xBB3D);
    }

    /// Resuming must be indistinguishable from hashing the whole run, or a
    /// record's checksum computed over "fixed part, then variable part" would
    /// silently differ from the one `dir_to_b` wrote over the two together.
    #[test]
    fn resuming_a_crc_matches_hashing_the_whole_run() {
        for split in 0..=9usize {
            let (a, b) = b"123456789".split_at(split);
            assert_eq!(
                crc16_arc_continued(crc16_arc(a), b),
                0xBB3D,
                "split at {split}"
            );
        }
    }
}
