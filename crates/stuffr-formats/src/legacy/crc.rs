//! CRC-16/ARC — the check ARC, ZOO and LHA all carry.
//!
//! Reflected polynomial 0xA001, init 0, no final xor. Promoted out of
//! `lha.rs`'s test module in Phase 3c, when ARC and ZOO needed it in
//! PRODUCTION code: their per-entry CRC is what verifies this project's
//! decoders against the tool that wrote the archive, so it stopped being a
//! test helper and became the witness.
//!
//! `#[allow(dead_code)]` is now needed for ONE build configuration rather
//! than for a task's worth of time: `--features lha` on its own. ARC and ZOO
//! both call this from production code, so any build carrying either has real
//! callers — but LHA's own read path never needed it (it delegates to
//! `delharc`'s internal `crc_check()`), and `lha.rs`'s only use is a
//! `#[cfg(test)]` fixture builder. Remove the attribute if `lha` ever gains a
//! production caller of its own.
#[allow(dead_code)]
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
