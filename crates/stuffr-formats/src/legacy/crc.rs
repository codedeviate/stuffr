//! CRC-16/ARC — the check ARC, ZOO and LHA all carry.
//!
//! Reflected polynomial 0xA001, init 0, no final xor. Promoted out of
//! `lha.rs`'s test module in Phase 3c, when ARC and ZOO needed it in
//! PRODUCTION code: their per-entry CRC is what verifies this project's
//! decoders against the tool that wrote the archive, so it stopped being a
//! test helper and became the witness.
//!
//! `#[allow(dead_code)]` is deliberate and temporary, not a suppressed real
//! warning: THIS task (Phase 3c Task 1) promotes the routine ahead of its
//! production callers, which land in the two tasks right after it — ARC and
//! ZOO read support. Until then, `lha.rs`'s `#[cfg(test)]` fixture builder
//! (`build_single_entry_lha`) and this file's own pinned test are the only
//! callers, and LHA's own production read path never needed this routine to
//! begin with — it delegates to `delharc`'s internal `crc_check()` instead.
//! Remove the attribute when ARC or ZOO's decoder calls this for real.
#[allow(dead_code)]
pub(crate) fn crc16_arc(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
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
}
