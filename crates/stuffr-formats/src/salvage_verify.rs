//! The shared streaming verifier behind `SalvageScan::verify`.
//!
//! Stage 1's `zip_salvage.rs` built `stream_verify` for zip alone, and it
//! hardcoded a 32-bit CRC state — the only width zip's own local header ever
//! carries. Stage 2 extends salvage to four legacy formats, three of which
//! (`lha`, `arc`, `zoo`) carry a CRC-**16**/ARC instead of a CRC-32, so a
//! per-format copy of this function would mean writing (and separately
//! falsifying) the same streaming/bounding logic four times over one already
//! generalised value: [`stuffr_core::salvage::Verifier`] already carries
//! both widths — it has since Stage 1's first task — this module is the
//! first thing that actually matches both of its arms.
//!
//! # Why this is the first real exercise of `Verifier::Crc16`
//!
//! `Verifier::Crc16` has existed since Stage 1 with no production caller: it
//! compiled, and nothing ever constructed or matched one. That is worth
//! naming plainly, because it means the CRC-16 branch below has no existing
//! test suite's incidental coverage to lean on — the anti-vacuity discipline
//! this project applies to a validation gate (see `zip_salvage.rs`'s own
//! module doc) applies here too: the task report records swapping the Crc16
//! arm onto the Crc32 state and confirming exactly the CRC-16 tests fail
//! while zip's stay green, which is what proves the two widths are
//! genuinely independent rather than one path accidentally serving both.
//!
//! # One fixed-size window, incremental state per width
//!
//! Both arms stream through the same [`VERIFY_CHUNK`]-sized window and never
//! materialise a whole payload — see `zip_salvage.rs`'s module doc
//! ("Verification") for the allocation defect that discipline closes and why
//! it is load-bearing, not a micro-optimisation. `Verifier::Crc32` resumes
//! `crc32_ieee_update`'s running state exactly as Stage 1 did; `Verifier::
//! Crc16` resumes [`crate::legacy::crc::crc16_arc_continued`] the identical
//! way — the function Phase 3c already built for exactly this: incremental
//! CRC-16/ARC over a fixed window, pinned against the published check value
//! `"123456789"` -> `0xBB3D`.
//!
//! The short/over-read length checks are format-agnostic and unchanged from
//! Stage 1: fewer bytes produced than `expected_len` declares, or a read
//! that fails partway, is `Partial` immediately; more bytes than declared is
//! also `Partial`, stopped the moment the excess is seen rather than trusted
//! to a decoder that might not stop on its own. Only the checksum comparison
//! itself differs per width — CRC-32/ISO-HDLC finalizes with a bitwise
//! complement (`!state == expected`); CRC-16/ARC has no final xor at all
//! (`state == expected`) — and getting that backwards is exactly the shape
//! Step 6's falsification exists to catch.
//!
//! # Public, because a sixth scanner cannot be written without it
//!
//! The final whole-branch review's F2. `0.6.0` spends a real breaking
//! release specifically to make [`stuffr_core::salvage::SalvageScan`]
//! implementable from outside — `Candidate` and `SalvagedEntry` closed with
//! `#[non_exhaustive]` and constructors, a whole "third shape" section in
//! `CONTRIBUTING.md` arguing for it — and then left the one thing that
//! turns a public [`Verifier`] into a public [`SalvageStatus`] behind a
//! `pub(crate)` fn in a private module. An outside scanner had to reimplement
//! a streaming CRC-16/ARC and CRC-32 comparison to reach the statuses the
//! public enum describes, which is the opposite of an open seam.
//!
//! This module is now `pub` and [`stream_verify`] with it. Nothing else
//! here is: `crc32_ieee_update` is an implementation detail of the Crc32
//! arm, and publishing a CRC table is not what the gap was about.
//!
//! # Why this lives in `stuffr-formats`, not `stuffr-core`
//!
//! `stuffr-core` carries zero format dependencies (see this crate's own
//! `CLAUDE.md`), and a CRC implementation is format-adjacent even though it
//! is not itself a decoder. `legacy::crc` already lives here for exactly
//! this reason; this module is the second caller of it, not a reason to
//! move it.

use std::io::Read;

use stuffr_core::salvage::{SalvageStatus, Verifier};

use crate::legacy::crc::crc16_arc_continued;

/// Bytes read per verification chunk. Fixed and small so a candidate's
/// declared length — up to `policy.max_entry`, 4 GiB by default — never
/// determines how much memory verification uses. Same figure, same
/// reasoning, as Stage 1's own constant of this name in `zip_salvage.rs`.
const VERIFY_CHUNK: usize = 64 * 1024;

/// Streams `reader` to completion, hashing as it goes and never
/// materialising a buffer: `expected_len` is the exact byte count `reader`
/// must produce, and `verifier` names both which checksum width to resume
/// and the value the original writer computed. Exceeding `expected_len`
/// stops immediately rather than reading further — the bound against an
/// unbounded decompression bomb, since nothing else on the OUTPUT side would
/// otherwise stop a small compressed input expanding far past what its own
/// header claims.
///
/// Never panics and never blocks on a short/failing read: a read error
/// partway through — a malformed compressed stream, a source that ran out
/// before `expected_len`, a genuine I/O error — is folded into
/// [`SalvageStatus::Partial`] alike, the same deliberate choice Stage 1's
/// `verify_candidate` documents (salvage exists to recover as much of a
/// damaged archive as it can; a caller-visible `Err` here would abort the
/// entire run over one bad entry).
pub fn stream_verify(
    mut reader: impl Read,
    expected_len: u64,
    verifier: &Verifier,
) -> SalvageStatus {
    let mut crc32_state: u32 = 0xFFFF_FFFF;
    let mut crc16_state: u16 = 0;
    let mut produced: u64 = 0;
    let mut buf = [0u8; VERIFY_CHUNK];

    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            // A short/failing read partway through — "the payload ran out,
            // or the decoder failed mid-stream", `SalvageStatus::Partial`'s
            // own words.
            Err(_) => return SalvageStatus::Partial,
        };
        produced += n as u64;
        if produced > expected_len {
            // Produced more than the caller's own declared size — refuse to
            // keep decoding rather than trusting the decoder to stop on its
            // own.
            return SalvageStatus::Partial;
        }
        match verifier {
            Verifier::Crc32(_) => crc32_state = crc32_ieee_update(crc32_state, &buf[..n]),
            Verifier::Crc16(_) => crc16_state = crc16_arc_continued(crc16_state, &buf[..n]),
        }
    }

    if produced != expected_len {
        // Fewer bytes than declared were actually produced — the payload
        // ran out before the caller said it would.
        return SalvageStatus::Partial;
    }

    // CRC-32/ISO-HDLC finalizes with a bitwise complement of the running
    // state; CRC-16/ARC has no final xor at all. Getting this backwards for
    // either width is exactly what this task's required falsification (swap
    // the Crc16 arm onto the Crc32 state) exists to catch — see the task
    // report.
    let agrees = match *verifier {
        Verifier::Crc32(expected) => !crc32_state == expected,
        Verifier::Crc16(expected) => crc16_state == expected,
    };

    if agrees {
        SalvageStatus::Intact
    } else {
        // Every declared byte decoded, but the result does not match the
        // checksum the original writer computed — not proven whole, so
        // `Partial`, never `Complete` (which would claim nothing had been
        // checked at all) and never `Intact`.
        SalvageStatus::Partial
    }
}

/// CRC-32/ISO-HDLC (reflected polynomial 0xEDB88320, init and xorout
/// 0xFFFFFFFF) — the checksum a zip local/central header's `crc32` field
/// carries, over the entry's UNCOMPRESSED bytes.
///
/// Written here rather than taken from `crc32fast` (already in this
/// workspace's dependency tree via `zip`/`flate2`, but not a direct
/// dependency of this crate): `legacy/arj.rs`'s own `crc32_ieee` makes the
/// identical argument for the identical algorithm — pulling in a crate for
/// one 12-line routine adds a dependency for no capability. Not reused from
/// `legacy/arj.rs` directly: that module is feature-gated behind
/// `arj`/`arc`/`zoo`/`lha`, none of which this module's own gate implies.
/// Moved here verbatim from Stage 1's `zip_salvage.rs` (Task 1 of Salvage
/// Stage 2) as part of generalising `stream_verify` to both CRC widths.
fn crc32_ieee_update(crc: u32, data: &[u8]) -> u32 {
    let mut crc = crc;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    crc
}

/// `#[cfg(test)]`-only whole-buffer convenience wrapper around
/// [`crc32_ieee_update`], pinning the algorithm against its published check
/// value. Production code only ever needs the incremental form, threaded
/// across chunks inside [`stream_verify`] — see that function's own doc.
#[cfg(test)]
fn crc32_ieee(data: &[u8]) -> u32 {
    !crc32_ieee_update(0xFFFF_FFFF, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy::crc::crc16_arc;

    // -------------------------------------------------------------------
    // The brief's own three tests (Step 1), verbatim.
    // -------------------------------------------------------------------

    #[test]
    fn a_crc16_payload_that_agrees_is_intact() {
        let data = b"the quick brown fox";
        let v = Verifier::Crc16(crc16_arc(data));
        assert_eq!(
            stream_verify(&data[..], data.len() as u64, &v),
            SalvageStatus::Intact
        );
    }

    #[test]
    fn a_crc16_payload_that_disagrees_is_partial_by_checksum() {
        let data = b"the quick brown fox";
        let v = Verifier::Crc16(crc16_arc(data) ^ 1);
        assert!(matches!(
            stream_verify(&data[..], data.len() as u64, &v),
            SalvageStatus::Partial
        ));
    }

    #[test]
    fn a_short_payload_is_partial_whatever_the_crc_width() {
        let data = b"cut";
        let v = Verifier::Crc16(0);
        assert!(matches!(
            stream_verify(&data[..], 99, &v),
            SalvageStatus::Partial
        ));
    }

    // -------------------------------------------------------------------
    // The CRC-32 side, unchanged in substance from Stage 1's own copy —
    // moved here because the algorithm they pin now lives here too.
    // -------------------------------------------------------------------

    /// Pinned to the algorithm's published check value (CRC RevEng
    /// catalogue: `CRC-32/ISO-HDLC`, ASCII `"123456789"` -> `0xCBF43926`) —
    /// an external constant, so a transcription error in the polynomial
    /// cannot hide behind this module's own expectations.
    #[test]
    fn crc32_ieee_matches_the_standard_check_value() {
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
    }

    /// The incremental form must be indistinguishable from hashing the whole
    /// run at once — `stream_verify` depends on this to hash a payload
    /// chunk-by-chunk without ever holding it whole.
    #[test]
    fn resuming_a_crc_matches_hashing_it_whole() {
        let data = b"123456789";
        for split in 0..=data.len() {
            let (a, b) = data.split_at(split);
            let resumed = !crc32_ieee_update(crc32_ieee_update(0xFFFF_FFFF, a), b);
            assert_eq!(resumed, crc32_ieee(data), "split at {split}");
        }
    }

    // -------------------------------------------------------------------
    // Symmetry check: CRC-32 through the shared function agrees with the
    // CRC-32-only helpers above, over the identical bytes.
    // -------------------------------------------------------------------

    #[test]
    fn a_crc32_payload_that_agrees_is_intact_through_the_shared_verifier() {
        let data = b"the quick brown fox";
        let v = Verifier::Crc32(crc32_ieee(data));
        assert_eq!(
            stream_verify(&data[..], data.len() as u64, &v),
            SalvageStatus::Intact
        );
    }
}
