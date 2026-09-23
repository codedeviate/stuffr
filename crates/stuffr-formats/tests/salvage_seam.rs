//! The published salvage seam, exercised from OUTSIDE both crates that
//! define it — the final whole-branch review's F2.
//!
//! `0.6.0` spends a breaking release specifically to make
//! [`stuffr_core::salvage::SalvageScan`] implementable by a third party:
//! `Candidate` and `SalvagedEntry` closed with `#[non_exhaustive]` plus
//! constructors, and a whole "third shape" section in `CONTRIBUTING.md`
//! arguing for it. The review's finding was that it was implementable and
//! **not usable**: the only thing in the workspace that turns a public
//! `Verifier` plus a reader into a public `SalvageStatus` was
//! `salvage_verify::stream_verify`, `pub(crate)` inside a **private**
//! module, so an outside scanner had to reimplement a streaming CRC-16/ARC
//! and CRC-32 comparison to reach the statuses the public enum describes.
//!
//! This file is the test that could not have been written before, and it is
//! an INTEGRATION test on purpose: an integration test compiles as its own
//! crate, so everything it reaches has to be genuinely `pub`. A unit test
//! inside either crate would compile against `pub(crate)` just as happily
//! and would have proved nothing.
//!
//! **What it does not claim.** A scanner written out of tree still cannot be
//! reached by `stuffr salvage` itself: the ops layer resolves a format name
//! to a scanner with no registration point. That half is Stage 3's and is
//! stated as such in `entries::write_salvaged_payload`'s own doc — this file
//! pins the half that did land, which is that the seam's two verbs
//! (verification and payload writing) are both reachable and both behave.

// The same gate `stuffr_formats::salvage_verify` itself carries: the module
// only exists in a build with at least one salvageable format, so this file
// must not try to import from it in one without.
#![cfg(any(
    feature = "zip",
    feature = "arc",
    feature = "zoo",
    feature = "lha",
    feature = "arj"
))]

use std::io::{Cursor, Read, SeekFrom, Write};

use stuffr_core::archive::EntryMeta;
use stuffr_core::error::Result;
use stuffr_core::salvage::{
    Candidate, SalvageScan, SalvageStatus, SalvagedEntry, Verifier, salvage_all,
};
use stuffr_core::source::SeekRead;
use stuffr_formats::salvage_verify::stream_verify;

/// One record: a 4-byte magic, a 2-byte big-endian length, a CRC-32 of the
/// payload, then the payload. Deliberately a format that exists nowhere —
/// the point is that nothing in this file may reach into a format stuffr
/// already knows how to read.
const MAGIC: &[u8; 4] = b"SXTH";
const HEADER_LEN: u64 = 4 + 2 + 4;

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn record(payload: &[u8], declared_crc: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    out.extend_from_slice(&declared_crc.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// A sixth scanner, written against nothing but the published surface.
struct SixthScan;

impl SalvageScan for SixthScan {
    fn next_candidate(&mut self, src: &mut dyn SeekRead, from: u64) -> Result<Option<Candidate>> {
        let len = src.seek(SeekFrom::End(0))?;
        let mut at = from;
        while at + HEADER_LEN <= len {
            src.seek(SeekFrom::Start(at))?;
            let mut header = [0u8; HEADER_LEN as usize];
            if src.read_exact(&mut header).is_err() {
                return Ok(None);
            }
            if &header[..4] != MAGIC {
                at += 1;
                continue;
            }
            let declared = u64::from(u16::from_be_bytes([header[4], header[5]]));
            let crc = u32::from_be_bytes([header[6], header[7], header[8], header[9]]);
            let payload_start = at + HEADER_LEN;
            let available = len.saturating_sub(payload_start);
            return Ok(Some(
                Candidate::new(at, payload_start, EntryMeta::file(format!("entry-at-{at}")))
                    .with_declared_len(Some(declared))
                    .with_verifier(Some(Verifier::Crc32(crc)))
                    .with_available_len((available < declared).then_some(available)),
            ));
        }
        Ok(None)
    }

    /// The whole point of the finding: this is reachable now.
    fn verify(&self, src: &mut dyn SeekRead, candidate: &Candidate) -> Result<SalvageStatus> {
        let Some(declared) = candidate.declared_len else {
            return Ok(SalvageStatus::Complete);
        };
        let Some(verifier) = candidate.verifier.as_ref() else {
            return Ok(SalvageStatus::Complete);
        };
        src.seek(SeekFrom::Start(candidate.payload_start))?;
        let bounded = candidate.available_len.unwrap_or(declared);
        Ok(stream_verify(src.take(bounded), declared, verifier))
    }
}

fn scan(bytes: &[u8]) -> Vec<SalvagedEntry> {
    let mut src = Cursor::new(bytes.to_vec());
    salvage_all(&mut SixthScan, &mut src, &Default::default())
        .expect("a sixth scanner must reach the engine through published API alone")
        .entries
}

#[test]
fn a_scanner_written_against_published_api_alone_reaches_every_status() {
    let good = b"the bytes that agree with their checksum";
    let bad = b"the bytes that DISAGREE with their checksum";

    // Intact: the checksum agrees.
    let entries = scan(&record(good, crc32(good)));
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].status,
        SalvageStatus::Intact,
        "`stream_verify` is what decides this, and it was unreachable from outside \
         `stuffr-formats` until F2"
    );

    // Partial: every declared byte is present and disagrees.
    let entries = scan(&record(bad, crc32(good)));
    assert_eq!(entries[0].status, SalvageStatus::Partial);

    // Partial again, for the other cause: the file is shorter than the
    // header declares. `available_len` carries that, and the engine bounds
    // the read with it before `verify` is ever called.
    let mut truncated = record(good, crc32(good));
    truncated.truncate(truncated.len() - 10);
    let entries = scan(&truncated);
    assert_eq!(
        entries[0].status,
        SalvageStatus::Partial,
        "the engine bounded the read with `available_len` before `verify` ran, so the \
         scanner never had to guess at how much of the payload survived"
    );
}

/// `write_payload` is on the trait now, with a refusal as its default. A
/// scanner that does not override it inherits that refusal rather than
/// failing to compile — the additive shape — and the refusal is a typed
/// `Unsupported`, never a panic and never exit 1.
#[test]
fn the_default_write_payload_refuses_rather_than_panicking() {
    let entry = SalvagedEntry::new(
        0,
        HEADER_LEN,
        0,
        EntryMeta::file("entry-at-0"),
        SalvageStatus::Intact,
    );
    let err = SixthScan
        .write_payload(
            std::path::Path::new("/nonexistent-sixth-scanner-probe"),
            &entry,
            0,
            &mut std::io::sink(),
        )
        .expect_err("the default implementation refuses");
    assert_eq!(err.exit_code(), 3, "a capability limit, never exit 1");
}

/// And an implementation that DOES override it is called through the trait
/// — which is how `entries::write_salvaged_payload` reaches all five
/// in-tree scanners since F2, so the seam this file pins is the one the ops
/// layer actually uses.
#[test]
fn an_overridden_write_payload_is_reached_through_the_trait() {
    struct Writable;
    impl SalvageScan for Writable {
        fn next_candidate(
            &mut self,
            _src: &mut dyn SeekRead,
            _from: u64,
        ) -> Result<Option<Candidate>> {
            Ok(None)
        }
        fn write_payload(
            &self,
            _archive_path: &std::path::Path,
            _entry: &SalvagedEntry,
            _compressed_len: u64,
            out: &mut dyn Write,
        ) -> Result<bool> {
            out.write_all(b"recovered")?;
            Ok(true)
        }
    }

    let entry = SalvagedEntry::new(0, 0, 0, EntryMeta::file("x"), SalvageStatus::Intact);
    let mut sink = Vec::new();
    let completed = Writable
        .write_payload(std::path::Path::new("unused"), &entry, 0, &mut sink)
        .unwrap();
    assert!(completed);
    assert_eq!(sink, b"recovered");
}
