//! Generates the fuzz harness's seed corpus (Phase 3a Task 4).
//!
//! Lives in the FACADE crate, not `stuffr-core`, per the task brief's Ruling
//! D: `stuffr-core` has zero format dependencies (a non-negotiable project
//! constraint), so it cannot build a real gzip stream or a real tar archive
//! — its conformance fixtures are mocks. Only `stuffr` has a populated
//! registry (`stuffr::registry()`, built from `stuffr_formats::register_all`),
//! so only here can seeds be REAL encoded/archived bytes rather than the
//! `MockCodec`/`MockContainer` doubles `stuffr-core::testing` provides for
//! its own unit tests.
//!
//! The corpus is written under `fuzz/corpus/`, which `fuzz/.gitignore`
//! already excludes (`/corpus`) — generated, never committed.
//!
//! Wire format is dictated entirely by the fuzz targets themselves
//! (`fuzz/fuzz_targets/{codec,container,chain}.rs`), not inferred from the
//! brief:
//! - `codec.rs` reads a leading selector byte, maps it through
//!   `CODEC_SLOTS[selector as usize % CODEC_SLOTS.len()]`, and feeds the
//!   REST of the bytes to that codec's decoder. So a codec seed is
//!   `[slot_index] ++ <that format's own encoded stream>`.
//! - `container.rs` reads a leading selector byte whose high bit (`0x80`)
//!   picks the ladder rung — set means a seekable `FileSource` (a real temp
//!   file), clear means a forward-only `ReaderSource` — and whose low seven
//!   bits index `CONTAINER_SLOTS`. So a container seed is
//!   `[rung_bit | slot_index] ++ <that format's own archive bytes>`.
//! - `chain.rs` takes no selector at all: the raw bytes are written to a
//!   temp file and handed straight to `ops::inspect` / `entries::list`, so a
//!   chain seed is just the bytes of some real, complete input (a plain
//!   archive, a bare codec stream, or a composed one).
//! - `roundtrip.rs` (Phase 3c Task 8) reads a leading selector byte whose
//!   HIGH BIT picks the TABLE rather than the ladder rung — set means
//!   `CODEC_SLOTS`, clear means `CONTAINER_SLOTS` — and whose remaining
//!   bytes are the archive's CONTENT, not its bytes. So a round-trip seed
//!   is `[table_bit | slot_index] ++ <arbitrary payload>`, and a seed needs
//!   no format knowledge at all: any bytes are a valid payload. The seeds
//!   below exist to put one live payload in front of every WRITABLE slot,
//!   so the fuzzer's first mutations start from a shape that already
//!   completes a round trip rather than from nothing.
//! - `salvage.rs` (Salvage Stage 1, converted to a selector byte in Stage 2
//!   Task 3b) reads a leading selector byte, maps it through
//!   `SALVAGE_SLOTS[selector as usize % SALVAGE_SLOTS.len()]`, and hands the
//!   REST of the bytes — written to a temp file — to that slot's scanner
//!   via `SalvageOpts::format`. So a salvage seed is
//!   `[slot_index] ++ <that format's own archive bytes>`, the same shape a
//!   codec seed takes. See [`SALVAGE_SHAPES`] for what each shape is, and
//!   for the two measurements behind them — the one that made seeding this
//!   target necessary at all (Stage 1) and the one that put ZOO seeds in it
//!   (Stage 2 Task 4). **Three slots are seeded**: a `zoo-*` shape carries
//!   `SALVAGE_SLOTS`'s `zoo` index, an `lha-*` shape its `lha` index, and
//!   every other shape its `zip` index — looked up, never a literal `0`, so
//!   appending a slot cannot silently re-point an existing seed.
//!
//! Phase 3b added three READ-ONLY slots (`lha`, `arj` and, at the time,
//! `compress`) and Phase 3c a fourth container (`arc`), none of which this
//! generator could build the way every other slot's seed is built — there
//! was no encoder/writer to call. Their "own encoded stream" / "own archive
//! bytes" above are instead read straight from the committed fixtures under
//! `crates/stuffr-formats/fixtures/legacy/` (see [`legacy_codec_fixture`] and
//! [`legacy_container_fixture`]); everything downstream of that — the
//! selector prefix, the forward/seekable duplication for containers, the
//! exact-count assertion — treats them exactly like any other registered
//! slot.
//!
//! **`compress` (Task 5), `lha` (Task 6) and `arj` (Task 7) have real
//! encoders now** and could each build their own seed the way every other
//! slot below does. [`legacy_codec_fixture`]/[`legacy_container_fixture`]
//! keep routing `compress` and `arj` through their committed fixtures
//! anyway, deliberately and for the same reason in both cases: a seed built
//! by this project's own encoder is a seed the fuzzer explores outward from
//! a shape that encoder already believes in. `hello.Z` is
//! `/usr/bin/compress`'s output, so it is an EXTERNAL encoder's; and while
//! `sample.arj` is hand-built rather than external (no `arj` tool is
//! obtainable — see `legacy::arj`'s module doc), it is at least not the
//! encoder's own output. `lha` stays on `sample.lzh` for the strongest
//! version of the same reason — `lhasa`, an implementation outside this
//! project, verified it — and `arc`/`zoo` have no writer to leave it for.

use std::io::Read;
use std::path::{Path, PathBuf};

use stuffr::entries;
use stuffr::ops::{self, CompressOpts, Input, Output};
use stuffr_core::FormatId;
use stuffr_core::testing::{CODEC_SLOTS, CONTAINER_SLOTS, SALVAGE_SLOTS};

/// The chain target's seeds carry no selector byte, so there is no slot
/// table to derive an expected count from the way `codec`/`container` do.
/// This constant IS the generator's manifest of shapes: `generate_corpus`
/// matches on it exhaustively (an unhandled entry panics naming itself,
/// rather than being silently skipped), and the corpus test below asserts
/// against its `len()`, not a hand-copied number — so the two cannot drift
/// apart the way a duplicated literal could.
const CHAIN_SHAPES: &[&str] = &["plain-tar", "gzip-stream", "tar-gz-composed"];

/// The `salvage` target's seeds, same discipline as [`CHAIN_SHAPES`]: this
/// constant IS the manifest and `generate_corpus` matches on it
/// exhaustively. Unlike `CHAIN_SHAPES`, a salvage seed DOES carry a leading
/// selector byte as of Stage 2 Task 3b (see the module doc's own bullet on
/// `salvage.rs`), and as of Stage 2 Task 4 they do NOT all select the same
/// slot: a shape named `zoo-*` carries `SALVAGE_SLOTS`'s `zoo` index, one
/// named `lha-*` its `lha` index (Stage 2 Task 5), and every other shape
/// carries its `zip` index.
///
/// **`arc` still has no seed and `zoo` now does, and that asymmetry is a
/// MEASUREMENT rather than an oversight.** Task 4 measured what earlier
/// revisions of this comment said had not been measured either way, by
/// running the built binary's `salvage --format <slot> --list` over all
/// 4,726 inputs a 200,000-run `salvage` session accumulated, split by the
/// slot each one's own selector byte chooses:
///
/// ```text
/// slot   inputs   >=1 salvaged row   >=1 Intact row
/// zip      3171               2677              593
/// arc       679                529               52
/// zoo       876                  0                0
/// ```
///
/// `arc` reaches its scanner unseeded because its anchor is two bytes (a
/// marker plus a method drawn from eleven values, a coincidence roughly
/// every 8 KiB), so mutation from zip seeds finds ARC headers by accident.
/// ZOO's is a FOUR-byte tag behind a full record gate, and 876 inputs
/// produced **not one salvaged record of any status** — the identical
/// vacuity this constant's own history section below describes, reproduced
/// for one slot inside an otherwise well-seeded target. `check_salvage_claim`
/// fires only on `Intact`, so the `zoo` slot's share of every run was
/// proving nothing at all.
///
/// **This target ran unseeded until the final whole-branch review**, and
/// `make fuzz` reported `target 'salvage': 2000 executions — OK` the whole
/// time, truthfully and while proving nothing. Measured harder: 100,000
/// runs plateaued at `cov: 217`, and running the binary's `salvage --list`
/// over all 64 accumulated corpus inputs produced **not one salvaged
/// record** — not an `Intact`, `Complete`, `Partial` or `Unverified` row
/// anywhere. The target's only oracle call, `check_salvage_claim`, fires
/// only on `SalvageStatus::Intact`, which needs a CRC-32 that matches its
/// payload; random mutation from an EMPTY corpus will not produce one, so
/// the assertion was unreachable by construction rather than merely
/// unlucky. This is Phase 3a's "ran clean, never completed an iteration"
/// in a subtler form: the iterations completed, they just never reached
/// the check.
///
/// The shapes are chosen so mutation starts from something that already
/// reaches `Intact` and can degrade away from it in each of the directions
/// the status tiers exist to describe:
///
/// - `healthy` — three Stored entries, every CRC correct. The baseline the
///   oracle actually fires on.
/// - `distinct-duplicates` / `identical-duplicates` — eight records under
///   six names, differing and byte-identical respectively. The two
///   annotation paths (`collides_with`, `shadows`) and the write side's
///   disambiguation.
/// - `zeroed-central-directory` — the raw scan alone, with no index to
///   reconcile against.
/// - `truncated-tail` — cut mid-payload of the last entry: the
///   `available_len` path and `Partial(Truncated)`.
/// - `crc-mismatch` — one payload byte flipped, sizes and index intact:
///   `Partial(ChecksumMismatch)`, the one shape where the checksum is what
///   fails rather than the structure.
///
/// The two ZOO shapes are BORROWED BYTES rather than built ones, since this
/// project has no ZOO encoder at all, and both reach `Intact` — which is
/// what `every_salvage_seed_produces_records_and_at_least_one_intact`
/// requires of every shape, damaged or not: a seed is something the fuzzer
/// degrades FROM, not something already past the check.
///
/// - `zoo-healthy` — `store.zoo` verbatim, the one borrowed fixture whose
///   payload IS its content.
/// - `zoo-zeroed-chain` — the same archive with its first record's `next`
///   link zeroed. Four bytes, and `stuffr list` refuses the whole 11 KiB
///   archive at exit 5 while the scanner still recovers the entry `Intact`:
///   the motivating shape for the whole ZOO scanner, and a seed whose
///   structure is already damaged where its record is not.
///
/// The two LHA shapes (Stage 2 Task 5) are seeded for the reason ZOO's
/// were, applied BEFORE the measurement rather than after it. LHA's anchor
/// is a FIVE-byte ASCII method identifier behind a header-checksum gate —
/// about one coincidence per 93 GiB of random bytes, against ZOO's one per
/// 4 GiB and ARC's one per 8 KiB — so mutation from zip seeds cannot
/// plausibly reach an LHA header at all, and an unseeded `lha` slot would
/// spend its whole share of every run the way the `zoo` slot measurably
/// spent its 876 inputs: producing not one salvaged record. Both shapes are
/// `sample.lzh`, which `lhasa` verified and no encoder here produced.
///
/// - `lha-healthy` — `sample.lzh` verbatim, two `-lh0-` entries, both
///   `Intact`.
/// - `lha-destroyed-first-header` — the same archive with the first
///   header's LENGTH and CHECKSUM bytes wiped. Two bytes, and the ordinary
///   reader can no longer reach any entry at all (LHA has no index: entry 2
///   is reachable only by having parsed entry 1), while the scanner still
///   recovers the second entry `Intact`. The motivating shape for the whole
///   LHA scanner.
const SALVAGE_SHAPES: &[&str] = &[
    "healthy",
    "distinct-duplicates",
    "identical-duplicates",
    "zeroed-central-directory",
    "truncated-tail",
    "crc-mismatch",
    "zoo-healthy",
    "zoo-zeroed-chain",
    "lha-healthy",
    "lha-destroyed-first-header",
];

/// Builds one small sample tree every container/chain seed packs: a file at
/// the top level and a nested one in a subdirectory, so a packed archive
/// always has more than one trivial entry to walk.
fn write_sample_tree(dir: &Path) -> std::io::Result<PathBuf> {
    let root = dir.join("sample");
    std::fs::create_dir_all(root.join("subdir"))?;
    std::fs::write(
        root.join("hello.txt"),
        b"stuffr fuzz corpus seed content\n".repeat(8),
    )?;
    std::fs::write(root.join("subdir").join("nested.txt"), b"nested seed\n")?;
    Ok(root)
}

fn read_all(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut f = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Strips the leading `SALVAGE_SLOTS` selector byte a generated `salvage/`
/// seed carries as of Stage 2 Task 3b, and writes the remaining archive
/// bytes to a fresh file under `scratch` — the same split
/// `salvage.rs`'s own `data.split_first()` performs before `entries::salvage`
/// ever sees a byte, so a direct-read test over these seeds exercises the
/// identical archive the fuzz target itself would scan.
fn salvage_payload_path(seed_path: &Path, scratch: &Path) -> PathBuf {
    let bytes = read_all(seed_path).expect("read salvage seed");
    let payload = bytes
        .split_first()
        .expect("salvage seed must carry a selector byte")
        .1;
    let out = scratch.join(
        seed_path
            .file_name()
            .expect("salvage seed path must have a file name"),
    );
    std::fs::write(&out, payload).expect("write stripped salvage payload");
    out
}

/// `CODEC_SLOTS` entries this build's registry actually has an encoder for,
/// paired with their slot index — the same "registered, not just listed"
/// filter `crates/stuffr/tests/facade.rs`'s
/// `every_selector_slot_names_a_registered_format` applies, because a slot
/// this build did not register (one tier vs. the other) must be skipped
/// here exactly as `codec.rs` itself skips it at fuzz time.
fn registered_codec_slots() -> Vec<(u8, &'static str)> {
    CODEC_SLOTS
        .iter()
        .enumerate()
        .filter(|(_, name)| stuffr::registry().codec(FormatId::new(name)).is_some())
        .map(|(i, name)| (i as u8, *name))
        .collect()
}

/// Same as [`registered_codec_slots`], for `CONTAINER_SLOTS`.
fn registered_container_slots() -> Vec<(u8, &'static str)> {
    CONTAINER_SLOTS
        .iter()
        .enumerate()
        .filter(|(_, name)| stuffr::registry().container(FormatId::new(name)).is_some())
        .map(|(i, name)| (i as u8, *name))
        .collect()
}

/// `compress`'s seed is the committed `hello.Z` fixture's bytes — deliberately
/// still, even though Phase 3c Task 5 gave it a real encoder `ops::compress`
/// could now call: `hello.Z` is `/usr/bin/compress`'s own output, an external
/// encoder's bytes, which the corpus keeps rather than trading for a seed
/// this project's own encoder produced (see this file's module doc). `None`
/// for every non-legacy slot, which builds its own seed by encoding.
fn legacy_codec_fixture(name: &str) -> Option<&'static str> {
    match name {
        "compress" => Some("hello.Z"),
        _ => None,
    }
}

/// Same idea as [`legacy_codec_fixture`], for the four legacy containers
/// whose seed comes from a committed fixture: `lha`, `arj`, `arc` and
/// `zoo`.
///
/// `arc` and `zoo` are here because they have no writer at all. `lha` and
/// `arj` gained one in Phase 3c Tasks 6 and 7 and stay here anyway, so that
/// the corpus keeps a seed neither format's own encoder produced —
/// `sample.lzh` was verified by `lhasa` and `sample.arj` is hand-built from
/// the published header tables. Neither fixture may be regenerated with the
/// encoder that now exists; `fixtures/legacy/MANIFEST.md` says so for both.
///
/// `arc`'s seed is `cpm.arc` rather than any of the nine other borrowed
/// archives, for the same reason it is the conformance fixture: two entries
/// and two different compression methods, so a mutation has more than one
/// header and more than one decoder to land in.
///
/// `zoo`'s is `high_per.zoo`, and the choice is the opposite trade made for
/// the same reason: all four ZOO fixtures hold one entry, so none offers a
/// second header, and what varies between them is the decoder behind that
/// entry. `high_per.zoo` is the LH5 one — the only ZOO method whose decoder
/// is a dependency rather than this module's own code, and therefore the
/// one whose failure modes nothing in this repository can reason about
/// from source. `store.zoo` would exercise no decoder at all.
fn legacy_container_fixture(name: &str) -> Option<&'static str> {
    match name {
        "lha" => Some("sample.lzh"),
        "arj" => Some("sample.arj"),
        "arc" => Some("arc/cpm.arc"),
        "zoo" => Some("zoo/high_per.zoo"),
        _ => None,
    }
}

/// Path to a committed fixture under `crates/stuffr-formats/fixtures/legacy/`.
/// `CARGO_MANIFEST_DIR` for this crate is `crates/stuffr`, so the fixtures
/// directory is a sibling crate's, not this one's own.
fn legacy_fixture_path(filename: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../stuffr-formats/fixtures/legacy")
        .join(filename)
}

/// Counts of seeds `generate_corpus` actually wrote, one field per fuzz
/// target directory — returned so callers can assert an EXACT expected
/// count (a generator that silently drops one slot must fail loudly, not
/// merely satisfy `n > 0`).
#[derive(Debug)]
pub struct CorpusCounts {
    pub codec: usize,
    pub container: usize,
    pub chain: usize,
    pub roundtrip: usize,
    pub salvage: usize,
}

// ---------------------------------------------------------------------
// The `salvage` target's seeds: hand-built Stored zips.
//
// Hand-built rather than written through `entries::create_archive`,
// because every shape below needs something this project's own writer
// will not produce: two records under one name, a zeroed index, a payload
// that disagrees with its own checksum. Stored (method 0) throughout, so
// a local header's declared compressed size IS the whole payload and
// every offset is arithmetic rather than something a deflate encoder
// decides — the same reasoning `zip.rs`'s own fixture builder records.
// ---------------------------------------------------------------------

/// CRC-32/ISO-HDLC, the checksum a zip header carries over an entry's
/// uncompressed bytes. Written here for the same reason `zip_salvage.rs`
/// and `legacy/arj.rs` each carry their own copy: a dependency for one
/// twelve-line routine buys no capability. Pinned against the algorithm's
/// published check value by `the_corpus_builders_crc_matches_the_published_
/// check_value` below.
fn seed_crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// One Stored local file header plus its payload, and where it was written.
struct SeedRecord {
    offset: u32,
    name: String,
    crc: u32,
    len: u32,
    bytes: Vec<u8>,
}

fn seed_local_record(offset: u32, name: &str, payload: &[u8]) -> SeedRecord {
    let crc = seed_crc32(payload);
    let len = u32::try_from(payload.len()).unwrap();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"PK\x03\x04");
    bytes.extend_from_slice(&20u16.to_le_bytes()); // version needed
    bytes.extend_from_slice(&0u16.to_le_bytes()); // flags
    bytes.extend_from_slice(&0u16.to_le_bytes()); // method: Stored
    bytes.extend_from_slice(&0u16.to_le_bytes()); // mod time
    bytes.extend_from_slice(&0x21u16.to_le_bytes()); // mod date
    bytes.extend_from_slice(&crc.to_le_bytes());
    bytes.extend_from_slice(&len.to_le_bytes()); // compressed size
    bytes.extend_from_slice(&len.to_le_bytes()); // uncompressed size
    bytes.extend_from_slice(&u16::try_from(name.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes()); // extra length
    bytes.extend_from_slice(name.as_bytes());
    bytes.extend_from_slice(payload);
    SeedRecord {
        offset,
        name: name.to_string(),
        crc,
        len,
        bytes,
    }
}

fn seed_central_record(r: &SeedRecord) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"PK\x01\x02");
    bytes.extend_from_slice(&20u16.to_le_bytes()); // version made by
    bytes.extend_from_slice(&20u16.to_le_bytes()); // version needed
    bytes.extend_from_slice(&0u16.to_le_bytes()); // flags
    bytes.extend_from_slice(&0u16.to_le_bytes()); // method: Stored
    bytes.extend_from_slice(&0u16.to_le_bytes()); // mod time
    bytes.extend_from_slice(&0x21u16.to_le_bytes()); // mod date
    bytes.extend_from_slice(&r.crc.to_le_bytes());
    bytes.extend_from_slice(&r.len.to_le_bytes());
    bytes.extend_from_slice(&r.len.to_le_bytes());
    bytes.extend_from_slice(&u16::try_from(r.name.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes()); // extra length
    bytes.extend_from_slice(&0u16.to_le_bytes()); // comment length
    bytes.extend_from_slice(&0u16.to_le_bytes()); // disk number start
    bytes.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
    bytes.extend_from_slice(&0u32.to_le_bytes()); // external attrs
    bytes.extend_from_slice(&r.offset.to_le_bytes());
    bytes.extend_from_slice(r.name.as_bytes());
    bytes
}

/// Assembles an archive from `(name, payload)` pairs, in file order, with a
/// central directory declaring every one of them. A repeated name is
/// perfectly legal here and is the whole point of two of the shapes.
fn build_seed_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut recs = Vec::new();
    for (name, payload) in entries {
        let r = seed_local_record(u32::try_from(out.len()).unwrap(), name, payload);
        out.extend_from_slice(&r.bytes);
        recs.push(r);
    }
    let cd_start = u32::try_from(out.len()).unwrap();
    for r in &recs {
        out.extend_from_slice(&seed_central_record(r));
    }
    let cd_size = u32::try_from(out.len()).unwrap() - cd_start;
    let total = u16::try_from(recs.len()).unwrap();
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes()); // disk number
    out.extend_from_slice(&0u16.to_le_bytes()); // disk with cd start
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_start.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment length
    out
}

/// The three-entry archive every salvage seed is derived from. Payloads
/// differ in length and content so no two records' headers are
/// interchangeable, and none is empty (a zero-length entry's checksum is a
/// fixed constant and proves nothing — see `stuffr_core::salvage`'s own
/// degenerate-case note).
fn healthy_salvage_seed() -> Vec<u8> {
    build_seed_zip(&[
        ("alpha.txt", b"alpha payload for the salvage fuzz corpus"),
        ("beta.txt", b"beta payload, a different length entirely"),
        (
            "gamma.bin",
            b"gamma payload, deliberately the longest of the three so a cut inside it has room",
        ),
    ])
}

/// Byte offset at which the LAST local record's payload begins, derived
/// from that record's own header rather than from arithmetic over the
/// builder's constants — so changing a name or a payload above cannot
/// silently move a truncation point out of the payload it is meant to land
/// inside.
fn last_payload_span(bytes: &[u8]) -> (usize, usize) {
    let at = (0..bytes.len().saturating_sub(4))
        .rev()
        .find(|&i| bytes[i..i + 4] == *b"PK\x03\x04")
        .expect("a seed archive holds at least one local header");
    let declared = u32::from_le_bytes([
        bytes[at + 18],
        bytes[at + 19],
        bytes[at + 20],
        bytes[at + 21],
    ]) as usize;
    let name_len = u16::from_le_bytes([bytes[at + 26], bytes[at + 27]]) as usize;
    let extra_len = u16::from_le_bytes([bytes[at + 28], bytes[at + 29]]) as usize;
    (at + 30 + name_len + extra_len, declared)
}

/// Overwrites the central directory's bytes with zeros, leaving the EOCD
/// and every local record intact — the shape that forces `salvage_zip` onto
/// its raw local-header scan with no index to reconcile against.
fn zero_the_central_directory(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    let eocd = out.len() - 22;
    let cd_start = u32::from_le_bytes([
        out[eocd + 16],
        out[eocd + 17],
        out[eocd + 18],
        out[eocd + 19],
    ]) as usize;
    for b in &mut out[cd_start..eocd] {
        *b = 0;
    }
    out
}

/// The payload every `roundtrip` seed carries after its selector byte.
///
/// Deliberately compressible and deliberately not a round number of bytes:
/// a payload that is all one value would let a codec whose output length
/// happens to match hide a content bug behind an equal length, and a length
/// on a power-of-two boundary is the one length every block-oriented
/// encoder is already tested at.
const ROUNDTRIP_PAYLOAD: &[u8] = b"stuffr round-trip fuzz seed \x00\x01\x02\xfe\xff payload; \
repetition repetition repetition repetition repetition.";

/// `CODEC_SLOTS` entries this build registers **with an encoder**, and
/// `CONTAINER_SLOTS` entries it registers **with a writer** — the filter
/// `roundtrip.rs` itself applies before doing anything, mirrored here so the
/// corpus does not carry a seed for a slot the target returns from
/// immediately. `arc` and `zoo` have no writer and never will, so they are
/// absent from the round-trip corpus while being present in `container`'s.
fn writable_codec_slots() -> Vec<(u8, &'static str)> {
    CODEC_SLOTS
        .iter()
        .enumerate()
        .filter(|(_, name)| {
            stuffr::registry()
                .codec(FormatId::new(name))
                .is_some_and(|c| c.caps().encode)
        })
        .map(|(i, name)| (i as u8, *name))
        .collect()
}

/// Same as [`writable_codec_slots`], for `CONTAINER_SLOTS`.
fn writable_container_slots() -> Vec<(u8, &'static str)> {
    CONTAINER_SLOTS
        .iter()
        .enumerate()
        .filter(|(_, name)| {
            stuffr::registry()
                .container(FormatId::new(name))
                .is_some_and(|c| c.caps().write)
        })
        .map(|(i, name)| (i as u8, *name))
        .collect()
}

/// Writes one seed corpus per fuzz target under `root/{codec,container,chain}`.
pub fn generate_corpus(root: &Path) -> stuffr_core::Result<CorpusCounts> {
    let codec_dir = root.join("codec");
    let container_dir = root.join("container");
    let chain_dir = root.join("chain");
    let roundtrip_dir = root.join("roundtrip");
    let salvage_dir = root.join("salvage");
    std::fs::create_dir_all(&codec_dir)?;
    std::fs::create_dir_all(&container_dir)?;
    std::fs::create_dir_all(&chain_dir)?;
    std::fs::create_dir_all(&roundtrip_dir)?;
    std::fs::create_dir_all(&salvage_dir)?;

    // Scratch area for building each seed before its bytes are read back and
    // (re-)written with a selector prefix under the real target directories.
    // Never itself part of the corpus.
    let work = tempfile::tempdir()?;
    let sample_dir = write_sample_tree(work.path())?;
    let sample_file = sample_dir.join("hello.txt");

    // --- codec/ -------------------------------------------------------
    // One encoded stream per registered `CODEC_SLOTS` entry, prefixed with
    // its slot index — exactly what `codec.rs`'s
    // `CODEC_SLOTS[selector as usize % CODEC_SLOTS.len()]` expects.
    //
    // `allow_weak_encoder: true` is needed unconditionally here: on the
    // default (pure) tier, zstd's encoder is declared weak
    // (`CodecCaps::weak_encoder`, write only under `--allow-weak-encoder`),
    // and `ops::compress` refuses a weak encoder outright without explicit
    // consent — without this, zstd's seed would silently never be written
    // rather than emit one, on exactly the tier where it matters most.
    let mut codec_count = 0usize;
    for (selector, name) in registered_codec_slots() {
        let mut seed = vec![selector];
        if let Some(fixture) = legacy_codec_fixture(name) {
            // A legacy slot named here routes through its committed
            // fixture's own bytes as the seed body — see
            // `legacy_codec_fixture`'s doc for why `compress` still does
            // this deliberately, now that it has an encoder.
            seed.extend(read_all(&legacy_fixture_path(fixture))?);
        } else {
            let out_path = work.path().join(format!("codec-{name}.out"));
            let o = CompressOpts {
                format: Some(FormatId::new(name)),
                allow_weak_encoder: true,
                sync: false,
                ..Default::default()
            };
            ops::compress(
                Input::Path(sample_file.clone()),
                Output::Path(out_path.clone()),
                &o,
            )?;
            seed.extend(read_all(&out_path)?);
        }
        std::fs::write(codec_dir.join(format!("{name}.seed")), &seed)?;
        codec_count += 1;
    }

    // --- container/ ----------------------------------------------------
    // One archive per registered `CONTAINER_SLOTS` entry, emitted TWICE:
    // once with selector `i` (the high bit clear, `container.rs` opens it
    // as a forward-only `ReaderSource`) and once with `i | 0x80` (a
    // seekable `FileSource` over a real temp file).
    //
    // The seekable half is load-bearing, not a redundant variant: zip's
    // declared entry count is reachable ONLY through the path that reads
    // the central directory (`declared_zip_index` in `container.rs`), so
    // without high-bit-set seeds, `check_entry_count` and
    // `check_fidelity_claim` would never be reached from the corpus at
    // all — undoing exactly the reachability Task 3's fix round was about.
    let mut container_count = 0usize;
    for (selector, name) in registered_container_slots() {
        let bytes = if let Some(fixture) = legacy_container_fixture(name) {
            // The committed fixture's own bytes ARE the archive — because
            // the container has no writer (`arc`, `zoo`) or because a seed
            // this project's own encoder produced would be worth less than
            // one it did not (`lha`, `arj`). See
            // `legacy_container_fixture`'s own doc.
            read_all(&legacy_fixture_path(fixture))?
        } else {
            let out_path = work.path().join(format!("container-{name}.out"));
            entries::create_archive(
                std::slice::from_ref(&sample_dir),
                Output::Path(out_path.clone()),
                FormatId::new(name),
                None,
                &CompressOpts {
                    sync: false,
                    ..Default::default()
                },
            )?;
            read_all(&out_path)?
        };

        // Both variants below apply to every container, including the two
        // legacy ones, the same as the writable containers — but what the
        // "forward" (high bit clear) variant actually EXERCISES differs for
        // them:
        // - `arj` declares `needs_seek: true`, so `resolve()` cannot honour
        //   a forward-only request over it at all — its "forward" seed
        //   still spools to a real seekable temp file (`Rung::Spilled`),
        //   exercising the ladder's spool path rather than a genuine
        //   forward parse.
        // - `lha` declares `needs_seek: false` and parses forward natively,
        //   so its "forward" seed is a real forward-only parse, same as
        //   `tar`/`ar`/`cpio`.
        for (tag, sel) in [("forward", selector), ("seekable", selector | 0x80)] {
            let mut seed = vec![sel];
            seed.extend_from_slice(&bytes);
            std::fs::write(container_dir.join(format!("{name}-{tag}.seed")), &seed)?;
            container_count += 1;
        }
    }

    // --- chain/ ----------------------------------------------------------
    // No selector byte — `chain.rs` has none, and hands the raw bytes
    // straight to format detection. Three shapes, matching `CHAIN_SHAPES`:
    // a plain container, a bare codec stream, and a composed
    // container-over-codec (a `.tar.gz`) — the last is deliberate, since a
    // composed chain is exactly where Phase 2c's silent wrong-format bug
    // lived and what `resolve_chain_deep` exists to get right.
    //
    // Deliberately well-formed only. `chain.rs` currently reaches a real,
    // unfixed bug — a truncated zlib stream reaching `entries::list` exits 1
    // ("stuffr failed") instead of 5 ("corrupt") — that a later task owns.
    // Seeding a truncated or otherwise corrupt stream here, "for coverage",
    // would make every future CI run of this target abort on iteration 1
    // over a finding already known: the fuzzer's OWN mutations are what
    // should produce that input, not a checked-in seed.
    let mut chain_count = 0usize;
    for shape in CHAIN_SHAPES {
        let out_path = work.path().join(format!("chain-{shape}.out"));
        match *shape {
            "plain-tar" => {
                entries::create_archive(
                    std::slice::from_ref(&sample_dir),
                    Output::Path(out_path.clone()),
                    FormatId::new("tar"),
                    None,
                    &CompressOpts {
                        sync: false,
                        ..Default::default()
                    },
                )?;
            }
            "gzip-stream" => {
                ops::compress(
                    Input::Path(sample_file.clone()),
                    Output::Path(out_path.clone()),
                    &CompressOpts {
                        format: Some(FormatId::new("gzip")),
                        sync: false,
                        ..Default::default()
                    },
                )?;
            }
            "tar-gz-composed" => {
                entries::create_archive(
                    std::slice::from_ref(&sample_dir),
                    Output::Path(out_path.clone()),
                    FormatId::new("tar"),
                    Some(FormatId::new("gzip")),
                    &CompressOpts {
                        sync: false,
                        ..Default::default()
                    },
                )?;
            }
            other => unreachable!("CHAIN_SHAPES lists an unhandled shape {other:?}"),
        }
        let bytes = read_all(&out_path)?;
        std::fs::write(chain_dir.join(format!("{shape}.seed")), &bytes)?;
        chain_count += 1;
    }

    // --- roundtrip/ ------------------------------------------------------
    // One seed per WRITABLE slot: the selector byte, then a payload. Unlike
    // every block above, nothing here has to build a valid stream of the
    // named format — the target does that itself, which is the whole point
    // of it. The seed's only job is to name a slot and hand it something to
    // write, so the fuzzer's first mutations start from an input that
    // already completes a round trip rather than from a selector with no
    // body at all.
    //
    // The high bit is the TABLE bit here, not the rung bit `container`'s
    // seeds carry: set selects `CODEC_SLOTS`, clear selects
    // `CONTAINER_SLOTS`. See `roundtrip.rs`'s own comment for why the write
    // side has no rung to choose.
    let mut roundtrip_count = 0usize;
    for (selector, name) in writable_container_slots() {
        let mut seed = vec![selector];
        seed.extend_from_slice(ROUNDTRIP_PAYLOAD);
        std::fs::write(roundtrip_dir.join(format!("container-{name}.seed")), &seed)?;
        roundtrip_count += 1;
    }
    for (selector, name) in writable_codec_slots() {
        let mut seed = vec![selector | 0x80];
        seed.extend_from_slice(ROUNDTRIP_PAYLOAD);
        std::fs::write(roundtrip_dir.join(format!("codec-{name}.seed")), &seed)?;
        roundtrip_count += 1;
    }

    // --- salvage/ --------------------------------------------------------
    // Leading selector byte as of Stage 2 Task 3b — `salvage.rs` reads it,
    // maps it through `SALVAGE_SLOTS`, and hands the REST of the bytes to a
    // temp file for that slot's scanner via `SalvageOpts::format`. The
    // shapes are `SALVAGE_SHAPES`; see that constant for why this target is
    // seeded at all and what each shape is for. A shape named `zoo-*`
    // carries `SALVAGE_SLOTS`'s `zoo` index and every other shape its `zip`
    // index — see `SALVAGE_SHAPES`'s own doc for the measurement that put
    // ZOO seeds here and left `arc` without one.
    //
    // Unlike `chain/`'s deliberately well-formed-only seeds, most of these
    // are DAMAGED on purpose, and that is not the same trade. The rule
    // `chain/` follows is "do not seed a known-unfixed finding", not "do not
    // seed damage": salvage's whole input domain is damaged archives, its
    // every status tier below `Intact` describes a kind of damage, and no
    // shape below reaches a known-unfixed defect — each is an outcome the
    // suite already pins end to end.
    let healthy = healthy_salvage_seed();
    let mut salvage_count = 0usize;
    let salvage_selector = |slot: &str| {
        SALVAGE_SLOTS
            .iter()
            .position(|&s| s == slot)
            .unwrap_or_else(|| panic!("SALVAGE_SLOTS must list {slot}")) as u8
    };
    for shape in SALVAGE_SHAPES {
        let bytes = match *shape {
            "healthy" => healthy.clone(),
            // Eight records, six names, duplicates carrying DIFFERENT bytes
            // — reaches `collides_with` and the write side's disambiguation.
            "distinct-duplicates" => build_seed_zip(&[
                ("one.txt", b"payload one"),
                ("dup.txt", b"the first record under this name"),
                ("two.txt", b"payload two"),
                ("dup.txt", b"a SECOND record, different bytes!"),
                ("three.txt", b"payload three"),
                ("five.txt", b"the first five"),
                ("six.txt", b"payload six"),
                ("five.txt", b"a different five"),
            ]),
            // The same shape with byte-identical duplicates — reaches
            // `shadows` and the skip path instead.
            "identical-duplicates" => build_seed_zip(&[
                ("one.txt", b"payload one"),
                ("dup.txt", b"the first record under this name"),
                ("two.txt", b"payload two"),
                ("dup.txt", b"the first record under this name"),
                ("three.txt", b"payload three"),
            ]),
            "zeroed-central-directory" => zero_the_central_directory(&healthy),
            // Cut partway through the LAST entry's payload, taking the
            // central directory with it — `available_len` and
            // `Partial(Truncated)`.
            "truncated-tail" => {
                let (start, declared) = last_payload_span(&healthy);
                healthy[..start + declared / 2].to_vec()
            }
            // One payload byte flipped, every size and the whole index left
            // alone — the one shape where the CHECKSUM is what fails, so
            // `Partial(ChecksumMismatch)` rather than a structural verdict.
            "crc-mismatch" => {
                let mut bytes = healthy.clone();
                let at = 30 + "alpha.txt".len() + 4;
                bytes[at] ^= 0xFF;
                bytes
            }
            // Borrowed bytes: this project has no ZOO encoder, and a
            // decades-old archive nothing here produced is stronger seed
            // material than one this crate could have written anyway.
            "zoo-healthy" => read_all(&legacy_fixture_path("zoo/store.zoo"))?,
            // Four bytes: the first record's `next` link zeroed, which turns
            // that record into a terminator and makes `stuffr list` refuse
            // the whole archive — while the raw record, and its payload, are
            // untouched.
            "zoo-zeroed-chain" => {
                let mut bytes = read_all(&legacy_fixture_path("zoo/store.zoo"))?;
                // `zoo.h`: ZSTART_I 24 in the archive header, NEXT_I 6 in a
                // directory record.
                let record =
                    u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]) as usize;
                for b in &mut bytes[record + 6..record + 10] {
                    *b = 0;
                }
                bytes
            }
            // Borrowed-in-spirit bytes: `sample.lzh` is hand-built from the
            // level-1 layout and independently verified by `lhasa`, an
            // implementation sharing no code with `delharc` — so it is not
            // this project's own encoder's output either.
            "lha-healthy" => read_all(&legacy_fixture_path("sample.lzh"))?,
            // Two bytes: the first header's length and checksum. LHA has no
            // index, so a reader that cannot parse header 1 never reaches
            // entry 2 — while entry 2's own header, payload and CRC-16 are
            // untouched.
            "lha-destroyed-first-header" => {
                let mut bytes = read_all(&legacy_fixture_path("sample.lzh"))?;
                bytes[0] = 0xFF;
                bytes[1] = 0xFF;
                bytes
            }
            other => unreachable!("SALVAGE_SHAPES lists an unhandled shape {other:?}"),
        };
        let slot = if shape.starts_with("zoo-") {
            "zoo"
        } else if shape.starts_with("lha-") {
            "lha"
        } else {
            "zip"
        };
        let mut seed = vec![salvage_selector(slot)];
        seed.extend_from_slice(&bytes);
        std::fs::write(salvage_dir.join(format!("{shape}.seed")), &seed)?;
        salvage_count += 1;
    }

    Ok(CorpusCounts {
        codec: codec_count,
        container: container_count,
        chain: chain_count,
        roundtrip: roundtrip_count,
        salvage: salvage_count,
    })
}

/// The generator must produce EXACTLY one seed per registered slot (two for
/// containers, per the forward/seekable duplication above), not merely a
/// non-empty directory. `n > 0` is satisfied by a generator that emits one
/// garbage seed and calls it done — this project's signature defect,
/// wearing a new hat — so the expected counts here are derived from the same
/// registry lookups `generate_corpus` itself uses, and a mismatch on any one
/// target names that target and both numbers.
#[test]
fn the_generated_corpus_has_exactly_one_seed_per_registered_slot() {
    let dir = tempfile::tempdir().unwrap();
    let counts = generate_corpus(dir.path()).unwrap();

    let expected_codec = registered_codec_slots().len();
    let expected_container = registered_container_slots().len() * 2;
    let expected_chain = CHAIN_SHAPES.len();
    let expected_roundtrip = writable_codec_slots().len() + writable_container_slots().len();
    let expected_salvage = SALVAGE_SHAPES.len();

    for (target, got, expected) in [
        ("codec", counts.codec, expected_codec),
        ("container", counts.container, expected_container),
        ("chain", counts.chain, expected_chain),
        ("roundtrip", counts.roundtrip, expected_roundtrip),
        ("salvage", counts.salvage, expected_salvage),
    ] {
        assert!(
            expected > 0,
            "target {target}'s own expected count is 0 — the derivation itself is vacuous, \
             which would make the assertion below pass on an empty corpus"
        );
        assert_eq!(
            got, expected,
            "target {target} generated {got} seed(s) but this build registers {expected} \
             slot(s) worth of seeds for it — a mismatch means the corpus is silently \
             incomplete"
        );

        let on_disk = std::fs::read_dir(dir.path().join(target)).unwrap().count();
        assert_eq!(
            on_disk, expected,
            "target {target}: {on_disk} file(s) on disk disagree with generate_corpus's own \
             reported count of {got} — a seed was overwritten or misnamed"
        );
    }
}

/// Writes the REAL seed corpus the fuzz targets read from, under
/// `fuzz/corpus/`.
///
/// `#[ignore]`d so `make check` (and `cargo test`/`cargo test --all-features`
/// generally) compiles and type-checks this whole file on every run without
/// writing a corpus every time — the corpus is generated, not part of the
/// gate. The `fuzz-corpus` Makefile target runs this one test explicitly
/// with `--ignored`. `fuzz/.gitignore`'s `/corpus` already excludes the
/// output, so nothing this writes is ever committed.
/// `seed_crc32` is pinned against CRC-32/ISO-HDLC's published check value
/// (`0xCBF43926` over `123456789`), not against anything this project
/// computed. A wrong polynomial would otherwise make every "healthy" seed
/// silently carry a checksum no reader agrees with — and the salvage
/// corpus's whole purpose is to start from an archive that reaches
/// `Intact`.
#[test]
fn the_corpus_builders_crc_matches_the_published_check_value() {
    assert_eq!(seed_crc32(b"123456789"), 0xCBF4_3926);
}

/// **The claim the salvage corpus is actually making.** Its seeds exist so
/// the fuzz target's only oracle call — `check_salvage_claim`, which fires
/// on `SalvageStatus::Intact` alone — is reachable at all. Before seeding,
/// all 64 accumulated corpus inputs produced not one salvaged record of
/// any status, so the target executed cleanly and proved nothing.
///
/// Asserting "the generator wrote N files" would reproduce exactly that
/// failure. This runs the real engine over every seed and checks what the
/// scan actually reports, so a seed that stopped reaching `Intact` (a
/// builder bug, a shape that drifted) fails here rather than going quiet
/// in a fuzz run nobody reads.
#[test]
fn every_salvage_seed_produces_records_and_at_least_one_intact() {
    use stuffr_core::salvage::SalvageStatus;

    let dir = tempfile::tempdir().unwrap();
    generate_corpus(dir.path()).unwrap();
    // Every `salvage/` seed now carries a leading `SALVAGE_SLOTS` selector
    // byte (Stage 2 Task 3b) that `entries::salvage` — which takes a path to
    // a real archive, not a fuzz-target-shaped blob — knows nothing about;
    // `salvage_payload_path` strips it into its own scratch file first, the
    // same split the fuzz target itself performs.
    let scratch = tempfile::tempdir().unwrap();

    let mut intact_seeds = 0usize;
    let mut seen = 0usize;
    for shape in SALVAGE_SHAPES {
        let seed_path = dir.path().join("salvage").join(format!("{shape}.seed"));
        let path = salvage_payload_path(&seed_path, scratch.path());
        let outcome = entries::salvage(
            &path,
            &entries::SalvageOpts {
                dest: None,
                policy: stuffr_core::salvage::SalvagePolicy::default(),
                select: None,
                format: None,
            },
        )
        .unwrap_or_else(|e| panic!("seed {shape} must scan without erroring: {e}"));
        assert!(
            !outcome.entries.is_empty(),
            "seed {shape} produced no salvaged record at all — the exact state the whole \
             corpus was in before it was seeded"
        );
        seen += 1;
        if outcome
            .entries
            .iter()
            .any(|r| r.status == SalvageStatus::Intact)
        {
            intact_seeds += 1;
        }
    }
    assert_eq!(seen, SALVAGE_SHAPES.len());
    assert_eq!(
        intact_seeds,
        SALVAGE_SHAPES.len(),
        "every shape must reach `Intact` on at least one of its records: that status is \
         the only one `check_salvage_claim` fires on, and a damaged shape is meant to be \
         a healthy archive the fuzzer can degrade FROM, not one already past the check"
    );

    // And the damaged shapes must genuinely be damaged, or the corpus is
    // several copies of one healthy archive wearing different names.
    for (shape, expected) in [
        ("truncated-tail", SalvageStatus::Partial),
        ("crc-mismatch", SalvageStatus::Partial),
    ] {
        let seed_path = dir.path().join("salvage").join(format!("{shape}.seed"));
        let path = salvage_payload_path(&seed_path, scratch.path());
        let outcome = entries::salvage(
            &path,
            &entries::SalvageOpts {
                dest: None,
                policy: stuffr_core::salvage::SalvagePolicy::default(),
                select: None,
                format: None,
            },
        )
        .unwrap();
        assert!(
            outcome.entries.iter().any(|r| r.status == expected),
            "seed {shape} must reach {expected:?}: {:?}",
            outcome.entries.iter().map(|r| r.status).collect::<Vec<_>>()
        );
    }

    // The two duplicate shapes must reach their own annotation, and not
    // each other's — the distinction the previous commit introduced.
    let duplicates = |shape: &str| {
        let seed_path = dir.path().join("salvage").join(format!("{shape}.seed"));
        let path = salvage_payload_path(&seed_path, scratch.path());
        entries::salvage(
            &path,
            &entries::SalvageOpts {
                dest: None,
                policy: stuffr_core::salvage::SalvagePolicy::default(),
                select: None,
                format: None,
            },
        )
        .unwrap()
    };
    let distinct = duplicates("distinct-duplicates");
    assert!(distinct.entries.iter().any(|r| r.collides_with.is_some()));
    assert!(distinct.entries.iter().all(|r| r.shadows.is_none()));
    let identical = duplicates("identical-duplicates");
    assert!(identical.entries.iter().any(|r| r.shadows.is_some()));
}

#[test]
#[ignore = "writes fuzz/corpus/*; run explicitly via `make fuzz-corpus`"]
fn generate_corpus_writes_the_real_seed_corpus() {
    // `CARGO_MANIFEST_DIR` is `crates/stuffr`; the fuzz crate's corpus lives
    // at the repo root's `fuzz/corpus`.
    let corpus_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus");
    let counts = generate_corpus(&corpus_root).unwrap();
    assert!(
        counts.codec > 0
            && counts.container > 0
            && counts.chain > 0
            && counts.roundtrip > 0
            && counts.salvage > 0,
        "wrote an empty corpus for at least one target: {counts:?}"
    );
}
