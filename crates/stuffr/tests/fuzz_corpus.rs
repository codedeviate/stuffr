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
use stuffr_core::testing::{CODEC_SLOTS, CONTAINER_SLOTS};

/// The chain target's seeds carry no selector byte, so there is no slot
/// table to derive an expected count from the way `codec`/`container` do.
/// This constant IS the generator's manifest of shapes: `generate_corpus`
/// matches on it exhaustively (an unhandled entry panics naming itself,
/// rather than being silently skipped), and the corpus test below asserts
/// against its `len()`, not a hand-copied number — so the two cannot drift
/// apart the way a duplicated literal could.
const CHAIN_SHAPES: &[&str] = &["plain-tar", "gzip-stream", "tar-gz-composed"];

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
}

/// Writes one seed corpus per fuzz target under `root/{codec,container,chain}`.
pub fn generate_corpus(root: &Path) -> stuffr_core::Result<CorpusCounts> {
    let codec_dir = root.join("codec");
    let container_dir = root.join("container");
    let chain_dir = root.join("chain");
    std::fs::create_dir_all(&codec_dir)?;
    std::fs::create_dir_all(&container_dir)?;
    std::fs::create_dir_all(&chain_dir)?;

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

    Ok(CorpusCounts {
        codec: codec_count,
        container: container_count,
        chain: chain_count,
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

    for (target, got, expected) in [
        ("codec", counts.codec, expected_codec),
        ("container", counts.container, expected_container),
        ("chain", counts.chain, expected_chain),
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
#[test]
#[ignore = "writes fuzz/corpus/*; run explicitly via `make fuzz-corpus`"]
fn generate_corpus_writes_the_real_seed_corpus() {
    // `CARGO_MANIFEST_DIR` is `crates/stuffr`; the fuzz crate's corpus lives
    // at the repo root's `fuzz/corpus`.
    let corpus_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus");
    let counts = generate_corpus(&corpus_root).unwrap();
    assert!(
        counts.codec > 0 && counts.container > 0 && counts.chain > 0,
        "wrote an empty corpus for at least one target: {counts:?}"
    );
}
