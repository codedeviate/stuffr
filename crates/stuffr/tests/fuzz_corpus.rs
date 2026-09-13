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

        let mut seed = vec![selector];
        seed.extend(read_all(&out_path)?);
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
        let bytes = read_all(&out_path)?;

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
