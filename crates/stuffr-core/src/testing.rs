//! Mock formats for testing the ladder and governor without any real codec.
//!
//! Enabled by `cfg(test)` in this crate and by the `testing` feature for
//! downstream crates.

use std::io::{Read, Write};

use crate::archive::{
    ArchiveRead, ArchiveWrite, Codec, Container, CreateOpts, DecodeOpts, EncodeOpts, Entry,
    EntryMeta, OpenOpts, Sink,
};
use crate::error::{Error, Result};
use crate::fidelity::{Fidelity, FidelityReport, Rung};
use crate::format::{CodecCaps, ContainerCaps, FormatId, FormatMeta, MagicRule};
use crate::ladder::Resolved;
use crate::source::Source;

pub use crate::conformance::{
    assert_codec_conforms, assert_codec_conforms_with, compressible, incompressible,
};
pub use crate::container_conformance::{
    ContainerFixture, ExpectedEntry, assert_container_conforms, assert_container_conforms_skipping,
    assert_container_conforms_with, assert_container_conforms_with_skipping, open_forward_only,
};
pub use crate::honesty::{
    Attestation, check_display_has_no_raw_controls, check_entries_carried, check_entry_count,
    check_entry_size, check_error_is_classified, check_extraction_contained, check_fidelity_claim,
    check_salvage_claim,
};

/// The fuzzer's codec selector table: byte `n % CODEC_SLOTS.len()` names a
/// format, so this ordering is the wire format of every GENERATED corpus seed.
///
/// **Append only. NEVER reorder, never remove — retire a slot by leaving it in
/// place.** Reordering silently changes what every generated seed means: a
/// seed written for `bzip2` would start feeding `brotli` instead, and nothing
/// would fail to tell you.
///
/// **What append-only protects is narrower than "every input on disk".** The
/// generator writes each seed's canonical index, below `len`, which no append
/// moves. An input the FUZZER accumulated carries whatever byte mutation left,
/// and appending changes `len` and with it `n % len`: measured at Salvage
/// Stage 3 Task 2's append to [`SALVAGE_SLOTS`], 4,491 of 12,013 accumulated
/// `salvage` inputs (37%) now route to a different slot. That is harmless —
/// `fuzz/corpus` is regenerated and gitignored — but it is not protected.
///
/// This lives in `stuffr-core` rather than in the fuzz targets because a later
/// task's corpus generator runs inside this crate and must write the *same*
/// selector byte the targets decode. `stuffr-core` cannot depend on `fuzz/`,
/// which is excluded from the workspace, so a copy in each would be free to
/// drift — precisely the failure the append-only rule exists to prevent.
pub const CODEC_SLOTS: &[&str] = &[
    "gzip", "zlib", "deflate", "bzip2", "brotli", "lz4", "snappy", "zstd", "xz", "lzma", "lzip",
    // Phase 3b. APPENDED, never inserted: the index of each name is the
    // selector byte of every generated corpus seed. `compress` is
    // read-only, so its corpus seed comes from a committed fixture rather
    // than from encoding through this build's own code — see
    // `crates/stuffr/tests/fuzz_corpus.rs`.
    "compress",
];

/// The fuzzer's container selector table. Same append-only rule as
/// [`CODEC_SLOTS`], for the same reason.
pub const CONTAINER_SLOTS: &[&str] = &[
    "tar", "ar", "cpio", "zip",
    // Phase 3b. APPENDED, never inserted, same reason as `compress` above.
    // Their corpus seeds are fixture-sourced rather than written by this
    // build — which was because neither could write when the slots landed,
    // and is now a deliberate choice: `lha` gained an encoder in Phase 3c
    // Task 6 and `arj` in Task 7, and both seeds still come from
    // `fixtures/legacy/` so the fuzzer explores outward from bytes this
    // project's own encoders did not produce. See `fuzz_corpus.rs`'s
    // `legacy_container_fixture`.
    "lha", "arj",
    // Phase 3c. APPENDED, never inserted. Read-only too, and the two slots
    // whose framing and decoders are this project's own from-scratch code
    // rather than a wrapped crate — which is precisely the kind the
    // `container` target exists to hammer. `zoo` adds a shape no other slot
    // has: a directory chain of attacker-controlled absolute file offsets,
    // where a mutated link is a walk that must still terminate.
    "arc", "zoo",
];

/// The `salvage` fuzz target's own selector table: its leading byte, `n %
/// SALVAGE_SLOTS.len()`, names the format `stuffr::entries::SalvageOpts::format`
/// is forced to — the same leading-selector-byte shape [`CONTAINER_SLOTS`]
/// already uses, rather than a second one invented for this target.
///
/// Lists only formats `stuffr::entries::salvage_scanner` actually dispatches
/// to a real scanner: `zip` (Salvage Stage 1), `arc` (Stage 2 Task 3), `zoo`
/// (Stage 2 Task 4), `lha` (Stage 2 Task 5), `arj` (Stage 2 Task 6), `tar`
/// (Stage 3 Task 2), `cpio` (Stage 3 Task 3) and `ar` (Stage 3 Task 4) —
/// every registered container, as of that task. A format with no scanner
/// answers `Error::Unsupported` from that dispatch (a claim about this BUILD,
/// not the archive; see `salvage_scan`'s own doc), so listing one here
/// before its own scanner lands would spend a share of every fuzzing run
/// proving nothing but that already-known refusal. Append a name in the same
/// commit that wires its scanner into `salvage_scanner`, never before.
///
/// **This is the fuzz target's wire format, not the answer to "which formats
/// can be salvaged"** — that is [`crate::ContainerCaps::salvage`], which
/// `stuffr::entries`' `salvage_caps_tests` pins to the dispatch for every
/// registered container (Salvage Stage 3 Task 5 deleted the older test that
/// pinned this list to the dispatch instead). A slot naming a format with no
/// scanner still fails loudly: the fuzz target's `attestation` and the corpus
/// generator's `top_tier` both read `stuffr::entries::salvage_attestation`,
/// and panic on `None`.
///
/// **Append-only, the identical rule [`CODEC_SLOTS`] and [`CONTAINER_SLOTS`]
/// carry, for the identical reason: the index is the wire format of every
/// generated corpus seed** — and, as [`CODEC_SLOTS`] says, of nothing the
/// fuzzer accumulated, whose `n % len` an append does move. Never reorder,
/// never remove — retire a slot by leaving it in place.
pub const SALVAGE_SLOTS: &[&str] = &["zip", "arc", "zoo", "lha", "arj", "tar", "cpio", "ar"];

/// The per-entry ceiling the `salvage` fuzz target runs under, in place of
/// [`crate::salvage::SalvagePolicy`]'s own 4 GiB default.
///
/// It lives here rather than in `fuzz/fuzz_targets/salvage.rs` for the same
/// reason [`SALVAGE_SLOTS`] does: `fuzz/` is excluded from the workspace, so
/// nothing the gate runs can see a constant declared there — and a ceiling
/// only the fuzz target knows is a ceiling no test can check a seed against.
/// Stage 2 Task 8 shipped it as a target-local constant and the review found
/// the consequence immediately: a future seed carrying an entry over it would
/// be silently `Unverified(OverEntryCeiling)` inside every run, contributing
/// nothing, with the whole suite green.
/// `crates/stuffr/tests/fuzz_corpus.rs`'s
/// `every_salvage_seed_is_scanned_the_way_the_fuzz_target_scans_it` now
/// asserts against this figure directly.
///
/// **256 KiB, and the number is a DISK bound, not only an allocation one**,
/// because that target writes what it recovers into a real destination
/// (Ruling S-O). It sits more than an order of magnitude above the largest
/// entry any seed carries, so nothing the corpus starts from is refused for
/// its size; an entry a mutation inflated past it is reported
/// `Unverified(OverEntryCeiling)` — a per-entry STATUS, never an error, so it
/// cannot end a run or take the entries around it with it.
pub const SALVAGE_FUZZ_MAX_ENTRY: u64 = 256 * 1024;

/// The `compat` fuzz target's tool selector: byte `n % COMPAT_NAMES.len()`
/// names the compatibility tool a case runs as, and `(n / len) & 1` the
/// flavour: the gzip family's (0 GNU, 1 BSD; R7 of 0.12.0) and, since
/// 0.16.0, the unzip family's (0 Ubuntu, 1 Apple: the same side as gzip's).
/// Only those two families read it. Every seed the 0.11.0 generator wrote has a name byte below 4,
/// so it decodes to the same tool, as GNU (`old_seeds_decode_unchanged`).
///
/// **Appending a name moves every flavour-1 byte**: `index + len` names a
/// different tool once `len` grows. Seeds are regenerated by
/// `make fuzz-corpus`; a corpus libFuzzer accumulated is only coverage.
///
/// These three tables live here for the reason [`SALVAGE_SLOTS`] does: they
/// are the wire format of the seeds `crates/stuffr/tests/fuzz_corpus.rs`
/// writes, and `fuzz/` is outside the workspace. **Append-only, never
/// reorder, never remove**, the rule [`CODEC_SLOTS`] states.
pub const COMPAT_NAMES: &[&str] = &[
    "bzip2",
    "bunzip2",
    "bzcat",
    "bzip2recover",
    "gzip",
    "gunzip",
    "zcat",
    "gzcat",
    "xz",
    "unxz",
    "xzcat",
    "lzma",
    "unlzma",
    "lzcat",
    "zstd",
    "unzstd",
    "zstdcat",
    "zstdmt",
    "lz4",
    "unlz4",
    "lz4cat",
    "lz4c",
    "unzip",
    "zipinfo",
    "funzip",
];

/// The files a `compat` case may create in its directory before the run,
/// one bit of the case's file mask each. Every one is also a token in
/// [`COMPAT_TOKENS`], so an operand can name it. Append-only.
///
/// Mask bit 4 is [`COMPAT_STDIN_BIT`], so a file at index 4 or later takes bit
/// `index + 1` (R6 of 0.12.0): the 0.11.0 seeds keep their meaning, and the
/// mask's eight bits hold seven files and standard input.
///
/// The xz family's five (0.13.0, R5) continue the rule onto bits 8-12, in
/// a second mask byte that follows the first only when the argument-count
/// byte is past [`COMPAT_MAX_ARGS`] (the count itself is still that byte
/// `% (COMPAT_MAX_ARGS + 1)`). No earlier generator wrote such a count
/// byte, so their seeds decode unchanged, payload included
/// (`old_seeds_decode_unchanged`); [`encode_compat_case`] writes the
/// second byte only for a case that names one of these five or later.
///
/// The zstd family's three (0.14.0, R5 again) take bits 13-15, which no
/// 0.13 generator wrote, and fill the second byte: a sixteenth file needs
/// a third mask byte. `d.dict` is a dictionary for `-D`.
///
/// The lz4 family's one (0.15.0, R5) is the sixteenth file, bit 16, so it
/// opens a **third mask byte**, present only when the argument-count byte
/// is at least `2 × (COMPAT_MAX_ARGS + 1)` (the count is still `byte % 9`;
/// no earlier generator wrote such a byte). lz4's `-D` takes `d.dict`:
/// there is no second dictionary file, because a seventeenth bit would
/// need a fourth byte for nothing a dictionary's contents add.
///
/// The unzip family's two (0.16.0) take bits 17 and 18 of that third byte:
/// `a.zip`, and `b.zip` for a second archive (unzip's wildcard and
/// several-archive paths, zipinfo's `-Z` over two).
pub const COMPAT_FILES: &[&str] = &[
    "a", "a.bz2", "a.tbz2", "a.out", // 0.11.0
    "a.gz", "a.tgz", "a.z", // 0.12.0: the gzip family
    "a.xz", "a.txz", "a.lzma", "a.tlz", "a.lz", // 0.13.0: the xz family
    "a.zst", "a.tzst", "d.dict", // 0.14.0: the zstd family
    "a.lz4",  // 0.15.0: the lz4 family (a third mask byte; its dictionary is `d.dict`)
    "a.zip", "b.zip", // 0.16.0: the unzip family (third mask byte, bits 17 and 18)
];

/// The `compat` target's argument vocabulary: byte `n % len` is one argument.
/// Every bzip2 1.0.8 short flag, an unknown one, some clusters, every long
/// flag, an unknown one, `--`, `-`, and the [`COMPAT_FILES`] names; then
/// (0.12.0) gzip's flags that bzip2 lacks, `.x` for `-S` to take, and the
/// gzip family's files; then (0.13.0) xz's flags, `-F`'s and `--check`'s
/// values, and the xz family's files; then (0.13.1) `--files=a` and
/// `--files0=a`, the list-file forms; then (0.14.0) zstd's flags that no
/// earlier family has, the dictionary and training options, and the zstd
/// family's files (`--output-dir-flat=d` names a directory no case
/// creates). Drawing
/// arguments from a fixed set, rather than from raw bytes, is what keeps
/// every operand inside the case's directory: no token is absolute, holds a
/// `/` or names `..`. Append-only.
pub const COMPAT_TOKENS: &[&str] = &[
    "-c",
    "-d",
    "-z",
    "-f",
    "-t",
    "-k",
    "-s",
    "-q",
    "-v",
    "-V",
    "-L",
    "-h",
    "-1",
    "-2",
    "-3",
    "-4",
    "-5",
    "-6",
    "-7",
    "-8",
    "-9",
    "-x",
    "-dc",
    "-cd",
    "-tv",
    "-kf",
    "-dfk",
    "-qt",
    "-vvv",
    "-zc",
    "-s1",
    "-dq",
    "--stdout",
    "--decompress",
    "--compress",
    "--force",
    "--test",
    "--keep",
    "--small",
    "--quiet",
    "--version",
    "--license",
    "--exponential",
    "--repetitive-best",
    "--repetitive-fast",
    "--fast",
    "--best",
    "--verbose",
    "--help",
    "--bogus",
    "--",
    "-",
    "a",
    "a.bz2",
    "a.tbz2",
    "a.out",
    // 0.12.0: the gzip family (`-c -d -f -t -k -q -v -V -L -h -1..-9
    // --stdout --decompress --force --test --keep --quiet --version --license
    // --fast --best --verbose --help` are above).
    "-l",
    "-n",
    "-N",
    "-r",
    "-S",
    ".x",
    "--list",
    "--name",
    "--no-name",
    "--recursive",
    "--suffix",
    "--rsyncable",
    "--synchronous",
    "-a",
    "--ascii",
    "a.gz",
    "a.tgz",
    "a.z",
    // 0.13.0: the xz family (`-l -t -9` and the rest above are shared).
    "-T0",
    "-T1",
    "-e",
    "-0",
    "-F",
    "xz",
    "lzma",
    "raw",
    "lzip",
    "--format",
    "--check",
    "crc32",
    "sha256",
    "none",
    "--single-stream",
    "--no-sparse",
    "--robot",
    "--memlimit-decompress=1MiB",
    "--lzma2=dict=4KiB",
    "--x86",
    "--delta=dist=2",
    "--block-size=1KiB",
    "--files",
    "--files0",
    "--ignore-check",
    "a.xz",
    "a.txz",
    "a.lzma",
    "a.tlz",
    "a.lz",
    // 0.13.1: `--files`/`--files0` reading their names from a file. getopt
    // takes an optional argument only in the `=` spelling, so the reader
    // was unreachable before. `a` is `COMPAT_FILES[0]`.
    "--files=a",
    "--files0=a",
    // 0.14.0: the zstd family (`-r`, `--rsyncable` and `--no-sparse` are
    // above).
    "-D",
    "d.dict",
    "--train",
    "--train-cover=k=16,d=6",
    "--train-fastcover",
    "--maxdict=1K",
    "--patch-from=a",
    "--long",
    "--long=24",
    "--memory=1M",
    "--ultra",
    "-22",
    "-19",
    "--fast=3",
    "-T2",
    "--no-check",
    "--no-content-size",
    "--stream-size=10",
    "--format=zstd",
    "--format=gzip",
    "--format=lz4",
    "--zstd=wlog=12",
    "--rm",
    "--sparse",
    "--pass-through",
    "--exclude-compressed",
    "--adapt",
    "-B1K",
    "--filelist=a",
    "--output-dir-flat=d",
    "--show-default-cparams",
    "a.zst",
    "a.tzst",
    // 0.15.0: the lz4 family (`-l -D -c -d -z -f -k -t -m -q -v -1..-9
    // --fast=3 --best --list --rm --sparse --no-sparse -T0 -T1 -T2 -B1K
    // -r --filelist=a d.dict --format=lz4 --stdout ...` are above). `-c0`
    // and `-hc` are lz4's legacy spellings; `d.lz4dict` names a dictionary
    // no case creates (`-D` of a missing file); `null` and `stdout` are
    // the output-name words.
    "-BD",
    "-BX",
    "-B4",
    "-B32",
    "-12",
    "--favor-decSpeed",
    "--no-frame-crc",
    "--content-size",
    "-m",
    "d.lz4dict",
    "null",
    "stdout",
    "-c0",
    "-hc",
    "-y",
    "a.lz4",
    // 0.16.0: the unzip family (`-l -v -t -c -n -d -x -a -L -q` are above;
    // `-P`, `-d`, `-x`, `-O` and `-I` take the next token as their value).
    "-p",
    "-o",
    "-P",
    "-Z",
    "-j",
    "-C",
    "-X",
    "-O",
    "-I",
    "-M",
    "a.zip",
    "b.zip",
];

/// The largest input the `compat` target runs. Here, not in the target, so
/// the corpus generator's test can hold every seed under it. A bzip2 block
/// holds at most 900k, but a fuzz-scale case never needs one: 64 KiB fits a
/// multi-block stream of compressible text at level 1 (the bzip2recover
/// seed) and keeps a run in the milliseconds.
///
/// **This is not the limit that binds in practice.** libFuzzer's effective
/// `-max_len` defaults to the largest seed, about 15.7 KiB (the bzip2recover
/// seeds), so mutated inputs stay near that unless `-max_len` is passed.
///
/// **The input cap does not bound decode work; `run_in`'s 8 MiB budget
/// does.** A 50-byte bzip2 stream decodes to 45 MB (one 900k block through
/// RLE1), so a 15.7 KiB input of ~300 such streams is ~14 GB of decoding,
/// about 30 s in a release build at the measured 0.1 s per stream and longer
/// instrumented. Output to stdout or files is capped by `run_in`, and since
/// fix round 1 so are the bytes `-t` decodes, which go nowhere and were the
/// one uncapped path; fuzz-deep.yml runs `compat` with `-timeout=60` so a
/// regression there is reported as a slow input rather than a hung job.
pub const COMPAT_FUZZ_MAX_INPUT: usize = 64 * 1024;

/// At most this many arguments per `compat` case (`argc % (MAX + 1)`).
pub const COMPAT_MAX_ARGS: usize = 8;

/// Mask bit: standard input carries the payload (otherwise it is empty).
pub const COMPAT_STDIN_BIT: u8 = 1 << 4;

/// The mask bit of [`COMPAT_FILES`]`[i]`: `i` below 4, `i + 1` from 4 on,
/// skipping [`COMPAT_STDIN_BIT`] (R6 of 0.12.0, R5 of 0.13.0). Bits 8 and
/// up are the second mask byte's.
fn file_bit(i: usize) -> u32 {
    1 << if i < 4 { i } else { i + 1 }
}

/// The first file whose mask bit is in the second mask byte.
const FIRST_WIDE_FILE: usize = 7;

/// The first file whose mask bit is in the third mask byte (0.15.0).
const FIRST_WIDER_FILE: usize = 15;

/// One `compat` fuzz case, decoded by [`decode_compat_case`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatCase<'a> {
    /// The tool, from [`COMPAT_NAMES`].
    pub name: &'static str,
    /// The flavour (R7): gzip's 0 GNU or 1 BSD, unzip's 0 Ubuntu or 1
    /// Apple; the other families ignore it.
    pub flavour: u8,
    /// The arguments after `argv[0]`, from [`COMPAT_TOKENS`].
    pub args: Vec<&'static str>,
    /// The [`COMPAT_FILES`] created before the run, each holding `payload`.
    pub files: Vec<&'static str>,
    /// Whether standard input carries `payload`.
    pub stdin: bool,
    /// The bytes every created file (and, with `stdin`, standard input)
    /// holds.
    pub payload: &'a [u8],
}

/// Decode `[name][argc][token; argc][mask][mask2?] ++ payload`, the
/// `compat` target's wire format, where `mask2` is there only when the
/// `argc` byte is past [`COMPAT_MAX_ARGS`], and a `mask3` after that only
/// when it is at least twice that ([`COMPAT_FILES`]). `None` when `data`
/// ends before the mask (or `mask2`, `mask3`).
pub fn decode_compat_case(data: &[u8]) -> Option<CompatCase<'_>> {
    let (&name, rest) = data.split_first()?;
    let (&argc_byte, rest) = rest.split_first()?;
    let argc = argc_byte as usize % (COMPAT_MAX_ARGS + 1);
    let wide = argc_byte as usize > COMPAT_MAX_ARGS;
    let wider = argc_byte as usize > 2 * COMPAT_MAX_ARGS + 1;
    if rest.len() < argc + 1 {
        return None;
    }
    let (tokens, rest) = rest.split_at(argc);
    let (&low, rest) = rest.split_first()?;
    let (mask, payload) = if wider {
        let (&high, rest) = rest.split_first()?;
        let (&top, rest) = rest.split_first()?;
        (u32::from_le_bytes([low, high, top, 0]), rest)
    } else if wide {
        let (&high, rest) = rest.split_first()?;
        (u32::from_le_bytes([low, high, 0, 0]), rest)
    } else {
        (u32::from(low), rest)
    };
    Some(CompatCase {
        name: COMPAT_NAMES[name as usize % COMPAT_NAMES.len()],
        flavour: ((name as usize / COMPAT_NAMES.len()) & 1) as u8,
        args: tokens
            .iter()
            .map(|&t| COMPAT_TOKENS[t as usize % COMPAT_TOKENS.len()])
            .collect(),
        files: COMPAT_FILES
            .iter()
            .enumerate()
            .filter(|&(i, _)| mask & file_bit(i) != 0)
            .map(|(_, &f)| f)
            .collect(),
        stdin: mask & u32::from(COMPAT_STDIN_BIT) != 0,
        payload,
    })
}

/// The inverse of [`decode_compat_case`], for the corpus generator.
///
/// # Panics
///
/// On a name, token or file outside its table, a `flavour` other than 0 or
/// 1, or more than [`COMPAT_MAX_ARGS`] arguments: a seed that cannot be
/// encoded is a bug in the generator.
pub fn encode_compat_case(
    name: &str,
    flavour: u8,
    args: &[&str],
    files: &[&str],
    stdin: bool,
    payload: &[u8],
) -> Vec<u8> {
    let index = |table: &[&str], s: &str| {
        table
            .iter()
            .position(|t| *t == s)
            .unwrap_or_else(|| panic!("{s:?} is not in its compat table"))
    };
    assert!(args.len() <= COMPAT_MAX_ARGS, "too many compat arguments");
    assert!(flavour <= 1, "a gzip flavour is 0 (GNU) or 1 (BSD)");
    let selector = index(COMPAT_NAMES, name) + usize::from(flavour) * COMPAT_NAMES.len();
    let selector = u8::try_from(selector).expect("a compat name selector fits a byte");
    let files: Vec<usize> = files.iter().map(|f| index(COMPAT_FILES, f)).collect();
    let wide = files.iter().any(|&i| i >= FIRST_WIDE_FILE);
    let wider = files.iter().any(|&i| i >= FIRST_WIDER_FILE);
    let argc = args.len()
        + if wider {
            2 * (COMPAT_MAX_ARGS + 1)
        } else if wide {
            COMPAT_MAX_ARGS + 1
        } else {
            0
        };
    let mut v = vec![selector, argc as u8];
    v.extend(args.iter().map(|a| index(COMPAT_TOKENS, a) as u8));
    let mut mask = if stdin {
        u32::from(COMPAT_STDIN_BIT)
    } else {
        0
    };
    for i in files {
        mask |= file_bit(i);
    }
    let [low, high, top, _] = mask.to_le_bytes();
    v.push(low);
    if wide || wider {
        v.push(high);
    }
    if wider {
        v.push(top);
    }
    v.extend_from_slice(payload);
    v
}

pub const MOCK_CODEC: FormatId = FormatId::new("mock-codec");
pub const MOCK_CONTAINER: FormatId = FormatId::new("mock-container");

/// A symmetric XOR-0xFF "codec". Trivially verifiable, and symmetric so a
/// round-trip bug cannot hide behind a matching pair of mistakes.
pub struct MockCodec;

struct XorReader(Box<dyn Read + Send>);

impl Read for XorReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.0.read(buf)?;
        for b in &mut buf[..n] {
            *b ^= 0xFF;
        }
        Ok(n)
    }
}

struct XorSink(Box<dyn Write + Send>);

impl Write for XorSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let flipped: Vec<u8> = buf.iter().map(|b| b ^ 0xFF).collect();
        self.0.write_all(&flipped)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl Sink for XorSink {
    fn finish(mut self: Box<Self>) -> Result<()> {
        self.0.flush()?;
        Ok(())
    }
}

impl Codec for MockCodec {
    fn id(&self) -> FormatId {
        MOCK_CODEC
    }

    fn caps(&self) -> CodecCaps {
        CodecCaps {
            encode: true,
            decode: true,
            ..Default::default()
        }
    }

    fn decoder(&self, src: Box<dyn Source>, _o: &DecodeOpts) -> Result<Box<dyn Source>> {
        Ok(Box::new(crate::source::StreamOnly::new(XorReader(
            Box::new(src),
        ))))
    }

    fn encoder(&self, dst: Box<dyn Write + Send>, _o: &EncodeOpts) -> Result<Box<dyn Sink>> {
        Ok(Box::new(XorSink(dst)))
    }
}

impl MockCodec {
    /// Stands in for what a real MT codec does: ask the governor for workers,
    /// use them, release. The mock immediately releases; a real codec would
    /// hold the set for the duration of the work.
    pub fn workers_for_opts(&self, o: &DecodeOpts) -> usize {
        match (&o.governor, o.threads) {
            (Some(g), want) => g.acquire_many(want.unwrap_or(1), 0).workers(),
            (None, _) => 1,
        }
    }
}

/// A deliberately ZIP-shaped mock container.
///
/// ```text
/// repeat: "ME" | name_len u16le | name | data_len u64le | data
/// footer: "MI" | count u32le | count * (offset u64le) | "MEND"
/// ```
///
/// `forward_parse` walks the `ME` records; `trailing_index` marks the `MI`
/// footer as authoritative. That combination is what exercises the same ladder
/// branches a real zip does.
pub struct MockContainer;

/// Builds a valid mock archive in memory. Used by tests across the crate.
pub fn mock_archive_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut offsets = Vec::new();
    for (name, data) in entries {
        offsets.push(out.len() as u64);
        out.extend_from_slice(b"ME");
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        out.extend_from_slice(data);
    }
    out.extend_from_slice(b"MI");
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for o in &offsets {
        out.extend_from_slice(&o.to_le_bytes());
    }
    out.extend_from_slice(b"MEND");
    out
}

pub struct MockArchiveRead {
    buf: Vec<u8>,
    pos: usize,
    report: FidelityReport,
    index: Option<Vec<u64>>,
}

impl MockContainer {
    fn parse_index(buf: &[u8]) -> Option<Vec<u64>> {
        if !buf.ends_with(b"MEND") {
            return None;
        }
        // Walk back: MEND(4) + offsets(8*count) + count(4) + "MI"(2)
        let end = buf.len() - 4;
        // Find "MI" by trying each plausible count.
        for count in 0..=((end.saturating_sub(6)) / 8) {
            let start = end.checked_sub(8 * count + 4 + 2)?;
            if &buf[start..start + 2] == b"MI" {
                let declared =
                    u32::from_le_bytes(buf[start + 2..start + 6].try_into().ok()?) as usize;
                if declared != count {
                    continue;
                }
                let mut offsets = Vec::with_capacity(count);
                for i in 0..count {
                    let o = start + 6 + i * 8;
                    offsets.push(u64::from_le_bytes(buf[o..o + 8].try_into().ok()?));
                }
                return Some(offsets);
            }
        }
        None
    }

    /// First offset at which a record marker appears. Used only by the
    /// Degraded rung, where the leading bytes cannot be trusted.
    fn find_first_record(buf: &[u8]) -> Option<usize> {
        buf.windows(2).position(|w| w == b"ME")
    }
}

impl Container for MockContainer {
    fn id(&self) -> FormatId {
        MOCK_CONTAINER
    }

    fn caps(&self) -> ContainerCaps {
        ContainerCaps {
            read: true,
            write: true,
            forward_parse: true,
            trailing_index: true,
            ..Default::default()
        }
    }

    fn open(&self, resolved: Resolved, _o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
        let Resolved {
            mut source,
            rung,
            report,
            ..
        } = resolved;
        let seekable = source.caps().seekable;
        let mut buf = Vec::new();
        source.read_to_end(&mut buf)?;

        // Degraded means "salvage what you can": do not trust the stream to
        // begin at a record boundary, scan for one. Reachable because the
        // ladder only ever selects Degraded for a NON-seekable source — if it
        // were seekable, rung 1 would have returned Exact long before.
        let pos = if rung == Rung::Degraded {
            Self::find_first_record(&buf).unwrap_or(buf.len())
        } else {
            0
        };

        let index = if seekable {
            Self::parse_index(&buf)
        } else {
            None
        };

        // Start from the ladder's report rather than re-deriving it, then add
        // only what parsing itself discovered.
        let mut report = report;
        if seekable && index.is_none() {
            report.warn(Fidelity::TruncatedStream {
                at: buf.len() as u64,
            });
        }

        Ok(Box::new(MockArchiveRead {
            buf,
            pos,
            report,
            index,
        }))
    }

    fn create(&self, dst: Box<dyn Sink>, _o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
        Ok(Box::new(MockArchiveWrite {
            dst,
            offsets: Vec::new(),
            written: 0,
        }))
    }
}

impl MockArchiveRead {
    fn read_record_at(&self, at: usize) -> Result<Option<(EntryMeta, usize, usize)>> {
        let b = &self.buf;
        if at + 2 > b.len() || &b[at..at + 2] != b"ME" {
            return Ok(None);
        }
        let name_len = u16::from_le_bytes(
            b[at + 2..at + 4]
                .try_into()
                .map_err(|_| Error::Corrupt("short name_len".into()))?,
        ) as usize;
        let name_at = at + 4;
        let size_at = name_at + name_len;
        if size_at + 8 > b.len() {
            return Err(Error::Corrupt("truncated entry header".into()));
        }
        let name = String::from_utf8_lossy(&b[name_at..size_at]).into_owned();
        let data_len = u64::from_le_bytes(
            b[size_at..size_at + 8]
                .try_into()
                .map_err(|_| Error::Corrupt("short len".into()))?,
        ) as usize;
        let data_at = size_at + 8;
        if data_at + data_len > b.len() {
            return Err(Error::Corrupt("truncated entry data".into()));
        }
        let mut meta = EntryMeta::file(name);
        meta.size = Some(data_len as u64);
        Ok(Some((meta, data_at, data_len)))
    }
}

impl ArchiveRead for MockArchiveRead {
    fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
        let Some((meta, data_at, data_len)) = self.read_record_at(self.pos)? else {
            return Ok(None);
        };
        self.pos = data_at + data_len;
        let slice = &self.buf[data_at..data_at + data_len];
        Ok(Some(Entry::new(
            meta,
            Box::new(std::io::Cursor::new(slice)),
        )))
    }

    fn by_index(&mut self, index: usize) -> Result<Entry<'_>> {
        let offsets = self
            .index
            .as_ref()
            .ok_or(Error::NotSeekable {
                format: MOCK_CONTAINER,
            })?
            .clone();
        let at = *offsets
            .get(index)
            .ok_or_else(|| Error::EntryNotFound(index.to_string()))?;
        let (meta, data_at, data_len) = self
            .read_record_at(at as usize)?
            .ok_or_else(|| Error::Corrupt("index points at a non-record".into()))?;
        let slice = &self.buf[data_at..data_at + data_len];
        Ok(Entry::new(meta, Box::new(std::io::Cursor::new(slice))))
    }

    fn fidelity(&self) -> &FidelityReport {
        &self.report
    }
}

pub struct MockArchiveWrite {
    dst: Box<dyn Sink>,
    offsets: Vec<u64>,
    written: u64,
}

impl ArchiveWrite for MockArchiveWrite {
    fn add(&mut self, meta: &EntryMeta, data: &mut dyn Read) -> Result<()> {
        let mut payload = Vec::new();
        data.read_to_end(&mut payload)?;

        self.offsets.push(self.written);
        let name = meta.name.as_bytes();
        self.dst.write_all(b"ME")?;
        self.dst.write_all(&(name.len() as u16).to_le_bytes())?;
        self.dst.write_all(name)?;
        self.dst.write_all(&(payload.len() as u64).to_le_bytes())?;
        self.dst.write_all(&payload)?;
        self.written += 2 + 2 + name.len() as u64 + 8 + payload.len() as u64;
        Ok(())
    }

    fn finish(mut self: Box<Self>) -> Result<Box<dyn Sink>> {
        self.dst.write_all(b"MI")?;
        self.dst
            .write_all(&(self.offsets.len() as u32).to_le_bytes())?;
        for o in &self.offsets {
            self.dst.write_all(&o.to_le_bytes())?;
        }
        self.dst.write_all(b"MEND")?;
        // Returned, not finished: completion belongs to the caller, once, at
        // the outermost layer.
        Ok(self.dst)
    }
}

/// A well-behaved FRAMED double for the container conformance harness,
/// analogous to `conformance::framed_mock::FramedMock` on the codec side.
///
/// `MockContainer` above stays exactly as it is — governor, ladder and probe
/// tests rely on its shape — but it reads its whole source to end before
/// returning even the first entry, which is fine for those tests and would
/// fail the harness's incrementality property outright (Task 2). This double
/// streams instead: [`ArchiveRead::next_entry`] parses one length-prefixed
/// record at a time and only ever buffers a single entry's payload, never the
/// whole archive.
///
/// Wire format:
/// ```text
/// repeat: "FE" | name_len u32le | name | data_len u64le | data
/// trailer: "FZ"
/// ```
pub struct FramedMockContainer;

pub const FRAMED_CONTAINER: FormatId = FormatId::new("framed-mock-container");

const FRAMED_MAGICS: &[MagicRule] = &[MagicRule {
    offset: 0,
    bytes: b"FE",
    format: FRAMED_CONTAINER,
}];

/// Registration metadata for [`FramedMockContainer`], for
/// `assert_container_conforms(&FramedMockContainer, &framed_container_meta())`.
pub fn framed_container_meta() -> FormatMeta {
    FormatMeta::container(FRAMED_CONTAINER, &["fmc"], FRAMED_MAGICS)
}

impl Container for FramedMockContainer {
    fn id(&self) -> FormatId {
        FRAMED_CONTAINER
    }

    fn caps(&self) -> ContainerCaps {
        ContainerCaps {
            read: true,
            write: true,
            forward_parse: true,
            ..Default::default()
        }
    }

    fn open(&self, resolved: Resolved, _o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
        let Resolved { source, report, .. } = resolved;
        Ok(Box::new(FramedArchiveRead {
            source,
            pending: 0,
            report,
        }))
    }

    fn create(&self, dst: Box<dyn Sink>, _o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
        Ok(Box::new(FramedArchiveWrite { dst }))
    }
}

struct FramedArchiveWrite {
    dst: Box<dyn Sink>,
}

impl ArchiveWrite for FramedArchiveWrite {
    fn add(&mut self, meta: &EntryMeta, data: &mut dyn Read) -> Result<()> {
        let mut payload = Vec::new();
        data.read_to_end(&mut payload)?;
        let name = meta.name.as_bytes();
        self.dst.write_all(b"FE")?;
        self.dst.write_all(&(name.len() as u32).to_le_bytes())?;
        self.dst.write_all(name)?;
        self.dst.write_all(&(payload.len() as u64).to_le_bytes())?;
        self.dst.write_all(&payload)?;
        Ok(())
    }

    fn finish(mut self: Box<Self>) -> Result<Box<dyn Sink>> {
        self.dst.write_all(b"FZ")?;
        Ok(self.dst)
    }
}

/// Bounds reads to `*remaining` bytes of `*source`, decrementing it as bytes
/// are actually delivered. Lets [`FramedArchiveRead::next_entry`] tell how
/// many bytes of a partially-read entry still need to be skipped before the
/// next record can be parsed.
struct BoundedReader<'a> {
    source: &'a mut Box<dyn Source>,
    remaining: &'a mut u64,
}

impl Read for BoundedReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if *self.remaining == 0 {
            return Ok(0);
        }
        let cap = (buf.len() as u64).min(*self.remaining) as usize;
        let n = self.source.read(&mut buf[..cap])?;
        *self.remaining -= n as u64;
        Ok(n)
    }
}

/// Streams one length-prefixed record at a time — see the struct's own doc
/// comment on why `MockArchiveRead`'s whole-source read cannot stand in once
/// the incrementality property (Task 2) exists.
struct FramedArchiveRead {
    source: Box<dyn Source>,
    /// Bytes of the current entry's payload not yet delivered to the caller.
    pending: u64,
    report: FidelityReport,
}

impl FramedArchiveRead {
    /// Discards whatever is left of the entry the caller did not fully read,
    /// so the next call starts exactly at the next record's tag.
    fn skip_pending(&mut self) -> Result<()> {
        if self.pending > 0 {
            let mut reader = BoundedReader {
                source: &mut self.source,
                remaining: &mut self.pending,
            };
            std::io::copy(&mut reader, &mut std::io::sink())?;
        }
        Ok(())
    }
}

/// Reads exactly `buf.len()` bytes, reclassifying a bare `UnexpectedEof` —
/// the shape every truncated stream produces once it runs out of bytes
/// mid-record — onto [`Error::Corrupt`], so a cut archive surfaces as
/// `io::ErrorKind::InvalidData` (conformance property 9) rather than a
/// generic `Error::Io`. Any other kind, notably a genuine source failure such
/// as `PermissionDenied`, passes through unchanged as `Error::Io` so it is
/// never mistaken for corruption (property 10).
fn read_exact_or_corrupt(source: &mut Box<dyn Source>, buf: &mut [u8]) -> Result<()> {
    source.read_exact(buf).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            Error::Corrupt("framed mock container: truncated stream".into())
        } else {
            Error::Io(e)
        }
    })
}

impl ArchiveRead for FramedArchiveRead {
    fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
        self.skip_pending()?;

        let mut tag = [0u8; 2];
        read_exact_or_corrupt(&mut self.source, &mut tag)?;
        match &tag {
            b"FZ" => Ok(None),
            b"FE" => {
                let mut len_buf = [0u8; 4];
                read_exact_or_corrupt(&mut self.source, &mut len_buf)?;
                let name_len = u32::from_le_bytes(len_buf) as usize;
                let mut name_buf = vec![0u8; name_len];
                read_exact_or_corrupt(&mut self.source, &mut name_buf)?;
                let name = String::from_utf8_lossy(&name_buf).into_owned();

                let mut dlen_buf = [0u8; 8];
                read_exact_or_corrupt(&mut self.source, &mut dlen_buf)?;
                let data_len = u64::from_le_bytes(dlen_buf);
                self.pending = data_len;

                let mut meta = EntryMeta::file(name);
                meta.size = Some(data_len);

                let reader = BoundedReader {
                    source: &mut self.source,
                    remaining: &mut self.pending,
                };
                Ok(Some(Entry::new(meta, Box::new(reader))))
            }
            _ => Err(Error::Corrupt(
                "framed mock container: unrecognised record tag".into(),
            )),
        }
    }

    fn by_index(&mut self, _index: usize) -> Result<Entry<'_>> {
        // No index is implemented by this double — every consumer of it so
        // far only needs forward iteration.
        Err(Error::NotSeekable {
            format: FRAMED_CONTAINER,
        })
    }

    fn fidelity(&self) -> &FidelityReport {
        &self.report
    }
}

/// A `'static`, cloneable in-memory sink.
///
/// `Codec::encoder` takes `Box<dyn Write + Send>` and `Container::create` a
/// `Box<dyn Sink>` (a `SharedBuf` reaches that through [`crate::PlainSink`]),
/// both implicitly `+ 'static`, so a test cannot hand them `&mut local_vec`.
/// Cloning a `SharedBuf` gives the test a handle on whatever the writer wrote.
#[derive(Clone, Default)]
pub struct SharedBuf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl SharedBuf {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn contents(&self) -> Vec<u8> {
        self.0.lock().expect("SharedBuf mutex poisoned").clone()
    }
}

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("SharedBuf mutex poisoned")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A [`Source`] that delivers `prefix` and then fails with `kind` forever.
///
/// The shape every "where does this error land, and how is it classified?"
/// test needs: the prefix is what lets a container get far enough to reach the
/// read that matters, and the failure is what that read then meets.
///
/// Pair it with [`decode_side_failing_source`] and [`raw_failing_source`],
/// which are the same bytes with and without
/// [`crate::source::mark_decode_side`] applied. Those two are the only
/// difference the classification turns on, so a test that runs both proves the
/// marking is what decided — not the error's kind, and not the call site.
pub struct FailsAfterPrefix {
    prefix: Vec<u8>,
    pos: usize,
    kind: std::io::ErrorKind,
    message: &'static str,
}

impl Read for FailsAfterPrefix {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.prefix[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        Err(std::io::Error::new(self.kind, self.message))
    }
}

impl Source for FailsAfterPrefix {
    fn caps(&self) -> crate::source::SourceCaps {
        crate::source::SourceCaps {
            seekable: false,
            len: None,
        }
    }

    fn as_seek(&mut self) -> Option<&mut dyn crate::source::SeekRead> {
        None
    }
}

/// The message [`decode_side_failing_source`] and [`raw_failing_source`] raise,
/// so a test can assert the decoder's own wording survived classification.
pub const FAILING_SOURCE_MESSAGE: &str = "the stream is malformed from here on";

/// `prefix` bytes, then a failure of `kind`, **marked as decode-side**.
///
/// Models a codec decoder that produced good bytes and then met malformed
/// input — the exact shape a 21-byte zstd frame whose decoded bytes open with
/// ARJ's `60 EA` magic presents to everything above it.
pub fn decode_side_failing_source(prefix: &[u8], kind: std::io::ErrorKind) -> Box<dyn Source> {
    crate::source::DecodeSideSource::wrap(raw_failing_source(prefix, kind))
}

/// `prefix` bytes, then a failure of `kind`, **unmarked**.
///
/// Models the raw source failing — a disk error, a pipe that broke — which
/// must stay [`crate::Error::Io`] however the failing read is spelled.
pub fn raw_failing_source(prefix: &[u8], kind: std::io::ErrorKind) -> Box<dyn Source> {
    Box::new(FailsAfterPrefix {
        prefix: prefix.to_vec(),
        pos: 0,
        kind,
        message: FAILING_SOURCE_MESSAGE,
    })
}

/// A reader that returns at most `chunk` bytes per `read` call, so tests can
/// exercise paths that only appear across several short reads. A `Cursor` hands
/// over everything at once and hides them.
pub struct ChunkedReader {
    data: Vec<u8>,
    pos: usize,
    chunk: usize,
}

impl ChunkedReader {
    pub fn new(data: Vec<u8>, chunk: usize) -> Self {
        assert!(chunk > 0, "chunk must be non-zero");
        Self {
            data,
            pos: 0,
            chunk,
        }
    }
}

impl Read for ChunkedReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.chunk.min(buf.len()).min(self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// A source that counts the bytes it DELIVERS — every byte a scanner asked
/// for and got, re-reads included. Wrapped around the source handed to a
/// `salvage_*` entry point, it measures the scan's work in the unit
/// [`check_scan_is_linear`] bounds.
#[derive(Debug)]
pub struct CountingSource<R> {
    inner: R,
    read: u64,
}

impl<R> CountingSource<R> {
    pub fn new(inner: R) -> Self {
        Self { inner, read: 0 }
    }
    pub fn bytes_read(&self) -> u64 {
        self.read
    }
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: std::io::Read> std::io::Read for CountingSource<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(out)?;
        self.read += n as u64;
        Ok(n)
    }
}

impl<R: std::io::Seek> std::io::Seek for CountingSource<R> {
    fn seek(&mut self, to: std::io::SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(to)
    }
}

/// The bound every salvage scan is held to: bytes delivered to the scanner
/// at most `SCAN_READ_FACTOR × file_len + SCAN_READ_SLACK`. The `salvage`
/// fuzz target applies it to every input's independent second scan, and
/// each scanner's own tests apply it to its hostile shapes at 256 KiB-1 MiB.
///
/// **Measured, 0.10.3 Task 4 (2026-10-09)**, over the local `salvage`
/// corpus — 12,907 inputs, 12,723 reaching a scanner, 0 to 11,529 bytes
/// (13.4 MiB in all) — with `STUFFR_FUZZ_SCAN_TRACE`. Largest ratio of bytes
/// read to input length, per slot, after that task's scanner fixes (before
/// them in brackets):
///
/// | slot | inputs | max ratio | before |
/// |---|---|---|---|
/// | `zip`  | 5,557 | 3.40 | 218.1 |
/// | `zoo`  | 2,075 | 5.72 | 131.9 |
/// | `lha`  |   606 | 3.24 | 106.2 |
/// | `arc`  |   269 | 1.83 |  93.3 |
/// | `arj`  |   202 | 1.09 |  15.0 |
/// | `cpio` |   100 | 2.65 |   3.1 |
/// | `tar`  | 2,792 | 1.60 |   2.2 |
/// | `ar`   | 1,122 | 2.00 |   2.0 |
///
/// No input read past `8 × len`; the largest single scan read 65,499 bytes
/// (`zoo`, an 11,454-byte input), so the tightest input sits 2.4x under
/// this bound. The figures are kept at the plan's ceiling rather than
/// lowered to the corpus: fuzz-scale inputs (≤ 11.5 KiB) sit almost wholly
/// inside the slack, and the scanners' own MiB-scale hostile fixtures
/// still reach 6-8x once fixed (`tar_salvage.rs`'s converging and
/// mixed-chain shapes), which a tighter factor would fail. Re-measure with the
/// `STUFFR_FUZZ_SCAN_TRACE` recipe in `CONTRIBUTING.md` before changing
/// either figure, and never raise one to fit a scanner.
pub const SCAN_READ_FACTOR: u64 = 8;
/// See [`SCAN_READ_FACTOR`].
pub const SCAN_READ_SLACK: u64 = 64 * 1024;

/// `Err` naming both figures when a scan read more than
/// [`SCAN_READ_FACTOR`] × `file_len` + [`SCAN_READ_SLACK`] bytes — work
/// that grows faster than its input, the class 0.10.3 closed in cpio
/// (zero-run rescans) and tar (converging extension chains).
pub fn check_scan_is_linear(bytes_read: u64, file_len: u64) -> std::result::Result<(), String> {
    let bound = SCAN_READ_FACTOR
        .saturating_mul(file_len)
        .saturating_add(SCAN_READ_SLACK);
    if bytes_read > bound {
        return Err(format!(
            "salvage scan read {bytes_read} bytes of a {file_len}-byte input, past the \
             {SCAN_READ_FACTOR}x + {SCAN_READ_SLACK} bound: its work grows faster than its input"
        ));
    }
    Ok(())
}

/// `Err` unless `sightings` came out of a [`crate::salvage::SightingLog`]
/// with its default cap and stand for exactly `total` sightings (0.10.4):
/// at most [`crate::salvage::SightingLog::DEFAULT_CAP`] stored per (format,
/// shape, kind), each group's stored offsets strictly ascending — the
/// smallest, so the offsets a caller lists are the ones an uncapped list
/// would show — and the stored count plus every [`Sighting::more`] equal to
/// `total`.
///
/// [`Sighting::more`]: crate::salvage::Sighting::more
pub fn check_sightings_bounded(
    sightings: &[crate::salvage::Sighting],
    total: u64,
) -> std::result::Result<(), String> {
    use crate::salvage::{SightingKind, SightingLog};
    let mut groups: Vec<((FormatId, &'static str, SightingKind), usize, u64)> = Vec::new();
    for s in sightings {
        let key = (s.format, s.shape, s.kind);
        match groups.iter_mut().find(|(k, _, _)| *k == key) {
            Some((_, stored, last)) => {
                if s.offset <= *last {
                    return Err(format!(
                        "{} {:?} stored offset {} after {last}: not ascending",
                        s.format, s.shape, s.offset
                    ));
                }
                *stored += 1;
                *last = s.offset;
            }
            None => groups.push((key, 1, s.offset)),
        }
    }
    if let Some(((format, shape, _), stored, _)) = groups
        .iter()
        .find(|(_, stored, _)| *stored > SightingLog::DEFAULT_CAP)
    {
        return Err(format!(
            "{stored} {format} {shape:?} sightings stored, past the cap of {}",
            SightingLog::DEFAULT_CAP
        ));
    }
    let counted: u64 = sightings.iter().map(|s| 1 + s.more).sum();
    if counted != total {
        return Err(format!("the sightings stand for {counted}, not {total}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::ReaderSource;
    use std::io::Read;

    /// Runs `src` through the ladder with `MockContainer`'s own capabilities
    /// and the default policy, producing the `Resolved` that `open` now
    /// requires. Most tests here care about `open`'s behaviour, not the
    /// ladder's, so this keeps that plumbing out of their way.
    fn resolve_default(src: Box<dyn Source>) -> Resolved {
        crate::resolve(
            src,
            MOCK_CONTAINER,
            MockContainer.caps(),
            &Default::default(),
        )
        .unwrap()
    }

    #[test]
    fn a_decoder_returns_a_source_so_capabilities_survive_the_layer() {
        // The point of the Source return type: a decoded stream can report what
        // it supports. The ordinary codec reports no seek; a codec with a frame
        // index would report otherwise, and the ladder could then run between
        // codec and container.
        let encoded: Vec<u8> = b"the quick brown fox".iter().map(|b| b ^ 0xFF).collect();
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(encoded)));
        let dec = MockCodec.decoder(src, &DecodeOpts::default()).unwrap();
        assert!(!dec.caps().seekable);
    }

    #[test]
    fn mock_codec_round_trips() {
        let plain = b"the quick brown fox".to_vec();
        let codec = MockCodec;

        let sink = SharedBuf::new();
        {
            let mut s = codec
                .encoder(Box::new(sink.clone()), &EncodeOpts::default())
                .unwrap();
            std::io::Write::write_all(&mut s, &plain).unwrap();
            s.finish().unwrap();
        }
        let encoded = sink.contents();
        assert_ne!(encoded, plain, "the mock must actually transform the bytes");

        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(encoded)));
        let mut dec = codec.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, plain);
    }

    #[test]
    fn mock_codec_declares_both_directions() {
        let c = MockCodec.caps();
        assert!(c.encode && c.decode);
    }

    #[test]
    fn mock_archive_reads_back_every_entry_in_order() {
        let bytes = mock_archive_bytes(&[("a.txt", b"alpha"), ("b.bin", b"bravo!!")]);
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
        let mut ar = MockContainer
            .open(resolve_default(src), &OpenOpts::default())
            .unwrap();

        let mut seen = Vec::new();
        while let Some(mut e) = ar.next_entry().unwrap() {
            let name = e.meta().name.clone();
            let mut data = Vec::new();
            e.reader().read_to_end(&mut data).unwrap();
            seen.push((name, data));
        }

        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0], ("a.txt".to_string(), b"alpha".to_vec()));
        assert_eq!(seen[1], ("b.bin".to_string(), b"bravo!!".to_vec()));
    }

    #[test]
    fn mock_container_declares_zip_shaped_capabilities() {
        let c = MockContainer.caps();
        assert!(c.read && c.write);
        assert!(c.forward_parse, "must exercise the ForwardOnly rung");
        assert!(c.trailing_index, "must exercise the index-loss warning");
        assert!(!c.needs_seek);
    }

    #[test]
    fn mock_archive_writer_output_is_readable_by_the_reader() {
        let sink = SharedBuf::new();
        {
            let mut w = MockContainer
                .create(
                    crate::archive::PlainSink::new(Box::new(sink.clone())),
                    &CreateOpts::default(),
                )
                .unwrap();
            w.add(&EntryMeta::file("only.txt"), &mut &b"hello"[..])
                .unwrap();
            w.finish().unwrap().finish().unwrap();
        }
        let buf = sink.contents();
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(buf)));
        let mut ar = MockContainer
            .open(resolve_default(src), &OpenOpts::default())
            .unwrap();
        let mut e = ar.next_entry().unwrap().expect("one entry");
        assert_eq!(e.meta().name, "only.txt");
        let mut data = Vec::new();
        e.reader().read_to_end(&mut data).unwrap();
        assert_eq!(data, b"hello");
    }

    #[test]
    fn traits_are_object_safe() {
        // Regression guard: a `&self`-less or generic method would break every
        // registry lookup, and the failure would surface far from the cause.
        let _c: &dyn Codec = &MockCodec;
        let _k: &dyn Container = &MockContainer;
    }

    #[test]
    fn by_index_reaches_entries_out_of_order_and_agrees_with_sequential_reads() {
        // by_index trusts offsets recorded by the writer. Reading out of order
        // is what distinguishes real random access from an accidental
        // sequential walk, and cross-checking against next_entry proves the
        // two paths agree rather than merely that each returns something.
        let bytes =
            mock_archive_bytes(&[("a.txt", b"alpha"), ("b.bin", b"bravo!!"), ("c.log", b"")]);

        let seekable = || -> Box<dyn Source> {
            let mut f = tempfile::NamedTempFile::new().unwrap();
            std::io::Write::write_all(&mut f, &bytes).unwrap();
            let (_, path) = f.keep().unwrap();
            Box::new(crate::source::FileSource::open(&path).unwrap())
        };

        // Sequential pass, for cross-checking.
        let mut ar = MockContainer
            .open(resolve_default(seekable()), &OpenOpts::default())
            .unwrap();
        let mut sequential = Vec::new();
        while let Some(mut e) = ar.next_entry().unwrap() {
            let name = e.meta().name.clone();
            let mut data = Vec::new();
            e.reader().read_to_end(&mut data).unwrap();
            sequential.push((name, data));
        }

        // Random access, deliberately out of order.
        let mut ar = MockContainer
            .open(resolve_default(seekable()), &OpenOpts::default())
            .unwrap();
        for i in [2usize, 0, 1] {
            let mut e = ar.by_index(i).unwrap();
            let name = e.meta().name.clone();
            let mut data = Vec::new();
            e.reader().read_to_end(&mut data).unwrap();
            assert_eq!(
                (name, data),
                sequential[i].clone(),
                "by_index({i}) disagreed with the sequential read"
            );
        }

        // Past the end is a miss, not a panic or a wrong entry.
        let mut ar = MockContainer
            .open(resolve_default(seekable()), &OpenOpts::default())
            .unwrap();
        assert!(matches!(
            ar.by_index(99),
            Err(crate::Error::EntryNotFound(_))
        ));
    }

    #[test]
    fn open_reports_lossless_fidelity_on_a_seekable_source() {
        let bytes = mock_archive_bytes(&[("a.txt", b"alpha")]);
        let mut f = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut f, &bytes).unwrap();
        let src: Box<dyn Source> = Box::new(crate::source::FileSource::open(f.path()).unwrap());

        let ar = MockContainer
            .open(resolve_default(src), &OpenOpts::default())
            .unwrap();
        let report = ar.fidelity();
        assert_eq!(report.rung, crate::Rung::Exact);
        assert!(
            report.is_lossless(),
            "a seekable source must yield an authoritative, warning-free report"
        );
    }

    #[test]
    fn open_reports_index_and_count_loss_on_a_non_seekable_source() {
        let bytes = mock_archive_bytes(&[("a.txt", b"alpha")]);
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));

        let ar = MockContainer
            .open(resolve_default(src), &OpenOpts::default())
            .unwrap();
        let report = ar.fidelity();
        assert_eq!(report.rung, crate::Rung::ForwardOnly);
        assert!(
            report
                .warnings
                .contains(&crate::Fidelity::TrailingIndexUnread {
                    format: MOCK_CONTAINER
                })
        );
        assert!(
            report
                .warnings
                .contains(&crate::Fidelity::EntryCountUnknown)
        );
    }

    #[test]
    fn a_container_can_see_the_rung_it_was_opened_at() {
        // Before this change the ladder could select Degraded but no container
        // could learn it had been asked for a salvage scan.
        let bytes = mock_archive_bytes(&[("a.txt", b"alpha")]);
        let caps = ContainerCaps {
            degraded_parse: true,
            ..MockContainer.caps()
        };
        let policy = crate::StreamPolicy::Adaptive {
            allow_forward_only: false,
            spill: crate::SpillPolicy::Off,
            allow_degraded: true,
        };
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
        let resolved = crate::resolve(src, MOCK_CONTAINER, caps, &policy).unwrap();
        assert_eq!(resolved.rung, crate::Rung::Degraded);

        let ar = MockContainer.open(resolved, &OpenOpts::default()).unwrap();
        assert_eq!(
            ar.fidelity().rung,
            crate::Rung::Degraded,
            "the rung must reach the container"
        );
    }

    #[test]
    fn a_spilled_read_reports_spilled_without_a_manual_merge() {
        // The ladder spills, so the container sees a SEEKABLE source. Before
        // this change it therefore reported Exact, and the spill was invisible
        // to anyone reading fidelity() alone.
        let bytes = mock_archive_bytes(&[("a.txt", b"alpha")]);
        let policy = crate::StreamPolicy::Adaptive {
            allow_forward_only: false,
            spill: crate::SpillPolicy::default(),
            allow_degraded: true,
        };
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
        let resolved = crate::resolve(src, MOCK_CONTAINER, MockContainer.caps(), &policy).unwrap();
        assert_eq!(resolved.rung, crate::Rung::Spilled);

        let ar = MockContainer.open(resolved, &OpenOpts::default()).unwrap();
        assert_eq!(ar.fidelity().rung, crate::Rung::Spilled);
        assert!(
            ar.fidelity().is_lossless(),
            "spilling costs disk, not accuracy"
        );
    }

    #[test]
    fn the_container_inherits_the_ladders_seed_rather_than_rederiving_it() {
        // The ladder seeds TrailingIndexUnread + EntryCountUnknown from caps.
        // The container must not independently derive the same two — inheriting
        // them is what removes the duplication merge() had to paper over.
        let bytes = mock_archive_bytes(&[("a.txt", b"alpha")]);
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
        let resolved = crate::resolve(
            src,
            MOCK_CONTAINER,
            MockContainer.caps(),
            &Default::default(),
        )
        .unwrap();
        let ar = MockContainer.open(resolved, &OpenOpts::default()).unwrap();

        let n = ar
            .fidelity()
            .warnings
            .iter()
            .filter(|w| matches!(w, crate::Fidelity::EntryCountUnknown))
            .count();
        assert_eq!(n, 1, "EntryCountUnknown must appear exactly once");
    }

    #[test]
    fn degraded_salvages_a_stream_that_forward_only_cannot_parse() {
        // Eight bytes of junk before the first record. A forward parse trusts
        // offset 0 and finds nothing; a salvage scan finds the record. Both
        // sources are non-seekable, so this is the difference the Degraded rung
        // actually buys — and it is reachable, unlike a difference gated on
        // seekability, which the ladder never pairs with Degraded.
        let mut bytes = b"JUNKJUNK".to_vec();
        bytes.extend_from_slice(&mock_archive_bytes(&[("a.txt", b"alpha")]));

        let forward = crate::resolve(
            Box::new(ReaderSource::new(std::io::Cursor::new(bytes.clone()))),
            MOCK_CONTAINER,
            MockContainer.caps(),
            &crate::StreamPolicy::default(),
        )
        .unwrap();
        assert_eq!(forward.rung, crate::Rung::ForwardOnly);
        let mut ar = MockContainer.open(forward, &OpenOpts::default()).unwrap();
        assert!(
            ar.next_entry().unwrap().is_none(),
            "a forward parse cannot start mid-junk"
        );

        let caps = ContainerCaps {
            degraded_parse: true,
            ..MockContainer.caps()
        };
        let policy = crate::StreamPolicy::Adaptive {
            allow_forward_only: false,
            spill: crate::SpillPolicy::Off,
            allow_degraded: true,
        };
        let salvage = crate::resolve(
            Box::new(ReaderSource::new(std::io::Cursor::new(bytes))),
            MOCK_CONTAINER,
            caps,
            &policy,
        )
        .unwrap();
        assert_eq!(salvage.rung, crate::Rung::Degraded);
        let mut ar = MockContainer.open(salvage, &OpenOpts::default()).unwrap();
        let mut e = ar
            .next_entry()
            .unwrap()
            .expect("salvage must recover the record");
        assert_eq!(e.meta().name, "a.txt");
        let mut data = Vec::new();
        e.reader().read_to_end(&mut data).unwrap();
        assert_eq!(data, b"alpha");
    }

    #[test]
    fn a_codec_parallelises_only_when_handed_a_governor() {
        // The seam: no ambient global. Without a governor the codec must not
        // claim workers; with one it draws from the shared budget.
        let plain = b"the quick brown fox".to_vec();

        let solo = DecodeOpts::default();
        assert!(solo.governor.is_none());
        assert_eq!(MockCodec.workers_for_opts(&solo), 1);

        let gov = crate::Governor::new(4, 1024 * 1024 * 1024);
        let opts = DecodeOpts {
            threads: Some(4),
            governor: Some(std::sync::Arc::clone(&gov)),
            ..Default::default()
        };
        assert_eq!(MockCodec.workers_for_opts(&opts), 4);
        assert_eq!(gov.outstanding(), 0, "the lease must be released again");

        // Decoding still works either way.
        let encoded: Vec<u8> = plain.iter().map(|b| b ^ 0xFF).collect();
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(encoded)));
        let mut dec = MockCodec.decoder(src, &opts).unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, plain);
    }

    #[test]
    fn opts_debug_does_not_require_a_debug_bound_on_governor() {
        let gov = crate::Governor::new(2, 1024);
        let o = DecodeOpts {
            threads: None,
            governor: Some(gov),
            ..Default::default()
        };
        assert!(format!("{o:?}").contains("governor"));
    }

    #[test]
    fn counting_source_counts_delivered_bytes() {
        use std::io::{Cursor, Seek, SeekFrom};
        let mut src = CountingSource::new(Cursor::new(vec![1u8; 100]));
        let mut buf = [0u8; 30];
        src.read_exact(&mut buf).unwrap();
        src.seek(SeekFrom::Start(0)).unwrap();
        src.read_exact(&mut buf).unwrap();
        assert_eq!(src.bytes_read(), 60);
    }

    #[test]
    fn a_compat_case_round_trips_through_its_wire_format() {
        let seed = encode_compat_case(
            "bunzip2",
            0,
            &["-k", "--", "a.bz2"],
            &["a.bz2"],
            true,
            b"BZh9",
        );
        let case = decode_compat_case(&seed).unwrap();
        assert_eq!(
            case,
            CompatCase {
                name: "bunzip2",
                flavour: 0,
                args: vec!["-k", "--", "a.bz2"],
                files: vec!["a.bz2"],
                stdin: true,
                payload: b"BZh9",
            }
        );
        let seed = encode_compat_case(
            "gzcat",
            1,
            &["-S", ".x", "a.tgz"],
            &["a.gz", "a.tgz", "a.z"],
            false,
            b"\x1f\x8b",
        );
        let case = decode_compat_case(&seed).unwrap();
        assert_eq!(
            case,
            CompatCase {
                name: "gzcat",
                flavour: 1,
                args: vec!["-S", ".x", "a.tgz"],
                files: vec!["a.gz", "a.tgz", "a.z"],
                stdin: false,
                payload: b"\x1f\x8b",
            }
        );
        // Cut before the mask: nothing to run.
        assert!(decode_compat_case(&seed[..5]).is_none());
        // Every file is a token, so an operand can name it.
        assert!(COMPAT_FILES.iter().all(|f| COMPAT_TOKENS.contains(f)));
        // No token leaves the case's directory.
        assert!(
            COMPAT_TOKENS
                .iter()
                .all(|t| !t.contains('/') && !t.contains(".."))
        );
    }

    /// R6: mask bit 4 stays the stdin bit; the files appended after the
    /// first four take bits 5, 6 and 7 (`index + 1`).
    #[test]
    fn compat_mask_skips_the_stdin_bit() {
        assert_eq!(&COMPAT_FILES[4..7], ["a.gz", "a.tgz", "a.z"]);
        for (file, bit) in [("a.gz", 5), ("a.tgz", 6), ("a.z", 7)] {
            let seed = encode_compat_case("gzip", 0, &[], &[file], false, b"");
            assert_eq!(seed.last(), Some(&(1u8 << bit)), "{file}");
            let case = decode_compat_case(&seed).unwrap();
            assert_eq!(case.files, [file]);
            assert!(!case.stdin, "{file} set the stdin bit");
        }
        // The stdin bit alone names no file.
        let case = decode_compat_case(&[4, 0, COMPAT_STDIN_BIT]).unwrap();
        assert!(case.stdin);
        assert!(case.files.is_empty(), "{:?}", case.files);
        // Every bit of the one mask byte: the first seven files and stdin.
        let case = decode_compat_case(&[4, 0, 0xff]).unwrap();
        assert_eq!(case.files, COMPAT_FILES[..7]);
        assert!(case.stdin);
    }

    /// A seed written by the 0.11.0 generator decodes as it did then, and
    /// as GNU: its name byte is below the first four names' count, its
    /// tokens below the 0.11.0 table's length, and its mask uses bits 0-4.
    /// The 0.11.0 decoder is restated here from that release's tables.
    /// Then the same for the 0.12.0 generator's seeds
    /// (`seeds_of_0_12_0_decode_unchanged`).
    #[test]
    fn old_seeds_decode_unchanged() {
        const OLD_NAMES: [&str; 4] = ["bzip2", "bunzip2", "bzcat", "bzip2recover"];
        const OLD_FILES: [&str; 4] = ["a", "a.bz2", "a.tbz2", "a.out"];
        // `git show v0.11.0:crates/stuffr-core/src/testing.rs`, verbatim.
        const OLD_TOKEN_TABLE: [&str; 56] = [
            "-c",
            "-d",
            "-z",
            "-f",
            "-t",
            "-k",
            "-s",
            "-q",
            "-v",
            "-V",
            "-L",
            "-h",
            "-1",
            "-2",
            "-3",
            "-4",
            "-5",
            "-6",
            "-7",
            "-8",
            "-9",
            "-x",
            "-dc",
            "-cd",
            "-tv",
            "-kf",
            "-dfk",
            "-qt",
            "-vvv",
            "-zc",
            "-s1",
            "-dq",
            "--stdout",
            "--decompress",
            "--compress",
            "--force",
            "--test",
            "--keep",
            "--small",
            "--quiet",
            "--version",
            "--license",
            "--exponential",
            "--repetitive-best",
            "--repetitive-fast",
            "--fast",
            "--best",
            "--verbose",
            "--help",
            "--bogus",
            "--",
            "-",
            "a",
            "a.bz2",
            "a.tbz2",
            "a.out",
        ];
        const OLD_TOKENS: usize = OLD_TOKEN_TABLE.len();
        assert_eq!(COMPAT_TOKENS[..OLD_TOKENS], OLD_TOKEN_TABLE);
        assert_eq!(COMPAT_NAMES[..4], OLD_NAMES);
        assert_eq!(COMPAT_FILES[..4], OLD_FILES);

        // `bunzip2 -k -- a.bz2`, with a.bz2 and stdin, as 0.11.0 wrote it.
        let seed = [1, 3, 5, 50, 53, 0b1_0010, b'B', b'Z', b'h', b'9'];
        let case = decode_compat_case(&seed).unwrap();
        assert_eq!(
            case,
            CompatCase {
                name: "bunzip2",
                flavour: 0,
                args: vec!["-k", "--", "a.bz2"],
                files: vec!["a.bz2"],
                stdin: true,
                payload: b"BZh9",
            }
        );

        // Every name byte, mask and token the 0.11.0 generator could write.
        for name in 0..4u8 {
            for mask in 0..32u8 {
                for token in 0..OLD_TOKENS as u8 {
                    let seed = [name, 1, token, mask];
                    let case = decode_compat_case(&seed).unwrap();
                    let old_files: Vec<&str> = (0..4)
                        .filter(|i| mask & (1 << i) != 0)
                        .map(|i| OLD_FILES[i])
                        .collect();
                    assert_eq!(case.name, OLD_NAMES[usize::from(name)]);
                    assert_eq!(case.flavour, 0);
                    assert_eq!(case.args, [OLD_TOKEN_TABLE[usize::from(token)]]);
                    assert_eq!(case.files, old_files);
                    assert_eq!(case.stdin, mask & 0x10 != 0);
                }
            }
        }
        seeds_of_0_12_0_decode_unchanged();
        seeds_of_0_13_decode_unchanged();
        seeds_of_0_14_decode_unchanged();
    }

    /// A seed written by the 0.12.0 generator decodes as it did then: a
    /// GNU name byte below that release's eight names, an argument count
    /// up to [`COMPAT_MAX_ARGS`], tokens below its 74, any of the mask's
    /// eight bits, and the payload right after the mask. (Its BSD name
    /// bytes, 8-15, moved when 0.13.0 appended the xz names: R7's
    /// documented price, `flavour_from_name_byte`.) The 0.12.0 decoder is
    /// restated from that release's tables.
    fn seeds_of_0_12_0_decode_unchanged() {
        const OLD_NAMES: [&str; 8] = [
            "bzip2",
            "bunzip2",
            "bzcat",
            "bzip2recover",
            "gzip",
            "gunzip",
            "zcat",
            "gzcat",
        ];
        const OLD_FILES: [&str; 7] = ["a", "a.bz2", "a.tbz2", "a.out", "a.gz", "a.tgz", "a.z"];
        const OLD_TOKENS: usize = 74;
        assert_eq!(COMPAT_NAMES[..8], OLD_NAMES);
        assert_eq!(COMPAT_FILES[..7], OLD_FILES);
        assert_eq!(COMPAT_TOKENS[OLD_TOKENS - 1], "a.z");
        let old_bit = |i: usize| 1u8 << if i < 4 { i } else { i + 1 };
        for name in 0..8u8 {
            for argc in 0..=COMPAT_MAX_ARGS as u8 {
                for mask in 0..=255u8 {
                    let token = (u32::from(mask) * 7 + u32::from(argc)) as u8 % OLD_TOKENS as u8;
                    let mut seed = vec![name, argc];
                    seed.extend(std::iter::repeat_n(token, usize::from(argc)));
                    seed.extend([mask, 0xA5, 0x5A]);
                    let case = decode_compat_case(&seed).unwrap();
                    let old_files: Vec<&str> = (0..7)
                        .filter(|&i| mask & old_bit(i) != 0)
                        .map(|i| OLD_FILES[i])
                        .collect();
                    assert_eq!(case.name, OLD_NAMES[usize::from(name)]);
                    assert_eq!(case.flavour, 0);
                    assert_eq!(case.args.len(), usize::from(argc));
                    assert!(
                        case.args
                            .iter()
                            .all(|a| *a == COMPAT_TOKENS[usize::from(token)])
                    );
                    assert_eq!(case.files, old_files, "mask {mask:#x}");
                    assert_eq!(case.stdin, mask & 0x10 != 0);
                    assert_eq!(case.payload, [0xA5, 0x5A], "argc {argc} mask {mask:#x}");
                    // And the 0.13.0 encoder writes exactly those bytes.
                    let again = encode_compat_case(
                        case.name,
                        0,
                        &case.args,
                        &case.files,
                        case.stdin,
                        case.payload,
                    );
                    assert_eq!(again, seed, "argc {argc} mask {mask:#x}");
                }
            }
        }
    }

    /// A seed written by the 0.13.0 to 0.13.2 generators decodes as it did
    /// then: a GNU name byte below that release's fourteen names, an
    /// argument count byte up to `2 × COMPAT_MAX_ARGS + 1` (past
    /// [`COMPAT_MAX_ARGS`], a second mask byte follows), tokens below its
    /// 106, the twelve files on bits 0-3 and 5-12, and the payload right
    /// after the mask. The second byte's bits 13-15 named nothing then and
    /// no generator of those releases wrote them (the 0.14.0 files take
    /// them, `zstd_files_take_bits_past_the_stdin_bit`). The decoder is
    /// restated from that release's tables.
    fn seeds_of_0_13_decode_unchanged() {
        const OLD_FILES: [&str; 12] = [
            "a", "a.bz2", "a.tbz2", "a.out", "a.gz", "a.tgz", "a.z", "a.xz", "a.txz", "a.lzma",
            "a.tlz", "a.lz",
        ];
        const OLD_NAMES: usize = 14;
        const OLD_TOKENS: usize = 106;
        assert_eq!(COMPAT_NAMES[OLD_NAMES - 1], "lzcat");
        assert_eq!(COMPAT_FILES[..12], OLD_FILES);
        assert_eq!(COMPAT_TOKENS[OLD_TOKENS - 1], "--files0=a");
        let old_bit = |i: usize| 1u16 << if i < 4 { i } else { i + 1 };
        let max = COMPAT_MAX_ARGS as u8;
        for name in 0..OLD_NAMES as u8 {
            for argc in [0, 3, max, max + 1, max + 4, 2 * max + 1] {
                let wide = argc > max;
                let highs: u8 = if wide { 0x20 } else { 1 };
                for high in 0..highs {
                    for low in 0..=255u8 {
                        let n = usize::from(argc % (max + 1));
                        let token = (u32::from(low) * 7 + u32::from(argc)) as u8 % OLD_TOKENS as u8;
                        let mut seed = vec![name, argc];
                        seed.extend(std::iter::repeat_n(token, n));
                        seed.push(low);
                        if wide {
                            seed.push(high);
                        }
                        seed.extend([0xA5, 0x5A]);
                        let case = decode_compat_case(&seed).unwrap();
                        let mask = u16::from_le_bytes([low, high]);
                        let old_files: Vec<&str> = (0..12)
                            .filter(|&i| mask & old_bit(i) != 0)
                            .map(|i| OLD_FILES[i])
                            .collect();
                        assert_eq!(case.name, COMPAT_NAMES[usize::from(name)]);
                        assert_eq!(case.flavour, 0);
                        assert_eq!(case.args.len(), n);
                        assert!(
                            case.args
                                .iter()
                                .all(|a| *a == COMPAT_TOKENS[usize::from(token)])
                        );
                        assert_eq!(case.files, old_files, "argc {argc} mask {mask:#x}");
                        assert_eq!(case.stdin, low & 0x10 != 0);
                        assert_eq!(case.payload, [0xA5, 0x5A], "argc {argc} mask {mask:#x}");
                        // A case naming an xz-family file re-encodes to the
                        // same bytes; one that did not (a wide count byte
                        // with only low files) re-encodes narrower, as
                        // every generator wrote it.
                        if wide == old_files.iter().any(|f| OLD_FILES[7..].contains(f)) {
                            let again = encode_compat_case(
                                case.name,
                                0,
                                &case.args,
                                &case.files,
                                case.stdin,
                                case.payload,
                            );
                            assert_eq!(again, seed, "argc {argc} mask {mask:#x}");
                        }
                    }
                }
            }
        }
    }

    /// A seed written by the 0.14.0 generator decodes as it did then: a GNU
    /// name byte below that release's eighteen names, an argument count
    /// byte up to `2 × COMPAT_MAX_ARGS + 1` (a second mask byte past
    /// [`COMPAT_MAX_ARGS`], never a third), tokens below its 148, and the
    /// fifteen files on bits 0-3 and 5-15. The decoder is restated from
    /// that release's tables; 0.15.0's third byte starts at a count byte
    /// of `2 × (COMPAT_MAX_ARGS + 1)`, which no earlier generator wrote.
    fn seeds_of_0_14_decode_unchanged() {
        const OLD_NAMES: usize = 18;
        // The 0.14 table's length (0.15.0 appended 16 tokens, 0.16.0 12).
        const OLD_TOKENS: usize = 139;
        const OLD_FILES: usize = 15;
        assert_eq!(COMPAT_NAMES[OLD_NAMES - 1], "zstdmt");
        assert_eq!(COMPAT_TOKENS[OLD_TOKENS - 1], "a.tzst");
        assert_eq!(COMPAT_FILES[OLD_FILES - 1], "d.dict");
        let old_bit = |i: usize| 1u16 << if i < 4 { i } else { i + 1 };
        let max = COMPAT_MAX_ARGS as u8;
        for name in 0..OLD_NAMES as u8 {
            for argc in [0, 3, max, max + 1, max + 4, 2 * max + 1] {
                let wide = argc > max;
                for high in if wide { 0..=255u8 } else { 0..=0 } {
                    for low in [0u8, 1, 0x10, 0x55, 0xaa, 0xff] {
                        let n = usize::from(argc % (max + 1));
                        let token = (u32::from(low) * 7 + u32::from(argc)) as u8 % OLD_TOKENS as u8;
                        let mut seed = vec![name, argc];
                        seed.extend(std::iter::repeat_n(token, n));
                        seed.push(low);
                        if wide {
                            seed.push(high);
                        }
                        seed.extend([0xA5, 0x5A]);
                        let case = decode_compat_case(&seed).unwrap();
                        let mask = u16::from_le_bytes([low, high]);
                        let old_files: Vec<&str> = (0..OLD_FILES)
                            .filter(|&i| mask & old_bit(i) != 0)
                            .map(|i| COMPAT_FILES[i])
                            .collect();
                        assert_eq!(case.name, COMPAT_NAMES[usize::from(name)]);
                        assert_eq!(case.args.len(), n);
                        assert_eq!(case.files, old_files, "argc {argc} mask {mask:#x}");
                        assert_eq!(case.stdin, low & 0x10 != 0);
                        assert_eq!(case.payload, [0xA5, 0x5A], "argc {argc} mask {mask:#x}");
                        if wide == old_files.iter().any(|f| COMPAT_FILES[7..].contains(f)) {
                            let again = encode_compat_case(
                                case.name,
                                0,
                                &case.args,
                                &case.files,
                                case.stdin,
                                case.payload,
                            );
                            assert_eq!(again, seed, "argc {argc} mask {mask:#x}");
                        }
                    }
                }
            }
        }
    }

    /// R5 (0.15.0): the lz4 family's `a.lz4` is the sixteenth file, bit 16,
    /// the first of a third mask byte that follows only when the argument
    /// count byte is at least `2 × (COMPAT_MAX_ARGS + 1)`.
    #[test]
    fn lz4_files_take_new_bits() {
        assert_eq!(COMPAT_FILES[15], "a.lz4");
        let k = COMPAT_TOKENS.iter().position(|t| *t == "-k").unwrap() as u8;
        let f = COMPAT_TOKENS.iter().position(|t| *t == "a.lz4").unwrap() as u8;
        let seed = encode_compat_case("lz4", 0, &["-k", "a.lz4"], &["a.lz4"], false, b"p");
        let argc = 2 * (COMPAT_MAX_ARGS as u8 + 1) + 2;
        assert_eq!(seed, [18, argc, k, f, 0, 0, 1, b'p']);
        let case = decode_compat_case(&seed).unwrap();
        assert_eq!(case.name, "lz4");
        assert_eq!(case.args, ["-k", "a.lz4"]);
        assert_eq!(case.files, ["a.lz4"]);
        assert!(!case.stdin);
        assert_eq!(case.payload, b"p");
        // Old and new files and stdin together round-trip.
        let all: Vec<&str> = COMPAT_FILES.to_vec();
        let seed = encode_compat_case("unlz4", 0, &["-d"], &all, true, b"xy");
        let case = decode_compat_case(&seed).unwrap();
        assert_eq!(case.files, all);
        assert!(case.stdin);
        assert_eq!(case.payload, b"xy");
        // Every bit of all three bytes. The argument-count byte is 18, which
        // is zero arguments (18 % 9 == 0, as COMPAT_MAX_ARGS + 1 is 9) and
        // still at least 2 x 9, so the third mask byte is read; the three
        // 0xff bytes then set every file bit and no token follows.
        let case = decode_compat_case(&[18, 18, 0xff, 0xff, 0xff]).unwrap();
        assert_eq!(case.files, COMPAT_FILES);
        // A third-byte case cut before its third byte: nothing to run.
        assert!(decode_compat_case(&[18, 18, 0, 0]).is_none());
        // Every token the lz4 family brought is in the table, and the
        // tables still fit the wire's byte; every file is a token.
        for t in [
            "-BD",
            "-BX",
            "-B4",
            "-B32",
            "-12",
            "--favor-decSpeed",
            "--no-frame-crc",
            "--content-size",
            "-m",
            "d.lz4dict",
            "null",
            "stdout",
            "-c0",
            "-hc",
            "-y",
            "a.lz4",
        ] {
            assert!(COMPAT_TOKENS.contains(&t), "{t}");
        }
        assert!(COMPAT_FILES.iter().all(|f| COMPAT_TOKENS.contains(f)));
        assert!(COMPAT_TOKENS.len() <= 256);
    }

    /// 0.16.0: the unzip family's `a.zip` and `b.zip` are the seventeenth
    /// and eighteenth files, bits 17 and 18 of the third mask byte, which no
    /// earlier generator set: every 0.15 seed decodes as it did.
    #[test]
    fn zip_files_take_bits_17_and_18() {
        assert_eq!(&COMPAT_FILES[16..], ["a.zip", "b.zip"]);
        let t = |s: &str| COMPAT_TOKENS.iter().position(|t| *t == s).unwrap() as u8;
        let argc = 2 * (COMPAT_MAX_ARGS as u8 + 1) + 2;
        for (file, top) in [("a.zip", 1u8 << 1), ("b.zip", 1 << 2)] {
            let seed = encode_compat_case("unzip", 1, &["-t", file], &[file], false, b"p");
            assert_eq!(seed, [22 + 25, argc, t("-t"), t(file), 0, 0, top, b'p']);
            let case = decode_compat_case(&seed).unwrap();
            assert_eq!((case.name, case.flavour), ("unzip", 1));
            assert_eq!(case.args, ["-t", file]);
            assert_eq!(case.files, [file]);
            assert!(!case.stdin);
        }
        // An lz4 seed of 0.15.0 (`a.lz4` alone in the third byte) decodes
        // unchanged.
        let old = [18, 18 + 1, t("-d"), 0, 0, 1, b'x'];
        let case = decode_compat_case(&old).unwrap();
        assert_eq!(case.files, ["a.lz4"]);
        assert_eq!(case.args, ["-d"]);
        assert_eq!(
            encode_compat_case("lz4", 0, &["-d"], &["a.lz4"], false, b"x"),
            old
        );
        // Every token the unzip family brought, and every file is a token.
        for tok in [
            "-l", "-v", "-t", "-p", "-c", "-o", "-n", "-P", "-d", "-x", "-Z", "-j", "-a", "-C",
            "-L", "-X", "-q", "-O", "-I", "-M", "a.zip", "b.zip",
        ] {
            assert!(COMPAT_TOKENS.contains(&tok), "{tok}");
        }
        assert!(COMPAT_FILES.iter().all(|f| COMPAT_TOKENS.contains(f)));
        assert!(COMPAT_TOKENS.len() <= 256);
    }

    /// R5 (0.14.0): the zstd family's files continue on bits 13-15 of the
    /// second mask byte, which fills it.
    #[test]
    fn zstd_files_take_bits_past_the_stdin_bit() {
        assert_eq!(&COMPAT_FILES[12..15], ["a.zst", "a.tzst", "d.dict"]);
        for (i, file) in COMPAT_FILES.iter().enumerate().skip(12).take(3) {
            let bit = i + 1;
            assert!((13..=15).contains(&bit));
            let seed = encode_compat_case("zstd", 0, &["-k", file], &[file], false, b"p");
            let argc = COMPAT_MAX_ARGS as u8 + 1 + 2;
            let k = COMPAT_TOKENS.iter().position(|t| *t == "-k").unwrap() as u8;
            let f = COMPAT_TOKENS.iter().position(|t| t == file).unwrap() as u8;
            assert_eq!(seed, [14, argc, k, f, 0, 1 << (bit - 8), b'p'], "{file}");
            let case = decode_compat_case(&seed).unwrap();
            assert_eq!(case.name, "zstd");
            assert_eq!(case.args, ["-k", *file]);
            assert_eq!(case.files, [*file]);
            assert!(!case.stdin, "{file} set the stdin bit");
            assert_eq!(case.payload, b"p");
        }
        // Files of every family and stdin together.
        let seed = encode_compat_case(
            "unzstd",
            0,
            &[],
            &["a", "a.gz", "a.lz", "d.dict"],
            true,
            b"",
        );
        let case = decode_compat_case(&seed).unwrap();
        assert_eq!(case.files, ["a", "a.gz", "a.lz", "d.dict"]);
        assert!(case.stdin);
        // Every bit of both bytes: all fifteen files and stdin.
        let case = decode_compat_case(&[14, 9, 0xff, 0xff]).unwrap();
        assert_eq!(case.files, COMPAT_FILES[..15]);
        assert!(case.stdin);
        // Every token the zstd family brought, and every file is a token.
        for t in [
            "-D",
            "--train",
            "--patch-from=a",
            "--format=lz4",
            "--output-dir-flat=d",
        ] {
            assert!(COMPAT_TOKENS.contains(&t), "{t}");
        }
        assert!(COMPAT_FILES.iter().all(|f| COMPAT_TOKENS.contains(f)));
        // A token index still fits the wire's byte.
        assert!(COMPAT_TOKENS.len() <= 256);
    }

    /// R5: the xz family's files follow the gzip family's on bits
    /// `index + 1`, past the stdin bit: bits 8-12, which a second mask
    /// byte holds. The second byte is there only when the argument-count
    /// byte is past [`COMPAT_MAX_ARGS`] (the count is still `byte % 9`),
    /// which no earlier generator wrote.
    #[test]
    fn xz_files_take_bits_past_the_stdin_bit() {
        assert_eq!(
            &COMPAT_FILES[7..12],
            ["a.xz", "a.txz", "a.lzma", "a.tlz", "a.lz"]
        );
        for (i, file) in COMPAT_FILES.iter().enumerate().skip(7).take(5) {
            let bit = i + 1;
            assert!((8..=12).contains(&bit));
            let seed = encode_compat_case("xz", 0, &["-k", file], &[file], false, b"p");
            let argc = COMPAT_MAX_ARGS as u8 + 1 + 2;
            let k = COMPAT_TOKENS.iter().position(|t| *t == "-k").unwrap() as u8;
            let f = COMPAT_TOKENS.iter().position(|t| t == file).unwrap() as u8;
            assert_eq!(seed, [8, argc, k, f, 0, 1 << (bit - 8), b'p'], "{file}");
            let case = decode_compat_case(&seed).unwrap();
            assert_eq!(case.name, "xz");
            assert_eq!(case.args, ["-k", *file]);
            assert_eq!(case.files, [*file]);
            assert!(!case.stdin, "{file} set the stdin bit");
            assert_eq!(case.payload, b"p");
        }
        // Old and new files and stdin together.
        let seed = encode_compat_case("unxz", 0, &[], &["a", "a.z", "a.lz"], true, b"");
        let case = decode_compat_case(&seed).unwrap();
        assert_eq!(case.files, ["a", "a.z", "a.lz"]);
        assert!(case.stdin);
        // Every bit of both bytes but the zstd family's (0.14.0): the
        // twelve files and stdin.
        let case = decode_compat_case(&[8, 9, 0xff, 0x1f]).unwrap();
        assert_eq!(case.files, COMPAT_FILES[..12]);
        assert!(case.stdin);
        assert!(case.args.is_empty());
        // An extended case cut before its second mask byte: nothing to run.
        assert!(decode_compat_case(&[8, 9, 0]).is_none());
        // A count byte of 9 + n still means n arguments.
        let case = decode_compat_case(&[8, 11, 0, 1, 0, 0]).unwrap();
        assert_eq!(case.args, [COMPAT_TOKENS[0], COMPAT_TOKENS[1]]);
        // Every file is still a token, so an operand can name it.
        assert!(COMPAT_FILES.iter().all(|f| COMPAT_TOKENS.contains(f)));
    }

    /// R7: the flavour is `(byte / COMPAT_NAMES.len()) & 1`, the name
    /// `byte % len`; the encoder writes `index + flavour * len`.
    #[test]
    fn flavour_from_name_byte() {
        let len = COMPAT_NAMES.len() as u8;
        assert_eq!(len, 25);
        let at = |byte: u8| {
            let seed = [byte, 0, 0];
            let case = decode_compat_case(&seed).unwrap();
            (case.name, case.flavour)
        };
        assert_eq!(at(0), ("bzip2", 0));
        assert_eq!(at(4), ("gzip", 0));
        assert_eq!(at(7), ("gzcat", 0));
        assert_eq!(at(8), ("xz", 0));
        assert_eq!(at(13), ("lzcat", 0));
        assert_eq!(at(14), ("zstd", 0));
        assert_eq!(at(17), ("zstdmt", 0));
        assert_eq!(at(18), ("lz4", 0));
        assert_eq!(at(21), ("lz4c", 0));
        assert_eq!(at(22), ("unzip", 0));
        assert_eq!(at(24), ("funzip", 0));
        assert_eq!(at(25), ("bzip2", 1));
        assert_eq!(at(29), ("gzip", 1));
        assert_eq!(at(32), ("gzcat", 1));
        assert_eq!(at(35), ("xzcat", 1));
        assert_eq!(at(44), ("unlz4", 1));
        assert_eq!(at(50), ("bzip2", 0));
        assert_eq!(at(255), ("gunzip", 0));
        for (i, name) in COMPAT_NAMES.iter().enumerate() {
            for flavour in 0..2u8 {
                let seed = encode_compat_case(name, flavour, &[], &[], false, b"");
                assert_eq!(
                    usize::from(seed[0]),
                    i + usize::from(flavour) * COMPAT_NAMES.len()
                );
                assert_eq!(at(seed[0]), (*name, flavour));
            }
        }
    }

    #[test]
    fn the_linear_bound_is_factor_times_length_plus_slack() {
        let len = 1_000_000;
        assert!(check_scan_is_linear(SCAN_READ_FACTOR * len + SCAN_READ_SLACK, len).is_ok());
        let err =
            check_scan_is_linear(SCAN_READ_FACTOR * len + SCAN_READ_SLACK + 1, len).unwrap_err();
        assert!(err.contains("read"), "{err}");
    }
}
