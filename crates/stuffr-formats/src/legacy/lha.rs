//! LHA/LZH, read-only, via `delharc`.
//!
//! # `delharc` streams; this is why LHA's caps differ from ARJ's
//!
//! `delharc::LhaDecodeReader<R>` is `impl<R: std::io::Read>` — no `Seek`
//! bound anywhere in its public API — and it implements `std::io::Read`
//! directly for the CURRENT entry's decoded bytes. So LHA parses forward off
//! a pipe natively: `--max-ratio` works normally here, and no
//! bound-before-allocation guard is needed the way ARJ's Task 6 needs one
//! (that crate materialises whole entries; this one does not). Do not copy
//! ARJ's guard in here "for symmetry" — it would be dead code protecting
//! against a decode shape this crate does not have.
//!
//! # No borrowed entry type — unlike tar, ar and cpio
//!
//! `LhaDecodeReader` does not hand back a borrowed `Entry<'a, R>` the way
//! `tar::Entries`/`ar::Archive`/`cpio::newc::Reader` do. It owns a "current
//! entry" cursor directly: `header()` describes it, `Read` decodes it, and
//! `next_file()` advances past whatever of it was not consumed. That means
//! this module needs none of `cpio.rs`'s or `tar.rs`'s self-referential
//! `Box::into_raw` machinery — [`LhaRead`] just owns the `LhaDecodeReader`
//! outright and hands back an `Entry` whose reader borrows `&mut self`.
//!
//! # The fixture's expectation comes from `lhasa`, not `delharc`
//!
//! That is the entire reason this format sits in Phase 3b rather than 3c —
//! see `fixtures/legacy/MANIFEST.md`'s `sample.lzh` entry for exactly how the
//! fixture was produced and independently verified (`lha v`/`lha t`/`lha x`,
//! lhasa 0.6.0). No tool on the build machine can CREATE an `.lzh` archive
//! (`lhasa` decompresses only; `delharc` itself has no writer), so the
//! fixture is hand-built from the LHA level-1 header layout and then checked
//! against lhasa, an implementation independent of the crate this module
//! wraps. Both agree, byte for byte — there is no lhasa/delharc disagreement
//! to report for this fixture.
//!
//! # Error mapping has no wildcard
//!
//! - `is_decoder_supported() == false` → [`Error::Unsupported`] (exit 3). A
//!   capability answer, not damage: the archive is fine, this build's `delharc`
//!   feature set (`std`, `lh1`, `lz` — no `lhx`) cannot decode that entry's
//!   method. Directories (`-lhd-`) are the one case where an unsupported
//!   decoder is NOT an error — see [`LhaRead::next_entry`].
//! - A failed `crc_check()` → `io::ErrorKind::InvalidData`, surfaced from the
//!   entry's own `Read` impl once its payload is fully consumed (see
//!   [`LhaEntryReader`]). Downstream, `entries.rs`'s `copy_charging` applies
//!   [`Error::from_decode_io`] to this, which is what turns it into
//!   [`Error::Corrupt`] (exit 5) for a real caller.
//! - Malformed header structure, encountered while [`LhaRead::next_entry`]
//!   advances via `next_file()` (or while [`Lha::open`] parses the first
//!   header), is classified directly by [`classify_lha_error`] into
//!   [`Error::Corrupt`] — a `crate::Error` constructed straight from
//!   `next_entry`'s own `Result`, never routed through the generic
//!   `io::Error -> Error::Io` `?`-conversion that would otherwise demote it
//!   to exit 1 (see that function's doc for why this distinction matters).
//! - Genuine io errors (a failing source) pass through as themselves via the
//!   same function.
//! - `create()` → [`Error::CapabilityUnavailable`] (exit 3), `` `lha` can be
//!   read but not written by this build``. Unreachable through ops, which is
//!   the point: `Registry::require_container_writer` refuses on `caps().write`
//!   before `create()` is ever called, so the trait method is a backstop that
//!   answers the same error rather than a second, differently-worded one.

use std::io::{self, Read};
use std::time::{Duration, UNIX_EPOCH};

use delharc::LhaDecodeReader;
use delharc::decode::LhaDecodeError;
use stuffr_core::{
    ArchiveRead, ArchiveWrite, Container, ContainerCaps, CorruptionDetection, CreateOpts, Entry,
    EntryKind, EntryMeta, Error, FidelityReport, FormatId, FormatMeta, MagicRule, OpenOpts,
    Resolved, Result, Sink, Source,
};

pub const LHA: FormatId = FormatId::new("lha");

/// LHA/LZH archives carry several method-family spellings at the same
/// offset (`compression` is 5 bytes: `-`, two method letters, a digit or
/// letter, `-`). Two rules, deliberately, not one: Task 1 left the
/// conformance harness's "at least one of several" magic semantics
/// unexercised by any registered format, and this is where it first gets a
/// real second rule to prove it against. `sample.lzh`'s own fixture uses
/// `-lh0-`, which matches the first rule and not the second — exactly the
/// "one hits, one doesn't" shape the property needs.
const LHA_MAGIC: &[MagicRule] = &[
    MagicRule {
        offset: 2,
        bytes: b"-lh",
        format: LHA,
    },
    MagicRule {
        offset: 2,
        bytes: b"-lz",
        format: LHA,
    },
];

pub fn meta() -> FormatMeta {
    FormatMeta::container(LHA, &["lzh", "lha"], LHA_MAGIC)
}

pub struct Lha;

impl Container for Lha {
    fn id(&self) -> FormatId {
        LHA
    }

    fn caps(&self) -> ContainerCaps {
        // `ContainerCaps::read_only()` rather than a literal spelling out
        // `read: true, write: false`: the constructor was written for exactly
        // this case ("a container that can be read but not written") and had
        // no user until the first two read-only containers arrived. It sets
        // `needs_seek: false` too, which `delharc` genuinely does not need.
        ContainerCaps {
            forward_parse: true,
            // Every plain LHA entry carries a CRC-16 the format MANDATES,
            // and `delharc`'s `crc_check()` is what raises on a mismatch —
            // a format-wide guarantee, not a per-writer option, so
            // `Always`. Read by the read-only conformance harness's
            // corruption property.
            detects_corruption: CorruptionDetection::Always,
            ..ContainerCaps::read_only()
        }
    }

    fn open(&self, resolved: Resolved, _o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
        let Resolved { source, report, .. } = resolved;
        let seekable = source.caps().seekable;
        let reader = LhaDecodeReader::new(source).map_err(classify_lha_error)?;
        Ok(Box::new(LhaRead {
            reader,
            report,
            seekable,
            advance_before_yield: false,
            done: false,
        }))
    }

    /// Unreachable through ops: `Registry::require_container_writer` reads
    /// `caps().write` and refuses first, exactly as `require_encoder` does
    /// for a decode-only codec. This is the trait-level backstop, and it
    /// answers the SAME error the registry raises — a caller who reached
    /// `create()` directly must not meet a differently-worded refusal for
    /// the identical contract.
    fn create(&self, _dst: Box<dyn Sink>, _o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
        Err(Error::CapabilityUnavailable {
            format: LHA,
            available: "read",
            requested: "written",
        })
    }
}

/// Classifies an error `delharc` raised while parsing a header, into this
/// project's error vocabulary — directly, as a `crate::Error`, from
/// [`LhaRead::next_entry`] (a `Result`-returning method), never via a bare
/// `io::Error` propagated through `?`.
///
/// That distinction is load-bearing, not stylistic. An `io::Error` reaching
/// a caller via `entry.reader().read_to_end(&mut data)?` is auto-converted
/// through `Error`'s `#[from] std::io::Error`, landing on `Error::Io` — and
/// `Error::Io` has no explicit arm in `Error::exit_code()`, so it ALWAYS
/// falls to that match's `_ => 1` wildcard regardless of the wrapped
/// `io::ErrorKind`. A corrupted header discovered here and reported that way
/// would say "stuffr failed", not "the archive is damaged". Building
/// `Error::Corrupt` directly and returning it from `next_entry()` sidesteps
/// that conversion entirely — `next_entry()`'s own signature is already
/// `Result<Option<Entry<'_>>>`, so nothing forces the io::Error round trip
/// here the way an `impl Read` payload reader is stuck with it.
///
/// `delharc`'s own `LhaError<io::Error> -> io::Error` conversion (used via
/// `LhaDecodeError`'s `Into<io::Error>`) folds `HeaderParse`, `Decompress`
/// and `Checksum` onto `io::ErrorKind::InvalidData` and passes `Io` through
/// unchanged. That alone is not the whole story, MEASURED directly against
/// this module's own `a_corrupted_second_header_is_reported_as_corrupt_
/// not_as_an_io_failure` test: flipping a header's declared length byte
/// does not always land on a checksum mismatch (`HeaderParse`, already
/// `InvalidData`) — it can instead make the parser try to read an
/// `extended_area` far past what the stream actually has left, which
/// surfaces as delharc's own synthesised "not enough bytes" signal
/// (`stub_io::Read::unexpected_eof`, wrapped as `LhaError::Io` since it
/// travels the ordinary `Read` error path, not a dedicated parse-error
/// variant) — `io::ErrorKind::UnexpectedEof`, passed through UNCHANGED by
/// delharc's own conversion. Left as `Error::Io`, that would fall to
/// `Error::exit_code`'s `_ => 1` wildcard: "stuffr failed", for a corrupted
/// archive.
///
/// `UnexpectedEof` is safe to fold onto `Corrupt` here, and specific to
/// this function rather than a widening of `stuffr_core::Error::
/// from_decode_io` itself, for the same reason `cpio.rs`'s
/// `CPIO_MALFORMED_AS_INVALID_DATA_EOF` and the other per-format constants
/// in `normalize.rs` are each their own constant: a genuine SOURCE failure
/// (a disk error) keeps ITS OWN native `io::ErrorKind` (e.g.
/// `PermissionDenied`) all the way through — delharc's blanket
/// `stub_io::Read` impl propagates such an error verbatim from the
/// underlying reader (`Err(e) => return Err(e)` in its `read_all`), it is
/// never rewritten to `UnexpectedEof`. Only delharc's own synthesised
/// "fewer bytes than requested, no underlying error" signal uses that kind,
/// so folding it here cannot mistake a bad disk for a bad archive.
fn classify_lha_error(e: LhaDecodeError<Box<dyn Source>>) -> Error {
    let io_err: io::Error = e.into();
    if io_err.kind() == io::ErrorKind::UnexpectedEof {
        return Error::Corrupt(io_err.to_string());
    }
    Error::from_decode_io(io_err)
}

struct LhaRead {
    reader: LhaDecodeReader<Box<dyn Source>>,
    report: FidelityReport,
    seekable: bool,
    /// Whether `next_file()` must be called before the header currently
    /// loaded in `reader` may be handed back as the next entry.
    ///
    /// `false` right after `open`: `LhaDecodeReader::new` already parsed the
    /// FIRST entry's header (that is how the crate's own API works — there
    /// is always a "current" entry, never a "before the first" state), so
    /// the first call to `next_entry` must not advance past it. Every call
    /// after that must.
    advance_before_yield: bool,
    /// Set once `next_file()` answers `Ok(false)` (clean end of archive) or
    /// any error was raised — either way, nothing more will be read.
    done: bool,
}

impl ArchiveRead for LhaRead {
    fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
        if self.done {
            return Ok(None);
        }

        if self.advance_before_yield {
            match self.reader.next_file() {
                Ok(true) => {}
                Ok(false) => {
                    self.done = true;
                    return Ok(None);
                }
                Err(e) => {
                    self.done = true;
                    return Err(classify_lha_error(e));
                }
            }
        }
        self.advance_before_yield = true;

        let header = self.reader.header();
        let name = header.parse_pathname_to_str();
        let is_directory = header.is_directory();
        let size = header.original_size;
        let compressed_size = header.compressed_size;
        let mtime = header
            .parse_last_modified()
            .to_utc()
            .and_then(|dt| u64::try_from(dt.timestamp()).ok())
            .map(|secs| UNIX_EPOCH + Duration::from_secs(secs));

        if !is_directory && !self.reader.is_decoder_supported() {
            let method = String::from_utf8_lossy(&header.compression).into_owned();
            self.done = true;
            return Err(Error::Unsupported(format!(
                "entry `{name}` uses LHA compression method `{method}`, which this build \
                 cannot decode (delharc compiled with `std`, `lh1`, `lz` — no `lhx`)"
            )));
        }

        let meta = EntryMeta {
            name,
            size: Some(size),
            compressed_size: Some(compressed_size),
            mtime,
            mode: None,
            uid: None,
            gid: None,
            kind: if is_directory {
                EntryKind::Dir
            } else {
                EntryKind::File
            },
            codec: None,
        };

        let reader: Box<dyn Read + '_> = if is_directory {
            Box::new(io::empty())
        } else {
            Box::new(LhaEntryReader {
                inner: &mut self.reader,
                crc_checked: false,
            })
        };

        Ok(Some(Entry::new(meta, reader)))
    }

    fn by_index(&mut self, index: usize) -> Result<Entry<'_>> {
        if self.seekable {
            return Err(Error::Unsupported(format!(
                "LHA carries no entry index, so entry {index} can only be reached by reading \
                 forward from the start"
            )));
        }
        Err(Error::NotSeekable { format: LHA })
    }

    fn fidelity(&self) -> &FidelityReport {
        &self.report
    }
}

/// Wraps `&mut LhaDecodeReader` for one entry's payload, adding the one thing
/// the crate leaves to its caller: verifying the trailing CRC-16 once the
/// payload is fully consumed.
///
/// `delharc`'s own `std::io::Read` impl for `LhaDecodeReader` never checks
/// the checksum itself — `crc_check()`/`crc_is_ok()` are separate methods a
/// caller is expected to call once reading is done (see the crate's own
/// `no_run` example in its module doc). Folding that check into `read()`
/// itself, rather than leaving it to a caller who might forget, is what lets
/// a corrupted `-lh0-` entry (whose PassthroughDecoder has no other way to
/// notice a flipped byte — it is a byte-for-byte copy, not a real codec)
/// still surface as an error instead of silently wrong bytes.
struct LhaEntryReader<'a> {
    inner: &'a mut LhaDecodeReader<Box<dyn Source>>,
    /// Whether the CRC has already been checked. Guards against checking it
    /// more than once (harmless) and against a zero-length `read()` call
    /// that has not actually reached the entry's real end (`is_empty()` is
    /// the true gate below, not merely `n == 0`).
    crc_checked: bool,
}

impl Read for LhaEntryReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if !self.crc_checked && self.inner.is_empty() {
            self.crc_checked = true;
            if !self.inner.crc_is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "LHA entry failed its CRC-16 check",
                ));
            }
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stuffr_core::testing::{ContainerFixture, ExpectedEntry, assert_container_conforms_with};
    use stuffr_core::{CreateOpts, OpenOpts, PlainSink, ReaderSource, StreamPolicy};

    const SAMPLE_LZH: &[u8] = include_bytes!("../../fixtures/legacy/sample.lzh");

    const LHA_EXPECTED: &[ExpectedEntry] = &[
        ExpectedEntry {
            name: "sample/hello.txt",
            content: b"alpha\n",
        },
        ExpectedEntry {
            name: "sample/sub/b.bin",
            content: b"beta\n",
        },
    ];

    fn lha_fixture() -> ContainerFixture {
        ContainerFixture {
            bytes: SAMPLE_LZH,
            expected: LHA_EXPECTED,
            provenance: "hand-built LHA level-1 archive (two `-lh0-`/store entries), \
                         independently verified with lhasa 0.6.0 (`lha v`/`lha t`/`lha x`) — \
                         an implementation independent of delharc; see \
                         fixtures/legacy/MANIFEST.md's `sample.lzh` entry",
        }
    }

    /// CRC-16/ARC, bit for bit the same table-driven algorithm as delharc's
    /// own `crc::Crc16` (verified against it directly: this is the same
    /// implementation used to build `sample.lzh` itself, cross-checked by
    /// `delharc` decoding that fixture and by `lha t`/`lha v` — see
    /// MANIFEST.md).
    fn crc16_arc(data: &[u8]) -> u16 {
        let mut crc: u16 = 0;
        for &b in data {
            crc ^= b as u16;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xA001;
                } else {
                    crc >>= 1;
                }
            }
        }
        crc
    }

    /// Hand-builds a one-entry LHA level-1 archive with an arbitrary
    /// 5-byte method identifier — the same layout `sample.lzh` uses (see
    /// MANIFEST.md), generalised so tests can exercise method families that
    /// fixture deliberately does not (an unsupported method, a directory).
    fn build_single_entry_lha(name: &str, method: &[u8; 5], content: &[u8]) -> Vec<u8> {
        let filename = name.as_bytes();
        let file_crc = crc16_arc(content);

        let mut counted = Vec::new();
        counted.extend_from_slice(method);
        counted.extend_from_slice(&(content.len() as u32).to_le_bytes()); // compressed_size
        counted.extend_from_slice(&(content.len() as u32).to_le_bytes()); // original_size
        counted.extend_from_slice(&0u32.to_le_bytes()); // last_modified
        counted.push(0x20); // msdos_attrs (ARCHIVE)
        counted.push(1); // lha_level
        counted.push(filename.len() as u8);
        counted.extend_from_slice(filename);
        counted.extend_from_slice(&file_crc.to_le_bytes());
        counted.push(b'U'); // os_type: Unix
        counted.extend_from_slice(&0u16.to_le_bytes()); // first_header_len: none

        let header_len = u8::try_from(counted.len()).expect("header fits in a u8 length field");
        let csum = counted.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));

        let mut out = Vec::with_capacity(2 + counted.len() + content.len() + 1);
        out.push(header_len);
        out.push(csum);
        out.extend_from_slice(&counted);
        out.extend_from_slice(content);
        out.push(0); // end-of-archive marker
        out
    }

    #[test]
    fn lha_conforms() {
        let fx = lha_fixture();
        assert_container_conforms_with(&Lha, &meta(), &fx);
    }

    /// Step 6: `forward_parse: true` is a claim the conformance harness
    /// checks only indirectly (via the read-only properties above, which
    /// never open a genuinely non-seekable source). This proves it directly:
    /// read the fixture through the exact "erase `Seek` at the type level"
    /// shape `container_conformance.rs`'s `open_forward_only` uses, and
    /// confirm every entry — names AND content — comes back correctly.
    #[test]
    fn reads_every_entry_through_a_genuinely_non_seekable_source() {
        let mut ar = stuffr_core::testing::open_forward_only(&Lha, SAMPLE_LZH);
        let mut got = Vec::new();
        while let Some(mut entry) = ar.next_entry().expect("forward-only next_entry") {
            let name = entry.meta().name.clone();
            let mut data = Vec::new();
            entry
                .reader()
                .read_to_end(&mut data)
                .expect("forward-only entry read");
            got.push((name, data));
        }
        let want: Vec<(String, Vec<u8>)> = LHA_EXPECTED
            .iter()
            .map(|e| (e.name.to_string(), e.content.to_vec()))
            .collect();
        assert_eq!(got, want, "forward-only read must recover every entry");
    }

    #[test]
    fn by_index_is_refused_on_every_source_shape() {
        let mut fwd = stuffr_core::testing::open_forward_only(&Lha, SAMPLE_LZH);
        assert!(
            matches!(fwd.by_index(0), Err(stuffr_core::Error::NotSeekable { .. })),
            "a forward-only source must answer NotSeekable"
        );

        let path = std::env::temp_dir().join(format!(
            "stuffr-lha-seekable-{}-{:p}.lzh",
            std::process::id(),
            SAMPLE_LZH
        ));
        std::fs::write(&path, SAMPLE_LZH).unwrap();
        let src: Box<dyn Source> = Box::new(stuffr_core::FileSource::open(&path).unwrap());
        let _ = std::fs::remove_file(&path);
        let resolved = stuffr_core::resolve(src, LHA, Lha.caps(), &StreamPolicy::default())
            .expect("resolve over a seekable source");
        let mut seekable = Lha.open(resolved, &OpenOpts::default()).unwrap();
        let err = seekable
            .by_index(0)
            .expect_err("LHA has no index to index into");
        assert!(
            matches!(err, Error::Unsupported(_)),
            "a seekable source with no index must answer Unsupported, not NotSeekable — \
             got {err:?}"
        );
        assert_eq!(err.exit_code(), 3, "{err}");
    }

    #[test]
    fn create_is_refused_as_a_capability_limit_not_a_panic() {
        match Lha.create(
            PlainSink::new(Box::new(stuffr_core::testing::SharedBuf::new())),
            &CreateOpts::default(),
        ) {
            Err(err) => {
                // The SAME variant `Registry::require_container_writer`
                // raises — the refusal a user actually meets. A different
                // one here would mean two sentences for one contract, which
                // is what this used to be.
                assert!(
                    matches!(err, Error::CapabilityUnavailable { .. }),
                    "got {err:?}"
                );
                assert_eq!(err.exit_code(), 3);
            }
            Ok(_) => panic!("LHA must refuse to write"),
        }
    }

    #[test]
    fn capabilities_and_metadata_match_the_format() {
        let c = Lha.caps();
        assert!(c.read && !c.write);
        assert!(c.forward_parse, "delharc streams; see this module's doc");
        assert!(!c.needs_seek);
        let m = meta();
        assert_eq!(m.id, LHA);
        assert_eq!(m.extensions, &["lzh", "lha"]);
    }

    /// Step 7 (Task 1's deferred minor): `lha_meta()` registers two magic
    /// rules (`-lh`, `-lz`), and the fixture's own bytes match only the
    /// first. `assert_container_conforms_with`'s fixture property 3 already runs
    /// this via `lha_conforms` above (it would fail loudly if the harness's
    /// "any one rule" semantics required EVERY rule to match instead) — this
    /// test pins the premise directly, so a future change to either the
    /// magic table or the fixture cannot silently stop exercising it.
    #[test]
    fn exactly_one_of_the_two_registered_magic_rules_matches_the_fixture() {
        let hits = LHA_MAGIC
            .iter()
            .filter(|r| {
                SAMPLE_LZH.len() >= r.offset + r.bytes.len()
                    && &SAMPLE_LZH[r.offset..r.offset + r.bytes.len()] == r.bytes
            })
            .count();
        assert_eq!(
            hits, 1,
            "expected exactly one registered magic rule to match sample.lzh — if this \
             is now 0, the fixture no longer matches this format at all; if it is 2, the \
             two rules no longer probe genuinely different method families and this test \
             stops proving the harness's 'at least one, not necessarily all' semantics"
        );
    }

    /// Falsifies [`classify_lha_error`]'s placement: a corrupted header
    /// discovered by `next_file()` must come back as `Error::Corrupt`
    /// (exit 5), never `Error::Io` (exit 1) — the whole reason that
    /// function is called directly from `next_entry()` rather than letting
    /// the error travel through a bare `io::Error` `?`-conversion.
    #[test]
    fn a_corrupted_second_header_is_reported_as_corrupt_not_as_an_io_failure() {
        // Offset 49 is the first byte of entry 2's header (its declared
        // header-length byte) — see the module's fixture layout in
        // MANIFEST.md. Flipping it desyncs the header parse deterministically
        // rather than merely truncating the stream.
        let mut corrupted = SAMPLE_LZH.to_vec();
        let mid = corrupted.len() / 2;
        corrupted[mid] ^= 0xFF;

        let src: Box<dyn Source> = Box::new(ReaderSource::new(io::Cursor::new(corrupted)));
        let resolved = stuffr_core::resolve(src, LHA, Lha.caps(), &StreamPolicy::default())
            .expect("resolve over a seekable source");
        let mut ar = Lha.open(resolved, &OpenOpts::default()).expect("open");

        // Entry 1 is untouched and reads back fine.
        let first = ar
            .next_entry()
            .expect("entry 1 unaffected")
            .expect("entry 1 present");
        drop(first);

        let err = ar
            .next_entry()
            .expect_err("a corrupted second header must not read back silently");
        assert!(
            matches!(err, Error::Corrupt(_)),
            "expected Error::Corrupt, got {err:?}"
        );
        assert_eq!(
            err.exit_code(),
            5,
            "a corrupted header must exit 5 (corrupt archive), not 1 (stuffr failed)"
        );
    }

    /// Falsifies [`LhaEntryReader`]'s CRC-16 check directly. `-lh0-` is a
    /// byte-for-byte passthrough with no structural redundancy at all — a
    /// flipped payload byte decodes cleanly through `delharc`'s own
    /// `PassthroughDecoder`, no error, just different bytes — so the ONLY
    /// thing that can catch this corruption is the trailing CRC-16 check
    /// [`LhaEntryReader::read`] adds. This is deliberately a DIFFERENT byte
    /// than [`a_corrupted_second_header_is_reported_as_corrupt_not_as_an_io_failure`]
    /// flips: that one lands in entry 2's HEADER (caught by
    /// `classify_lha_error`, before any `Entry` is even produced); this one
    /// lands inside entry 1's PAYLOAD (offsets 43..49, "alpha\n"), which no
    /// header-parsing check ever sees — proven by neutering the CRC check to
    /// a bare passthrough (`self.inner.read(buf)`) and re-running: every
    /// other test in this module, including `lha_conforms`, still passed,
    /// and only this one went red. See the task report for the exact
    /// command and panic message.
    ///
    /// Classified the same way `ar.rs`'s own
    /// `a_cut_inside_an_entry_payload_is_reported_as_corrupt` classifies a
    /// payload-level error: `entry.reader().read_to_end` can only return a
    /// bare `io::Error` (that is all `std::io::Read` can express), so this
    /// applies `Error::from_decode_io` itself, exactly as `entries.rs`'s own
    /// `copy_charging` does for a real caller — the container_conformance
    /// harness's raw `?`-based `Error::Io` wrapping is a property of THAT
    /// harness's own helper, not of how a real caller sees this error.
    #[test]
    fn a_corrupted_payload_byte_fails_its_crc_check() {
        let mut corrupted = SAMPLE_LZH.to_vec();
        // Offset 45 is the 'p' of entry 1's "alpha\n" payload (offsets
        // 43..49) — see the module's fixture layout in MANIFEST.md.
        corrupted[45] ^= 0xFF;

        let src: Box<dyn Source> = Box::new(ReaderSource::new(io::Cursor::new(corrupted)));
        let resolved = stuffr_core::resolve(src, LHA, Lha.caps(), &StreamPolicy::default())
            .expect("resolve over a seekable source");
        let mut ar = Lha.open(resolved, &OpenOpts::default()).expect("open");
        let mut entry = ar
            .next_entry()
            .expect("entry 1 header parses fine")
            .expect("entry 1 present");

        let mut data = Vec::new();
        let io_err = entry
            .reader()
            .read_to_end(&mut data)
            .expect_err("a payload byte flipped under -lh0- must fail its trailing CRC-16 check");
        let err = Error::from_decode_io(io_err);
        assert_eq!(
            err.exit_code(),
            5,
            "a failed CRC-16 check must be Corrupt (exit 5), got {err:?}"
        );
    }

    /// `sample.lzh` only ever exercises `-lh0-`, so the `is_decoder_supported
    /// () == false` branch in `next_entry` has no coverage from the fixture
    /// harness at all. `-pm1-` (PMarc) is recognised by `CompressionMethod`
    /// but has no decoder in this build (delharc compiled with `std`, `lh1`,
    /// `lz` — no PMarc support at all), so it is unsupported for a reason
    /// unrelated to feature gating: this build can never read it. A
    /// capability gap, not damage — must be `Error::Unsupported` (exit 3),
    /// never `Error::Corrupt`.
    #[test]
    fn an_entry_with_an_unsupported_compression_method_is_reported_as_unsupported() {
        let bytes = build_single_entry_lha("weird.bin", b"-pm1-", b"whatever");
        let src: Box<dyn Source> = Box::new(ReaderSource::new(io::Cursor::new(bytes)));
        let resolved = stuffr_core::resolve(src, LHA, Lha.caps(), &StreamPolicy::default())
            .expect("resolve over a seekable source");
        let mut ar = Lha.open(resolved, &OpenOpts::default()).expect("open");
        let err = ar
            .next_entry()
            .expect_err("an unsupported method must be refused, not produce a fake entry");
        assert!(
            matches!(err, Error::Unsupported(_)),
            "expected Error::Unsupported, got {err:?}"
        );
        assert_eq!(err.exit_code(), 3);
    }

    /// `-lhd-` is delharc's own "this entry is a directory (or symlink)"
    /// marker (`CompressionMethod::Lhd`), and — like `-pm1-` above — has no
    /// decoder of its own, so `is_decoder_supported()` is ALSO false for it.
    /// The two must not be confused: a directory is not a capability gap,
    /// it simply has no payload to decode, and `next_entry` must produce a
    /// `EntryKind::Dir` entry rather than raising `Error::Unsupported`.
    #[test]
    fn a_directory_entry_is_produced_not_refused() {
        let bytes = build_single_entry_lha("adir", b"-lhd-", b"");
        let src: Box<dyn Source> = Box::new(ReaderSource::new(io::Cursor::new(bytes)));
        let resolved = stuffr_core::resolve(src, LHA, Lha.caps(), &StreamPolicy::default())
            .expect("resolve over a seekable source");
        let mut ar = Lha.open(resolved, &OpenOpts::default()).expect("open");
        let mut entry = ar
            .next_entry()
            .expect("a directory entry must not be refused")
            .expect("a directory entry must be produced");
        assert_eq!(entry.meta().kind, EntryKind::Dir);
        let mut data = Vec::new();
        entry
            .reader()
            .read_to_end(&mut data)
            .expect("a directory's reader must be empty, not erroring");
        assert!(data.is_empty());
    }
}
