//! ZOO, read-only, parsed from scratch against the original implementation.
//!
//! # No crate wraps this one either, and one that tried gets the record
//! size wrong
//!
//! Like `legacy::arc`, this container wraps nothing: `unarc-rs` 0.6.3 is
//! disqualified as a dependency for the three measured reasons
//! `fixtures/legacy/MANIFEST.md` records, so its MIT/Apache corpus is
//! borrowed as BYTES and its `src/zoo/` was read as a description of the
//! format. Only the LH5 layer is delegated, to `delharc`, which this crate
//! already depends on for `legacy::lha`.
//!
//! Unlike ARC, the format here could be checked against the **original**
//! implementation rather than against one modern reading of it: zoo 2.10's
//! own C source (Debian `zoo` 2.10-28, fetched during this task and read,
//! never compiled or linked). Every structural constant below cites the
//! file and macro it came from, and three of them contradict `unarc-rs`.
//!
//! # The fixed directory-entry record is 56 bytes, not 59
//!
//! `zoo.h` defines exactly two record lengths:
//!
//! ```text
//! #define  SIZ_DIR  51          /* length of type 1 directory entry */
//! #define  SIZ_DIRL 56          /* length of type 2 directory entry */
//! #define  VARDIRLEN_I  51      /* length of var. direntry */
//! #define  TZ_I     53          /* timezone */
//! #define  DCRC_I   54          /* CRC of directory entry */
//! #define  NAMLEN_I   (SIZ_DIRL + 0)
//! #define  DIRLEN_I   (SIZ_DIRL + 1)
//! ```
//!
//! So `var_dir_len` is a **`u16`** at offset 51, `tz` a byte at 53,
//! `dir_crc` a **`u16`** at 54, the fixed part ends at 56, and `namlen` /
//! `dirlen` are the first two bytes of the VARIABLE part. `unarc-rs`'s
//! `DIRENT_HEADER_SIZE = 59` reaches that figure by modelling
//! `var_dir_len` as a `u8`, `dir_crc` as a `u32`, and pulling `namlen` and
//! `dirlen` into the fixed record — three mistakes that happen to cancel to
//! `56 + 3`.
//!
//! **That mattered before a line of this module was written**, because
//! `MANIFEST.md` inherited the 59 and described all four borrowed fixtures
//! as ending in a *short* 56-byte terminal marker that a blind 59-byte
//! `read_exact` would reject. There is no short marker. The trailer is a
//! COMPLETE type-2 record, and five independent measurements say so:
//!
//! - `tz` reads `127` in every fixture at offset 53 and nothing at 52 —
//!   and `zoo.h`'s `#define NO_TZ 127` is the sentinel zoo writes when the
//!   timezone is unknown. Under the 59-byte reading that byte is `0`.
//! - `var_dir_len` as a `u16` reads 13, 10, 13 — and the variable part is
//!   then self-consistent: `namlen=0`, `dirlen=3`, `dirname="..\0"`, plus
//!   the eight bytes `dir_to_b` writes after it (`system_id` 2, `fattr` 3,
//!   `vflag`+`version_no` 3) is exactly 2+0+3+8 = 13, and 2+0+0+8 = 10 for
//!   the fixture whose `dirlen` is 0.
//! - The stored `dir_crc` — a CRC-16/ARC over the record with its own CRC
//!   field zeroed, `portable.c`'s `dir_to_b` — reproduces byte-exactly for
//!   all four REAL records under this layout and matches none of them under
//!   the 59-byte one (`0x38f3`, `0x8805`, `0x27c2`, `0x38f3` against the
//!   recorded `0x0272`, `0x5810`, `0xbe16`, `0x0272`).
//!   `a_directory_entrys_own_crc_confirms_the_fifty_six_byte_record` pins it.
//!   **The terminal record is deliberately NOT part of that argument**,
//!   though its own CRC does check out: it is the last thing in the file, so
//!   a 59-byte slice of it clips at EOF back to the same 56 bytes and both
//!   models produce the identical `0x83fc`. A check that cannot distinguish
//!   two hypotheses is evidence for neither, and citing it would have made
//!   the case look broader than it is.
//! - `next` + 56 is exactly each fixture's file length. Under 59 every ZOO
//!   file ever written would end three bytes into its own terminator.
//! - `offset` − (record end) is exactly 5 in all four, which is
//!   `zoo.h`'s `SIZ_FLDR` — see the next section.
//!
//! # The five bytes between a directory entry and its data
//!
//! `zoo.h` defines `FILE_LEADER "@)#("` and `SIZ_FLDR 5` ("4 chars plus
//! null"), and `zooadd.c` computes `direntry.offset = this_dir_offset +
//! SIZ_DIRL + direntry.var_dir_len + SIZ_FLDR`. The bytes `40 29 23 28 00`
//! that sit between every fixture's directory entry and its payload are
//! that leader. This reader never looks at them: `offset` is an ABSOLUTE
//! file position and is the only thing consulted to find an entry's data,
//! exactly as zoo's own extractor does. Recorded because a reader who
//! computes the data position from the record length instead will be five
//! bytes wrong and will not know why.
//!
//! # `needs_seek: true` — a claim, with its evidence and its cost
//!
//! ```text
//! ContainerCaps {
//!     needs_seek: true,
//!     ..ContainerCaps::read_only()   // read: true, write: false,
//! }                                  // forward_parse: false
//! ```
//!
//! ZOO's directory is a linked list of ABSOLUTE file offsets — each record
//! carries `next` (the position of the next record) and `offset` (the
//! position of its own payload) — so nothing about the format implies
//! either lies ahead of where a reader currently is. `arj.rs` carries the
//! same pair of caps for a different reason (its dependency needs `Seek`);
//! here the reason is the format's own shape.
//!
//! The evidence was weighed BOTH ways rather than assumed, because
//! `lha`/`arc` do claim `forward_parse` and a spool costs a user disk:
//!
//! - **For a forward walk, and it is stronger than it first looks:** zoo's
//!   own `zoolist.c` refuses a chain that does not advance (`if
//!   (direntry.next <= zoo_pointer) prterror('f', "ZOO chain structure is
//!   corrupted\n")`), and the writer puts both fields ahead of the reader
//!   too — `zooadd.c` computes `direntry.offset = this_dir_offset +
//!   SIZ_DIRL + var_dir_len + SIZ_FLDR` and then sets `next = zootell()`
//!   immediately past the payload. So for any zoo-WRITTEN archive a forward
//!   parse is demonstrably feasible, `offset` included. This reader enforces
//!   the chain half of that rule — see [`ZooRead::next_entry`].
//! - **Against:** what `zooadd.c` shows is what one writer does, not what
//!   the FORMAT requires — `offset` is an absolute position and nothing in
//!   `portable.c`'s reader constrains it, where the chain at least has
//!   `zoolist.c`'s explicit rule behind it. **And every borrowed fixture
//!   holds exactly ONE entry**, so no byte in this project's possession can
//!   demonstrate a multi-entry forward walk at all. Claiming `forward_parse`
//!   would mean shipping a walk whose correctness rests on a writer's
//!   habit and which no test here can exercise; the failure mode of getting
//!   it wrong is refusing a legitimate archive over a pipe, where the cost
//!   of the conservative choice is only a temp file.
//!
//! So a file opens at `Rung::Exact` and a pipe is spooled to a temp file and
//! opens at `Rung::Spilled` — a lower rung, still `is_authoritative()`, so
//! `cat old.zoo | stuffr list -` works and the fidelity report says how.
//! `a_piped_source_is_spooled_and_reads_back_correctly` pins it. Revisit
//! when a multi-entry ZOO fixture exists to prove a forward walk against;
//! nothing else about this module would have to change.
//!
//! # The chain must advance, and that is zoo's own rule
//!
//! `next` is attacker-controlled and a self-referential or cyclic chain
//! would spin forever. [`ZooRead::next_entry`] refuses any `next` that does
//! not clear the current record's own bytes, as [`Error::Corrupt`] (exit 5)
//! — the file contradicting its own shape, `Error::exit_code`'s rule, and
//! nothing was allocated on its say-so.
//!
//! **It is STRICTER than zoo's own rule, not the same one**, and the
//! difference is worth stating rather than glossed as agreement.
//! `zoolist.c:447` is fatal on `next <= zoo_pointer`, i.e. a link that does
//! not move past the record's START; this refuses one that does not clear
//! the record's END, up to 55 bytes further on. Every archive zoo writes
//! satisfies both (`next = offset + size_now`, past the record and its
//! payload), so nothing real sits in the gap — but a file could, and this
//! reader would refuse what zoo 2.10 accepts. Both a self-referential entry
//! and a longer cycle are pinned, because a guard that only catches
//! self-reference is the common half-fix.
//!
//! # Methods: three, and the third is `delharc`'s
//!
//! | byte | method | here |
//! |---|---|---|
//! | 0 | Stored | the payload IS the content |
//! | 1 | Compressed | zoo's own `lzd` LZW, from scratch — see [`lzw_decode`] |
//! | 2 | CompressedLh5 | `delharc`'s `Lh5Decoder` over the raw stream |
//! | 3.. | — | [`Error::Unsupported`] (exit 3) |
//!
//! `zoo.h`'s `#define MAX_PACK 2` is the whole method space: zoo itself
//! refuses anything higher, so a byte above 2 is a capability limit this
//! build names rather than damage it invents.
//!
//! **Method 1 is a THIRD LZW engine in this crate**, after
//! `legacy::compress_z`'s and `legacy::arc`'s, and that is Ruling I applied
//! rather than ignored: the dialects genuinely differ. Unix `compress` has
//! a header-declared `maxbits`, block mode and byte-group padding after a
//! CLEAR; ARC's Crunched has an inline maxbits byte, no end marker and an
//! RLE90 pass under it; ZOO's has a 13-bit ceiling, an explicit
//! end-of-stream code (`Z_EOF = 257`) that neither of the others has, and
//! therefore a first free code of 258 rather than 257. A shared engine
//! would have to be parameterised over all of that. What IS shared is the
//! bit reader, which is the same computation three times over — see
//! [`super::bits`], extracted in this task for the reason `legacy::dos` was.
//!
//! **The 13-bit ceiling is measured, not inherited.** `lzconst.h` gives
//! `MAXBITS 13`, `CLEAR 256`, `Z_EOF 257`, `FIRST_FREE 258`, `MAXMAX
//! 8192`, and `lzc.c` emits a CLEAR when its table fills at that ceiling.
//! `unarc-rs` routes this method through `salzweg`, which caps at **12**
//! bits and errors past 4096 entries — and it decodes the borrowed fixture
//! correctly only because that fixture never gets there: measured, its
//! dictionary peaks at 4011 of 8192 entries and its widest code is 12 bits.
//! A 12-bit reading would fail on any larger ZOO archive, so the format's
//! own figure is the one implemented. The two readings are byte-identical
//! on every fixture this project holds, which is why no test here can
//! separate them — stated rather than left to look like coverage.
//!
//! # An entry decodes whole, like ARJ and ARC
//!
//! The CRC-16 is over the whole decoded entry and neither the LZW nor the
//! LH5 layer has a streaming form here, so every entry is decoded into
//! memory and handed back as a `Cursor`. Same two consequences `arc.rs`
//! spells out: `--max-ratio` is a coarser bound than on a streaming
//! container, and the real backstop is [`MAX_ZOO_ENTRY_LEN`], a fixed
//! structural ceiling checked against `size_now` and `org_size` BEFORE the
//! buffers those fields would size are allocated, and against the LZW
//! output as it grows. It is deliberately not `--memory-limit`, which binds
//! a CODEC through `DecodeOpts`; a container opens through [`OpenOpts`],
//! which has no memory field at all.
//!
//! So `stuffr list old.zoo` decodes every entry, as it does for `arc` and
//! `arj` and does not for the other four containers. Kept for the same
//! reason: the eager decode is what makes [`check_declared_size`] possible
//! at all.
//!
//! # Which readings no borrowed byte witnesses
//!
//! **Three branches are pinned only by archives written in this module's own
//! test code, and that is the weakest evidence class in this phase.** Each
//! reading is derived from zoo 2.10's source, so it is not
//! self-referential — but `build_zoo` and the reader above share an author,
//! so a field both sides read from the same wrong offset would agree with
//! itself and be wrong on disk. Named here rather than discovered later:
//!
//! - **The long filename** in the variable part (`zoo.h`'s `NAMLEN_I`,
//!   `LFNAME_I`). Every fixture has `namlen == 0`.
//! - **A deleted entry** being skipped (`zoolist.c`'s own handling). No
//!   fixture carries `deleted == 1`.
//! - **The 51-byte type-0/1 record** (`zoo.h`'s `SIZ_DIR`). Every fixture is
//!   type 2.
//!
//! What the borrowed bytes DO witness is the layout itself — the 56-byte
//! record, the variable part, the file leader and the per-entry CRC — and
//! those are proven against the four real archives with a parser written out
//! longhand, never against anything this module builds.
//!
//! # Three deliberate limitations, each with its evidence
//!
//! - **A deleted entry is skipped, not listed.** `zoo` marks a deleted
//!   entry `deleted = 1` and leaves it in the chain; `zoolist.c` counts
//!   those separately and does not list them, and `zoo x` does not extract
//!   them. This reader does the same, and counts it as a record ON the chain
//!   — which is what keeps an all-deleted archive out of
//!   [`ZooRead::refuse_a_chain_that_reaches_nothing`]'s way.
//! - **The directory name in the variable part is NOT joined onto the entry
//!   name.** Every borrowed fixture sets it to `..` — and zoo 2.10's own
//!   `frd_dir` strips `../` components out of that field for
//!   CVE-2005-2349. Joining it would hand `entries.rs`'s containment check
//!   a traversal to reject for no gain. The long FILENAME (`namlen` /
//!   `lfname`) IS used when present, since that is the entry's real name
//!   and the 13-byte DOS field is its truncation.
//! - **`dir_crc` is checked and SURFACED, never enforced.** zoo itself
//!   treats a bad one as advisory — `zoolist.c` prints a `*` beside the
//!   entry and carries on — so refusing would be stricter than the
//!   reference tool, which is how a guard comes to fire on legitimate
//!   input. But staying silent is the other way to get it wrong: every
//!   field a caller is about to trust comes out of that record. A mismatch
//!   is [`Fidelity::DirectoryRecordChecksum`], which `--strict-fidelity`
//!   turns into exit 4. It doubles as the independent witness that this
//!   module's record layout is right at all.
//!
//! # Error mapping has no wildcard
//!
//! - A method byte above 2 → [`Error::Unsupported`] (exit 3).
//! - A directory-entry `type` above 2 → [`Error::Unsupported`] (exit 3):
//!   `portable.c` asserts `type <= 2`, so a higher one is a shape from
//!   outside the format rather than damage inside it.
//! - A declared `size_now`/`org_size` past [`MAX_ZOO_ENTRY_LEN`], or an LZW
//!   decode that grows past it → [`Error::ResourceLimit`] (exit 6), refused
//!   before the allocation it would size.
//! - Malformed framing — a missing tag, a truncated record or payload, a
//!   chain that does not advance, an LZW code past the dictionary — →
//!   [`Error::Corrupt`] (exit 5).
//! - A decoded entry whose CRC-16/ARC disagrees with its own header →
//!   [`Error::Corrupt`] (exit 5), naming both values.
//! - A genuine source failure passes through as ITSELF ([`Error::Io`]):
//!   [`classify_zoo_io`] folds `UnexpectedEof` alone, exactly as `arc.rs`,
//!   `lha.rs` and `arj.rs` do. Container-conformance fixture property 9 is
//!   the standing proof.
//! - `create()` → [`Error::CapabilityUnavailable`] (exit 3), the one shared
//!   sentence `Registry::require_container_writer` raises first.

use std::io::{self, Read, Seek, SeekFrom};
use std::time::SystemTime;

use delharc::decode::{Decoder, Lh5Decoder};
use stuffr_core::{
    ArchiveRead, ArchiveWrite, Container, ContainerCaps, CorruptionDetection, CreateOpts, Entry,
    EntryKind, EntryMeta, Error, Fidelity, FidelityReport, FormatId, FormatMeta, MagicRule,
    OpenOpts, Resolved, Result, SeekRead, Sink, Source,
};

use super::bits::LsbBitReader;
use super::crc::{crc16_arc, crc16_arc_continued};
use super::dos;

pub const ZOO: FormatId = FormatId::new("zoo");

/// `zoo.h`: `#define ZOO_TAG ((unsigned long) 0xFDC4A7DCL)`. It opens the
/// archive header at offset 20 and every directory entry at its own offset
/// 0 — "a random choice", in the source's own words.
pub(super) const ZOO_TAG: u32 = 0xFDC4_A7DC;

/// `zoo.h`: `#define MINZOOHSIZ 34` — the smallest archive header, and the
/// prefix every version shares. Newer archives carry eight more bytes
/// (`type`, `acmt_pos`, `acmt_len`, `vdata`, `SIZ_ZOOH 42`), none of which
/// this reader needs: `zoo_start` is the authoritative pointer to the first
/// directory entry, so the header's real length never has to be inferred.
const MIN_HEADER_LEN: usize = 34;

/// `zoo.h`: `#define SIZ_ZOOH 42` — the newer archive header, the classic
/// 34-byte prefix plus `type`, `acmt_pos`, `acmt_len` and `vdata`.
const SIZ_ZOOH: usize = 42;

/// `zoo.h`: `#define FIXED_OFFSET 34` — `zoo_start` in archives old enough to
/// have no extended header at all. `portable.c`'s `b_to_zooh` keys off this
/// exact value, not off the file's length, to decide whether those four extra
/// fields are present.
const FIXED_OFFSET: u32 = 34;

/// `zoo.h`: `#define SIZ_DIR 51` — a type-0/1 directory entry, which ends
/// at `fname` with no `var_dir_len`, `tz` or `dir_crc` behind it.
pub(super) const SIZ_DIR: usize = 51;

/// `zoo.h`: `#define SIZ_DIRL 56` — a type-2 directory entry, five bytes
/// longer. See this module's doc for the measurements that rule out
/// `unarc-rs`'s 59.
pub(super) const SIZ_DIRL: usize = 56;

/// `zoo.h`: `#define SIZ_FLDR 5` — "4 chars plus null", the width of the
/// `FILE_LEADER "@)#("` that sits between a directory entry and the payload
/// it describes.
///
/// This container's own reader never needs it: `offset` is an ABSOLUTE file
/// position and is the only thing consulted to find an entry's data. It is
/// `pub(super)` for `../zoo_salvage.rs`, which has no chain to trust and
/// therefore computes a payload's position STRUCTURALLY, from the record's
/// own end — `zooadd.c`'s own arithmetic, `direntry.offset = this_dir_offset
/// + SIZ_DIRL + var_dir_len + SIZ_FLDR`, read forwards.
pub(super) const SIZ_FLDR: u64 = 5;

/// `zoo.h`: `#define VARDIRLEN_I 51` and `#define DCRC_I 54` — the `u16`
/// length of the variable part and the record's own CRC-16, both inside the
/// 56-byte fixed record. `pub(super)` for `../zoo_salvage.rs`'s tests, which
/// build and damage records and must not hand-copy the two numbers this
/// module's entire doc is about.
pub(super) const VARDIRLEN_I: usize = 51;
pub(super) const DCRC_I: usize = 54;

/// `zoo.h`: `#define FNM_SIZ 13`, at `#define FNAME_I 38`.
pub(super) const FNAME_I: usize = 38;
pub(super) const FNM_SIZ: usize = 13;

/// The archive header's own tag sits at `zoo.h`'s `#define ZTAG_I 20`.
///
/// One rule, on the four bytes the format itself uses to identify an
/// archive. The 20-byte `text` field ahead of it is deliberately NOT part
/// of the signature: zoo stamps its own version into it (`TEXT "ZOO 2.10
/// Archive.\032"`), so matching on it would refuse an archive written by
/// any other version — the tag is what `zoo`'s own reader checks, and it is
/// what `b_to_zooh` refuses an archive for.
const ZOO_MAGIC: &[MagicRule] = &[MagicRule {
    offset: 20,
    bytes: &[0xDC, 0xA7, 0xC4, 0xFD],
    format: ZOO,
}];

pub fn meta() -> FormatMeta {
    FormatMeta::container(ZOO, &["zoo"], ZOO_MAGIC)
}

pub struct Zoo;

impl Container for Zoo {
    fn id(&self) -> FormatId {
        ZOO
    }

    fn caps(&self) -> ContainerCaps {
        // See this module's doc: `needs_seek` is measured against the
        // format's own shape and argued both ways, not copied from a
        // sibling. `forward_parse` stays false (the `read_only()` default),
        // which together with `needs_seek` means the ladder never hands
        // this container a genuinely forward-only source.
        ContainerCaps {
            needs_seek: true,
            // Every ZOO entry carries a CRC-16/ARC the format mandates, and
            // this reader checks it before handing back a single byte.
            detects_corruption: CorruptionDetection::Always,
            ..ContainerCaps::read_only()
        }
    }

    fn open(&self, resolved: Resolved, _o: &OpenOpts) -> Result<Box<dyn ArchiveRead>> {
        let Resolved { source, report, .. } = resolved;
        let mut src = ZooSeekAdapter(source);

        let mut header = [0u8; MIN_HEADER_LEN];
        src.read_exact(&mut header).map_err(classify_zoo_io)?;
        let tag = le32(&header, 20);
        if tag != ZOO_TAG {
            return Err(Error::Corrupt(format!(
                "not a ZOO archive: the header records the tag {tag:#010x} where the format \
                 requires {ZOO_TAG:#010x}"
            )));
        }
        let zoo_start = le32(&header, 24);

        // `portable.c`'s `b_to_zooh` reads the newer header's four extra
        // fields only when `zoo_start != FIXED_OFFSET`, and this follows that
        // rule rather than the byte count: an archive whose data starts at 34
        // IS the old header, and there is nothing behind it to read. Only the
        // archive comment's extent is kept — it is the one legitimate thing
        // that can sit outside the directory chain, and
        // [`ZooRead::refuse_a_chain_that_reaches_nothing`] has to account for
        // it.
        let mut archive_comment_end = 0u64;
        if zoo_start != FIXED_OFFSET {
            let mut ext = [0u8; SIZ_ZOOH - MIN_HEADER_LEN];
            src.read_exact(&mut ext).map_err(classify_zoo_io)?;
            // `ACMTPOS_I 35`, `ACMTLEN_I 39`, i.e. offsets 1 and 5 within
            // the eight bytes behind the classic header.
            let acmt_len = u64::from(le16(&ext, 5));
            if acmt_len > 0 {
                archive_comment_end = u64::from(le32(&ext, 1)) + acmt_len;
            }
        }

        let file_len = src.seek(SeekFrom::End(0)).map_err(classify_zoo_io)?;

        Ok(Box::new(ZooRead {
            src,
            report,
            next_pos: Some(u64::from(zoo_start)),
            archive_comment_end,
            file_len,
            entries_on_chain: 0,
            done: false,
        }))
    }

    /// Unreachable through ops: `Registry::require_container_writer` reads
    /// `caps().write` and refuses first. This is the trait-level backstop,
    /// answering the SAME error rather than a second wording of one
    /// contract — see `lha.rs`'s twin.
    fn create(&self, _dst: Box<dyn Sink>, _o: &CreateOpts) -> Result<Box<dyn ArchiveWrite>> {
        Err(Error::CapabilityUnavailable {
            format: ZOO,
            available: "read",
            requested: "written",
        })
    }
}

/// Presents a ladder [`Source`] as the `Read + Seek` this container's own
/// offset-following walk requires.
///
/// Only constructed once the ladder has already guaranteed a seekable
/// source — `Zoo::caps` declares `needs_seek: true` and `forward_parse:
/// false`, so `stuffr_core::ladder::resolve` either hands this container an
/// already-seekable rung (`Exact`) or spools a pipe to a temp file first
/// (`Spilled`, still seekable). `as_seek` returning `None` is therefore
/// unreachable in practice; it is reported as an I/O error rather than a
/// panic because `Seek` has no other channel — the same choice `arj.rs`'s
/// and `zip.rs`'s own adapters make.
struct ZooSeekAdapter(Box<dyn Source>);

impl Read for ZooSeekAdapter {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Seek for ZooSeekAdapter {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let seek: &mut dyn SeekRead = self
            .0
            .as_seek()
            .ok_or_else(|| io::Error::other("zoo: source reported seekable but cannot seek"))?;
        seek.seek(pos)
    }
}

/// The ceiling on any single header-declared length this container acts on,
/// and on the size an LZW decode may grow its output to.
///
/// 256 MiB, the same figure `arc.rs`'s `MAX_ARC_ENTRY_LEN` and `arj.rs`'s
/// `MAX_ARJ_ENTRY_LEN` use and for the same argument: generous headroom for
/// any legitimate archive in a floppy-era format, while far short of what a
/// hostile or merely corrupt `u32` header field could otherwise force this
/// build to allocate for one entry. Fixed rather than derived from
/// `DecodeOpts::memory_limit` — see this module's doc.
pub(super) const MAX_ZOO_ENTRY_LEN: u64 = 256 * 1024 * 1024;

/// Refuses a length past [`MAX_ZOO_ENTRY_LEN`] before anything is allocated
/// for it.
///
/// Three call sites, which are the only three places a length can grow
/// unboundedly here: `size_now` before the payload buffer it sizes exists,
/// `org_size` before the LH5 output buffer it sizes exists, and the LZW
/// decoder's output as it grows.
fn refuse_if_over_ceiling(name: &str, declared: u64, field: &str) -> Result<()> {
    if declared > MAX_ZOO_ENTRY_LEN {
        return Err(Error::ResourceLimit(format!(
            "entry `{name}` declares {declared} bytes of {field}, past the \
             {MAX_ZOO_ENTRY_LEN}-byte ceiling this container decodes whole and cannot stream; \
             no legitimate ZOO entry is this large"
        )));
    }
    Ok(())
}

/// Classifies an `io::Error` raised while reading an archive's own bytes.
///
/// `UnexpectedEof` — and only that kind — folds onto [`Error::Corrupt`]. It
/// is this reader's own `read_exact` reporting that the archive stopped
/// mid-record or mid-payload, which is damage; left as `Error::Io` it would
/// reach `Error::exit_code`'s `_ => 1` wildcard and announce that *stuffr*
/// failed. Every other kind passes through untouched, so a failing disk
/// still arrives as `PermissionDenied` — the same narrowness `arc.rs`'s
/// `classify_arc_io` argues for, proven by container-conformance fixture
/// property 9.
fn classify_zoo_io(e: io::Error) -> Error {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        return Error::Corrupt(format!("ZOO archive ended mid-record: {e}"));
    }
    Error::from_decode_io(e)
}

fn le32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

fn le16(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}

/// The packing methods this build decodes. `zoo.h`'s `#define MAX_PACK 2`
/// is the whole space the format ever assigned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Method {
    /// 0 — the payload IS the content.
    Stored,
    /// 1 — zoo's own `lzd` LZW.
    Lzw,
    /// 2 — the LH5 stream `delharc` decodes.
    Lh5,
}

impl Method {
    /// The highest method byte the format ever assigned — `zoo.h`'s
    /// `#define MAX_PACK 2`, which is the WHOLE method space: zoo itself
    /// refuses anything higher. `../zoo_salvage.rs`'s discovery gate reads
    /// this rather than re-deriving a second list of its own, the same way
    /// `../arc_salvage.rs` mirrors `arc.rs`'s `ARC_MAGIC` table.
    pub(super) const MAX_PACK: u8 = 2;

    pub(super) fn from_byte(b: u8, name: &str) -> Result<Self> {
        match b {
            0 => Ok(Method::Stored),
            1 => Ok(Method::Lzw),
            2 => Ok(Method::Lh5),
            other => Err(Error::Unsupported(format!(
                "entry `{name}` uses ZOO packing method {other}, which is past the format's own \
                 maximum of 2 (`zoo.h`'s MAX_PACK) and which this build cannot decode"
            ))),
        }
    }

    /// The [`FormatId`] `../zoo_salvage.rs` records in a candidate's
    /// [`EntryMeta::codec`] for this method, and dispatches its own
    /// `write_payload` on.
    ///
    /// The single fact about each variant that both directions of that
    /// mapping derive from — `codec_for_zoo_method` is
    /// `Self::from_byte(..).ok().map(Self::codec)` and `method_for_codec`
    /// searches [`Self::all`] for the variant whose `codec()` matches —
    /// rather than two hand-maintained tables beside [`Self::from_byte`]'s
    /// own. `arc.rs`'s [`super::arc::Method::codec`] carries the full
    /// argument for why (Ruling S-K), and the cost of getting it wrong is
    /// the one this seam exists to prevent: an unmapped method makes every
    /// entry using it a silent `SalvageDisposition::SkippedNotBuiltIn`.
    ///
    /// **A fourth decodable method is a COMPILE ERROR until three `match`es
    /// in this file name it** — [`Self::from_byte`]'s, this one, and
    /// [`Self::next`]'s.
    pub(super) fn codec(self) -> FormatId {
        match self {
            Method::Stored => FormatId::new("zoo-stored"),
            Method::Lzw => FormatId::new("zoo-lzw"),
            Method::Lh5 => FormatId::new("zoo-lh5"),
        }
    }

    /// The variant after `self` in declaration order, `None` past the last.
    ///
    /// Exists only to drive [`Self::all`], and is an exhaustive `match` for
    /// exactly one reason: **a fourth variant added to [`Method`] without an
    /// arm here does not compile.** Its ARC twin replaced a hand-written
    /// `const DECODABLE: [Method; 5]` that the compiler could not check —
    /// see [`super::arc::Method::next`] for what forgetting it cost there.
    const fn next(self) -> Option<Self> {
        match self {
            Method::Stored => Some(Method::Lzw),
            Method::Lzw => Some(Method::Lh5),
            Method::Lh5 => None,
        }
    }

    /// Every decodable method, in declaration order — seeded from the first
    /// variant and driven by [`Self::next`]'s exhaustive `match`.
    ///
    /// **The chain is compiler-checked; the SEED is not**, the identical
    /// asymmetry [`super::arc::Method::all`] documents: a variant added at
    /// the END cannot be forgotten, one added at the FRONT compiles cleanly
    /// and is silently absent. The front door is closed by
    /// `zoo_salvage.rs`'s `every_method_the_reader_decodes_can_be_written_back`,
    /// which round-trips **every byte `from_byte` accepts** rather than
    /// iterating this function.
    pub(super) fn all() -> impl Iterator<Item = Self> {
        std::iter::successors(Some(Method::Stored), |method| method.next())
    }
}

/// One directory entry, parsed out of its fixed record and the variable
/// part behind it.
///
/// `pub(super)`, as are [`read_dir_entry`], [`Method`], [`decode`],
/// [`zoo_mtime`] and the layout constants above: Salvage Stage 2 Task 4's
/// `../zoo_salvage.rs` is a sibling module under `legacy`, not a descendant
/// of this one, and reuses this container's own record parse and decoders
/// rather than carrying a second copy of the 56-byte layout. **That reuse is
/// the point, not a convenience** — the layout is the exact thing
/// `unarc-rs` got wrong (59 bytes; see this module's doc), so a scanner with
/// its own copy of it would be one edit away from disagreeing with the
/// reader beside it and nothing would fail to say so.
///
/// The test-only `raw_entries` in this file's own `tests` module stays
/// INDEPENDENT of both, deliberately: it establishes the borrowed fixtures'
/// ground truth, and a manifest derived from the parser under test would
/// agree with it by construction. Reuse flows from reader to scanner, never
/// into the witness.
pub(super) struct DirEntry {
    /// Total bytes the fixed record occupies: [`SIZ_DIR`] or [`SIZ_DIRL`].
    pub(super) fixed_len: usize,
    /// Fixed part plus variable part — what `dir_to_b` writes, and where the
    /// next thing in the file begins.
    pub(super) record_len: u64,
    /// `Some((computed, recorded))` when this record's own `dir_crc`
    /// disagrees with its bytes. `None` for a record that checks out AND for
    /// a type-0/1 record, which carries no such field at all.
    pub(super) dir_crc_mismatch: Option<(u16, u16)>,
    pub(super) method_byte: u8,
    pub(super) next: u32,
    pub(super) offset: u32,
    pub(super) packed_datetime: u32,
    pub(super) crc16: u16,
    pub(super) org_size: u32,
    pub(super) size_now: u32,
    pub(super) deleted: bool,
    pub(super) name: String,
}

/// Reads one directory entry at `pos`, variable part included.
///
/// The record is read in two steps — [`SIZ_DIR`] bytes, then five more only
/// if `type == 2` — rather than as one blind fixed-size read, because the
/// format has two record lengths and reading the longer one over a type-1
/// entry would consume the first five bytes of whatever follows it.
pub(super) fn read_dir_entry(src: &mut dyn SeekRead, pos: u64) -> Result<DirEntry> {
    src.seek(SeekFrom::Start(pos)).map_err(classify_zoo_io)?;
    let mut rec = [0u8; SIZ_DIRL];
    src.read_exact(&mut rec[..SIZ_DIR])
        .map_err(classify_zoo_io)?;

    let tag = le32(&rec, 0);
    if tag != ZOO_TAG {
        return Err(Error::Corrupt(format!(
            "the ZOO directory entry at offset {pos} records the tag {tag:#010x} where the \
             format requires {ZOO_TAG:#010x}; the chain does not lead to a directory entry"
        )));
    }

    let dir_type = rec[4];
    let fixed_len = match dir_type {
        0 | 1 => SIZ_DIR,
        2 => {
            src.read_exact(&mut rec[SIZ_DIR..SIZ_DIRL])
                .map_err(classify_zoo_io)?;
            SIZ_DIRL
        }
        other => {
            return Err(Error::Unsupported(format!(
                "the ZOO directory entry at offset {pos} declares type {other}; the format \
                 defines only types 0, 1 and 2 (`portable.c` asserts `type <= 2`), so this \
                 build has no record layout for it"
            )));
        }
    };

    // Stored VERBATIM, never sanitised, for the reason
    // container-conformance property 12 states: refusing a hostile name is
    // the ops layer's job, and a container that helpfully rewrote one would
    // destroy the evidence that refusal depends on.
    let dos_name = {
        let field = &rec[FNAME_I..FNAME_I + FNM_SIZ];
        let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
        String::from_utf8_lossy(&field[..end]).into_owned()
    };

    let mut name = dos_name;
    let mut var: Vec<u8> = Vec::new();
    let mut dir_crc_mismatch = None;
    if fixed_len == SIZ_DIRL {
        // The variable part. `var_dir_len` is a `u16`, so this allocation is
        // bounded by 64 KiB by the field's own type and needs no ceiling of
        // its own — unlike `size_now`/`org_size`, which are `u32`.
        let var_len = usize::from(le16(&rec, VARDIRLEN_I));
        if var_len > 0 {
            var = vec![0u8; var_len];
            src.read_exact(&mut var).map_err(classify_zoo_io)?;
            // `zoo.h`: NAMLEN_I = SIZ_DIRL + 0, DIRLEN_I = SIZ_DIRL + 1,
            // LFNAME_I = SIZ_DIRL + 2. `dirlen`/`dirname` are deliberately
            // not read — see this module's doc on CVE-2005-2349.
            if var.len() >= 2 {
                let namlen = usize::from(var[0]);
                if namlen > 0 {
                    let Some(field) = var.get(2..2 + namlen) else {
                        return Err(Error::Corrupt(format!(
                            "entry `{name}` declares a {namlen}-byte long filename inside a \
                             {var_len}-byte variable directory part that cannot hold it"
                        )));
                    };
                    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
                    name = String::from_utf8_lossy(&field[..end]).into_owned();
                }
            }
        }

        // `dir_to_b` (`portable.c`) zeroes the `dir_crc` field, runs
        // `addbfcrc` over `SIZ_DIRL + var_dir_len` bytes, and writes the
        // result back into it. Recomputed the same way and COMPARED, never
        // enforced — see [`Fidelity::DirectoryRecordChecksum`] for why a
        // record checksum warns where a content checksum refuses.
        let recorded = le16(&rec, DCRC_I);
        let mut zeroed = rec;
        zeroed[DCRC_I] = 0;
        zeroed[DCRC_I + 1] = 0;
        let mut computed = crc16_arc(&zeroed);
        if !var.is_empty() {
            computed = crc16_arc_continued(computed, &var);
        }
        if computed != recorded {
            dir_crc_mismatch = Some((computed, recorded));
        }
    }

    Ok(DirEntry {
        fixed_len,
        record_len: fixed_len as u64 + var.len() as u64,
        dir_crc_mismatch,
        method_byte: rec[5],
        next: le32(&rec, 6),
        offset: le32(&rec, 10),
        // `zoo.h`: DAT_I 14, TIM_I 16 — two `u16`s, so the little-endian
        // `u32` at 14 is `date | (time << 16)`, the same packing ARC uses.
        packed_datetime: le32(&rec, 14),
        crc16: le16(&rec, 18),
        org_size: le32(&rec, 20),
        size_now: le32(&rec, 24),
        deleted: rec[30] != 0,
        name,
    })
}

/// Converts ZOO's packed `date`/`time` pair into a `SystemTime`.
///
/// `None` whenever the packed value carries no valid calendar date, which is
/// how an entry with no timestamp at all reports itself. The calendar
/// arithmetic is [`super::dos`]'s, shared with `arc` and `arj`; only the
/// unpacking is here.
pub(super) fn zoo_mtime(packed: u32) -> Option<SystemTime> {
    let date = (packed & 0xFFFF) as u16;
    let time = (packed >> 16) as u16;
    dos::mtime(
        1980 + i64::from(date >> 9),
        u32::from((date >> 5) & 0x0F),
        u32::from(date & 0x1F),
        u32::from(time >> 11),
        u32::from((time >> 5) & 0x3F),
        u32::from(time & 0x1F) * 2,
    )
}

struct ZooRead {
    src: ZooSeekAdapter,
    report: FidelityReport,
    /// Position of the next directory entry to read, or `None` once the
    /// terminator was reached.
    next_pos: Option<u64>,
    /// End of the archive comment, or 0 when there is none. The one thing
    /// that can legitimately sit outside the directory chain — see
    /// [`ZooRead::refuse_a_chain_that_reaches_nothing`].
    archive_comment_end: u64,
    /// The archive's own length, read once at `open`.
    file_len: u64,
    /// Directory records the chain led to, the terminator excluded. Counts
    /// DELETED records too: they are entries this archive holds and does not
    /// hand back, which is a different thing from a chain that led nowhere.
    entries_on_chain: u64,
    /// Set once the chain ended or any error was raised — either way
    /// nothing more will be read.
    done: bool,
}

impl ZooRead {
    /// Reads one entry's stored payload.
    ///
    /// The ceiling is checked FIRST, before the buffer the header's own
    /// field would size exists. That ordering is the whole point, and it is
    /// what `refuses_an_absurd_size_now_before_the_allocation_it_would_size`
    /// proves with a source that panics on an oversized read: a check bolted
    /// on after the read passes an error-code assertion while the memory was
    /// allocated anyway, which is the entire defect.
    fn read_payload(&mut self, e: &DirEntry) -> Result<Vec<u8>> {
        refuse_if_over_ceiling(&e.name, u64::from(e.size_now), "compressed data")?;
        // Checked here too, and before the decode rather than inside it,
        // because `Method::Lh5`'s output buffer is sized from this field.
        refuse_if_over_ceiling(&e.name, u64::from(e.org_size), "decompressed data")?;
        self.src
            .seek(SeekFrom::Start(u64::from(e.offset)))
            .map_err(classify_zoo_io)?;
        let mut payload = vec![0u8; e.size_now as usize];
        self.src.read_exact(&mut payload).map_err(classify_zoo_io)?;
        Ok(payload)
    }

    /// Returns the decoded entry as OWNED parts rather than an
    /// [`Entry`], so that `next_entry` can set `done` after calling it: an
    /// `Entry<'_>` borrows `self` for the caller's whole lifetime, which
    /// would make the error/end bookkeeping around it unexpressible.
    /// Refuses an archive whose directory chain led to NO entry at all while
    /// the file holds bytes nothing on that chain accounts for.
    ///
    /// **The reproducer is four bytes.** Zeroing the first record's `next` in
    /// `store.zoo` turns that record into a terminator: `list` printed no
    /// rows, `test --strict-fidelity` answered `0 bytes verified (exact
    /// fidelity)` and `unpack --strict-fidelity` made an empty directory, all
    /// at exit 0, over 11,418 bytes of content the chain never mentions. A
    /// user concludes the archive was empty.
    ///
    /// **`Error::Corrupt` (exit 5), and the two zip precedents resolve it
    /// rather than leaving it to feel.** `note_unreachable_records` warns,
    /// because there the index is self-consistent and handing back what IS
    /// reachable is a service. `refuse_an_index_that_reaches_nothing` refuses,
    /// because nothing is reachable and a warning would leave `unpack`
    /// creating an empty directory at exit 0 with `--strict-fidelity` the only
    /// thing between a user and it. This is the second shape exactly. Against
    /// `Error::exit_code`'s own rule: nothing was allocated on the file's
    /// say-so and no larger budget could make it readable, so this is not
    /// exit 6 — the bytes were read and found to contradict themselves, which
    /// is 5.
    ///
    /// **The predicate is a CONJUNCTION, and both arms matter**, for the same
    /// reason zip's is: an archive with no entries is a legitimate thing to
    /// meet, and refusing one would be the fourteenth instance of this
    /// project's second-commonest defect.
    ///
    /// - Arm 1 counts records ON THE CHAIN, not entries yielded, so an
    ///   archive whose every member is marked `deleted` — what `zoo d`
    ///   leaves behind, with the payloads still in the file — never reaches
    ///   arm 2 at all.
    /// - Arm 2 asks whether anything lies past what a chain with no entries
    ///   can account for: the terminator record itself, and the archive
    ///   comment, whose extent comes from the header's own `acmt_pos`/
    ///   `acmt_len`.
    ///
    /// **Can a legitimately empty `.zoo` exist?** Established from zoo 2.10's
    /// source rather than from the fixtures, because four fixtures are an
    /// observation. `zoo a` on a new archive that adds nothing `unlink`s the
    /// file (`zooadd.c`: "No files added"), and `zoo P` over an archive whose
    /// members are all deleted unlinks its temp file and keeps the original
    /// (`zoopack.c`, `extcount == 0`) — so zoo 2.10 itself never writes one.
    /// That is emphatically NOT a licence to refuse one: a header followed by
    /// a terminator satisfies every rule the format states, another writer may
    /// produce it, and `a_legitimately_empty_archive_is_accepted` builds one
    /// and proves it reads as zero entries at exit 0.
    fn refuse_a_chain_that_reaches_nothing(&self, pos: u64, terminator: &DirEntry) -> Result<()> {
        if self.entries_on_chain > 0 {
            return Ok(());
        }
        let accounted = (pos + terminator.record_len).max(self.archive_comment_end);
        if self.file_len > accounted {
            return Err(Error::Corrupt(format!(
                "the ZOO directory chain reaches no entry at all — the record at offset {pos} \
                 is already the terminator — yet {} bytes lie past everything that chain \
                 accounts for, so this archive holds content nothing can reach",
                self.file_len - accounted
            )));
        }
        Ok(())
    }

    fn next_entry_inner(&mut self) -> Result<Option<(EntryMeta, Vec<u8>)>> {
        loop {
            let Some(pos) = self.next_pos else {
                return Ok(None);
            };
            let header = read_dir_entry(&mut self.src, pos)?;

            // Surfaced for EVERY record, the terminator included, and before
            // anything is decided on the strength of its fields. A record
            // that fails its own checksum has been altered since it was
            // written, and the name, sizes, offset and next link a caller is
            // about to trust all come out of it — see
            // `Fidelity::DirectoryRecordChecksum` for why this warns where a
            // content checksum refuses.
            if let Some((computed, recorded)) = header.dir_crc_mismatch {
                self.report.warn(Fidelity::DirectoryRecordChecksum {
                    format: ZOO,
                    offset: pos,
                    computed,
                    recorded,
                });
            }

            if header.next == 0 {
                // The terminator. `next == 0` is the WHOLE rule and no other
                // field is specified: `zooadd.c` writes the trailing record
                // as `direntry` with `next = offset = 0` and everything else
                // left at whatever the struct held, and `zoolist.c` breaks on
                // `next == 0` before consulting a single other field. All
                // four borrowed fixtures happen to carry an all-zero
                // terminator — that is an observation about one writer's
                // zeroed struct, not a rule, and requiring it would be
                // exactly the inheritance Ruling J exists to prevent.
                self.next_pos = None;
                self.refuse_a_chain_that_reaches_nothing(pos, &header)?;
                return Ok(None);
            }

            // THE CHAIN GUARD — see this module's doc. `next` must clear the
            // record it was read from, which makes the walk strictly
            // increasing and therefore finite. zoo's own `zoolist.c` is
            // fatal on the weaker `next <= zoo_pointer`.
            let end_of_record = pos + header.fixed_len as u64;
            if u64::from(header.next) < end_of_record {
                return Err(Error::Corrupt(format!(
                    "the ZOO directory entry at offset {pos} points its `next` link at \
                     {} — inside the {}-byte record it was read from, so the chain does not \
                     advance and following it would never terminate",
                    header.next, header.fixed_len
                )));
            }
            self.next_pos = Some(u64::from(header.next));
            self.entries_on_chain += 1;

            if header.deleted {
                // `zoo` keeps deleted entries in the chain and neither lists
                // nor extracts them — see this module's doc.
                continue;
            }

            let method = Method::from_byte(header.method_byte, &header.name)?;
            let payload = self.read_payload(&header)?;
            let decoded = decode(method, &payload, &header.name, header.org_size)?;
            check_declared_size(&header, decoded.len())?;
            let got = crc16_arc(&decoded);
            if got != header.crc16 {
                return Err(Error::Corrupt(format!(
                    "entry `{}` decoded to bytes whose CRC-16/ARC is {got:#06x}, but its own \
                     directory entry records {:#06x}",
                    header.name, header.crc16
                )));
            }

            let meta = EntryMeta {
                name: header.name,
                size: Some(u64::from(header.org_size)),
                compressed_size: Some(u64::from(header.size_now)),
                mtime: zoo_mtime(header.packed_datetime),
                // ZOO's directory entry has no kind, mode, owner or group
                // field this reader can honestly map: `struc` is a file
                // STRUCTURE hint (always 0 here) and `fattr` lives in the
                // variable part as a 24-bit DOS/Unix hybrid zoo itself only
                // writes on some systems. Every entry is a plain file.
                kind: EntryKind::File,
                ..Default::default()
            };
            return Ok(Some((meta, decoded)));
        }
    }
}

impl ArchiveRead for ZooRead {
    fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
        if self.done {
            return Ok(None);
        }
        match self.next_entry_inner() {
            Ok(Some((meta, data))) => Ok(Some(Entry::new(meta, Box::new(io::Cursor::new(data))))),
            Ok(None) => {
                self.done = true;
                Ok(None)
            }
            Err(e) => {
                self.done = true;
                Err(e)
            }
        }
    }

    /// One honest answer, not two — the same shape `arj.rs` argues for.
    ///
    /// `needs_seek: true` plus `forward_parse: false` means `resolve` never
    /// hands this container a forward-only source, so `Error::NotSeekable`
    /// would be unreachable and claiming it would be a lie about why. ZOO's
    /// directory is a LINKED LIST — reaching entry N means walking N links
    /// — so the format carries no index in the sense `by_index` means, and
    /// `Error::Unsupported` routes `entries.rs` to its counted forward walk,
    /// exactly as `tar`/`ar`/`cpio` do on a seekable source.
    fn by_index(&mut self, index: usize) -> Result<Entry<'_>> {
        Err(Error::Unsupported(format!(
            "ZOO's directory is a linked list rather than an index, so entry {index} can only \
             be reached by walking the chain from the start"
        )))
    }

    fn fidelity(&self) -> &FidelityReport {
        &self.report
    }
}

/// Refuses an entry whose decoded length disagrees with the `org_size` its
/// own directory entry declares — in EITHER direction.
///
/// This is the declared-versus-delivered guard `tar.rs`, `ar.rs`,
/// `cpio.rs`, `zip.rs` and `arc.rs` each already carry, and
/// `Error::exit_code`'s own doc records the ruling: the archive contradicts
/// itself, so there is nothing honest to hand back and it is
/// [`Error::Corrupt`] (exit 5), never a fidelity warning. A warning would
/// leave `unpack` writing the wrong-length file at exit 0, with
/// `--strict-fidelity` the only thing between a user and it.
///
/// **The per-entry CRC-16 is not a substitute**, and the reproducer that
/// proved it on `arc.rs` transfers unchanged: a Stored entry declaring
/// `size_now = 10` and `org_size = 4096`, carrying the CORRECT CRC-16 of
/// the ten bytes it really holds, satisfies its own checksum exactly.
/// `an_entry_that_declares_a_size_its_payload_does_not_deliver_is_corrupt`
/// pins both directions with exactly that shape.
///
/// **Honest about its own reach:** for [`Method::Lh5`] the output buffer is
/// SIZED from `org_size`, so `produced == declared` by construction and
/// this guard can never fire — the CRC is what protects that method. It
/// does real work for `Stored` (where the two fields are independent
/// `u32`s) and for [`Method::Lzw`] (where the decoder produces whatever the
/// code stream says).
fn check_declared_size(header: &DirEntry, produced: usize) -> Result<()> {
    let declared = u64::from(header.org_size);
    let produced = produced as u64;
    let name = &header.name;
    if produced < declared {
        return Err(Error::Corrupt(format!(
            "entry `{name}` decoded to {produced} bytes, {} short of the {declared} its \
             directory entry declares; the archive is truncated",
            declared - produced
        )));
    }
    if produced > declared {
        return Err(Error::Corrupt(format!(
            "entry `{name}` decoded to {produced} bytes, past the {declared} its directory \
             entry declares; the header and the entry's contents disagree"
        )));
    }
    Ok(())
}

/// Runs one entry's payload through the decoder its method names.
///
/// Takes `name` and `org_size` rather than a whole [`DirEntry`] because
/// `../zoo_salvage.rs`'s write path has neither in hand as a record — it
/// reconstructs both from the [`stuffr_core::salvage::SalvagedEntry`] its
/// own scan produced — and those two fields are all any of the three
/// decoders ever reads.
pub(super) fn decode(method: Method, payload: &[u8], name: &str, org_size: u32) -> Result<Vec<u8>> {
    match method {
        Method::Stored => Ok(payload.to_vec()),
        Method::Lzw => lzw_decode(payload, name),
        Method::Lh5 => lh5_decode(payload, name, org_size),
    }
}

/// Decodes ZOO's method 2 through `delharc`'s `-lh5-` decoder.
///
/// `delharc` is already this crate's LHA dependency, and `Lh5Decoder` is
/// public and usable over a bare `Read` — so the LH5 layer needs no second
/// implementation here the way the LZW layer does. The stream carries no
/// LHA header: it is the raw compressed body, which is why the decoder is
/// constructed directly rather than through `LhaDecodeReader`.
///
/// **`org_size` must already have been bounded against
/// [`MAX_ZOO_ENTRY_LEN`] by the caller**, which is what makes the
/// `vec![0; org_size]` below safe — it is a `u32`, so an unbounded one is a
/// 4 GiB allocation from a header field. Two callers do that now, in two
/// different ways and for the same reason: [`ZooRead::read_payload`] refuses
/// over-ceiling with [`Error::ResourceLimit`], and `../zoo_salvage.rs`
/// answers `Unverified(OverEntryCeiling)` — a per-entry STATUS, because an
/// `Err` out of a salvage scanner aborts the whole run.
/// `fill_buffer` fills the WHOLE buffer or errors, so a stream that runs
/// out early is `UnexpectedEof` — folded to [`Error::Corrupt`], since the
/// reader here is an in-memory slice and cannot produce a genuine source
/// failure at all.
fn lh5_decode(payload: &[u8], name: &str, org_size: u32) -> Result<Vec<u8>> {
    let mut out = vec![0u8; org_size as usize];
    let mut decoder = Lh5Decoder::new(payload);
    decoder.fill_buffer(&mut out).map_err(|e| {
        Error::Corrupt(format!(
            "entry `{name}` is LH5-compressed and did not decode: {e}"
        ))
    })?;
    Ok(out)
}

// ---- zoo's own LZW (`lzd.c`), method 1 ----

/// `lzconst.h`: `#define CLEAR 256`.
const LZW_CLEAR: u32 = 256;
/// `lzconst.h`: `#define Z_EOF 257` — the explicit end-of-stream code
/// neither of this crate's other two LZW dialects has.
const LZW_EOF: u32 = 257;
/// `lzconst.h`: `#define FIRST_FREE 258`, one higher than ARC's and Unix
/// `compress`'s because of [`LZW_EOF`].
const LZW_FIRST_FREE: u32 = 258;
/// `lzconst.h`: `#define MAXBITS 13`.
const LZW_MAXBITS: u32 = 13;
/// `lzconst.h`: `#define MAXMAX 8192` — "max code + 1".
const LZW_MAXMAX: u32 = 8192;

/// Decodes zoo's LZW, following `lzd.c`'s own state machine.
///
/// Two places are deliberately STRICTER than the original, both refusing
/// input no encoder can produce:
///
/// - `lzd.c` treats `cur_code >= free_code` as the K-w-K-w-K case, so a
///   code well past the dictionary silently decodes as something else.
///   Only `cur_code == free_code` is that case; anything higher is
///   [`Error::Corrupt`].
/// - `lzd.c` writes the code following a CLEAR straight out as a byte
///   without checking it is one. A value above 255 there is
///   [`Error::Corrupt`].
///
/// One place is deliberately more FORGIVING, and for the same reason
/// `unpack_rle90` tolerates a trailing DLE in `arc.rs`: a stream that ends
/// without [`LZW_EOF`] stops cleanly rather than raising, because the final
/// byte's leftover bits are padding and the CRC-16 over the whole entry is
/// what catches real damage — with a message naming both checksums, which
/// "missing end code" would not.
fn lzw_decode(input: &[u8], name: &str) -> Result<Vec<u8>> {
    let mut prefix = vec![0u16; LZW_MAXMAX as usize];
    let mut suffix = vec![0u8; LZW_MAXMAX as usize];
    let mut out: Vec<u8> = Vec::new();
    let mut stack: Vec<u8> = Vec::new();

    let mut br = LsbBitReader::new(input);
    let mut nbits = 9u32;
    let mut max_code = 512u32;
    let mut free_code = LZW_FIRST_FREE;
    let mut old_code = 0u32;
    // False until a code has been emitted since the last CLEAR — `lzd.c`
    // reaches the same state by reading the code after a CLEAR inline.
    let mut have_old = false;

    // `while let` rather than `loop` + `let else`: running out of bits IS the
    // clean end of stream here (see this function's doc), so the absence of a
    // code is the loop's own exit condition.
    while let Some(raw) = br.read_bits(nbits) {
        let mut code = u32::from(raw);

        if code == LZW_EOF {
            break;
        }
        if code == LZW_CLEAR {
            // `lzd.c`'s `init_dtab()`.
            nbits = 9;
            max_code = 512;
            free_code = LZW_FIRST_FREE;
            have_old = false;
            continue;
        }

        if !have_old {
            if code > 255 {
                return Err(Error::Corrupt(format!(
                    "entry `{name}` opens an LZW block with code {code}, which is not a literal \
                     byte — no dictionary entry exists yet for it to name"
                )));
            }
            guard_output(name, out.len() + 1)?;
            out.push(code as u8);
            old_code = code;
            have_old = true;
            continue;
        }

        let in_code = code;
        if code > free_code {
            return Err(Error::Corrupt(format!(
                "entry `{name}` uses LZW code {code}, past the {free_code} entries its own \
                 stream has defined so far"
            )));
        }
        stack.clear();
        if code == free_code {
            // K-w-K-w-K: the word is the previous one plus its own first
            // character. `lzd.c` pushes `firstchar(old_code)` and unwinds
            // `old_code` instead.
            stack.push(first_char(&prefix, old_code, name)?);
            code = old_code;
        }
        let mut guard = 0u32;
        while code > 255 {
            stack.push(suffix[code as usize]);
            code = u32::from(prefix[code as usize]);
            guard += 1;
            if guard > LZW_MAXMAX {
                // Unreachable: every `prefix[n]` written below is strictly
                // less than `n`, so a chain cannot cycle. Bounded anyway,
                // because "unreachable" is a claim about today's code.
                return Err(Error::Corrupt(format!(
                    "entry `{name}` has an LZW prefix chain that does not terminate"
                )));
            }
        }
        let first = code as u8;
        stack.push(first);

        guard_output(name, out.len() + stack.len())?;
        out.extend(stack.iter().rev());

        if free_code < LZW_MAXMAX {
            prefix[free_code as usize] = old_code as u16;
            suffix[free_code as usize] = first;
            free_code += 1;
            // `lzd.c`'s `add_code`: the decoder widens one code EARLIER than
            // the encoder (`lzc.c` grows on `free_code > max_code`), which
            // is the standard compensation for the decoder running one
            // entry behind.
            if free_code >= max_code && nbits < LZW_MAXBITS {
                nbits += 1;
                max_code <<= 1;
            }
        }
        old_code = in_code;
    }

    Ok(out)
}

/// `lzd.c`'s `firstchar()`: walk a code's prefix chain down to its literal.
fn first_char(prefix: &[u16], mut code: u32, name: &str) -> Result<u8> {
    let mut guard = 0u32;
    while code > 255 {
        code = u32::from(prefix[code as usize]);
        guard += 1;
        if guard > LZW_MAXMAX {
            return Err(Error::Corrupt(format!(
                "entry `{name}` has an LZW prefix chain that does not terminate"
            )));
        }
    }
    Ok(code as u8)
}

/// The output-side half of the ceiling — see [`refuse_if_over_ceiling`].
fn guard_output(name: &str, len: usize) -> Result<()> {
    refuse_if_over_ceiling(name, len as u64, "decompressed data")
}

/// The ZOO archive BUILDER, shared by this module's own tests and by
/// `../zoo_salvage.rs`'s.
///
/// Lifted out of `mod tests` in Salvage Stage 2 Task 4 rather than copied:
/// a second hand-written copy of the 56-byte record layout in the scanner's
/// test module is exactly how a fixture and its expectation drift apart, and
/// the 56-versus-59 question this format's whole module doc is about makes
/// that risk concrete rather than theoretical.
///
/// Everything the original doc comment on [`build_zoo`] says still holds and
/// is repeated there: an archive built here is evidence about BEHAVIOUR,
/// never about LAYOUT, because the builder and the reader share an author.
/// Layout is settled by the four borrowed fixtures and by zoo 2.10's own
/// source.
#[cfg(test)]
pub(super) mod test_archives {
    use super::*;

    /// One entry to assemble into a synthesised archive.
    #[derive(Clone)]
    pub(in crate::legacy) struct Spec {
        pub(in crate::legacy) name: &'static str,
        pub(in crate::legacy) dir_type: u8,
        pub(in crate::legacy) method: u8,
        pub(in crate::legacy) payload: Vec<u8>,
        /// `None` means "declare exactly what the payload is", which is the
        /// honest case; `Some` is how a header is made to lie.
        pub(in crate::legacy) declared_org: Option<u32>,
        /// `None` means "the real CRC-16 of the payload", so a test of the
        /// SIZE guard cannot accidentally be passing on the checksum's back.
        pub(in crate::legacy) crc16: Option<u16>,
        pub(in crate::legacy) deleted: bool,
        pub(in crate::legacy) long_name: Option<&'static str>,
        /// Overrides the `next` link this entry would otherwise get, which
        /// is how a cyclic chain is built.
        pub(in crate::legacy) next_override: Option<u32>,
        /// Replaces the variable part wholesale, for shapes the fields
        /// above cannot express.
        pub(in crate::legacy) var_override: Option<Vec<u8>>,
    }

    impl Spec {
        pub(in crate::legacy) fn stored(name: &'static str, payload: &[u8]) -> Self {
            Spec {
                name,
                dir_type: 2,
                method: 0,
                payload: payload.to_vec(),
                declared_org: None,
                crc16: None,
                deleted: false,
                long_name: None,
                next_override: None,
                var_override: None,
            }
        }
    }

    /// Assembles a complete ZOO archive: a 42-byte header, one record plus
    /// leader plus payload per spec, and the trailing terminator `zooadd.c`
    /// writes.
    ///
    /// **This builder and the reader above share an author, and that is the
    /// weakest evidence class in this phase.** Offsets, `next` links and each
    /// record's `dir_crc` are filled in from the real byte positions — which
    /// keeps the builder self-consistent, and self-consistency is precisely
    /// what it cannot vouch for: a field both sides read from the same wrong
    /// offset would agree here and be wrong on disk. Every archive built
    /// here is therefore evidence about BEHAVIOUR (a cycle is refused, a
    /// deleted entry is skipped, a size lie is caught) and never about
    /// LAYOUT. Layout is settled by the four borrowed fixtures and by zoo
    /// 2.10's own source, which is why
    /// `a_directory_entrys_own_crc_confirms_the_fifty_six_byte_record` walks
    /// the real archives with a parser written out longhand instead.
    pub(in crate::legacy) fn build_zoo(specs: &[Spec]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        let mut text = [0u8; 20];
        text[..18].copy_from_slice(b"ZOO 2.10 Archive.\x1a");
        out.extend_from_slice(&text);
        out.extend_from_slice(&ZOO_TAG.to_le_bytes());
        out.extend_from_slice(&42u32.to_le_bytes()); // zoo_start
        out.extend_from_slice(&42i32.wrapping_neg().to_le_bytes()); // zoo_minus
        out.extend_from_slice(&[2, 0]); // major/minor
        out.push(1); // header type
        out.extend_from_slice(&0u32.to_le_bytes()); // acmt_pos
        out.extend_from_slice(&0u16.to_le_bytes()); // acmt_len
        out.push(3); // vdata
        assert_eq!(out.len(), 42, "SIZ_ZOOH");

        // `(record start, fixed+variable length)` per record, so the
        // `dir_crc` pass below can cover exactly what `dir_to_b` covers.
        let mut records: Vec<(usize, usize)> = Vec::new();
        let mut dir_at: Vec<usize> = Vec::new();
        for spec in specs {
            let at = out.len();
            dir_at.push(at);
            let fixed = if spec.dir_type == 2 {
                SIZ_DIRL
            } else {
                SIZ_DIR
            };
            let mut rec = vec![0u8; fixed];
            rec[0..4].copy_from_slice(&ZOO_TAG.to_le_bytes());
            rec[4] = spec.dir_type;
            rec[5] = spec.method;
            let crc = spec.crc16.unwrap_or_else(|| crc16_arc(&spec.payload));
            rec[18..20].copy_from_slice(&crc.to_le_bytes());
            let org = spec.declared_org.unwrap_or(spec.payload.len() as u32);
            rec[20..24].copy_from_slice(&org.to_le_bytes());
            rec[24..28].copy_from_slice(&(spec.payload.len() as u32).to_le_bytes());
            rec[28] = 1;
            rec[30] = u8::from(spec.deleted);
            let n = spec.name.len().min(FNM_SIZ);
            rec[FNAME_I..FNAME_I + n].copy_from_slice(&spec.name.as_bytes()[..n]);

            let var: Vec<u8> = match (&spec.var_override, spec.long_name) {
                (Some(v), _) => v.clone(),
                (None, Some(long)) => {
                    // `dir_to_b`: namlen, dirlen, lfname, dirname, then the
                    // eight bytes of system_id/fattr/vflag/version_no. The
                    // NUL is counted, as `dirlen = 3` for `..` shows.
                    let mut v = vec![long.len() as u8 + 1, 0];
                    v.extend_from_slice(long.as_bytes());
                    v.push(0);
                    v.extend_from_slice(&[0u8; 8]);
                    v
                }
                (None, None) => Vec::new(),
            };
            if fixed == SIZ_DIRL {
                rec[51..53].copy_from_slice(&(var.len() as u16).to_le_bytes());
                rec[53] = 127; // NO_TZ
            }
            records.push((at, fixed + var.len()));
            out.extend_from_slice(&rec);
            out.extend_from_slice(&var);
            out.extend_from_slice(b"@)#(\0"); // FILE_LEADER + SIZ_FLDR
            let payload_at = out.len() as u32;
            out.extend_from_slice(&spec.payload);
            out[at + 10..at + 14].copy_from_slice(&payload_at.to_le_bytes());
        }

        let term_at = out.len() as u32;
        let mut term = vec![0u8; SIZ_DIRL];
        term[0..4].copy_from_slice(&ZOO_TAG.to_le_bytes());
        term[4] = 2;
        term[53] = 127; // NO_TZ, as `newdir` sets it
        records.push((term_at as usize, SIZ_DIRL));
        out.extend_from_slice(&term);

        for (i, &at) in dir_at.iter().enumerate() {
            let next = specs[i]
                .next_override
                .unwrap_or_else(|| dir_at.get(i + 1).map(|&n| n as u32).unwrap_or(term_at));
            out[at + 6..at + 10].copy_from_slice(&next.to_le_bytes());
        }

        // LAST, because `dir_to_b` computes the record's checksum once every
        // other field is final — and `next` is only final after the pass
        // above. A builder that hashed each record as it wrote it would
        // produce archives that warn about themselves.
        for (at, len) in records {
            if out[at + 4] != 2 {
                continue; // a type-0/1 record carries no `dir_crc` field
            }
            out[at + 54] = 0;
            out[at + 55] = 0;
            let crc = crc16_arc(&out[at..at + len]);
            out[at + 54..at + 56].copy_from_slice(&crc.to_le_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::test_archives::{Spec, build_zoo};
    use super::*;
    use std::time::UNIX_EPOCH;
    use stuffr_core::testing::{ContainerFixture, ExpectedEntry, assert_container_conforms_with};
    use stuffr_core::{
        CreateOpts, OpenOpts, PlainSink, ReaderSource, SourceCaps, StreamPolicy, resolve,
    };

    const STORE_ZOO: &[u8] = include_bytes!("../../fixtures/legacy/zoo/store.zoo");
    const DEFAULT_ZOO: &[u8] = include_bytes!("../../fixtures/legacy/zoo/default.zoo");
    const HIGH_PER_ZOO: &[u8] = include_bytes!("../../fixtures/legacy/zoo/high_per.zoo");
    const WRONGCRC16_ZOO: &[u8] = include_bytes!("../../fixtures/legacy/zoo/wrongcrc16.zoo");

    const PROVENANCE: &str = "archive bytes from unarc-rs 0.6.3's MIT/Apache test corpus, \
                              borrowed as bytes only; every stored_crc below is parsed from \
                              the archive's OWN directory entry at test time by this module's \
                              `raw_entries`, never from a literal and never from decoding \
                              anything. See fixtures/legacy/MANIFEST.md";

    /// One directory entry as it appears in an archive's raw bytes.
    struct RawEntry {
        name: String,
        method: u8,
        crc16: u16,
        org_size: u32,
        payload: &'static [u8],
        /// The whole record — fixed part plus variable part — as the CRC
        /// `dir_to_b` computes covers it.
        record: &'static [u8],
        dir_crc: u16,
        tz: u8,
        var_len: usize,
        at: usize,
        payload_at: usize,
        next: u32,
    }

    /// Walks an archive's directory chain with a parser written out longhand
    /// here, independent of everything above it in this file.
    ///
    /// Two rules `MANIFEST.md`'s banner states, and this is the code that
    /// keeps them: `stored_crc` is TRANSCRIBED from the archive's own bytes,
    /// never hardcoded from the manifest's tables (a hand-copied hex literal
    /// silently strands when a fixture changes) and never computed by
    /// decoding a payload and hashing the result (which would turn the CRC
    /// conformance property into a self-consistency check, duplicating
    /// property 5). Deliberately NOT [`read_dir_entry`]: a manifest derived
    /// from the parser under test would agree with it by construction.
    ///
    /// The terminator (`next == 0`) is not returned, matching `zoolist.c`.
    fn raw_entries(bytes: &'static [u8]) -> Vec<RawEntry> {
        let le32 = |i: usize| {
            u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]) as usize
        };
        let le16 = |i: usize| u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        assert_eq!(le32(20), 0xFDC4_A7DC, "archive tag at offset 20");
        let mut at = le32(24); // zoo_start
        let mut out = Vec::new();
        loop {
            assert_eq!(le32(at), 0xFDC4_A7DC, "directory-entry tag at offset {at}");
            let dir_type = bytes[at + 4];
            assert_eq!(dir_type, 2, "every borrowed fixture uses a type-2 entry");
            let next = le32(at + 6) as u32;
            if next == 0 {
                return out;
            }
            let var_len = usize::from(le16(at + 51));
            let record_len = 56 + var_len;
            let offset = le32(at + 10);
            let compressed = le32(at + 24);
            let name_field = &bytes[at + 38..at + 51];
            let end = name_field
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(name_field.len());
            out.push(RawEntry {
                name: String::from_utf8_lossy(&name_field[..end]).into_owned(),
                method: bytes[at + 5],
                crc16: le16(at + 18),
                org_size: le32(at + 20) as u32,
                payload: &bytes[offset..offset + compressed],
                record: &bytes[at..at + record_len],
                dir_crc: le16(at + 54),
                tz: bytes[at + 53],
                var_len,
                at,
                payload_at: offset,
                next,
            });
            at = next as usize;
        }
    }

    /// The LICENSE plaintext all four fixtures carry, taken from the ONE
    /// that stores it uncompressed.
    ///
    /// `store.zoo`'s entry is method 0, so its payload IS its content — a
    /// byte range, with no decoder involved. That makes it usable as the
    /// expected output for `default.zoo` and `high_per.zoo` without ever
    /// asking this module's own decoders to vouch for themselves, and it is
    /// independently anchored by the CRC-16 `store.zoo`'s own header records
    /// (`the_stored_fixtures_payload_matches_the_crc_its_archive_records`).
    fn license() -> &'static [u8] {
        raw_entries(STORE_ZOO)[0].payload
    }

    fn manifest(archive: &'static [u8], contents: &[&'static [u8]]) -> &'static [ExpectedEntry] {
        let raw = raw_entries(archive);
        assert_eq!(
            raw.len(),
            contents.len(),
            "entry count vs expected contents"
        );
        let entries: Vec<ExpectedEntry> = raw
            .iter()
            .zip(contents)
            .map(|(r, c)| {
                ExpectedEntry::with_crc(Box::leak(r.name.clone().into_boxed_str()), c, r.crc16)
            })
            .collect();
        Box::leak(entries.into_boxed_slice())
    }

    fn fixture(bytes: &'static [u8], contents: &[&'static [u8]]) -> ContainerFixture {
        ContainerFixture::new(bytes, manifest(bytes, contents), PROVENANCE)
    }

    /// A seekable in-memory source, which is what this container's caps
    /// require of every source it is ever opened over.
    struct CursorSource(io::Cursor<Vec<u8>>);

    impl Read for CursorSource {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Source for CursorSource {
        fn caps(&self) -> SourceCaps {
            SourceCaps {
                seekable: true,
                len: Some(self.0.get_ref().len() as u64),
            }
        }
        fn as_seek(&mut self) -> Option<&mut dyn SeekRead> {
            Some(&mut self.0)
        }
    }

    fn open_seekable(bytes: &[u8]) -> Result<Box<dyn ArchiveRead>> {
        let src: Box<dyn Source> = Box::new(CursorSource(io::Cursor::new(bytes.to_vec())));
        let resolved = resolve(src, ZOO, Zoo.caps(), &StreamPolicy::default())?;
        Zoo.open(resolved, &OpenOpts::default())
    }

    fn read_all(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
        let mut ar = open_seekable(bytes)?;
        let mut out = Vec::new();
        while let Some(mut entry) = ar.next_entry()? {
            let name = entry.meta().name.clone();
            let mut data = Vec::new();
            entry.reader().read_to_end(&mut data)?;
            out.push((name, data));
        }
        Ok(out)
    }

    // ---- the fixtures' own ground truth, established with no decoder ----

    /// The one fixture whose payload is its content, checked against the
    /// CRC its own directory entry records — with no decoder in the loop.
    /// Everything downstream uses [`license`] as an expectation, so if this
    /// is wrong nothing else is evidence.
    #[test]
    fn the_stored_fixtures_payload_matches_the_crc_its_archive_records() {
        let raw = raw_entries(STORE_ZOO);
        assert_eq!(raw.len(), 1, "store.zoo holds one entry");
        assert_eq!(raw[0].name, "license");
        assert_eq!(raw[0].method, 0, "stored");
        assert_eq!(crc16_arc(raw[0].payload), raw[0].crc16);
        assert_eq!(raw[0].payload.len(), 11_357);
    }

    #[test]
    fn each_fixtures_method_byte_is_the_one_the_manifest_records() {
        for (bytes, label, method) in [
            (STORE_ZOO, "store.zoo", 0u8),
            (DEFAULT_ZOO, "default.zoo", 1),
            (HIGH_PER_ZOO, "high_per.zoo", 2),
            (WRONGCRC16_ZOO, "wrongcrc16.zoo", 0),
        ] {
            let raw = raw_entries(bytes);
            assert_eq!(raw.len(), 1, "{label} holds one entry");
            assert_eq!(raw[0].method, method, "{label}");
            assert_eq!(raw[0].name, "license", "{label}");
            assert_eq!(raw[0].org_size, 11_357, "{label}");
        }
    }

    /// **The layout witness.** `dir_to_b` (`portable.c`) computes a
    /// CRC-16/ARC over `SIZ_DIRL + var_dir_len` bytes with the `dir_crc`
    /// field itself zeroed. Reproducing the stored value requires the record
    /// to start and end in exactly the right places and `var_dir_len` to be
    /// the `u16` at offset 51 — so this is the single test that decides
    /// between this module's 56-byte record and `unarc-rs`'s 59.
    ///
    /// **The four REAL records carry the whole argument.** The terminal
    /// record is checked too, and it verifies clean — but it is NOT evidence
    /// and must not be cited as such: it is the last thing in the file, so a
    /// 59-byte slice of it clips at EOF back to the same 56 bytes and both
    /// models compute the identical `0x83fc`. A check that cannot
    /// distinguish two hypotheses supports neither. It is kept because "the
    /// terminator's own CRC checks out" is a true and useful fact about the
    /// fixtures; the assertion that discriminates is the loop above it.
    /// The `tz == 127` assertion is the second, independent leg — `NO_TZ`
    /// lands at offset 53 only under this layout.
    #[test]
    fn a_directory_entrys_own_crc_confirms_the_fifty_six_byte_record() {
        for (bytes, label) in [
            (STORE_ZOO, "store.zoo"),
            (DEFAULT_ZOO, "default.zoo"),
            (HIGH_PER_ZOO, "high_per.zoo"),
            (WRONGCRC16_ZOO, "wrongcrc16.zoo"),
        ] {
            let raw = raw_entries(bytes);
            let e = &raw[0];
            assert_eq!(e.tz, 127, "{label}: zoo.h's NO_TZ sits at offset 53");
            let mut zeroed = e.record.to_vec();
            zeroed[54] = 0;
            zeroed[55] = 0;
            assert_eq!(
                crc16_arc(&zeroed),
                e.dir_crc,
                "{label}: the directory entry's own CRC only reproduces over a \
                 {SIZ_DIRL}-byte fixed record plus its variable part"
            );
            // And the counter-model FAILS, which is what makes the line above
            // a discriminator rather than a coincidence: `unarc-rs`'s 59-byte
            // fixed record with `dir_crc` as a u32 at 53 hashes a different
            // span and reads its expectation from a different place.
            let alt = &bytes[e.at..e.at + 59 + e.var_len];
            let mut alt_zeroed = alt.to_vec();
            for b in &mut alt_zeroed[53..57] {
                *b = 0;
            }
            assert_ne!(
                crc16_arc(&alt_zeroed),
                u32::from_le_bytes([alt[53], alt[54], alt[55], alt[56]]) as u16,
                "{label}: the 59-byte model must NOT also reproduce, or this proves nothing"
            );

            // The terminator, read as a COMPLETE record ending at EOF.
            let term = e.next as usize;
            assert_eq!(
                term + SIZ_DIRL,
                bytes.len(),
                "{label}: the trailing record must end exactly at end of file"
            );
            let mut tail = bytes[term..].to_vec();
            let stored = u16::from_le_bytes([tail[54], tail[55]]);
            tail[54] = 0;
            tail[55] = 0;
            assert_eq!(
                crc16_arc(&tail),
                stored,
                "{label}: the terminal record's own CRC confirms it is complete, not \
                 three bytes short of a 59-byte one"
            );
        }
    }

    /// The five bytes between a record and its payload are `zoo.h`'s
    /// `FILE_LEADER "@)#("` plus its NUL (`SIZ_FLDR 5`), in every fixture.
    /// Pinned because a reader that computes the data position from the
    /// record length rather than from `offset` is exactly five bytes wrong.
    #[test]
    fn a_file_leader_sits_between_every_record_and_its_payload() {
        for (bytes, label) in [
            (STORE_ZOO, "store.zoo"),
            (DEFAULT_ZOO, "default.zoo"),
            (HIGH_PER_ZOO, "high_per.zoo"),
        ] {
            let e = &raw_entries(bytes)[0];
            let record_end = e.at + e.record.len();
            assert_eq!(&bytes[record_end..record_end + 5], b"@)#(\0", "{label}");
            assert_eq!(
                record_end + 5,
                e.payload_at,
                "{label}: the leader is EXACTLY what separates a record from its data, so \
                 `offset` must land five bytes past the record's end — this is the arithmetic \
                 a reader must not do for itself, pinned so that doing it would at least be \
                 visibly wrong here"
            );
        }
    }

    // ---- conformance ----

    #[test]
    fn zoo_conforms() {
        assert_container_conforms_with(&Zoo, &meta(), &fixture(STORE_ZOO, &[license()]));
    }

    #[test]
    fn a_compressed_archive_conforms() {
        assert_container_conforms_with(&Zoo, &meta(), &fixture(DEFAULT_ZOO, &[license()]));
    }

    #[test]
    fn an_lh5_archive_conforms() {
        assert_container_conforms_with(&Zoo, &meta(), &fixture(HIGH_PER_ZOO, &[license()]));
    }

    /// Three encoders' output against one expectation that came out of a
    /// fourth archive's stored payload.
    #[test]
    fn every_method_decodes_to_the_same_bytes() {
        for (bytes, label) in [
            (STORE_ZOO, "store.zoo"),
            (DEFAULT_ZOO, "default.zoo"),
            (HIGH_PER_ZOO, "high_per.zoo"),
        ] {
            let got = read_all(bytes).unwrap_or_else(|e| panic!("{label}: {e}"));
            assert_eq!(got.len(), 1, "{label}");
            assert_eq!(got[0].0, "license", "{label}");
            assert_eq!(
                got[0].1,
                license(),
                "{label} decoded to different bytes than store.zoo carries verbatim"
            );
        }
    }

    // ---- refusals ----

    /// The CRC witness firing for real. `wrongcrc16.zoo` stores `0xB065` —
    /// the CRC of the correct LICENSE content — over a payload that computes
    /// `0xE763`, so a reader that skipped the check would hand back wrong
    /// bytes at exit 0. Its entry is Stored, so no decompression step is
    /// involved: the mismatch is in the archive's own bytes.
    #[test]
    fn a_zoo_whose_crc_does_not_match_its_payload_is_corrupt() {
        let err = read_all(WRONGCRC16_ZOO).expect_err("a CRC mismatch must be refused");
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 5, "{err}");
        let msg = err.to_string();
        assert!(
            msg.contains("0xe763") && msg.contains("0xb065"),
            "the message must name both the computed and the recorded CRC, got: {msg}"
        );
    }

    /// The declared-versus-delivered guard, with the CRC-16 CORRECT for the
    /// payload actually carried — so the guard cannot be passing on the
    /// checksum's back. This is the defect `arc.rs` shipped and had to fix:
    /// unguarded, `list` prints the declared size, `test --strict-fidelity`
    /// answers "exact fidelity" and `unpack` writes a truncated file, all at
    /// exit 0.
    #[test]
    fn an_entry_that_declares_a_size_its_payload_does_not_deliver_is_corrupt() {
        for (declared_org, direction) in [(4096u32, "short"), (3u32, "long")] {
            let mut spec = Spec::stored("LIE.TXT", b"ten bytes!");
            spec.declared_org = Some(declared_org);
            let bytes = build_zoo(&[spec]);
            // The CRC in that record is the real one for the ten bytes
            // behind it, so nothing below can be the checksum firing.
            let raw_crc = u16::from_le_bytes([bytes[42 + 18], bytes[42 + 19]]);
            assert_eq!(raw_crc, crc16_arc(b"ten bytes!"));

            let err = match read_all(&bytes) {
                Ok(v) => panic!("a header lying {direction} by design was accepted: {v:?}"),
                Err(e) => e,
            };
            assert!(matches!(err, Error::Corrupt(_)), "{direction}: {err:?}");
            assert_eq!(
                err.exit_code(),
                5,
                "{direction}: a self-contradicting archive is corrupt, not a capability \
                 limit or a resource ceiling — {err}"
            );
            let msg = err.to_string();
            assert!(
                msg.contains("LIE.TXT")
                    && msg.contains("10")
                    && msg.contains(&declared_org.to_string()),
                "{direction}: the message must name the entry and both figures, got: {msg}"
            );
        }
    }

    /// The regression guard for the test above: every borrowed archive
    /// decodes to exactly the `org_size` its record declares, so the
    /// comparison cannot be one that fires on legitimate input — this
    /// project's second-commonest defect.
    #[test]
    fn every_fixture_decodes_to_exactly_the_size_its_header_declares() {
        for (bytes, label) in [
            (STORE_ZOO, "store.zoo"),
            (DEFAULT_ZOO, "default.zoo"),
            (HIGH_PER_ZOO, "high_per.zoo"),
        ] {
            let mut ar = open_seekable(bytes).unwrap();
            let mut seen = 0usize;
            while let Some(mut entry) = ar.next_entry().unwrap_or_else(|e| panic!("{label}: {e}")) {
                let declared = entry.meta().size.expect("ZOO always declares a size");
                let mut data = Vec::new();
                entry.reader().read_to_end(&mut data).unwrap();
                assert_eq!(data.len() as u64, declared, "{label}");
                seen += 1;
            }
            assert!(seen > 0, "{label} yielded no entry");
        }
    }

    #[test]
    fn a_packing_method_past_the_formats_own_maximum_is_unsupported() {
        let mut spec = Spec::stored("X.TXT", b"whatever");
        spec.method = 3;
        let err = read_all(&build_zoo(&[spec])).unwrap_err();
        assert!(
            matches!(err, Error::Unsupported(_)),
            "a method this build cannot decode is a capability limit, not damage: {err:?}"
        );
        assert_eq!(err.exit_code(), 3, "{err}");
        assert!(err.to_string().contains('3'), "{err}");
    }

    /// The OTHER record length. `zoo.h` gives `SIZ_DIR 51` for a type-0/1
    /// entry — no `var_dir_len`, no `tz`, no `dir_crc`, and no variable part
    /// behind it — and every borrowed fixture is type 2, so nothing in the
    /// corpus exercises the shorter branch. Reading a 56-byte record over a
    /// 51-byte one would swallow the first five bytes of the file leader and
    /// put `offset` five bytes out for every entry after it.
    #[test]
    fn a_type_one_entry_is_read_as_the_shorter_fifty_one_byte_record() {
        let mut first = Spec::stored("OLD1.TXT", b"an older entry");
        first.dir_type = 1;
        let mut second = Spec::stored("OLD2.TXT", b"and the one behind it");
        second.dir_type = 1;
        let got = read_all(&build_zoo(&[first, second])).expect("a type-1 chain reads");
        assert_eq!(
            got,
            vec![
                ("OLD1.TXT".to_string(), b"an older entry".to_vec()),
                ("OLD2.TXT".to_string(), b"and the one behind it".to_vec()),
            ]
        );
    }

    /// An LH5 payload that is not an LH5 stream is damage, not a capability
    /// limit: the method IS decodable by this build, these particular bytes
    /// are not. `delharc`'s own error is folded to [`Error::Corrupt`], never
    /// left as `Error::Io` — the reader here is an in-memory slice, so there
    /// is no genuine source failure it could be confused with.
    #[test]
    fn an_lh5_payload_that_does_not_decode_is_corrupt() {
        let mut spec = Spec::stored("BAD.LH5", &[0xFFu8; 64]);
        spec.method = 2;
        spec.declared_org = Some(4096);
        let err = read_all(&build_zoo(&[spec])).expect_err("garbage is not an LH5 stream");
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 5, "{err}");
        assert!(err.to_string().contains("BAD.LH5"), "{err}");
    }

    #[test]
    fn a_directory_entry_type_past_two_is_unsupported() {
        let mut spec = Spec::stored("X.TXT", b"whatever");
        spec.dir_type = 3;
        let err = read_all(&build_zoo(&[spec])).unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "{err:?}");
        assert_eq!(err.exit_code(), 3, "{err}");
    }

    #[test]
    fn a_file_that_is_not_a_zoo_archive_is_refused_at_open() {
        let mut bytes = STORE_ZOO.to_vec();
        bytes[20] ^= 0xFF;
        let err = read_all(&bytes).expect_err("a wrong archive tag must be refused");
        assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
        assert_eq!(err.exit_code(), 5, "{err}");
    }

    /// A chain link that does not land on a directory entry is refused
    /// rather than parsed as one — this reader never scans for the next
    /// plausible record, the same call `arc.rs` makes about ARC's marker.
    #[test]
    fn a_chain_link_that_misses_a_directory_entry_is_corrupt() {
        let mut spec = Spec::stored("X.TXT", b"whatever");
        spec.next_override = Some(200);
        let mut bytes = build_zoo(&[spec]);
        bytes.resize(400, 0);
        let err = read_all(&bytes).expect_err("a link into nothing must be refused");
        assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
        assert_eq!(err.exit_code(), 5, "{err}");
        assert!(err.to_string().contains("tag"), "{err}");
    }

    /// The archive really does stop three bytes early if a reader demands
    /// 59 bytes of the terminator — so cutting three bytes off a GOOD
    /// archive must be refused, which is what pins the record size from the
    /// other side.
    #[test]
    fn an_archive_whose_terminal_record_is_short_is_corrupt() {
        let cut = &STORE_ZOO[..STORE_ZOO.len() - 3];
        let err = read_all(cut).expect_err("a truncated terminator must be refused");
        assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
        assert_eq!(err.exit_code(), 5, "{err}");
    }

    // ---- a chain that reaches nothing ----

    /// What one archive read produced: its entries, and the fidelity report
    /// that came with them.
    type ReadWithReport = (Vec<(String, Vec<u8>)>, FidelityReport);

    /// Opens an archive and returns its entries alongside the fidelity report
    /// the read produced, because several properties below are about what was
    /// WARNED rather than what came back.
    fn read_all_with_report(bytes: &[u8]) -> Result<ReadWithReport> {
        let mut ar = open_seekable(bytes)?;
        let mut out = Vec::new();
        while let Some(mut entry) = ar.next_entry()? {
            let name = entry.meta().name.clone();
            let mut data = Vec::new();
            entry.reader().read_to_end(&mut data)?;
            out.push((name, data));
        }
        let report = ar.fidelity().clone();
        Ok((out, report))
    }

    /// Zeroes the first record's `next` in a real archive — the reviewer's
    /// four-byte mutation.
    fn with_the_chain_cut_at_the_first_record(bytes: &[u8]) -> Vec<u8> {
        let mut out = bytes.to_vec();
        let start = u32::from_le_bytes([out[24], out[25], out[26], out[27]]) as usize;
        out[start + 6..start + 10].copy_from_slice(&0u32.to_le_bytes());
        out
    }

    /// **The required fix.** Four bytes turn `store.zoo`'s only record into a
    /// terminator, and before this guard `list` printed no rows, `test
    /// --strict-fidelity` answered `0 bytes verified (exact fidelity)` and
    /// `unpack --strict-fidelity` made an empty directory — all at exit 0,
    /// over 11,418 bytes of content the chain never mentions.
    #[test]
    fn a_chain_that_reaches_no_entry_over_a_file_holding_content_is_corrupt() {
        let bytes = with_the_chain_cut_at_the_first_record(STORE_ZOO);
        assert_eq!(bytes.len(), STORE_ZOO.len(), "only four bytes change");
        let err = read_all(&bytes).expect_err("an archive nothing can reach must be refused");
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
        assert_eq!(
            err.exit_code(),
            5,
            "the bytes were read and found to contradict themselves, and no larger budget \
             could make the file readable — see Error::exit_code's own rule: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("11418") && msg.contains("reaches no entry"),
            "the message must name the orphaned bytes, got: {msg}"
        );
    }

    /// The other half of the conjunction, and the one that decides whether
    /// this guard is a fix or the fourteenth wrong refusal. A header followed
    /// by nothing but a terminator satisfies every rule the format states.
    ///
    /// zoo 2.10 itself never writes one — `zoo a` unlinks a new archive that
    /// added nothing, and `zoo P` over an all-deleted archive keeps the
    /// original rather than writing an emptied one — which is a fact about
    /// that writer, not about the format, and is not licence to refuse one.
    #[test]
    fn a_legitimately_empty_archive_is_accepted() {
        let bytes = build_zoo(&[]);
        assert_eq!(bytes.len(), 42 + SIZ_DIRL, "a header and a terminator");
        let (got, report) = read_all_with_report(&bytes).expect("an empty archive is not corrupt");
        assert!(got.is_empty(), "no entries, and no error either: {got:?}");
        assert!(
            !report.has_warnings(),
            "an empty archive is exact, not approximated: {:?}",
            report.warnings
        );
    }

    /// An empty archive that carries an archive COMMENT still reads. The
    /// comment is the one thing that legitimately sits outside the directory
    /// chain, so arm 2 accounts for it from the header's own `acmt_pos` /
    /// `acmt_len` rather than treating every trailing byte as orphaned.
    #[test]
    fn an_empty_archive_with_an_archive_comment_is_accepted() {
        let mut bytes = build_zoo(&[]);
        let comment = b"packed by something that is not zoo";
        let at = bytes.len() as u32;
        bytes.extend_from_slice(comment);
        // ACMTPOS_I 35, ACMTLEN_I 39.
        bytes[35..39].copy_from_slice(&at.to_le_bytes());
        bytes[39..41].copy_from_slice(&(comment.len() as u16).to_le_bytes());
        let got = read_all(&bytes).expect("an archive comment is not orphaned content");
        assert!(got.is_empty());
    }

    /// An archive whose every member is marked deleted yields no entries and
    /// must still not be refused — `zoo d` leaves exactly this, payloads
    /// included. Arm 1 counts records ON THE CHAIN rather than entries
    /// yielded, so this never reaches arm 2 at all.
    #[test]
    fn an_archive_whose_every_entry_is_deleted_is_accepted() {
        let mut a = Spec::stored("GONE1.TXT", b"first, deleted");
        a.deleted = true;
        let mut b = Spec::stored("GONE2.TXT", b"second, deleted");
        b.deleted = true;
        let (got, report) = read_all_with_report(&build_zoo(&[a, b]))
            .expect("an all-deleted archive is not corrupt");
        assert!(got.is_empty(), "{got:?}");
        assert!(!report.has_warnings(), "{:?}", report.warnings);
    }

    /// **Arm 1 is what keeps trailing bytes tolerated**, and this is the test
    /// that makes it load-bearing. `arc.rs` already ruled on this shape for
    /// the four `.pak` fixtures' ten unexplained trailing bytes: content
    /// after a valid end marker is IGNORED, never read as corruption. A guard
    /// that asked "does anything lie past the terminator?" without first
    /// asking "did the chain reach anything?" would refuse a perfectly
    /// readable archive for a byte nobody consults.
    #[test]
    fn an_archive_with_trailing_bytes_after_its_terminator_still_reads() {
        let mut bytes = STORE_ZOO.to_vec();
        bytes.extend_from_slice(b"whatever a later tool appended here");
        let (got, report) = read_all_with_report(&bytes).expect("trailing bytes are ignored");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, license());
        assert!(!report.has_warnings(), "{:?}", report.warnings);
    }

    /// The regression guard for the refusal: all four real fixtures, and a
    /// well-formed multi-entry archive, must be unaffected.
    #[test]
    fn the_borrowed_fixtures_are_never_refused_as_reaching_nothing() {
        for (bytes, label) in [
            (STORE_ZOO, "store.zoo"),
            (DEFAULT_ZOO, "default.zoo"),
            (HIGH_PER_ZOO, "high_per.zoo"),
        ] {
            let (got, report) =
                read_all_with_report(bytes).unwrap_or_else(|e| panic!("{label}: {e}"));
            assert_eq!(got.len(), 1, "{label}");
            assert!(!report.has_warnings(), "{label}: {:?}", report.warnings);
        }
        // `wrongcrc16.zoo` fails on its entry's CONTENT checksum, which is a
        // different verdict and must stay that one.
        let err = read_all(WRONGCRC16_ZOO).unwrap_err();
        assert!(err.to_string().contains("CRC-16/ARC"), "{err}");
    }

    // ---- the record's own checksum ----

    /// zoo prints a `*` beside a record whose `dir_crc` fails and carries on
    /// listing it (`zoolist.c`). This reader does the same thing in this
    /// project's vocabulary: a fidelity warning, which `--strict-fidelity`
    /// turns into exit 4, and never a refusal — refusing would be stricter
    /// than the reference implementation.
    #[test]
    fn a_record_that_fails_its_own_checksum_warns_rather_than_refusing() {
        // Alter a field no other check reads: the entry's own DOS name. The
        // content CRC still matches, the sizes still agree, the chain still
        // advances — only the record's self-check notices.
        let mut bytes = STORE_ZOO.to_vec();
        let start = 42usize;
        bytes[start + FNAME_I] = b'L'; // "license" -> "License"
        let (got, report) = read_all_with_report(&bytes).expect("a record checksum never refuses");
        assert_eq!(got.len(), 1, "the entry is still handed back");
        assert_eq!(got[0].0, "License", "the altered name is reported verbatim");
        assert!(
            report.has_warnings(),
            "--strict-fidelity must gate on this: exit 0 over an altered record is the defect"
        );
        let warned = report.warnings.iter().any(|w| {
            matches!(
                w,
                Fidelity::DirectoryRecordChecksum { offset, .. } if *offset == start as u64
            )
        });
        assert!(warned, "got {:?}", report.warnings);
    }

    /// The mutation that motivated the refusal also fails its record
    /// checksum, and that is a SECOND, independent observation rather than
    /// the one the refusal rests on — the refusal is structural (a chain
    /// reaching nothing over a file holding content) and fires on formats
    /// and record types that carry no checksum at all.
    #[test]
    fn the_cut_chains_record_also_fails_its_own_checksum() {
        let bytes = with_the_chain_cut_at_the_first_record(STORE_ZOO);
        let rec = &bytes[42..42 + SIZ_DIRL + 13];
        let mut zeroed = rec.to_vec();
        zeroed[54] = 0;
        zeroed[55] = 0;
        assert_ne!(
            crc16_arc(&zeroed),
            u16::from_le_bytes([rec[54], rec[55]]),
            "zeroing `next` must invalidate the record's own checksum"
        );
    }

    // ---- the chain guard ----

    /// A self-referential link: the commonest shape, and the one a half-fix
    /// catches.
    #[test]
    fn a_self_referential_chain_is_refused() {
        let mut spec = Spec::stored("LOOP.TXT", b"payload");
        spec.next_override = Some(42); // its own position
        let err = read_all(&build_zoo(&[spec])).expect_err("a self-link must be refused");
        assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
        assert_eq!(
            err.exit_code(),
            5,
            "a chain contradicting its own shape is corrupt, not a resource ceiling: {err}"
        );
        assert!(err.to_string().contains("advance"), "{err}");
    }

    /// A two-link cycle: A points forward at B, B points back at A. A guard
    /// that only compares a link against its OWN record — the half-fix —
    /// passes A and then spins forever on B.
    #[test]
    fn a_longer_chain_cycle_is_refused() {
        let a = Spec::stored("A.TXT", b"first");
        let mut b = Spec::stored("B.TXT", b"second");
        b.next_override = Some(42); // back to A
        let err = read_all(&build_zoo(&[a, b])).expect_err("a cycle must be refused");
        assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
        assert_eq!(err.exit_code(), 5, "{err}");
    }

    /// The regression guard for the two above: an ordinary multi-entry
    /// archive whose chain advances normally must still read end to end.
    /// Without it the cycle guard could be "refuse every second entry" and
    /// both cycle tests would still pass — and no borrowed fixture has a
    /// second entry to notice.
    #[test]
    fn a_chain_that_advances_normally_walks_every_entry() {
        let bytes = build_zoo(&[
            Spec::stored("A.TXT", b"first entry"),
            Spec::stored("B.TXT", b"second entry"),
            Spec::stored("C.TXT", b"third entry"),
        ]);
        let got = read_all(&bytes).expect("a well-formed three-entry chain");
        assert_eq!(
            got,
            vec![
                ("A.TXT".to_string(), b"first entry".to_vec()),
                ("B.TXT".to_string(), b"second entry".to_vec()),
                ("C.TXT".to_string(), b"third entry".to_vec()),
            ]
        );
    }

    // ---- the variable part, deleted entries ----

    #[test]
    fn a_deleted_entry_is_skipped_and_the_walk_continues() {
        let mut gone = Spec::stored("GONE.TXT", b"deleted payload");
        gone.deleted = true;
        let bytes = build_zoo(&[gone, Spec::stored("KEPT.TXT", b"kept payload")]);
        let got = read_all(&bytes).expect("a deleted entry is skipped, not an error");
        assert_eq!(
            got,
            vec![("KEPT.TXT".to_string(), b"kept payload".to_vec())],
            "zoo neither lists nor extracts a deleted entry"
        );
    }

    #[test]
    fn a_long_filename_in_the_variable_part_replaces_the_dos_name() {
        let mut spec = Spec::stored("LONGFI~1.TXT", b"body");
        spec.long_name = Some("a-considerably-longer-name.txt");
        let got = read_all(&build_zoo(&[spec])).expect("a long name is read, not refused");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "a-considerably-longer-name.txt");
    }

    #[test]
    fn a_variable_part_too_small_for_the_long_name_it_declares_is_corrupt() {
        let mut spec = Spec::stored("SHORT.TXT", b"body");
        // namlen = 200 inside a 4-byte variable part.
        spec.var_override = Some(vec![200, 0, b'x', 0]);
        let err = read_all(&build_zoo(&[spec])).expect_err("a name longer than its own field");
        assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
        assert_eq!(err.exit_code(), 5, "{err}");
    }

    /// The regression guard for the test above: every borrowed fixture
    /// carries a variable part (13, 10, 13 bytes) with `namlen == 0`, and
    /// all three must still read. `zoo_conforms` would catch a wrong
    /// refusal, but only for one of them.
    #[test]
    fn the_borrowed_fixtures_variable_parts_are_read_without_complaint() {
        for (bytes, label, var_len) in [
            (STORE_ZOO, "store.zoo", 13usize),
            (DEFAULT_ZOO, "default.zoo", 10),
            (HIGH_PER_ZOO, "high_per.zoo", 13),
        ] {
            let e = &raw_entries(bytes)[0];
            assert_eq!(
                e.var_len, var_len,
                "{label}: the u16 at offset 51 is the variable part's length"
            );
            assert_eq!(read_all(bytes).unwrap()[0].0, "license", "{label}");
        }
    }

    // ---- the ceiling ----

    /// A seekable `Source` that panics if ever asked to fill a buffer larger
    /// than `max_single_read` — the same instrument `cpio.rs`'s
    /// `refuses_an_absurd_namesize_before_the_allocation_it_would_size`
    /// uses, made seekable because this container's caps mean the ladder
    /// would otherwise spool a forward-only one to a temp file and the
    /// panicking source would never be in the read path at all.
    ///
    /// `ZooRead::read_payload` allocates `vec![0u8; size_now]` and hands it
    /// straight to `read_exact`, whose first call requests the whole buffer.
    /// So a read past any sane window is proof the allocation already
    /// happened, i.e. that the ceiling check ran after the fact rather than
    /// before. A test asserting only the error code passes even then, which
    /// is the entire defect.
    struct PanicsOnBigRead {
        inner: io::Cursor<Vec<u8>>,
        max_single_read: usize,
    }

    impl Read for PanicsOnBigRead {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            assert!(
                buf.len() <= self.max_single_read,
                "a single read of {} bytes was requested — past the {}-byte guard. That is \
                 proof a buffer was already allocated from a header's own field before any \
                 refusal ran",
                buf.len(),
                self.max_single_read
            );
            self.inner.read(buf)
        }
    }

    impl Seek for PanicsOnBigRead {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    impl Source for PanicsOnBigRead {
        fn caps(&self) -> SourceCaps {
            SourceCaps {
                seekable: true,
                len: Some(self.inner.get_ref().len() as u64),
            }
        }
        fn as_seek(&mut self) -> Option<&mut dyn SeekRead> {
            Some(self)
        }
    }

    fn open_guarded(bytes: Vec<u8>, max_single_read: usize) -> Box<dyn ArchiveRead> {
        let src: Box<dyn Source> = Box::new(PanicsOnBigRead {
            inner: io::Cursor::new(bytes),
            max_single_read,
        });
        let resolved = resolve(src, ZOO, Zoo.caps(), &StreamPolicy::default()).expect("resolve");
        Zoo.open(resolved, &OpenOpts::default())
            .expect("open reads only the 34-byte header")
    }

    /// The same declared size the Phase 3a `container` fuzz target's cpio
    /// reproducer named — 2,863,311,530 bytes — reused so the figure is a
    /// real one rather than a stand-in.
    const ABSURD_SIZE: u32 = 0xAAAA_AAAA;

    /// Patches a field of the first directory entry in place, so a header
    /// can declare a size its archive does not carry.
    fn patch_first_record(bytes: &mut [u8], field_at: usize, value: u32) {
        bytes[42 + field_at..42 + field_at + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn refuses_an_absurd_size_now_before_the_allocation_it_would_size() {
        let mut bytes = build_zoo(&[Spec::stored("BIG.BIN", b"")]);
        patch_first_record(&mut bytes, 24, ABSURD_SIZE); // SIZNOW_I
        let mut ar = open_guarded(bytes, stuffr_core::PROBE_LEN);
        let err = ar
            .next_entry()
            .expect_err("an absurd size_now must be refused");
        assert!(
            matches!(err, Error::ResourceLimit(_)),
            "an implausible declared length is this build refusing to allocate, not a verdict \
             that the file is damaged — see MAX_ZOO_ENTRY_LEN's doc; got {err:?}"
        );
        assert_eq!(err.exit_code(), 6, "ResourceLimit is exit 6: {err:?}");
        assert!(
            err.to_string().contains(&ABSURD_SIZE.to_string()),
            "the message must name the declared size, got: {err}"
        );
    }

    /// `org_size` is the second field that reaches an allocator — it sizes
    /// [`lh5_decode`]'s output buffer — and it is bounded in the same place,
    /// BEFORE the payload read rather than at the decoder that would use it.
    ///
    /// Instrumented so that the ordering is what fails, not only the error
    /// code. An `org_size` this absurd cannot be caught by watching an
    /// allocation: `vec![0u8; 2_863_311_530]` is lazy on macOS and would
    /// succeed at a few megabytes of RSS (the same reason the `xz-pure`
    /// index bomb looked healthy at the CLI). So the entry carries a
    /// LEGITIMATE 8 KiB payload instead, larger than the guarded read
    /// window: if the `org_size` check is moved down to the decoder, the
    /// payload is read first and this source panics.
    #[test]
    fn refuses_an_absurd_org_size_before_the_payload_it_would_decode_is_read() {
        let mut spec = Spec::stored("BIG.BIN", &vec![0x11u8; 8192]);
        spec.method = 2; // the method whose output buffer org_size sizes
        let mut bytes = build_zoo(&[spec]);
        patch_first_record(&mut bytes, 20, ABSURD_SIZE); // ORGS_I
        let mut ar = open_guarded(bytes, stuffr_core::PROBE_LEN);
        let err = ar
            .next_entry()
            .expect_err("an absurd org_size must be refused");
        assert!(matches!(err, Error::ResourceLimit(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 6, "{err}");
        assert!(
            err.to_string().contains(&ABSURD_SIZE.to_string()),
            "the message must name the declared size, got: {err}"
        );
    }

    /// The regression guard for the two above: a size UNDER the ceiling with
    /// no data behind it must still fail — as ordinary corruption, exit 5,
    /// never `ResourceLimit`. Pins that the check is bounded by
    /// `MAX_ZOO_ENTRY_LEN` and is not "any size with no data behind it".
    #[test]
    fn a_modest_size_with_no_data_behind_it_is_corrupt_not_resource_limited() {
        let mut bytes = build_zoo(&[Spec::stored("SHORT.BIN", b"")]);
        patch_first_record(&mut bytes, 24, 64);
        patch_first_record(&mut bytes, 20, 64);
        let mut ar = open_guarded(bytes, 4096);
        let err = ar.next_entry().expect_err("a truncated entry must fail");
        assert_eq!(
            err.exit_code(),
            5,
            "a small, merely-truncated payload is corruption, not a resource ceiling: {err:?}"
        );
    }

    /// A legitimately large entry — far past any borrowed fixture,
    /// comfortably under the ceiling — must still read. Guards the obvious
    /// way to get a ceiling wrong: setting it so tight it refuses real
    /// archives, which this project has shipped before.
    #[test]
    fn an_entry_far_larger_than_any_fixture_is_still_read() {
        let payload = vec![0x5Au8; 2 * 1024 * 1024];
        assert!(
            (payload.len() as u64) < MAX_ZOO_ENTRY_LEN,
            "the fixture must stay under the ceiling to prove a real entry is unaffected"
        );
        let bytes = build_zoo(&[Spec::stored("BIG.BIN", &payload)]);
        let got = read_all(&bytes).expect("a 2 MiB entry is not absurd");
        assert_eq!(got[0].1.len(), payload.len());
    }

    /// The output half of the ceiling, exercised as a predicate rather than
    /// end to end: reaching it through a real decode means actually
    /// producing 256 MiB, which is not a cost worth paying on every gate
    /// run. Its call site is covered by
    /// `an_entry_far_larger_than_any_fixture_is_still_read` (which proves
    /// the guard does not fire early) and by every LZW decode above.
    #[test]
    fn the_output_ceiling_refuses_past_its_bound_and_not_at_it() {
        let at = guard_output("X", MAX_ZOO_ENTRY_LEN as usize);
        assert!(at.is_ok(), "exactly at the ceiling must be allowed");
        let over = guard_output("X", MAX_ZOO_ENTRY_LEN as usize + 1).unwrap_err();
        assert!(matches!(over, Error::ResourceLimit(_)), "{over:?}");
        assert_eq!(over.exit_code(), 6);
    }

    // ---- the LZW engine ----

    /// Packs `(width, code)` pairs least-significant-bit-first, the way
    /// `rd_dcode` reads them.
    fn pack_codes(codes: &[(u32, u16)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        for &(width, code) in codes {
            acc |= u32::from(code) << bits;
            bits += width;
            while bits >= 8 {
                out.push((acc & 0xFF) as u8);
                acc >>= 8;
                bits -= 8;
            }
        }
        if bits > 0 {
            out.push((acc & 0xFF) as u8);
        }
        out
    }

    /// A mid-stream CLEAR, built so that BOTH halves of `init_dtab()` are
    /// load-bearing — the trap Task 3's own CLEAR test fell into, where the
    /// whole stream was one code width and the reset it existed to prove was
    /// a no-op inside it.
    ///
    /// 255 literal codes take `free_code` from 258 to 512, which widens the
    /// stream to 10 bits; the CLEAR is therefore READ at 10 bits and every
    /// code after it at 9. Drop the `nbits` reset and the tail is read at
    /// the wrong width and decodes to something else. The tail then names
    /// code 258, which after the reset is the pair built from the two
    /// literals behind it (`"BC"`) and without the `free_code` reset is
    /// whatever the A-run left there (`"AA"`) — so the second half of the
    /// reset is pinned too.
    #[test]
    fn a_mid_stream_clear_code_resets_both_the_width_and_the_dictionary() {
        let mut codes: Vec<(u32, u16)> = vec![(9, u16::from(b'A')); 255];
        codes.push((10, 256)); // CLEAR, read at the widened width
        codes.push((9, u16::from(b'B')));
        codes.push((9, u16::from(b'C')));
        codes.push((9, 258)); // the entry the two literals above just built
        codes.push((9, 257)); // Z_EOF
        let stream = pack_codes(&codes);

        let mut want = vec![b'A'; 255];
        want.extend_from_slice(b"BCBC");
        assert_eq!(lzw_decode(&stream, "t").unwrap(), want);
    }

    #[test]
    fn an_lzw_code_past_the_dictionary_is_corrupt() {
        let stream = pack_codes(&[(9, 256), (9, u16::from(b'A')), (9, 300)]);
        let err = lzw_decode(&stream, "t").unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
        assert_eq!(err.exit_code(), 5);
        assert!(err.to_string().contains("300"), "{err}");
    }

    #[test]
    fn an_lzw_block_opening_with_a_non_literal_code_is_corrupt() {
        let stream = pack_codes(&[(9, 256), (9, 400)]);
        let err = lzw_decode(&stream, "t").unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
        assert_eq!(err.exit_code(), 5);
    }

    /// An empty payload is a clean empty decode, not a panic and not an
    /// error: `lzd.c` reaches its end-of-input the same way.
    #[test]
    fn an_empty_lzw_payload_decodes_to_nothing() {
        assert_eq!(lzw_decode(&[], "t").unwrap(), Vec::<u8>::new());
    }

    // ---- metadata ----

    /// `store.zoo` stamps 2024-05-16T23:08:26Z — `date` in the low half of
    /// the `u32` at `DAT_I`, `time` in the high half, the same packing ARC
    /// uses. The second count is computed independently of this module.
    #[test]
    fn a_packed_timestamp_reads_the_date_the_fixture_carries() {
        let mut ar = open_seekable(STORE_ZOO).unwrap();
        let first = ar.next_entry().unwrap().expect("one entry");
        let mtime = first.meta().mtime.expect("store.zoo carries a date");
        let secs = mtime.duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(secs, 1_715_900_906);
    }

    #[test]
    fn an_all_zero_timestamp_reports_no_mtime() {
        assert_eq!(zoo_mtime(0), None);
    }

    #[test]
    fn every_entry_is_a_plain_file_with_no_invented_metadata() {
        let mut ar = open_seekable(STORE_ZOO).unwrap();
        let entry = ar.next_entry().unwrap().expect("one entry");
        let m = entry.meta();
        assert_eq!(m.kind, EntryKind::File);
        assert_eq!(m.mode, None);
        assert_eq!(m.uid, None);
        assert_eq!(m.gid, None);
        assert_eq!(m.size, Some(11_357));
        assert_eq!(m.compressed_size, Some(11_357));
    }

    // ---- capabilities ----

    #[test]
    fn capabilities_and_metadata_match_the_format() {
        let c = Zoo.caps();
        assert!(c.read && !c.write);
        assert!(
            c.needs_seek,
            "ZOO's directory is a chain of absolute offsets — see this module's doc"
        );
        assert!(
            !c.forward_parse,
            "claiming forward_parse would assert what no one-entry fixture can witness"
        );
        assert_eq!(c.detects_corruption, CorruptionDetection::Always);
        let m = meta();
        assert_eq!(m.id, ZOO);
        assert_eq!(m.extensions, &["zoo"]);
    }

    /// A pipe still opens: the ladder spools it to a temp file first
    /// (`Rung::Spilled`), which `is_authoritative()` accepts, so the entry
    /// reads back correctly and the fidelity report says how it got there
    /// rather than claiming `Exact`. This is the user-visible cost of
    /// `needs_seek: true`, pinned rather than left as prose.
    #[test]
    fn a_piped_source_is_spooled_and_reads_back_correctly() {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(io::Cursor::new(STORE_ZOO)));
        let resolved = resolve(src, ZOO, Zoo.caps(), &StreamPolicy::default())
            .expect("a pipe must still resolve — ZOO's caps make the ladder spool it");
        assert_eq!(
            resolved.rung,
            stuffr_core::Rung::Spilled,
            "needs_seek + !forward_parse must spool a pipe, not forward-parse it"
        );
        let mut ar = Zoo
            .open(resolved, &OpenOpts::default())
            .expect("open a spooled source");
        assert!(
            ar.fidelity().rung.is_authoritative(),
            "Spilled must be reported as authoritative"
        );
        let mut entry = ar.next_entry().unwrap().expect("one entry");
        let mut data = Vec::new();
        entry.reader().read_to_end(&mut data).unwrap();
        assert_eq!(data, license());
    }

    #[test]
    fn by_index_is_always_unsupported() {
        let mut ar = open_seekable(STORE_ZOO).unwrap();
        let err = ar
            .by_index(0)
            .expect_err("ZOO's directory is a linked list, not an index");
        assert!(matches!(err, Error::Unsupported(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 3, "{err}");
    }

    #[test]
    fn create_is_refused_as_a_capability_limit_not_a_panic() {
        match Zoo.create(
            PlainSink::new(Box::new(stuffr_core::testing::SharedBuf::new())),
            &CreateOpts::default(),
        ) {
            Err(err) => {
                assert!(
                    matches!(err, Error::CapabilityUnavailable { .. }),
                    "got {err:?}"
                );
                assert_eq!(err.exit_code(), 3);
            }
            Ok(_) => panic!("ZOO must refuse to write"),
        }
    }

    #[test]
    fn the_registered_magic_matches_every_fixture() {
        for (bytes, label) in [
            (STORE_ZOO, "store.zoo"),
            (DEFAULT_ZOO, "default.zoo"),
            (HIGH_PER_ZOO, "high_per.zoo"),
            (WRONGCRC16_ZOO, "wrongcrc16.zoo"),
        ] {
            let hits = ZOO_MAGIC
                .iter()
                .filter(|r| {
                    bytes.len() >= r.offset + r.bytes.len()
                        && &bytes[r.offset..r.offset + r.bytes.len()] == r.bytes
                })
                .count();
            assert_eq!(hits, 1, "{label} matched {hits} magic rules, expected 1");
        }
    }
}
