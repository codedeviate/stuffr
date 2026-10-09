//! cpio salvage scan: recovers `newc` entries by testing every byte offset
//! for a `070701` header whose fields are plausible, rather than walking
//! forward from the first header the way `cpio::newc::Reader` does.
//!
//! `cpio.rs` is a correct reader for an INTACT archive, and it reaches entry
//! N only by having parsed entries 1..N-1: `newc` has no index and no entry
//! count, so one header whose fields do not parse ends the archive (exit 5)
//! for every entry behind it. That is the damage this module is for. It is
//! the seventh scanner on the shared [`stuffr_core::salvage`] machinery, and
//! the second of Salvage Stage 3's three checksumless containers.
//!
//! # cpio is `Unattested`, never `Complete` — and that is the honest answer
//!
//! **`newc` carries no checksum anywhere.** Not over the content (that is
//! the `070702` "crc" sibling, which this build does not read) and not over
//! the header: tar at least checksums each header block, and `newc` has
//! nothing of the kind. So a run of bytes that reads `070701` and parses as
//! a header, found in the middle of some other entry's payload, cannot be
//! told from a real header by ANY evidence the format carries.
//!
//! Every candidate that clears the gate below is therefore
//! [`SalvageStatus::Unattested`] — "nothing attests that this is an entry at
//! all" — and never [`SalvageStatus::Complete`], which asserts a header
//! self-check `newc` does not have. It is written under its real name
//! (salvage is the recovery-biased verb), the `--list` row says why, and the
//! run exits 4. `stuffr_core::testing::check_salvage_claim` holds the line:
//! cpio's class is `Attestation::Nothing`, and `Unattested` with nothing
//! checked is the one claim that class permits.
//!
//! # The gate, and how much it carries
//!
//! A `newc` header is six ASCII bytes of magic and thirteen 8-byte ASCII hex
//! fields (`c_ino` .. `c_check`, 110 bytes in all), then `c_namesize` bytes
//! of NUL-terminated name, padded to a multiple of four from the header's
//! start; the payload follows, padded the same way. Layout from `cpio`
//! 0.4.1's `newc::Reader::new` — the reader `cpio.rs` uses — which this
//! scanner mirrors field for field. A candidate at offset `H` is a header
//! only once ALL of these hold, in this order:
//!
//! 1. **The magic is `070701`** — the anchor the scan searches for.
//! 2. **All 110 header bytes are present, and every one of the thirteen
//!    fields is eight ASCII hex digits** (`hex8`). The reader parses the
//!    same fields with `u32::from_str_radix`, which also accepts a leading
//!    `+`; this gate does not, since no writer emits one.
//! 3. **`c_namesize` is at most `MAX_CPIO_NAME_LEN`** — `cpio.rs`'s own
//!    ceiling (65,536), reused rather than restated, and checked BEFORE the
//!    name is allocated.
//! 4. **The whole name is inside the source.**
//! 5. **The name's last byte is NUL**, as the reader requires.
//! 6. **The name is UTF-8**, as the reader requires.
//! 7. **The name, with trailing NULs removed (the reader's own dracut
//!    tolerance), is not empty.**
//!
//! A payload that runs past the end of the source is REPORTED, never
//! rejected — `Candidate::available_len`, `Partial`, the genuine prefix
//! written as `NAME.partial` — which is every scanner's truncated-tail rule.
//! A header named `TRAILER!!!` clears the gate and is never an entry: the
//! reader stops there, and the scan carries on past it, because an initramfs
//! is several cpio archives back to back.
//!
//! **Against random bytes the gate is effectively absolute, and the number
//! is worth having.** The magic alone is one chance in `2^48` per offset —
//! once per **256 TiB** of uniform noise. Criterion 2 then asks 104 bytes to
//! each be one of 22 hex spellings (`0-9a-fA-F`): `(22/256)^104`, about
//! `10^-111`. Criterion 3 asks `c_namesize`'s top four digits to read `0`
//! (about `10^-5.4` more) and criterion 5 one specific byte (`1/256`). All
//! together: roughly **one false header per `10^133` offsets** of uniform
//! random data — compressed payloads included, which is the case the six
//! bytes of magic alone could not answer. For comparison, LHA's five-byte
//! method identifier is one per 93 GiB before its checksum is consulted.
//!
//! **Against STRUCTURED data it carries nothing, and that is why the tier
//! is `Unattested`.** The number above is about noise. A real `newc`
//! header is also plausible by construction, so a cpio archive stored,
//! uncompressed, as the payload of an entry whose own header was destroyed
//! is reported entry by entry — real headers over real bytes, found where
//! the outer entry was. So is a text file holding a hex dump of one. Nothing
//! in the format tells those apart from the archive's own entries, and no
//! gate built on plausibility ever could.
//!
//! With the gate that strong against noise, a noise test finds nothing
//! whether or not any single criterion still works — the vacuity Stage 2
//! measured. So the noise corpus carries **one crafted splice per
//! criterion 2-7** (plus one for the trailer rule), each a whole entry
//! whose ONLY defect is that criterion; see
//! `tests::the_noise_corpus_reaches_each_criterion_it_claims_to` and the
//! task report's falsification table.
//!
//! # Byte-granular, and a payload is jumped only when the jump is corroborated
//!
//! `newc` keeps every header on a multiple of four from the archive's own
//! start, but the archive this verb exists for may have lost that alignment
//! (a carved image, a download missing its first bytes), so the scan tests
//! every offset. After a whole candidate it can resume at the header after
//! that entry's padded payload rather than inside it — see [`CpioSalvage`]
//! — or a cpio stored inside a cpio (every initramfs that embeds one) would
//! be reported as its contents.
//!
//! **But `c_filesize` is attested by nothing**, and that is the difference
//! from tar, whose own jump this copies: tar's header checksum refuses a
//! header whose size field changed, and `newc` has no such check. Task 3's
//! review measured the cost of trusting it unconditionally: `one.txt` (16
//! bytes), `two.txt`, `three.txt`, with ONE hex digit of `one.txt`'s size
//! changed `0`→`F` — `two.txt` vanished, with no row and no note, and
//! `one.txt` was written holding `two.txt`'s header. So the jump is taken
//! only when the bytes it lands on corroborate the size
//! (`corroborates_the_size`): a header of any cpio variant that clears its
//! gate (the trailer included), EOF, or zero padding all the way to EOF.
//! Anything else and the scan resumes **one byte past the header** — not at
//! the engine's own `offset + declared_len`, which measures the same
//! unattested number from the header and would skip neighbours when the
//! damage makes a size LARGER.
//! A refused jump costs a scan of the zero run once; the scan's memo
//! (`KnownZeros`) answers every later landing in it, so many headers
//! pointing into one run stay linear.
//!
//! **What corroboration buys:** one damaged size costs at most its own
//! entry's bytes (the entry is still reported, over what its header claims),
//! never the entry behind it —
//! `tests::a_damaged_size_never_costs_the_entry_behind_it` pins the
//! review's reproducer and its larger-size twin. **What it still cannot
//! catch:** a damaged size that happens to land exactly on another valid
//! header — a size shrunk or grown by a whole number of entries, or landing
//! on a header inside the payload's own data. The jump is then corroborated
//! and taken, and whatever lies between is not scanned. **What it costs:**
//! an entry whose next header is itself destroyed is not jumped, so a cpio
//! stored in THAT entry's payload is reported entry by entry — real headers
//! over real bytes, never invented. A truncated candidate is never believed
//! about where anything ends, and the scan resumes one byte past it.
//!
//! **The entry with the uncorroborated size stays `Unattested`**, and that
//! is a choice. An uncorroborated jump is not evidence the size is WRONG —
//! the same thing happens when the NEXT header is the damaged one, and then
//! this entry is perfectly whole. `Partial` would claim missing bytes (every
//! declared byte is present), and `Unverified` would decline to write an
//! entry that is, in that second case, intact. `Unattested` already says
//! nothing attests the record — its size included — and routes to exit 4.
//!
//! # Variants this build does not read are sightings (Ruling 3-J)
//!
//! `cpio.rs` reads `newc` alone and refuses the `odc` (`070707`) and
//! `newc-crc` (`070702`) variants at exit 3 — they are valid archives, not
//! damaged ones. A header of either that is well-formed by the same
//! criteria (octal fields for `odc`, whose 76-byte header has no padding)
//! is recorded as a [`Sighting`], never a candidate, so the engine never
//! advances by its declared length. A run that recovered nothing while
//! seeing one is [`Error::Unsupported`] (exit 3) naming the variant — never
//! "the scan found nothing recoverable" at exit 5 over a healthy archive of
//! another variant; a mixed run keeps its own exit code and carries the
//! sightings for the CLI's note. Binary (`070707` as a 16-bit word) cpio is
//! neither: its magic is two bytes, far too weak to anchor a scan, and
//! `stuffr list` does not recognise it either.
//!
//! # The whole-entry ceiling: none of this scanner's own
//!
//! [`CpioSalvage::max_whole_entry`] is `u64::MAX`. `newc` entries are stored
//! and [`write_payload`] streams them through `stream_bounded_copy`, so no
//! payload length ever sizes a buffer; the only header field that does is
//! `c_namesize`, bounded by criterion 3 before its allocation, and a
//! symlink's target, bounded by `cpio.rs`'s `MAX_SYMLINK_TARGET_LEN`. The
//! allocator-probe tests below prove both, each paired with the lower bound
//! that proves the probe is attached.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use stuffr_core::salvage::{
    Candidate, ForwardSearch, SalvageOutcome, SalvagePolicy, SalvageScan, SalvageStatus,
    SalvagedEntry, ScanBudget, Sighting, SightingKind, SightingLog, UnverifiedCause, salvage_all,
    stream_bounded_copy,
};
use stuffr_core::{EntryKind, EntryMeta, Error, FormatId, Result, SeekRead};

use crate::cpio::{
    CPIO, MAX_CPIO_NAME_LEN, MAX_SYMLINK_TARGET_LEN, RECOGNISED_UNREADABLE_VARIANTS, entry_kind,
    is_symlink_mode,
};

const MAGIC_LEN: usize = 6;
const NEWC_MAGIC: &[u8; MAGIC_LEN] = b"070701";
const CRC_MAGIC: &[u8; MAGIC_LEN] = b"070702";
const ODC_MAGIC: &[u8; MAGIC_LEN] = b"070707";

/// Six bytes of magic and thirteen 8-byte hex fields — `cpio` 0.4.1
/// `newc.rs`'s `HEADER_LEN`.
const NEWC_HEADER_LEN: usize = 110;
const NEWC_FIELD_LEN: usize = 8;
const NEWC_FIELDS: usize = 13;

/// Field positions, in `newc.rs`'s read order: `c_ino`, `c_mode`, `c_uid`,
/// `c_gid`, `c_nlink`, `c_mtime`, `c_filesize`, `c_devmajor`, `c_devminor`,
/// `c_rdevmajor`, `c_rdevminor`, `c_namesize`, `c_check`.
const MODE: usize = 1;
const UID: usize = 2;
const GID: usize = 3;
const MTIME: usize = 5;
const FILESIZE: usize = 6;
const NAMESIZE: usize = 11;

/// The `odc` header: six bytes of magic, then `c_dev`, `c_ino`, `c_mode`,
/// `c_uid`, `c_gid`, `c_nlink`, `c_rdev` (six octal digits each), `c_mtime`
/// (eleven), `c_namesize` (six) and `c_filesize` (eleven) — POSIX.1's
/// portable format. 76 bytes, and the name follows with no padding.
const ODC_FIELD_WIDTHS: [usize; 10] = [6, 6, 6, 6, 6, 6, 6, 11, 6, 11];
const ODC_HEADER_LEN: usize = 76;
const ODC_NAMESIZE: usize = 8;

/// The name `newc.rs`'s `Entry::is_trailer` ends an archive on.
const TRAILER_NAME: &str = "TRAILER!!!";

/// The codec a `newc` entry carries in [`EntryMeta::codec`]. **Setting it at
/// all is load-bearing**: `entries.rs` hands it to [`write_payload`], which
/// refuses anything else, and an unset codec would make every entry a silent
/// `SkippedNotBuiltIn` — the exact defect ARC shipped in Salvage Stage 2.
pub const STORED: FormatId = FormatId::new("cpio-stored");

/// A variant this build does not read — see the module doc's sightings
/// section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Variant {
    Odc,
    Crc,
}

/// One shape phrase per variant, shared by the mixed-run [`Sighting`] and
/// the exit-3 refusal so the two cannot describe one shape two ways.
const ODC_SHAPE: &str = "header(s) in the odc variant (magic `070707`)";
const CRC_SHAPE: &str = "header(s) in the newc-crc variant (magic `070702`)";

/// The phrase for a header refused because reading its name or symlink
/// target would have taken the scan past its [`ScanBudget`] — see
/// [`CpioSalvage::budget`].
const VERDICT_BUDGET_SHAPE: &str =
    "header(s) whose name or symlink target it did not read once that work was spent";

impl Variant {
    fn shape(self) -> &'static str {
        match self {
            Variant::Odc => ODC_SHAPE,
            Variant::Crc => CRC_SHAPE,
        }
    }

    fn magic(self) -> &'static [u8; MAGIC_LEN] {
        match self {
            Variant::Odc => ODC_MAGIC,
            Variant::Crc => CRC_MAGIC,
        }
    }

    /// The variant's full name, from `cpio.rs`'s own table — the one place
    /// that names what this build refuses to read.
    fn name(self) -> &'static str {
        RECOGNISED_UNREADABLE_VARIANTS
            .iter()
            .find(|(magic, _)| *magic == self.magic().as_slice())
            .map(|(_, name)| *name)
            .expect("cpio.rs names both variants this scanner sights")
    }
}

/// Why the bytes at an offset are not a header — one arm per gate
/// criterion, so a test can say which criterion stopped a splice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// Fewer header bytes than the header's fixed length remain.
    ShortHeader,
    /// Criterion 2: a `newc` field that is not eight hex digits.
    NotHex,
    /// Criterion 2's `odc` twin: a field that is not all octal digits.
    NotOctal,
    /// Criterion 3.
    NameOverCeiling,
    /// Criterion 4.
    NameRunsPastEnd,
    /// Criterion 5.
    NameNotNulTerminated,
    /// Criterion 6.
    NameNotUtf8,
    /// Criterion 7.
    EmptyName,
    /// Not judged: reading the name would have overspent the scan's
    /// [`ScanBudget`] (0.10.3 Task 4b).
    OverBudget,
}

/// A `newc` (or `newc-crc`) header that cleared the gate.
#[derive(Debug)]
struct Newc {
    fields: [u32; NEWC_FIELDS],
    name: String,
    /// The header's offset plus the header, the name, and the name's
    /// padding to four — `newc.rs`'s `pad(HEADER_LEN + name_len)`.
    payload_start: u64,
}

impl Newc {
    fn file_size(&self) -> u64 {
        u64::from(self.fields[FILESIZE])
    }

    fn is_trailer(&self) -> bool {
        self.name == TRAILER_NAME
    }
}

/// Gate criterion 2 for one field: eight ASCII hex digits, read as a `u32`
/// (eight hex digits always fit one).
fn hex8(field: &[u8]) -> Option<u32> {
    if field.len() != NEWC_FIELD_LEN || !field.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    u32::from_str_radix(std::str::from_utf8(field).ok()?, 16).ok()
}

/// Gate criterion 2 for one `odc` field: every byte an octal digit. Eleven
/// digits is 33 bits, so a `u64` holds any of them.
fn octal(field: &[u8]) -> Option<u64> {
    if field.is_empty() || !field.iter().all(|b| (b'0'..=b'7').contains(b)) {
        return None;
    }
    u64::from_str_radix(std::str::from_utf8(field).ok()?, 8).ok()
}

/// `n` rounded up to a multiple of four — `newc.rs`'s `pad`. `None` on
/// overflow.
fn round_up_to_4(n: u64) -> Option<u64> {
    Some(n.checked_add(3)? & !3)
}

/// `len` bytes at `at`, or `None` if the source does not hold all of them.
/// Every caller has bounded `len` before calling: a header's fixed length,
/// a name under [`MAX_CPIO_NAME_LEN`], a symlink target under
/// [`MAX_SYMLINK_TARGET_LEN`]. A read error folds into `None` — to a
/// scanner it means the same thing, these bytes are not usable.
fn read_at(src: &mut dyn SeekRead, at: u64, len: u64, file_len: u64) -> Option<Vec<u8>> {
    if at.checked_add(len)? > file_len {
        return None;
    }
    src.seek(SeekFrom::Start(at)).ok()?;
    let mut bytes = vec![0u8; usize::try_from(len).ok()?];
    src.read_exact(&mut bytes).ok()?;
    Some(bytes)
}

/// Gate criteria 5-7, shared by both header shapes: the reader's own name
/// rule (`newc.rs`: the last byte must be NUL, trailing NULs are dropped,
/// the rest must be UTF-8), then non-empty.
fn name_of(mut bytes: Vec<u8>) -> std::result::Result<String, Refusal> {
    if bytes.last() != Some(&0) {
        return Err(Refusal::NameNotNulTerminated);
    }
    bytes.pop();
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    let name = String::from_utf8(bytes).map_err(|_| Refusal::NameNotUtf8)?;
    if name.is_empty() {
        return Err(Refusal::EmptyName);
    }
    Ok(name)
}

/// A name's `len` bytes at `at`, paid for from `budget` once they are known
/// to lie inside the source and before they are read — criterion 4, then
/// the scan's budget.
fn read_name(
    src: &mut dyn SeekRead,
    at: u64,
    len: u64,
    file_len: u64,
    budget: &mut ScanBudget,
) -> std::result::Result<Vec<u8>, Refusal> {
    if at.checked_add(len).is_none_or(|end| end > file_len) {
        return Err(Refusal::NameRunsPastEnd);
    }
    if !budget.try_spend(len) {
        return Err(Refusal::OverBudget);
    }
    read_at(src, at, len, file_len).ok_or(Refusal::NameRunsPastEnd)
}

/// Gate criteria 2-7 for a `newc`-shaped header at `offset` — the magic
/// (criterion 1) is the caller's, since the same layout serves `070701` and
/// the `070702` sighting. The name is paid for from `budget`.
fn gate_newc_within(
    src: &mut dyn SeekRead,
    offset: u64,
    file_len: u64,
    budget: &mut ScanBudget,
) -> std::result::Result<Newc, Refusal> {
    let header =
        read_at(src, offset, NEWC_HEADER_LEN as u64, file_len).ok_or(Refusal::ShortHeader)?;
    newc_named(src, offset, newc_fields(&header)?, file_len, budget)
}

/// [`gate_newc_within`] with no budget to spend — the tests' entry point,
/// whose verdicts are the budgeted one's whenever the budget holds.
#[cfg(test)]
fn gate_newc_at(
    src: &mut dyn SeekRead,
    offset: u64,
    file_len: u64,
) -> std::result::Result<Newc, Refusal> {
    gate_newc_within(src, offset, file_len, &mut ScanBudget::for_input(u64::MAX))
}

/// Where the payload of a `newc` header at `offset` with a `namesize`-byte
/// name begins — `newc.rs`'s `pad(HEADER_LEN + name_len)`.
fn newc_payload_start(offset: u64, namesize: u64) -> Option<u64> {
    round_up_to_4(NEWC_HEADER_LEN as u64 + namesize).and_then(|span| offset.checked_add(span))
}

/// Gate criteria 2 and 3 on a `newc`-shaped header's [`NEWC_HEADER_LEN`]
/// fixed bytes alone: thirteen hex fields, and a name size under the
/// ceiling. Reads nothing, so [`find_next_header`] judges it inside its
/// search.
fn newc_fields(header: &[u8]) -> std::result::Result<[u32; NEWC_FIELDS], Refusal> {
    let mut fields = [0u32; NEWC_FIELDS];
    for (i, slot) in fields.iter_mut().enumerate() {
        let at = MAGIC_LEN + i * NEWC_FIELD_LEN;
        *slot = hex8(&header[at..at + NEWC_FIELD_LEN]).ok_or(Refusal::NotHex)?;
    }
    if u64::from(fields[NAMESIZE]) > MAX_CPIO_NAME_LEN {
        return Err(Refusal::NameOverCeiling);
    }
    Ok(fields)
}

/// Gate criteria 4-7 for the `newc`-shaped header at `offset` whose fixed
/// fields [`newc_fields`] already cleared: the name read behind them.
fn newc_named(
    src: &mut dyn SeekRead,
    offset: u64,
    fields: [u32; NEWC_FIELDS],
    file_len: u64,
    budget: &mut ScanBudget,
) -> std::result::Result<Newc, Refusal> {
    let namesize = u64::from(fields[NAMESIZE]);
    let name_at = offset
        .checked_add(NEWC_HEADER_LEN as u64)
        .ok_or(Refusal::NameRunsPastEnd)?;
    let name = name_of(read_name(src, name_at, namesize, file_len, budget)?)?;
    let payload_start = newc_payload_start(offset, namesize).ok_or(Refusal::NameRunsPastEnd)?;
    Ok(Newc {
        fields,
        name,
        payload_start,
    })
}

/// The same criteria for an `odc` header at `offset`: every field octal,
/// the name under the ceiling, inside the source, NUL-terminated, UTF-8 and
/// non-empty. Answers the name, which is all a sighting needs. The name is
/// paid for from `budget`.
fn gate_odc_within(
    src: &mut dyn SeekRead,
    offset: u64,
    file_len: u64,
    budget: &mut ScanBudget,
) -> std::result::Result<String, Refusal> {
    let header =
        read_at(src, offset, ODC_HEADER_LEN as u64, file_len).ok_or(Refusal::ShortHeader)?;
    odc_named(src, offset, odc_namesize(&header)?, file_len, budget)
}

/// [`gate_odc_within`] with no budget to spend — the tests' entry point.
#[cfg(test)]
fn gate_odc_at(
    src: &mut dyn SeekRead,
    offset: u64,
    file_len: u64,
) -> std::result::Result<String, Refusal> {
    gate_odc_within(src, offset, file_len, &mut ScanBudget::for_input(u64::MAX))
}

/// [`newc_fields`]' `odc` twin: every field octal and the name size under
/// the ceiling, on the [`ODC_HEADER_LEN`] fixed bytes alone. Answers the
/// name size.
fn odc_namesize(header: &[u8]) -> std::result::Result<u64, Refusal> {
    let mut at = MAGIC_LEN;
    let mut namesize = 0;
    for (i, width) in ODC_FIELD_WIDTHS.into_iter().enumerate() {
        let value = octal(&header[at..at + width]).ok_or(Refusal::NotOctal)?;
        if i == ODC_NAMESIZE {
            namesize = value;
        }
        at += width;
    }
    if namesize > MAX_CPIO_NAME_LEN {
        return Err(Refusal::NameOverCeiling);
    }
    Ok(namesize)
}

/// The name behind an `odc` header whose fixed fields [`odc_namesize`]
/// already cleared.
fn odc_named(
    src: &mut dyn SeekRead,
    offset: u64,
    namesize: u64,
    file_len: u64,
    budget: &mut ScanBudget,
) -> std::result::Result<String, Refusal> {
    let name_at = offset
        .checked_add(ODC_HEADER_LEN as u64)
        .ok_or(Refusal::NameRunsPastEnd)?;
    name_of(read_name(src, name_at, namesize, file_len, budget)?)
}

/// Which of the three magics sits at an offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Magic {
    Newc,
    Crc,
    Odc,
}

fn magic_of(bytes: &[u8]) -> Option<Magic> {
    if bytes == NEWC_MAGIC {
        Some(Magic::Newc)
    } else if bytes == CRC_MAGIC {
        Some(Magic::Crc)
    } else if bytes == ODC_MAGIC {
        Some(Magic::Odc)
    } else {
        None
    }
}

/// A header whose fixed bytes cleared gate criteria 1-3 inside the search
/// ([`find_next_header`]), with what the rest of the gate needs from them.
#[derive(Debug, Clone, Copy)]
enum Fixed {
    /// `070701` or, with `crc`, `070702`.
    Newc {
        crc: bool,
        fields: [u32; NEWC_FIELDS],
    },
    /// `070707`, with its name size.
    Odc(u64),
}

/// Gate criteria 1-3 on the bytes `w` at a header start — [`NEWC_HEADER_LEN`]
/// of them, or every byte left before EOF down to [`ODC_HEADER_LEN`].
/// `None` for anything the gate refuses before reading a name, which is
/// every verdict those bytes alone can decide.
fn fixed_header(w: &[u8]) -> Option<Fixed> {
    match magic_of(&w[..MAGIC_LEN])? {
        magic @ (Magic::Newc | Magic::Crc) => Some(Fixed::Newc {
            crc: magic == Magic::Crc,
            fields: newc_fields(w.get(..NEWC_HEADER_LEN)?).ok()?,
        }),
        Magic::Odc => odc_namesize(&w[..ODC_HEADER_LEN]).ok().map(Fixed::Odc),
    }
}

/// Searches forward from `from` for the next header whose fixed bytes clear
/// gate criteria 1-3 ([`fixed_header`]), through [`ForwardSearch`], and
/// returns its offset with what they say.
///
/// **Judged inside the search, not after it (0.10.3 Task 4b).** The scan
/// used to search for a bare magic and read the 110-byte header behind
/// each, resuming one byte past every refusal: `070701` repeated through a
/// file — every field of it hex — read 19x its input that way, one header
/// per six bytes. Judged here, a refused magic costs nothing beyond the
/// search's own pass over it. A magic with fewer than [`ODC_HEADER_LEN`]
/// bytes behind it cannot hold any header, and was always refused.
fn find_next_header(
    search: &mut ForwardSearch,
    src: &mut dyn SeekRead,
    from: u64,
    file_len: u64,
) -> io::Result<Option<(u64, Fixed)>> {
    let mut found = None;
    let at = search.find_to_eof(src, from, file_len, NEWC_HEADER_LEN, ODC_HEADER_LEN, |w| {
        found = fixed_header(w);
        found.is_some()
    })?;
    Ok(at.zip(found))
}

/// Searches forward from `from` for the next offset carrying one of the
/// three magics, through [`ForwardSearch`]: a short first read that doubles
/// only while the answer is still not found, so a hit a few bytes away costs
/// a few bytes, not a fixed 64 KiB. O(1) memory however far the next one is.
/// The tests' census of where a corpus carries a magic at all; the scan
/// itself searches with [`find_next_header`].
#[cfg(test)]
fn find_next_magic(
    search: &mut ForwardSearch,
    src: &mut dyn SeekRead,
    from: u64,
    file_len: u64,
) -> io::Result<Option<(u64, Magic)>> {
    let mut found = None;
    let at = search.find(src, from, file_len, MAGIC_LEN, |w| {
        found = magic_of(w);
        found.is_some()
    })?;
    Ok(at.zip(found))
}

/// The zero runs this scan has already read, as disjoint
/// `start -> (end, to_eof)` records: `[start, end)` is all zero, and `to_eof`
/// says whether it ran to EOF (`end == file_len`) or stopped at a non-zero
/// byte at `end`. Many headers landing in a handful of runs, in any order,
/// then read each zero byte at most once (plus one short chunk of overshoot
/// per landing); memory is linear in the number of runs.
type KnownZeros = BTreeMap<u64, (u64, bool)>;

/// A candidate, and where the scan resumes after it.
struct Found {
    candidate: Candidate,
    /// The header after this entry's padded payload when something there
    /// CORROBORATES the size ([`corroborates_the_size`]); otherwise one byte
    /// past this header, so every byte the size might have wrongly claimed
    /// is scanned. A truncated candidate is never believed about where
    /// anything ends, and resumes one byte on too.
    resume_at: u64,
}

/// Whether the bytes at `next_header` — where this entry's `c_filesize`
/// says the next header begins — back that size up: a header of any cpio
/// variant that clears its gate (a trailer included), EOF, or zeros all the
/// way to EOF (a writer's block padding). See the module doc's jump section
/// for what this buys and what it still cannot catch.
///
/// The landing header's name is paid for from `budget`; one the budget
/// cannot pay for does not corroborate, so the scan resumes one byte past
/// the candidate and reaches that header itself, where it is reported.
fn corroborates_the_size(
    src: &mut dyn SeekRead,
    next_header: u64,
    file_len: u64,
    memo: &mut KnownZeros,
    budget: &mut ScanBudget,
) -> bool {
    if next_header >= file_len {
        return true;
    }
    let head = read_at(src, next_header, MAGIC_LEN as u64, file_len);
    match head.as_deref().and_then(magic_of) {
        Some(Magic::Newc | Magic::Crc) => {
            gate_newc_within(src, next_header, file_len, budget).is_ok()
        }
        Some(Magic::Odc) => gate_odc_within(src, next_header, file_len, budget).is_ok(),
        // No magic and a non-zero byte already in hand: the zeros cannot
        // reach EOF, which is all `zeros_to_eof` would find at its first
        // non-zero byte. (`None` from `read_at` — fewer than `MAGIC_LEN`
        // bytes left — takes the ordinary path.)
        None if head.as_deref().is_some_and(|h| h.iter().any(|&b| b != 0)) => false,
        None => zeros_to_eof(src, next_header, file_len, memo),
    }
}

/// Whether every byte from `from` to EOF is zero, read in chunks that start
/// at 64 bytes and double to 4096, stopping at the first that is not. A read
/// error answers `false`: an uncorroborated jump costs a scan of the run
/// once (the memo answers every later landing in it), never an entry.
///
/// `memo` holds every run this scan has read. A landing point inside one is
/// answered with no read; a scan that reaches the first byte of one stops
/// there and adopts its answer, merging the two. So a zero byte is read at
/// most once, plus at most one geometric chunk of overshoot per landing: a
/// landing on a non-zero byte costs 64 bytes, not 4 KiB (0.10.3 §1: a run
/// was once read per header, quadratically).
fn zeros_to_eof(src: &mut dyn SeekRead, from: u64, file_len: u64, memo: &mut KnownZeros) -> bool {
    if let Some((_, &(end, to_eof))) = memo.range(..=from).next_back() {
        if from < end {
            return to_eof;
        }
        // The byte at `end` is the non-zero one that stopped the run.
        if from == end && !to_eof {
            return false;
        }
    }
    if src.seek(SeekFrom::Start(from)).is_err() {
        return false;
    }
    let mut buf = [0u8; 4096];
    let mut chunk = 64usize;
    let mut pos = from;
    while pos < file_len {
        // Never read into a known run: stop at its first byte and adopt it.
        let next = memo.range(pos..).next().map(|(&s, &v)| (s, v));
        if let Some((start, (end, to_eof))) = next
            && start == pos
        {
            memo.remove(&start);
            memo.insert(from, (end, to_eof));
            return to_eof;
        }
        let limit = next.map_or(file_len, |(start, _)| start.min(file_len));
        let want = usize::try_from((limit - pos).min(chunk as u64)).unwrap_or(chunk);
        chunk = (chunk * 2).min(buf.len());
        match src.read(&mut buf[..want]) {
            Ok(0) | Err(_) => return false,
            Ok(n) => {
                if let Some(i) = buf[..n].iter().position(|&b| b != 0) {
                    let end = pos + i as u64;
                    if end > from {
                        memo.insert(from, (end, false));
                    }
                    return false;
                }
                pos += n as u64;
            }
        }
    }
    memo.insert(from, (file_len, true));
    true
}

/// What gating one magic hit found.
enum Scanned {
    Found(Box<Found>),
    Sighting(Variant),
    NotAnEntry,
    /// Not judged: its name or symlink target would have overspent the
    /// scan's [`ScanBudget`].
    OverBudget,
}

impl From<Refusal> for Scanned {
    /// A refusal is not an entry — unless it is the budget's, which is not a
    /// verdict at all.
    fn from(refusal: Refusal) -> Self {
        if refusal == Refusal::OverBudget {
            Scanned::OverBudget
        } else {
            Scanned::NotAnEntry
        }
    }
}

/// Gates the header at `offset` whose fixed bytes the search already
/// cleared: criteria 4-7, the name behind them.
fn scan_at(
    src: &mut dyn SeekRead,
    offset: u64,
    fixed: Fixed,
    file_len: u64,
    memo: &mut KnownZeros,
    budget: &mut ScanBudget,
) -> Scanned {
    match fixed {
        Fixed::Newc { crc: false, fields } => {
            match newc_named(src, offset, fields, file_len, budget) {
                // The reader's end of archive, never an entry — and not the
                // end of the SCAN, since archives are concatenated
                // (initramfs).
                Ok(newc) if newc.is_trailer() => Scanned::NotAnEntry,
                Ok(newc) => candidate_from(src, offset, newc, file_len, memo, budget)
                    .map_or(Scanned::OverBudget, |found| Scanned::Found(Box::new(found))),
                Err(refusal) => refusal.into(),
            }
        }
        Fixed::Newc { crc: true, fields } => {
            match newc_named(src, offset, fields, file_len, budget) {
                Ok(newc) if !newc.is_trailer() => Scanned::Sighting(Variant::Crc),
                Ok(_) => Scanned::NotAnEntry,
                Err(refusal) => refusal.into(),
            }
        }
        Fixed::Odc(namesize) => match odc_named(src, offset, namesize, file_len, budget) {
            Ok(name) if name != TRAILER_NAME => Scanned::Sighting(Variant::Odc),
            Ok(_) => Scanned::NotAnEntry,
            Err(refusal) => refusal.into(),
        },
    }
}

/// A symlink's target — its payload, as `cpio.rs` reads it — when the
/// payload is whole and under [`MAX_SYMLINK_TARGET_LEN`], which is checked
/// before anything is allocated. `Ok(None)` otherwise, and
/// `Err(Refusal::OverBudget)` when the target, though whole, would have
/// overspent `budget` — it is paid for before it is read.
fn symlink_target(
    src: &mut dyn SeekRead,
    newc: &Newc,
    file_len: u64,
    budget: &mut ScanBudget,
) -> std::result::Result<Option<String>, Refusal> {
    let len = newc.file_size();
    if len > MAX_SYMLINK_TARGET_LEN
        || newc
            .payload_start
            .checked_add(len)
            .is_none_or(|end| end > file_len)
    {
        return Ok(None);
    }
    if !budget.try_spend(len) {
        return Err(Refusal::OverBudget);
    }
    Ok(read_at(src, newc.payload_start, len, file_len)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()))
}

/// Builds the candidate for a header that cleared the gate, with the fields
/// `cpio.rs`'s `entry_meta` reports and the kind from its own `entry_kind`.
/// `None` when a symlink's target, which decides its kind, would have
/// overspent `budget`: the header is then not judged.
fn candidate_from(
    src: &mut dyn SeekRead,
    offset: u64,
    newc: Newc,
    file_len: u64,
    memo: &mut KnownZeros,
    budget: &mut ScanBudget,
) -> Option<Found> {
    let size = newc.file_size();
    let (available_len, next_header) = match newc.payload_start.checked_add(size) {
        Some(end) if end <= file_len => (
            None,
            round_up_to_4(size).and_then(|span| newc.payload_start.checked_add(span)),
        ),
        // Fewer bytes are present than the header promises. `Some(n)`
        // always means `n < declared_len`, per the field's contract.
        _ => (Some(file_len.saturating_sub(newc.payload_start)), None),
    };
    // Task 3 review, I1: nothing attests `c_filesize`, so the jump past this
    // payload is taken only where the landing point corroborates it.
    let resume_at = match next_header {
        Some(next) if corroborates_the_size(src, next, file_len, memo, budget) => next,
        _ => offset + 1,
    };
    let mode = newc.fields[MODE];
    // `cpio.rs`'s `entry_kind` answers `Other` for a symlink until its
    // reader has read the target; so does this, when there is no target to
    // read (a truncated or over-ceiling payload).
    let kind = if is_symlink_mode(mode) {
        symlink_target(src, &newc, file_len, budget)
            .ok()?
            .map_or(EntryKind::Other, |target| EntryKind::Symlink { target })
    } else {
        entry_kind(mode)
    };

    let mut meta = EntryMeta::file(newc.name.clone());
    meta.size = Some(size);
    meta.compressed_size = Some(size);
    meta.mtime = Some(UNIX_EPOCH + Duration::from_secs(u64::from(newc.fields[MTIME])));
    meta.mode = Some(mode);
    meta.uid = Some(newc.fields[UID]);
    meta.gid = Some(newc.fields[GID]);
    meta.kind = kind;
    meta.codec = Some(STORED);

    // No verifier: cpio has none, which is also why no two cpio records are
    // ever proven shadows of each other (only name collisions are reported).
    Some(Found {
        candidate: Candidate::new(offset, newc.payload_start, meta)
            .with_declared_len(Some(size))
            .with_available_len(available_len),
        resume_at,
    })
}

/// Scans a `newc` archive for headers directly — see the module doc.
///
/// `resume` is where the scan carries on after the last candidate: past its
/// payload when the size is corroborated, one byte past its header when it
/// is not — see `Found::resume_at`.
/// `sightings` is every well-formed header of a variant this build does not
/// read, in scan order.
///
/// **One instance scans one source.** The scanner is stateful: its resume position, its
/// sightings, its zero-run memo, its `ForwardSearch` window and its `ScanBudget`
/// with the offsets it refused.
/// Reusing an instance across sources carries that spent state into the
/// next scan, so build a fresh one (`CpioSalvage::default()`) per source.
#[derive(Debug, Default)]
pub struct CpioSalvage {
    resume: Option<Resume>,
    /// Every variant header seen, and every header refused because a read
    /// would have overspent [`Self::budget`] (a
    /// [`Sighting::verdict_bounded`]; its own `over_budget` list before
    /// 0.10.4). A [`SightingLog`]: each is
    /// counted, at most [`SightingLog::DEFAULT_CAP`] stored per shape, pushed
    /// in ascending offset order because the scan only moves forward, so the
    /// ones kept are the first. The exit-3 refusal reads its counts from it.
    sightings: SightingLog,
    /// The zero runs this scan has read — see [`KnownZeros`].
    memo: KnownZeros,
    /// The magic search's reusable window.
    search: ForwardSearch,
    /// The name and symlink-target bytes this scan may read — 0.10.3 Task
    /// 4b. A header's verdict reads its name, up to 64 KiB, and a symlink's
    /// kind reads its target, up to 64 KiB more; a refused header, an
    /// uncorroborated size and a truncated payload all resume the scan one
    /// byte past the header. Headers every 128 bytes declaring 65,535-byte
    /// names read 482x the input that way, and symlinks declaring 65,535-byte
    /// targets 483x. Charged before each is read, in the scan and in the
    /// corroboration check alike ([`read_name`], [`symlink_target`]). Built
    /// on the first call, from the source's length; one per scan.
    budget: Option<ScanBudget>,
}

#[derive(Debug, Clone, Copy)]
struct Resume {
    header: u64,
    at: u64,
}

impl CpioSalvage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SalvageScan for CpioSalvage {
    fn next_candidate(&mut self, src: &mut dyn SeekRead, from: u64) -> Result<Option<Candidate>> {
        let file_len = src.seek(SeekFrom::End(0))?;
        let budget = self
            .budget
            .get_or_insert_with(|| ScanBudget::for_input(file_len));
        // The engine's own advance is `offset + declared_len` — the same
        // unattested `c_filesize` — so after a candidate this scanner, not
        // the engine, decides where to carry on. Taken, not peeked: it
        // describes one candidate, and the engine always calls back with a
        // `from` past that candidate's header.
        let mut search_from = match self.resume.take() {
            Some(resume) if from > resume.header => resume.at,
            _ => from,
        };
        loop {
            let Some((offset, fixed)) =
                find_next_header(&mut self.search, src, search_from, file_len)?
            else {
                return Ok(None);
            };
            match scan_at(src, offset, fixed, file_len, &mut self.memo, budget) {
                Scanned::Found(found) => {
                    self.resume = Some(Resume {
                        header: found.candidate.offset,
                        at: found.resume_at,
                    });
                    return Ok(Some(found.candidate));
                }
                // Recorded, never a candidate: the engine must never advance
                // by a length this build could not gate.
                Scanned::Sighting(variant) => {
                    self.sightings
                        .push(Sighting::new(CPIO, offset, variant.shape()))
                }
                Scanned::NotAnEntry => {}
                // Not judged: reported, and resumed exactly like a refusal.
                Scanned::OverBudget => self.sightings.push(Sighting::verdict_bounded(
                    CPIO,
                    offset,
                    VERDICT_BUDGET_SHAPE,
                )),
            }
            // One byte on, so a genuine header overlapping this one is never
            // skipped.
            search_from = offset + 1;
        }
    }

    /// `u64::MAX`: this scanner imposes no ceiling of its own — see the
    /// module doc's last section.
    fn max_whole_entry(&self) -> u64 {
        u64::MAX
    }

    /// `Unattested` for a whole entry whose fixed header still clears the
    /// gate where discovery found it, and still places and sizes its payload
    /// as it did (the name behind it was judged at discovery and is not read
    /// again, 0.10.3 Task 4b) — never `Complete`, which would assert a
    /// header self-check `newc` does not have. `Partial` for a truncated
    /// payload, or a header that no longer reads as it did. Never `Err`.
    fn verify(&self, src: &mut dyn SeekRead, candidate: &Candidate) -> Result<SalvageStatus> {
        verify_candidate(src, candidate)
    }

    fn write_payload(
        &self,
        archive_path: &Path,
        entry: &SalvagedEntry,
        compressed_len: u64,
        out: &mut dyn Write,
    ) -> Result<bool> {
        write_payload(archive_path, entry, compressed_len, out)
    }
}

/// Decides [`SalvageStatus`] for one candidate. See [`CpioSalvage::verify`].
fn verify_candidate(src: &mut dyn SeekRead, candidate: &Candidate) -> Result<SalvageStatus> {
    if candidate.available_len.is_some() {
        return Ok(SalvageStatus::Partial);
    }
    if candidate.meta.codec != Some(STORED) {
        return Ok(SalvageStatus::Unverified(
            UnverifiedCause::UndecodableMethod,
        ));
    }
    let Ok(file_len) = src.seek(SeekFrom::End(0)) else {
        return Ok(SalvageStatus::Partial);
    };
    // The fixed header alone (0.10.3 Task 4b): the payload's start and
    // length come from its fields, and the name behind them was judged at
    // discovery. Re-reading a 64 KiB name per candidate here doubled the
    // scan's name reads, outside its budget.
    let magic = read_at(src, candidate.offset, MAGIC_LEN as u64, file_len);
    let still_the_header = magic.as_deref() == Some(NEWC_MAGIC.as_slice())
        && read_at(src, candidate.offset, NEWC_HEADER_LEN as u64, file_len)
            .ok_or(Refusal::ShortHeader)
            .and_then(|header| newc_fields(&header))
            .is_ok_and(|fields| {
                newc_payload_start(candidate.offset, u64::from(fields[NAMESIZE]))
                    == Some(candidate.payload_start)
                    && Some(u64::from(fields[FILESIZE])) == candidate.declared_len
            });
    Ok(if still_the_header {
        SalvageStatus::Unattested
    } else {
        SalvageStatus::Partial
    })
}

/// Writes one entry's stored payload to `out`, answering whether every
/// declared byte was written. The read is bounded by what the SOURCE holds,
/// so a truncated entry's genuine surviving prefix is written — and only
/// that: nothing pads it to the declared length.
pub fn write_payload(
    archive_path: &Path,
    entry: &SalvagedEntry,
    compressed_len: u64,
    out: &mut dyn Write,
) -> Result<bool> {
    // Refused BEFORE `archive_path` is opened — `entries.rs`'s
    // `salvage_caps_tests` probes every salvage-capable container with a
    // codec-less entry and a path that does not exist.
    if entry.meta.codec != Some(STORED) {
        return Err(Error::Unsupported(format!(
            "entry `{}` carries codec {:?}; this build's cpio salvage writer writes stored \
             newc entries only",
            entry.meta.name, entry.meta.codec
        )));
    }
    // Not `unwrap_or(0)`: with an expected length of 0, `stream_bounded_copy`
    // reports success having written nothing.
    let Some(expected) = entry.meta.size else {
        return Err(Error::Corrupt(format!(
            "entry `{}` carries no declared size; this scanner sets one for every candidate, \
             so its own invariant does not hold for this entry",
            entry.meta.name
        )));
    };
    let mut f = File::open(archive_path)?;
    let Ok(file_len) = f.seek(SeekFrom::End(0)) else {
        return Ok(false);
    };
    if f.seek(SeekFrom::Start(entry.payload_start)).is_err() {
        return Ok(false);
    }
    let readable_len = compressed_len.min(file_len.saturating_sub(entry.payload_start));
    let truncated = readable_len < compressed_len;
    let completed = stream_bounded_copy((&mut f).take(readable_len), expected, out)?;
    Ok(completed && !truncated)
}

/// The sentence a run that recovered NOTHING reports when it saw variant
/// headers — naming each variant, and that the archive is not thereby
/// shown damaged.
fn refusal(sightings: &SightingLog) -> String {
    let parts: Vec<String> = [Variant::Odc, Variant::Crc]
        .into_iter()
        .filter_map(|variant| {
            let n = variant_count(sightings, variant);
            (n > 0).then(|| format!("{n} {} — {}", variant.shape(), variant.name()))
        })
        .collect();
    format!(
        "this build's cpio salvage scanner found {} and nothing it can recover: each is a \
         well-formed header of a cpio variant this build does not read, so this says nothing \
         about damage — the archive may be perfectly healthy. This build salvages `newc` \
         (magic `070701`) only; `stuffr list` names the variant",
        parts.join(" and ")
    )
}

/// How many `variant` headers `sightings` counted — exact, stored or not.
fn variant_count(sightings: &SightingLog, variant: Variant) -> u64 {
    sightings.count(CPIO, variant.shape(), SightingKind::Ungateable)
}

/// Runs [`CpioSalvage`] over `src` and annotates the result — the whole
/// scanner, matching every other format's `salvage_*` entry point. cpio has
/// no index to reconcile against, so the raw scan is the only source.
pub fn salvage_cpio(src: &mut dyn SeekRead, policy: &SalvagePolicy) -> Result<SalvageOutcome> {
    let mut scanner = CpioSalvage::new();
    let mut outcome = salvage_all(&mut scanner, src, policy)?;
    // Ruling 3-J: nothing recovered, a variant seen — a claim about this
    // BUILD (exit 3), never "nothing recoverable" about the archive (exit
    // 5). Only when nothing came back (Ruling S-X): a mixed run reports what
    // it got at its own code, and carries the sightings for the note.
    let variants = [Variant::Odc, Variant::Crc]
        .into_iter()
        .any(|variant| variant_count(&scanner.sightings, variant) > 0);
    if outcome.entries.is_empty() && variants {
        return Err(Error::Unsupported(refusal(&scanner.sightings)));
    }
    // 0.10.3 Task 4b: beside them, every header the scan's budget left
    // unjudged — never an entry, and printed by the caller like any other
    // sighting.
    outcome.sightings = scanner.sightings.into_sightings();
    // Stable, so each group keeps its ascending order and the sighting
    // carrying its `more`.
    outcome.sightings.sort_by_key(|s| s.offset);
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use stuffr_core::salvage::describe_sightings;
    use stuffr_core::testing::SharedBuf;
    use stuffr_core::{Container, CreateOpts, OpenOpts, PlainSink, ReaderSource, Source};

    use super::*;
    use crate::cpio::CpioNewc;

    /// The size of the allocation [`probe_canary`] makes. The allocator-probe
    /// tests below used to take the scan's own 64 KiB read buffer as proof
    /// the recording allocator was attached; since 0.10.3 the scan reads 64
    /// bytes first and allocates no such buffer for a small input, so the
    /// proof is now an allocation the test makes itself, inside the measured
    /// closure.
    const PROBE_CANARY: usize = 64 * 1024;

    fn probe_canary() {
        std::hint::black_box(vec![0u8; PROBE_CANARY]);
    }

    fn scan(bytes: &[u8]) -> SalvageOutcome {
        salvage_cpio(&mut Cursor::new(bytes.to_vec()), &SalvagePolicy::default()).expect(
            "a salvage scan must not error here — an `Err` is a variant sighting (Ruling 3-J), \
             which none of these inputs may produce",
        )
    }

    fn names_and_statuses(out: &SalvageOutcome) -> Vec<(String, SalvageStatus)> {
        out.entries
            .iter()
            .map(|e| (e.meta.name.clone(), e.status))
            .collect()
    }

    fn gate(bytes: &[u8], offset: usize) -> std::result::Result<Newc, Refusal> {
        gate_newc_at(
            &mut Cursor::new(bytes.to_vec()),
            offset as u64,
            bytes.len() as u64,
        )
    }

    // -------------------------------------------------------------------
    // Fixture builders.
    //
    // `build_cpio` writes through `cpio.rs`'s own writer — the `cpio`
    // crate's `Builder`, the same crate whose `Reader` the layout here is
    // read off — so a test standing on it proves AGREEMENT with that crate
    // and nothing more. `newc_entry` builds one header by hand, for shapes
    // no writer produces. The reference-writer test at the end is the
    // independent witness.
    // -------------------------------------------------------------------

    fn build_cpio(entries: &[(EntryMeta, &[u8])]) -> Vec<u8> {
        let buf = SharedBuf::new();
        let mut w = CpioNewc
            .create(
                PlainSink::new(Box::new(buf.clone())),
                &CreateOpts::default(),
            )
            .expect("create");
        for (meta, data) in entries {
            w.add(meta, &mut Cursor::new(*data)).expect("add");
        }
        w.finish().expect("finish").finish().expect("finish sink");
        buf.contents()
    }

    fn files(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let metas: Vec<(EntryMeta, &[u8])> = entries
            .iter()
            .map(|(name, data)| (EntryMeta::file(*name), *data))
            .collect();
        build_cpio(&metas)
    }

    /// One `newc` entry by hand: `name_field` is the name's bytes EXACTLY as
    /// stored (its NUL included, or not), `c_namesize` is their length.
    fn newc_entry_raw(magic: &[u8; 6], name_field: &[u8], data: &[u8]) -> Vec<u8> {
        let fields: [u32; NEWC_FIELDS] = [
            1,
            0o100644,
            0,
            0,
            1,
            0x5F00_0000,
            data.len() as u32,
            0,
            0,
            0,
            0,
            name_field.len() as u32,
            0,
        ];
        let mut out = magic.to_vec();
        for field in fields {
            out.extend_from_slice(format!("{field:08X}").as_bytes());
        }
        out.extend_from_slice(name_field);
        out.resize(round_up_to_4(out.len() as u64).unwrap() as usize, 0);
        out.extend_from_slice(data);
        out.resize(round_up_to_4(out.len() as u64).unwrap() as usize, 0);
        out
    }

    fn newc_entry(name: &str, data: &[u8]) -> Vec<u8> {
        let mut field = name.as_bytes().to_vec();
        field.push(0);
        newc_entry_raw(NEWC_MAGIC, &field, data)
    }

    /// One `odc` entry by hand, in POSIX's layout (no padding anywhere).
    fn odc_entry(name: &str, data: &[u8]) -> Vec<u8> {
        let mut out = ODC_MAGIC.to_vec();
        let values = [
            0u64,
            1,
            0o100644,
            0,
            0,
            1,
            0,
            0o14727046122,
            name.len() as u64 + 1,
            data.len() as u64,
        ];
        for (value, width) in values.into_iter().zip(ODC_FIELD_WIDTHS) {
            out.extend_from_slice(format!("{value:0width$o}").as_bytes());
        }
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        out.extend_from_slice(data);
        out
    }

    fn with_trailer(mut entries: Vec<u8>, magic: &[u8; 6]) -> Vec<u8> {
        entries.extend_from_slice(&newc_entry_raw(magic, b"TRAILER!!!\0", b""));
        entries
    }

    /// Where a field starts in a `newc` header.
    fn field_at(i: usize) -> std::ops::Range<usize> {
        MAGIC_LEN + i * NEWC_FIELD_LEN..MAGIC_LEN + (i + 1) * NEWC_FIELD_LEN
    }

    /// One entry as the ordinary reader reports it: name, size, kind, bytes.
    type ReaderRow = (String, u64, EntryKind, Vec<u8>);

    fn read_through_the_reader(bytes: &[u8]) -> Result<Vec<ReaderRow>> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(Cursor::new(bytes.to_vec())));
        let resolved = stuffr_core::resolve(
            src,
            CPIO,
            CpioNewc.caps(),
            &stuffr_core::StreamPolicy::default(),
        )?;
        let mut ar = CpioNewc.open(resolved, &OpenOpts::default())?;
        let mut out = Vec::new();
        while let Some(mut entry) = ar.next_entry()? {
            let meta = entry.meta().clone();
            let mut data = Vec::new();
            entry.reader().read_to_end(&mut data)?;
            out.push((meta.name, meta.size.unwrap_or(0), meta.kind, data));
        }
        Ok(out)
    }

    struct TempArchive(std::path::PathBuf);

    impl TempArchive {
        fn new(bytes: &[u8], tag: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "stuffr-cpio-salvage-{tag}-{}-{}.cpio",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::write(&path, bytes).expect("write temp archive");
            TempArchive(path)
        }
    }

    impl Drop for TempArchive {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// Writes every entry of `outcome` back out through [`write_payload`],
    /// returning `(bytes, completed)` per entry.
    fn write_back(bytes: &[u8], outcome: &SalvageOutcome) -> Vec<(Vec<u8>, bool)> {
        let archive = TempArchive::new(bytes, "write-back");
        outcome
            .entries
            .iter()
            .map(|entry| {
                let mut out = Vec::new();
                let completed = write_payload(
                    &archive.0,
                    entry,
                    entry
                        .meta
                        .compressed_size
                        .expect("every candidate declares one"),
                    &mut out,
                )
                .expect("a stored entry must write");
                (out, completed)
            })
            .collect()
    }

    // -------------------------------------------------------------------
    // The anti-vacuity pair
    // -------------------------------------------------------------------

    /// The LCG every scanner's noise test uses — byte-identical everywhere.
    fn deterministic_noise(len: usize) -> Vec<u8> {
        let mut state: u32 = 0xC0FF_EE42;
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            out.extend_from_slice(&state.to_le_bytes());
        }
        out.truncate(len);
        out
    }

    /// Bare magics with noise after them, for all three variants. The gate
    /// strength the module doc states means incidental magics essentially
    /// never occur, so these are SEEDED: each must reach the gate and be
    /// stopped by criterion 2, and a scanner keying on the magic alone would
    /// report ten phantoms (and four sightings) here.
    const SEEDED_NEWC_OFFSETS: [usize; 6] = [65_536, 196_608, 344_064, 491_520, 638_976, 786_432];
    const SEEDED_CRC_OFFSETS: [usize; 2] = [250_000, 550_000];
    const SEEDED_ODC_OFFSETS: [usize; 2] = [520_000, 950_000];

    /// A whole entry whose ONLY defect is one non-hex digit in `c_mtime`, a
    /// field that locates nothing — criterion 2's splice. A scanner that
    /// validated only the fields it needs would report it.
    pub(super) const NOT_HEX_OFFSET: usize = 300_000;
    /// `c_namesize` one past [`MAX_CPIO_NAME_LEN`], over a name that really
    /// is that long and NUL-terminated — criterion 3's splice.
    const NAME_OVER_CEILING_OFFSET: usize = 400_000;
    /// A name whose last byte is not NUL — criterion 5's splice.
    const NO_NUL_OFFSET: usize = 600_000;
    /// A name that is not UTF-8 — criterion 6's splice.
    const NOT_UTF8_OFFSET: usize = 700_000;
    /// A name of NULs alone — criterion 7's splice.
    const EMPTY_NAME_OFFSET: usize = 800_000;
    /// A well-formed `TRAILER!!!` header — the trailer rule's splice.
    const TRAILER_OFFSET: usize = 900_000;

    fn not_hex_splice() -> Vec<u8> {
        let mut entry = newc_entry("NOTHEX.TXT", b"payload");
        entry[field_at(MTIME)].copy_from_slice(b"5F00000G");
        entry
    }

    fn name_over_ceiling_splice() -> Vec<u8> {
        let mut name = b"BIGNAME".to_vec();
        name.resize(MAX_CPIO_NAME_LEN as usize + 1, 0);
        newc_entry_raw(NEWC_MAGIC, &name, b"")
    }

    fn no_nul_splice() -> Vec<u8> {
        newc_entry_raw(NEWC_MAGIC, b"NONUL!", b"")
    }

    fn not_utf8_splice() -> Vec<u8> {
        newc_entry_raw(NEWC_MAGIC, b"BAD\xFFNAME\0", b"")
    }

    fn empty_name_splice() -> Vec<u8> {
        newc_entry_raw(NEWC_MAGIC, b"\0\0", b"")
    }

    fn trailer_splice() -> Vec<u8> {
        newc_entry_raw(NEWC_MAGIC, b"TRAILER!!!\0", b"")
    }

    /// Every splice, with the criterion that must stop it (`None`: the
    /// trailer, which clears the gate and is still not an entry) and the
    /// name it carries once that one defect is repaired.
    fn splices() -> [(usize, Vec<u8>, Option<Refusal>); 6] {
        [
            (NOT_HEX_OFFSET, not_hex_splice(), Some(Refusal::NotHex)),
            (
                NAME_OVER_CEILING_OFFSET,
                name_over_ceiling_splice(),
                Some(Refusal::NameOverCeiling),
            ),
            (
                NO_NUL_OFFSET,
                no_nul_splice(),
                Some(Refusal::NameNotNulTerminated),
            ),
            (
                NOT_UTF8_OFFSET,
                not_utf8_splice(),
                Some(Refusal::NameNotUtf8),
            ),
            (
                EMPTY_NAME_OFFSET,
                empty_name_splice(),
                Some(Refusal::EmptyName),
            ),
            (TRAILER_OFFSET, trailer_splice(), None),
        ]
    }

    fn noise_with_splices(len: usize) -> Vec<u8> {
        let mut noise = deterministic_noise(len);
        for &at in &SEEDED_NEWC_OFFSETS {
            noise[at..at + MAGIC_LEN].copy_from_slice(NEWC_MAGIC);
        }
        for &at in &SEEDED_CRC_OFFSETS {
            noise[at..at + MAGIC_LEN].copy_from_slice(CRC_MAGIC);
        }
        for &at in &SEEDED_ODC_OFFSETS {
            noise[at..at + MAGIC_LEN].copy_from_slice(ODC_MAGIC);
        }
        for (at, splice, _) in splices() {
            noise[at..at + splice.len()].copy_from_slice(&splice);
        }
        noise
    }

    /// The negative double for the whole feature: nothing but plausibility
    /// stands between a phantom and a written file in this format, so a
    /// phantom here would be a file invented from noise.
    #[test]
    fn cpio_salvage_over_random_bytes_finds_nothing() {
        let out = scan(&noise_with_splices(1 << 20));
        assert!(
            out.entries.is_empty(),
            "1 MiB of noise with ten seeded magics and six near-miss headers produced {} \
             phantom(s): {:?}",
            out.entries.len(),
            out.entries
                .iter()
                .map(|e| (&e.meta.name, e.offset))
                .collect::<Vec<_>>()
        );
        assert!(
            out.sightings.is_empty(),
            "a bare variant magic is not a sighting: {:?}",
            out.sightings
        );
    }

    /// **The half that makes the test above a test.** Each splice stops at
    /// exactly its own criterion, and with that one defect repaired it is
    /// found — so each criterion is individually load-bearing. Each seeded
    /// bare magic reaches the gate and is stopped by criterion 2. And the
    /// only magics in the corpus are the seeded ones and the splices, so the
    /// empty outcome is the gate rejecting them, not the noise never trying.
    #[test]
    fn the_noise_corpus_reaches_each_criterion_it_claims_to() {
        let noise = noise_with_splices(1 << 20);

        for (at, _, refusal) in splices() {
            match refusal {
                Some(refusal) => assert_eq!(
                    gate(&noise, at).map(|n| n.name).unwrap_err(),
                    refusal,
                    "the splice at {at}"
                ),
                None => assert!(gate(&noise, at).unwrap().is_trailer()),
            }
        }

        // Each splice, repaired in place, is exactly one entry at its offset.
        let repaired = |at: usize, fix: &dyn Fn(&mut [u8])| {
            let mut bytes = noise.clone();
            fix(&mut bytes[at..]);
            scan(&bytes)
                .entries
                .iter()
                .map(|e| (e.meta.name.clone(), e.status, e.offset))
                .collect::<Vec<_>>()
        };
        let one =
            |name: &str, at: usize| vec![(name.to_string(), SalvageStatus::Unattested, at as u64)];
        assert_eq!(
            repaired(NOT_HEX_OFFSET, &|b| b[field_at(MTIME)]
                .copy_from_slice(b"5F000000")),
            one("NOTHEX.TXT", NOT_HEX_OFFSET),
            "one hex digit is the ONLY thing between that splice and an entry"
        );
        assert_eq!(
            repaired(NAME_OVER_CEILING_OFFSET, &|b| {
                b[field_at(NAMESIZE)].copy_from_slice(format!("{MAX_CPIO_NAME_LEN:08X}").as_bytes())
            }),
            one("BIGNAME", NAME_OVER_CEILING_OFFSET),
            "the ceiling, and only the ceiling, refuses that splice — a name AT it is accepted"
        );
        assert_eq!(
            repaired(NO_NUL_OFFSET, &|b| b[NEWC_HEADER_LEN + 5] = 0),
            one("NONUL", NO_NUL_OFFSET)
        );
        assert_eq!(
            repaired(NOT_UTF8_OFFSET, &|b| b[NEWC_HEADER_LEN + 3] = b'_'),
            one("BAD_NAME", NOT_UTF8_OFFSET)
        );
        assert_eq!(
            repaired(EMPTY_NAME_OFFSET, &|b| b[NEWC_HEADER_LEN] = b'E'),
            one("E", EMPTY_NAME_OFFSET)
        );
        assert_eq!(
            repaired(TRAILER_OFFSET, &|b| b[NEWC_HEADER_LEN] = b'X'),
            one("XRAILER!!!", TRAILER_OFFSET)
        );

        // Every seeded bare magic reaches the gate and is stopped at
        // criterion 2 — the field after the magic is noise.
        let mut src = Cursor::new(noise.clone());
        let len = noise.len() as u64;
        for &at in SEEDED_NEWC_OFFSETS.iter().chain(&SEEDED_CRC_OFFSETS) {
            assert_eq!(
                gate(&noise, at).map(|n| n.name).unwrap_err(),
                Refusal::NotHex
            );
        }
        for &at in &SEEDED_ODC_OFFSETS {
            assert_eq!(
                gate_odc_at(&mut src, at as u64, len).unwrap_err(),
                Refusal::NotOctal
            );
        }

        // And nothing else in the corpus carries a magic at all.
        let mut hits = Vec::new();
        let mut from = 0;
        let mut search = ForwardSearch::new();
        while let Some((at, _)) = find_next_magic(&mut search, &mut src, from, len).unwrap() {
            hits.push(at as usize);
            from = at + 1;
        }
        let mut expected: Vec<usize> = SEEDED_NEWC_OFFSETS
            .iter()
            .chain(&SEEDED_CRC_OFFSETS)
            .chain(&SEEDED_ODC_OFFSETS)
            .copied()
            .chain(splices().into_iter().map(|(at, _, _)| at))
            .collect();
        expected.sort_unstable();
        assert_eq!(hits, expected);
    }

    // -------------------------------------------------------------------
    // Healthy and damaged archives
    // -------------------------------------------------------------------

    /// The ordinary reader groups a GNU hard-link group by inode (data on
    /// the last link; earlier names held back and returned as links after
    /// it). Salvage does NOT: it reports headers as it finds them, in archive
    /// order, the earlier name as the 0-byte file its header declares.
    #[test]
    fn salvage_reports_a_gnu_link_group_header_by_header() {
        // `newc_entry` writes `c_ino = 1`; force `c_nlink` (offset 38) to 2.
        let mut a = newc_entry("a", b"");
        let mut c = newc_entry("c", b"hello");
        for member in [&mut a, &mut c] {
            member[38..46].copy_from_slice(b"00000002");
        }
        let mut entries = a;
        entries.extend(c);
        let bytes = with_trailer(entries, NEWC_MAGIC);

        let out = scan(&bytes);
        assert!(out.sightings.is_empty());
        assert_eq!(
            out.entries
                .iter()
                .map(|e| (e.meta.name.as_str(), e.meta.size, e.meta.kind.clone()))
                .collect::<Vec<_>>(),
            vec![
                ("a", Some(0), EntryKind::File),
                ("c", Some(5), EntryKind::File),
            ]
        );

        let reader = read_through_the_reader(&bytes).expect("the reader reads it");
        assert_eq!(
            reader
                .iter()
                .map(|(n, s, k, _)| (n.as_str(), *s, k.clone()))
                .collect::<Vec<_>>(),
            vec![
                ("c", 5, EntryKind::File),
                ("a", 5, EntryKind::Hardlink { target: "c".into() }),
            ]
        );
    }

    /// Every entry a healthy archive holds comes back `Unattested` — never
    /// `Complete` — named, sized and kinded as the ordinary reader reports
    /// it, with no trailer row and no sighting, and its bytes written back
    /// verbatim. Stands on this project's own writer; see the builders' note.
    #[test]
    fn every_entry_of_a_healthy_cpio_is_unattested_and_agrees_with_the_reader() {
        let long_name = format!("deep/{}/file.txt", "n".repeat(300));
        let mut dir = EntryMeta::file("deep");
        dir.kind = EntryKind::Dir;
        let mut link = EntryMeta::file("link.txt");
        link.kind = EntryKind::Symlink {
            target: "a.txt".into(),
        };
        let big = vec![0xA5u8; 3 * 512 + 17];
        let bytes = build_cpio(&[
            (dir, b""),
            (EntryMeta::file("a.txt"), b"alpha"),
            (EntryMeta::file("empty.bin"), b""),
            (EntryMeta::file(long_name.clone()), b"long"),
            (link, b""),
            (EntryMeta::file("big.bin"), &big),
        ]);

        let reader = read_through_the_reader(&bytes).expect("the reader reads it");
        let out = scan(&bytes);
        assert!(out.sightings.is_empty());
        assert_eq!(
            out.entries.len(),
            reader.len(),
            "{:?}",
            names_and_statuses(&out)
        );
        let written = write_back(&bytes, &out);
        for ((entry, (name, size, kind, data)), (payload, completed)) in
            out.entries.iter().zip(&reader).zip(&written)
        {
            assert_eq!(entry.status, SalvageStatus::Unattested, "{name}");
            assert_eq!(&entry.meta.name, name);
            assert_eq!(entry.meta.size, Some(*size), "{name}");
            assert_eq!(&entry.meta.kind, kind, "{name}");
            assert_eq!(entry.meta.codec, Some(STORED), "{name}");
            assert!(completed, "{name}");
            // The reader hands a symlink's target over as its kind, not as
            // bytes; the payload IS the target.
            match kind {
                EntryKind::Symlink { target } => assert_eq!(payload, target.as_bytes()),
                _ => assert_eq!(payload, data, "{name}"),
            }
        }
        assert_eq!(out.entries[3].meta.name, long_name);
    }

    /// One header destroyed: the reader refuses the whole archive, and the
    /// scan loses that entry alone.
    #[test]
    fn a_destroyed_first_header_costs_that_entry_alone() {
        let mut bytes = files(&[("a.txt", b"alpha"), ("b.txt", b"beta"), ("c.txt", b"gamma")]);
        bytes[field_at(0).start] = b'x';
        assert!(read_through_the_reader(&bytes).is_err());
        let out = scan(&bytes);
        assert_eq!(
            names_and_statuses(&out),
            vec![
                ("b.txt".to_string(), SalvageStatus::Unattested),
                ("c.txt".to_string(), SalvageStatus::Unattested)
            ]
        );
        let written = write_back(&bytes, &out);
        assert_eq!(written[0], (b"beta".to_vec(), true));
        assert_eq!(written[1], (b"gamma".to_vec(), true));
    }

    /// A cut inside the last entry's payload: that entry is `Partial`, its
    /// genuine prefix is written, and nothing pads it.
    #[test]
    fn a_truncated_tail_is_partial_and_its_genuine_prefix_is_written() {
        let bytes = files(&[("a.txt", b"alpha"), ("c.txt", b"the last entry's payload")]);
        let c_at = bytes
            .windows(5)
            .position(|w| w == b"c.txt")
            .expect("c.txt's name");
        // The header starts 110 bytes before the name, and `c.txt\0` (six
        // bytes) ends it on a multiple of four: 116 is already aligned.
        let payload_at = c_at + 6;
        let cut = &bytes[..payload_at + 8];
        let out = scan(cut);
        assert_eq!(
            names_and_statuses(&out),
            vec![
                ("a.txt".to_string(), SalvageStatus::Unattested),
                ("c.txt".to_string(), SalvageStatus::Partial)
            ]
        );
        assert_eq!(
            out.entries[1].meta.size,
            Some(24),
            "the declared size is the header's"
        );
        let written = write_back(cut, &out);
        assert_eq!(written[1], (b"the last".to_vec(), false));
    }

    /// A `newc` archive stored inside a `newc` archive is ONE entry: the
    /// scan jumps a whole entry's payload rather than reporting what is in
    /// it (every initramfs that embeds one would otherwise be flattened).
    #[test]
    fn a_cpio_stored_inside_a_cpio_is_one_entry_not_its_contents() {
        let inner = files(&[("inner-a.txt", b"one"), ("inner-b.txt", b"two")]);
        let outer = files(&[("inner.cpio", &inner), ("after.txt", b"after")]);
        assert_eq!(
            names_and_statuses(&scan(&outer)),
            vec![
                ("inner.cpio".to_string(), SalvageStatus::Unattested),
                ("after.txt".to_string(), SalvageStatus::Unattested)
            ]
        );

        // The case only the payload JUMP protects. The engine alone resumes
        // at `offset + declared_len`, which is the payload's length measured
        // from the HEADER, so it lands one header-and-name short of the
        // payload's end — exactly where an inner archive's last header sits
        // when it has no trailer after it. Measured: with the jump removed,
        // the first half of this test stays green and this half does not.
        let mut inner = newc_entry("inner-a.txt", b"one");
        inner.extend_from_slice(&newc_entry("inner-b.txt", b""));
        let outer = files(&[("inner.cpio", &inner), ("after.txt", b"after")]);
        assert_eq!(
            names_and_statuses(&scan(&outer)),
            vec![
                ("inner.cpio".to_string(), SalvageStatus::Unattested),
                ("after.txt".to_string(), SalvageStatus::Unattested)
            ]
        );
    }

    /// Task 3 review, I1: `c_filesize` is attested by NOTHING, so the
    /// payload jump must not trust it alone. The reviewer's reproducer,
    /// exactly: `one.txt` holds 16 bytes, and the last hex digit of its
    /// `c_filesize` is changed from `0` to `F` (0x10 → 0x1F). With the jump
    /// unconditional, `two.txt` vanished — no row, no note — and `one.txt`
    /// was written with `two.txt`'s header bytes inside it. The jump now
    /// lands only where a header (or EOF, or zero padding to EOF)
    /// corroborates it; otherwise the scan resumes one byte past the header.
    ///
    /// The second damage grows the size instead (0x10 → 0x410), which is
    /// why the fallback is NOT the engine's own advance: that is `offset +
    /// c_filesize`, the same unattested number, and would carry the scan
    /// 1,040 bytes on — straight past `two.txt`.
    #[test]
    fn a_damaged_size_never_costs_the_entry_behind_it() {
        let healthy = files(&[
            ("one.txt", b"sixteen bytes..!"),
            ("two.txt", b"the entry behind"),
            ("three.txt", &[b'3'; 2000]),
        ]);
        assert_eq!(&healthy[field_at(FILESIZE)], b"00000010");
        for (at, digit, declared) in [(7, b'F', 0x1F), (5, b'4', 0x410)] {
            let mut bytes = healthy.clone();
            bytes[field_at(FILESIZE).start + at] = digit;
            assert!(read_through_the_reader(&bytes).is_err());
            let out = scan(&bytes);
            assert_eq!(
                out.entries
                    .iter()
                    .map(|e| (e.meta.name.as_str(), e.meta.size))
                    .collect::<Vec<_>>(),
                vec![
                    ("one.txt", Some(declared)),
                    ("two.txt", Some(16)),
                    ("three.txt", Some(2000))
                ],
                "size 0x{declared:X}: a damaged size must cost its own entry's bytes at most, \
                 never the entry behind it"
            );
            let written = write_back(&bytes, &out);
            assert_eq!(written[1], (b"the entry behind".to_vec(), true));
            // What `one.txt` itself holds is the genuine prefix of what the
            // header declared — its own sixteen bytes first, never padded.
            assert_eq!(&written[0].0[..16], b"sixteen bytes..!");
        }
    }

    /// Off its four-byte alignment (a carved image, a download missing its
    /// first bytes), every entry is still found.
    #[test]
    fn a_cpio_shifted_off_its_alignment_is_still_found() {
        let mut bytes = b"xyz".to_vec();
        bytes.extend_from_slice(&files(&[("a.txt", b"alpha"), ("b.txt", b"beta")]));
        let out = scan(&bytes);
        assert_eq!(
            out.entries
                .iter()
                .map(|e| (e.meta.name.as_str(), e.offset % 4))
                .collect::<Vec<_>>(),
            vec![("a.txt", 3), ("b.txt", 3)]
        );
        assert_eq!(write_back(&bytes, &out)[1], (b"beta".to_vec(), true));
    }

    /// An initramfs is several archives back to back. The trailer ends the
    /// reader and never the scan, and is never a row itself.
    #[test]
    fn the_trailer_is_never_an_entry_and_a_concatenated_archive_is_found() {
        let mut bytes = files(&[("first.txt", b"1")]);
        bytes.extend_from_slice(&[0u8; 512]);
        bytes.extend_from_slice(&files(&[("second.txt", b"2")]));
        assert_eq!(
            names_and_statuses(&scan(&bytes)),
            vec![
                ("first.txt".to_string(), SalvageStatus::Unattested),
                ("second.txt".to_string(), SalvageStatus::Unattested)
            ]
        );
    }

    /// Criterion 4: a header whose name runs past the end of the source is
    /// not a header — there is no name to report it under.
    #[test]
    fn a_name_that_runs_past_the_end_is_not_a_header() {
        let mut bytes = newc_entry("kept.txt", b"kept");
        let second_at = bytes.len();
        bytes.extend_from_slice(&newc_entry("a-name-cut-short.txt", b""));
        let cut = &bytes[..second_at + NEWC_HEADER_LEN + 4];
        assert_eq!(
            gate(cut, second_at).map(|n| n.name).unwrap_err(),
            Refusal::NameRunsPastEnd
        );
        assert_eq!(
            names_and_statuses(&scan(cut)),
            vec![("kept.txt".to_string(), SalvageStatus::Unattested)]
        );
    }

    /// `verify` answers `Unattested` only for a header that still clears
    /// the gate where discovery found it.
    #[test]
    fn verify_does_not_answer_unattested_for_a_header_that_changed() {
        let bytes = files(&[("a.txt", b"alpha")]);
        let mut scanner = CpioSalvage::new();
        let candidate = scanner
            .next_candidate(&mut Cursor::new(bytes.clone()), 0)
            .unwrap()
            .expect("a candidate");
        assert_eq!(
            scanner
                .verify(&mut Cursor::new(bytes.clone()), &candidate)
                .unwrap(),
            SalvageStatus::Unattested
        );
        let mut changed = bytes;
        changed[field_at(FILESIZE).start] = b'Z';
        assert_eq!(
            scanner
                .verify(&mut Cursor::new(changed), &candidate)
                .unwrap(),
            SalvageStatus::Partial
        );
    }

    // -------------------------------------------------------------------
    // Variants this build does not read (Ruling 3-J)
    // -------------------------------------------------------------------

    /// A healthy archive of a variant this build does not read is exit 3
    /// naming the variant, never "nothing recoverable" (exit 5).
    #[test]
    fn an_archive_of_a_variant_this_build_cannot_read_is_a_sighting_not_an_absence() {
        let mut odc = odc_entry("a.txt", b"alpha");
        odc.extend_from_slice(&odc_entry("TRAILER!!!", b""));
        let crc = with_trailer(newc_entry_raw(CRC_MAGIC, b"a.txt\0", b"alpha"), CRC_MAGIC);
        for (bytes, magic, name) in [(odc, "070707", "odc"), (crc, "070702", "newc-crc")] {
            let err = salvage_cpio(&mut Cursor::new(bytes), &SalvagePolicy::default())
                .expect_err("a variant archive must refuse, not report empty");
            assert_eq!(err.exit_code(), 3, "{err}");
            let message = err.to_string();
            for needle in [
                magic,
                name,
                "newc",
                "`070701`",
                "stuffr list",
                "1 header(s)",
            ] {
                assert!(message.contains(needle), "{needle:?} missing: {message}");
            }
        }
    }

    /// In a MIXED run a variant header is carried as a sighting with its
    /// offset — never a row, never the exit code — and a healthy `newc`
    /// archive carries none.
    #[test]
    fn a_mixed_run_carries_its_sightings_and_still_lists_none_of_them() {
        let mut bytes = files(&[("ok.txt", b"fine")]);
        let odc_at = bytes.len() as u64;
        bytes.extend_from_slice(&odc_entry("old.txt", b"old"));
        let out = scan(&bytes);
        assert_eq!(
            names_and_statuses(&out),
            vec![("ok.txt".to_string(), SalvageStatus::Unattested)]
        );
        assert_eq!(out.sightings, vec![Sighting::new(CPIO, odc_at, ODC_SHAPE)]);
        let note = describe_sightings(&out.sightings).unwrap();
        assert!(
            note.contains("odc") && note.contains(&format!("offset(s) {odc_at}")),
            "{note}"
        );
        assert!(scan(&files(&[("ok.txt", b"fine")])).sightings.is_empty());
    }

    // -------------------------------------------------------------------
    // Bounded lengths: the allocator-probe pairs
    // -------------------------------------------------------------------

    /// A header declaring a 2.8 GB name is refused at criterion 3 before the
    /// name is allocated — the shape `cpio.rs`'s own guard closes for the
    /// reader (a real fuzz OOM, `malloc(2863311530)`).
    #[test]
    fn an_absurd_name_size_never_becomes_an_allocation() {
        let mut bytes = newc_entry("x", b"");
        bytes[field_at(NAMESIZE)].copy_from_slice(b"AAAAAAAA");
        bytes.extend_from_slice(&[0x5A; 100]);
        assert_eq!(
            gate(&bytes, 0).map(|n| n.name).unwrap_err(),
            Refusal::NameOverCeiling
        );
        let mut src = Cursor::new(bytes);
        let (out, largest) = crate::alloc_probe::largest_single_allocation(|| {
            probe_canary();
            salvage_cpio(&mut src, &SalvagePolicy::default()).unwrap()
        });
        assert!(out.entries.is_empty());
        assert!(
            largest <= 1 << 20,
            "largest single allocation was {largest} bytes"
        );
        assert!(
            largest >= PROBE_CANARY,
            "largest single allocation was only {largest} bytes, below the {PROBE_CANARY}-byte \
             canary the closure allocates — the recording allocator is not attached"
        );
    }

    /// A name exactly AT the ceiling is read, and costs about its own size.
    #[test]
    fn a_name_at_the_ceiling_is_read_and_bounded() {
        let mut name = "n".repeat(MAX_CPIO_NAME_LEN as usize - 1).into_bytes();
        name.push(0);
        let bytes = newc_entry_raw(NEWC_MAGIC, &name, b"data");
        let mut src = Cursor::new(bytes);
        let (out, largest) = crate::alloc_probe::largest_single_allocation(|| {
            probe_canary();
            salvage_cpio(&mut src, &SalvagePolicy::default()).unwrap()
        });
        assert_eq!(out.entries.len(), 1);
        assert_eq!(
            out.entries[0].meta.name.len(),
            MAX_CPIO_NAME_LEN as usize - 1
        );
        assert!(
            largest < 256 << 10,
            "largest single allocation was {largest} bytes"
        );
        assert!(
            largest >= PROBE_CANARY,
            "the recording allocator is not attached ({largest})"
        );
    }

    /// A 4 GiB declaration over 100 present bytes is `Partial`, and neither
    /// the scan, the verify nor the write sizes anything from it.
    #[test]
    fn a_four_gigabyte_declaration_never_becomes_an_allocation() {
        let mut bytes = newc_entry("huge.bin", b"");
        bytes[field_at(FILESIZE)].copy_from_slice(b"FFFFFFFF");
        bytes.extend_from_slice(&[0x5A; 100]);
        let archive = TempArchive::new(&bytes, "huge");
        let mut src = Cursor::new(bytes);
        let ((out, written), largest) = crate::alloc_probe::largest_single_allocation(|| {
            probe_canary();
            let out = salvage_cpio(&mut src, &SalvagePolicy::default()).unwrap();
            let written = write_payload(
                &archive.0,
                &out.entries[0],
                u64::from(u32::MAX),
                &mut io::sink(),
            )
            .unwrap();
            (out, written)
        });
        assert!(
            largest <= 1 << 20,
            "largest single allocation was {largest} bytes"
        );
        assert!(
            largest >= PROBE_CANARY,
            "the recording allocator is not attached ({largest})"
        );
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].status, SalvageStatus::Partial);
        assert_eq!(out.entries[0].meta.size, Some(u64::from(u32::MAX)));
        assert!(!written);
    }

    /// A WHOLE entry eight times anything the scanner buffers is scanned,
    /// verified and written without becoming one allocation. The archive and
    /// its cursor are built OUTSIDE the measured closure.
    #[test]
    fn a_whole_entry_is_written_without_being_buffered() {
        let payload = vec![0xC3u8; 8 << 20];
        let bytes = files(&[("big.bin", &payload)]);
        let archive = TempArchive::new(&bytes, "whole");
        let mut src = Cursor::new(bytes);
        let ((status, completed), largest) = crate::alloc_probe::largest_single_allocation(|| {
            probe_canary();
            let out = salvage_cpio(&mut src, &SalvagePolicy::default()).unwrap();
            let completed = write_payload(
                &archive.0,
                &out.entries[0],
                payload.len() as u64,
                &mut io::sink(),
            )
            .unwrap();
            (out.entries[0].status, completed)
        });
        assert!(
            largest < 1 << 20,
            "largest single allocation was {largest} bytes"
        );
        assert!(
            largest >= PROBE_CANARY,
            "the recording allocator is not attached ({largest})"
        );
        assert_eq!(status, SalvageStatus::Unattested);
        assert!(completed);
    }

    // -------------------------------------------------------------------
    // 0.10.3 §1: the scan is linear (zero-run memo, `ForwardSearch`)
    // -------------------------------------------------------------------

    /// One newc header + NUL-terminated name, padded to 4, declaring `size`
    /// payload bytes but carrying none (the caller lays out what follows).
    fn newc_header_only(name: &str, size: u32) -> Vec<u8> {
        let namesize = name.len() as u32 + 1;
        let mut h = format!(
            "070701{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}",
            1, 0o100644, 0, 0, 1, 0, size, 0, 0, 0, 0, namesize, 0
        )
        .into_bytes();
        h.extend_from_slice(name.as_bytes());
        h.push(0);
        while h.len() % 4 != 0 {
            h.push(0);
        }
        h
    }

    /// 0.10.3 §1: many headers whose declared sizes land in one long zero run
    /// that ends in a non-zero byte. Before the memo every one rescanned the
    /// run: quadratic.
    fn dense_headers_into_a_zero_run() -> Vec<u8> {
        let headers = 2_000usize;
        let run = 900 * 1024usize;
        let mut out = Vec::new();
        let mut layout = Vec::new();
        for i in 0..headers {
            layout.push(newc_header_only(&format!("f{i}"), 0));
        }
        let header_bytes: usize = layout.iter().map(Vec::len).sum();
        // Each header's size lands it (4-aligned) somewhere inside the run.
        let mut at = 0usize;
        for (i, h) in layout.iter().enumerate() {
            let payload_start = at + h.len();
            let landing = header_bytes + 4 * (i + 1);
            let size = (landing - payload_start) as u32;
            out.extend_from_slice(&newc_header_only(&format!("f{i}"), size));
            at = out.len();
        }
        out.resize(header_bytes + run, 0);
        out.push(1); // the run does not reach EOF
        out
    }

    #[test]
    fn dense_headers_into_a_zero_run_scan_linearly() {
        use stuffr_core::testing::{CountingSource, check_scan_is_linear};
        let data = dense_headers_into_a_zero_run();
        let len = data.len() as u64;
        let mut src = CountingSource::new(Cursor::new(data));
        let outcome = salvage_cpio(&mut src, &SalvagePolicy::default()).unwrap();
        assert!(!outcome.entries.is_empty());
        check_scan_is_linear(src.bytes_read(), len).unwrap();
    }

    /// 0.10.3 Task 4b: each magic repeated through 256 KiB — `070701` and
    /// `070702` repeated are hex in every field, `070707` octal, so every
    /// one reaches the fixed header's name-size check. Before the search
    /// judged the fixed header, a magic every six bytes read a 110- or
    /// 76-byte header each: 19x, 19x and 39x the input (at 1 MiB).
    #[test]
    fn dense_magics_scan_linearly() {
        use stuffr_core::testing::{CountingSource, check_scan_is_linear};
        const LEN: usize = 256 * 1024;
        for magic in [NEWC_MAGIC, CRC_MAGIC, ODC_MAGIC] {
            let data: Vec<u8> = magic.iter().copied().cycle().take(LEN).collect();
            let mut src = CountingSource::new(Cursor::new(data));
            let outcome = salvage_cpio(&mut src, &SalvagePolicy::default()).unwrap();
            assert!(outcome.entries.is_empty() && outcome.sightings.is_empty());
            check_scan_is_linear(src.bytes_read(), LEN as u64)
                .unwrap_or_else(|e| panic!("{magic:?}: {e}"));
        }
    }

    /// [`long_names_and_symlink_targets_spend_a_bounded_budget`]'s units:
    /// a `newc` header every 128 bytes, 1 MiB of them.
    fn long_name_units(mode: u32, filesize: u32, namesize: u32, nul_at: Option<usize>) -> Vec<u8> {
        const LEN: usize = 1024 * 1024;
        let fields = [1, mode, 0, 0, 1, 0, filesize, 0, 0, 0, 0, namesize, 0];
        let mut unit = NEWC_MAGIC.to_vec();
        for field in fields {
            unit.extend_from_slice(format!("{field:08X}").as_bytes());
        }
        if mode == 0o120_777 {
            unit.extend_from_slice(b"a\0");
        }
        unit.resize(128, b'B');
        if let Some(at) = nul_at {
            unit[at] = 0;
        }
        unit.iter().copied().cycle().take(LEN).collect()
    }

    /// 0.10.4: `odc` and `newc-crc` entries alternating through 1 MiB, after
    /// one healthy `newc` entry when `mixed` — two variant groups, every
    /// header a sighting.
    fn dense_variants(mixed: bool) -> Vec<u8> {
        let mut bytes = if mixed {
            files(&[("ok.txt", b"fine")])
        } else {
            Vec::new()
        };
        let mut i = 0;
        while bytes.len() < 1 << 20 {
            let name = format!("v{i}.txt");
            if i % 2 == 0 {
                bytes.extend_from_slice(&odc_entry(&name, b"data"));
            } else {
                let mut field = name.into_bytes();
                field.push(0);
                bytes.extend_from_slice(&newc_entry_raw(CRC_MAGIC, &field, b"data"));
            }
            i += 1;
        }
        bytes
    }

    /// 0.10.4: on a dense hostile input the scan stores at most
    /// `SightingLog::DEFAULT_CAP` sightings per group, in ascending offset
    /// order, and they still stand for every one it saw — the counts
    /// and the offsets the printed sentence lists are those of the uncapped
    /// list before the cap (pinned from 7244937, where every one was stored).
    #[test]
    fn dense_sightings_are_bounded_and_the_sentence_is_unchanged() {
        use stuffr_core::salvage::describe_sightings;
        use stuffr_core::testing::check_sightings_bounded;
        let legs: [(&str, Vec<u8>, u64, &[&str]); 4] = [
            (
                "variants",
                dense_variants(true),
                9803,
                &[
                    "4902 cpio",
                    "at offset(s) 248, 459, 670, 881, 1092, 1303, 1515, 1727, and 4894 more",
                    "4901 cpio",
                    "at offset(s) 335, 546, 757, 968, 1179, 1391, 1603, 1815, and 4893 more",
                ][..],
            ),
            (
                "refused names",
                long_name_units(0o100_644, 0, 0xFFFF, None),
                7648,
                &[
                    "7648 cpio",
                    "at offset(s) 4096, 4224, 4352, 4480, 4608, 4736, 4864, 4992, and 7640 more",
                ][..],
            ),
            (
                "accepted names",
                long_name_units(0o100_644, 0, 65_419, Some(120)),
                7649,
                &[
                    "7649 cpio",
                    "at offset(s) 4096, 4224, 4352, 4480, 4608, 4736, 4864, 4992, and 7641 more",
                ][..],
            ),
            (
                "symlink targets",
                long_name_units(0o120_777, 0xFFFF, 2, None),
                7648,
                &[
                    "7648 cpio",
                    "at offset(s) 4096, 4224, 4352, 4480, 4608, 4736, 4864, 4992, and 7640 more",
                ][..],
            ),
        ];
        for (label, bytes, total, listed) in legs {
            let out = salvage_cpio(&mut Cursor::new(bytes), &SalvagePolicy::default()).unwrap();
            check_sightings_bounded(&out.sightings, total)
                .unwrap_or_else(|e| panic!("{label}: {e}"));
            let note = describe_sightings(&out.sightings).unwrap();
            for fragment in listed {
                assert!(
                    note.contains(fragment),
                    "{label}: {fragment:?} missing: {note}"
                );
            }
        }
        // And the exit-3 refusal still counts every variant header.
        let err = salvage_cpio(
            &mut Cursor::new(dense_variants(false)),
            &SalvagePolicy::default(),
        )
        .unwrap_err();
        for count in [
            "4903 header(s) in the odc variant",
            "4903 header(s) in the newc-crc variant",
        ] {
            assert!(err.to_string().contains(count), "{count:?} missing: {err}");
        }
    }

    /// 0.10.3 Task 4b: `newc` headers one every 128 bytes, 1 MiB of them,
    /// each making its verdict read about 64 KiB — and each resuming the
    /// scan one byte on. Three siblings: names that are refused once read
    /// (no NUL at their end), names that are accepted (so `verify` met them
    /// too, and used to read each a second time), and symlinks whose kind
    /// needs a 65,535-byte target read. Before the scan-wide budget these
    /// read 482x, 961x and 483x their input. The budget's refusals are
    /// reported as verdict-bounded sightings.
    #[test]
    fn long_names_and_symlink_targets_spend_a_bounded_budget() {
        use stuffr_core::salvage::SightingKind;
        use stuffr_core::testing::{CountingSource, check_scan_is_linear};
        let fill = long_name_units;
        // A 65,419-byte name ends on byte 120 of a later unit: 110 + 65,419
        // - 1 is 120 more than a multiple of 128.
        let shapes = [
            ("refused names", fill(0o100_644, 0, 0xFFFF, None), false),
            (
                "accepted names",
                fill(0o100_644, 0, 65_419, Some(120)),
                true,
            ),
            ("symlink targets", fill(0o120_777, 0xFFFF, 2, None), true),
        ];
        for (shape, bytes, accepted) in shapes {
            let mut src = CountingSource::new(Cursor::new(bytes.clone()));
            let out = salvage_cpio(&mut src, &SalvagePolicy::default()).unwrap();
            check_scan_is_linear(src.bytes_read(), bytes.len() as u64)
                .unwrap_or_else(|e| panic!("{shape}: {e}"));
            assert_eq!(!out.entries.is_empty(), accepted, "{shape}");
            assert!(
                !out.sightings.is_empty()
                    && out
                        .sightings
                        .iter()
                        .all(|s| s.kind == SightingKind::VerdictBounded
                            && s.shape == VERDICT_BUDGET_SHAPE),
                "{shape}: {:?}",
                out.sightings.first()
            );
        }
    }

    /// Task 4b's other half: a legitimate archive whose every entry carries
    /// the longest name the gate allows, and a symlink target as long as
    /// `cpio.rs` reads, pays for each once in the scan and once more when
    /// the header before it corroborates its size — and never comes near
    /// the budget: every entry recovered, no sighting.
    #[test]
    fn an_archive_of_maximum_names_and_targets_spends_no_budget_sighting() {
        let mut bytes = Vec::new();
        for i in 0..20u8 {
            let mut name = "n".repeat(65_534);
            name.replace_range(..1, &char::from(b'a' + i).to_string());
            bytes.extend_from_slice(&newc_entry(&name, b"payload"));
            let mut link =
                newc_entry_raw(NEWC_MAGIC, format!("l{i}\0").as_bytes(), &[b't'; 65_536]);
            // `c_mode` is the second field: a symlink's.
            link[MAGIC_LEN + NEWC_FIELD_LEN..MAGIC_LEN + 2 * NEWC_FIELD_LEN]
                .copy_from_slice(format!("{:08X}", 0o120_777).as_bytes());
            bytes.extend_from_slice(&link);
        }
        bytes.extend_from_slice(&newc_entry(TRAILER_NAME, b""));
        let out = scan(&bytes);
        assert_eq!(out.entries.len(), 40);
        assert!(
            out.entries
                .iter()
                .all(|e| e.status == SalvageStatus::Unattested),
            "{:?}",
            out.entries.iter().map(|e| &e.status).collect::<Vec<_>>()
        );
        assert!(out.entries.iter().skip(1).step_by(2).all(
            |e| matches!(&e.meta.kind, EntryKind::Symlink { target } if target.len() == 65_536)
        ));
        assert!(out.sightings.is_empty(), "{:?}", out.sightings.first());
    }

    #[test]
    fn the_memo_answers_like_a_fresh_scan() {
        // Two shapes, each salvaged once: the results must equal the pre-memo
        // answers pinned here. (a) a run that reaches EOF (writer padding: the
        // jump IS taken); (b) a run ending in a non-zero byte (the jump is NOT
        // taken), with every landing point inside one already-known run.
        let mut eof_padded = newc_header_only("a", 4);
        eof_padded.extend_from_slice(b"abcd");
        eof_padded.extend_from_slice(&newc_header_only("TRAILER!!!", 0));
        eof_padded.resize(eof_padded.len() + 4096, 0);
        let a = salvage_cpio(&mut Cursor::new(eof_padded), &SalvagePolicy::default()).unwrap();
        let names: Vec<_> = a.entries.iter().map(|e| e.meta.name.as_str()).collect();
        assert_eq!(names, ["a"]);

        let data = dense_headers_into_a_zero_run();
        let b = salvage_cpio(&mut Cursor::new(data.clone()), &SalvagePolicy::default()).unwrap();
        assert_eq!(b.entries.len(), 2_000);
        assert!(
            b.entries
                .iter()
                .enumerate()
                .all(|(i, e)| e.meta.name == format!("f{i}"))
        );
    }

    /// Headers landing alternately in `k` distinct zero runs, each ending in
    /// a non-zero byte. A one-record memo evicted the other run's record on
    /// every landing: quadratic. (Review of 0.10.3 Task 2.)
    fn alternating_zero_runs(headers: usize, k: usize, run: usize) -> Vec<u8> {
        let header_bytes: usize = (0..headers)
            .map(|i| newc_header_only(&format!("f{i}"), 0).len())
            .sum();
        let run_start = |r: usize| header_bytes + r * (run + 4);
        let mut out = Vec::new();
        for i in 0..headers {
            let h = newc_header_only(&format!("f{i}"), 0);
            let payload_start = out.len() + h.len();
            let landing = run_start(i % k) + 4 * (i / k + 1);
            out.extend_from_slice(&newc_header_only(
                &format!("f{i}"),
                (landing - payload_start) as u32,
            ));
        }
        for _ in 0..k {
            out.resize(out.len() + run, 0);
            out.extend_from_slice(&[1, 1, 1, 1]);
        }
        out
    }

    fn assert_scans_linearly_with(data: Vec<u8>, headers: usize) {
        use stuffr_core::testing::{CountingSource, check_scan_is_linear};
        let len = data.len() as u64;
        let mut src = CountingSource::new(Cursor::new(data));
        let outcome = salvage_cpio(&mut src, &SalvagePolicy::default()).unwrap();
        assert_eq!(outcome.entries.len(), headers);
        check_scan_is_linear(src.bytes_read(), len).unwrap();
    }

    #[test]
    fn headers_alternating_between_two_zero_runs_scan_linearly() {
        assert_scans_linearly_with(alternating_zero_runs(2_000, 2, 450 * 1024), 2_000);
    }

    #[test]
    fn headers_alternating_between_three_zero_runs_scan_linearly() {
        assert_scans_linearly_with(alternating_zero_runs(2_000, 3, 300 * 1024), 2_000);
    }

    /// Landings that DESCEND through one run: each lands before the run
    /// already known, so the scan must stop at the known start, adopt it and
    /// merge.
    #[test]
    fn descending_landings_in_one_zero_run_scan_linearly() {
        let headers = 2_000usize;
        let run = 900 * 1024usize;
        let header_bytes: usize = (0..headers)
            .map(|i| newc_header_only(&format!("f{i}"), 0).len())
            .sum();
        let mut out = Vec::new();
        for i in 0..headers {
            let h = newc_header_only(&format!("f{i}"), 0);
            let payload_start = out.len() + h.len();
            let landing = header_bytes + run - 4 * (i + 1);
            out.extend_from_slice(&newc_header_only(
                &format!("f{i}"),
                (landing - payload_start) as u32,
            ));
        }
        out.resize(header_bytes + run, 0);
        out.push(1);
        assert_scans_linearly_with(out, headers);
    }

    /// `count` headers whose sizes land them `landing(i)` bytes into
    /// `region`, which follows the headers.
    fn headers_landing_in(
        count: usize,
        region: &[u8],
        landing: impl Fn(usize) -> usize,
    ) -> Vec<u8> {
        let header_bytes: usize = (0..count)
            .map(|i| newc_header_only(&format!("f{i}"), 0).len())
            .sum();
        let mut out = Vec::new();
        for i in 0..count {
            let h = newc_header_only(&format!("f{i}"), 0);
            let payload_start = out.len() + h.len();
            let at = header_bytes + landing(i);
            out.extend_from_slice(&newc_header_only(
                &format!("f{i}"),
                (at - payload_start) as u32,
            ));
        }
        out.extend_from_slice(region);
        out
    }

    /// Every landing on a non-zero byte: a fixed 4 KiB read per landing that
    /// recorded nothing, repeated 2,000 times (review round 2).
    #[test]
    fn landings_on_non_zero_bytes_scan_linearly() {
        let region = vec![1u8; 4 * 2_001];
        assert_scans_linearly_with(headers_landing_in(2_000, &region, |i| 4 * i), 2_000);
    }

    /// Every landing in its own 4-byte zero run (`0000 1111` repeated).
    #[test]
    fn landings_in_their_own_short_zero_runs_scan_linearly() {
        let region: Vec<u8> = (0..2_001).flat_map(|_| [0, 0, 0, 0, 1, 1, 1, 1]).collect();
        assert_scans_linearly_with(headers_landing_in(2_000, &region, |i| 8 * i), 2_000);
    }

    /// The memo's answer equals a fresh all-zero check, and its records stay
    /// disjoint and truthful, over random buffers and landing orders. Fixed
    /// seed.
    #[test]
    fn the_memo_matches_a_fresh_zero_check_on_random_buffers() {
        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut rnd = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..1_500 {
            let len = if rnd() % 4 == 0 {
                (rnd() % 20_000 + 1) as usize
            } else {
                (rnd() % 200 + 1) as usize
            };
            let mut buf = vec![0u8; len];
            for _ in 0..rnd() % 4 {
                let p = (rnd() as usize) % len;
                buf[p] = 1 + (rnd() % 255) as u8;
            }
            let mut memo = KnownZeros::new();
            let mut src = Cursor::new(buf.clone());
            for _ in 0..30 {
                let from = rnd() % len as u64;
                let fresh = buf[from as usize..].iter().all(|&b| b == 0);
                assert_eq!(
                    zeros_to_eof(&mut src, from, len as u64, &mut memo),
                    fresh,
                    "buf={buf:?} from={from} memo={memo:?}"
                );
                let mut prev_end: Option<u64> = None;
                for (&start, &(end, to_eof)) in &memo {
                    assert!(
                        start < end && prev_end.is_none_or(|p| start > p),
                        "{memo:?}"
                    );
                    assert!(buf[start as usize..end as usize].iter().all(|&b| b == 0));
                    if to_eof {
                        assert_eq!(end, len as u64);
                    } else {
                        assert_ne!(buf[end as usize], 0);
                    }
                    prev_end = Some(end);
                }
            }
        }
    }

    // -------------------------------------------------------------------
    // Reference writers — the independent witness
    // -------------------------------------------------------------------

    fn which(bin: &str) -> Option<std::path::PathBuf> {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path).find_map(|dir| {
            let candidate = dir.join(bin);
            candidate.is_file().then_some(candidate)
        })
    }

    /// Runs `cpio -o -H <format>` over `names` in `dir`, or `None` when that
    /// writer does not offer the format.
    fn reference_archive(cpio: &Path, dir: &Path, names: &[&str], format: &str) -> Option<Vec<u8>> {
        let mut child = std::process::Command::new(cpio)
            .args(["-o", "-H", format])
            .current_dir(dir)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn cpio");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(names.join("\n").as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        out.status.success().then_some(out.stdout)
    }

    /// What `cpio` itself writes — bsdcpio (libarchive) here, GNU cpio on
    /// the CI runner, and GNU cpio's keg-only install when it is present —
    /// is recovered whole, name for name and byte for byte, each entry
    /// `Unattested`; and the same writer's `odc` (and, where offered, `crc`)
    /// output is exit 3 naming the variant. None of these writers shares a
    /// line with the `cpio` crate. The system `cpio` is REQUIRED (CI
    /// installs it); a silent skip would prove nothing.
    #[test]
    fn every_reference_writer_s_archive_is_recovered_whole() {
        let tree = tempfile_dir("tree");
        let long = format!("dir/{}.txt", "l".repeat(150));
        std::fs::create_dir_all(tree.0.join("dir")).unwrap();
        let contents: [(&str, &[u8]); 3] = [
            ("a.txt", b"alpha\n"),
            ("dir/b.bin", b"\x00\xff\x00\x07"),
            (&long, b"long name\n"),
        ];
        for (name, data) in contents {
            std::fs::write(tree.0.join(name), data).unwrap();
        }
        let names: Vec<&str> = contents.iter().map(|(n, _)| *n).collect();

        let system = which("cpio").unwrap_or_else(|| {
            panic!("no reference `cpio` on PATH — this test proved nothing, which is worth knowing")
        });
        let mut writers = vec![system];
        let gnu = std::path::PathBuf::from("/opt/homebrew/opt/cpio/bin/cpio");
        if gnu.is_file() {
            writers.push(gnu);
        }
        for writer in &writers {
            let bytes = reference_archive(writer, &tree.0, &names, "newc")
                .unwrap_or_else(|| panic!("{} cannot write newc", writer.display()));
            let out = scan(&bytes);
            let written = write_back(&bytes, &out);
            assert_eq!(
                out.entries
                    .iter()
                    .zip(&written)
                    .map(|(e, (data, done))| (
                        e.meta.name.as_str(),
                        e.status,
                        data.as_slice(),
                        *done
                    ))
                    .collect::<Vec<_>>(),
                contents
                    .iter()
                    .map(|(name, data)| (*name, SalvageStatus::Unattested, *data, true))
                    .collect::<Vec<_>>(),
                "{}",
                writer.display()
            );
            for (format, variant) in [("odc", "070707"), ("crc", "070702")] {
                // bsdcpio offers no `crc`; skipping a format a writer lacks
                // is not skipping the writer.
                let Some(bytes) = reference_archive(writer, &tree.0, &names, format) else {
                    continue;
                };
                let err = salvage_cpio(&mut Cursor::new(bytes), &SalvagePolicy::default())
                    .expect_err("a variant archive is a sighting");
                assert_eq!(err.exit_code(), 3, "{}: {err}", writer.display());
                assert!(err.to_string().contains(variant), "{err}");
            }
        }
    }

    struct TempDir(std::path::PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tempfile_dir(tag: &str) -> TempDir {
        let dir = std::env::temp_dir().join(format!(
            "stuffr-cpio-salvage-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    // -------------------------------------------------------------------
    // Salvage Stage 3 Task 6: the damage catalogue.
    //
    // **Every expectation here is the PRE-DAMAGE state, and none of it
    // comes from this scanner.** [`inputs`] is written to disk, a REAL
    // `cpio -o -H newc` archives it, and what each mutation must produce is
    // derived from those input files plus the record geometry [`members`]
    // parses longhand out of the writer's bytes — never from what
    // `salvage_cpio` currently returns. The writers are the platform `cpio`
    // (bsdcpio here, GNU on the CI runner) and, on macOS, GNU cpio's
    // keg-only install. Both are REQUIRED: macOS's and Linux's `cpio` are
    // different programs, and a catalogue that ran over one alone would
    // repeat the 0.2.0 gap `reference-tools.md` records.
    // -------------------------------------------------------------------
    mod damage_catalogue {
        use std::path::PathBuf;

        use super::*;

        /// The files every writer is fed: THE pre-damage state. Each payload
        /// is at least 1,500 bytes — **large on purpose**: a flip at a
        /// payload's middle is then ~750 bytes from the nearest header, so
        /// it cannot land inside one (a `newc` header is 110 bytes plus the
        /// name, and on tiny payloads "mid-payload" and "in the next
        /// header" are a few bytes apart). None contains `070701`.
        fn inputs() -> Vec<(&'static str, Vec<u8>)> {
            vec![
                (
                    "alpha.txt",
                    (0..200)
                        .flat_map(|i| format!("alpha line {i}\n").into_bytes())
                        .collect(),
                ),
                (
                    "beta.txt",
                    (0..301)
                        .flat_map(|i| format!("beta {i};").into_bytes())
                        .collect(),
                ),
                (
                    "gamma.bin",
                    (0..1500u32).map(|i| ((i * 7 + 3) % 256) as u8).collect(),
                ),
                (
                    "delta.txt",
                    (0..151)
                        .flat_map(|i| format!("delta row {i}\n").into_bytes())
                        .collect(),
                ),
            ]
        }

        /// GNU cpio's keg-only Homebrew install — see `reference-tools.md`.
        const GNU_CPIO_ON_MACOS: &str = "/opt/homebrew/opt/cpio/bin/cpio";

        /// The writers: the platform `cpio`, plus GNU cpio on macOS, where
        /// the platform's is bsdcpio. On Linux the platform `cpio` IS GNU's.
        fn writers() -> Vec<PathBuf> {
            let mut out = vec![which("cpio").unwrap_or_else(|| {
                panic!("no reference `cpio` on PATH — this catalogue proved nothing")
            })];
            if cfg!(target_os = "macos") {
                let gnu = PathBuf::from(GNU_CPIO_ON_MACOS);
                assert!(
                    gnu.is_file(),
                    "GNU cpio not at {GNU_CPIO_ON_MACOS} (`brew install cpio`) — without it \
                     this catalogue covers bsdcpio alone, and CI runs GNU's"
                );
                out.push(gnu);
            }
            out
        }

        /// Every writer's `newc` archive of [`inputs`]: `(label, bytes)`.
        fn reference_archives(tag: &str) -> Vec<(String, Vec<u8>)> {
            let tree = tempfile_dir(&format!("catalogue-{tag}"));
            for (name, data) in inputs() {
                std::fs::write(tree.0.join(name), data).unwrap();
            }
            let names: Vec<&str> = inputs().iter().map(|(n, _)| *n).collect();
            writers()
                .into_iter()
                .map(|writer| {
                    let bytes = reference_archive(&writer, &tree.0, &names, "newc")
                        .unwrap_or_else(|| panic!("{} cannot write newc", writer.display()));
                    (writer.display().to_string(), bytes)
                })
                .collect()
        }

        /// One entry's geometry, read by THIS TEST from the raw bytes.
        struct Member {
            name: String,
            header: usize,
            payload: std::ops::Range<usize>,
        }

        fn round4(n: usize) -> usize {
            n.div_ceil(4) * 4
        }

        /// Walks a `newc` archive by its published layout — `070701`,
        /// thirteen 8-digit hex fields (`c_filesize` the 7th at byte 54,
        /// `c_namesize` the 12th at byte 94), the NUL-terminated name, both
        /// name and payload padded to four — up to `TRAILER!!!`.
        /// Hand-rolled rather than read through [`gate_newc_at`], which is
        /// the code under test.
        fn members(bytes: &[u8]) -> Vec<Member> {
            let hex = |at: usize| {
                usize::from_str_radix(std::str::from_utf8(&bytes[at..at + 8]).unwrap(), 16).unwrap()
            };
            let mut out = Vec::new();
            let mut at = 0usize;
            loop {
                assert_eq!(&bytes[at..at + 6], b"070701", "a newc header at {at}");
                let namesize = hex(at + 94);
                let filesize = hex(at + 54);
                let name =
                    String::from_utf8(bytes[at + 110..at + 110 + namesize - 1].to_vec()).unwrap();
                if name == "TRAILER!!!" {
                    return out;
                }
                let start = round4(at + 110 + namesize);
                out.push(Member {
                    name,
                    header: at,
                    payload: start..start + filesize,
                });
                at = round4(start + filesize);
            }
        }

        /// The platform cpio's own extraction of `name` from `bytes`, and
        /// whether it exited 0.
        fn platform_extract(bytes: &[u8], name: &str) -> (bool, Vec<u8>) {
            let dir = tempfile_dir("catalogue-extract");
            let mut child = std::process::Command::new(&writers()[0])
                .arg("-i")
                .arg(name)
                .current_dir(&dir.0)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(bytes).unwrap();
            let status = child.wait().unwrap();
            (
                status.success(),
                std::fs::read(dir.0.join(name)).unwrap_or_default(),
            )
        }

        fn rows(out: &SalvageOutcome) -> Vec<(&str, SalvageStatus)> {
            out.entries
                .iter()
                .map(|e| (e.meta.name.as_str(), e.status))
                .collect()
        }

        fn all_unattested(want: &[(&'static str, Vec<u8>)]) -> Vec<(&'static str, SalvageStatus)> {
            want.iter()
                .map(|(n, _)| (*n, SalvageStatus::Unattested))
                .collect()
        }

        // ---------------------------------------------------------------
        // Step 1: the agreement property.
        // ---------------------------------------------------------------

        /// **Salvage of an UNDAMAGED archive agrees exactly with the
        /// ordinary reader AND with the files that went in** — names, sizes
        /// and kinds as `list` reports them, bytes as the input files hold
        /// them, every entry `Unattested` (never `Complete`, never `Intact`),
        /// no sighting.
        #[test]
        fn salvage_of_every_writer_s_healthy_archive_agrees_with_the_reader_and_the_inputs() {
            let want = inputs();
            for (writer, bytes) in reference_archives("agree") {
                let reader = read_through_the_reader(&bytes)
                    .unwrap_or_else(|e| panic!("{writer}: the ordinary reader must walk it: {e}"));
                let out = scan(&bytes);
                assert!(out.sightings.is_empty(), "{writer}: {:?}", out.sightings);
                assert_eq!(
                    out.entries
                        .iter()
                        .map(|e| (e.meta.name.clone(), e.meta.size, e.meta.kind.clone()))
                        .collect::<Vec<_>>(),
                    reader
                        .iter()
                        .map(|(n, s, k, _)| (n.clone(), Some(*s), k.clone()))
                        .collect::<Vec<_>>(),
                    "{writer}: salvage and the ordinary reader must describe every entry alike"
                );
                assert_eq!(
                    members(&bytes)
                        .iter()
                        .map(|m| m.name.as_str())
                        .collect::<Vec<_>>(),
                    want.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
                    "{writer}: sanity, this test's own geometry finds the inputs in order"
                );
                assert_eq!(rows(&out), all_unattested(&want), "{writer}");
                let written = write_back(&bytes, &out);
                for (i, (name, data)) in want.iter().enumerate() {
                    assert_eq!(&reader[i].3, data, "{writer}: the reader's {name}");
                    assert_eq!(&written[i], &(data.clone(), true), "{writer}: {name}");
                }
            }
        }

        // ---------------------------------------------------------------
        // Step 2: the mutation catalogue.
        // ---------------------------------------------------------------

        /// Row 1/3 — **a truncated tail.** Cut inside the LAST entry's
        /// payload (which takes the trailer with it): every earlier entry
        /// `Unattested` with exactly its input bytes, the cut one `Partial`
        /// with exactly the input's surviving prefix.
        #[test]
        fn damage_catalogue_a_truncated_tail() {
            let want = inputs();
            let last = want.len() - 1;
            for (writer, bytes) in reference_archives("tail") {
                let payload = members(&bytes)[last].payload.clone();
                for keep in [0, 1, payload.len() / 2, payload.len() - 1] {
                    let cut = &bytes[..payload.start + keep];
                    let out = scan(cut);
                    let mut expected = all_unattested(&want);
                    expected[last].1 = SalvageStatus::Partial;
                    assert_eq!(rows(&out), expected, "{writer} keep={keep}");
                    let written = write_back(cut, &out);
                    for (i, (name, data)) in want.iter().enumerate().take(last) {
                        assert_eq!(&written[i], &(data.clone(), true), "{writer} {name}");
                    }
                    assert_eq!(
                        written[last],
                        (want[last].1[..keep].to_vec(), false),
                        "{writer} keep={keep}: exactly the surviving prefix"
                    );
                }
            }
        }

        /// Row 2/3 — **a byte flipped mid-payload. The stage's point.**
        /// `newc` checksums nothing, so the damaged entry is a SILENTLY
        /// WRONG FILE. The tier must not claim otherwise: `Unattested`,
        /// never `Intact` (and never `Complete`, which would claim a header
        /// check `newc` lacks) — and the bytes written are asserted to
        /// DIFFER from the input in exactly the flipped byte. The platform
        /// `cpio` extracts the same wrong bytes at exit 0. Every entry takes
        /// its turn; the flip is asserted to sit hundreds of bytes inside
        /// its payload, nowhere near a header.
        #[test]
        fn damage_catalogue_a_byte_flipped_mid_payload() {
            let want = inputs();
            for (writer, bytes) in reference_archives("flip") {
                let geometry = members(&bytes);
                for (damaged, target) in geometry.iter().enumerate() {
                    let mid = target.payload.len() / 2;
                    assert!(
                        mid >= 500 && target.payload.len() - mid >= 500,
                        "the flip must be unambiguously mid-payload"
                    );
                    let mut flipped = bytes.clone();
                    flipped[target.payload.start + mid] ^= 0xFF;

                    let out = scan(&flipped);
                    assert_eq!(
                        rows(&out),
                        all_unattested(&want),
                        "{writer} damaged={damaged}"
                    );
                    assert!(out.sightings.is_empty(), "{writer}: {:?}", out.sightings);
                    let written = write_back(&flipped, &out);
                    let mut wrong = want[damaged].1.clone();
                    wrong[mid] ^= 0xFF;
                    assert_ne!(
                        written[damaged].0, want[damaged].1,
                        "{writer}: silently wrong"
                    );
                    assert_eq!(
                        written[damaged],
                        (wrong.clone(), true),
                        "{writer}: wrong in exactly the flipped byte and no other"
                    );
                    for (i, (name, data)) in want.iter().enumerate() {
                        if i != damaged {
                            assert_eq!(&written[i], &(data.clone(), true), "{writer}: {name}");
                        }
                    }
                    assert_eq!(
                        platform_extract(&flipped, want[damaged].0),
                        (true, wrong),
                        "{writer}: the platform cpio extracts the same wrong bytes at exit 0"
                    );
                }
            }
        }

        /// Row 3/3 — **a header field corrupted.** That entry is absent;
        /// every other entry is `Unattested` with exactly its input bytes.
        /// Three fields against every entry in turn (the first included):
        /// (a) the MAGIC's last digit, (b) a `c_mode` digit made non-hex,
        /// (c) a `c_filesize` digit made non-hex — the last leaves nothing
        /// to say where its payload ends, so that payload is scanned
        /// through. The entry BEFORE the damage is the subtle one: its size
        /// is no longer corroborated by the header it lands on, so its jump
        /// is not taken — and it must still come back whole.
        #[test]
        fn damage_catalogue_a_corrupted_header_field() {
            let want = inputs();
            for (writer, bytes) in reference_archives("header") {
                for (damaged, target) in members(&bytes).iter().enumerate() {
                    let h = target.header;
                    for (field, at) in
                        [("magic", h + 5), ("c_mode", h + 14), ("c_filesize", h + 61)]
                    {
                        let mut bad = bytes.clone();
                        bad[at] = b'x';
                        assert!(
                            read_through_the_reader(&bad).is_err(),
                            "{writer} {field}: sanity, the ordinary reader must refuse it"
                        );
                        let out = scan(&bad);
                        let survivors: Vec<_> = all_unattested(&want)
                            .into_iter()
                            .enumerate()
                            .filter(|(i, _)| *i != damaged)
                            .map(|(_, row)| row)
                            .collect();
                        assert_eq!(
                            rows(&out),
                            survivors,
                            "{writer} damaged={damaged} {field}: that entry absent, its \
                             neighbours unaffected"
                        );
                        assert!(out.sightings.is_empty(), "{writer}: {:?}", out.sightings);
                        let written = write_back(&bad, &out);
                        for (entry, got) in out.entries.iter().zip(&written) {
                            let name = &entry.meta.name;
                            let data = &want.iter().find(|(n, _)| n == name).unwrap().1;
                            assert_eq!(got, &(data.clone(), true), "{writer} {field}: {name}");
                        }
                    }
                }
            }
        }

        /// The header field that is NOT absent-or-refused: a `c_filesize`
        /// that still PARSES but lies (grown by 0x100). Nothing in `newc`
        /// can tell, so the entry is reported over what its header claims —
        /// `Unattested`, never a tier that vouches for it — and its written
        /// bytes are WRONG (they run into the next header). What must hold
        /// is that the lie costs no neighbour: the jump it asks for lands on
        /// no header, so it is not taken, and the entry behind it is found.
        #[test]
        fn damage_catalogue_a_size_that_lies_costs_no_neighbour() {
            let want = inputs();
            for (writer, bytes) in reference_archives("lying-size") {
                let geometry = members(&bytes);
                for (damaged, target) in geometry.iter().enumerate().take(geometry.len() - 1) {
                    let h = target.header;
                    let mut bad = bytes.clone();
                    let lie = target.payload.len() + 0x100;
                    bad[h + 54..h + 62].copy_from_slice(format!("{lie:08X}").as_bytes());

                    let out = scan(&bad);
                    assert_eq!(
                        rows(&out),
                        all_unattested(&want),
                        "{writer} damaged={damaged}"
                    );
                    let written = write_back(&bad, &out);
                    assert_ne!(
                        written[damaged].0, want[damaged].1,
                        "{writer}: the lying entry's bytes are wrong, and its tier never said \
                         otherwise"
                    );
                    for (i, (name, data)) in want.iter().enumerate() {
                        if i != damaged {
                            assert_eq!(&written[i], &(data.clone(), true), "{writer}: {name}");
                        }
                    }
                }
            }
        }
    }
}
