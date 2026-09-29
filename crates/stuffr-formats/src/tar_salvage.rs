//! tar salvage scan: recovers entries by testing every byte offset for a
//! header block whose checksum agrees with itself, rather than walking
//! forward from the first header the way `tar::Archive` does.
//!
//! `tar.rs` is a correct, honest reader for an INTACT archive, and the way it
//! reaches entry N is by having parsed entries 1..N-1: tar has no index, no
//! entry count and no trailer beyond two zero blocks, so one header whose
//! checksum disagrees ends the archive (`archive header checksum mismatch`,
//! exit 5) for every entry BEHIND it. That is the damage this module is for.
//! It is the sixth scanner built on the shared [`stuffr_core::salvage`]
//! machinery, and the first of Salvage Stage 3's three checksumless
//! containers.
//!
//! # tar is `Complete`, never `Intact`, and that is the whole point
//!
//! tar is the one format of Stage 3's three whose header SELF-VERIFIES: each
//! 512-byte header block carries a checksum over itself. It carries nothing
//! at all over the payload. So an entry that clears the gate below and has
//! every declared byte present is [`SalvageStatus::Complete`] — "every
//! declared byte was present and the header self-verified" — and **never
//! [`SalvageStatus::Intact`]**, which would claim a content checksum tar does
//! not have. [`stuffr_core::testing::check_salvage_claim`] holds that line:
//! tar's class is `Attestation::HeaderChecksumOnly`, and `Complete` is the
//! one claim-bearing tier that class may reach, and only with the header
//! checksum actually checked. [`TarSalvage::verify`] overrides the trait's
//! default (which answers `Unattested`) for exactly that reason, and checks
//! the header a second time itself rather than standing on discovery's word.
//!
//! What `Complete` does NOT tell you, stated because it is the tier's whole
//! weakness: **a payload byte flipped after writing is invisible.** The
//! header still checks out and every declared byte is still present, so the
//! damaged entry is reported `Complete`, at exit 0, exactly as `tar` itself,
//! `bsdtar` and `tarfile` would extract it. Nothing in the format can say
//! otherwise.
//!
//! # Where this module's layout comes from (Ruling F)
//!
//! Almost nowhere in this file — and that is deliberate. Every field except
//! one is read through `tar::Header`, **the same parser `tar.rs`'s ordinary
//! reader uses**, so `stuffr list` and `stuffr salvage --list` decode a
//! header's name, size, mode, mtime and typeflag identically by
//! construction: octal and GNU base-256 numbers, the ustar `prefix` join,
//! the GNU/ustar magic test. The name→kind table is `tar.rs`'s own
//! [`crate::tar::entry_kind`] and the mtime is `tar.rs`'s own
//! [`crate::tar::header_mtime`], reached rather than restated.
//!
//! The one field this module locates for itself is the checksum, because
//! the gate must be falsifiable from inside this crate and `tar` computes it
//! in a private method. Its position and its rule, cited:
//!
//! | what | value | source |
//! |---|---|---|
//! | block size | 512 | `tar.rs`'s [`crate::tar::BLOCK`]; `tar` 0.4.46 `archive.rs` `BLOCK_SIZE` |
//! | checksum field | bytes `148..156` | `tar` 0.4.46 `header.rs:55-67` (`OldHeader`: name 100, mode 8, uid 8, gid 8, size 12, mtime 12, then `cksum: [u8; 8]`) |
//! | magic and version | bytes `257..265` | `tar.rs`'s `TAR_MAGIC` (`ustar` at 257); `tar` 0.4.46 `header.rs:71-84` (`UstarHeader`: the 257 bytes above, then `magic: [u8; 6]`, `version: [u8; 2]`) and `:201-209` (`is_ustar`, `is_gnu`) |
//! | checksum rule | unsigned sum of all 512 bytes, the checksum field counted as eight spaces | `tar` 0.4.46 `archive.rs:316-325`; POSIX.1-1988 ustar, `chksum` |
//! | recorded value | the field up to its first NUL, trimmed, read as octal, truncated to `u32` | `tar` 0.4.46 `header.rs:733-742` (`cksum`) and `:1475-1490` (`octal_from`) |
//! | payload position | the block after the header; the next header after the payload rounded up to 512 | `tar` 0.4.46 `archive.rs:348-363` |
//! | extensions | GNU `L`/`K` and pax `x` describe the NEXT header, and are consumed only when the header carries GNU or ustar magic, at most one of each | `tar` 0.4.46 `archive.rs:386-448` |
//! | precedence | name: `L`, then pax `path`, then the header; link: `K`, then pax `linkpath`, then the header; span: pax `size`, then the header | `tar` 0.4.46 `entry.rs:308-365`, `archive.rs:335-357` |
//!
//! **What that buys, and what it does not.** Reading through the reader's
//! own parser proves this scanner AGREES with `tar.rs`; it does not prove
//! either of them right. Where a test below builds its archive with this
//! project's own writer (`tar.rs`'s `create`, itself built on the `tar`
//! crate's `Builder`), it proves agreement with the crate and nothing more,
//! and says so. The independent witnesses are the reference writers
//! [`tests::every_reference_writer_s_archive_is_recovered_whole`] drives —
//! the platform's `tar` (bsdtar here, GNU on the CI runner), `gtar` and
//! Python's `tarfile`, none of which shares a line of code with the `tar`
//! crate — and the checksum rule's own definition in POSIX, which
//! [`tests::the_checksum_rule_matches_its_definition_on_a_foreign_header`]
//! applies to a header Python wrote.
//!
//! # The gate
//!
//! A block at offset `H` is a header only once ALL of these hold:
//!
//! 1. All 512 bytes are present in the source.
//! 2. **The checksum field parses and agrees with the block** — the rule in
//!    the table above, applied exactly as `tar.rs` applies it. An all-zero
//!    block (the end-of-archive marker, or padding) fails here: its field is
//!    empty, and an empty field is not a number.
//! 3. **The magic field reads `ustar`, or it is blank and the header is
//!    provably not a shifted copy**: bytes `257..262` are `ustar` (POSIX's
//!    `ustar\0` and GNU's `ustar ` both begin so); or all eight bytes of
//!    magic and version are zero, as a pre-POSIX (v7) header leaves them,
//!    AND the checksum field is spelled the way a measured writer spells it
//!    ([`spelled_like_a_writer`]), AND no block up to seven bytes earlier
//!    looks like the header this one would be a copy of
//!    ([`looks_like_a_shifted_twin`]). See the next section for why.
//! 4. The size field parses (`tar::Header::entry_size`), since without it
//!    nothing locates the payload.
//! 5. The name, after any extension, is not empty. A block of zeros whose
//!    only non-zero bytes are a checksum field reading `400` (eight spaces'
//!    worth) satisfies criterion 2 exactly and names nothing; so does a
//!    phantom, and neither is something a user could be handed.
//!
//! Any failure is not an error: it means these 512 bytes were not a header,
//! and the scan resumes **one byte later**, never one block later. One
//! failure is also COUNTED (Ruling 3-J, below): a block that clears 2, 4
//! and 5 and is refused by 3 alone.
//!
//! The checksum is the criterion with the strength against NOISE: the field
//! must hold octal text (about ten byte values in 256 each), and that text
//! must then equal a 17-bit sum. Its strength against an ADVERSARY is none —
//! anyone can write a valid header. See [`tests::CHECKSUM_ONLY_DEFECT_OFFSET`]
//! for the splice that proves the noise test can reach the gate, and the
//! task report for the run with the comparison deleted.
//!
//! # A plain sum survives a one-byte shift, which is why criterion 3 exists
//!
//! The checksum is an unsigned SUM, and a sum does not notice bytes moving.
//! Slide a header's 512-byte window one byte later and the block loses its
//! first byte (the name's first character) and gains the payload's first
//! byte; its checksum field slides one byte too, so `0005331\0` reads as
//! `005331` — the same number, since every checksum a real header records
//! is small enough to carry a leading zero. When the dropped byte and the
//! gained byte are equal, and the typeflag that slides INTO the field's
//! last position equals the leading `0` that slides out of its first — a
//! regular file, typeflag `0` — **the shifted window agrees with itself
//! exactly**: a checksum-valid header one byte later, named without its
//! first character, sized from a shifted size field, over a payload one
//! byte off.
//!
//! That is not a curiosity. It was the first thing this module's own
//! `a_destroyed_first_header_costs_that_entry_alone` test measured: an
//! archive of `a.txt` ("alpha"), `b.txt` ("beta"), `c.txt` ("gamma") with one
//! byte flipped in the first header came back as TWO entries, both named
//! `.txt`, both `Complete` — the damaged header revived one byte late with
//! a payload of `lpha` and a NUL, then `b.txt`'s own shifted twin, whose
//! payload jump then carried the scan straight past `c.txt`, which was lost.
//! The flipped byte changed the dropped byte by one and made the damaged
//! header's twin agree where the healthy one's had not; nothing about the
//! archive was unusual.
//!
//! The magic field is what a shift cannot carry: a shifted POSIX or GNU
//! header reads `star` at 257, which is neither `ustar` nor blank.
//! [`tests::SHIFTED_HEADER_OFFSET`] is the splice.
//!
//! **A v7 header has no magic to shift** — zeros before, zeros after — and
//! the first version of this criterion accepted any blank magic, so Task 2's
//! review reproduced the same phantom on a real writer: `gtar --format=v7`
//! holding `a.txt` ("1st line"), `b.txt`, `c.txt` with byte 0 flipped came
//! back as two `Complete` rows named `.txt` with shifted bytes, and `c.txt`
//! was never reported. The coincidence is as ordinary as before; with GNU's
//! NUL typeflag it needs `payload[0] == name[0] - 48`, so `a`→`1`.
//!
//! What a v7 shift DOES move is the checksum field's terminator (Ruling
//! 3-J). Every measured writer ends its digits at index 6 or 7
//! ([`spelled_like_a_writer`]'s table, measured on bsdtar 3.5.3, GNU tar
//! 1.35, macOS `pax`, Python `tarfile` and the `tar` crate); a copy seen `k`
//! bytes late has that terminator at `6 - k` or `7 - k`, inside the digits.
//! The one exception — `%07o\0` with a space typeflag, one byte late — is
//! closed by [`looks_like_a_shifted_twin`], which recognises the genuine
//! header seven bytes or fewer upstream. Both layers are checked
//! exhaustively over every typeflag byte, each with the other disabled, by
//! [`tests::every_writer_spelling_refuses_its_own_shifted_copy`].
//! [`tests::V7_SHIFTED_HEADER_OFFSET`] is the v7 splice.
//!
//! **What it costs** is headers this build cannot gate: a magic area
//! holding anything but `ustar` or zeros, or a v7 checksum field spelled in
//! a way no measured writer spells it. `tar.rs` reads both. The scan refuses
//! them — admitting them readmits the shifted copies — and says so:
//!
//! # A header this build cannot gate is a sighting, not an absence (Ruling 3-J)
//!
//! A block that clears criteria 2, 4 and 5 — checksum agrees, size parses,
//! name present — and is refused by criterion 3 alone, and is not
//! [`looks_like_a_shifted_twin`], is COUNTED ([`UngateableSightings`]),
//! never listed. A run that recovered nothing while counting one is
//! [`Error::Unsupported`], **exit 3**, naming the shape and saying the
//! ordinary verbs still read the archive — never "the scan found nothing
//! recoverable" at exit 5, which is a claim about the archive where the
//! truth is a claim about this build. A run that recovered something
//! reports it at its ordinary code (Ruling S-X) — and, since Task 2-N,
//! carries every sighting with its offset in
//! [`SalvageOutcome::sightings`], which the CLI prints on stderr: before
//! that, the mixed run was completely silent about a header `stuffr list`
//! reads. This is Ruling S-V's shape, and `lha_salvage.rs`'s
//! `UngateableSightings` is the template.
//!
//! Counted and never listed, because a listed candidate is one the engine
//! advances past by its declared length — which is exactly how a phantom's
//! payload jump used to carry the scan past a real header. And a twin is
//! never counted: a damaged archive whose only header is a twin's source
//! holds nothing recoverable, and says so. **One refused "twin" is**: a
//! block the twin check matched that sits on the 512-byte grid of the
//! entries the run recovered. A real copy lies 1..7 bytes off the grid its
//! source is on, so a block ON it is a genuine header the check could not
//! tell from the window before it (Task 2-N, N1) — reported, still never
//! listed. See [`looks_like_a_shifted_twin`] for the layout that does this.
//!
//! # Byte-granular, deliberately not 512-aligned
//!
//! A healthy tar keeps every header on a multiple of 512 from its own start,
//! and the scan could step a block at a time. It does not, because the
//! archive this verb exists for is not healthy: a download missing its first
//! N bytes, a tar carved out of a disk image, or one with bytes inserted
//! mid-file has lost that alignment, and a block-stepping scan finds NOTHING
//! in it. [`tests::a_tar_shifted_off_its_block_alignment_is_still_found`]
//! pins the difference. The cost is CPU (one field parse per byte offset, a
//! 512-byte sum only when the field parses), not correctness.
//!
//! # After a whole entry, the scan jumps its payload
//!
//! When a header's declared payload fits in the file, the next scan starts
//! at the next block boundary after that payload rather than inside it —
//! see [`TarSalvage`]'s `resume`. Scanning the payload would report the
//! contents of every tar STORED inside a tar as entries of the outer one:
//! their headers are real, 512-aligned and checksum-valid, and nothing in
//! the format tells an inner archive from an outer one.
//! [`tests::a_tar_stored_inside_a_tar_is_one_entry_not_its_contents`] pins
//! it.
//!
//! That trust is the engine's own ruling (`collect_candidates` advances by
//! an untruncated candidate's declared length): a header whose checksum
//! verified and whose payload fits in the file is believed about where its
//! payload ends. A TRUNCATED candidate is not believed — the engine resumes
//! one byte past it, and so does this scanner.
//!
//! **The consequence when the outer header is the damaged one** is that its
//! payload IS scanned, so an inner tar's entries are then reported. They are
//! real headers holding real bytes, and there is nothing to distinguish
//! them; they are recovered, not invented.
//!
//! # Extension headers: consumed where the reader consumes them
//!
//! A GNU long name (`L`), long link (`K`) or pax extended header (`x`) is
//! never reported as an entry of its own; it is applied to the header that
//! follows, exactly as `tar::Archive` applies it. When the chain does not
//! reach a real header — the following block fails the gate, an extension
//! repeats, or an extension's payload is truncated or over its ceiling —
//! the extension is dropped and the scan resumes one byte past it, which
//! finds the following header on its own and reports it under its own
//! header fields. That is the one place salvage can name an entry
//! differently from `list`: a name longer than 100 bytes then comes back
//! truncated to what the header block itself holds.
//!
//! The two ceilings, both on METADATA rather than on an entry, and both
//! checked before a byte is allocated for them:
//!
//! - [`MAX_LONG_NAME`] — 65,536 bytes for a GNU `L`/`K` payload, the figure
//!   `cpio.rs` bounds a name and a symlink target with (16x Linux's
//!   `PATH_MAX`);
//! - [`MAX_PAX_EXTENSION`] — 1 MiB for a pax `x` payload, which is parsed
//!   by `tar::PaxExtensions` (the reader's own parser) and so must be held
//!   whole. A pax header past it is one carrying extended attributes on that
//!   scale; the entry behind it is still recovered, under its header fields.
//!
//! The ordinary reader bounds neither (`EntryFields::read_all` grows without
//! limit), so this is a narrowing `list` does not share, and a documented
//! one.
//!
//! pax `g` (global) headers are not consumed by `tar::Archive`, which hands
//! them back as entries of kind `Other`; so does this scanner.
//!
//! # Sparse files are recognised and not written
//!
//! A GNU sparse entry (typeflag `S`) stores its data regions back to back
//! and a map of where they belong; a pax 1.0 sparse entry stores that map
//! INSIDE its payload, under an ordinary typeflag and a `GNU.sparse.*`
//! record. Writing either payload verbatim would hand back bytes that are
//! not the file. Both are therefore [`UnverifiedCause::UndecodableMethod`]
//! — listed, not written, exit 3 — with [`SPARSE`] as their codec. That is
//! stricter than `tar.rs` for pax sparse, which the `tar` crate does not
//! recognise and reads back raw.
//!
//! # The whole-entry ceiling: none of this scanner's own
//!
//! [`TarSalvage::max_whole_entry`] is `u64::MAX`, the LHA/zip case rather
//! than the ARC/ZOO one: tar entries are stored, and [`write_payload`]
//! streams them through `stream_bounded_copy`'s fixed window. No header
//! field ever becomes a buffer, so a ceiling would stand in front of no
//! allocation and would only cost recoverable entries.
//! [`tests::an_eight_gigabyte_declaration_never_becomes_an_allocation`] and
//! [`tests::a_whole_entry_is_written_without_being_buffered`] prove that with
//! the recording allocator, each paired with the lower bound that proves
//! the allocator is attached.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use stuffr_core::salvage::{
    Candidate, SalvageOutcome, SalvagePolicy, SalvageScan, SalvageStatus, SalvagedEntry, Sighting,
    UnverifiedCause, salvage_all, stream_bounded_copy,
};
use stuffr_core::{EntryMeta, Error, FormatId, Result, SeekRead};

use crate::tar::{BLOCK, TAR, entry_kind, header_mtime};

/// [`BLOCK`] as the `u64` every offset below is.
const BLOCK_U64: u64 = BLOCK as u64;

/// Where the checksum field starts — `tar` 0.4.46 `header.rs:55-67`: after
/// `name` (100), `mode` (8), `uid` (8), `gid` (8), `size` (12) and `mtime`
/// (12). See this module's layout table.
const CHECKSUM_AT: usize = 148;

/// The checksum field's width, `cksum: [u8; 8]`.
const CHECKSUM_LEN: usize = 8;

/// Where the magic field starts — `tar.rs`'s `TAR_MAGIC` offset, and the
/// first byte past `OldHeader`'s 257 bytes of fields.
const MAGIC_AT: usize = 257;

/// `magic: [u8; 6]` plus `version: [u8; 2]`.
const MAGIC_AND_VERSION_LEN: usize = 8;

/// Whether the magic field begins `ustar` — POSIX's `ustar\0` and GNU's
/// `ustar ` both do.
fn magic_is_ustar(block: &[u8]) -> bool {
    block[MAGIC_AT..MAGIC_AT + 5] == *b"ustar"
}

/// Whether all eight bytes of magic and version are zero, as a pre-POSIX
/// (v7) header leaves them.
fn magic_is_blank(block: &[u8]) -> bool {
    block[MAGIC_AT..MAGIC_AT + MAGIC_AND_VERSION_LEN]
        .iter()
        .all(|&b| b == 0)
}

fn magic_is_ustar_or_blank(block: &[u8]) -> bool {
    magic_is_ustar(block) || magic_is_blank(block)
}

/// Whether an eight-byte checksum field is spelled the way a real tar writer
/// spells it — the half of gate criterion 3 a blank-magic (v7) header must
/// pass. See the module doc's section on the one-byte shift for why, and
/// for the writers each spelling was measured on.
///
/// The spellings, each a run of optional leading spaces then at least one
/// octal digit (the "body"), then a terminator:
///
/// | spelling | body | then | written by |
/// |---|---|---|---|
/// | `%06o\0 ` | 6 bytes | NUL, space | bsdtar `--format v7`, GNU tar `--format=v7`, and every ustar/GNU/pax header of both and of Python's `tarfile` |
/// | `%6o\0 ` | 6 bytes, leading spaces | NUL, space | Seventh Edition `tar` itself (`sprintf("%6o")` over a field of spaces) |
/// | `%07o\0` | 7 bytes | NUL | macOS `pax -x tar`; the `tar` crate (`octal_into`) |
/// | `%07o ` | 7 bytes | space | macOS `pax -x ustar` |
///
/// **The spelling alone does not refuse every shifted copy, and the
/// exhaustive test proved it.** A window `k` bytes late sees the field's
/// bytes `k..8` followed by the typeflag, so the writer's terminator moves
/// to `6 - k` or `7 - k`, inside the body — refused — EXCEPT one case:
/// `%07o\0` seen one byte late reads as six digits and a NUL, and if the
/// typeflag byte that slides in behind it is a SPACE, that is `%06o\0 `.
/// No writer measured writes a space typeflag, but the property cannot rest
/// on that, so [`clears_criterion_3`] also asks [`looks_like_a_shifted_twin`]
/// for a blank-magic header. The two together are what
/// [`tests::every_writer_spelling_refuses_its_own_shifted_copy`] checks
/// exhaustively, over every typeflag byte.
fn spelled_like_a_writer(field: &[u8]) -> bool {
    let body_is_spaces_then_digits = |body: &[u8]| {
        let digits = body.iter().skip_while(|&&b| b == b' ');
        let mut any = false;
        for &b in digits {
            if !(b'0'..=b'7').contains(&b) {
                return false;
            }
            any = true;
        }
        any
    };
    (body_is_spaces_then_digits(&field[..6]) && field[6] == 0 && field[7] == b' ')
        || (body_is_spaces_then_digits(&field[..7]) && (field[7] == 0 || field[7] == b' '))
}

/// Gate criterion 3 for the block at `offset` — see the module doc's section
/// on the one-byte shift.
///
/// A `ustar` magic is enough on its own: a shifted POSIX or GNU header reads
/// `star` there. A BLANK magic is not, because a v7 header has zeros there
/// and so does its shifted copy — so for those the checksum field must also
/// be [`spelled_like_a_writer`], AND the block must not be
/// [`looks_like_a_shifted_twin`] of a header up to seven bytes earlier.
/// Anything else in the magic field is refused.
fn clears_criterion_3(src: &mut dyn SeekRead, offset: u64, file_len: u64, block: &[u8]) -> bool {
    magic_is_ustar(block)
        || (magic_is_blank(block)
            && spelled_like_a_writer(&block[CHECKSUM_AT..CHECKSUM_AT + CHECKSUM_LEN])
            && !looks_like_a_shifted_twin(src, offset, file_len, SourceMustName::Yes))
}

/// Whether the block at `offset` is a real header seen `k` bytes late, for
/// some `k` in `1..=7`: the block `k` bytes EARLIER looks like the genuine
/// header — a writer-spelled checksum field, a `ustar` or blank magic, and a
/// mode and size field that both parse.
///
/// Two callers. [`clears_criterion_3`] asks it of every blank-magic header,
/// because the checksum spelling alone lets one shifted shape through. And
/// for a block criterion 3 has refused, [`sighting_at`] asks it to decide
/// whether that refusal is an UNGATEABLE SIGHTING (Ruling 3-J) or the scan
/// correctly declining a phantom. A twin is never a sighting: it is evidence
/// of a header the scan has already met or already lost, not of one it
/// cannot read.
///
/// # Why the mode and size fields are part of it
///
/// Because the checksum field alone mistook GENUINE headers for twins, twice
/// over, in the first run of the tests that now pin it. The block `k` bytes
/// before a genuine header has its checksum field at that header's own
/// bytes `148 - k .. 156 - k` — the tail of its `mtime`, then the start of
/// its checksum. bsdtar ends `mtime` with a space (`%011o `), so at `k = 1`
/// that window reads ` 005013\0`: a spelled `%07o\0`. Seventh Edition
/// `tar` starts its checksum with a space (`%6o`), so at `k = 7` the window
/// reads the last six `mtime` digits, its NUL, and that space: a spelled
/// `%06o\0 `. Both genuine headers were refused, and bsdtar's v7 archive
/// came back as its first entry alone.
///
/// The earlier block's `mode` and `size` fields are what separate the two:
/// in a real twin's source they are the genuine header's own, and parse; in
/// the window before a genuine header they begin inside the NUL padding of
/// its name field and the NUL terminator of its `gid` field, and do not.
/// [`tests::every_writer_spelling_refuses_its_own_shifted_copy`] checks both
/// halves for every spelling and typeflag, and the v7 writers test is the
/// measurement on real archives.
///
/// The earlier block's own checksum is deliberately NOT required to agree:
/// the case that produces a twin at all is the genuine header being damaged.
///
/// # Why it must also name something (Task 2-N, N1)
///
/// Mode and size are not enough on a layout no measured writer uses, and
/// Task 2's re-review built one: space-terminated numeric fields (`pax -x
/// ustar`'s style), a 100-byte name ending in an octal digit, a measured
/// `%06o\0 ` checksum. One byte before that header the window reads mode
/// `70000644` (`name[99]` then the mode), size ` 00000000004` (`gid[7]`, a
/// space, then the size) and checksum ` 030404\0` — every test passes, and
/// the genuine header was judged a copy of ITSELF: as the middle of three
/// entries it vanished from `salvage` at exit 0, with nothing said.
///
/// That window is not a header anything could have been copied from. Its
/// name field begins with the `k` bytes BEFORE the genuine header, which in
/// an archive are the previous entry's zero padding, so it names nothing —
/// gate criterion 5, which every header this module reports must clear. A
/// real twin's source is a real header, and it names something: the damage
/// that leaves a checksum-valid twin behind is damage in the `k` bytes the
/// twin does not contain — the start of the source's name. So the earlier
/// block must name something too.
///
/// **Only in criterion 3** ([`SourceMustName::Yes`]), where the answer
/// decides whether a block is PROMOTED to a candidate — that is the one
/// place N1's genuine header needs the stricter reading. [`sighting_at`]
/// asks with [`SourceMustName::No`], the pre-2-N predicate, and must: there
/// the answer decides between a sighting and a [`Scanned::Copy`] the grid
/// rules on, and damage that writes a NUL into byte 0 of a genuine `ustar`
/// header empties the source's name while leaving its one-byte-late copy
/// checksum-valid. Asked strictly, that copy was an `UnrecognisedMagic`
/// sighting, and a one-entry archive `stuffr list` refuses at exit 5 came
/// back exit 3, "`stuffr list` and `stuffr unpack` read these headers
/// normally" — false on both counts (Task 2-N fix round 1, I1). Asked
/// leniently it is a copy, off the grid, and silent: exit 5 again.
///
/// **The residual the strict reading costs**, stated: damage empties the
/// source's name only by writing a NUL into byte 0. A v7 header whose byte 0
/// became NUL, and whose one-byte-late copy also passes the checksum
/// spelling (only the `%07o\0` + space-typeflag shape does, and no measured
/// writer writes a space typeflag), is no longer recognised as a copy in
/// criterion 3 — so that copy CLEARS the gate and becomes a LISTED
/// candidate: a phantom row, named without its first byte, whose declared
/// length the engine then advances by (Ruling 3-J item 3's hazard). No
/// writer on this machine produces it; it is recorded rather than closed.
/// With a `ustar` or junk magic the copy fails criterion 3 on the magic
/// alone, reaches [`sighting_at`], and is judged there leniently.
///
/// When the bytes before the genuine header are payload rather than padding,
/// the window DOES name something and the header is still refused;
/// [`salvage_tar`] reports that refusal as a [`Sighting`] when the header
/// sits on the recovered entries' block grid, which a real copy never does
/// (`UngateableSightings::into_sightings`).
fn looks_like_a_shifted_twin(
    src: &mut dyn SeekRead,
    offset: u64,
    file_len: u64,
    source_must_name: SourceMustName,
) -> bool {
    (1..=7u64).any(|k| {
        offset
            .checked_sub(k)
            .and_then(|at| read_block(src, at, file_len))
            .is_some_and(|b| {
                let earlier = tar::Header::from_byte_slice(&b);
                spelled_like_a_writer(&b[CHECKSUM_AT..CHECKSUM_AT + CHECKSUM_LEN])
                    && magic_is_ustar_or_blank(&b)
                    && earlier.mode().is_ok()
                    && earlier.entry_size().is_ok()
                    && (source_must_name == SourceMustName::No || !earlier.path_bytes().is_empty())
            })
    })
}

/// Whether [`looks_like_a_shifted_twin`] requires the earlier block to name
/// something — see its "only in criterion 3" section for which caller asks
/// which, and why the two must differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceMustName {
    /// Criterion 3: a genuine header may be promoted to a candidate past a
    /// window that names nothing (N1).
    Yes,
    /// [`sighting_at`]: the pre-2-N predicate, so a copy of a header whose
    /// byte 0 became NUL is still a copy, and the grid decides it.
    No,
}

/// A header shape the scan recognised and has no gate for — Ruling 3-J,
/// this scanner's Ruling S-V (`lha_salvage.rs`'s `UngateableSightings` is
/// the template).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ungateable {
    /// A checksum-valid header whose magic field is neither `ustar` nor
    /// blank, and which is not a shifted copy of a real header.
    UnrecognisedMagic,
    /// A checksum-valid v7 (blank-magic) header whose checksum field is not
    /// spelled the way any writer this project measured spells it, and
    /// which is not a shifted copy of a real header.
    UnrecognisedV7Spelling,
}

impl Ungateable {
    /// The phrase for this shape, shared by the exit-3 refusal and the
    /// [`Sighting`] a mixed run reports, so the two cannot describe one shape
    /// two ways.
    fn shape(self) -> &'static str {
        match self {
            Ungateable::UnrecognisedMagic => UNRECOGNISED_MAGIC_SHAPE,
            Ungateable::UnrecognisedV7Spelling => UNRECOGNISED_V7_SPELLING_SHAPE,
        }
    }
}

/// [`Ungateable::UnrecognisedMagic`]'s phrase.
const UNRECOGNISED_MAGIC_SHAPE: &str =
    "header(s) whose magic field (bytes 257..265) is neither `ustar` nor blank";

/// [`Ungateable::UnrecognisedV7Spelling`]'s phrase.
const UNRECOGNISED_V7_SPELLING_SHAPE: &str = "pre-POSIX (v7) header(s) whose checksum field is \
     not spelled the way any tar writer this build knows spells it";

/// The phrase for a block refused as a shifted copy that sits on the
/// recovered entries' own block boundaries — see
/// [`UngateableSightings::into_sightings`].
const POSSIBLE_SHIFTED_COPY_SHAPE: &str = "header(s) that read as a copy of another seen up to \
     seven bytes earlier, yet sit on the block boundaries of the entries recovered around them";

/// What the scan saw and could not gate, with where. Never listed as a
/// candidate: a candidate would be advanced past by its declared length
/// (`salvage.rs`'s `collect_candidates`), and that is how a phantom used to
/// jump the scan past a real header.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct UngateableSightings {
    /// Every ungateable header, in scan order.
    seen: Vec<(u64, Ungateable)>,
    /// Every block with a header's structure (checksum, size, name) that
    /// was refused ONLY because [`looks_like_a_shifted_twin`] matched it.
    /// Most are real copies and are dropped; see [`Self::into_sightings`]
    /// for the ones that are not.
    copies: Vec<u64>,
}

impl UngateableSightings {
    fn any(&self) -> bool {
        !self.seen.is_empty()
    }

    /// How many of `kind` were seen.
    fn count(&self, kind: Ungateable) -> usize {
        self.seen.iter().filter(|(_, k)| *k == kind).count()
    }

    /// The sentence a run reports when it recovered nothing and saw one of
    /// these — naming the shape, and saying that the ordinary verbs still
    /// read the archive, which is the whole difference from "nothing
    /// recoverable".
    fn refusal(&self) -> String {
        let shapes: Vec<String> = [
            Ungateable::UnrecognisedMagic,
            Ungateable::UnrecognisedV7Spelling,
        ]
        .into_iter()
        .filter_map(|kind| {
            let n = self.count(kind);
            (n > 0).then(|| format!("{n} {}", kind.shape()))
        })
        .collect();
        format!(
            "this build's tar salvage scanner found {} — each with a checksum that agrees, but \
             in a shape it has no gate for, because a header seen one byte late takes exactly \
             that shape; the archive itself may be perfectly readable — `stuffr list` and \
             `stuffr unpack` read these headers normally, and it is the SCAN that stops here",
            shapes.join(" and ")
        )
    }

    /// The [`Sighting`]s a run that recovered `entries` reports (Task 2-N):
    /// every ungateable header, and every refused copy that sits on the
    /// block boundaries of a recovered entry.
    ///
    /// **Why the boundary decides it.** Every header of one tar is a whole
    /// number of blocks from every other, so a genuine header lies on the
    /// recovered entries' 512-byte grid, and the copy of a damaged genuine
    /// header lies 1..7 bytes OFF it — its source is the one on the grid. A
    /// block the twin check refused that is ON the grid is therefore the
    /// genuine header the check could not tell from the window before it
    /// (N1's second shape), not a copy, and it must be reported rather than
    /// vanish. It is still never listed: nothing in its bytes says which of
    /// the two it is, only its position does, and a position is not a gate.
    ///
    /// A run that recovered nothing has no grid, so no copy is reported
    /// there, and an archive whose only header is damaged still holds
    /// nothing recoverable (exit 5) rather than a sighting (exit 3).
    fn into_sightings(self, entries: &[SalvagedEntry]) -> Vec<Sighting> {
        // One flag per position within a block, set once: a lookup per copy
        // rather than a pass over every entry for each one.
        let mut grid = [false; BLOCK];
        for entry in entries {
            grid[(entry.offset % BLOCK_U64) as usize] = true;
        }
        let on_grid = |offset: u64| grid[(offset % BLOCK_U64) as usize];
        let mut sightings: Vec<Sighting> = self
            .seen
            .into_iter()
            .map(|(offset, kind)| Sighting::new(TAR, offset, kind.shape()))
            .chain(
                self.copies
                    .into_iter()
                    .filter(|&offset| on_grid(offset))
                    .map(|offset| Sighting::new(TAR, offset, POSSIBLE_SHIFTED_COPY_SHAPE)),
            )
            .collect();
        sightings.sort_by_key(|s| s.offset);
        sightings
    }
}

/// Bytes read per [`find_next_header`] chunk. O(1) memory however far the
/// next header is — the same figure every other scanner's `SCAN_CHUNK` is.
const SCAN_CHUNK: usize = 64 * 1024;

/// The most bytes a GNU `L`/`K` payload may declare before this scanner
/// refuses to read it — see the module doc's extension section.
pub const MAX_LONG_NAME: u64 = 65_536;

/// The most bytes a pax `x` payload may declare before this scanner refuses
/// to read it — see the module doc's extension section.
pub const MAX_PAX_EXTENSION: u64 = 1024 * 1024;

/// The codec a stored tar entry carries in [`EntryMeta::codec`].
///
/// **Setting it at all is load-bearing**, even though a tar entry is not
/// compressed: `entries.rs`'s salvage write path hands `EntryMeta::codec`
/// to this module's [`write_payload`], which refuses anything else, and an
/// unset codec would make every entry a silent `SkippedNotBuiltIn` — the
/// exact defect ARC shipped in Salvage Stage 2 Task 3.
pub const STORED: FormatId = FormatId::new("tar-stored");

/// The codec a sparse tar entry carries — recognised, never written. See
/// the module doc's sparse section.
pub const SPARSE: FormatId = FormatId::new("tar-sparse");

/// Scans a tar archive for header blocks directly — see the module doc.
///
/// The one piece of state is `resume`: where the last WHOLE candidate's
/// payload ends, so the next scan can start there rather than inside the
/// payload (the module doc's "jumps its payload" section).
#[derive(Debug, Default)]
pub struct TarSalvage {
    resume: Option<Resume>,
    /// Header shapes this scan recognised and cannot gate — Ruling 3-J.
    seen: UngateableSightings,
}

/// The last reported candidate whose payload fit in the file.
#[derive(Debug, Clone, Copy)]
struct Resume {
    /// That candidate's header offset.
    header: u64,
    /// The first block boundary after its payload.
    next_header: u64,
}

impl TarSalvage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SalvageScan for TarSalvage {
    fn next_candidate(&mut self, src: &mut dyn SeekRead, from: u64) -> Result<Option<Candidate>> {
        let file_len = src.seek(SeekFrom::End(0))?;
        // The engine advances past a candidate by an amount of its own
        // choosing; any position strictly inside the last whole entry's
        // header-plus-payload span means "carry on after that entry", which
        // is where its payload ends, not where the engine's arithmetic
        // happened to land. Taken, not peeked: it describes one candidate.
        let mut search_from = match self.resume.take() {
            Some(resume) if from > resume.header && from <= resume.next_header => {
                resume.next_header
            }
            _ => from,
        };
        loop {
            let Some(offset) = find_next_header(src, search_from, file_len)? else {
                return Ok(None);
            };
            match read_candidate_at(src, offset, file_len) {
                Scanned::Found(found) => {
                    self.resume = found.next_header.map(|next_header| Resume {
                        header: found.candidate.offset,
                        next_header,
                    });
                    return Ok(Some(found.candidate));
                }
                // Counted, not reported — see `UngateableSightings`.
                Scanned::Ungateable(kind) => {
                    self.seen.seen.push((offset, kind));
                    search_from = offset + 1;
                }
                // Kept aside, and decided once the scan is over — see
                // `UngateableSightings::into_sightings`.
                Scanned::Copy => {
                    self.seen.copies.push(offset);
                    search_from = offset + 1;
                }
                // A checksum-valid block the rest of the gate refused, or an
                // extension chain that reached no header. Resume one byte
                // on, so a genuine header overlapping this one is never
                // skipped.
                Scanned::NotAHeader => search_from = offset + 1,
            }
        }
    }

    /// `u64::MAX`: this scanner imposes no ceiling of its own. See the module
    /// doc's last section — tar entries are stored and streamed, so no header
    /// field ever sizes a buffer, and the policy's `max_entry` is the only
    /// figure that bounds a read.
    fn max_whole_entry(&self) -> u64 {
        u64::MAX
    }

    /// `Complete` for a whole entry whose header checks out — **checked
    /// again here**, rather than on discovery's word, so the one tier this
    /// method can claim stands on a check this method made. Never `Intact`:
    /// tar carries no content checksum. See the module doc.
    ///
    /// Never `Err`, for any input: every per-entry outcome is a status, the
    /// discipline every scanner's `verify` follows.
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

/// The checksum a header records, per `tar` 0.4.46's `cksum` — the field up
/// to its first NUL, as UTF-8, trimmed, read as octal, truncated to `u32`.
/// `None` for a field that `tar.rs` would refuse to parse.
fn recorded_checksum(field: &[u8]) -> Option<u32> {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    let text = std::str::from_utf8(&field[..end]).ok()?;
    // `as u32` is the crate's own truncation (`.map(|u| u as u32)`), kept so
    // an absurd octal value compares the way `tar.rs` compares it.
    u64::from_str_radix(text.trim(), 8).ok().map(|v| v as u32)
}

/// Gate criterion 2: whether `block`'s recorded checksum agrees with the
/// block. See the module doc's layout table for the rule and its sources.
///
/// `pub(crate)` so the tests can state what a gate-clearing block is
/// without restating the rule.
pub(crate) fn header_checksum_agrees(block: &[u8]) -> bool {
    debug_assert_eq!(block.len(), BLOCK);
    let Some(recorded) = recorded_checksum(&block[CHECKSUM_AT..CHECKSUM_AT + CHECKSUM_LEN]) else {
        return false;
    };
    let summed: u32 = block[..CHECKSUM_AT]
        .iter()
        .chain(&block[CHECKSUM_AT + CHECKSUM_LEN..])
        .map(|&b| u32::from(b))
        .sum::<u32>()
        + CHECKSUM_LEN as u32 * u32::from(b' ');
    summed == recorded
}

/// Searches forward from `from` for the next offset whose 512 bytes clear
/// gate criteria 1 and 2, in bounded chunks. Carries `BLOCK - 1` bytes
/// across a chunk boundary — the most a header can straddle.
fn find_next_header(src: &mut dyn SeekRead, from: u64, file_len: u64) -> io::Result<Option<u64>> {
    if file_len.saturating_sub(from) < BLOCK_U64 {
        return Ok(None);
    }
    src.seek(SeekFrom::Start(from))?;

    let mut window: Vec<u8> = Vec::with_capacity(SCAN_CHUNK + BLOCK);
    let mut window_start = from;
    let mut buf = vec![0u8; SCAN_CHUNK];

    loop {
        let n = src.read(&mut buf)?;
        window.extend_from_slice(&buf[..n]);
        if window.len() >= BLOCK {
            let last = window.len() - BLOCK;
            if let Some(at) = (0..=last).find(|&i| header_checksum_agrees(&window[i..i + BLOCK])) {
                return Ok(Some(window_start + at as u64));
            }
            // Keep the last `BLOCK - 1` bytes: every offset before them has
            // now been tested against a whole block.
            let tested = last + 1;
            window_start += tested as u64;
            window.drain(..tested);
        }
        if n == 0 {
            return Ok(None);
        }
    }
}

/// Reads the 512-byte block at `at`, or `None` if the source does not hold
/// all of it — gate criterion 1. A read error folds into `None` too: to a
/// scanner it means the same thing, these bytes are not a usable header.
fn read_block(src: &mut dyn SeekRead, at: u64, file_len: u64) -> Option<[u8; BLOCK]> {
    if at.checked_add(BLOCK_U64)? > file_len {
        return None;
    }
    src.seek(SeekFrom::Start(at)).ok()?;
    let mut block = [0u8; BLOCK];
    src.read_exact(&mut block).ok()?;
    Some(block)
}

/// `n` rounded up to the next multiple of [`BLOCK`], or `None` on overflow —
/// `tar` 0.4.46 `archive.rs:356-363`'s own `size + BLOCK_SIZE - 1 & !(..)`.
fn round_up_to_block(n: u64) -> Option<u64> {
    Some(n.checked_add(BLOCK_U64 - 1)? & !(BLOCK_U64 - 1))
}

/// What the extension headers ahead of a real header said about it.
#[derive(Debug, Default)]
struct Extensions {
    /// A GNU `L` payload, verbatim.
    long_name: Option<Vec<u8>>,
    /// A GNU `K` payload, verbatim.
    long_link: Option<Vec<u8>>,
    /// A pax `x` payload, verbatim.
    pax: Option<Vec<u8>>,
}

impl Extensions {
    /// A pax record's value for `key`, the first well-formed one — `tar`
    /// 0.4.46 `entry.rs`'s `filter_map(ok).find(..)` for `path` and
    /// `linkpath`.
    fn pax_value(&self, key: &[u8]) -> Option<Vec<u8>> {
        let pax = self.pax.as_deref()?;
        tar::PaxExtensions::new(pax)
            .filter_map(|record| record.ok())
            .find(|record| record.key_bytes() == key)
            .map(|record| record.value_bytes().to_vec())
    }

    /// The pax `size` override, with `tar` 0.4.46 `pax.rs:64-85`'s
    /// (`pax_extensions_value`) exact semantics: the first malformed record
    /// ends the search with no answer, and so does a `size` value that is
    /// not a decimal `u64`.
    fn pax_size(&self) -> Option<u64> {
        let pax = self.pax.as_deref()?;
        for record in tar::PaxExtensions::new(pax) {
            let record = record.ok()?;
            if record.key() != Ok("size") {
                continue;
            }
            return record.value().ok()?.parse::<u64>().ok();
        }
        None
    }

    /// Whether any well-formed pax record is a `GNU.sparse.*` one — pax
    /// sparse, which the module doc's sparse section refuses to write.
    fn pax_is_sparse(&self) -> bool {
        self.pax.as_deref().is_some_and(|pax| {
            tar::PaxExtensions::new(pax)
                .filter_map(|record| record.ok())
                .any(|record| record.key_bytes().starts_with(b"GNU.sparse."))
        })
    }
}

/// `bytes` with ONE trailing NUL removed, as `tar` 0.4.46 `entry.rs:308-318`
/// strips a GNU long name or link.
fn strip_one_nul(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.last() == Some(&0) {
        bytes.pop();
    }
    bytes
}

/// Reads an extension payload of `len` bytes at `at`, refusing — before
/// anything is allocated — one over `ceiling` or one the source does not
/// wholly hold.
fn read_extension(
    src: &mut dyn SeekRead,
    at: u64,
    len: u64,
    ceiling: u64,
    file_len: u64,
) -> Option<Vec<u8>> {
    if len > ceiling || at.checked_add(len)? > file_len {
        return None;
    }
    src.seek(SeekFrom::Start(at)).ok()?;
    let mut bytes = vec![0u8; usize::try_from(len).ok()?];
    src.read_exact(&mut bytes).ok()?;
    Some(bytes)
}

/// A candidate, and where the next header would begin if its payload is
/// whole.
struct Found {
    candidate: Candidate,
    /// `None` for a truncated candidate, whose declared length is not
    /// trusted to say where anything ends.
    next_header: Option<u64>,
}

/// The most extension headers one entry can carry: `tar::Archive` refuses a
/// second `L`, `K` or `x` for the same member, so three.
const MAX_EXTENSIONS: usize = 3;

/// What gating the block at one offset found.
enum Scanned {
    /// Boxed: a `Candidate` is far larger than the other two arms, and this
    /// is built once per checksum-valid block, not in a hot loop.
    Found(Box<Found>),
    /// A checksum-valid block refused by criterion 3 alone, with a size and a
    /// name, that is not a shifted copy of a real header — Ruling 3-J.
    Ungateable(Ungateable),
    /// The same, except that it DOES look like a shifted copy of a header up
    /// to seven bytes earlier — the one refusal whose verdict waits for the
    /// end of the scan (Task 2-N, N1).
    Copy,
    NotAHeader,
}

/// Gates the block at `offset` and, if it is an extension, the chain it
/// begins — see the module doc.
fn read_candidate_at(src: &mut dyn SeekRead, offset: u64, file_len: u64) -> Scanned {
    if let Some(block) = read_block(src, offset, file_len)
        && header_checksum_agrees(&block)
        && !clears_criterion_3(src, offset, file_len, &block)
    {
        return sighting_at(src, offset, file_len, &block);
    }
    gate_chain_at(src, offset, file_len)
        .map_or(Scanned::NotAHeader, |found| Scanned::Found(Box::new(found)))
}

/// Whether a checksum-valid block that criterion 3 refused is an ungateable
/// SIGHTING: it must carry the structure a header needs (a size that parses
/// and a name), and it must not be a shifted copy of a real header — or, if
/// it looks like one, it is a [`Scanned::Copy`], whose verdict waits for the
/// end of the scan.
fn sighting_at(src: &mut dyn SeekRead, offset: u64, file_len: u64, block: &[u8; BLOCK]) -> Scanned {
    let header = tar::Header::from_byte_slice(block);
    if header.entry_size().is_err() || header.path_bytes().is_empty() {
        return Scanned::NotAHeader;
    }
    if looks_like_a_shifted_twin(src, offset, file_len, SourceMustName::No) {
        return Scanned::Copy;
    }
    // Reached only for a block criterion 3 refused and that is no twin, so a
    // blank magic here means an unmeasured checksum spelling.
    Scanned::Ungateable(if magic_is_blank(block) {
        Ungateable::UnrecognisedV7Spelling
    } else {
        Ungateable::UnrecognisedMagic
    })
}

/// Gates the header at `offset` and, if it is an extension, the chain it
/// begins — see the module doc. `None` for anything that does not reach a
/// real header.
fn gate_chain_at(src: &mut dyn SeekRead, offset: u64, file_len: u64) -> Option<Found> {
    let mut extensions = Extensions::default();
    let mut at = offset;
    for _ in 0..=MAX_EXTENSIONS {
        let block = read_block(src, at, file_len)?;
        if !header_checksum_agrees(&block) || !clears_criterion_3(src, at, file_len, &block) {
            return None;
        }
        let header = tar::Header::from_byte_slice(&block);
        let raw_span = header.entry_size().ok()?;
        let payload_start = at.checked_add(BLOCK_U64)?;

        // `archive.rs:408-409`: an extension is consumed only when the
        // header carries GNU or ustar magic. A v7 header whose typeflag
        // happens to read `L` is an ordinary (`Other`) entry to the reader,
        // and so it is here.
        let recognised = header.as_gnu().is_some() || header.as_ustar().is_some();
        let entry_type = header.entry_type();
        if recognised
            && (entry_type.is_gnu_longname()
                || entry_type.is_gnu_longlink()
                || entry_type.is_pax_local_extensions())
        {
            let (slot, ceiling) = if entry_type.is_gnu_longname() {
                (&mut extensions.long_name, MAX_LONG_NAME)
            } else if entry_type.is_gnu_longlink() {
                (&mut extensions.long_link, MAX_LONG_NAME)
            } else {
                (&mut extensions.pax, MAX_PAX_EXTENSION)
            };
            // "two long name entries describing the same member" — the
            // reader refuses the archive; the chain is broken here.
            if slot.is_some() {
                return None;
            }
            *slot = Some(read_extension(
                src,
                payload_start,
                raw_span,
                ceiling,
                file_len,
            )?);
            at = payload_start.checked_add(round_up_to_block(raw_span)?)?;
            continue;
        }

        return candidate_from(header, at, payload_start, raw_span, &extensions, file_len);
    }
    None
}

/// Builds the candidate for a real header whose extensions have been read.
fn candidate_from(
    header: &tar::Header,
    offset: u64,
    payload_start: u64,
    raw_span: u64,
    extensions: &Extensions,
    file_len: u64,
) -> Option<Found> {
    let name = match &extensions.long_name {
        Some(long) => strip_one_nul(long.clone()),
        None => extensions
            .pax_value(b"path")
            .unwrap_or_else(|| header.path_bytes().into_owned()),
    };
    // Criterion 5.
    if name.is_empty() {
        return None;
    }

    let entry_type = header.entry_type();
    let kind = entry_kind(entry_type, || match &extensions.long_link {
        Some(long) => Some(strip_one_nul(long.clone())),
        None => extensions
            .pax_value(b"linkpath")
            .or_else(|| header.link_name_bytes().map(|b| b.into_owned())),
    });

    // The payload's byte span in the file: `archive.rs:348-354`'s pax
    // override, then the header's own field.
    let span = extensions.pax_size().unwrap_or(raw_span);
    let sparse = entry_type.is_gnu_sparse() || extensions.pax_is_sparse();
    // A GNU sparse header's own `realsize` is the file's logical size; for
    // everything else the span IS the size, as `tar.rs` reports it.
    let size = if entry_type.is_gnu_sparse() {
        header.size().unwrap_or(span)
    } else {
        span
    };

    let (available_len, next_header) = match payload_start.checked_add(span) {
        Some(end) if end <= file_len => (None, payload_start.checked_add(round_up_to_block(span)?)),
        // Either the declared end overflows, or it runs past the source:
        // fewer bytes are present than the header promises. `Some(n)` always
        // means `n < declared_len`, per the field's contract.
        _ => (Some(file_len.saturating_sub(payload_start)), None),
    };

    let mut meta = EntryMeta::file(String::from_utf8_lossy(&name).into_owned());
    meta.size = Some(size);
    meta.compressed_size = Some(span);
    meta.kind = kind;
    meta.mtime = header_mtime(header);
    meta.mode = header.mode().ok();
    meta.uid = header.uid().ok().and_then(|v| u32::try_from(v).ok());
    meta.gid = header.gid().ok().and_then(|v| u32::try_from(v).ok());
    meta.codec = Some(if sparse { SPARSE } else { STORED });

    // `payload_start` computed once, here, with `checked_add` — see
    // `Candidate::payload_start`'s own doc. No verifier: tar has no content
    // checksum, which is also why no two tar records are ever proven
    // shadows of each other (only name collisions are reported). No deleted
    // flag: the format has none.
    Some(Found {
        candidate: Candidate::new(offset, payload_start, meta)
            .with_declared_len(Some(span))
            .with_available_len(available_len),
        next_header,
    })
}

/// Decides [`SalvageStatus`] for one candidate. See [`TarSalvage::verify`].
fn verify_candidate(src: &mut dyn SeekRead, candidate: &Candidate) -> Result<SalvageStatus> {
    // Provably incomplete; nothing more to check. Above the sparse arm for
    // the reason every scanner gives: `Partial` (proven missing) is the
    // stronger claim than `Unverified` (nothing attempted).
    if candidate.available_len.is_some() {
        return Ok(SalvageStatus::Partial);
    }
    if candidate.meta.codec != Some(STORED) {
        // `SPARSE`, or a codec this scanner never sets: recognised, not
        // written — see the module doc's sparse section.
        return Ok(SalvageStatus::Unverified(
            UnverifiedCause::UndecodableMethod,
        ));
    }
    let Ok(file_len) = src.seek(SeekFrom::End(0)) else {
        return Ok(SalvageStatus::Partial);
    };
    // The header checked again, by this method. A block that no longer
    // agrees with itself (the source changed under the scan) has proven
    // nothing, and `Complete` is the one thing it must not be.
    let block = read_block(src, candidate.offset, file_len);
    Ok(match block {
        Some(block)
            if header_checksum_agrees(&block)
                && clears_criterion_3(src, candidate.offset, file_len, &block) =>
        {
            SalvageStatus::Complete
        }
        _ => SalvageStatus::Partial,
    })
}

/// Writes one entry's stored payload to `out`, answering whether every
/// declared byte was written — `entries.rs`'s own signal for `PartialCause`,
/// matching every other scanner's `write_payload`.
///
/// The read is bounded by what the SOURCE holds, never by `compressed_len`
/// alone, so a truncated entry's genuine surviving prefix is written — and
/// only that: nothing pads it to the declared length.
pub fn write_payload(
    archive_path: &Path,
    entry: &SalvagedEntry,
    compressed_len: u64,
    out: &mut dyn Write,
) -> Result<bool> {
    // Refused BEFORE `archive_path` is opened — `entries.rs`'s
    // `every_salvage_slot_reaches_a_real_payload_writer` probes every slot
    // with a codec-less entry and a path that does not exist.
    if entry.meta.codec != Some(STORED) {
        return Err(Error::Unsupported(format!(
            "entry `{}` carries codec {:?}; this build's tar salvage writer writes stored \
             entries only, and a sparse entry's payload is not the file's bytes",
            entry.meta.name, entry.meta.codec
        )));
    }
    // Not `unwrap_or(0)`: with an expected length of 0, `stream_bounded_copy`
    // reports success having written nothing — the declared-versus-produced
    // lie, arrived at through a default. This scanner sets `size` on every
    // candidate, so reaching here names a broken invariant.
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
    // Decided from the lengths, before the read: fewer stored bytes than the
    // header declared is truncation, whatever the copy goes on to report.
    let truncated = readable_len < compressed_len;
    let completed = stream_bounded_copy((&mut f).take(readable_len), expected, out)?;
    Ok(completed && !truncated)
}

/// Runs [`TarSalvage`] over `src` and annotates the result — the whole
/// scanner, matching every other format's `salvage_*` entry point.
///
/// Like ARC, ZOO, LHA and ARJ, and unlike zip, there is no second index to
/// reconcile against: tar has none, so the raw scan is the only source.
pub fn salvage_tar(src: &mut dyn SeekRead, policy: &SalvagePolicy) -> Result<SalvageOutcome> {
    let mut scanner = TarSalvage::new();
    let mut outcome = salvage_all(&mut scanner, src, policy)?;

    // **Ruling 3-J** — this scanner's Ruling S-V. A run that recovered
    // NOTHING while recognising a header shape it cannot gate must not fall
    // through to the empty outcome the CLI reports as "the scan found nothing
    // recoverable" (exit 5): that is a claim about the ARCHIVE, and the truth
    // is a claim about this BUILD. `Error::Unsupported` is exit 3.
    //
    // **Only when nothing came back** (Ruling S-X): an `Err` discards every
    // entry the run recovered, so a run that got something reports it at its
    // ordinary exit code — and, since Task 2-N, carries what it saw and could
    // not gate as `sightings`, which the caller prints. Before that, a mixed
    // run said nothing at all about an entry `stuffr list` shows.
    if outcome.entries.is_empty() && scanner.seen.any() {
        return Err(Error::Unsupported(scanner.seen.refusal()));
    }
    outcome.sightings = std::mem::take(&mut scanner.seen).into_sightings(&outcome.entries);
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use stuffr_core::testing::SharedBuf;
    use stuffr_core::{
        Container, CreateOpts, EntryKind, OpenOpts, PlainSink, ReaderSource, Source, StreamPolicy,
    };

    use stuffr_core::salvage::describe_sightings;

    use super::*;
    use crate::tar::{TAR, Tar};

    fn scan(bytes: &[u8]) -> SalvageOutcome {
        salvage_tar(&mut Cursor::new(bytes.to_vec()), &SalvagePolicy::default()).expect(
            "a salvage scan must not error here — an `Err` is an ungateable sighting \
                 (Ruling 3-J), which none of these inputs may produce",
        )
    }

    // -------------------------------------------------------------------
    // Fixture builders.
    //
    // Two kinds, and they carry different weight. `build_tar` writes through
    // this project's own `tar.rs` writer, which is built on the `tar`
    // crate's `Builder` — the same crate whose `Header` this scanner parses
    // with — so a test standing on it proves AGREEMENT with that crate and
    // nothing more. `header_block` builds a single header with the crate's
    // own setters, for shapes no writer produces; same weight. The
    // reference-writer test further down is the independent witness.
    // -------------------------------------------------------------------

    /// Writes `entries` through `Tar` itself — the path `stuffr pack` takes.
    fn build_tar(entries: &[(EntryMeta, &[u8])]) -> Vec<u8> {
        let buf = SharedBuf::new();
        let mut w = Tar
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
        build_tar(&metas)
    }

    /// One GNU header block, checksummed by the crate's own `set_cksum`.
    fn header_block(name: &str, size: u64, entry_type: tar::EntryType) -> [u8; BLOCK] {
        let mut header = tar::Header::new_gnu();
        header.set_path(name).unwrap();
        header.set_size(size);
        header.set_mode(0o644);
        header.set_entry_type(entry_type);
        header.set_cksum();
        let mut block = [0u8; BLOCK];
        block.copy_from_slice(header.as_bytes());
        block
    }

    /// `payload` padded with zeros to a whole number of blocks.
    fn padded(payload: &[u8]) -> Vec<u8> {
        let mut out = payload.to_vec();
        out.resize(round_up_to_block(payload.len() as u64).unwrap() as usize, 0);
        out
    }

    /// One entry as the ordinary reader reports it: name, size, kind, bytes.
    type ReaderRow = (String, u64, EntryKind, Vec<u8>);

    /// Every entry the ORDINARY reader returns, read over a non-seekable
    /// source, which is how `stuffr list` meets a pipe and changes nothing
    /// about tar.
    fn read_through_the_reader(bytes: &[u8]) -> Result<Vec<ReaderRow>> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(Cursor::new(bytes.to_vec())));
        let resolved = stuffr_core::resolve(src, TAR, Tar.caps(), &StreamPolicy::default())?;
        let mut ar = Tar.open(resolved, &OpenOpts::default())?;
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
                "stuffr-tar-salvage-{tag}-{}-{}.tar",
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
                        .expect("every candidate declares a span"),
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

    /// A small LCG, not `rand` — the corpus must be byte-identical on every
    /// machine. The constants every other scanner's noise test uses.
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

    /// Where the `ustar` magic is forced, block-relative, with everything
    /// around it left as noise. The magic is half of criterion 3, but it is
    /// never ENOUGH — criterion 2, the checksum, comes first — and these are
    /// seeded to show that: a scanner keying on the magic alone would report
    /// six phantoms here.
    const SEEDED_MAGIC_OFFSETS: [usize; 6] = [65_536, 196_608, 344_064, 491_520, 638_976, 786_432];

    /// A complete GNU header plus payload whose ONLY defect is its recorded
    /// checksum, one more than the block's true sum — gate criterion 2's
    /// splice, and the one the comparison's deletion turns into a phantom.
    pub(super) const CHECKSUM_ONLY_DEFECT_OFFSET: usize = 300_000;

    /// A block of zeros whose checksum field alone reads `0000400` — eight
    /// spaces' worth, so it AGREES with itself — and which names nothing:
    /// gate criterion 5's splice.
    const EMPTY_NAME_OFFSET: usize = 500_000;

    /// A checksum-valid header whose size field is not a number: criterion
    /// 4's splice.
    const UNPARSABLE_SIZE_OFFSET: usize = 700_000;

    /// A real GNU header and its payload with the header's FIRST byte
    /// removed, so the block at this offset is that header seen one byte
    /// late — checksum-valid, because the dropped name byte and the gained
    /// payload byte are both `a`. Criterion 3's splice; see the module doc's
    /// section on the one-byte shift.
    pub(super) const SHIFTED_HEADER_OFFSET: usize = 900_000;

    /// The v7 twin of [`SHIFTED_HEADER_OFFSET`]: a GNU-tar-style v7 header
    /// (`%06o\0 ` checksum, NUL typeflag) with its first byte removed. It is
    /// checksum-valid, because `a` (97) dropped and `1` (49) gained differ by
    /// exactly the `0` (48) that slides out of the checksum field while the
    /// NUL typeflag slides in — and its magic is blank. Criterion 3's v7 half,
    /// the checksum-field spelling, is the only thing that refuses it (Ruling
    /// 3-J; F1 of Task 2's review).
    pub(super) const V7_SHIFTED_HEADER_OFFSET: usize = 960_000;

    fn checksum_only_defect() -> Vec<u8> {
        let mut block = header_block("CKSUMONLY.TXT", 7, tar::EntryType::Regular);
        let recorded = recorded_checksum(&block[CHECKSUM_AT..CHECKSUM_AT + CHECKSUM_LEN]).unwrap();
        write_checksum(&mut block, recorded + 1);
        let mut out = block.to_vec();
        out.extend_from_slice(&padded(b"payload"));
        out
    }

    /// Writes `value` into `block`'s checksum field in the crate's own
    /// spelling (six octal digits, NUL, space).
    fn write_checksum(block: &mut [u8; BLOCK], value: u32) {
        let text = format!("{value:06o}\0 ");
        block[CHECKSUM_AT..CHECKSUM_AT + CHECKSUM_LEN].copy_from_slice(text.as_bytes());
    }

    fn empty_name_block() -> [u8; BLOCK] {
        let mut block = [0u8; BLOCK];
        write_checksum(&mut block, CHECKSUM_LEN as u32 * u32::from(b' '));
        block
    }

    fn unparsable_size_block() -> [u8; BLOCK] {
        let mut block = header_block("BADSIZE.TXT", 7, tar::EntryType::Regular);
        block[124..136].copy_from_slice(b"not-a-size!\0");
        let summed = block[..CHECKSUM_AT]
            .iter()
            .chain(&block[CHECKSUM_AT + CHECKSUM_LEN..])
            .map(|&b| u32::from(b))
            .sum::<u32>()
            + CHECKSUM_LEN as u32 * u32::from(b' ');
        write_checksum(&mut block, summed);
        block
    }

    /// See [`SHIFTED_HEADER_OFFSET`]. Built with the crate's own writer, so
    /// the header it shifts is an ordinary one.
    fn shifted_header() -> Vec<u8> {
        files(&[("a.txt", b"alpha")])[1..2 * BLOCK].to_vec()
    }

    /// See [`V7_SHIFTED_HEADER_OFFSET`].
    fn v7_shifted_header() -> Vec<u8> {
        v7_archive(&[("a.txt", b"1st line\n")], V7_GNU_SPELLING)[1..2 * BLOCK].to_vec()
    }

    fn noise_with_splices(len: usize) -> Vec<u8> {
        let mut noise = deterministic_noise(len);
        for &at in &SEEDED_MAGIC_OFFSETS {
            noise[at + 257..at + 262].copy_from_slice(b"ustar");
        }
        let splices: [(usize, Vec<u8>); 5] = [
            (CHECKSUM_ONLY_DEFECT_OFFSET, checksum_only_defect()),
            (EMPTY_NAME_OFFSET, empty_name_block().to_vec()),
            (UNPARSABLE_SIZE_OFFSET, unparsable_size_block().to_vec()),
            (SHIFTED_HEADER_OFFSET, shifted_header()),
            (V7_SHIFTED_HEADER_OFFSET, v7_shifted_header()),
        ];
        for (at, splice) in splices {
            noise[at..at + splice.len()].copy_from_slice(&splice);
        }
        noise
    }

    /// The negative double for the whole feature: a scanner that reported a
    /// phantom here would be worse than no scanner, because tar has nothing
    /// BUT its header checksum to tell a phantom from an entry.
    #[test]
    fn tar_salvage_over_random_bytes_finds_nothing() {
        let out = scan(&noise_with_splices(1 << 20));
        assert!(
            out.entries.is_empty(),
            "1 MiB of noise with five near-miss headers spliced in produced {} phantom(s): {:?}",
            out.entries.len(),
            out.entries
                .iter()
                .map(|e| (&e.meta.name, e.offset))
                .collect::<Vec<_>>()
        );
    }

    /// **The half that makes the test above a test.** A noise test is only
    /// non-vacuous if the noise reaches the gate; this proves each splice
    /// stops exactly where its name says, and that nothing else in the
    /// corpus clears criterion 2 by accident — so the three rejections above
    /// are the gate's doing and not the corpus's emptiness.
    #[test]
    fn the_noise_corpus_reaches_each_criterion_it_claims_to() {
        let noise = noise_with_splices(1 << 20);
        let block_at = |at: usize| &noise[at..at + BLOCK];

        // Criterion 2: the checksum-only defect is off by exactly one, and
        // everything else about it is a header this scanner accepts — with
        // the recorded value corrected, it is found.
        let defect = block_at(CHECKSUM_ONLY_DEFECT_OFFSET);
        assert!(!header_checksum_agrees(defect));
        let recorded = recorded_checksum(&defect[CHECKSUM_AT..CHECKSUM_AT + CHECKSUM_LEN]).unwrap();
        let mut repaired = noise.clone();
        let mut block: [u8; BLOCK] = defect.try_into().unwrap();
        write_checksum(&mut block, recorded - 1);
        repaired[CHECKSUM_ONLY_DEFECT_OFFSET..CHECKSUM_ONLY_DEFECT_OFFSET + BLOCK]
            .copy_from_slice(&block);
        let found = scan(&repaired);
        assert_eq!(
            found
                .entries
                .iter()
                .map(|e| (e.meta.name.as_str(), e.offset))
                .collect::<Vec<_>>(),
            vec![("CKSUMONLY.TXT", CHECKSUM_ONLY_DEFECT_OFFSET as u64)],
            "one checksum unit is the ONLY thing standing between that splice and an entry"
        );

        // Criteria 3, 4 and 5: each clears criterion 2, so each reaches the
        // part of the gate its name claims.
        let v7_shifted = block_at(V7_SHIFTED_HEADER_OFFSET);
        assert!(
            header_checksum_agrees(v7_shifted),
            "a plain sum survives the v7 shift too"
        );
        assert!(
            magic_is_blank(v7_shifted),
            "and a v7 magic is blank before and after"
        );
        assert!(
            !spelled_like_a_writer(&v7_shifted[CHECKSUM_AT..CHECKSUM_AT + CHECKSUM_LEN]),
            "the checksum field's spelling is what the shift moved"
        );
        assert_eq!(&v7_shifted[..5], b".txt\0");
        let shifted = block_at(SHIFTED_HEADER_OFFSET);
        assert!(
            header_checksum_agrees(shifted),
            "a plain sum survives the shift"
        );
        assert!(!magic_is_ustar_or_blank(shifted));
        assert_eq!(
            &shifted[MAGIC_AT..MAGIC_AT + 4],
            b"star",
            "the magic slid too"
        );
        assert_eq!(&shifted[..5], b".txt\0", "and so did the name");
        assert!(magic_is_ustar_or_blank(block_at(EMPTY_NAME_OFFSET)));
        assert!(magic_is_ustar_or_blank(block_at(UNPARSABLE_SIZE_OFFSET)));
        assert!(header_checksum_agrees(block_at(EMPTY_NAME_OFFSET)));
        assert!(
            tar::Header::from_byte_slice(block_at(EMPTY_NAME_OFFSET))
                .path_bytes()
                .is_empty()
        );
        assert!(header_checksum_agrees(block_at(UNPARSABLE_SIZE_OFFSET)));
        assert!(
            tar::Header::from_byte_slice(block_at(UNPARSABLE_SIZE_OFFSET))
                .entry_size()
                .is_err()
        );

        // The magic is there, six times over, and alone admits nothing.
        for &at in &SEEDED_MAGIC_OFFSETS {
            assert_eq!(&noise[at + 257..at + 262], b"ustar");
        }

        // And nothing ELSE in the corpus clears criterion 2: the four
        // splices above are the only checksum-valid blocks, so the empty
        // outcome is the gate rejecting them, not the noise never trying.
        let agreeing: Vec<usize> = (0..=noise.len() - BLOCK)
            .filter(|&i| header_checksum_agrees(&noise[i..i + BLOCK]))
            .collect();
        assert_eq!(
            agreeing,
            vec![
                EMPTY_NAME_OFFSET,
                UNPARSABLE_SIZE_OFFSET,
                SHIFTED_HEADER_OFFSET,
                V7_SHIFTED_HEADER_OFFSET
            ]
        );
    }

    // -------------------------------------------------------------------
    // Healthy archives
    // -------------------------------------------------------------------

    /// Every entry a healthy archive holds comes back `Complete` — never
    /// `Intact` — named, sized and kinded as the ordinary reader reports it,
    /// and its bytes written back verbatim.
    ///
    /// Stands on this project's own writer, so it proves agreement with the
    /// `tar` crate; see the fixture builders' note.
    #[test]
    fn every_entry_of_a_healthy_tar_is_complete_and_agrees_with_the_reader() {
        let long_name = format!("deep/{}/file.txt", "n".repeat(120));
        let mut dir = EntryMeta::file("deep");
        dir.kind = EntryKind::Dir;
        let mut link = EntryMeta::file("link.txt");
        link.kind = EntryKind::Symlink {
            target: "a.txt".into(),
        };
        let big = vec![0xA5u8; 3 * BLOCK + 17];
        let bytes = build_tar(&[
            (dir, b""),
            (EntryMeta::file("a.txt"), b"alpha"),
            (EntryMeta::file("empty.bin"), b""),
            (
                EntryMeta::file(long_name.clone()),
                b"through a GNU long name",
            ),
            (EntryMeta::file("big.bin"), &big),
            (link, b""),
        ]);

        let out = scan(&bytes);
        let reader = read_through_the_reader(&bytes).expect("a healthy archive reads");
        assert_eq!(out.entries.len(), reader.len());
        for (entry, (name, size, kind, _)) in out.entries.iter().zip(&reader) {
            assert_eq!(&entry.meta.name, name);
            assert_eq!(entry.meta.size, Some(*size), "{name}");
            assert_eq!(&entry.meta.kind, kind, "{name}");
            assert_eq!(entry.status, SalvageStatus::Complete, "{name}");
            assert_eq!(
                entry.meta.codec,
                Some(STORED),
                "{name}: the ARC Task 3 defect"
            );
        }
        assert!(out.entries.iter().any(|e| e.meta.name == long_name));

        for ((written, completed), (name, _, _, data)) in
            write_back(&bytes, &out).iter().zip(&reader)
        {
            assert!(completed, "{name}");
            assert_eq!(written, data, "{name}");
        }
    }

    /// The motivating damage: one flipped byte in the FIRST header. The
    /// ordinary reader refuses the whole archive; salvage loses that entry
    /// and nothing else.
    ///
    /// **This is the test that found the one-byte-shift phantom** (module
    /// doc), with the fixture unchanged: before criterion 3 it answered two
    /// entries both named `.txt` and lost `c.txt`. The three names share
    /// their first byte with their payloads by accident of the alphabet,
    /// which is exactly how ordinary the shape is.
    #[test]
    fn a_destroyed_first_header_costs_that_entry_alone() {
        let mut bytes = files(&[("a.txt", b"alpha"), ("b.txt", b"beta"), ("c.txt", b"gamma")]);
        bytes[0] ^= 0x01;
        let refused = read_through_the_reader(&bytes).expect_err("the reader must refuse");
        assert_eq!(refused.exit_code(), 5, "{refused}");

        let out = scan(&bytes);
        assert_eq!(
            out.entries
                .iter()
                .map(|e| (e.meta.name.as_str(), e.status))
                .collect::<Vec<_>>(),
            vec![
                ("b.txt", SalvageStatus::Complete),
                ("c.txt", SalvageStatus::Complete)
            ]
        );
        let written = write_back(&bytes, &out);
        assert_eq!(written[0], (b"beta".to_vec(), true));
        assert_eq!(written[1], (b"gamma".to_vec(), true));
    }

    /// The commonest damaged archive: cut short inside the last payload. The
    /// entry is `Partial`, both lengths are reported as they are, and what
    /// is written is exactly the bytes that exist — never padded.
    #[test]
    fn a_truncated_tail_is_partial_and_its_genuine_prefix_is_written() {
        let last = b"0123456789abcdefghij".repeat(40);
        let whole = files(&[("a.txt", b"alpha"), ("last.bin", &last)]);
        let payload_at = 3 * BLOCK; // a.txt's header and block, then last's header
        let keep = 300;
        let bytes = &whole[..payload_at + keep];

        let out = scan(bytes);
        assert_eq!(out.entries.len(), 2);
        assert_eq!(out.entries[0].status, SalvageStatus::Complete);
        let cut = &out.entries[1];
        assert_eq!(cut.meta.name, "last.bin");
        assert_eq!(cut.status, SalvageStatus::Partial);
        assert_eq!(
            cut.meta.size,
            Some(last.len() as u64),
            "the declared size, as declared"
        );

        let written = write_back(bytes, &out);
        assert_eq!(
            written[1].0,
            &last[..keep],
            "the genuine prefix, not padded"
        );
        assert!(!written[1].1, "and reported as not complete");
    }

    /// A stored `.tar` inside a tar is ONE entry: its contents are real,
    /// aligned, checksum-valid headers, and scanning the outer payload would
    /// report each of them as an entry of the outer archive.
    #[test]
    fn a_tar_stored_inside_a_tar_is_one_entry_not_its_contents() {
        let inner = files(&[("inner-1.txt", b"one"), ("inner-2.txt", b"two")]);
        let bytes = files(&[
            ("before.txt", b"b"),
            ("inner.tar", &inner),
            ("after.txt", b"a"),
        ]);
        let out = scan(&bytes);
        assert_eq!(
            out.entries
                .iter()
                .map(|e| e.meta.name.as_str())
                .collect::<Vec<_>>(),
            vec!["before.txt", "inner.tar", "after.txt"]
        );
        assert_eq!(write_back(&bytes, &out)[1], (inner, true));
    }

    /// With seven bytes in front, no header is on a block boundary any more
    /// — the shape a download missing its start, or a carved image, has. A
    /// scan stepping 512 bytes at a time finds nothing here.
    #[test]
    fn a_tar_shifted_off_its_block_alignment_is_still_found() {
        let healthy = files(&[("a.txt", b"alpha"), ("b.txt", b"beta")]);
        let mut bytes = b"JUNK!!!".to_vec();
        bytes.extend_from_slice(&healthy);
        let out = scan(&bytes);
        assert_eq!(
            out.entries
                .iter()
                .map(|e| (e.meta.name.as_str(), e.offset, e.status))
                .collect::<Vec<_>>(),
            vec![
                ("a.txt", 7, SalvageStatus::Complete),
                ("b.txt", 7 + 2 * BLOCK_U64, SalvageStatus::Complete)
            ]
        );
        let written = write_back(&bytes, &out);
        assert_eq!(written[0], (b"alpha".to_vec(), true));
        assert_eq!(written[1], (b"beta".to_vec(), true));
    }

    /// pax records are applied the way the ordinary reader applies them: a
    /// `path` longer than the header can hold, and a `size` that overrides
    /// the header's own field — here the header says 0 and pax says 5, so
    /// a reader that ignored pax would lose the payload and read its bytes
    /// as the next header.
    #[test]
    fn pax_records_are_applied_as_the_reader_applies_them() {
        let long = format!("pax/{}.txt", "p".repeat(150));
        let mut builder = tar::Builder::new(Vec::new());
        builder
            .append_pax_extensions([("path", long.as_bytes()), ("size", &b"5"[..])])
            .unwrap();
        // `Builder::append` writes the header as given and pads from the
        // bytes it copied, so the header's own size field can say 0 while
        // five bytes follow — the pax record is what frames them.
        let mut header = tar::Header::new_ustar();
        header.set_path("short-placeholder").unwrap();
        header.set_size(0);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, &b"hello"[..]).unwrap();
        let mut next = tar::Header::new_ustar();
        next.set_path("next.txt").unwrap();
        next.set_size(4);
        next.set_cksum();
        builder.append(&next, &b"next"[..]).unwrap();
        let bytes = builder.into_inner().unwrap();

        let reader = read_through_the_reader(&bytes).expect("the reader accepts it");
        let out = scan(&bytes);
        assert_eq!(
            out.entries
                .iter()
                .map(|e| (e.meta.name.clone(), e.meta.size.unwrap()))
                .collect::<Vec<_>>(),
            reader
                .iter()
                .map(|(n, s, _, _)| (n.clone(), *s))
                .collect::<Vec<_>>(),
            "salvage and list must name and size every entry alike"
        );
        assert_eq!(out.entries[0].meta.name, long);
        let written = write_back(&bytes, &out);
        assert_eq!(written[0], (b"hello".to_vec(), true));
        assert_eq!(written[1], (b"next".to_vec(), true));
    }

    /// A sparse payload is not the file's bytes, so both sparse spellings
    /// are recognised and refused — `Unverified`, never `Complete`, and the
    /// writer will not produce them.
    #[test]
    fn a_sparse_entry_is_recognised_and_never_written() {
        // GNU sparse: typeflag `S`.
        let mut gnu = header_block("gnu-sparse.bin", 5, tar::EntryType::GNUSparse).to_vec();
        gnu.extend_from_slice(&padded(b"hello"));
        // pax sparse: an ordinary typeflag behind a `GNU.sparse.*` record,
        // in ONE builder — `into_inner` writes the end-of-archive marker.
        let mut builder = tar::Builder::new(Vec::new());
        builder
            .append_pax_extensions([("GNU.sparse.major", &b"1"[..]), ("GNU.sparse.minor", b"0")])
            .unwrap();
        let block = header_block("pax-sparse.bin", 5, tar::EntryType::Regular);
        builder
            .append(tar::Header::from_byte_slice(&block), &b"hello"[..])
            .unwrap();
        let pax = builder.into_inner().unwrap();

        for (label, bytes) in [("GNU", gnu), ("pax", pax)] {
            let out = scan(&bytes);
            assert_eq!(out.entries.len(), 1, "{label}");
            let entry = &out.entries[0];
            assert_eq!(
                entry.status,
                SalvageStatus::Unverified(UnverifiedCause::UndecodableMethod),
                "{label}"
            );
            assert_eq!(entry.meta.codec, Some(SPARSE), "{label}");
            let archive = TempArchive::new(&bytes, "sparse");
            let refused = write_payload(&archive.0, entry, 5, &mut Vec::new())
                .expect_err("a sparse payload must not be written");
            assert!(
                matches!(refused, Error::Unsupported(_)),
                "{label}: {refused:?}"
            );
        }
    }

    /// An extension that describes no header — the archive cut just after
    /// it — reports nothing and does not error.
    #[test]
    fn an_orphaned_extension_reports_nothing() {
        let mut bytes = header_block("././@LongLink", 20, tar::EntryType::GNULongName).to_vec();
        bytes.extend_from_slice(&padded(b"a-name-for-nothing\0"));
        assert!(scan(&bytes).entries.is_empty());
    }

    /// `verify`'s `Complete` stands on a check `verify` makes: a candidate
    /// whose header no longer agrees with itself is not `Complete`.
    #[test]
    fn verify_does_not_answer_complete_for_a_header_that_no_longer_agrees() {
        let mut bytes = files(&[("a.txt", b"alpha")]);
        let mut scanner = TarSalvage::new();
        let candidate = scanner
            .next_candidate(&mut Cursor::new(bytes.clone()), 0)
            .unwrap()
            .expect("one header");
        assert_eq!(
            scanner
                .verify(&mut Cursor::new(bytes.clone()), &candidate)
                .unwrap(),
            SalvageStatus::Complete
        );
        bytes[0] ^= 0x01;
        assert_eq!(
            scanner.verify(&mut Cursor::new(bytes), &candidate).unwrap(),
            SalvageStatus::Partial
        );
    }

    // -------------------------------------------------------------------
    // Allocation: what the recording allocator can see
    // -------------------------------------------------------------------

    /// A header declaring 8 GiB over a file holding 100 bytes of it. tar
    /// streams, so no header field ever sizes a buffer — and the only
    /// instrument that can tell "nothing was allocated" from "the status
    /// came out right anyway" is the recording allocator.
    ///
    /// The assertion is on the ALLOCATION and is made first, so a change
    /// that started buffering a payload fails here rather than hiding
    /// behind a status that stays the same.
    #[test]
    fn an_eight_gigabyte_declaration_never_becomes_an_allocation() {
        let declared = 8u64 << 30;
        let mut bytes = header_block("huge.bin", declared, tar::EntryType::Regular).to_vec();
        bytes.extend_from_slice(&[0x5Au8; 100]);
        assert_eq!(
            tar::Header::from_byte_slice(&bytes[..BLOCK])
                .entry_size()
                .unwrap(),
            declared,
            "the fixture must really declare 8 GiB (GNU base-256)"
        );
        let archive = TempArchive::new(&bytes, "huge");

        let mut src = Cursor::new(bytes.clone());
        let ((out, written), largest) = crate::alloc_probe::largest_single_allocation(|| {
            let out = salvage_tar(
                &mut src,
                &SalvagePolicy {
                    max_entry: u64::MAX,
                    ..SalvagePolicy::default()
                },
            )
            .unwrap();
            let mut sink = io::sink();
            let written = write_payload(&archive.0, &out.entries[0], declared, &mut sink).unwrap();
            (out, written)
        });
        assert!(
            largest <= 1 << 20,
            "largest single allocation was {largest} bytes — an 8 GiB header field became a \
             buffer, which `max_whole_entry`'s `u64::MAX` says cannot happen"
        );
        // The LOWER bound: an assertion that is only an upper bound cannot
        // notice the probe's own absence (detach `alloc_probe`'s
        // `#[global_allocator]` and it reports 0). `find_next_header`
        // allocates a `SCAN_CHUNK` buffer on every scan, so that is a floor
        // the probe cannot report unless it is attached.
        assert!(
            largest >= SCAN_CHUNK,
            "largest single allocation was only {largest} bytes, below the {SCAN_CHUNK}-byte \
             buffer every scan allocates — the recording allocator is not attached"
        );
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].status, SalvageStatus::Partial);
        assert_eq!(out.entries[0].meta.size, Some(declared));
        assert!(!written);
    }

    /// A WHOLE entry eight times the size of anything the scanner buffers is
    /// scanned, verified and written without its payload ever becoming one
    /// allocation. The archive is built, and its cursor made, OUTSIDE the
    /// measured closure.
    #[test]
    fn a_whole_entry_is_written_without_being_buffered() {
        let payload = vec![0xC3u8; 8 << 20];
        let bytes = files(&[("big.bin", &payload)]);
        let archive = TempArchive::new(&bytes, "whole");
        let mut src = Cursor::new(bytes);

        let ((status, completed), largest) = crate::alloc_probe::largest_single_allocation(|| {
            let out = salvage_tar(&mut src, &SalvagePolicy::default()).unwrap();
            let mut sink = io::sink();
            let completed =
                write_payload(&archive.0, &out.entries[0], payload.len() as u64, &mut sink)
                    .unwrap();
            (out.entries[0].status, completed)
        });
        assert!(
            largest < 1 << 20,
            "largest single allocation was {largest} bytes for an {}-byte payload — the \
             payload was buffered",
            payload.len()
        );
        assert!(
            largest >= SCAN_CHUNK,
            "the recording allocator is not attached ({largest})"
        );
        assert_eq!(status, SalvageStatus::Complete);
        assert!(completed);
    }

    /// A GNU long name declaring (and holding) 1 MiB is refused before it is
    /// read, not after: [`MAX_LONG_NAME`] is checked against the declared
    /// length, ahead of the `vec!`. The header it described is still found,
    /// under its own name field.
    #[test]
    fn an_oversized_long_name_is_refused_before_it_is_allocated() {
        let declared = 1u64 << 20;
        let mut bytes =
            header_block("././@LongLink", declared, tar::EntryType::GNULongName).to_vec();
        bytes.extend_from_slice(&vec![b'n'; declared as usize]);
        bytes.extend_from_slice(&files(&[("own-name.txt", b"kept")]));
        let mut src = Cursor::new(bytes);

        let (out, largest) = crate::alloc_probe::largest_single_allocation(|| {
            salvage_tar(&mut src, &SalvagePolicy::default()).unwrap()
        });
        assert!(
            largest < 256 << 10,
            "largest single allocation was {largest} bytes — a {declared}-byte long name was \
             read into memory past MAX_LONG_NAME"
        );
        assert!(
            largest >= SCAN_CHUNK,
            "the recording allocator is not attached ({largest})"
        );
        assert_eq!(
            out.entries
                .iter()
                .map(|e| (e.meta.name.as_str(), e.status))
                .collect::<Vec<_>>(),
            vec![("own-name.txt", SalvageStatus::Complete)]
        );
    }

    /// The same for a pax header past [`MAX_PAX_EXTENSION`].
    #[test]
    fn an_oversized_pax_header_is_refused_before_it_is_allocated() {
        let record_len = 2usize << 20;
        let mut record = format!("{record_len} SCHILY.xattr.big=").into_bytes();
        record.resize(record_len - 1, b'x');
        record.push(b'\n');
        let mut bytes =
            header_block("PaxHeaders/x", record.len() as u64, tar::EntryType::XHeader).to_vec();
        bytes.extend_from_slice(&padded(&record));
        bytes.extend_from_slice(&files(&[("own-name.txt", b"kept")]));
        let mut src = Cursor::new(bytes);

        let (out, largest) = crate::alloc_probe::largest_single_allocation(|| {
            salvage_tar(&mut src, &SalvagePolicy::default()).unwrap()
        });
        assert!(
            largest < 512 << 10,
            "largest single allocation was {largest} bytes — a {record_len}-byte pax header \
             was read into memory past MAX_PAX_EXTENSION"
        );
        assert!(
            largest >= SCAN_CHUNK,
            "the recording allocator is not attached ({largest})"
        );
        assert_eq!(
            out.entries
                .iter()
                .map(|e| e.meta.name.as_str())
                .collect::<Vec<_>>(),
            vec!["own-name.txt"]
        );
    }

    // -------------------------------------------------------------------
    // v7 headers, the shifted twin, and ungateable sightings (Ruling 3-J)
    // -------------------------------------------------------------------

    /// Spells a checksum value into an eight-byte field.
    type Spelling = fn(u32) -> [u8; 8];

    /// GNU tar's and bsdtar's v7 checksum spelling, `%06o\0 `.
    const V7_GNU_SPELLING: fn(u32) -> [u8; 8] = |v| {
        let mut f = [0u8; 8];
        f.copy_from_slice(format!("{v:06o}\0 ").as_bytes());
        f
    };

    /// macOS `pax -x tar`'s spelling, `%07o\0`.
    const V7_PAX_SPELLING: fn(u32) -> [u8; 8] = |v| {
        let mut f = [0u8; 8];
        f.copy_from_slice(format!("{v:07o}\0").as_bytes());
        f
    };

    /// A spelling no writer this project measured uses — digits, then NULs.
    /// `tar.rs`'s reader accepts it (the field is read up to its first NUL).
    const UNMEASURED_SPELLING: fn(u32) -> [u8; 8] = |v| {
        let mut f = [0u8; 8];
        let text = format!("{v:o}");
        f[..text.len()].copy_from_slice(text.as_bytes());
        f
    };

    /// One v7 header, laid out the way GNU tar `--format=v7` lays it out —
    /// mode, uid and gid as `%07o\0`, size and mtime as `%011o\0`, a NUL
    /// typeflag, blank magic — with `magic` written over bytes 257..265 and
    /// the checksum field spelled by `spell`. Built by hand, so it proves
    /// agreement with this module's own reading of v7; the v7 writers test
    /// is the witness.
    fn v7_block(name: &str, size: u64, spell: fn(u32) -> [u8; 8], magic: [u8; 8]) -> [u8; BLOCK] {
        let mut b = [0u8; BLOCK];
        b[..name.len()].copy_from_slice(name.as_bytes());
        b[100..108].copy_from_slice(b"0000644\0");
        b[108..116].copy_from_slice(b"0000000\0");
        b[116..124].copy_from_slice(b"0000000\0");
        b[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
        b[136..148].copy_from_slice(b"14727046122\0");
        b[MAGIC_AT..MAGIC_AT + MAGIC_AND_VERSION_LEN].copy_from_slice(&magic);
        b[CHECKSUM_AT..CHECKSUM_AT + CHECKSUM_LEN].fill(b' ');
        let sum: u32 = b.iter().map(|&x| u32::from(x)).sum();
        b[CHECKSUM_AT..CHECKSUM_AT + CHECKSUM_LEN].copy_from_slice(&spell(sum));
        b
    }

    /// A whole v7 archive: each entry's header and padded payload, then the
    /// two-block end-of-archive marker.
    fn v7_archive(entries: &[(&str, &[u8])], spell: fn(u32) -> [u8; 8]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, data) in entries {
            out.extend_from_slice(&v7_block(name, data.len() as u64, spell, [0; 8]));
            out.extend_from_slice(&padded(data));
        }
        out.extend_from_slice(&[0u8; 2 * BLOCK]);
        out
    }

    /// The reviewer's reproducer, by hand: `gtar --format=v7`'s shape, three
    /// files whose names start one digit-offset from their payloads. With
    /// the first header's byte 0 flipped, the header seen one byte late
    /// agrees with its own checksum — and before Ruling 3-J it came back as
    /// two `Complete` rows named `.txt` holding shifted bytes, with `c.txt`
    /// never reported.
    #[test]
    fn a_v7_header_seen_one_byte_late_is_not_revived() {
        let files = [
            ("a.txt", &b"1st line\n"[..]),
            ("b.txt", b"2nd line\n"),
            ("c.txt", b"third\n"),
        ];
        let healthy = v7_archive(&files, V7_GNU_SPELLING);
        let reader = read_through_the_reader(&healthy).expect("the reader accepts v7");
        let out = scan(&healthy);
        assert_eq!(
            out.entries
                .iter()
                .map(|e| (e.meta.name.as_str(), e.status))
                .collect::<Vec<_>>(),
            reader
                .iter()
                .map(|(n, _, _, _)| (n.as_str(), SalvageStatus::Complete))
                .collect::<Vec<_>>()
        );

        let mut damaged = healthy.clone();
        damaged[0] ^= 0x01;
        assert!(
            header_checksum_agrees(&damaged[1..1 + BLOCK]),
            "the fixture must really carry a checksum-valid twin one byte late"
        );
        let out = scan(&damaged);
        assert_eq!(
            out.entries
                .iter()
                .map(|e| (e.meta.name.as_str(), e.status))
                .collect::<Vec<_>>(),
            vec![
                ("b.txt", SalvageStatus::Complete),
                ("c.txt", SalvageStatus::Complete)
            ],
            "the damaged entry is lost and nothing else is — no `.txt` twin, and `c.txt` found"
        );
        assert!(
            out.sightings.is_empty(),
            "a shifted copy is never a sighting: {:?}",
            out.sightings
        );
        let written = write_back(&damaged, &out);
        assert_eq!(written[0], (b"2nd line\n".to_vec(), true));
        assert_eq!(written[1], (b"third\n".to_vec(), true));
    }

    /// **The property criterion 3's v7 half stands on**, checked
    /// exhaustively rather than argued: for every checksum spelling a
    /// measured writer uses, and every typeflag byte that header could
    /// carry, the header itself clears criterion 3, and its copy seen `k`
    /// bytes late (`k` in `1..=7`) does not.
    ///
    /// Run twice, once per layer, so that each layer is shown to carry
    /// weight:
    ///
    /// - **with the genuine header intact**, every shifted copy is refused —
    ///   and with [`looks_like_a_shifted_twin`] removed from
    ///   [`clears_criterion_3`] this goes red, on the one shape the spelling
    ///   alone lets through: `"0005017\0"` with a SPACE typeflag, seen one
    ///   byte late, reads `"005017\0 "`, a perfectly spelled `%06o\0 `. This
    ///   test found that case on its first run;
    /// - **with the genuine header's mode field destroyed**, so that nothing
    ///   upstream of the copy looks like a header and the twin layer cannot
    ///   fire, every shifted copy is STILL refused except that one shape —
    ///   and with [`spelled_like_a_writer`] removed, this goes red on every
    ///   spelling. The residual is a `%07o\0` header with a space typeflag,
    ///   which no measured writer produces, whose mode field is also gone.
    #[test]
    fn every_writer_spelling_refuses_its_own_shifted_copy() {
        let spellings: [(&str, Spelling); 4] = [
            ("%06o\\0 (bsdtar, GNU tar)", V7_GNU_SPELLING),
            ("%6o\\0 (Seventh Edition)", |v| {
                let mut f = [0u8; 8];
                f.copy_from_slice(format!("{v:6o}\0 ").as_bytes());
                f
            }),
            ("%07o\\0 (pax -x tar, the tar crate)", V7_PAX_SPELLING),
            ("%07o  (pax -x ustar)", |v| {
                let mut f = [0u8; 8];
                f.copy_from_slice(format!("{v:07o} ").as_bytes());
                f
            }),
        ];
        let mut refused = 0usize;
        let mut residual = Vec::new();
        for destroy_mode in [false, true] {
            for (label, spell) in spellings {
                for typeflag in 0..=255u8 {
                    let mut header = v7_block("a.txt", 9, spell, [0; 8]);
                    header[156] = typeflag;
                    if destroy_mode {
                        header[100..108].copy_from_slice(b"garbage!");
                    }
                    header[CHECKSUM_AT..CHECKSUM_AT + CHECKSUM_LEN].fill(b' ');
                    let sum: u32 = header.iter().map(|&x| u32::from(x)).sum();
                    header[CHECKSUM_AT..CHECKSUM_AT + CHECKSUM_LEN].copy_from_slice(&spell(sum));
                    // A zero block in front, as an archive's previous payload
                    // padding would be, then the header and its payload.
                    let mut bytes = vec![0u8; BLOCK];
                    bytes.extend_from_slice(&header);
                    bytes.extend_from_slice(&padded(b"1st line\n"));
                    let len = bytes.len() as u64;
                    let mut src = Cursor::new(bytes.clone());
                    if !destroy_mode {
                        assert!(
                            clears_criterion_3(&mut src, BLOCK_U64, len, &bytes[BLOCK..2 * BLOCK]),
                            "{label}, typeflag {typeflag}: the genuine header must clear it"
                        );
                    }
                    for k in 1..=7usize {
                        let at = BLOCK + k;
                        if clears_criterion_3(&mut src, at as u64, len, &bytes[at..at + BLOCK]) {
                            let read = String::from_utf8_lossy(
                                &bytes[at + CHECKSUM_AT..at + CHECKSUM_AT + CHECKSUM_LEN],
                            )
                            .into_owned();
                            assert!(
                                destroy_mode,
                                "{label}, typeflag {typeflag}: the copy seen {k} byte(s) late \
                                 reads {read:?} and clears criterion 3"
                            );
                            residual.push((label, typeflag, k, read));
                        } else {
                            refused += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(
            residual
                .iter()
                .map(|(l, t, k, _)| (*l, *t, *k))
                .collect::<Vec<_>>(),
            vec![("%07o\\0 (pax -x tar, the tar crate)", b' ', 1)],
            "exactly one shape may pass with no header upstream of it: {residual:?}"
        );
        assert_eq!(refused, 2 * 4 * 256 * 7 - 1);
    }

    /// Ruling 3-J, F2 of Task 2's review: a healthy archive `stuffr list`
    /// reads, whose one header carries junk in its magic field, used to be
    /// "nothing recoverable" (exit 5). It is an ungateable SIGHTING — exit 3,
    /// naming the shape — and in a mixed archive, the gateable entries still
    /// come back at their ordinary code.
    #[test]
    fn a_header_this_build_cannot_gate_is_a_sighting_not_an_absence() {
        let mut junk = v7_block("j.txt", 4, V7_GNU_SPELLING, *b"JUNKJUNK").to_vec();
        junk.extend_from_slice(&padded(b"junk"));
        junk.extend_from_slice(&[0u8; 2 * BLOCK]);
        let reader = read_through_the_reader(&junk).expect("the reader accepts it");
        assert_eq!(reader.len(), 1);

        let err = salvage_tar(&mut Cursor::new(junk.clone()), &SalvagePolicy::default())
            .expect_err("nothing recoverable is not the truth here");
        assert!(matches!(err, Error::Unsupported(_)), "{err:?}");
        assert_eq!(err.exit_code(), 3);
        assert!(err.to_string().contains("magic field"), "{err}");

        // A v7 header whose checksum field no measured writer spells like
        // this: the other kind of sighting, named as such.
        let mut odd = v7_archive(&[("o.txt", b"odd")], UNMEASURED_SPELLING);
        assert!(read_through_the_reader(&odd).is_ok());
        let err = salvage_tar(&mut Cursor::new(odd.clone()), &SalvagePolicy::default())
            .expect_err("an unmeasured spelling is a sighting too");
        assert!(err.to_string().contains("v7"), "{err}");

        // Mixed: what CAN be gated comes back, at its ordinary code.
        odd.truncate(2 * BLOCK);
        odd.extend_from_slice(&files(&[("fine.txt", b"fine")]));
        let out = scan(&odd);
        assert_eq!(
            out.entries
                .iter()
                .map(|e| e.meta.name.as_str())
                .collect::<Vec<_>>(),
            vec!["fine.txt"]
        );
    }

    /// The half of Ruling 3-J that keeps the sighting honest: a header seen
    /// one byte late is never counted as one. An archive whose ONLY header
    /// is damaged, leaving nothing but its checksum-valid twin, really does
    /// hold nothing recoverable — `Ok` and empty, the CLI's exit 5 — for the
    /// ustar twin and the v7 twin alike.
    #[test]
    fn a_shifted_twin_is_never_a_sighting() {
        // Byte 0 flipped, and byte 0 zeroed (Task 2-N fix round 1, I1): a
        // zeroed byte 0 leaves the damaged header naming NOTHING, which must
        // not stop its checksum-valid copy one byte late from counting as a
        // copy here — it used to make it an exit-3 "may be perfectly
        // readable" sighting over an archive `stuffr list` refuses at exit 5.
        for (damage, zero) in [("^0x01", false), ("=0", true)] {
            let mut ustar = files(&[("a.txt", b"alpha")]);
            let mut v7 = v7_archive(&[("a.txt", b"1st line\n")], V7_GNU_SPELLING);
            for (label, bytes) in [("ustar", &mut ustar), ("v7", &mut v7)] {
                let label = format!("{label} {damage}");
                bytes[0] = if zero { 0 } else { bytes[0] ^ 0x01 };
                assert!(header_checksum_agrees(&bytes[1..1 + BLOCK]), "{label}");
                let out = salvage_tar(&mut Cursor::new(bytes.clone()), &SalvagePolicy::default())
                    .unwrap_or_else(|e| panic!("{label}: a twin is not a sighting: {e}"));
                assert!(out.entries.is_empty(), "{label}: {:?}", out.entries);
                assert!(out.sightings.is_empty(), "{label}: {:?}", out.sightings);

                // And in a mixed run the copy is no note either: it sits one
                // byte off the grid the surviving entry is on.
                let mut mixed = bytes.clone();
                mixed.truncate(2 * BLOCK);
                mixed.extend_from_slice(&files(&[("b.txt", b"beta")]));
                let out = scan(&mixed);
                assert_eq!(
                    out.entries
                        .iter()
                        .map(|e| e.meta.name.as_str())
                        .collect::<Vec<_>>(),
                    vec!["b.txt"],
                    "{label}"
                );
                assert!(out.sightings.is_empty(), "{label}: {:?}", out.sightings);
            }
        }
    }

    /// Task 2-N, N3: in a MIXED run a sighting used to be completely silent —
    /// the `JUNKJUNK` header `stuffr list` reads was simply absent, at exit
    /// 0, with nothing said. The run still reports what it got at its
    /// ordinary code (Ruling S-X), and the outcome now carries the sighting,
    /// with where it was, for the caller to print. Still never a row.
    #[test]
    fn a_mixed_run_carries_its_sightings_and_still_lists_none_of_them() {
        let mut bytes = v7_block("j.txt", 4, V7_GNU_SPELLING, *b"JUNKJUNK").to_vec();
        bytes.extend_from_slice(&padded(b"junk"));
        bytes.extend_from_slice(&files(&[("ok.txt", b"fine")]));
        assert_eq!(read_through_the_reader(&bytes).unwrap().len(), 2);

        let out = scan(&bytes);
        assert_eq!(
            out.entries
                .iter()
                .map(|e| (e.meta.name.as_str(), e.status))
                .collect::<Vec<_>>(),
            vec![("ok.txt", SalvageStatus::Complete)]
        );
        assert_eq!(
            out.sightings,
            vec![Sighting::new(TAR, 0, UNRECOGNISED_MAGIC_SHAPE)]
        );
        let note = describe_sightings(&out.sightings).expect("a sighting has a note");
        assert!(
            note.contains("offset(s) 0") && note.contains("stuffr list"),
            "{note}"
        );

        // And a healthy archive carries none — the note must never fire on
        // an archive with nothing wrong in it.
        let healthy = files(&[("a.txt", b"alpha"), ("b.txt", b"beta")]);
        assert!(scan(&healthy).sightings.is_empty());
        let v7 = v7_archive(&[("a.txt", b"1st line\n")], V7_GNU_SPELLING);
        assert!(scan(&v7).sightings.is_empty());
    }

    /// Task 2's re-review, N1: a v7 header laid out with `pax -x ustar`'s
    /// space-terminated numeric fields, a 100-byte name ending in an octal
    /// digit, and a measured `%06o\0 ` checksum. The window one byte before
    /// it then reads as a header of its own — mode `70000644`, size
    /// ` 00000000004`, checksum ` 030404\0` (spelled), blank magic — so the
    /// twin check judged the genuine header a shifted copy of ITSELF.
    /// Hand-built; no writer on this machine produces it.
    fn self_twin_block(size: u64) -> [u8; BLOCK] {
        let mut b = [0u8; BLOCK];
        b[..100].copy_from_slice(format!("{}7", "m".repeat(99)).as_bytes());
        b[100..108].copy_from_slice(b"0000644 ");
        b[108..116].copy_from_slice(b"0000000 ");
        b[116..124].copy_from_slice(b"0000000 ");
        b[124..136].copy_from_slice(format!("{size:011o} ").as_bytes());
        b[136..148].copy_from_slice(b"14727046122 ");
        b[CHECKSUM_AT..CHECKSUM_AT + CHECKSUM_LEN].fill(b' ');
        let sum: u32 = b.iter().map(|&x| u32::from(x)).sum();
        b[CHECKSUM_AT..CHECKSUM_AT + CHECKSUM_LEN].copy_from_slice(&V7_GNU_SPELLING(sum));
        b
    }

    /// `first`'s payload, then [`self_twin_block`] holding `middle`, then
    /// `third.txt`, as one v7 archive.
    fn self_twin_archive(first: &[u8], middle: &[u8]) -> (Vec<u8>, u64) {
        let mut bytes = v7_block("first.txt", first.len() as u64, V7_GNU_SPELLING, [0; 8]).to_vec();
        bytes.extend_from_slice(&padded(first));
        let middle_at = bytes.len() as u64;
        bytes.extend_from_slice(&self_twin_block(middle.len() as u64));
        bytes.extend_from_slice(&padded(middle));
        bytes.extend_from_slice(&v7_block("third.txt", 6, V7_GNU_SPELLING, [0; 8]));
        bytes.extend_from_slice(&padded(b"third\n"));
        bytes.extend_from_slice(&[0u8; 2 * BLOCK]);
        (bytes, middle_at)
    }

    /// N1, the reviewer's reproducer: as the middle of three entries, `list`
    /// read all three and `salvage` returned two at exit 0 with nothing said.
    /// A window whose name field begins in the previous entry's zero padding
    /// names nothing, so it is no header a copy could have been taken from —
    /// and the genuine header is recovered, `Complete`, with its own bytes.
    #[test]
    fn a_genuine_v7_header_is_never_judged_a_copy_of_itself() {
        let (bytes, middle_at) = self_twin_archive(b"first\n", b"midd");
        let window = &bytes[middle_at as usize - 1..middle_at as usize - 1 + BLOCK];
        let seen_early = tar::Header::from_byte_slice(window);
        assert!(
            spelled_like_a_writer(&window[CHECKSUM_AT..CHECKSUM_AT + CHECKSUM_LEN])
                && seen_early.mode().is_ok()
                && seen_early.entry_size().is_ok(),
            "the fixture must really carry the window the old twin check matched"
        );
        let reader = read_through_the_reader(&bytes).expect("the reader accepts it");
        assert_eq!(reader.len(), 3);

        let out = scan(&bytes);
        assert_eq!(
            out.entries
                .iter()
                .map(|e| (e.meta.name.clone(), e.status))
                .collect::<Vec<_>>(),
            reader
                .iter()
                .map(|(n, _, _, _)| (n.clone(), SalvageStatus::Complete))
                .collect::<Vec<_>>()
        );
        assert!(out.sightings.is_empty(), "{:?}", out.sightings);
        let written = write_back(&bytes, &out);
        assert_eq!(written[1], (b"midd".to_vec(), true));
    }

    /// N1's other half. When the byte before the genuine header is payload,
    /// not padding, the window one byte earlier DOES name something, and
    /// nothing in these bytes says which of the two is the copy — so the
    /// header is still refused. But a real shifted copy sits 1..7 bytes off
    /// the block boundaries of the archive it came from, and this one sits
    /// ON the boundaries of the entry recovered before it: it is counted as
    /// a sighting, which the run reports, instead of vanishing.
    #[test]
    fn a_header_refused_as_a_copy_on_the_archive_s_own_boundary_is_a_sighting() {
        let first = vec![b'x'; BLOCK];
        let (bytes, middle_at) = self_twin_archive(&first, b"midd");
        assert_eq!(read_through_the_reader(&bytes).unwrap().len(), 3);

        let out = scan(&bytes);
        assert_eq!(
            out.entries
                .iter()
                .map(|e| (e.meta.name.as_str(), e.status))
                .collect::<Vec<_>>(),
            vec![
                ("first.txt", SalvageStatus::Complete),
                ("third.txt", SalvageStatus::Complete)
            ]
        );
        assert_eq!(
            out.sightings,
            vec![Sighting::new(TAR, middle_at, POSSIBLE_SHIFTED_COPY_SHAPE)]
        );
    }

    /// **The witness for the spelling rule.** Every v7-capable writer on this
    /// machine — the platform `tar` and `gtar` with `--format=v7`, and `pax
    /// -x tar` — writes three files; salvage must recover them whole, and
    /// with the first header destroyed must lose that entry and nothing
    /// else. A writer whose spelling the rule did not know would fail the
    /// first half (its archive would be a sighting, not three entries).
    /// Python's `tarfile` has no v7 format: every format it writes carries
    /// `ustar` magic, and the reference-writer test covers those.
    #[test]
    fn every_v7_writer_s_archive_survives_a_destroyed_first_header() {
        let dir = std::env::temp_dir().join(format!(
            "stuffr-tar-salvage-v7-writers-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let tree = dir.join("tree");
        std::fs::create_dir_all(&tree).unwrap();
        let contents: [(&str, &[u8]); 3] = [
            ("a.txt", b"1st line\n"),
            ("b.txt", b"2nd line\n"),
            ("c.txt", b"third\n"),
        ];
        for (name, data) in contents {
            std::fs::write(tree.join(name), data).unwrap();
        }

        let mut archives: Vec<(String, std::path::PathBuf)> = Vec::new();
        for bin in ["tar", "gtar"] {
            let Some(tar_bin) = which(bin) else { continue };
            let archive = dir.join(format!("{bin}-v7.tar"));
            let status = std::process::Command::new(&tar_bin)
                .env("COPYFILE_DISABLE", "1")
                .arg("--format=v7")
                .arg("-cf")
                .arg(&archive)
                .arg("-C")
                .arg(&tree)
                .args(["a.txt", "b.txt", "c.txt"])
                .status()
                .unwrap();
            assert!(status.success(), "{bin} could not write a v7 archive");
            archives.push((format!("{bin} --format=v7"), archive));
        }
        if let Some(pax) = which("pax") {
            let archive = dir.join("pax-tar.tar");
            let strip = format!(",^{}/,,", tree.display());
            let status = std::process::Command::new(&pax)
                .env("COPYFILE_DISABLE", "1")
                .args(["-w", "-x", "tar", "-s", &strip, "-f"])
                .arg(&archive)
                .args(contents.iter().map(|(n, _)| tree.join(n)))
                .status()
                .unwrap();
            assert!(status.success(), "pax could not write a v7 archive");
            archives.push(("pax -x tar".into(), archive));
        }
        assert!(
            !archives.is_empty(),
            "no v7 writer found at all — this test proved nothing"
        );

        for (writer, archive) in &archives {
            let healthy = std::fs::read(archive).unwrap();
            assert!(
                magic_is_blank(&healthy[..BLOCK]),
                "{writer}: the fixture must really be v7"
            );
            let out = salvage_tar(&mut Cursor::new(healthy.clone()), &SalvagePolicy::default())
                .unwrap_or_else(|e| {
                    panic!("{writer}: its spelling is not one the rule knows: {e}")
                });
            assert_eq!(
                out.entries
                    .iter()
                    .map(|e| (e.meta.name.as_str(), e.status))
                    .collect::<Vec<_>>(),
                contents
                    .iter()
                    .map(|(n, _)| (*n, SalvageStatus::Complete))
                    .collect::<Vec<_>>(),
                "{writer}"
            );

            let mut damaged = healthy;
            damaged[0] ^= 0x01;
            let out = scan(&damaged);
            assert_eq!(
                out.entries
                    .iter()
                    .map(|e| (e.meta.name.as_str(), e.status))
                    .collect::<Vec<_>>(),
                vec![
                    ("b.txt", SalvageStatus::Complete),
                    ("c.txt", SalvageStatus::Complete)
                ],
                "{writer}: a destroyed first header must cost that entry and nothing else"
            );
            assert!(out.sightings.is_empty(), "{writer}: {:?}", out.sightings);
            let written = write_back(&damaged, &out);
            assert_eq!(written[0], (b"2nd line\n".to_vec(), true), "{writer}");
            assert_eq!(written[1], (b"third\n".to_vec(), true), "{writer}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------
    // Independent witnesses
    // -------------------------------------------------------------------

    fn which(bin: &str) -> Option<std::path::PathBuf> {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path).find_map(|dir| {
            let candidate = dir.join(bin);
            candidate.is_file().then_some(candidate)
        })
    }

    /// The checksum rule, checked on a header no code of this project's —
    /// and none of the `tar` crate's — wrote. Python's `tarfile` computes
    /// the POSIX sum itself; this project's reading of it must agree, and
    /// must disagree once one byte moves.
    #[test]
    fn the_checksum_rule_matches_its_definition_on_a_foreign_header() {
        let Some(python) = which("python3") else {
            eprintln!("python3 absent: this witness did not run");
            return;
        };
        let out = std::process::Command::new(python)
            .arg("-c")
            .arg(
                "import sys, tarfile\n\
                 t = tarfile.TarInfo('witness.txt'); t.size = 3; t.mtime = 1234567890\n\
                 sys.stdout.buffer.write(t.tobuf(tarfile.USTAR_FORMAT))\n",
            )
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let mut block = out.stdout;
        assert_eq!(block.len(), BLOCK);
        assert!(
            header_checksum_agrees(&block),
            "python's own checksum must agree"
        );
        block[0] ^= 0x01;
        assert!(
            !header_checksum_agrees(&block),
            "one byte moved must disagree"
        );
    }

    /// **The independent witness.** Every reference writer on this machine
    /// — the platform `tar` (bsdtar on macOS, GNU on the CI runner), `gtar`,
    /// and Python's `tarfile` in both its GNU and pax spellings — writes the
    /// same tree, including a name too long for a header's own field, so
    /// each exercises its own long-name extension (GNU `L` or pax `path`).
    /// Salvage must recover every file with its bytes, and must name every
    /// entry exactly as the ordinary reader does.
    ///
    /// None of those writers shares code with the `tar` crate, which is what
    /// the rest of this module's fixtures cannot say.
    #[test]
    fn every_reference_writer_s_archive_is_recovered_whole() {
        let dir =
            std::env::temp_dir().join(format!("stuffr-tar-salvage-writers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let tree = dir.join("tree");
        let long = "l".repeat(130);
        std::fs::create_dir_all(tree.join("sub")).unwrap();
        let files_in_tree: [(String, Vec<u8>); 3] = [
            ("a.txt".into(), b"alpha\n".to_vec()),
            (format!("sub/{long}.txt"), b"a long name\n".repeat(50)),
            ("sub/empty".into(), Vec::new()),
        ];
        for (name, data) in &files_in_tree {
            std::fs::write(tree.join(name), data).unwrap();
        }

        let mut archives: Vec<(String, std::path::PathBuf)> = Vec::new();
        for bin in ["tar", "gtar"] {
            let Some(tar_bin) = which(bin) else { continue };
            let archive = dir.join(format!("{bin}.tar"));
            let status = std::process::Command::new(&tar_bin)
                .arg("-cf")
                .arg(&archive)
                .arg("-C")
                .arg(&dir)
                .arg("tree")
                .status()
                .unwrap();
            assert!(status.success(), "{bin} could not write the tree");
            archives.push((bin.to_string(), archive));
        }
        if let Some(python) = which("python3") {
            for format in ["GNU_FORMAT", "PAX_FORMAT"] {
                let archive = dir.join(format!("python-{format}.tar"));
                let script = format!(
                    "import tarfile\n\
                     t = tarfile.open({archive:?}, 'w', format=tarfile.{format})\n\
                     t.add({tree:?}, arcname='tree')\n\
                     t.close()\n",
                    archive = archive.to_str().unwrap(),
                    tree = tree.to_str().unwrap(),
                );
                let out = std::process::Command::new(&python)
                    .arg("-c")
                    .arg(&script)
                    .output()
                    .unwrap();
                assert!(
                    out.status.success(),
                    "{}",
                    String::from_utf8_lossy(&out.stderr)
                );
                archives.push((format!("python {format}"), archive));
            }
        }
        assert!(
            !archives.is_empty(),
            "no reference tar writer found at all — this test proved nothing"
        );

        for (writer, archive) in &archives {
            let bytes = std::fs::read(archive).unwrap();
            let out = scan(&bytes);
            let reader = read_through_the_reader(&bytes)
                .unwrap_or_else(|e| panic!("{writer}: the reader must accept it: {e}"));
            assert_eq!(
                out.entries
                    .iter()
                    .map(|e| (e.meta.name.clone(), e.meta.size, e.meta.kind.clone()))
                    .collect::<Vec<_>>(),
                reader
                    .iter()
                    .map(|(n, s, k, _)| (n.clone(), Some(*s), k.clone()))
                    .collect::<Vec<_>>(),
                "{writer}: salvage and list must describe every entry alike"
            );
            let written = write_back(&bytes, &out);
            for (name, data) in &files_in_tree {
                let at = out
                    .entries
                    .iter()
                    .position(|e| e.meta.name == format!("tree/{name}"))
                    .unwrap_or_else(|| panic!("{writer}: tree/{name} was not recovered"));
                assert_eq!(
                    out.entries[at].status,
                    SalvageStatus::Complete,
                    "{writer}: {name}"
                );
                assert_eq!(&written[at], &(data.clone(), true), "{writer}: {name}");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
