# Legacy format fixtures

Fixtures for the read-only legacy formats registered in Phase 3b
(`crates/stuffr-formats/src/legacy/`). Each entry below records exactly how
its fixture was produced, so its provenance can be checked without re-running
anything.

Append one entry per fixture added, in the same shape.

**This file now documents fixtures built under three different provenance
styles, and a future editor must know which one applies before touching
anything.** Confusing them is the recurring failure mode this note exists to
head off — each style fails differently when mishandled.

1. **Hand-built, literal-hex style (`sample.lzh`).** This project wrote the
   bytes AND the expectations, and the expectations are recorded here as
   frozen hex, checked by nothing at test time. A hand-edit to the fixture's
   bytes can silently strand the literal hex below it — it would no longer
   describe the bytes on disk, and nothing would fail to say so. Regenerate
   the recorded values by hand (re-run `lha v`/`t`) if the bytes ever
   change.
2. **Hand-built, recompute-at-test-time style (`sample.arj`).** This project
   also wrote both the bytes and the expectations, but the expectations are
   derived from the same construction recipe every test run
   (`legacy::arj::tests::build_arj`), never from literals written here. A
   hand-edit to the fixture without a matching edit to the recipe fails the
   test that checks re-derivability, rather than silently stranding a
   comment.
3. **Borrowed, immutable-bytes style (the `unarc-rs` ARC/PAK/ZOO corpus,
   below).** Neither the bytes nor a construction recipe belong to this
   project — nobody here will ever regenerate them, and there is no recipe
   to recompute from. The method/name/size/CRC tables in that section exist
   **only** for human provenance and cross-checking; they are pinned by no
   test and must never become the source a test reads its expectations
   from. In particular, `ExpectedEntry::stored_crc` for these fixtures must
   be **parsed from each archive's own header bytes at test time** — never
   hardcoded from this file's tables, and never computed by decoding the
   payload and hashing the result (that would silently turn the CRC
   conformance property into a self-consistency check). A future editor who
   only reads this banner, and never reaches that section's own prose,
   should still know that rule from here.

---

## `hello.Z`

- **Format:** Unix `compress` (`.Z` / LZC), consumed by `legacy::compress_z`.
- **Producer:** the system `/usr/bin/compress` (verified present on this
  machine; not this project's own code, since `compress_z` is decode-only).
- **Input bytes:** the 44-byte ASCII string
  `the quick brown fox jumps over the lazy dog\n`.
- **Exact commands:**
  ```bash
  printf 'the quick brown fox jumps over the lazy dog\n' > /tmp/hello.txt
  /usr/bin/compress -c /tmp/hello.txt > crates/stuffr-formats/fixtures/legacy/hello.Z
  ```
- **Verification:** `xxd hello.Z | head -1` begins `1f9d 9074 ...` — magic
  `1f 9d`, matching the format's registered `MagicRule`. File is 51 bytes.
- **Expectation provenance: known by construction.** The plaintext is fixed
  and typed directly into the command above, so the expected decode output
  is the exact 44-byte string, not inferred from decoding anything — this is
  the strongest provenance available in this phase (see the phase's own
  task brief): a conformance or interop test that gets this fixture's
  expected output wrong is checking against ground truth typed by hand, not
  against the decoder's own opinion of itself.

---

## `sample.lzh`

- **Format:** LHA/LZH, consumed by `legacy::lha`.
- **Producer: hand-built, not any tool on this machine.** No tool available
  here can CREATE an `.lzh` archive: `lhasa` (installed via `brew install
  lhasa`, 0.6.0) is decompress-only (`lha l|v|t|x|p`, no add/create verb —
  see its own `lha` usage banner), and `delharc` (the Rust crate this
  container wraps) is a reader with no writer at all, by its own module doc
  ("This library does not provide high level methods for creating files").
  That absence is itself the finding the task brief asked this step to
  surface: there is no lhasa/delharc DISAGREEMENT to report, because there
  is no second implementation capable of producing the input in the first
  place. So the fixture is hand-assembled directly from the LHA level-1
  header layout (traced against `delharc 0.6.2`'s own parser,
  `src/header/parser.rs`'s `LhaHeader::read`), using the `-lh0-` ("store",
  no compression) method for both entries so no compression algorithm needs
  reimplementing — the archive is a byte-for-byte passthrough of its two
  entries' plaintext plus LHA's own header framing.
- **Two entries:**
  - `sample/hello.txt` — the 6-byte ASCII string `alpha\n`.
  - `sample/sub/b.bin` — the 5-byte ASCII string `beta\n`. The `/`-separated
    path is stored directly in the level-1 header's own `filename` field (no
    separate `EXT_HEADER_PATH` extra header): `delharc`'s
    `parse_pathname_to_str` splits on literal `/`, `\` and `0xFF` bytes,
    so this reads back as the two path segments `sample` and `sub/b.bin`
    joined into one path, exactly as if a real archiver had stored it that
    way.
- **Exact construction:** a throwaway Python script (not checked into the
  repo — the layout is documented here instead) built each entry as:
  `header_len(1) + csum(1) + compression(5) + compressed_size(4) +
  original_size(4) + last_modified(4, zero) + msdos_attrs(1, 0x20) +
  level(1, =1) + filename_len(1) + filename(N) + file_crc(2) + os_type(1,
  'U') + first_header_len(2, zero)`, followed by the raw payload bytes, with
  a single trailing `0x00` byte as the archive's end-of-archive marker.
  `header_len` is the byte count from (and including) itself through
  `first_header_len`'s own 2 bytes; `csum` is an 8-bit wrapping sum over
  every byte from `compression` through `first_header_len` inclusive
  (matching `delharc`'s own `Parser::read_exact`-driven accumulation
  exactly — traced field by field against its source, not guessed).
  `file_crc` is CRC-16/ARC (`delharc::crc::Crc16` — poly `0xA001`
  reflected, init 0, no xorout) of the entry's plaintext.
- **Verification, independent of `delharc`:**
  ```
  $ lha v sample.lzh
   PERMSSN    UID  GID    PACKED    SIZE  RATIO METHOD CRC     STAMP          NAME
  ---------- ----------- ------- ------- ------ ---------- ------------ -------------
  [Unix]     *****/*****       6       6 100.0% -lh0- f3aa *** ** ***** sample/hello.txt
  [Unix]     *****/*****       5       5 100.0% -lh0- 890e *** ** ***** sample/sub/b.bin
  ---------- ----------- ------- ------- ------ ---------- ------------ -------------
   Total         2 files      11      11 100.0%            Sep 14 02:29

  $ lha t sample.lzh
  sample/hello.txt        - Testing  :  .sample/hello.txt        - Tested
  sample/sub/b.bin        - Testing  :  .sample/sub/b.bin        - Tested

  $ lha xf sample.lzh   # extracted bytes diffed byte-for-byte against
                        # the plaintext above — identical.
  ```
  `lha v` independently confirms both paths, both CRC-16 values (`f3aa`,
  `890e`) and the `-lh0-` method; `lha t` independently verifies both
  entries' CRC-16 against lhasa's OWN decoder; `lha xf` independently
  decodes both entries and their bytes matched the plaintext exactly. This
  is `lhasa` 0.6.0, an implementation wholly independent of `delharc`,
  agreeing with what `delharc` itself reports (see
  `legacy::lha::tests::lha_conforms`'s own fixture and provenance string).
- **Expectation provenance: lhasa's own decode (`lha v`/`lha t`/`lha x`),
  not delharc's.** That is the entire reason this fixture exists in Phase 3b
  rather than 3c, per the task brief. No disagreement between the two
  implementations was found — both report identical paths, sizes, CRC-16
  values and plaintext.

---

## `sample.arj`

- **Format:** ARJ, consumed by `legacy::arj`.
- **Spec consulted:** "ARJ TECHNICAL INFORMATION", April 1993 (ARJ Software
  Inc.'s own format notes, widely mirrored; the copy read for this task is
  <https://www.opennet.ru/docs/formats/arj.txt>) — for the general shape:
  header id `0x60 0xEA`, a basic-header CRC-32, the "zero-length header
  size means end of archive" convention, and the extended-header
  size-prefixed-then-zero-terminated framing.
- **Producer: hand-built, not any tool on this machine, and with no
  independent witness at all — the weakest provenance in this phase.**
  `arj`/`unarj` are not in Homebrew and nothing else on this machine reads
  or writes ARJ; unlike `sample.lzh` (independently verified against
  `lhasa`, a decoder wholly separate from `delharc`) and `hello.Z` (built by
  the real `/usr/bin/compress`), this fixture has no second implementation
  to check it against. **The exact byte layout was therefore traced
  field-by-field from `unarj-rs` 0.2.1's own parser source** —
  `main_header.rs::MainHeader::load_from`, `local_file_header.rs::
  LocalFileHeader::load_from`, and `arj_archive.rs`'s `read_header`/
  `read_extended_headers`/`get_next_entry`/`read` — rather than purely from
  the published spec above, because that is what determines whether the
  fixture actually decodes under the crate this container wraps, and the
  spec text's own field names for a few bytes (e.g. whether offset 8 holds
  one creation timestamp or two separate ones) do not matter to a minimal
  fixture that zeroes that range regardless. **Stated plainly, per the task
  brief: the expectation this fixture is checked against was derived from
  reading `unarj-rs`'s own parsing logic, so a mistake shared between this
  fixture's construction and that parser would agree with itself and pass
  completely undetected.** `legacy::arj::tests::build_arj` is the
  construction expressed as real, checked-in Rust (unlike `sample.lzh`'s
  throwaway, unchecked-in Python script) — run
  `the_checked_in_fixture_matches_its_own_construction_recipe` to reproduce
  these exact bytes from that function.
- **Two entries, both `compression_method = 0` (Stored)** so no compression
  algorithm needs reimplementing to build this fixture, the same choice
  `sample.lzh` makes with `-lh0-`:
  - `sample/hello.txt` — the 6-byte ASCII string `alpha\n`.
  - `sample/sub/b.bin` — the 5-byte ASCII string `beta\n`.
  Both names are stored directly in each local file header's own
  null-terminated `name` field (no separator translation applied anywhere
  in `unarj-rs` or in `legacy::arj`), so `/` reads back as a literal path
  separator exactly as written. **Each local header sets `arj_flags =
  0x10` (`PATHSYM_FLAG`) accordingly**, which it did not until the Phase 3b
  fix wave: the spec's local-file-header table reads "(0x10 =
  PATHSYM_FLAG) indicates filename translated (`\` changed to `/`)", and a
  cleared flag beside a `/`-bearing name entitles a spec-conformant reader
  to take `/` as a literal character in a flat filename. `unarj-rs` never
  reads the byte, so nothing in this repository could have caught it —
  exactly the parser-agrees-with-itself shape the `file_type = 2`
  deviation below already had. The MAIN header's own `flags` byte stays
  `0`, correctly: that bit describes the ARCHIVE NAME, which this fixture
  leaves empty.
- **Byte layout, traced from the crate's own field-by-field parse** (each
  local file header's fixed prefix, and the main header's, are both exactly
  30 bytes — `header_size`, the header content's OWN first byte, is 30 in
  both, at or below the crate's extension thresholds `STD_HDR_SIZE`/
  `FIRST_HDR_SIZE`, so neither writes the crate's conditional 4-byte
  extension block):
  - Main header content (32 bytes: the 30-byte fixed prefix above, then an
    empty name and an empty comment, each a lone `0x00`): `header_size(1,
    =30) + archiver_version_number(1) + min_version_to_extract(1) +
    host_os(1, =2 Unix) + flags(1) + security_version(1) + file_type(1, =2
    — the ARJ spec's main-header table requires this field equal 2;
    `unarj-rs` never validates it, so an earlier version of this fixture
    shipped it as 0 and nothing in this repo noticed until the task-6
    review checked the fixture against the published spec directly) +
    reserved(1) + creation_date_time(4, zero) + compr_size(4, zero) +
    archive_size(4, zero) + security_envelope(4, zero) +
    file_spec_position(2, zero) + security_envelope_length(2, zero) +
    encryption_version(1) + last_chapter(1) + name(1, empty) + comment(1,
    empty)`.
  - Each local file header's content (30-byte fixed prefix + name + two
    NULs): `header_size(1, =30) + archiver_version_number(1) +
    min_version_to_extract(1) + host_os(1, =2 Unix) + arj_flags(1, =0x10
    PATHSYM_FLAG, since both names use `/`) +
    compression_method(1, =0 Stored) + file_type(1, =0 Binary) +
    reserved(1) + date_time_modified(4, zero — no valid calendar date, so
    this container's `dos_mtime` reports `None` for both entries) +
    compressed_size(4, = the entry's byte length, since Stored) +
    original_size(4, = the same length) + original_crc32(4, CRC-32/
    IEEE of the plaintext) + file_spec_position(2, zero) +
    file_access_mode(2, zero) + first_chapter(1) + last_chapter(1) +
    name(N, e.g. `sample/hello.txt`) + name_terminator(1, `0x00`) +
    comment(1, empty, `0x00`)`.
  - Every header (main and local) is wrapped identically: magic `0x60 0xEA`
    + a little-endian `u16` content length + the content above + a
    little-endian `u32` CRC-32/IEEE over the content + a little-endian
    `u16` zero, the "no extended headers" terminator
    `read_extended_headers` reads immediately after every header.
  - Each local file header's wrapped envelope is followed directly by that
    entry's raw payload bytes (verbatim, since `Stored`).
  - The archive ends with `0x60 0xEA` followed by a `u16` zero — `
    read_header` recognises a zero content length as "no more headers" and
    returns *before* reading any CRC after it, so this marker is exactly
    four bytes, not the six a non-empty header would need.
  - 173 bytes total: main header (32-byte content, wrapped with magic +
    u16 length + 4-byte CRC + u16 terminator = 42 bytes) + entry 1 (30-byte
    header prefix + 16-byte name `sample/hello.txt` + 2 NULs = 48-byte
    content, wrapped = 58 bytes, + 6 payload bytes = 64) + entry 2 (30 +
    16-byte name `sample/sub/b.bin` + 2 = 48-byte content, wrapped = 58
    bytes, + 5 payload bytes = 63) + 4-byte end marker: 42 + 64 + 63 + 4 =
    173, matching `ls -l sample.arj`.
- **`archiver_version_number = 0` and `min_version_to_extract = 0`, in the
  main header and in both local headers: checked against the spec and left
  as they are, deliberately.** The published table gives these two bytes as
  bare `1 archiver version number` / `1 minimum archiver version to
  extract` with no stated range, no reserved value and no rule that 0 is
  illegal, so unlike `file_type` (which the table requires equal 2) and
  `arj_flags` (whose meaning the table states outright) there is nothing
  here to conform TO. Real ARJ would write its own release number; this
  fixture was not written by ARJ, and inventing a plausible-looking version
  would make it look more provenanced than it is — which is the opposite of
  what this manifest is for. `unarj-rs` reads neither byte
  (`main_header.rs`/`local_file_header.rs` parse them into fields nothing
  consults), so the choice is inert in both directions. Recorded here so a
  future reader meets a ruling rather than an oversight.
- **Verification: none independent — see above.** The only checks run were
  internal consistency ones: `legacy::arj::tests::arj_conforms` (the
  fixture read back through `unarj-rs` itself, which is not independent of
  the construction) and `the_checked_in_fixture_matches_its_own_
  construction_recipe` (the checked-in bytes match `build_arj`'s output
  exactly, which proves re-derivability, not correctness against any
  outside ground truth).

---

## The `unarc-rs` 0.6.3 borrowed corpus (ARC/PAK, ZOO) — Phase 3c Task 2

Fourteen archives in `fixtures/legacy/arc/` (ten: four `.pak`, six `.arc`) and
`fixtures/legacy/zoo/` (four `.zoo`), for the ARC/PAK and ZOO **read-only**
decoders landing in Phase 3c Tasks 3–4. All fourteen are byte-for-byte copies
of files from `unarc-rs` 0.6.3's own `tests/` tree — no bytes here were
written by this project.

**Provenance.** `unarc-rs` 0.6.3, downloaded from crates.io (`cargo download`
equivalent — the extracted `.crate` tarball, not a git checkout).
`Cargo.toml` declares `license = "MIT OR Apache-2.0"` (verified directly by
reading the file: `license = "MIT OR Apache-2.0"` on its own line, package
`unarc-rs`, version `0.6.3`, repository
`https://github.com/mkrueger/unarc-rs`). The package's own `LICENSE` file
(11,357 bytes) is the Apache-2.0 full text; no separate MIT text file ships
inside this downloaded package (`find <extracted crate> -maxdepth 1 -iname
'*license*'` finds exactly one file). The SPDX `license` field in `Cargo.toml`
is what is relied on here — a dual `MIT OR Apache-2.0` grant lets the
downstream user (this project) pick either license, and a permissive licence
does not require both texts to ship in every redistribution to be valid. This
is recorded so a future reader does not mistake the single bundled file for
the whole story.

**The crate itself is disqualified as a dependency — bytes only, never code.**
Same three reasons the Phase 3c design doc gives: an unconditional MSRV of
rustc 1.95 via `delharc = "0.8.0"` (six minors past this project's 1.88 floor
— the same `delharc` 0.8 line already ruled out for LHA in Phase 3b, see this
file's `sample.lzh` section and `crates/stuffr-formats/Cargo.toml`'s own
pin note), vendored C++ via `unrar = "0.5.8"`, and a second zip
(`zip = "8.6.0"`) and tar (`tar = "0.4"`) stack duplicating what
`stuffr-formats` already carries. Confirmed directly in
`unarc-rs-0.6.3/Cargo.toml`'s `[dependencies]` table, not assumed. Only the
test corpus under `tests/` is reused; nothing here imports or calls into
`unarc_rs`.

**The expectation is the CRC-16 inside each file, not anything we or
`unarc-rs` assert.** Every ARC/PAK entry and every ZOO entry carries a
per-entry CRC-16/ARC (`crate::legacy::crc::crc16_arc`, polynomial `0xA001`,
pinned in Phase 3c Task 1 against the published check value `"123456789"` →
`0xBB3D`) computed by the *original* archiving tool, decades before this
project existed. The conformance property Task 1 built checks stuffr's own
decoder output against that stored value — a witness independent of both
`unarc-rs` and of this project. **Following `sample.arj`'s style, not
`sample.lzh`'s:** the per-entry `stored_crc` (and method/name/size) values
below are recorded here for human provenance and cross-checking, but
Task 3/4's actual `ExpectedEntry::stored_crc` values must be **parsed from
each archive's own header bytes at test time**, by code, the way
`legacy::arj::tests::build_arj` derives `sample.arj`'s expectations from its
own construction recipe every run — never hardcoded from the hex literals in
this manifest, and **never computed by decoding the payload and hashing the
result**. That second form would silently turn the CRC property back into a
self-consistency check (decode, hash your own output, compare to itself) —
exactly the defect class Task 1's fix round closed for the codec side
(`stored_crc` must be transcribed from bytes the archive itself supplies, not
derived from what our own decoder produces). The byte offsets in the two
subsections below are what a header parser must read to get `stored_crc`
independently of decoding.

**Independent measurement method.** All fields below (method byte, name,
compressed/original size, stored CRC-16) were read directly from each
archive's raw bytes by a throwaway Python script (not checked into the repo;
kept in the session scratchpad), which reimplements the ARC and ZOO header
layouts from scratch against `unarc-rs`'s own struct definitions
(`src/arc/local_file_header.rs` + `src/arc/arc_archive.rs`'s `read_header`;
`src/zoo/dirent.rs` + `src/zoo/zoo_header.rs`) — i.e. the *format*, not the
*crate*, was consulted, the same way Phase 3b traced `sample.arj`'s byte
layout from `unarj-rs`'s parser source without running `unarj-rs` itself.
`unarc-rs`'s own tests (`tests/arc_decompression.rs`,
`tests/zoo_decompression.rs`) were read afterward only as a **cross-check**,
never as the source of truth — their asserted method names agree with every
figure below, which is corroborating, not foundational.

### ARC header layout (as measured)

Each entry: a `0x1A` marker byte, then a 28-byte fixed record — `method(1) +
name(13, NUL-padded) + compressed_size(u32 LE) + date_time(u32 LE, packed
DOS) + crc16(u16 LE) + original_size(u32 LE)` — then that many bytes of
payload. `method == 0` immediately after a `0x1A` marks end-of-archive (a
2-byte marker, no trailing record). This is the ARC format from
`ArcArchive::HEADER_SIZE = 28`/`ID = 0x1A`, confirmed against every file
below (every computed payload range stayed in-bounds; `store.arc`'s single
entry's payload was also byte-for-byte diffed against `unarc-rs`'s own
bundled `LICENSE` file and matched exactly, 11,357 bytes).

| file | entry name | method byte | method | compressed | original | stored CRC-16 |
|---|---|---|---|---|---|---|
| `arc/store.arc` | `LICENSE` | 2 | Unpacked (Stored) | 11357 | 11357 | `0xB065` |
| `arc/crunch.arc` | `LICENSE` | 8 | Crunched | 5309 | 11357 | `0xB065` |
| `arc/crunch2.arc` | `LICENSE` | 8 | Crunched | 5258 | 11357 | `0xB065` |
| `arc/squashed.arc` | `LICENSE` | 9 | Squashed | 5279 | 11357 | `0xB065` |
| `arc/wrongcrc16.arc` | `LICENSE` | 2 | Unpacked (Stored) | 11357 | 11357 | `0xB065` (see below — payload is NOT the 0xB065 content) |
| `arc/cpm.arc` entry 1 | `DDTZ.COM` | 4 | Squeezed (RLE+Huffman) | 9348 | 9984 | `0xB3F0` |
| `arc/cpm.arc` entry 2 | `READ.COM` | 3 | RLE90 (Packed) | 67 | 128 | `0xC093` |
| `arc/license.pak` | `LICENSE` | 11 | Distilled | 4246 | 11357 | `0xB065` |
| `arc/license_crunched.pak` | `LICENSE` | 8 | Crunched | 5255 | 11357 | `0xB065` |
| `arc/license_squashed.pak` | `LICENSE` | 9 | Squashed | 5279 | 11357 | `0xB065` |
| `arc/license_crushed.pak` | `LICENSE` | 10 | Crushed | 5261 | 11357 | `0xB065` |

**The four `.pak` files carry 10 bytes after their 2-byte EOF marker; the six
`.arc` files carry none.** Measured directly, not inferred: `license.pak`,
`license_crunched.pak`, `license_squashed.pak` and `license_crushed.pak` each
end `... 1a 00 fe 02 01 00 00 00 00 00 fe 00` — the ordinary `0x1A 0x00`
end-of-archive marker, followed by the identical ten bytes `fe 02 01 00 00 00
00 00 fe 00` in all four files, with nothing after them (confirmed against
each file's own size: header + payload + 2-byte marker + these 10 bytes
accounts for the entire file, e.g. `license.pak` is exactly `29 + 4246 + 2 +
10 = 4287` bytes). `store.arc`, `crunch.arc`, `crunch2.arc`, `squashed.arc`,
`wrongcrc16.arc` and `cpm.arc` all end at the 2-byte marker with no trailing
bytes at all.

**These ten bytes are unexplained.** Nothing in `unarc-rs`'s own `arc`
module reads or references them — `ArcArchive`'s `FileType` enum
(`arc/local_file_header.rs`) is never constructed or consulted by
`arc_archive.rs`, `read_header`, or anywhere else in the crate that was
checked — and no short reading of the classic ARC/PAK header layout traced
for the tables above accounts for a trailing 10-byte record after the
EOF marker. Rather than guess what they are, this manifest records only what
is certain: they exist, they are byte-identical across all four `.pak`
fixtures, and `unarc-rs`'s own reader ignores them completely because
`read_header` returns as soon as it sees `0x1A 0x00`, never scanning past
it.

**The consequence for Task 3 is what matters, independent of the
explanation:** an ARC/PAK reader must stop consuming input at the EOF
marker and must **not** assert that the marker coincides with end of file —
a reader written to require exact end-of-file at the marker (the way several
containers already in this project assert full consumption) will fail on
these four `.pak` fixtures for a reason invisible until this note. Trailing
bytes after a valid EOF marker must be tolerated (ignored), not treated as
corruption or as a sign more entries remain.

**Do not read `license_crushed.pak`'s name as evidence it is `crunch`'s
scope.** ARC's method table has both a `Crunched` family (methods 5–8, one
LZW variant with an RLE90 pre/post pass — all four numbers decode through the
identical routine in `unarc-rs`, and presumably must in any reader, since
nothing distinguishes them but the version of the tool that wrote them) *and*
a separate, later `Crushed` method (10, a different LZW variant, no RLE
pass) — "crushed" and "crunched" are two different methods by design, not a
spelling variant of one. This file measures as method **10**, Crushed, not
part of the 5–8 Crunched family — exactly the trap the task brief's "a
filename is not a method identifier" warning names. Likewise
`license_squashed.pak` (method 9, Squashed — no RLE pass, distinct from
`Crunched`) and `license.pak` (method 11, Distilled) are each their own
method, not aliases.

### Two expected-output files, borrowed alongside the archives — Phase 3c Task 3

`arc/DDTZ.COM` (9,984 bytes) and `arc/READ.COM` (128 bytes) are byte-for-byte
copies of the two files of the same names in `unarc-rs` 0.6.3's own
`tests/arc/` tree — the plaintext `cpm.arc`'s two entries decode to. Same
provenance, same licence and the same **borrowed, immutable-bytes** style as
the archives above: nobody here will regenerate them, and there is no recipe
to recompute them from. Verified identical to the crate's copies by SHA-256
at the time of borrowing (`fc2769fe…d2c9` and `25784f64…7e79`).

**Why they were borrowed at all, when the ten archives were not enough.**
Container-conformance fixture property 5 compares each entry's decoded bytes
against `ExpectedEntry::content`, so a fixture needs the plaintext from
somewhere. For every *stored* entry that somewhere is the archive itself —
`store.arc`'s method-2 payload IS the LICENSE content, a byte range with no
decoder involved, and `legacy::arc`'s tests slice it directly and reuse it as
the expectation for `crunch.arc`, `crunch2.arc`, `squashed.arc`,
`license_crunched.pak` and `license_squashed.pak`. `cpm.arc` has no such
sibling: both of its entries are compressed (Squeezed and RLE90) and the
corpus holds no stored copy of either file. The only alternative would have
been to let this project's own decoder supply the expectation it is then
checked against, which is precisely the self-agreement this manifest's banner
exists to prevent.

**They are bound to the archive by the archive's own CRC, not by anyone's
decoder.** `crc16_arc(DDTZ.COM)` is `0xB3F0` and `crc16_arc(READ.COM)` is
`0xC093` — exactly the values `cpm.arc`'s two headers carry (the table above,
measured independently of both). `legacy::arc::tests::the_borrowed_expected_
outputs_match_the_crc_their_archive_stores` re-derives that agreement on every
test run, with no decompression anywhere in the loop, so a future edit to
either `.COM` file goes red before any conformance test does. The same test
checks `store.arc`'s raw payload against its own stored `0xB065`, which is what
qualifies that byte range to stand in as the LICENSE expectation.

### `date` and `time` are the LOW and HIGH halves of that `u32` — Phase 3c Task 3

The table above reads the field as `date_time(u32 LE, packed DOS)` without
committing to which half is which, and the distinction turns out to matter.
ARC's header stores `date` first and `time` second, so the little-endian `u32`
is `date | (time << 16)`. `unarc-rs`'s `DosDateTime` takes the opposite halves
(`(self.0 >> 25) & 0x7F` for the year, `self.0 & 0x1F` for the seconds), and
under that reading `cpm.arc`'s two entries have **month 0** — not a date at
all. Under the reading used by `legacy::arc` they are 1985-11-20 00:00:38 and
1985-11-20 00:01:52, which is a plausible stamp for a CP/M archive, and
`crunch.arc`'s becomes 2024-05-16 23:08:26 rather than a month-8 date in 2072.

**Settled by measurement, not left as a reading of the spec.** The swapped
order is falsified independently by all ten borrowed archives — re-derived
from the bytes, not transcribed from a review:

| fixtures | date-low (this reading) | swapped (`unarc-rs`'s) |
|---|---|---|
| `arc/cpm.arc` #1 | 1985-11-20 00:00:38 | **1980-00-19** — month 0, not a date |
| the four `.pak`s | 2025-12-16 16:18:58 | **2045-02-29** — a 29 February in a non-leap year |
| the five other `.arc`s | 2024-05-16 23:08:26 | 2072-08-13 11:05:32 |

Two impossibilities and one implausibility (a 2072 stamp on a 2024 corpus)
against four plausible ones — 1985 for a CP/M archive, 2024-25 for a corpus
assembled then — plus the structural argument above. A future reader must not
"correct" this toward `unarc-rs`. The cost had it been wrong would have been a
wrong timestamp on `stuffr list`, never wrong data: no conformance property
reads `mtime`.

### ZOO header layout (as measured)

The archive header is `"ZOO 2.10 Archive."` (17 bytes) padded to a 20-byte
text field, then `zoo_tag(u32 LE, must be 0xFDC4A7DC) + zoo_start(u32 LE) +
zoo_minus(u32 LE) + major_ver(u8) + minor_ver(u8)`, at which point the true
on-disk classic header ends (34 bytes) — `zoo_start` is the authoritative
pointer to the first directory entry and was used directly rather than
assuming a fixed offset; it independently confirmed `zoo_start = 42` and byte
42 does carry the `0xFDC4A7DC` tag in all four fixtures, so the extra 8
bytes between the 34-byte classic header and offset 42 are archive-format
padding this parser does not need to interpret. **Caution for a future
reader:** `unarc-rs`'s own `ZooHeader::load_from` reads a fixed 46-byte
buffer that runs 12 bytes past the real 34-byte header and into the first
directory entry's own bytes before `zoo_archive.rs` seeks back to
`zoo_start` — so any field this manifest might have reported from bytes
34–45 (there are none of interest here) would have been reading directory-entry
bytes mislabeled as header fields, not a stuffr-specific mistake, an
artifact of how the crate's struct is laid out. `major_ver`/`minor_ver` (both
measured as `2`/`0` across all four fixtures) sit safely inside the real
34-byte header and are not affected.

Each directory entry is `zoo_tag(u32 LE) + dir_type(u8) + method(u8) +
next(u32 LE) + offset(u32 LE, absolute file position of payload) +
date_time(u32 LE) + crc16(u16 LE) + original_size(u32 LE) +
compressed_size(u32 LE) + major_ver(u8) + minor_ver(u8) + deleted(u8) +
struc(u8) + comment(u32 LE) + cmt_size(u16 LE) + name(13, NUL-padded) +
var_dir_len(u8) + tz(u8) + dir_crc(u32 LE) + namlen(u8) + dirlen(u8)` — 59
bytes fixed, from `DIRENT_HEADER_SIZE`. `next == 0` on a *fully present*
entry means "last real entry"; all four fixtures here additionally carry a
**short terminal marker after the last real entry** — 56 bytes, not 59 (the
archive ends 3 bytes into what would be the fixed record), but the `next`
field at byte offset 6 is fully present and reads `0` within those 56 bytes,
so a reader must not require the full 59-byte record before checking `next`
for the terminator, only enough of it (the `next` field alone: 10 bytes in)
to see the terminator's `next == 0`. Confirmed byte-for-byte, not assumed:
all four fixtures end with the identical 56-byte tail
`dca7c4fd0200000000…00fc83` (tag + `dir_type=2` + zeros + two bytes that
land inside what would be `dir_crc`'s field, immaterial since `next` already
read `0`). **Worth flagging for Task 4's reader, not just this manifest**:
`unarc-rs`'s own `get_next_entry` does an unconditional `read_exact` of the
full 59-byte buffer and would raise an I/O error on this exact shape if it
were ever called a second time — none of `unarc-rs`'s own tests do call it
twice, so this edge case is untested by the crate that wrote these fixtures.

| file | entry name | method byte | method | compressed | original | stored CRC-16 |
|---|---|---|---|---|---|---|
| `zoo/store.zoo` | `license` | 0 | Stored | 11357 | 11357 | `0xB065` |
| `zoo/default.zoo` | `license` | 1 | Compressed (old LZW, `salzweg`) | 5282 | 11357 | `0xB065` |
| `zoo/high_per.zoo` | `license` | 2 | CompressedLh5 (delharc LH5) | 4003 | 11357 | `0xB065` |
| `zoo/wrongcrc16.zoo` | `license` | 0 | Stored | 11357 | 11357 | `0xB065` (see below — payload is NOT the 0xB065 content) |

### Step 3 verdict: does the corpus cover what an ARC/ZOO reader must support?

**Yes, against the master design's own scope, with one honestly-flagged gap
that does not block Tasks 3–4.**

The master design (`~/Development/Thomas/superpowers/stuffr/specs/
2026-08-25-stuffr-compression-tool-design.md`) names ARC's required method
set in three words: "RLE90 + squeeze + crunch". Measured coverage:

- **RLE90 (method 3):** `arc/cpm.arc` entry 2 (`READ.COM`). Present in no
  other borrowed file.
- **Squeeze (method 4):** `arc/cpm.arc` entry 1 (`DDTZ.COM`). Present in no
  other borrowed file.
- **Crunch (methods 5–8, one decode routine):** method 8 specifically, in
  four files (`crunch.arc`, `crunch2.arc`, `license_crunched.pak`, and — see
  Ruling D below — `license_cypted.arc`, not borrowed). Methods 5–7 have no
  fixture at all, but `unarc-rs`'s own decoder (and, by the design doc's
  reasoning, any reader following the same table) routes all four numbers
  through one routine, so 8 stands in for the family the same way `xz`/`lzma`
  share one backend in this project's own codec tier split.
- **Stored (methods 1 / 2):** method 2 covered by `store.arc` and both
  `.pak`/`.arc` "stored-shape" entries. **Method 1 has ZERO coverage in this
  corpus — measured, and confirmed twice** (the from-scratch parser found no
  method-1 entry anywhere in the fourteen files, and neither does a `grep`
  of every measured method byte in the two tables above). That much is
  fact, derived from bytes on disk.
  **Ruling F — what follows is NOT measured, and an earlier draft of this
  manifest stated it with the same authority as the tables above, which was
  wrong.** This manifest previously asserted that method 1 is "an old,
  pre-5.21 header shape without the trailing `original_size` field (24 bytes
  instead of 28)". That claim is inherited domain knowledge about the
  historical ARC format, not something derived from any byte in this
  corpus — this corpus contains no method-1 entry to derive it from. Worse,
  it is **contradicted by the one piece of evidence this repo does have**:
  `unarc-rs`'s own `arc/local_file_header.rs` parses method 1 and method 2
  through the exact same code path (`CompressionMethod::Unpacked(1)` and
  `Unpacked(2)` are the only two arms that map to `Unpacked`, and
  `LocalFileHeader::load_from` reads one fixed 28-byte record regardless of
  which of the two the method byte says), so the one reference implementation
  in reach of this task treats methods 1 and 2 as identical at 28 bytes, not
  24. Separating what is known from what is believed: **measured (twice)** —
  this corpus has no method-1 fixture; **measured, in source** — the one
  reference parser available treats method 1 identically to method 2, both
  28 bytes; **unverified belief, provenance unclear** — that some historical,
  pre-5.21 ARC tool wrote a genuinely different, shorter 24-byte header for
  method 1. This repository has no fixture, no tool output and no spec text
  in hand to confirm or refute that belief either way, so it is recorded
  here as an open question, not as settled fact.
  The consequence for Task 3, stated explicitly rather than left implicit:
  **treating method 1 identically to method 2 (28-byte header) is a
  defensible implementation choice** — at least as well-founded as writing a
  24-byte special case for a shape this project has never seen a single byte
  of — and Task 3 gets to rule on it rather than inherit a settled-sounding
  sentence from this manifest. The cost if the open question resolves the
  other way later is small and bounded: one additional reader branch, added
  once a real method-1 archive exists to test it against.
- **Beyond the minimum, for free:** Squashed (9), Crushed (10) and Distilled
  (11) are all covered too (the four `.pak` files), though none is named in
  the master design's three-method list — bonus coverage, not required.

ZOO's required scope in the design doc is just "ZOO (own)", with no method
list — the corpus covers all three of the format's known methods (Stored 0,
Compressed 1, CompressedLh5 2), which is a superset of any minimum this
design doc names.

**Ruling D verdict, as instructed:**
- **`cpm.arc`: borrowed.** Not because it is a refusal fixture — because it
  is the *only* borrowed file exercising RLE90 or Squeeze at all, both named
  explicitly in the master design's ARC method list. Skipping it would leave
  two of three required methods with zero corpus coverage.
- **`license_cypted.arc`: not borrowed, and this is the "redundant" branch of
  Ruling D's either/or.** Its one entry uses Crunched(8) (already covered by
  `crunch.arc`/`crunch2.arc`/`license_crunched.pak`) under ARC's XOR
  "encryption" (`arc_archive.rs`'s own doc comment: "ARC has no encryption
  flag in headers — wrong passwords result in CRC errors"). Because there is
  no header bit marking an entry encrypted, a reader with no password support
  cannot special-case it at all — it can only decode the method normally and
  observe the CRC-16 mismatch that decrypting-with-no-key produces, which is
  the *identical* code path `wrongcrc16.arc` already forces (successful
  method-level decode, CRC-16 disagreement, `Error::Corrupt`). It exercises
  no method and no code path the other nine ARC-family fixtures do not
  already cover, so it was left out rather than borrowed for a feature this
  format cannot even signal it needs.

### Step 4: `wrongcrc16.zoo` and `wrongcrc16.arc` really do carry bad CRCs

Both are the negative fixture the CRC conformance property needs — proof the
property can actually fire, not just pass vacuously. Confirmed with an
**independent** CRC-16/ARC implementation (a from-scratch Python
bit-at-a-time version, not a port of `crc16_arc` in
`crates/stuffr-formats/src/legacy/crc.rs` and not calling into `unarc-rs`),
pinned first against the same published check value Task 1 used
(`crc16_arc(b"123456789") == 0xBB3D`), then sanity-checked against the two
*correct* stored-method siblings before touching the "wrong" ones:

| file | stored CRC-16 (header) | CRC-16 of the actual on-disk payload | match? |
|---|---|---|---|
| `arc/store.arc` (sanity check) | `0xB065` | `0xB065` | yes |
| `zoo/store.zoo` (sanity check) | `0xB065` | `0xB065` | yes |
| `arc/wrongcrc16.arc` | `0xB065` | `0xE763` | **no** |
| `zoo/wrongcrc16.zoo` | `0xB065` | `0xE763` | **no** |

Both negative fixtures declare the *same* header CRC as the correct
`LICENSE` content (`0xB065`, matching `store.arc`/`store.zoo`) while their
actual stored payload bytes compute to the *same* wrong value (`0xE763`) in
both formats — consistent with both being derived from one shared corrupted
copy of the same underlying test asset upstream, not two independent
mistakes. Both entries use method "Stored" (ARC method 2, ZOO method 0), so
no decompression step is involved in either check above — the mismatch is in
the raw bytes themselves, not introduced by this measurement. **The
anti-vacuity double is present and confirmed for both formats — Ruling D's
concern (that only the ZOO side might have one) does not hold: `unarc-rs`
ships the ARC-side twin too, and it was borrowed.**
