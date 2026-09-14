# Legacy format fixtures

Fixtures for the read-only legacy formats registered in Phase 3b
(`crates/stuffr-formats/src/legacy/`). Each entry below records exactly how
its fixture was produced, so its provenance can be checked without re-running
anything.

Append one entry per fixture added, in the same shape.

**Before editing `sample.lzh` or `sample.arj`, note this asymmetry between
them.** `sample.lzh`'s entry below records its two entries' CRC-16 values and
`lha v`'s output as literal hex, frozen at the moment the fixture was built.
`sample.arj`'s entry computes its expectations (CRC-32, sizes) from the
construction recipe at TEST time (`legacy::arj::tests::build_arj`), not from
literals written here. So a hand-edit to `sample.lzh`'s bytes can silently
strand the literal hex recorded below — it would no longer describe the
bytes on disk, and nothing would fail to say so — in a way a hand-edit to
`sample.arj` cannot, since its test recomputes expectations from the same
recipe every run. Regenerate `sample.lzh`'s recorded CRCs by hand (re-run
`lha v`/`t` from its own section below) if its bytes ever change;
`sample.arj` needs no such step.

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
