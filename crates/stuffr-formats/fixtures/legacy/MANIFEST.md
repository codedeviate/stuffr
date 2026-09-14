# Legacy format fixtures

Fixtures for the read-only legacy formats registered in Phase 3b
(`crates/stuffr-formats/src/legacy/`). Each entry below records exactly how
its fixture was produced, so its provenance can be checked without re-running
anything.

Append one entry per fixture added, in the same shape.

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
