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
- **Input bytes:** the 45-byte ASCII string
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
  is the exact 45-byte string, not inferred from decoding anything — this is
  the strongest provenance available in this phase (see the phase's own
  task brief): a conformance or interop test that gets this fixture's
  expected output wrong is checking against ground truth typed by hand, not
  against the decoder's own opinion of itself.
