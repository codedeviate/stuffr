# stuffr-core

The foundation of [stuffr](https://github.com/codedeviate/stuffr), a universal
compression and archive toolkit: traits, the stream ladder, the fidelity model,
the resource governor, the format registry and probe.

**This crate has zero format dependencies** — no `flate2`, no `zstd`, no
`liblzma`. That is deliberate and load-bearing: it is what makes the stream
ladder and the thread governor testable against mock formats with no C toolchain
in the loop. Real implementations live in
[`stuffr-formats`](https://crates.io/crates/stuffr-formats); most users want the
[`stuffr`](https://crates.io/crates/stuffr) facade instead of this crate
directly.

Errors are typed `thiserror` values, never `anyhow`, so a caller can `match` on
`NotSeekable` or `FormatNotEnabled` rather than parse a string.

## What is in here

- **`Codec` / `Container`** — the two axes. Compressing and collecting are
  separate operations that compose.
- **The stream ladder** — a format that needs to seek gets escalated over a
  source that cannot: in memory, then spooled to disk. The rung reached is
  *reported*, not hidden.
- **Fidelity** — what a round trip preserved and what it lost, as data, so the
  CLI's `--strict-fidelity` gate and its exit codes are one model rather than
  several.
- **The governor** — a single thread budget bounded by both CPU and memory.
  Codecs declare their per-worker demand; the governor hands out fewer, slower
  workers rather than risking the OOM killer.
- **The conformance harness** (`testing` feature) — twelve properties every
  codec must satisfy, in one line per codec:

  ```rust
  stuffr_core::testing::assert_codec_conforms(&MyCodec, &meta());
  ```

## License

[MIT](LICENSE).
